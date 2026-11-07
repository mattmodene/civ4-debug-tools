"""Review fixes F1-F5 and F7 for the in-game module, and F8 host edge cases."""

import os

import pytest
from agentrepl_support import (
    ROOT,
    install_fake_game,
    load_module,
    posix_only,
    put_request,
    reply_path,
    symlink_or_skip,
    write_status,
)

from civ4dbg import remote
from civ4dbg.__main__ import main


@pytest.fixture
def env(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    d = tmp_path / "ex"
    d.mkdir()
    return load_module(d), d


def enable(d, write=False):
    (d / "ENABLE").write_text("")
    if write:
        (d / "ENABLE_WRITE").write_text("")


def run(env_, rid, src, age=0.0, **kw):
    mod, d = env_
    put_request(d, rid, src, age, **kw)
    mod.poll(force=True)
    p = reply_path(d, rid)
    return p.read_text() if p.exists() else None


def status_of(text):
    for line in text.splitlines():
        if line.startswith("status: "):
            return line[8:]


def audit_text(d):
    return (d / "audit.log").read_text()


def test_f1_full_source_is_audited_before_it_runs(env, monkeypatch):
    mod, d = env
    enable(d)
    seen = {}
    real = mod._execute

    def spy(src, ns, budget):
        seen["audit"] = audit_text(d)
        return real(src, ns, budget)

    monkeypatch.setattr(mod, "_execute", spy)
    run(env, "f1", "#" + "x" * 300 + "\nprint('tail-marker')")
    assert "f1 begin" in seen["audit"] and "tail-marker" in seen["audit"]  # untruncated, and before running
    assert seen["audit"].count("\n") == 1 and "\\n" in seen["audit"]  # escaped onto one line
    assert "f1 end ok" in audit_text(d)


def test_f1_audit_failure_means_no_execution(env):
    mod, d = env
    enable(d)
    (d / "audit.log").mkdir()  # appending now fails
    r = run(env, "f1b", "ran = 1")
    assert status_of(r) == "error" and "audit unavailable" in r
    (d / "audit.log").rmdir()
    assert "NameError" in run(env, "f1c", "ran")


def test_f1_escape_is_loss_free(env):
    mod, _ = env
    assert mod._escape("a\\b\r\nc") == "a\\\\b\\r\\nc"


def test_f2_directory_named_like_a_request_does_not_wedge_the_queue(env):
    mod, d = env
    enable(d)
    (d / "req-poison.py").mkdir()
    (d / "req-poison.py" / "keep").write_text("x")  # non-empty: cannot be removed
    put_request(d, "zz-good", "1+1")
    for _ in range(4):
        mod.poll(force=True)
    assert reply_path(d, "zz-good").exists()
    assert audit_text(d).count("poison unreadable") == 1  # once, not once per poll
    assert not mod._S["disabled"] and mod._S["fails"] == 0


def test_f2_unreadable_file_is_removed_with_audit(env):
    mod, d = env
    enable(d)
    p = put_request(d, "locked", "1")
    os.chmod(p, 0)
    if os.access(p, os.R_OK):
        pytest.skip("running as a user that ignores file modes")
    mod.poll(force=True)
    assert not p.exists() and "locked unreadable, removed" in audit_text(d)


def test_f2_request_errors_never_self_disable(env, monkeypatch):
    mod, d = env
    enable(d)

    def boom(*a):
        raise RuntimeError("per-request")

    monkeypatch.setattr(mod, "_send_reply", boom)
    for i in range(mod.MAX_FAILS + 3):
        put_request(d, "pr%d" % i, "1")
        mod._S["next"] = 0.0
        mod.onGameUpdate()
    assert not mod._S["disabled"]
    assert audit_text(d).count("REQUEST-ERROR") == mod.MAX_FAILS + 3


def test_f3_the_game_only_runs_what_it_claimed(env, monkeypatch):
    mod, d = env
    enable(d)
    real_read = mod._read

    def host_wins(path, limit):
        data = real_read(path, limit)
        os.remove(path)  # the host's withdrawal lands between read and claim
        return data

    monkeypatch.setattr(mod, "_read", host_wins)
    put_request(d, "f3", "ran = 1")
    mod.poll(force=True)
    assert not reply_path(d, "f3").exists() and "f3 withdrawn" in audit_text(d)
    monkeypatch.setattr(mod, "_read", real_read)
    assert "NameError" in run(env, "f3b", "ran")


@pytest.mark.parametrize("raiser", ["raise GeneratorExit", "raise KeyboardInterrupt", "raise BaseException('b')"])
def test_f4_non_exception_raises_still_get_a_reply_and_audit(env, raiser):
    mod, d = env
    enable(d)
    r = run(env, "f4", raiser)
    assert status_of(r) == "error" and "--- traceback ---" in r
    assert "f4 end error" in audit_text(d) and mod._S["fails"] == 0
    assert status_of(run(env, "f4b", "1")) == "ok"


def test_f5_text_is_encoded_as_utf8_bytes(env):
    mod, d = env
    assert mod._b("café") == "café".encode()
    assert mod._b(b"raw") == b"raw"
    enable(d)
    run(env, "f5", "print('café')")
    body = reply_path(d, "f5").read_bytes()
    assert b"stdout_bytes: 6\n" in body and "café\n".encode() in body  # bytes, not characters


def test_file_mtime_plays_no_part_in_staleness(env):
    """The coarse mtime rules (past and future) are gone: only the request's own deadline counts."""
    mod, d = env
    enable(d)
    for rid, age in (("f7a", -3600), ("f7b", 3600), ("f7c", 100000)):
        assert status_of(run(env, rid, "marker = 1", age=age)) == "ok", rid


def test_deadline_boundary_on_the_relative_clock(env):
    """A deadline D runs at game clock D and is stale just after it; the check uses the exact clock."""
    mod, d = env
    now = [500.0]
    mod._clock = lambda: now[0]
    enable(d)
    put_request(d, "rs1", "1", notafter=560.0)
    put_request(d, "rs2", "2", notafter=560.0)
    mod._note_requests(str(d), now[0])
    now[0] = 560.0
    mod.poll(force=True)  # handles rs1 only (one per poll)
    assert status_of(reply_path(d, "rs1").read_text()) == "ok"  # exactly at the deadline
    now[0] = 560.5
    mod.poll(force=True)
    r = reply_path(d, "rs2").read_text()
    assert status_of(r) == "stale" and "deadline passed" in r  # discarded unrun
    assert "2" not in r.split("---")[1]


def test_seen_cap_refuses_new_requests_and_tracked_ones_keep_their_deadline(env):
    """C1: beyond SEEN_CAP tracked requests, NEW ones are refused (deleted, audited, answered), never
    left untracked where they would look first-seen-now forever."""
    mod, d = env
    now = [100.0]
    mod._clock = lambda: now[0]
    for i in range(mod.SEEN_CAP + 10):
        put_request(d, "b%04d" % i, "1")
    mod._note_requests(str(d), now[0])
    mod._note_requests(str(d), now[0])  # the refusals are rate limited per poll (8 + 2)
    assert len(mod._S["seen"]) == mod.SEEN_CAP
    assert len(list(d.glob("req-*.py"))) == mod.SEEN_CAP  # only the tracked ones remain
    rep = reply_path(d, "b%04d" % mod.SEEN_CAP).read_text()
    assert status_of(rep) == "refused" and "queue is full" in rep
    assert audit_text(d).count("refused: queue full") == 10
    # a tracked request is still judged by its deadline on the relative clock (300 s ahead of 100)
    enable(d)
    now[0] = 401.0
    mod.poll(force=True)
    assert status_of(reply_path(d, "b0000").read_text()) == "stale"


def test_seen_cap_refusals_are_rate_limited_per_poll(env):
    mod, d = env
    for i in range(mod.SEEN_CAP + mod.PER_POLL_LIMIT + 5):
        put_request(d, "c%04d" % i, "1")
    mod._note_requests(str(d), 1.0)
    assert audit_text(d).count("refused: queue full") == mod.PER_POLL_LIMIT
    mod._note_requests(str(d), 1.0)
    assert audit_text(d).count("refused: queue full") == mod.PER_POLL_LIMIT + 5


def test_seen_memory_is_pruned(env):
    mod, d = env
    enable(d)
    for i in range(5):
        put_request(d, "p%d" % i, "1")
    mod._note_requests(str(d), 1.0)
    assert len(mod._S["seen"]) == 5
    for p in d.glob("req-*.py"):
        p.unlink()
    mod.poll(force=True)
    assert mod._S["seen"] == {}


# --- host (F6, F8) ------------------------------------------------------------------


@pytest.fixture
def exch(tmp_path):
    d = tmp_path / "AgentRepl"
    d.mkdir()
    os.chmod(d, 0o700)
    (d / "ENABLE").write_text("")
    write_status(d)
    return d


def cli(d, *argv):
    return main(["exec", "--dir", str(d), *argv])


@pytest.mark.parametrize("bad", ["nan", "inf", "-1", "0"])
def test_f8_timeout_must_be_finite_and_positive(exch, bad):
    assert cli(exch, "-c", "1", "--timeout", bad) == 2
    assert not [p for p in os.listdir(exch) if p.startswith("req-")]


@pytest.mark.parametrize("bad", ["nan", "inf"])
def test_f8_budget_must_be_finite(exch, bad):
    assert cli(exch, "-c", "1", "--budget", bad) == 2


def test_f8_keyboard_interrupt_withdraws_the_request(exch, capsys, monkeypatch):
    def interrupted(fd, rid, until):
        raise KeyboardInterrupt

    monkeypatch.setattr(remote, "_wait_reply", interrupted)
    assert cli(exch, "-c", "1") == 3
    err = capsys.readouterr().err
    assert "interrupted" in err and "did NOT run" in err
    assert not [p for p in os.listdir(exch) if p.startswith("req-")]


SIGTERM_CHILD = """
import os, signal, sys
root, exchange = sys.argv[1], sys.argv[2]
sys.path.insert(0, root)
from civ4dbg import remote
from civ4dbg.__main__ import main

def term(fd, rid, until):
    os.kill(os.getpid(), signal.SIGTERM)
    raise AssertionError("not reached")

remote._wait_reply = term
rc = main(["exec", "--dir", exchange, "-c", "1"])
print("restored=%s" % (signal.getsignal(signal.SIGTERM) is not signal.default_int_handler))
sys.exit(rc)
"""


@posix_only("SIGTERM delivery; on Windows os.kill is TerminateProcess and nothing can handle it")
def test_f8_sigterm_is_treated_like_ctrl_c(exch, tmp_path):
    # Runs in a child process so a signal handling bug can never terminate the pytest runner.
    import subprocess
    import sys

    r = subprocess.run(
        [sys.executable, "-I", "-c", SIGTERM_CHILD, str(ROOT), str(exch)],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    assert r.returncode == 3, (r.stdout, r.stderr)
    assert "interrupted" in r.stderr
    assert "restored=True" in r.stdout  # handler restored
    assert not [p for p in os.listdir(exch) if p.startswith("req-")]


def test_f8_permission_error_on_withdrawal_is_reported(exch, capsys, monkeypatch):
    real = os.unlink

    def deny(path, *a, **k):
        if str(path).startswith("req-"):
            raise PermissionError(13, "denied")
        return real(path, *a, **k)

    monkeypatch.setattr(os, "unlink", deny)
    assert cli(exch, "-c", "1", "--timeout", "0.7", "--budget", "0.1") == 3
    assert "MAY still run" in capsys.readouterr().err


def test_f6_symlinked_ancestor_is_refused(tmp_path):
    real = tmp_path / "real"
    real.mkdir()
    sub = real / "AgentRepl"
    sub.mkdir()
    os.chmod(sub, 0o700)
    (sub / "ENABLE").write_text("")
    symlink_or_skip(real, tmp_path / "linked")
    assert cli(tmp_path / "linked" / "AgentRepl", "-c", "1") == 5
    assert cli(sub, "--status") in (3, 4, 0)  # the direct path is accepted


@posix_only("group/other write bits on an ancestor; not checked on Windows")
def test_f6_group_writable_ancestor_is_refused(tmp_path):
    parent = tmp_path / "open"
    parent.mkdir()
    sub = parent / "AgentRepl"
    sub.mkdir()
    os.chmod(sub, 0o700)
    os.chmod(parent, 0o777)
    assert cli(sub, "-c", "1") == 5


def test_f6_reply_that_is_a_symlink_is_refused(exch, tmp_path, monkeypatch):
    monkeypatch.setattr(remote, "new_id", lambda: "fixedid")
    target = tmp_path / "target.txt"
    target.write_text("id: fixedid\nstatus: ok\nstdout_bytes: 0\n---\n")
    symlink_or_skip(target, exch / "rep-fixedid.txt")
    assert cli(exch, "-c", "1", "--timeout", "1", "--budget", "0.1") == 6


def test_f6_oversize_reply_is_refused(exch, monkeypatch):
    monkeypatch.setattr(remote, "new_id", lambda: "bigid")
    (exch / "rep-bigid.txt").write_bytes(b"x" * (remote.REPLY_CAP + 10))
    assert cli(exch, "-c", "1", "--timeout", "1", "--budget", "0.1") == 6


@posix_only("os.mkfifo")
def test_f6_fifo_reply_does_not_hang(exch, monkeypatch):
    monkeypatch.setattr(remote, "new_id", lambda: "fifoid")
    os.mkfifo(exch / "rep-fifoid.txt")
    assert cli(exch, "-c", "1", "--timeout", "1", "--budget", "0.1") == 6
