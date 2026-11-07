"""Session-token replay protection, purge-while-disabled, and the hardened host status read.

Game side (module imported under Python 3, driven by hand) and host side (``civ4dbg.remote``).
The relative-clock (60 s) and coarse (256 s) rules are pinned here as secondary defences.
"""

import os
import re
import threading
import time

import pytest
from agentrepl_support import (
    FAKE_TOKEN,
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

TOKEN_SHAPE = re.compile(r"[0-9a-f]{32}\Z")


@pytest.fixture
def env(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    d = tmp_path / "ex"
    d.mkdir()
    return load_module(d), d


def enable(d):
    (d / "ENABLE").write_text("")


def status_of(text):
    for line in text.splitlines():
        if line.startswith("status: "):
            return line[8:]


def audit(d):
    p = d / "audit.log"
    return p.read_text() if p.exists() else ""


def run_one(env_, rid, src, **kw):
    mod, d = env_
    put_request(d, rid, src, **kw)
    mod.poll(force=True)
    p = reply_path(d, rid)
    return p.read_text() if p.exists() else None


# ------------------------------------------------------------------ the token itself


def test_token_is_published_first_in_status_and_stable(env):
    mod, d = env
    mod.poll(force=True)
    lines = (d / "status.txt").read_text().splitlines()
    assert lines[0] == "session: " + mod.SESSION_TOKEN
    assert TOKEN_SHAPE.match(mod.SESSION_TOKEN)
    mod._S["next"] = 0.0
    mod._S["next_hb"] = 0.0
    mod.poll(force=True)
    assert (d / "status.txt").read_text().splitlines()[0] == "session: " + mod.SESSION_TOKEN


def test_each_load_gets_a_new_token(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    tokens = {load_module(tmp_path).SESSION_TOKEN for _ in range(20)}
    assert len(tokens) == 20


def test_fallback_token_when_urandom_fails(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)

    def broken(n):
        raise NotImplementedError("no urandom")

    monkeypatch.setattr(os, "urandom", broken)
    mod = load_module(tmp_path)
    assert TOKEN_SHAPE.match(mod.SESSION_TOKEN)  # same shape, so the host accepts it
    monkeypatch.setattr(os, "getpid", lambda: 4242)
    assert mod._make_token()[:8] == "00001092"  # the pid is the first component


def test_host_accepts_only_well_formed_tokens():
    assert remote.session_token({"session": "ab" * 16}) == "ab" * 16
    for bad in ("", "short", "ZZ" * 16, "ab" * 40, "ab" * 16 + " x", "AB" * 16):
        assert remote.session_token({"session": bad}) is None
    assert remote.session_token({}) is None and remote.session_token(None) is None


# ------------------------------------------------------------------ the game refuses bad tokens


def test_request_with_the_right_token_runs(env):
    enable(env[1])
    assert status_of(run_one(env, "t1", "1+1")) == "ok"


@pytest.mark.parametrize(
    "src",
    [
        "marker = 1\n",  # no directive line at all
        "#@ budget 1\nmarker = 1\n",  # directives, but no session line
        "#@ budget 1\n#@ session TOKEN\nmarker = 1\n",  # token not on the FIRST line
        "#@ session\nmarker = 1\n",  # no value
        "#@ session TOKEN extra\nmarker = 1\n",  # trailing junk
        "# @ session TOKEN\nmarker = 1\n",
        "",
    ],
)
def test_missing_or_misplaced_token_is_refused_audited_and_not_run(env, src):
    mod, d = env
    enable(d)
    put_request(d, "m1", src.replace("TOKEN", mod.SESSION_TOKEN), token=False)
    mod.poll(force=True)
    rep = reply_path(d, "m1").read_text()
    assert status_of(rep) == "badsession" and "missing session token" in rep
    assert "m1 begin" in audit(d) and "m1 end badsession" in audit(d)
    assert "marker" not in (mod._S["ns"] or {})
    assert not (d / "req-m1.py").exists()  # claimed, not left to be retried


def test_wrong_token_is_refused_audited_and_not_run(env):
    mod, d = env
    enable(d)
    rep = run_one(env, "w1", "marker = 1", token="0" * 32)
    assert status_of(rep) == "badsession" and "mismatch" in rep
    assert mod.SESSION_TOKEN not in rep  # the reply does not echo the token
    assert "w1 end badsession" in audit(d)
    assert "marker" not in (mod._S["ns"] or {})


def test_token_check_does_not_depend_on_write_or_directives(env):
    mod, d = env
    enable(d)
    (d / "ENABLE_WRITE").write_text("")
    rep = run_one(env, "w2", "#@ write\nimport os\nmarker = 1", token="1" * 32)
    assert status_of(rep) == "badsession"  # ENABLE_WRITE + #@ write do not bypass it


def test_request_from_an_old_session_is_refused_after_a_restart(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    d = tmp_path / "ex"
    d.mkdir()
    enable(d)
    old = load_module(d)
    old_token = old.SESSION_TOKEN
    put_request(d, "o1", "marker = 1", token=old_token)  # written in the old session, never served
    new = load_module(d)  # the game restarted: new module, new token
    assert new.SESSION_TOKEN != old_token
    new.poll(force=True)
    rep = reply_path(d, "o1").read_text()
    assert status_of(rep) == "badsession"
    assert "marker" not in (new._S["ns"] or {})
    # and the new session still serves a request that carries its own token
    assert status_of(run_one((new, d), "o2", "1")) == "ok"


# ------------------------------------------------------------------ secondary defences, pinned


def test_request_without_a_valid_deadline_is_stale_and_audited(env):
    mod, d = env
    enable(d)
    for rid, kw in (
        ("n1", {"notafter": False}),
        ("n2", {"notafter": "abc"}),
        ("n3", {"notafter": "nan"}),
        ("n4", {"notafter": "inf"}),
        ("n5", {"notafter": "-5"}),
        ("n6", {"notafter": "1e9"}),
        ("n7", {"notafter": "99999999999999999999999"}),
        ("n8", {"notafter": "5 6"}),
        ("n9", {"notafter": ""}),
    ):
        r = run_one(env, rid, "marker = 1", **kw)
        assert status_of(r) == "stale", (rid, r)
        assert "deadline" in r
    assert "marker" not in (mod._S["ns"] or {})
    assert audit(d).count(" end stale ") == 9


def test_deadline_must_be_the_second_line_after_the_session_line(env):
    mod, d = env
    enable(d)
    tok = mod.SESSION_TOKEN
    ahead = mod._clock() + 100
    # on the third line, or before the session line: not the second line
    put_request(d, "p1", "#@ budget 3\n#@ notafter %.3f\nmarker = 1" % ahead, notafter=False)
    put_request(d, "p2", "marker = 1", token=False)
    (d / "req-p2.py").write_text("#@ notafter %.3f\n#@ session %s\nmarker = 1\n" % (ahead, tok))
    for rid in ("p1", "p2"):
        mod.poll(force=True)
        assert status_of(reply_path(d, rid).read_text()) in ("stale", "badsession"), rid
    assert "marker" not in (mod._S["ns"] or {})


def test_a_stale_request_with_a_wrong_token_is_badsession_first(env):
    mod, d = env
    enable(d)
    r = run_one(env, "w1", "1", token="WRONG", notafter=mod._clock() - 50)
    assert status_of(r) == "badsession"


def test_deadline_is_judged_on_the_relative_clock_not_the_wall_clock(env):
    mod, d = env
    enable(d)
    mod.time = type("T", (), {"time": staticmethod(lambda: 1.0), "clock": staticmethod(lambda: 0.0)})()
    assert status_of(run_one(env, "k1", "1", notafter=mod._clock() + 5)) == "ok"
    assert status_of(run_one(env, "k2", "1", notafter=mod._clock() - 5)) == "stale"


# ------------------------------------------------------------------ purge while ENABLE is absent


def test_requests_queued_while_off_are_deleted_audited_and_never_run(env):
    mod, d = env
    put_request(d, "q1", "marker = 1")
    put_request(d, "q2", "marker = 2")
    (d / "rep-keep.txt").write_text("not a request")
    (d / "ENABLE_WRITE").write_text("")
    mod.poll(force=True)
    assert not list(d.glob("req-*.py"))
    log = audit(d)
    assert "q1 purged (console switched off)" in log and "q2 purged (console switched off)" in log
    assert (d / "rep-keep.txt").exists() and (d / "ENABLE_WRITE").exists() and (d / "status.txt").exists()
    enable(d)
    mod._S["next"] = 0.0
    mod.poll(force=True)
    mod._S["next"] = 0.0
    mod.poll(force=True)
    assert "purged" in reply_path(d, "q1").read_text()  # answered, so a waiting host knows it did not run
    assert status_of(reply_path(d, "q2").read_text()) == "refused"
    assert " begin " not in audit(d) and "marker" not in (mod._S["ns"] or {})


def test_purge_is_rate_limited_per_poll(env):
    mod, d = env
    n = mod.PER_POLL_LIMIT + 3
    for i in range(n):
        put_request(d, "z%03d" % i, "1")
    mod.poll(force=True)
    assert len(list(d.glob("req-*.py"))) == 3
    mod._S["next"] = 0.0
    mod.poll(force=True)
    assert not list(d.glob("req-*.py"))
    assert audit(d).count("purged (console switched off)") == n


def test_purge_skips_undeletable_entries_without_repeating(env):
    mod, d = env
    (d / "req-dir1.py").mkdir()
    (d / "req-dir1.py" / "keep").write_text("x")
    put_request(d, "after", "1")
    mod.poll(force=True)
    mod._S["next"] = 0.0
    mod.poll(force=True)
    assert (d / "req-dir1.py").is_dir() and not (d / "req-after.py").exists()
    assert audit(d).count("dir1 purge failed") == 1


def test_enabled_but_self_disabled_module_does_not_purge(env):
    mod, d = env
    enable(d)
    mod._S["disabled"] = "5 consecutive internal errors"
    put_request(d, "k1", "1")
    mod.poll(force=True)
    assert (d / "req-k1.py").exists()  # ENABLE present: not the 'switched off' case


# ------------------------------------------------------------------ host: read_status hardening


def test_read_status_reads_a_regular_file(tmp_path):
    write_status(tmp_path)
    st = remote.read_status(str(tmp_path))
    assert st is not None and st["session"] == FAKE_TOKEN


@posix_only("os.O_DIRECTORY and dir_fd")
def test_read_status_reads_relative_to_a_directory_descriptor(tmp_path):
    write_status(tmp_path)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        assert remote.read_status(str(tmp_path), dir_fd=fd)["session"] == FAKE_TOKEN
    finally:
        os.close(fd)


def test_read_status_refuses_a_symlink(tmp_path):
    (tmp_path / "elsewhere.txt").write_text("session: " + "cd" * 16 + "\nepoch: 1\nenabled: true\n")
    symlink_or_skip(tmp_path / "elsewhere.txt", tmp_path / "status.txt")
    assert remote.read_status(str(tmp_path)) is None


@posix_only("os.mkfifo")
def test_read_status_does_not_hang_on_a_fifo(tmp_path):
    os.mkfifo(tmp_path / "status.txt")
    out = []
    t = threading.Thread(target=lambda: out.append(remote.read_status(str(tmp_path))), daemon=True)
    t.start()
    t.join(5)
    assert not t.is_alive() and out == [None]


def test_read_status_refuses_non_regular_and_oversize(tmp_path):
    (tmp_path / "status.txt").mkdir()
    assert remote.read_status(str(tmp_path)) is None
    (tmp_path / "status.txt").rmdir()
    (tmp_path / "status.txt").write_bytes(b"epoch: 1\nenabled: true\n" + b"x" * remote.STATUS_CAP)
    assert remote.read_status(str(tmp_path)) is None
    (tmp_path / "status.txt").write_bytes(b"epoch: 1\nenabled: true\n" + b"x" * (remote.STATUS_CAP - 100))
    assert remote.read_status(str(tmp_path)) is not None  # just under the cap is fine


def test_future_dated_heartbeat_is_not_fresh(tmp_path):
    path = write_status(tmp_path)
    now = time.time()
    os.utime(path, (now + 60, now + 60))
    assert remote.heartbeat_age(remote.read_status(str(tmp_path)), now, str(path)) is None
    os.utime(path, (now + 4, now + 4))  # within the 5 s slop: skew, reads as fresh
    assert remote.heartbeat_age(None, now, str(path)) == 0.0
    os.utime(path, (now + 6, now + 6))  # just past it: not a heartbeat
    assert remote.heartbeat_age(None, now, str(path)) is None
    os.utime(path, (now - 3, now - 3))
    assert 2.9 < remote.heartbeat_age(None, now, str(path)) < 3.1
    os.utime(path, (now + 60, now + 60))
    code, msg = remote.diagnose(str(tmp_path))
    assert code == remote.EXIT_TIMEOUT and "not polling" in msg


# ------------------------------------------------------------------ host: token in requests, retry once


def test_build_request_puts_the_session_line_first():
    data = remote.build_request("x = 1", 3.0, True, True, FAKE_TOKEN).decode().splitlines()
    assert data[:5] == [f"#@ session {FAKE_TOKEN}", "#@ reset", "#@ write", "#@ budget 3", "x = 1"]
    assert remote.build_request("x", None, False, False).decode() == "x\n"  # no token: untouched


@pytest.fixture
def exch(tmp_path):
    d = tmp_path / "AgentRepl"
    d.mkdir()
    os.chmod(d, 0o700)
    enable(d)
    return d


class Scripted(threading.Thread):
    """A game that answers each request by a script of (status, new_status_token_or_None)."""

    def __init__(self, d, script):
        super().__init__(daemon=True)
        self.d, self.script, self.requests = d, list(script), []
        self.stop = threading.Event()

    def run(self):
        while not self.stop.is_set():
            for name in sorted(os.listdir(self.d)):
                if name.startswith("req-") and name.endswith(".py"):
                    rid = name[4:-3]
                    src = (self.d / name).read_bytes().decode()
                    os.remove(self.d / name)
                    self.requests.append(src)
                    status, new_token = self.script.pop(0)
                    if new_token:
                        write_status(self.d, token=new_token)
                    detail = "session token mismatch" if status == "badsession" else ""
                    head = [
                        f"id: {rid}",
                        f"status: {status}",
                        "elapsed_ms: 1",
                        "turn: 3",
                        "polls: 9",
                        "stdout_bytes: 3",
                    ] + ([f"detail: {detail}"] if detail else [])
                    data = ("\n".join(head) + "\n---\nok\n").encode()
                    (self.d / f"rep-{rid}.tmp").write_bytes(data)
                    os.rename(self.d / f"rep-{rid}.tmp", self.d / f"rep-{rid}.txt")
            time.sleep(0.01)


def cli(d, *argv):
    return main(["exec", "--dir", str(d), *argv])


def test_host_retries_once_with_the_new_token_when_the_game_restarted(exch, capsys):
    write_status(exch, token="aa" * 16)
    g = Scripted(exch, [("badsession", "bb" * 16), ("ok", None)])
    g.start()
    try:
        assert cli(exch, "-c", "1") == 0
    finally:
        g.stop.set()
    assert [r.splitlines()[0] for r in g.requests] == ["#@ session " + "aa" * 16, "#@ session " + "bb" * 16]
    assert capsys.readouterr().out == "ok\n"


def test_host_does_not_retry_when_the_token_is_unchanged(exch, capsys):
    write_status(exch, token="aa" * 16)
    g = Scripted(exch, [("badsession", None), ("ok", None)])
    g.start()
    try:
        assert cli(exch, "-c", "1") == 3
    finally:
        g.stop.set()
    assert len(g.requests) == 1
    assert "did not run" in capsys.readouterr().err


def test_host_retries_at_most_once(exch, capsys):
    write_status(exch, token="aa" * 16)
    g = Scripted(exch, [("badsession", "bb" * 16), ("badsession", "cc" * 16), ("ok", None)])
    g.start()
    try:
        assert cli(exch, "-c", "1") == 3
    finally:
        g.stop.set()
    assert len(g.requests) == 2
    assert "refused the session token again" in capsys.readouterr().err


@pytest.mark.parametrize(
    "script",
    [
        [("badsession", "bb" * 16), ("stale", None), ("ok", None)],
        [("stale", None), ("badsession", "bb" * 16), ("ok", None)],
        [("stale", None), ("stale", None), ("ok", None)],
        [("badsession", "bb" * 16), ("badsession", "cc" * 16), ("ok", None)],
    ],
)
def test_mixed_refusals_end_after_two_sends_with_exit_3(exch, capsys, script):
    write_status(exch, token="aa" * 16)
    g = Scripted(exch, script)
    g.start()
    try:
        assert cli(exch, "-c", "1") == 3
    finally:
        g.stop.set()
    assert len(g.requests) == 2  # the third ("ok") is never sent
    assert not list(exch.glob("req-*"))
    assert "did not run" in capsys.readouterr().err


def test_host_sends_nothing_without_a_valid_token_in_status(exch, capsys):
    assert cli(exch, "-c", "1") == 3  # no status.txt at all
    write_status(exch, token="not-a-token")
    assert cli(exch, "-c", "1") == 3
    assert "session token" in capsys.readouterr().err
    assert not list(exch.glob("req-*"))


def test_real_game_rejects_a_stale_token_and_the_host_retries(tmp_path, monkeypatch):
    """The real poll loop: the host first reads a token that is no longer the game's, gets 'badsession',
    re-reads status.txt and retries once with the real one."""
    install_fake_game(monkeypatch)
    d = tmp_path / "AgentRepl"
    d.mkdir()
    os.chmod(d, 0o700)
    enable(d)
    mod = load_module(d)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            mod.onGameUpdate()
            time.sleep(0.01)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        deadline = time.monotonic() + 5
        while not (d / "status.txt").exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        real = remote.session_token
        calls = []

        def first_wrong(status):
            calls.append(1)
            return "0" * 32 if len(calls) == 1 else real(status)

        monkeypatch.setattr(remote, "session_token", first_wrong)
        assert cli(d, "-c", "print('through')") == 0
        assert len(calls) >= 2  # the wrong one, then the newer reading (re-derived for the retry)
        log = audit(d)
        assert log.count(" begin ") == 2, log  # exactly two sends: the badsession one and the retry
    finally:
        stop.set()
        t.join(5)
    log = audit(d)
    assert "end badsession" in log and "end ok" in log


# ------------------------------------------------------------------ D2 / D4


def test_host_reports_a_purged_request_as_not_run_and_switched_off(tmp_path, monkeypatch, capsys):
    """The user removes ENABLE after the host wrote its request: the game purges it and answers; the host
    must say it did NOT run (exit 4), not 'picked up ... ran'."""
    install_fake_game(monkeypatch)
    d = tmp_path / "AgentRepl"
    d.mkdir()
    os.chmod(d, 0o700)
    enable(d)
    mod = load_module(d)
    mod.poll(force=True)  # status.txt with the real token
    real_sleep = time.sleep

    def user_removes_enable_then_game_polls(secs):
        if (d / "ENABLE").exists():
            (d / "ENABLE").unlink()
            mod._S["next"] = 0.0
            mod.poll(force=True)  # sees ENABLE absent: purges + answers
        real_sleep(0)

    monkeypatch.setattr(remote.time, "sleep", user_removes_enable_then_game_polls)
    assert cli(d, "-c", "1") == 4
    err = capsys.readouterr().err
    assert "did not run" in err and "WAS picked up" not in err
    assert "purged" in audit(d)


def test_old_installed_module_without_a_session_line_gets_a_reinstall_message(exch, capsys):
    (exch / "status.txt").write_text(
        "alive_clock: 1\nepoch: %.3f\nturn: 5\nenabled: true\npolls: 4\nversion: 1\n" % time.time()
    )
    assert cli(exch, "-c", "1") == 3
    err = capsys.readouterr().err
    assert "older than this civ4dbg" in err and "agentrepl_install.py install" in err
    assert not list(exch.glob("req-*"))
    # a STALE status without a session line is the ordinary 'not polling' diagnosis, not a reinstall hint
    os.utime(exch / "status.txt", (time.time() - 60, time.time() - 60))
    assert cli(exch, "-c", "1") == 3
    assert "older than this civ4dbg" not in capsys.readouterr().err


def test_host_maps_a_readonly_reply_to_exit_5(exch, capsys):
    write_status(exch)
    g = Scripted(exch, [("readonly", None)])
    g.start()
    try:
        assert cli(exch, "-c", "p.changeGold(1)") == 5
    finally:
        g.stop.set()
    assert "read-only" in capsys.readouterr().err
