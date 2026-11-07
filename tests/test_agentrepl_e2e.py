"""End-to-end: the real in-game poll loop (background thread, stubbed game modules, real exchange
directory, real 0.25 s throttle) driven by the real host CLI run as a subprocess (``civ4dbg.py exec``).

Plus adversarial inputs against the real module. Nothing here touches a real mod or the git-ignored binaries
directory.
"""

import os
import re
import subprocess
import sys
import threading
import time

import pytest
from agentrepl_support import ROOT, install_fake_game, load_module, put_request, symlink_or_skip, write_status

LAUNCHER = str(ROOT / "civ4dbg.py")


@pytest.fixture
def exch(tmp_path):
    d = tmp_path / "AgentRepl"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)
    return d


class Game:
    """The poll loop on a thread, exactly as the BUG gameUpdate event would call it (throttled)."""

    def __init__(self, exch_dir, monkeypatch):
        install_fake_game(monkeypatch)
        self.dir = exch_dir
        self.mod = load_module(exch_dir)
        self.stop = threading.Event()
        self.escaped = []  # anything that escaped onGameUpdate
        self.thread = threading.Thread(target=self._loop, daemon=True)

    def _loop(self):
        while not self.stop.is_set():
            try:
                self.mod.onGameUpdate()
            except BaseException as exc:  # onGameUpdate must never raise
                self.escaped.append(exc)
            time.sleep(0.01)

    def start(self):
        self.thread.start()
        assert wait_for(lambda: (self.dir / "status.txt").exists()), "the game never wrote status.txt"
        return self

    def close(self):
        self.stop.set()
        self.thread.join(15)
        assert not self.thread.is_alive(), "poll thread did not stop"

    def audit(self):
        p = self.dir / "audit.log"
        return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


@pytest.fixture
def game(exch, monkeypatch):
    g = Game(exch, monkeypatch)
    yield g
    g.close()
    assert g.escaped == []


def host_cmd(d, *argv):
    return [sys.executable, "-I", LAUNCHER, "exec", "--dir", str(d), *argv]


def host(d, *argv, timeout=60, stdin=None):
    return subprocess.run(host_cmd(d, *argv), capture_output=True, text=True, timeout=timeout, input=stdin)


def enable(d, write=False):
    (d / "ENABLE").write_text("")
    if write:
        (d / "ENABLE_WRITE").write_text("")


def head_bytes(game, ahead=300.0):
    """The two header lines a host writes: the session token and a deadline `ahead` s from now."""
    return (
        b"#@ session " + game.mod.SESSION_TOKEN.encode() + b"\n" + b"#@ notafter %.3f\n" % (game.mod._clock() + ahead)
    )


def wait_for(pred, secs=10.0):
    end = time.monotonic() + secs
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


# ---------------------------------------------------------------- 1. the round trips


def test_print_roundtrip(game, exch):
    enable(exch)
    game.start()
    r = host(exch, "-c", "print(game.getGameTurn(), 'hi')")
    assert (r.returncode, r.stdout) == (0, "241 hi\n"), r.stderr
    # the reply is consumed by the host
    assert not list(exch.glob("rep-*")) and not list(exch.glob("req-*"))


def test_exception_reply(game, exch):
    enable(exch)
    game.start()
    r = host(exch, "-c", "def f():\n    raise ValueError('boom')\nf()")
    assert r.returncode == 1
    assert "ValueError: boom" in r.stderr
    assert any(" end error " in ln for ln in game.audit())


def test_budget_timeout_interrupts_busy_loop(game, exch):
    enable(exch)
    game.start()
    t0 = time.monotonic()
    r = host(exch, "--budget", "1", "--timeout", "8", "-c", "while True:\n    pass")
    assert r.returncode == 3, r.stderr
    assert "budget exceeded" in r.stderr
    assert time.monotonic() - t0 < 7
    # the loop survived and is usable
    r = host(exch, "-c", "print('after')")
    assert (r.returncode, r.stdout) == (0, "after\n")


def test_enable_off_then_on(game, exch):
    game.start()
    r = host(exch, "-c", "print(1)")
    assert r.returncode == 4 and "switched off" in r.stderr
    assert not (exch / "ENABLE").exists()  # the tool never creates ENABLE
    assert not list(exch.glob("req-*"))
    # a request planted while off (even one with the right token) is deleted, audited and never runs ...
    req = put_request(exch, "planted-1", "print('planted')\n")
    assert wait_for(lambda: not req.exists(), 5)  # purged within OFF_INTERVAL
    assert any("planted-1 purged" in ln for ln in game.audit())
    # ... so flipping the switch afterwards runs nothing
    enable(exch)
    time.sleep(0.8)
    assert "status: refused" in (exch / "rep-planted-1.txt").read_text()  # answered "purged", not run
    assert not any("planted-1 begin" in ln for ln in game.audit())
    # and switched off again stops service and the heartbeat says so
    (exch / "ENABLE").unlink()
    assert wait_for(lambda: "enabled: false" in (exch / "status.txt").read_text(), 5)
    r = host(exch, "-c", "print(2)")
    assert r.returncode == 4


def test_write_gate(game, exch):
    enable(exch)  # ENABLE only
    game.start()
    r = host(exch, "--write", "-c", "print(1)")
    assert r.returncode == 5 and "ENABLE_WRITE" in r.stderr
    assert not list(exch.glob("req-*"))  # refused by the host before anything was sent
    # a hand-planted '#@ write' request with a refused construct, still no ENABLE_WRITE: refused by the game
    put_request(exch, "w1", "#@ write\nimport os\nprint(os.sep)\n")
    assert wait_for(lambda: (exch / "rep-w1.txt").exists())
    rep = (exch / "rep-w1.txt").read_text()
    assert "status: readonly" in rep and "ENABLE_WRITE is absent" in rep
    # ENABLE_WRITE exists but the request has no '#@ write': still refused
    (exch / "ENABLE_WRITE").write_text("")
    r = host(exch, "-c", "import os\nprint(os.sep)")
    assert r.returncode == 5 and "refused by the game" in r.stderr
    # both present: runs
    r = host(exch, "--write", "-c", "import os\nprint(os.sep)")
    assert (r.returncode, r.stdout) == (0, "/\n"), r.stderr


def test_host_timeout_did_not_run(exch):
    enable(exch)  # nobody is polling; a (stale) status.txt carries a token
    write_status(exch, age=30)
    r = host(exch, "--budget", "0.5", "--timeout", "1.2", "-c", "print(1)")
    assert r.returncode == 3
    assert "did NOT run" in r.stderr and "WAS picked up" not in r.stderr
    assert not list(exch.glob("req-*"))  # withdrawn


def test_host_without_status_sends_nothing(exch):
    enable(exch)  # no status.txt, so no session token to send
    r = host(exch, "--budget", "0.5", "--timeout", "1.2", "-c", "print(1)")
    assert r.returncode == 3 and "session token" in r.stderr
    assert not list(exch.glob("req-*"))


def test_host_timeout_was_picked_up(game, exch):
    enable(exch)
    game.mod._send_reply = lambda d, rid, data: None  # the game consumes and runs but never answers
    game.start()
    r = host(exch, "--budget", "0.5", "--timeout", "1.5", "-c", "print('ran')")
    assert r.returncode == 3
    assert "WAS picked up" in r.stderr and "did NOT run" not in r.stderr
    assert any(" begin " in ln for ln in game.audit())  # and it really did run (audited)


def test_two_concurrent_host_processes(game, exch):
    enable(exch)
    game.start()
    procs = [
        subprocess.Popen(
            host_cmd(exch, "-c", f"print('client-{n}')"), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )
        for n in range(2)
    ]
    results = [p.communicate(timeout=60) for p in procs]
    assert [p.returncode for p in procs] == [0, 0], results
    assert sorted(out for out, _ in results) == ["client-0\n", "client-1\n"]


def test_audit_order_and_full_source(game, exch):
    enable(exch)
    game.start()
    src = "x = 'a\\\\b'\nprint('line2')\n# " + "z" * 500
    seen = []

    def watch():
        # the begin line must be on disk before the reply exists
        while not game.stop.is_set():
            has_reply = bool(list(exch.glob("rep-*.txt")))
            begin = any(" begin " in ln for ln in game.audit())
            if has_reply:
                seen.append(begin)
                return
            time.sleep(0.002)

    w = threading.Thread(target=watch, daemon=True)
    w.start()
    r = host(exch, "-c", src)
    w.join(5)
    assert r.returncode == 0, r.stderr
    assert seen in ([True], [])  # [] only if the host consumed the reply first
    lines = game.audit()
    begins = [i for i, ln in enumerate(lines) if " begin " in ln]
    ends = [i for i, ln in enumerate(lines) if " end ok " in ln]
    assert len(begins) == 1 and len(ends) == 1 and begins[0] < ends[0]
    body = lines[begins[0]].split(" begin ", 1)[1]
    assert re.fullmatch(
        r"#@ session %s\\n#@ notafter \d+\.\d{3}\\n" % game.mod.SESSION_TOKEN,
        body[: body.index("\\n", body.index("notafter")) + 2],
    )
    body = body.split("\\n", 2)[2]  # past the session and notafter lines the source is intact
    expect = (src + "\n").replace("\\", "\\\\").replace("\n", "\\n")
    assert body == expect  # untruncated, one line, escaped
    # line format: epoch_coarse=<n> clock=<x> <id> <event> ...
    rid_b = lines[begins[0]].split()[2]
    assert rid_b == lines[ends[0]].split()[2]


# ---------------------------------------------------------------- 2. adversarial inputs


def outside_untouched(tmp_path, exch):
    """Every file under tmp_path that is outside the exchange dir (the canary and parents)."""
    return sorted(str(p.relative_to(tmp_path)) for p in tmp_path.rglob("*") if exch not in p.parents and p != exch)


@pytest.mark.parametrize("rid", ["..%2f..%2fcanary", "a b", "x;y", "é", "a" * 81, "a.b", "..", ""])
def test_hostile_request_ids_never_escape(game, exch, tmp_path, rid):
    (tmp_path / "canary.txt").write_text("canary")
    before = outside_untouched(tmp_path, exch)
    enable(exch)
    game.start()
    (exch / f"req-{rid}.py").write_text("print('x')\n")
    time.sleep(0.9)
    assert outside_untouched(tmp_path, exch) == before
    assert (tmp_path / "canary.txt").read_text() == "canary"
    assert game.escaped == []
    # an id that is invalid is dropped, not run
    assert not any(" begin " in ln for ln in game.audit())


def test_ids_with_real_path_separators(game, exch, tmp_path):
    """A name with a slash cannot be a directory entry; a '..' prefix id must be just a name."""
    enable(exch)
    game.start()
    (exch / "sub").mkdir()
    (exch / "sub" / "req-x.py").write_text("print(1)\n")  # nested: never looked at
    (exch / "req-..py").write_text("print(1)\n")  # id '.'
    (exch / "req-....py").write_text("print(1)\n")  # id '..'
    time.sleep(0.9)
    assert (exch / "sub" / "req-x.py").exists()
    assert sorted(p.name for p in tmp_path.iterdir()) == ["AgentRepl"]
    assert not any(" begin " in ln for ln in game.audit())


def test_huge_request(game, exch):
    enable(exch)
    game.start()
    (exch / "req-big1.py").write_bytes(head_bytes(game) + b"#" * (5 * 1024 * 1024) + b"\nprint(1)\n")
    assert wait_for(lambda: (exch / "rep-big1.txt").exists(), 10)
    assert "status: toolarge" in (exch / "rep-big1.txt").read_text()
    assert not (exch / "req-big1.py").exists()
    log = (exch / "audit.log").stat().st_size
    assert log < 200 * 1024  # begin line capped, not 5 MiB
    r = host(exch, "-c", "print('alive')")
    assert r.returncode == 0


def test_host_rejects_oversize_before_sending(exch):
    enable(exch)
    r = host(exch, "-c", "#" * (70 * 1024))
    assert r.returncode == 2 and not list(exch.glob("req-*"))


def test_binary_garbage_and_empty(game, exch):
    enable(exch)
    game.start()
    head = head_bytes(game)
    (exch / "req-bin1.py").write_bytes(head + bytes(range(256)) * 40 + b"\x00\xff\xfe")
    (exch / "req-emp1.py").write_bytes(head)
    (exch / "req-nul1.py").write_bytes(head + b"print(1)\x00\n")
    for rid in ("bin1", "emp1", "nul1"):
        assert wait_for(lambda rid=rid: (exch / f"rep-{rid}.txt").exists(), 10), rid
    for rid in ("bin1", "nul1"):  # garbage cannot be tokenized: refused by read-only mode, never run
        assert "status: readonly" in (exch / f"rep-{rid}.txt").read_text()
    assert "status: ok" in (exch / "rep-emp1.txt").read_text()
    r = host(exch, "-c", "print('alive')")
    assert r.returncode == 0 and game.escaped == []


def test_symlink_planted_as_request(game, exch, tmp_path):
    secret = tmp_path / "secret.txt"
    secret.write_text("print('SECRET-RAN')\n")
    enable(exch)
    game.start()
    symlink_or_skip(secret, exch / "req-lnk1.py")
    assert wait_for(lambda: (exch / "rep-lnk1.txt").exists() or not os.path.lexists(exch / "req-lnk1.py"), 10)
    time.sleep(0.6)
    assert secret.read_text() == "print('SECRET-RAN')\n"  # the target is never deleted
    reply = (exch / "rep-lnk1.txt").read_text() if (exch / "rep-lnk1.txt").exists() else ""
    assert "SECRET-RAN" not in reply  # a symlinked request must not be followed


def test_symlink_planted_as_dangling_request(game, exch):
    enable(exch)
    game.start()
    symlink_or_skip(str(exch.parent / "nonexistent"), exch / "req-dng1.py")
    time.sleep(0.9)
    assert game.escaped == []
    r = host(exch, "-c", "print('alive')")
    assert r.returncode == 0


def test_symlink_planted_as_reply_host_refuses(exch, tmp_path, monkeypatch):
    import civ4dbg.remote as remote

    enable(exch)
    write_status(exch)
    secret = tmp_path / "secret.txt"
    secret.write_text("LEAK")
    rid = "20260101000000-1-abcd"
    monkeypatch.setattr(remote, "new_id", lambda: rid)
    symlink_or_skip(secret, exch / f"rep-{rid}.txt")
    with pytest.raises(remote.ReplError) as ei:
        remote.execute(str(exch), "print(1)", timeout=1.5, budget=0.5)
    assert ei.value.code == remote.EXIT_MALFORMED
    assert secret.read_text() == "LEAK"


def test_reply_replaced_mid_read(exch, tmp_path, monkeypatch, capsys):
    """The reply path is swapped (symlink / garbage / other id) while the host polls it."""
    import civ4dbg.remote as remote

    enable(exch)
    write_status(exch)
    rid = "20260101000000-1-feed"
    monkeypatch.setattr(remote, "new_id", lambda: rid)
    target = exch / f"rep-{rid}.txt"
    secret = tmp_path / "secret.txt"
    secret.write_text("LEAK")
    stop = threading.Event()

    def flipper():
        n = 0
        while not stop.is_set():
            tmp = exch / f"flip{n}.tmp"
            try:
                if n % 3 == 0:
                    os.symlink(secret, tmp)
                elif n % 3 == 1:
                    tmp.write_text("garbage without separator")
                else:
                    tmp.write_text("id: other\nstatus: ok\n---\nLEAK")
                os.replace(tmp, target)
            except OSError:
                pass
            n += 1

    t = threading.Thread(target=flipper, daemon=True)
    t.start()
    try:
        with pytest.raises(remote.ReplError) as ei:
            remote.execute(str(exch), "print(1)", timeout=1.5, budget=0.5)
    finally:
        stop.set()
        t.join(5)
    assert ei.value.code == remote.EXIT_MALFORMED
    assert "LEAK" not in capsys.readouterr().out
    assert secret.read_text() == "LEAK"


def test_directory_named_like_request_does_not_break_loop(game, exch):
    enable(exch)
    game.start()
    (exch / "req-dir1.py").mkdir()
    (exch / "req-dir1.py" / "keep").write_text("x")
    time.sleep(0.9)
    r = host(exch, "-c", "print('alive')")
    assert r.returncode == 0 and game.escaped == []


def test_exchange_dir_vanishes_midway(game, exch, tmp_path):
    enable(exch)
    game.start()
    time.sleep(0.4)
    import shutil

    shutil.rmtree(exch)
    time.sleep(1.5)
    assert game.escaped == []
    assert game.thread.is_alive()
