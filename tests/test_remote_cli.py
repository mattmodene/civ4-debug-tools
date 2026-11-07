"""Host side of AgentRepl: `civ4dbg exec` against a simulated game, and against the real module."""

import os
import threading
import time

import pytest
from agentrepl_support import install_fake_game, load_module, posix_only, symlink_or_skip

from civ4dbg import remote
from civ4dbg.__main__ import main


def make_reply(rid, status="ok", out="", tb="", detail=""):
    ob = out.encode()
    head = [f"id: {rid}", f"status: {status}", "elapsed_ms: 1", "turn: 3", "polls: 9", f"stdout_bytes: {len(ob)}"]
    if detail:
        head.append(f"detail: {detail}")
    data = ("\n".join(head) + "\n---\n").encode() + ob
    if tb:
        data += b"--- traceback ---\n" + tb.encode()
    return data


class FakeGame(threading.Thread):
    """Answers requests in the exchange directory like the game would, with a scripted reply."""

    def __init__(self, d, responder, consume=True):
        super().__init__(daemon=True)
        self.d, self.responder, self.consume = d, responder, consume
        self.stop = threading.Event()
        self.requests = []

    def run(self):
        while not self.stop.is_set():
            for name in sorted(os.listdir(self.d)):
                if name.startswith("req-") and name.endswith(".py"):
                    rid = name[4:-3]
                    path = os.path.join(self.d, name)
                    src = open(path, "rb").read().decode()
                    self.requests.append(src)
                    if self.consume:
                        os.unlink(path)
                    data = self.responder(rid, src)
                    if data is not None:
                        tmp = os.path.join(self.d, f"rep-{rid}.tmp")
                        open(tmp, "wb").write(data)
                        os.rename(tmp, os.path.join(self.d, f"rep-{rid}.txt"))
            time.sleep(0.01)


@pytest.fixture
def exch(tmp_path):
    d = tmp_path / "AgentRepl"
    d.mkdir(mode=0o700)
    os.chmod(d, 0o700)
    return d


TOKEN = "ab12cd34" * 4  # the simulated game's session token


def enable(d, write=False):
    (d / "ENABLE").write_text("")
    if not (d / "status.txt").exists():
        heartbeat(d)
    if write:
        (d / "ENABLE_WRITE").write_text("")


def cli(d, *argv):
    return main(["exec", "--dir", str(d), *argv])


def game(d, responder, **kw):
    g = FakeGame(str(d), responder, **kw)
    g.start()
    return g


def heartbeat(d, enabled=True, age=0.0, reason="", session=None):
    session = TOKEN if session is None else session
    (d / "status.txt").write_text(
        f"session: {session}\nalive_clock: 1\nepoch: {time.time() - age:.3f}\nturn: 5\n"
        f"enabled: {str(enabled).lower()}\n"
        f"write_enabled: false\ndisabled_reason: {reason}\nlast_id: \npolls: 4\nversion: 3\n"
    )
    t = time.time() - age  # the host judges freshness by the file mtime
    os.utime(d / "status.txt", (t, t))


# --- exit codes ------------------------------------------------------------


def test_exit0_prints_stdout(exch, capsys):
    enable(exch)
    g = game(exch, lambda rid, src: make_reply(rid, out="42\n"))
    try:
        assert cli(exch, "-c", "6*7") == 0
    finally:
        g.stop.set()
    assert capsys.readouterr().out == "42\n"
    assert not [p for p in os.listdir(exch) if p.startswith(("rep-", "req-"))]  # host cleaned up


def test_exit1_remote_exception(exch, capsys):
    enable(exch)
    g = game(exch, lambda rid, src: make_reply(rid, "error", "partial\n", "Traceback...\nZeroDivisionError\n"))
    try:
        assert cli(exch, "-c", "1/0") == 1
    finally:
        g.stop.set()
    cap = capsys.readouterr()
    assert cap.out == "partial\n" and "ZeroDivisionError" in cap.err


def test_exit2_usage(exch, capsys):
    enable(exch)
    assert cli(exch) == 2
    assert cli(exch, "-c", "1", "file.py") == 2
    assert cli(exch, "-c", "1", "--budget", "11") == 2
    assert cli(exch, "-c", "1", "--budget", "0") == 2
    assert cli(exch, "-c", "1", "--budget", "5", "--timeout", "5.2") == 2
    assert cli(exch, "-c", "x" * 70000) == 2
    assert cli(exch, str(exch / "missing.py")) == 2
    assert not [p for p in os.listdir(exch) if p.startswith("req-")]


def test_exit3_timeout_withdraws_request_and_says_it_did_not_run(exch, capsys):
    enable(exch)
    heartbeat(exch, age=30)
    assert cli(exch, "-c", "1", "--timeout", "0.7", "--budget", "0.1") == 3
    err = capsys.readouterr().err
    assert "did NOT run" in err and "not polling" in err
    assert not [p for p in os.listdir(exch) if p.startswith("req-")]  # own request unlinked


def test_exit3_when_consumed_but_no_reply_reports_it_ran(exch, capsys, monkeypatch):
    enable(exch)
    heartbeat(exch)
    monkeypatch.setattr(remote, "POLL_SLEEP", 0.01)
    g = game(exch, lambda rid, src: None)  # consumes the request, never answers
    try:
        assert cli(exch, "-c", "1", "--timeout", "0.7", "--budget", "0.1") == 3
    finally:
        g.stop.set()
    assert "WAS picked up" in capsys.readouterr().err


def test_exit3_budget_timeout_and_stale_replies(exch, capsys):
    enable(exch)
    g = game(exch, lambda rid, src: make_reply(rid, "timeout", "x\n", "Timeout\n", "budget 2.0 s exceeded"))
    try:
        assert cli(exch, "-c", "while 1: pass") == 3
        g.responder = lambda rid, src: make_reply(rid, "stale", detail="old")
        assert cli(exch, "-c", "1") == 3
    finally:
        g.stop.set()


def test_exit3_when_directory_missing(tmp_path, capsys):
    assert cli(tmp_path / "nope", "-c", "1") == 3


def test_exit4_switched_off_and_never_creates_enable(exch, capsys):
    assert cli(exch, "-c", "1") == 4
    assert not (exch / "ENABLE").exists() and not [p for p in os.listdir(exch) if p.startswith("req-")]
    assert "ENABLE" in capsys.readouterr().err


def test_exit5_refused_by_game(exch, capsys):
    enable(exch)
    g = game(exch, lambda rid, src: make_reply(rid, "refused", detail="contains 'saveGame'"))
    try:
        assert cli(exch, "-c", "game.saveGame()") == 5
    finally:
        g.stop.set()
    assert "saveGame" in capsys.readouterr().err


def test_exit5_write_without_enable_write(exch):
    enable(exch)
    assert cli(exch, "-c", "1", "--write") == 5


def test_write_and_reset_and_budget_become_directives(exch):
    enable(exch, write=True)
    g = game(exch, lambda rid, src: make_reply(rid))
    try:
        assert cli(exch, "-c", "x = 1", "--write", "--reset", "--budget", "3") == 0
        assert cli(exch, "--reset") == 0
    finally:
        g.stop.set()
    first = g.requests[0].splitlines()
    assert first[0] == f"#@ session {TOKEN}" and first[1].startswith("#@ notafter ")
    assert first[2:5] == ["#@ reset", "#@ write", "#@ budget 3"] and first[5] == "x = 1"
    assert g.requests[1].startswith(f"#@ session {TOKEN}\n#@ notafter ") and g.requests[1].splitlines()[2] == "#@ reset"


def test_file_and_stdin_sources(exch, tmp_path, monkeypatch):
    enable(exch)
    g = game(exch, lambda rid, src: make_reply(rid))
    script = tmp_path / "s.py"
    script.write_text("y = 2\n")
    try:
        assert cli(exch, str(script)) == 0
        import io

        monkeypatch.setattr("sys.stdin", io.StringIO("z = 3\n"))
        assert cli(exch, "-") == 0
    finally:
        g.stop.set()
    assert [r.split("\n", 2)[0] for r in g.requests] == [f"#@ session {TOKEN}"] * 2
    assert [r.split("\n", 2)[2] for r in g.requests] == ["y = 2\n", "z = 3\n"]
    assert all(r.split("\n", 2)[1].startswith("#@ notafter ") for r in g.requests)


@pytest.mark.parametrize(
    "bad",
    [
        b"no separator here",
        b"id: WRONG\nstatus: ok\nstdout_bytes: 0\n---\n",
        b"id: {rid}\nstdout_bytes: 0\n---\n",
        b"id: {rid}\nstatus: ok\nstdout_bytes: abc\n---\n",
        b"id: {rid}\nstatus: ok\nstdout_bytes: 99\n---\nshort",
        b"id: {rid}\nstatus: ok\nstdout_bytes: 0\n---\ngarbage",
        b"id: {rid}\nstatus: weird\nstdout_bytes: 0\n---\n",
    ],
)
def test_exit6_malformed_reply(exch, bad):
    enable(exch)
    g = game(exch, lambda rid, src: bad.replace(b"{rid}", rid.encode()))
    try:
        assert cli(exch, "-c", "1") == 6
    finally:
        g.stop.set()


# --- directory safety --------------------------------------------------------


@posix_only("Windows modes are synthesized, so the 0700 check does not exist there")
def test_directory_mode_must_be_0700(exch):
    enable(exch)
    os.chmod(exch, 0o750)
    assert cli(exch, "-c", "1") == 5
    os.chmod(exch, 0o702)
    assert cli(exch, "-c", "1") == 5


def test_directory_symlink_refused(exch, tmp_path):
    enable(exch)
    link = tmp_path / "link"
    symlink_or_skip(exch, link)
    assert cli(link, "-c", "1") == 5


@posix_only("os.getuid; Windows has no uid and no owner check")
def test_directory_owner_checked(exch, monkeypatch):
    enable(exch)
    monkeypatch.setattr(os, "getuid", lambda: os.stat(exch).st_uid + 1)
    assert cli(exch, "-c", "1") == 5


def test_dir_resolution_flag_env_mod_dir_and_no_default(monkeypatch):
    monkeypatch.delenv(remote.ENV_DIR, raising=False)
    monkeypatch.delenv(remote.ENV_MOD_DIR, raising=False)
    with pytest.raises(remote.ReplError) as err:
        remote.resolve_dir(None)
    assert err.value.code == remote.EXIT_USAGE
    assert remote.ENV_MOD_DIR in str(err.value) and "--dir" in str(err.value)
    monkeypatch.setenv(remote.ENV_MOD_DIR, "/mod")
    assert remote.resolve_dir(None) == "/mod/UserSettings/AgentRepl"
    monkeypatch.setenv(remote.ENV_DIR, "/env")
    assert remote.resolve_dir(None) == "/env"
    assert remote.resolve_dir("/flag") == "/flag"


def test_exec_without_any_directory_is_a_usage_error(monkeypatch, capsys):
    monkeypatch.delenv(remote.ENV_DIR, raising=False)
    monkeypatch.delenv(remote.ENV_MOD_DIR, raising=False)
    assert main(["exec", "-c", "1"]) == 2
    assert "no exchange directory given" in capsys.readouterr().err


# --- --status ----------------------------------------------------------------


def test_status_exit_codes(exch, capsys):
    assert cli(exch, "--status") == 3  # no heartbeat
    heartbeat(exch, enabled=False)
    assert cli(exch, "--status") == 4  # alive but off
    heartbeat(exch, enabled=True)
    enable(exch)
    assert cli(exch, "--status") == 0
    out = capsys.readouterr().out
    assert "polls: 4" in out and "ENABLE: present" in out
    heartbeat(exch, age=60)
    assert cli(exch, "--status") == 3


# --- end to end with the real in-game module ------------------------------------


def test_roundtrip_against_the_real_module(exch, monkeypatch, capsys):
    install_fake_game(monkeypatch)
    mod = load_module(exch)
    enable(exch)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            mod.poll(force=True)
            time.sleep(0.01)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        assert cli(exch, "-c", "print(game.getGameTurn())") == 0
        assert cli(exch, "-c", "1/0") == 1
        assert cli(exch, "-c", "import os") == 5
        assert cli(exch, "-c", "x = 7") == 0
        assert cli(exch, "-c", "x") == 0
    finally:
        stop.set()
        t.join(2)
    cap = capsys.readouterr()
    assert cap.out.splitlines() == ["241", "7"]
    assert "ZeroDivisionError" in cap.err
