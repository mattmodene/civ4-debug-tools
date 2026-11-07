"""The per-request deadline (`#@ notafter`) on the game's relative clock: the host side, and host + real module."""

import os
import re
import threading
import time

import pytest
from agentrepl_support import FAKE_TOKEN, install_fake_game, load_module, write_status
from test_agentrepl_session_token import Scripted

from civ4dbg import remote
from civ4dbg.__main__ import main


@pytest.fixture
def exch(tmp_path):
    d = tmp_path / "AgentRepl"
    d.mkdir()
    os.chmod(d, 0o700)
    (d / "ENABLE").write_text("")
    return d


def cli(d, *argv):
    return main(["exec", "--dir", str(d), *argv])


def notafter_of(request):
    lines = request.split("\n")
    assert lines[0].startswith("#@ session ")
    m = re.fullmatch(r"#@ notafter (\d+\.\d{3})", lines[1])
    assert m, lines[:3]
    return float(m.group(1))


def test_protocol_version_is_three(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    mod = load_module(tmp_path)
    assert mod.VERSION == "3" and remote.MIN_VERSION == 3


def test_build_request_second_line_is_the_deadline():
    lines = remote.build_request("x = 1", 3.0, True, True, FAKE_TOKEN, 1234.5).decode().splitlines()
    assert lines[:6] == [
        f"#@ session {FAKE_TOKEN}",
        "#@ notafter 1234.500",
        "#@ reset",
        "#@ write",
        "#@ budget 3",
        "x = 1",
    ]


def test_clock_estimate_is_alive_clock_plus_the_age_of_status_txt(tmp_path):
    path = write_status(tmp_path, alive_clock=1000.5, age=7.0)
    est = remote.game_clock_estimate(remote.read_status(str(tmp_path)), str(path))
    assert 1007.4 < est < 1008.0
    now = time.time()
    os.utime(path, (now + 60, now + 60))  # future-dated: no estimate
    assert remote.game_clock_estimate(remote.read_status(str(tmp_path)), str(path)) is None
    os.utime(path, (now + 2, now + 2))  # small skew: clamped to zero age
    assert remote.game_clock_estimate(remote.read_status(str(tmp_path)), str(path), now) == 1000.5


def test_deadline_is_estimate_plus_timeout_plus_two(exch):
    write_status(exch, alive_clock=500.0, age=10.0)
    g = Scripted(exch, [("ok", None)])
    g.start()
    try:
        assert cli(exch, "-c", "1", "--timeout", "20") == 0
    finally:
        g.stop.set()
    # 500 + about 10 s since the heartbeat + 20 s timeout + 2 s slack
    assert 531.5 < notafter_of(g.requests[0]) < 534.0


def test_host_retries_a_stale_reply_once_with_a_fresh_estimate(exch, capsys):
    write_status(exch, alive_clock=500.0)
    g = Scripted(exch, [("stale", None), ("ok", None)])
    g.start()
    try:
        assert cli(exch, "-c", "1") == 0
    finally:
        g.stop.set()
    assert len(g.requests) == 2 and capsys.readouterr().out == "ok\n"


def test_host_gives_up_after_a_second_stale_reply(exch, capsys):
    write_status(exch, alive_clock=500.0)
    g = Scripted(exch, [("stale", None), ("stale", None), ("ok", None)])
    g.start()
    try:
        assert cli(exch, "-c", "1") == 3
    finally:
        g.stop.set()
    assert len(g.requests) == 2
    err = capsys.readouterr().err
    assert "stale again" in err and "did not run" in err


def test_host_refuses_to_send_to_a_version_2_module(exch, capsys):
    write_status(exch, version=2)
    assert cli(exch, "-c", "1") == 3
    err = capsys.readouterr().err
    assert "older than this civ4dbg" in err and "reinstall and restart" in err
    assert not list(exch.glob("req-*"))


def test_status_flags_a_version_2_module_as_older(exch, capsys):
    write_status(exch, version=2)
    assert cli(exch, "--status") == 3
    err = capsys.readouterr().err
    assert "older" in err and "reinstall and restart" in err
    write_status(exch, version=3)
    assert cli(exch, "--status") == 0


def test_host_refuses_when_alive_clock_is_missing(exch, capsys):
    path = write_status(exch)
    path.write_text(path.read_text().replace("alive_clock: 1.0\n", ""))
    assert cli(exch, "-c", "1") == 3
    assert "alive_clock" in capsys.readouterr().err and not list(exch.glob("req-*"))


def test_real_module_runs_a_host_request_and_refuses_an_expired_one(tmp_path, monkeypatch):
    """Host + the real poll loop: a normal request runs; a request whose deadline already passed is
    discarded by the game ('stale'), audited, and the host reports it (after its one retry)."""
    install_fake_game(monkeypatch)
    d = tmp_path / "AgentRepl"
    d.mkdir()
    os.chmod(d, 0o700)
    (d / "ENABLE").write_text("")
    mod = load_module(d)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            mod.onGameUpdate()
            time.sleep(0.01)

    t = threading.Thread(target=loop, daemon=True)
    t.start()
    try:
        end = time.monotonic() + 5
        while not (d / "status.txt").exists() and time.monotonic() < end:
            time.sleep(0.02)
        assert cli(d, "-c", "print('fine')") == 0
        monkeypatch.setattr(remote, "DEADLINE_SLACK", -1000.0)  # every deadline is already past
        assert cli(d, "-c", "print('late')", "--timeout", "5") == 3
    finally:
        stop.set()
        t.join(5)
    log = (d / "audit.log").read_text()
    assert log.count(" end stale ") == 2 and "late" in log and log.count(" end ok ") == 1
