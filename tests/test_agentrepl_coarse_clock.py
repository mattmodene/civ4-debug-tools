"""Hypothesis: inside the game (Direct3D 9 sets the x87 FPU to single precision) time.time()
is quantized to float32 resolution (128 s near 1.79e9), while the relative clock stays exact.

These tests pin the CORRECT behaviour, which the code implements (they pass).
  Problems guarded against: (a) host heartbeat_age/diagnose/status trust the game-written wall-clock epoch;
  (b) the game compares request file mtimes (true host time) with its own coarse time.time();
  (c) other wall-clock uses (audit stamps) carry no relative clock to correlate against.
"""

import math
import os
import re
import struct
import time as real_time

import pytest
from agentrepl_support import install_fake_game, load_module, put_request, reply_path

from civ4dbg import remote

STEP = 128.0
BASE = 14015625 * 128.0  # a multiple of 128 near 1.794e9


def f32(t):
    return struct.unpack("<f", struct.pack("<f", t))[0]


def floor128(t):
    return math.floor(t / STEP) * STEP


def ceil128(t):
    return math.ceil(t / STEP) * STEP


class CoarseTime:
    """Stand-in for the game's `time` module: time() is quantized, everything else is real."""

    def __init__(self, quant):
        self._quant = quant

    def time(self):
        return self._quant(real_time.time())

    def __getattr__(self, name):
        return getattr(real_time, name)


@pytest.fixture
def env(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    d = tmp_path / "ex"
    d.mkdir()
    (d / "ENABLE").write_text("")
    return load_module(d), d


def _set_mtime(path, t):
    os.utime(path, (t, t))


def _run_with_true_time(mod, d, monkeypatch, quant, true_now, rid="c1"):
    """Game clock = quant(true_now); the request file's mtime is the true host time true_now."""

    class Fixed:
        def time(self):
            return quant(true_now)

        def __getattr__(self, name):
            return getattr(real_time, name)

    monkeypatch.setattr(mod, "time", Fixed())
    p = put_request(d, rid, "marker = 41 + 1")
    _set_mtime(p, true_now)
    mod.poll(force=True)
    r = reply_path(d, rid)
    return r.read_text() if r.exists() else None


def _status(text):
    for line in text.splitlines():
        if line.startswith("status: "):
            return line[8:]


# --- (b) game-side staleness ------------------------------------------------


@pytest.mark.parametrize("offset", [10, 70, 127])
def test_request_runs_when_game_clock_is_behind(env, monkeypatch, offset):
    """floor to 128 s: game clock is up to 127 s behind true time, so a fresh request looks 'future'."""
    mod, d = env
    r = _run_with_true_time(mod, d, monkeypatch, floor128, BASE + offset + 0.5)
    assert r is not None and _status(r) == "ok", "fresh request discarded with game clock %d s behind: %r" % (
        offset,
        r and r.split("---")[0],
    )


@pytest.mark.parametrize("offset", [1, 30, 60])
def test_request_runs_when_game_clock_is_ahead(env, monkeypatch, offset):
    """ceil to 128 s: game clock is up to 127 s ahead, so a fresh request looks > 60 s old."""
    mod, d = env
    r = _run_with_true_time(mod, d, monkeypatch, ceil128, BASE + offset + 0.5)
    assert r is not None and _status(r) == "ok", "fresh request discarded with game clock %d s ahead: %r" % (
        128 - offset,
        r and r.split("---")[0],
    )


@pytest.mark.parametrize("phase", [63.0, 65.0])
def test_request_runs_under_float32_rounding(env, monkeypatch, phase):
    """Round-to-nearest float32 (the actual FPU mode): error up to +-64 s around 1.79e9."""
    mod, d = env
    true_now = BASE + phase
    assert abs(f32(true_now) - true_now) > 60 - 1e-9  # the simulation really is coarse
    r = _run_with_true_time(mod, d, monkeypatch, f32, true_now)
    assert r is not None and _status(r) == "ok", "fresh request discarded under float32 time (error %.0f s): %r" % (
        f32(true_now) - true_now,
        r and r.split("---")[0],
    )


def test_request_runs_with_live_float32_clock_over_many_phases(env, monkeypatch):
    """Sweep the 128 s phase with the real file mtime; every fresh request must run."""
    mod, d = env
    bad = []
    for i, phase in enumerate(range(0, 128, 8)):
        r = _run_with_true_time(mod, d, monkeypatch, f32, BASE + phase + 0.25, rid="p%d" % i)
        if r is None or _status(r) != "ok":
            bad.append(phase)
    assert not bad, "fresh requests discarded at 128 s phases %r" % bad


def test_genuinely_old_request_still_stale_under_coarse_clock(env, monkeypatch):
    """Guard for the fix: a 10-minute-old request must still be refused as stale."""
    mod, d = env
    monkeypatch.setattr(mod, "time", CoarseTime(f32))
    p = put_request(d, "old1", "marker = 1", notafter=mod._clock() - 600)
    _set_mtime(p, real_time.time())
    mod.poll(force=True)
    assert _status(reply_path(d, "old1").read_text()) == "stale"


# --- (a) host-side heartbeat -------------------------------------------------


def _write_status(d, epoch, mtime):
    p = d / "status.txt"
    p.write_text(
        "session: " + "ab12cd34" * 4 + "\nalive_clock: 71.199\nepoch: %.3f\nturn: 1\nenabled: true\n"
        "write_enabled: false\ndisabled_reason: \nlast_id: -\npolls: 277\nversion: 3\n" % epoch
    )
    _set_mtime(p, mtime)
    return p


@pytest.mark.parametrize("err", [-127.0, -64.0, 64.0, 127.0])
def test_diagnose_reports_fresh_when_epoch_is_quantized(tmp_path, err):
    """Fresh status.txt (mtime now) whose game-written epoch is off by up to 127 s."""
    now = real_time.time()
    _write_status(tmp_path, now + err, now - 1.0)
    code, msg = remote.diagnose(str(tmp_path))
    assert "not polling" not in msg, "fresh heartbeat reported stale: %s" % msg


@pytest.mark.parametrize("err", [-127.0, 127.0])
def test_status_command_ok_when_epoch_is_quantized(tmp_path, capsys, err):
    now = real_time.time()
    _write_status(tmp_path, now + err, now - 1.0)
    code = remote._status_command(str(tmp_path))
    out = capsys.readouterr()
    assert code == remote.EXIT_OK, "exec --status exit %d: %s" % (code, out.err.strip())


def test_heartbeat_age_uses_file_mtime_not_game_epoch(tmp_path):
    """The reported age must be (about) how long ago the file was written: ~1 s, not ~100 s."""
    now = real_time.time()
    p = _write_status(tmp_path, floor128(now) - 100.0, now - 1.0)
    status = remote.read_status(str(tmp_path))
    try:
        age = remote.heartbeat_age(status, path=str(p))  # a fix may take the path ...
    except TypeError:
        age = remote.heartbeat_age(status)  # ... or not; then it cannot know
    assert age is not None and abs(age - 1.0) < 3.0, "heartbeat age %.1f s for a file written 1 s ago" % age


def test_truly_stale_status_still_reported_stale(tmp_path):
    """Guard for the fix: a status.txt untouched for 10 minutes is still 'not polling'."""
    now = real_time.time()
    _write_status(tmp_path, now - 600, now - 600)
    code, msg = remote.diagnose(str(tmp_path))
    assert "not polling" in msg


# --- (c) other wall-clock uses -----------------------------------------------


def test_audit_lines_carry_relative_clock(env):
    """Audit stamps are wall-clock (coarse in-game); each line should also carry the relative clock."""
    mod, d = env
    mod._clock = lambda: 4242.5
    put_request(d, "au1", "1+1")
    mod.poll(force=True)
    lines = (d / "audit.log").read_text().splitlines()
    assert lines
    for ln in lines:
        assert re.search(r"4242\.\d", ln), "audit line has no relative-clock stamp: %r" % ln[:80]


def test_status_epoch_is_not_the_only_wall_clock_in_heartbeat(env):
    """status.txt carries alive_clock (relative) next to epoch; the host needs a basis that survives
    a coarse epoch. Verify the heartbeat does not depend on epoch for liveness: a fresh heartbeat
    written under a 128 s quantized time.time() must be judged fresh by the host."""
    mod, d = env
    mod.time = CoarseTime(lambda t: floor128(t) - 100.0)  # coarse epoch, ~100 s behind
    mod.poll(force=True)
    code, msg = remote.diagnose(str(d))
    assert "not polling" not in msg, "host judged a just-written heartbeat stale: %s" % msg
