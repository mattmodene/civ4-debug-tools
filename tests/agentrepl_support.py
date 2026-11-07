"""Shared helpers: load the in-game AgentRepl module under Python 3 with stubbed game modules."""

import importlib.util
import os
import pathlib
import sys
import types

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent

IS_WINDOWS = sys.platform == "win32"


def posix_only(reason):
    """Skip on Windows, naming what POSIX-only facility the test needs (getuid, mkfifo, modes, ...)."""
    return pytest.mark.skipif(IS_WINDOWS, reason="needs POSIX: " + reason)


def symlink_or_skip(target, link):
    """os.symlink. Skips only on Windows (creating one needs developer mode or administrator); any other
    OS re-raises, so a real failure there is a failure and not a silent skip of a security test."""
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as exc:
        if not IS_WINDOWS:
            raise
        pytest.skip(f"cannot create a symlink here ({exc}); Windows needs developer mode or administrator")


MODULE_PATH = ROOT / "ingame" / "AgentRepl.py"


def install_fake_game(monkeypatch, turn=241):
    """Put a fake CvPythonExtensions in sys.modules (what the game provides)."""
    cpe = types.ModuleType("CvPythonExtensions")

    class CyGame:
        def getGameTurn(self):
            return turn

    class CyGlobalContext:
        def getGame(self):
            return CyGame()

    cpe.CyGame = CyGame
    cpe.CyGlobalContext = CyGlobalContext
    cpe.NO_PLAYER = -1
    monkeypatch.setitem(sys.modules, "CvPythonExtensions", cpe)
    return cpe


_TOKENS = {}  # exchange dir -> session token of the module most recently loaded for it
_MODULES = {}  # exchange dir -> the module most recently loaded for it (for its relative clock)
DEFAULT_AHEAD = 300.0  # default deadline: this many seconds ahead of the module's relative clock


def load_module(exchange_dir):
    """A fresh copy of AgentRepl (fresh state, its own session token) pointed at exchange_dir."""
    spec = importlib.util.spec_from_file_location("AgentRepl_under_test", MODULE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.EXCHANGE_DIR = str(exchange_dir)
    _TOKENS[str(exchange_dir)] = mod.SESSION_TOKEN
    _MODULES[str(exchange_dir)] = mod
    return mod


def put_request(d, rid, source, age=0.0, token=None, notafter=None):
    """Queue a request. By default it carries the session token of the module loaded for `d` and a
    deadline DEFAULT_AHEAD seconds ahead of that module's relative clock (what the host does).
    token="WRONG" sends that token, token=False sends the source untouched (no deadline line either).
    notafter=<number or str> sends that deadline, notafter=False omits the line, notafter=-<n> style
    values are plain numbers (use notafter_ahead for "n seconds from the module's clock")."""
    if token is None:
        token = _TOKENS.get(str(d))
    if token is not False and token is not None:
        if notafter is None:
            mod = _MODULES.get(str(d))
            notafter = (mod._clock() if mod is not None else 0.0) + DEFAULT_AHEAD
        if notafter is not False:
            if isinstance(notafter, (int, float)):
                notafter = f"{notafter:.3f}"
            source = f"#@ notafter {notafter}\n" + source
        source = f"#@ session {token}\n" + source
    path = pathlib.Path(d) / f"req-{rid}.py"
    path.write_bytes(source.encode("utf-8"))
    if age:
        t = os.path.getmtime(path) - age
        os.utime(path, (t, t))
    return path


def reply_path(d, rid):
    return pathlib.Path(d) / f"rep-{rid}.txt"


FAKE_TOKEN = "ab12cd34" * 4


def write_status(d, token=FAKE_TOKEN, enabled=True, age=0.0, alive_clock=1.0, version=3):
    """A status.txt like the game's (for tests with no game polling); mtime is `age` seconds ago."""
    import time

    path = pathlib.Path(d) / "status.txt"
    lines = [
        f"session: {token}",
        f"alive_clock: {alive_clock}",
        f"epoch: {time.time() - age:.3f}",
        "turn: 5",
        f"enabled: {str(enabled).lower()}",
        "write_enabled: false",
        "disabled_reason: ",
        "last_id: ",
        "polls: 4",
        f"version: {version}",
    ]
    path.write_text("\n".join(lines) + "\n")
    t = time.time() - age
    os.utime(path, (t, t))
    return path
