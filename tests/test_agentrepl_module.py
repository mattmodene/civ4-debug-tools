"""The in-game module, imported under Python 3 with stubbed game modules."""

import ast
import os
import re
import sys
import time

import pytest
from agentrepl_support import MODULE_PATH, install_fake_game, load_module, put_request, reply_path


@pytest.fixture
def env(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    d = tmp_path / "ex"
    d.mkdir()
    mod = load_module(d)
    return mod, d


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


# --- gate ------------------------------------------------------------------


def test_gate_off_by_default_request_never_runs(env):
    mod, d = env
    put_request(d, "a1", "1+1")
    mod.poll(force=True)
    assert not (d / "req-a1.py").exists()  # purged, not run
    assert "purged" in reply_path(d, "a1").read_text()
    assert "a1 purged" in (d / "audit.log").read_text()
    assert "enabled: false" in (d / "status.txt").read_text()


def test_gate_checked_on_every_poll(env):
    mod, d = env
    enable(d)
    assert status_of(run(env, "a1", "1+1")) == "ok"
    (d / "ENABLE").unlink()
    put_request(d, "a2", "1+1")
    mod.poll(force=True)
    assert status_of(reply_path(d, "a2").read_text()) == "refused"
    enable(d)
    mod.poll(force=True)
    assert "a2 begin" not in (d / "audit.log").read_text()  # it was purged while off; it never runs later
    assert status_of(run(env, "a3", "1+1")) == "ok"


def test_throttle_one_request_per_poll(env):
    mod, d = env
    enable(d)
    put_request(d, "a1", "1")
    put_request(d, "a2", "2")
    mod.poll(force=True)
    assert reply_path(d, "a1").exists() and not reply_path(d, "a2").exists()
    mod.poll()  # inside the 0.25 s window: throttled
    assert not reply_path(d, "a2").exists()
    mod.poll(force=True)
    assert reply_path(d, "a2").exists()


def test_missing_exchange_dir_is_silent(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    mod = load_module(tmp_path / "nope")
    mod.onGameUpdate()
    assert not (tmp_path / "nope").exists()


# --- execution -------------------------------------------------------------


def test_expression_echoes_repr_and_statement_prints(env):
    enable(env[1])
    r = run(env, "e1", "6*7")
    assert status_of(r) == "ok" and "\n---\n42\n" in r
    r = run(env, "e2", "x = 5\nprint(x + 1)")
    assert "\n---\n6\n" in r


def test_namespace_persists_has_game_names_and_reset(env):
    enable(env[1])
    run(env, "n1", "keep = 99")
    assert "\n---\n99\n" in run(env, "n2", "keep")
    r = run(env, "n3", "gc.getGame().getGameTurn()")
    assert "\n---\n241\n" in r and "turn: 241" in r
    assert "\n---\n241\n" in run(env, "n4", "game.getGameTurn()")
    assert "\n---\n-1\n" in run(env, "n5", "NO_PLAYER")
    assert "CyGame" in run(env, "n6", "repr(CyGame)")
    r = run(env, "n7", "#@ reset\ntry:\n    keep\nexcept NameError:\n    print('gone')")
    assert "gone" in r


def test_exception_capture_and_stdout_restored(env):
    enable(env[1])
    before = sys.stdout
    r = run(env, "x1", "print('partial')\n1/0")
    assert status_of(r) == "error"
    assert "partial" in r and "--- traceback ---" in r and "ZeroDivisionError" in r
    assert sys.stdout is before
    assert status_of(run(env, "x2", "x = = 1")) == "error"  # syntax error is an error reply
    assert status_of(run(env, "x2b", "def broken(:")) == "readonly"  # cannot even be tokenized: refused
    assert status_of(run(env, "x3", "1")) == "ok"


def test_systemexit_is_captured_with_write(env):
    enable(env[1], write=True)
    r = run(env, "q1", "#@ write\nraise SystemExit(3)")
    assert status_of(r) == "error" and "SystemExit" in r


def test_output_cap(env):
    mod, d = env
    enable(d)
    r = run(env, "c1", "print('x' * 200000)")
    assert status_of(r) == "ok"
    assert "truncated_bytes: " in r and "bytes dropped]" in r
    assert len(r.encode()) < mod.OUTPUT_CAP + 2000


def test_budget_timeout_interrupts_busy_loop(env):
    enable(env[1])
    t0 = time.monotonic()
    r = run(env, "t1", "#@ budget 0.3\nwhile True:\n    pass")
    assert status_of(r) == "timeout" and "Timeout" in r
    assert time.monotonic() - t0 < 3
    assert status_of(run(env, "t2", "1")) == "ok"  # module healthy afterwards


def test_timeout_not_swallowed_by_except_exception(env):
    enable(env[1])
    r = run(env, "t3", "#@ budget 0.3\nwhile True:\n    try:\n        pass\n    except Exception:\n        pass")
    assert status_of(r) == "timeout"


def test_budget_parsing_and_clamp(env):
    mod, _ = env
    assert mod._parse_directives("#@ budget 999\n")["budget"] == mod.MAX_BUDGET
    assert mod._parse_directives("1\n")["budget"] == mod.DEFAULT_BUDGET
    assert mod._parse_directives("#@ budget nope\n")["budget"] == mod.DEFAULT_BUDGET


# --- refusal ---------------------------------------------------------------

REFUSED = [
    "gc.getGame().saveGame()",
    "game.doControl(1)",
    "game.setWinner(0, 1)",
    "game.setGameTurn(5)",
    "import os",
    "import math, os",
    "from subprocess import call",
    "x = 1; import sys",
    "open('f')",
    "__import__('os')",
    "eval('1')",
    "exec('1')",
    "sys.exit(0)",
    "os.remove('x')",
    "game.setActivePlayer(1, 0)",
    "CyMessageControl()",
    "game.sendModNetMessage(1)",
]
ALLOWED = ["math.sqrt(4)", "clock() >= 0", "pos = 3\npos", "game.getGameTurn()"]  # math, clock: pre-bound


# Read-only mode is now an allowlist of reads (status "readonly") followed by the older refuse list
# (status "refused"): imports, subprocess and CyMessageControl are still the refuse list's.
OLD_LIST_ONLY = ["CyMessageControl()"]  # imports are refused by the allowlist itself since R1


@pytest.mark.parametrize("src", REFUSED)
def test_refuse_list_without_write(env, src):
    enable(env[1])
    r = run(env, "r1", src)
    want = "refused" if src in OLD_LIST_ONLY else "readonly"
    assert status_of(r) == want, src
    assert "detail: " in r


@pytest.mark.parametrize("src", ALLOWED)
def test_refuse_list_lets_readonly_code_through(env, src):
    enable(env[1])
    assert status_of(run(env, "r2", src)) == "ok"


def test_write_needs_both_marker_file_and_request_directive(env):
    mod, d = env
    enable(d)
    # directive without ENABLE_WRITE: still refused, says why
    r = run(env, "w1", "#@ write\nopen")
    assert status_of(r) == "readonly" and "ENABLE_WRITE is absent" in r
    # ENABLE_WRITE without the directive: still refused
    (d / "ENABLE_WRITE").write_text("")
    assert status_of(run(env, "w2", "open")) == "readonly"
    # both: the refuse list is skipped (the missing attribute proves the code ran)
    r = run(env, "w3", "#@ write\ngame.saveGame")
    assert status_of(r) == "error" and "AttributeError" in r


def test_refuse_reason_unit(env):
    mod, _ = env
    assert mod.refuse_reason("import re, collections") is None
    assert "os" in mod.refuse_reason("import re, os")
    assert mod.refuse_reason("from os.path import join")


# --- requests --------------------------------------------------------------


@pytest.mark.parametrize("rid", ["a b", "x.y", "a;b", "é"])
def test_bad_ids_are_discarded_without_reply(env, rid):
    mod, d = env
    enable(d)
    put_request(d, rid, "1")
    mod.poll(force=True)
    assert not (d / f"req-{rid}.py").exists()
    assert not list(d.glob("rep-*"))
    assert "badid" in (d / "audit.log").read_text()


def test_valid_id_charset(env):
    mod, _ = env
    assert mod.valid_id("20261106120000-123-ab12")
    for bad in ("", "a/b", "a..b", "a\n", "a_b", "x" * 81):
        assert not mod.valid_id(bad)


def test_stale_request_is_discarded_not_run(env):
    enable(env[1])
    mod = env[0]
    r = run(env, "s1", "marker = 1", notafter=mod._clock() - 1.0)  # the deadline has passed
    assert status_of(r) == "stale"
    assert "NameError" in run(env, "s2", "marker")


def test_oversize_request(env):
    mod, d = env
    enable(d)
    r = run(env, "o1", "#" + "x" * (mod.REQUEST_CAP + 10))
    assert status_of(r) == "toolarge"


def test_request_removed_before_running_and_crlf_ok(env):
    mod, d = env
    enable(d)
    put_request(d, "k1", "a = 1\r\nprint(a)\r\n")
    mod.poll(force=True)
    assert not (d / "req-k1.py").exists()
    assert "\n---\n1\n" in reply_path(d, "k1").read_text()


def test_oldest_request_first(env):
    mod, d = env
    enable(d)
    put_request(d, "20260101000002-1-aaaa", "2")
    put_request(d, "20260101000001-1-aaaa", "1")
    mod.poll(force=True)
    assert reply_path(d, "20260101000001-1-aaaa").exists()


# --- replies, heartbeat, audit ----------------------------------------------


def test_reply_unique_per_request_and_no_tmp_left(env):
    mod, d = env
    enable(d)
    run(env, "u1", "1")
    run(env, "u2", "2")
    names = sorted(p.name for p in d.iterdir() if p.name.startswith("rep-"))
    assert names == ["rep-u1.txt", "rep-u2.txt"]


def test_rename_never_targets_existing_file(env, monkeypatch):
    mod, d = env
    enable(d)
    (d / "rep-dup.txt").write_text("OLD")
    real = os.rename

    def guarded(src, dst):
        assert not os.path.exists(dst), "rename onto an existing file"
        return real(src, dst)

    monkeypatch.setattr(mod.os, "rename", guarded)
    assert status_of(run(env, "dup", "1")) == "ok"


def test_reply_written_through_tmp_name(env, monkeypatch):
    mod, d = env
    enable(d)
    seen = []
    real = os.rename

    def spy(s, t):
        seen.append((os.path.basename(s), os.path.basename(t)))
        return real(s, t)

    monkeypatch.setattr(mod.os, "rename", spy)
    run(env, "at", "1")
    assert ("rep-at.tmp", "rep-at.txt") in seen


def test_heartbeat_fields_and_refresh(env):
    mod, d = env
    mod.poll(force=True)
    fields = dict(ln.split(": ", 1) for ln in (d / "status.txt").read_text().splitlines())
    for key in (
        "session",
        "alive_clock",
        "epoch",
        "turn",
        "enabled",
        "write_enabled",
        "disabled_reason",
        "last_id",
        "polls",
        "version",
    ):
        assert key in fields
    assert fields["turn"] == "241" and fields["enabled"] == "false"
    assert abs(float(fields["epoch"]) - time.time()) < 5
    enable(d)
    mod.poll(force=True)  # state change rewrites at once
    assert "enabled: true" in (d / "status.txt").read_text()


def test_audit_log_records_requests(env):
    mod = env[0]
    enable(env[1])
    run(env, "l1", "print('hello')")
    run(env, "l2", "open")
    text = (env[1] / "audit.log").read_text()
    assert re.search(r"l1 begin #@ session %s\\n#@ notafter \d+\.\d{3}\\nprint\('hello'\)" % mod.SESSION_TOKEN, text)
    assert "l1 end ok" in text and "l2 end readonly" in text


def test_audit_rotates(env):
    mod, d = env
    (d / "audit.log").write_bytes(b"x" * (mod.AUDIT_ROTATE + 1))
    mod._audit(str(d), "new")
    assert (d / "audit.log.1").exists() and (d / "audit.log").read_text().endswith("new\n")


# --- never raises ---------------------------------------------------------------


def test_never_raises_and_self_disables_after_repeated_failures(env, monkeypatch):
    mod, d = env
    enable(d)

    def boom(dd):
        raise RuntimeError("internal")

    monkeypatch.setattr(mod, "_handle_one", boom)
    for _ in range(mod.MAX_FAILS + 2):
        mod._S["next"] = 0.0
        mod.onGameUpdate()  # must not raise
    assert mod._S["disabled"]
    assert "INTERNAL" in (d / "audit.log").read_text()
    mod._S["next"] = 0.0
    mod.onGameUpdate()
    assert "consecutive internal errors" in (d / "status.txt").read_text()


def test_onGameUpdate_survives_missing_game_modules(tmp_path, monkeypatch):
    monkeypatch.delitem(sys.modules, "CvPythonExtensions", raising=False)
    d = tmp_path / "ex"
    d.mkdir()
    (d / "ENABLE").write_text("")
    mod = load_module(d)
    put_request(d, "m1", "1+1")
    mod.onGameUpdate()
    text = reply_path(d, "m1").read_text()
    assert "\n---\n2\n" in text and "turn: -1" in text


def test_reentrant_poll_is_ignored(env):
    mod, d = env
    enable(d)
    put_request(d, "re1", "1")
    mod._S["busy"] = True
    mod.poll(force=True)
    assert not reply_path(d, "re1").exists()


# --- Python 2.4 / 3 common-subset guard -----------------------------------------

BANNED_NODES = {
    "With",
    "AsyncWith",
    "IfExp",
    "JoinedStr",
    "Set",
    "SetComp",
    "DictComp",
    "Nonlocal",
    "Await",
    "AsyncFunctionDef",
    "YieldFrom",
    "NamedExpr",
    "AnnAssign",
    "Match",
    "TryStar",
    "MatMult",
}
BANNED_NAMES = {"any", "all", "next", "bytearray", "format"}
BANNED_ATTRS = {"format", "partition", "rpartition"}
BANNED_IMPORTS = {"json", "hashlib", "uuid", "functools", "typing", "__future__", "pathlib"}


def test_ingame_file_is_in_the_py24_py3_subset():
    src = MODULE_PATH.read_text()
    tree = ast.parse(src)
    problems = []
    for node in ast.walk(tree):
        kind = type(node).__name__
        line = getattr(node, "lineno", 0)
        if kind in BANNED_NODES:
            problems.append((kind, line))
        if isinstance(node, ast.ExceptHandler) and node.name is not None:
            problems.append(("except-as", line))
        if isinstance(node, ast.Try) and node.handlers and node.finalbody:
            problems.append(("combined try/except/finally", line))
        if isinstance(node, ast.Constant) and isinstance(node.value, bytes):
            problems.append(("bytes literal", line))
        if isinstance(node, ast.Attribute) and node.attr in BANNED_ATTRS:
            problems.append(("." + node.attr, line))
        if isinstance(node, ast.Name) and node.id in BANNED_NAMES and isinstance(node.ctx, ast.Load):
            problems.append((node.id, line))
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] + [getattr(node, "module", None) or ""]
            if any(n.split(".")[0] in BANNED_IMPORTS for n in names):
                problems.append(("import", line))
        if isinstance(node, ast.FunctionDef):
            a = node.args
            if a.kwonlyargs or a.posonlyargs or node.returns or any(x.annotation for x in a.args):
                problems.append(("py3-only signature", line))
            if node.decorator_list:
                problems.append(("decorator", line))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "startswith":
            if node.args and isinstance(node.args[0], ast.Tuple):
                problems.append(("startswith(tuple)", line))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "print":
            problems.append(("print()", line))
        if isinstance(node, ast.Raise) and node.cause is not None:
            problems.append(("raise from", line))
        if isinstance(node, ast.ClassDef) and (node.decorator_list or node.keywords):
            problems.append(("class decorator/metaclass", line))
        if isinstance(node, ast.ImportFrom) and node.level:
            problems.append(("relative import", line))
        if isinstance(node, ast.Starred) and not isinstance(getattr(node, "ctx", None), ast.Load):
            problems.append(("starred target", line))
        if isinstance(node, ast.Call):
            if any(isinstance(a, ast.Starred) for a in node.args) and node.keywords:
                problems.append(("*args with keywords at call site", line))
            fn = node.func
            name = fn.attr if isinstance(fn, ast.Attribute) else getattr(fn, "id", "")
            if name in ("encode", "decode", "open", "sort", "sorted", "split", "rsplit") and node.keywords:
                problems.append(("keyword args to " + name, line))
            if name == "endswith" and node.args and isinstance(node.args[0], ast.Tuple):
                problems.append(("endswith(tuple)", line))
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and node.attr in ("replace", "scandir", "fspath")
        ):
            problems.append(("os." + node.attr, line))
        if isinstance(node, ast.Name) and node.id == "bytes":
            problems.append(("bytes name", line))
    assert problems == []
    assert src.count("perf_counter") == 1  # only the py3 fallback for the missing time.clock
    assert "unicode" in src  # F5: unicode handled on Python 2
    import io
    import tokenize

    for tok in tokenize.generate_tokens(io.StringIO(src).readline):
        if tok.type == tokenize.STRING:
            prefix = re.match(r"[A-Za-z]*", tok.string).group(0)
            assert prefix in ("", "r", "R"), ("string prefix", tok.start)
        if tok.type == tokenize.NUMBER:
            assert "_" not in tok.string, ("numeric underscore", tok.start)
            assert not re.match(r"0[oObB]", tok.string), ("0o/0b literal", tok.start)
            assert not re.search(r"[jJlL]$", tok.string), ("complex/long literal", tok.start)
    text = "\n".join(ln for ln in src.splitlines() if not ln.lstrip().startswith("#"))
    assert not re.search(r"^\s*print\s", text, re.M)
    assert not re.search(r"\bexcept\s+\w[\w.]*\s*,\s*\w+\s*:", text)


def test_ingame_file_is_ascii_only():
    """Python 2.4 reads a source file with no encoding declaration as ASCII: one stray byte is a SyntaxError."""
    data = MODULE_PATH.read_bytes()
    bad = [(i, b) for i, b in enumerate(data) if b > 0x7F]
    assert not bad, "non-ASCII byte(s) in ingame/AgentRepl.py at offsets %s" % [i for i, _ in bad[:5]]
