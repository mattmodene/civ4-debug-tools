"""Installer round trip on a synthetic mod tree, the pre-PR guard against synthetic git forks, and
a hygiene check that the AgentRepl tests reference neither the real mod tree nor the binaries directory."""

import importlib.util
import pathlib
import re
import shutil
import stat
import subprocess

import pytest
from agentrepl_support import IS_WINDOWS, ROOT

HAVE_GIT = shutil.which("git") is not None


def _load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inst = _load("agentrepl_install")

# A minimal faithful replica of the structure of the real init.xml (tab indentation, an
# ISO-8859-1 declaration, a multi-line comment, nested elements, a single closing </bug>).
INIT = (
    '<?xml version="1.0" encoding="ISO-8859-1"?>\n'
    "\t<!-- Replica -->\n"
    "\t<!--\n\tMain Initialization\n\n\tCopyright (c) 2008.\n\t-->\n"
    "<bug>\n"
    "\t<!-- BUG Core -->\n"
    '\t<load mod="BUG Config"/>\n'
    '\t<init module="ColorUtil">\n'
    "\t\t<!--\n\t\t\tYou can safely modify this list \xe9\n\t\t-->\n"
    '\t\t<arg name="colors" type="tuple">\n\t\t\t"COLOR_RED",\n\t\t\t"COLOR_BLACK"\n\t\t</arg>\n'
    "\t</init>\n"
    '\t<event type="LanguageChanged" module="ColorUtil" function="createColors"/>\n'
    '\t<events module="WoodlandCycle"/>\n'
    "</bug>\n"
)


def make_mod(base, eol="\n"):
    mod = pathlib.Path(base) / "mod"
    (mod / "Assets" / "Config").mkdir(parents=True)
    (mod / "Assets" / "Python" / "BUG").mkdir(parents=True)
    data = INIT.replace("\n", eol).encode("iso-8859-1")
    (mod / "Assets" / "Config" / "init.xml").write_bytes(data)
    return mod, data


def tool(action, mod, backup, *extra):
    return inst.main([action, "--mod-dir", str(mod), "--backup-dir", str(backup), *extra])


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_install_status_uninstall_is_byte_identical(tmp_path, capsys, eol):
    mod, original = make_mod(tmp_path / "mods", eol)
    init = mod / "Assets" / "Config" / "init.xml"
    backup = tmp_path / "backup"
    assert tool("status", mod, backup) == 0
    assert "install allowed: yes" in capsys.readouterr().out
    assert tool("install", mod, backup) == 0
    installed = init.read_bytes()
    assert installed != original
    assert installed.count(b"AgentRepl") == 1
    assert installed.count(eol.encode()) == original.count(eol.encode()) + 1  # exactly one line added
    assert installed.index(b"AgentRepl") < installed.index(b"</bug>")
    if eol == "\r\n":  # no bare LF slipped in
        assert installed.count(b"\n") == installed.count(b"\r\n")
    # only the one added line differs
    diff = [ln for ln in installed.split(eol.encode()) if ln not in original.split(eol.encode())]
    assert len(diff) == 1 and b"AgentRepl" in diff[0]
    assert (mod / "Assets/Python/BUG/AgentRepl.py").is_file()
    ex = mod / "UserSettings" / "AgentRepl"
    assert ex.is_dir()
    if not IS_WINDOWS:  # Windows has no mode 0700; see docs/platform-support.md
        assert stat.S_IMODE(ex.stat().st_mode) == 0o700
    assert not (ex / "ENABLE").exists() and not (ex / "ENABLE_WRITE").exists()  # never created
    capsys.readouterr()
    assert tool("status", mod, backup) == 0
    out = capsys.readouterr().out
    assert "module present: True" in out and "init.xml line:  True" in out
    # idempotent
    assert tool("install", mod, backup) == 0
    assert init.read_bytes() == installed
    # uninstall restores the file exactly (the user's ENABLE switch is also cleared)
    (ex / "ENABLE").write_text("")
    assert tool("uninstall", mod, backup) == 0
    assert init.read_bytes() == original
    assert not (mod / "Assets/Python/BUG/AgentRepl.py").exists()
    assert not (ex / "ENABLE").exists()
    assert tool("uninstall", mod, backup) == 0  # twice is fine
    assert init.read_bytes() == original
    assert (backup / "init.xml.pre-agentrepl").read_bytes() == original


def test_dry_run_changes_nothing(tmp_path):
    mod, original = make_mod(tmp_path / "mods")
    assert tool("install", mod, tmp_path / "b", "--dry-run") == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == original
    assert not (mod / "UserSettings").exists() and not (mod / "Assets/Python/BUG/AgentRepl.py").exists()


def test_odd_init_shapes_are_refused_not_mangled(tmp_path):
    mod, _ = make_mod(tmp_path / "mods")
    init = mod / "Assets/Config/init.xml"
    for bad in (b"<bug>\n</bug>\n</bug>\n", b"<bug>\n"):
        init.write_bytes(bad)
        assert tool("install", mod, tmp_path / "b") == 4
        assert init.read_bytes() == bad


def git(cwd, *args, check=True):
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(cwd), *args],
        capture_output=True,
        text=True,
        check=check,
    )


@pytest.mark.skipif(not HAVE_GIT, reason="git not installed")
@pytest.mark.parametrize("where", ["root", "nested"])
def test_install_refused_inside_a_git_work_tree(tmp_path, capsys, where):
    tree = tmp_path / "repo"
    tree.mkdir()
    git(tree, "init", "-q")
    base = tree if where == "root" else tree / "deeper" / "still"
    base.mkdir(parents=True, exist_ok=True)
    mod, original = make_mod(base)
    assert tool("install", mod, tmp_path / "b") == 3
    assert "git work tree" in capsys.readouterr().err
    assert (mod / "Assets/Config/init.xml").read_bytes() == original
    assert not (mod / "UserSettings").exists() and not (mod / "Assets/Python/BUG/AgentRepl.py").exists()
    assert tool("status", mod, tmp_path / "b") == 0
    assert "install allowed: no" in capsys.readouterr().out


@pytest.mark.skipif(not HAVE_GIT, reason="git not installed")
def test_install_refused_when_dot_git_is_a_file(tmp_path):
    """A worktree/submodule style `.git` file (gitdir: ...) counts too."""
    mod, original = make_mod(tmp_path / "wt")
    (tmp_path / "wt" / ".git").write_text("gitdir: /nonexistent\n")
    assert tool("install", mod, tmp_path / "b") == 3
    assert (mod / "Assets/Config/init.xml").read_bytes() == original


# ---------------------------------------------------------------- hygiene


def test_agentrepl_tests_do_not_reference_work_or_absolute_data_paths():
    forbidden = [
        re.compile(r"(?<![\w.])work" + "/"),
        re.compile("/" + "data" + r"(/|\b)"),
        re.compile(r"[\"']work[\"']"),
    ]
    names = [
        "agentrepl_support.py",
        "test_agentrepl_module.py",
        "test_agentrepl_install.py",
        "test_agentrepl_review_fixes.py",
        "test_agentrepl_e2e.py",
        "test_agentrepl_install_e2e.py",
        "test_remote_cli.py",
    ]
    offenders = []
    for name in names:
        text = (ROOT / "tests" / name).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), 1):
            if line.lstrip().startswith("forbidden") or "re.compile" in line:
                continue  # this check's own patterns
            for rx in forbidden:
                if rx.search(line):
                    offenders.append(f"{name}:{lineno}: {line.strip()}")
    assert offenders == []
