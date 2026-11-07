"""Installer and pre-PR guard, against synthetic mod trees in tmp_path (never the real mod)."""

import hashlib
import importlib.util
import os
import pathlib
import shutil
import stat
import subprocess
import sys

import pytest
from agentrepl_support import IS_WINDOWS, posix_only, symlink_or_skip

ROOT = pathlib.Path(__file__).resolve().parent.parent


def load(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / "tools" / f"{name}.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


inst = load("agentrepl_install")

LINE = '<event type="gameUpdate" module="AgentRepl" function="onGameUpdate"/>'
HAVE_GIT = shutil.which("git") is not None


def init_xml(eol):
    lines = [
        '<?xml version="1.0" encoding="ISO-8859-1"?>',
        "<bug>",
        '\t<load mod="BUG Core"/>',
        '\t<events module="VolcanoCycle"/>',
        "</bug>",
    ]
    return (eol.join(lines) + eol).encode("latin-1")


def make_mod(base, eol="\n", data=None):
    mod = base / "mod"
    (mod / "Assets" / "Config").mkdir(parents=True)
    (mod / "Assets" / "Python" / "BUG").mkdir(parents=True)
    (mod / "Assets" / "Config" / "init.xml").write_bytes(data if data is not None else init_xml(eol))
    return mod


def run_install(mod, tmp_path, *extra):
    return inst.main(["install", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk"), *extra])


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_install_adds_exactly_one_line_with_the_files_line_ending(tmp_path, eol, capsys):
    mod = make_mod(tmp_path, eol)
    original = (mod / "Assets/Config/init.xml").read_bytes()
    assert run_install(mod, tmp_path) == 0
    new = (mod / "Assets/Config/init.xml").read_bytes()
    lines = new.split(eol.encode())
    assert new.count(LINE.encode()) == 1
    assert len(new.splitlines()) == len(original.splitlines()) + 1
    idx = lines.index(b"\t" + LINE.encode())
    assert lines[idx + 1] == b"</bug>"  # directly before </bug>, tab-indented
    assert new.replace(b"\t" + LINE.encode() + eol.encode(), b"") == original  # nothing else changed
    if eol == "\r\n":
        assert new.count(b"\n") == new.count(b"\r\n")  # no bare LF introduced
    assert (mod / "Assets/Python/BUG/AgentRepl.py").read_bytes() == (ROOT / "ingame/AgentRepl.py").read_bytes()
    ex = mod / "UserSettings" / "AgentRepl"
    if not IS_WINDOWS:  # Windows has no mode 0700; see docs/platform-support.md
        assert stat.S_IMODE(ex.stat().st_mode) == 0o700
    assert not (ex / "ENABLE").exists() and not (ex / "ENABLE_WRITE").exists()  # the user only
    bk = tmp_path / "bk"
    assert (bk / "init.xml.pre-agentrepl").read_bytes() == original
    assert (bk / "init.xml.pre-agentrepl.sha256").read_text().strip() == hashlib.sha256(original).hexdigest()


def test_install_is_idempotent(tmp_path):
    mod = make_mod(tmp_path)
    assert run_install(mod, tmp_path) == 0
    once = (mod / "Assets/Config/init.xml").read_bytes()
    assert run_install(mod, tmp_path) == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == once
    assert (tmp_path / "bk" / "init.xml.pre-agentrepl").read_bytes() != once  # backup still the pristine file


@pytest.mark.parametrize("eol", ["\n", "\r\n"])
def test_uninstall_round_trip_is_byte_identical(tmp_path, eol):
    mod = make_mod(tmp_path, eol)
    original = (mod / "Assets/Config/init.xml").read_bytes()
    assert run_install(mod, tmp_path) == 0
    ex = mod / "UserSettings" / "AgentRepl"
    (ex / "ENABLE").write_text("")
    (ex / "ENABLE_WRITE").write_text("")
    (ex / "status.txt").write_text("x")
    (ex / "rep-1.txt").write_text("x")
    (mod / "Assets/Python/BUG/AgentRepl.pyc").write_bytes(b"x")
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == original
    assert not (mod / "Assets/Python/BUG/AgentRepl.py").exists()
    assert not (mod / "Assets/Python/BUG/AgentRepl.pyc").exists()
    assert not (ex / "ENABLE").exists() and not (ex / "ENABLE_WRITE").exists()
    bkargs = ["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]
    assert inst.main(bkargs) == 0  # second run is a no-op


def test_uninstall_keeps_audit_log_unless_purged(tmp_path):
    mod = make_mod(tmp_path)
    run_install(mod, tmp_path)
    ex = mod / "UserSettings" / "AgentRepl"
    (ex / "audit.log").write_text("line\n")
    inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")])
    assert (ex / "audit.log").exists()
    inst.main(["uninstall", "--mod-dir", str(mod), "--purge", "--backup-dir", str(tmp_path / "bk")])
    assert not ex.exists()


def test_dry_run_changes_nothing(tmp_path):
    mod = make_mod(tmp_path)
    before = (mod / "Assets/Config/init.xml").read_bytes()
    assert run_install(mod, tmp_path, "--dry-run") == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == before
    assert not (mod / "UserSettings").exists() and not (tmp_path / "bk").exists()


def snapshot(base):
    return {str(p.relative_to(base)): (p.read_bytes() if p.is_file() else None) for p in sorted(base.rglob("*"))}


def default_dir(mod):
    return inst.default_backup_dir(mod)


def test_state_root_per_os(monkeypatch, tmp_path):
    monkeypatch.delenv("CIV4DBG_STATE_DIR")
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    monkeypatch.setenv("USERPROFILE", str(tmp_path / "home"))
    home = pathlib.Path(os.path.expanduser("~"))
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.delenv("XDG_STATE_HOME", raising=False)
    assert inst.state_root() == home / ".local" / "state" / "civ4dbg" / "agentrepl"
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "xdg"))
    assert inst.state_root() == tmp_path / "xdg" / "civ4dbg" / "agentrepl"
    monkeypatch.setenv("XDG_STATE_HOME", "relative/ignored")
    assert inst.state_root() == home / ".local" / "state" / "civ4dbg" / "agentrepl"
    monkeypatch.setattr(sys, "platform", "darwin")
    assert inst.state_root() == home / "Library" / "Application Support" / "civ4dbg" / "agentrepl"
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "local"))
    assert inst.state_root() == tmp_path / "local" / "civ4dbg" / "agentrepl"
    monkeypatch.delenv("LOCALAPPDATA")
    with pytest.raises(inst.InstallError) as ei:
        inst.state_root()
    assert ei.value.code == 2 and "LOCALAPPDATA" in str(ei.value)


def test_state_dir_env_override_wins(monkeypatch, tmp_path):
    for plat in ("linux", "darwin", "win32"):
        monkeypatch.setattr(sys, "platform", plat)
        monkeypatch.setenv("CIV4DBG_STATE_DIR", str(tmp_path / "over"))
        assert inst.state_root() == tmp_path / "over"


def test_folder_name_is_deterministic_and_sanitised(tmp_path):
    a = tmp_path / "My Mod (v1)"
    a.mkdir()
    b = tmp_path / "other" / "My Mod (v1)"
    b.mkdir(parents=True)
    n1, n2 = inst.install_folder_name(a), inst.install_folder_name(b)
    assert n1 == inst.install_folder_name(a) == inst.install_folder_name(a / ".." / a.name)
    assert n1 != n2  # same leaf name, different path
    prefix, _, digest = n1.rpartition("-")
    assert prefix.lower() == "my_mod__v1_" and len(digest) == 12 and int(digest, 16) >= 0
    assert digest == hashlib.sha256(os.path.normcase(os.path.realpath(a)).encode()).hexdigest()[:12]


def test_default_install_writes_backup_and_manifest_round_trip(tmp_path, capsys):
    import json

    mod = make_mod(tmp_path)
    original = (mod / "Assets/Config/init.xml").read_bytes()
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    bk = default_dir(mod)
    assert str(bk) in capsys.readouterr().out
    assert (bk / "init.xml.pre-agentrepl").read_bytes() == original
    doc = json.loads((bk / "manifest.json").read_text())
    assert doc["schema_version"] == 1 and doc["mod_path"] == str(mod.resolve())
    assert doc["tool_version"] == inst.tool_version() and doc["tool_version"] != ""
    assert doc["created_utc"].endswith("Z")
    assert doc["files_backed_up"][0]["sha256"] == hashlib.sha256(original).hexdigest()
    assert "Assets/Config/init.xml" in doc["files_changed"]
    assert not list(bk.glob("*.tmp"))
    assert inst.read_manifest(bk) == doc


def test_uninstall_auto_locates_the_backup(tmp_path, capsys):
    mod = make_mod(tmp_path)
    original = (mod / "Assets/Config/init.xml").read_bytes()
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    capsys.readouterr()
    assert inst.main(["uninstall", "--mod-dir", str(mod)]) == 0
    assert str(default_dir(mod)) in capsys.readouterr().out
    assert (mod / "Assets/Config/init.xml").read_bytes() == original
    assert (default_dir(mod) / "manifest.json").is_file()  # uninstall leaves the backup alone


def test_uninstall_refuses_without_backup_folder_and_touches_nothing(tmp_path, capsys):
    mod = make_mod(tmp_path)
    assert run_install(mod, tmp_path) == 0  # explicit dir: the default folder does not exist
    before = snapshot(tmp_path)
    capsys.readouterr()
    assert inst.main(["uninstall", "--mod-dir", str(mod)]) == 2
    err = capsys.readouterr().err
    assert str(default_dir(mod)) in err and "--backup-dir" in err
    assert snapshot(tmp_path) == before


def test_uninstall_refuses_default_folder_without_manifest(tmp_path, capsys):
    mod = make_mod(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    (default_dir(mod) / "manifest.json").unlink()
    before = snapshot(tmp_path)
    assert inst.main(["uninstall", "--mod-dir", str(mod)]) == 2
    assert "--backup-dir" in capsys.readouterr().err
    assert snapshot(tmp_path) == before


def test_uninstall_refuses_mismatched_manifest_auto_and_explicit(tmp_path, capsys):
    import json

    mod = make_mod(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    bk = default_dir(mod)
    doc = json.loads((bk / "manifest.json").read_text())
    doc["mod_path"] = str(tmp_path / "some" / "other" / "mod")
    (bk / "manifest.json").write_text(json.dumps(doc))
    before = snapshot(tmp_path)
    capsys.readouterr()
    assert inst.main(["uninstall", "--mod-dir", str(mod)]) == 2
    assert "different mod" in capsys.readouterr().err
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(bk)]) == 2  # explicit still refuses
    assert "different mod" in capsys.readouterr().err
    assert snapshot(tmp_path) == before


def test_uninstall_explicit_backup_dir_without_manifest_warns_and_proceeds(tmp_path, capsys):
    mod = make_mod(tmp_path)
    original = (mod / "Assets/Config/init.xml").read_bytes()
    assert run_install(mod, tmp_path) == 0
    (tmp_path / "bk" / "manifest.json").unlink()  # a backup made before manifests existed
    capsys.readouterr()
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 0
    out = capsys.readouterr().out
    assert out.count("warning:") == 1 and "could not verify" in out
    assert (mod / "Assets/Config/init.xml").read_bytes() == original
    assert not (tmp_path / "bk" / "manifest.json").exists()  # uninstall never writes into the backup


def test_explicit_backup_dir_gets_a_manifest_and_uninstall_verifies_it(tmp_path, capsys):
    mod = make_mod(tmp_path)
    assert run_install(mod, tmp_path) == 0
    assert inst.read_manifest(tmp_path / "bk")["mod_path"] == str(mod.resolve())
    assert not default_dir(mod).exists()
    capsys.readouterr()
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 0
    assert "warning" not in capsys.readouterr().out


def test_install_does_not_clobber_the_original_backup(tmp_path, capsys):
    mod = make_mod(tmp_path)
    original = (mod / "Assets/Config/init.xml").read_bytes()
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    bk = default_dir(mod)
    assert inst.main(["uninstall", "--mod-dir", str(mod)]) == 0
    manifest = (bk / "manifest.json").read_bytes()
    (mod / "Assets/Config/init.xml").write_bytes(original.replace(b"VolcanoCycle", b"Edited"))  # drifted
    capsys.readouterr()
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    out = capsys.readouterr().out
    assert "NOT overwritten" in out and "differs" in out
    assert (bk / "init.xml.pre-agentrepl").read_bytes() == original
    assert (bk / "manifest.json").read_bytes() == manifest


def test_backup_inside_git_work_tree_is_refused(tmp_path, capsys, monkeypatch):
    mod = make_mod(tmp_path)
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    before = snapshot(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod), "--backup-dir", str(repo / "deep" / "bk")]) == 3
    assert "git work tree" in capsys.readouterr().err
    assert snapshot(tmp_path) == before
    monkeypatch.setenv("CIV4DBG_STATE_DIR", str(repo / "state"))  # the default location too
    assert inst.main(["install", "--mod-dir", str(mod)]) == 3
    assert snapshot(tmp_path) == before


def test_backup_inside_mod_dir_is_refused(tmp_path, capsys):
    mod = make_mod(tmp_path)
    before = snapshot(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod), "--backup-dir", str(mod / "UserSettings" / "bk")]) == 3
    assert "inside the mod directory" in capsys.readouterr().err
    assert snapshot(tmp_path) == before


def test_backup_inside_forbidden_dir_is_refused(tmp_path, capsys):
    mod = make_mod(tmp_path)
    forbidden = tmp_path / "nope"
    forbidden.mkdir()
    before = snapshot(tmp_path)
    args = ["install", "--mod-dir", str(mod), "--backup-dir", str(forbidden / "bk"), "--forbid", str(forbidden)]
    assert inst.main(args) == 3 and "--forbid" in capsys.readouterr().err
    assert snapshot(tmp_path) == before


def test_dry_run_default_location_prints_it_and_touches_nothing(tmp_path, capsys):
    mod = make_mod(tmp_path)
    before = snapshot(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod), "--dry-run"]) == 0
    assert str(default_dir(mod)) in capsys.readouterr().out
    assert snapshot(tmp_path) == before
    assert not default_dir(mod).exists()


@posix_only("POSIX modes")
def test_backup_folders_are_0700(tmp_path, monkeypatch):
    root = tmp_path / "fresh" / "state"
    monkeypatch.setenv("CIV4DBG_STATE_DIR", str(root))
    mod = make_mod(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod)]) == 0
    for d in (root, default_dir(mod)):
        assert stat.S_IMODE(d.stat().st_mode) == 0o700


def test_windows_backup_protection_text_says_no_mode(monkeypatch):
    monkeypatch.setattr(inst, "_is_windows", lambda: True)
    assert "no mode is enforced on Windows" in inst.backup_protection_text()


def test_unexpected_init_shape_is_not_edited(tmp_path):
    bad = b"<bug>\n</bug>\n</bug>\n"
    mod = make_mod(tmp_path, data=bad)
    assert run_install(mod, tmp_path) == 4
    assert (mod / "Assets/Config/init.xml").read_bytes() == bad
    assert not (mod / "Assets/Python/BUG/AgentRepl.py").exists()


def test_not_a_mod_tree(tmp_path):
    (tmp_path / "x").mkdir()
    assert run_install(tmp_path / "x", tmp_path) == 2


def test_missing_trailing_newline_and_indented_close(tmp_path):
    mod = make_mod(tmp_path, data=b"<bug>\r\n  <a/>\r\n  </bug>")
    assert run_install(mod, tmp_path) == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == b"<bug>\r\n  <a/>\r\n  \t" + LINE.encode() + b"\r\n  </bug>"


def test_status_runs(tmp_path, capsys):
    mod = make_mod(tmp_path)
    assert inst.main(["status", "--mod-dir", str(mod)]) == 0
    assert "init.xml line:  False" in capsys.readouterr().out


# --- refusal inside a git work tree / upstream locations ----------------------------


@pytest.mark.skipif(not HAVE_GIT, reason="git not installed")
def test_refuses_mod_dir_inside_a_git_work_tree(tmp_path, capsys):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q", str(repo)], check=True, capture_output=True)
    mod = make_mod(repo)
    before = (mod / "Assets/Config/init.xml").read_bytes()
    assert run_install(mod, tmp_path) == 3
    assert "git work tree" in capsys.readouterr().err
    assert (mod / "Assets/Config/init.xml").read_bytes() == before
    assert not (mod / "Assets/Python/BUG/AgentRepl.py").exists() and not (mod / "UserSettings").exists()
    # git itself says so too, independent of the .git walk
    r = subprocess.run(["git", "-C", str(mod), "rev-parse", "--is-inside-work-tree"], capture_output=True, text=True)
    assert r.stdout.strip() == "true"


def test_refuses_dot_git_marker_without_git(tmp_path, monkeypatch):
    mod = make_mod(tmp_path)
    (tmp_path / ".git").mkdir()
    monkeypatch.setattr(inst.subprocess, "run", lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("git")))
    assert run_install(mod, tmp_path) == 3
    # a worktree/submodule-style .git FILE counts as well
    (tmp_path / ".git").rmdir()
    (tmp_path / ".git").write_text("gitdir: elsewhere\n")
    assert run_install(mod, tmp_path) == 3


def test_refuses_forbidden_locations_named_on_the_command_line(tmp_path, capsys):
    fork = tmp_path / "civ4" / "forbidden-a"
    up = tmp_path / "civ4" / "mods" / "forbidden-b"
    for place in (fork, up):
        (place / "Assets" / "Config").mkdir(parents=True)
        (place / "Assets" / "Python" / "BUG").mkdir(parents=True)
        (place / "Assets" / "Config" / "init.xml").write_bytes(init_xml("\n"))
        forbid = ["--forbid", str(fork), "--forbid", str(up)]
        assert run_install(place, tmp_path, *forbid) == 3
        assert run_install(place / "Assets", tmp_path, *forbid) == 3
        assert "--forbid marks as off limits" in capsys.readouterr().err
        assert LINE.encode() not in (place / "Assets" / "Config" / "init.xml").read_bytes()


def test_there_is_no_built_in_forbidden_location(tmp_path):
    assert not hasattr(inst, "FORBIDDEN")
    assert inst.git_refusal(make_mod(tmp_path)) is None


def test_uninstall_is_allowed_inside_git(tmp_path):
    mod = make_mod(tmp_path)
    run_install(mod, tmp_path)
    (tmp_path / ".git").mkdir()
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 0
    assert LINE.encode() not in (mod / "Assets/Config/init.xml").read_bytes()


def test_cli_runs_under_isolated_python(tmp_path):
    mod = make_mod(tmp_path)
    r = subprocess.run(
        [sys.executable, "-I", str(ROOT / "tools" / "agentrepl_install.py"), "status", "--mod-dir", str(mod)],
        capture_output=True,
        text=True,
    )
    assert r.returncode == 0, r.stderr


# --- review fixes (F9, F10) ---------------------------------------------------------


def test_f9_module_is_copied_before_init_is_edited(tmp_path, monkeypatch):
    mod = make_mod(tmp_path)
    before = (mod / "Assets/Config/init.xml").read_bytes()

    def boom(*a, **k):
        raise OSError("disk full")

    monkeypatch.setattr(inst, "_atomic_write", boom)
    assert run_install(mod, tmp_path) == 2
    assert (mod / "Assets/Python/BUG/AgentRepl.py").exists()  # module first
    assert (mod / "Assets/Config/init.xml").read_bytes() == before  # never "line without module"


def test_f9_failed_module_copy_leaves_init_untouched_and_no_tmp(tmp_path, monkeypatch):
    mod = make_mod(tmp_path)
    before = (mod / "Assets/Config/init.xml").read_bytes()
    monkeypatch.setattr(inst.shutil, "copyfile", lambda s, d: (_ for _ in ()).throw(OSError("nope")))
    assert run_install(mod, tmp_path) == 2
    assert (mod / "Assets/Config/init.xml").read_bytes() == before
    assert not list(mod.rglob("*.agentrepl.tmp"))


def test_f9_failed_init_replace_leaves_no_tmp_file(tmp_path, monkeypatch):
    mod = make_mod(tmp_path)
    real = os.replace

    def flaky(src, dst):
        if str(dst).endswith("init.xml"):
            raise OSError("replace failed")
        return real(src, dst)

    monkeypatch.setattr(inst.os, "replace", flaky)
    assert run_install(mod, tmp_path) == 2
    assert not list(mod.rglob("*.agentrepl.tmp"))


def test_f9_symlinked_exchange_dir_is_refused(tmp_path):
    mod = make_mod(tmp_path)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (mod / "UserSettings").mkdir()
    symlink_or_skip(elsewhere, mod / "UserSettings" / "AgentRepl")
    assert run_install(mod, tmp_path) == 3
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 3
    assert not (mod / "Assets/Python/BUG/AgentRepl.py").exists()


@posix_only("mode bits; Windows ignores them and the installer says so")
def test_f9_exchange_dir_is_0700_from_creation(tmp_path):
    mod = make_mod(tmp_path)
    old = os.umask(0)
    try:
        assert run_install(mod, tmp_path) == 0
    finally:
        os.umask(old)
    assert stat.S_IMODE((mod / "UserSettings" / "AgentRepl").stat().st_mode) == 0o700


def test_f9_hand_edited_variant_line_is_not_duplicated_and_is_removed(tmp_path):
    variant = b'\t<event  module="AgentRepl"  type="gameUpdate" function="onGameUpdate" />\n'
    data = b"<bug>\n" + variant + b"</bug>\n"
    mod = make_mod(tmp_path, data=data)
    assert run_install(mod, tmp_path) == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == data
    assert inst.main(["uninstall", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 0
    assert (mod / "Assets/Config/init.xml").read_bytes() == b"<bug>\n</bug>\n"


def test_shared_explicit_backup_dir_without_manifest_is_refused_not_claimed(tmp_path, capsys):
    a = make_mod(tmp_path / "a")
    b = make_mod(tmp_path / "b", data=init_xml("\n").replace(b"VolcanoCycle", b"Other"))
    shared = tmp_path / "shared"
    assert inst.main(["install", "--mod-dir", str(a), "--backup-dir", str(shared)]) == 0
    (shared / "manifest.json").unlink()  # a backup made before manifests existed
    before = snapshot(tmp_path)
    capsys.readouterr()
    assert inst.main(["install", "--mod-dir", str(b), "--backup-dir", str(shared)]) == 3
    assert "cannot be shown to belong" in capsys.readouterr().err
    assert snapshot(tmp_path) == before  # no manifest written, nothing else touched
    assert not (shared / "manifest.json").exists()


def test_explicit_backup_dir_without_manifest_matching_this_mod_is_adopted(tmp_path):
    mod = make_mod(tmp_path)
    shared = tmp_path / "bk"
    shared.mkdir()
    (shared / inst.BACKUP_NAME).write_bytes((mod / "Assets/Config/init.xml").read_bytes())
    assert run_install(mod, tmp_path) == 0
    assert inst.read_manifest(shared)["mod_path"] == str(mod.resolve())


def test_relative_state_dir_is_rejected(monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("CIV4DBG_STATE_DIR", "relative/state")
    with pytest.raises(inst.InstallError) as ei:
        inst.state_root()
    assert ei.value.code == 2 and "absolute" in str(ei.value)
    mod = make_mod(tmp_path)
    before = snapshot(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod)]) == 2
    assert "CIV4DBG_STATE_DIR" in capsys.readouterr().err
    assert snapshot(tmp_path) == before


def test_failed_backup_write_leaves_no_partial_backup(tmp_path, monkeypatch):
    mod = make_mod(tmp_path)
    original = (mod / "Assets/Config/init.xml").read_bytes()

    def boom(fd):
        raise OSError("disk full")

    monkeypatch.setattr(inst.os, "fsync", boom)
    assert run_install(mod, tmp_path) == 2
    bk = tmp_path / "bk"
    assert sorted(p.name for p in bk.iterdir()) == []  # no backup, no .tmp, no manifest
    assert (mod / "Assets/Config/init.xml").read_bytes() == original


def test_platform_checks_go_through_the_helper():
    src = (ROOT / "tools" / "agentrepl_install.py").read_text(encoding="utf-8")
    assert src.count("sys.platform") == 2  # only inside _is_windows and _is_darwin
