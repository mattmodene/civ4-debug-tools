"""Windows and macOS code paths, exercised on any OS with mocks.

These tests run everywhere. They do not prove Windows or macOS behaviour: they pin what the code does
when it believes it is on one (`remote._HARDENED` False for Windows, `_is_darwin` True for macOS).
"""

import importlib.util
import os
import pathlib
import stat
import sys
import types

import pytest
from agentrepl_support import ROOT, install_fake_game, load_module, symlink_or_skip
from test_remote_cli import TOKEN, FakeGame, enable, heartbeat, make_reply

from civ4dbg import remote
from civ4dbg.__main__ import main


class FakeStat:
    """A real stat result plus st_file_attributes (which only Windows provides)."""

    def __init__(self, real, attrs):
        self._real = real
        self.st_file_attributes = attrs

    def __getattr__(self, name):
        return getattr(self._real, name)


@pytest.fixture
def windows_model(monkeypatch):
    """Make remote.py take the code path it takes where uid / O_NOFOLLOW / dir_fd are missing."""
    monkeypatch.setattr(remote, "_HARDENED", False)
    monkeypatch.setattr(remote, "_warned", False)


@pytest.fixture
def exch(tmp_path):
    d = tmp_path / "AgentRepl"
    d.mkdir()
    return d


# --- the ancestor walk -------------------------------------------------------


def test_prefixes_keep_the_drive_letter_attached():
    assert remote._prefixes("C:\\a\\b", windows=True) == ["C:\\a", "C:\\a\\b"]
    assert remote._prefixes("D:\\", windows=True) == []
    assert remote._prefixes("\\\\srv\\share", windows=True) == []


def test_prefixes_handle_a_unc_share():
    assert remote._prefixes("\\\\srv\\share\\x\\y", windows=True) == ["\\\\srv\\share\\x", "\\\\srv\\share\\x\\y"]


def test_prefixes_posix_start_at_the_root():
    assert remote._prefixes("/a/b", windows=False) == ["/", "/a", "/a/b"]


# --- the Windows model --------------------------------------------------------


def test_windows_model_accepts_an_open_mode_and_warns_once(windows_model, exch, capsys):
    os.chmod(exch, 0o777)  # POSIX would refuse this; Windows modes are synthesized and not checked
    remote.check_dir(str(exch))
    remote.check_dir(str(exch))
    err = capsys.readouterr().err
    assert err.count("warning:") == 1
    for named in ("ownership", "0700", "O_NOFOLLOW"):
        assert named in err


def test_posix_model_never_prints_the_reduced_protection_warning(exch, capsys, monkeypatch):
    monkeypatch.setattr(remote, "_HARDENED", True)
    monkeypatch.setattr(remote, "_warned", False)
    os.chmod(exch, 0o700)
    remote.check_dir(str(exch))
    assert "warning:" not in capsys.readouterr().err


def test_windows_model_refuses_a_reparse_point_in_the_path(windows_model, exch, monkeypatch):
    real = os.lstat
    flag = stat.FILE_ATTRIBUTE_REPARSE_POINT

    def lstat(path, *a, **kw):
        st = real(path, *a, **kw)
        return FakeStat(st, flag if os.path.basename(str(path)) == exch.parent.name else 0)

    monkeypatch.setattr(os, "lstat", lstat)
    with pytest.raises(remote.ReplError) as err:
        remote.check_dir(str(exch))
    assert err.value.code == remote.EXIT_REFUSED and "reparse point" in str(err.value)


def test_windows_model_refuses_a_symlinked_directory(windows_model, exch, tmp_path):
    link = tmp_path / "link"
    symlink_or_skip(exch, link)
    with pytest.raises(remote.ReplError) as err:
        remote.check_dir(str(link))
    assert err.value.code == remote.EXIT_REFUSED


def test_windows_model_round_trip_without_descriptors(windows_model, exch, capsys):
    enable(exch)
    game = FakeGame(str(exch), lambda rid, src: make_reply(rid, out="hi\n"))
    game.start()
    try:
        assert main(["exec", "--dir", str(exch), "-c", "print('hi')"]) == 0
    finally:
        game.stop.set()
    assert capsys.readouterr().out == "hi\n"
    assert not [n for n in os.listdir(exch) if n.startswith(("req-", "rep-"))]
    assert isinstance(remote.open_dir(str(exch)), remote._PathDir)


def test_windows_model_status_read_goes_through_the_checked_open(windows_model, exch):
    heartbeat(exch)
    assert remote.read_status(str(exch))["session"] == TOKEN
    st = remote.read_status(str(exch), dir_fd=remote._PathDir(str(exch)))
    assert st is not None and st["session"] == TOKEN


def test_windows_model_refuses_a_symlinked_reply(windows_model, exch, tmp_path, monkeypatch):
    enable(exch)
    monkeypatch.setattr(remote, "new_id", lambda: "fixedid")
    target = tmp_path / "target.txt"
    target.write_text("id: fixedid\nstatus: ok\nstdout_bytes: 0\n---\n")
    symlink_or_skip(target, exch / "rep-fixedid.txt")
    assert main(["exec", "--dir", str(exch), "-c", "1", "--timeout", "1", "--budget", "0.1"]) == 6


def test_checked_open_refuses_a_reparse_point_and_a_swapped_file(tmp_path, monkeypatch):
    f = tmp_path / "f.txt"
    f.write_text("x")
    real_lstat = os.lstat
    monkeypatch.setattr(
        os, "lstat", lambda p, *a, **k: FakeStat(real_lstat(p, *a, **k), stat.FILE_ATTRIBUTE_REPARSE_POINT)
    )
    with pytest.raises(OSError, match="reparse"):
        remote._open_checked(str(f), os.O_RDONLY)
    monkeypatch.setattr(os, "lstat", real_lstat)
    fd = remote._open_checked(str(f), os.O_RDONLY)
    os.close(fd)

    class Other:
        st_ino, st_dev = -1, -1

    monkeypatch.setattr(os, "fstat", lambda fd: Other())
    with pytest.raises(OSError, match="changed between"):
        remote._open_checked(str(f), os.O_RDONLY)


def test_anchor_only_path_is_refused_not_passed_unchecked(monkeypatch):
    monkeypatch.setattr(remote, "_prefixes", lambda absolute, windows: [])
    with pytest.raises(remote.ReplError) as err:
        remote.check_dir("D:\\")
    assert err.value.code == remote.EXIT_REFUSED and "share root" in str(err.value)


def test_exchange_directory_swap_after_the_check_is_caught(windows_model, exch, tmp_path):
    heartbeat(exch)
    ref = remote.open_dir(str(exch))
    assert isinstance(ref, remote._PathDir) and ref.ident is not None
    assert remote.read_status(str(exch), dir_fd=ref)["session"] == TOKEN
    other = tmp_path / "other"
    other.mkdir()
    (other / "status.txt").write_bytes((exch / "status.txt").read_bytes())
    moved = tmp_path / "moved"
    exch.rename(moved)
    other.rename(exch)  # a different directory now sits at the checked path
    assert remote.read_status(str(exch), dir_fd=ref) is None  # the open is refused, so it reads as missing
    with pytest.raises(OSError, match="changed since"):
        remote._open_in(ref, str(exch), "status.txt", os.O_RDONLY)
    with pytest.raises(OSError, match="changed since"):
        remote._unlink_in(ref, "status.txt")
    with pytest.raises(OSError, match="changed since"):
        remote._replace_in(ref, "a", "b")


def test_exchange_directory_swapped_for_a_reparse_point_is_caught(windows_model, exch, monkeypatch):
    ref = remote.open_dir(str(exch))
    real_lstat = os.lstat
    monkeypatch.setattr(
        os, "lstat", lambda p, *a, **k: FakeStat(real_lstat(p, *a, **k), stat.FILE_ATTRIBUTE_REPARSE_POINT)
    )
    with pytest.raises(OSError, match="reparse"):
        ref.recheck()


def test_missing_file_identity_skips_the_directory_recheck(windows_model, exch, monkeypatch):
    real_lstat = os.lstat

    class NoIdentity(FakeStat):
        st_dev = 0
        st_ino = 0

    monkeypatch.setattr(os, "lstat", lambda p, *a, **k: NoIdentity(real_lstat(p, *a, **k), 0))
    ref = remote.open_dir(str(exch))
    assert ref.ident is None
    ref.recheck()  # nothing to compare: passes, which is the documented gap


def test_exclusive_create_refuses_a_planted_link(exch, tmp_path):
    target = tmp_path / "victim.txt"
    target.write_text("keep")
    symlink_or_skip(target, exch / "req-x.tmp")
    with pytest.raises(OSError):
        remote._open_checked(str(exch / "req-x.tmp"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    assert target.read_text() == "keep"
    fresh = remote._open_checked(str(exch / "req-y.tmp"), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    os.close(fresh)


# --- macOS: /var -> /private/var ------------------------------------------------


def _alias_tree(tmp_path, target="private/var"):
    root = tmp_path / "fsroot"
    (root / "private" / "var" / "folders").mkdir(parents=True)
    (root / "elsewhere").mkdir()
    symlink_or_skip(root / target, root / "var")
    return root


def test_system_alias_is_resolved_when_root_owned(tmp_path, monkeypatch):
    root = _alias_tree(tmp_path)
    monkeypatch.setattr(remote, "_ROOT_UID", os.getuid())  # stand-in for "owned by root"
    got = remote._resolve_system_alias("/var/folders/x", root=str(root))
    assert got == os.path.join(str(root), "private", "var", "folders", "x")
    assert remote._resolve_system_alias("/var", root=str(root)) == os.path.join(str(root), "private", "var")


def test_system_alias_not_owned_by_root_is_left_to_be_refused(tmp_path, monkeypatch):
    root = _alias_tree(tmp_path)
    monkeypatch.setattr(remote, "_ROOT_UID", os.getuid() + 12345)
    assert remote._resolve_system_alias("/var/folders/x", root=str(root)) == "/var/folders/x"


def test_system_alias_pointing_anywhere_else_is_left_to_be_refused(tmp_path, monkeypatch):
    root = _alias_tree(tmp_path, target="elsewhere")
    monkeypatch.setattr(remote, "_ROOT_UID", os.getuid())
    assert remote._resolve_system_alias("/var/folders/x", root=str(root)) == "/var/folders/x"


def test_system_alias_pointing_through_another_link_is_left_to_be_refused(tmp_path, monkeypatch):
    root = _alias_tree(tmp_path, target="hop")
    symlink_or_skip(root / "private" / "var", root / "hop")  # var -> hop -> private/var: same place, not literal
    monkeypatch.setattr(remote, "_ROOT_UID", os.getuid())
    assert remote._resolve_system_alias("/var/folders/x", root=str(root)) == "/var/folders/x"


def test_other_leading_components_are_never_rewritten(tmp_path, monkeypatch):
    root = _alias_tree(tmp_path)
    monkeypatch.setattr(remote, "_ROOT_UID", os.getuid())
    assert remote._resolve_system_alias("/home/x", root=str(root)) == "/home/x"


def test_alias_rewrite_only_happens_on_darwin(monkeypatch):
    monkeypatch.setattr(remote, "_HARDENED", True)
    monkeypatch.setattr(remote, "_resolve_system_alias", lambda p: "REWRITTEN")
    monkeypatch.setattr(remote, "_is_darwin", lambda: False)
    assert remote._normalize("/var/x") == "/var/x"
    monkeypatch.setattr(remote, "_is_darwin", lambda: True)
    assert remote._normalize("/var/x") == "REWRITTEN"


# --- installer: what is claimed per OS --------------------------------------------


def _installer():
    spec = importlib.util.spec_from_file_location("agentrepl_install_pt", ROOT / "tools" / "agentrepl_install.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _mod_tree(tmp_path):
    mod = tmp_path / "mod"
    (mod / "Assets" / "Config").mkdir(parents=True)
    (mod / "Assets" / "Python" / "BUG").mkdir(parents=True)
    (mod / "Assets" / "Config" / "init.xml").write_bytes(b"<bug>\n</bug>\n")
    return mod


@pytest.mark.parametrize("windows", [False, True])
def test_installer_states_the_protection_of_the_os(tmp_path, capsys, monkeypatch, windows):
    inst = _installer()
    monkeypatch.setattr(inst, "_is_windows", lambda: windows)
    mod = _mod_tree(tmp_path)
    assert inst.main(["install", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 0
    out = capsys.readouterr().out
    assert ("no mode applies on Windows" in out) is windows
    assert ("mode 0700" in out) is (not windows)
    assert inst.main(["status", "--mod-dir", str(mod)]) == 0
    out = capsys.readouterr().out
    assert ("(mode 0" in out) is (not windows)
    assert ("protection:" in out) is windows


def test_installer_error_names_bug_and_what_is_missing(tmp_path, capsys):
    inst = _installer()
    mod = tmp_path / "mod"
    (mod / "Assets" / "Python").mkdir(parents=True)
    assert inst.main(["install", "--mod-dir", str(mod), "--backup-dir", str(tmp_path / "bk")]) == 2
    err = capsys.readouterr().err
    assert "BUG" in err and "init.xml" in err and "Assets/Python/BUG/" in err
    assert "Missing:" in err and "not a Civ4 mod tree" not in err
    assert str(mod / "Assets" / "Config" / "init.xml") in err and str(mod / "Assets" / "Python" / "BUG") in err


# --- in-game module without BUG's SystemPaths ------------------------------------


def _located_module(tmp_path, monkeypatch, with_dir=True):
    install_fake_game(monkeypatch)
    mod_dir = tmp_path / "somemod"
    bug = mod_dir / "Assets" / "Python" / "BUG"
    bug.mkdir(parents=True)
    ex = mod_dir / "UserSettings" / "AgentRepl"
    if with_dir:
        ex.mkdir(parents=True)
    mod = load_module(tmp_path / "unused")
    mod.EXCHANGE_DIR = None
    mod.__file__ = str(bug / "AgentRepl.py")
    monkeypatch.setitem(sys.modules, "SystemPaths", None)  # makes `import SystemPaths` raise ImportError
    return mod, mod_dir, ex


def test_exchange_dir_falls_back_to_the_module_location_and_audits_once(tmp_path, monkeypatch, capsys):
    mod, mod_dir, ex = _located_module(tmp_path, monkeypatch)
    assert mod._exchange_dir() == str(ex)
    assert mod._exchange_dir() == str(ex)
    audit = (ex / "audit.log").read_text()
    assert audit.count("SystemPaths (BUG) is not available") == 1
    assert capsys.readouterr().err == ""


def test_exchange_dir_fallback_without_the_directory_writes_to_stderr_once(tmp_path, monkeypatch, capsys):
    mod, mod_dir, ex = _located_module(tmp_path, monkeypatch, with_dir=False)
    assert mod._exchange_dir() == str(ex)
    mod._exchange_dir()
    err = capsys.readouterr().err
    assert err.count("AgentRepl: SystemPaths (BUG) is not available") == 1
    assert not ex.exists()


def test_exchange_dir_prefers_systempaths_when_present(tmp_path, monkeypatch, capsys):
    mod, mod_dir, ex = _located_module(tmp_path, monkeypatch)
    sp = types.ModuleType("SystemPaths")
    sp.modDir = str(tmp_path / "other")
    monkeypatch.setitem(sys.modules, "SystemPaths", sp)
    assert mod._exchange_dir() == os.path.join(str(tmp_path / "other"), "UserSettings", "AgentRepl")
    assert not (ex / "audit.log").exists() and capsys.readouterr().err == ""


def test_failed_systempaths_import_is_not_retried_every_poll(tmp_path, monkeypatch):
    mod, mod_dir, ex = _located_module(tmp_path, monkeypatch)
    assert mod._exchange_dir() == str(ex)
    sp = types.ModuleType("SystemPaths")
    sp.modDir = str(tmp_path / "other")
    monkeypatch.setitem(sys.modules, "SystemPaths", sp)  # appears later: the cached failure still wins
    assert mod._exchange_dir() == str(ex)


def test_mod_dir_from_file_walks_four_levels_up(tmp_path, monkeypatch):
    mod, mod_dir, _ = _located_module(tmp_path, monkeypatch)
    assert pathlib.Path(mod._mod_dir_from_file()) == mod_dir


def _swap_exchange_directory(exch, tmp_path):
    """Really rename the checked directory away and put a different one (with a fresh status.txt) in its place."""
    other = tmp_path / "other"
    other.mkdir()
    (other / "status.txt").write_bytes((exch / "status.txt").read_bytes())
    (other / "ENABLE").write_text("")
    exch.rename(tmp_path / "moved")
    other.rename(exch)


def test_diagnostic_reads_are_refused_after_a_directory_swap(windows_model, exch, tmp_path):
    heartbeat(exch)
    (exch / "ENABLE").write_text("")
    ref = remote.open_dir(str(exch))
    status = remote.read_status(str(exch), dir_fd=ref)
    path = str(exch / "status.txt")
    assert remote.heartbeat_age(status, path=path, ref=ref) is not None  # unswapped: fine
    _swap_exchange_directory(exch, tmp_path)
    calls = [
        lambda: remote.heartbeat_age(status, path=path, ref=ref),
        lambda: remote.game_clock_estimate(status, path, ref=ref),
        lambda: remote.diagnose(str(exch), ref),
        lambda: remote._status_command(str(exch), ref),
        lambda: remote._exists_in(ref, str(exch), "ENABLE"),
    ]
    for call in calls:
        with pytest.raises(remote.ReplError) as err:
            call()
        assert err.value.code == remote.EXIT_REFUSED and "changed since" in str(err.value)


def test_status_command_prints_nothing_from_a_swapped_directory(windows_model, exch, tmp_path, capsys):
    heartbeat(exch)
    ref = remote.open_dir(str(exch))
    _swap_exchange_directory(exch, tmp_path)
    with pytest.raises(remote.ReplError) as err:
        remote._status_command(str(exch), ref)
    assert err.value.code == remote.EXIT_REFUSED
    assert capsys.readouterr().out == ""


def test_status_flag_exits_refused_when_the_directory_is_a_reparse_point(windows_model, exch, monkeypatch, capsys):
    heartbeat(exch)
    real_lstat = os.lstat
    state = {"checked": False}

    def lstat(p, *a, **k):
        st = real_lstat(p, *a, **k)
        # the walk and the identity capture see a plain directory; every later look sees a reparse point
        return FakeStat(st, stat.FILE_ATTRIBUTE_REPARSE_POINT if state["checked"] else 0)

    real_open_dir = remote.open_dir

    def open_dir(path):
        ref = real_open_dir(path)
        state["checked"] = True
        return ref

    monkeypatch.setattr(os, "lstat", lstat)
    monkeypatch.setattr(remote, "open_dir", open_dir)
    assert main(["exec", "--dir", str(exch), "--status"]) == remote.EXIT_REFUSED


@pytest.mark.skipif(not remote._HARDENED, reason="POSIX descriptor path")
def test_posix_diagnostics_stay_on_the_checked_descriptor(exch, tmp_path):
    heartbeat(exch)
    exch.chmod(0o700)
    fd = remote.open_dir(str(exch))
    try:
        _swap_exchange_directory(exch, tmp_path)  # the descriptor still names the original directory
        remote._recheck(fd)  # a no-op for a descriptor, never an error
        assert remote._exists_in(fd, str(exch), "ENABLE") is True  # path-based, as before: sees the swapped-in one
    finally:
        remote.close_dir(fd)
