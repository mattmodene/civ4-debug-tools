"""Install, remove or inspect AgentRepl in an installed Civ4 mod directory (for example Caveman2Cosmos).

    python3 -I tools/agentrepl_install.py install   --mod-dir DIR [--dry-run] [--backup-dir DIR] [--forbid DIR ...]
    python3 -I tools/agentrepl_install.py uninstall --mod-dir DIR [--dry-run] [--purge] [--backup-dir DIR]
    python3 -I tools/agentrepl_install.py status    --mod-dir DIR [--forbid DIR ...]

``install`` does exactly three things inside the mod directory:

  1. copies ``ingame/AgentRepl.py`` to ``Assets/Python/BUG/AgentRepl.py``;
  2. adds exactly one line to ``Assets/Config/init.xml`` (before ``</bug>``, with the
     file's own line ending; byte-preserving; a backup is taken first, see below);
  3. creates ``UserSettings/AgentRepl/``: mode 0700 on Linux and macOS; on Windows the mode is
     ignored and the directory is only as private as the ACL it inherits from its parent folder.

It NEVER creates ``ENABLE`` / ``ENABLE_WRITE``: the user creates them by hand.
``install`` is idempotent. ``uninstall`` removes the module, its .pyc and the line
(and the exchange directory, but keeps ``audit.log`` unless ``--purge``).

Defence in depth against the console reaching a version-controlled tree (and from there a
pull request): ``install`` refuses a --mod-dir that is inside a git work tree, or inside
any directory named with ``--forbid`` (see ``git_refusal``). Only an SVN working copy or a
plain directory is accepted.

Backup location. Without ``--backup-dir`` the backup goes to a per-install folder under the user's
state directory: ``$CIV4DBG_STATE_DIR`` if set, else ``$XDG_STATE_HOME/civ4dbg/agentrepl`` (default
``~/.local/state/civ4dbg/agentrepl``) on Linux and other POSIX, ``~/Library/Application
Support/civ4dbg/agentrepl`` on macOS, ``%LOCALAPPDATA%\\civ4dbg\\agentrepl`` on Windows. The folder is
named ``<mod dir name>-<first 12 hex of sha256 of the resolved mod path>``. It holds
``init.xml.pre-agentrepl``, its ``.sha256`` and ``manifest.json`` (schema version, resolved mod path,
UTC time, tool version, files backed up and changed). Folders are created mode 0700 on POSIX;
Windows enforces no mode (a folder only inherits the ACL of its parent). An explicit ``--backup-dir``
always wins and gets a manifest too. The backup location is refused inside a git work tree, inside
the mod directory, or inside a ``--forbid`` directory.

No clobber: an install never overwrites an existing backup. The first, pre-install copy is kept
(and a note is printed if init.xml has since changed). The backup is written atomically (temporary
file, fsync, replace). With no manifest, an existing backup is trusted only if it is byte-identical to
this mod's init.xml; otherwise install refuses (exit 3, nothing changed), since the backup could belong
to another mod sharing the --backup-dir. ``CIV4DBG_STATE_DIR`` must be an absolute path (else exit 2).

``uninstall`` without ``--backup-dir`` locates the folder from the mod path and REQUIRES a manifest
naming that same mod path (else exit 2, naming where it looked). With ``--backup-dir`` and no
manifest it only warns (backups made before manifests existed have none); a manifest that names
another mod path refuses either way. ``uninstall`` never modifies the backup.

Exit codes: 0 ok, 2 usage / not a mod tree / backup not found or mismatched, 3 refused (git work
tree, forbidden location, unsafe backup location, or an existing backup with no manifest.json that is not
byte-identical to this mod's current init.xml), 4 init.xml has an unexpected shape.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SOURCE = REPO / "ingame" / "AgentRepl.py"
LINE = b'<event type="gameUpdate" module="AgentRepl" function="onGameUpdate"/>'
OWNED_FILES = ("ENABLE", "ENABLE_WRITE", "status.txt")

EXIT_OK, EXIT_USAGE, EXIT_REFUSED, EXIT_SHAPE = 0, 2, 3, 4

BACKUP_NAME = "init.xml.pre-agentrepl"
MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA = 1
STATE_ENV = "CIV4DBG_STATE_DIR"


def _is_windows() -> bool:
    return sys.platform == "win32"


def _is_darwin() -> bool:
    return sys.platform == "darwin"


def protection_text() -> str:
    """What actually protects the exchange directory on this OS (never claims a mode Windows ignores)."""
    if _is_windows():
        return (
            "no mode applies on Windows; access is whatever ACL it inherits from its parent folder, so keep "
            "the mod directory inside your own user profile"
        )
    return "mode 0700"


def backup_protection_text() -> str:
    """What protects the backup folder on this OS."""
    if _is_windows():
        return (
            "no mode is enforced on Windows; the backup folder only inherits the ACL of its parent folder, "
            "so keep it inside your own user profile"
        )
    return "mode 0700"


class InstallError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def paths(mod: pathlib.Path) -> dict[str, pathlib.Path]:
    return {
        "init": mod / "Assets" / "Config" / "init.xml",
        "bug": mod / "Assets" / "Python" / "BUG",
        "module": mod / "Assets" / "Python" / "BUG" / "AgentRepl.py",
        "exchange": mod / "UserSettings" / "AgentRepl",
    }


def git_refusal(mod: pathlib.Path, forbidden: tuple[pathlib.Path, ...] = ()) -> str | None:
    """Return a refusal message if mod is somewhere the console must never be installed."""
    real = mod.resolve()
    for bad in forbidden:
        bad_real = bad.resolve()
        if real == bad_real or bad_real in real.parents:
            return f"{mod} is inside {bad}, which --forbid marks as off limits. Refusing"
    for parent in [real, *real.parents]:
        if (parent / ".git").exists():
            return f"{mod} is inside a git work tree ({parent}). Refusing"
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    try:
        r = subprocess.run(
            ["git", "-C", str(real), "rev-parse", "--is-inside-work-tree"],
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError):
        return None  # git absent: the .git walk above is the check
    if r.returncode == 0 and r.stdout.strip() == "true":
        return f"{mod} is inside a git work tree (git rev-parse). Refusing"
    return None


def tool_version() -> str:
    """The package version: installed metadata, else this checkout's pyproject.toml, else 'unknown'."""
    try:
        from importlib import metadata

        return metadata.version("civ4dbg")
    except Exception:  # not installed, or metadata unreadable
        pass
    try:
        import tomllib

        with open(REPO / "pyproject.toml", "rb") as fh:
            return str(tomllib.load(fh)["project"]["version"])
    except Exception:
        return "unknown"


def state_root() -> pathlib.Path:
    """Where backups live by default (see the module docstring)."""
    override = os.environ.get(STATE_ENV)
    if override:
        if not os.path.isabs(override):
            raise InstallError(
                EXIT_USAGE,
                f"{STATE_ENV} must be an absolute path (got {override!r}); a relative value would point "
                "install and uninstall at different folders when run from different directories",
            )
        return pathlib.Path(override)
    home = pathlib.Path(os.path.expanduser("~"))
    if _is_windows():
        local = os.environ.get("LOCALAPPDATA")
        if not local:
            raise InstallError(
                EXIT_USAGE,
                f"%LOCALAPPDATA% is not set, so there is no default backup location; set {STATE_ENV} "
                "or pass --backup-dir",
            )
        return pathlib.Path(local) / "civ4dbg" / "agentrepl"
    if _is_darwin():
        return home / "Library" / "Application Support" / "civ4dbg" / "agentrepl"
    xdg = os.environ.get("XDG_STATE_HOME")
    base = pathlib.Path(xdg) if xdg and os.path.isabs(xdg) else home / ".local" / "state"
    return base / "civ4dbg" / "agentrepl"


def _norm(path: pathlib.Path | str) -> str:
    return os.path.normcase(os.path.realpath(path))


def install_folder_name(mod: pathlib.Path) -> str:
    """<sanitised mod dir name>-<first 12 hex of sha256 of the resolved, normalised mod path>."""
    resolved = _norm(mod)
    name = re.sub(r"[^A-Za-z0-9._-]", "_", pathlib.Path(resolved).name).strip(".") or "mod"
    return f"{name[:48]}-{hashlib.sha256(resolved.encode('utf-8')).hexdigest()[:12]}"


def default_backup_dir(mod: pathlib.Path) -> pathlib.Path:
    return state_root() / install_folder_name(mod)


def _mkdir_private(path: pathlib.Path) -> None:
    """Create path and any missing parents; each directory this call creates is mode 0700 on POSIX."""
    missing = []
    cur = path
    while not cur.exists():
        missing.append(cur)
        if cur.parent == cur:
            break
        cur = cur.parent
    for d in reversed(missing):
        d.mkdir(mode=0o700)
        os.chmod(d, 0o700)  # no-op on Windows, where the parent's ACL applies


def backup_refusal(backup: pathlib.Path, mod: pathlib.Path, forbidden: tuple[pathlib.Path, ...] = ()) -> str | None:
    """Refuse a backup location in the mod directory, a git work tree, or a --forbid directory."""
    real_mod = mod.resolve()
    real = backup.resolve()
    if real == real_mod or real_mod in real.parents:
        return f"backup location {backup} is inside the mod directory {mod}. Refusing"
    probe = real
    while not probe.exists() and probe.parent != probe:
        probe = probe.parent
    msg = git_refusal(probe, forbidden)
    if msg:
        return f"backup location {backup} is unsafe: {msg}"
    return None


def read_manifest(folder: pathlib.Path) -> dict | None:
    """The manifest as a dict, None if absent; InstallError if present but unreadable."""
    f = folder / MANIFEST_NAME
    if not f.is_file():
        return None
    try:
        data = json.loads(f.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("mod_path"), str):
            raise ValueError("no mod_path")
    except (OSError, ValueError) as exc:
        raise InstallError(
            EXIT_USAGE, f"{f} is not a readable manifest ({exc}); pass a different --backup-dir"
        ) from exc
    return data


def write_manifest(folder: pathlib.Path, mod: pathlib.Path, backed_up: dict[str, str], changed: list[str]) -> None:
    """Write manifest.json atomically (temporary file, then replace)."""
    doc = {
        "schema_version": MANIFEST_SCHEMA,
        "mod_path": str(mod.resolve()),
        "created_utc": datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "tool_version": tool_version(),
        "files_backed_up": [{"name": n, "sha256": h} for n, h in sorted(backed_up.items())],
        "files_changed": changed,
    }
    tmp = folder / (MANIFEST_NAME + ".tmp")
    try:
        tmp.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        os.replace(tmp, folder / MANIFEST_NAME)
    finally:
        if tmp.exists():
            tmp.unlink()


def _check_manifest_matches(folder: pathlib.Path, mod: pathlib.Path, man: dict, code: int) -> None:
    if _norm(man["mod_path"]) != _norm(mod):
        raise InstallError(
            code,
            f"{folder / MANIFEST_NAME} belongs to a different mod ({man['mod_path']}), not {mod.resolve()}. "
            "Refusing; pass the --backup-dir that was used for this mod",
        )


def _split_lines(data: bytes) -> list[bytes]:
    return data.splitlines(keepends=True)


def _bare(line: bytes) -> bytes:
    return line.strip()


def _is_ours(line: bytes) -> bool:
    """The exact line, or a hand-edited variant of it (different spacing or attribute order)."""
    b = _bare(line)
    return b == LINE or (b.startswith(b"<event") and b'"gameUpdate"' in b and b'module="AgentRepl"' in b)


def add_line(data: bytes) -> bytes:
    """Return init.xml bytes with the AgentRepl line added before </bug> (unchanged if present)."""
    lines = _split_lines(data)
    if any(_is_ours(ln) for ln in lines):
        return data
    hits = [i for i, ln in enumerate(lines) if _bare(ln) == b"</bug>"]
    if len(hits) != 1 or data.count(b"</bug>") != 1:
        raise InstallError(EXIT_SHAPE, "init.xml: expected exactly one </bug> line; not editing")
    i = hits[0]
    close = lines[i]
    indent = close[: len(close) - len(close.lstrip(b" \t"))] + b"\t"
    eol = b"\n"
    if i > 0:
        prev = lines[i - 1]
        for cand in (b"\r\n", b"\n", b"\r"):
            if prev.endswith(cand):
                eol = cand
                break
    lines.insert(i, indent + LINE + eol)
    return b"".join(lines)


def remove_line(data: bytes) -> bytes:
    return b"".join(ln for ln in _split_lines(data) if not _is_ours(ln))


def _atomic_write(path: pathlib.Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".agentrepl.tmp")
    try:
        tmp.write_bytes(data)
        shutil.copymode(path, tmp)
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()  # never leave an svn "?" entry behind


def _atomic_create(path: pathlib.Path, data: bytes) -> None:
    """Write a file atomically: temp file in the same directory, fsync, os.replace (no partial file)."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        with open(tmp, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    finally:
        if tmp.exists():
            tmp.unlink()


def _copy_module(src: pathlib.Path, dst: pathlib.Path) -> None:
    tmp = dst.with_name(dst.name + ".agentrepl.tmp")
    try:
        shutil.copyfile(src, tmp)
        os.replace(tmp, dst)
    finally:
        if tmp.exists():
            tmp.unlink()


def _is_link_like(path: pathlib.Path) -> bool:
    """A symlink, or (Windows) a junction or other reparse point."""
    if path.is_symlink():
        return True
    try:
        attrs = getattr(os.lstat(path), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _check_exchange(ex: pathlib.Path) -> None:
    if _is_link_like(ex):
        raise InstallError(EXIT_REFUSED, f"{ex} is a symlink or reparse point; refusing to use or modify it")
    if _is_link_like(ex.parent):
        raise InstallError(EXIT_REFUSED, f"{ex.parent} is a symlink or reparse point; refusing")


def _check_tree(mod: pathlib.Path) -> dict[str, pathlib.Path]:
    p = paths(mod)
    missing = []
    if not p["init"].is_file():
        missing.append(f"{p['init']} (BUG's event configuration file)")
    if not p["bug"].is_dir():
        missing.append(f"{p['bug']} (BUG's Python package directory)")
    if missing:
        raise InstallError(
            EXIT_USAGE,
            f"{mod} cannot host AgentRepl: it needs the BUG mod framework (Assets/Config/init.xml with a "
            "<bug> element, and Assets/Python/BUG/), because the console is hooked in as a BUG gameUpdate "
            "event. Missing: " + "; ".join(missing) + ". This is not a general Civ4 requirement: a mod "
            "without BUG is not supported yet.",
        )
    return p


def install(
    mod: pathlib.Path, backup_dir: pathlib.Path | None, dry: bool, forbidden: tuple[pathlib.Path, ...] = ()
) -> None:
    refusal = git_refusal(mod, forbidden)
    if refusal:
        raise InstallError(EXIT_REFUSED, refusal)
    p = _check_tree(mod)
    if not SOURCE.is_file():
        raise InstallError(EXIT_USAGE, f"missing {SOURCE}")
    data = p["init"].read_bytes()
    new = add_line(data)
    note = "init.xml already has the line" if new == data else "init.xml: adding one line before </bug>"
    print(note)
    ex = p["exchange"]
    _check_exchange(ex)
    where = "default location" if backup_dir is None else "explicit --backup-dir"
    bk = backup_dir if backup_dir is not None else default_backup_dir(mod)
    msg = backup_refusal(bk, mod, forbidden)
    if msg:
        raise InstallError(EXIT_REFUSED, msg)
    man = read_manifest(bk)
    if man is not None:
        _check_manifest_matches(bk, mod, man, EXIT_REFUSED)
    orig = bk / BACKUP_NAME
    kept = orig.exists()
    if kept and man is None and new != data and orig.read_bytes() != data:
        # An existing backup with no manifest cannot be shown to belong to this mod; a manifest claiming
        # it would be a guess. Refuse and touch nothing (the safer choice over writing nothing and warning).
        raise InstallError(
            EXIT_REFUSED,
            f"{bk} already holds {BACKUP_NAME} but no {MANIFEST_NAME}, and it does not match this mod's "
            "init.xml, so it cannot be shown to belong to this mod (a shared --backup-dir?). Refusing; "
            "pass a different --backup-dir, or remove that backup yourself if it is stale",
        )
    if dry:
        print(f"dry run: would copy AgentRepl.py to {p['module']}, create {ex} ({protection_text()})")
        if new != data:
            what = "keep the existing original backup in" if kept else "back up init.xml and write manifest.json to"
            print(f"dry run: would {what} {bk} ({where}; {backup_protection_text()})")
        else:
            print(f"dry run: init.xml needs no edit, so no backup is made (backup location would be {bk})")
        return
    _copy_module(SOURCE, p["module"])  # module first: a half install is then never "line without module"
    ex.parent.mkdir(parents=True, exist_ok=True)
    # POSIX: mode 0700 from creation. Windows ignores the mode bits (only the read-only flag maps), so
    # these two calls change nothing there and the directory keeps its parent's inherited ACL.
    if not ex.exists():
        ex.mkdir(mode=0o700)
    os.chmod(ex, 0o700)
    if new != data:
        _mkdir_private(bk)
        if kept:
            # No clobber: the first backup is the pristine pre-install file; never replace it.
            print(f"backup kept: {orig} already exists and is NOT overwritten (the original pre-install copy stays)")
            if orig.read_bytes() != data:
                print("note: the current init.xml differs from that kept backup")
        else:
            _atomic_create(orig, data)
            _atomic_create(bk / (BACKUP_NAME + ".sha256"), (hashlib.sha256(data).hexdigest() + "\n").encode("ascii"))
            print(f"backup: {orig}")
        if man is None:
            write_manifest(
                bk,
                mod,
                {BACKUP_NAME: hashlib.sha256(orig.read_bytes()).hexdigest()},
                ["Assets/Config/init.xml", "Assets/Python/BUG/AgentRepl.py"],
            )
        print(f"backup location: {bk} ({where}; {backup_protection_text()})")
        _atomic_write(p["init"], new)
    else:
        print(f"no backup needed: init.xml was not changed (backup location would be {bk})")
    print(f"installed {p['module']}; exchange directory {ex} ({protection_text()})")
    print("ENABLE was NOT created: the user creates it by hand to switch the console on.")


def locate_backup(mod: pathlib.Path, backup_dir: pathlib.Path | None) -> pathlib.Path:
    """Resolve and validate the backup folder for uninstall (see the module docstring)."""
    if backup_dir is not None:
        man = read_manifest(backup_dir)
        if man is None:
            print(f"warning: {backup_dir / MANIFEST_NAME} not found; could not verify the backup belongs to {mod}")
        else:
            _check_manifest_matches(backup_dir, mod, man, EXIT_USAGE)
        return backup_dir
    bk = default_backup_dir(mod)
    howto = f"looked in {bk}; if the backup is elsewhere, pass --backup-dir DIR"
    man = read_manifest(bk) if bk.is_dir() else None
    if man is None:
        raise InstallError(EXIT_USAGE, f"no backup folder with a {MANIFEST_NAME} found for {mod.resolve()}: {howto}")
    try:
        _check_manifest_matches(bk, mod, man, EXIT_USAGE)
    except InstallError as exc:
        raise InstallError(EXIT_USAGE, f"{exc} ({howto})") from exc
    return bk


def uninstall(mod: pathlib.Path, dry: bool, purge: bool, backup_dir: pathlib.Path | None = None) -> None:
    p = paths(mod)
    ex = p["exchange"]
    bk = locate_backup(mod, backup_dir)  # validated before anything is touched
    print(f"backup location: {bk} (left untouched)")
    _check_exchange(ex)
    for name in OWNED_FILES:  # switch off first
        if (ex / name).exists():
            print(f"remove {ex / name}")
            if not dry:
                (ex / name).unlink()
    if p["init"].is_file():
        data = p["init"].read_bytes()
        new = remove_line(data)
        if new != data:
            print("init.xml: removing the AgentRepl line")
            if not dry:
                _atomic_write(p["init"], new)
    for f in (p["module"], p["module"].with_suffix(".pyc"), p["module"].with_suffix(".pyo")):
        if f.exists():
            print(f"remove {f}")
            if not dry:
                f.unlink()
    if ex.is_dir():
        for f in sorted(ex.iterdir()):
            if f.is_file() and (f.name.startswith(("req-", "rep-")) or (purge and f.name.startswith("audit.log"))):
                print(f"remove {f}")
                if not dry:
                    f.unlink()
        if not dry:
            try:
                ex.rmdir()
                print(f"removed {ex}")
            except OSError:
                held = ", ".join(sorted(x.name for x in ex.iterdir()))
                print(f"kept {ex} (still holds: {held}; --purge removes audit.log)")


def status(mod: pathlib.Path, forbidden: tuple[pathlib.Path, ...] = ()) -> None:
    p = paths(mod)
    refusal = git_refusal(mod, forbidden)
    init = p["init"].read_bytes() if p["init"].is_file() else b""
    print(f"mod dir:        {mod}")
    print(f"install allowed: {'no: ' + refusal if refusal else 'yes'}")
    print(f"module present: {p['module'].is_file()}")
    print(f"init.xml line:  {init.count(LINE.strip()) > 0}")
    ex = p["exchange"]
    shown = f" (mode {ex.stat().st_mode & 0o777:04o})" if ex.is_dir() and not _is_windows() else ""
    print(f"exchange dir:   {ex.is_dir()}{shown}")
    if ex.is_dir() and _is_windows():
        print(f"protection:     {protection_text()}")
    print(f"ENABLE:         {(ex / 'ENABLE').exists()}")
    print(f"ENABLE_WRITE:   {(ex / 'ENABLE_WRITE').exists()}")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", choices=["install", "uninstall", "status"])
    ap.add_argument(
        "--mod-dir", required=True, type=pathlib.Path, help="the installed mod directory (explicit, no default)"
    )
    ap.add_argument(
        "--forbid",
        action="append",
        default=[],
        type=pathlib.Path,
        metavar="DIR",
        help="refuse to install into DIR or anything under it (repeatable); e.g. a mod clone or fork workspace "
        "that must never carry the console. No default",
    )
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument(
        "--backup-dir",
        type=pathlib.Path,
        default=None,
        help="where init.xml is backed up before the edit. Default: a per-install folder under the user state "
        "directory ($CIV4DBG_STATE_DIR, else the per-OS location; see the top of this help). Wins over the "
        "default; uninstall uses it to find the backup",
    )
    ap.add_argument("--purge", action="store_true", help="uninstall: also delete audit.log")
    args = ap.parse_args(argv)
    try:
        if not args.mod_dir.is_dir():
            raise InstallError(EXIT_USAGE, f"{args.mod_dir} is not a directory")
        if args.action == "install":
            install(args.mod_dir, args.backup_dir, args.dry_run, tuple(args.forbid))
        elif args.action == "uninstall":
            uninstall(args.mod_dir, args.dry_run, args.purge, args.backup_dir)
        else:
            status(args.mod_dir, tuple(args.forbid))
    except InstallError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
