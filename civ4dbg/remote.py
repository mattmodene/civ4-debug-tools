"""Host side of the AgentRepl remote console: ``civ4dbg exec``.

Writes one request file into the exchange directory, waits for the game-side
module (``ingame/AgentRepl.py``) to answer with ``rep-<id>.txt``, and maps the
reply to an exit code. It never creates the ``ENABLE`` switch: the user
creates it by hand. The protocol is documented at the top of ``ingame/AgentRepl.py``.

Exit codes of ``exec`` (these differ from the PDB commands' codes):

    0 ok                         3 timeout / game not polling / budget exceeded / stale
    1 remote exception           4 switched off (no ENABLE)
    2 usage error                5 refused (refuse list, no ENABLE_WRITE, unsafe directory)
    6 reply malformed
"""

from __future__ import annotations

import argparse
import math
import os
import pathlib
import re
import secrets
import signal
import stat
import sys
import time

EXIT_OK = 0
EXIT_REMOTE_ERROR = 1
EXIT_USAGE = 2
EXIT_TIMEOUT = 3
EXIT_OFF = 4
EXIT_REFUSED = 5
EXIT_MALFORMED = 6

ENV_DIR = "CIV4_REPL_DIR"  # the exchange directory itself
ENV_MOD_DIR = "CIV4DBG_MOD_DIR"  # the installed mod directory; the exchange is UserSettings/AgentRepl under it
EXCHANGE_SUBDIR = os.path.join("UserSettings", "AgentRepl")
DEFAULT_TIMEOUT = 15.0
DEFAULT_BUDGET = 2.0
MAX_BUDGET = 10.0
REQUEST_CAP = 64 * 1024
HEARTBEAT_FRESH = 5.0
POLL_SLEEP = 0.05
REPLY_CAP = 256 * 1024
STATUS_CAP = 8192
FUTURE_SLOP = 5.0  # a status.txt mtime further ahead of the host clock than this is not fresh
OLDER_VERSION_MESSAGE = (
    "the installed AgentRepl is older than this civ4dbg (protocol version {have}, need "
    "{need}); reinstall and restart (tools/agentrepl_install.py install --mod-dir DIR, "
    "then restart the game)"
)
OLD_MODULE_MESSAGE = (
    "status.txt has a fresh heartbeat but no session line: the installed module is older; "
    "reinstall and restart (the installed AgentRepl is older than this civ4dbg; run "
    "tools/agentrepl_install.py install --mod-dir DIR, then restart the game)"
)
MIN_VERSION = 3  # the oldest module protocol this host speaks (3: per-request `notafter` deadline)
DEADLINE_SLACK = 2.0  # seconds added to the host's own timeout when computing the game-side deadline
MAX_TOKEN = 64
TOKEN_RE = re.compile(r"[0-9a-f]{16,%d}\Z" % MAX_TOKEN)


class ReplError(Exception):
    """A condition that maps directly to an exit code."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code


def resolve_dir(cli_value: str | None) -> str:
    """The exchange directory: ``--dir``, else ``$CIV4_REPL_DIR``, else ``$CIV4DBG_MOD_DIR/UserSettings/AgentRepl``.

    There is no built-in default: the install location differs per machine, so guessing one would
    point the tool at somebody else's directory.
    """
    if cli_value:
        return cli_value
    env_dir = os.environ.get(ENV_DIR)
    if env_dir:
        return env_dir
    mod_dir = os.environ.get(ENV_MOD_DIR)
    if mod_dir:
        return os.path.join(mod_dir, EXCHANGE_SUBDIR)
    raise ReplError(
        EXIT_USAGE,
        f"no exchange directory given: pass --dir DIR, or set {ENV_DIR} (the exchange directory) "
        f"or {ENV_MOD_DIR} (the installed mod directory; the exchange is {EXCHANGE_SUBDIR} under it)",
    )


# --- platform model -----------------------------------------------------------------------------
#
# What each OS actually enforces for the exchange directory (nothing here claims more):
#
# POSIX (Linux; macOS), `_HARDENED` is True:
#   * every path component is lstat'ed: a symlink, a non-directory, or a directory owned by neither
#     you nor root (the directory itself: only you) is refused;
#   * the exchange directory must have no group/other bits (0700); ancestors must not be
#     group/other-writable unless sticky;
#   * the directory is then opened once with O_DIRECTORY | O_NOFOLLOW and re-checked by fstat
#     (owner, mode); every later file operation is relative to that descriptor (dir_fd), with
#     O_NOFOLLOW (and O_NONBLOCK for reads), so a swap of the path after the check changes nothing;
#   * the reply must be a regular file owned by you.
#   * macOS only: root's own aliases /var, /tmp, /etc (symlinks into /private) are rewritten to
#     their real location before the walk (see `_resolve_system_alias`); no other symlink is allowed.
#
# Windows (and any platform lacking uid, O_DIRECTORY, O_NOFOLLOW or dir_fd), `_HARDENED` is False:
#   * every path component below the drive/share root is lstat'ed: a symlink, a junction or any
#     other reparse point (FILE_ATTRIBUTE_REPARSE_POINT, which includes mount points and OneDrive
#     placeholders; refused conservatively), or a non-directory, is refused;
#   * the identity of the exchange directory (st_dev, st_ino: the volume serial and file index) is
#     captured when it is checked and compared again before every file operation (opens, replaces,
#     unlinks, and the status, heartbeat-age and ENABLE reads), and the directory is re-checked for a
#     reparse point; replacing the directory, or an ancestor, by a junction after the check is refused;
#   * files (status.txt, rep-<id>.txt) are checked by lstat before the open (no reparse point,
#     regular file) and by fstat after it (regular file, same file index as the lstat), narrowing
#     but NOT closing the check-to-use race, since Windows has no O_NOFOLLOW;
#   * all opens are binary (O_BINARY).
#   NOT enforced on Windows, and the CLI says so once per run (`_warn_reduced_protection`):
#   directory ownership (no uid; ACLs are not read), the 0700 mode check (Windows modes are
#   synthesized), reply-file ownership, descriptor-relative operations (dir_fd), and closing the race
#   described above. Three gaps remain on Windows: a swap in the instant between the comparison and the open;
#   a file system that reports no file index, where the comparison is skipped; and anyone with write
#   access to the parent folder. The directory's privacy rests on the ACLs it inherits from its parent
#   (a folder inside your own user profile is private to you and administrators by default).
_HARDENED = (
    hasattr(os, "getuid") and hasattr(os, "O_DIRECTORY") and hasattr(os, "O_NOFOLLOW") and os.open in os.supports_dir_fd
)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_NONBLOCK = getattr(os, "O_NONBLOCK", 0)
_BINARY = getattr(os, "O_BINARY", 0)  # Windows only: without it os.read translates CRLF and stops at Ctrl-Z
_ROOT_UID = 0
_SYSTEM_ALIASES = ("var", "tmp", "etc")  # macOS: /var -> /private/var, etc.; root-owned
_REDUCED_PROTECTION_MESSAGE = (
    "warning: on this OS civ4dbg cannot enforce all the exchange-directory protections it enforces on "
    "Linux/macOS. Not enforced: directory ownership (no uid check; ACLs are not inspected), the 0700 mode "
    "check, reply-file ownership, and race-free opening (no O_NOFOLLOW or directory-relative opens, so a path "
    "swapped between a check and the use is only narrowly caught). Also, SIGTERM does not withdraw a pending "
    "request here (Ctrl-C does). Still enforced: symlinks, junctions and other reparse "
    "points in the path are refused. Keep the exchange directory inside your own user profile (its inherited "
    "ACL is what keeps others out)."
)
_warned = False


class _PathDir:
    """A checked exchange directory on a platform without directory descriptors: just its path."""

    def __init__(self, path: str, ident: tuple[int, int] | None = None):
        self.path = path
        self.ident = ident  # (st_dev, st_ino) captured when the directory was checked; None = unknown

    def recheck(self) -> None:
        """Refuse if the directory is no longer the one that was checked (swapped for a link or another dir).

        lstat does not follow a final junction or symlink, and follows an intermediate one, so a swap of the
        directory or of any ancestor shows up as a different identity or as a reparse point.
        """
        try:
            st = os.lstat(self.path)
        except OSError as exc:
            raise OSError(f"{self.path} is gone or unreadable: {exc}") from None
        if stat.S_ISLNK(st.st_mode) or getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
            raise OSError(f"{self.path} became a symlink or reparse point")
        if not stat.S_ISDIR(st.st_mode):
            raise OSError(f"{self.path} is no longer a directory")
        if self.ident is not None and (st.st_dev, st.st_ino) != self.ident:
            raise OSError(f"{self.path} changed since it was checked")


def _warn_reduced_protection() -> None:
    """Print the not-enforced list once per process, only where `_HARDENED` is False."""
    global _warned
    if _HARDENED or _warned:
        return
    _warned = True
    print(_REDUCED_PROTECTION_MESSAGE, file=sys.stderr)


def _is_darwin() -> bool:
    return sys.platform == "darwin"


def _resolve_system_alias(absolute: str, root: str = "/") -> str:
    """macOS: rewrite a leading /var, /tmp or /etc to its real /private/... location.

    Those three are symlinks owned by root, and `check_dir` otherwise refuses any symlink in the path,
    so the usual temp location (/var/folders/...) would be refused. The rewrite happens only when the
    component is a symlink, owned by root, whose real target is exactly <root>/private/<name>; any other
    symlink, or a lookalike not owned by root, is left in place and refused by the walk. Only used on darwin.
    """
    parts = pathlib.PurePosixPath(absolute).parts
    if len(parts) < 2 or parts[0] != "/" or parts[1] not in _SYSTEM_ALIASES:
        return absolute
    alias = os.path.join(root, parts[1])
    try:
        st = os.lstat(alias)
    except OSError:
        return absolute
    target = os.path.join(root, "private", parts[1])
    if stat.S_ISLNK(st.st_mode) and st.st_uid == _ROOT_UID and _alias_target(alias) == target:
        return os.path.join(target, *parts[2:]) if len(parts) > 2 else target
    return absolute


def _alias_target(alias: str) -> str | None:
    """The literal target of the alias symlink, made absolute against its directory (no further resolving)."""
    try:
        link = os.readlink(alias)
    except OSError:
        return None
    return os.path.normpath(os.path.join(os.path.dirname(alias), link))


def _normalize(path: str) -> str:
    absolute = os.path.abspath(path)
    if _HARDENED and _is_darwin():
        absolute = _resolve_system_alias(absolute)
    return absolute


def _prefixes(absolute: str, windows: bool) -> list[str]:
    """Every ancestor of `absolute` (and itself), outermost first, below the root/drive/share anchor.

    Uses pure path classes so a drive letter (`C:\\a\\b`) or UNC share is the anchor and is never
    treated as a relative `C:` (the old os.sep prefix walk did exactly that).
    """
    pure = pathlib.PureWindowsPath(absolute) if windows else pathlib.PurePosixPath(absolute)
    parts = pure.parts
    # POSIX also checks the root "/" itself (it must be a directory owned by root or you). On Windows the
    # drive/share anchor is not lstat'ed: it is the volume root, not something a user can swap for a link.
    out = [pure.anchor] if pure.anchor and not windows else []
    cur = pure.anchor
    for part in parts[1:] if pure.anchor else parts:
        cur = str(type(pure)(cur, part))
        out.append(cur)
    return out


def _check_component(path: str, final: bool) -> None:
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        raise ReplError(
            EXIT_TIMEOUT,
            f"exchange directory {path} does not exist (the module is not installed, or the path is wrong)",
        ) from None
    if stat.S_ISLNK(st.st_mode):
        raise ReplError(EXIT_REFUSED, f"{path} is a symlink; refusing")
    if getattr(st, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT:
        raise ReplError(EXIT_REFUSED, f"{path} is a junction or other reparse point; refusing")
    if not stat.S_ISDIR(st.st_mode):
        raise ReplError(EXIT_REFUSED, f"{path} is not a directory")
    if not _HARDENED:
        return  # no uid and no meaningful mode bits here; see the platform model above
    me = os.getuid()
    if st.st_uid != me and (final or st.st_uid != 0):
        raise ReplError(EXIT_REFUSED, f"{path} is owned by uid {st.st_uid}, not you")
    if final:
        if st.st_mode & 0o077:
            raise ReplError(
                EXIT_REFUSED,
                f"exchange directory {path} has mode {stat.S_IMODE(st.st_mode):04o}; it must be 0700 (chmod 700)",
            )
    elif st.st_mode & 0o022 and not st.st_mode & stat.S_ISVTX:
        raise ReplError(EXIT_REFUSED, f"{path} is group/other-writable and not sticky; refusing")


def check_dir(path: str) -> None:
    """Refuse a directory whose any path component is a symlink (or, on Windows, any reparse point).

    POSIX also refuses foreign owners and a directory open to group/other; see the platform model above.
    """
    _warn_reduced_protection()
    absolute = _normalize(path)
    prefixes = _prefixes(absolute, windows=os.name == "nt")
    if not prefixes:
        # An anchor only (a bare drive or UNC share root): nothing below it to check, and it is not an
        # exchange directory. Refuse rather than pass it unchecked.
        raise ReplError(EXIT_REFUSED, f"{path} is a drive or share root, not an exchange directory; refusing")
    for i, prefix in enumerate(prefixes):
        _check_component(prefix, final=(i == len(prefixes) - 1))


def open_dir(path: str) -> int | _PathDir:
    """check_dir, then open the directory once (no symlink following) and re-check the descriptor.

    POSIX returns a descriptor. Where that is impossible (Windows) it returns a `_PathDir`, and every later
    operation re-checks the file it touches (see the platform model above for what that does not cover).
    """
    check_dir(path)
    absolute = _normalize(path)
    if not _HARDENED:
        try:
            st = os.lstat(absolute)
        except OSError as exc:
            raise ReplError(EXIT_REFUSED, f"cannot open {path} safely: {exc}") from None
        ident = (st.st_dev, st.st_ino)
        return _PathDir(absolute, None if ident == (0, 0) else ident)
    try:
        fd = os.open(absolute, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as exc:
        raise ReplError(EXIT_REFUSED, f"cannot open {path} safely: {exc}") from None
    st = os.fstat(fd)
    if st.st_uid != os.getuid() or st.st_mode & 0o077:
        os.close(fd)
        raise ReplError(EXIT_REFUSED, f"{path} changed under us (owner or mode); refusing")
    return fd


def close_dir(ref: int | _PathDir) -> None:
    if isinstance(ref, int):
        os.close(ref)


def _open_checked(path: str, flags: int, mode: int = 0o777) -> int:
    """Path-based open for platforms without O_NOFOLLOW: lstat (no reparse point), open, fstat (same file).

    Narrows the check-to-use race; cannot close it. Raises OSError for anything refused.
    """
    creating = bool(flags & os.O_CREAT and flags & os.O_EXCL)
    try:
        before = os.lstat(path)
    except FileNotFoundError:
        if not creating:
            raise
        before = None  # a new file: O_EXCL itself refuses an existing name, a planted link included
    if before is not None and (
        stat.S_ISLNK(before.st_mode) or getattr(before, "st_file_attributes", 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT
    ):
        raise OSError(f"{path} is a symlink or reparse point")
    fd = os.open(path, flags | _BINARY, mode)
    if before is not None:
        after = os.fstat(fd)
        if (before.st_ino, before.st_dev) != (after.st_ino, after.st_dev):
            os.close(fd)
            raise OSError(f"{path} changed between check and open")
    return fd


def _open_in(ref: int | _PathDir | None, d: str, name: str, flags: int, mode: int = 0o777) -> int:
    """Open `name` inside the exchange directory without following a symlink, as far as the OS allows."""
    if isinstance(ref, int):
        return os.open(name, flags | _NOFOLLOW | _BINARY, mode, dir_fd=ref)
    if isinstance(ref, _PathDir):
        ref.recheck()
    base = ref.path if isinstance(ref, _PathDir) else d
    path = os.path.join(base, name)
    if _HARDENED:
        return os.open(path, flags | _NOFOLLOW | _BINARY, mode)
    return _open_checked(path, flags, mode)


def _replace_in(ref: int | _PathDir, src: str, dst: str) -> None:
    if isinstance(ref, int):
        os.replace(src, dst, src_dir_fd=ref, dst_dir_fd=ref)
    else:
        ref.recheck()
        os.replace(os.path.join(ref.path, src), os.path.join(ref.path, dst))


def _unlink_in(ref: int | _PathDir, name: str) -> None:
    if isinstance(ref, int):
        os.unlink(name, dir_fd=ref)
    else:
        ref.recheck()
        os.unlink(os.path.join(ref.path, name))


def _read_status_file(d: str, dir_fd: int | _PathDir | None) -> bytes | None:
    """Open status.txt without following a symlink or blocking on a FIFO; regular file, size-capped."""
    try:
        fd = _open_in(dir_fd, d, "status.txt", os.O_RDONLY | _NONBLOCK)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > STATUS_CAP:
            return None
        return os.read(fd, STATUS_CAP)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_status(d: str, dir_fd: int | _PathDir | None = None) -> dict[str, str] | None:
    """Parse status.txt; None if missing, not a small regular file, or unparseable.

    It is rewritten in place, so a torn read is retried once. With `dir_fd` the file is opened relative
    to the already-checked directory descriptor; either way a symlink is refused (O_NOFOLLOW) and a FIFO
    cannot block (O_NONBLOCK), a non-regular file or one over STATUS_CAP bytes reads as missing.
    """
    for _ in range(2):
        raw = _read_status_file(d, dir_fd)
        if raw is None:
            return None
        out: dict[str, str] = {}
        for line in raw.decode("utf-8", "replace").splitlines():
            key, sep, value = line.partition(": ")
            if sep:
                out[key] = value
        if "epoch" in out and "enabled" in out:
            return out
        time.sleep(0.02)
    return None


def session_token(status: dict[str, str] | None) -> str | None:
    """The game's session token from a parsed status.txt, or None if absent or malformed."""
    if status is None:
        return None
    token = status.get("session", "")
    return token if TOKEN_RE.match(token) else None


def module_version(status: dict[str, str] | None) -> int | None:
    """The protocol version a parsed status.txt reports, or None if absent or not an integer."""
    if status is None:
        return None
    try:
        return int(status.get("version", ""))
    except ValueError:
        return None


def older_module_message(status: dict[str, str] | None) -> str | None:
    """A reinstall message if status.txt shows a module older than MIN_VERSION, else None."""
    have = module_version(status)
    if have is not None and have < MIN_VERSION:
        return OLDER_VERSION_MESSAGE.format(have=have, need=MIN_VERSION)
    return None


def _recheck(ref: int | _PathDir | None) -> None:
    """Directory-identity re-check for the read-only diagnostic reads: refuse (EXIT_REFUSED) on a mismatch.

    The same `_PathDir.recheck` that guards open, replace and unlink. A no-op for a descriptor (POSIX: the
    descriptor cannot be swapped) and for None (no checked directory was given).
    """
    if isinstance(ref, _PathDir):
        try:
            ref.recheck()
        except OSError as exc:
            raise ReplError(EXIT_REFUSED, f"exchange directory refused: {exc}") from None


def _exists_in(ref: int | _PathDir | None, d: str, name: str) -> bool:
    """os.path.exists on a file in the exchange directory, after the identity re-check."""
    _recheck(ref)
    return os.path.exists(os.path.join(ref.path if isinstance(ref, _PathDir) else d, name))


def game_clock_estimate(
    status: dict[str, str] | None, path: str, now: float | None = None, ref: int | _PathDir | None = None
) -> float | None:
    """The game's relative clock right now, estimated: `alive_clock` (written with the heartbeat) plus
    the host time since status.txt was written (its mtime, stamped by the OS). None if either is unknown
    or the mtime is in the future by more than FUTURE_SLOP."""
    if status is None:
        return None
    try:
        alive = float(status["alive_clock"])
    except (KeyError, ValueError):
        return None
    if not math.isfinite(alive) or alive < 0:
        return None
    current = time.time() if now is None else now
    _recheck(ref)
    try:
        age = current - os.lstat(path).st_mtime
    except OSError:
        return None
    if age < -FUTURE_SLOP:
        return None
    return alive + max(age, 0.0)


def heartbeat_age(
    status: dict[str, str] | None,
    now: float | None = None,
    path: str | None = None,
    ref: int | _PathDir | None = None,
) -> float | None:
    """Seconds since the game last wrote status.txt, or None if unknown.

    The game's own wall clock is quantized (float32 under Direct3D 9: 128 s steps, so `epoch` can be
    ~127 s off either way); the file's mtime is stamped by the OS on the host's clock and is exact.
    So the age is `now - mtime` of `path`; the game's `epoch` is only a fallback when the stat fails.
    An mtime more than FUTURE_SLOP seconds ahead of the host clock is not a heartbeat (None, never
    "fresh"); a smaller negative age is clock skew and reads as 0.
    """
    current = time.time() if now is None else now
    if path is not None:
        _recheck(ref)
        try:
            age = current - os.lstat(path).st_mtime
        except OSError:
            # The file vanished or is unreadable: fall through to the game's own epoch fallback below.
            pass
        else:
            if age < -FUTURE_SLOP:
                return None
            return max(age, 0.0)
    if status is None:
        return None
    try:
        age = current - float(status["epoch"])
    except (KeyError, ValueError):
        return None
    return None if age < -FUTURE_SLOP else max(age, 0.0)


def diagnose(d: str, ref: int | _PathDir | None = None) -> tuple[int, str]:
    """Explain a missing reply from status.txt. Returns (exit code, message).

    With `ref` (the checked exchange directory) the reads go through the same identity re-check as every
    other file operation and a mismatch raises ReplError(EXIT_REFUSED).
    """
    _recheck(ref)
    status = read_status(d, dir_fd=ref)
    age = heartbeat_age(status, path=os.path.join(d, "status.txt"), ref=ref)
    if status is None or age is None or age > HEARTBEAT_FRESH:
        shown = "no usable status.txt" if age is None else f"status.txt is {age:.0f} s old"
        return EXIT_TIMEOUT, (
            f"game is not polling ({shown}): not running, module not loaded, at the "
            "main menu, or the main thread is blocked"
        )
    if status.get("enabled") != "true":
        return EXIT_OFF, "the console is switched off: the user must create the ENABLE file"
    if status.get("disabled_reason"):
        return EXIT_TIMEOUT, f"module disabled itself: {status['disabled_reason']}"
    return EXIT_TIMEOUT, f"game is polling (heartbeat {age:.1f} s old) but did not answer in time"


def _status_command(d: str, ref: int | _PathDir | None = None) -> int:
    _recheck(ref)
    status = read_status(d, dir_fd=ref)
    age = heartbeat_age(status, path=os.path.join(d, "status.txt"), ref=ref)
    print(f"directory: {d}")
    for name in ("ENABLE", "ENABLE_WRITE"):
        print(f"{name}: {'present' if _exists_in(ref, d, name) else 'absent'}")
    if status is None:
        print("status.txt: missing or unreadable")
        return EXIT_TIMEOUT
    for key, value in status.items():
        print(f"{key}: {value}")
    print(f"heartbeat_age_s: {age:.1f}" if age is not None else "heartbeat_age_s: unknown")
    if age is None or age > HEARTBEAT_FRESH:
        print("game is not polling (heartbeat stale)", file=sys.stderr)
        return EXIT_TIMEOUT
    if "session" not in status:
        print(OLD_MODULE_MESSAGE, file=sys.stderr)
        return EXIT_TIMEOUT
    older = older_module_message(status)
    if older is not None:
        print(older, file=sys.stderr)
        return EXIT_TIMEOUT
    if status.get("enabled") != "true":
        print("the console is switched off: the user must create the ENABLE file", file=sys.stderr)
        return EXIT_OFF
    if status.get("disabled_reason"):
        print(f"module disabled itself: {status['disabled_reason']}", file=sys.stderr)
        return EXIT_TIMEOUT
    return EXIT_OK


def new_id() -> str:
    return time.strftime("%Y%m%d%H%M%S") + f"-{os.getpid()}-{secrets.token_hex(2)}"


def build_request(
    code: str, budget: float | None, write: bool, reset: bool, session: str | None = None, notafter: float | None = None
) -> bytes:
    """The request bytes. With `session`, the first line is `#@ session <token>` (the game refuses
    a request without its current token); with `notafter`, the second line is `#@ notafter <t>`, the
    deadline on the game's relative clock (the game answers 'stale' to a request without a valid one)."""
    head = []
    if session is not None:
        head.append(f"#@ session {session}")
    if notafter is not None:
        head.append(f"#@ notafter {notafter:.3f}")
    if reset:
        head.append("#@ reset")
    if write:
        head.append("#@ write")
    if budget is not None:
        head.append(f"#@ budget {budget:g}")
    text = "\n".join(head + [code]) if head else code
    if not text.endswith("\n"):
        text += "\n"
    return text.encode("utf-8")


def parse_reply(data: bytes, rid: str) -> tuple[dict[str, str], str, str]:
    """Return (header, stdout, traceback). Raises ReplError(6) when malformed."""
    marker = data.find(b"\n---\n")
    if marker < 0:
        raise ReplError(EXIT_MALFORMED, "reply has no header separator")
    header: dict[str, str] = {}
    for line in data[:marker].decode("utf-8", "replace").split("\n"):
        key, sep, value = line.partition(": ")
        if not sep:
            raise ReplError(EXIT_MALFORMED, f"bad header line {line!r}")
        header[key] = value
    if header.get("id") != rid:
        raise ReplError(EXIT_MALFORMED, f"reply id {header.get('id')!r} != request id {rid!r}")
    try:
        n = int(header["stdout_bytes"])
        header["status"]
    except (KeyError, ValueError):
        raise ReplError(EXIT_MALFORMED, "reply lacks status or stdout_bytes") from None
    body = data[marker + 5 :]
    if n < 0 or n > len(body):
        raise ReplError(EXIT_MALFORMED, "stdout_bytes exceeds the reply body")
    out = body[:n].decode("utf-8", "replace")
    rest = body[n:]
    tb = ""
    if rest:
        tag = b"--- traceback ---\n"
        if not rest.startswith(tag):
            raise ReplError(EXIT_MALFORMED, "unexpected bytes after stdout")
        tb = rest[len(tag) :].decode("utf-8", "replace")
    return header, out, tb


def _read_reply(fd: int | _PathDir, rid: str) -> bytes | None:
    """Open rep-<id>.txt inside the checked directory: no symlinks, regular file (owned by us on POSIX), size-capped."""
    try:
        rfd = _open_in(fd, "", f"rep-{rid}.txt", os.O_RDONLY | _NONBLOCK)
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ReplError(EXIT_MALFORMED, f"cannot open the reply safely: {exc}") from None
    try:
        st = os.fstat(rfd)
        # The owner check is POSIX-only (Windows has no uid; see the platform model above).
        if not stat.S_ISREG(st.st_mode) or (_HARDENED and st.st_uid != os.getuid()):
            raise ReplError(EXIT_MALFORMED, "the reply is not a regular file owned by you")
        if st.st_size > REPLY_CAP:
            raise ReplError(EXIT_MALFORMED, f"the reply is {st.st_size} bytes; the limit is {REPLY_CAP}")
        data = b""
        while len(data) <= REPLY_CAP:
            chunk = os.read(rfd, 65536)
            if not chunk:
                break
            data += chunk
        if len(data) > REPLY_CAP:
            raise ReplError(EXIT_MALFORMED, "the reply grew beyond the size limit")
        return data
    finally:
        os.close(rfd)


def _wait_reply(fd: int | _PathDir, rid: str, until: float) -> bytes | None:
    while True:
        data = _read_reply(fd, rid)
        if data is not None:
            return data
        if time.monotonic() >= until:
            return None
        time.sleep(POLL_SLEEP)


def _withdraw(fd: int | _PathDir, rid: str) -> str:
    """Try to take the request back. 'withdrawn' = never ran; 'consumed' = the game claimed it;
    'unknown' = could not tell (the request may still run)."""
    try:
        _unlink_in(fd, f"req-{rid}.py")
    except FileNotFoundError:
        return "consumed"
    except OSError:
        return "unknown"
    return "withdrawn"


def _finish(header: dict[str, str], out: str, tb: str) -> int:
    status = header["status"]
    detail = header.get("detail", "")
    if out:
        sys.stdout.write(out)
        sys.stdout.flush()
    if status == "ok":
        return EXIT_OK
    if status == "error":
        sys.stderr.write(tb)
        return EXIT_REMOTE_ERROR
    if status == "timeout":
        print(f"error: execution budget exceeded in the game ({detail}); the code was interrupted", file=sys.stderr)
        sys.stderr.write(tb)
        return EXIT_TIMEOUT
    if status == "stale":
        print(f"error: the game discarded the request as stale ({detail}); it did not run", file=sys.stderr)
        return EXIT_TIMEOUT
    if status == "readonly":
        print(f"error: refused by the game (read-only mode): {detail}", file=sys.stderr)
        return EXIT_REFUSED
    if status == "refused" and detail.startswith("purged"):
        print(f"error: {detail}", file=sys.stderr)
        return EXIT_OFF
    if status == "refused":
        print(f"error: refused by the game: {detail}", file=sys.stderr)
        return EXIT_REFUSED
    if status == "badsession":
        print(f"error: the game refused the session token ({detail}); the request did not run", file=sys.stderr)
        return EXIT_TIMEOUT
    if status == "toolarge":
        print(f"error: {detail}", file=sys.stderr)
        return EXIT_USAGE
    print(f"error: unknown reply status {status!r}", file=sys.stderr)
    return EXIT_MALFORMED


def execute(
    d: str,
    code: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    budget: float | None = None,
    write: bool = False,
    reset: bool = False,
) -> int:
    """Send one request and wait for its reply. Returns the exit code."""
    eff_budget = DEFAULT_BUDGET if budget is None else budget
    if not (math.isfinite(eff_budget) and 0 < eff_budget <= MAX_BUDGET):
        raise ReplError(EXIT_USAGE, f"--budget must be a number in (0, {MAX_BUDGET:g}] seconds")
    if not math.isfinite(timeout) or timeout <= eff_budget + 0.5:
        raise ReplError(
            EXIT_USAGE, f"--timeout must be finite and exceed the budget by more than 0.5 s (budget {eff_budget:g})"
        )
    # The token line is at most 8 + 64 bytes, so size-check the request with a worst-case token.
    size = len(build_request(code, budget, write, reset, "0" * MAX_TOKEN, 1e15))
    if size > REQUEST_CAP:
        raise ReplError(EXIT_USAGE, f"request is {size} bytes; the limit is {REQUEST_CAP}")
    fd = open_dir(d)
    try:
        return _execute_in(fd, d, (code, budget, write, reset), timeout, eff_budget)
    finally:
        close_dir(fd)


class _SessionRejected(Exception):
    """The game answered 'badsession' for the token we used."""

    def __init__(self, header: dict[str, str]):
        super().__init__(header.get("detail", ""))
        self.header = header


class _Stale(Exception):
    """The game answered 'stale': its deadline for the request had passed, so it did not run."""

    def __init__(self, header: dict[str, str]):
        super().__init__(header.get("detail", ""))
        self.header = header


def _current_token(fd: int | _PathDir, d: str, status: dict[str, str] | None = None) -> tuple[str, float]:
    """(session token, estimated game clock now) from a status.txt (read now unless given), or raise ReplError."""
    if status is None:
        status = read_status(d, dir_fd=fd)
    token = session_token(status)
    if token is None:
        age = heartbeat_age(status, path=os.path.join(d, "status.txt"), ref=fd)
        if status is not None and age is not None and age <= HEARTBEAT_FRESH and "session" not in status:
            raise ReplError(EXIT_TIMEOUT, OLD_MODULE_MESSAGE)
        _, message = diagnose(d, fd)
        raise ReplError(EXIT_TIMEOUT, "cannot send: status.txt has no valid session token (" + message + ")")
    older = older_module_message(status)
    if older is not None:
        raise ReplError(EXIT_TIMEOUT, older)
    clock = game_clock_estimate(status, os.path.join(d, "status.txt"), ref=fd)
    if clock is None:
        raise ReplError(
            EXIT_TIMEOUT,
            "cannot send: status.txt has no usable alive_clock or its mtime is "
            "unusable, so no game-side deadline can be computed",
        )
    return token, clock


def _payload(parts: tuple[str, float | None, bool, bool], token: str, clock: float, timeout: float) -> bytes:
    code, budget, write, reset = parts
    return build_request(code, budget, write, reset, token, clock + timeout + DEADLINE_SLACK)


def _execute_in(
    fd: int | _PathDir, d: str, parts: tuple[str, float | None, bool, bool], timeout: float, eff_budget: float
) -> int:
    code, budget, write, reset = parts
    if not _exists_in(fd, d, "ENABLE"):
        raise ReplError(
            EXIT_OFF,
            f"the console is switched off: the user must create {os.path.join(d, 'ENABLE')} (this tool never does)",
        )
    if write and not _exists_in(fd, d, "ENABLE_WRITE"):
        raise ReplError(EXIT_REFUSED, "--write needs the user to create ENABLE_WRITE")

    # Each attempt re-reads status.txt: the token (a restart changes it) and the clock estimate (the
    # deadline is the moment this attempt stops waiting, on the game's own clock). Two kinds of refusal
    # mean "it did not run, and a fresh status.txt may fix it", so each is retried exactly once:
    # 'badsession' only if the token changed, 'stale' (the estimate was too low) unconditionally.
    retried = False
    status = None
    while True:
        token, clock = _current_token(fd, d, status)
        try:
            return _send_once(fd, d, _payload(parts, token, clock, timeout), timeout, eff_budget)
        except _SessionRejected as rejected:
            status = read_status(d, dir_fd=fd)  # the next attempt uses this reading
            newer = session_token(status)
            detail = rejected.header.get("detail", "")
            if retried:
                print(
                    f"error: the game refused the session token again ({detail}); the request did not run",
                    file=sys.stderr,
                )
                return EXIT_TIMEOUT
            if newer is None or newer == token:
                print(
                    f"error: the game refused the session token ({detail}) and status.txt shows no newer one; "
                    "the request did not run",
                    file=sys.stderr,
                )
                return EXIT_TIMEOUT
        except _Stale as stale:
            if retried:
                print(
                    f"error: the game discarded the request as stale again ({stale.header.get('detail', '')}); "
                    "it did not run",
                    file=sys.stderr,
                )
                return EXIT_TIMEOUT
            status = None  # re-read: the clock estimate was too low
        retried = True


def _send_once(fd: int | _PathDir, d: str, payload: bytes, timeout: float, eff_budget: float) -> int:
    rid = new_id()
    tmp = f"req-{rid}.tmp"
    final = f"req-{rid}.py"
    # O_EXCL makes the create fail on any existing name (a planted symlink included), on every OS.
    rfd = _open_in(fd, d, tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(rfd, "wb") as f:
            f.write(payload)
        _replace_in(fd, tmp, final)
    except BaseException:
        try:
            _unlink_in(fd, tmp)
        except OSError:
            # Best-effort cleanup of our own temp file; the original exception is re-raised below
            # and must not be masked by a failure to delete.
            pass
        raise

    try:
        reply = _wait_reply(fd, rid, time.monotonic() + timeout)
    except KeyboardInterrupt:
        outcome = _withdraw(fd, rid)
        print(f"error: interrupted; {_outcome_text(outcome)}", file=sys.stderr)
        return EXIT_TIMEOUT
    if reply is None:
        outcome = _withdraw(fd, rid)
        if outcome == "withdrawn":
            code_, message = diagnose(d, fd)
            print(f"error: timed out after {timeout:g} s; the request was withdrawn and did NOT run", file=sys.stderr)
            print(message, file=sys.stderr)
            return code_
        if outcome == "unknown":
            print(
                f"error: timed out after {timeout:g} s and the request could not be withdrawn; it MAY still run",
                file=sys.stderr,
            )
            print(diagnose(d, fd)[1], file=sys.stderr)
            return EXIT_TIMEOUT
        # Consumed by the game: it is running or has run. Wait out the budget.
        try:
            reply = _wait_reply(fd, rid, time.monotonic() + eff_budget + 2.0)
        except KeyboardInterrupt:
            print("error: interrupted; the request WAS picked up by the game and ran (or is running)", file=sys.stderr)
            return EXIT_TIMEOUT
        if reply is None:
            print(
                "error: the request WAS picked up by the game and ran (or is still running), "
                "but no reply arrived; side effects may have happened",
                file=sys.stderr,
            )
            print(diagnose(d, fd)[1], file=sys.stderr)
            return EXIT_TIMEOUT
    try:
        header, out, tb = parse_reply(reply, rid)
    finally:
        try:
            _unlink_in(fd, f"rep-{rid}.txt")
        except OSError:
            # Best-effort removal of the consumed reply; the result is already in hand and a
            # stale rep- file is swept by the game or the next run.
            pass
    if header["status"] == "badsession":
        raise _SessionRejected(header)
    if header["status"] == "stale":
        raise _Stale(header)
    return _finish(header, out, tb)


def _outcome_text(outcome: str) -> str:
    if outcome == "withdrawn":
        return "the request was withdrawn and did NOT run"
    if outcome == "consumed":
        return "the request WAS picked up by the game and ran (or is running)"
    return "the request could not be withdrawn and MAY still run"


def add_exec_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser(
        "exec",
        help="run Python inside the live game through AgentRepl (the user must enable it)",
        description="Run Python in the running game via the AgentRepl file exchange. "
        "Exit codes: 0 ok, 1 remote exception, 2 usage, 3 timeout/not polling, "
        "4 switched off, 5 refused, 6 reply malformed.",
    )
    p.add_argument("-c", dest="code", metavar="CODE", help="source to run")
    p.add_argument("file", nargs="?", help="file to run, or - for stdin")
    p.add_argument(
        "--dir",
        help=f"exchange directory (else ${ENV_DIR}, else ${ENV_MOD_DIR}/{EXCHANGE_SUBDIR})",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=DEFAULT_TIMEOUT,
        help="seconds to wait for the reply (default 15; must exceed budget + 0.5)",
    )
    p.add_argument(
        "--budget", type=float, default=None, help="game-side execution budget in seconds (default 2, maximum 10)"
    )
    p.add_argument(
        "--write", action="store_true", help="ask to bypass the refuse list (needs the user's ENABLE_WRITE file)"
    )
    p.add_argument("--reset", action="store_true", help="rebuild the persistent namespace first")
    p.add_argument("--status", action="store_true", help="print the heartbeat and switch state, then exit")
    p.set_defaults(func=run_exec)


def run_exec(args: argparse.Namespace) -> int:
    # SIGTERM acts like Ctrl-C (withdraw the request) where the OS can deliver it. On Windows nothing
    # delivers SIGTERM gracefully (os.kill is TerminateProcess), so only Ctrl-C (SIGINT) withdraws there.
    old = None
    try:
        old = signal.signal(signal.SIGTERM, signal.default_int_handler)
    except (ValueError, OSError):
        old = None
    try:
        return _run_exec(args)
    finally:
        if old is not None:
            signal.signal(signal.SIGTERM, old)


def _run_exec(args: argparse.Namespace) -> int:
    try:
        d = resolve_dir(args.dir)
        if args.status:
            ref = open_dir(d)
            try:
                return _status_command(d, ref)
            finally:
                close_dir(ref)
        if args.code is not None and args.file is not None:
            raise ReplError(EXIT_USAGE, "give either -c CODE or a FILE, not both")
        if args.code is not None:
            code = args.code
        elif args.file == "-":
            code = sys.stdin.read()
        elif args.file is not None:
            try:
                with open(args.file, encoding="utf-8", errors="replace") as f:
                    code = f.read()
            except OSError as exc:
                raise ReplError(EXIT_USAGE, f"cannot read {args.file}: {exc}") from None
        elif args.reset:
            code = ""
        else:
            raise ReplError(EXIT_USAGE, "give -c CODE, a FILE, or - for stdin (or --reset / --status)")
        return execute(d, code, timeout=args.timeout, budget=args.budget, write=args.write, reset=args.reset)
    except ReplError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.code
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
