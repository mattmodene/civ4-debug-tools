# AgentRepl - a file-exchange Python console for a running Civ4 game.
#
# Runs INSIDE the game's embedded Python 2.4 (Wine/Proton) and is also imported
# by the host test-suite under Python 3, so it is written in the subset that is
# valid in both: no "with", no "except E as e", no conditional expressions, no
# combined try/except/finally, no print statement, no b'' literals, no
# str.format, no json/hashlib, no any/all/partition. A test enforces this.
#
# Safety model (see README "Remote console (AgentRepl)"):
#   * does nothing unless <exchange dir>/ENABLE exists (checked on every poll);
#   * a request is read-only unless <dir>/ENABLE_WRITE exists AND the request carries
#     "#@ write"; read-only code must pass a token-based allowlist of read names
#     (check_readonly), then an older refuse list (refuse_reason);
#   * NOT a sandbox: both checks are name-based guards against accidents only;
#   * every request is recorded in <dir>/audit.log;
#   * never raises into the game.
#
# Exchange protocol (all files in the exchange directory):
#   req-<id>.tmp -> req-<id>.py   host writes the request, then renames
#   rep-<id>.tmp -> rep-<id>.txt  this module writes the reply, then renames
#   status.txt                    heartbeat, rewritten in place; its first line is
#                                 "session: <token>", this process's session token
#   audit.log                     one line per request
# Every request must start with the line "#@ session <token>" (the token read from status.txt);
# a request with no token, or another one, is refused and answered with status "badsession".
# Its second line must be "#@ notafter <deadline>", a time on this game's relative clock (_clock());
# a request whose deadline has passed, or that has no valid notafter line, is answered "stale".
# <id> is [0-9A-Za-z-]+ .  Reply names are unique per request, so a rename never
# targets an existing file (Python 2.4 on Windows cannot rename over one).

import math
import os
import re
import stat
import sys
import time
import traceback

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

VERSION = "3"
POLL_INTERVAL = 0.25     # seconds between polls while enabled
OFF_INTERVAL = 1.0       # seconds between polls while switched off
HEARTBEAT_INTERVAL = 2.0
DEFAULT_BUDGET = 2.0
MAX_BUDGET = 10.0
OUTPUT_CAP = 64 * 1024
REQUEST_CAP = 64 * 1024
TRACEBACK_CAP = 16 * 1024
# REPLAY PROTECTION. Two exact, wall-clock-free checks, both made before anything runs:
#   * SESSION TOKEN. At module load the game makes a random token (_make_token), publishes it as the
#     first line of status.txt, and refuses (audited, "badsession") every request whose first line is
#     not "#@ session <token>". A request left over from an earlier game session, or written against
#     an earlier status.txt, can never carry this session's token.
#   * PER-REQUEST DEADLINE. The second line must be "#@ notafter <deadline>", a time on the relative
#     clock. The host computes it from status.txt: alive_clock + (host_now - status mtime) + its own
#     timeout + 2, so it is the moment the host stops waiting, in the game's own time. The game
#     refuses (audited, "stale") a request whose deadline has passed on its own _clock(), and one with
#     no valid notafter line. This covers what the token cannot see: a request of THIS session that
#     the host abandoned (for example after SIGKILL) while the game thread was blocked and not polling.
# CLOCKS. Inside the game Direct3D 9 puts the FPU in single precision, so time.time() is quantized to
# float32 resolution (128 s near 1.79e9) and can be ~127 s off, in either direction. The relative
# clock (the monotonic one, time.clock in the game) stays exact, so NO request decision uses the wall
# clock or a file mtime: the `epoch` in status.txt and the audit "epoch_coarse" are informational only.
# There is deliberately no separate "first seen N seconds ago" rule any more: every request now carries
# an explicit deadline on the exact clock, which bounds its age by construction, and a rule with a fixed
# 60 s limit would only refuse a request the host was still willing to wait for.
# TRACKING CAP. At most SEEN_CAP request files are tracked. A NEW request that would exceed the cap is
# refused (deleted, audited, answered "refused"). The tracking is only a bound on the queue.
# While ENABLE is absent every queued req-*.py is deleted (audited), so nothing queued while the
# console is off can run after it is switched on.
MAX_NOTAFTER_DIGITS = 20
SEEN_CAP = 256
PER_POLL_LIMIT = 8       # purge / overflow-refusal actions per poll, so a flood cannot freeze a frame
AUDIT_ROTATE = 1024 * 1024
MAX_FAILS = 5

# Test hook: when not None, the exchange directory to use.
EXCHANGE_DIR = None

_PY3 = sys.version_info[0] >= 3

if hasattr(time, "clock"):
    _clock = time.clock
else:
    _clock = time.perf_counter

def _hex_of(raw):
    out = []
    for c in raw:
        if isinstance(c, int):
            n = c
        else:
            n = ord(c)
        out.append("%02x" % n)
    return "".join(out)


def _make_token():
    """A per-session token: 16 random bytes as 32 hex digits, no wall-clock precision needed.

    os.urandom exists in Python 2.4 (new in 2.4; CryptGenRandom on Windows, so under Wine too) and is
    preferred: pid, the relative clock and id() are nearly the same in every game session (the clock
    starts near 0 at launch, addresses repeat), so they are only the fallback when urandom is missing
    or fails. The fallback still differs between sessions through the pid and the coarse time.
    """
    try:
        return _hex_of(os.urandom(16))
    except Exception:
        mask = 0xFFFFFFFF
        parts = (os.getpid() & mask, int(_clock() * 1000000.0) & mask, id(_make_token) & mask,
                 int(time.time()) & mask)
        return "".join(["%08x" % p for p in parts])


SESSION_TOKEN = _make_token()

try:
    _Base = BaseException
except NameError:
    _Base = Exception


class Timeout(_Base):
    """Raised from the trace function when the execution budget is spent.

    Derives from BaseException where that exists, so user code that says
    "except Exception" cannot swallow it (Python 2.4 has no BaseException; there
    it can be swallowed, which is a documented limit).
    """


# --------------------------------------------------------------------------
# refuse list (best effort, token scan; see header: not a sandbox)

_REFUSE_WORDS = [
    "saveGame", "saveReplay", "doControl", "setWinner", "setGameState",
    "setActivePlayer", "setGameTurn", "setAIAutoPlay", "setForcedAIAutoPlay",
    "toggleDebugMode", "sendModNetMessage", "CyMessageControl",
    "exitWorldBuilder", "execfile", "__import__", "__builtins__",
    "__subclasses__", "__globals__", "subprocess", "thread", "_thread",
    "threading", "exec", "open",
]
_REFUSE_REGEXES = [
    ("sys.exit", re.compile(r"\bsys\s*\.\s*exit")),
    ("os.", re.compile(r"\bos\s*\.")),
    ("file(", re.compile(r"\bfile\s*\(")),
    ("eval(", re.compile(r"\beval\s*\(")),
    ("compile(", re.compile(r"\bcompile\s*\(")),
    ("exit(", re.compile(r"\b(exit|quit)\s*\(")),
]
_ALLOWED_IMPORTS = [
    "CvPythonExtensions", "math", "string", "time", "re", "itertools",
    "collections", "BugUtil", "CvUtil",
]
_IMPORT_RE = re.compile(r"(?:^|;)[ \t]*import[ \t]+([^\n;]+)", re.M)
_FROM_RE = re.compile(r"(?:^|;)[ \t]*from[ \t]+([\w.]+)[ \t]+import\b", re.M)
_WORD_RES = {}


def refuse_reason(src):
    """Return a short reason string if src contains a refused construct, else None."""
    for word in _REFUSE_WORDS:
        rx = _WORD_RES.get(word)
        if rx is None:
            rx = re.compile(r"\b" + re.escape(word) + r"\b")
            _WORD_RES[word] = rx
        if rx.search(src):
            return "contains '%s'" % word
    for label, rx in _REFUSE_REGEXES:
        if rx.search(src):
            return "contains '%s'" % label
    for m in _IMPORT_RE.finditer(src):
        for part in m.group(1).split(","):
            name = part.strip().split(" ")[0].strip()
            if name and name.split(".")[0] not in _ALLOWED_IMPORTS:
                return "imports '%s'" % name
    for m in _FROM_RE.finditer(src):
        name = m.group(1)
        if name.split(".")[0] not in _ALLOWED_IMPORTS:
            return "imports from '%s'" % name
    return None


# --------------------------------------------------------------------------
# read-only allowlist (Bug A). Read-only means: NOT (ENABLE_WRITE present AND "#@ write" requested).
#
# This is a NAME-BASED check on the token stream. It guards against ACCIDENTS (an agent that meant
# to look and called a setter), not against a determined caller: it is NOT a sandbox. It uses the
# tokenize module (in Python 2.4 and 3; the ast module does not exist on 2.4) and never executes
# anything. What it enforces:
#   * every attribute (a NAME right after '.') must be a read: get*/is*/can*/has*/count*/find*
#     (the prefix followed by an upper-case letter, a digit, '_' or the end), an UPPER_CASE
#     constant, or a name in _READ_ATTRS (reads seen in the live inspections plus plain
#     str/list/dict/math/time methods). Aliasing (f = p.changeGold), comprehensions and
#     map/apply tricks all still name the attribute, so they are refused with it;
#   * _DENIED_NAMES (setattr, exec, eval, open, ...) are refused wherever they appear; getattr is
#     allowed only as getattr(x, 'literal read name'[, default]);
#   * any NAME containing "__" is refused (no __class__/__dict__/__globals__ walking);
#   * assignment, augmented assignment, del and for/as targets may not be attributes, and a
#     subscript target must be a local dict/list built in this request (or bound to one in the
#     namespace), so groups[gid] = [] works and gc.x[0] = 1 does not;
#   * a token error means refused. lambda is allowed: its body is scanned like any other code,
#     so it hides no call from the checks above. Backticks do not tokenize and are refused.
#   * every import statement is refused (math and clock are pre-bound in the namespace), as are
#     _NEVER_NAMES (BugUtil, getFunction, sleep, ...), the RNG-advancing getters (_RNG_DENIED), a
#     coding cookie or BOM, and, after a write-mode request, the namespace is rebuilt.
# Imports and the other refuse-list words are still judged afterwards by refuse_reason().
# NOT preventable by names: pure computation that stalls in one C call (9**9**9**9, a catastrophic
# regex); the settrace budget cannot interrupt a single C call either.

_READ_PREFIX_RE = re.compile(r"(get|is|can|has|count|find)([A-Z0-9_]|\Z)")
_CONSTANT_RE = re.compile(r"[A-Z][A-Z0-9_]*\Z")
# NOTE: this list was derived from ONE mod's DLL sources (Caveman2Cosmos, see below) and may be
# incomplete for another mod, whose DLL can bind more RNG-advancing getters. Review it before using
# this module with a different game-core DLL.
# The "get" names found to hand out or advance a synchronized game RNG; NOT a proven-complete list.
# Found by reading the .def( rows of the Cy*.cpp tables at C2C bcf1d3c58 (3009 rows) for CvRandom targets
# and their callers: CyGame.getSorenRand / getSorenRandNum / getMapRand / getMapRandNum,
# CyGlobalContext.getASyncRand (bound as "getASyncRand"), and CyPlayer.getNewCityName (CvPlayer.cpp
# getNewCityName -> getCivilizationCityName calls getSorenRandNum). CyMap.syncRandPlot also draws, but it
# is not a read prefix and stays refused as an unknown name. The other names with "Rand" in them
# (getMaxWarRand, getRandAppearance, ...) are pure Info reads of XML data and are allowed.
_RNG_DENIED = ["getSorenRand", "getSorenRandNum", "getMapRand", "getMapRandNum", "getASyncRand",
               "getNewCityName"]
# "get" names that call a function by name
_GETTER_DENIED = ["getFunction", "lookupFunction", "lookupModule", "callFunction", "bindFunction",
                  "deferCall"]
_READ_ATTRS = [
    # game reads that do not follow the get/is/can/has prefix (from the live inspections)
    "plot", "groups", "firstUnit", "nextUnit", "readyToMove", "baseCombatStr", "movesLeft",
    "maxMoves", "defenseModifier", "firstCity", "nextCity", "firstSelectionGroup",
    "nextSelectionGroup",
    # str / list / dict / tuple methods
    "append", "extend", "pop", "sort", "reverse", "keys", "values", "items", "get", "has_key",
    "setdefault", "copy", "join", "split", "strip", "lstrip", "rstrip", "format", "lower",
    "upper", "startswith", "endswith", "replace", "index", "rfind", "zfill", "isdigit",
    # math (the pre-bound module; read-only code cannot import anything). Pure functions and
    # constants only; none of these names is a Cy method (checked against every .def row).
    # ("log" is NOT here: CyGame.log(file, text) writes a log file; log10 is fine.)
    "pi", "e", "sqrt", "floor", "ceil", "fabs", "fmod", "exp", "pow", "hypot", "sin", "cos", "tan",
    "asin", "acos", "atan", "atan2", "sinh", "cosh", "tanh", "degrees", "radians", "log10", "modf",
    "frexp", "ldexp",
]
# NOTE: the RNG getters found are denied by exact name (_RNG_DENIED), not by a "Rand" substring, so pure
# Info reads such as getMaxWarRand and getRandAppearance stay allowed. A NEW RNG-advancing method
# in a future build would have to be added to that list.
_DENIED_NAMES = [
    "setattr", "delattr", "exec", "eval", "compile", "execfile", "__import__", "open", "file",
    "reload", "globals", "locals", "vars", "input", "raw_input",
    # stdin / interpreter-exit builtins that site may install
    "help", "license", "credits", "copyright", "quit", "exit",
]
# Refused as ANY name (also as an attribute, also if it was imported into the namespace): they call
# a function or module by name, or sleep inside one C call the tracer cannot interrupt.
_NEVER_NAMES = [
    "BugUtil", "CvUtil", "getFunction", "lookupFunction", "lookupModule", "callFunction",
    "bindFunction", "deferCall", "Function", "sleep",
]
_CODING_RE = re.compile(r"coding[:=]")
_AUG_OPS = ["+=", "-=", "*=", "/=", "%=", "&=", "|=", "^=", "<<=", ">>=", "**=", "//="]
_CONTAINER_BUILDERS = ["dict", "list", "set", "defaultdict", "sorted", "range", "map", "zip"]


def _is_read_attr(name):
    if name in _RNG_DENIED or name in _GETTER_DENIED or name in _NEVER_NAMES:
        return False
    if name in _READ_ATTRS:
        return True
    return _READ_PREFIX_RE.match(name) is not None or _CONSTANT_RE.match(name) is not None


def _tokenize_all(src):
    """List of (type, string) without comments and layout; raises on a tokenize error."""
    import tokenize
    out = []
    readline = StringIO(src).readline
    for tok in tokenize.generate_tokens(readline):
        ttype = tok[0]
        text = tok[1]
        if ttype == tokenize.ERRORTOKEN and text.strip() == "":
            continue
        if ttype in (tokenize.COMMENT, tokenize.NL, tokenize.INDENT, tokenize.DEDENT,
                     tokenize.ENDMARKER):
            continue
        out.append((ttype, text))
    return out


def _getattr_problem(toks, i):
    """toks[i] is NAME getattr. None if it is getattr(<expr>, '<read name>'[, default])."""
    import tokenize
    n = len(toks)
    if i + 1 >= n or toks[i + 1][1] != "(":
        return "'getattr' may only be called as getattr(obj, 'literal read name')"
    depth = 0
    j = i + 1
    while j < n:
        text = toks[j][1]
        if text in ("(", "[", "{"):
            depth = depth + 1
        elif text in (")", "]", "}"):
            depth = depth - 1
            if depth == 0:
                return "'getattr' needs a literal attribute name as its second argument"
        elif text == "," and depth == 1:
            break
        j = j + 1
    if j + 2 >= n:
        return "'getattr' needs a literal attribute name as its second argument"
    lit = toks[j + 1]
    after = toks[j + 2][1]
    if lit[0] != tokenize.STRING or after not in (",", ")"):
        return "'getattr' needs a literal attribute name as its second argument"
    body = lit[1].lstrip("uUrR")
    if len(body) < 2 or body[0] not in ("'", '"') or body[:3] in ("'''", '"""') or "\\" in body:
        return "'getattr' needs a plain string literal as its attribute name"
    name = body[1:-1]
    if not _is_read_attr(name):
        return "'getattr' of '%s' is not an allowed read" % name
    return None


def _split_statements(toks):
    """Token lists, one per logical statement (split at NEWLINE and at ';' outside brackets)."""
    import tokenize
    out = []
    cur = []
    depth = 0
    for tok in toks:
        text = tok[1]
        if tok[0] == tokenize.OP:
            if text in ("(", "[", "{"):
                depth = depth + 1
            elif text in (")", "]", "}"):
                depth = depth - 1
        if tok[0] == tokenize.NEWLINE or (text == ";" and tok[0] == tokenize.OP and depth == 0):
            if cur:
                out.append(cur)
            cur = []
            continue
        cur.append(tok)
    if cur:
        out.append(cur)
    return out


def _depth0_runs(toks):
    """Split a statement at depth 0 into [segments separated by '=' / augmented op].

    Returns (segments, op): segments are token lists; op is None, '=' (one or more) or an aug op.
    """
    segs = []
    cur = []
    depth = 0
    op = None
    for tok in toks:
        text = tok[1]
        if text in ("(", "[", "{"):
            depth = depth + 1
        elif text in (")", "]", "}"):
            depth = depth - 1
        if depth == 0 and text == "=":
            segs.append(cur)
            cur = []
            op = "="
            continue
        if depth == 0 and text in _AUG_OPS:
            segs.append(cur)
            cur = []
            op = text
            continue
        cur.append(tok)
    segs.append(cur)
    return segs, op


def _target_elements(seg):
    """Split one assignment target into tuple elements; each is a list of (text, depth0_flag).

    Parentheses that merely group a tuple target are transparent; [..] subscripts are kept as a
    '[' ... ']' pair whose inside is flagged as not depth 0.
    """
    elems = []
    cur = []
    depth = 0
    for tok in seg:
        text = tok[1]
        if depth == 0 and text == ",":
            elems.append(cur)
            cur = []
            continue
        if depth == 0 and text in ("(", ")"):
            continue
        if text in ("[", "(", "{"):
            cur.append((text, depth == 0))
            depth = depth + 1
            continue
        if text in ("]", ")", "}"):
            depth = depth - 1
            cur.append((text, depth == 0))
            continue
        cur.append((text, depth == 0))
    elems.append(cur)
    return elems


def _target_problem(seg, containers):
    """Describe why an assignment/del target is not allowed, else None."""
    # "if x: y[k] = 1" on one line: the target is what follows the last depth-0 ':'
    depth = 0
    cut = 0
    for idx in range(len(seg)):
        text = seg[idx][1]
        if text in ("(", "[", "{"):
            depth = depth + 1
        elif text in (")", "]", "}"):
            depth = depth - 1
        elif text == ":" and depth == 0:
            cut = idx + 1
    seg = seg[cut:]
    for elem in _target_elements(seg):
        flat = [t for t, top in elem if top]
        if "." in flat:
            k = flat.index(".")
            name = ""
            if k + 1 < len(flat):
                name = flat[k + 1]
            return "assignment to attribute '%s' is not allowed in read-only mode" % name
        if "[" in flat:
            # exactly NAME[...]: one subscript level on a local dict/list (no d[0][1] = ...)
            if (len(flat) != 3 or flat[1] != "[" or flat[0] not in containers):
                return ("item assignment is only allowed as NAME[...] = on a dict or list created in "
                        "the same request (target starts with '%s')" % flat[0])
    return None


def check_readonly(src, ns=None):
    """(True, "") if src only reads game state, else (False, reason). See the block comment above.

    ns, if given, is the persistent namespace: a name bound there to a dict or list counts as a
    local container for item assignment.
    """
    import tokenize
    # An encoding cookie (PEP 263) or a BOM can make Python 2's compile() read the source in another
    # codec than the tokenizer did, so the tokens checked would not be the code that runs.
    # (kept ASCII-only: a raw U+FEFF here would need an encoding declaration on Python 2.4)
    if src[:3] == "\xef\xbb\xbf" or (src[:1] != "" and ord(src[:1]) == 0xFEFF):
        return False, "a byte order mark is not allowed in read-only mode"
    for line in src.split("\n")[:2]:
        if _CODING_RE.search(line):
            return False, "an encoding declaration ('coding:') is not allowed in read-only mode"
    try:
        toks = _tokenize_all(src)
    except Exception:
        return False, "the source could not be tokenized (read-only mode refuses what it cannot read)"
    prev = ""
    for i in range(len(toks)):
        ttype, text = toks[i]
        if ttype == tokenize.ERRORTOKEN:
            return False, "unreadable token %r" % text
        if text == "`":
            return False, "backtick (repr) is not allowed in read-only mode"
        if ttype == tokenize.NAME:
            if text in _NEVER_NAMES:
                return False, "'%s' is refused in read-only mode" % text
            if text == "import":
                return False, ("'import' is refused in read-only mode (the namespace already has gc, game, "
                               "the CvPythonExtensions names, math and clock)")
            if text.find("__") >= 0:
                return False, "name '%s' contains '__'" % text
            if prev == ".":
                if not _is_read_attr(text):
                    return False, "attribute '%s' is not a known read (read-only mode)" % text
            else:
                if text in _DENIED_NAMES:
                    return False, "'%s' is refused in read-only mode" % text
                if text == "getattr":
                    problem = _getattr_problem(toks, i)
                    if problem is not None:
                        return False, problem
        prev = text
    containers = {}
    if ns is not None:
        for key in list(ns.keys()):
            if isinstance(ns[key], (dict, list)):
                containers[key] = 1
    statements = _split_statements(toks)
    for stmt in statements:
        segs, op = _depth0_runs(stmt)
        if op is None:
            continue
        # value is the last segment; names assigned a literal container / constructor are locals
        value = segs[-1]
        for seg in segs[:-1]:
            flat = [tok[1] for tok in seg]
            if len(flat) == 1 and value:
                head = value[0][1]
                if head in ("{", "[") or (head in _CONTAINER_BUILDERS and len(value) > 1
                                          and value[1][1] == "("):
                    containers[flat[0]] = 1
    for stmt in statements:
        segs, op = _depth0_runs(stmt)
        if op is not None:
            for seg in segs[:-1]:
                problem = _target_problem(seg, containers)
                if problem is not None:
                    return False, problem
        # del targets
        # (a 'del' can follow a colon, "if x: del a.b", so look at every 'del' in the statement)
        for k in range(len(stmt)):
            if stmt[k][1] == "del" and stmt[k][0] == tokenize.NAME:
                problem = _target_problem(stmt[k + 1:], containers)
                if problem is not None:
                    return False, problem.replace("assignment to", "del of")
    # for / as targets (also inside comprehensions): between 'for' and 'in', and after 'as'
    for i in range(len(toks)):
        text = toks[i][1]
        if toks[i][0] != tokenize.NAME:
            continue
        if text == "for":
            j = i + 1
            depth = 0
            seg = []
            while j < len(toks):
                t = toks[j][1]
                if t in ("(", "[", "{"):
                    depth = depth + 1
                elif t in (")", "]", "}"):
                    depth = depth - 1
                if depth == 0 and t == "in" and toks[j][0] == tokenize.NAME:
                    break
                seg.append(toks[j])
                j = j + 1
            for tok in seg:
                if tok[1] == "." or tok[1] == "[":
                    return False, "a 'for' target may not be an attribute or item"
        elif text == "as" and i + 2 < len(toks) and toks[i + 2][1] in (".", "["):
            return False, "an 'as' target may not be an attribute or item"
    return True, ""


# --------------------------------------------------------------------------
# small helpers

try:
    _Text = unicode
except NameError:
    _Text = str


def _b(text):
    """Text -> UTF-8 bytes. On 3 str is text; on 2 unicode is text and str is already bytes."""
    if isinstance(text, _Text):
        return text.encode("utf-8", "replace")
    return text


def _join(chunks):
    return _b("").join(chunks)     # empty bytes on 3, empty str (= bytes) on 2


def _read(path, limit):
    """Read at most limit bytes of a REGULAR file; refuse symlinks and special files.

    Protection by platform (be honest about what holds):
      * POSIX Python (the host tests; Linux/macOS): lstat must say regular file (not a symlink,
        FIFO, device or directory), the open uses O_NOFOLLOW and O_NONBLOCK (closing the
        lstat/open race and a blocking FIFO), and the opened descriptor is fstat-checked again.
        A symlink planted as req-<id>.py is refused, never followed.
      * Windows Python 2.4 under Wine (the game): os.lstat is plain stat, os.path.islink is always
        False, and os.O_NOFOLLOW does not exist, so a symlink / reparse point CANNOT be
        detected or refused here. What still holds: the path must be a regular file (S_ISREG
        rejects directories and devices), at most `limit` bytes are read, and only files named
        req-<valid id>.py inside the exchange directory are considered. The real protection under
        Wine is the directory itself: only its owner can plant a link in it.
    """
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        raise IOError("not a regular file: %s" % path)
    flags = os.O_RDONLY
    flags = flags | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise IOError("not a regular file: %s" % path)
        chunks = []
        got = 0
        while got < limit:
            chunk = os.read(fd, limit - got)
            if not chunk:
                break
            chunks.append(chunk)
            got = got + len(chunk)
        data = _join(chunks)
    finally:
        os.close(fd)
    return data


def _write(path, data, mode):
    f = open(path, mode)
    try:
        f.write(data)
    finally:
        f.close()


_NOTED = {}
_NOSYSPATHS = []  # non-empty once `import SystemPaths` has failed


def _note_once(key, text):
    """One diagnostic line per key: into audit.log if the exchange directory exists, else to the game's
    stderr (the game writes it to its Python error log). Never raises."""
    if key in _NOTED:
        return
    _NOTED[key] = 1
    try:
        d = os.path.join(_mod_dir_from_file(), "UserSettings", "AgentRepl")
        if _audit(d, "note " + text):
            return
        sys.stderr.write("AgentRepl: %s\n" % text)
    except Exception:
        pass


def _mod_dir_from_file():
    """The mod directory implied by where this module sits: <mod>/Assets/Python/BUG/AgentRepl.py."""
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.dirname(os.path.dirname(os.path.dirname(here)))


def _exchange_dir():
    if EXCHANGE_DIR is not None:
        return EXCHANGE_DIR
    mod_dir = None
    if not _NOSYSPATHS:
        try:
            import SystemPaths as SP
            mod_dir = SP.modDir
        except (ImportError, AttributeError):
            # SystemPaths is a BUG module. A mod without it still works when this file sits where the
            # installer puts it (<mod>/Assets/Python/BUG/), so fall back to the directory implied by
            # __file__. A failed import is not cached by Python 2.4, so remember it: this runs every poll.
            _NOSYSPATHS.append(1)
            mod_dir = None
    if mod_dir is None:
        mod_dir = _mod_dir_from_file()
        _note_once("nosyspaths", "SystemPaths (BUG) is not available; using the mod directory implied by "
                   "this module's location: %s" % mod_dir)
    return os.path.join(mod_dir, "UserSettings", "AgentRepl")


def valid_id(rid):
    return bool(rid) and len(rid) <= 80 and re.match(r"[0-9A-Za-z-]+\Z", rid) is not None


def _one_line(text, limit):
    text = text.replace("\r", " ").replace("\n", " | ")
    return text[:limit]


# --------------------------------------------------------------------------
# state

_S = {}


def _reset_state():
    _S.clear()
    _S.update({
        "next": 0.0, "next_hb": 0.0, "polls": 0, "busy": False, "fails": 0,
        "disabled": "", "last_id": "", "ns": None, "enabled": None, "bad": {}, "seen": {},
    })


_reset_state()


def _audit_strict(d, text):
    """Append one line to audit.log (rotating at 1 MiB). Raises if the line cannot be written."""
    path = os.path.join(d, "audit.log")
    try:
        if os.path.getsize(path) > AUDIT_ROTATE:
            old = path + ".1"
            if os.path.exists(old):
                os.remove(old)
            os.rename(path, old)
    except (OSError, IOError):
        # Rotation is best-effort (no audit.log yet, or a rename race); the append below is the
        # step that must succeed, and it raises.
        pass
    # epoch_coarse is the in-game wall clock (float32-quantized, +-127 s): informational only.
    # clock is the exact relative clock: correlate lines by it.
    _write(path, _b("epoch_coarse=%d clock=%.3f %s\n" % (int(time.time()), _clock(), text)), "ab")


def _audit(d, text):
    """Best-effort audit line for events that gate nothing. Never raises."""
    try:
        _audit_strict(d, text)
        return True
    except Exception:
        return False


def _escape(text):
    """One-line, loss-free form: backslash, CR and LF are escaped."""
    return text.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n")


def _game_turn():
    try:
        import CvPythonExtensions as cpe
        return int(cpe.CyGlobalContext().getGame().getGameTurn())
    except Exception:
        return -1


def _heartbeat(d, now, enabled, force):
    if not force and now < _S["next_hb"]:
        return
    _S["next_hb"] = now + HEARTBEAT_INTERVAL
    lines = [
        "session: %s" % SESSION_TOKEN,
        "alive_clock: %.3f" % now,
        "epoch: %.3f" % time.time(),     # coarse in-game wall clock (informational only)
        "turn: %d" % _game_turn(),
        "enabled: %s" % str(bool(enabled)).lower(),
        "write_enabled: %s" % str(os.path.exists(os.path.join(d, "ENABLE_WRITE"))).lower(),
        "disabled_reason: %s" % _one_line(_S["disabled"], 200),
        "last_id: %s" % _S["last_id"],
        "polls: %d" % _S["polls"],
        "version: %s" % VERSION,
    ]
    _write(os.path.join(d, "status.txt"), _b("\n".join(lines) + "\n"), "wb")


# --------------------------------------------------------------------------
# namespace

def _build_namespace():
    # math and clock are pre-bound because read-only requests may not import anything.
    ns = {"__name__": "__agentrepl__", "__doc__": None, "math": math, "clock": _clock}
    try:
        import CvPythonExtensions as cpe
        for name in dir(cpe):
            if name[:1] != "_":
                try:
                    ns[name] = getattr(cpe, name)
                except Exception:
                    pass
        try:
            ns["gc"] = cpe.CyGlobalContext()
            ns["game"] = ns["gc"].getGame()
        except Exception:
            pass
    except Exception:
        pass
    return ns


def _namespace(reset):
    if reset or _S["ns"] is None:
        _S["ns"] = _build_namespace()
    return _S["ns"]


# --------------------------------------------------------------------------
# request execution

def _tracer(frame, event, arg):
    if _clock() > _S["deadline"]:
        raise Timeout()
    return _tracer


def _parse_directives(src):
    opts = {"budget": DEFAULT_BUDGET, "reset": False, "write": False}
    for line in src.split("\n"):
        if line[:2] != "#@":
            break
        parts = line[2:].split()
        if not parts:
            continue
        if parts[0] == "reset":
            opts["reset"] = True
        elif parts[0] == "write":
            opts["write"] = True
        elif parts[0] == "budget" and len(parts) > 1:
            try:
                value = float(parts[1])
            except ValueError:
                value = 0.0
            if value > 0:
                if value > MAX_BUDGET:
                    value = MAX_BUDGET
                opts["budget"] = value
    return opts


def _execute(src, ns, budget):
    """Run src in ns under a deadline. Returns (status, stdout_text, traceback_text)."""
    buf = StringIO()
    status = "ok"
    tb = ""
    old_out = sys.stdout
    getter = getattr(sys, "gettrace", None)
    old_trace = None
    if getter is not None:
        old_trace = getter()
    _S["deadline"] = _clock() + budget
    sys.stdout = buf
    try:
        try:
            sys.settrace(_tracer)
            try:
                code = compile(src, "<repl>", "eval")
                is_expr = True
            except SyntaxError:
                code = compile(src, "<repl>", "exec")
                is_expr = False
            result = eval(code, ns)
            if is_expr and result is not None:
                buf.write(repr(result) + "\n")
        except Timeout:
            sys.settrace(None)
            status = "timeout"
            tb = traceback.format_exc()
        except (SystemExit, KeyboardInterrupt):
            sys.settrace(None)
            status = "error"
            tb = traceback.format_exc()
        except Exception:
            sys.settrace(None)
            status = "error"
            tb = traceback.format_exc()
        except:
            # string exceptions (2.4) and anything else not derived from Exception
            sys.settrace(None)
            status = "error"
            tb = traceback.format_exc()
    finally:
        sys.settrace(None)
        if old_trace is not None:
            sys.settrace(old_trace)
        sys.stdout = old_out
    return status, buf.getvalue(), tb


def _build_reply(rid, status, elapsed_ms, out_text, tb, detail):
    out = _b(out_text)
    extra = []
    if len(out) > OUTPUT_CAP:
        dropped = len(out) - OUTPUT_CAP
        out = out[:OUTPUT_CAP] + _b("\n[... %d bytes dropped]\n" % dropped)
        extra.append("truncated_bytes: %d" % dropped)
    if len(tb) > TRACEBACK_CAP:
        tb = "[... traceback truncated ...]\n" + tb[-TRACEBACK_CAP:]
    head = [
        "id: %s" % rid,
        "status: %s" % status,
        "elapsed_ms: %d" % elapsed_ms,
        "turn: %d" % _game_turn(),
        "polls: %d" % _S["polls"],
        "stdout_bytes: %d" % len(out),
    ]
    if detail:
        head.append("detail: %s" % _one_line(detail, 300))
    head.extend(extra)
    data = _b("\n".join(head) + "\n---\n") + out
    if tb:
        data = data + _b("--- traceback ---\n" + tb)
    return data


def _send_reply(d, rid, data):
    tmp = os.path.join(d, "rep-%s.tmp" % rid)
    final = os.path.join(d, "rep-%s.txt" % rid)
    _write(tmp, data, "wb")
    if os.path.exists(final):
        os.remove(final)  # same id reused by the host; never rename onto a file
    os.rename(tmp, final)


def _skip(name):
    _S["bad"][name] = 1


def _first_sight(name, now):
    """Track a request file name (the cap is enforced in _note_requests); returns the clock at first sight."""
    seen = _S["seen"]
    if name not in seen:
        seen[name] = now
    return seen[name]


def _is_request_name(name):
    return name[:4] == "req-" and name[-3:] == ".py"


def _purge_queue(d):
    """ENABLE is absent: delete queued requests (audited) so none runs after the console is switched on."""
    count = 0
    names = []
    for name in os.listdir(d):
        if _is_request_name(name) and name not in _S["bad"]:
            names.append(name)
    names.sort()
    for name in names:
        if count >= PER_POLL_LIMIT:
            break
        count = count + 1
        rid = _one_line(name[4:-3], 60)
        try:
            os.remove(os.path.join(d, name))
        except (OSError, IOError):
            if os.path.exists(os.path.join(d, name)):
                _skip(name)
                _audit(d, "%s purge failed, skipped from now on" % rid)
            continue
        _audit(d, "%s purged (console switched off)" % rid)
        if valid_id(name[4:-3]):
            # Answer, so a host still waiting does not conclude the request ran.
            try:
                _send_reply(d, name[4:-3], _build_reply(
                    name[4:-3], "refused", 0, "", "",
                    "purged: the console is switched off (ENABLE absent); the request did not run"))
            except Exception:
                pass


def _refuse_overflow(d, name):
    """A new request beyond SEEN_CAP: claim (delete) it, audit it, answer 'refused' when the id is valid."""
    rid = name[4:-3]
    try:
        os.remove(os.path.join(d, name))
    except (OSError, IOError):
        if os.path.exists(os.path.join(d, name)):
            _skip(name)
            _audit(d, "%s over cap, delete failed, skipped from now on" % _one_line(rid, 60))
        return
    _audit(d, "%s refused: queue full (%d tracked requests)" % (_one_line(rid, 60), SEEN_CAP))
    if valid_id(rid):
        detail = "request queue is full (%d tracked requests); resend later" % SEEN_CAP
        try:
            _send_reply(d, rid, _build_reply(rid, "refused", 0, "", "", detail))
        except Exception:
            pass


def _note_requests(d, now):
    """Record first sight of every request file (also while switched off); forget the gone ones;
    refuse new ones beyond SEEN_CAP."""
    names = []
    for name in os.listdir(d):
        if _is_request_name(name):
            names.append(name)
    names.sort()
    seen = _S["seen"]
    for name in list(seen.keys()):
        if name not in names:
            del seen[name]
    refused = 0
    for name in names:
        if name in seen:
            continue
        if len(seen) >= SEEN_CAP:
            if refused < PER_POLL_LIMIT and name not in _S["bad"]:
                refused = refused + 1
                _refuse_overflow(d, name)
            continue
        _first_sight(name, now)


def _session_problem(src):
    """None if the request's first line is '#@ session <this session's token>', else the reason."""
    first = src.split("\n")[0]
    parts = []
    if first[:2] == "#@":
        parts = first[2:].split()
    if len(parts) != 2 or parts[0] != "session":
        return "missing session token (the first line must be '#@ session <token>' from status.txt)"
    if parts[1] != SESSION_TOKEN:
        return "session token mismatch: the request is from another game session or an old status.txt"
    return None


_NOTAFTER_RE = re.compile(r"\d+(\.\d+)?\Z")


def _deadline_problem(src, now):
    """None if the second line is '#@ notafter <deadline>' and the deadline has not passed on the
    relative clock `now`, else the reason. A missing, malformed, nan or inf deadline is a problem."""
    lines = src.split("\n")
    second = ""
    if len(lines) > 1:
        second = lines[1]
    parts = []
    if second[:2] == "#@":
        parts = second[2:].split()
    if len(parts) != 2 or parts[0] != "notafter":
        return "missing deadline (the second line must be '#@ notafter <seconds on the game clock>')"
    text = parts[1]
    if len(text) > MAX_NOTAFTER_DIGITS or _NOTAFTER_RE.match(text) is None:
        return "malformed deadline %r (a plain non-negative decimal number is required)" % text[:24]
    deadline = float(text)
    if now > deadline:
        return "deadline passed: %.1f s of game time ago (the host had stopped waiting)" % (now - deadline)
    return None


def _handle_request(d, name):
    rid = name[4:-3]
    path = os.path.join(d, name)
    if not valid_id(rid):
        try:
            os.remove(path)
        except (OSError, IOError):
            _skip(name)
        _audit(d, "- badid %s" % _one_line(rid, 60))
        return
    _S["last_id"] = rid
    started = _clock()
    try:
        _first_sight(name, started)
        raw = _read(path, REQUEST_CAP + 1)
    except (OSError, IOError):
        if not os.path.exists(path):
            _audit(d, "%s withdrawn" % rid)
            return
        # unreadable (for example a directory): drop it, or remember to skip it
        try:
            os.remove(path)
            _audit(d, "%s unreadable, removed" % rid)
        except (OSError, IOError):
            _skip(name)
            _audit(d, "%s unreadable, skipped from now on" % rid)
        return
    try:
        os.remove(path)   # THE CLAIM: only the side whose delete succeeds may act on the request
    except (OSError, IOError):
        if os.path.exists(path):
            _skip(name)
        _audit(d, "%s withdrawn" % rid)   # the host's timeout-unlink won; do not run
        return
    if not isinstance(raw, str):
        raw = raw.decode("utf-8", "replace")
    src = raw.replace("\r\n", "\n").replace("\r", "\n")
    if src[-1:] != "\n":
        src = src + "\n"
    status = "ok"
    detail = ""
    out_text = ""
    tb = ""
    session_problem = _session_problem(src)
    deadline_problem = None
    if session_problem is None:
        deadline_problem = _deadline_problem(src, started)
    # Audit BEFORE running: the full source, escaped. No audit line, no execution.
    try:
        _audit_strict(d, "%s begin %s" % (rid, _escape(src[:REQUEST_CAP])))
        audited = True
    except Exception:
        audited = False
    if not audited:
        status = "error"
        detail = "audit unavailable: request not run"
    elif session_problem is not None:
        status = "badsession"
        detail = session_problem
    elif deadline_problem is not None:
        status = "stale"
        detail = deadline_problem
    elif len(raw) > REQUEST_CAP:
        status = "toolarge"
        detail = "request exceeds %d bytes" % REQUEST_CAP
    else:
        opts = _parse_directives(src)
        write_ok = False
        if opts["write"] and os.path.exists(os.path.join(d, "ENABLE_WRITE")):
            write_ok = True
        reason = None
        reason_status = "refused"
        if not write_ok:
            # Read-only is everything that is not BOTH ENABLE_WRITE and "#@ write": an allowlist
            # of reads first (status "readonly"), then the older refuse list (imports, os., ...).
            ok, why = check_readonly(src, _S["ns"])
            if not ok:
                reason = why
                reason_status = "readonly"
            else:
                reason = refuse_reason(src)
            if reason is not None and opts["write"]:
                reason = reason + " (ENABLE_WRITE is absent)"
        if reason is not None:
            status = reason_status
            detail = reason
        else:
            ns = _namespace(opts["reset"])
            status, out_text, tb = _execute(src, ns, opts["budget"])
            if write_ok:
                # Nothing defined in write mode (a function, a class, an object) may be called later
                # from a read-only request, where its body would escape the allowlist: start afresh.
                _S["ns"] = None
            if status == "timeout":
                detail = "budget %.1f s exceeded" % opts["budget"]
    elapsed = int((_clock() - started) * 1000)
    _audit(d, "%s end %s %dms" % (rid, status, elapsed))
    _send_reply(d, rid, _build_reply(rid, status, elapsed, out_text, tb, detail))


def _handle_one(d):
    names = []
    for name in os.listdir(d):
        if _is_request_name(name) and name not in _S["bad"] and name in _S["seen"]:
            names.append(name)
    if not names:
        return
    names.sort()
    name = names[0]
    try:
        _handle_request(d, name)
    except:
        # A problem with one request must not count against the module (no self-disable).
        line = _one_line(traceback.format_exc(), 400)
        if os.path.exists(os.path.join(d, name)):
            _skip(name)
        _audit(d, "%s REQUEST-ERROR %s" % (name[4:-3], line))


# --------------------------------------------------------------------------
# polling

def _internal_error(d):
    try:
        _S["fails"] = _S["fails"] + 1
        line = _one_line(traceback.format_exc(), 400)
        _S["next_hb"] = 0.0
        if _S["fails"] >= MAX_FAILS and not _S["disabled"]:
            _S["disabled"] = "%d consecutive internal errors: %s" % (_S["fails"], line)
        if d is not None:
            _audit(d, "- INTERNAL %s" % line)
    except Exception:
        pass


def poll(force=False):
    """One poll. force=True skips the time throttle (tests). May raise."""
    now = _clock()
    if _S["busy"] or (not force and now < _S["next"]):
        return
    _S["busy"] = True
    try:
        d = _exchange_dir()
        if not os.path.isdir(d):
            _S["next"] = now + OFF_INTERVAL
            return
        enabled = os.path.exists(os.path.join(d, "ENABLE"))
        if enabled and not _S["disabled"]:
            _S["next"] = now + POLL_INTERVAL
        else:
            _S["next"] = now + OFF_INTERVAL
        _S["polls"] = _S["polls"] + 1
        changed = (_S["enabled"] != enabled)
        _S["enabled"] = enabled
        _heartbeat(d, now, enabled, changed)
        if not enabled:
            _purge_queue(d)
        _note_requests(d, now)
        if enabled and not _S["disabled"]:
            _handle_one(d)
    finally:
        _S["busy"] = False


def onGameUpdate(*args):
    """BUG gameUpdate handler. Never raises."""
    try:
        d = None
        try:
            poll()
            _S["fails"] = 0
        except:
            try:
                d = _exchange_dir()
            except Exception:
                d = None
            _internal_error(d)
    except:
        pass
