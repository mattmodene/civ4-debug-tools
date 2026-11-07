"""check_readonly(): the token-based read-only allowlist, edge cases beyond the request-path tests in
test_agentrepl_readonly.py. The checker is name-based and guards against accidents; it is not a sandbox."""

import sys

import pytest
from agentrepl_support import install_fake_game, load_module


@pytest.fixture
def mod(tmp_path, monkeypatch):
    install_fake_game(monkeypatch)
    return load_module(tmp_path)


OK = [
    "gc.getGame().getGameTurn()",
    "p = gc.getPlayer(0)\nprint(p.isAlive(), p.canTrain(1), p.hasTech(2), p.countCities())\n",
    "pl = gc.getMap().plot(1, 2)\nx = pl.getX()\n",
    "u, it = p.firstUnit(False)\nu, it = p.nextUnit(it, False)\n",
    "d = {}\nd[1] = 2\nd[1] += 1\nd.setdefault(3, []).append(4)\n",
    "d = dict()\nd[gc.getGame().getGameTurn()] = 1\n",
    "xs = []\nxs.append(1)\nxs.sort()\nxs[0] = 5\n",
    "a, b = 1, 2\n",
    "x = gc.getInfoTypeForString('UNITAI_ATTACK')\ny = CyGame.UNITAI_ATTACK\n",
    "getattr(p, 'getGold')()\n",
    "getattr(p, 'getGold', None)\n",
    "f = lambda u: u.getID()\nprint(f(u))\n",
    "print('%s' % ', '.join(sorted(d.keys())))\n",
    "math.sqrt(2)\nclock()\n",
    "d = {}\nif x: d[1] = 2\n",
    "for k, v in d.items():\n    print(k, v)\n",
    "s = ''\ns += 'x'\n",
    "(a, b) = (1, 2)\n",
]

REFUSED = [
    ("p.changeGold(1)", "changeGold"),
    ("f = p.setGold", "setGold"),
    ("p.x = 1", "'x'"),
    ("p.x += 1", "'x'"),
    ("p.a.b = 1", "attribute"),
    ("p.x, y = 1, 2", "'x'"),
    ("a[0].x = 1", "'x'"),
    ("gc[0] = 1", "gc"),
    ("gc.getX()[0] = 1", "attribute"),
    ("d = {}\nd[1].y = 1", "'y'"),
    ("del p.x", "'x'"),
    ("del gc[0]", "gc"),
    ("for p.x in range(3): pass", "attribute 'x'"),
    ("xs = []\nfor xs[0] in range(3): pass", "'for'"),
    ("xs = []\nys = [1 for xs[0] in range(3)]", "'for'"),
    ("with open2 as p.x: pass", "attribute 'x'"),
    ("with open2 as xs[0]: pass", "'as'"),
    ("setattr(p, 'x', 1)", "setattr"),
    ("delattr(p, 'x')", "delattr"),
    ("eval('1')", "eval"),
    ("exec('1')", "exec"),
    ("compile('1', 'x', 'eval')", "compile"),
    ("execfile('x')", "execfile"),
    ("open('x')", "open"),
    ("file('x')", "file"),
    ("reload(m)", "reload"),
    ("globals()", "globals"),
    ("locals()", "locals"),
    ("vars(p)", "vars"),
    ("input()", "input"),
    ("raw_input()", "raw_input"),
    ("__import__('os')", "__import__"),
    ("p.__class__", "__class__"),
    ("__builtins__", "__builtins__"),
    ("x__y = 1", "x__y"),
    ("getattr(p, 'set' + 'Gold')", "getattr"),
    ("getattr(p, name)", "getattr"),
    ("getattr(p, 'setGold')", "setGold"),
    ("getattr(p)", "getattr"),
    ("g = getattr", "getattr"),
    ('getattr(p, """getGold""")', "getattr"),
    ("p.getSorenRandNum(5, 'x')", "getSorenRandNum"),
    ("p.getter2 = 1", "getter2"),
    ("p.gettext()", "gettext"),
    ("p.issue()", "issue"),
    ("x = `1`", "backtick|unreadable token"),
    ("def f(:", "tokenized|unreadable token"),
    ("'unterminated", "tokenized|unreadable token"),
    ("map(p.changeGold, [1])", "changeGold"),
    ("sorted(xs, key=p.setGold)", "setGold"),
    ("[p.kill() for p in ps]", "kill"),
    ("(lambda: p.kill())()", "kill"),
    ("x = 1; p.kill()", "kill"),
    ("d.update(x)", "update"),
    ("os.remove('x')", "remove"),
    ("time.sleep(1)", "sleep"),
]


@pytest.mark.parametrize("src", OK)
def test_allowed(mod, src):
    ok, why = mod.check_readonly(src)
    assert ok, (src, why)


@pytest.mark.parametrize("src,needle", REFUSED)
def test_refused_with_a_reason_naming_the_construct(mod, src, needle):
    ok, why = mod.check_readonly(src)
    assert not ok, src
    # "a|b": the stdlib tokenizer reports these inputs differently before and after Python 3.12
    assert any(n in why for n in needle.split("|")), (src, why)


def test_constants_and_prefixes(mod):
    assert mod.check_readonly("x = CyGame.NO_PLAYER_X + a.ACTIVITY_SLEEP")[0]
    for name in ("getX", "getID", "isOnlyDefensive", "canFight", "hasTech", "countX", "findPath", "get", "is_x"):
        assert mod.check_readonly("o.%s()" % name)[0], name
    for name in ("getattrX", "gets", "island", "canon", "Get", "setX", "changeX", "kill"):
        # lower-case continuation after the prefix is not a read (getattr..., island, canon, gets)
        assert not mod.check_readonly("o.%s()" % name)[0], name


def test_subscript_target_uses_the_persistent_namespace(mod):
    assert not mod.check_readonly("store[1] = 2")[0]
    assert mod.check_readonly("store[1] = 2", {"store": {}})[0]
    assert mod.check_readonly("store[1] = 2", {"store": []})[0]
    assert not mod.check_readonly("store[1] = 2", {"store": object()})[0]
    assert not mod.check_readonly("gc[1] = 2", {"gc": object()})[0]


def test_comments_and_session_directive_lines_are_ignored(mod):
    assert mod.check_readonly("#@ session abc\n#@ budget 3\n# p.changeGold(1)\nx = 1\n")[0]
    assert not mod.check_readonly("#@ session abc\nx = p.changeGold(1)  # fine\n")[0]


@pytest.mark.skipif(
    sys.version_info < (3, 12),
    reason="Python < 3.12 tokenizes an f-string as one STRING token, so names inside it are not scanned "
    "(the in-game Python 2.4 has no f-strings at all)",
)
def test_fstring_names_are_still_scanned(mod):
    assert mod.check_readonly("x = f'{p.getGold()}'\n")[0]
    assert not mod.check_readonly("x = f'{p.changeGold(1)}'\n")[0]


# ------------------------------------------------------------------ adversarial review R1-R9

R_REFUSED = [
    # R1: imports, BugUtil / CvUtil call-by-name routes
    ("import BugUtil\nBugUtil.getFunction('os', 'system', True)('echo hi')", "import"),
    ("from BugUtil import callFunction\ncallFunction('os', 'system', 'echo hi')", "BugUtil"),
    ("from CvUtil import setScriptData\nsetScriptData(p, 'a', 1)", "CvUtil"),
    ("from BugUtil import *\ndeferCall(None)", "BugUtil"),
    ("import math", "import"),
    ("from CvPythonExtensions import *", "import"),
    ("x = 1; import sys", "import"),
    ("if 1: import os", "import"),
    ("BugUtil.getFunction('os', 'system')", "BugUtil"),
    ("CvUtil.getScriptData(p, ['a'])", "CvUtil"),
    ("f = lookupModule('os')", "lookupModule"),
    ("x = o.getFunction('os', 'system')", "getFunction"),
    ("o.lookupFunction('a', 'b')", "lookupFunction"),
    ("o.callFunction('a', 'b')", "callFunction"),
    ("o.bindFunction('a', 'b')", "bindFunction"),
    ("deferCall(f)", "deferCall"),
    ("Function('a', 'b')", "Function"),
    # R2: sleep
    ("sleep(30)", "sleep"),
    ("from time import sleep\nsleep(30)", "import"),
    ("from time import *\nsleep(30)", "import"),
    ("from time import sleep as z\nz(60)", "import"),
    ("t.sleep(1)", "sleep"),
    # R3: RNG-advancing getters
    ("gc.getGame().getMapRandNum(10, 'x')", "getMapRandNum"),
    ("gc.getGame().getMapRand().get(10, 'x')", "getMapRand"),
    ("gc.getASyncRand().get(10, 'x')", "getASyncRand"),
    ("gc.getGame().getSorenRand().get(10, 'x')", "getSorenRand"),
    ("getattr(gc, 'getMapRand')()", "getMapRand"),
    # R4: coding cookie, BOM
    ("# coding: utf-7\np.+AGM-hangeGold(1)", "coding"),
    ("x = 1\n# -*- coding=utf-7 -*-\n", "coding"),
    ("\ufeffx = 1", "byte order mark"),
    ("\xef\xbb\xbfx = 1", "byte order mark"),
    # R6: del after a colon
    ("if 1: del mod.getFoo", "attribute"),
    ("d = {}\nif 1: del d[0].x", "attribute"),
    ("del p.x", "attribute"),
    ("x = 1; del gc[0]", "gc"),
    # R7: exactly one subscript level
    ("d = [pl]\nd[0][1] = 5", "item assignment"),
    ("d = {}\nd[0][1] += 5", "item assignment"),
    ("d = {}\nd[0].append(1)\nd[0][1] = 5", "item assignment"),
    ("d = {}\ndel d[0][1]", "item assignment"),
    # R8: log
    ("game.log('../x', 'y')", "log"),
    ("math.log(2)", "log"),
    # R9: stdin / exit builtins
    ("help()", "help"),
    ("license()", "license"),
    ("credits()", "credits"),
    ("copyright()", "copyright"),
    ("quit()", "quit"),
    ("exit()", "exit"),
]


@pytest.mark.parametrize("src,needle", R_REFUSED)
def test_review_repro_is_refused(mod, src, needle):
    ok, why = mod.check_readonly(src)
    assert not ok, src
    assert needle in why, (src, why)


R_ALLOWED = [
    "d = {}\nd[1] = 2\nif 1: del d[1]\n",
    "d = {}\nd[0] = []\nd[0].append(1)\n",
    "x = math.sqrt(2) + clock()\n",
    "gc.getGame().getGameTurn()\n",
    "# coding is fine here, no colon\nx = 1\n",
]


@pytest.mark.parametrize("src", R_ALLOWED)
def test_review_neighbours_still_allowed(mod, src):
    ok, why = mod.check_readonly(src)
    assert ok, (src, why)


def test_cookie_only_counts_in_the_first_two_lines(mod):
    assert mod.check_readonly("x = 1\ny = 2\n# coding: ascii\n")[0]
    assert not mod.check_readonly("#@ session abc\n# coding: ascii\nx = 1\n")[0]


def test_removed_read_names(mod):
    for name in (
        "log",
        "getMapRand",
        "getMapRandNum",
        "getASyncRand",
        "getSorenRand",
        "getSorenRandNum",
        "getFunction",
        "sleep",
    ):
        assert not mod._is_read_attr(name), name
    assert "log" not in mod._READ_ATTRS


def test_namespace_prebinds_math_and_clock(mod):
    ns = mod._build_namespace()
    assert ns["math"].sqrt(4) == 2.0 and ns["clock"]() >= 0


def test_cookie_look_alike_in_a_string_on_line_one_is_refused_conservatively(mod):
    assert not mod.check_readonly("x = 'coding: utf-7'\n")[0]


def test_math_constants_and_pure_functions_are_allowed(mod):
    for name in (
        "pi",
        "e",
        "fmod",
        "sqrt",
        "floor",
        "ceil",
        "fabs",
        "exp",
        "pow",
        "hypot",
        "sin",
        "cos",
        "tan",
        "asin",
        "acos",
        "atan",
        "atan2",
        "sinh",
        "cosh",
        "tanh",
        "degrees",
        "radians",
        "log10",
        "modf",
        "frexp",
        "ldexp",
    ):
        assert mod.check_readonly("x = math.%s" % name)[0], name
    assert mod.check_readonly("x = math.fmod(7, 3) + math.pi * math.e")[0]
    assert not mod.check_readonly("x = math.log(2)")[0]


def test_dead_module_names_are_gone_from_the_read_list(mod):
    for name in (
        "match",
        "search",
        "findall",
        "chain",
        "izip",
        "islice",
        "groupby",
        "defaultdict",
        "deque",
        "clock",
        "time",
    ):
        assert name not in mod._READ_ATTRS, name


RNG_DENIED = ("getSorenRand", "getSorenRandNum", "getMapRand", "getMapRandNum", "getASyncRand", "getNewCityName")
PURE_RAND_READS = (
    "getDogpileWarRand",
    "getGroupRand",
    "getImprovementBonusDiscoverRand",
    "getLimitedWarRand",
    "getMaxWarRand",
    "getRandAppearance",
    "getRandIceLatitude",
    "getWonderConstructRand",
)


@pytest.mark.parametrize("name", RNG_DENIED)
def test_each_rng_advancing_method_is_refused(mod, name):
    assert not mod._is_read_attr(name)
    for src in (
        "x = gc.getGame().%s(10, 'x')" % name,
        "x = gc.%s()" % name,
        "f = gc.%s\nf()" % name,
        "x = getattr(gc, '%s')" % name,
    ):
        ok, why = mod.check_readonly(src)
        assert not ok and name in why, (src, why)


def test_the_deny_list_is_the_rng_methods_found(mod):
    assert sorted(mod._RNG_DENIED) == sorted(RNG_DENIED)


@pytest.mark.parametrize("name", PURE_RAND_READS)
def test_pure_info_reads_with_rand_in_the_name_are_allowed(mod, name):
    assert mod._is_read_attr(name)
    ok, why = mod.check_readonly("x = gc.getLeaderHeadInfo(0).%s()" % name)
    assert ok, why
    assert mod.check_readonly("x = getattr(info, '%s')" % name)[0]
