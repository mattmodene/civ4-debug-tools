"""Read-only mode must be an allowlist of reads, not a refuse list (Bug A), and the host must
notice a module that predates the session token (Bug B).

Bug A, proven live 2026-11-06: ENABLE present, ENABLE_WRITE absent, request
``gc.getActivePlayer().changeGold(100)`` without ``#@ write`` ran and changed game state.

Everything goes through the request path with a stubbed game whose mutators record calls, so a
failure shows up as "the stubbed mutator was called". The fix is expected to add a checker
(for example ``check_readonly(source) -> (ok, reason)``) and a reply/audit status "readonly".
"""

import pytest
from agentrepl_support import install_fake_game, load_module, put_request, reply_path, write_status

from civ4dbg.__main__ import main

CALLS = []


class Plot:
    def getNumUnits(self):
        return 2

    def getUnit(self, i):
        return Unit(i)

    def getOwner(self):
        return 7

    def getArea(self):
        return 3

    def getX(self):
        return 101

    def getY(self):
        return 76

    def setXY(self, x, y):
        CALLS.append("plot.setXY")


class Group:
    def getID(self):
        return 11

    def getOwner(self):
        return 7

    def getNumUnits(self):
        return 2

    def getHeadUnit(self):
        return Unit(0)

    def readyToMove(self, flag):
        return True

    def getActivityType(self):
        return 0

    def pushMission(self, *a):
        CALLS.append("pushMission")


class Unit:
    def __init__(self, i=0):
        self.i = i
        self.m_iSomething = 0

    def getID(self):
        return 100 + self.i

    def getGroupID(self):
        return 11

    def getGroup(self):
        return Group()

    def getX(self):
        return 101

    def getY(self):
        return 76

    def getUnitType(self):
        return 5

    def getUnitAIType(self):
        return 1

    def isOnlyDefensive(self):
        return False

    def canFight(self):
        return True

    def plot(self):
        return Plot()

    def setXY(self, x, y):
        CALLS.append("setXY")


class Player:
    def getGold(self):
        return 50

    def changeGold(self, n):
        CALLS.append("changeGold")

    def setGold(self, n):
        CALLS.append("setGold")

    def kill(self):
        CALLS.append("kill")

    def groups(self):
        return [Group(), Group()]

    def firstUnit(self, flag):
        return Unit(0), 1

    def nextUnit(self, it, flag):
        return None, it

    def getNumSelectionGroups(self):
        return 2

    def isTurnActive(self):
        return False


class UnitInfo:
    def getType(self):
        return "UNIT_AXEMAN"


class MapStub:
    def plot(self, x, y):
        return Plot()


@pytest.fixture
def env(tmp_path, monkeypatch):
    del CALLS[:]
    cpe = install_fake_game(monkeypatch)

    class CyGame(cpe.CyGame):
        def getGameTurn(self):
            return 241

    class Ctx:
        def getGame(self):
            return CyGame()

        def getActivePlayer(self):
            return Player_

        def getPlayer(self, i):
            return Player_

        def getMap(self):
            return MapStub()

        def getUnitInfo(self, i):
            return UnitInfo()

        def getInfoTypeForString(self, s):
            return 4

    Player_ = Player()
    cpe.CyGlobalContext = Ctx
    d = tmp_path / "ex"
    d.mkdir()
    (d / "ENABLE").write_text("")
    return load_module(d), d


def audit(d):
    p = d / "audit.log"
    return p.read_text() if p.exists() else ""


def header(text, key):
    for line in text.splitlines():
        if line.startswith(key + ": "):
            return line[len(key) + 2 :]


def run(env_, rid, src):
    mod, d = env_
    put_request(d, rid, src)
    mod.poll(force=True)
    return reply_path(d, rid).read_text()


# (request body, a name/construct the refusal must mention, the stubbed call that must NOT happen)
REFUSED = [
    ("gc.getActivePlayer().changeGold(100)\n", "changeGold", "changeGold"),
    ("p = gc.getActivePlayer()\np.setGold(1)\n", "setGold", "setGold"),
    ("p = gc.getActivePlayer()\np.kill()\n", "kill", "kill"),
    ("u = gc.getActivePlayer().firstUnit(False)[0]\nu.setXY(1, 2)\n", "setXY", "setXY"),
    ("g = gc.getActivePlayer().groups()[0]\ng.pushMission(1, 2, 3)\n", "pushMission", "pushMission"),
    ("x = gc.getActivePlayer().firstUnit(False)[0]\nx.m_iSomething = 1\n", "m_iSomething", None),
    ("p = gc.getActivePlayer()\nsetattr(p, 'x', 1)\n", "setattr", None),
    ("p = gc.getActivePlayer()\ngetattr(p, 'change' + 'Gold')(1)\n", "getattr", "changeGold"),
    ("p = gc.getActivePlayer()\nf = p.changeGold\nf(1)\n", "changeGold", "changeGold"),
    ("p = gc.getActivePlayer()\n[p.changeGold(1) for i in range(1)]\n", "changeGold", "changeGold"),
    ("p = gc.getActivePlayer()\nexec 'p.changeGold(1)'\n", "exec", "changeGold"),
    ("p = gc.getActivePlayer()\nprint(p.__class__)\n", "__class__", None),
]


@pytest.mark.parametrize("src,needle,mutator", REFUSED, ids=[r[1] for r in REFUSED])
def test_read_only_refuses(env, src, needle, mutator):
    mod, d = env
    rep = run(env, "r1", src)
    assert mutator is None or mutator not in CALLS, "read-only request reached stubbed %s()" % mutator
    assert header(rep, "status") == "readonly", "status was %r, want 'readonly':\n%s" % (header(rep, "status"), rep)
    assert needle in (header(rep, "detail") or ""), "refusal detail does not name %r:\n%s" % (needle, rep)
    assert "r1 end readonly" in audit(d), "no 'end readonly' audit line:\n" + audit(d)


def test_read_only_refuses_even_when_write_present_but_not_requested(env):
    mod, d = env
    (d / "ENABLE_WRITE").write_text("")
    rep = run(env, "r2", "gc.getActivePlayer().changeGold(100)\n")  # no '#@ write'
    assert "changeGold" not in CALLS, "ENABLE_WRITE alone let a mutator run without '#@ write'"
    assert header(rep, "status") == "readonly", rep


# --- what the live inspections did must keep working (py3-valid renderings of live-inspect/q*.py)

ALLOWED = {
    "getters_and_format": (
        "p = gc.getPlayer(7)\n"
        "print('turn %d p7 active %s gold %d' % (gc.getGame().getGameTurn(), p.isTurnActive(), p.getGold()))\n",
        "turn 241 p7 active False gold 50",
    ),
    "plot_loop_dict_list": (
        "pl = gc.getMap().plot(101, 76)\n"
        "groups = {}\n"
        "for i in range(pl.getNumUnits()):\n"
        "    u = pl.getUnit(i)\n"
        "    if u is None:\n"
        "        continue\n"
        "    gid = u.getGroupID()\n"
        "    if gid not in groups:\n"
        "        groups[gid] = []\n"
        "    groups[gid].append(u)\n"
        "for gid in sorted(groups.keys()):\n"
        "    us = groups[gid]\n"
        "    g = us[0].getGroup()\n"
        "    print('GROUP %d owner %d units %d head %s' % (gid, g.getOwner(), len(us), "
        "gc.getUnitInfo(g.getHeadUnit().getUnitType()).getType()))\n",
        "GROUP 11 owner 7 units 2 head UNIT_AXEMAN",
    ),
    "groups_histogram": (
        "p = gc.getPlayer(7)\n"
        "byact = {}\n"
        "ready = []\n"
        "for g in p.groups():\n"
        "    a = int(g.getActivityType())\n"
        "    byact[a] = byact.get(a, 0) + 1\n"
        "    if g.readyToMove(True):\n"
        "        ready.append((g.getID(), g.getNumUnits(), g.getHeadUnit().getX()))\n"
        "ready.sort()\n"
        "print('n %d hist %s ready %s' % (len(p.groups()), byact, len(ready)))\n",
        "n 2 hist {0: 2} ready 2",
    ),
    "firstUnit_iterator": (
        "p = gc.getPlayer(7)\n"
        "n = 0\n"
        "ai_hist = {}\n"
        "u, it = p.firstUnit(False)\n"
        "while u is not None:\n"
        "    n = n + 1\n"
        "    ai = int(u.getUnitAIType())\n"
        "    ai_hist[ai] = ai_hist.get(ai, 0) + 1\n"
        "    k = (gc.getUnitInfo(u.getUnitType()).getType(), u.isOnlyDefensive(), u.canFight())\n"
        "    if u.plot().getArea() == gc.getMap().plot(1, 1).getArea():\n"
        "        n = n + 0\n"
        "    u, it = p.nextUnit(it, False)\n"
        "print('units %d %s %s' % (n, ai_hist, k))\n",
        "units 1 {1: 1} ('UNIT_AXEMAN', False, True)",
    ),
    "builtins_and_comprehension": (
        "xs = [gc.getMap().plot(i, i).getNumUnits() for i in range(3)]\n"
        "d = dict([(i, x) for i, x in enumerate(xs)])\n"
        "print(len(xs), sum(xs), min(xs), max(xs), abs(-1), repr(sorted(d.keys())), str(list(zip(xs, xs))[0]),\n"
        "      isinstance(d, dict), tuple(xs), int('3'))\n",
        "3 6 2 2 1 [0, 1, 2] (2, 2) True (2, 2, 2) 3",
    ),
    "info_type_lookup": ("print(gc.getInfoTypeForString('UNITAI_ATTACK_CITY'))\n", "4"),
}


@pytest.mark.parametrize("name", sorted(ALLOWED))
def test_read_only_allows_queries(env, name):
    src, want = ALLOWED[name]
    rep = run(env, "q1", src)
    assert header(rep, "status") == "ok", "a read-only query was refused or failed:\n" + rep
    assert want in rep, "unexpected output:\n" + rep
    assert not CALLS


# --- write mode lifts the read restriction


def test_write_mode_allows_changeGold(env):
    mod, d = env
    (d / "ENABLE_WRITE").write_text("")
    rep = run(env, "w1", "#@ write\ngc.getActivePlayer().changeGold(100)\n")
    assert header(rep, "status") == "ok", rep
    assert CALLS == ["changeGold"]


def test_write_mode_refused_without_enable_write_is_readonly_not_a_run(env):
    mod, d = env
    rep = run(env, "w2", "#@ write\ngc.getActivePlayer().changeGold(100)\n")  # ENABLE_WRITE absent
    assert "changeGold" not in CALLS
    assert header(rep, "status") == "readonly", rep


# --- Bug B: --status must notice a module older than the session-token protocol


def test_status_without_session_line_is_exit_3_and_says_older(tmp_path, capsys):
    d = tmp_path / "ex"
    d.mkdir(mode=0o700)
    (d / "ENABLE").write_text("")
    p = write_status(d)
    p.write_text("".join(ln + "\n" for ln in p.read_text().splitlines() if not ln.startswith("session:")))
    import os
    import time

    os.utime(p, (time.time(), time.time()))
    code = main(["exec", "--dir", str(d), "--status"])
    err = capsys.readouterr().err
    assert code == 3, "exec --status returned %d for a fresh heartbeat with no session line" % code
    assert "installed module is older; reinstall and restart" in err, err


def test_module_version_is_bumped_past_the_pre_token_protocol(env):
    mod, d = env
    assert int(mod.VERSION) >= 2, "VERSION is %r, identical to the pre-token module" % mod.VERSION
    mod.poll(force=True)
    published = [ln for ln in (d / "status.txt").read_text().splitlines() if ln.startswith("version:")]
    assert published and int(published[0].split(":")[1]) >= 2, published
