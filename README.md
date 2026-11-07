# civ4-debug-tools

**Purpose**: Turn crash addresses (RVAs) in a Civilization IV mod's `CvGameCoreDLL.dll`
into function names, offsets and source lines, using the PDB the mod ships, and inspect a
running game through an opt-in Python console. LLVM's tools cannot read the old-style PDB of
the mod this was written against, Caveman2Cosmos (see `docs/llvm-diagnosis.md`, a historical case study), so this
reads PDBs directly. Standard library only.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

Version 0.1.0 (see [CHANGELOG.md](./CHANGELOG.md)). Released under the MIT license.

Not affiliated with Firaxis, 2K or the Caveman2Cosmos team. This repository ships no game
files: you supply your own DLL, PDB and minidumps.

## Contents

- [Requirements](#requirements)
- [Install](#install)
- [Layout](#layout)
- [Usage](#usage)
- [How an address is named](#how-an-address-is-named)
- [Hang/snapshot dumps and threads](#hangsnapshot-dumps-and-threads)
- [Caveats](#caveats)
- [Remote console (AgentRepl)](#remote-console-agentrepl)
- [Security](#security)
- [Development](#development)
- [Contributing](#contributing)
- [Standards conformance](#standards-conformance)
- [License](#license)

## Requirements

- Python 3.11 or newer, standard library only (no runtime dependencies; the decision is
  recorded in [CDT-001](./docs/architecture/adrs/cdt/CDT-001-standard-library-only-runtime.md)).
  Tested on 3.11 and the current 3.x.
- The `--pdb` file (and normally the `--dll` and any minidump) from the build you are
  diagnosing. Nothing else: the game, Wine and Proton are needed only to take dumps or to use
  the remote console, never to run the tests.
- **Offline reader (any mod).** `resolve`, `dump`, `compare` and `info` work for any Beyond the
  Sword mod DLL that has a matching PDB: MSF 7.00 (Microsoft compilers from 7.0 on), no OMAP data,
  and x86 minidumps. Firaxis ships no PDBs, so the mod author must build with debug info.
- **AgentRepl (BUG mods only).** The remote console requires BUG. The installer needs
  `Assets/Config/init.xml` and `Assets/Python/BUG/` in the mod, and the in-game module finds its
  exchange directory through BUG's `SystemPaths`, falling back to the path implied by where the module
  file itself sits (`<mod>/Assets/Python/BUG/AgentRepl.py`). Mods without BUG are not supported yet.
- Platform status (what is tested on Linux, Windows and macOS) is in
  [docs/platform-support.md](./docs/platform-support.md).

### What a mod author needs

To make crashes in your mod readable with this tool: build `CvGameCoreDLL.dll` with debug info and
keep the PDB that matches each DLL you ship (or publish it); do not post-link reorder the DLL
(`/ORDER`, which produces OMAP data); and ask players for x86 minidumps of the 32-bit game, however
they were taken. For the remote console, the mod must ship BUG.

## Install

From a clone, nothing to install: run the launcher with isolated mode (`-I` drops the
working directory and `PYTHONPATH` from the import path; the launcher adds its own directory).

    python3 -I civ4dbg.py --help

To get a `civ4dbg` command on your path:

    pip install .             # from a clone
    civ4dbg --help
    python3 -I -m civ4dbg --help      # also works once installed

The installed package contains only `civ4dbg/` and the license. The in-game module
(`ingame/AgentRepl.py`) and the installer (`tools/agentrepl_install.py`) are **not** in the
wheel: clone the repository to install the remote console into a mod.

For development, `pip install -e ".[dev]"` adds `pytest` (see [Development](#development)).

## Layout

    civ4dbg.py            launcher (works under python3 -I)
    civ4dbg/errors.py     the tool's own error types and the exit codes
    civ4dbg/msf.py        MSF 7.00 container: superblock, block map(s), stream directory
    civ4dbg/pdb.py        DBI, section headers, S_PUB32, S_GPROC32/S_LPROC32, C11 + C13 lines
    civ4dbg/pe.py         PE headers (the SizeOfHeaders bytes), plus the debug-directory entries and the 24-byte CodeView (RSDS) header
    civ4dbg/minidump.py   x86 minidump reader: fault address, access, x86 integer registers, module list, stack scan, ThreadList
    civ4dbg/compare.py    ranks the PDB functions that recur in a thread's stack scan across several dumps
    civ4dbg/buildcheck.py dump-vs-DLL build comparison (TimeDateStamp, SizeOfImage)
    civ4dbg/remote.py     host side of the AgentRepl remote console (`exec` command)
    ingame/AgentRepl.py   the in-game half (Python 2.4/3 subset; installed into the mod, not imported by civ4dbg)
    tests/                pytest suite; fixtures/ holds a small lld-link-built PDB
    tools/                dev.py (development commands), fuzz_inputs.py (malformed-input fuzz),
                          check_pdb_claims.py (docs checks), agentrepl_install.py (install/uninstall/status)
    docs/                 llvm-diagnosis.md, prior-art.md, architecture/ (decision records), PREFIXES.md

Example paths below name files in the current directory; any path works.

## Usage

    # RVAs given directly (hex or decimal) are looked up exactly as given
    python3 -I civ4dbg.py resolve --pdb CvGameCoreDLL.pdb --dll CvGameCoreDLL.dll 0x4f54a5 0x4f74a8

    # the same RVAs, if they are return addresses (looked up at RVA-1)
    python3 -I civ4dbg.py resolve --pdb CvGameCoreDLL.pdb --return-address 0x4f74a8

    # straight from a minidump: fault site plus the stack scan
    python3 -I civ4dbg.py dump --pdb CvGameCoreDLL.pdb --dll CvGameCoreDLL.dll MiniDump-....dmp

    # a hang/snapshot dump (winedbg): the threads that touch the module, not the break-in thread
    python3 -I civ4dbg.py dump --pdb CvGameCoreDLL.pdb --dll CvGameCoreDLL.dll hang-....dmp
    python3 -I civ4dbg.py dump --pdb ... --dll ... --thread 336 hang-....dmp     # one thread
    python3 -I civ4dbg.py dump --pdb ... --dll ... --all-threads hang-....dmp    # every thread

    # several snapshots of one hang: functions that recur in a thread's stack scan
    python3 -I civ4dbg.py compare --pdb ... --dll ... hang-1.dmp hang-2.dmp hang-3.dmp

    # container summary
    python3 -I civ4dbg.py info --pdb CvGameCoreDLL.pdb

### Options

| Option | Commands | Meaning |
|---|---|---|
| `--pdb PATH` | all | the PDB (required) |
| `--dll PATH` | all | the DLL. `resolve`/`info`: cross-check the PDB section table against the DLL's PE headers. `dump`: also enables the build-match check (below). Strongly recommended for `dump` |
| `--module NAME` | `dump` | file name of the module to resolve, default `CvGameCoreDLL.dll`. Matched against the dump's module list by whole file name, case-insensitive, directories ignored (`Other` + `CvGameCoreDLL.dll` does not match) |
| `--stack-limit N` | `dump` | how many stack words (that point into the module) to look at, default 20, `0` for none. Applied before the adjacent-duplicate collapse, so fewer than N distinct lines may print; only *consecutive* repeats collapse |
| `--thread TID` | `dump`, `compare` | `dump`: show this thread (decimal or `0x` hex; repeatable) instead of the default selection; an unknown id exits 2 and lists the ids. `compare`: compare this thread id only |
| `--all-threads` | `dump` | show every thread in the ThreadList; a thread with no address in the module is one line. Excludes `--thread` |
| `--min-dumps N` | `compare` | list a function only if it is in at least N dumps (default 2) |
| `--top N` | `compare` | at most N functions per thread (default 30) |
| `--return-address` | `resolve` | treat the given RVAs as return addresses (look up RVA-1) |
| `--all-candidates` | `resolve`, `dump` | list every identical-code-folding candidate instead of the first 5 plus a count |
| `--allow-pdb-mismatch` | all | continue when the PDB's GUID/age does not match the DLL's CodeView record |
| `--allow-build-mismatch` | `dump` | print names even when the dump and DLL are different builds (loud warning) |

### Exit codes

| Code | Meaning |
|---|---|
| 0 | success |
| 1 | an input file is unreadable or malformed (truncated minidump, corrupt PDB, zero-byte file, bad PE headers): one line `error: ...` on stderr |
| 2 | usage error (bad option), the `--module` is not in the dump, or the `--thread` id is not in the dump (for `compare`: not in every dump, or no thread id common to all) |
| 3 | build mismatch: the minidump's module record disagrees with the DLL, or the PDB does not match the DLL (GUID or age rule, or no GUID and different section tables) |
| 4 | input is well formed but unsupported: a PDB with OMAP streams, a non-x86 dump, a Memory64-only dump |
| 5 | internal error: an unexpected exception type escaped on malformed input (a bug; please report) |

## How an address is named

Output per RVA: section and offset, function name, offset into the function, the
record type that supplied it (`S_GPROC32`, `S_LPROC32` or `S_PUB32`), source
file:line when the PDB has line info, plus the matching public symbol and object file.

### Identical-code folding (several names, one address)

The linker keeps one body for functions with identical code (`CvArea::getID`,
`CvDeal::getID`, `CvSelectionGroup::getID` and 24 other names are one body at one
address in the Caveman2Cosmos build), while the PDB still
lists every function at that address. So one address can have many valid names,
and the PDB cannot say which one ran. When more than one distinct function covers
an address the line is marked and no name is presented as certain:

    0x4942f2 [.text:0x4932f1]  <AMBIGUOUS: 2 candidate functions share this address (identical code folding); the name is NOT certain: a | b>  (S_GPROC32)

The CLI lists the first 5 names (sorted) and `(+N more)`; `--all-candidates` lists
all. In the API (`Pdb.resolve` returns a `Resolution`), `candidates` always has
every name, `ambiguous` is true, and `function`/`function_offset`/`source` are
`None`. They are set only when exactly one function covers the address. Source
file and line are omitted for an ambiguous result (they would belong to one
alias only). The same applies to several function publics at one address.

### Exact addresses and return addresses

`Pdb.resolve(rva, kind)` takes an explicit `AddressKind`:

- `AddressKind.EXACT` (the default): look up the RVA itself. Used for the fault
  address and for RVAs you type to `resolve`.
- `AddressKind.RETURN_ADDRESS` (`resolve_return_address`): look up `RVA - 1`, the
  last byte of the call. Stack words are return addresses, and a call to a
  no-return function can leave the return address equal to the *next* function's
  start. The result keeps the original `rva`, records `lookup_rva`, and the
  printed line says `(return address; looked up at 0x...)`. Offsets refer to the
  looked-up byte, so they are one less than an exact lookup of the same RVA. A
  return address in a non-executable section (`.data`, `.reloc`) is reported as
  "not a return address". If the original RVA is itself the start of a function,
  the line says so (a function pointer or stale word, not a return address).

`dump` looks up the fault address exactly and every stack word as a return address.

### Public symbols never name a function by themselves

A public symbol (`S_PUB32`) has a start but no length. So a public names a function
only when it starts exactly at the address and no procedure record covers it.
Otherwise the line is `<no function symbol covers this address (outside any known
function); nearest preceding public X, 0xNN bytes before it; ...>`: a hint, not a
name. A non-function (data) public is reported as `non-function symbol (data)`.
More than 0x2000 bytes away is also marked "not credible".

### Build-match check (`dump --dll`)

A minidump's module record carries the module's `TimeDateStamp` and `SizeOfImage`.
`dump --dll` compares both with the DLL's PE headers. On a mismatch it prints no
names and exits 3 (`--allow-build-mismatch` prints them under a loud banner). With
no `--dll`, it warns on stderr that the build was not checked. With `--dll`, every command also matches the PDB to the DLL: the PDB info stream's GUID
and age against the DLL's CodeView (RSDS) record (the only debug-directory data read). A different GUID, a PDB info-stream age older than the
DLL's, or a nonzero DBI-header age that differs from the DLL's, is refused with exit 3
(`--allow-pdb-mismatch` overrides). A PDB info-stream age newer than the DLL's with the
same GUID is accepted and noted with both ages. This is Microsoft's `OpenValidate`
rule as read from the public microsoft-pdb source on 2026-11-02; it was not run
against a debugger. If the DLL has no RSDS record and the PDB's section table differs
from the DLL's, that is also refused (exit 3) unless overridden; with an identical
section table it only warns that GUID/age were not checked.

### OMAP

A PDB with OMAP streams (post-link reordering) would need its addresses translated.
That is not implemented, so such a PDB is refused for `resolve` and `dump` (exit 4)
instead of printing names with a warning. `info` still works. The Caveman2Cosmos PDB has no
OMAP streams.

## Hang/snapshot dumps and threads

A debugger-made dump of a *hung* process has no fault. `winedbg --minidump` attaches
by creating a break-in thread in ntdll and records its breakpoint (`0x80000003`; also
`0x4000001F`) as the exception, so the exception thread is the debugger's own, with an
empty stack. `dump` recognises this (a break-in exception code, or no exception stream
at all, with a ThreadList present) and prints `hang/snapshot dump ... not a crash` instead of a
fault, but it still prints the exception code and address. The code alone cannot tell a
debugger break-in from a real breakpoint crash (`int 3`/assert in the game); the header
says so, and `--thread <exception tid>` shows that thread. Other crash dumps behave exactly as before.
A crash dump whose ThreadList is malformed prints a warning on stderr, skips the thread list
and reports the exception thread as before; a snapshot dump with a malformed ThreadList is an
error (exit 1). Stack words from all threads together are capped at 64 MiB.

`dump` reads the ThreadList (stream 3). Per thread it prints the thread id, the x86
integer registers, `eip` (looked up exactly in the PDB when it is inside the module,
otherwise only the owning module name), and the stack-scan candidates. The scan covers
the thread's own stack range from `esp` to its end (capped at 4 MiB per thread) and says
`scanned N of M words`. Words are only numbers looked up in the PDB; memory at `eip` is never read.

Which threads are shown:

| Dump | Options | Threads shown |
|---|---|---|
| crash | none | the exception thread, as always (fault site and stack) |
| hang/snapshot | none | every thread whose `eip` or any stack word is inside the module, **except** the break-in thread; the output says how many other threads were left out and their ids. If no thread qualifies, ThreadList entry #0, with a note |
| any | `--thread TID` | exactly those threads (a crash dump then shows them instead of the fault report) |
| any | `--all-threads` | the whole ThreadList |

The hang default is "threads that touch the game DLL" rather than "the first thread" or
"the one holding the exe": it does not assume the ThreadList order or identify the main
thread by any rule, and in a Proton hang dump it normally yields exactly the game thread
(the other threads sit in ntdll waits). Use `--all-threads` to check that claim on your dump.

`compare` takes two or more dumps. For one thread id (`--thread`, default: every id present
in all the dumps) it resolves each dump's `eip` (exact) and module stack words (as return
addresses), then lists the functions ranked by how many dumps they appear in, then total
hits. Names that share one body (identical-code folding) are listed together as `AMBIGUOUS`.
The result is a ranking of **scan candidates**, not an unwind: a function high on the list
recurs in the stack words, which can include stale residue, and the list says nothing
about call order or whether the function was running.

### Taking the dumps under Proton

1. Use the 32-bit winedbg of the game's prefix: `wine C:\windows\syswow64\winedbg.exe` with the
   prefix environment set (the same `WINEPREFIX`/Proton runtime the game runs in).
2. `--minidump 'Z:\path\to\x.dmp' <hexpid>`: the path in Windows form, quoted, and the PID
   in hex (`0x14c`), taken from the process list. Run it from a directory the prefix can see.
3. Write the dump into a staging directory the Proton container can see and write
   (Wine's `Z:` maps the host root, but check visibility first with `wine cmd /c type Z:\...`),
   then move it out of the staging directory. A path the prefix cannot see yields no file and no error.
4. Never kill a winedbg that is attached: it freezes the game. Let it exit on its own;
   a second attach is safe once the first has exited.
5. Take several dumps some seconds apart and run `compare` on them.

## Caveats

- The stack list from `dump` is a heuristic scan for words that fall inside the
  DLL, not a verified unwind. Some entries are stale stack residue.
- Line numbers in an optimised build are approximate (the line nearest at or
  before the address in the line table).
- The Caveman2Cosmos PDB stores old-style (C11) line tables; modern C13 tables are also
  supported and verified against `llvm-pdbutil`.
- Only x86 minidumps with a MemoryList stream are supported. The ThreadInfoList stream is not read (the ThreadList carries the thread ids).
- A thread's stack list and `compare`'s ranking are scans for words that look like addresses in the module, not unwinds. A hang dump's thread positions are one instant per dump.
- `dump` prints a `registers:` line with the x86 CONTEXT integer registers and
  EFlags (eax ebx ecx edx esi edi ebp esp eip eflags), read from the dump's thread
  context. They are data the game wrote; the tool does not read the memory they
  point at.

## Remote console (AgentRepl)

Lets you (or a script or an assistant) run Python **inside the live game**, for example to inspect
a hung AI turn, through files in a private directory. The in-game half, `ingame/AgentRepl.py`, is a
BUG `gameUpdate` handler that polls every 0.25 s on the game's main thread; `civ4dbg exec`
(`python3 -I civ4dbg.py exec`) is the host half. It is a different class of action from the rest of
this tool: it executes code in the game rather than reading files. The design and its rejected
alternatives are in
[CDT-002](./docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md). **It is not a
sandbox**: read-only mode is a name-based guard against accidents, and write mode is arbitrary
Python in the game process (see [Security](#security)).

    python3 -I civ4dbg.py exec --dir /path/to/UserSettings/AgentRepl -c 'print(gc.getGame().getGameTurn())'
    python3 -I civ4dbg.py exec script.py            # or: ... exec - < script.py
    python3 -I civ4dbg.py exec --status             # heartbeat, switch state
    python3 -I civ4dbg.py exec --reset              # rebuild the persistent namespace

The namespace persists between requests and holds `gc`, `game` and everything from
`CvPythonExtensions`. Output is capped at 64 KiB; a `sys.settrace` deadline (default 2 s,
`--budget` up to 10 s) interrupts Python loops but **cannot interrupt one long engine call**, and
the game is frozen while a request runs. Under Python 2.4 an `except Exception:` in your code can
swallow the timeout. Ctrl-C on the CLI withdraws the request and says whether it ran; SIGTERM does the same on Linux and macOS only (on Windows it terminates the CLI at once, so the
request stays queued until the game answers it as `stale` once its deadline has passed). `--timeout` and `--budget` must be finite. Tracebacks count the `#@` directive lines the CLI prepends.

**Exchange directory.** There is no built-in default. `exec` resolves it, in order, from
`--dir DIR`; else the environment variable `CIV4_REPL_DIR` (the exchange directory itself); else
`CIV4DBG_MOD_DIR` (the installed mod's directory; the exchange directory is
`$CIV4DBG_MOD_DIR/UserSettings/AgentRepl`). With none of the three, `exec` exits 2 and says so.

**Safety gates**

- **Off by default.** The module does nothing unless `<exchange dir>/ENABLE` exists; it is checked on
  every poll, so deleting it switches the console off with no restart. **Only a person creates
  `ENABLE`** (`touch`). Neither the installer nor `civ4dbg exec` creates it.
- **Read-only by default (a read-name allowlist).** A request runs with full write power only if **both**
  `ENABLE_WRITE` exists **and** the request carries `#@ write` (the CLI's `--write`). Anything else
  (no `ENABLE_WRITE`, no `#@ write`, or `#@ write` without the file) is **read-only**, and read-only code is
  checked, before it runs, by `check_readonly()` on the request's tokens (the `tokenize` module, so it works on
  Python 2.4 and 3 and nothing is executed to check it). A refusal has status `readonly` (CLI exit 5, "refused
  by the game (read-only mode)") and an `end readonly` audit line naming the construct. What is **allowed**:
  - attributes that are reads: `get*`, `is*`, `can*`, `has*`, `count*`, `find*` (the prefix then an upper-case
    letter, digit, `_` or the end of the name, so `getGold` and `isTurnActive` pass but `getattr`, `island` and
    `gets` do not), `UPPER_CASE` constants, and a short list of other reads and plain methods: `plot`,
    `groups`, `firstUnit`, `nextUnit`, `readyToMove`, `baseCombatStr`, `movesLeft`, `maxMoves`,
    `defenseModifier`, `firstCity`/`nextCity`, `firstSelectionGroup`/`nextSelectionGroup`, the `str`/list/dict
    methods `append`, `extend`, `pop`, `sort`, `reverse`, `keys`, `values`, `items`, `get`, `has_key`,
    `setdefault`, `copy`, `join`, `split`, `strip`, `lstrip`, `rstrip`, `format`, `lower`, `upper`,
    `startswith`, `endswith`, `replace`, `index`, `rfind`, `zfill`, `isdigit`, and the pure `math` names `pi`,
    `e`, `fmod`, `sqrt`, `floor`, `ceil`, `fabs`, `exp`, `pow`, `hypot`, `sin`, `cos`, `tan`, `asin`, `acos`,
    `atan`, `atan2`, `sinh`, `cosh`, `tanh`, `degrees`, `radians`, `log10`, `modf`, `frexp`, `ldexp` (`log` is
    not one: `CyGame.log(file, text)` writes a log file). Pure Info reads with `Rand` in the name
    (`getMaxWarRand`, `getRandAppearance`, `getGroupRand`, ...) are reads of XML data and are allowed;
  - ordinary Python: loops, comprehensions, `lambda` (its body is scanned like any other code), `print`,
    builtins such as `len`, `sorted`, `range`, `sum`; assignment to local names; item assignment on a dict
    or list built in the same request (or kept in the namespace), exactly as `name[...] = value` (not
    `d[0][1] = ...`), such as `groups[gid] = []`; `getattr(obj, 'getGold')` with a plain string literal that
    is a read;
  - `math` and `clock()`, which the namespace has pre-bound (read-only code cannot import anything).

  What is **refused**: any other attribute (`changeGold`, `setXY`, `pushMission`, `kill`, `saveGame`, ...,
  including when aliased, passed to `map`, or hidden in a comprehension, because the attribute name itself is
  refused); **every `import` and `from ... import` statement** (so no `BugUtil`/`CvUtil` call-by-name route
  and no `from time import sleep`); the names `BugUtil`, `CvUtil`, `getFunction`, `lookupFunction`,
  `lookupModule`, `callFunction`, `bindFunction`, `deferCall`, `Function` and `sleep`, `help`, `license`,
  `credits`, `copyright`, `quit`, `exit`; the names `setattr`, `delattr`, `exec`, `eval`, `compile`,
  `execfile`, `__import__`, `open`, `file`, `reload`, `globals`, `locals`, `vars`, `input`, `raw_input`;
  `getattr` unless its second argument is a literal read name; any name containing `__`; assignment,
  augmented assignment, `del`, `for` and `as` targets that are attributes, or items of anything not known to
  be a local dict or list (a `del` is checked wherever it appears, also after a colon); the getters found to
  hand out or advance a game random generator, by name: `getSorenRand`, `getSorenRandNum`, `getMapRand`,
  `getMapRandNum`, `getASyncRand`, `getNewCityName` (found by reading the game's Python method tables in one
  Caveman2Cosmos build; **not a proven-complete list**: another such method, in this build or a later one,
  would pass until it is added; the list is `_RNG_DENIED` in `ingame/AgentRepl.py`, derived from the DLL of
  that one mod, and it may be incomplete for any other mod's DLL); a request whose first two lines contain `coding:` or `coding=`, or that
  starts with a byte order mark (Python 2 could compile it in another encoding than the one that was
  checked); backticks (`repr()` in disguise); and anything that does not tokenize. A second, older refuse
  list then runs over the same source in read-only mode (mutating game calls such as `saveGame`,
  `setGameTurn` and `doControl`, plus `os.`, `open`, `subprocess`, `CyMessageControl`, threads and
  imports outside a short list).

  **This is a name-based guard against accidents, not a sandbox.** A getter that mutates state under a
  read-looking name, or a mutator reached through an allowed name, would pass; the allowlist is as good as the
  names, and a determined caller can find a way round it. **What it cannot stop:** pure computation that stalls
  the game in one long C call (`9**9**9**9`, `'a' * 10**10`, a catastrophic regular expression), because a name
  check cannot see it and the `sys.settrace` budget cannot interrupt a single C call (see the budget note
  above). A name that is not on the lists is simply refused, so a legitimate read may need an addition.

  **Write mode** (`ENABLE_WRITE` **and** `#@ write`): the allowlist and the refuse list are both off
  **entirely**; `saveGame`, `os.`, `open` and imports all pass. After a write-mode request the persistent
  namespace is rebuilt, so a function or object defined there cannot be called later from a read-only request.
  Nothing in the code limits what a write-mode request does: saving over saves, quitting, changing the
  active player or the turn are all possible.
- **Replay defence 1: session token.** At load the game makes a random per-session token (`os.urandom(16)`,
  32 hex digits; it exists in Python 2.4 and does not depend on the quantized clock; if it is missing the token is
  built from the pid, the relative clock, `id()` and the coarse time, which still differs between sessions) and
  publishes it as the first line of `status.txt` (`session: <token>`). The host reads it and writes
  `#@ session <token>` as the **first line of every request**. The game refuses, with an audit line and a
  `badsession` reply (exit 3, "the request did not run"), any request whose first line is missing or carries
  another token, even with `ENABLE_WRITE` and `#@ write`. A request left from an earlier game session can
  therefore never run in a later one. If the game restarts between the host reading `status.txt` and the game
  polling, the host re-reads the token and retries **once** (it never ran); it sends nothing at all when
  `status.txt` has no valid token. The token is not a secret against the same user account (it is in `status.txt`, in a
  private directory): it separates sessions, it does not authenticate a caller.
- **Replay defence 2: per-request deadline.** The token cannot see a request of the *current* session that the
  host abandoned (for example after SIGKILL) while the game thread was blocked. So the host also writes
  `#@ notafter <deadline>` as the **second line** (after `#@ session`), a time on the game's **relative clock**
  (`time.clock`, exact; the wall clock is quantized to 128 s inside the game by the single-precision FPU under
  Direct3D 9). It reads `alive_clock` from `status.txt` and that file's mtime and computes
  `deadline = alive_clock + (host_now - status_mtime) + timeout + 2`, which is the moment the host stops waiting,
  in the game's own time. The game refuses, with an audit line and a `stale` reply (exit 3, "it did not run"),
  any request whose deadline has passed on its own clock, and any request whose second line is not a valid
  `#@ notafter <non-negative decimal>` (nan, inf, signs, exponents and trailing words are all invalid). On a
  `stale` reply the host re-reads `status.txt` and retries **once**. No file mtime or wall-clock reading is used
  for any request decision. Needs the module protocol **version 3**; `exec` and `exec --status` report a module
  whose `status.txt` says `version: 2` (or lower) as "older; reinstall and restart" and send nothing.
- **Switched off means purged.** While `ENABLE` is absent the game deletes every queued `req-*.py` (one audit line
  each, at most 8 per poll; a valid id also gets a `refused` reply saying it was purged, which the host reports as exit 4, "did not run"), so nothing queued while the console is off can run after it is switched on. A module
  that disabled itself with `ENABLE` still present does not purge.
- **Request hygiene.** ids are `[0-9A-Za-z-]`; 64 KiB limit. The wall clock (`time.time()`, the `epoch` in
  `status.txt`) is informational only. Audit lines carry both `epoch_coarse=` and the exact `clock=`.
  **Cap:** at most 256 request files are tracked; a *new* request beyond that is refused (deleted, audited,
  answered `refused`, at most 8 per poll). An unreadable request is removed or skipped with one audit line, and never blocks the queue or
  counts toward the self-disable.
- **Status file (host).** `status.txt` is opened without following symlinks and without blocking (so a FIFO there
  cannot hang the host), must be a regular file of at most 8 KiB, and its mtime counts as a heartbeat (and as the
  basis of the deadline estimate) only if it is not more than 5 s ahead of the host clock.
- **Audit.** Before a request runs, its full source (backslash, CR and LF escaped onto one line) is appended to
  `audit.log` as `<id> begin ...`; if that write fails the request is **not run**. The outcome follows as
  `<id> end <status> <ms>`. So a request that hangs or kills the game still has its source on record. The
  game claims a request by deleting it and runs it only if that delete succeeds, so a host-side
  withdrawal that wins is never executed. Rotated at 1 MiB.
- **Private directory.** On Linux and macOS the exchange directory is mode 0700 in the mod's `UserSettings/`.
  The CLI refuses a directory if any path component is a symlink or not owned by you (or root), if an
  ancestor is group/other-writable without the sticky bit, or if the directory has any group/other
  permission. It opens the directory once and works relative to that descriptor; replies are opened without
  following symlinks, must be regular files, and are capped at 256 KiB. On Windows there is no mode 0700,
  no owner check and no descriptor-relative opening: the directory is only as private as the ACL it
  inherits from its parent folder (keep the mod inside your own user profile), and the reply file's
  owner is not checked. The CLI still refuses symlinks, junctions and other reparse points in the path;
  it records the exchange directory's identity (volume serial and file index) when it checks it and compares
  it again, with a reparse-point check, before every file operation (every open, replace, unlink and
  file read, including the `--status`, heartbeat-age and `ENABLE` reads), so replacing the
  directory or one of its ancestors afterwards is refused (exit 5); it also checks each file it opens (lstat,
  then open, then fstat of the same file index), and replies must be regular files within the 256 KiB cap.
  Three gaps remain on Windows: a swap in the instant between the comparison and the open; a file system
  that reports no file index, where the comparison is skipped; and anyone with write access to the parent
  folder. The CLI prints a warning naming what is not enforced. The per-OS table is in
  [docs/platform-support.md](./docs/platform-support.md).
- **Never raises into the game**; after 5 consecutive internal errors the module disables itself and says so
  in `status.txt`.

**Exit codes of `exec`** (not the PDB commands' codes above):

| Code | Meaning |
|---|---|
| 0 | ok (stdout printed) |
| 1 | the code raised in the game (stdout on stdout, traceback on stderr) |
| 2 | usage error (bad option, no exchange directory given, budget outside (0, 10], request over 64 KiB, unreadable file) |
| 3 | no reply: timed out, game not polling or no session token in `status.txt`, directory missing, the game-side budget was exceeded, the request was stale (its deadline passed in the game, after the one retry), or the game refused the session token (after the one retry), or the installed module is older than version 3. On a host timeout the request file is deleted; the message says whether it was withdrawn (did **not** run) or had already been picked up (**ran**, reply lost) |
| 4 | switched off: no `ENABLE` |
| 5 | refused: read-only mode (`readonly`), the older refuse list, `--write` without `ENABLE_WRITE`, or an unsafe exchange directory |
| 6 | reply malformed |

**Install** (explicit `--mod-dir`; review the `--dry-run` first). Run from a clone of this repository, since
the installer and the in-game module are not in the wheel:

    python3 -I tools/agentrepl_install.py install --mod-dir /path/to/mod [--dry-run] [--backup-dir DIR] [--forbid DIR ...]
    python3 -I tools/agentrepl_install.py status  --mod-dir /path/to/mod

It copies `AgentRepl.py` to `Assets/Python/BUG/`, adds exactly one line to `Assets/Config/init.xml`,
`<event type="gameUpdate" module="AgentRepl" function="onGameUpdate"/>` just
before `</bug>` (file's own line ending kept, original backed up first, see **Backup location** below,
idempotent, a hand-edited variant of the line counts as present; the module is copied first, `init.xml` last),
and creates `UserSettings/AgentRepl/` (mode 0700 on Linux and macOS; Windows ignores modes, so there it only inherits its parent folder's ACL, and the installer says so). It does **not** create `ENABLE`: start the game, load a
save, and create `ENABLE` by hand when ready. `install` **refuses** (exit 3) a `--mod-dir` that is inside any git
work tree (`git -C DIR rev-parse --is-inside-work-tree`, plus a `.git` walk in case git is missing), so the
console cannot be committed into a repository by accident, and any directory you name with `--forbid DIR`
(repeatable; there is no built-in list). It goes only into a plain directory or a non-git working copy such as
an SVN checkout.

**Backup location.** Without `--backup-dir`, the original `init.xml` goes to a per-install folder named
`<mod directory name>-<first 12 hex of the sha256 of the resolved mod path>` under:

| OS | Default root |
|---|---|
| Linux and other POSIX | `$XDG_STATE_HOME/civ4dbg/agentrepl`, else `~/.local/state/civ4dbg/agentrepl` |
| macOS | `~/Library/Application Support/civ4dbg/agentrepl` |
| Windows | `%LOCALAPPDATA%\civ4dbg\agentrepl` (an error if unset) |

`CIV4DBG_STATE_DIR`, if set, replaces the root on every OS. The folder holds `init.xml.pre-agentrepl`, its
`.sha256` and `manifest.json` (schema version, resolved mod path, UTC time, tool version, files backed up
and changed). Folders are created mode 0700 on Linux and macOS; Windows enforces no mode, so there a
backup folder only inherits its parent's ACL. `--backup-dir DIR` always wins and also gets a manifest.
The installer refuses (exit 3) a backup location inside a git work tree, inside the mod directory, or
inside a `--forbid` directory, and prints the location on install and uninstall; `--dry-run` prints it and
touches nothing. An install never overwrites an existing backup: the first, pre-install copy is kept. A backup is written atomically. With
the backup location (the default folder or an explicit `--backup-dir`) that already holds a backup but no `manifest.json`, install refuses (exit 3, nothing
changed) unless that backup is identical to the mod's `init.xml`, since it could belong to another mod. This applies only when install would edit `init.xml`.
`CIV4DBG_STATE_DIR` must be an absolute path (a relative value exits 2).

**Uninstall**: `python3 -I tools/agentrepl_install.py uninstall --mod-dir DIR [--backup-dir DIR]` removes `ENABLE*`, the line,
`AgentRepl.py` (and `.pyc`), and the exchange directory's request/reply/status files; `audit.log` is kept
unless `--purge`. Without `--backup-dir` it finds the backup folder from the mod path and requires its
`manifest.json` to name the same mod path, else it exits 2 and says where it looked. With `--backup-dir`, a
missing manifest (a backup made by an earlier version) only prints a warning; a manifest naming a
different mod path refuses either way. Uninstall removes only the inserted line from `init.xml` and never restores the backup automatically; the backup is a safety copy for manual recovery, and it is never changed.

**Python 2.4 note.** `ingame/AgentRepl.py` is restricted to the subset valid in Python 2.4 and 3 (no
`with`, `as e`, ternaries, combined try/except/finally, `json`, `hashlib`, `print` statements) so the host
tests can import it; `tests/test_agentrepl_module.py` enforces this with an AST check.

## Security

The remote console runs Python in the game process, which is a larger power than anything else in
this tool. Read this before enabling it. Reporting: see [SECURITY.md](./SECURITY.md).

- **Write mode is arbitrary Python execution in the game process**, with the privileges of the user who
  started the game. A write-mode request can import any module, open files, start processes, save over
  saves, quit the game or change game state.
- **Under Wine or Proton, the `Z:` drive can reach the host filesystem** unless the prefix has removed or
  remapped it. Game Python can then read and write whatever that user can. Whether `Z:` is mapped depends on
  the prefix; do not rely on it being absent.
- **It is off by default.** Nothing happens until a person creates `ENABLE` by hand, and write power needs a
  second file (`ENABLE_WRITE`) and `#@ write` on the request. The installer and the CLI never create either
  file. Delete `ENABLE` to switch it off with no restart.
- **Read-only mode is a guard against accidents, not a boundary.** It is a name-based check on the request's
  tokens (see above). Treat anything that can write into the exchange directory as able to run code in the
  game: the session token sits in `status.txt` in that directory, so it separates sessions and authenticates
  no one. The access control is the directory's owner and mode 0700 plus the two files (on Windows: the ACL the directory inherits from its parent folder plus the two files; there is no owner or mode check).
- Every request is recorded in `audit.log` before it runs.
- The PDB, minidump and PE readers only read files you point them at, and treat them as untrusted input:
  malformed input fails with a clean error (exit 1 or 4), and `tools/fuzz_inputs.py` checks that no other
  exception escapes.

The full decision, including what was rejected, is
[CDT-002](./docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md).

## Development

Run everything from the repository root with isolated mode:

    python3 -I tools/dev.py check    # ruff check + ruff format --check + pytest + synthetic fuzz
    python3 -I tools/dev.py lint     # ruff check + ruff format --check
    python3 -I tools/dev.py test     # pytest
    python3 -I tools/dev.py fuzz     # seeded malformed-input fuzz on the committed synthetic fixtures

Each exits 0 on success and non-zero on failure. Setup: `pip install -e ".[dev]"` (adds `pytest==9.1.1`) and
`ruff` pinned to **0.17.4**. `dev.py` uses `ruff` from `PATH` only if it is exactly that version, otherwise
`uvx ruff@0.17.4`, otherwise it stops with an install hint. The pin lives in `tools/dev.py`
(`RUFF_VERSION`) and `.github/workflows/ci.yml`; change both together.

CI (`.github/workflows/ci.yml`) runs `tools/dev.py check` on the latest 3.11 patch release (the supported floor) and the latest 3.x, each on Linux, Windows and macOS. (`.python-version` pins 3.11.18 for local development only; setup-python has no build of it for macOS arm64 or Windows.) **CI never
needs the game, Wine, a game DLL or PDB, a minidump or a test-data directory.** The tests that use real game
files (`tests/test_real_*.py`, and the named `.dmp` they need) skip themselves with a reason that names the
missing file when it is absent; everything else runs on synthetic inputs and a small committed PDB built
by LLVM's linker.

To run the real-binary tests, put your own copies of the files (not redistributable, never commit them) in
a directory outside this repository and name it in `CIV4DBG_TEST_DATA`:

    CIV4DBG_TEST_DATA=/path/to/data python3 -I tools/dev.py check

The tests look for `CvGameCoreDLL.pdb`, `CvGameCoreDLL.dll` and the three `MiniDump-v45.BETA.8848-*.dmp`
crash dumps by those names. When the variable is unset, or a file is missing, the test that needs it
skips with a reason naming the variable and the file. `tools/check_pdb_claims.py` and the real-data options
of `tools/fuzz_inputs.py` take explicit paths.

    python3 -I tools/check_pdb_claims.py --pdb P [--dll D]       # reproduces the checks quoted in docs/llvm-diagnosis.md

`check_pdb_claims.py` needs a real PDB and is not part of `check`. Decisions are recorded under
[docs/architecture/adrs/cdt/](./docs/architecture/adrs/cdt/INDEX.md); the local prefix is registered in
[docs/PREFIXES.md](./docs/PREFIXES.md).

## Contributing

Issues, Discussions and validation reports are welcome; pull requests and third-party code are not
accepted. See [CONTRIBUTING.md](./CONTRIBUTING.md) for why and how to report, and
[docs/platform-support.md](./docs/platform-support.md) for what has been tested and where
validation reports are most needed. Questions and ideas go to GitHub Discussions. Using a coding agent
in a fork? See [AGENTS.md](./AGENTS.md).

## Standards conformance

This repository follows the Stele documentation and engineering standards. Deviations are recorded in
[.standards-config.json](./.standards-config.json) and printed by the Stele validator.

## License

MIT. See [LICENSE](./LICENSE). Copyright (c) 2026 Matt Modene.
