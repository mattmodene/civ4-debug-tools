# CDT-002: AgentRepl, an Opt-In File-Exchange Python Console

**Status**: Accepted
**Date**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

## Context

A crash address says where the game died, not why. For hangs and bad AI turns the useful question is "what is the game state right now", and the only way to ask it is to run code inside the live game. Civ4's embedded interpreter is Python 2.4 running under Wine or Proton. It executes on the game's main thread, so code that runs there can read and change anything the game exposes.

That is a different class of action from the rest of this project, which only reads files. The decision therefore has to answer one question before any other: what stops a console like this from doing damage? The honest constraints are:

- Python 2.4 has no `ast` module, no `rexec`, no `with` statement and no `json`, so the usual ways to restrict untrusted Python are unavailable. The only restriction mechanism the interpreter offers is name-level inspection of the token stream (`tokenize`), which can be wrong.
- Inside the game, Direct3D 9 puts the floating-point unit into single precision, so `time.time()` is quantized to roughly 128 s and can be about 127 s off in either direction. A relative clock (`time.clock`) stays exact. No request decision may use the wall clock or a file's modification time.
- The game thread is frozen while a request runs, and a `sys.settrace` deadline cannot interrupt a single long call into native code.
- A request file can outlive the game session, or the host that wrote it, and must not run later when nobody is watching.
- The console is a developer tool. It must be absent from, and unreachable in, anything that is not deliberately set up for it.

## Decision

We will provide the console as a BUG `gameUpdate` handler (`ingame/AgentRepl.py`) that exchanges files with a host CLI (`civ4dbg exec`, `civ4dbg/remote.py`) through one private directory, and we will make it inert, read-only and audited by default. It is **not a sandbox** and we will say so wherever it is described.

1. **Off unless switched on.** The module does nothing unless the file `ENABLE` exists in the exchange directory. It is checked on every poll, so deleting it turns the console off with no restart. Only a person creates `ENABLE`, by hand; neither the installer nor the host CLI ever creates it. While `ENABLE` is absent, every queued request is deleted, so nothing queued while the console is off runs when it is switched on.
2. **Read-only unless two gates are both present.** A request has write power only if the file `ENABLE_WRITE` exists **and** the request carries the line `#@ write`. Anything else is read-only. This is the only access rule; there is no third mode.
3. **Read-only means an allowlist, not a deny-list.** Before a read-only request runs, its tokens (via `tokenize`; nothing is executed to check it) must pass `check_readonly()`. Attributes must be reads (`get*`, `is*`, `can*`, `has*`, `count*`, `find*`, `UPPER_CASE` constants, or a short named list); names that call by string, introspect or open files are refused; imports, assignments to attributes and items of non-local containers, and anything that does not tokenize are refused. A second, older refuse list then runs over the same source. A name not on the lists is refused, so the failure direction is "refuse a legitimate read".
4. **Write mode turns both checks off entirely.** With both gates present the source runs unchecked, and the persistent namespace is rebuilt afterwards so that nothing defined in write mode can be called later from a read-only request.
5. **Session token.** At load the game makes a random token (`os.urandom(16)`) and publishes it as the first line of `status.txt`. Every request's first line must be `#@ session <token>`; otherwise it is answered `badsession`.
6. **Per-request deadline (protocol 3).** The second line must be `#@ notafter <deadline>`, a time on the game's relative clock, computed by the host from `status.txt` as the moment the host stops waiting. A request whose deadline has passed, or whose line is missing or malformed, is answered `stale`.
7. **Audit before execution.** The full source (escaped onto one line) is appended to `audit.log` as `<id> begin ...` before it runs; if that write fails the request does not run. The outcome follows as `<id> end <status> <ms>`.
8. **Bounded work.** One request per poll; request and output caps of 64 KiB; at most 256 tracked request files; a default execution budget of 2 s, at most 10 s; and self-disable after 5 consecutive internal errors. The module never raises into the game.

The wire format is below. It is the load-bearing contract between the two halves and is versioned (`version: 3` in `status.txt`; the host refuses an older module).

| Item | Contract |
|---|---|
| Exchange directory | `<mod>/UserSettings/AgentRepl/`, mode 0700; the host refuses a symlink, a foreign owner, or any group/other permission |
| Request | host writes `req-<id>.tmp`, renames to `req-<id>.py`; `<id>` is `[0-9A-Za-z-]+`, at most 80 characters |
| Directives | `#@ session <token>` (line 1), `#@ notafter <t>` (line 2), then optional `#@ write`, `#@ reset`, `#@ budget <s>` |
| Claim | the game deletes the request file and runs it only if the delete succeeded; a host-side withdrawal that wins is never executed |
| Reply | game writes `rep-<id>.tmp`, renames to `rep-<id>.txt`: header lines (`id`, `status`, `elapsed_ms`, `turn`, `polls`, `stdout_bytes`, optional `detail`), a `---` line, stdout, then an optional traceback |
| Statuses | `ok`, `error`, `timeout`, `badsession`, `stale`, `toolarge`, `refused`, `readonly` |
| Heartbeat | `status.txt`, rewritten about every 2 s: `session`, `alive_clock`, `epoch` (informational), `turn`, `enabled`, `write_enabled`, `disabled_reason`, `last_id`, `polls`, `version` |
| Polling | every 0.25 s while enabled, every 1 s while off, on the main thread |

Installation changes the mod in exactly three ways (`tools/agentrepl_install.py`): copies the module, adds one `gameUpdate` event line to the mod's `Assets/Config/init.xml`, and creates the exchange directory. The installer refuses a target that is inside a git work tree, so the console cannot be committed into a repository by accident.

## Consequences

### Positive
- The console can answer "what is the game doing" for a hang or a bad turn, which no file-reading tool can.
- It is absent by default: with no `ENABLE` file it is a heartbeat and a purge loop, and nothing queued while off can run later.
- The read-only allowlist fails closed. A forgotten mutator is refused rather than run, which is the opposite of a deny-list, where the mutator you did not think of runs.
- Replay is excluded without trusting the unreliable wall clock: the session token rules out requests from an earlier game, and the deadline rules out a request of the current session that the host abandoned.
- Every request that runs, and every one that does not, is on record in `audit.log`, with its source recorded first.

### Negative
- **Write mode is arbitrary code execution inside the game process.** With `ENABLE_WRITE` and `#@ write` present, a request can import any module, open files, start processes, save over saves, quit the game or change game state. The process runs with the full privileges of the user who started the game. Under Wine's default configuration the host filesystem is reachable through the `Z:` drive, so the files that user can read or write are reachable from game Python. Whether `Z:` is mapped depends on the Wine prefix; this decision does not rely on it being absent.
- **Read-only is a guard against accidents, not a security boundary.** It is as good as the names. A getter that mutates state under a read-looking name, or a mutator reached through an allowed name, passes. The allowlist reflects the method tables read at one build of the mod (including a named list of getters that advance the game's random generator, which is not proven complete); a new method in a later build is judged only by its name.
- **The checks cannot see computation that stalls in one native call** (`9**9**9**9`, a huge string multiplication, a catastrophic regular expression). The trace-based budget interrupts Python-level loops only, and the game is frozen for the duration. Under Python 2.4 user code can also swallow the timeout with a bare `except Exception:`.
- **The session token authenticates no one.** It lives in `status.txt` in the same directory. Any process that can read that directory can send valid requests. The real access control is directory ownership and mode 0700, plus the `ENABLE`/`ENABLE_WRITE` files.
- Policy such as "never save over the player's saves, quit, change the active player or alter the turn without being asked" is not enforced in code once both write gates are present.
- The in-game module is restricted to the subset of Python common to 2.4 and 3 (so the host tests can import it), which makes it harder to read and to extend. A test enforces the subset.
- Two cooperating halves must stay in step; a protocol change needs a version bump and a reinstall plus game restart.

### Neutral
- A request that times out on the host is withdrawn if it has not yet been claimed, and the CLI says whether it ran. If it was already claimed, it ran and the reply was lost.
- The wall clock is recorded in the audit log and `status.txt` for humans, but never used to decide anything.

## Alternatives Considered

### Alternative 1: No console; rely on logs and minidumps
**Description**: Diagnose only from files the game writes and from crash dumps.
**Pros**: No execution in the game; no new attack or accident surface.
**Cons**: A hang or a corrupted AI turn leaves no dump at the moment of interest, and a dump holds memory, not the game's object model. Questions like "which unit group is stuck" cannot be asked.
**Rejection Reason**: It leaves the hardest class of bug without a way in. It remains the default path for crashes; the console is for live inspection only.

### Alternative 2: A network listener inside the game
**Description**: Open a socket in the game and accept commands from a client.
**Pros**: Lower latency; no polling; a conventional remote-REPL design.
**Cons**: It exposes code execution to every local process, or to the network if bound badly, and authentication has to be built. Polling file access is limited by operating-system permissions on a directory the user owns, with no new listening port. Polling at 0.25 s is adequate.
**Rejection Reason**: A larger and harder-to-reason-about attack surface for a latency we do not need.

### Alternative 3: A real sandbox (restricted builtins, `rexec`, AST analysis)
**Description**: Constrain execution so even hostile code cannot escape.
**Pros**: Would justify running unattended code.
**Cons**: The interpreter is Python 2.4. It has no `ast` module, and `rexec` is disabled. Restricted-builtins sandboxes in Python are well known to be escapable, and the game exposes a large native API (`CvPythonExtensions`) that any sandbox would have to model. A guarantee we cannot deliver is worse than an honest guard.
**Rejection Reason**: Not achievable on this interpreter, and claiming it would be misleading. We chose a token-level allowlist for accidents and put the real control in the two files and the directory permissions.

### Alternative 4: A deny-list of known mutators as the read-only rule
**Description**: Allow everything except a list of names known to change state.
**Pros**: Simple, and does not refuse legitimate reads.
**Cons**: It fails open. Any mutator not on the list, including ones in later builds, runs in what the operator believes is read-only mode. The game's API has thousands of methods and the list is never complete.
**Rejection Reason**: The failure direction is wrong. The deny-list survives only as a second layer behind the allowlist.

### Alternative 5: Always-on, or on by a switch the tool can set
**Description**: Enable the console at install time or from the host CLI.
**Pros**: Fewer manual steps.
**Cons**: A tool that can turn on its own access removes the human decision that makes the rest of the design meaningful, and a stray install would leave a live console.
**Rejection Reason**: `ENABLE` and `ENABLE_WRITE` are created only by a person, by hand.

## Success Metrics

- A mod with no `ENABLE` file never runs a request; the audit log shows only purges.
- A request without `#@ write`, or without `ENABLE_WRITE`, never changes game state; a call to a setter is answered `readonly` and appears in the audit log as `end readonly`.
- No request runs from an earlier game session or after the host stopped waiting.
- The module's tests (the read-only checker, session token, deadline, coarse clock and end-to-end suites) pass on the host Python, and the subset test passes.

**Review Triggers**:
- Evidence that a read-only request changed state (treat any as a defect in the allowlist, and extend the list by name).
- A new build of the mod that adds methods not covered by the allowlist's name rules, or new random-generator getters.
- A way to run a sandboxed interpreter for the game's Python.
- Any need to run the console unattended or from another user account, which this design does not support.

## References

- Related to [CDT-001](./CDT-001-standard-library-only-runtime.md): the host half is standard-library-only Python.
- [`ingame/AgentRepl.py`](../../../../ingame/AgentRepl.py) - the in-game module; its header documents the protocol
- [`ingame/INDEX.md`](../../../../ingame/INDEX.md) - the in-game directory
- [`civ4dbg/remote.py`](../../../../civ4dbg/remote.py) - the host CLI (`exec`) and its exit codes
- [`tools/agentrepl_install.py`](../../../../tools/agentrepl_install.py) - install, uninstall and status
- [README](../../../../README.md), section "Remote console (AgentRepl)" - usage, exit codes and the full list of what the allowlist accepts and refuses

## Amendments

### 2026-11-07 - Correction: the "mode 0700" protection holds on Linux and macOS only

**Reason**: The Decision's wire-format table ("Exchange directory ... mode 0700; the host refuses a symlink, a foreign owner, or any group/other permission") and the first Consequence bullet naming "directory ownership and mode 0700" as the real access control were written for POSIX and read as true of every OS. When the host CLI gained Windows and macOS support, the platform model made the per-OS truth explicit:

- **Linux and macOS**: as written. The directory is owned by the user and mode 0700, ancestors are checked for owner and writability, and the host opens it once and works relative to the descriptor.
- **Windows**: there is no uid and no meaningful mode. The directory's privacy is the ACL it inherits from its parent folder. The host still refuses symlinks, junctions and other reparse points in the path, compares the directory's identity again before each file operation, and checks each file it opens, but it does not check directory or reply-file ownership, and it cannot close the race between a check and the open that follows. It prints a one-time warning naming this.

**Effect on the decision**: None. The decision (opt-in, read-only by default, audited, not a sandbox, one private exchange directory) is unchanged; only the claim of what makes the directory private is narrowed on Windows. The current per-OS table is in [platform-support](../../../platform-support.md#exchange-directory-protection-by-os).
