# Changelog

**Purpose**: Notable changes to civ4-debug-tools, one section per release.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

All notable changes are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

**Pre-1.0.** Below 1.0.0 the public interface (the `civ4dbg` command line, its exit codes, the
Python API of the `civ4dbg` package and the AgentRepl exchange protocol, currently version 3) may
change in any minor release (0.x). A breaking change bumps the minor number; additive changes and
fixes bump the patch number. Breaking changes are listed under "Changed" or "Removed".

Standards deviations are recorded in `.standards-config.json` and printed by the Stele validator.

## [Unreleased]

## [0.1.0] - 2026-11-07

Initial public release.

### Added

- `civ4dbg` command line (`python3 -I civ4dbg.py`, or the `civ4dbg` console script after
  `pip install .`) with four commands:
  - `resolve`: look up RVAs in a PDB, as exact addresses or as return addresses, with source file
    and line when the PDB has them. Several functions at one address (identical-code folding) are
    reported as ambiguous with every candidate, never as one name.
  - `dump`: read an x86 minidump and resolve the fault site, the x86 integer registers and a stack
    scan, with a build-match check of the dump against the DLL (`TimeDateStamp`, `SizeOfImage`) and of
    the PDB against the DLL (CodeView GUID and age). Hang/snapshot dumps made by a debugger are
    recognised, and `--thread` / `--all-threads` select threads from the ThreadList.
  - `compare`: rank the PDB functions that recur in a thread's stack scan across several dumps.
  - `info`: summarise the PDB container.
- Readers, written from published layouts and using only the standard library
  ([CDT-001](./docs/architecture/adrs/cdt/CDT-001-standard-library-only-runtime.md)): MSF 7.00
  containers, the DBI stream, section headers, public and procedure symbols, C11 and C13 line
  tables, PE headers and the debug directory, and x86 minidumps. Distinct exit codes for unreadable
  input (1), usage errors (2), build mismatch (3), unsupported input such as OMAP streams (4) and
  internal errors (5).
- AgentRepl, an opt-in Python console for a running game
  ([CDT-002](./docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md)): the in-game
  module `ingame/AgentRepl.py` (Python 2.4/3 subset), the host command `civ4dbg exec`, and the installer
  `tools/agentrepl_install.py` (`install`, `uninstall`, `status`, `--dry-run`, `--backup-dir` (optional: the default is a per-install folder under the user state directory, with a
  `manifest.json`; an install never overwrites an existing backup, writes it atomically, and refuses an explicit `--backup-dir` holding a backup with no manifest that does not match the mod's `init.xml`; `CIV4DBG_STATE_DIR` must be absolute; `uninstall` verifies the manifest and removes only the inserted line, never restoring the backup), repeatable
  `--forbid DIR`; it refuses a mod directory inside a git work tree). Off unless an `ENABLE` file exists;
  read-only by default through a tokenize-based allowlist of read names; write mode needs `ENABLE_WRITE`
  and `#@ write`; session-token and per-request-deadline replay defences; audit log written before each
  request runs; exchange protocol version 3.
- The exchange directory for `exec` is given by `--dir DIR`, else `CIV4_REPL_DIR`, else
  `CIV4DBG_MOD_DIR` (the installed mod's directory). There is no built-in default; with none of them
  `exec` exits 2.
- `SECURITY.md` with the supported versions, how to report, and the AgentRepl threat summary.
- Development command surface `tools/dev.py` (`check`, `lint`, `test`, `fuzz`), a pinned `ruff`
  (0.17.4) configuration, a `dev` extra (`pytest>=8`), a malformed-input fuzz harness, and a GitHub
  Actions workflow that runs `check` on Python 3.11 and the latest 3.x without a game, a DLL/PDB or
  any local game file. Tests that need real game files read them from the directory named by
  `CIV4DBG_TEST_DATA` and skip with a reason naming the variable and the missing file.
- Architecture decision records CDT-001 and CDT-002 with a local prefix registry.
- `civ4dbg exec` and the AgentRepl installer also run on Windows and macOS (untested on both until CI
  has run; see [docs/platform-support.md](./docs/platform-support.md)). Where the OS offers no uid,
  `O_NOFOLLOW` or directory descriptors, the CLI refuses symlinks, junctions and other reparse points,
  compares the exchange directory's identity before every file operation (opens, replaces, removals, and
  the `--status`, heartbeat-age and `ENABLE` reads; a mismatch is refused with exit 5), checks each file
  it opens, and prints a one-time warning naming what is not enforced. Three gaps remain on Windows: a
  swap in the instant between the comparison and the open; a file system that reports no file index, where
  the comparison is skipped; and anyone with write access to the parent folder. On macOS the root-owned
  `/var`, `/tmp` and `/etc` aliases into `/private` are accepted. The per-OS protection table is in the
  platform-support doc.
- The installer states plainly that AgentRepl needs BUG, and names which of `Assets/Config/init.xml`
  and `Assets/Python/BUG/` is missing.
- Community files: `CONTRIBUTING.md`, `CODE_OF_CONDUCT.md`, issue forms (bug report, validation report),
  a pull request template and a workflow that closes pull requests, with
  [docs/platform-support.md](./docs/platform-support.md) for what is tested where.
- GitHub Actions runs `check` on Ubuntu, Windows and macOS (Windows is non-blocking for now).
- The in-game module finds its exchange directory through BUG's `SystemPaths`, falling back to a path
  derived from where the module file sits, and notes the fallback once in `audit.log` (or the game's
  stderr). A failed `SystemPaths` import is remembered rather than retried on every poll.
- SIGTERM on the CLI withdraws a pending request on Linux and macOS only; on Windows only Ctrl-C does.
- `AGENTS.md` and `CLAUDE.md`: instructions for coding agents working in a fork or local checkout.

### Notes

- The documentation states mode 0700 for Linux and macOS only; on Windows the directory is as private as
  the ACL it inherits ([CDT-002](./docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md),
  Amendments).
- The README states that the read-only random-generator getter list (`_RNG_DENIED`) comes from one mod's
  DLL and may be incomplete for others.
- Requires Python 3.11 or newer. The wheel contains only the `civ4dbg` package and the license; the
  in-game module and the installer are used from a clone of the repository.
- Licensed under the MIT license.
- Not affiliated with Firaxis, 2K or the Caveman2Cosmos team. No game files are included.
- Tested against the Caveman2Cosmos mod's build; the readers are not specific to it.

[Unreleased]: https://github.com/mattmodene/civ4-debug-tools/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/mattmodene/civ4-debug-tools/releases/tag/v0.1.0
