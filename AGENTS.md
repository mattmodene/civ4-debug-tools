# Agent Guide

**Purpose**: Instructions for coding agents working in a fork or local checkout of civ4-debug-tools: how to run the checks, what must not change, and how to report findings upstream.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## What this is

civ4-debug-tools resolves crash addresses in a Civilization IV mod's `CvGameCoreDLL.dll` to function names and source lines using its PDB, and reads minidumps. It also provides AgentRepl, an opt-in Python console that runs inside the running game, driven from the host by `civ4dbg exec`. The runtime uses only the Python standard library. You may change anything in your own fork or checkout. The upstream project accepts no pull requests and no third-party code (see "Proposing changes upstream").

## Commands

Run from the repository root:

```bash
python3 -I tools/dev.py check   # lint + test + fuzz (what CI runs)
python3 -I tools/dev.py lint    # ruff check and ruff format --check
python3 -I tools/dev.py test    # pytest
python3 -I tools/dev.py fuzz    # malformed-input fuzz on the committed synthetic fixtures
```

- Python 3.11 or newer (`.python-version` holds the development floor; `pyproject.toml` has `requires-python`).
- Install the dev tools with `pip install -e .[dev]`. The pytest pin is in `pyproject.toml`; the ruff pin is `RUFF_VERSION` in `tools/dev.py` and is mirrored in `.github/workflows/ci.yml`. Read the pins there rather than from this file. `tools/dev.py` uses a matching `ruff` on PATH, else `uvx ruff@<version>`.
- The real-binary tests need game files that are not in the repository. Set `CIV4DBG_TEST_DATA` to a directory holding them (see `tests/realdata.py`); without it they skip, saying why.
- CI runs `check` on Linux, Windows and macOS and never needs the game, Wine or any game file. The Windows job is non-blocking.

## Hard constraints

- **The runtime is standard library only** (`civ4dbg/`, the launcher, `ingame/`, `tools/`). Do not add a runtime dependency. pytest and ruff are development tools only. Rationale: [CDT-001](./docs/architecture/adrs/cdt/CDT-001-standard-library-only-runtime.md).
- **`ingame/AgentRepl.py` must stay in the subset common to Python 2.4 and Python 3**, because the game embeds Python 2.4. No f-strings, `with`, conditional expressions, set literals or other newer syntax. `test_ingame_file_is_in_the_py24_py3_subset` in `tests/test_agentrepl_module.py` enforces it. Ruff does not lint `ingame/`.
- **Never commit game binaries, PDBs, minidumps, or files from a user's game or mod install.** Not as fixtures, not in docs, not as test data. `.gitignore` ignores `*.dmp`, `*.pdb`, `*.dll` and `*.exe` as a backstop only; do not rely on it.
- **`tests/fixtures/small.pdb` and `small.dll` are self-built** from `tests/fixtures/small.c` with `tests/fixtures/build_small.sh`. Do not replace them with files from a game or mod.

## Security invariants not to weaken

AgentRepl runs Python inside the game, so its guards are the point of the design. Decision record: [CDT-002](./docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md). Threat model and reporting: [SECURITY.md](./SECURITY.md).

- **The exchange-folder checks in `civ4dbg/remote.py`** (symlink and reparse-point refusal, ownership and mode checks, descriptor-relative file operations, directory identity re-checks). What each OS enforces is in [docs/platform-support.md](./docs/platform-support.md). Do not remove or loosen a check to make a platform pass; record the gap instead.
- **The read-only allowlist and the write gate.** A request is read-only unless the exchange folder has `ENABLE_WRITE` and the request carries `#@ write` (the CLI's `--write`). Do not widen the allowlist, add a way past it, or make write mode implicit.
- **The tools never create `ENABLE` or `ENABLE_WRITE`.** Only a person does, by hand. Neither the installer nor `civ4dbg exec` may create either file, and the module stays off and purges queued requests while `ENABLE` is absent.
- **The installer backs up `init.xml` before editing it**, to a per-install folder under the user state directory by default (`--backup-dir` overrides; `uninstall` verifies the folder's `manifest.json`). It refuses a backup location inside a git work tree or the mod directory, never overwrites an existing backup, and never writes a manifest for a backup it cannot tie to the mod. `uninstall` removes only the inserted line and never restores the backup. Use `--dry-run` first, and never point the installer at a tree you cannot restore.

## Proposing changes upstream

Upstream takes issues, discussions and validation reports. It does not take pull requests or third-party code. See [CONTRIBUTING.md](./CONTRIBUTING.md).

- Open an issue (a bug or a validation report) or a discussion that describes the problem, the behavior you want and how you tested it, in words.
- Do not open a pull request. Do not paste a patch or diff as the deliverable; a fix can be described in prose, and the maintainer makes the change independently.
- Report security issues privately as described in [SECURITY.md](./SECURITY.md), never in a public issue.

## Help wanted

Windows and macOS validation, and mods that do not ship BUG. The matrix of what has been tested, and where reports are most needed, is [docs/platform-support.md](./docs/platform-support.md).
