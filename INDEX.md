# civ4-debug-tools Index

**Purpose**: Project root index for civ4-debug-tools, which turns crash addresses in a Civ4 mod's game DLL into function names and source lines. Lists direct children only.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Files in This Directory

- **[README.md](./README.md)** - What the tool does, requirements, install, usage, security and development
- **[CHANGELOG.md](./CHANGELOG.md)** - Release history (Keep a Changelog, Semantic Versioning)
- **[CONTRIBUTING.md](./CONTRIBUTING.md)** - What is welcome (issues, discussions, validation reports) and why pull requests are not accepted
- **[AGENTS.md](./AGENTS.md)** - Instructions for coding agents working in a fork or local checkout: commands, hard constraints, security invariants, how to report upstream
- **[CLAUDE.md](./CLAUDE.md)** - Claude Code entry point; imports AGENTS.md
- **[CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md)** - Contributor Covenant 2.1
- **[SECURITY.md](./SECURITY.md)** - Supported versions, how to report a vulnerability, AgentRepl threat summary
- **[LICENSE](./LICENSE)** - MIT license
- **[civ4dbg.py](./civ4dbg.py)** - Launcher script
- **[pyproject.toml](./pyproject.toml)** - Python project metadata, ruff and pytest configuration
- **[.python-version](./.python-version)** - Python version for local development
- **[.standards-config.json](./.standards-config.json)** - Stele validator configuration and recorded standards deviations
- **[.gitignore](./.gitignore)** - Ignored paths

## Subdirectories

### [civ4dbg/](./civ4dbg/INDEX.md)
The Python package: readers for the PDB container, PE headers and minidumps.

**View details**: See [civ4dbg/INDEX.md](./civ4dbg/INDEX.md)

### [.github/](./.github/INDEX.md)
GitHub configuration: the CI workflow, the pull-request auto-close workflow, issue forms and the pull request notice.

**View details**: See [.github/INDEX.md](./.github/INDEX.md)

### [docs/](./docs/INDEX.md)
Platform support matrix, LLVM diagnosis (historical C2C case study), prior art, architecture decisions and the prefix registry.

**View details**: See [docs/INDEX.md](./docs/INDEX.md)

### [ingame/](./ingame/INDEX.md)
Code installed into the running game (Python 2.4/3 subset): the AgentRepl remote console.

**View details**: See [ingame/INDEX.md](./ingame/INDEX.md)

### [tests/](./tests/INDEX.md)
Test suite and fixtures.

**View details**: See [tests/INDEX.md](./tests/INDEX.md)

### [tools/](./tools/INDEX.md)
Development command surface, fuzzing, claims check and the AgentRepl installer.

**View details**: See [tools/INDEX.md](./tools/INDEX.md)

