# Security Policy

**Purpose**: How to report a vulnerability in civ4-debug-tools, which versions are supported, and what the remote console's threat model is.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| earlier | No (never released) |

Fixes land on the latest 0.1.x release. While the project is below 1.0.0, a fix may change the
command-line interface or the AgentRepl protocol version; the change is listed in
[CHANGELOG.md](./CHANGELOG.md).

## Reporting a vulnerability

Please report privately:

1. Use GitHub's private vulnerability reporting: open
   <https://github.com/mattmodene/civ4-debug-tools/security/advisories/new> (Security tab,
   "Report a vulnerability").
2. Or email security@modene.software with "civ4-debug-tools security" in the subject.

Do not put details, proofs of concept or file contents in a public issue or Discussion. If you
cannot use either channel, open an issue that says only that you have a security report.

Include the version, the command you ran, and a minimal reproducing input (a small crafted PDB,
minidump or PE file, or the request text for the console) where one exists. Expect an
acknowledgement within a week; this is a single-maintainer project, so fix times vary.

## What is in scope

- **The file readers** (PDB/MSF, minidump, PE). They treat their input as untrusted. A crafted file
  must fail with a clean error (exit 1 or 4) and must not hang, exhaust memory, or raise an uncaught
  exception (exit 5 reports one). A violation is a bug and in scope. `tools/fuzz_inputs.py` checks this.
- **The host side of the remote console** (`civ4dbg/remote.py`, `civ4dbg exec`) and the installer
  (`tools/agentrepl_install.py`): path handling, symlink and permission checks on the exchange
  directory, and anything that makes the installer touch files outside the mod directory.
- **The in-game module** (`ingame/AgentRepl.py`) where it runs a request that its documented gates
  should have stopped.

## AgentRepl threat summary

AgentRepl lets a person run Python inside the running game process. The decision, its rejected
alternatives and its limits are recorded in
[CDT-002](./docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md); the short form:

- **Write mode is arbitrary code execution in the game process**, with the privileges of the user
  who started the game. A request can import any module, open files, start processes, save over
  saves, quit the game or change game state.
- **Under Wine or Proton the `Z:` drive can reach the host filesystem**, so game Python can read and
  write whatever that user can, unless the prefix has removed or remapped `Z:`. This depends on the
  prefix and is not something this project controls.
- **It is off by default.** The module does nothing unless the file `ENABLE` exists in the exchange
  directory; write power also needs `ENABLE_WRITE` and `#@ write` on the request. The installer and
  the CLI never create either file.
- **Read-only mode is a guard against accidents, not a security boundary.** It is a name-based
  allowlist over the request's tokens. A getter that changes state under a read-looking name would
  pass it, and pure computation that stalls in one native call cannot be stopped.
- **The session token authenticates no one.** It is in `status.txt` in the exchange directory. The
  real access control is that directory's ownership and mode 0700 on Linux and macOS (on Windows, the ACL it
  inherits from its parent folder, with no owner or mode check), and the two switch files. Anyone
  who can write to the directory can run code in the game while the console is enabled.
- Every request's source is appended to `audit.log` before it runs.

Reports that read-only mode can be bypassed with a name that is not a read are expected to be
possible by design (the allowlist is "as good as the names") and are welcome as additions to the
allowlist, but they are not treated as security vulnerabilities. A bypass of the `ENABLE` switch,
the `ENABLE_WRITE` plus `#@ write` gate, the session-token and deadline checks, or the directory
checks is in scope.

## Out of scope

- Use of the console in write mode by someone who enabled it: that is the documented behaviour.
- Vulnerabilities in the game, Wine, Proton, the mod or Python itself.
- Findings that need a malicious `ENABLE` file the user created, or a hostile process that already
  runs as the same user.
