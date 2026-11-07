# Platform support

**Purpose**: What has been verified, on which platform, for each component of civ4-debug-tools, and how to help fill the gaps.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

The maintainer develops and tests on Linux, with the game running under Wine/Proton, and has no
Windows or macOS machine. This page records what that means for users. Statuses:

| Status | Meaning |
|---|---|
| tested | Exercised by the maintainer on real hardware or the real target. |
| CI only | Built or tested in CI only; never run by the maintainer. |
| untested | Believed to work, not verified. |
| unsupported | Known not to work, or deliberately out of scope. |

"untested (CI pending)" means the platform is planned for the continuous-integration matrix
(Windows first, as a non-blocking job until it is green, then required) and nothing has run yet.
The Windows and macOS columns will be reconciled with the per-OS behavior of the code once CI is
running.

## Components by environment, for BUG-based mods

| Component | Linux (game under Wine/Proton) | Windows | macOS |
|---|---|---|---|
| Offline PDB and minidump reader | tested | untested (CI pending) | untested (CI pending) |
| CLI `resolve`, `dump`, `compare`, `info` | tested | untested (CI pending) | untested (CI pending) |
| `civ4dbg exec` (AgentRepl client) | tested | untested (CI pending) | untested (CI pending) |
| AgentRepl installer | tested | untested (CI pending) | untested (CI pending) |
| AgentRepl in the game | tested | untested | untested |

The offline reader needs only Python 3.11 or newer and the files from the build under
diagnosis. The AgentRepl rows need the game and a mod that ships BUG. The exchange directory's
privacy relies on POSIX permission modes, which Windows does not provide in the same form; this is
one reason Windows stays "untested" until it is reviewed. The protection each OS enforces is in
[Exchange-directory protection by OS](#exchange-directory-protection-by-os).

## Exchange-directory protection by OS

What `civ4dbg exec` enforces for the exchange directory. Nothing here has been run on Windows or macOS;
the Windows and macOS entries are read from the code and exercised on Linux with mocks.

| Protection | Linux | macOS | Windows |
|---|---|---|---|
| Symlink in any path component refused | yes | yes, after the `/var`, `/tmp`, `/etc` alias handling below | yes |
| Junction or other reparse point refused | n/a | n/a | yes (any reparse point, so also OneDrive placeholders) |
| Anchor-only path (bare drive or UNC share root) refused | n/a | n/a | yes |
| Directory owned by you (ancestors: you or root) | yes | yes | **no** (no uid; ACLs are not read) |
| Directory mode 0700; ancestors not group/other-writable unless sticky | yes | yes | **no** (modes are synthesized) |
| Directory opened once without following links, owner and mode re-checked on the descriptor | yes | yes | **no** |
| File operations relative to that descriptor | yes | yes | **no** (path-based) |
| Directory identity (volume serial and file index) re-compared before each file operation | n/a (descriptor) | n/a (descriptor) | yes, for every open, replace, unlink and the `--status`, heartbeat-age and `ENABLE` reads; skipped if the file system reports no index |
| Per-file lstat, open, fstat of the same file | n/a (descriptor) | n/a (descriptor) | yes; narrows the race, does not close it |
| Reply is a regular file, at most 256 KiB | yes | yes | yes |
| Reply file owned by you | yes | yes | **no** |
| Request created with `O_EXCL` (a planted name is refused) | yes | yes | yes |
| SIGTERM withdraws a pending request | yes | yes | **no** (Ctrl-C does) |
| One-time warning on stderr naming what is not enforced | no | no | yes |
| What keeps others out of the directory | owner + 0700 | owner + 0700 | only the ACL inherited from the parent folder (inside your user profile: you and administrators) |

**macOS `/private` alias.** `/var`, `/tmp` and `/etc` are root-owned symlinks into `/private`, and the
walk otherwise refuses every symlink. Only when the first path component is one of those three, is a
symlink owned by root, and its literal target (`os.readlink`, not a resolved path) is exactly
`/private/<name>`, the component is rewritten to `/private/<name>` before the walk. Any other symlink,
a lookalike not owned by root, or an alias that points anywhere else is left in place and refused. The
rest of the walk is unchanged.

**Windows gaps, stated plainly.** Three gaps remain on Windows: a swap in the instant between the comparison and the open; a file system that reports no file index, where the comparison is skipped; and anyone with write access to the parent folder. The warning the CLI prints once per run says so.

## Installer backup folder

The installer keeps its `init.xml` backup and a `manifest.json` in a per-install folder under the user
state directory (`$CIV4DBG_STATE_DIR`, else `$XDG_STATE_HOME/civ4dbg/agentrepl` or
`~/.local/state/civ4dbg/agentrepl` on Linux, `~/Library/Application Support/civ4dbg/agentrepl` on macOS,
`%LOCALAPPDATA%\civ4dbg\agentrepl` on Windows). On Linux and macOS the folders it creates are mode 0700.
On Windows no mode is enforced: the folder only inherits the ACL of its parent, so it should stay inside
the user's own profile. Only the Linux behavior has been run.

## Mod types

| Mod type | Offline reader | AgentRepl |
|---|---|---|
| BUG-based mods | tested (one mod, Caveman2Cosmos) | tested (one mod, Caveman2Cosmos) |
| Non-BUG mods | untested, expected to work if the mod author supplies a matching PDB | unsupported; help wanted |

AgentRepl needs BUG: the installer edits `Assets/Config/init.xml`, the in-game module is installed
into `Assets/Python/BUG/` and finds its directory through `SystemPaths`, falling back to a path derived
from the module file's own location (`__file__`). Supporting mods without BUG
is deferred. If you want it, say so in an issue or a Discussion, and describe the mod's Python
layout.

The offline reader works with any Beyond the Sword mod DLL that has a matching PDB: MSF 7.00
(Microsoft compilers from 7.0 on), no OMAP data, and x86 minidumps. Firaxis ships no PDBs, so the
mod author must build with debug info and keep or publish the PDB that matches the shipped DLL.

## How to help

Validation reports are the most useful help. Run part of the tool on a system or mod not listed as
tested above and open a **Validation report** issue (the issue form asks for the OS, Python
version, Civ4 version or edition, mod name and whether it ships BUG, the component, what you ran
and the result). Failures are as welcome as successes.

- Issues labelled `needs-validation` are areas waiting for a report.
- Issues labelled `help wanted` are open problems, such as AgentRepl without BUG.
- Pull requests and code are not accepted; see [CONTRIBUTING.md](../CONTRIBUTING.md).

The matrix changes only after the maintainer has repeated a reported result independently.
