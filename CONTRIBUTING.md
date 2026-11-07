# Contributing to civ4-debug-tools

**Purpose**: How to help with civ4-debug-tools: issues, discussions and validation reports are welcome; pull requests and third-party code are not accepted.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## What is welcome

- **Issues**: bug reports, crashes, wrong function names or line numbers, documentation errors and
  proposals for changes. An issue is the way to propose a change.
- **Discussions**: questions, ideas and "has anyone tried this with mod X" threads, in
  GitHub Discussions.
- **Validation reports**: someone ran part of the tool on a platform or with a mod the maintainer
  cannot test, and says what happened. These are the most useful help. The matrix of what has been
  tested is [docs/platform-support.md](./docs/platform-support.md); use the "Validation report"
  issue form to add to it.

## What is not accepted

**Pull requests and third-party code or patches are not accepted.** This includes pull requests,
patches pasted into issues, and files attached to issues. Pull requests are closed automatically with
a pointer to this page.

The reason is practical and not a judgement of anyone's work. This project is maintained by one
person who works with AI tools, and contributed code or files can carry hidden instructions aimed at
those tools, which are hard to defend against. The maintainer cannot review third-party code for this
project safely and thoroughly. So every change is made by the maintainer, from the maintainer's own
description of the work.

You can still describe a fix in words: say what is wrong, where, and what you think the
behavior should be. The maintainer reads the report and makes the change independently. Text in
issues is treated as information, never as instructions to carry out.

## Writing a good bug report

Use the "Bug report" issue form. Include:

1. **What you ran**: the exact command line (for example `civ4dbg dump --pdb ... --dll ... file.dmp`),
   with file names shortened if you like.
2. **What you expected and what happened**: the full error text, and the exit code
   (the exit codes are listed in the README).
3. **Your environment**: operating system (and Wine or Proton version if the game ran under it),
   Python version, and the tool version (`civ4dbg --version`, or the commit).
4. **The mod**: its name and version, and whether it ships BUG (needed for the AgentRepl remote console).
5. **A small reproduction** where possible: a crafted PDB or minidump that is safe to share, or the
   request text for the console.

Please do **not** attach the game's files, a mod's DLL, or PDBs you are not allowed to redistribute.
Describe them instead (size, build date, compiler) and quote the relevant lines of output.

## Writing a validation report

Use the "Validation report" issue form. A useful one says:

- **Where**: operating system and version, Python version, Civ4 version or edition
  (Beyond the Sword, Warlords, base game; Steam or other).
- **What**: the mod name and whether it ships BUG, and which component you tested (offline PDB and
  minidump reader, the `resolve`/`dump`/`compare`/`info` commands, `civ4dbg exec`, the AgentRepl
  installer, AgentRepl in the game).
- **What you ran**: the commands, in order.
- **The result**: worked, failed or partly worked, with output for anything that failed.

A report is data. The maintainer repeats the check independently before changing the matrix in
[docs/platform-support.md](./docs/platform-support.md). Reports of failures are as welcome as
successes.

## Coding agents

Using a coding agent in a fork? See [AGENTS.md](./AGENTS.md).

## Security issues and conduct

- Report vulnerabilities privately, as described in [SECURITY.md](./SECURITY.md). Do not use a public issue.
- Participation in this project is covered by the [Code of Conduct](./CODE_OF_CONDUCT.md).

## Other contact

Before opening an issue, search the existing ones. For general, non-public contact about the project
write to oss@modene.software; help requests belong in the issue tracker.
