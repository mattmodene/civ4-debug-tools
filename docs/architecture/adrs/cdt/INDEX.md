# CDT Decisions Index

**Purpose**: civ4-debug-tools' architecture decisions, the `CDT` scope prefix
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Overview

Numbering is per prefix, 3-digit and sequential, and a number is never reused (ARCH-001-F). This index is the authority on the records in the scope and on each record's status; derive the next free number from the files, not from this text:

    ls CDT-*.md | sed 's/CDT-0*\([0-9]*\)-.*/\1/' | sort -n | tail -1

## Files in This Directory

- **[CDT-001-standard-library-only-runtime.md](./CDT-001-standard-library-only-runtime.md)** - Accepted. Standard library only at runtime; the PDB, MSF, PE and minidump readers are in-house
- **[CDT-002-agentrepl-file-exchange-console.md](./CDT-002-agentrepl-file-exchange-console.md)** - Accepted. AgentRepl: an opt-in, read-only-by-default, file-exchange Python console inside the game; not a sandbox

## Related

- [ADRs index](../INDEX.md) - Every scope folder
