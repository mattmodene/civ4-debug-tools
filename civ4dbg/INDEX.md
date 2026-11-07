# civ4dbg package Index

**Purpose**: The civ4dbg Python package: readers for the PDB container, PE headers and minidumps, and the crash-address resolver.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Files in This Directory

- **[__init__.py](./__init__.py)** - Civ4 crash-site and live-game tooling (standard library only)
- **[__main__.py](./__main__.py)** - Command line: `python3 -I -m civ4dbg <command> ...`
- **[buildcheck.py](./buildcheck.py)** - Does the minidump belong to the same build as the DLL on disk?
- **[compare.py](./compare.py)** - Ranks the PDB functions that recur in a thread's stack scan across several dumps
- **[errors.py](./errors.py)** - The tool's own exception types and the CLI exit codes they map to
- **[minidump.py](./minidump.py)** - Minimal Windows minidump reader for 32-bit (x86) crash dumps, with the ThreadList
- **[msf.py](./msf.py)** - MSF 7.00 container reader (the file format underneath a PDB)
- **[remote.py](./remote.py)** - Host side of the AgentRepl remote console (`exec` command)
- **[pdb.py](./pdb.py)** - PDB (MSF + DBI + CodeView symbols) reader and RVA resolver
- **[pe.py](./pe.py)** - PE header reader: COFF header, optional-header basics and the section table
