# CDT-001: Standard Library Only at Runtime

**Status**: Accepted
**Date**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

## Context

civ4-debug-tools turns crash addresses in a game library (`CvGameCoreDLL.dll`) into function names, offsets and source lines. To do that it must read four binary container formats: the MSF 7.00 file container that holds a PDB, the PDB's own streams (DBI, public and procedure symbols, C11 and C13 line tables), the PE headers of the DLL (including its CodeView debug record, used to check that a PDB matches a DLL), and x86 minidumps.

The target PDB is an 84 MB file with 1024-byte blocks, 399 streams and a stream directory of 320 blocks. Its block map therefore spans two blocks. LLVM's reader refuses that shape ("Too many directory blocks"), so the obvious existing tool cannot read the one file this project exists for. The analysis is in [llvm-diagnosis.md](../../../llvm-diagnosis.md). The survey of existing Python readers is in [prior-art.md](../../../prior-art.md).

Three further forces apply:

- The tool is run by people debugging a game mod, often on a machine set up for something else (Linux, with the game under Wine or Proton). It is run on crash data and on files the game wrote, and it should start with nothing to install and nothing to audit beyond the Python it runs on.
- It is run in isolated mode (`python3 -I`), which ignores user site-packages and `PYTHON*` environment variables. The same behavior should hold on every machine.
- The input formats are binary and may be truncated or hostile. A reader that fails with an uncaught exception, or reads past a bound, is worse than one that refuses the input with a named error.

## Decision

We will use only the Python standard library at runtime, on Python 3.11 or newer, and we will implement the MSF, PDB, PE and minidump readers in this repository (`civ4dbg/msf.py`, `pdb.py`, `pe.py`, `minidump.py`).

- No third-party package is imported by `civ4dbg/`, by the launcher, or by `ingame/` and `tools/`. `pytest` and `ruff` are development tools only; nothing at runtime depends on them.
- The tool does not call LLVM, `llvm-pdbutil`, `llvm-symbolizer` or any other external program to read a file. External tools may be used by hand as test oracles on small PDBs.
- The readers parse container and metadata structures (headers, directories, symbol and line records, module and thread lists). They do not decode machine code.
- The format knowledge comes from public format descriptions (the `microsoft-pdb` repository and LLVM's PDB documentation), checked against small PDBs built with `lld-link` and against synthetic files built by the test suite. The tests and fixtures never contain the game's own files.
- Each reader treats its input as untrusted: every length and offset is bounded, and a malformed file raises one of the tool's own error types with a distinct exit code.

## Consequences

### Positive
- The tool reads the target PDB, which LLVM's reader cannot. The reader treats the block map as consecutive blocks and consumes the directory exactly, and the checks in `tools/check_pdb_claims.py` reproduce this.
- Installing is copying the repository. There is no dependency resolution, version pin, build step, or supply-chain surface other than CPython itself.
- Behavior under `python3 -I` is the same everywhere the minimum Python version is present.
- Every byte read is read by code in this repository, so bounds checks and error types are uniform and can be fuzzed (`tools/fuzz_inputs.py`).

### Negative
- We own the format code. A PDB feature this tool does not yet read (an unseen record kind, a different MSF layout, OMAP in general) is our work to add, not an upgrade to pull in. Unsupported shapes are refused with a named error rather than guessed at.
- Our understanding of the format rests on public descriptions and on the files we have seen. The multi-block block map is accepted by this reader on the evidence of one real file and a synthetic one; LLVM's own source comment says it is unclear what the format intends. A different producer could write something this reader misreads.
- A pure-Python reader is slower than a native one on an 84 MB file. This is acceptable for interactive crash triage; it would not be for bulk processing.
- Python 3.11 or newer is required (this excludes older distribution Pythons).
- Duplicated effort: other projects read PDBs, and any improvement made here is not shared with them unless we send it upstream.

### Neutral
- The in-game half of the project (`ingame/AgentRepl.py`) runs in the game's own embedded Python 2.4 and is outside this rule; it uses only that interpreter's standard library and is described in [CDT-002](./CDT-002-agentrepl-file-exchange-console.md).

## Alternatives Considered

### Alternative 1: Wrap LLVM's tools (`llvm-pdbutil`, `llvm-symbolizer`)
**Description**: Call LLVM as a subprocess and parse its output.
**Pros**: Mature, maintained reference implementation; no format code to own; also reads types and other detail we do not.
**Cons**: It rejects the target PDB (verified with LLVM 23.1.1 and recorded in the diagnosis note). It adds a large external binary whose version must match. Output parsing is a second fragile layer.
**Rejection Reason**: It cannot read the file the tool exists for. It remains useful as a test oracle on small, ordinary PDBs. Lifting the one-block cap in LLVM's validator may be the whole upstream change, but we have not built or tested that, and a patched LLVM is not something users can be asked to install.

### Alternative 2: Depend on an existing third-party Python PDB reader
**Description**: Use `pdbparse` (or a similar package) for the container and symbol streams.
**Pros**: Less code to write; shared maintenance.
**Cons**: Evaluated on 2026-11-02: `pdbparse` 1.5 read this PDB's stream directory correctly (399 streams; sizes and block lists identical to ours). It did not install on a current Python because it pins `construct<2.10`; with `construct` 2.10 forced in, DBI parsing raised `TypeError` and type-stream parsing raised `KeyError: LF_STMEMBER`. Its design is a type dumper for Windows debugging, not an address-to-line resolver. It would also bring a transitive dependency chain into a tool meant to have none. Other candidates (for example `pdbpy`) turned up in a short survey and were not evaluated; absence from that survey is not proof that no suitable reader exists.
**Rejection Reason**: It did not work on current Python or on the target file's later streams, and a dependency on a pinned, unmaintained chain contradicts the install and isolation requirements above. Its stream-directory result is kept as an independent cross-check, run by hand.

### Alternative 3: Third-party dependencies for ergonomics only (a parsing library, a CLI framework)
**Description**: Use a binary-parsing library such as `construct` or a CLI library over our own format knowledge.
**Pros**: Declarative structure definitions; less boilerplate.
**Cons**: Reintroduces the dependency and isolation problems of Alternative 2 for little saving. `struct`, `argparse`, `dataclasses`, `mmap` and `bisect` cover what these readers need.
**Rejection Reason**: The saving is small and the cost is permanent.

## Success Metrics

- `grep` over `civ4dbg/`, `civ4dbg.py`, `ingame/` and `tools/` finds no import outside the standard library.
- The test suite and the malformed-input fuzz pass under `python3 -I` with only `pytest` installed.
- The fuzz reports zero uncaught exceptions on truncated and corrupted inputs.

**Review Triggers**:
- A maintained third-party reader that installs on current Python and reads multi-block-map PDBs, with a small, stable dependency set.
- LLVM lifting the one-block cap, which would make it a viable reader for this PDB shape.
- A required feature (for example full type-stream decoding) whose in-house cost clearly exceeds that of a dependency.
- A need for bulk processing where pure-Python speed becomes the limit.

## References

- Related to [CDT-002](./CDT-002-agentrepl-file-exchange-console.md): the in-game console runs in the game's embedded Python 2.4, outside the interpreter this decision assumes, and is limited to the subset of the language common to 2.4 and 3.
- [Why LLVM rejects the Caveman2Cosmos PDB](../../../llvm-diagnosis.md) - the block-map analysis and LLVM source check
- [Prior art: existing Python PDB readers](../../../prior-art.md) - the survey and the `pdbparse` evaluation
- [README](../../../../README.md) - requirements, layout, commands and the verification tools
- `microsoft-pdb` repository and LLVM's PDB documentation (public format descriptions, read 2026-11-02)
