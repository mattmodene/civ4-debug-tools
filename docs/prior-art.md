# Prior art: existing Python PDB readers

**Last Updated**: 2026-11-07 (survey run 2026-11-02)
**Authors**: Matt Modene (mattmodene@modene.software)

Question: does an existing Python library read MSF 7.00 PDBs with a stream
directory that needs several block-map blocks (the shape LLVM rejects, see
`llvm-diagnosis.md`)?

| Project | Version / date | Finding |
|---|---|---|
| **pdbparse** (PyPI `pdbparse`, github.com/moyix/pdbparse) | 1.5; last push 2024-07-30; 347 stars; license not asserted by GitHub's detector | Parses the C2C PDB's stream directory correctly (399 streams, sizes and block lists identical to this tool's). Cannot go further on this machine: `pip install pdbparse` fails (it pins `construct<2.10`, and no matching old `construct` builds on Python 3.14); with `construct` 2.10 force-installed, DBI parsing raises `TypeError` and TPI parsing raises `KeyError: LF_STMEMBER`. Its design is a type-info / structure-dumper reader aimed at Windows debugging, not at lookups with C11 line tables. |
| pdbreader, python-pdb, atomium, etc. | various | Protein Data Bank (molecular structure) tools, not Microsoft PDBs. Irrelevant. |
| pdbpy (DrInfiniteExplorer/pdbpy) | last push 2024-04-15; 6 stars | "pure Python implementation of Program Database file parsing"; listed by a GitHub search, **not evaluated**. |
| LLVM `llvm-pdbutil` / `llvm-symbolizer` | 23.1.1 | The reference implementation for small PDBs, used here as the oracle on a known-good fixture. Rejects the C2C PDB (see `llvm-diagnosis.md`). |

Search used: PyPI names `pdbparse`, `pdbfile`, `pdb-parser`, `python-pdb`, `pdbreader`,
`pdb-reader`, `raw-pdb`; GitHub repository search "pdb parser python" and
"pdb parser language:python msf". The survey was short; absence from it is not
proof that no other reader exists.

## Use made of it

- pdbparse was installed in a throwaway venv outside the repository **only**
  to cross-check the stream directory. It is not a dependency and nothing in the
  shipped code imports it.
- The tool in this repository is standard library only (declared minimum Python 3.10; run only on 3.14). The
  format knowledge came from the public format descriptions (microsoft-pdb and
  LLVM documentation) and was verified against the lld-link-written fixture.
  The sources checked for the age rule and the block-map cap were fetched on
  2026-11-02 (read-only) from:
  `https://github.com/microsoft/microsoft-pdb` (`PDB/dbi/pdb.cpp`, `OpenValidate`),
  `https://github.com/llvm/llvm-project` (`llvm/docs/PDB/PdbStream.md`,
  `DbiStream.md`, `MsfFile.md`; `llvm/lib/DebugInfo/MSF/MSFCommon.cpp`,
  `MSFBuilder.cpp`; `llvm/lib/DebugInfo/PDB/Native/PDBFile.cpp`). The commits are
  recorded in `llvm-diagnosis.md`. The earlier format knowledge
  (before that date) has no recorded URLs or dates.
