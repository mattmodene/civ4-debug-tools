# civ4-debug-tools tools Index

**Purpose**: Development commands, helper scripts that reproduce the documented PDB claims and fuzz the input readers, and the AgentRepl installer.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Files in This Directory

- **[dev.py](./dev.py)** - Development command surface: `check`, `lint`, `test`, `fuzz` (ruff pinned to one version)
- **[check_pdb_claims.py](./check_pdb_claims.py)** - Reproduce the structural checks quoted in docs/llvm-diagnosis.md
- **[agentrepl_install.py](./agentrepl_install.py)** - Install, uninstall or inspect AgentRepl in an installed mod (refuses git work trees)
- **[fuzz_inputs.py](./fuzz_inputs.py)** - Seeded fuzz over PDB, minidump and PE input; counts uncaught exceptions
