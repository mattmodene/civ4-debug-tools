# Prefix Registry

**Purpose**: civ4-debug-tools' local document prefixes, used only in `docs/` and below
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

Every prefix here may be used in this directory and below it, in addition to the universal prefixes of Stele. The columns, the registration process and the rules for local registries are defined in Stele's ENG-002; every change to this table is recorded in [PREFIXES-CHANGELOG.md](./PREFIXES-CHANGELOG.md).

| Prefix | Category | Descriptor | Justification | Defined by | Status | Added |
|--------|----------|------------|---------------|------------|--------|-------|
| `CDT` | Scope | Architecture decisions for civ4-debug-tools: the crash-address resolver and the AgentRepl in-game console | A scope prefix for one named tool, so its decision numbering stays separate and unambiguous when cited from outside this repository; distinct from the universal `PLATFORM` and `LIB` scopes, which bind more than one component | [CDT decisions index](./architecture/adrs/cdt/INDEX.md) | Active | 2026-11-07 |
