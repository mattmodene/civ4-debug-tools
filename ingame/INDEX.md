# ingame Index

**Purpose**: Code that runs inside the game's own embedded Python (2.4 under Wine), kept in this repository as the source of truth and installed into the mod by `tools/agentrepl_install.py`. Written in the Python 2.4/3 common subset so the host tests can import it. Not part of the `civ4dbg` package.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Files in This Directory

- **[AgentRepl.py](./AgentRepl.py)** - File-exchange Python console polled from the BUG `gameUpdate` event; off unless the user creates `ENABLE`; read-only unless `ENABLE_WRITE` exists and the request carries `#@ write` ([CDT-002](../docs/architecture/adrs/cdt/CDT-002-agentrepl-file-exchange-console.md))
