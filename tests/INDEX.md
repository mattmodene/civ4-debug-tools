# civ4-debug-tools tests Index

**Purpose**: The pytest suite for civ4dbg, with synthetic-input builders and a small committed fixture.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Files in This Directory

- **[agentrepl_support.py](./agentrepl_support.py)** - Loads the in-game AgentRepl module under Python 3 with a stubbed game
- **[c11_layout.py](./c11_layout.py)** - Byte-exact builder for the old-style (C11, `sstSrcModule`) line block
- **[conftest.py](./conftest.py)** - Shared pytest configuration: puts the repository root on the import path
- **[synth.py](./synth.py)** - Builders for synthetic MSF / PDB / minidump / PE bytes used by the tests
- **[realdata.py](./realdata.py)** - Locates the optional real game files through `CIV4DBG_TEST_DATA`; the real-binary tests skip with a reason naming the variable and the file
- **[test_agentrepl_install.py](./test_agentrepl_install.py)** - Installer (idempotency, line endings, round trip, git and `--forbid` refusal)
- **[test_agentrepl_readonly.py](./test_agentrepl_readonly.py)** - Read-only mode is an allowlist (a stubbed game whose mutators record calls), allowed live-inspection queries, write mode, `--status` on a module older than the session token, VERSION bump
- **[test_agentrepl_readonly_checker.py](./test_agentrepl_readonly_checker.py)** - `check_readonly()` edge cases: allowed and refused constructs, getattr literal rule, assignment/del/for/as targets, namespace containers
- **[test_agentrepl_coarse_clock.py](./test_agentrepl_coarse_clock.py)** - The game's quantized wall clock versus the exact relative clock: no request decision may use the wall clock or a file's mtime
- **[test_agentrepl_e2e.py](./test_agentrepl_e2e.py)** - The in-game poll loop (background thread, stubbed game) driven by the host CLI as a subprocess, plus adversarial inputs
- **[test_agentrepl_install_e2e.py](./test_agentrepl_install_e2e.py)** - Installer round trip on a synthetic mod tree, git-work-tree refusals, and a hygiene check on the AgentRepl tests
- **[test_agentrepl_deadline.py](./test_agentrepl_deadline.py)** - Per-request `#@ notafter` deadline on the relative clock: host estimate (alive_clock + status age + timeout + 2), retry once on `stale`, version-2 module refusal, `--status`
- **[test_agentrepl_session_token.py](./test_agentrepl_session_token.py)** - Session-token replay protection (wrong/missing/old-session/retry), purge while ENABLE is absent, missing/malformed `notafter` deadlines, hardened host `read_status`
- **[test_agentrepl_review_fixes.py](./test_agentrepl_review_fixes.py)** - Review fixes: audit-before-run, poison requests, claim-by-delete, non-Exception raises, unicode, future mtimes, host signal/NaN/symlink handling
- **[test_agentrepl_module.py](./test_agentrepl_module.py)** - The in-game module: gates, older refuse list, budget, caps, replies, heartbeat, Python 2.4 subset guard
- **[test_build_match_omap_exit_codes.py](./test_build_match_omap_exit_codes.py)** - Build-match check (dump vs DLL), OMAP refusal and the CLI exit codes
- **[test_c11_lines.py](./test_c11_lines.py)** - C11 (old-style `sstSrcModule`) line tables, from the published layout
- **[test_codeview_match.py](./test_codeview_match.py)** - PDB-to-DLL matching through the DLL's CodeView (RSDS) record: GUID and age only
- **[test_fixture_hygiene.py](./test_fixture_hygiene.py)** - The committed fixture must carry no host path and must be reproducible
- **[test_fixture_pdb.py](./test_fixture_pdb.py)** - Known-good PDB written by LLVM's own linker (lld-link), checked against llvm-pdbutil
- **[test_icf_and_return_addresses.py](./test_icf_and_return_addresses.py)** - Identical-code folding (several names, one address) and return-address lookups
- **[test_malformed_input.py](./test_malformed_input.py)** - Truncated and malformed input: the readers must fail with their own clean error types
- **[test_minidump_pe.py](./test_minidump_pe.py)** - Minidump and PE reader tests
- **[test_msf.py](./test_msf.py)** - MSF container reader tests
- **[test_pe_reader.py](./test_pe_reader.py)** - The PE reader stays inside SizeOfHeaders and rejects inconsistent headers
- **[test_real_dump_resolution.py](./test_real_dump_resolution.py)** - Integration test against a real build's dump, PDB and DLL (local files named by `CIV4DBG_TEST_DATA` only; skips with a reason when absent)
- **[test_real_pdb_integration.py](./test_real_pdb_integration.py)** - Optional integration test against the local PDB and DLL named by `CIV4DBG_TEST_DATA` (skips with a reason when absent)
- **[test_remote_cli.py](./test_remote_cli.py)** - `civ4dbg exec`: exit codes against a simulated game and the real module, directory safety
- **[test_symbol_boundaries.py](./test_symbol_boundaries.py)** - Symbol-boundary and record-precedence behaviour of `Pdb.resolve`
- **[test_synthetic_pdb.py](./test_synthetic_pdb.py)** - Resolver tests against a hand-built PDB (covers C11 and C13 line formats)
- **[test_threads.py](./test_threads.py)** - ThreadList parsing, hang/snapshot detection, thread selection, multi-dump comparison, malformed ThreadList
- **[test_threads_cli.py](./test_threads_cli.py)** - Edge cases and CLI behaviour of thread selection, hang dumps and `compare` (synthetic dumps)
- **[test_tools.py](./test_tools.py)** - The scripts under tools/ run, exit 0 on good input and report what they claim

## Subdirectories

- **[fixtures/](./fixtures/INDEX.md)** - Small committed PDB and DLL fixture, with the source and script that produce it
