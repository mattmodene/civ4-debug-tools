# .github Index

**Purpose**: GitHub configuration for civ4-debug-tools: workflows, issue forms and the pull request notice.
**Last Updated**: 2026-11-07
**Authors**: Matt Modene ([@mattmodene](https://github.com/mattmodene))

---

## Files in This Directory

- **[workflows/ci.yml](./workflows/ci.yml)** - Runs `python3 -I tools/dev.py check` on Python 3.11 and the latest 3.x, with ruff pinned to the version in `tools/dev.py`. Needs no game, DLL, PDB, minidump or `CIV4DBG_TEST_DATA` directory.
- **[workflows/close-prs.yml](./workflows/close-prs.yml)** - Closes every opened or reopened pull request with a comment linking CONTRIBUTING.md. Never checks out or runs pull request code.
- **[pull_request_template.md](./pull_request_template.md)** - States that pull requests are not accepted and links CONTRIBUTING.md
- **[ISSUE_TEMPLATE/config.yml](./ISSUE_TEMPLATE/config.yml)** - Disables blank issues; links the private security advisory form and Discussions
- **[ISSUE_TEMPLATE/bug_report.yml](./ISSUE_TEMPLATE/bug_report.yml)** - Bug report form
- **[ISSUE_TEMPLATE/validation_report.yml](./ISSUE_TEMPLATE/validation_report.yml)** - Validation report form (OS, Python, Civ4 edition, mod, component, result)
