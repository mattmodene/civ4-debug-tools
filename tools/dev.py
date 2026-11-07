"""Single command surface for development checks (stdlib only).

    python3 -I tools/dev.py check    # lint + format check + tests + synthetic fuzz
    python3 -I tools/dev.py lint     # ruff check + ruff format --check
    python3 -I tools/dev.py test     # pytest
    python3 -I tools/dev.py fuzz     # tools/fuzz_inputs.py on the committed synthetic fixtures

Nothing here needs Civilization IV, a game install, Wine, a game DLL/PDB, a minidump or
any local game file: tests that depend on those read them from the directory named by
``CIV4DBG_TEST_DATA`` and skip with a reason naming the variable and the file, and
the fuzz run uses only the committed fixtures and synthetic inputs.

ruff is pinned to one exact version (``RUFF_VERSION``). The same version is installed by
``.github/workflows/ci.yml``; change both together. ``ruff`` is taken from PATH when it is
that exact version, else run through ``uvx ruff@<version>``.

Development needs ``pytest==9.1.1`` (``pip install -e .[dev]``) and ruff; the package itself needs nothing.

``tools/check_pdb_claims.py`` needs a real PDB and is deliberately not part of ``check``.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

RUFF_VERSION = "0.17.4"  # keep in sync with .github/workflows/ci.yml
ROOT = pathlib.Path(__file__).resolve().parent.parent


def _ruff_command() -> list[str]:
    exe = shutil.which("ruff")
    if exe:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, check=False).stdout
        if out.strip() == f"ruff {RUFF_VERSION}":
            return [exe]
        print(f"note: ruff on PATH is {out.strip()!r}, not {RUFF_VERSION}; looking for uvx", file=sys.stderr)
    uvx = shutil.which("uvx")
    if uvx:
        return [uvx, f"ruff@{RUFF_VERSION}"]
    raise SystemExit(
        f"error: ruff {RUFF_VERSION} not found. Install it with `python3 -m pip install ruff=={RUFF_VERSION}` "
        f"or install uv (which provides `uvx ruff@{RUFF_VERSION}`)."
    )


def _run(label: str, cmd: list[str]) -> int:
    print(f"==> {label}: {' '.join(cmd)}", flush=True)
    return subprocess.run(cmd, cwd=ROOT, check=False).returncode


def lint() -> int:
    ruff = _ruff_command()
    rc = _run("ruff check", [*ruff, "check", "."])
    rc2 = _run("ruff format --check", [*ruff, "format", "--check", "."])
    return rc or rc2


def test() -> int:
    if subprocess.run([sys.executable, "-I", "-c", "import pytest"], capture_output=True, check=False).returncode:
        print(
            "error: pytest is not installed for this interpreter: python3 -m pip install 'pytest==9.1.1'",
            file=sys.stderr,
        )
        return 1
    return _run("pytest", [sys.executable, "-I", "-m", "pytest", "-q"])


def fuzz() -> int:
    return _run("fuzz (synthetic only)", [sys.executable, "-I", "tools/fuzz_inputs.py", "--cases", "1000"])


COMMANDS = {"lint": [lint], "test": [test], "fuzz": [fuzz], "check": [lint, test, fuzz]}


def main(argv: list[str]) -> int:
    if len(argv) != 1 or argv[0] not in COMMANDS:
        print(__doc__, file=sys.stderr)
        return 2
    failed = [step.__name__ for step in COMMANDS[argv[0]] if step() != 0]
    if failed:
        print(f"FAILED: {', '.join(failed)}", file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
