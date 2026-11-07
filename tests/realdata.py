"""Where the optional real-binary tests find the game files.

The files (a game DLL, its PDB, crash dumps) are not redistributable and are never in this repository.
Set CIV4DBG_TEST_DATA to a directory that holds them; when it is unset, or a needed file is missing,
the test that needs it skips with a reason naming the variable and the file.
"""

import os
import pathlib

import pytest

VAR = "CIV4DBG_TEST_DATA"


def data_dir():
    """The directory named by CIV4DBG_TEST_DATA, or None when the variable is unset or empty."""
    value = os.environ.get(VAR, "")
    return pathlib.Path(value) if value else None


def path_of(name):
    """The path of a data file. Without the variable it is a relative path that does not exist."""
    base = data_dir()
    return (base or pathlib.Path("CIV4DBG_TEST_DATA-unset")) / name


def missing_reason(*names):
    """None when every named file exists, else a skip reason naming the variable and the file(s)."""
    base = data_dir()
    if base is None:
        return f"{VAR} is not set (needs {', '.join(names)})"
    absent = [n for n in names if not (base / n).is_file()]
    if absent:
        return f"{VAR}={base} has no {', '.join(absent)}"
    return None


def skipif_missing(*names):
    """A pytest marker that skips unless every named file exists in the data directory."""
    reason = missing_reason(*names)
    return pytest.mark.skipif(reason is not None, reason=reason or "")
