"""The committed fixture must carry no host path and must be reproducible."""

import pathlib
import re
import shutil
import subprocess

import pytest

FIX = pathlib.Path(__file__).parent / "fixtures"
HOST_PATH = re.compile(rb"/(?:data|home|tmp|root|Users|mnt|var|opt|srv)/[\w.\-]+")
ABS_WIN = re.compile(rb"[A-Za-z]:\\[^\0\"]*")


@pytest.mark.parametrize("name", ["small.pdb", "small.dll"])
def test_no_host_absolute_path_in_fixture(name):
    blob = (FIX / name).read_bytes()
    assert HOST_PATH.findall(blob) == []
    # the only drive-letter path allowed is the pinned fake build root C:\src
    bad = [m for m in ABS_WIN.findall(blob) if not re.match(rb"C:\\+src", m)]
    assert bad == []


def test_fixture_source_is_ours_and_pdb_names_it_relative_to_the_fake_root():
    assert b"C:\\src\\small.c" in (FIX / "small.pdb").read_bytes()


def _llvm_version():
    try:
        out = subprocess.run(["clang-cl", "--version"], capture_output=True, text=True, timeout=30).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"clang version (\S+)", out)
    return m.group(1) if m else None


@pytest.mark.skipif(
    shutil.which("lld-link") is None or shutil.which("clang-cl") is None, reason="clang-cl / lld-link not installed"
)
def test_rebuild_script_reproduces_the_committed_bytes(tmp_path):
    ver = _llvm_version()
    if ver is None or f"clang version {ver}".encode() not in (FIX / "small.pdb").read_bytes():
        pytest.skip("installed LLVM differs from the one that built the committed fixture")
    for f in ("build_small.sh", "small.c"):
        shutil.copy(FIX / f, tmp_path / f)
    r = subprocess.run(["sh", str(tmp_path / "build_small.sh")], capture_output=True, text=True, timeout=120)
    assert r.returncode == 0, r.stderr
    for f in ("small.pdb", "small.dll"):
        assert (tmp_path / f).read_bytes() == (FIX / f).read_bytes(), f
