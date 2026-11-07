"""The scripts under tools/ run, exit 0 on good input and report what they claim."""

import pathlib
import subprocess
import sys

from realdata import path_of, skipif_missing

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures"


def run(*argv):
    return subprocess.run(
        [sys.executable, "-I", *map(str, argv)], capture_output=True, text=True, cwd=ROOT, timeout=300
    )


def test_check_pdb_claims_passes_on_the_fixture():
    r = run("tools/check_pdb_claims.py", "--pdb", FIX / "small.pdb", "--dll", FIX / "small.dll")
    assert r.returncode == 0, r.stdout + r.stderr
    lines = r.stdout.splitlines()
    kinds = [ln.split()[0] for ln in lines]
    assert len(lines) == 7 and kinds.count("PASS") == 6 and kinds.count("INFO") == 1
    assert next(ln for ln in lines if "free-block map vs" in ln).startswith("INFO")
    assert "0 claimed twice" in r.stdout


def test_check_pdb_claims_fails_on_a_clobbered_file(tmp_path):
    bad = tmp_path / "bad.pdb"
    bad.write_bytes((FIX / "small.pdb").read_bytes()[:5000])
    r = run("tools/check_pdb_claims.py", "--pdb", bad)
    assert r.returncode != 0


@skipif_missing("CvGameCoreDLL.pdb", "CvGameCoreDLL.dll")
def test_check_pdb_claims_reproduces_the_documented_figures():
    r = run("tools/check_pdb_claims.py", "--pdb", path_of("CvGameCoreDLL.pdb"), "--dll", path_of("CvGameCoreDLL.dll"))
    assert r.returncode == 0, r.stdout + r.stderr
    for figure in (
        "directory 327492 bytes = 320 blocks of 1024",
        "2 block(s)",
        "399 streams",
        "81958 distinct blocks",
        "0 claimed twice",
        "320 of 81958",
        "46133 S_GPROC32 records",
        "0 without an S_PUB32",
        "878 S_LPROC32",
        "5 sections; differences: none",
    ):
        assert figure in r.stdout, figure


def test_fuzz_tool_reports_zero_uncaught_and_a_nonzero_case_count():
    r = run("tools/fuzz_inputs.py", "--cases", "300")
    assert r.returncode == 0, r.stdout + r.stderr
    last = r.stdout.splitlines()[-1]
    assert last.startswith("TOTAL cases") and last.endswith("uncaught exceptions 0")
    total = int(last.split()[2])
    assert total >= 1500
    assert (
        "UNCAUGHT 0" in r.stdout
        and "small.pdb" in r.stdout
        and "synthetic minidump" in r.stdout
        and "small.dll" in r.stdout
    )
