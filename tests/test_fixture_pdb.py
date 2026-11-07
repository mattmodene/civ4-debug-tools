"""Known-good PDB written by LLVM's own linker (lld-link), checked against llvm-pdbutil.

Expected values below come from running, on tests/fixtures/small.pdb:
  llvm-pdbutil dump -publics -section-headers -symbols -l
  llvm-symbolizer --obj=small.dll --relative-address <rva>...
(LLVM 23.1.1, 2026-11-02). Section offsets in llvm-pdbutil output are printed
in decimal for publics (e.g. 0001:0112 == 0x70).
"""

import pathlib

import pytest

from civ4dbg.pdb import Pdb
from civ4dbg.pe import compare_sections, read_pe_headers

FIX = pathlib.Path(__file__).parent / "fixtures"


@pytest.fixture(scope="module")
def pdb() -> Pdb:
    return Pdb.open(FIX / "small.pdb")


def test_container_shape(pdb):
    assert pdb.msf.block_size == 4096
    assert pdb.msf.num_streams == 16
    assert len(pdb.modules) == 2
    assert pdb.machine == 0x14C


def test_sections_match_pe(pdb):
    pe = read_pe_headers(FIX / "small.dll")
    assert compare_sections(pdb.sections, pe.sections) == []
    assert [s.name for s in pdb.sections] == [".text", ".rdata", ".data", ".reloc"]


def test_publics_match_llvm_pdbutil(pdb):
    got = {(p.name, p.section, p.offset, p.is_function) for p in pdb.publics()}
    assert got == {
        ("_g_counter", 3, 0x0, False),
        ("_alpha", 1, 0x0, True),
        ("_beta", 1, 0x50, True),
        ("_mainfn", 1, 0x70, True),
    }


@pytest.mark.parametrize(
    "rva, func, kind, line",
    [  # (rva, function, record type, line) from llvm-symbolizer / llvm-pdbutil
        (0x1000, "alpha", "S_GPROC32", 6),
        (0x1020, "alpha", "S_GPROC32", 8),
        (0x1040, "helper", "S_LPROC32", 4),
        (0x1060, "beta", "S_GPROC32", 11),
        (0x1070, "mainfn", "S_GPROC32", 13),
    ],
)
def test_functions_and_lines_match_oracle(pdb, rva, func, kind, line):
    r = pdb.resolve(rva)
    assert (r.function, r.source, r.line) == (func, kind, line)
    assert r.file.endswith("small.c")


def test_offset_into_function(pdb):
    r = pdb.resolve(0x1040)  # helper starts at 0x30
    assert r.function_offset == 0x10
