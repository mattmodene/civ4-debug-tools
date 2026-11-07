"""Optional integration test against the local Caveman2Cosmos files named by CIV4DBG_TEST_DATA.

The files are never committed; the test skips, naming the variable and the file, when they are absent. It pins the
2026-11-02 findings for the crashing build (DLL 10,235,904 bytes).
"""

import pytest
from realdata import path_of, skipif_missing

from civ4dbg import minidump
from civ4dbg.pdb import Pdb
from civ4dbg.pe import compare_sections, read_pe_headers

PDB = path_of("CvGameCoreDLL.pdb")
DLL = path_of("CvGameCoreDLL.dll")
DUMP = path_of("MiniDump-v45.BETA.8848-20261002-080426.dmp")

pytestmark = skipif_missing("CvGameCoreDLL.pdb", "CvGameCoreDLL.dll")


@pytest.fixture(scope="module")
def pdb():
    return Pdb.open(PDB)


def test_multi_block_map_container(pdb):
    assert (pdb.msf.block_size, pdb.msf.num_dir_blocks, pdb.msf.num_map_blocks) == (1024, 320, 2)


def test_section_table_matches_dll(pdb):
    assert compare_sections(pdb.sections, read_pe_headers(DLL).sections) == []


def test_fault_site(pdb):
    r = pdb.resolve(0x4F54A5)
    assert r.function == "CvUnit::invisibilityIntensityTotal"
    assert r.function_offset == 0x25
    assert r.file.endswith("cvunit.cpp")


@skipif_missing(DUMP.name)
def test_dump_reproduces_handoff_numbers():
    info = minidump.read_minidump(DUMP)
    mod = info.find_module("CvGameCoreDLL.dll")
    assert info.exception_address - mod.base == 0x4F54A5
    assert (info.access_type, info.access_target) == (0, 0x34)
    rvas = minidump.stack_rvas(info, mod)
    dedup = [r for i, r in enumerate(rvas) if i == 0 or r != rvas[i - 1]]
    assert len(dedup) == 18 and dedup[:3] == [0x4F74A8, 0x3510F2, 0x36A47E]
