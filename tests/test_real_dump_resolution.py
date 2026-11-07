"""Integration test against the real Caveman2Cosmos build (local files only).

The files are named by CIV4DBG_TEST_DATA (see realdata.py); every test here skips
cleanly, with a reason naming the variable and the file, when they are absent.
Pins the 2026-11-02 results for the crashing build:
fault RVA 0x4f54a5 -> CvUnit::invisibilityIntensityTotal, and the 18 distinct
stack RVAs (innermost first) of the 20261002-080426 dump.
"""

import pytest
from c11_layout import build_c11, decode_c11
from realdata import missing_reason, path_of, skipif_missing

from civ4dbg import __main__ as cli
from civ4dbg import minidump
from civ4dbg.pdb import AddressKind, Pdb, format_resolution

PDB = path_of("CvGameCoreDLL.pdb")
DLL = path_of("CvGameCoreDLL.dll")
DUMPS = {
    "20261002-075316": path_of("MiniDump-v45.BETA.8848-20261002-075316.dmp"),
    "20261002-075708": path_of("MiniDump-v45.BETA.8848-20261002-075708.dmp"),
    "20261002-080426": path_of("MiniDump-v45.BETA.8848-20261002-080426.dmp"),
}
DUMP = DUMPS["20261002-080426"]

needs_pdb = skipif_missing("CvGameCoreDLL.pdb")
needs_dump = skipif_missing(DUMP.name)

FAULT_RVA = 0x4F54A5
STACK_RVAS = [  # 18 distinct, innermost first
    0x4F74A8,
    0x3510F2,
    0x36A47E,
    0x9111F4,
    0x71843B,
    0x36A695,
    0x562EC0,
    0x1B5F53,
    0x718610,
    0x48EC61,
    0x721D08,
    0x4942F2,
    0x481CE0,
    0x722268,
    0x726A27,
    0x563103,
    0x497A07,
    0x970023,
]
# Named results from the 2026-11-02 run (offset into the function, file, line)
STACK_NAMED = {
    0x4F74A8: ("CvUnit::isInvisible", 0x138, "cvunit.cpp", 14485),
    0x3510F2: ("CvPlayerAI::AI_plotDangerUnitCheck", 0xF2, "cvplayerai.cpp", 3424),
    0x36A47E: ("CvPlayerAI::AI_getPlotDangerInternal", 0x22E, "cvplayerai.cpp", 3616),
    0x36A695: ("CvPlayerAI::AI_getPlotDanger", 0x105, "cvplayerai.cpp", 3720),
    0x562EC0: ("CvUnit::killUnconditional", 0xD00, "cvunit.cpp", 1798),
    0x1B5F53: ("CvMalloc", 0x43, "cvallocator.cpp", 79),
    0x563103: ("CvUnit::doDelayedDeath", 0x43, "cvunit.cpp", 19276),
    0x497A07: ("CvSelectionGroup::doDelayedDeath", 0x307, "cvselectiongroup.cpp", 450),
}


@pytest.fixture(scope="module")
def pdb():
    return Pdb.open(PDB)


@needs_pdb
def test_fault_rva_resolves_to_invisibility_intensity_total(pdb):
    r = pdb.resolve(FAULT_RVA)
    assert r.function == "CvUnit::invisibilityIntensityTotal"
    assert (r.function_offset, r.source) == (0x25, "S_GPROC32")
    assert r.file.lower().endswith("cvunit.cpp") and r.line == 37567
    assert r.section_name == ".text"


@needs_pdb
@pytest.mark.parametrize("rva", sorted(STACK_NAMED))
def test_named_stack_frames(pdb, rva):
    name, off, fname, line = STACK_NAMED[rva]
    r = pdb.resolve(rva)
    assert (r.function, r.function_offset, r.source) == (name, off, "S_GPROC32")
    assert r.file.lower().endswith(fname) and r.line == line


# The same frames read as return addresses (looked up at RVA-1): (name, offset, file, line).
STACK_AS_RETURN = {
    0x4F74A8: ("CvUnit::isInvisible", 0x137, "cvunit.cpp", 14485),
    0x3510F2: ("CvPlayerAI::AI_plotDangerUnitCheck", 0xF1, "cvplayerai.cpp", 3424),
    0x36A47E: ("CvPlayerAI::AI_getPlotDangerInternal", 0x22D, "cvplayerai.cpp", 3616),
    0x36A695: ("CvPlayerAI::AI_getPlotDanger", 0x104, "cvplayerai.cpp", 3720),
    0x562EC0: ("CvUnit::killUnconditional", 0xCFF, "cvunit.cpp", 1798),
    0x1B5F53: ("CvMalloc", 0x42, "cvallocator.cpp", 61),
    0x563103: ("CvUnit::doDelayedDeath", 0x42, "cvunit.cpp", 19275),
    0x497A07: ("CvSelectionGroup::doDelayedDeath", 0x306, "cvselectiongroup.cpp", 450),
}


@needs_pdb
@pytest.mark.parametrize("rva", sorted(STACK_AS_RETURN))
def test_named_stack_frames_as_return_addresses(pdb, rva):
    name, off, fname, line = STACK_AS_RETURN[rva]
    r = pdb.resolve(rva, AddressKind.RETURN_ADDRESS)
    assert (r.rva, r.lookup_rva, r.kind) == (rva, rva - 1, AddressKind.RETURN_ADDRESS)
    assert (r.function, r.function_offset, r.source) == (name, off, "S_GPROC32")
    assert not r.ambiguous
    assert r.file.lower().endswith(fname) and r.line == line


@needs_pdb
def test_exact_and_return_modes_differ_by_one_byte(pdb):
    exact = pdb.resolve(0x4F74A8)
    ret = pdb.resolve(0x4F74A8, AddressKind.RETURN_ADDRESS)
    assert exact.kind is AddressKind.EXACT and exact.lookup_rva == 0x4F74A8
    assert exact.function_offset == ret.function_offset + 1


@needs_pdb
def test_stack_frames_that_are_not_functions_are_flagged_not_named(pdb):
    data = pdb.resolve(0x9111F4)  # exact lookup of a data address
    assert data.section_name == ".data" and data.function is None and "non-function" in data.note
    assert data.public.startswith("?plotDangerCache@CvPlayerAI")
    as_ret = pdb.resolve(0x9111F4, AddressKind.RETURN_ADDRESS)
    assert as_ret.function is None and "not executable" in as_ret.note
    reloc = pdb.resolve(0x970023)
    assert reloc.section_name == ".reloc" and reloc.function is None
    assert reloc.note == "no symbol found"
    for rva in (0x71843B, 0x718610, 0x721D08, 0x722268, 0x726A27):
        for kind in AddressKind:
            r = pdb.resolve(rva, kind)
            assert r.function is None and "not credible" in r.note, (hex(rva), kind)


@needs_pdb
def test_canDelete_frame_is_a_function_entry_not_a_return_address(pdb):
    exact = pdb.resolve(0x481CE0)
    assert exact.function == "`anonymous namespace'::canDelete" and exact.function_offset == 0
    ret = pdb.resolve(0x481CE0, AddressKind.RETURN_ADDRESS)
    assert ret.function is None and ret.entry_symbols == 1
    assert "itself the start of 1 symbol" in format_resolution(ret)


@needs_pdb
def test_identical_code_folded_functions_are_reported_as_ambiguous(pdb):
    """CvArea::getID, CvDeal::getID, CvSelectionGroup::getID ... are one body in the image."""
    starts = {p.offset for m in range(len(pdb.modules)) for p in pdb.module_procs(m) if p.name == "CvArea::getID"}
    assert starts, "CvArea::getID not found in the PDB"
    rva = pdb.section_to_rva(1, min(starts))
    r = pdb.resolve(rva)
    names = [c.name for c in r.candidates]
    assert r.ambiguous and r.function is None and r.function_offset is None
    assert {"CvArea::getID", "CvDeal::getID", "CvSelectionGroup::getID"} <= set(names)
    assert len(names) == len(set(names)) and len(names) >= 20  # 27 on 2026-11-02
    line = format_resolution(r)
    assert "AMBIGUOUS" in line and f"{len(names)} candidate" in line and "NOT certain" in line
    assert "(+" in line and "more" in line  # capped list, with the remainder counted
    assert all(n in format_resolution(r, None) for n in names)  # all shown on request


@needs_pdb
def test_the_fault_address_is_covered_by_exactly_one_procedure(pdb):
    covering = pdb.procs_covering(1, pdb.rva_to_section(FAULT_RVA)[1])
    assert [p.name for p in covering] == ["CvUnit::invisibilityIntensityTotal"]


@needs_pdb
@needs_dump
def test_dump_gives_the_fault_rva_and_exactly_the_18_stack_rvas():
    info = minidump.read_minidump(DUMP)
    mod = info.find_module("CvGameCoreDLL.dll")
    assert info.exception_address - mod.base == FAULT_RVA
    assert (info.exception_code, info.access_type, info.access_target) == (0xC0000005, 0, 0x34)
    raw = minidump.stack_rvas(info, mod)
    assert len(raw) == 20  # 20 words in the default window, two adjacent duplicates
    dedup = [r for i, r in enumerate(raw) if i == 0 or r != raw[i - 1]]
    assert dedup == STACK_RVAS and len(set(dedup)) == 18


@needs_pdb
@pytest.mark.parametrize("key", sorted(DUMPS))
def test_all_three_crash_dumps_fault_at_the_same_site(pdb, key):
    reason = missing_reason(DUMPS[key].name)
    if reason:
        pytest.skip(reason)
    info = minidump.read_minidump(DUMPS[key])
    mod = info.find_module("CvGameCoreDLL.dll")
    rva = info.exception_address - mod.base
    assert rva == FAULT_RVA
    assert pdb.resolve(rva).function == "CvUnit::invisibilityIntensityTotal"


@needs_pdb
@needs_dump
def test_cli_dump_end_to_end(capsys):
    rc = cli.main(
        ["dump", "--pdb", str(PDB), "--dll", str(DLL), str(DUMP)]
        if DLL.exists()
        else ["dump", "--pdb", str(PDB), str(DUMP)]
    )
    out = capsys.readouterr().out
    assert rc == 0
    assert "CvUnit::invisibilityIntensityTotal +0x25" in out
    stack = out.split("== stack")[1].splitlines()[1:]
    assert [ln.split()[0] for ln in stack if ln.strip()] == [f"{r:#x}" for r in STACK_RVAS]


@needs_pdb
def test_every_c11_block_is_rebuilt_byte_for_byte_by_the_independent_builder(pdb):
    """Oracle for the C11 layout used by the synthetic tests: decoding every real
    block and re-serialising it with tests/c11_layout.py gives identical bytes."""
    checked = multi_file = 0
    for m in pdb.modules:
        if not m.c11_bytes or m.stream == 0xFFFF:
            continue
        block = pdb.msf.read_stream(m.stream)[m.sym_bytes : m.sym_bytes + m.c11_bytes]
        files = decode_c11(block)
        assert build_c11(files) == block, m.name
        checked += 1
        multi_file += len(files) > 1
    assert checked >= 300 and multi_file > 100  # 339 / 167 on 2026-11-02
