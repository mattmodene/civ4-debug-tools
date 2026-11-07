"""Resolver tests against a hand-built PDB (covers C11 and C13 line formats)."""

import struct

import pytest
from synth import (
    build_pdb,
    c11_lines,
    c13_lines,
    module_stream,
    proc32,
    pub32,
    section_header,
)

from civ4dbg.msf import Msf
from civ4dbg.pdb import S_GPROC32, S_LPROC32, Pdb, format_resolution

TEXT_VA = 0x1000
SECTIONS = [section_header(".text", 0x8000, TEXT_VA), section_header(".data", 0x100, 0xA000)]


@pytest.fixture(scope="module")
def pdb() -> Pdb:
    # module 0: C11 line info (what the Caveman2Cosmos PDB uses)
    sym0 = proc32(S_GPROC32, "Foo::bar", 1, 0x100, 0x40) + proc32(S_LPROC32, "helper", 1, 0x140, 0x20)
    c11 = c11_lines([("a.cpp", 1, 0x100, 0x13F, [(0x100, 10), (0x110, 11), (0x130, 12)])])
    data0, sb0 = module_stream(sym0, c11=c11)
    # module 1: C13 line info (what modern toolchains write)
    sym1 = proc32(S_GPROC32, "Baz::qux", 1, 0x400, 0x80)
    c13 = c13_lines(1, 0x400, 0x80, 0, [(0, 100), (0x20, 101)])
    data1, sb1 = module_stream(sym1, c13=c13)
    publics = (
        pub32("?bar@Foo@@QAEXXZ", 1, 0x100)
        + pub32("?qux@Baz@@QAEXXZ", 1, 0x400)
        + pub32("_far_away", 1, 0x10)
        + pub32("_global", 2, 0x8, function=False)
    )
    raw = build_pdb(
        SECTIONS,
        publics,
        [
            ("a.obj", data0, sb0, len(c11), 0),
            ("b.obj", data1, sb1, 0, len(c13)),
        ],
        [(1, 0x100, 0x60, 0), (1, 0x400, 0x80, 1)],
        names=b"b.cpp\0",
    )
    return Pdb(Msf(raw))


def test_sections_and_rva_conversion(pdb):
    assert [s.name for s in pdb.sections] == [".text", ".data"]
    sec, off = pdb.rva_to_section(TEXT_VA + 0x104)
    assert (sec.index, off) == (1, 0x104)
    assert pdb.rva_to_section(0x9000) is None


def test_gproc_with_c11_lines(pdb):
    r = pdb.resolve(TEXT_VA + 0x114)
    assert (r.function, r.function_offset, r.source) == ("Foo::bar", 0x14, "S_GPROC32")
    assert (r.file, r.line) == ("a.cpp", 11)
    assert r.public == "?bar@Foo@@QAEXXZ" and r.public_offset == 0x14


def test_lproc_without_public(pdb):
    r = pdb.resolve(TEXT_VA + 0x144)
    assert (r.function, r.source) == ("helper", "S_LPROC32")


def test_c13_lines_use_block_base(pdb):
    # entries are relative to the block's code offset: 0x400 + 0x20 -> line 101
    r = pdb.resolve(TEXT_VA + 0x425)
    assert r.function == "Baz::qux" and r.function_offset == 0x25
    assert (r.file, r.line) == ("b.cpp", 101)
    assert pdb.resolve(TEXT_VA + 0x400).line == 100


def test_public_is_only_a_hint_when_no_module_covers(pdb):
    r = pdb.resolve(TEXT_VA + 0x500)  # past module 1's contribution, 0x100 after _qux
    assert r.function is None and r.source is None
    assert (r.public, r.public_offset) == ("?qux@Baz@@QAEXXZ", 0x100)
    assert "outside any known function" in r.note


def test_far_public_is_not_credible(pdb):
    r = pdb.resolve(TEXT_VA + 0x3000)  # >0x2000 past the nearest public
    assert r.function is None
    assert "not credible" in r.note


def test_data_public_flagged(pdb):
    r = pdb.resolve(0xA008)
    assert r.function is None and r.public == "_global" and r.public_offset == 0
    assert "non-function" in r.note


def test_unresolvable_rva(pdb):
    r = pdb.resolve(0x20000)
    assert r.function is None and "outside" in r.note
    assert "unresolved" in format_resolution(r)


# -- section extents, line-lookup cache, C13 sanity, closing ------------------------------------------


def test_a_section_with_zero_virtual_size_uses_its_raw_size():
    secs = [section_header(".text", 0x8000, TEXT_VA), section_header(".rawonly", 0, 0xC000, rsize=0x200)]
    pdb = Pdb(Msf(build_pdb(secs, b"", [], [])))
    assert pdb.rva_to_section(0xC000 + 0x1FF)[0].name == ".rawonly"
    assert pdb.rva_to_section(0xC000 + 0x200) is None
    both_zero = Pdb(Msf(build_pdb([section_header(".empty", 0, 0xC000)], b"", [], [])))
    assert both_zero.rva_to_section(0xC000) is None


def test_section_to_rva_rejects_a_section_that_does_not_exist(pdb):
    from civ4dbg.pdb import PdbError

    assert pdb.section_to_rva(1, 0x10) == TEXT_VA + 0x10
    for bad in (0, 3, -1):
        with pytest.raises(PdbError, match="does not exist"):
            pdb.section_to_rva(bad, 0)


def test_repeated_line_lookups_agree_and_use_the_cached_offsets(pdb):
    lines = pdb.module_lines(0)
    first = [lines.lookup(1, o) for o in (0x100, 0x10F, 0x110, 0x12F, 0x130, 0x13F, 0x140)]
    assert first == [("a.cpp", 10), ("a.cpp", 10), ("a.cpp", 11), ("a.cpp", 11), ("a.cpp", 12), ("a.cpp", 12), None]
    assert lines._offsets  # built once per block, reused
    assert [lines.lookup(1, o) for o in (0x100, 0x10F, 0x110, 0x12F, 0x130, 0x13F, 0x140)] == first


def test_a_c13_line_block_smaller_than_its_header_is_a_pdberror():
    from civ4dbg.pdb import PdbError

    sym = proc32(S_GPROC32, "Baz::qux", 1, 0x400, 0x80)
    c13 = c13_lines(1, 0x400, 0x80, 0, [(0, 100), (0x20, 101)])
    good_block = struct.pack("<III", 0, 2, 12 + 8 * 2)
    assert good_block in c13
    bad = c13.replace(good_block, struct.pack("<III", 0, 2, 8))
    data, sb = module_stream(sym, c13=bad)
    raw = build_pdb(SECTIONS, b"", [("b.obj", data, sb, 0, len(bad))], [(1, 0x400, 0x80, 0)], names=b"b.cpp\0")
    p = Pdb(Msf(raw))
    with pytest.raises(PdbError, match="smaller than its header"):
        p.resolve(TEXT_VA + 0x410)


def test_pdb_open_as_a_context_manager_closes_the_mapping(tmp_path):
    import pathlib

    src = pathlib.Path(__file__).parent / "fixtures" / "small.pdb"
    with Pdb.open(src) as p:
        assert not p.msf._buf.closed
        assert p.resolve(0x1000).function == "alpha"
    assert p.msf._buf.closed
