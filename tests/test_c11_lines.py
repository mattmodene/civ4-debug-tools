"""C11 (old-style ``sstSrcModule``) line tables, from the published layout.

There is no external oracle for C11 (LLVM ignores it). The fixtures come from
``c11_layout.build_c11``, whose layout was verified byte-for-byte against all
339 C11 blocks of the real PDB (see test_real_pdb_integration.py). Here the
decoder is checked against known line numbers at every boundary.
"""

import struct

from c11_layout import SrcFile, Table, build_c11, decode_c11
from synth import build_pdb, module_stream, proc32, section_header

from civ4dbg.msf import Msf
from civ4dbg.pdb import S_GPROC32, Pdb

TEXT = 0x1000
TEXT2 = 0x4000
SECTIONS = [section_header(".text", 0x2000, TEXT), section_header(".text2", 0x1000, TEXT2)]


def pdb_with(c11: bytes, procs: list[bytes], contributions, c13: bytes = b"", names: bytes = b"") -> Pdb:
    data, sym_bytes = module_stream(b"".join(procs), c11=c11, c13=c13)
    raw = build_pdb(SECTIONS, b"", [("m.obj", data, sym_bytes, len(c11), len(c13))], contributions, names=names)
    return Pdb(Msf(raw))


def line_at(pdb: Pdb, section_base: int, off: int):
    r = pdb.resolve(section_base + off)
    return (r.file, r.line)


# -- builder sanity: layout invariants of the published format ---------------------


def test_builder_header_matches_published_layout():
    blk = build_c11([SrcFile("a.c", [Table(1, 0x10, 0x1F, [(0x10, 1)])])])
    c_file, c_seg = struct.unpack_from("<HH", blk, 0)
    (base_src_file,) = struct.unpack_from("<I", blk, 4)
    start, end = struct.unpack_from("<II", blk, 8)
    (seg,) = struct.unpack_from("<H", blk, 16)
    assert (c_file, c_seg, base_src_file, (start, end), seg) == (1, 1, 0x14, (0x10, 0x1F), 1)
    assert len(blk) % 4 == 0
    assert decode_c11(blk)[0].name == "a.c"


# -- decoding ------------------------------------------------------------------------


def test_single_table_boundaries_and_inclusive_end():
    """Table range is [start, end] INCLUSIVE; entries at 0x100, 0x110, 0x130."""
    c11 = build_c11([SrcFile("a.c", [Table(1, 0x100, 0x13F, [(0x100, 10), (0x110, 11), (0x130, 12)])])])
    pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x40)], [(1, 0x100, 0x40, 0)])
    assert line_at(pdb, TEXT, 0x100) == ("a.c", 10)  # exactly the first entry
    assert line_at(pdb, TEXT, 0x10F) == ("a.c", 10)  # byte before the next entry
    assert line_at(pdb, TEXT, 0x110) == ("a.c", 11)  # exactly an interior entry
    assert line_at(pdb, TEXT, 0x12F) == ("a.c", 11)
    assert line_at(pdb, TEXT, 0x130) == ("a.c", 12)  # exactly the last entry
    assert line_at(pdb, TEXT, 0x13F) == ("a.c", 12)  # last byte: the end is inclusive


def test_one_byte_past_the_range_end_has_no_line_but_still_a_function():
    # The proc is longer than the line table (0x100..0x13F): the tail has no line.
    c11 = build_c11([SrcFile("a.c", [Table(1, 0x100, 0x13F, [(0x100, 10)])])])
    pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x80)], [(1, 0x100, 0x80, 0)])
    r = pdb.resolve(TEXT + 0x140)
    assert r.function == "f" and r.source == "S_GPROC32"
    assert (r.file, r.line) == (None, None)


def test_address_before_the_first_entry_inside_the_range_has_no_line():
    c11 = build_c11([SrcFile("a.c", [Table(1, 0x100, 0x13F, [(0x108, 10)])])])
    pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x40)], [(1, 0x100, 0x40, 0)])
    assert line_at(pdb, TEXT, 0x104) == (None, None)
    assert line_at(pdb, TEXT, 0x108) == ("a.c", 10)


def test_several_tables_in_one_file_given_out_of_address_order():
    """The real PDB lists a file's tables in non-ascending address order."""
    t_hi = Table(1, 0x200, 0x21F, [(0x200, 300), (0x210, 301)])
    t_lo = Table(1, 0x100, 0x11F, [(0x100, 100), (0x118, 101)])
    t_mid = Table(1, 0x150, 0x15F, [(0x150, 200)])
    c11 = build_c11([SrcFile("big.cpp", [t_hi, t_lo, t_mid])])
    procs = [proc32(S_GPROC32, n, 1, o, 0x20) for n, o in (("lo", 0x100), ("mid", 0x150), ("hi", 0x200))]
    pdb = pdb_with(c11, procs, [(1, 0x100, 0x20, 0), (1, 0x150, 0x10, 0), (1, 0x200, 0x20, 0)])
    assert line_at(pdb, TEXT, 0x119) == ("big.cpp", 101)
    assert line_at(pdb, TEXT, 0x155) == ("big.cpp", 200)
    assert line_at(pdb, TEXT, 0x21F) == ("big.cpp", 301)
    assert line_at(pdb, TEXT, 0x200) == ("big.cpp", 300)


def test_two_files_inlined_code_picks_the_nearest_preceding_entry():
    """A header function inlined into a .cpp function: the header's table lies
    inside the .cpp table's range. The nearest preceding entry decides."""
    cpp = Table(1, 0x100, 0x1FF, [(0x100, 10), (0x140, 12), (0x180, 13)])
    hdr = Table(1, 0x120, 0x13F, [(0x120, 500), (0x130, 501)])
    c11 = build_c11([SrcFile("main.cpp", [cpp]), SrcFile("inl.h", [hdr])])
    pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x100)], [(1, 0x100, 0x100, 0)])
    assert line_at(pdb, TEXT, 0x110) == ("main.cpp", 10)
    assert line_at(pdb, TEXT, 0x120) == ("inl.h", 500)
    assert line_at(pdb, TEXT, 0x135) == ("inl.h", 501)
    assert line_at(pdb, TEXT, 0x140) == ("main.cpp", 12)  # back in the .cpp
    assert line_at(pdb, TEXT, 0x1FF) == ("main.cpp", 13)


def test_same_offsets_in_two_sections_do_not_mix():
    t1 = Table(1, 0x100, 0x10F, [(0x100, 1)])
    t2 = Table(2, 0x100, 0x10F, [(0x100, 2)])
    c11 = build_c11([SrcFile("a.c", [t1]), SrcFile("b.c", [t2])])
    procs = [proc32(S_GPROC32, "one", 1, 0x100, 0x10), proc32(S_GPROC32, "two", 2, 0x100, 0x10)]
    pdb = pdb_with(c11, procs, [(1, 0x100, 0x10, 0), (2, 0x100, 0x10, 0)])
    assert line_at(pdb, TEXT, 0x104) == ("a.c", 1)
    assert line_at(pdb, TEXT2, 0x104) == ("b.c", 2)


def test_line_numbers_are_unsigned_16_bit():
    c11 = build_c11([SrcFile("a.c", [Table(1, 0x100, 0x10F, [(0x100, 65535), (0x108, 0)])])])
    pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x10)], [(1, 0x100, 0x10, 0)])
    assert line_at(pdb, TEXT, 0x100) == ("a.c", 65535)
    assert line_at(pdb, TEXT, 0x108) == ("a.c", 0)


def test_empty_line_table_and_empty_block_are_tolerated():
    c11 = build_c11([SrcFile("a.c", [Table(1, 0x100, 0x10F, [])])])
    pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x10)], [(1, 0x100, 0x10, 0)])
    r = pdb.resolve(TEXT + 0x104)
    assert r.function == "f" and r.line is None
    empty = pdb_with(b"", [proc32(S_GPROC32, "f", 1, 0x100, 0x10)], [(1, 0x100, 0x10, 0)])
    assert empty.resolve(TEXT + 0x104).function == "f"


def test_long_path_with_backslashes_and_alignment_padding_is_preserved():
    for name in ("c:\\projects\\caveman2cosmos\\sources\\cvunit.cpp", "a", "ab", "abc", "abcd"):
        c11 = build_c11([SrcFile(name, [Table(1, 0x100, 0x10F, [(0x100, 7)])])])
        pdb = pdb_with(c11, [proc32(S_GPROC32, "f", 1, 0x100, 0x10)], [(1, 0x100, 0x10, 0)])
        assert line_at(pdb, TEXT, 0x100) == (name, 7), name


def test_c11_and_c13_in_the_same_module_are_both_read():
    """C11 sits at SymByteSize, C13 follows it. Two functions, one per format."""
    from synth import c13_lines

    c11 = build_c11([SrcFile("old.c", [Table(1, 0x100, 0x10F, [(0x100, 5)])])])
    c13 = c13_lines(1, 0x200, 0x10, 0, [(0, 77)])
    procs = [proc32(S_GPROC32, "old", 1, 0x100, 0x10), proc32(S_GPROC32, "new", 1, 0x200, 0x10)]
    pdb = pdb_with(c11, procs, [(1, 0x100, 0x10, 0), (1, 0x200, 0x10, 0)], c13=c13, names=b"new.c\0")
    assert line_at(pdb, TEXT, 0x104) == ("old.c", 5)
    assert line_at(pdb, TEXT, 0x204) == ("new.c", 77)


def test_decode_round_trip_through_builder():
    files = [
        SrcFile("x.c", [Table(1, 0x10, 0x2F, [(0x10, 1), (0x20, 2)]), Table(2, 0x0, 0x7, [(0x0, 9)])]),
        SrcFile("y.h", [Table(1, 0x14, 0x17, [(0x14, 40)])]),
    ]
    assert decode_c11(build_c11(files)) == files
