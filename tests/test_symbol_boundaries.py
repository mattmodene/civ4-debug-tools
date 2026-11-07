"""Symbol-boundary and record-precedence behaviour of ``Pdb.resolve``.

All fixtures are synthetic (``synth.build_pdb``); every RVA below is written as
``section base + section offset`` so the arithmetic is visible in the test.
"""

import pytest
from synth import build_pdb, module_stream, proc32, pub32, section_header

from civ4dbg.msf import Msf
from civ4dbg.pdb import S_GPROC32, S_LPROC32, Pdb, format_resolution

TEXT = 0x1000  # .text   seg 1, vsize 0x8000 -> RVAs 0x1000..0x8fff
DATA = 0xA000  # .data   seg 2, vsize 0x100
RELOC = 0xB000  # .reloc  seg 3, vsize 0x200 (not code, no symbols at all)
SECTIONS = [
    section_header(".text", 0x8000, TEXT),
    section_header(".data", 0x100, DATA),
    section_header(".reloc", 0x200, RELOC),
]


def make(modules, contributions, publics):
    """modules = [(name, [proc records])]; returns an opened Pdb."""
    mods = []
    for name, procs in modules:
        data, sym_bytes = module_stream(b"".join(procs))
        mods.append((name, data, sym_bytes, 0, 0))
    return Pdb(Msf(build_pdb(SECTIONS, b"".join(publics), mods, contributions)))


@pytest.fixture(scope="module")
def pdb() -> Pdb:
    # first : [0x100, 0x140) global    adj : [0x140, 0x160) local, directly after
    # gap   : [0x200, 0x210) global, 0x160..0x1ff is padding between functions
    procs = [
        proc32(S_GPROC32, "first", 1, 0x100, 0x40),
        proc32(S_LPROC32, "adj", 1, 0x140, 0x20),
        proc32(S_GPROC32, "gap", 1, 0x200, 0x10),
    ]
    return make(
        [("m.obj", procs)],
        [(1, 0x100, 0x60, 0), (1, 0x200, 0x10, 0)],  # contributions cover the functions only
        [
            pub32("_first", 1, 0x100),
            pub32("_adj", 1, 0x140),
            pub32("_gap", 1, 0x200),
            pub32("_dat", 2, 0x8, function=False),
        ],
    )


# -- exact function boundaries ---------------------------------------------------


@pytest.mark.parametrize(
    "off, func, foff, source",
    [
        (0x100, "first", 0x00, "S_GPROC32"),  # exactly the function start
        (0x101, "first", 0x01, "S_GPROC32"),
        (0x13F, "first", 0x3F, "S_GPROC32"),  # last byte of first
        (0x140, "adj", 0x00, "S_LPROC32"),  # the byte after first's last is adj's start
        (0x15F, "adj", 0x1F, "S_LPROC32"),  # last byte of adj
        (0x200, "gap", 0x00, "S_GPROC32"),
        (0x20F, "gap", 0x0F, "S_GPROC32"),  # last byte of gap
    ],
)
def test_inside_function_boundaries_use_the_proc_record(pdb, off, func, foff, source):
    r = pdb.resolve(TEXT + off)
    assert (r.function, r.function_offset, r.source) == (func, foff, source)
    assert r.section_name == ".text" and r.section_offset == off


@pytest.mark.parametrize("off", [0x160, 0x161, 0x180, 0x1FF, 0x210, 0x211])
def test_one_past_the_end_and_padding_are_never_a_proc_hit(pdb, off):
    """No S_*PROC record covers these bytes, so the answer must not claim one did."""
    r = pdb.resolve(TEXT + off)
    assert r.source != "S_GPROC32" and r.source != "S_LPROC32"


def test_padding_after_a_function_does_not_name_the_preceding_function(pdb):
    """``_adj`` is the nearest public at or before 0x180, but it is only 0x20 bytes
    long, so it must not be offered as *the* function: the result has no function
    name and says the address is outside any known function."""
    r = pdb.resolve(TEXT + 0x180)
    assert r.function is None and r.candidates == () and r.source is None
    assert r.public == "_adj" and r.public_offset == 0x40 and r.public_is_function is True
    assert "outside any known function" in r.note and "_adj" in r.note
    assert "not credible" not in r.note
    line = format_resolution(r)
    assert "+0x40  (S_PUB32)" not in line and "outside any known function" in line


def test_one_past_last_byte_of_a_function_is_not_attributed_to_it(pdb):
    r = pdb.resolve(TEXT + 0x210)  # gap is [0x200, 0x210)
    assert r.function is None and r.candidates == ()
    assert r.public == "_gap" and r.public_offset == 0x10
    assert "outside any known function" in r.note


def test_a_public_that_starts_exactly_here_does_name_the_function_when_no_proc_covers_it():
    pdb = make([], [], [pub32("_thunk", 1, 0x300)])
    r = pdb.resolve(TEXT + 0x300)
    assert (r.function, r.function_offset, r.source) == ("_thunk", 0, "S_PUB32")
    assert not r.ambiguous and r.note is None
    assert pdb.resolve(TEXT + 0x301).function is None  # one byte later: no length known


# -- below the first symbol, section edges, non-code sections ------------------------


@pytest.mark.parametrize("off", [0x0, 0x1, 0xFF])
def test_below_the_first_symbol_is_no_symbol_found(pdb, off):
    r = pdb.resolve(TEXT + off)
    assert r.function is None and r.source is None
    assert r.note == "no symbol found"
    assert r.public is None
    assert "no symbol found" in format_resolution(r)


def test_data_section_before_its_first_public_does_not_borrow_from_text(pdb):
    """.data has its first public at 0x8; .text has publics. Offset 0x4 must not
    resolve to .text's last public (the bisect crosses a section boundary)."""
    r = pdb.resolve(DATA + 0x4)
    assert r.function is None and r.public is None
    assert r.note == "no symbol found"


def test_data_public_is_never_a_function(pdb):
    for off in (0x8, 0x20):  # exactly on it, and past it
        r = pdb.resolve(DATA + off)
        assert r.function is None and r.candidates == ()
        assert r.public == "_dat" and r.public_offset == off - 0x8 and r.public_is_function is False
        assert "non-function" in r.note


def test_reloc_section_has_no_symbol(pdb):
    for off in (0x0, 0x10, 0x1FF):
        r = pdb.resolve(RELOC + off)
        assert r.section_name == ".reloc" and r.section_offset == off
        assert r.function is None and r.note == "no symbol found"
        assert r.module is None


@pytest.mark.parametrize(
    "rva, inside",
    [
        (TEXT - 1, False),  # PE headers, below .text
        (TEXT, True),
        (TEXT + 0x7FFF, True),  # last byte of .text
        (TEXT + 0x8000, False),  # one past: the hole before .data
        (DATA - 1, False),
        (DATA + 0xFF, True),  # last byte of .data
        (DATA + 0x100, False),
        (RELOC + 0x1FF, True),
        (RELOC + 0x200, False),
        (0, False),
        (0xFFFFFFFF, False),
    ],
)
def test_section_edges(pdb, rva, inside):
    r = pdb.resolve(rva)
    if inside:
        assert r.section is not None
    else:
        assert r.section is None and "outside every section" in r.note
        assert "unresolved" in format_resolution(r)


def test_negative_rva_is_outside_every_section(pdb):
    r = pdb.resolve(-1)
    assert r.section is None


# -- far-public boundary (FAR_PUBLIC_GAP = 0x2000, strictly greater is doubtful) -------


@pytest.fixture(scope="module")
def lonely() -> Pdb:
    return make([], [], [pub32("_lonely", 1, 0x100)])


def test_public_exactly_at_the_gap_limit_is_not_flagged_as_far(lonely):
    r = lonely.resolve(TEXT + 0x100 + 0x2000)
    assert r.function is None  # never named: a public carries no length
    assert r.public == "_lonely" and r.public_offset == 0x2000
    assert "not credible" not in r.note


def test_public_one_past_the_gap_limit_is_not_credible(lonely):
    r = lonely.resolve(TEXT + 0x100 + 0x2001)
    assert r.function is None
    assert "not credible" in r.note and "_lonely" in r.note
    assert r.public == "_lonely" and r.public_offset == 0x2001


# -- precedence: S_GPROC32 / S_LPROC32 / S_PUB32 ----------------------------------------


def test_proc_record_beats_a_public_at_the_same_address():
    pdb = make(
        [("m.obj", [proc32(S_GPROC32, "Real::name", 1, 0x300, 0x40)])],
        [(1, 0x300, 0x40, 0)],
        [pub32("?mangled@Real@@QAEXXZ", 1, 0x300)],
    )
    r = pdb.resolve(TEXT + 0x310)
    assert (r.function, r.source) == ("Real::name", "S_GPROC32")
    assert r.public == "?mangled@Real@@QAEXXZ" and r.public_offset == 0x10
    assert "pub: ?mangled@Real@@QAEXXZ +0x10" in format_resolution(r)


@pytest.mark.parametrize("kind, label", [(S_GPROC32, "S_GPROC32"), (S_LPROC32, "S_LPROC32")])
def test_each_proc_kind_resolves_without_any_public(kind, label):
    pdb = make([("m.obj", [proc32(kind, "only", 1, 0x300, 0x40)])], [(1, 0x300, 0x40, 0)], [])
    r = pdb.resolve(TEXT + 0x305)
    assert (r.function, r.source, r.public) == ("only", label, None)


def test_public_alone_is_a_hint_not_a_name():
    pdb = make([], [], [pub32("_only_pub", 1, 0x300)])
    r = pdb.resolve(TEXT + 0x305)
    assert r.function is None and r.source is None
    assert (r.public, r.public_offset) == ("_only_pub", 5)


def test_proc_record_without_a_covering_contribution_is_invisible():
    """The module is found through the section contributions; a proc in a module
    with no contribution over the address is invisible, and the public that
    precedes the address is only a hint."""
    pdb = make(
        [("m.obj", [proc32(S_GPROC32, "hidden", 1, 0x300, 0x40)])],
        [],  # no contributions at all
        [pub32("_pub", 1, 0x300)],
    )
    r = pdb.resolve(TEXT + 0x310)
    assert r.function is None and r.candidates == ()
    assert r.public == "_pub"


@pytest.mark.parametrize("order", [[(S_GPROC32, "g"), (S_LPROC32, "l")], [(S_LPROC32, "l"), (S_GPROC32, "g")]])
def test_overlapping_global_and_local_proc_are_both_reported_not_decided_by_stream_order(order):
    """Two records covering one address are candidates, whatever their kind or order."""
    procs = [proc32(kind, name, 1, 0x300, 0x40) for kind, name in order]
    pdb = make([("m.obj", procs)], [(1, 0x300, 0x40, 0)], [])
    r = pdb.resolve(TEXT + 0x310)
    assert r.ambiguous and r.function is None
    assert [(c.name, c.source) for c in r.candidates] == [("g", "S_GPROC32"), ("l", "S_LPROC32")]


def test_nested_contribution_does_not_hide_the_enclosing_one():
    """A small contribution of module 1 sits inside a large one of module 0; an
    address past the small one must still be attributed to module 0."""
    pdb = make(
        [
            ("big.obj", [proc32(S_GPROC32, "outer", 1, 0x400, 0x200)]),
            ("small.obj", []),
        ],
        [(1, 0x400, 0x200, 0), (1, 0x480, 0x10, 1)],
        [],
    )
    assert pdb.resolve(TEXT + 0x4F0).function == "outer"  # beyond the nested one
    assert pdb.resolve(TEXT + 0x485).module == "small.obj"  # inside the nested one
    assert pdb.resolve(TEXT + 0x4FF).function_offset == 0xFF


def test_contribution_is_half_open_at_its_end():
    pdb = make(
        [("a.obj", [proc32(S_GPROC32, "a", 1, 0x300, 0x10)]), ("b.obj", [proc32(S_GPROC32, "b", 1, 0x310, 0x10)])],
        [(1, 0x300, 0x10, 0), (1, 0x310, 0x10, 1)],
        [],
    )
    assert (pdb.resolve(TEXT + 0x30F).function, pdb.resolve(TEXT + 0x310).function) == ("a", "b")
    assert pdb.resolve(TEXT + 0x30F).module == "a.obj" and pdb.resolve(TEXT + 0x310).module == "b.obj"
