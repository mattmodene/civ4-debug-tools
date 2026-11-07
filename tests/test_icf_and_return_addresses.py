"""Identical-code folding (several names, one address) and return-address lookups.

Synthetic PDBs only; see test_real_dump_resolution.py for the real-PDB cases.
"""

import pathlib

import pytest
from synth import build_minidump, build_pdb, module_stream, proc32, pub32, section_header

from civ4dbg import __main__ as cli
from civ4dbg.msf import Msf
from civ4dbg.pdb import (
    MAX_SHOWN_NAMES,
    S_GPROC32,
    S_LPROC32,
    AddressKind,
    Pdb,
    format_resolution,
    join_names,
)

SMALL = str(pathlib.Path(__file__).parent / "fixtures" / "small.pdb")
TEXT, DATA = 0x1000, 0xA000
SECTIONS = [
    section_header(".text", 0x8000, TEXT),
    section_header(".data", 0x100, DATA, chars=0xC0000040),  # not executable
]


def make(modules, contributions, publics):
    mods = []
    for name, procs in modules:
        data, sym_bytes = module_stream(b"".join(procs))
        mods.append((name, data, sym_bytes, 0, 0))
    return Pdb(Msf(build_pdb(SECTIONS, b"".join(publics), mods, contributions)))


def folded(names, kind=S_GPROC32, start=0x100, length=0x10):
    """One module per name, all procs at the same address; only module 0 is credited."""
    modules = [(f"m{i}.obj", [proc32(kind, n, 1, start, length)]) for i, n in enumerate(names)]
    return make(modules, [(1, start, length, 0)], [])


# -- identical-code folding ---------------------------------------------------------


def test_two_functions_at_one_address_are_both_reported_and_none_is_chosen():
    pdb = folded(["Zeta::get", "Alpha::get"])
    r = pdb.resolve(TEXT + 0x104)
    assert r.ambiguous and len(r.candidates) == 2
    assert r.function is None and r.function_offset is None and r.source is None
    assert [c.name for c in r.candidates] == ["Alpha::get", "Zeta::get"]  # sorted: no order is privileged
    assert all(c.offset == 4 for c in r.candidates)
    assert "ambiguous" in r.note and r.file is None and r.line is None


def test_the_cli_line_marks_the_ambiguity_and_lists_every_candidate():
    pdb = folded(["Zeta::get", "Alpha::get"])
    line = format_resolution(pdb.resolve(TEXT + 0x104))
    assert "AMBIGUOUS" in line and "NOT certain" in line and "2 candidate" in line
    assert "Alpha::get | Zeta::get" in line
    assert "Alpha::get +0x4" not in line and "Zeta::get +0x4" not in line  # never as a certain +off


def test_a_long_candidate_list_is_capped_with_a_count_and_expands_on_request():
    names = [f"Cls{i:02d}::getID" for i in range(MAX_SHOWN_NAMES + 4)]
    pdb = folded(names)
    r = pdb.resolve(TEXT + 0x100)
    assert len(r.candidates) == len(names)  # the API result is never truncated
    capped = format_resolution(r)
    assert "Cls00::getID" in capped and f"Cls{MAX_SHOWN_NAMES - 1:02d}::getID" in capped
    assert f"Cls{MAX_SHOWN_NAMES:02d}::getID" not in capped
    assert f"(+{len(names) - MAX_SHOWN_NAMES} more)" in capped
    assert f"{len(names)} candidate" in capped
    full = format_resolution(r, None)
    assert all(n in full for n in names) and "more)" not in full


def test_join_names_edge_cases():
    assert join_names(["a"]) == "a"
    assert join_names(["a", "b", "c"], 3) == "a | b | c"
    assert join_names(["a", "b", "c"], 2) == "a | b | (+1 more)"


def test_the_same_name_in_two_modules_is_one_candidate_not_an_ambiguity():
    pdb = folded(["Same::fn", "Same::fn"])
    r = pdb.resolve(TEXT + 0x100)
    assert not r.ambiguous and r.function == "Same::fn" and len(r.candidates) == 1


def test_a_unique_function_still_gets_its_name_offset_and_line_info():
    pdb = folded(["Only::fn"])
    r = pdb.resolve(TEXT + 0x108)
    assert (r.function, r.function_offset, r.source) == ("Only::fn", 8, "S_GPROC32")
    assert not r.ambiguous and "AMBIGUOUS" not in format_resolution(r)


def test_aliases_are_found_in_modules_the_linker_did_not_credit():
    """Only module 0 has a contribution over the address; module 1's alias must still count."""
    pdb = make(
        [
            ("credited.obj", [proc32(S_GPROC32, "A::f", 1, 0x100, 0x10)]),
            ("other.obj", [proc32(S_LPROC32, "B::f", 1, 0x100, 0x10)]),
        ],
        [(1, 0x100, 0x10, 0)],
        [],
    )
    r = pdb.resolve(TEXT + 0x100)
    assert [c.name for c in r.candidates] == ["A::f", "B::f"]
    assert {c.module for c in r.candidates} == {"credited.obj", "other.obj"}
    assert r.module == "credited.obj"


def test_aliases_with_different_starts_that_both_cover_the_address_are_candidates():
    pdb = make(
        [
            ("a.obj", [proc32(S_GPROC32, "Outer", 1, 0x100, 0x40)]),
            ("b.obj", [proc32(S_GPROC32, "Inner", 1, 0x110, 0x10)]),
        ],
        [(1, 0x100, 0x40, 0)],
        [],
    )
    r = pdb.resolve(TEXT + 0x118)
    assert [(c.name, c.offset) for c in r.candidates] == [("Inner", 8), ("Outer", 0x18)]
    assert pdb.resolve(TEXT + 0x120).function == "Outer"  # past Inner: unique again


def test_function_publics_sharing_an_exact_address_are_ambiguous_too():
    pdb = make([], [], [pub32("_b_thunk", 1, 0x300), pub32("_a_thunk", 1, 0x300)])
    r = pdb.resolve(TEXT + 0x300)
    assert r.ambiguous and [c.name for c in r.candidates] == ["_a_thunk", "_b_thunk"]
    assert {c.source for c in r.candidates} == {"S_PUB32"}
    assert "AMBIGUOUS" in format_resolution(r)
    assert [p.name for p in pdb.find_publics(1, 0x305)] == ["_a_thunk", "_b_thunk"]


def test_several_publics_before_an_uncovered_address_are_all_named_in_the_hint():
    pdb = make([], [], [pub32("_y", 1, 0x300), pub32("_x", 1, 0x300)])
    r = pdb.resolve(TEXT + 0x310)
    assert r.function is None and r.public is None  # no single public either
    assert r.public_names == ("_x", "_y") and r.public_offset == 0x10
    assert "_x | _y" in r.note


# -- return addresses -----------------------------------------------------------------


@pytest.fixture(scope="module")
def adjacent() -> Pdb:
    """caller [0x2C0, 0x300) ends in a no-return call; callee starts at 0x300."""
    return make(
        [("m.obj", [proc32(S_GPROC32, "caller", 1, 0x2C0, 0x40), proc32(S_GPROC32, "callee", 1, 0x300, 0x40)])],
        [(1, 0x2C0, 0x80, 0)],
        [pub32("_caller", 1, 0x2C0), pub32("_callee", 1, 0x300)],
    )


def test_exact_mode_looks_up_the_address_as_given(adjacent):
    r = adjacent.resolve(TEXT + 0x300)
    assert r.kind is AddressKind.EXACT and r.lookup_rva == TEXT + 0x300
    assert (r.function, r.function_offset) == ("callee", 0)


def test_default_mode_is_exact(adjacent):
    assert adjacent.resolve(TEXT + 0x300) == adjacent.resolve(TEXT + 0x300, AddressKind.EXACT)


def test_return_address_mode_looks_up_rva_minus_one_and_keeps_the_original(adjacent):
    r = adjacent.resolve(TEXT + 0x300, AddressKind.RETURN_ADDRESS)
    assert r.kind is AddressKind.RETURN_ADDRESS
    assert r.rva == TEXT + 0x300 and r.lookup_rva == TEXT + 0x2FF
    assert (r.function, r.function_offset) == ("caller", 0x3F)
    assert r.section_offset == 0x2FF
    assert adjacent.resolve_return_address(TEXT + 0x300) == r


def test_return_address_inside_a_function_is_one_byte_earlier_than_exact(adjacent):
    exact = adjacent.resolve(TEXT + 0x2E5)
    ret = adjacent.resolve(TEXT + 0x2E5, AddressKind.RETURN_ADDRESS)
    assert exact.function == ret.function == "caller"
    assert exact.function_offset == ret.function_offset + 1


def test_a_return_address_that_is_a_function_entry_is_flagged(adjacent):
    ret = adjacent.resolve(TEXT + 0x300, AddressKind.RETURN_ADDRESS)
    assert ret.entry_symbols == 1
    line = format_resolution(ret)
    assert "return address; looked up at 0x12ff" in line and "caller +0x3f" in line
    assert "itself the start of 1 symbol" in line and "function pointer" in line
    plain = adjacent.resolve(TEXT + 0x2E5, AddressKind.RETURN_ADDRESS)
    assert plain.entry_symbols == 0 and "itself the start" not in format_resolution(plain)


def test_exact_mode_never_sets_the_entry_flag(adjacent):
    assert adjacent.resolve(TEXT + 0x300).entry_symbols == 0


def test_a_return_address_into_a_non_executable_section_is_not_named(adjacent):
    r = adjacent.resolve(DATA + 0x10, AddressKind.RETURN_ADDRESS)
    assert r.function is None and "not executable" in r.note
    assert adjacent.resolve(DATA + 0x10).note != r.note  # exact mode does not apply the rule


def test_return_address_at_section_start_looks_before_the_section(adjacent):
    r = adjacent.resolve(TEXT, AddressKind.RETURN_ADDRESS)  # TEXT - 1 is in the headers
    assert r.section is None and "return address - 1 is outside every section" in r.note
    assert "looked up at 0xfff" in format_resolution(r)


def test_return_address_zero_is_outside_every_section(adjacent):
    r = adjacent.resolve(0, AddressKind.RETURN_ADDRESS)
    assert r.section is None and r.lookup_rva == -1


# -- the command line -------------------------------------------------------------------


def test_cli_resolve_defaults_to_exact_and_flag_switches_to_return_address(capsys):
    pdb = SMALL
    assert cli.main(["resolve", "--pdb", pdb, "0x1050"]) == 0
    exact = capsys.readouterr().out
    assert "beta +0x0" in exact and "return address" not in exact
    assert cli.main(["resolve", "--pdb", pdb, "--return-address", "0x1050"]) == 0
    ret = capsys.readouterr().out
    assert "return address; looked up at 0x104f" in ret and "beta +0x0" not in ret


def test_cli_dump_resolves_the_fault_exactly_and_stack_words_as_return_addresses(tmp_path, capsys):
    pdb = SMALL
    base = 0x2C50000
    dmp = build_minidump(
        [(base, 0x9E6000, r"S:\game\CvGameCoreDLL.dll")],
        0xC0000005,
        base + 0x1050,
        (0, 0x34),
        base + 0x1050,
        [base + 0x1050, base + 0x1071],
    )
    f = tmp_path / "x.dmp"
    f.write_bytes(dmp)
    assert cli.main(["dump", "--pdb", pdb, "--allow-build-mismatch", str(f)]) == 0
    out = capsys.readouterr().out
    fault = out.split("== fault site ==")[1].split("== stack")[0]
    assert "beta +0x0" in fault and "return address" not in fault  # fault: exact
    stack = out.split("== stack")[1]
    assert "0x1050 (return address; looked up at 0x104f)" in stack
    assert "0x1071 (return address; looked up at 0x1070)" in stack and "mainfn +0x0" in stack


def test_the_cli_cap_is_literally_five_names_then_a_count_of_the_rest():
    pdb = folded([f"N{i}::f" for i in range(9)])
    line = format_resolution(pdb.resolve(TEXT + 0x100))
    shown = line.split("NOT certain: ")[1].split(">")[0]
    assert shown == "N0::f | N1::f | N2::f | N3::f | N4::f | (+4 more)"
    assert MAX_SHOWN_NAMES == 5
