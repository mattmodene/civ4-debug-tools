"""Build-match check (dump vs DLL), OMAP refusal and the CLI exit codes."""

import pathlib

import pytest
from synth import build_minidump, build_pdb, module_stream, proc32, pub32, section_header

from civ4dbg import __main__ as cli
from civ4dbg import minidump
from civ4dbg.buildcheck import build_mismatches
from civ4dbg.errors import (
    EXIT_BUILD_MISMATCH,
    EXIT_INPUT,
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    EXIT_UNSUPPORTED,
)
from civ4dbg.msf import Msf
from civ4dbg.pdb import S_GPROC32, OmapUnsupportedError, Pdb, PdbError
from civ4dbg.pe import read_pe_headers

FIX = pathlib.Path(__file__).parent / "fixtures"
PDB, DLL = str(FIX / "small.pdb"), str(FIX / "small.dll")
PE = read_pe_headers(DLL)
BASE = 0x2C50000


def dump(tmp_path, ts=PE.timestamp, size=PE.size_of_image, name=r"S:\game\CvGameCoreDLL.dll", **kw):
    f = tmp_path / "x.dmp"
    f.write_bytes(
        build_minidump(
            [(0x400000, 0x100000, r"S:\game\Civ4BeyondSword.exe"), (BASE, size, name, ts)],
            0xC0000005,
            BASE + 0x1000,
            (0, 0x34),
            BASE + 0x1000,
            [BASE + 0x1071],
            **kw,
        )
    )
    return str(f)


def run(capsys, *argv):
    rc = cli.main(list(argv))
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


# -- build match ----------------------------------------------------------------------


def test_module_record_is_read_from_the_dump():
    info = minidump.parse_minidump(build_minidump([(BASE, 0x5000, "a.dll", 0xDEADBEEF)], 1, 0, None, 0, []))
    assert (info.modules[0].timestamp, info.modules[0].size) == (0xDEADBEEF, 0x5000)


def test_build_mismatches_compares_timestamp_and_size_of_image():
    m = minidump.Module(BASE, PE.size_of_image, "x.dll", PE.timestamp)
    assert build_mismatches(m, PE) == []
    ts_only = build_mismatches(minidump.Module(BASE, PE.size_of_image, "x.dll", PE.timestamp + 1), PE)
    assert len(ts_only) == 1 and ts_only[0].startswith("TimeDateStamp")
    sz_only = build_mismatches(minidump.Module(BASE, PE.size_of_image + 0x1000, "x.dll", PE.timestamp), PE)
    assert len(sz_only) == 1 and sz_only[0].startswith("SizeOfImage")
    both = build_mismatches(minidump.Module(BASE, 1, "x.dll", 2), PE)
    assert len(both) == 2


def test_matching_build_resolves_and_reports_both_checks(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, dump(tmp_path))
    assert rc == EXIT_OK and "alpha" in out
    assert "build match" in err and "PDB matches the DLL" in err


def test_timestamp_mismatch_is_refused_and_prints_no_names(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, dump(tmp_path, ts=PE.timestamp + 1))
    assert rc == EXIT_BUILD_MISMATCH == 3
    assert "error:" in err
    assert "NOT from this DLL's build" in err and "TimeDateStamp" in err
    assert "== fault site" not in out and "alpha" not in out


def test_size_of_image_mismatch_is_refused(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, dump(tmp_path, size=PE.size_of_image + 0x1000))
    assert rc == EXIT_BUILD_MISMATCH and "SizeOfImage" in err and "alpha" not in out


def test_the_override_prints_names_under_a_loud_warning(tmp_path, capsys):
    rc, out, err = run(
        capsys, "dump", "--pdb", PDB, "--dll", DLL, "--allow-build-mismatch", dump(tmp_path, ts=PE.timestamp + 1)
    )
    assert rc == EXIT_OK and "alpha" in out
    assert "BUILD MISMATCH" in err and "!!!!!!!!" in err and "TimeDateStamp" in err


def test_no_dll_means_the_build_is_not_checked_and_says_so(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, dump(tmp_path, ts=1))
    assert rc == EXIT_OK and "build match NOT checked" in err


# -- OMAP -----------------------------------------------------------------------------


def omap_pdb(omap=True):
    data, sb = module_stream(proc32(S_GPROC32, "f", 1, 0x10, 0x10))
    return build_pdb(
        [section_header(".text", 0x1000, 0x1000)],
        pub32("_f", 1, 0x10),
        [("m.obj", data, sb, 0, 0)],
        [(1, 0x10, 0x10, 0)],
        omap=omap,
    )


def test_omap_pdb_opens_but_refuses_to_resolve():
    p = Pdb(Msf(omap_pdb()))
    assert p.has_omap
    with pytest.raises(OmapUnsupportedError, match="OMAP"):
        p.resolve(0x1014)
    assert not Pdb(Msf(omap_pdb(omap=False))).has_omap
    assert Pdb(Msf(omap_pdb(omap=False))).resolve(0x1014).function == "f"


def test_cli_dump_refuses_an_omap_pdb_before_printing_any_name(tmp_path, capsys):
    f = tmp_path / "omap.pdb"
    f.write_bytes(omap_pdb())
    rc, out, err = run(capsys, "dump", "--pdb", str(f), "--allow-build-mismatch", dump(tmp_path))
    assert rc == EXIT_UNSUPPORTED and "OMAP" in err
    assert "== fault site" not in out and "== stack" not in out


def test_omap_error_is_a_pdberror_and_maps_to_the_unsupported_exit_code():
    assert issubclass(OmapUnsupportedError, PdbError)
    assert OmapUnsupportedError.exit_code == EXIT_UNSUPPORTED == 4


def test_cli_refuses_names_for_an_omap_pdb_but_info_still_works(tmp_path, capsys):
    f = tmp_path / "omap.pdb"
    f.write_bytes(omap_pdb())
    rc, out, err = run(capsys, "resolve", "--pdb", str(f), "0x1014")
    assert rc == EXIT_UNSUPPORTED and err.startswith("error:") and "OMAP" in err and out == ""
    rc, out, err = run(capsys, "info", "--pdb", str(f))
    assert rc == EXIT_OK and "OMAP streams present" in out


# -- exit codes -----------------------------------------------------------------------


def test_exit_code_constants_are_distinct_and_documented_values():
    codes = [EXIT_OK, EXIT_INPUT, EXIT_NOT_FOUND, EXIT_BUILD_MISMATCH, EXIT_UNSUPPORTED, EXIT_INTERNAL]
    assert codes == [0, 1, 2, 3, 4, 5]


@pytest.mark.parametrize("name, content", [("empty.pdb", b""), ("junk.pdb", b"not a pdb at all")])
def test_malformed_pdb_files_exit_1_with_one_line(tmp_path, capsys, name, content):
    f = tmp_path / name
    f.write_bytes(content)
    rc, out, err = run(capsys, "resolve", "--pdb", str(f), "0x1000")
    assert rc == 1 and out == "" and err.startswith("error:") and err.count("\n") == 1


def test_zero_byte_minidump_and_dll_exit_1(tmp_path, capsys):
    empty = tmp_path / "e"
    empty.write_bytes(b"")
    rc, out, err = run(capsys, "dump", "--pdb", PDB, str(empty))
    assert rc == 1 and err.startswith("error:") and "Traceback" not in err
    rc, out, err = run(capsys, "info", "--pdb", PDB, "--dll", str(empty))
    assert rc == 1 and "error:" in err and "Traceback" not in err


def test_a_directory_instead_of_a_file_exits_1(tmp_path, capsys):
    rc, out, err = run(capsys, "info", "--pdb", str(tmp_path))
    assert rc == 1 and err.startswith("error:")


def test_unsupported_dump_exits_4(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, dump(tmp_path, arch=9))
    assert rc == EXIT_UNSUPPORTED and "not x86" in err


def test_module_absent_from_the_dump_exits_2(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--module", "Nope.dll", dump(tmp_path))
    assert rc == EXIT_NOT_FOUND and "not found in dump" in err


def test_a_negative_stack_limit_is_a_usage_error(tmp_path, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.main(["dump", "--pdb", PDB, "--stack-limit", "-1", dump(tmp_path)])
    assert exc.value.code == 2


def test_module_option_matches_the_whole_file_name_not_a_suffix(tmp_path, capsys):
    other = dump(tmp_path, name=r"S:\game\OtherCvGameCoreDLL.dll")
    rc, out, err = run(capsys, "dump", "--pdb", PDB, other)
    assert rc == EXIT_NOT_FOUND
    rc, out, err = run(
        capsys, "dump", "--pdb", PDB, "--allow-build-mismatch", "--module", "othercvgamecoredll.dll", other
    )
    assert rc == EXIT_OK and "alpha" in out


def test_stack_limit_option_bounds_the_stack_lines(tmp_path, capsys):
    f = tmp_path / "x.dmp"
    f.write_bytes(
        build_minidump(
            [(BASE, PE.size_of_image, r"S:\game\CvGameCoreDLL.dll", PE.timestamp)],
            0xC0000005,
            BASE + 0x1000,
            (0, 0x34),
            BASE + 0x1000,
            [BASE + 0x1001, BASE + 0x1031, BASE + 0x1051, BASE + 0x1071],
        )
    )
    for limit, expected in ((0, 0), (2, 2), (20, 4)):
        rc, out, err = run(capsys, "dump", "--pdb", PDB, "--stack-limit", str(limit), str(f))
        stack = out.split("== stack")[1].splitlines()[1:]
        assert rc == 0 and len([ln for ln in stack if ln.strip()]) == expected, limit


def test_an_unexpected_exception_type_is_a_one_line_internal_error(monkeypatch, capsys):
    def boom(*a, **k):
        raise IndexError("synthetic")

    monkeypatch.setattr(cli.Pdb, "open", boom)
    rc, out, err = run(capsys, "info", "--pdb", PDB)
    assert rc == EXIT_INTERNAL and err.startswith("error: internal:") and "IndexError" in err
    assert err.count("\n") == 1


def test_a_programming_error_is_not_swallowed(monkeypatch):
    monkeypatch.setattr(cli.Pdb, "open", lambda *a, **k: (_ for _ in ()).throw(AttributeError("bug")))
    with pytest.raises(AttributeError):
        cli.main(["info", "--pdb", PDB])
