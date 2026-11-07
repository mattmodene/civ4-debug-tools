"""PDB-to-DLL matching through the DLL's CodeView (RSDS) record: GUID and age only."""

import io
import pathlib
import struct

import pytest
from synth import build_pe, section_header

from civ4dbg import __main__ as cli
from civ4dbg.buildcheck import pdb_age_note, pdb_mismatches
from civ4dbg.errors import EXIT_BUILD_MISMATCH, EXIT_OK
from civ4dbg.pdb import Pdb
from civ4dbg.pe import CodeViewId, PeError, read_codeview_id, read_codeview_id_from_path, read_pe_headers

FIX = pathlib.Path(__file__).parent / "fixtures"
PDB, DLL = FIX / "small.pdb", FIX / "small.dll"


class Spy(io.BytesIO):
    def __init__(self, b):
        super().__init__(b)
        self.read_total = 0

    def read(self, n=-1):
        d = super().read(n)
        self.read_total += len(d)
        return d


def test_codeview_id_of_the_fixture_equals_the_pdb_identity():
    pe = read_pe_headers(DLL)
    cv = read_codeview_id_from_path(DLL, pe)
    with Pdb.open(PDB) as p:
        assert (cv.guid, cv.age) == p.guid_age()
    assert pe.debug_dir_rva == 0x2000 and pe.debug_dir_size == 56


def test_only_the_debug_directory_and_24_record_bytes_are_read():
    raw = DLL.read_bytes()
    pe = read_pe_headers(DLL)
    spy = Spy(raw)
    cv = read_codeview_id(spy, pe)
    assert cv is not None
    assert spy.read_total == pe.debug_dir_size + 24  # entries + signature/GUID/age; not the path


def test_mismatch_rules():
    g = bytes(range(16))
    cv = CodeViewId(g, 3)
    assert pdb_mismatches((g, 3), cv) == [] and pdb_age_note((g, 3), cv) is None
    assert pdb_mismatches((g, 7), cv) == [] and "info-stream age 7" in pdb_age_note((g, 7), cv)
    assert len(pdb_mismatches((g, 2), cv)) == 1  # PDB older than the image
    assert pdb_mismatches((bytes(16), 3), cv)[0].startswith("GUID")


def test_dbi_age_must_equal_the_dll_age_or_be_zero():
    g = bytes(range(16))
    cv = CodeViewId(g, 1)
    assert pdb_mismatches((g, 2), cv, dbi_age=1) == []  # the real C2C pair: info 2, DBI 1, DLL 1
    assert pdb_mismatches((g, 2), cv, dbi_age=0) == []  # old PDBs have DBI age 0: not checked
    assert pdb_mismatches((g, 2), cv, dbi_age=None) == []
    (problem,) = pdb_mismatches((g, 2), cv, dbi_age=2)
    assert "DBI-header age 2" in problem
    assert "DBI age 1" in pdb_age_note((g, 2), cv, dbi_age=1)


def patched_dll(tmp_path, guid=None, age=None):
    raw = bytearray(DLL.read_bytes())
    cv = read_codeview_id_from_path(DLL, read_pe_headers(DLL))
    at = raw.index(b"RSDS" + cv.guid)
    if guid is not None:
        raw[at + 4 : at + 20] = guid
    if age is not None:
        struct.pack_into("<I", raw, at + 20, age)
    f = tmp_path / "x.dll"
    f.write_bytes(bytes(raw))
    return str(f)


def run(capsys, *argv):
    rc = cli.main(list(argv))
    c = capsys.readouterr()
    return rc, c.out, c.err


def test_matching_pair_is_accepted_and_says_so(capsys):
    rc, out, err = run(capsys, "resolve", "--pdb", str(PDB), "--dll", str(DLL), "0x1000")
    assert rc == EXIT_OK and "alpha" in out and "PDB matches the DLL: GUID and age agree" in err


def test_guid_mismatch_is_refused_without_names(tmp_path, capsys):
    dll = patched_dll(tmp_path, guid=bytes(16))
    rc, out, err = run(capsys, "resolve", "--pdb", str(PDB), "--dll", dll, "0x1000")
    assert rc == EXIT_BUILD_MISMATCH and out == "" and "does not belong to this DLL" in err and "GUID" in err


def test_override_flag_prints_names_with_a_warning(tmp_path, capsys):
    dll = patched_dll(tmp_path, guid=bytes(16))
    rc, out, err = run(capsys, "resolve", "--pdb", str(PDB), "--dll", dll, "--allow-pdb-mismatch", "0x1000")
    assert rc == EXIT_OK and "alpha" in out and "PDB/DLL MISMATCH" in err


def test_a_dll_age_above_the_pdb_age_is_refused_and_a_lower_one_accepted(tmp_path, capsys):
    rc, _, err = run(capsys, "resolve", "--pdb", str(PDB), "--dll", patched_dll(tmp_path, age=9), "0x1000")
    assert rc == EXIT_BUILD_MISMATCH and "older than the DLL" in err
    # DLL age 0: the info-stream age (1) is not older, but the DBI age (1) differs from it
    rc, out, err = run(capsys, "resolve", "--pdb", str(PDB), "--dll", patched_dll(tmp_path, age=0), "0x1000")
    assert rc == EXIT_BUILD_MISMATCH and out == "" and "DBI-header age" in err


def _plain_dll(tmp_path, sections):
    f = tmp_path / "plain.dll"
    f.write_bytes(build_pe(0x400, sections))
    return str(f)


def test_dll_without_a_codeview_record_and_a_different_section_table_is_refused(tmp_path, capsys):
    dll = _plain_dll(tmp_path, [section_header(".text", 0x1000, 0x1000)])
    rc, out, err = run(capsys, "info", "--pdb", str(PDB), "--dll", dll)
    assert rc == EXIT_BUILD_MISMATCH and "no usable CodeView" in err and "differs" in err
    rc, out, err = run(capsys, "info", "--pdb", str(PDB), "--dll", dll, "--allow-pdb-mismatch")
    assert rc == EXIT_OK and "GUID/age NOT checked" in err


def test_dll_without_a_codeview_record_but_identical_sections_only_warns(tmp_path, capsys):
    with Pdb.open(PDB) as p:
        heads = [
            section_header(s.name, s.virtual_size, s.virtual_address, s.raw_size, s.raw_pointer, s.characteristics)
            for s in p.sections
        ]
    rc, out, err = run(capsys, "info", "--pdb", str(PDB), "--dll", _plain_dll(tmp_path, heads))
    assert rc == EXIT_OK and "GUID/age NOT checked" in err


def test_debug_directory_outside_every_section_is_a_pe_error():
    raw = bytearray(build_pe(0x400, [section_header(".text", 0x1000, 0x1000, 0x200, 0x400)], total=0x800))
    opt = 0x80 + 24
    struct.pack_into("<I", raw, opt + 92, 16)
    struct.pack_into("<II", raw, opt + 96 + 48, 0x9000, 28)
    pe = read_pe_headers_from_bytes(bytes(raw))
    assert pe.debug_dir_rva == 0x9000
    with pytest.raises(PeError, match="debug directory"):
        read_codeview_id(io.BytesIO(bytes(raw)), pe)


def read_pe_headers_from_bytes(b):
    from civ4dbg.pe import read_pe_headers_from

    return read_pe_headers_from(io.BytesIO(b))


def _dll_with_record(data_size=56, rva=None, ptr=None, chars=0x40000040, record=b"RSDS" + bytes(range(16)) + bytes(4)):
    """A PE with one data section holding a debug directory (1 entry) and a record."""
    sec_va, sec_raw, raw_size = 0x1000, 0x400, 0x200
    head = bytearray(build_pe(0x400, [section_header(".rdata", 0x200, sec_va, raw_size, sec_raw, chars)], total=0x600))
    opt = 0x80 + 24
    struct.pack_into("<I", head, opt + 92, 16)
    struct.pack_into("<II", head, opt + 96 + 48, sec_va, 28)
    rec_off = 0x400 + 0x40
    entry = struct.pack(
        "<IIHHIIII",
        0,
        0,
        0,
        0,
        2,
        data_size,
        sec_va + 0x40 if rva is None else rva,
        rec_off if ptr is None else ptr,
    )
    head[0x400 : 0x400 + 28] = entry
    head[rec_off : rec_off + len(record)] = record
    return bytes(head)


def _read(raw):
    pe = read_pe_headers_from_bytes(raw)
    return read_codeview_id(io.BytesIO(raw), pe)


def test_well_formed_synthetic_record_is_read():
    assert _read(_dll_with_record()) == CodeViewId(bytes(range(16)), 0)


def test_record_smaller_than_its_header_is_a_pe_error():
    with pytest.raises(PeError, match="smaller than its RSDS header"):
        _read(_dll_with_record(data_size=23))


def test_pointer_past_end_of_file_is_a_pe_error():
    with pytest.raises(PeError, match="CodeView record"):
        _read(_dll_with_record(ptr=0x7FFFFFF0))


def test_pointer_that_disagrees_with_the_rva_is_a_pe_error():
    with pytest.raises(PeError, match="disagrees with its RVA"):
        _read(_dll_with_record(ptr=0x100))  # inside the headers, not where the RVA maps


def test_record_rva_outside_every_section_is_a_pe_error():
    with pytest.raises(PeError, match="does not lie inside any section"):
        _read(_dll_with_record(rva=0x9000))


def test_record_in_an_executable_section_is_refused():
    with pytest.raises(PeError, match="executable section"):
        _read(_dll_with_record(chars=0x60000020))


def test_unrecognised_record_signature_gives_none():
    assert _read(_dll_with_record(record=b"NB10" + bytes(20))) is None


def test_file_ending_inside_the_record_is_a_pe_error():
    raw = _dll_with_record()
    with pytest.raises(PeError, match="file ends inside the CodeView record"):
        _read(raw[: 0x400 + 0x40 + 10])
