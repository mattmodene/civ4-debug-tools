"""Truncated and malformed input: the readers must fail with their own clean
error types (``MsfError`` / ``PdbError`` / ``MinidumpError``), quickly, and never
with a raw ``struct.error`` / ``IndexError`` traceback or a hang.

Every malformed-input path must end in one of the tool's own error types and,
at the command line, in a one-line ``error: ...`` message with a defined exit
code. The tests that pinned the earlier leaks as strict xfails are now plain
tests asserting the clean error.
"""

import faulthandler
import pathlib
import random
import struct

import pytest
from synth import build_minidump, build_msf, build_pdb, module_stream, proc32, pub32, section_header

from civ4dbg import __main__ as cli
from civ4dbg import minidump
from civ4dbg.msf import Msf, MsfError
from civ4dbg.pdb import S_GPROC32, Pdb, PdbError

FIX = pathlib.Path(__file__).parent / "fixtures"
SMALL = (FIX / "small.pdb").read_bytes()
CLEAN_PDB = (MsfError, PdbError)


@pytest.fixture
def deadline():
    """Abort the whole test run (instead of hanging it) if the body takes over 10 seconds.

    Cross-platform and dependency-free: faulthandler's watchdog thread dumps every thread's traceback
    to stderr and terminates the process if the body is still running after 10 s. That ends the whole
    pytest run with a non-zero exit rather than failing one test, which is the right trade for "a hang
    is a bug". Under pytest's default output capture the traceback dump is swallowed; rerun with `-s`
    to see where it was stuck. This uses faulthandler's single global timer, so it would conflict with
    pytest's `faulthandler_timeout` option if that were ever set. (signal.SIGALRM, used before, does
    not exist on Windows.)
    """
    faulthandler.dump_traceback_later(10, exit=True)
    try:
        yield
    finally:
        faulthandler.cancel_dump_traceback_later()


def _super(raw: bytes, **fields) -> bytes:
    """Rewrite named superblock fields of an MSF image."""
    names = ["block_size", "free_block_map", "num_blocks", "dir_bytes", "unknown", "block_map_addr"]
    vals = list(struct.unpack_from("<6I", raw, 32))
    for k, v in fields.items():
        vals[names.index(k)] = v
    out = bytearray(raw)
    struct.pack_into("<6I", out, 32, *vals)
    return bytes(out)


# -- MSF ------------------------------------------------------------------------------------


MSF = build_msf([b"hello" * 300, None, b"x" * 2000, b""], block_size=512)


@pytest.mark.parametrize("length", [0, 1, 31, 32, 55, 56, 57, 511, 512, 513, len(MSF) - 512, len(MSF) - 1])
def test_truncated_msf_is_an_msferror(length, deadline):
    with pytest.raises(MsfError):
        Msf(MSF[:length])


def test_every_truncation_of_a_real_pdb_is_an_msferror(deadline):
    # dense over the header and the tail, sampled in between
    lengths = list(range(0, 300)) + list(range(300, len(SMALL), 4093)) + [len(SMALL) - 1]
    for n in lengths:
        with pytest.raises(MsfError):
            Msf(SMALL[:n])


@pytest.mark.parametrize("pos", range(32))
def test_any_single_flipped_magic_byte_is_rejected(pos):
    raw = bytearray(MSF)
    raw[pos] ^= 0x01
    with pytest.raises(MsfError, match="bad magic"):
        Msf(bytes(raw))


def test_empty_and_garbage_input(deadline):
    for blob in (b"", b"\0" * 4096, b"MZ" + b"\0" * 1000, bytes(range(256)) * 20):
        with pytest.raises(MsfError):
            Msf(blob)


@pytest.mark.parametrize("bs", [0, 1, 100, 511, 513, 3000, 65536, 0xFFFFFFFF])
def test_unsupported_block_sizes(bs, deadline):
    with pytest.raises(MsfError, match="block size"):
        Msf(_super(MSF, block_size=bs))


@pytest.mark.parametrize("n", [0, 1, 0x7FFFFFFF, 0xFFFFFFFF])
def test_wrong_num_blocks(n, deadline):
    with pytest.raises(MsfError):
        Msf(_super(MSF, num_blocks=n))


@pytest.mark.parametrize(
    "fields",
    [
        {"dir_bytes": 0},
        {"dir_bytes": 3},
        {"dir_bytes": 0xFFFFFFFF},
        {"dir_bytes": 0x7FFFFFFF},
        {"block_map_addr": 0},
        {"block_map_addr": 0xFFFFFFFF},
        {"block_map_addr": len(MSF) // 512},  # first block past the end
    ],
)
def test_bad_directory_fields_are_msferrors_not_hangs(fields, deadline):
    with pytest.raises(MsfError):
        Msf(_super(MSF, **fields))


def test_block_map_pointing_outside_the_file(deadline):
    raw = bytearray(MSF)
    m = Msf(MSF)
    struct.pack_into("<I", raw, m.block_map_addr * 512, 0xFFFFFFF0)
    with pytest.raises(MsfError, match="out of range"):
        Msf(bytes(raw))


def test_stream_block_list_pointing_outside_the_file_fails_on_read_not_open(deadline):
    m = Msf(MSF)
    raw = bytearray(MSF)
    dir_block = struct.unpack_from("<I", MSF, m.block_map_addr * 512)[0]
    # directory: nStreams, sizes[4], then stream 0's blocks -> corrupt the first one
    struct.pack_into("<I", raw, dir_block * 512 + 4 + 16, 0x7FFFFFFF)
    broken = Msf(bytes(raw))
    with pytest.raises(MsfError, match="out of range"):
        broken.read_stream(0)
    assert broken.read_stream(2) == b"x" * 2000  # other streams stay readable


def test_stream_count_larger_than_the_directory_can_hold(deadline):
    m = Msf(MSF)
    raw = bytearray(MSF)
    dir_block = struct.unpack_from("<I", MSF, m.block_map_addr * 512)[0]
    struct.pack_into("<I", raw, dir_block * 512, 0xFFFFFFFF)
    with pytest.raises(MsfError):
        Msf(bytes(raw))


def test_directory_with_trailing_unconsumed_bytes_is_rejected(deadline):
    """Shrinking a stream's size leaves block numbers unread at the end of the
    directory: not a struct.error, so only the explicit length check catches it."""
    m = Msf(MSF)
    raw = bytearray(MSF)
    dir_block = struct.unpack_from("<I", MSF, m.block_map_addr * 512)[0]
    struct.pack_into("<I", raw, dir_block * 512 + 4, 5)  # stream 0: 1500 B (3 blocks) -> 5 B (1 block)
    with pytest.raises(MsfError, match="length mismatch"):
        Msf(bytes(raw))


def test_stream_size_declared_huge(deadline):
    m = Msf(MSF)
    raw = bytearray(MSF)
    dir_block = struct.unpack_from("<I", MSF, m.block_map_addr * 512)[0]
    struct.pack_into("<I", raw, dir_block * 512 + 4, 0xFFFFFFFE)  # stream 0, ~4 GiB
    with pytest.raises(MsfError):
        Msf(bytes(raw))


def test_seeded_superblock_and_directory_fuzz_only_raises_msferror(deadline):
    m = Msf(SMALL)
    bs = m.block_size
    dir_block = struct.unpack_from("<I", SMALL, m.block_map_addr * bs)[0]
    rnd = random.Random(20261102)
    for _ in range(1500):
        b = bytearray(SMALL)
        for _ in range(rnd.randint(1, 4)):
            if rnd.random() < 0.5:
                b[rnd.randrange(32, 56)] = rnd.randrange(256)
            else:
                b[dir_block * bs + rnd.randrange(m.dir_bytes)] = rnd.randrange(256)
        try:
            Msf(bytes(b))
        except MsfError:
            pass  # the only acceptable failure


def test_out_of_range_stream_index_is_an_msferror():
    msf = Msf(MSF)
    assert not msf.stream_exists(99) and not msf.stream_exists(-1)
    for index in (99, -1):
        with pytest.raises(MsfError, match="does not exist"):
            msf.read_stream(index)
        with pytest.raises(MsfError, match="does not exist"):
            msf.stream_size(index)


# -- PDB layer -----------------------------------------------------------------------------------

SECTIONS = [section_header(".text", 0x1000, 0x1000)]


def _pdb_bytes(contributions=None) -> bytes:
    data, sb = module_stream(proc32(S_GPROC32, "f", 1, 0x10, 0x10))
    return build_pdb(
        SECTIONS,
        pub32("_f", 1, 0x10),
        [("m.obj", data, sb, 0, 0)],
        contributions if contributions is not None else [(1, 0x10, 0x10, 0)],
    )


def test_pdb_with_a_short_dbi_stream_is_a_pdberror():
    raw = build_msf([b"", b"", b"", b"\0" * 20])
    with pytest.raises(PdbError, match="too short"):
        Pdb(Msf(raw))


def test_pdb_without_section_header_stream_is_a_pdberror():
    # DBI header says 0 module bytes etc., optional debug header slot 5 unset
    import struct as s

    opt = s.pack("<11H", *([0xFFFF] * 11))
    dbi = (
        s.pack(
            "<iIIHHHHHHiiiiiIiiHHI",
            -1,
            19990903,
            1,
            0xFFFF,
            0,
            0xFFFF,
            0,
            0xFFFF,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            len(opt),
            0,
            0,
            0x14C,
            0,
        )
        + opt
    )
    with pytest.raises(PdbError, match="section-header"):
        Pdb(Msf(build_msf([b"", b"", b"", dbi])))


def test_pdb_dbi_substream_sizes_that_do_not_add_up_are_a_pdberror():
    good = Pdb(Msf(_pdb_bytes()))
    dbi = bytearray(good.msf.read_stream(3))
    struct.pack_into("<i", dbi, 24, struct.unpack_from("<i", dbi, 24)[0] + 4)  # ModInfoSize + 4
    streams = [good.msf.read_stream(i) if good.msf.stream_exists(i) else None for i in range(good.msf.num_streams)]
    streams[3] = bytes(dbi)
    with pytest.raises(PdbError):
        Pdb(Msf(build_msf(streams)))


def test_unknown_section_contribution_version_is_a_pdberror():
    good = Pdb(Msf(_pdb_bytes()))
    dbi = bytearray(good.msf.read_stream(3))
    sc_at = 64 + struct.unpack_from("<i", dbi, 24)[0]
    struct.pack_into("<I", dbi, sc_at, 0x12345678)
    streams = [good.msf.read_stream(i) if good.msf.stream_exists(i) else None for i in range(good.msf.num_streams)]
    streams[3] = bytes(dbi)
    with pytest.raises(PdbError, match="contribution"):
        Pdb(Msf(build_msf(streams)))


def test_cli_reports_msf_errors_without_a_traceback(tmp_path, capsys):
    bad = tmp_path / "trunc.pdb"
    bad.write_bytes(SMALL[:5000])
    rc = cli.main(["info", "--pdb", str(bad)])
    err = capsys.readouterr().err
    assert rc == 1 and err.startswith("error:") and "Traceback" not in err


def test_cli_reports_a_missing_file_cleanly(tmp_path, capsys):
    rc = cli.main(["resolve", "--pdb", str(tmp_path / "nope.pdb"), "0x1000"])
    assert rc == 1 and "error:" in capsys.readouterr().err


# Corrupt-but-container-valid content must not leak raw exceptions.


def test_contribution_with_out_of_range_module_index_is_a_clean_error():
    pdb = Pdb(Msf(_pdb_bytes(contributions=[(1, 0x10, 0x10, 77)])))
    with pytest.raises(PdbError):
        pdb.resolve(0x1000 + 0x14)


def test_dbi_byte_flip_fuzz_only_raises_clean_errors(deadline):
    base = Pdb(Msf(SMALL))
    size = base.msf.stream_size(3)
    streams = [base.msf.read_stream(i) if base.msf.stream_exists(i) else None for i in range(base.msf.num_streams)]
    rnd = random.Random(20261102)
    for _ in range(600):
        s = list(streams)
        dbi = bytearray(streams[3])
        for _ in range(rnd.randint(1, 3)):
            dbi[rnd.randrange(size)] = rnd.randrange(256)
        s[3] = bytes(dbi)
        try:
            p = Pdb(Msf(build_msf(s, base.msf.block_size)))
            p.publics()
            for rva in (0x1000, 0x1020, 0x1070, 0x5000):
                p.resolve(rva)
        except CLEAN_PDB:
            pass


@pytest.mark.parametrize("offset", [20, 104], ids=["symrec-stream-index-0xFF", "modinfo-field-0xFF"])
def test_cli_never_tracebacks_on_corrupt_dbi(tmp_path, capsys, offset):
    base = Pdb(Msf(SMALL))
    streams = [base.msf.read_stream(i) if base.msf.stream_exists(i) else None for i in range(base.msf.num_streams)]
    dbi = bytearray(streams[3])
    dbi[offset] = 0xFF  # container stays valid; only DBI content is wrong
    streams[3] = bytes(dbi)
    f = tmp_path / "bad.pdb"
    f.write_bytes(build_msf(streams, base.msf.block_size))
    rc = cli.main(["resolve", "--pdb", str(f), "0x1000"])
    assert rc == 1 and "error:" in capsys.readouterr().err


def test_empty_file_on_disk_is_an_msferror(tmp_path):
    from civ4dbg.msf import OpenedMsf

    f = tmp_path / "empty.pdb"
    f.write_bytes(b"")
    with pytest.raises(MsfError, match="empty file"):
        OpenedMsf(f)


# -- minidump ---------------------------------------------------------------------------------------

DLL = (0x2C50000, 0x9E6000, r"S:\game\CvGameCoreDLL.dll")
EXE = (0x400000, 0x100000, r"S:\game\Civ4BeyondSword.exe")


def mk(stack=(), code=0xC0000005, access=(0, 0x34), addr=0x31454A5, eip=0x31454A5, modules=(EXE, DLL)):
    return build_minidump(list(modules), code, addr, access, eip, list(stack))


def test_good_dump_parses():
    info = minidump.parse_minidump(mk())
    assert info.eip == 0x31454A5 and info.esp == 0x130000


@pytest.mark.parametrize("length", [0, 1, 4, 31])
def test_dump_shorter_than_header_is_a_minidumperror(length):
    with pytest.raises(minidump.MinidumpError):
        minidump.parse_minidump(mk()[:length])


def test_dump_with_zero_streams_names_the_missing_stream():
    hdr = struct.pack("<4sIIII", b"MDMP", 0xA793, 0, 32, 0).ljust(32, b"\0")
    with pytest.raises(minidump.MinidumpError, match="no stream"):
        minidump.parse_minidump(hdr)


@pytest.mark.parametrize("drop", [4, 5, 6])
def test_dump_missing_one_required_stream(drop):
    raw = bytearray(mk())
    for i in range(3):  # retag the directory entry so the stream is absent
        kind = struct.unpack_from("<I", raw, 32 + 12 * i)[0]
        if kind == drop:
            struct.pack_into("<I", raw, 32 + 12 * i, 0x7777)
    with pytest.raises(minidump.MinidumpError, match=f"no stream {drop}"):
        minidump.parse_minidump(bytes(raw))


def test_every_truncation_of_a_dump_is_a_minidumperror():
    raw = mk([DLL[0] + 0x10] * 8)
    for n in range(len(raw)):
        try:
            minidump.parse_minidump(raw[:n])
        except minidump.MinidumpError:
            pass


def test_directory_count_beyond_file_is_a_minidumperror():
    raw = bytearray(mk())
    struct.pack_into("<I", raw, 8, 0x10000)  # NumberOfStreams
    with pytest.raises(minidump.MinidumpError):
        minidump.parse_minidump(bytes(raw))


def test_non_access_violation_has_no_access_info():
    info = minidump.parse_minidump(mk(code=0xC0000094, access=None))  # integer divide by zero
    assert info.exception_code == 0xC0000094
    assert info.access_type is None and info.access_target is None
    assert "access type" not in minidump.format_report(info)


def test_access_violation_with_fewer_than_two_parameters_has_no_access_info():
    info = minidump.parse_minidump(mk(access=None))  # code is 0xC0000005 but NumberParameters == 0
    assert info.exception_code == 0xC0000005 and info.access_type is None


@pytest.mark.parametrize("typ, label", [(0, "read"), (1, "write"), (8, "DEP (execute)"), (5, "?")])
def test_access_types_in_report(typ, label):
    info = minidump.parse_minidump(mk(access=(typ, 0xDEAD)))
    assert f"access type {typ} ({label}) target 0xdead" in minidump.format_report(info)


def test_fault_outside_every_module_is_reported_without_a_module_line():
    info = minidump.parse_minidump(mk(addr=0x7FFE0000))
    assert info.module_at(info.exception_address) is None
    assert "in module" not in minidump.format_report(info)


def test_module_range_is_half_open():
    info = minidump.parse_minidump(mk())
    m = info.find_module("CVGAMECOREDLL.DLL")  # case-insensitive suffix match
    assert m.contains(m.base) and m.contains(m.base + m.size - 1)
    assert not m.contains(m.base - 1) and not m.contains(m.base + m.size)


def test_target_module_missing_from_the_dump():
    info = minidump.parse_minidump(mk(modules=(EXE,)))
    assert info.find_module("CvGameCoreDLL.dll") is None
    assert "modules;" not in minidump.format_report(info)


def test_stack_rva_filter_boundaries_and_limit():
    base, size = DLL[0], DLL[1]
    words = [base - 1, base, base + 1, base + size - 1, base + size, 0, 0xFFFFFFFF]
    info = minidump.parse_minidump(mk(words))
    m = info.find_module("CvGameCoreDLL.dll")
    assert minidump.stack_rvas(info, m) == [0, 1, size - 1]
    assert minidump.stack_rvas(info, m, limit=0) == []
    assert minidump.stack_rvas(info, m, limit=None) == [0, 1, size - 1]
    assert minidump.stack_rvas(info, m, limit=2) == [0, 1]


def test_stack_scan_is_bounded_to_4096_bytes():
    base = DLL[0]
    words = [base + 0x10] * 1024 + [base + 0x20] * 4  # 1024 words = 0x1000 bytes, then 4 more
    info = minidump.parse_minidump(mk(words))
    assert len(info.stack_words) == 1024
    assert base + 0x20 not in info.stack_words


def test_stack_pointer_outside_every_memory_range_gives_empty_stack():
    raw = bytearray(mk([DLL[0] + 0x10]))
    ctx_rva = struct.unpack_from("<I", raw, 32 + 12 * 3 + 4 + 108 * 2 + 8 + 152 + 4)[0]
    struct.pack_into("<I", raw, ctx_rva + 0xC4, 0x900000)  # Esp
    info = minidump.parse_minidump(bytes(raw))
    assert info.esp == 0x900000 and info.stack_words == []


def test_stack_pointer_unaligned_and_near_range_end():
    # esp 2 bytes before the end of a 12-byte stack region: no word fits, no crash
    raw = bytearray(mk([DLL[0] + 1, DLL[0] + 2, DLL[0] + 3]))
    ctx_rva = struct.unpack_from("<I", raw, 32 + 12 * 3 + 4 + 108 * 2 + 8 + 152 + 4)[0]
    struct.pack_into("<I", raw, ctx_rva + 0xC4, 0x130000 + 10)
    info = minidump.parse_minidump(bytes(raw))
    assert info.stack_words == []


def test_dump_cli_clean_error_on_bad_signature(tmp_path, capsys):
    f = tmp_path / "x.dmp"
    f.write_bytes(b"NOPE" + b"\0" * 64)
    rc = cli.main(["dump", "--pdb", str(FIX / "small.pdb"), str(f)])
    assert rc == 1 and "bad minidump signature" in capsys.readouterr().err


def test_dump_cli_module_not_in_dump_exits_2(tmp_path, capsys):
    f = tmp_path / "x.dmp"
    f.write_bytes(mk(modules=(EXE,)))
    rc = cli.main(["dump", "--pdb", str(FIX / "small.pdb"), str(f)])
    out = capsys.readouterr()
    assert rc == 2 and "not found in dump" in out.err


def test_dump_cli_collapses_only_adjacent_duplicate_rvas(tmp_path, capsys):
    base = DLL[0]
    f = tmp_path / "x.dmp"
    # RVAs: 0x10 0x10 0x20 0x10  -> adjacent duplicate collapses, the later repeat stays
    f.write_bytes(mk([base + 0x1010, base + 0x1010, base + 0x1020, base + 0x1010], addr=base + 0x1000))
    rc = cli.main(["dump", "--pdb", str(FIX / "small.pdb"), str(f)])
    out = capsys.readouterr().out
    stack = out.split("== stack")[1].splitlines()[1:]
    assert rc == 0
    assert [ln.split()[0] for ln in stack if ln.strip()] == ["0x1010", "0x1020", "0x1010"]
    assert "alpha" in out.split("== fault site ==")[1].split("==")[0]


def test_dump_cli_fault_not_in_target_module(tmp_path, capsys):
    f = tmp_path / "x.dmp"
    f.write_bytes(mk(addr=0x400100))  # inside the exe, not the dll
    rc = cli.main(["dump", "--pdb", str(FIX / "small.pdb"), str(f)])
    out = capsys.readouterr().out
    assert rc == 0 and "fault is not inside CvGameCoreDLL.dll" in out


# -- additional clean-error coverage (minidump content, unsupported dumps, fuzz) -----------------------


def test_a_dump_for_another_architecture_is_an_unsupported_dump_error():
    raw = build_minidump([DLL], 0xC0000005, 0x31454A5, (0, 0x34), 0x31454A5, [], arch=9)
    with pytest.raises(minidump.UnsupportedDumpError, match="not x86"):
        minidump.parse_minidump(raw)
    info = minidump.parse_minidump(build_minidump([DLL], 0xC0000005, 0x31454A5, (0, 0x34), 0x31454A5, [], arch=0))
    assert info.eip == 0x31454A5


def test_a_thread_context_too_small_for_x86_is_a_minidumperror():
    raw = build_minidump([DLL], 0xC0000005, 0x31454A5, (0, 0x34), 0x31454A5, [], ctx_size=0x40)
    with pytest.raises(minidump.MinidumpError, match="too small"):
        minidump.parse_minidump(raw)


def test_a_memory64_only_dump_gets_a_clear_unsupported_message():
    raw = bytearray(mk())
    for i in range(3):  # the directory entry for stream 5 becomes stream 9 (Memory64List)
        if struct.unpack_from("<I", raw, 32 + 12 * i)[0] == 5:
            struct.pack_into("<I", raw, 32 + 12 * i, 9)
    with pytest.raises(minidump.UnsupportedDumpError, match="Memory64List"):
        minidump.parse_minidump(bytes(raw))


def test_implausible_stream_count_is_a_minidumperror():
    raw = bytearray(mk())
    struct.pack_into("<I", raw, 8, 0xFFFFFFFF)
    with pytest.raises(minidump.MinidumpError, match="implausible stream count"):
        minidump.parse_minidump(bytes(raw))


def test_module_name_with_odd_length_is_a_minidumperror():
    raw = bytearray(mk())
    # first module's name RVA, then its 4-byte length (bytes) -> make it odd
    mod_rva = struct.unpack_from("<I", raw, 32 + 8)[0] if struct.unpack_from("<I", raw, 32)[0] == 4 else None
    assert mod_rva is not None
    name_rva = struct.unpack_from("<I", raw, mod_rva + 4 + 16)[0]
    struct.pack_into("<I", raw, name_rva, 3)
    with pytest.raises(minidump.MinidumpError):
        minidump.parse_minidump(bytes(raw))


def test_find_module_compares_the_whole_file_name_case_insensitively():
    info = minidump.parse_minidump(mk(modules=(EXE, (0x5000000, 0x1000, r"C:\x\OtherCvGameCoreDLL.dll"), DLL)))
    assert info.find_module("cvgamecoredll.DLL").base == DLL[0]
    assert info.find_module(r"D:\elsewhere\CvGameCoreDLL.dll").base == DLL[0]  # directories ignored
    assert info.find_module("GameCoreDLL.dll") is None and info.find_module("DLL") is None
    assert info.find_module("OtherCvGameCoreDLL.dll").base == 0x5000000


def test_seeded_minidump_bit_flip_fuzz_only_raises_minidump_errors():
    base = mk([DLL[0] + 0x10] * 8)
    rnd = random.Random(20261102)
    for _ in range(3000):
        b = bytearray(base)
        for _ in range(rnd.randint(1, 4)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        if rnd.random() < 0.3:
            del b[rnd.randrange(len(b)) :]
        try:
            minidump.parse_minidump(bytes(b))
        except minidump.MinidumpError:
            pass


def _streams_of(raw: bytes):
    base = Pdb(Msf(raw))
    streams = [base.msf.read_stream(i) if base.msf.stream_exists(i) else None for i in range(base.msf.num_streams)]
    return streams, base.msf.block_size


def _exercise(p: Pdb) -> None:
    p.publics()
    for rva in (0x1000, 0x1020, 0x1040, 0x1070, 0x2000, 0x3004, 0x5000):
        from civ4dbg.pdb import AddressKind, format_resolution

        format_resolution(p.resolve(rva))
        format_resolution(p.resolve(rva, AddressKind.RETURN_ADDRESS))


NONEMPTY_STREAMS = [i for i, s in enumerate(_streams_of(SMALL)[0]) if s]


@pytest.mark.parametrize("stream", NONEMPTY_STREAMS)
def test_every_stream_of_a_valid_pdb_fails_cleanly_when_corrupted(stream, deadline):
    streams, block_size = _streams_of(SMALL)
    rnd = random.Random(20261102 + stream)
    for _ in range(120):
        s = list(streams)
        data = bytearray(streams[stream])
        for _ in range(rnd.randint(1, 4)):
            data[rnd.randrange(len(data))] = rnd.choice((0, 0xFF, rnd.randrange(256)))
        s[stream] = bytes(data)
        try:
            _exercise(Pdb(Msf(build_msf(s, block_size))))
        except CLEAN_PDB:
            pass


def test_whole_file_bit_flip_fuzz_only_raises_clean_errors(deadline):
    rnd = random.Random(20261102)
    clean_errors = accepted = 0
    for _ in range(600):
        b = bytearray(SMALL)
        for _ in range(rnd.randint(1, 6)):
            b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
        try:
            _exercise(Pdb(Msf(bytes(b))))
            accepted += 1
        except CLEAN_PDB:
            clean_errors += 1
    assert clean_errors > 0 and accepted > 0  # the fuzz reaches both outcomes


def test_a_module_index_beyond_the_module_list_names_the_index():
    pdb = Pdb(Msf(_pdb_bytes(contributions=[(1, 0x10, 0x10, 77)])))
    with pytest.raises(PdbError, match="module index 77 is out of range"):
        pdb.resolve(0x1000 + 0x14)


def test_direct_module_access_on_a_corrupt_module_stream_is_a_pdberror():
    streams, block_size = _streams_of(SMALL)
    base = Pdb(Msf(SMALL))
    mi = base.modules[0]
    data = bytearray(streams[mi.stream])
    # a proc record whose name has no terminator inside its record length
    pos = 4
    while True:
        reclen, kind = struct.unpack_from("<HH", data, pos)
        if kind in (0x1110, 0x110F):
            break
        pos += 2 + reclen
    struct.pack_into("<H", data, pos, 4 + 35)  # record ends right where the name starts
    streams[mi.stream] = bytes(data)
    p = Pdb(Msf(build_msf(streams, block_size)))
    with pytest.raises(PdbError, match="corrupt or truncated module symbol stream"):
        p.module_procs(0)
