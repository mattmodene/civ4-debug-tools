"""ThreadList parsing, hang/snapshot dumps, thread selection and multi-dump comparison.

All dumps here are synthetic (``synth.build_thread_minidump``) and resolve against the
committed ``small.pdb``/``small.dll``; no game file is used.
"""

import pathlib
import struct

import pytest
from synth import build_minidump, build_thread_minidump

from civ4dbg import __main__ as cli
from civ4dbg import minidump
from civ4dbg.compare import rank_recurring
from civ4dbg.errors import EXIT_INPUT, EXIT_NOT_FOUND, EXIT_OK
from civ4dbg.pdb import Pdb
from civ4dbg.pe import read_pe_headers

FIX = pathlib.Path(__file__).parent / "fixtures"
PDB, DLL = str(FIX / "small.pdb"), str(FIX / "small.dll")
PE = read_pe_headers(DLL)
BASE = 0x2C50000
MODS = [
    (0x400000, 0x100000, r"S:\game\Civ4BeyondSword.exe"),
    (BASE, PE.size_of_image, r"S:\game\CvGameCoreDLL.dll", PE.timestamp),
    (0x7BE00000, 0x100000, r"C:\windows\ntdll.dll"),
]
NT = 0x7BE01000
BREAKIN = 0x80000003


def ret(rva):  # a stack word that is a return address at module RVA ``rva``
    return BASE + rva


def hang(main_stack, with_exception=True, extra=()):
    """Main thread 336 in the module; idle thread 480 in ntdll; break-in thread 792."""
    threads = [
        {"tid": 336, "eip": BASE + 0x1020, "stack_words": main_stack, "registers": {"eax": 0xAAAA}},
        {"tid": 480, "eip": NT, "stack_words": [0x1, 0x2, NT]},
        {"tid": 792, "eip": NT + 4, "stack_words": [NT]},
        *extra,
    ]
    return build_thread_minidump(MODS, threads, (792, BREAKIN, NT + 4) if with_exception else None)


def write(tmp_path, name, raw):
    f = tmp_path / name
    f.write_bytes(raw)
    return str(f)


def run(capsys, *argv):
    rc = cli.main(list(argv))
    cap = capsys.readouterr()
    return rc, cap.out, cap.err


# -- parsing ---------------------------------------------------------------------------


def test_thread_list_is_parsed_for_every_thread():
    info = minidump.parse_minidump(hang([ret(0x1071), 7, ret(0x1011)]))
    assert [t.thread_id for t in info.threads] == [336, 480, 792]
    main = info.thread(336)
    assert main.index == 0 and main.eip == BASE + 0x1020 and main.registers["eax"] == 0xAAAA
    assert main.esp == 0x130000
    assert list(main.stack_words) == [ret(0x1071), 7, ret(0x1011)]
    assert main.stack_total_words == 3
    assert minidump.thread_stack_rvas(main, info.find_module("CvGameCoreDLL.dll")) == [0x1071, 0x1011]
    assert list(info.thread(480).stack_words) == [1, 2, NT]
    assert info.thread(12345) is None


def test_stack_scan_is_bounded_by_the_threads_own_range():
    # esp sits 0x10 bytes into the range; the words after it are all there is
    info = minidump.parse_minidump(hang([1, 2, 3, 4]))
    t = info.thread(336)
    assert t.stack_start == 0x130000 - 0x10 and t.stack_size == 0x10 + 16
    assert (len(t.stack_words), t.stack_total_words) == (4, 4)


def test_stack_falls_back_to_the_memory_list_range_holding_esp():
    raw = bytearray(hang([ret(0x1071)]))
    # blank the ThreadList stack descriptor of thread 0 (start 0, size 0): MemoryList still covers esp
    off = _stream(raw, 3) + 4
    struct.pack_into("<QI", raw, off + 24, 0, 0)  # stack StartOfMemoryRange (u64) at +24, DataSize at +32
    info = minidump.parse_minidump(bytes(raw))
    assert list(info.thread(336).stack_words) == [ret(0x1071)]


def test_crash_dump_without_threadlist_has_no_threads_and_is_not_a_snapshot():
    raw = build_minidump(MODS, 0xC0000005, BASE + 0x1000, (0, 0x34), BASE + 0x1000, [ret(0x1071)])
    info = minidump.parse_minidump(raw)
    assert info.threads == [] and info.has_exception and not info.is_snapshot


# -- hang / snapshot detection ---------------------------------------------------------


def test_break_in_exception_is_a_snapshot_not_a_fault():
    info = minidump.parse_minidump(hang([ret(0x1071)]))
    assert info.is_snapshot and info.exception_code == BREAKIN and info.thread_id == 792
    text = minidump.format_report(info)
    assert "hang/snapshot dump" in text and "not a crash" in text
    assert "access type" not in text


def test_wow64_breakpoint_code_is_also_a_break_in():
    raw = build_thread_minidump(MODS, [{"tid": 1, "eip": NT, "stack_words": []}], (1, 0x4000001F, NT))
    assert minidump.parse_minidump(raw).is_snapshot


def test_dump_without_exception_stream_is_a_snapshot():
    info = minidump.parse_minidump(hang([ret(0x1071)], with_exception=False))
    assert not info.has_exception and info.is_snapshot and len(info.threads) == 3
    assert "no exception record" in minidump.format_report(info)


def test_genuine_crash_with_a_threadlist_is_still_a_crash():
    raw = build_thread_minidump(
        MODS, [{"tid": 5, "eip": BASE + 0x1000, "stack_words": [ret(0x1071)]}], (5, 0xC0000005, BASE + 0x1000)
    )
    info = minidump.parse_minidump(raw)
    assert not info.is_snapshot
    assert "hang/snapshot" not in minidump.format_report(info)


# -- CLI: selection --------------------------------------------------------------------


def test_default_for_a_hang_dump_is_the_threads_that_touch_the_module(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([ret(0x1071), ret(0x1011)]))
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, f)
    assert rc == EXIT_OK
    assert "hang/snapshot dump" in out and "fault site" not in out and "== fault is not" not in out
    assert "thread 336" in out and "thread 480" not in out.replace("tids 480", "")
    assert "break-in thread 792 not examined" in out
    assert "eip (exact)" in out and "alpha" in out  # eip 0x1020 resolved exactly
    assert "mainfn" in out and "scanned 2 of 2 words" in out


def test_default_falls_back_to_thread_0_when_nothing_touches_the_module(tmp_path, capsys):
    raw = build_thread_minidump(
        MODS, [{"tid": 9, "eip": NT, "stack_words": [NT]}, {"tid": 10, "eip": NT, "stack_words": []}], (10, BREAKIN, NT)
    )
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, write(tmp_path, "i.dmp", raw))
    assert rc == EXIT_OK and "thread 9 " in out and "no thread has an address" in out


def test_thread_option_selects_one_thread(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([ret(0x1071)]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "480", f)
    assert rc == EXIT_OK and "thread 480" in out and "thread 336" not in out
    assert "0 point into CvGameCoreDLL.dll" in out
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "792", f)
    assert "debugger break-in thread" in out


def test_all_threads_lists_every_thread_idle_ones_briefly(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([ret(0x1071)]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--all-threads", f)
    heads = [ln for ln in out.splitlines() if ln.startswith("== thread")]
    assert rc == EXIT_OK and len(heads) == 3
    assert any("no stack word in CvGameCoreDLL.dll" in h for h in heads)


def test_unknown_thread_exits_2_and_lists_the_tids(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([]))
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "999", f)
    assert rc == EXIT_NOT_FOUND and "thread 999 is not in the dump" in err and "336, 480, 792" in err


def test_thread_and_all_threads_are_mutually_exclusive(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([]))
    with pytest.raises(SystemExit) as e:
        cli.main(["dump", "--pdb", PDB, "--thread", "1", "--all-threads", f])
    assert e.value.code == 2


def test_crash_dump_output_is_unchanged_without_thread_options(tmp_path, capsys):
    raw = build_minidump(MODS, 0xC0000005, BASE + 0x1000, (0, 0x34), BASE + 0x1000, [ret(0x1071)])
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, write(tmp_path, "c.dmp", raw))
    assert rc == EXIT_OK and "== fault site ==" in out and "hang/snapshot" not in out


def test_thread_option_works_on_a_crash_dump_with_a_threadlist(tmp_path, capsys):
    raw = build_thread_minidump(
        MODS, [{"tid": 5, "eip": BASE + 0x1000, "stack_words": [ret(0x1071)]}], (5, 0xC0000005, BASE + 0x1000)
    )
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "5", write(tmp_path, "c.dmp", raw))
    assert rc == EXIT_OK and "thread 5 (0x5)" in out and "alpha" in out and "mainfn" in out


# -- comparison ------------------------------------------------------------------------


def test_rank_recurring_orders_by_dump_count_then_hits():
    pdb = Pdb.open(PDB)
    with pdb:
        per_dump = [
            (None, [0x1071, 0x1071, 0x1011]),  # mainfn x2, alpha
            (0x1020, [0x1071, 0x1031]),  # alpha (eip), mainfn, helper
            (None, [0x1071]),  # mainfn
        ]
        ranked, unresolved = rank_recurring(pdb.resolve, per_dump, min_dumps=2)
        assert [r.names for r in ranked] == [("mainfn",), ("alpha",)]
        mainfn, alpha = ranked
        assert (len(mainfn.dumps), mainfn.hits) == (3, 4)
        assert (len(alpha.dumps), alpha.hits, alpha.eip_dumps) == (2, 2, {1})
        assert unresolved == 0
        everything, _ = rank_recurring(pdb.resolve, per_dump, min_dumps=1)
        assert [r.names for r in everything] == [("mainfn",), ("alpha",), ("helper",)]


def test_rank_recurring_counts_unresolved_words_and_skips_them():
    with Pdb.open(PDB) as pdb:
        ranked, unresolved = rank_recurring(pdb.resolve, [(None, [0x1071, 0x90000]), (None, [0x1071])])
        assert [r.names for r in ranked] == [("mainfn",)] and unresolved == 1


def test_compare_cli_ranks_recurring_functions(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", hang([ret(0x1071), ret(0x1011)]))
    b = write(tmp_path, "b.dmp", hang([ret(0x1071), ret(0x1031)]))
    c = write(tmp_path, "c.dmp", hang([ret(0x1071)]))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b, c)
    assert rc == EXIT_OK
    assert "scan candidates" in out and "NOT an unwind" in out
    lines = [ln for ln in out.splitlines() if "dumps  hits" in ln]
    # both are in 3/3 dumps; alpha has more hits (eip 0x1020 in each dump + 0x1011 in a): 4 vs 3
    assert "3/3 dumps" in lines[0] and "hits 4" in lines[0] and "alpha" in lines[0] and "eip in 3" in lines[0]
    assert "3/3 dumps" in lines[1] and "hits 3" in lines[1] and "mainfn" in lines[1]
    assert not any("helper" in ln for ln in lines)  # seen in 1 dump only
    assert "== thread 336" in out and "== thread 480" not in out


def test_compare_single_thread_and_min_dumps(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", hang([ret(0x1071)]))
    b = write(tmp_path, "b.dmp", hang([ret(0x1031)]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--thread", "336", "--min-dumps", "1", a, b)
    assert rc == EXIT_OK and "helper" in out and "mainfn" in out
    assert "build match NOT checked" not in out


def test_compare_unknown_thread_and_too_few_dumps(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", hang([]))
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--thread", "5", a, a)
    assert rc == EXIT_NOT_FOUND and "thread 5" in err
    with pytest.raises(SystemExit) as e:
        cli.main(["compare", "--pdb", PDB, a])
    assert e.value.code == 2


def test_compare_refuses_a_dump_of_another_build(tmp_path, capsys):
    mods = [MODS[0], (BASE, PE.size_of_image, r"S:\game\CvGameCoreDLL.dll", PE.timestamp + 1), MODS[2]]
    bad = write(tmp_path, "bad.dmp", build_thread_minidump(mods, [{"tid": 1, "eip": NT, "stack_words": []}]))
    good = write(tmp_path, "good.dmp", build_thread_minidump(MODS, [{"tid": 1, "eip": NT, "stack_words": []}]))
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, good, bad)
    assert rc == 3 and "NOT from this DLL's build" in err


# -- malformed ThreadList --------------------------------------------------------------


def _stream(raw, kind):
    n, dir_rva = struct.unpack_from("<II", raw, 8)
    for i in range(n):
        k, _size, off = struct.unpack_from("<III", raw, dir_rva + 12 * i)
        if k == kind:
            return off
    raise AssertionError(kind)


def test_fallback_skips_a_range_that_overlaps_a_listed_module():
    mods = MODS + [(0x120000, 0x30000, r"S:\game\Overlap.dll")]  # covers 0x12fff0..
    raw = bytearray(build_thread_minidump(mods, [{"tid": 336, "eip": NT, "stack_words": [ret(0x1071)]}], None))
    struct.pack_into("<QI", raw, _stream(raw, 3) + 4 + 24, 0, 0)
    info = minidump.parse_minidump(bytes(raw))
    assert len(info.thread(336).stack_words) == 0 and info.thread(336).stack_total_words == 0


def test_entries_aliasing_one_stack_hit_the_total_cap_cleanly():
    # many 48-byte entries all pointing at one big stack range: a few KB of file, GBs of words
    base = bytearray(build_thread_minidump(MODS, [{"tid": 1, "eip": NT, "stack_words": [0] * 0x40000}], None))
    off = _stream(base, 3)
    entry = bytes(base[off + 4 : off + 4 + 48])
    n = 100
    new_list = struct.pack("<I", n) + entry * n
    # put the enlarged list at the end of the file and repoint stream 3 at it
    new_off = len(base)
    base += new_list
    ndir, dir_rva = struct.unpack_from("<II", base, 8)
    for i in range(ndir):
        k, _size, _o = struct.unpack_from("<III", base, dir_rva + 12 * i)
        if k == 3:
            struct.pack_into("<III", base, dir_rva + 12 * i, 3, len(new_list), new_off)
    # 100 x 1 MiB (0x40000 words) = 100 MiB > the 64 MiB cap
    with pytest.raises(minidump.MinidumpError, match="add up"):
        minidump.parse_minidump(bytes(base))


def test_every_truncation_of_a_threaded_dump_is_a_clean_error():
    raw = hang([ret(0x1071)] * 4)
    for n in range(0, len(raw), 7):
        try:
            minidump.parse_minidump(raw[:n])
        except minidump.MinidumpError:
            pass


def test_absurd_thread_count_is_rejected():
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3), 0xFFFFFFF0)
    with pytest.raises(minidump.MinidumpError, match="ThreadList"):
        minidump.parse_minidump(bytes(raw))


def test_thread_count_beyond_the_file_is_rejected():
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3), 5000)
    with pytest.raises(minidump.MinidumpError, match="ThreadList"):
        minidump.parse_minidump(bytes(raw))


@pytest.mark.parametrize("field_off,label", [(44, "context"), (36, "stack")])
def test_bad_rva_in_a_thread_entry_is_a_clean_error(field_off, label):
    raw = bytearray(hang([ret(0x1071)], with_exception=False))
    entry = _stream(raw, 3) + 4
    struct.pack_into("<I", raw, entry + field_off, 0xFFFFFF00)
    with pytest.raises(minidump.MinidumpError, match=label):
        minidump.parse_minidump(bytes(raw))


def test_too_small_thread_context_is_a_clean_error():
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3) + 4 + 40, 0x20)
    with pytest.raises(minidump.MinidumpError, match="CONTEXT"):
        minidump.parse_minidump(bytes(raw))


def test_malformed_threadlist_exits_1_at_the_command_line(tmp_path, capsys):
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3), 5000)
    rc, _, err = run(capsys, "dump", "--pdb", PDB, write(tmp_path, "m.dmp", bytes(raw)))
    assert rc == EXIT_INPUT and err.startswith("error:")


# -- degraded and ambiguous cases ---------------------------------------------------------


def test_crash_dump_with_a_malformed_threadlist_degrades_to_the_exception_thread(tmp_path, capsys):
    raw = bytearray(
        build_thread_minidump(
            MODS, [{"tid": 5, "eip": BASE + 0x1000, "stack_words": [ret(0x1071)]}], (5, 0xC0000005, BASE + 0x1000)
        )
    )
    struct.pack_into("<I", raw, _stream(raw, 3), 5000)
    info = minidump.parse_minidump(bytes(raw))
    assert info.threads == [] and info.thread_list_error and not info.is_snapshot
    assert info.exception_code == 0xC0000005
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, write(tmp_path, "c.dmp", bytes(raw)))
    assert rc == EXIT_OK and "WARNING" in err and "ThreadList unusable" in err
    assert "== fault site ==" in out


def test_breakpoint_code_snapshot_still_reports_code_and_address_and_how_to_see_the_thread(tmp_path, capsys):
    # an int 3 / assert crash in the game has the same code as a debugger break-in
    raw = build_thread_minidump(
        MODS,
        [{"tid": 5, "eip": BASE + 0x1000, "stack_words": [ret(0x1071)]}, {"tid": 6, "eip": NT, "stack_words": []}],
        (5, BREAKIN, BASE + 0x1000),
    )
    info = minidump.parse_minidump(raw)
    text = minidump.format_report(info)
    assert "0x80000003" in text and f"{BASE + 0x1000:#x}" in text
    assert "real breakpoint crash" in text and "--thread 5" in text
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "5", write(tmp_path, "b.dmp", raw))
    assert rc == EXIT_OK and "alpha" in out and "mainfn" in out


def test_thread_fields_that_are_not_needed_are_not_kept():
    t = minidump.parse_minidump(hang([])).threads[0]
    assert not hasattr(t, "teb") and not hasattr(t, "suspend_count")
