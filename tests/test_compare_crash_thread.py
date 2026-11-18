"""``compare --crash-thread``, the MiscInfo process id, and the refusal-message hints.

Synthetic dumps only (``synth.build_thread_minidump``).
"""

import struct

import pytest
from synth import build_thread_minidump
from test_threads import BASE, DLL, MODS, NT, PDB, ret, run, write

from civ4dbg import __main__ as cli
from civ4dbg import minidump
from civ4dbg.errors import EXIT_INPUT, EXIT_NOT_FOUND, EXIT_OK

FAULT = BASE + 0x1020
IDLE = {"tid": 480, "eip": NT, "stack_words": [0x1, NT]}


def crash(tid, pid=None, code=0xC0000005, fault=FAULT, words=(0x1071, 0x1011), eip=None):
    thread = {"tid": tid, "eip": fault if eip is None else eip, "stack_words": [ret(w) for w in words]}
    return build_thread_minidump(MODS, [thread, IDLE], (tid, code, fault), pid=pid)


def compare(capsys, *dumps, extra=()):
    return run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *extra, *dumps)


def pair(tmp_path, a, b):
    return write(tmp_path, "a.dmp", a), write(tmp_path, "b.dmp", b)


def patch_directory(raw, kind, size=None, rva=None):
    """Rewrite one stream's directory entry (size and/or rva)."""
    raw = bytearray(raw)
    (n, dir_rva) = struct.unpack_from("<II", raw, 8)
    for i in range(n):
        k, sz, off = struct.unpack_from("<III", raw, dir_rva + 12 * i)
        if k == kind:
            struct.pack_into(
                "<III", raw, dir_rva + 12 * i, k, sz if size is None else size, off if rva is None else rva
            )
            return bytes(raw), off
    raise AssertionError("no such stream")


# -- happy path --------------------------------------------------------------------------


def test_crash_thread_matches_exception_threads_with_different_thread_and_process_ids(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340, pid=336), crash(344, pid=348))
    rc, out, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK, err
    assert "exception threads matched by role (not by thread id)" in out
    assert "[0] a.dmp: exception 0xc0000005 at CvGameCoreDLL.dll+0x1020" in out
    assert "thread 340, process 336" in out and "thread 344, process 348" in out
    assert "== exception threads:" in out and "2/2 dumps" in out and "mainfn" in out
    assert "exception code identical (0xc0000005); faulting module+offset identical" in out
    assert "consistent with the same crash" in out and "do not establish an identical root cause" in out


def test_crash_thread_header_omits_process_when_there_is_no_miscinfo(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK and "thread 340" in out and "process" not in out.split("# scan")[0]


def test_crash_thread_counts_agreeing_leading_frames(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344, words=(0x1071, 0x1011)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert " leading scan frame(s) resolve to the same function in all 2 dumps" in out
    a, b = pair(tmp_path, crash(340, words=(0x1071,)), crash(344, words=(0x1011,)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    # the eip frame is the same in both; the next frames differ
    assert "# evidence:" in out and "1 leading scan frame(s)" in out


def test_crash_thread_with_three_dumps(tmp_path, capsys):
    paths = [write(tmp_path, f"{n}.dmp", crash(t, pid=p)) for n, t, p in (("a", 340, 1), ("b", 344, 2), ("c", 348, 3))]
    rc, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    assert rc == EXIT_OK and "3/3 dumps" in out and "in all 3 dumps" in out
    assert "[2] c.dmp: exception" in out and "thread 348, process 3" in out


# -- the evidence line ---------------------------------------------------------------------


def test_differing_exception_code_is_stated_and_not_called_the_same_crash(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344, code=0xC0000094))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK
    assert "exception code DIFFERS (0xc0000005, 0xc0000094)" in out
    assert "do not treat them as the same crash" in out and "consistent with the same crash" not in out


def test_differing_fault_offset_is_stated_and_not_called_the_same_crash(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344, fault=FAULT + 1))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK
    assert "exception code identical" in out and "faulting module+offset DIFFERS" in out
    assert "consistent with the same crash" not in out


def test_fault_outside_every_module_is_reported_by_address(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340, fault=0x500, eip=FAULT), crash(344, fault=0x500, eip=FAULT))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK and "at 0x500 (in no listed module)" in out


# -- refusals ----------------------------------------------------------------------------


def test_crash_thread_refuses_a_dump_without_an_exception_stream_naming_it(tmp_path, capsys):
    snapshot = build_thread_minidump(MODS, [{"tid": 344, "eip": FAULT, "stack_words": [ret(0x1071)]}, IDLE])
    a, b = pair(tmp_path, crash(340), snapshot)
    rc, out, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_NOT_FOUND and "b.dmp has no exception record" in err
    assert "== exception threads" not in out


def test_crash_thread_refuses_a_debugger_break_in(tmp_path, capsys):
    brk = build_thread_minidump(
        MODS, [{"tid": 344, "eip": FAULT, "stack_words": [ret(0x1071)]}], (344, 0x80000003, FAULT)
    )
    a, b = pair(tmp_path, crash(340), brk)
    rc, _, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_NOT_FOUND and "b.dmp records only a breakpoint exception (0x80000003)" in err
    assert "taken for a debugger break-in" in err and "genuine breakpoint or assert crash is refused too" in err
    assert "`civ4dbg dump` shows the record" in err


def test_crash_thread_cannot_be_combined_with_thread(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344))
    with pytest.raises(SystemExit) as e:
        cli.main(["compare", "--pdb", PDB, "--crash-thread", "--thread", "340", a, b])
    assert e.value.code == 2
    assert "not allowed with argument" in capsys.readouterr().err


def test_crash_thread_with_no_module_frames_still_exits_0_and_says_so(tmp_path, capsys):
    idle_crash = crash(340, fault=NT, eip=NT, words=())
    a, b = pair(tmp_path, idle_crash, crash(344, fault=NT, eip=NT, words=()))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK and "# no exception thread has an address in CvGameCoreDLL.dll" in out
    assert "0 functions" in out


# -- malformed streams ---------------------------------------------------------------------


def test_exception_stream_with_a_too_small_context_is_a_clean_error(tmp_path, capsys):
    raw = crash(340, pid=1)
    raw, off = patch_directory(raw, 6)
    raw = bytearray(raw)
    struct.pack_into("<I", raw, off + 8 + 152, 4)  # context size
    a, b = pair(tmp_path, bytes(raw), crash(344))
    rc, _, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_INPUT and err.count("error:") == 1 and "Traceback" not in err


def test_exception_stream_outside_the_file_is_a_clean_error(tmp_path, capsys):
    raw, _ = patch_directory(crash(340), 6, rva=0x7FFFFFF0)
    a, b = pair(tmp_path, raw, crash(344))
    rc, _, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_INPUT and "error:" in err and "Traceback" not in err


def test_miscinfo_stream_outside_the_file_is_ignored_and_the_pid_is_unavailable(tmp_path, capsys):
    raw, _ = patch_directory(crash(340, pid=1), 15, rva=0x7FFFFFF0)
    a, b = pair(tmp_path, raw, crash(344, pid=348))
    rc, out, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK
    assert "[0] a.dmp: exception" in out and "thread 340, process" not in out and "thread 344, process 348" in out
    assert "Traceback" not in err


def test_miscinfo_stream_outside_the_file_uses_the_hedged_wording_in_the_refusal(tmp_path, capsys):
    raw, _ = patch_directory(crash(340, pid=1), 15, rva=0x7FFFFFF0)
    a, b = pair(tmp_path, raw, crash(344, pid=348))
    rc, _, err = compare(capsys, a, b)
    assert rc == EXIT_NOT_FOUND and "typical when" in err and "different processes" not in err


def test_truncated_file_through_the_miscinfo_stream_is_a_clean_error(tmp_path, capsys):
    raw = crash(340, pid=1)
    cut, off = patch_directory(raw, 15)
    a, b = pair(tmp_path, cut[: off + 4], crash(344))
    rc, _, err = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_INPUT and "error:" in err and "Traceback" not in err


def test_miscinfo_too_short_for_a_process_id_is_ignored():
    raw, _ = patch_directory(crash(340, pid=1), 15, size=8)
    assert minidump.parse_minidump(raw).process_id is None


def test_miscinfo_without_the_process_id_flag_is_ignored():
    raw = build_thread_minidump(
        MODS,
        [{"tid": 1, "eip": FAULT, "stack_words": []}],
        (1, 0xC0000005, FAULT),
        misc_info=struct.pack("<IIIIII", 24, 0, 77, 0, 0, 0),
    )
    assert minidump.parse_minidump(raw).process_id is None


def test_miscinfo_process_id_is_parsed():
    assert minidump.parse_minidump(crash(340, pid=4242)).process_id == 4242
    assert minidump.parse_minidump(crash(340)).process_id is None


# -- the refusal message of the default mode -----------------------------------------------


def test_refusal_suggests_crash_thread_when_every_dump_has_an_exception_record(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344))
    rc, _, err = compare(capsys, a, b)
    assert rc == EXIT_NOT_FOUND and "--crash-thread" in err and "every dump has an exception record" in err


def test_refusal_does_not_suggest_crash_thread_without_exception_records(tmp_path, capsys):
    def snap_dump(tid):
        return build_thread_minidump(MODS, [{"tid": tid, "eip": FAULT, "stack_words": [ret(0x1071)]}, IDLE])

    a, b = pair(tmp_path, snap_dump(340), snap_dump(344))
    rc, _, err = compare(capsys, a, b)
    assert rc == EXIT_NOT_FOUND and "--crash-thread" not in err


def test_refusal_says_different_processes_when_the_process_ids_differ(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340, pid=336), crash(344, pid=348))
    _, _, err = compare(capsys, a, b)
    assert "come from different processes" in err and "[0] a.dmp: 336; [1] b.dmp: 348" in err
    assert "typical when" not in err


def test_refusal_keeps_the_hedge_when_process_ids_are_missing_or_equal(tmp_path, capsys):
    for pids in ((None, None), (None, 5), (5, 5)):
        a, b = pair(tmp_path, crash(340, pid=pids[0]), crash(344, pid=pids[1]))
        _, _, err = compare(capsys, a, b)
        assert "typical when" in err and "different processes" not in err, pids


def test_default_mode_output_without_the_flag_is_unchanged_for_common_threads(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340, pid=1), crash(340, pid=2))
    rc, out, _ = compare(capsys, a, b)
    assert rc == EXIT_OK and "== thread 340 " in out and "exception threads matched" not in out


# -- which dumps are the odd ones out (three or more dumps) ---------------------------------------------------


def _many(tmp_path, specs):
    return [write(tmp_path, f"d{i}.dmp", crash(340 + 4 * i, **kw)) for i, kw in enumerate(specs)]


def test_evidence_names_the_dump_whose_exception_code_differs(tmp_path, capsys):
    paths = _many(tmp_path, [{}, {}, {"code": 0xC0000094}])
    rc, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    assert rc == EXIT_OK
    assert "# differs from the most common value (the first dump's on a tie): exception code in [2] d2.dmp" in out
    assert "module+offset in" not in out.split("# differs from")[1]


def test_evidence_names_the_dump_whose_fault_offset_differs(tmp_path, capsys):
    paths = _many(tmp_path, [{"fault": FAULT + 1}, {}, {}])
    _, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    assert "module+offset in [0] d0.dmp" in out and "exception code in" not in out.split("# differs from")[1]


def test_evidence_outlier_choice_on_a_tie_follows_the_first_dump(tmp_path, capsys):
    paths = _many(tmp_path, [{}, {}, {"code": 0xC0000094}, {"code": 0xC0000094}])
    _, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    assert "exception code in [2] d2.dmp, [3] d3.dmp" in out


def test_evidence_outlier_list_is_bounded(tmp_path, capsys):
    paths = _many(tmp_path, [{}] + [{"code": 0xC0000094 + i} for i in range(1, 8)])
    _, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    # every code is distinct, so the first dump's is the reference: 7 differ, 5 are named
    assert ", ... and 2 more" in out and "[6] d6.dmp" not in out.split("# differs from")[1]


def test_two_dumps_get_no_outlier_line_because_the_header_already_shows_both(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344, code=0xC0000094))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "# differs from the most common value" not in out


# -- the faulting module's build is compared across the dumps themselves ---------------------------------------


def _mods(ts=None, size=None, cv=None, name=r"C:\windows\ntdll.dll"):
    ntdll = (0x7BE00000, 0x100000 if size is None else size, name, 0 if ts is None else ts, cv)
    return [MODS[0], MODS[1], ntdll]


def crash_in_ntdll(tid, mods):
    thread = {"tid": tid, "eip": NT, "stack_words": [ret(0x1071), ret(0x1011)]}
    return build_thread_minidump(mods, [thread, IDLE], (tid, 0xC0000005, NT))


def test_a_fault_in_another_module_with_a_different_timestamp_is_not_called_the_same_crash(tmp_path, capsys):
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(ts=1)), crash_in_ntdll(344, _mods(ts=2)))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK
    assert "faulting module+offset identical; faulting module builds DIFFER" in out
    assert "consistent with the same crash" not in out
    assert "module+offset is not comparable" in out and "different build" in out


def test_a_different_module_size_is_a_different_build(tmp_path, capsys):
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(size=0x100000)), crash_in_ntdll(344, _mods(size=0x110000)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module builds DIFFER" in out and "consistent with the same crash" not in out


def test_a_different_codeview_signature_is_a_different_build(tmp_path, capsys):
    cv1, cv2 = (b"\x01" * 16, 1), (b"\x02" * 16, 1)
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(cv=cv1)), crash_in_ntdll(344, _mods(cv=cv2)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module builds DIFFER" in out and "consistent with the same crash" not in out
    a, b = pair(
        tmp_path, crash_in_ntdll(340, _mods(cv=(b"\x01" * 16, 1))), crash_in_ntdll(344, _mods(cv=(b"\x01" * 16, 2)))
    )
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module builds DIFFER" in out


def test_the_same_codeview_signature_and_a_missing_one_do_not_differ(tmp_path, capsys):
    cv = (b"\x01" * 16, 1)
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(cv=cv)), crash_in_ntdll(344, _mods(cv=cv)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module build identical" in out and "consistent with the same crash" in out
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(cv=cv)), crash_in_ntdll(344, _mods()))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module build identical" in out and "consistent with the same crash" in out


def test_module_build_difference_in_the_target_module_is_reported_without_dll(tmp_path, capsys):
    dll1 = [MODS[0], (BASE, MODS[1][1], MODS[1][2], MODS[1][3] + 1), MODS[2]]
    ok = write(tmp_path, "a.dmp", crash(340))
    other = write(
        tmp_path,
        "b.dmp",
        build_thread_minidump(
            dll1,
            [{"tid": 344, "eip": FAULT, "stack_words": [ret(0x1071), ret(0x1011)]}, IDLE],
            (344, 0xC0000005, FAULT),
        ),
    )
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--crash-thread", ok, other)
    assert rc == EXIT_OK and "faulting module builds DIFFER" in out and "consistent with the same crash" not in out


def test_module_build_difference_names_the_odd_dump_with_three_dumps(tmp_path, capsys):
    paths = [
        write(tmp_path, "a.dmp", crash_in_ntdll(340, _mods(ts=1))),
        write(tmp_path, "b.dmp", crash_in_ntdll(344, _mods(ts=1))),
        write(tmp_path, "c.dmp", crash_in_ntdll(348, _mods(ts=9))),
    ]
    _, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    assert "module build in [2] c.dmp" in out


def test_identical_builds_keep_the_same_crash_wording(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340), crash(344))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module build identical" in out and "consistent with the same crash" in out


def test_codeview_record_is_parsed_and_a_broken_one_is_ignored():
    cv = (b"\xab" * 16, 7)
    raw = build_thread_minidump(_mods(cv=cv), [{"tid": 1, "eip": NT, "stack_words": []}], (1, 0xC0000005, NT))
    mods = minidump.parse_minidump(raw).modules
    assert mods[2].cv_id == cv and mods[0].cv_id is None
    # a CvRecord that points past the end of the file is ignored, never an error
    broken = bytearray(raw)
    (n, dir_rva) = struct.unpack_from("<II", broken, 8)
    for i in range(n):
        k, sz, off = struct.unpack_from("<III", broken, dir_rva + 12 * i)
        if k == 4:
            struct.pack_into("<II", broken, off + 4 + 108 * 2 + 76, 24, 0x7FFFFFF0)
    assert minidump.parse_minidump(bytes(broken)).modules[2].cv_id is None


# -- a fault outside every listed module is not comparable as module+offset ------------------------------------


def test_identical_fault_address_outside_every_module_is_not_called_module_plus_offset_identical(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340, fault=0x500, eip=FAULT), crash(344, fault=0x500, eip=FAULT))
    rc, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert rc == EXIT_OK
    assert "faulting module+offset identical" not in out
    assert "faulting module+offset not comparable (the fault address is in no listed module in any dump" in out
    assert "the raw addresses are equal" in out
    assert "consistent with the same crash" not in out and "not comparable as module+offset" in out


def test_different_fault_addresses_outside_every_module_are_not_the_same_crash(tmp_path, capsys):
    a, b = pair(tmp_path, crash(340, fault=0x500, eip=FAULT), crash(344, fault=0x600, eip=FAULT))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module+offset DIFFERS" in out and "do not treat them as the same crash" in out


# -- a missing CodeView id is unknown, not a difference ---------------------------------------------------------


def test_outlier_line_never_names_a_dump_that_differs_only_by_a_missing_codeview_id(tmp_path, capsys):
    cv = (b"\x01" * 16, 1)
    paths = [
        write(tmp_path, "a.dmp", crash_in_ntdll(340, _mods(ts=1, cv=cv))),
        write(tmp_path, "b.dmp", crash_in_ntdll(344, _mods(ts=1))),  # same build, no CodeView record
        write(tmp_path, "c.dmp", crash_in_ntdll(348, _mods(ts=9, cv=cv))),  # a different build
    ]
    _, out, _ = compare(capsys, *paths, extra=("--crash-thread",))
    odd = out.split("# differs from the most common value")[1].splitlines()[0]
    assert "module build in [2] c.dmp" in odd and "b.dmp" not in odd and "a.dmp" not in odd


def test_note_says_the_build_comparison_rests_on_timestamp_and_size_when_no_codeview_id_exists(tmp_path, capsys):
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(ts=1)), crash_in_ntdll(344, _mods(ts=1)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "faulting module build identical" in out
    assert (
        "# the module build comparison rests on timestamp and size only; the CodeView id is unavailable in 2 of 2"
        in out
    )


def test_note_says_how_many_dumps_lack_the_codeview_id_when_only_some_do(tmp_path, capsys):
    cv = (b"\x01" * 16, 1)
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(cv=cv)), crash_in_ntdll(344, _mods()))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "timestamp and size, plus the CodeView id where available; the CodeView id is unavailable in 1 of 2" in out


def test_no_codeview_note_when_every_dump_carries_the_id_or_the_fault_is_outside_every_module(tmp_path, capsys):
    cv = (b"\x01" * 16, 1)
    a, b = pair(tmp_path, crash_in_ntdll(340, _mods(cv=cv)), crash_in_ntdll(344, _mods(cv=cv)))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "the module build comparison rests on" not in out
    a, b = pair(tmp_path, crash(340, fault=0x500, eip=FAULT), crash(344, fault=0x500, eip=FAULT))
    _, out, _ = compare(capsys, a, b, extra=("--crash-thread",))
    assert "the module build comparison rests on" not in out
