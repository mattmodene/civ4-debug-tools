"""Edge cases and CLI-level behaviour of the thread / hang-dump / compare work.

Complements test_threads.py. Synthetic dumps only (``synth.build_thread_minidump``).
"""

import struct

import pytest
from synth import build_thread_minidump
from test_threads import BASE, BREAKIN, DLL, MODS, NT, PDB, _stream, hang, ret, run, write

from civ4dbg import __main__ as cli
from civ4dbg import minidump
from civ4dbg.errors import EXIT_INPUT, EXIT_NOT_FOUND, EXIT_OK


def snap(threads, exception=None):
    return build_thread_minidump(MODS, threads, exception)


# -- zero threads / empty stacks / per-thread cap ------------------------------------------


def test_zero_threads_without_exception_parses_as_an_empty_snapshot():
    info = minidump.parse_minidump(snap([]))
    assert info.threads == [] and info.is_snapshot and not info.has_exception


def test_zero_threads_dump_command_reports_it_and_exits_0(tmp_path, capsys):
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, write(tmp_path, "z.dmp", snap([])))
    assert rc == EXIT_OK and "no ThreadList" in out


def test_zero_threads_all_threads_and_unknown_thread(tmp_path, capsys):
    f = write(tmp_path, "z.dmp", snap([]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--all-threads", f)
    assert rc == EXIT_OK and "== thread" not in out
    rc, _, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "1", f)
    assert rc == EXIT_NOT_FOUND and "no ThreadList" in err


def test_thread_with_an_empty_stack_is_reported_not_a_crash(tmp_path, capsys):
    f = write(tmp_path, "e.dmp", snap([{"tid": 7, "eip": BASE + 0x1020, "stack_words": []}]))
    info = minidump.parse_minidump(open(f, "rb").read())
    t = info.thread(7)
    assert len(t.stack_words) == 0 and t.stack_total_words == 0
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "7", f)
    assert rc == EXIT_OK and "alpha" in out and "scanned 0 of 0 words" in out


def test_empty_stack_thread_with_eip_outside_module_is_idle_in_all_threads(tmp_path, capsys):
    f = write(tmp_path, "e.dmp", snap([{"tid": 7, "eip": NT, "stack_words": []}]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--all-threads", f)
    assert rc == EXIT_OK and "no stack word in CvGameCoreDLL.dll" in out


def test_stack_range_larger_than_the_per_thread_cap_is_truncated_from_esp():
    cap_words = 0x400000 // 4
    words = [ret(0x1071)] + [0] * (cap_words + 99)  # hit at esp; filler beyond the cap
    words[-1] = ret(0x1011)  # beyond the cap: must not be scanned
    t = minidump.parse_minidump(snap([{"tid": 1, "eip": NT, "stack_words": words}])).thread(1)
    assert len(t.stack_words) == cap_words
    assert t.stack_total_words == len(words)
    assert t.stack_words[0] == ret(0x1071) and ret(0x1011) not in t.stack_words


def test_truncated_scan_is_reported_at_the_command_line(tmp_path, capsys):
    cap_words = 0x400000 // 4
    words = [ret(0x1071)] + [0] * (cap_words + 9)
    f = write(tmp_path, "big.dmp", snap([{"tid": 1, "eip": NT, "stack_words": words}]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "1", f)
    assert rc == EXIT_OK and f"scanned {cap_words} of {cap_words + 10} words" in out


# -- selection, repeated --thread, headers -------------------------------------------------


def test_thread_option_is_repeatable(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([ret(0x1071)]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "336", "--thread", "480", f)
    heads = [ln for ln in out.splitlines() if ln.startswith("== thread")]
    assert rc == EXIT_OK and len(heads) == 2


def test_one_unknown_tid_among_known_ones_still_exits_2(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([]))
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, "--thread", "336", "--thread", "1", f)
    assert rc == EXIT_NOT_FOUND and "thread 1 is not in the dump" in err


def test_snapshot_without_exception_stream_cli_header(tmp_path, capsys):
    f = write(tmp_path, "n.dmp", hang([ret(0x1071)], with_exception=False))
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, f)
    assert rc == EXIT_OK and "hang/snapshot dump" in out and "no exception record" in out
    assert "thread 336" in out and "break-in thread" not in out and "WARNING" not in err


def test_snapshot_header_names_the_break_in_thread_and_code(tmp_path, capsys):
    f = write(tmp_path, "h.dmp", hang([ret(0x1071)]))
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, f)
    assert "0x80000003" in out and "thread 792" in out


def test_breakpoint_snapshot_default_selection_excludes_the_reporting_thread(tmp_path, capsys):
    # documented behaviour: with code 0x80000003 the exception thread is treated as break-in
    raw = snap(
        [
            {"tid": 5, "eip": BASE + 0x1000, "stack_words": [ret(0x1071)]},
            {"tid": 6, "eip": BASE + 0x1020, "stack_words": []},
        ],
        (5, BREAKIN, BASE + 0x1000),
    )
    rc, out, _ = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, write(tmp_path, "b.dmp", raw))
    heads = [ln for ln in out.splitlines() if ln.startswith("== thread")]
    assert rc == EXIT_OK and len(heads) == 1 and "thread 6" in heads[0]
    assert "break-in thread 5 not examined" in out


def test_snapshot_with_malformed_threadlist_exits_1_with_message(tmp_path, capsys):
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3), 5000)
    rc, out, err = run(capsys, "dump", "--pdb", PDB, write(tmp_path, "m.dmp", bytes(raw)))
    assert rc == EXIT_INPUT and "ThreadList" in err and out == ""


def test_malformed_threadlist_zero_context_size_is_an_error_not_a_degrade_on_snapshot():
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3) + 4 + 40, 0)
    with pytest.raises(minidump.MinidumpError):
        minidump.parse_minidump(bytes(raw))


# -- compare -------------------------------------------------------------------------------


def _one(tid, words, eip=NT):
    return snap([{"tid": tid, "eip": eip, "stack_words": words}])


def test_compare_with_disjoint_thread_sets_exits_2(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _one(1, [ret(0x1071)]))
    b = write(tmp_path, "b.dmp", _one(2, [ret(0x1071)]))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_NOT_FOUND and "no thread id is present in every dump" in err


def test_compare_with_partially_overlapping_thread_sets_uses_common_tids(tmp_path, capsys):
    a = write(
        tmp_path,
        "a.dmp",
        snap(
            [{"tid": 1, "eip": NT, "stack_words": [ret(0x1071)]}, {"tid": 2, "eip": NT, "stack_words": [ret(0x1071)]}]
        ),
    )
    b = write(
        tmp_path,
        "b.dmp",
        snap(
            [{"tid": 2, "eip": NT, "stack_words": [ret(0x1071)]}, {"tid": 3, "eip": NT, "stack_words": [ret(0x1071)]}]
        ),
    )
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_OK and "== thread 2 " in out
    assert "== thread 1 " not in out and "== thread 3 " not in out


def test_compare_thread_missing_from_one_dump_names_that_dump(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _one(1, []))
    b = write(tmp_path, "b.dmp", _one(2, []))
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--thread", "1", a, b)
    assert rc == EXIT_NOT_FOUND and "thread 1 is not in dump" in err and "b.dmp" in err


def test_compare_min_dumps_filters_and_is_clamped_to_dump_count(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _one(1, [ret(0x1071), ret(0x1011)]))
    b = write(tmp_path, "b.dmp", _one(1, [ret(0x1071)]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--min-dumps", "2", a, b)
    assert rc == EXIT_OK and "mainfn" in out and "alpha" not in out
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--min-dumps", "9", a, b)
    assert rc == EXIT_OK and "at least 2 of 2 dumps" in out and "mainfn" in out
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--min-dumps", "1", a, b)
    assert "alpha" in out and "mainfn" in out


def test_compare_top_truncates_and_says_how_many_more(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _one(1, [ret(0x1071), ret(0x1011), ret(0x1031)]))
    b = write(tmp_path, "b.dmp", _one(1, [ret(0x1071), ret(0x1011), ret(0x1031)]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--top", "1", a, b)
    rows = [ln for ln in out.splitlines() if "dumps  hits" in ln]
    assert rc == EXIT_OK and len(rows) == 1
    assert "... 2 more (see --top)" in out
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--top", "3", a, b)
    assert len([ln for ln in out.splitlines() if "dumps  hits" in ln]) == 3 and "more (see" not in out


def test_compare_top_zero_or_negative_is_a_usage_error(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _one(1, []))
    for bad in ("0", "-1"):
        with pytest.raises(SystemExit) as e:
            cli.main(["compare", "--pdb", PDB, "--top", bad, a, a])
        assert e.value.code == 2


def test_compare_reports_idle_threads_in_one_line(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", hang([ret(0x1071)]))
    b = write(tmp_path, "b.dmp", hang([ret(0x1071)]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_OK and "2 thread(s) had no address in CvGameCoreDLL.dll in any dump" in out


def _separate_runs_crash(crash_tid, eip=BASE + 0x1020):
    """A crash dump of one run: the crashing thread plus two idle threads.

    Thread ids are per process instance, so two runs of the same crash give the
    crashing thread different ids while the idle threads can keep the same ones.
    """
    threads = [
        {"tid": crash_tid, "eip": eip, "stack_words": [ret(0x1071), ret(0x1011)]},
        {"tid": 480, "eip": NT, "stack_words": [0x1, 0x2, NT]},
        {"tid": 484, "eip": NT + 4, "stack_words": [NT]},
    ]
    return snap(threads, (crash_tid, 0xC0000005, eip))


def test_compare_of_crash_dumps_whose_module_threads_share_no_id_does_not_report_success(tmp_path, capsys):
    # Same crash, two runs: the thread in the module is 340 in one and 344 in the other. Thread ids 480
    # and 484 are common to both dumps, so the "no thread id common to all" exit (2) does not fire, but
    # every common thread is idle: no thread carrying module addresses could be matched, so nothing was
    # compared. The command must not exit 0 as if it had produced a ranking.
    a = write(tmp_path, "a.dmp", _separate_runs_crash(340))
    b = write(tmp_path, "b.dmp", _separate_runs_crash(344))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc != EXIT_OK, f"compare exited 0 having compared nothing; stdout was:\n{out}"
    assert err.strip(), "a failed comparison must say why on stderr"


def test_compare_of_hang_dumps_whose_module_thread_id_is_not_in_every_dump_does_not_report_success(tmp_path, capsys):
    # The same rule for snapshot dumps: the game thread is 336 in the first dump and 340 in the second,
    # the idle thread 480 is in both. Nothing carrying module addresses can be matched.
    a = write(tmp_path, "a.dmp", hang([ret(0x1071)], with_exception=False))
    other = [
        {"tid": 340, "eip": BASE + 0x1020, "stack_words": [ret(0x1071)]},
        {"tid": 480, "eip": NT, "stack_words": [0x1, 0x2, NT]},
    ]
    b = write(tmp_path, "b.dmp", snap(other))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc != EXIT_OK, f"compare exited 0 having compared nothing; stdout was:\n{out}"
    assert err.strip(), "a failed comparison must say why on stderr"


def test_compare_of_crash_dumps_with_the_same_module_thread_id_still_ranks(tmp_path, capsys):
    # Guard against over-correcting: when the module thread's id IS common, the ranking is produced.
    a = write(tmp_path, "a.dmp", _separate_runs_crash(340))
    b = write(tmp_path, "b.dmp", _separate_runs_crash(340))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_OK and "== thread 340 " in out and "mainfn" in out


def test_compare_refusal_is_exactly_exit_2_and_names_the_unmatched_threads_per_dump(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _separate_runs_crash(340))
    b = write(tmp_path, "b.dmp", _separate_runs_crash(344))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_NOT_FOUND == 2
    assert ("error: no thread carrying addresses in CvGameCoreDLL.dll is common to all the dumps") in err
    assert "[0] a.dmp: 340; [1] b.dmp: 344" in err
    assert "not present in every dump" in err and "typical when" in err and "separate runs" in err
    assert "civ4dbg dump" in err
    # Nothing on stdout may suggest a result: no ranking, no thread header, no idle-count line.
    assert "== thread" not in out and "thread(s) had no address" not in out


def test_compare_refusal_lists_only_module_threads_not_idle_ones(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _separate_runs_crash(340))
    b = write(tmp_path, "b.dmp", _separate_runs_crash(344))
    _, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert "480" not in err and "484" not in err


def _two_module_threads(common_tid, extra_tid):
    threads = [
        {"tid": common_tid, "eip": BASE + 0x1020, "stack_words": [ret(0x1071), ret(0x1011)]},
        {"tid": extra_tid, "eip": BASE + 0x1020, "stack_words": [ret(0x1071)]},
        {"tid": 480, "eip": NT, "stack_words": [0x1, NT]},
    ]
    return snap(threads, (common_tid, 0xC0000005, BASE + 0x1020))


def test_compare_with_one_common_module_thread_ranks_it_and_notes_the_left_out_ones(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _two_module_threads(340, 350))
    b = write(tmp_path, "b.dmp", _two_module_threads(340, 354))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_OK and "== thread 340 " in out and "mainfn" in out
    assert (
        "# thread(s) with addresses in CvGameCoreDLL.dll that are not in every dump were left out: "
        "[0] a.dmp: 350; [1] b.dmp: 354"
    ) in out
    assert "== thread 350" not in out and "== thread 354" not in out


def test_compare_with_every_module_thread_common_prints_no_left_out_note(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", _separate_runs_crash(340))
    b = write(tmp_path, "b.dmp", _separate_runs_crash(340))
    _, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert "were left out" not in out


def test_compare_with_no_module_thread_in_any_dump_keeps_exit_0_and_the_idle_line(tmp_path, capsys):
    idle = [{"tid": 480, "eip": NT, "stack_words": [0x1, NT]}]
    a = write(tmp_path, "a.dmp", snap(idle))
    b = write(tmp_path, "b.dmp", snap(idle))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_OK and "# none of the 2 dumps has a thread with an address in CvGameCoreDLL.dll" in out
    assert "thread(s) had no address" not in out


def _mod_thread(tid, eip=BASE + 0x1020, words=(0x1071,)):
    return {"tid": tid, "eip": eip, "stack_words": [ret(w) for w in words]}


def test_compare_three_dumps_thread_in_two_of_three_is_refused_and_named_in_each_dump_that_has_it(tmp_path, capsys):
    idle = {"tid": 480, "eip": NT, "stack_words": [NT]}
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340), idle]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(344), idle]))
    c = write(tmp_path, "c.dmp", snap([_mod_thread(340), idle]))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b, c)
    assert rc == EXIT_NOT_FOUND
    assert "[0] a.dmp: 340; [1] b.dmp: 344; [2] c.dmp: 340" in err
    assert "not present in every dump" in err and "no counterpart" not in err
    assert "== thread" not in out


def test_compare_caps_a_long_unmatched_id_list_and_states_the_remainder(tmp_path, capsys):
    idle = {"tid": 480, "eip": NT, "stack_words": [NT]}
    a = write(tmp_path, "a.dmp", snap([_mod_thread(1000 + i) for i in range(25)] + [idle]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(344), idle]))
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_NOT_FOUND
    assert "1009, ... and 15 more" in err and "1010" not in err and "[1] b.dmp: 344" in err


def test_compare_note_caps_a_long_left_out_list_too(tmp_path, capsys):
    extra = [_mod_thread(1000 + i) for i in range(12)]
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340)] + extra))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(340)]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_OK and "[0] a.dmp: 1000," in out and "1009, ... and 2 more" in out


def test_compare_thread_option_naming_a_module_thread_ignores_unmatched_ones(tmp_path, capsys):
    # --thread is exempt from the refusal and the left-out note: the named id is compared as given.
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340), _mod_thread(350)]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(340), _mod_thread(354)]))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--thread", "340", a, b)
    assert rc == EXIT_OK and "== thread 340 " in out
    assert "were left out" not in out and "not present in every dump" not in err


def test_compare_thread_option_naming_a_thread_idle_in_every_dump_is_refused(tmp_path, capsys):
    idle = {"tid": 480, "eip": NT, "stack_words": [NT]}
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340), idle]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(344), idle]))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--thread", "480", a, b)
    assert rc == EXIT_NOT_FOUND == 2
    assert "thread 480 has no address in CvGameCoreDLL.dll in any of the 2 dumps" in err
    assert "civ4dbg dump" in err
    assert "== thread" not in out and "thread(s) had no address" not in out


def test_compare_thread_option_with_addresses_in_only_some_dumps_still_ranks(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340)]))
    b = write(tmp_path, "b.dmp", snap([{"tid": 340, "eip": NT, "stack_words": [NT]}]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--thread", "340", "--min-dumps", "1", a, b)
    assert rc == EXIT_OK and "== thread 340 " in out


def test_compare_thread_option_absent_from_a_dump_is_still_exit_2(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340)]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(344)]))
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--thread", "340", a, b)
    assert rc == EXIT_NOT_FOUND and "thread 340 is not in dump" in err


def test_compare_detects_a_module_thread_through_stack_words_alone(tmp_path, capsys):
    # eip outside the module: only the stack words carry module addresses.
    idle = {"tid": 480, "eip": NT, "stack_words": [NT]}
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340, eip=NT), idle]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(344, eip=NT), idle]))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert rc == EXIT_NOT_FOUND and "[0] a.dmp: 340; [1] b.dmp: 344" in err


def test_compare_common_thread_with_an_empty_ranking_still_counts_as_compared(tmp_path, capsys):
    # Same module thread id, but --min-dumps above what recurs is clamped to the dump count; use disjoint
    # functions so nothing recurs in both dumps: the thread was compared, so no refusal.
    a = write(tmp_path, "a.dmp", snap([_mod_thread(340, eip=NT, words=(0x1071,)), _mod_thread(350)]))
    b = write(tmp_path, "b.dmp", snap([_mod_thread(340, eip=NT, words=(0x1011,)), _mod_thread(354)]))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--min-dumps", "2", a, b)
    assert rc == EXIT_OK and "== thread 340 (0x154): 0 functions" in out and "were left out" in out


def test_compare_lists_dump_kinds_and_thread_counts(tmp_path, capsys):
    a = write(tmp_path, "a.dmp", hang([ret(0x1071)]))
    b = write(tmp_path, "b.dmp", hang([ret(0x1071)], with_exception=False))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, a, b)
    assert "[0] a.dmp (hang/snapshot, 3 threads)" in out and "[1] b.dmp (hang/snapshot, 3 threads)" in out


def test_compare_with_a_malformed_snapshot_threadlist_exits_1(tmp_path, capsys):
    good = write(tmp_path, "g.dmp", hang([], with_exception=False))
    raw = bytearray(hang([], with_exception=False))
    struct.pack_into("<I", raw, _stream(raw, 3), 5000)
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, good, write(tmp_path, "m.dmp", bytes(raw)))
    assert rc == EXIT_INPUT and err.startswith("error:")


def test_compare_with_a_crash_dump_whose_threadlist_is_malformed_warns_on_stderr(tmp_path, capsys):
    raw = bytearray(
        build_thread_minidump(
            MODS, [{"tid": 5, "eip": BASE + 0x1000, "stack_words": []}], (5, 0xC0000005, BASE + 0x1000)
        )
    )
    struct.pack_into("<I", raw, _stream(raw, 3), 5000)
    bad = write(tmp_path, "c.dmp", bytes(raw))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, bad, bad)
    # no thread list in either dump: nothing to compare, but the warning must have been given
    assert "WARNING" in err and "ThreadList unusable" in err
    assert rc == EXIT_NOT_FOUND


def test_cumulative_cap_error_surfaces_as_exit_1_at_the_command_line(tmp_path, capsys):
    base = bytearray(snap([{"tid": 1, "eip": NT, "stack_words": [0] * 0x40000}]))
    off = _stream(base, 3)
    entry = bytes(base[off + 4 : off + 4 + 48])
    new_list = struct.pack("<I", 100) + entry * 100
    new_off = len(base)
    base += new_list
    nd, dr = struct.unpack_from("<II", base, 8)
    for i in range(nd):
        if struct.unpack_from("<I", base, dr + 12 * i)[0] == 3:
            struct.pack_into("<III", base, dr + 12 * i, 3, len(new_list), new_off)
    rc, _, err = run(capsys, "dump", "--pdb", PDB, write(tmp_path, "cap.dmp", bytes(base)))
    assert rc == EXIT_INPUT and "add up" in err
