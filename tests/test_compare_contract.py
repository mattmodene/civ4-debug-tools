"""The exit-code and stdout/stderr contract of ``compare``, as tables, plus the ``--crash-thread`` evidence rule.

Complements test_threads_cli.py (single scenarios) and test_compare_crash_thread.py (the flag's happy path
and refusals): this file sweeps combinations (3 and 4 dumps, outliers in every position) so a flipped
condition in the refusal logic or the evidence rule is caught whichever dump carries the odd one out.
Synthetic dumps only (``synth.build_thread_minidump``); the module is ``small.dll``'s ``CvGameCoreDLL.dll``.
"""

import itertools

import pytest
from synth import build_thread_minidump
from test_threads import BASE, DLL, MODS, NT, PDB, PE, run, write

from civ4dbg.errors import EXIT_BUILD_MISMATCH, EXIT_NOT_FOUND, EXIT_OK

MOD = "CvGameCoreDLL.dll"
FAULT_OFFSET = 0x1020  # inside `alpha` in the fixture PDB
CODE = 0xC0000005
LEFT_OUT = f"# thread(s) with addresses in {MOD} that are not in every dump were left out: "


def mods_at(base, timestamp=None, size=None):
    """MODS with the game DLL loaded at ``base`` (and optionally another identity)."""
    return [
        MODS[0],
        (
            base,
            PE.size_of_image if size is None else size,
            r"S:\game\CvGameCoreDLL.dll",
            PE.timestamp if timestamp is None else timestamp,
        ),
        MODS[2],
    ]


def snapshot(spec, base=BASE):
    """A ThreadList-only dump. ``spec`` maps tid to ``"mod"`` (eip and a stack word in the module) or ``"idle"``."""
    threads = []
    for tid, kind in spec:
        if kind == "mod":
            threads.append({"tid": tid, "eip": base + FAULT_OFFSET, "stack_words": [base + 0x1071]})
        else:
            threads.append({"tid": tid, "eip": NT, "stack_words": [0x1, NT]})
    return build_thread_minidump(mods_at(base), threads)


def crash_dump(
    tid, *, base=BASE, code=CODE, fault_offset=FAULT_OFFSET, words=(0x1071,), timestamp=None, size=None, pid=None
):
    """A crash dump whose exception thread is ``tid``; stack words are module RVAs; one idle thread besides."""
    fault = base + fault_offset
    threads = [
        {"tid": tid, "eip": fault, "stack_words": [base + w for w in words]},
        {"tid": 480, "eip": NT, "stack_words": [0x1, NT]},
    ]
    return build_thread_minidump(mods_at(base, timestamp, size), threads, (tid, code, fault), pid=pid)


def write_all(tmp_path, raws):
    return [write(tmp_path, f"d{i}.dmp", raw) for i, raw in enumerate(raws)]


# -- default mode: one table ---------------------------------------------------------------------------------


def idle3(*mod_tids_per_dump):
    """One dump per entry: its module threads plus the idle threads 480 and 484 that every dump has."""
    return [snapshot([(t, "mod") for t in tids] + [(480, "idle"), (484, "idle")]) for tids in mod_tids_per_dump]


# (id, dumps, extra args, rc, stdout has, stdout lacks, stderr has, stderr lacks)
DEFAULT_MODE_CASES = [
    (
        "all-three-share-the-module-thread",
        idle3([340], [340], [340]),
        (),
        EXIT_OK,
        ["== thread 340 ", "3/3 dumps", "mainfn"],
        ["were left out", "none of the", "== thread 480"],
        [],
        ["error:"],
    ),
    (
        "four-dumps-share-the-module-thread",
        idle3([340], [340], [340], [340]),
        (),
        EXIT_OK,
        ["== thread 340 ", "4/4 dumps"],
        ["were left out"],
        [],
        ["error:"],
    ),
    (
        "common-thread-ranks-and-one-outlier-each-is-noted",
        idle3([500, 340], [500, 344], [500, 348]),
        (),
        EXIT_OK,
        ["== thread 500 ", LEFT_OUT + "[0] d0.dmp: 340; [1] d1.dmp: 344; [2] d2.dmp: 348"],
        ["== thread 340", "== thread 344", "== thread 348"],
        [],
        ["error:"],
    ),
    (
        "outlier-only-in-the-last-dump-is-noted-for-that-dump-alone",
        idle3([500], [500], [500, 348]),
        (),
        EXIT_OK,
        ["== thread 500 ", LEFT_OUT + "[2] d2.dmp: 348"],
        ["[0] d0.dmp: ", "[1] d1.dmp: "],
        [],
        ["error:"],
    ),
    (
        "module-thread-present-in-only-some-dumps-by-id-is-refused-with-three-dumps",
        idle3([340], [340], [344]),
        (),
        EXIT_NOT_FOUND,
        ["== compare: 3 dumps"],
        ["== thread", "functions in at least", "none of the"],
        [
            "no thread carrying addresses in CvGameCoreDLL.dll is common to all the dumps",
            "[0] d0.dmp: 340; [1] d1.dmp: 340; [2] d2.dmp: 344",
        ],
        ["480", "484"],
    ),
    (
        "no-two-dumps-share-a-module-thread",
        idle3([340], [344], [348], [352]),
        (),
        EXIT_NOT_FOUND,
        [],
        ["== thread"],
        ["[0] d0.dmp: 340; [1] d1.dmp: 344; [2] d2.dmp: 348; [3] d3.dmp: 352", "civ4dbg dump"],
        ["480"],
    ),
    (
        "no-thread-carries-the-module-anywhere",
        idle3([], [], []),
        (),
        EXIT_OK,
        ["# none of the 3 dumps has a thread with an address in CvGameCoreDLL.dll"],
        ["== thread", "were left out", "had no address"],
        [],
        ["error:"],
    ),
    (
        "common-id-carries-addresses-in-one-dump-only",
        [snapshot([(340, "mod")]), snapshot([(340, "idle")]), snapshot([(340, "idle")])],
        (),
        EXIT_OK,
        ["== thread 340 ", "0 functions in at least 2 of 3 dumps"],
        ["were left out", "none of the"],
        [],
        ["error:"],
    ),
    (
        "thread-option-names-a-thread-idle-in-every-dump",
        idle3([340], [340], [340]),
        ("--thread", "480"),
        EXIT_NOT_FOUND,
        [],
        ["== thread"],
        ["thread 480 has no address in CvGameCoreDLL.dll in any of the 3 dumps"],
        [],
    ),
    (
        "thread-option-names-a-thread-missing-from-the-last-dump",
        idle3([340], [340], [344]),
        ("--thread", "340"),
        EXIT_NOT_FOUND,
        [],
        ["== thread"],
        ["thread 340 is not in dump", "d2.dmp"],
        [],
    ),
    (
        "thread-option-names-a-module-thread-the-others-lack-ids-for",
        idle3([340, 500], [340, 504], [340, 508]),
        ("--thread", "340"),
        EXIT_OK,
        ["== thread 340 ", "3/3 dumps"],
        ["were left out", "== thread 500"],
        [],
        ["error:"],
    ),
]


@pytest.mark.parametrize(
    "dumps,extra,rc_want,out_has,out_lacks,err_has,err_lacks",
    [c[1:] for c in DEFAULT_MODE_CASES],
    ids=[c[0] for c in DEFAULT_MODE_CASES],
)
def test_default_mode_contract_table(tmp_path, capsys, dumps, extra, rc_want, out_has, out_lacks, err_has, err_lacks):
    paths = write_all(tmp_path, dumps)
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *extra, *paths)
    assert rc == rc_want, (rc, out, err)
    assert "Traceback" not in err
    for text in out_has:
        assert text in out, (text, out)
    for text in out_lacks:
        assert text not in out, (text, out)
    for text in err_has:
        assert text in err, (text, err)
    for text in err_lacks:
        assert text not in err, (text, err)
    if rc_want != EXIT_OK:
        assert err.startswith("error:") or "\nerror:" in err  # one `error:` report, after any `#` info lines
        assert err.count("error:") == 1


# -- 3+ dumps: the refusal and the note are decided on every dump, whichever carries the outlier -----------


@pytest.mark.parametrize("outlier", [0, 1, 2, 3])
def test_one_dump_with_a_different_module_thread_id_is_refused_wherever_it_sits(tmp_path, capsys, outlier):
    tids = [340] * 4
    tids[outlier] = 344
    paths = write_all(tmp_path, idle3(*([t] for t in tids)))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *paths)
    assert rc == EXIT_NOT_FOUND and "== thread" not in out
    for i, t in enumerate(tids):
        assert f"[{i}] d{i}.dmp: {t}" in err


@pytest.mark.parametrize("outlier", [0, 1, 2, 3])
def test_common_thread_is_ranked_and_the_outlier_noted_wherever_it_sits(tmp_path, capsys, outlier):
    specs = [[500] for _ in range(4)]
    specs[outlier] = [500, 344]
    paths = write_all(tmp_path, idle3(*specs))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *paths)
    assert rc == EXIT_OK and "4/4 dumps" in out
    assert LEFT_OUT + f"[{outlier}] d{outlier}.dmp: 344" in out
    assert (
        out.count("d0.dmp: 344") + out.count("d1.dmp: 344") + out.count("d2.dmp: 344") + out.count("d3.dmp: 344") == 1
    )


def test_a_crash_dump_pair_with_the_same_module_thread_id_needs_no_flag(tmp_path, capsys):
    paths = write_all(tmp_path, [crash_dump(340), crash_dump(340), crash_dump(340)])
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *paths)
    assert rc == EXIT_OK and "== thread 340 " in out and "--crash-thread" not in err + out


def test_the_crash_thread_hint_needs_an_exception_record_in_every_dump_including_the_last(tmp_path, capsys):
    raws = [crash_dump(340), crash_dump(344), snapshot([(348, "mod"), (480, "idle")])]
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *write_all(tmp_path, raws))
    assert rc == EXIT_NOT_FOUND and "--crash-thread" not in err
    raws[2] = crash_dump(348)
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *write_all(tmp_path, raws))
    assert rc == EXIT_NOT_FOUND and "rerun with --crash-thread" in err


def test_different_processes_wording_needs_a_process_id_in_every_dump(tmp_path, capsys):
    pids = [(1, 2, 3), (1, 2, None), (1, 1, 1)]
    wording = []
    for p in pids:
        raws = [crash_dump(340 + 4 * i, pid=p[i]) for i in range(3)]
        _, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *write_all(tmp_path, raws))
        wording.append("come from different processes" in err)
    assert wording == [True, False, False]


# -- --crash-thread: the evidence line is "consistent with the same crash" iff code and module+offset agree --

SAME_CRASH = "consistent with the same crash"
NOT_SAME = "do not treat them as the same crash"


def crash_set(n, odd=None, what=None, bases=None):
    """``n`` crash dumps with distinct thread ids; dump ``odd`` differs in ``what`` ("code" or "offset")."""
    raws = []
    for i in range(n):
        kwargs = {}
        if i == odd and what == "code":
            kwargs["code"] = 0xC0000094
        if i == odd and what == "offset":
            kwargs["fault_offset"] = FAULT_OFFSET + 4
        if bases:
            kwargs["base"] = bases[i]
        raws.append(crash_dump(340 + 4 * i, **kwargs))
    return raws


@pytest.mark.parametrize("n,odd,what", [(n, o, w) for n in (2, 3, 4) for o in range(n) for w in ("code", "offset")])
def test_a_single_odd_dump_breaks_the_same_crash_verdict_wherever_it_sits(tmp_path, capsys, n, odd, what):
    paths = write_all(tmp_path, crash_set(n, odd, what))
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK, err
    assert NOT_SAME in out and SAME_CRASH not in out
    evidence = next(ln for ln in out.splitlines() if ln.startswith("# evidence:"))
    if what == "code":
        assert "exception code DIFFERS" in evidence and "faulting module+offset identical" in evidence
    else:
        assert "exception code identical" in evidence and "faulting module+offset DIFFERS" in evidence


@pytest.mark.parametrize("n", [2, 3, 4])
def test_all_dumps_agreeing_gives_the_verdict_and_never_the_negative(tmp_path, capsys, n):
    paths = write_all(tmp_path, crash_set(n))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK and SAME_CRASH in out and NOT_SAME not in out
    assert f"all {n} dumps" in out


def test_both_code_and_offset_differing_is_reported_as_both(tmp_path, capsys):
    raws = [crash_dump(340), crash_dump(344, code=0xC0000094, fault_offset=FAULT_OFFSET + 4)]
    _, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *write_all(tmp_path, raws))
    assert "exception code DIFFERS (0xc0000005, 0xc0000094); faulting module+offset DIFFERS" in out
    assert SAME_CRASH not in out


def test_a_module_loaded_at_different_bases_still_gives_the_same_module_and_offset(tmp_path, capsys):
    bases = [BASE, 0x3A00000, 0x1C00000]
    paths = write_all(tmp_path, crash_set(3, bases=bases))
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK and SAME_CRASH in out and "faulting module+offset identical" in out
    for i in range(3):
        assert f"[{i}] d{i}.dmp: exception 0xc0000005 at {MOD}+0x1020 (alpha)" in out
    assert "3/3 dumps" in out and "3 leading scan frame(s)" not in out and "2 leading scan frame(s)" in out


def test_a_different_base_does_not_hide_a_different_offset(tmp_path, capsys):
    raws = [crash_dump(340), crash_dump(344, base=0x3A00000, fault_offset=FAULT_OFFSET + 4)]
    _, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *write_all(tmp_path, raws))
    assert NOT_SAME in out and "faulting module+offset DIFFERS" in out


def test_fault_addresses_outside_every_module_that_differ_are_not_the_same_crash(tmp_path, capsys):
    def outside(tid, addr):
        t = {"tid": tid, "eip": BASE + FAULT_OFFSET, "stack_words": [BASE + 0x1071]}
        return build_thread_minidump(MODS, [t], (tid, CODE, addr))

    paths = write_all(tmp_path, [outside(340, 0x500), outside(344, 0x600)])
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK and "0x500 (in no listed module)" in out and "0x600 (in no listed module)" in out
    assert NOT_SAME in out and SAME_CRASH not in out


def test_a_fault_inside_the_module_versus_one_outside_it_is_not_the_same_crash(tmp_path, capsys):
    def outside(tid):
        t = {"tid": tid, "eip": BASE + FAULT_OFFSET, "stack_words": [BASE + 0x1071]}
        return build_thread_minidump(MODS, [t], (tid, CODE, 0x500))

    paths = write_all(tmp_path, [crash_dump(340), outside(344)])
    _, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert NOT_SAME in out and SAME_CRASH not in out


def test_the_same_offset_in_two_different_modules_is_not_the_same_crash(tmp_path, capsys):
    def in_module(tid, base):
        t = {"tid": tid, "eip": base + 0x1000, "stack_words": []}
        return build_thread_minidump(MODS, [t], (tid, CODE, base + 0x1000))

    # the exe (0x400000) and ntdll (0x7BE00000) both fault at +0x1000
    paths = write_all(tmp_path, [in_module(340, 0x400000), in_module(344, 0x7BE00000)])
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK and "Civ4BeyondSword.exe+0x1000" in out and "ntdll.dll+0x1000" in out
    assert NOT_SAME in out and SAME_CRASH not in out


def test_exception_thread_without_module_frames_in_one_dump_only_is_ranked_empty_and_not_the_same(tmp_path, capsys):
    idle = build_thread_minidump(MODS, [{"tid": 344, "eip": NT, "stack_words": []}], (344, CODE, NT))
    paths = write_all(tmp_path, [crash_dump(340), idle])
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK and "== exception threads: 0 functions" in out
    assert "# no exception thread has an address" not in out  # dump 0 does have module frames
    assert "0 leading scan frame(s)" in out and NOT_SAME in out


def test_min_dumps_and_top_apply_to_the_crash_thread_ranking_with_an_outlier(tmp_path, capsys):
    raws = [crash_dump(340), crash_dump(344), crash_dump(348, words=(0x1031,))]  # mainfn, mainfn, helper
    paths = write_all(tmp_path, raws)
    base = ("compare", "--pdb", PDB, "--dll", DLL, "--crash-thread")
    rows = lambda out: [ln for ln in out.splitlines() if "dumps  hits" in ln]  # noqa: E731
    _, out, _ = run(capsys, *base, *paths)
    assert [("alpha" in r, "mainfn" in r) for r in rows(out)] == [(True, False), (False, True)]
    _, out, _ = run(capsys, *base, "--min-dumps", "3", *paths)
    assert len(rows(out)) == 1 and "alpha" in rows(out)[0] and "3/3 dumps" in rows(out)[0]
    _, out, _ = run(capsys, *base, "--min-dumps", "1", "--top", "1", *paths)
    assert len(rows(out)) == 1 and "... 2 more (see --top)" in out


# -- module identity between dumps ---------------------------------------------------------------------------


@pytest.mark.parametrize("what", ["timestamp", "size"])
def test_a_dump_of_another_build_is_refused_by_crash_thread_when_the_dll_is_given(tmp_path, capsys, what):
    other = crash_dump(344, timestamp=PE.timestamp + 1) if what == "timestamp" else crash_dump(344, size=0x9000)
    paths = write_all(tmp_path, [crash_dump(340), other])
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_BUILD_MISMATCH and "NOT from this DLL's build" in err
    assert SAME_CRASH not in out


def test_without_the_dll_crash_thread_warns_that_the_build_match_was_not_checked(tmp_path, capsys):
    paths = write_all(tmp_path, [crash_dump(340), crash_dump(344, timestamp=PE.timestamp + 1)])
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--crash-thread", *paths)
    # What is pinned is only the warning, which the README promises. Whether two dumps whose module records
    # differ should still be called "consistent with the same crash" is reported to the owner, not encoded.
    assert rc == EXIT_OK and "build match NOT checked (no --dll)" in err


def test_crash_thread_falls_back_to_the_exception_record_when_there_is_no_thread_list(tmp_path, capsys):
    from synth import build_minidump

    def old_style():
        return build_minidump(MODS, CODE, BASE + FAULT_OFFSET, (0, 0x34), BASE + FAULT_OFFSET, [BASE + 0x1071])

    paths = write_all(tmp_path, [old_style(), old_style()])
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
    assert rc == EXIT_OK and "2/2 dumps" in out and "mainfn" in out and SAME_CRASH in out
    # the same dumps are refused by default mode, which has no thread ids to match
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *paths)
    assert rc == EXIT_NOT_FOUND and "no thread id is present in every dump" in err


def test_crash_thread_order_of_dumps_does_not_change_the_verdict(tmp_path, capsys):
    raws = crash_set(3, odd=1, what="offset")
    verdicts = set()
    for perm in itertools.permutations(range(3)):
        paths = write_all(tmp_path, [raws[i] for i in perm])
        _, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *paths)
        verdicts.add((SAME_CRASH in out, NOT_SAME in out))
    assert verdicts == {(False, True)}


def test_leading_frame_count_stops_at_a_frame_no_function_covers(tmp_path, capsys):
    # eip is in alpha in both dumps; the next scanned word (RVA 0x1030) resolves to no function in either, so the
    # agreement must stop at 1 even though the two "unresolved" frames are equal to each other; mainfn follows
    raws = [crash_dump(340, words=(0x1030, 0x1071)), crash_dump(344, words=(0x1030, 0x1071))]
    rc, out, _ = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", *write_all(tmp_path, raws))
    assert rc == EXIT_OK and "1 leading scan frame(s) resolve to the same function in all 2 dumps" in out
    assert "(2 words resolved to no function)" in out
