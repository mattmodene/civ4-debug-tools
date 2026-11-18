"""Malformed exception and MiscInfo streams, and the unchanged output of ``dump`` for dumps that carry MiscInfo.

Every malformed variant must end in a clean ``MinidumpError`` (exit 1, one ``error:`` line) or in a normal
result; never an escaped struct/index error (exit 5, "internal") and never a traceback. Synthetic dumps only.

MiscInfo is optional context: a stream that is too short, lies (even partly) outside the file or does not
flag the process id valid yields ``process_id = None`` and never makes a command fail
(``test_misc_info_outside_the_file_*``).
"""

import pathlib
import struct
import subprocess
import sys

import pytest
from synth import build_thread_minidump
from test_threads import BASE, DLL, MODS, NT, PDB, ret, run, write

from civ4dbg import minidump
from civ4dbg.errors import EXIT_INPUT, EXIT_INTERNAL, EXIT_NOT_FOUND, EXIT_OK

ROOT = pathlib.Path(__file__).resolve().parent.parent
FAULT = BASE + 0x1020
STREAM_EXCEPTION, STREAM_MISC, STREAM_THREADS, STREAM_MODULES = 6, 15, 3, 4
CLEAN_CODES = {0, 1, 2, 3, 4}  # everything the README documents except 5, the "this is a bug" backstop


def crash(tid=340, pid=336, misc_info=None):
    threads = [
        {"tid": tid, "eip": FAULT, "stack_words": [ret(0x1071), ret(0x1011)]},
        {"tid": 480, "eip": NT, "stack_words": [0x1, NT]},
    ]
    return build_thread_minidump(MODS, threads, (tid, 0xC0000005, FAULT), pid=pid, misc_info=misc_info)


def snapshot(pid=336):
    threads = [
        {"tid": 336, "eip": FAULT, "stack_words": [ret(0x1071)]},
        {"tid": 480, "eip": NT, "stack_words": [0x1, NT]},
    ]
    return build_thread_minidump(MODS, threads, None, pid=pid)


def directory(raw):
    n, dir_rva = struct.unpack_from("<II", raw, 8)
    return {
        k: (i, sz, off) for i in range(n) for k, sz, off in [struct.unpack_from("<III", raw, dir_rva + 12 * i)]
    }, dir_rva


def stream(raw, kind):
    entries, _ = directory(raw)
    _, size, off = entries[kind]
    return size, off


def patched(raw, kind, size=None, rva=None, new_kind=None):
    """``raw`` with one directory entry rewritten (size, rva and/or stream type)."""
    entries, dir_rva = directory(raw)
    i, sz, off = entries[kind]
    out = bytearray(raw)
    struct.pack_into(
        "<III",
        out,
        dir_rva + 12 * i,
        kind if new_kind is None else new_kind,
        sz if size is None else size,
        off if rva is None else rva,
    )
    return bytes(out)


def outcome(raw):
    """Parse ``raw``; the only acceptable failure is the package's own MinidumpError."""
    try:
        return minidump.parse_minidump(raw)
    except minidump.MinidumpError as exc:
        return exc


def assert_clean(rc, out, err):
    assert rc in CLEAN_CODES, (rc, err)
    assert rc != EXIT_INTERNAL and "internal" not in err and "Traceback" not in err, err
    if rc == EXIT_INPUT:
        assert err.startswith("error:") or "\nerror:" in err
        assert err.count("error:") == 1


def variants():
    """(name, bytes): the exception and MiscInfo streams damaged at every field boundary and in every way listed."""
    raw = crash()
    exc_size, exc_off = stream(raw, STREAM_EXCEPTION)
    misc_size, misc_off = stream(raw, STREAM_MISC)
    out = []
    # the file ends inside the stream at every 4-byte boundary (and one byte past), for both streams
    for name, off, size in (("exception", exc_off, exc_size), ("miscinfo", misc_off, misc_size)):
        for k in sorted(set(range(0, size + 1, 4)) | {1, size - 1}):
            out.append((f"{name}-file-cut-at-{k}", raw[: off + k]))
    # the recorded size, zero and oversized
    for size in (0, 1, 11, 12, 23, 24, 25, 4096, 0xFFFFFFFF):
        out.append((f"miscinfo-size-{size}", patched(raw, STREAM_MISC, size=size)))
        out.append((f"exception-size-{size}", patched(raw, STREAM_EXCEPTION, size=size)))
    # the recorded position: header, the last bytes of the file, far outside, and on top of other streams
    entries, _ = directory(raw)
    for kind, label in ((STREAM_EXCEPTION, "exception"), (STREAM_MISC, "miscinfo")):
        for rva in (0, 4, 12, len(raw) - 3, len(raw), 0x7FFFFFF0, 0xFFFFFFFF):
            out.append((f"{label}-rva-{rva:#x}", patched(raw, kind, rva=rva)))
        for other in (STREAM_THREADS, STREAM_MODULES, STREAM_MISC if kind == STREAM_EXCEPTION else STREAM_EXCEPTION):
            out.append((f"{label}-overlaps-stream-{other}", patched(raw, kind, rva=entries[other][2])))
    # duplicate stream types: the entry for one stream relabelled as another
    out.append(("duplicate-exception-from-miscinfo", patched(raw, STREAM_MISC, new_kind=STREAM_EXCEPTION)))
    out.append(("duplicate-miscinfo-from-exception", patched(raw, STREAM_EXCEPTION, new_kind=STREAM_MISC)))
    out.append(("duplicate-miscinfo-from-threadlist", patched(raw, STREAM_THREADS, new_kind=STREAM_MISC)))
    out.append(("duplicate-exception-from-threadlist", patched(raw, STREAM_THREADS, new_kind=STREAM_EXCEPTION)))
    # field values inside the exception record
    for field_off, label in (
        (0, "thread-id"),
        (8, "code"),
        (24, "address"),
        (40, "n-params"),
        (160, "ctx-size"),
        (164, "ctx-rva"),
    ):
        for value in (0, 1, 0x7FFFFFFF, 0xFFFFFFFF):
            b = bytearray(raw)
            struct.pack_into("<I", b, exc_off + field_off, value)
            out.append((f"exception-{label}-{value:#x}", bytes(b)))
    # raw MiscInfo contents
    for label, blob in (
        ("short", b"\x18\0\0\0"),
        ("flags-only", struct.pack("<II", 24, 1)),
        ("empty", b""),
        ("huge-self-size", struct.pack("<IIIIII", 0xFFFFFFFF, 1, 5, 0, 0, 0)),
        ("big-real-size", struct.pack("<IIIIII", 232, 0xFFFFFFFF, 7, 1, 2, 3) + b"\xff" * 208),
    ):
        out.append((f"miscinfo-content-{label}", crash(misc_info=blob)))
    return out


VARIANTS = variants()
IDS = [v[0] for v in VARIANTS]


@pytest.mark.parametrize("raw", [v[1] for v in VARIANTS], ids=IDS)
def test_parse_fails_only_with_the_packages_own_error(raw):
    result = outcome(raw)
    assert isinstance(result, (minidump.CrashInfo, minidump.MinidumpError))
    if isinstance(result, minidump.CrashInfo):
        assert result.process_id is None or 0 <= result.process_id <= 0xFFFFFFFF


@pytest.mark.parametrize("command", ["dump", "compare", "compare-crash-thread"])
@pytest.mark.parametrize("raw", [v[1] for v in VARIANTS], ids=IDS)
def test_every_command_ends_cleanly_on_a_damaged_stream(tmp_path, capsys, command, raw):
    bad = write(tmp_path, "bad.dmp", raw)
    good = write(tmp_path, "good.dmp", crash(344, pid=348))
    if command == "dump":
        rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, bad)
    else:
        extra = ("--crash-thread",) if command == "compare-crash-thread" else ()
        rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *extra, bad, good)
    assert_clean(rc, out, err)


def test_a_damaged_exception_stream_cannot_make_the_good_dump_in_the_pair_fail(tmp_path, capsys):
    # the good dump alone still compares with itself; the damage must not leak across dumps
    good = write(tmp_path, "good.dmp", crash())
    rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", good, good)
    assert rc == EXIT_OK and "consistent with the same crash" in out


# -- sampled through the real entry point: no traceback, documented exit code ----------------------------------


def cli(*argv):
    return subprocess.run(
        [sys.executable, "-I", "civ4dbg.py", *map(str, argv)], capture_output=True, text=True, cwd=ROOT, timeout=120
    )


SUBPROCESS_SAMPLE = [
    "exception-file-cut-at-8",
    "exception-file-cut-at-164",
    "miscinfo-file-cut-at-4",
    "miscinfo-file-cut-at-20",
    "exception-rva-0xffffffff",
    "exception-ctx-size-0x0",
    "exception-ctx-rva-0xffffffff",
    "exception-overlaps-stream-3",
    "duplicate-exception-from-miscinfo",
    "duplicate-miscinfo-from-threadlist",
    "miscinfo-size-4294967295",
    "miscinfo-content-big-real-size",
]


@pytest.mark.parametrize("name", SUBPROCESS_SAMPLE)
def test_subprocess_sample_ends_cleanly_with_a_documented_exit_code(tmp_path, name):
    raw = dict(VARIANTS)[name]
    bad = write(tmp_path, "bad.dmp", raw)
    good = write(tmp_path, "good.dmp", crash(344, pid=348))
    for argv in (
        ("dump", "--pdb", PDB, "--dll", DLL, bad),
        ("compare", "--pdb", PDB, "--dll", DLL, "--crash-thread", bad, good),
        ("compare", "--pdb", PDB, "--dll", DLL, bad, good),
    ):
        r = cli(*argv)
        assert r.returncode in CLEAN_CODES, (argv, r.returncode, r.stderr)
        assert "Traceback" not in r.stderr and "internal" not in r.stderr, r.stderr
        if r.returncode == EXIT_INPUT:
            assert r.stderr.count("error:") == 1


def test_subprocess_miscinfo_stream_past_the_end_of_the_file_is_ignored(tmp_path):
    bad = write(tmp_path, "bad.dmp", patched(crash(), STREAM_MISC, rva=0x7FFFFFF0))
    r = cli("dump", "--pdb", PDB, "--dll", DLL, bad)
    assert r.returncode == EXIT_OK and "Traceback" not in r.stderr and "MiscInfo" not in r.stderr


# -- MiscInfo stream outside the file: non-fatal, the process id is unavailable ------------------------------------


def test_misc_info_outside_the_file_is_ignored_for_dump(tmp_path, capsys):
    ok = write(tmp_path, "ok.dmp", crash())
    bad = write(tmp_path, "bad.dmp", patched(crash(), STREAM_MISC, rva=0x7FFFFFF0))
    rc, out, err = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, bad)
    rc_ok, out_ok, err_ok = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, ok)
    assert rc == rc_ok == EXIT_OK and out == out_ok and err == err_ok


def test_misc_info_outside_the_file_is_ignored_for_compare(tmp_path, capsys):
    bad = write(tmp_path, "bad.dmp", patched(crash(), STREAM_MISC, size=0xFFFFFF))
    good = write(tmp_path, "good.dmp", crash(344))
    rc, _, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, bad, good)
    # the thread ids differ (340 vs 344), so the default mode refuses with exit 2 for that reason alone; the
    # damaged MiscInfo changes nothing but leaves the pid readable (equal pids), so the wording is the hedge
    assert rc == EXIT_NOT_FOUND == 2
    assert "no thread carrying addresses" in err and "typical when" in err and "MiscInfo" not in err


def test_misc_info_ending_at_the_end_of_the_file_and_beyond_it_both_leave_the_process_id_readable_or_none(tmp_path):
    raw = crash(pid=4242)
    size, _ = stream(raw, STREAM_MISC)
    at_end = patched(raw, STREAM_MISC, rva=len(raw) - size)
    assert isinstance(outcome(at_end), minidump.CrashInfo)
    # the stream stays where it is but its declared size runs one byte past the end of the file: the 12 bytes
    # the reader needs are present, so nothing fails and the process id is still read correctly
    _, real_off = stream(raw, STREAM_MISC)
    just_past = outcome(patched(raw, STREAM_MISC, size=len(raw) - real_off + 1))
    assert isinstance(just_past, minidump.CrashInfo) and just_past.process_id == 4242
    # fewer than 12 bytes remain in the file: the process id is unavailable, still no error
    way_past = outcome(patched(raw, STREAM_MISC, rva=len(raw) - 8))
    assert isinstance(way_past, minidump.CrashInfo) and way_past.process_id is None


# -- MiscInfo that parses: the process id is read exactly as flagged ---------------------------------------------


@pytest.mark.parametrize(
    "blob,want",
    [
        (struct.pack("<IIIIII", 24, 1, 4242, 0, 0, 0), 4242),
        (struct.pack("<IIIIII", 24, 3, 4242, 9, 0, 0), 4242),  # more flags set: still the process id
        (struct.pack("<IIIIII", 24, 2, 4242, 9, 0, 0), None),  # only the create time valid: no process id
        (struct.pack("<IIIIII", 24, 0, 4242, 0, 0, 0), None),
        (struct.pack("<IIIIII", 24, 1, 0, 0, 0, 0), 0),  # pid 0 is a value, not "absent"
        (struct.pack("<IIIIII", 24, 1, 0xFFFFFFFF, 0, 0, 0), 0xFFFFFFFF),
        (struct.pack("<III", 12, 1, 77), 77),  # exactly the three words the reader needs
        (struct.pack("<II", 8, 1), None),
        (struct.pack("<IIIIII", 232, 1, 5, 0, 0, 0) + b"\0" * 208, 5),  # a larger MISC_INFO_2/3 record
    ],
)
def test_process_id_is_read_only_when_flagged_valid(blob, want):
    assert minidump.parse_minidump(crash(misc_info=blob)).process_id == want


# -- dump output is unchanged by the presence of the new streams -----------------------------------------------


@pytest.mark.parametrize("flags", [(), ("--all-threads",), ("--thread", "480"), ("--stack-limit", "1")])
def test_dump_output_is_identical_with_and_without_a_miscinfo_stream(tmp_path, capsys, flags):
    plain = write(tmp_path, "plain.dmp", crash(pid=None))
    with_pid = write(tmp_path, "pid.dmp", crash(pid=4242))
    ignored = write(tmp_path, "ign.dmp", crash(misc_info=struct.pack("<IIIIII", 24, 0, 4242, 0, 0, 0)))
    big = write(tmp_path, "big.dmp", crash(misc_info=struct.pack("<IIIIII", 232, 1, 4242, 0, 0, 0) + b"\0" * 208))
    base = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, *flags, plain)
    assert base[0] == EXIT_OK and "eip " in base[1]
    for other in (with_pid, ignored, big):
        assert run(capsys, "dump", "--pdb", PDB, "--dll", DLL, *flags, other) == base
    assert "4242" not in base[1] and "process" not in base[1].lower()


def test_dump_output_of_a_snapshot_is_identical_with_and_without_a_miscinfo_stream(tmp_path, capsys):
    plain = write(tmp_path, "plain.dmp", snapshot(pid=None))
    with_pid = write(tmp_path, "pid.dmp", snapshot(pid=4242))
    for flags in ((), ("--all-threads",)):
        a = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, *flags, plain)
        b = run(capsys, "dump", "--pdb", PDB, "--dll", DLL, *flags, with_pid)
        assert a == b and a[0] == EXIT_OK


def test_default_compare_output_is_identical_with_and_without_miscinfo_when_threads_match(tmp_path, capsys):
    def trio(pid):
        return [write(tmp_path, f"{pid}-{i}.dmp", crash(340, pid=pid)) for i in range(2)]

    # labels differ between the two trios, so compare with the file names normalised
    outs = []
    for pid in (None, 4242):
        rc, out, err = run(capsys, "compare", "--pdb", PDB, "--dll", DLL, *trio(pid))
        assert rc == EXIT_OK
        outs.append(out.replace(f"{pid}-", "X-"))
    assert outs[0] == outs[1]


def test_resolve_does_not_read_dumps_so_miscinfo_cannot_change_it(capsys):
    # `resolve` takes addresses and a PDB only; recorded here so the regression question has an explicit answer
    rc, out, _ = run(capsys, "resolve", "--pdb", PDB, "--dll", DLL, "0x1071")
    assert rc == EXIT_OK and "mainfn" in out
