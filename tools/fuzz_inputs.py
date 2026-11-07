"""Seeded fuzz over PDB, minidump and PE input; counts uncaught exceptions.

    python3 -I tools/fuzz_inputs.py [--pdb PATH] [--dll PATH] [--dump PATH]
                                    [--cases N] [--seed S] [--real-pdb-cases N]

With no options it fuzzes the committed fixtures (``tests/fixtures/small.pdb``,
``small.dll``) and a synthetic minidump. Pass the real files to fuzz them too.
"Clean" means one of the tool's own errors (``civ4dbg.errors.Civ4DbgError``);
"uncaught" is anything else (the target is 0). Exit status is 0 when nothing
was uncaught, 1 otherwise. Nothing is written to disk.
"""

from __future__ import annotations

import argparse
import collections
import io
import pathlib
import random
import sys
import traceback

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from civ4dbg import minidump  # noqa: E402
from civ4dbg.errors import Civ4DbgError  # noqa: E402
from civ4dbg.msf import Msf  # noqa: E402
from civ4dbg.pdb import AddressKind, Pdb, format_resolution  # noqa: E402
from civ4dbg.pe import parse_pe_headers, read_codeview_id, read_pe_headers_from  # noqa: E402

FIX = ROOT / "tests" / "fixtures"


class Tally:
    def __init__(self, name: str) -> None:
        self.name = name
        self.cases = self.accepted = self.clean = 0
        self.uncaught: collections.Counter[str] = collections.Counter()
        self.first: dict[str, str] = {}

    def run(self, fn) -> None:  # type: ignore[no-untyped-def]
        self.cases += 1
        try:
            fn()
            self.accepted += 1
        except Civ4DbgError:
            self.clean += 1
        except BaseException as exc:  # noqa: BLE001 - this is the point of the tool
            key = f"{type(exc).__name__}"
            self.uncaught[key] += 1
            self.first.setdefault(key, "".join(traceback.format_exception(exc)[-3:]))

    def line(self) -> str:
        n = sum(self.uncaught.values())
        extra = f" {dict(self.uncaught)}" if n else ""
        return (
            f"{self.name:<34} cases {self.cases:>6}  accepted {self.accepted:>6}  "
            f"clean-error {self.clean:>6}  UNCAUGHT {n}{extra}"
        )


def exercise_pdb(raw, rvas) -> None:  # type: ignore[no-untyped-def]
    pdb = Pdb(Msf(raw))
    pdb.publics()
    for rva in rvas:
        for kind in AddressKind:
            format_resolution(pdb.resolve(rva, kind))


def fuzz_pdb(raw: bytes, cases: int, rnd: random.Random, rvas, name: str) -> Tally:
    t = Tally(name)
    for _ in range(cases):
        b = bytearray(raw)
        for _ in range(rnd.randint(1, 6)):
            b[rnd.randrange(len(b))] ^= 1 << rnd.randrange(8)
        t.run(lambda: exercise_pdb(bytes(b), rvas))
    return t


def fuzz_pdb_streams(raw: bytes, cases: int, rnd: random.Random, rvas, name: str) -> Tally:
    """Corrupt one stream's bytes inside a valid container (MSF stays well formed)."""
    from synth import build_msf

    base = Msf(raw)
    streams = [base.read_stream(i) if base.stream_exists(i) else None for i in range(base.num_streams)]
    live = [i for i, s in enumerate(streams) if s]
    t = Tally(name)
    for _ in range(cases):
        i = rnd.choice(live)
        data = bytearray(streams[i])  # type: ignore[arg-type]
        for _ in range(rnd.randint(1, 4)):
            data[rnd.randrange(len(data))] = rnd.choice((0, 0xFF, rnd.randrange(256)))
        s = list(streams)
        s[i] = bytes(data)
        t.run(lambda: exercise_pdb(build_msf(s, base.block_size), rvas))
    return t


def fuzz_real_pdb(path: str, cases: int, rnd: random.Random, rvas) -> Tally:
    """Flip bytes in the superblock, the directory and the DBI stream of the real PDB."""
    raw = pathlib.Path(path).read_bytes()
    base = Msf(raw)
    dbi_blocks = base._streams[3][1]  # noqa: SLF001
    t = Tally("real PDB (superblock/dir/DBI flips)")
    bs = base.block_size
    for _ in range(cases):
        b = bytearray(raw)
        for _ in range(rnd.randint(1, 4)):
            where = rnd.choice(("super", "dbi", "any"))
            if where == "super":
                pos = rnd.randrange(56)
            elif where == "dbi":
                pos = rnd.choice(dbi_blocks) * bs + rnd.randrange(bs)
            else:
                pos = rnd.randrange(len(b))
            b[pos] = rnd.randrange(256)
        t.run(lambda: exercise_pdb(bytes(b), rvas))
    return t


def fuzz_minidump(raw: bytes, cases: int, rnd: random.Random, name: str) -> Tally:
    t = Tally(name)
    for _ in range(cases):
        b = bytearray(raw)
        for _ in range(rnd.randint(1, 4)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        if rnd.random() < 0.3:
            del b[rnd.randrange(len(b)) :]
        t.run(lambda: minidump.parse_minidump(bytes(b)))
    return t


def fuzz_pe(raw: bytes, cases: int, rnd: random.Random, name: str) -> Tally:
    t = Tally(name)
    for _ in range(cases):
        b = bytearray(raw)
        for _ in range(rnd.randint(1, 4)):
            b[rnd.randrange(len(b))] = rnd.randrange(256)
        if rnd.random() < 0.2:
            del b[rnd.randrange(len(b)) :]
        data = bytes(b)
        t.run(lambda: parse_pe_headers(data))
        t.run(lambda: read_pe_headers_from(io.BytesIO(data)))
    return t


def fuzz_codeview(raw: bytes, cases: int, rnd: random.Random, name: str) -> Tally:
    """Mutate the debug-directory entry, the record pointer and the file length of a whole DLL."""
    from civ4dbg.pe import parse_pe_headers

    pe0 = parse_pe_headers(raw[: read_pe_headers_from(io.BytesIO(raw)).size_of_headers])
    sec = next(s for s in pe0.sections if s.virtual_address <= pe0.debug_dir_rva < s.virtual_address + s.raw_size)
    dir_pos = sec.raw_pointer + pe0.debug_dir_rva - sec.virtual_address
    t = Tally(name)
    for _ in range(cases):
        b = bytearray(raw)
        for _ in range(rnd.randint(1, 4)):
            pos = (
                dir_pos + rnd.randrange(min(pe0.debug_dir_size, 28 * 16))
                if rnd.random() < 0.8
                else rnd.randrange(len(b))
            )
            b[pos] = rnd.randrange(256)
        if rnd.random() < 0.2:
            del b[rnd.randrange(len(b)) :]
        data = bytes(b)

        def one() -> None:
            fh = io.BytesIO(data)
            read_codeview_id(fh, read_pe_headers_from(fh))

        t.run(one)
    return t


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pdb", help="a real PDB to fuzz as well (slow: ~0.4 s per case)")
    ap.add_argument("--dll", help="a real DLL whose header region is fuzzed")
    ap.add_argument("--dump", help="a real minidump to fuzz")
    ap.add_argument("--cases", type=int, default=3000)
    ap.add_argument("--real-pdb-cases", type=int, default=150)
    ap.add_argument("--seed", type=int, default=20261102)
    args = ap.parse_args()
    rnd = random.Random(args.seed)
    tallies: list[Tally] = []

    small = (FIX / "small.pdb").read_bytes()
    rvas = (0x1000, 0x1020, 0x1040, 0x1070, 0x2000, 0x3004, 0x4010, 0x5000)
    tallies.append(fuzz_pdb(small, args.cases, rnd, rvas, "small.pdb (whole-file flips)"))
    tallies.append(fuzz_pdb_streams(small, args.cases, rnd, rvas, "small.pdb (per-stream corruption)"))

    from synth import build_minidump, build_thread_minidump

    dll_mod = (0x2C50000, 0x9E6000, r"S:\game\CvGameCoreDLL.dll")
    synth_dump = build_minidump(
        [(0x400000, 0x100000, r"S:\game\x.exe"), dll_mod],
        0xC0000005,
        0x31454A5,
        (0, 0x34),
        0x31454A5,
        [0x2C50000 + 0x1000] * 8,
    )
    tallies.append(fuzz_minidump(synth_dump, args.cases, rnd, "synthetic minidump"))
    threads = [
        {"tid": 336, "eip": 0x2C50000 + 0x1020, "stack_words": [0x2C50000 + 0x1071] * 6},
        {"tid": 480, "eip": 0x7BE01000, "stack_words": [1, 2, 3]},
        {"tid": 792, "eip": 0x7BE01004, "stack_words": [0x7BE01000]},
    ]
    tallies.append(
        fuzz_minidump(
            build_thread_minidump(
                [(0x400000, 0x100000, r"S:\game\x.exe"), dll_mod], threads, (792, 0x80000003, 0x7BE01004)
            ),
            args.cases,
            rnd,
            "synthetic hang minidump (ThreadList + break-in)",
        )
    )
    tallies.append(
        fuzz_minidump(
            build_thread_minidump([(0x400000, 0x100000, r"S:\game\x.exe"), dll_mod], threads),
            args.cases,
            rnd,
            "synthetic hang minidump (ThreadList, no exception)",
        )
    )
    pe_head = (FIX / "small.dll").read_bytes()
    tallies.append(fuzz_pe(pe_head[:0x400], args.cases, rnd, "small.dll headers"))
    tallies.append(fuzz_codeview(pe_head, args.cases, rnd, "small.dll CodeView record"))

    if args.dump:
        tallies.append(fuzz_minidump(pathlib.Path(args.dump).read_bytes(), args.cases, rnd, "real minidump"))
    if args.dll:
        with open(args.dll, "rb") as fh:
            head = fh.read(0x1000)
        tallies.append(fuzz_pe(head, args.cases, rnd, "real DLL headers"))
    if args.pdb:
        real_rvas = (0x1000, 0x4F54A5, 0x4F74A8, 0x71843B, 0x748000, 0x894000, 0x93F000)
        tallies.append(fuzz_real_pdb(args.pdb, args.real_pdb_cases, rnd, real_rvas))

    total = bad = 0
    for t in tallies:
        print(t.line())
        total += t.cases
        bad += sum(t.uncaught.values())
        for key, tb in t.first.items():
            print(f"   first {key}:\n" + "".join("     " + ln for ln in tb.splitlines(True)))
    print(f"TOTAL cases {total}  uncaught exceptions {bad}")
    return 0 if bad == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
