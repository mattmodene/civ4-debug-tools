"""Command line: ``python3 -I -m civ4dbg <command> ...``.

Exit codes: 0 success; 1 unreadable or malformed input; 2 usage error, or the
module is not in the dump; 3 build mismatch (dump vs DLL) refused; 4 input not
supported (OMAP PDB, non-x86 dump); 5 internal error (an unexpected exception
type escaped; a bug to report).
"""

from __future__ import annotations

import argparse
import struct
import sys

from . import compare, minidump, remote
from .buildcheck import build_mismatches, pdb_age_note, pdb_mismatches
from .errors import (
    EXIT_INPUT,
    EXIT_INTERNAL,
    EXIT_NOT_FOUND,
    EXIT_OK,
    BuildMismatchError,
    Civ4DbgError,
    ThreadNotFoundError,
)
from .pdb import AddressKind, OmapUnsupportedError, Pdb, Resolution, format_resolution
from .pe import PeHeaders, compare_sections, read_codeview_id_from_path, read_pe_headers


def _int(text: str) -> int:
    return int(text, 0)


def _nonneg(text: str) -> int:
    value = int(text, 0)
    if value < 0:
        raise argparse.ArgumentTypeError("must be 0 or more")
    return value


def _pos(text: str) -> int:
    value = int(text, 0)
    if value < 1:
        raise argparse.ArgumentTypeError("must be 1 or more")
    return value


def _check_pdb_matches_dll(pdb: Pdb, dll_path: str, pe: PeHeaders, allow: bool, sections_differ: bool = False) -> None:
    cv = read_codeview_id_from_path(dll_path, pe)
    if cv is None:
        if sections_differ and not allow:
            raise BuildMismatchError(
                "the DLL has no usable CodeView (RSDS) record, so the PDB cannot be matched by "
                "GUID, and the PDB's section table differs from the DLL's (see above): this is "
                "probably not the PDB of this DLL. Use the PDB built with the DLL, or pass "
                "--allow-pdb-mismatch"
            )
        print(
            "WARNING: the DLL has no usable CodeView (RSDS) record (absent, or an old/unrecognised format): "
            "PDB GUID/age NOT checked",
            file=sys.stderr,
        )
        return
    ident = pdb.guid_age()
    problems = pdb_mismatches(ident, cv, pdb.dbi_age)
    if not problems:
        note = pdb_age_note(ident, cv, pdb.dbi_age)
        print("# PDB matches the DLL: GUID and age agree" + (f" ({note})" if note else ""), file=sys.stderr)
        return
    detail = "; ".join(problems)
    if not allow:
        raise BuildMismatchError(
            f"the PDB does not belong to this DLL ({detail}). Names from it would be wrong. "
            "Use the PDB built with the DLL, or pass --allow-pdb-mismatch"
        )
    print(f"WARNING: PDB/DLL MISMATCH ({detail}); names below are unreliable", file=sys.stderr)


def _open_pdb(
    pdb_path: str, dll_path: str | None, *, names: bool = True, allow_pdb_mismatch: bool = False
) -> tuple[Pdb, PeHeaders | None]:
    """Open the PDB (and the DLL headers); ``names`` refuses a PDB whose names cannot be trusted."""
    pdb = Pdb.open(pdb_path)
    try:
        pe = read_pe_headers(dll_path) if dll_path else None
        if names and pdb.has_omap:
            raise OmapUnsupportedError(
                "the PDB has OMAP streams; RVAs would need translating through OMAP, which is "
                "not implemented, so no names are printed"
            )
        if pe is not None:
            diffs = compare_sections(pdb.sections, pe.sections)
            if diffs:
                print("WARNING: PDB section headers differ from the DLL PE table:", file=sys.stderr)
                for d in diffs:
                    print("  " + d, file=sys.stderr)
            else:
                print(
                    f"# section table of PDB matches DLL PE headers "
                    f"({len(pe.sections)} sections, image base {pe.image_base:#x})",
                    file=sys.stderr,
                )
            _check_pdb_matches_dll(pdb, dll_path, pe, allow_pdb_mismatch, bool(diffs))
    except BaseException:
        pdb.close()
        raise
    return pdb, pe


def _cmd_resolve(args: argparse.Namespace) -> int:
    kind = AddressKind.RETURN_ADDRESS if args.return_address else AddressKind.EXACT
    pdb, _pe = _open_pdb(args.pdb, args.dll, allow_pdb_mismatch=args.allow_pdb_mismatch)
    with pdb:
        limit = None if args.all_candidates else 5
        for rva in args.rva:
            print(format_resolution(pdb.resolve(rva, kind), limit))
    return EXIT_OK


def _check_build(target: minidump.Module, pe: PeHeaders | None, allow_mismatch: bool) -> None:
    if pe is None:
        print(
            "WARNING: build match NOT checked (no --dll): the dump may be from a different "
            "build than the PDB, in which case the names below are wrong",
            file=sys.stderr,
        )
        return
    problems = build_mismatches(target, pe)
    if not problems:
        print(
            f"# build match: dump module record equals DLL PE headers "
            f"(TimeDateStamp {pe.timestamp:#x}, SizeOfImage {pe.size_of_image:#x})",
            file=sys.stderr,
        )
        return
    detail = "; ".join(problems)
    if not allow_mismatch:
        raise BuildMismatchError(
            f"the minidump is NOT from this DLL's build ({detail}). Resolving it would print "
            "wrong names. Use the DLL and PDB of the build that crashed, or pass "
            "--allow-build-mismatch to see the names anyway"
        )
    print("!" * 72, file=sys.stderr)
    print("WARNING: BUILD MISMATCH between the minidump and the DLL; every name below is", file=sys.stderr)
    print("         for the wrong build unless the PDB happens to match the dump:", file=sys.stderr)
    for p in problems:
        print("         " + p, file=sys.stderr)
    print("!" * 72, file=sys.stderr)


def _module_note(info: minidump.CrashInfo, address: int) -> str:
    m = info.module_at(address)
    return f"in {m.basename} +{address - m.base:#x}" if m else "in no listed module"


def _select_threads(
    info: minidump.CrashInfo, target: minidump.Module, args: argparse.Namespace
) -> tuple[list[minidump.ThreadInfo], str]:
    """Pick the threads to show and a one-line account of what was left out and why.

    Explicit ``--thread`` / ``--all-threads`` win. A hang/snapshot dump with neither
    shows every thread that touches the module (eip in it, or a stack word in it),
    leaving out the debugger's break-in thread; if none does, thread #0 of the list.
    """
    if args.thread:
        chosen = []
        for tid in args.thread:
            t = info.thread(tid)
            if t is None:
                have = ", ".join(str(x.thread_id) for x in info.threads) or "none: the dump has no ThreadList"
                raise ThreadNotFoundError(f"thread {tid} is not in the dump (threads: {have})")
            chosen.append(t)
        return chosen, ""
    if args.all_threads:
        return list(info.threads), ""
    breakin = info.thread_id if info.has_exception and info.is_snapshot else None
    touching = [
        t
        for t in info.threads
        if t.thread_id != breakin and (target.contains(t.eip) or any(target.contains(w) for w in t.stack_words))
    ]
    touching_ids = {t.thread_id for t in touching}
    others = [t for t in info.threads if t.thread_id not in touching_ids]
    if touching:
        left = [str(t.thread_id) for t in others if t.thread_id != breakin]
        note = f"default selection: every thread whose eip or stack words are in {target.basename}"
        if breakin is not None:
            note += f"; break-in thread {breakin} not examined"
        if left:
            note += (
                f"; {len(left)} other threads have no address in the module (tids {', '.join(left)}); see --all-threads"
            )
        return touching, note
    if info.threads:
        return info.threads[:1], (
            f"no thread has an address in {target.basename}; showing ThreadList entry #0 only (see --all-threads)"
        )
    return [], "the dump has no ThreadList"


def _print_thread(
    pdb: Pdb,
    info: minidump.CrashInfo,
    t: minidump.ThreadInfo,
    target: minidump.Module,
    limit: int | None,
    stack_limit: int,
    brief_if_idle: bool,
) -> None:
    rvas = minidump.thread_stack_rvas(t, target, limit=None)
    in_eip = target.contains(t.eip)
    head = f"thread {t.thread_id} ({t.thread_id:#x}), ThreadList #{t.index}"
    if info.has_exception and t.thread_id == info.thread_id and info.is_snapshot:
        head += ", debugger break-in thread"
    if brief_if_idle and not in_eip and not rvas:
        print(f"== {head}: eip {t.eip:#x} {_module_note(info, t.eip)}; no stack word in {target.basename} ==")
        return
    print(f"== {head} ==")
    print("registers: " + " ".join(f"{n} {t.registers[n]:#x}" for n in minidump.REGISTER_ORDER if n in t.registers))
    print(f"eip {t.eip:#x} {_module_note(info, t.eip)}")
    if in_eip:
        print("-- eip (exact) --")
        print(format_resolution(pdb.resolve(t.eip - target.base), limit))
    scanned = len(t.stack_words)
    print(
        f"-- stack: scanned {scanned} of {t.stack_total_words} words from esp {t.esp:#x}; "
        f"{len(rvas)} point into {target.basename} (innermost first; heuristic scan, not an unwind; "
        "looked up at return address - 1) --"
    )
    seen: list[int] = []
    for rva in rvas[:stack_limit]:
        if rva in seen[-1:]:
            continue
        seen.append(rva)
        print(format_resolution(pdb.resolve(rva, AddressKind.RETURN_ADDRESS), limit))


def _warn_thread_list(info: minidump.CrashInfo, path: str) -> None:
    if info.thread_list_error:
        print(
            f"WARNING: {path}: ThreadList unusable ({info.thread_list_error}); skipped. "
            "Only the exception thread is available",
            file=sys.stderr,
        )


def _cmd_dump(args: argparse.Namespace) -> int:
    info = minidump.read_minidump(args.dump)
    _warn_thread_list(info, args.dump)
    print(minidump.format_report(info, args.module))
    target = info.find_module(args.module)
    if target is None:
        print(f"module {args.module} not found in dump", file=sys.stderr)
        return EXIT_NOT_FOUND
    threaded = bool(args.thread or args.all_threads or info.is_snapshot)
    selected: list[minidump.ThreadInfo] = []
    note = ""
    if threaded:
        selected, note = _select_threads(info, target, args)
    pdb, pe = _open_pdb(args.pdb, args.dll, allow_pdb_mismatch=args.allow_pdb_mismatch)
    with pdb:
        _check_build(target, pe, args.allow_build_mismatch)
        limit = None if args.all_candidates else 5
        print()
        if threaded:
            if note:
                print(f"# {note}")
            for t in selected:
                _print_thread(
                    pdb, info, t, target, limit, args.stack_limit, brief_if_idle=args.all_threads and not args.thread
                )
            return EXIT_OK
        fault = info.module_at(info.exception_address)
        if fault is target:
            print("== fault site ==")
            print(format_resolution(pdb.resolve(info.exception_address - target.base), limit))
        else:
            print(f"== fault is not inside {args.module} ({fault.name if fault else 'unknown module'}) ==")
        print("== stack (innermost first; heuristic scan, not an unwind; looked up at return address - 1) ==")
        seen: list[int] = []
        for rva in minidump.stack_rvas(info, target, limit=args.stack_limit):
            if rva in seen[-1:]:
                continue
            seen.append(rva)
            print(format_resolution(pdb.resolve(rva, AddressKind.RETURN_ADDRESS), limit))
    return EXIT_OK


def _cmd_compare(args: argparse.Namespace) -> int:
    infos = [minidump.read_minidump(p) for p in args.dumps]
    for p, info in zip(args.dumps, infos):
        _warn_thread_list(info, p)
    targets = []
    for p, info in zip(args.dumps, infos):
        m = info.find_module(args.module)
        if m is None:
            print(f"module {args.module} not found in dump {p}", file=sys.stderr)
            return EXIT_NOT_FOUND
        targets.append(m)
    if args.thread is not None:
        tids = [args.thread]
        for p, info in zip(args.dumps, infos):
            if info.thread(args.thread) is None:
                raise ThreadNotFoundError(f"thread {args.thread} is not in dump {p}")
    else:
        tids = [t.thread_id for t in infos[0].threads if all(i.thread(t.thread_id) for i in infos[1:])]
        if not tids:
            raise ThreadNotFoundError("no thread id is present in every dump (do the dumps have a ThreadList?)")
    labels = []
    for p in args.dumps:
        base = p.replace("\\", "/").rsplit("/", 1)[-1]
        labels.append(base)
    pdb, pe = _open_pdb(args.pdb, args.dll, allow_pdb_mismatch=args.allow_pdb_mismatch)
    with pdb:
        for m in targets:
            _check_build(m, pe, args.allow_build_mismatch)
        cache: dict[tuple[int, AddressKind], Resolution] = {}

        def resolve(rva: int, kind: AddressKind) -> Resolution:
            key = (rva, kind)
            if key not in cache:
                cache[key] = pdb.resolve(rva, kind)
            return cache[key]

        n = len(infos)
        print(f"== compare: {n} dumps, module {args.module} ==")
        for i, lab in enumerate(labels):
            kind = "hang/snapshot" if infos[i].is_snapshot else "crash"
            print(f"  [{i}] {lab} ({kind}, {len(infos[i].threads)} threads)")
        print(
            "# scan candidates: eip (exact) and stack words that look like return addresses "
            "(looked up at address - 1). NOT an unwind; stale stack residue is possible."
        )
        shown = idle = 0
        for tid in tids:
            per_dump = []
            for info, m in zip(infos, targets):
                t = info.thread(tid)
                if t is None:
                    raise ThreadNotFoundError(f"thread {tid} is not in every dump")
                eip = t.eip - m.base if m.contains(t.eip) else None
                per_dump.append((eip, minidump.thread_stack_rvas(t, m, limit=None)))
            ranked, unresolved = compare.rank_recurring(resolve, per_dump, min_dumps=min(args.min_dumps, n))
            if not ranked and not any(e is not None or r for e, r in per_dump):
                idle += 1
                continue
            shown += 1
            print(
                f"== thread {tid} ({tid:#x}): {len(ranked)} functions in at least {min(args.min_dumps, n)} of {n} dumps"
                f" ({unresolved} words resolved to no function) =="
            )
            for rec in ranked[: args.top]:
                print(compare.format_recurring(rec, n))
            if len(ranked) > args.top:
                print(f"  ... {len(ranked) - args.top} more (see --top)")
        if idle:
            print(f"# {idle} thread(s) had no address in {args.module} in any dump")
    return EXIT_OK


def _cmd_info(args: argparse.Namespace) -> int:
    pdb, _pe = _open_pdb(args.pdb, args.dll, names=False, allow_pdb_mismatch=args.allow_pdb_mismatch)
    with pdb:
        m = pdb.msf
        print(f"block size {m.block_size}, blocks {m.num_blocks}, streams {m.num_streams}")
        print(
            f"directory {m.dir_bytes} bytes in {m.num_dir_blocks} blocks; "
            f"block map spans {m.num_map_blocks} block(s) at {m.block_map_addr}"
        )
        print(f"machine {pdb.machine:#x}, modules {len(pdb.modules)}, contributions {len(pdb.contributions)}")
        if pdb.has_omap:
            print("OMAP streams present: names would not be printed by resolve/dump")
        for s in pdb.sections:
            print(f"  section {s.index} {s.name} va {s.virtual_address:#x} vsize {s.virtual_size:#x}")
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(
        prog="civ4dbg", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("resolve", help="resolve RVAs to function / source line")
    r.add_argument("--pdb", required=True)
    r.add_argument("--dll", help="optional: cross-check section table against the DLL PE headers")
    r.add_argument(
        "--return-address",
        action="store_true",
        help="treat the given RVAs as return addresses (look up RVA-1); default: exact",
    )
    r.add_argument(
        "--all-candidates",
        action="store_true",
        help="list every identical-code-folding candidate instead of the first 5",
    )
    r.add_argument("rva", nargs="+", type=_int)
    r.add_argument(
        "--allow-pdb-mismatch",
        action="store_true",
        help="continue when the PDB's GUID/age does not match the DLL's CodeView record",
    )
    r.set_defaults(func=_cmd_resolve)

    d = sub.add_parser("dump", help="read a minidump and resolve the fault site and stack")
    d.add_argument("--pdb", required=True)
    d.add_argument("--dll", help="the DLL of the crashing build: enables the build-match check")
    d.add_argument(
        "--module",
        default="CvGameCoreDLL.dll",
        help="file name of the module to resolve (case-insensitive, whole name)",
    )
    d.add_argument(
        "--stack-limit",
        type=_nonneg,
        default=20,
        help="max stack words reported (consecutive duplicates collapsed afterwards)",
    )
    d.add_argument(
        "--allow-build-mismatch",
        action="store_true",
        help="print names even when the dump and the DLL are different builds",
    )
    d.add_argument(
        "--all-candidates",
        action="store_true",
        help="list every identical-code-folding candidate instead of the first 5",
    )
    sel = d.add_mutually_exclusive_group()
    sel.add_argument(
        "--thread",
        type=_nonneg,
        action="append",
        metavar="TID",
        help="show this thread id instead of the default (repeatable); on a crash dump this replaces the fault report",
    )
    sel.add_argument(
        "--all-threads",
        action="store_true",
        help="show every thread in the ThreadList (threads with nothing in the module as one line)",
    )
    d.add_argument("dump")
    d.add_argument(
        "--allow-pdb-mismatch",
        action="store_true",
        help="continue when the PDB's GUID/age does not match the DLL's CodeView record",
    )
    d.set_defaults(func=_cmd_dump)

    c = sub.add_parser(
        "compare", help="rank the PDB functions that recur in a thread's stack scan across several dumps"
    )
    c.add_argument("--pdb", required=True)
    c.add_argument("--dll", help="the DLL of the build that was dumped: enables the build-match check")
    c.add_argument(
        "--module",
        default="CvGameCoreDLL.dll",
        help="file name of the module to resolve (case-insensitive, whole name)",
    )
    c.add_argument(
        "--thread",
        type=_nonneg,
        metavar="TID",
        help="compare this thread id only; default: every thread id present in all the dumps",
    )
    c.add_argument(
        "--min-dumps", type=_pos, default=2, help="list only functions seen in at least this many dumps (default 2)"
    )
    c.add_argument("--top", type=_pos, default=30, help="max functions listed per thread (default 30)")
    c.add_argument(
        "--allow-build-mismatch",
        action="store_true",
        help="print names even when a dump and the DLL are different builds",
    )
    c.add_argument(
        "--allow-pdb-mismatch",
        action="store_true",
        help="continue when the PDB's GUID/age does not match the DLL's CodeView record",
    )
    c.add_argument("dumps", nargs="+", metavar="dump")
    c.set_defaults(func=_cmd_compare)

    i = sub.add_parser("info", help="summarise the PDB container")
    i.add_argument("--pdb", required=True)
    i.add_argument("--dll")
    i.add_argument(
        "--allow-pdb-mismatch",
        action="store_true",
        help="continue when the PDB's GUID/age does not match the DLL's CodeView record",
    )
    i.set_defaults(func=_cmd_info)

    remote.add_exec_parser(sub)

    args = ap.parse_args(argv)
    if args.cmd == "compare" and len(args.dumps) < 2:
        ap.error("compare needs at least two dump files")
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    try:
        return args.func(args)
    except Civ4DbgError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return exc.exit_code
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except (struct.error, ValueError, IndexError, OverflowError, MemoryError) as exc:
        print(
            f"error: internal: unexpected {type(exc).__name__} on malformed input "
            f"(a bug in civ4dbg, please report): {exc}",
            file=sys.stderr,
        )
        return EXIT_INTERNAL


def run() -> None:
    """Console-script entry point: ``main`` returns the exit status."""
    sys.exit(main())


if __name__ == "__main__":
    run()
