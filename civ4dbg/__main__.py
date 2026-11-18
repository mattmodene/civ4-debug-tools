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
from collections.abc import Callable

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
    if args.crash_thread:
        return _compare_crash_threads(args, infos, targets)
    if args.thread is not None:
        tids = [args.thread]
        for p, info in zip(args.dumps, infos):
            if info.thread(args.thread) is None:
                raise ThreadNotFoundError(f"thread {args.thread} is not in dump {p}")
    else:
        tids = [t.thread_id for t in infos[0].threads if all(i.thread(t.thread_id) for i in infos[1:])]
        if not tids:
            raise ThreadNotFoundError("no thread id is present in every dump (do the dumps have a ThreadList?)")
    labels = _dump_labels(args.dumps)
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
        # Threads carrying module addresses whose id is not in every dump: never compared by id.
        unmatched: list[list[int]] = []
        if args.thread is None:
            unmatched = [
                [t.thread_id for t in info.threads if t.thread_id not in tids and _carries_module_addresses(t, m)]
                for info, m in zip(infos, targets)
            ]
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
        if args.thread is not None and not shown:
            raise ThreadNotFoundError(
                f"thread {args.thread} has no address in {args.module} in any of the {n} dumps, so nothing was "
                "compared; run `civ4dbg dump --thread` on a dump to see where that thread was"
            )
        if any(unmatched):
            if not shown:
                raise ThreadNotFoundError(_no_common_module_thread_message(args.module, labels, unmatched, infos))
            print(
                f"# thread(s) with addresses in {args.module} that are not in every dump were left out: "
                + _format_unmatched(labels, unmatched)
            )
        if idle and not shown:
            print(f"# none of the {n} dumps has a thread with an address in {args.module}")
        elif idle:
            print(f"# {idle} thread(s) had no address in {args.module} in any dump")
    return EXIT_OK


def _dump_labels(paths: list[str]) -> list[str]:
    return [p.replace("\\", "/").rsplit("/", 1)[-1] for p in paths]


def _has_crash_thread(info: minidump.CrashInfo) -> bool:
    """True when the dump records a real exception (not a debugger break-in) and so names a crashing thread."""
    return info.has_exception and not info.is_snapshot


def _crash_thread_evidence(info: minidump.CrashInfo, m: minidump.Module) -> tuple[int | None, list[int]]:
    """(eip RVA if in the module, module stack RVAs) for the exception thread of one dump.

    Uses the ThreadList entry of the exception thread when there is one, else the exception record's
    own context and stack. When both exist they are two captures of the same thread (the record's context
    is the thread's at the fault); this deliberately prefers the ThreadList entry, as ``compare`` does for
    every other thread, so the stack words come from one source for all threads. The two are not
    cross-checked, and the choice is not shown in the output.
    """
    t = info.thread(info.thread_id)
    if t is not None:
        eip, stack = t.eip, minidump.thread_stack_rvas(t, m, limit=None)
    else:
        eip, stack = info.eip, minidump.stack_rvas(info, m, limit=None)
    return (eip - m.base if m.contains(eip) else None), stack


def _frame_keys(
    resolve: Callable[[int, AddressKind], Resolution], evidence: tuple[int | None, list[int]]
) -> list[tuple[str, ...] | None]:
    """The scan's leading-to-trailing frames as function-name keys (None: no function covers it).

    Frames are the exact-eip function (only when eip is in the module) followed by the module stack words in
    stack order with consecutive repeats collapsed. They are positional scan candidates, not an unwind, so
    the agreement count compares position by position and can pair an eip frame with a return-address frame.
    """
    eip, stack = evidence
    frames: list[tuple[str, ...] | None] = []
    seen: list[int] = []
    if eip is not None:
        frames.append(_key(resolve(eip, AddressKind.EXACT)))
    for rva in stack:
        if rva in seen[-1:]:
            continue
        seen.append(rva)
        frames.append(_key(resolve(rva, AddressKind.RETURN_ADDRESS)))
    return frames


def _key(res: Resolution) -> tuple[str, ...] | None:
    return tuple(sorted({c.name for c in res.candidates})) or None


def _leading_agreement(per_dump: list[list[tuple[str, ...] | None]]) -> int:
    """How many leading frames name the same function in every dump (stops at the first difference or gap).

    A limited signal: stale stack residue, identical-code folding (equal candidate sets only) and the
    positional pairing noted in :func:`_frame_keys` all bear on it. It never proves a common root cause.
    """
    n = 0
    for frames in zip(*per_dump):
        if frames[0] is None or any(f != frames[0] for f in frames):
            break
        n += 1
    return n


def _compare_crash_threads(args: argparse.Namespace, infos: list[minidump.CrashInfo], targets: list) -> int:
    """``compare --crash-thread``: the exception thread of every dump, matched by role and not by id."""
    labels = _dump_labels(args.dumps)
    for lab, info in zip(labels, infos):
        if not _has_crash_thread(info):
            if not info.has_exception:
                why = "has no exception record"
            else:
                why = (
                    f"records only a breakpoint exception ({info.exception_code:#x}), which is taken for a debugger "
                    "break-in; a genuine breakpoint or assert crash is refused too, and `civ4dbg dump` shows the record"
                )
            raise ThreadNotFoundError(
                f"--crash-thread needs a crash dump with an exception record in every dump, but {lab} {why}"
            )
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
        min_dumps = min(args.min_dumps, n)
        print(f"== compare: {n} dumps, module {args.module}, exception threads matched by role (not by thread id) ==")
        faults: list[tuple[int, tuple]] = []
        idents: list[tuple | None] = []  # build identity of the faulting module, None when the fault is in none
        for i, (lab, info, m) in enumerate(zip(labels, infos, targets)):
            addr = info.exception_address
            fault_mod = info.module_at(addr)
            if fault_mod is None:
                where = f"{addr:#x} (in no listed module)"
                fault_key: tuple = ("raw", addr)
                idents.append(None)
            else:
                where = f"{fault_mod.basename}+{addr - fault_mod.base:#x}"
                fault_key = ("module", fault_mod.basename.lower(), addr - fault_mod.base)
                idents.append((fault_mod.basename.lower(), fault_mod.timestamp, fault_mod.size, fault_mod.cv_id))
            if fault_mod is m:
                res = resolve(addr - m.base, AddressKind.EXACT)
                if res.function:
                    where += f" ({res.function})"
                elif res.candidates:
                    where += f" ({len(res.candidates)} candidate functions, identical code folding)"
            faults.append((info.exception_code, fault_key))
            pid = f", process {info.process_id}" if info.process_id is not None else ""
            print(f"  [{i}] {lab}: exception {info.exception_code:#x} at {where}, thread {info.thread_id}{pid}")
        print(
            "# scan candidates: eip (exact) and stack words that look like return addresses "
            "(looked up at address - 1). NOT an unwind; stale stack residue is possible."
        )
        evidence = [_crash_thread_evidence(info, m) for info, m in zip(infos, targets)]
        ranked, unresolved = compare.rank_recurring(resolve, evidence, min_dumps=min_dumps)
        print(
            f"== exception threads: {len(ranked)} functions in at least {min_dumps} of {n} dumps"
            f" ({unresolved} words resolved to no function) =="
        )
        for rec in ranked[: args.top]:
            print(compare.format_recurring(rec, n))
        if len(ranked) > args.top:
            print(f"  ... {len(ranked) - args.top} more (see --top)")
        if not any(e is not None or r for e, r in evidence):
            print(f"# no exception thread has an address in {args.module}")
        same_code = len({c for c, _ in faults}) == 1
        same_site = len({k for _, k in faults}) == 1
        outside = [i for i, (_, k) in enumerate(faults) if k[0] == "raw"]
        agree = _leading_agreement([_frame_keys(resolve, ev) for ev in evidence])
        # The faulting module's build is compared across the dumps themselves (name, TimeDateStamp, SizeOfImage,
        # and the CodeView GUID/age where the dumps carry one), with or without --dll: module+offset from two
        # different builds is not comparable. A missing CodeView record is unknown, not a difference.
        builds_same: bool | None = None
        if all(x is not None for x in idents) and len({x[0] for x in idents}) == 1:
            cvs = {x[3] for x in idents if x[3] is not None}
            builds_same = len({(x[1], x[2]) for x in idents}) == 1 and len(cvs) <= 1
        code_txt = (
            f"identical ({faults[0][0]:#x})"
            if same_code
            else "DIFFERS (" + ", ".join(f"{c:#x}" for c in dict.fromkeys(c for c, _ in faults)) + ")"
        )
        if outside and same_site:
            site_txt = (
                "not comparable (the fault address is in no listed module in any dump; the raw addresses are equal)"
            )
        else:
            site_txt = "identical" if same_site else "DIFFERS"
        n_no_cv = sum(1 for x in idents if x is not None and x[3] is None)
        build_txt = (
            ""
            if builds_same is None
            else ("; faulting module build identical" if builds_same else "; faulting module builds DIFFER")
        )
        print(
            f"# evidence: exception code {code_txt}; faulting module+offset {site_txt}{build_txt}; "
            f"{agree} leading scan frame(s) resolve to the same function in all {n} dumps."
        )
        if builds_same is not None and n_no_cv:
            print(
                "# the module build comparison rests on timestamp and size"
                + (" only" if n_no_cv == n else ", plus the CodeView id where available")
                + f"; the CodeView id is unavailable in {n_no_cv} of {n} dump(s)."
            )
        if not (same_code and same_site):
            print(
                "# the dumps differ in exception code or faulting module+offset: do not treat them as the same crash."
            )
        elif outside:
            print(
                "# the fault address is in no listed module, so it is not comparable as module+offset; "
                "nothing is said about whether this is the same crash."
            )
        elif builds_same is False:
            print(
                "# the faulting module is a different build in some dumps (timestamp, size or signature differ), "
                "so module+offset is not comparable; nothing is said about whether this is the same crash."
            )
        else:
            print(
                "# the dumps agree on exception code and faulting module+offset, consistent with the same crash. "
                "Agreeing frames are scan candidates, not an unwind, and do not establish an identical root cause."
            )
        # With three or more dumps, say which ones are the odd ones out (against the most common value).
        odd = []
        for what, values, differs in (
            ("exception code", [c for c, _ in faults], not same_code),
            ("module+offset", [k for _, k in faults], not same_site),
            ("module build", _build_keys(idents), builds_same is False),
        ):
            if differs:
                odd.append(f"{what} in {_name_dumps(_outliers(values), labels)}")
        if odd and n > 2:
            print("# differs from the most common value (the first dump's on a tie): " + "; ".join(odd))
    return EXIT_OK


def _build_keys(idents: list) -> list:
    """Per-dump build keys for the outlier line, by the same rule as the build check: a missing CodeView id
    is unknown, not a difference, so it takes the most common id that is present (the earliest on a tie)."""
    present = [x[3] for x in idents if x is not None and x[3] is not None]
    fill = max(present, key=present.count) if present else None
    return [None if x is None else (x[0], x[1], x[2], x[3] if x[3] is not None else fill) for x in idents]


def _outliers(values: list) -> list[int]:
    """Indices of the entries that differ from the most common value (the earliest value on a tie)."""
    counts: dict = {}
    for v in values:
        counts[repr(v)] = counts.get(repr(v), 0) + 1
    best = max(counts.values())
    ref = next(repr(v) for v in values if counts[repr(v)] == best)
    return [i for i, v in enumerate(values) if repr(v) != ref]


def _name_dumps(indices: list[int], labels: list[str], cap: int = 5) -> str:
    text = ", ".join(f"[{i}] {labels[i]}" for i in indices[:cap])
    if len(indices) > cap:
        text += f", ... and {len(indices) - cap} more"
    return text


def _carries_module_addresses(thread: minidump.ThreadInfo, module: minidump.Module) -> bool:
    return module.contains(thread.eip) or bool(minidump.thread_stack_rvas(thread, module, limit=None))


_UNMATCHED_ID_CAP = 10


def _format_ids(tids: list[int]) -> str:
    text = ", ".join(str(t) for t in tids[:_UNMATCHED_ID_CAP])
    if len(tids) > _UNMATCHED_ID_CAP:
        text += f", ... and {len(tids) - _UNMATCHED_ID_CAP} more"
    return text


def _format_unmatched(labels: list[str], unmatched: list[list[int]]) -> str:
    return "; ".join(
        f"[{i}] {lab}: {_format_ids(tids)}" for i, (lab, tids) in enumerate(zip(labels, unmatched)) if tids
    )


def _no_common_module_thread_message(
    module: str, labels: list[str], unmatched: list[list[int]], infos: list[minidump.CrashInfo]
) -> str:
    pids = [info.process_id for info in infos]
    if all(p is not None for p in pids) and len(set(pids)) > 1:
        cause = (
            "the dumps come from different processes (process ids "
            + "; ".join(f"[{i}] {lab}: {p}" for i, (lab, p) in enumerate(zip(labels, pids)))
            + "), and thread ids differ per process; compare matches threads by id only.\n"
        )
    else:
        cause = (
            "this is typical when the dumps were taken from separate runs of the process, because thread ids "
            "differ per run; compare matches threads by id only.\n"
        )
    hint = ""
    if all(_has_crash_thread(info) for info in infos):
        hint = (
            "every dump has an exception record: to compare the exception (crashing) thread of each dump "
            "regardless of thread id, rerun with --crash-thread.\n"
        )
    return (
        f"no thread carrying addresses in {module} is common to all the dumps, so nothing was compared.\n"
        f"threads with {module} addresses that are not present in every dump (thread ids): "
        + _format_unmatched(labels, unmatched)
        + "\n"
        + cause
        + hint
        + "run `civ4dbg dump` on each dump to inspect it on its own."
    )


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
    which = c.add_mutually_exclusive_group()
    which.add_argument(
        "--thread",
        type=_nonneg,
        metavar="TID",
        help="compare this thread id only; default: every thread id present in all the dumps",
    )
    which.add_argument(
        "--crash-thread",
        action="store_true",
        help="compare the exception (crashing) thread of each crash dump, whatever its thread id "
        "(for dumps of one crash taken in separate runs); cannot be combined with --thread",
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
