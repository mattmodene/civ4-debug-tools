"""Reproduce the structural checks quoted in docs/llvm-diagnosis.md.

    python3 -I tools/check_pdb_claims.py --pdb PATH/CvGameCoreDLL.pdb [--dll PATH/CvGameCoreDLL.dll]

Prints one line per claim with the measured figures (PASS, FAIL, or INFO for a
figure that is reported but is not a pass/fail claim). It reads PDB streams and,
when ``--dll`` is given, the DLL's PE headers (section table), nothing else.
Exit status is 0 when no check FAILs, 1 otherwise.

Independence: the checks reuse this repository's own MSF parser, so they show the
file is consistent *as this parser reads it*, not that an independent reader
agrees. What it does NOT reproduce (see the document): the pdbparse cross-check
(needs a third-party package that does not install on current Pythons) and
LLVM's own behaviour (the condition in LLVM's source is quoted in the document,
not run here).

It reads a few private attributes of the MSF object (``_block``, ``_streams``)
on purpose: it audits the container layout, which the public API hides.
"""

from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from civ4dbg.msf import NIL_STREAM, OpenedMsf  # noqa: E402
from civ4dbg.pdb import Pdb  # noqa: E402
from civ4dbg.pe import compare_sections, read_pe_headers  # noqa: E402


def check_block_map(msf) -> tuple[bool, str]:
    need = msf.num_dir_blocks * 4
    # The block-count formula is the parser's own, so only the placement is a real check.
    ok = msf.block_map_addr + msf.num_map_blocks <= msf.num_blocks
    return ok, (
        f"directory {msf.dir_bytes} bytes = {msf.num_dir_blocks} blocks of {msf.block_size}; "
        f"block map needs {need} bytes = {msf.num_map_blocks} block(s) "
        f"(a one-block map would hold {msf.block_size // 4} directory blocks); "
        f"{msf.num_streams} streams; directory consumed exactly (checked at open)"
    )


def used_blocks(msf) -> tuple[dict[int, str], list[str]]:
    """Map block -> owner, plus any block claimed twice."""
    owner: dict[int, str] = {}
    clashes: list[str] = []

    def claim(block: int, who: str) -> None:
        if block in owner:
            clashes.append(f"block {block}: {owner[block]} and {who}")
        else:
            owner[block] = who

    claim(0, "superblock")
    for k in range(-(-msf.num_blocks // msf.block_size)):
        for fpm in (1, 2):
            b = k * msf.block_size + fpm
            if b < msf.num_blocks:
                claim(b, "free-block-map")
    for i in range(msf.num_map_blocks):
        claim(msf.block_map_addr + i, "block map")
    map_bytes = b"".join(msf._block(msf.block_map_addr + i) for i in range(msf.num_map_blocks))
    import struct

    for b in struct.unpack_from(f"<{msf.num_dir_blocks}I", map_bytes):
        claim(b, "directory")
    for s, (size, blocks) in enumerate(msf._streams):
        if size == NIL_STREAM:
            continue
        for b in blocks:
            claim(b, f"stream {s}")
    return owner, clashes


def check_disjoint(msf) -> tuple[bool, str]:
    owner, clashes = used_blocks(msf)
    return not clashes, (
        f"{len(owner)} distinct blocks claimed by the superblock, free-block maps, block map, "
        f"directory and streams; {len(clashes)} claimed twice" + (f" (first: {clashes[0]})" if clashes else "")
    )


def check_stale_free_map(msf) -> tuple[bool | None, str]:
    """Blocks that are in use but marked free in the active free-block map."""
    owner, _ = used_blocks(msf)
    interval = msf.block_size  # one FPM block per interval of block_size blocks
    n_int = -(-msf.num_blocks // interval)
    raw = b"".join(msf._block(msf.free_block_map + k * interval) for k in range(n_int))
    raw = raw[: -(-msf.num_blocks // 8)]
    marked_free = [b for b in owner if raw[b // 8] >> (b % 8) & 1]
    return None, (
        f"active free-block map is block {msf.free_block_map}; {len(marked_free)} of "
        f"{len(owner)} in-use blocks are marked free in it (informational: not a pass/fail claim)"
    )


def check_dbi_and_publics(pdb: Pdb) -> tuple[bool, str]:
    pubs = {(p.section, p.offset) for p in pdb.publics()}
    g = n_local = missing = 0
    for m in range(len(pdb.modules)):
        for p in pdb.module_procs(m):
            if p.kind == "S_GPROC32":
                g += 1
                if (p.section, p.offset) not in pubs:
                    missing += 1
            elif p.kind == "S_LPROC32":
                n_local += 1
    return missing == 0, (
        f"DBI substream sizes sum to the stream length (checked at open); {g} S_GPROC32 records, "
        f"{missing} without an S_PUB32 at the same section:offset; {n_local} S_LPROC32 records"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pdb", required=True)
    ap.add_argument("--dll")
    args = ap.parse_args()
    for label, given in (("--pdb", args.pdb), ("--dll", args.dll)):
        if given and not pathlib.Path(given).is_file():
            print(
                f"error: {label} {given} does not exist. This tool needs a real CvGameCoreDLL.pdb (and optionally "
                "its DLL), which are not part of this repository; supply your own copy.",
                file=sys.stderr,
            )
            return 2
    results = []
    with OpenedMsf(args.pdb) as msf:
        size_ok = msf.num_blocks * msf.block_size == pathlib.Path(args.pdb).stat().st_size
        results.append(
            (
                "file size == NumBlocks * BlockSize",
                size_ok,
                f"{pathlib.Path(args.pdb).stat().st_size} bytes; {msf.num_blocks} blocks x {msf.block_size}",
            )
        )
        results.append(("block map and directory arithmetic", *check_block_map(msf)))
        results.append(("blocks pairwise disjoint", *check_disjoint(msf)))
        results.append(("free-block map vs in-use blocks", *check_stale_free_map(msf)))
        pdb = Pdb(msf)
        results.append(("DBI sums, GPROC32 has a PUB32", *check_dbi_and_publics(pdb)))
        results.append(("OMAP streams absent", not pdb.has_omap, f"has_omap={pdb.has_omap}"))
        if args.dll:
            pe = read_pe_headers(args.dll)
            diffs = compare_sections(pdb.sections, pe.sections)
            results.append(
                (
                    "PDB section table == DLL PE table",
                    not diffs,
                    f"{len(pdb.sections)} sections; differences: {diffs or 'none'}",
                )
            )
    for name, ok, detail in results:
        print(f"{'INFO' if ok is None else 'PASS' if ok else 'FAIL'}  {name}: {detail}")
    return 0 if all(ok is not False for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
