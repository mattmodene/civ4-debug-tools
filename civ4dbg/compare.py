"""Compare several snapshot dumps: which PDB functions recur in a thread's stack scan.

Input per dump is the thread's eip (exact lookup) and its stack words that fall in
the module (return-address lookups). Output is ranked by how many dumps contain the
function, then by total hits. These are scan candidates: a stack word that happens
to look like a return address, possibly stale residue. It is not an unwind and says
nothing about call order. Standard library only.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass, field

from .pdb import AddressKind, Resolution

# One dump's evidence for one thread: (eip RVA if eip is in the module, stack RVAs).
DumpHits = tuple[int | None, list[int]]


@dataclass
class Recurring:
    """A function (or an identical-code-folding group of names) seen across dumps."""

    names: tuple[str, ...]  # sorted; more than one means ICF-ambiguous
    dumps: set[int] = field(default_factory=set)  # indices of dumps containing it
    eip_dumps: set[int] = field(default_factory=set)  # dumps where it is the eip's function
    hits: int = 0  # total occurrences over all dumps
    rvas: set[int] = field(default_factory=set)
    lines: set[str] = field(default_factory=set)  # "file:line" for unambiguous results

    @property
    def ambiguous(self) -> bool:
        return len(self.names) > 1


def rank_recurring(
    resolve: Callable[[int, AddressKind], Resolution],
    per_dump: Iterable[DumpHits],
    min_dumps: int = 2,
) -> tuple[list[Recurring], int]:
    """Rank functions by the number of dumps they appear in.

    Returns ``(ranked, unresolved)``; ``unresolved`` counts words that no function
    covers (they are not ranked). Ranking: dumps containing it (descending), total
    hits (descending), then name, so the order is deterministic.
    """
    table: dict[tuple[str, ...], Recurring] = {}
    unresolved = 0

    def add(idx: int, rva: int, kind: AddressKind, is_eip: bool) -> None:
        nonlocal unresolved
        res = resolve(rva, kind)
        if not res.candidates:
            unresolved += 1
            return
        key = tuple(sorted({c.name for c in res.candidates}))
        rec = table.setdefault(key, Recurring(key))
        rec.dumps.add(idx)
        if is_eip:
            rec.eip_dumps.add(idx)
        rec.hits += 1
        rec.rvas.add(rva)
        if res.file and not res.ambiguous:
            rec.lines.add(f"{res.file}:{res.line}")

    for idx, (eip_rva, rvas) in enumerate(per_dump):
        if eip_rva is not None:
            add(idx, eip_rva, AddressKind.EXACT, True)
        for rva in rvas:
            add(idx, rva, AddressKind.RETURN_ADDRESS, False)
    ranked = [r for r in table.values() if len(r.dumps) >= min_dumps]
    ranked.sort(key=lambda r: (-len(r.dumps), -r.hits, r.names))
    return ranked, unresolved


def format_recurring(rec: Recurring, n_dumps: int, max_names: int = 5) -> str:
    if rec.ambiguous:
        shown = " | ".join(rec.names[:max_names])
        more = f" (+{len(rec.names) - max_names} more)" if len(rec.names) > max_names else ""
        name = f"AMBIGUOUS({len(rec.names)}, identical code folding): {shown}{more}"
    else:
        name = rec.names[0]
    extra = ""
    if rec.eip_dumps:
        extra += f"  eip in {len(rec.eip_dumps)}"
    if rec.lines:
        lines = sorted(rec.lines)
        extra += "  " + ", ".join(lines[:3]) + (f" (+{len(lines) - 3})" if len(lines) > 3 else "")
    return f"  {len(rec.dumps)}/{n_dumps} dumps  hits {rec.hits:<4} {name}{extra}"
