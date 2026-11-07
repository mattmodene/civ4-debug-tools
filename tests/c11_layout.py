"""Byte-exact builder for the old-style (C11, ``sstSrcModule``) line block.

Independent of ``synth.c11_lines`` (which writes a reduced header). This one
writes the full published layout, and was checked against real data: the
real-data integration test rebuilds every C11 block of the real Caveman2Cosmos
PDB from its decoded values and requires byte equality.

Layout (all little-endian, every sub-record 4-byte aligned)::

    SrcModule:  u16 cFile, u16 cSeg,
                u32 baseSrcFile[cFile],        # offsets from the block start
                u32 startEnd[cSeg][2],         # module-wide ranges, end INCLUSIVE
                u16 seg[cSeg], (pad to 4)
    SrcFile:    u16 cSeg, u16 pad,
                u32 baseSrcLn[cSeg],           # offsets from the block start
                u32 startEnd[cSeg][2],         # end INCLUSIVE
                char name[] NUL-terminated, (pad to 4)
    SrcLn:      u16 seg, u16 cPair,
                u32 offset[cPair],             # section offsets, absolute
                u16 line[cPair], (pad to 4)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field


@dataclass
class Table:
    seg: int
    start: int
    end_inclusive: int
    pairs: list[tuple[int, int]] = field(default_factory=list)  # (section offset, line)


@dataclass
class SrcFile:
    name: str
    tables: list[Table]


def _pad4(n: int) -> int:
    return -n % 4


def build_c11(files: list[SrcFile], module_ranges: list[tuple[int, int, int]] | None = None) -> bytes:
    """``module_ranges`` = (seg, start, end_inclusive); derived from the tables if None."""
    if module_ranges is None:
        spans: dict[int, list[int]] = {}
        for f in files:
            for t in f.tables:
                lo, hi = spans.setdefault(t.seg, [t.start, t.end_inclusive])
                spans[t.seg] = [min(lo, t.start), max(hi, t.end_inclusive)]
        module_ranges = [(seg, lo, hi) for seg, (lo, hi) in sorted(spans.items())]
    c_seg = len(module_ranges)
    head_len = 4 + 4 * len(files) + 8 * c_seg + 2 * c_seg
    head_len += _pad4(head_len)
    body = b""
    file_offsets: list[int] = []
    for f in files:
        file_offsets.append(head_len + len(body))
        n = len(f.tables)
        entry_len = 4 + 4 * n + 8 * n + len(f.name.encode()) + 1
        entry_len += _pad4(entry_len)
        table_blobs: list[bytes] = []
        offsets: list[int] = []
        cursor = head_len + len(body) + entry_len
        for t in f.tables:
            blob = struct.pack("<HH", t.seg, len(t.pairs))
            blob += b"".join(struct.pack("<I", o) for o, _ in t.pairs)
            blob += b"".join(struct.pack("<H", ln) for _, ln in t.pairs)
            blob += b"\0" * _pad4(len(blob))
            offsets.append(cursor)
            cursor += len(blob)
            table_blobs.append(blob)
        entry = struct.pack("<HH", n, 0)
        entry += b"".join(struct.pack("<I", o) for o in offsets)
        entry += b"".join(struct.pack("<II", t.start, t.end_inclusive) for t in f.tables)
        entry += f.name.encode() + b"\0"
        entry += b"\0" * _pad4(len(entry))
        assert len(entry) == entry_len
        body += entry + b"".join(table_blobs)
    head = struct.pack("<HH", len(files), c_seg)
    head += b"".join(struct.pack("<I", o) for o in file_offsets)
    head += b"".join(struct.pack("<II", s, e) for _, s, e in module_ranges)
    head += b"".join(struct.pack("<H", seg) for seg, _, _ in module_ranges)
    head += b"\0" * _pad4(len(head))
    assert len(head) == head_len
    return head + body


def decode_c11(block: bytes) -> list[SrcFile]:
    """Straightforward reference decoder used only to feed ``build_c11`` real data."""
    c_file, _c_seg = struct.unpack_from("<HH", block, 0)
    out = []
    for fo in struct.unpack_from(f"<{c_file}I", block, 4):
        n, _pad = struct.unpack_from("<HH", block, fo)
        lns = struct.unpack_from(f"<{n}I", block, fo + 4)
        rng = struct.unpack_from(f"<{2 * n}I", block, fo + 4 + 4 * n)
        end = block.index(b"\0", fo + 4 + 12 * n)
        name = block[fo + 4 + 12 * n : end].decode("latin-1")
        tables = []
        for i, ln in enumerate(lns):
            seg, cnt = struct.unpack_from("<HH", block, ln)
            offs = struct.unpack_from(f"<{cnt}I", block, ln + 4)
            nums = struct.unpack_from(f"<{cnt}H", block, ln + 4 + 4 * cnt)
            tables.append(Table(seg, rng[2 * i], rng[2 * i + 1], list(zip(offs, nums))))
        out.append(SrcFile(name, tables))
    return out
