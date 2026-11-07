"""Builders for synthetic MSF / PDB / minidump / PE bytes used by the tests.

Everything here is test scaffolding: it writes the structures the parsers read,
following the public format descriptions, so the parsers can be exercised
without any real game file.
"""

from __future__ import annotations

import random
import struct

from civ4dbg.msf import MAGIC


def build_msf(streams: list[bytes | None], block_size: int = 512, seed: int = 1234) -> bytes:
    """Serialise ``streams`` as an MSF 7.00 file with a scrambled block layout.

    ``None`` makes a nil stream. Block numbers are shuffled so that a reader
    which assumes contiguous streams or a contiguous directory fails.
    """
    # Fixed-point: directory size depends on block count which depends on dir size.
    sizes = [0xFFFFFFFF if s is None else len(s) for s in streams]
    blocks_per = [0 if s is None else -(-len(s) // block_size) for s in streams]
    dir_bytes = 4 + 4 * len(streams) + 4 * sum(blocks_per)
    n_dir_blocks = -(-dir_bytes // block_size)
    n_map_blocks = -(-n_dir_blocks * 4 // block_size)
    total_data = sum(blocks_per)
    # Block 0 super, 1/2 free-block maps (and every block_size stride), map, dir, data.
    needed = 3 + n_map_blocks + n_dir_blocks + total_data
    num_blocks = needed + needed // block_size * 2 + 4
    reserved = {0}
    for b in range(num_blocks):
        if b % block_size in (1, 2):
            reserved.add(b)
    free = [b for b in range(num_blocks) if b not in reserved]
    map_start = free[0]
    # The block map must be consecutive blocks starting at map_start.
    map_blocks = list(range(map_start, map_start + n_map_blocks))
    for b in map_blocks:
        assert b not in reserved, "block map would cross a free-block-map block"
    rest = [b for b in free if b not in set(map_blocks)]
    random.Random(seed).shuffle(rest)
    dir_blocks = rest[:n_dir_blocks]
    data_pool = rest[n_dir_blocks:]
    directory = struct.pack("<I", len(streams)) + struct.pack(f"<{len(streams)}I", *sizes)
    image = bytearray(num_blocks * block_size)
    cursor = 0
    for s, n in zip(streams, blocks_per):
        mine = data_pool[cursor : cursor + n]
        cursor += n
        directory += struct.pack(f"<{n}I", *mine)
        for i, b in enumerate(mine):
            chunk = s[i * block_size : (i + 1) * block_size]  # type: ignore[index]
            image[b * block_size : b * block_size + len(chunk)] = chunk
    assert len(directory) == dir_bytes
    for i, b in enumerate(dir_blocks):
        chunk = directory[i * block_size : (i + 1) * block_size]
        image[b * block_size : b * block_size + len(chunk)] = chunk
    map_bytes = struct.pack(f"<{n_dir_blocks}I", *dir_blocks)
    for i, b in enumerate(map_blocks):
        chunk = map_bytes[i * block_size : (i + 1) * block_size]
        image[b * block_size : b * block_size + len(chunk)] = chunk
    struct.pack_into("<6I", image, 32, block_size, 1, num_blocks, dir_bytes, 0, map_start)
    image[0:32] = MAGIC
    return bytes(image)


def section_header(name: str, vsize: int, vaddr: int, rsize: int = 0, rptr: int = 0, chars: int = 0x60000020) -> bytes:
    """``chars`` defaults to code | execute | read; pass 0xC0000040 for data."""
    return struct.pack("<8sIIIIIIHHI", name.encode(), vsize, vaddr, rsize, rptr, 0, 0, 0, 0, chars)


def _align4(b: bytes) -> bytes:
    return b + b"\0" * (-len(b) % 4)


def sym(kind: int, payload: bytes) -> bytes:
    body = struct.pack("<H", kind) + payload
    body += b"\0" * (-(len(body) + 2) % 4)
    return struct.pack("<H", len(body)) + body


def pub32(name: str, seg: int, off: int, function: bool = True) -> bytes:
    return sym(0x110E, struct.pack("<IIH", 2 if function else 0, off, seg) + name.encode() + b"\0")


def proc32(kind: int, name: str, seg: int, off: int, length: int) -> bytes:
    return sym(
        kind,
        struct.pack("<7I", 0, 0, 0, length, 0, 0, 0x1001) + struct.pack("<IHB", off, seg, 0) + name.encode() + b"\0",
    )


def c11_lines(files: list[tuple[str, int, int, int, list[tuple[int, int]]]]) -> bytes:
    """Old-style line block. files = (name, seg, start, end_inclusive, [(off, line)])."""
    n = len(files)
    head = struct.pack("<HH", n, 0)
    table_len = 4 + 4 * n
    bodies, offsets, pos = [], [], table_len
    for name, seg, start, end, entries in files:
        lt = struct.pack("<HH", seg, len(entries))
        lt += b"".join(struct.pack("<I", o) for o, _ in entries)
        lt += b"".join(struct.pack("<H", ln) for _, ln in entries)
        lt = _align4(lt)
        fe_len = 4 + 4 + 8 + len(name) + 1
        lt_off = pos + len(_align4(b"x" * fe_len))
        fe = struct.pack("<HH", 1, 0) + struct.pack("<I", lt_off) + struct.pack("<II", start, end)
        fe = _align4(fe + name.encode() + b"\0")
        offsets.append(pos)
        bodies.append(fe + lt)
        pos += len(fe) + len(lt)
    return head + struct.pack(f"<{n}I", *offsets) + b"".join(bodies)


def c13_lines(seg: int, base: int, length: int, file_name_off: int, entries: list[tuple[int, int]]) -> bytes:
    """C13 subsections: FILECHKSMS (one file) + LINES (one block)."""
    chk = struct.pack("<IBB", file_name_off, 0, 0)
    chk = _align4(chk + b"\0\0")
    out = struct.pack("<II", 0xF4, len(chk)) + chk
    lines = struct.pack("<IHHI", base, seg, 0, length)
    lines += struct.pack("<III", 0, len(entries), 12 + 8 * len(entries))
    for o, ln in entries:
        lines += struct.pack("<II", o, ln | 0x80000000)
    out += struct.pack("<II", 0xF2, len(lines)) + _align4(lines)
    return out


def module_stream(symbols: bytes, c11: bytes = b"", c13: bytes = b"") -> tuple[bytes, int]:
    syms = struct.pack("<I", 4) + symbols
    return syms + c11 + c13 + struct.pack("<I", 0), len(syms)


def modinfo(name: str, stream: int, sym_bytes: int, c11: int, c13: int) -> bytes:
    sc = struct.pack("<HHiiIHHII", 1, 0, 0, 0, 0, 0, 0, 0, 0)
    rec = struct.pack("<I", 0) + sc
    rec += struct.pack("<HHIIIHHIII", 0, stream, sym_bytes, c11, c13, 1, 0, 0, 0, 0)
    assert len(rec) == 64
    rec += name.encode() + b"\0" + name.encode() + b"\0"
    return _align4(rec)


def build_pdb(
    sections: list[bytes],
    publics: bytes,
    modules: list[tuple[str, bytes, int, int, int]],
    contributions: list[tuple[int, int, int, int]],
    names: bytes = b"",
    block_size: int = 512,
    extra_streams: int = 0,
    omap: bool = False,
) -> bytes:
    """Assemble a tiny PDB: stream 0 old dir, 1 info, 2 TPI, 3 DBI, then data.

    ``omap=True`` points the OMAP-to-source slot at a stream.

    modules = (name, module-stream bytes, sym_bytes, c11_size, c13_size).
    contributions = (section, offset, size, module index).
    """
    streams: list[bytes | None] = [b"", b"", b"", b""]
    # stream 4: section headers, 5: names, 6: symrec, 7: publics(unused body)
    streams.append(b"".join(sections))
    names_stream = struct.pack("<III", 0xEFFEEFFE, 1, len(names)) + names
    streams.append(names_stream)
    streams.append(publics)
    streams.append(b"\0" * 16)
    mod_info = b""
    for name, data, sb, c11, c13 in modules:
        streams.append(data)
        mod_info += modinfo(name, len(streams) - 1, sb, c11, c13)
    sc = struct.pack("<I", 0xF12EBA2D)
    for sec, off, size, mod in contributions:
        sc += struct.pack("<HHiiIHHII", sec, 0, off, size, 0, mod, 0, 0, 0)
    opt = struct.pack("<11H", *([0xFFFF] * 11))
    opt = bytearray(opt)
    struct.pack_into("<H", opt, 5 * 2, 4)  # slot 5 = section headers -> stream 4
    if omap:
        struct.pack_into("<H", opt, 3 * 2, 7)  # slot 3 = OMAP to source -> stream 7
    dbi = (
        struct.pack(
            "<iIIHHHHHHiiiiiIiiHHI",
            -1,
            19990903,
            1,
            0xFFFF,
            0,
            7,
            0,
            6,
            0,
            len(mod_info),
            len(sc),
            0,
            0,
            0,
            0,
            len(opt),
            0,
            0,
            0x14C,
            0,
        )
        + mod_info
        + sc
        + bytes(opt)
    )
    streams[3] = dbi
    # info stream: version, sig, age, GUID, string buffer with "/names", hash table
    buf = b"/names\0"
    info = struct.pack("<III", 20000404, 1, 1) + b"\0" * 16
    info += struct.pack("<I", len(buf)) + buf
    info += struct.pack("<II", 1, 4)  # size, capacity
    info += struct.pack("<II", 1, 1)  # present bitvector: 1 word, bit 0
    info += struct.pack("<I", 0)  # deleted bitvector: 0 words
    info += struct.pack("<II", 0, 5)  # key offset 0 -> stream 5
    streams[1] = info
    for _ in range(extra_streams):
        streams.append(b"")
    return build_msf(streams, block_size)


# Independent copy of the winnt.h x86 CONTEXT layout (the test must not import the reader's table).
CTX_X86_OFFSETS = {
    "edi": 0x9C,
    "esi": 0xA0,
    "ebx": 0xA4,
    "edx": 0xA8,
    "ecx": 0xAC,
    "eax": 0xB0,
    "ebp": 0xB4,
    "eip": 0xB8,
    "eflags": 0xC0,
    "esp": 0xC4,
}


def build_minidump(
    modules: list[tuple],
    exc_code: int,
    exc_addr: int,
    access: tuple[int, int] | None,
    eip: int,
    stack_words: list[int],
    arch: int | None = None,
    ctx_size: int | None = None,
    registers: dict[str, int] | None = None,
) -> bytes:
    """A minimal x86 minidump with module list, one stack region and an exception.

    ``modules`` are ``(base, size, name)`` or ``(base, size, name, timestamp)``.
    ``arch`` adds a SystemInfo stream (7) with that ProcessorArchitecture;
    ``ctx_size`` overrides the thread-context size recorded in the exception stream;
    ``registers`` sets other CONTEXT integer registers (by name).
    """
    esp = 0x130000
    stack = b"".join(struct.pack("<I", w) for w in stack_words)
    # layout: header(32) dir(3*12) modlist ctx stack names
    n_streams = 3 if arch is None else 4
    dir_rva = 32
    mod_rva = dir_rva + 12 * n_streams
    mod_size = 4 + 108 * len(modules)
    exc_rva = mod_rva + mod_size
    exc_size = 8 + 152 + 8
    mem_rva = exc_rva + exc_size
    mem_size = 4 + 16
    ctx_rva = mem_rva + mem_size
    ctx = bytearray(0x2CC)
    struct.pack_into("<I", ctx, 0xB8, eip)
    struct.pack_into("<I", ctx, 0xC4, esp)
    for name, value in (registers or {}).items():
        struct.pack_into("<I", ctx, CTX_X86_OFFSETS[name], value)
    stack_rva = ctx_rva + len(ctx)
    names_rva = stack_rva + len(stack)
    name_blobs, name_offs, cur = b"", [], names_rva
    for mod in modules:
        nm = mod[2]
        raw = nm.encode("utf-16le")
        blob = struct.pack("<I", len(raw)) + raw + b"\0\0"
        name_offs.append(cur)
        cur += len(blob)
        name_blobs += blob
    out = struct.pack("<4sIIII", b"MDMP", 0xA793, n_streams, dir_rva, 0).ljust(32, b"\0")
    out += struct.pack("<III", 4, mod_size, mod_rva)
    out += struct.pack("<III", 6, exc_size, exc_rva)
    out += struct.pack("<III", 5, mem_size, mem_rva)
    sys_rva = names_rva + len(name_blobs)
    if arch is not None:
        out += struct.pack("<III", 7, 56, sys_rva)
    mods = struct.pack("<I", len(modules))
    for mod, no in zip(modules, name_offs):
        base, size = mod[0], mod[1]
        ts = mod[3] if len(mod) > 3 else 0
        mods += struct.pack("<QIIII", base, size, 0, ts, no).ljust(108, b"\0")
    out += mods
    params = [0] * 15
    n_params = 0
    if access is not None:
        params[0], params[1] = access
        n_params = 2
    exc = struct.pack("<II", 1, 0)
    exc += struct.pack("<IIQQI", exc_code, 0, 0, exc_addr, n_params) + b"\0" * 4
    exc += struct.pack("<15Q", *params)
    exc += struct.pack("<II", len(ctx) if ctx_size is None else ctx_size, ctx_rva)
    assert len(exc) == exc_size
    out += exc
    out += struct.pack("<I", 1) + struct.pack("<QII", esp, len(stack), stack_rva)
    out += bytes(ctx) + stack + name_blobs
    if arch is not None:
        out += struct.pack("<HH", arch, 0).ljust(56, b"\0")
    return out


def build_thread_minidump(
    modules: list[tuple],
    threads: list[dict],
    exception: tuple | None = None,
) -> bytes:
    """A synthetic x86 minidump with a ThreadList (3), module list (4), memory list (5).

    ``threads`` items: ``tid``, ``eip``, ``stack_words`` (the words from esp upwards),
    optional ``registers`` (by name). Each thread gets its own stack range
    (0x10 zero bytes below esp, then the words), also listed in the MemoryList.
    ``exception`` is ``None`` (no stream 6, a ThreadList-only snapshot) or
    ``(tid, code, address)``; its context is that thread's.
    """
    n_streams = 3 + (exception is not None)
    dir_rva = 32
    mod_rva = dir_rva + 12 * n_streams
    mod_size = 4 + 108 * len(modules)
    thr_rva = mod_rva + mod_size
    thr_size = 4 + 48 * len(threads)
    mem_rva = thr_rva + thr_size
    mem_size = 4 + 16 * len(threads)
    exc_rva = mem_rva + mem_size
    exc_size = 8 + 152 + 8 if exception is not None else 0
    blob_rva = exc_rva + exc_size
    blobs = bytearray()
    ctx_locs, stack_locs, stack_ranges = {}, {}, {}
    for i, t in enumerate(threads):
        esp = 0x130000 + 0x10000 * i
        ctx = bytearray(0x2CC)
        struct.pack_into("<I", ctx, 0xB8, t["eip"])
        struct.pack_into("<I", ctx, 0xC4, esp)
        for name, value in t.get("registers", {}).items():
            struct.pack_into("<I", ctx, CTX_X86_OFFSETS[name], value)
        ctx_locs[i] = (len(ctx), blob_rva + len(blobs))
        blobs += ctx
        stack = b"\0" * 0x10 + b"".join(struct.pack("<I", w) for w in t["stack_words"])
        stack_locs[i] = blob_rva + len(blobs)
        stack_ranges[i] = (esp - 0x10, len(stack))
        blobs += stack
    names_rva = blob_rva + len(blobs)
    name_offs, cur = [], names_rva
    for mod in modules:
        raw = mod[2].encode("utf-16le")
        blob = struct.pack("<I", len(raw)) + raw + b"\0\0"
        name_offs.append(cur)
        cur += len(blob)
        blobs += blob
    out = struct.pack("<4sIIII", b"MDMP", 0xA793, n_streams, dir_rva, 0).ljust(32, b"\0")
    out += struct.pack("<III", 4, mod_size, mod_rva)
    out += struct.pack("<III", 3, thr_size, thr_rva)
    out += struct.pack("<III", 5, mem_size, mem_rva)
    if exception is not None:
        out += struct.pack("<III", 6, exc_size, exc_rva)
    mods = struct.pack("<I", len(modules))
    for mod, no in zip(modules, name_offs):
        ts = mod[3] if len(mod) > 3 else 0
        mods += struct.pack("<QIIII", mod[0], mod[1], 0, ts, no).ljust(108, b"\0")
    out += mods
    out += struct.pack("<I", len(threads))
    for i, t in enumerate(threads):
        start, size = stack_ranges[i]
        out += struct.pack(
            "<IIIIQQIIII",
            t["tid"],
            0,
            0,
            0,
            0,
            start,
            size,
            stack_locs[i],
            ctx_locs[i][0],
            ctx_locs[i][1],
        )
    out += struct.pack("<I", len(threads))
    for i in range(len(threads)):
        out += struct.pack("<QII", stack_ranges[i][0], stack_ranges[i][1], stack_locs[i])
    if exception is not None:
        tid, code, addr = exception
        idx = [t["tid"] for t in threads].index(tid)
        exc = struct.pack("<II", tid, 0)
        exc += struct.pack("<IIQQI", code, 0, 0, addr, 0) + b"\0" * 4
        exc += struct.pack("<15Q", *([0] * 15))
        exc += struct.pack("<II", *ctx_locs[idx])
        assert len(exc) == exc_size
        out += exc
    return out + bytes(blobs)


def build_pe(
    size_of_headers: int,
    sections: list[bytes],
    timestamp: int = 0x6A8E2472,
    size_of_image: int = 0x20000,
    image_base: int = 0x10000000,
    total: int | None = None,
    marker: bytes = b"\xcc",
    lfanew: int = 0x80,
    opt_size: int = 0xE0,
) -> bytes:
    """A PE32 image: headers occupy ``size_of_headers`` bytes, then ``marker`` fills the rest.

    The marker stands for section contents; a reader that stays within
    SizeOfHeaders never sees it.
    """
    head = bytearray(size_of_headers)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, lfanew)
    head[lfanew : lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, lfanew + 4, 0x14C, len(sections), timestamp, 0, 0, opt_size, 0x2102)
    opt = lfanew + 24
    struct.pack_into("<H", head, opt, 0x10B)
    struct.pack_into("<I", head, opt + 28, image_base)
    struct.pack_into("<I", head, opt + 56, size_of_image)
    struct.pack_into("<I", head, opt + 60, size_of_headers)
    table = opt + opt_size
    for i, sh in enumerate(sections):
        head[table + 40 * i : table + 40 * i + 40] = sh
    total = size_of_headers + 0x2000 if total is None else total
    return bytes(head) + (marker * (total - size_of_headers))
