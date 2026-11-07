"""PDB (MSF + DBI + CodeView symbols) reader and RVA resolver.

Standard library only. The structures follow the public ``microsoft-pdb`` and
LLVM documentation of the PDB format. Only what is needed to turn an RVA into
``function + offset`` and ``file:line`` is implemented:

* DBI stream header and its substreams (module info, section contributions,
  optional debug header),
* the section-header debug stream (RVA <-> section:offset),
* ``S_PUB32`` records from the symbol-record stream,
* ``S_GPROC32``/``S_LPROC32`` (and ``_ID`` variants) from module streams,
* ``DEBUG_S_LINES`` + ``DEBUG_S_FILECHKSMS`` with the ``/names`` string table.
"""

from __future__ import annotations

import bisect
import enum
import functools
import struct
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, TypeVar

from .errors import Civ4DbgError, UnsupportedError
from .msf import Msf, OpenedMsf

STREAM_PDB_INFO = 1
STREAM_DBI = 3

# CodeView symbol record kinds
S_PUB32 = 0x110E
S_LPROC32 = 0x110F
S_GPROC32 = 0x1110
S_LPROC32_ID = 0x1146
S_GPROC32_ID = 0x1147
S_LPROC32_DPC = 0x1155
S_LPROC32_DPC_ID = 0x1156
PROC_KINDS = {
    S_LPROC32: "S_LPROC32",
    S_GPROC32: "S_GPROC32",
    S_LPROC32_ID: "S_LPROC32_ID",
    S_GPROC32_ID: "S_GPROC32_ID",
    S_LPROC32_DPC: "S_LPROC32_DPC",
    S_LPROC32_DPC_ID: "S_LPROC32_DPC_ID",
}

# C13 debug subsections
DEBUG_S_LINES = 0xF2
DEBUG_S_FILECHKSMS = 0xF4

CVPSF_FUNCTION = 0x2
# A public symbol has no length. When no procedure covers an address, the nearest
# preceding public is reported only as a hint, never as the function; beyond this
# distance the hint is marked "not credible".
FAR_PUBLIC_GAP = 0x2000
MAX_SHOWN_NAMES = 5  # how many alias names a one-line description lists before "+N more"
IMAGE_SCN_CNT_CODE = 0x20
IMAGE_SCN_MEM_EXECUTE = 0x20000000
DBI_HEADER_SIZE = 64
MODINFO_FIXED = 64
SC_V1 = 0xF12EBA2D
SC_V2 = 0xF13151E4

# Optional debug header slots (index into the uint16 array)
DBG_OMAP_TO_SRC = 3
DBG_OMAP_FROM_SRC = 4
DBG_SECTION_HDR = 5
DBG_SECTION_HDR_ORIG = 10


_F = TypeVar("_F", bound=Callable)


class PdbError(Civ4DbgError):
    """Raised when a PDB does not have the expected structure."""


class OmapUnsupportedError(PdbError, UnsupportedError):
    """The PDB carries OMAP streams (the image was post-processed); not applied by this tool."""


def _guard(what: str) -> Callable[[_F], _F]:
    """Turn the low-level exceptions a corrupt structure can cause into :class:`PdbError`."""

    def deco(fn: _F) -> _F:
        @functools.wraps(fn)
        def wrapper(*args, **kwargs):  # type: ignore[no-untyped-def]
            try:
                return fn(*args, **kwargs)
            except Civ4DbgError:
                raise
            except (struct.error, ValueError, IndexError, OverflowError, MemoryError) as exc:
                raise PdbError(f"corrupt or truncated {what}: {exc}") from exc

        return wrapper  # type: ignore[return-value]

    return deco


class AddressKind(enum.Enum):
    """How the address given to :meth:`Pdb.resolve` is to be interpreted."""

    EXACT = "exact"  # the address of an instruction: a fault address, an RVA the user typed
    RETURN_ADDRESS = "return-address"  # a stack word / unwound frame: looked up at address - 1


def join_names(names: tuple[str, ...] | list[str], limit: int | None = MAX_SHOWN_NAMES) -> str:
    """``a | b | c`` with at most ``limit`` names and a ``(+N more)`` tail."""
    shown = list(names) if limit is None else list(names[:limit])
    text = " | ".join(shown)
    if len(shown) < len(names):
        text += f" | (+{len(names) - len(shown)} more)"
    return text


@dataclass(frozen=True)
class Section:
    """An ``IMAGE_SECTION_HEADER`` (1-based index in PDB addresses)."""

    index: int
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_pointer: int
    characteristics: int

    @property
    def extent(self) -> int:
        """Bytes the section occupies in the image (raw size when the virtual size is 0)."""
        return self.virtual_size if self.virtual_size else self.raw_size

    @property
    def executable(self) -> bool:
        return bool(self.characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE))

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + self.extent


def parse_section_headers(data: bytes) -> list[Section]:
    out = []
    for i in range(len(data) // 40):
        name, vsize, vaddr, rsize, rptr, _r, _l, _nr, _nl, chars = struct.unpack_from("<8sIIIIIIHHI", data, 40 * i)
        out.append(Section(i + 1, name.rstrip(b"\0").decode("latin-1"), vsize, vaddr, rsize, rptr, chars))
    return out


def _cstr(data: bytes, off: int) -> tuple[str, int]:
    end = data.find(b"\0", off)
    if off < 0 or end < 0:
        raise PdbError(f"unterminated string at offset {off:#x}")
    return data[off:end].decode("utf-8", "replace"), end + 1


@dataclass(frozen=True)
class ModuleInfo:
    index: int
    stream: int
    sym_bytes: int
    c11_bytes: int
    c13_bytes: int
    name: str
    obj: str


@dataclass(frozen=True)
class Contribution:
    section: int
    offset: int
    size: int
    module: int


@dataclass(frozen=True)
class Public:
    section: int
    offset: int
    name: str
    is_function: bool


@dataclass(frozen=True)
class Proc:
    section: int
    offset: int
    length: int
    name: str
    kind: str
    module: int


@dataclass(frozen=True)
class LineEntry:
    offset: int
    line: int


@dataclass
class ModuleLines:
    """Line info of one module: per section, sorted (start, end, file, entries)."""

    blocks: list[tuple[int, int, int, str, list[LineEntry]]] = field(default_factory=list)
    _offsets: dict[int, list[int]] = field(default_factory=dict, repr=False, compare=False)

    def lookup(self, section: int, offset: int) -> tuple[str, int] | None:
        best: tuple[int, str, int] | None = None
        for n, (sec, start, end, fname, entries) in enumerate(self.blocks):
            if sec != section or not start <= offset < end:
                continue
            offs = self._offsets.get(n)
            if offs is None or len(offs) != len(entries):
                offs = self._offsets[n] = [e.offset for e in entries]
            i = bisect.bisect_right(offs, offset) - 1
            if i >= 0 and (best is None or entries[i].offset > best[0]):
                best = (entries[i].offset, fname, entries[i].line)
        return None if best is None else (best[1], best[2])


@dataclass(frozen=True)
class Candidate:
    """One symbol that could be the function at an address."""

    name: str
    offset: int  # distance of the looked-up address from the symbol's start
    source: str  # "S_GPROC32", "S_LPROC32", ... or "S_PUB32"
    module: str | None = None  # object file holding the record (None for a public)


@dataclass(frozen=True)
class Resolution:
    """Everything known about one address.

    ``rva`` is the address as given; ``lookup_rva`` is the address that was
    actually looked up (``rva - 1`` for :attr:`AddressKind.RETURN_ADDRESS`).
    ``section_offset`` and every candidate offset refer to ``lookup_rva``.

    ``candidates`` lists every distinct function name that covers the address.
    Identical-code folding makes several names share one body, so more than one
    candidate is normal, and then **no single name is certain**: ``function`` is
    ``None`` and ``ambiguous`` is true. ``function`` is set only when exactly
    one candidate exists. A name is never given for an address no procedure
    record covers, except a public symbol that starts exactly there.
    """

    rva: int
    section: int | None
    section_name: str | None
    section_offset: int | None
    kind: AddressKind = AddressKind.EXACT
    lookup_rva: int | None = None
    candidates: tuple[Candidate, ...] = ()
    module: str | None = None  # object file the linker credited with the bytes
    file: str | None = None
    line: int | None = None
    public_names: tuple[str, ...] = ()  # nearest public(s) at or before the address
    public_offset: int | None = None  # distance from those public(s) to the address
    public_is_function: bool | None = None
    note: str | None = None
    entry_symbols: int = 0  # return-address mode: symbols starting exactly at ``rva``

    @property
    def ambiguous(self) -> bool:
        return len(self.candidates) > 1

    @property
    def function(self) -> str | None:
        return self.candidates[0].name if len(self.candidates) == 1 else None

    @property
    def function_offset(self) -> int | None:
        return self.candidates[0].offset if len(self.candidates) == 1 else None

    @property
    def source(self) -> str | None:
        return self.candidates[0].source if len(self.candidates) == 1 else None

    @property
    def public(self) -> str | None:
        return self.public_names[0] if len(self.public_names) == 1 else None


@dataclass
class _ProcIndex:
    """Procedures of one section: sorted distinct starts, procs per start, prefix max of ends."""

    starts: list[int]
    groups: list[list[Proc]]
    prefix_max_end: list[int]


class Pdb:
    """A PDB opened for symbol lookup."""

    @_guard("DBI stream")
    def __init__(self, msf: Msf) -> None:
        self.msf = msf
        dbi = msf.read_stream(STREAM_DBI)
        if len(dbi) < DBI_HEADER_SIZE:
            raise PdbError("DBI stream too short")
        (
            sig,
            self.dbi_version,
            self.dbi_age,
            _gsi,
            _build,
            self.public_stream,
            _pdbdll,
            self.symrec_stream,
            _rbld,
            mod_size,
            sc_size,
            secmap_size,
            srcinfo_size,
            tsm_size,
            _mfc,
            optdbg_size,
            ec_size,
            _flags,
            self.machine,
            _pad,
        ) = struct.unpack_from("<iIIHHHHHHiiiiiIiiHHI", dbi, 0)
        if sig != -1:
            raise PdbError("old-format DBI header (signature != -1)")
        sizes = (mod_size, sc_size, secmap_size, srcinfo_size, tsm_size, optdbg_size, ec_size)
        if any(v < 0 for v in sizes):
            raise PdbError("negative DBI substream size")
        pos = DBI_HEADER_SIZE
        self._modinfo = dbi[pos : pos + mod_size]
        pos += mod_size
        self._sc = dbi[pos : pos + sc_size]
        pos += sc_size + secmap_size + srcinfo_size + tsm_size + ec_size
        optdbg = dbi[pos : pos + optdbg_size]
        pos += optdbg_size
        if pos != len(dbi):
            raise PdbError(f"DBI substreams total {pos}, stream is {len(dbi)}")
        self.dbg_streams = list(struct.unpack_from(f"<{optdbg_size // 2}H", optdbg))
        self.has_omap = any(
            len(self.dbg_streams) > i and self.dbg_streams[i] not in (0xFFFF, 0)
            for i in (DBG_OMAP_TO_SRC, DBG_OMAP_FROM_SRC)
        )
        if len(self.dbg_streams) <= DBG_SECTION_HDR or not msf.stream_exists(self.dbg_streams[DBG_SECTION_HDR]):
            raise PdbError("PDB has no section-header debug stream")
        sec_idx = self.dbg_streams[DBG_SECTION_HDR]
        self.sections = parse_section_headers(msf.read_stream(sec_idx))
        self.modules = self._parse_modules()
        self.contributions = self._parse_contributions()
        self._ckeys = [(c.section, c.offset) for c in self.contributions]
        self._publics: list[Public] | None = None
        self._pub_keys: list[tuple[int, int]] = []
        self._procs_cache: dict[int, list[Proc]] = {}
        self._lines_cache: dict[int, ModuleLines] = {}
        self._proc_index_cache: dict[int, _ProcIndex] | None = None
        self._names: bytes | None = None
        self._names_loaded = False

    # -- construction helpers --------------------------------------------
    @classmethod
    def open(cls, path: str | Path) -> Pdb:
        msf = OpenedMsf(path)
        try:
            return cls(msf)
        except BaseException:
            msf.close()
            raise

    def close(self) -> None:
        close = getattr(self.msf, "close", None)
        if close is not None:
            close()

    def __enter__(self) -> Pdb:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def _parse_modules(self) -> list[ModuleInfo]:
        data, pos, out = self._modinfo, 0, []
        while pos < len(data):
            (_flags, stream, sym_bytes, c11, c13) = struct.unpack_from("<HHIII", data, pos + 4 + 28)
            name, p = _cstr(data, pos + MODINFO_FIXED)
            obj, p = _cstr(data, p)
            out.append(ModuleInfo(len(out), stream, sym_bytes, c11, c13, name, obj))
            pos = (p + 3) & ~3
        return out

    def _parse_contributions(self) -> list[Contribution]:
        data = self._sc
        if not data:
            return []
        (ver,) = struct.unpack_from("<I", data, 0)
        if ver == SC_V1:
            stride = 28
        elif ver == SC_V2:
            stride = 32
        else:
            raise PdbError(f"unknown section contribution version {ver:#x}")
        out = []
        for pos in range(4, len(data) - stride + 1, stride):
            sec, _p, off, size, _ch, mod = struct.unpack_from("<HHiiIH", data, pos)
            out.append(Contribution(sec, off, size, mod))
        out.sort(key=lambda c: (c.section, c.offset))
        return out

    # -- address conversion ------------------------------------------------
    def rva_to_section(self, rva: int) -> tuple[Section, int] | None:
        for s in self.sections:
            if s.contains_rva(rva):
                return s, rva - s.virtual_address
        return None

    def section_to_rva(self, section: int, offset: int) -> int:
        if not 1 <= section <= len(self.sections):
            raise PdbError(f"section {section} does not exist (the PDB has {len(self.sections)})")
        return self.sections[section - 1].virtual_address + offset

    # -- publics -------------------------------------------------------------
    @_guard("public-symbol stream")
    def publics(self) -> list[Public]:
        """All ``S_PUB32`` records, sorted by (section, offset)."""
        if self._publics is None:
            data = self.msf.read_stream(self.symrec_stream)
            pubs = []
            pos, n = 0, len(data)
            unpack = struct.unpack_from
            while pos + 4 <= n:
                reclen, kind = unpack("<HH", data, pos)
                if kind == S_PUB32:
                    flags, off, seg = unpack("<IIH", data, pos + 4)
                    end = data.index(b"\0", pos + 14, pos + 2 + reclen)
                    pubs.append(
                        Public(
                            seg,
                            off,
                            data[pos + 14 : end].decode("utf-8", "replace"),
                            bool(flags & CVPSF_FUNCTION),
                        )
                    )
                pos += 2 + reclen
            pubs.sort(key=lambda p: (p.section, p.offset))
            self._publics = pubs
            self._pub_keys = [(p.section, p.offset) for p in pubs]
        return self._publics

    def find_publics(self, section: int, offset: int) -> list[Public]:
        """Every public at the nearest offset at or before ``offset`` in ``section``.

        Several publics can share one address (identical-code folding), so this
        returns all of them, sorted by name; empty when none precedes the address.
        """
        pubs = self.publics()
        i = bisect.bisect_right(self._pub_keys, (section, offset)) - 1
        if i < 0 or pubs[i].section != section:
            return []
        key = self._pub_keys[i]
        j = i
        while j > 0 and self._pub_keys[j - 1] == key:
            j -= 1
        return sorted(pubs[j : i + 1], key=lambda p: p.name)

    def find_public(self, section: int, offset: int) -> Public | None:
        """One public at the nearest preceding offset (the first by name); see :meth:`find_publics`."""
        group = self.find_publics(section, offset)
        return group[0] if group else None

    @_guard("PDB info stream")
    def guid_age(self) -> tuple[bytes, int]:
        """The PDB's identity from the info stream: (16 GUID bytes as stored, age)."""
        info = self.msf.read_stream(STREAM_PDB_INFO)
        if len(info) < 28:
            raise PdbError("PDB info stream too short for a GUID")
        (age,) = struct.unpack_from("<I", info, 8)
        return bytes(info[12:28]), age

    # -- names stream ---------------------------------------------------------
    @_guard("PDB info stream")
    def _load_names(self) -> bytes | None:
        if self._names_loaded:
            return self._names
        self._names_loaded = True
        info = self.msf.read_stream(STREAM_PDB_INFO)
        pos = 28  # version, signature, age, GUID
        (buf_size,) = struct.unpack_from("<I", info, pos)
        buf = info[pos + 4 : pos + 4 + buf_size]
        pos += 4 + buf_size
        size, _cap = struct.unpack_from("<II", info, pos)
        pos += 8
        (nwords,) = struct.unpack_from("<I", info, pos)
        if nwords * 4 > len(info):
            raise PdbError("named-stream hash table is larger than the stream")
        present = struct.unpack_from(f"<{nwords}I", info, pos + 4)
        pos += 4 + 4 * nwords
        (ndel,) = struct.unpack_from("<I", info, pos)
        pos += 4 + 4 * ndel
        bits = [i for i in range(nwords * 32) if present[i // 32] >> (i % 32) & 1]
        for _slot in bits[:size]:
            key, val = struct.unpack_from("<II", info, pos)
            pos += 8
            if _cstr(buf, key)[0] == "/names" and self.msf.stream_exists(val):
                self._names = self.msf.read_stream(val)
                break
        return self._names

    def _name_at(self, offset: int) -> str:
        names = self._load_names()
        if not names or len(names) < 12:
            return f"<file@{offset:#x}>"
        return _cstr(names, 12 + offset)[0]

    # -- module streams --------------------------------------------------------
    def _module(self, module: int) -> ModuleInfo:
        if not 0 <= module < len(self.modules):
            raise PdbError(f"module index {module} is out of range (the PDB lists {len(self.modules)} modules)")
        return self.modules[module]

    def _module_stream(self, mi: ModuleInfo) -> bytes | None:
        if mi.stream != 0xFFFF and self.msf.stream_exists(mi.stream):
            return self.msf.read_stream(mi.stream)
        return None

    @_guard("module symbol stream")
    def module_procs(self, module: int) -> list[Proc]:
        """The procedure records (``S_GPROC32``/``S_LPROC32``...) of one module."""
        cached = self._procs_cache.get(module)
        if cached is not None:
            return cached
        mi = self._module(module)
        data = self._module_stream(mi)
        procs = self._scan_procs(data[4 : mi.sym_bytes], module) if data is not None else []
        self._procs_cache[module] = procs
        return procs

    @_guard("module line information")
    def module_lines(self, module: int) -> ModuleLines:
        """The line tables (old-style C11 and C13) of one module."""
        cached = self._lines_cache.get(module)
        if cached is not None:
            return cached
        mi = self._module(module)
        data = self._module_stream(mi)
        lines = ModuleLines()
        if data is not None:
            # SymByteSize includes the 4-byte signature, so the C11 (old-style)
            # line block starts at sym_bytes, and C13 follows the C11 block.
            c11 = data[mi.sym_bytes : mi.sym_bytes + mi.c11_bytes]
            c13_start = mi.sym_bytes + mi.c11_bytes
            c13 = data[c13_start : c13_start + mi.c13_bytes]
            lines = self._parse_c11(c11)
            lines.blocks.extend(self._parse_c13(c13).blocks)
        self._lines_cache[module] = lines
        return lines

    def module_symbols(self, module: int) -> tuple[list[Proc], ModuleLines]:
        return self.module_procs(module), self.module_lines(module)

    @staticmethod
    def _scan_procs(data: bytes, module: int) -> list[Proc]:
        out, pos, n = [], 0, len(data)
        while pos + 4 <= n:
            reclen, kind = struct.unpack_from("<HH", data, pos)
            if kind in PROC_KINDS:
                (length,) = struct.unpack_from("<I", data, pos + 4 + 12)
                off, seg = struct.unpack_from("<IH", data, pos + 4 + 28)
                nstart = pos + 4 + 35
                end = data.index(b"\0", nstart, pos + 2 + reclen)
                out.append(
                    Proc(seg, off, length, data[nstart:end].decode("utf-8", "replace"), PROC_KINDS[kind], module)
                )
            pos += 2 + reclen
        return out

    def _parse_c11(self, data: bytes) -> ModuleLines:
        """Old-style (sstSrcModule) line info: this PDB carries it instead of C13.

        ``u16 cFile, u16 cSeg, u32 file[cFile], u32 startEnd[2*cSeg], u16 seg[cSeg]``;
        each file entry is ``u16 cSeg, u16 pad, u32 lineTable[cSeg],
        u32 startEnd[2*cSeg], char name[]`` (NUL-terminated); each line table is
        ``u16 seg, u16 count, u32 sectionOffset[count], u16 line[count]``.
        """
        result = ModuleLines()
        if len(data) < 4:
            return result
        c_file, _c_seg = struct.unpack_from("<HH", data, 0)
        file_offs = struct.unpack_from(f"<{c_file}I", data, 4)
        for fo in file_offs:
            c_seg, _pad = struct.unpack_from("<HH", data, fo)
            tables = struct.unpack_from(f"<{c_seg}I", data, fo + 4)
            ranges = struct.unpack_from(f"<{2 * c_seg}I", data, fo + 4 + 4 * c_seg)
            name, _ = _cstr(data, fo + 4 + 12 * c_seg)
            for i, tbl in enumerate(tables):
                seg, count = struct.unpack_from("<HH", data, tbl)
                offs = struct.unpack_from(f"<{count}I", data, tbl + 4)
                nums = struct.unpack_from(f"<{count}H", data, tbl + 4 + 4 * count)
                entries = sorted((LineEntry(o, n) for o, n in zip(offs, nums)), key=lambda e: e.offset)
                result.blocks.append((seg, ranges[2 * i], ranges[2 * i + 1] + 1, name, entries))
        return result

    def _parse_c13(self, c13: bytes) -> ModuleLines:
        subs: list[tuple[int, bytes]] = []
        pos = 0
        while pos + 8 <= len(c13):
            kind, ln = struct.unpack_from("<II", c13, pos)
            subs.append((kind, c13[pos + 8 : pos + 8 + ln]))
            pos += 8 + ln
            pos = (pos + 3) & ~3
        checksums: dict[int, int] = {}  # offset in subsection -> name offset
        for kind, body in subs:
            if kind == DEBUG_S_FILECHKSMS:
                p = 0
                while p + 8 <= len(body):
                    name_off, cb, _t = struct.unpack_from("<IBB", body, p)
                    checksums[p] = name_off
                    p = (p + 6 + cb + 3) & ~3
        result = ModuleLines()
        for kind, body in subs:
            if kind != DEBUG_S_LINES:
                continue
            off_con, seg_con, _flags, cb_con = struct.unpack_from("<IHHI", body, 0)
            p = 12
            while p + 12 <= len(body):
                file_id, nlines, cb_block = struct.unpack_from("<III", body, p)
                if cb_block < 12:
                    raise PdbError(f"C13 line block of {cb_block} bytes is smaller than its header")
                lp = p + 12
                entries = []
                for k in range(nlines):
                    o, packed = struct.unpack_from("<II", body, lp + 8 * k)
                    entries.append(LineEntry(off_con + o, packed & 0xFFFFFF))
                entries.sort(key=lambda e: e.offset)
                fname = self._name_at(checksums[file_id]) if file_id in checksums else "?"
                result.blocks.append((seg_con, off_con, off_con + cb_con, fname, entries))
                p += cb_block
        return result

    # -- procedure index across all modules --------------------------------------
    @_guard("module symbol stream")
    def _proc_index(self) -> dict[int, _ProcIndex]:
        if self._proc_index_cache is None:
            by_sec: dict[int, dict[int, list[Proc]]] = {}
            for m in range(len(self.modules)):
                for p in self.module_procs(m):
                    by_sec.setdefault(p.section, {}).setdefault(p.offset, []).append(p)
            index: dict[int, _ProcIndex] = {}
            for sec, by_start in by_sec.items():
                starts = sorted(by_start)
                groups = [by_start[s] for s in starts]
                pmax: list[int] = []
                run = -1
                for g in groups:
                    run = max(run, max(p.offset + p.length for p in g))
                    pmax.append(run)
                index[sec] = _ProcIndex(starts, groups, pmax)
            self._proc_index_cache = index
        return self._proc_index_cache

    def procs_covering(self, section: int, offset: int) -> list[Proc]:
        """Every procedure record, in any module, whose range covers the address.

        More than one is the normal result for identical-code-folded functions:
        the linker keeps one body and the PDB still lists every function.
        """
        ix = self._proc_index().get(section)
        if ix is None:
            return []
        out: list[Proc] = []
        i = bisect.bisect_right(ix.starts, offset) - 1
        while i >= 0 and ix.prefix_max_end[i] > offset:
            out.extend(p for p in ix.groups[i] if p.offset <= offset < p.offset + p.length)
            i -= 1
        return out

    def procs_starting_at(self, section: int, offset: int) -> list[Proc]:
        ix = self._proc_index().get(section)
        if ix is None:
            return []
        i = bisect.bisect_left(ix.starts, offset)
        return list(ix.groups[i]) if i < len(ix.starts) and ix.starts[i] == offset else []

    # -- resolution --------------------------------------------------------------
    def find_module(self, section: int, offset: int) -> int | None:
        cs = self.contributions
        keys = self._ckeys
        i = bisect.bisect_right(keys, (section, offset)) - 1
        while i >= 0 and cs[i].section == section:
            c = cs[i]
            if c.offset <= offset < c.offset + c.size:
                return c.module
            if offset - c.offset > 0x100000:
                break
            i -= 1
        return None

    def resolve_return_address(self, rva: int) -> Resolution:
        """Shorthand for ``resolve(rva, AddressKind.RETURN_ADDRESS)``."""
        return self.resolve(rva, AddressKind.RETURN_ADDRESS)

    def _entry_symbols(self, section: int, offset: int) -> int:
        names = {p.name for p in self.procs_starting_at(section, offset)}
        if not names:  # a proc and its public are one function; count publics only when no proc
            names = {p.name for p in self.find_publics(section, offset) if p.offset == offset and p.is_function}
        return len(names)

    def resolve(self, rva: int, kind: AddressKind = AddressKind.EXACT) -> Resolution:
        """Name the code at ``rva``.

        ``kind`` says how to read the address. ``EXACT`` (the default) looks up
        ``rva`` itself: use it for a fault address and for an RVA a person typed.
        ``RETURN_ADDRESS`` looks up ``rva - 1``, the last byte of the call
        instruction: a return address can equal the *next* function's start
        when the call was a no-return call. The result keeps the original
        ``rva`` and records what was looked up in ``lookup_rva``.
        """
        if self.has_omap:
            raise OmapUnsupportedError(
                "the PDB has OMAP streams (the image was reordered after linking); RVAs would "
                "have to be translated through OMAP, which this tool does not implement, so no "
                "names are printed"
            )
        lookup = rva - 1 if kind is AddressKind.RETURN_ADDRESS else rva
        loc = self.rva_to_section(lookup)
        if loc is None:
            what = "RVA" if kind is AddressKind.EXACT else "return address - 1"
            return Resolution(
                rva,
                None,
                None,
                None,
                kind=kind,
                lookup_rva=lookup,
                note=f"{what} is outside every section",
            )
        sec, off = loc

        pubs = self.find_publics(sec.index, off)
        pub_distance = off - pubs[0].offset if pubs else None
        pub_fields: dict[str, Any] = {}
        if pubs:
            pub_fields = dict(
                public_names=tuple(p.name for p in pubs),
                public_offset=pub_distance,
                public_is_function=any(p.is_function for p in pubs),
            )

        def make(**kw: Any) -> Resolution:
            return Resolution(rva, sec.index, sec.name, off, kind=kind, lookup_rva=lookup, **pub_fields, **kw)

        if kind is AddressKind.RETURN_ADDRESS and not sec.executable:
            return make(
                note=f"section {sec.name} is not executable: not a return address (a data pointer or stale stack word)",
            )

        entry_symbols = 0
        if kind is AddressKind.RETURN_ADDRESS:
            here = self.rva_to_section(rva)
            if here is not None and here[0].index == sec.index:
                entry_symbols = self._entry_symbols(sec.index, here[1])

        mod = self.find_module(sec.index, off)
        module_name = self._module(mod).name if mod is not None else None
        covering = self.procs_covering(sec.index, off) if mod is not None else []

        if covering:
            by_name: dict[str, Proc] = {}
            for p in sorted(covering, key=lambda q: (q.name, q.module)):
                by_name.setdefault(p.name, p)
            cands = tuple(
                Candidate(p.name, off - p.offset, p.kind, self.modules[p.module].name) for p in by_name.values()
            )
            if len(cands) == 1:
                only = next(iter(by_name.values()))
                hit = self.module_lines(only.module).lookup(sec.index, off)
                return make(
                    candidates=cands,
                    module=module_name,
                    entry_symbols=entry_symbols,
                    file=hit[0] if hit else None,
                    line=hit[1] if hit else None,
                )
            return make(
                candidates=cands,
                module=module_name,
                entry_symbols=entry_symbols,
                note=f"ambiguous: {len(cands)} functions share this address "
                "(identical code folding); the PDB cannot say which one ran",
            )

        # No procedure record covers the address. A public symbol has no length, so
        # it can name the function only when it starts exactly here.
        if pubs and pub_distance == 0 and any(p.is_function for p in pubs):
            fn_pubs = [p for p in pubs if p.is_function]
            return make(
                candidates=tuple(Candidate(p.name, 0, "S_PUB32") for p in fn_pubs),
                module=module_name,
                entry_symbols=entry_symbols,
                note=(
                    f"ambiguous: {len(fn_pubs)} public symbols share this address "
                    "(identical code folding); no procedure record covers it"
                )
                if len(fn_pubs) > 1
                else None,
            )
        if pubs:
            names = join_names([p.name for p in pubs])
            s = "s" if len(pubs) > 1 else ""
            far = f" (not credible: more than {FAR_PUBLIC_GAP:#x} bytes away)" if pub_distance > FAR_PUBLIC_GAP else ""
            if any(p.is_function for p in pubs):
                note = (
                    f"no function symbol covers this address (outside any known function); "
                    f"nearest preceding public{s} {names}, {pub_distance:#x} bytes before it; "
                    f"may be padding, an unlisted function or that function's tail{far}"
                )
            else:
                note = (
                    f"no function symbol covers this address; nearest preceding public{s} "
                    f"{names} +{pub_distance:#x} is a non-function symbol (data){far}"
                )
            return make(note=note, module=module_name, entry_symbols=entry_symbols)
        return make(note="no symbol found", module=module_name, entry_symbols=entry_symbols)


def format_resolution(r: Resolution, max_candidates: int | None = MAX_SHOWN_NAMES) -> str:
    """One line per address. An ambiguous result lists its candidates and says so.

    ``max_candidates`` caps the names shown for an ambiguous result (``None`` shows all).
    """
    head = f"{r.rva:#x}"
    if r.kind is AddressKind.RETURN_ADDRESS:
        head += f" (return address; looked up at {r.lookup_rva:#x})"
    if r.section is None:
        return f"{head}  <unresolved: {r.note}>"
    where = f"[{r.section_name}:{r.section_offset:#x}]"
    obj = f"  | obj: {r.module}" if r.module else ""
    entry = ""
    if r.entry_symbols:
        entry = (
            f"  | note: {r.rva:#x} is itself the start of {r.entry_symbols} symbol(s): "
            "possibly a function pointer or stale word, not a return address"
        )
    if not r.candidates:
        return f"{head} {where}  <{r.note}>{obj}{entry}"
    if r.ambiguous:
        names = join_names([c.name for c in r.candidates], max_candidates)
        sources = "/".join(sorted({c.source for c in r.candidates}))
        s = (
            f"{head} {where}  <AMBIGUOUS: {len(r.candidates)} candidate functions share this "
            f"address (identical code folding); the name is NOT certain: {names}>  ({sources})"
        )
    else:
        c = r.candidates[0]
        s = f"{head} {where}  {c.name} +{c.offset:#x}  ({c.source})"
        if r.file:
            s += f"  {r.file}:{r.line}"
        if r.public_names and c.source != "S_PUB32":
            s += f"  | pub: {join_names(r.public_names, max_candidates)} +{r.public_offset:#x}"
    return s + obj + entry
