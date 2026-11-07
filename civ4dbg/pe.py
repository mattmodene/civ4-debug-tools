"""PE header reader: COFF header, optional-header basics and the section table.

Deliberately reads **only the headers**: exactly the first ``SizeOfHeaders``
bytes of the file (bounded, see ``MAX_HEADER_BYTES``), never section contents.
Used to cross-check a PDB's section headers and to compare the build identity
fields (``TimeDateStamp``, ``SizeOfImage``) with a minidump's module record.

The one exception to "headers only" is :func:`read_codeview_id`: it reads the debug directory entry
that locates the CodeView (RSDS) record and the first 24 bytes of that record
(signature, GUID, age), nothing else, to match the DLL to its PDB.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .errors import Civ4DbgError
from .pdb import Section

MAX_HEADER_BYTES = 0x10000  # SizeOfHeaders above this is treated as corrupt
MAX_LFANEW = 0x10000  # the PE signature must sit within the first 64 KiB
MAX_SECTIONS = 96  # the PE format's own limit
_DOS_HEADER = 0x40
# SizeOfHeaders is at optional-header offset 60 (PE32 and PE32+); read one
# 4-byte field past it, which lies inside the optional header of any valid file.
_SIZE_OF_HEADERS_END = 24 + 64


class PeError(Civ4DbgError):
    """Raised when the file is not a PE image this reader understands."""


@dataclass(frozen=True)
class PeHeaders:
    machine: int
    timestamp: int
    image_base: int
    size_of_image: int
    sections: list[Section]
    size_of_headers: int = 0
    debug_dir_rva: int = 0  # data directory 6 (0 when absent)
    debug_dir_size: int = 0


@dataclass(frozen=True)
class CodeViewId:
    """The identity in a DLL's CodeView (RSDS) record."""

    guid: bytes  # the 16 bytes as stored
    age: int


def _lfanew(first: bytes) -> int:
    if len(first) < _DOS_HEADER or first[:2] != b"MZ":
        raise PeError("missing MZ signature")
    (lfanew,) = struct.unpack_from("<I", first, 0x3C)
    if not _DOS_HEADER <= lfanew <= MAX_LFANEW:
        raise PeError(f"implausible e_lfanew {lfanew:#x}")
    return lfanew


def _size_of_headers(prefix: bytes, lfanew: int) -> int:
    if prefix[lfanew : lfanew + 4] != b"PE\0\0":
        raise PeError("missing PE signature")
    (size,) = struct.unpack_from("<I", prefix, lfanew + _SIZE_OF_HEADERS_END - 4)
    if not 0 < size <= MAX_HEADER_BYTES:
        raise PeError(f"implausible SizeOfHeaders {size:#x}")
    return size


def parse_pe_headers(head: bytes) -> PeHeaders:
    """Parse the header bytes of a PE file.

    Only ``head[:SizeOfHeaders]`` is looked at, so a caller that passes extra
    bytes cannot make this decode section contents.
    """
    try:
        return _parse(head)
    except (struct.error, IndexError, UnicodeDecodeError) as exc:
        raise PeError(f"truncated or inconsistent PE headers: {exc}") from exc


def _parse(head: bytes) -> PeHeaders:
    lfanew = _lfanew(head)
    if len(head) < lfanew + _SIZE_OF_HEADERS_END:
        raise PeError("file too short for the PE optional header")
    size_of_headers = _size_of_headers(head, lfanew)
    head = head[:size_of_headers]
    machine, nsec, ts, _symp, _nsym, opt_size, _chars = struct.unpack_from("<HHIIIHH", head, lfanew + 4)
    opt = lfanew + 24
    (magic,) = struct.unpack_from("<H", head, opt)
    if magic == 0x10B:  # PE32
        (image_base,) = struct.unpack_from("<I", head, opt + 28)
    elif magic == 0x20B:  # PE32+
        (image_base,) = struct.unpack_from("<Q", head, opt + 24)
    else:
        raise PeError(f"unknown optional-header magic {magic:#x}")
    (size_of_image,) = struct.unpack_from("<I", head, opt + 56)
    dirs_at, count_at = (opt + 96, opt + 92) if magic == 0x10B else (opt + 112, opt + 108)
    (n_dirs,) = struct.unpack_from("<I", head, count_at)
    dbg_rva = dbg_size = 0
    if n_dirs > 6 and dirs_at + 8 * 7 <= min(len(head), opt + opt_size):
        dbg_rva, dbg_size = struct.unpack_from("<II", head, dirs_at + 8 * 6)
    if nsec > MAX_SECTIONS:
        raise PeError(f"implausible section count {nsec}")
    table = opt + opt_size
    if table + 40 * nsec > len(head):
        raise PeError(
            f"the section table ({nsec} entries at {table:#x}) does not fit inside SizeOfHeaders ({size_of_headers:#x})"
        )
    sections = []
    for i in range(nsec):
        name, vsize, vaddr, rsize, rptr, _r, _l, _nr, _nl, chars = struct.unpack_from(
            "<8sIIIIIIHHI", head, table + 40 * i
        )
        sections.append(Section(i + 1, name.rstrip(b"\0").decode("latin-1"), vsize, vaddr, rsize, rptr, chars))
    return PeHeaders(machine, ts, image_base, size_of_image, sections, size_of_headers, dbg_rva, dbg_size)


def read_pe_headers_from(fh: BinaryIO) -> PeHeaders:
    """Read exactly the header region of an open binary file.

    Three bounded reads, none of which goes past ``SizeOfHeaders`` of a valid
    file: the 64-byte DOS header, the bytes up to ``SizeOfHeaders`` in the
    optional header, then the whole header region.
    """
    lfanew = _lfanew(fh.read(_DOS_HEADER))
    fh.seek(0)
    prefix = fh.read(lfanew + _SIZE_OF_HEADERS_END)
    if len(prefix) < lfanew + _SIZE_OF_HEADERS_END:
        raise PeError("file too short for the PE optional header")
    size = _size_of_headers(prefix, lfanew)
    fh.seek(0)
    head = fh.read(size)
    if len(head) < size:
        raise PeError(f"file ends inside the headers (SizeOfHeaders {size:#x})")
    return parse_pe_headers(head)


def read_pe_headers(path: str | Path) -> PeHeaders:
    """Read the header region (``SizeOfHeaders`` bytes) of ``path``."""
    with open(path, "rb") as fh:
        return read_pe_headers_from(fh)


_DEBUG_ENTRY = 28
_MAX_DEBUG_ENTRIES = 16
_IMAGE_DEBUG_TYPE_CODEVIEW = 2
_RSDS_HEADER = 24  # signature, GUID, age


def read_codeview_id(fh: BinaryIO, pe: PeHeaders) -> CodeViewId | None:
    """GUID and age from the DLL's CodeView record; ``None`` when it has none.

    Reads only the debug directory entries (at most 16 x 28 bytes, located through
    the section table) and 24 bytes of the CodeView record: signature, GUID, age.
    The path string after them is not read.
    """
    try:
        return _read_codeview(fh, pe)
    except (struct.error, OSError) as exc:
        raise PeError(f"unreadable debug directory: {exc}") from exc


def _check_record_location(pe: PeHeaders, rva: int, ptr: int) -> None:
    """The record's file pointer must be the section-table image of its RVA, in a data section.

    Keeps the 24-byte read inside the file data of a non-executable section, so a
    crafted pointer cannot make this reader read outside a data section.
    """
    for sec in pe.sections:
        rel = rva - sec.virtual_address
        if 0 <= rel and rel + _RSDS_HEADER <= sec.raw_size:
            if sec.executable:
                raise PeError(f"the CodeView record lies in an executable section ({sec.name})")
            if ptr != sec.raw_pointer + rel:
                raise PeError("the CodeView record's file pointer disagrees with its RVA")
            return
    raise PeError("the CodeView record does not lie inside any section's file data")


def _read_codeview(fh: BinaryIO, pe: PeHeaders) -> CodeViewId | None:
    if not pe.debug_dir_rva or not pe.debug_dir_size:
        return None
    size = min(pe.debug_dir_size, _MAX_DEBUG_ENTRIES * _DEBUG_ENTRY)
    for sec in pe.sections:
        rel = pe.debug_dir_rva - sec.virtual_address
        if 0 <= rel and rel + size <= sec.raw_size:
            fh.seek(sec.raw_pointer + rel)
            table = fh.read(size)
            break
    else:
        raise PeError("the debug directory does not lie inside any section's file data")
    if len(table) < size:
        raise PeError("file ends inside the debug directory")
    for i in range(size // _DEBUG_ENTRY):
        _c, _ts, _maj, _min, kind, data_size, rva, ptr = struct.unpack_from("<IIHHIIII", table, i * _DEBUG_ENTRY)
        if kind != _IMAGE_DEBUG_TYPE_CODEVIEW:
            continue
        if data_size < _RSDS_HEADER:
            raise PeError("CodeView record is smaller than its RSDS header")
        _check_record_location(pe, rva, ptr)
        fh.seek(ptr)
        rec = fh.read(_RSDS_HEADER)
        if len(rec) < _RSDS_HEADER:
            raise PeError("file ends inside the CodeView record")
        if rec[:4] != b"RSDS":
            return None  # an old (NB10) or unrecognised record: no GUID to compare
        return CodeViewId(rec[4:20], struct.unpack_from("<I", rec, 20)[0])
    return None


def read_codeview_id_from_path(path: str | Path, pe: PeHeaders) -> CodeViewId | None:
    with open(path, "rb") as fh:
        return read_codeview_id(fh, pe)


def compare_sections(a: list[Section], b: list[Section]) -> list[str]:
    """Return human-readable differences between two section tables."""
    problems = []
    if len(a) != len(b):
        problems.append(f"section count differs: {len(a)} vs {len(b)}")
    for x, y in zip(a, b):
        for attr in ("name", "virtual_address", "virtual_size", "raw_size", "raw_pointer"):
            if getattr(x, attr) != getattr(y, attr):
                problems.append(f"section {x.index} {attr}: {getattr(x, attr)!r} vs {getattr(y, attr)!r}")
    return problems
