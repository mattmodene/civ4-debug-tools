"""Does the minidump belong to the same build as the DLL on disk?

A minidump's module record carries the loaded module's ``TimeDateStamp`` and
``SizeOfImage``. The DLL's PE headers carry the same two fields
(``FileHeader.TimeDateStamp``, ``OptionalHeader.SizeOfImage``). A dump from
another build of the mod must not be resolved against this DLL and PDB: the
names would be confidently wrong.

:func:`pdb_mismatches` additionally compares the PDB's GUID and ages with the DLL's
CodeView record: the debug-directory entry and the first 24 bytes of the RSDS record
(signature, GUID, age). The age rule comes from Microsoft's published microsoft-pdb
source, cited in :func:`pdb_mismatches`.
"""

from __future__ import annotations

from datetime import UTC, datetime

from .minidump import Module
from .pe import CodeViewId, PeHeaders


def _when(ts: int) -> str:
    try:
        return datetime.fromtimestamp(ts, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
    except (OverflowError, OSError, ValueError):
        return "out of range"


def build_mismatches(module: Module, pe: PeHeaders) -> list[str]:
    """Human-readable differences; an empty list means the two records agree."""
    problems = []
    if module.timestamp != pe.timestamp:
        problems.append(
            f"TimeDateStamp: dump {module.timestamp:#010x} ({_when(module.timestamp)}) "
            f"vs DLL {pe.timestamp:#010x} ({_when(pe.timestamp)})"
        )
    if module.size != pe.size_of_image:
        problems.append(f"SizeOfImage: dump {module.size:#x} vs DLL {pe.size_of_image:#x}")
    return problems


def _fmt_guid(g: bytes) -> str:
    import uuid

    return str(uuid.UUID(bytes_le=g)).upper()


def pdb_mismatches(pdb_id: tuple[bytes, int], cv: CodeViewId, dbi_age: int | None = None) -> list[str]:
    """Differences between the PDB's identity and the DLL's CodeView record.

    The rule follows Microsoft's published ``PDB1::OpenValidate`` (microsoft-pdb,
    ``PDB/dbi/pdb.cpp``, fetched 2026-11-02): the PDB info
    stream's GUID must equal the image's, its age must be greater than or equal to
    the image's, and the DBI header's age must equal the image's or be 0. This is a
    reading of that source; it was not run against a debugger. ``dbi_age=None``
    skips the DBI test.
    """
    problems = []
    if pdb_id[0] != cv.guid:
        problems.append(f"GUID: PDB {_fmt_guid(pdb_id[0])} vs DLL {_fmt_guid(cv.guid)}")
    if pdb_id[1] < cv.age:
        problems.append(f"age: PDB info-stream age {pdb_id[1]} is older than the DLL's {cv.age}")
    if dbi_age not in (None, 0, cv.age):
        problems.append(f"age: PDB DBI-header age {dbi_age} differs from the DLL's {cv.age}")
    return problems


def pdb_age_note(pdb_id: tuple[bytes, int], cv: CodeViewId, dbi_age: int | None = None) -> str | None:
    """An informational note when the info-stream age differs from the DLL's (accepted)."""
    if pdb_id[1] != cv.age:
        dbi = "" if dbi_age is None else f", DBI age {dbi_age}"
        return (
            f"PDB info-stream age {pdb_id[1]}{dbi}, DLL age {cv.age}; accepted: GUIDs match "
            "and the PDB age is not older"
        )
    return None
