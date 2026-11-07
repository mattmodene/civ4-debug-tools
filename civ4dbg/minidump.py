"""Minimal Windows minidump reader for 32-bit (x86) crash dumps.

Reads only the streams needed to name a crash site or a thread's position: the
thread list (3), the module list (4), the memory list (5) and the exception
stream (6). The x86 ``CONTEXT`` offsets
(the integer registers 0x9C-0xC4, see ``_CTX_X86_REGISTERS``) are hard-coded, so
this reader targets x86 dumps.
Standard library only.
"""

from __future__ import annotations

import struct
import sys
from array import array
from dataclasses import dataclass, field
from pathlib import Path

from .errors import Civ4DbgError, UnsupportedError

STREAM_THREAD_LIST = 3
STREAM_MODULE_LIST = 4
STREAM_MEMORY_LIST = 5
STREAM_EXCEPTION = 6
STREAM_SYSTEM_INFO = 7
STREAM_MEMORY64_LIST = 9
PROCESSOR_ARCHITECTURE_X86 = 0
MAX_STREAMS = 0x1000  # a real dump has tens; more is treated as corrupt

# x86 CONTEXT integer registers and their offsets (winnt.h CONTEXT, 32-bit).
_CTX_X86_REGISTERS = (
    ("edi", 0x9C),
    ("esi", 0xA0),
    ("ebx", 0xA4),
    ("edx", 0xA8),
    ("ecx", 0xAC),
    ("eax", 0xB0),
    ("ebp", 0xB4),
    ("eip", 0xB8),
    ("eflags", 0xC0),
    ("esp", 0xC4),
)
REGISTER_ORDER = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip", "eflags")
_CTX_X86_MIN_SIZE = 0xCC  # through SegSs; everything this reader touches lies below
_MODULE_ENTRY_SIZE = 108
_STACK_SCAN_BYTES = 0x1000
_THREAD_ENTRY_SIZE = 48  # MINIDUMP_THREAD
MAX_THREADS = 0x10000  # a real process has tens; more is treated as corrupt
_THREAD_STACK_MAX_BYTES = 0x400000  # per-thread scan cap (4 MiB from esp)
_TOTAL_STACK_MAX_BYTES = 0x4000000  # cap over all threads together (64 MiB); more is treated as corrupt

# Exception codes a debugger raises when it attaches and breaks in; a dump whose only
# exception is one of these is a snapshot of a live process, not a crash.
EXC_BREAKPOINT = 0x80000003
EXC_WOW64_BREAKPOINT = 0x4000001F
BREAK_IN_CODES = (EXC_BREAKPOINT, EXC_WOW64_BREAKPOINT)

ACCESS_TYPES = {0: "read", 1: "write", 8: "DEP (execute)"}


class MinidumpError(Civ4DbgError):
    """Raised when the file is not a minidump this reader understands."""


class UnsupportedDumpError(MinidumpError, UnsupportedError):
    """A well-formed minidump of a kind this reader does not handle (not x86, 64-bit memory list)."""


@dataclass(frozen=True)
class Module:
    base: int
    size: int
    name: str
    timestamp: int = 0  # TimeDateStamp of the module's PE file header, as recorded in the dump
    checksum: int = 0

    @property
    def basename(self) -> str:
        return self.name.replace("\\", "/").rsplit("/", 1)[-1]

    def contains(self, address: int) -> bool:
        return self.base <= address < self.base + self.size


@dataclass
class ThreadInfo:
    """One ThreadList entry: id, x86 integer registers and the words on its stack.

    ``stack_words`` are the 32-bit words from ``esp`` up to the end of the thread's
    stack range (capped at 4 MiB); ``stack_total_words`` is how many there are to
    the end of that range, so ``len(stack_words) < stack_total_words`` means the
    cap cut the scan. Both are empty/zero when ``esp`` lies in no captured range.
    They are numbers to look up in the PDB, nothing more.
    """

    index: int  # position in the ThreadList
    thread_id: int
    registers: dict[str, int]
    stack_start: int  # range holding esp (0 when none)
    stack_size: int
    stack_words: array[int] = field(default_factory=lambda: array("I"))
    stack_total_words: int = 0

    @property
    def eip(self) -> int:
        return self.registers.get("eip", 0)

    @property
    def esp(self) -> int:
        return self.registers.get("esp", 0)


@dataclass
class CrashInfo:
    thread_id: int
    exception_code: int
    exception_address: int
    access_type: int | None
    access_target: int | None
    eip: int
    esp: int
    modules: list[Module] = field(default_factory=list)
    stack_words: list[int] = field(default_factory=list)
    registers: dict[str, int] = field(default_factory=dict)  # full x86 CONTEXT integer registers
    threads: list[ThreadInfo] = field(default_factory=list)  # ThreadList (empty when the dump has none)
    has_exception: bool = True  # False: no exception stream (a ThreadList-only snapshot)
    thread_list_error: str | None = None  # set when a crash dump's ThreadList was unusable and was skipped

    @property
    def is_snapshot(self) -> bool:
        """True for a hang/snapshot dump: no exception record, or only a debugger break-in.

        Such a dump records where every thread was at attach time; the exception
        thread (when present) is the debugger's own break-in thread, not a fault.
        """
        return (not self.has_exception) or self.exception_code in BREAK_IN_CODES

    def thread(self, thread_id: int) -> ThreadInfo | None:
        for t in self.threads:
            if t.thread_id == thread_id:
                return t
        return None

    def module_at(self, address: int) -> Module | None:
        for m in self.modules:
            if m.contains(address):
                return m
        return None

    def find_module(self, name: str) -> Module | None:
        """The module whose file name equals ``name`` (case-insensitive, directories ignored)."""
        want = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
        for m in self.modules:
            if m.basename.lower() == want:
                return m
        return None


def _utf16_string(data: bytes, off: int) -> str:
    (length,) = struct.unpack_from("<I", data, off)
    return data[off + 4 : off + 4 + length].decode("utf-16le")


def parse_minidump(data: bytes) -> CrashInfo:
    """Parse the bytes of a minidump file into a :class:`CrashInfo`.

    Raises :class:`MinidumpError` (or its :class:`UnsupportedDumpError`
    subclass) for every malformed or unsupported input; nothing else escapes.
    """
    try:
        return _parse(data)
    except (struct.error, IndexError, UnicodeDecodeError, OverflowError) as exc:
        raise MinidumpError(f"truncated or inconsistent minidump: {exc}") from exc


def _parse(data: bytes) -> CrashInfo:
    if len(data) < 32:
        raise MinidumpError("file too short for a minidump header")
    sig, _version, n_streams, dir_rva = struct.unpack_from("<4sIII", data, 0)
    if sig != b"MDMP":
        raise MinidumpError(f"bad minidump signature {sig!r}")
    if n_streams > MAX_STREAMS:
        raise MinidumpError(f"implausible stream count {n_streams}")
    streams: dict[int, tuple[int, int]] = {}
    for i in range(n_streams):
        kind, size, off = struct.unpack_from("<III", data, dir_rva + 12 * i)
        streams[kind] = (size, off)
    if STREAM_SYSTEM_INFO in streams:
        _, sys_off = streams[STREAM_SYSTEM_INFO]
        (arch,) = struct.unpack_from("<H", data, sys_off)
        if arch != PROCESSOR_ARCHITECTURE_X86:
            raise UnsupportedDumpError(
                f"minidump is for processor architecture {arch}, not x86 (0); this reader "
                "decodes only the x86 thread context"
            )
    # The exception stream may be absent only in a dump that has a ThreadList (a snapshot).
    required = (STREAM_MODULE_LIST, STREAM_MEMORY_LIST)
    if STREAM_THREAD_LIST not in streams:
        required += (STREAM_EXCEPTION,)
    for needed in required:
        if needed not in streams:
            if needed == STREAM_MEMORY_LIST and STREAM_MEMORY64_LIST in streams:
                raise UnsupportedDumpError(
                    "minidump has a Memory64List (stream 9, a full-memory dump) but no "
                    "MemoryList (stream 5); only MemoryList dumps are supported"
                )
            raise MinidumpError(f"minidump has no stream {needed}")

    _, off = streams[STREAM_MODULE_LIST]
    (count,) = struct.unpack_from("<I", data, off)
    modules = []
    for i in range(count):
        base, size, chk, ts, name_rva = struct.unpack_from("<QIIII", data, off + 4 + _MODULE_ENTRY_SIZE * i)
        modules.append(Module(base, size, _utf16_string(data, name_rva), ts, chk))

    ranges = _memory_ranges(data, streams[STREAM_MEMORY_LIST][1])
    threads: list[ThreadInfo] = []
    thread_list_error = None
    if STREAM_THREAD_LIST in streams:
        try:
            threads = _parse_threads(data, streams[STREAM_THREAD_LIST][1], ranges, modules)
        except (MinidumpError, struct.error, IndexError, OverflowError) as exc:
            if STREAM_EXCEPTION not in streams:
                raise  # a snapshot has nothing else to show
            thread_list_error = str(exc)  # a crash dump keeps its exception-thread report

    if STREAM_EXCEPTION not in streams:
        return CrashInfo(
            thread_id=0,
            exception_code=0,
            exception_address=0,
            access_type=None,
            access_target=None,
            eip=0,
            esp=0,
            modules=modules,
            threads=threads,
            has_exception=False,
        )

    _, off = streams[STREAM_EXCEPTION]
    thread_id, _ = struct.unpack_from("<II", data, off)
    code, _flags, _record, address, n_params = struct.unpack_from("<IIQQI", data, off + 8)
    params = struct.unpack_from("<15Q", data, off + 8 + 32)
    access_type = access_target = None
    if code == 0xC0000005 and n_params >= 2:
        access_type, access_target = params[0], params[1]
    ctx_size, ctx_rva = struct.unpack_from("<II", data, off + 8 + 152)
    if ctx_size < _CTX_X86_MIN_SIZE:
        raise MinidumpError(
            f"thread context is {ctx_size} bytes, too small for an x86 CONTEXT ({_CTX_X86_MIN_SIZE:#x} needed)"
        )
    registers = {name: struct.unpack_from("<I", data, ctx_rva + off)[0] for name, off in _CTX_X86_REGISTERS}
    eip = registers["eip"]
    esp = registers["esp"]

    stack_words: list[int] = []
    for start, size, rva in ranges:
        if start <= esp < start + size:
            blob = data[rva : rva + size]
            begin = esp - start
            end = min(len(blob) - 3, begin + _STACK_SCAN_BYTES)
            stack_words = [struct.unpack_from("<I", blob, k)[0] for k in range(begin, end, 4)]
            break

    return CrashInfo(
        thread_id=thread_id,
        exception_code=code,
        exception_address=address,
        access_type=access_type,
        access_target=access_target,
        eip=eip,
        esp=esp,
        modules=modules,
        stack_words=stack_words,
        registers=registers,
        threads=threads,
        thread_list_error=thread_list_error,
    )


def _memory_ranges(data: bytes, off: int) -> list[tuple[int, int, int]]:
    (n_ranges,) = struct.unpack_from("<I", data, off)
    return [struct.unpack_from("<QII", data, off + 4 + 16 * i) for i in range(n_ranges)]


def _parse_threads(
    data: bytes, off: int, ranges: list[tuple[int, int, int]], modules: list[Module]
) -> list[ThreadInfo]:
    """The ThreadList stream (3): every thread's id, registers and stack words."""
    (count,) = struct.unpack_from("<I", data, off)
    if count > MAX_THREADS or off + 4 + _THREAD_ENTRY_SIZE * count > len(data):
        raise MinidumpError(f"implausible or truncated ThreadList: {count} threads")
    out: list[ThreadInfo] = []
    budget = _TOTAL_STACK_MAX_BYTES
    for i in range(count):
        tid, _suspend, _pclass, _prio, _teb, s_start, s_size, s_rva, c_size, c_rva = struct.unpack_from(
            "<IIIIQQIIII", data, off + 4 + _THREAD_ENTRY_SIZE * i
        )
        if c_size < _CTX_X86_MIN_SIZE or c_rva + c_size > len(data):
            raise MinidumpError(
                f"thread {tid} (ThreadList entry {i}): context of {c_size} bytes at "
                f"{c_rva:#x} is too small for an x86 CONTEXT or lies outside the file"
            )
        regs = {n: struct.unpack_from("<I", data, c_rva + o)[0] for n, o in _CTX_X86_REGISTERS}
        esp = regs["esp"]
        if s_size and s_rva + s_size > len(data):
            raise MinidumpError(
                f"thread {tid} (ThreadList entry {i}): stack memory at {s_rva:#x} (+{s_size:#x}) lies outside the file"
            )
        # Prefer the thread's own stack descriptor; else the MemoryList range holding esp.
        rng = None
        if s_start <= esp < s_start + s_size:
            rng = (s_start, s_size, s_rva)
        else:
            for r in ranges:
                # never take a range that overlaps a listed module: that would be code, not stack
                in_module = any(r[0] < m.base + m.size and m.base < r[0] + r[1] for m in modules)
                if r[0] <= esp < r[0] + r[1] and not in_module:
                    rng = r
                    break
        words = array("I")
        total = 0
        r_start = r_size = 0
        if rng is not None:
            r_start, r_size, r_rva = rng
            if r_rva + r_size > len(data):
                raise MinidumpError(
                    f"thread {tid} (ThreadList entry {i}): stack range at {r_rva:#x} "
                    f"(+{r_size:#x}) lies outside the file"
                )
            begin = esp - r_start
            total = (r_size - begin) // 4
            n = min(total, _THREAD_STACK_MAX_BYTES // 4)
            budget -= n * 4
            if budget < 0:
                raise MinidumpError(
                    f"ThreadList stacks add up to more than {_TOTAL_STACK_MAX_BYTES:#x} bytes "
                    "(entries share stack ranges?); refusing to scan them"
                )
            if n:
                words.frombytes(data[r_rva + begin : r_rva + begin + n * 4])
                if sys.byteorder == "big":
                    words.byteswap()
        out.append(ThreadInfo(i, tid, regs, r_start, r_size, words, total))
    return out


def read_minidump(path: str | Path) -> CrashInfo:
    return parse_minidump(Path(path).read_bytes())


def stack_rvas(info: CrashInfo, module: Module, limit: int | None = 20) -> list[int]:
    """Stack words that fall inside ``module``, as RVAs, innermost first.

    Heuristic: this is a scan for plausible return addresses, not an unwind.
    """
    out = [w - module.base for w in info.stack_words if module.contains(w)]
    return out if limit is None else out[:limit]


def thread_stack_rvas(thread: ThreadInfo, module: Module, limit: int | None = 20) -> list[int]:
    """A thread's stack words that fall inside ``module``, as RVAs, innermost first.

    Same heuristic as :func:`stack_rvas`: candidates, not an unwind.
    """
    out = [w - module.base for w in thread.stack_words if module.contains(w)]
    return out if limit is None else out[:limit]


def format_snapshot_report(info: CrashInfo, module_name: str = "CvGameCoreDLL.dll") -> str:
    """Header for a hang/snapshot dump: says plainly that there is no fault."""
    if not info.has_exception:
        lines = ["hang/snapshot dump: no exception record; not a crash"]
    else:
        lines = [
            f"hang/snapshot dump: exception {info.exception_code:#x} (breakpoint) at "
            f"{info.exception_address:#x} on thread {info.thread_id}; treated as a debugger "
            "break-in, so presented as a snapshot (not a crash)",
            f"for a debugger attach, thread {info.thread_id} is the break-in thread and its "
            "position says nothing about the hang. If this is instead a real breakpoint crash "
            f"(int 3 / assert), use --thread {info.thread_id} to see that thread",
        ]
    lines.append(f"{len(info.threads)} threads in the ThreadList")
    target = info.find_module(module_name)
    if target:
        lines.append(
            f"{len(info.modules)} modules; {target.basename} base {target.base:#x} "
            f"size {target.size:#x} timestamp {target.timestamp:#x}"
        )
    return "\n".join(lines)


def format_report(info: CrashInfo, module_name: str = "CvGameCoreDLL.dll") -> str:
    if info.is_snapshot:
        return format_snapshot_report(info, module_name)
    lines = [
        f"thread {info.thread_id} code {info.exception_code:#x} address {info.exception_address:#x}",
        f"eip {info.eip:#x} esp {info.esp:#x}",
    ]
    if info.registers:
        lines.append(
            "registers: " + " ".join(f"{n} {info.registers[n]:#x}" for n in REGISTER_ORDER if n in info.registers)
        )
    fault = info.module_at(info.exception_address)
    if fault:
        lines.append(f"in module {fault.name} +{info.exception_address - fault.base:#x}")
    if info.access_type is not None:
        lines.append(
            f"access type {info.access_type} ({ACCESS_TYPES.get(info.access_type, '?')}) target {info.access_target:#x}"
        )
    target = info.find_module(module_name)
    if target:
        lines.append(
            f"{len(info.modules)} modules; {target.basename} base {target.base:#x} "
            f"size {target.size:#x} timestamp {target.timestamp:#x}"
        )
        lines.append(
            "words on the stack that point into the module (RVAs; return-address candidates): "
            + " ".join(f"{r:#x}" for r in stack_rvas(info, target))
        )
    return "\n".join(lines)
