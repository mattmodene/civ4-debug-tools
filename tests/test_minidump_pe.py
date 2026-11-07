import struct

import pytest
from synth import build_minidump, section_header

from civ4dbg import minidump
from civ4dbg.pe import PeError, parse_pe_headers

DLL = (0x2C50000, 0x9E6000, r"S:\game\CvGameCoreDLL.dll")


def make(stack_words, exc_addr=0x31454A5, eip=0x31454A5):
    return build_minidump(
        [(0x400000, 0x100000, r"S:\game\Civ4BeyondSword.exe"), DLL],
        0xC0000005,
        exc_addr,
        (0, 0x34),
        eip,
        stack_words,
    )


def test_fault_and_access():
    info = minidump.parse_minidump(make([]))
    assert info.exception_code == 0xC0000005
    assert (info.access_type, info.access_target) == (0, 0x34)
    mod = info.module_at(info.exception_address)
    assert mod.name.endswith("CvGameCoreDLL.dll")
    assert info.exception_address - mod.base == 0x4F54A5


def test_stack_rvas_filters_to_module_and_keeps_order():
    base = DLL[0]
    words = [0x1, base + 0x4F74A8, 0xFFFFFFFF, base + 0x3510F2, base + DLL[1]]  # last is one past the end
    info = minidump.parse_minidump(make(words))
    mod = info.find_module("cvgamecoredll.dll")
    assert minidump.stack_rvas(info, mod) == [0x4F74A8, 0x3510F2]
    assert minidump.stack_rvas(info, mod, limit=1) == [0x4F74A8]


def test_bad_signature():
    with pytest.raises(minidump.MinidumpError):
        minidump.parse_minidump(b"NOPE" + b"\0" * 64)


def test_format_report_mentions_rva():
    info = minidump.parse_minidump(make([DLL[0] + 0x10]))
    text = minidump.format_report(info)
    assert "+0x4f54a5" in text and "0x10" in text


def test_pe_section_table():
    lfanew = 0x80
    head = bytearray(0x400)
    head[0:2] = b"MZ"
    struct.pack_into("<I", head, 0x3C, lfanew)
    head[lfanew : lfanew + 4] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", head, lfanew + 4, 0x14C, 2, 0x1234, 0, 0, 0xE0, 0x2102)
    opt = lfanew + 24
    struct.pack_into("<H", head, opt, 0x10B)
    struct.pack_into("<I", head, opt + 28, 0x10000000)
    struct.pack_into("<I", head, opt + 56, 0x20000)
    struct.pack_into("<I", head, opt + 60, 0x400)  # SizeOfHeaders
    table = opt + 0xE0
    head[table : table + 40] = section_header(".text", 0x746C3A, 0x1000, 0x747000, 0x1000)
    head[table + 40 : table + 80] = section_header(".data", 0x96104, 0x894000)
    pe = parse_pe_headers(bytes(head))
    assert pe.image_base == 0x10000000
    assert [(s.name, s.virtual_address) for s in pe.sections] == [(".text", 0x1000), (".data", 0x894000)]


def test_pe_rejects_non_pe():
    with pytest.raises(PeError):
        parse_pe_headers(b"\x7fELF" + b"\0" * 100)


REGS = {
    "edi": 0x0D,
    "esi": 0x11111111,
    "ebx": 0x22222222,
    "edx": 0x33333333,
    "ecx": 0x44444444,
    "eax": 0x0,
    "ebp": 0x55555555,
    "eflags": 0x10246,
}


def test_all_integer_registers_are_read_from_distinct_offsets():
    raw = build_minidump([DLL], 0xC0000005, 0x31454A5, (0, 0x34), 0x31454A5, [], registers=REGS)
    info = minidump.parse_minidump(raw)
    assert info.registers == {**REGS, "eip": 0x31454A5, "esp": 0x130000}
    assert info.eip == 0x31454A5 and info.esp == 0x130000


def test_format_report_prints_registers_in_fixed_order():
    raw = build_minidump([DLL], 0xC0000005, 0x31454A5, (0, 0x34), 0x31454A5, [], registers=REGS)
    text = minidump.format_report(minidump.parse_minidump(raw))
    assert (
        "registers: eax 0x0 ebx 0x22222222 ecx 0x44444444 edx 0x33333333 "
        "esi 0x11111111 edi 0xd ebp 0x55555555 esp 0x130000 eip 0x31454a5 eflags 0x10246"
    ) in text.splitlines()
