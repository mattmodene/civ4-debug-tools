"""The PE reader stays inside SizeOfHeaders and rejects inconsistent headers."""

import io
import pathlib
import random
import struct

import pytest
from synth import build_pe, section_header

from civ4dbg.pe import MAX_HEADER_BYTES, PeError, parse_pe_headers, read_pe_headers, read_pe_headers_from

SECTIONS = [section_header(".text", 0x746C3A, 0x1000, 0x747000, 0x400), section_header(".data", 0x96104, 0x894000)]
FIX = pathlib.Path(__file__).parent / "fixtures"


class Watermark(io.BytesIO):
    """Records the highest file offset any read reached."""

    high = 0

    def read(self, n=-1):
        data = super().read(n)
        self.high = max(self.high, self.tell())
        return data


@pytest.mark.parametrize("size_of_headers", [0x200, 0x400, 0x1000])
def test_reads_exactly_size_of_headers_and_never_section_contents(size_of_headers):
    raw = build_pe(size_of_headers, SECTIONS, total=0x8000)
    assert len(raw) == 0x8000 and raw[size_of_headers:][:1] == b"\xcc"
    fh = Watermark(raw)
    pe = read_pe_headers_from(fh)
    assert fh.high == size_of_headers  # not 4096, and not one byte of the marker region
    assert pe.size_of_headers == size_of_headers
    assert [s.name for s in pe.sections] == [".text", ".data"]
    assert (pe.timestamp, pe.size_of_image, pe.image_base) == (0x6A8E2472, 0x20000, 0x10000000)


def test_small_headers_do_not_pull_in_the_following_4k(tmp_path):
    f = tmp_path / "a.dll"
    f.write_bytes(build_pe(0x200, SECTIONS, total=0x6000))
    assert read_pe_headers(f).size_of_headers == 0x200


def test_the_committed_fixture_dll_is_read_within_its_headers():
    raw = (FIX / "small.dll").read_bytes()
    fh = Watermark(raw)
    pe = read_pe_headers_from(fh)
    assert fh.high == pe.size_of_headers < len(raw)


def test_parse_ignores_bytes_after_size_of_headers():
    """A section table that would extend past SizeOfHeaders is an error, even if the
    next bytes exist in the buffer: they are section contents, not headers."""
    raw = bytearray(build_pe(0x200, SECTIONS, total=0x1000))
    nsec_at = 0x80 + 4 + 2
    struct.pack_into("<H", raw, nsec_at, 20)  # 20 headers need 0x80+24+0xE0+800 > 0x200
    with pytest.raises(PeError, match="does not fit inside SizeOfHeaders"):
        parse_pe_headers(bytes(raw))
    # the same table fits when SizeOfHeaders is large enough
    raw = bytearray(build_pe(0x800, SECTIONS, total=0x1000))
    struct.pack_into("<H", raw, nsec_at, 20)
    assert len(parse_pe_headers(bytes(raw)).sections) == 20


@pytest.mark.parametrize("bad", [0, MAX_HEADER_BYTES + 1, 0xFFFFFFFF])
def test_implausible_size_of_headers_is_rejected(bad):
    raw = bytearray(build_pe(0x200, SECTIONS))
    struct.pack_into("<I", raw, 0x80 + 24 + 60, bad)
    with pytest.raises(PeError, match="SizeOfHeaders"):
        parse_pe_headers(bytes(raw))
    with pytest.raises(PeError, match="SizeOfHeaders"):
        read_pe_headers_from(io.BytesIO(bytes(raw)))


@pytest.mark.parametrize("lfanew", [0, 0x20, 0x10001, 0xFFFFFFFF])
def test_implausible_e_lfanew_is_rejected(lfanew):
    raw = bytearray(build_pe(0x200, SECTIONS))
    struct.pack_into("<I", raw, 0x3C, lfanew)
    with pytest.raises(PeError):
        parse_pe_headers(bytes(raw))
    with pytest.raises(PeError):
        read_pe_headers_from(io.BytesIO(bytes(raw)))


def test_section_count_above_the_pe_limit_is_rejected():
    raw = bytearray(build_pe(0x200, SECTIONS))
    struct.pack_into("<H", raw, 0x80 + 4 + 2, 97)
    with pytest.raises(PeError, match="section count"):
        parse_pe_headers(bytes(raw))


def test_unknown_optional_header_magic_is_rejected():
    raw = bytearray(build_pe(0x200, SECTIONS))
    struct.pack_into("<H", raw, 0x80 + 24, 0x1234)
    with pytest.raises(PeError, match="magic"):
        parse_pe_headers(bytes(raw))


def test_missing_signatures_are_pe_errors():
    with pytest.raises(PeError, match="MZ"):
        parse_pe_headers(b"\x7fELF" + b"\0" * 200)
    raw = bytearray(build_pe(0x200, SECTIONS))
    raw[0x80:0x84] = b"XX\0\0"
    with pytest.raises(PeError, match="PE signature"):
        parse_pe_headers(bytes(raw))


def test_file_that_ends_inside_its_headers_is_a_pe_error():
    raw = build_pe(0x400, SECTIONS)[:0x300]
    with pytest.raises(PeError):
        read_pe_headers_from(io.BytesIO(raw))


@pytest.mark.parametrize("length", [0, 1, 0x3F, 0x40, 0x80, 0x90, 0xA0, 0xD7, 0xD8])
def test_every_short_prefix_is_a_pe_error(length):
    raw = build_pe(0x400, SECTIONS)[:length]
    with pytest.raises(PeError):
        read_pe_headers_from(io.BytesIO(raw))
    with pytest.raises(PeError):
        parse_pe_headers(raw)


def test_seeded_bit_flip_fuzz_only_raises_pe_errors():
    base = build_pe(0x400, SECTIONS, total=0x800)[:0x400]
    rnd = random.Random(20261102)
    for _ in range(3000):
        b = bytearray(base)
        for _ in range(rnd.randint(1, 4)):
            b[rnd.randrange(0x400)] = rnd.randrange(256)
        for fn in (
            lambda: parse_pe_headers(bytes(b)),
            lambda: read_pe_headers_from(io.BytesIO(bytes(b) + b"\xcc" * 0x400)),
        ):
            try:
                fn()
            except PeError:
                pass


@pytest.mark.parametrize("lfanew", [0x10001, 0x7FFFFFFF, 0xFFFFFFFF])
def test_a_huge_e_lfanew_does_not_make_the_reader_read_the_file(lfanew):
    raw = bytearray(build_pe(0x200, SECTIONS, total=0x40000))
    struct.pack_into("<I", raw, 0x3C, lfanew)
    fh = Watermark(bytes(raw))
    with pytest.raises(PeError, match="e_lfanew"):
        read_pe_headers_from(fh)
    assert fh.high == 0x40  # only the DOS header was read
