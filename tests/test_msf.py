import struct

import pytest
from synth import build_msf

from civ4dbg.msf import Msf, MsfError


def test_roundtrip_small_directory():
    streams = [b"A" * 10, None, bytes(range(256)) * 5, b""]
    msf = Msf(build_msf(streams, block_size=512))
    assert msf.num_streams == 4
    assert msf.num_map_blocks == 1
    assert msf.read_stream(0) == streams[0]
    assert not msf.stream_exists(1)
    assert msf.read_stream(1) == b""
    assert msf.read_stream(2) == streams[2]
    assert msf.read_stream(3) == b""


def test_directory_needing_multiple_block_map_blocks():
    """512-byte blocks: >128 directory blocks overflow a single block-map block.

    This is the shape of the Caveman2Cosmos PDB (1024-byte blocks, 320 directory
    blocks, 2 block-map blocks) that LLVM rejects with 'Too many directory blocks'.
    """
    big = bytes((i * 7 + 3) % 251 for i in range(512 * 17000))
    streams = [big, b"tail-stream"]
    raw = build_msf(streams, block_size=512)
    msf = Msf(raw)
    assert msf.num_dir_blocks > 128
    assert msf.num_map_blocks >= 2
    assert msf.read_stream(0) == big
    assert msf.read_stream(1) == b"tail-stream"


def test_bad_magic_rejected():
    raw = bytearray(build_msf([b"x"]))
    raw[0:4] = b"XXXX"
    with pytest.raises(MsfError):
        Msf(bytes(raw))


def test_size_mismatch_rejected():
    raw = build_msf([b"x"])
    with pytest.raises(MsfError):
        Msf(raw + b"\0" * 512)


def test_directory_length_mismatch_detected():
    raw = bytearray(build_msf([b"x" * 600, b"y"]))
    # Corrupt stream 1's size so the block lists no longer fill the directory.
    msf = Msf(bytes(raw))
    dir_block = struct.unpack_from("<I", raw, msf.block_map_addr * 512)[0]
    struct.pack_into("<I", raw, dir_block * 512 + 8, 5000)
    with pytest.raises(MsfError):
        Msf(bytes(raw))
