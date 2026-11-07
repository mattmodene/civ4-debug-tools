"""MSF 7.00 container reader (the file format underneath a PDB).

Layout (all integers little-endian):

* Block 0 holds the 56-byte superblock: a 32-byte magic, then
  ``BlockSize, FreeBlockMapBlock, NumBlocks, NumDirectoryBytes, Unknown,
  BlockMapAddr`` (six ``uint32``).
* The stream directory is stored in ``ceil(NumDirectoryBytes / BlockSize)``
  blocks that need not be contiguous. Their block numbers are listed in the
  *block map*: ``uint32`` entries stored in ``ceil(nDirBlocks * 4 / BlockSize)``
  **consecutive** blocks starting at ``BlockMapAddr``. With a small block size
  and a large directory the block map spans several blocks; LLVM insists that it
  fit in one (see ``docs/llvm-diagnosis.md``), this reader does not.
* The directory is ``uint32 nStreams``, ``nStreams`` ``uint32`` byte sizes
  (``0xFFFFFFFF`` marks a deleted/nil stream), then each stream's block list.
"""

from __future__ import annotations

import mmap
import os
import struct
from pathlib import Path
from typing import BinaryIO

from .errors import Civ4DbgError

MAGIC = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\x00\x00\x00"
NIL_STREAM = 0xFFFFFFFF


class MsfError(Civ4DbgError):
    """Raised when the file is not a well-formed MSF 7.00 container."""


class Msf:
    """A parsed MSF container backed by a buffer (bytes, mmap, ...)."""

    def __init__(self, buf: bytes | mmap.mmap) -> None:
        self._buf = buf
        if len(buf) < 56 or bytes(buf[:32]) != MAGIC:
            raise MsfError("not an MSF 7.00 file (bad magic)")
        (
            self.block_size,
            self.free_block_map,
            self.num_blocks,
            self.dir_bytes,
            _unknown,
            self.block_map_addr,
        ) = struct.unpack_from("<6I", buf, 32)
        if self.block_size not in (512, 1024, 2048, 4096, 8192, 16384, 32768):
            raise MsfError(f"unsupported block size {self.block_size}")
        if self.num_blocks * self.block_size != len(buf):
            raise MsfError(f"file size {len(buf)} != NumBlocks*BlockSize {self.num_blocks * self.block_size}")
        self.num_dir_blocks = -(-self.dir_bytes // self.block_size)
        self.num_map_blocks = -(-self.num_dir_blocks * 4 // self.block_size)
        self._streams: list[tuple[int, list[int]]] = self._read_directory()

    # -- block access -----------------------------------------------------
    def _block(self, index: int) -> bytes:
        if not 0 <= index < self.num_blocks:
            raise MsfError(f"block {index} out of range (NumBlocks={self.num_blocks})")
        start = index * self.block_size
        return bytes(self._buf[start : start + self.block_size])

    def _read_blocks(self, blocks: list[int], size: int) -> bytes:
        return b"".join(self._block(b) for b in blocks)[:size]

    # -- directory --------------------------------------------------------
    def _read_directory(self) -> list[tuple[int, list[int]]]:
        try:
            return self._read_directory_unchecked()
        except struct.error as exc:
            raise MsfError(f"truncated or inconsistent stream directory: {exc}") from exc

    def _read_directory_unchecked(self) -> list[tuple[int, list[int]]]:
        map_bytes = b"".join(self._block(self.block_map_addr + i) for i in range(self.num_map_blocks))
        dir_blocks = list(struct.unpack_from(f"<{self.num_dir_blocks}I", map_bytes))
        directory = self._read_blocks(dir_blocks, self.dir_bytes)
        (n_streams,) = struct.unpack_from("<I", directory, 0)
        sizes = struct.unpack_from(f"<{n_streams}I", directory, 4)
        pos = 4 + 4 * n_streams
        streams: list[tuple[int, list[int]]] = []
        for size in sizes:
            n = 0 if size == NIL_STREAM else -(-size // self.block_size)
            blocks = list(struct.unpack_from(f"<{n}I", directory, pos)) if n else []
            pos += 4 * n
            streams.append((size, blocks))
        if pos != len(directory):
            raise MsfError(f"directory length mismatch: consumed {pos} of {len(directory)} bytes")
        return streams

    # -- public API -------------------------------------------------------
    @property
    def num_streams(self) -> int:
        return len(self._streams)

    def _entry(self, index: int) -> tuple[int, list[int]]:
        if not 0 <= index < len(self._streams):
            raise MsfError(f"stream {index} does not exist (the file has {len(self._streams)})")
        return self._streams[index]

    def stream_size(self, index: int) -> int:
        size = self._entry(index)[0]
        return 0 if size == NIL_STREAM else size

    def stream_exists(self, index: int) -> bool:
        return 0 <= index < len(self._streams) and self._streams[index][0] != NIL_STREAM

    def read_stream(self, index: int) -> bytes:
        """Return the full contents of stream ``index`` (empty for nil)."""
        size, blocks = self._entry(index)
        if size == NIL_STREAM:
            return b""
        return self._read_blocks(blocks, size)


class OpenedMsf(Msf):
    """An :class:`Msf` that owns a memory-mapped file."""

    def __init__(self, path: str | Path) -> None:
        self._fh: BinaryIO = open(path, "rb")
        try:
            if os.fstat(self._fh.fileno()).st_size == 0:
                raise MsfError("empty file (0 bytes)")
            try:
                mm = mmap.mmap(self._fh.fileno(), 0, access=mmap.ACCESS_READ)
            except ValueError as exc:  # e.g. a file the OS cannot map
                raise MsfError(f"cannot map the file: {exc}") from exc
            try:
                super().__init__(mm)
            except BaseException:
                mm.close()
                raise
        except BaseException:
            self._fh.close()
            raise

    def close(self) -> None:
        close = getattr(self._buf, "close", None)
        if close is not None:
            close()
        self._fh.close()

    def __enter__(self) -> OpenedMsf:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
