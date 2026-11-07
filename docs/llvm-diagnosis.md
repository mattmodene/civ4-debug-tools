# Why LLVM rejects the Caveman2Cosmos PDB

**Status**: Historical case study of the Caveman2Cosmos (C2C) PDB. It records why this tool reads PDBs itself, and says nothing about PDBs from other mods.

**Last Updated**: 2026-11-07
**Authors**: Matt Modene (mattmodene@modene.software)

## Symptom

`llvm-pdbutil dump -publics CvGameCoreDLL.pdb`, `llvm-pdbutil dump -summary ...`
and `llvm-symbolizer --obj=CvGameCoreDLL.dll` all fail with:

    The data is in an unexpected format. Too many directory blocks.

Reproduced on 2026-11-02 with `llvm-pdbutil` from **LLVM 23.1.1** (the original
hand-off reported LLVM 21, so the behaviour is not new).

## Finding: the container is self-consistent; LLVM's reader caps the block map at one block

The structural facts are reproducible with `tools/check_pdb_claims.py` (see
"Reproducing the checks"). The container is consistent with every check this
repository can run. The cause of the refusal was first *inferred* from the
message LLVM prints; the "Source check" section below compares that inference
with LLVM's public source, read on 2026-11-02, and it holds. The one-block cap
is: the *block map* (the list of directory block numbers) must fit in **one**
block.

| Quantity | Value |
|---|---|
| File size | 83,930,112 bytes |
| Block size | 1024 bytes |
| Blocks | 81,963 (`NumBlocks * BlockSize` equals the file size exactly) |
| Stream directory | 327,492 bytes = **320** blocks |
| Block map needed | 320 * 4 = **1280** bytes = **2** blocks (BlockMapAddr 81959, 81960) |
| Streams | 399 |

LLVM's check is, in effect, the following (the first version of this note
inferred it from two message strings found once, by hand, in the installed
library: reader side "Too many directory blocks." in `libLLVM.so.23.1`, writer
side "The directory block map ({0} bytes) doesn't fit in a block ({1} bytes)"; the
`llvm-pdbutil` failure itself was also run by hand and is not scripted here):

    NumDirectoryBlocks * 4 > BlockSize   ->   reject

With a 1024-byte block size that caps the directory at 256 blocks (256 KiB). The
C2C PDB has a 320-block directory, so it trips that limit. With the more
common 4096-byte block size the same rule caps the directory at 1024 blocks
(4 MiB), which would explain why this is rarely seen. That is arithmetic on the
rule, not a test: no 4096-byte-block PDB of this content was built or loaded
here, so whether one would load is **untested**.

### Source check (2026-11-02)

The source was fetched read-only from `raw.githubusercontent.com/llvm/llvm-project`
on 2026-11-02 (`main` was at commit `42ff89a36c3d`, 2026-11-02 14:07 UTC):

- `llvm/lib/DebugInfo/MSF/MSFCommon.cpp` (last changed in `2946cd701067`,
  2019-01-19), in `isValidSuperBlock`: `NumDirectoryBlocks = bytesToBlocks(SB.NumDirectoryBytes,
  SB.BlockSize)`, then `if (NumDirectoryBlocks > SB.BlockSize / sizeof(ulittle32_t))`
  returns the error "Too many directory blocks." The comment above it reads: "The
  directory, as we understand it, is a block which consists of a list of block
  numbers. It is unclear what would happen if the number of blocks couldn't fit on
  a single block." This is the reader's cap, and it is the same condition as above.
- `llvm/lib/DebugInfo/MSF/MSFBuilder.cpp` (last changed in `0bbf644a01c1`,
  2025-11-12), in `MSFBuilder::commit`: `DirectoryBlockMapSize = NumDirectoryBlocks *
  sizeof(ulittle32_t)`; `if (DirectoryBlockMapSize > BlockSize)` returns "The
  directory block map ({0} bytes) doesn't fit in a block ({1} bytes)". This is the
  writer's cap.
- `llvm/lib/DebugInfo/PDB/Native/PDBFile.cpp` (last changed in `a36723fa84e5`,
  2026-10-28), in `parseFileHeaders`: after validation the reader does
  `Reader.setOffset(getBlockMapOffset())` and `readArray(DirectoryBlocks,
  getNumDirectoryBlocks())`, one contiguous array of that many entries starting at
  `BlockMapAddr`. Nothing in that read limits it to one block, so the check in
  `MSFCommon.cpp` is what refuses a file whose map spans two.
- `llvm/docs/PDB/MsfFile.md` (last changed in `d0b078ef5b6b`, 2026-08-25) describes
  the block map as an array of `ceil(NumDirectoryBytes / BlockSize)` entries at
  `BlockMapAddr`. It does not say whether the array may continue into the following
  blocks.

What this does not show: the source gives LLVM's behaviour. It does not show that
the format *allows* a multi-block map; the LLVM comment itself says that is unclear.
Microsoft's own writer was not checked for it (the `microsoft-pdb` repository was
not searched for the map layout). This repository's reader treats the map as
consecutive blocks and consumes the directory exactly, which is evidence the C2C
file was written that way, not proof that other tools do.

## Evidence that the file is not malformed

Items 1 to 3 are reproduced by `tools/check_pdb_claims.py`; item 4 was checked
once, by hand, and cannot be reproduced from this repository. Note that the
script reuses this repository's own MSF parser: items 1 to 3 show the file is
consistent *as this parser reads it*, which is why item 4 matters.

1. Reading the block map as consecutive blocks starting at `BlockMapAddr`
   (`ceil(320*4/1024) = 2` blocks) yields 320 directory block numbers. The
   directory they describe is consumed **exactly**: 4 + 4*399 bytes of header plus
   every stream's block list equals the directory size with no bytes left over.
   (Script lines: "file size", "block map and directory arithmetic".)
2. No block is claimed twice: the superblock, free-block-map blocks, block map,
   directory blocks and all stream blocks are pairwise disjoint (81,958 distinct
   blocks, none twice). (Script line: "blocks pairwise disjoint".)
3. Every stream parsed from the directory is internally consistent: the DBI
   header's substream sizes add up to the DBI stream length exactly; the
   section-header stream parses to 5 sections that equal the DLL's PE section
   table field by field; all 46,133 `S_GPROC32` records have an `S_PUB32` at the
   same section:offset. (Script lines: "DBI sums, GPROC32 has a PUB32", "PDB
   section table == DLL PE table".)
4. **Checked once, manually (not reproducible from this repo):** an independent
   implementation, **pdbparse 1.5** (PyPI), read the same directory: 399
   streams, identical sizes and identical block lists for every stream. It then
   failed much later, in type-stream parsing, because of its own `construct`
   version pin. pdbparse does not install on current Python versions, so this
   check is not scripted and the repository carries no copy of its output.

## Reproducing the checks

    python3 -I tools/check_pdb_claims.py --pdb CvGameCoreDLL.pdb --dll CvGameCoreDLL.dll

The script prints one PASS/FAIL line per check with the measured figures (the
figures quoted above come from this output on 2026-11-02) and exits 0 when every
check holds. It reads PDB streams and the DLL's PE section table only.

## One oddity, unrelated to the rejection

The active free-block map (block 2) marks exactly 320 in-use blocks as *free*
(`tools/check_pdb_claims.py`, line "free-block map vs in-use blocks"). That count
equals the number of directory blocks, which suggests the map is stale relative
to the last directory write; this is a guess from the matching count. No reader that
only reads streams (this one, pdbparse) is affected. It is not what LLVM
complains about. Not investigated further.

## Note for LLVM upstream

The Caveman2Cosmos PDB has a 320-block directory with 1024-byte blocks, so its block map
(`320 * 4 = 1280` bytes) occupies two blocks at `BlockMapAddr`, and the rest of
the file is consistent with that (see "Evidence that the file is not malformed").
LLVM's reader (`MSFCommon.cpp`, `isValidSuperBlock`) and writer (`MSFBuilder.cpp`,
`commit`) both cap the map at one block; the source comment says it is unclear what
should happen otherwise. `PDBFile::parseFileHeaders` already reads the map as one
contiguous array of `NumDirectoryBlocks` entries from `BlockMapAddr`, so lifting the
cap in the validator looks like the whole change, but that is an unverified
suggestion: I have not built or run an LLVM with it. Whether the PDB format
officially allows a multi-block map was not checked beyond the LLVM docs, which are
silent on it. A reproduction needs the
84 MB PDB (a game file, not redistributable here); a synthetic file with 512-byte blocks and a
directory over 128 blocks reproduces the same shape, see
`tests/test_msf.py::test_directory_needing_multiple_block_map_blocks`.
