#!/bin/sh
# Regenerates small.dll / small.pdb from small.c: a known-good PDB written by
# LLVM's own linker, built so that no host path is embedded.
#
# Needs clang-cl and lld-link (LLVM; the committed pair was made with 23.1.1).
# Usage: sh build_small.sh        (from anywhere; writes next to this script)
#
# How the host path is kept out:
#   * the build runs in a fresh scratch directory, so any stray absolute path
#     would be the scratch directory, never the repo;
#   * -fdebug-compilation-dir / -fcoverage-compilation-dir pin the compiler's
#     "current directory" to the fixed string C:\src;
#   * /pdbsourcepath pins the linker's idea of the same directory (otherwise
#     lld-link records the real working directory in the PDB build-info stream);
#   * /PDBALTPATH embeds the bare name small.pdb in the DLL's debug directory;
#   * /Brepro makes the PE timestamp/GUID a hash of the content, so two builds
#     of the same inputs are byte-identical.
# What can still appear is the clang driver path (/usr/bin/clang-cl) and its
# resource dir (/usr/lib/clang/NN) in the recorded compiler command line:
# system paths, not the repo's. No toolchain flag was found that removes them.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
tmpd=$(mktemp -d)
trap 'rm -f "$tmpd"/* && rmdir "$tmpd"' EXIT
cp "$here/small.c" "$tmpd/small.c"
cd "$tmpd"
clang-cl --target=i686-pc-windows-msvc /Z7 /Od /Zl \
    '-fdebug-compilation-dir=C:\src' '-fcoverage-compilation-dir=C:\src' \
    /c small.c /Fosmall.obj
lld-link /DEBUG /NOENTRY /DLL /MACHINE:X86 /NODEFAULTLIB /EXPORT:mainfn \
    /Brepro /PDBALTPATH:small.pdb '/pdbsourcepath:C:\src' \
    /OUT:small.dll /PDB:small.pdb small.obj
cp small.dll small.pdb "$here/"
