"""The tool's own exception types and the CLI exit codes they map to.

Every malformed-input path in ``msf``, ``pdb``, ``pe`` and ``minidump`` ends in
one of these. The command line turns each into a one-line ``error: ...`` message
and a defined exit code; nothing else may escape on bad input.
"""

from __future__ import annotations

# Exit codes (documented in README.md)
EXIT_OK = 0
EXIT_INPUT = 1  # unreadable or malformed input file
EXIT_NOT_FOUND = 2  # also argparse's usage-error code: bad option, or module absent from the dump
EXIT_BUILD_MISMATCH = 3  # the dump, the DLL and (by extension) the PDB are not the same build
EXIT_UNSUPPORTED = 4  # well-formed but not supported (OMAP-translated PDB, non-x86 dump)
EXIT_INTERNAL = 5  # backstop: an unexpected exception type escaped; this is a bug to report


class Civ4DbgError(ValueError):
    """Base class of every error this tool raises on bad input."""

    exit_code = EXIT_INPUT


class UnsupportedError(Civ4DbgError):
    """Input that is well formed but uses a feature this tool does not implement."""

    exit_code = EXIT_UNSUPPORTED


class BuildMismatchError(Civ4DbgError):
    """The dump disagrees with the DLL (TimeDateStamp/SizeOfImage), or the PDB with the DLL.

    The PDB check compares GUID/age, or the section tables when there is no GUID.
    """

    exit_code = EXIT_BUILD_MISMATCH


class ThreadNotFoundError(Civ4DbgError):
    """A requested thread id is not in the dump (or no thread id is common to the compared dumps)."""

    exit_code = EXIT_NOT_FOUND
