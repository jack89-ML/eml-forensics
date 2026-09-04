"""Error taxonomy and POSIX exit-code contract.

  0   success
  1   completed with zero records (verified empty)
  2   operational error
  130 interrupted by user (SIGINT)
"""

from __future__ import annotations

EXIT_OK = 0
EXIT_EMPTY = 1
EXIT_ERROR = 2
EXIT_INTERRUPTED = 130


class ForensicsError(Exception):
    """Operational failure: unreadable input, missing optional dependency,
    downstream tool error. Maps to exit code 2."""


class OptionalDependencyError(ForensicsError):
    """The requested action needs the optional ``[ocr]`` extra."""


def exit_code(completed: bool, found: int) -> int:
    if not completed:
        return EXIT_ERROR
    return EXIT_OK if found > 0 else EXIT_EMPTY
