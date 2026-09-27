"""Relative-path validation for changed-file inputs.

Retirement Task 2 trim: the symbol-index retrieval machinery served the
retired seven-role chain; only this shared path validator remains (used by
the platform scout and the GitHub source provider).
"""

from __future__ import annotations

from pathlib import PurePosixPath


def _validate_changed_path(path: str) -> None:
    if not isinstance(path, str) or not path:
        raise ValueError("changed file paths must be non-empty strings")
    if "\\" in path:
        raise ValueError(f"changed file path must be POSIX-relative, got {path!r}")
    if len(path) >= 2 and path[1] == ":":
        raise ValueError(f"changed file path must be relative, got {path!r}")
    pure = PurePosixPath(path)
    if pure.is_absolute() or ".." in pure.parts:
        raise ValueError(
            f"changed file path must not escape the snapshot, got {path!r}"
        )
