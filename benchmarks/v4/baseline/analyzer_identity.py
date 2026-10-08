"""Portable source identity for the local, stdlib-only scanner workload.

The complete installed LIMA Python source bundle is included conservatively:
changes to a shared rule or helper cannot silently keep the old identity. Git
refs, checkout paths, cache files and newline conventions do not enter it.
This describes source provenance, not an authenticity signature.
"""

from __future__ import annotations

import hashlib
import sys
from pathlib import Path

import lima


def scanner_implementation_manifest() -> dict[str, object]:
    """Return a recomputable manifest of the loaded package's source files.

    Baseline runners record this in scanner_config before deriving the config,
    analyzer and run digests. Historical manifests are verified from their own
    recorded config, without replacing their identity with today's sources.
    A source-only installation is required; incomplete/linked bundles fail.
    """
    return _source_manifest(Path(lima.__file__).resolve().parent)


def _source_manifest(root: Path) -> dict[str, object]:
    if not root.is_dir():
        raise ValueError("scanner source package is unavailable")
    required = {
        "repository_scanner.py",
        "reviewer.py",
        "python_analyzer.py",
        "python_dataflow.py",
        "workspace.py",
        "models.py",
    }
    entries = list(root.rglob("*"))
    # rglob does not follow directory symlinks. Check the directory entries
    # too, otherwise a linked helper package could disappear from the manifest.
    for entry in entries:
        if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
            raise ValueError("scanner source bundle must not contain symbolic links")
    paths = sorted(
        (entry for entry in entries if entry.suffix == ".py"),
        key=lambda path: path.relative_to(root).as_posix(),
    )
    sources = {}
    for path in paths:
        if path.is_symlink() or any(
            parent.is_symlink()
            for parent in path.parents
            if parent != root and root in parent.parents
        ):
            raise ValueError("scanner source bundle must not contain symbolic links")
        relative = path.relative_to(root).as_posix()
        # Universal newline decoding makes the same Git content portable across
        # Windows core.autocrlf and Linux; all other source bytes remain bound.
        source = path.read_text(encoding="utf-8").encode("utf-8")
        sources["lima/" + relative] = hashlib.sha256(source).hexdigest()
    if not required <= {path.relative_to(root).as_posix() for path in paths}:
        raise ValueError("scanner source bundle is incomplete")
    return {
        "scheme": "lima-python-source-v1",
        "runtime": {
            "implementation": sys.implementation.name,
            "python_version": list(sys.version_info[:3]),
        },
        "sources": sources,
    }
