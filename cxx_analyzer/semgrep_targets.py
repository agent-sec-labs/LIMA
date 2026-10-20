"""Execute one fixed Semgrep scan from an analyzer-owned bounded target list.

This launcher keeps administrator command limits unchanged. It runs inside the
same process/filesystem sandbox, replacing itself rather than spawning a shell.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
from pathlib import Path, PurePosixPath

MAX_TARGETS = 20_000
MAX_TARGET_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
SOURCE_SUFFIXES = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}


def load_targets(manifest: Path) -> list[str]:
    with manifest.open("rb") as stream:
        raw = stream.read(MAX_MANIFEST_BYTES + 1)
    if len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("target manifest exceeds budget")
    targets = json.loads(raw)
    if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
        raise ValueError("target manifest must contain a bounded list")
    root = Path.cwd().resolve()
    total_bytes = 0
    for target in targets:
        if not isinstance(target, str):
            raise ValueError("target must be text")
        path = PurePosixPath(target)
        if (
            not target
            or path.is_absolute()
            or "\\" in target
            or "\0" in target
            or any(part in {"", ".", ".."} for part in target.split("/"))
            or path.suffix.lower() not in SOURCE_SUFFIXES
            or len(target.encode("utf8")) > 4096
        ):
            raise ValueError("invalid relative source target")
        resolved = (root / target).resolve(strict=True)
        if resolved != root / target or not resolved.is_relative_to(root) or not resolved.is_file():
            raise ValueError("target must be a regular snapshot file without links")
        total_bytes += len(target.encode("utf8")) + 1
    if total_bytes > MAX_TARGET_BYTES:
        raise ValueError("target arguments exceed budget")
    return targets


def main() -> None:
    if len(sys.argv) != 4:
        raise ValueError("expected fixed rules, manifest and file budget")
    rules, manifest = Path(sys.argv[1]), Path(sys.argv[2])
    if rules.parent != manifest.parent or not rules.is_file():
        raise ValueError("rules and manifest must share analyzer staging")
    max_bytes = int(sys.argv[3])
    if not 0 < max_bytes <= 1024 * 1024 * 1024:
        raise ValueError("invalid source byte budget")
    targets = load_targets(manifest)
    executable = shutil.which("semgrep")
    if not executable:
        raise ValueError("Semgrep is unavailable")
    os.execv(  # noqa: S606 - fixed Semgrep executable and bounded argv, no shell.
        executable,
        [
            executable,
            "scan",
            "--experimental",
            "--json",
            "--quiet",
            "--no-rewrite-rule-ids",
            "--jobs",
            "2",
            "--max-target-bytes",
            str(max_bytes),
            "--config",
            str(rules),
            "--metrics=off",
            "--disable-version-check",
            "--",
            *targets,
        ],
    )


if __name__ == "__main__":
    main()
