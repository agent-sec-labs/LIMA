"""Trusted synthetic-fixture runner for unit tests only; never production wiring.

The production path always uses Docker. These fixed, repository-owned test
fixtures still execute their real functional assertions when CI has no daemon.
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from lima.container_execution import ContainerRunResult

FIXTURE_IMAGE = "sha256:" + "f" * 64


def run_trusted_fixture(
    docker_argv, *, name, timeout_seconds, stdout_path, stderr_path,
    stop_log_path, capture_limit_bytes,
):
    image_at = docker_argv.index(FIXTURE_IMAGE)
    if docker_argv[image_at + 1] != "-c":
        raise AssertionError("test sandbox bootstrap missing")
    command = docker_argv[image_at + 3:]
    if command != ["python", "-m", "unittest", "discover", "-s", "."]:
        raise AssertionError("only the fixed synthetic regression command is allowed")
    mount = next(value for value in docker_argv if "target=/input,readonly" in value)
    source = Path(next(part[7:] for part in mount.split(",") if part.startswith("source=")))
    started = time.monotonic()
    with tempfile.TemporaryDirectory(prefix="lima-trusted-unit-fixture-") as temporary:
        worktree = Path(temporary) / "repository"
        shutil.copytree(source, worktree)
        metadata_mount = next(
            value for value in docker_argv if "target=/lima-modes.json,readonly" in value
        )
        metadata = Path(next(
            part[7:] for part in metadata_mount.split(",") if part.startswith("source=")
        ))
        for path, mode in json.loads(metadata.read_text(encoding="utf-8")).items():
            os.chmod(worktree / path, int(mode, 8) & 0o777)
        result = subprocess.run(  # noqa: S603 - fixed unittest command over trusted synthetic fixtures
            [sys.executable, *command[1:]], cwd=worktree,
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            capture_output=True, timeout=timeout_seconds, check=False,
        )
    Path(stdout_path).write_bytes(result.stdout[-capture_limit_bytes:])
    Path(stderr_path).write_bytes(result.stderr[-capture_limit_bytes:])
    return ContainerRunResult(
        result.returncode, False, False, time.monotonic() - started,
        stop_confirmed=True,
        stdout_truncated=len(result.stdout) > capture_limit_bytes,
        stderr_truncated=len(result.stderr) > capture_limit_bytes,
    )
