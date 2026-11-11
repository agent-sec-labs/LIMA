"""Host deployment checks for Build Agent execution.

The production executor starts isolated Docker containers from the process
running LIMA.  This module keeps that prerequisite explicit and bounded:
the check neither prints daemon diagnostics into task data nor trusts a
permission-bit probe in place of an actual write.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Final

__all__ = ["build_environment_failure"]

_DOCKER_INFO_TIMEOUT_SECONDS: Final = 5


def build_environment_failure(artifacts_root: str | Path) -> str | None:
    """Return a stable unavailable reason, or ``None`` when host-ready.

    Docker's diagnostic output can contain host-specific details and is not
    useful to the task result, so the readiness command discards both streams.
    The artifacts root is proved writable with a temporary file because an
    access-bit check is unreliable for ACLs, mounts and read-only filesystems.
    """

    docker = shutil.which("docker")
    if docker is None:
        return "docker-cli-unavailable"
    try:
        result = subprocess.run(  # noqa: S603 - resolved local Docker CLI, fixed argv
            [docker, "info", "--format", "{{.ServerVersion}}"],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=_DOCKER_INFO_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError):
        return "docker-daemon-unavailable"
    if result.returncode != 0:
        return "docker-daemon-unavailable"

    root = Path(artifacts_root)
    try:
        root.mkdir(parents=True, exist_ok=True)
        descriptor, name = tempfile.mkstemp(prefix=".lima-build-preflight-", dir=root)
        os.close(descriptor)
        Path(name).unlink()
    except OSError:
        return "build-artifacts-unwritable"
    return None

