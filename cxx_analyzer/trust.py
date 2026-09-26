"""Fail-closed trust gate for untrusted build system generation.

Executing an untrusted snapshot's ``CMakeLists.txt`` must never depend on
``auto_cmake`` alone: a CMake ``configure`` step can run arbitrary code
through ``execute_process()`` and similar constructs. Generation is
therefore authorized only while an administrator-level switch is enabled
AND every capability of a two-column checklist holds:

1. Machine-provable capabilities, probed at runtime by this module and
   each implemented as an independent fail-closed probe (unreadable or
   unknown always means False): ``landlock`` (Landlock ABI),
   ``process_isolation`` (audited seccomp denylist), ``non_root`` (uid),
   ``network_isolated`` (no interface besides loopback) and
   ``snapshot_readonly`` (read-only mount under the snapshot work root).
2. Compose/deployment static guarantees that cannot be proven from inside
   the process, declared in ``COMPOSE_STATIC_GUARANTEES`` and enforced by
   the deployment configuration plus the Compose contract tests:
   - snapshot-and-import-mounts-are-read-only
   - no-docker-socket-host-path-or-credential-mounts
   - scratch-and-build-directories-are-ephemeral-tmpfs
   - cpu-memory-pid-output-filesize-and-wallclock-limits-configured

Generation runs only when column one is fully true at execution time and
the deployment guarantees column two; any missing item fails closed.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Final

from . import sandbox
from .config import AnalyzerSettings

# Mirrors cxx_analyzer.server.WORK_ROOT; kept local to avoid importing the
# server module (and its request wiring) from the gate itself.
WORK_ROOT: Final = Path("/work/snapshots")
_NETWORK_CLASS_DIR: Final = Path("/sys/class/net")
_PROC_MOUNTS: Final = Path("/proc/mounts")

COMPOSE_STATIC_GUARANTEES: Final = frozenset(
    {
        "snapshot-and-import-mounts-are-read-only",
        "no-docker-socket-host-path-or-credential-mounts",
        "scratch-and-build-directories-are-ephemeral-tmpfs",
        "cpu-memory-pid-output-filesize-and-wallclock-limits-configured",
    }
)


def landlock_available() -> bool:
    """Return whether the required Landlock ABI is usable in this process."""

    try:
        return sandbox.landlock_abi() >= sandbox.MIN_LANDLOCK_ABI
    except OSError:
        return False


def process_isolation_available() -> bool:
    """Return whether this architecture has the audited seccomp denylist."""

    return sandbox.process_isolation_available()


def running_as_non_root() -> bool:
    """Return whether the process runs as a non-root uid; unknown means no."""

    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return False
    return geteuid() != 0


def network_isolated() -> bool:
    """Return whether no network interface besides loopback exists."""

    try:
        interfaces = set(os.listdir(_NETWORK_CLASS_DIR))
    except OSError:
        return False
    return interfaces <= {"lo"}


def snapshot_mount_readonly() -> bool:
    """Return whether the snapshot work root sits on a read-only mount."""

    return _longest_mount_readonly(str(WORK_ROOT))


def _longest_mount_readonly(target: str) -> bool:
    """Report the ``ro`` option of the longest mount point covering ``target``."""

    try:
        lines = _PROC_MOUNTS.read_text(encoding="utf-8").splitlines()
    except OSError:
        return False
    matched_length = -1
    readonly = False
    for line in lines:
        fields = line.split()
        if len(fields) < 4:
            continue
        mount_point = fields[1].replace("\\040", " ")
        if mount_point == target:
            prefix_length = len(mount_point)
        elif target.startswith(mount_point.rstrip("/") + "/"):
            prefix_length = len(mount_point)
        else:
            continue
        if prefix_length > matched_length:
            matched_length = prefix_length
            readonly = "ro" in fields[3].split(",")
    return readonly


def build_generation_capabilities() -> dict[str, bool]:
    """Probe every machine-provable capability of the generation checklist."""

    return {
        "landlock": landlock_available(),
        "process_isolation": process_isolation_available(),
        "non_root": running_as_non_root(),
        "network_isolated": network_isolated(),
        "snapshot_readonly": snapshot_mount_readonly(),
    }


def generation_allowed(settings: AnalyzerSettings) -> bool:
    """Return whether the admin gate and every probed capability hold.

    The administrator switch ``trusted_build_context_generation`` is a
    deployment-level setting: analysis requests, repository content and
    model output can never set or influence it. Without the switch, or
    with any machine probe false, generation is refused (fail-closed).
    """

    return settings.trusted_build_context_generation and all(
        build_generation_capabilities().values()
    )
