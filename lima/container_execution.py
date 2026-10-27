"""Shared bounded container-execution primitives for trusted host workers.

This module is the single authority for the docker argv shape used by LIMA's
agent-driven build executor: fixed hardening flags, resource limits, optional
network isolation, atomic JSON evidence records, the cancel-then-publish rule
for worker results, and the confirmed stop/kill teardown for runaway
containers.  ``lima.container_build`` (the manual full-build CLI) keeps its own
stdlib-only copy of the overlapping helpers because that file also runs
standalone inside the build image as the worker script, where no ``lima``
package is importable; converging the two distributions is deferred until
worker delivery stops being single-file.  The behavioral rules themselves are
shared: they are frozen by the tests of both modules.
"""

from __future__ import annotations

# ruff: noqa: S607
# Docker is a local toolchain command; the host worker only runs fixed argv lists.
import dataclasses
import json
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final

__all__ = [
    "CANCEL_MARKER",
    "ContainerExecutionError",
    "ContainerLimits",
    "ContainerRunResult",
    "PUBLISHED_RECORD",
    "WORKER_RECORD",
    "bounded_text",
    "docker_run_argv",
    "publish_verified_worker_record",
    "run_isolated_worker",
    "save_record",
    "stop_container_with_confirmation",
]

CANCEL_MARKER: Final = "cancel-requested.json"
WORKER_RECORD: Final = "worker-result.json"
PUBLISHED_RECORD: Final = "build-result.json"

_TRUNCATION_MARKER: Final = "[truncated: showing last {kept} of {total} bytes]\n"
_POLL_INTERVAL_SECONDS: Final = 0.05
_STOP_GRACE_SECONDS: Final = 20.0
_STOP_TOOL_TIMEOUT_SECONDS: Final = 30.0
# Bounded capture per stream: a build script can print at disk-filling speed
# inside its CPU/memory limits, so raw streams are drained into memory tail
# buffers instead of unbounded files on the host.
DEFAULT_CAPTURE_LIMIT_BYTES: Final = 8 * 1024 * 1024
_DRAIN_CHUNK_BYTES: Final = 64 * 1024


class ContainerExecutionError(RuntimeError):
    """A hardened container interaction could not be carried out."""


@dataclasses.dataclass(frozen=True, slots=True)
class ContainerLimits:
    """Resource and network limits applied to every agent-driven container."""

    memory: str = "10g"
    cpus: str = "6"
    pids_limit: int = 1024
    network: bool = True


def docker_run_argv(
    *,
    image: str,
    name: str,
    mounts: Sequence[str],
    workdir: str,
    argv: Sequence[str],
    limits: ContainerLimits | None = None,
) -> list[str]:
    """Assemble one hardened ``docker run`` command (argv list, never a shell).

    Every invocation drops capabilities, forbids privilege escalation and is
    bounded in memory, CPUs and PIDs; ``ContainerLimits(network=False)``
    additionally cuts the container off the network.
    """

    effective = limits if limits is not None else ContainerLimits()
    command = [
        "docker",
        "run",
        "--rm",
        "--name",
        name,
        "--init",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        effective.memory,
        "--cpus",
        effective.cpus,
        "--pids-limit",
        str(effective.pids_limit),
    ]
    if not effective.network:
        command += ["--network", "none"]
    for mount in mounts:
        command += ["--mount", mount]
    return command + ["--workdir", workdir, image, *list(argv)]


def save_record(
    output: Path, record: dict, *, filename: str = PUBLISHED_RECORD
) -> None:
    """Atomically write one JSON evidence record (tmp file + replace)."""

    temporary = output / filename.replace(".json", ".tmp")
    temporary.write_text(json.dumps(record, indent=2), encoding="utf8")
    temporary.replace(output / filename)


def publish_verified_worker_record(attempt_dir: Path) -> dict:
    """Publish a worker result, but never after cancellation was requested.

    The pending-cancellation marker outranks a late worker exit: once the host
    has decided to stop the container, whatever the worker wrote must not
    replace the host-side terminal record.
    """

    if (attempt_dir / CANCEL_MARKER).exists():
        raise ValueError("Cannot publish a result after cancellation")
    record = json.loads(
        (attempt_dir / WORKER_RECORD).read_text(encoding="utf8")
    )
    save_record(attempt_dir, record)
    return record


def bounded_text(text: str, limit: int) -> tuple[str, bool]:
    """Keep the tail of ``text`` within ``limit`` bytes.

    Diagnostics cluster at the end of a log, so truncation keeps the tail and
    prefixes an explicit marker line.  Returns ``(text, truncated)``.
    """

    if limit <= 0:
        raise ValueError("limit must be positive")
    data = text.encode("utf8", errors="replace")
    if len(data) <= limit:
        return text, False
    marker = _TRUNCATION_MARKER.format(kept=limit, total=len(data)).encode(
        "utf8"
    )
    return (marker + data[-limit:]).decode("utf8", errors="replace"), True


def stop_container_with_confirmation(name: str, log_path: Path) -> bool:
    """Stop (then kill) one container; only a confirmed exit returns True.

    The docker CLI calls themselves are bounded, and any failure - a non-zero
    exit, a timeout or an OS error - means the stop could not be confirmed;
    the caller must treat the container as possibly still alive.
    """

    with log_path.open("a", encoding="utf8") as log:
        try:
            stopped = subprocess.run(  # noqa: S603, S607 - docker CLI, fixed argv
                ["docker", "stop", "--timeout", "10", name],
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
                timeout=_STOP_TOOL_TIMEOUT_SECONDS,
            ).returncode == 0
            if not stopped:
                stopped = subprocess.run(  # noqa: S603, S607
                    ["docker", "kill", name],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                    check=False,
                    timeout=_STOP_TOOL_TIMEOUT_SECONDS,
                ).returncode == 0
        except subprocess.TimeoutExpired:
            log.write(f"docker stop/kill timed out for {name}\n")
            return False
        except OSError as exc:
            log.write(f"Docker stop/kill could not run: {exc}\n")
            return False
    return stopped


@dataclasses.dataclass(frozen=True, slots=True)
class ContainerRunResult:
    """Outcome of one hardened container command.

    ``stop_confirmed`` is False when neither ``docker stop`` nor ``docker
    kill`` could be confirmed: the container may still be alive and hold the
    work copy, which callers must record instead of treating the
    interruption as cleanly torn down.  ``stdout_truncated``/
    ``stderr_truncated`` are True when the raw stream exceeded the capture
    limit and only the tail was kept.
    """

    returncode: int | None
    timed_out: bool
    cancelled: bool
    elapsed_seconds: float
    stop_confirmed: bool = True
    stdout_truncated: bool = False
    stderr_truncated: bool = False


class _TailBuffer:
    """Bounded in-memory stream capture that keeps the tail."""

    def __init__(self, limit: int) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self._limit = limit
        self._data = bytearray()
        self.total = 0

    def write(self, chunk: bytes) -> None:
        self.total += len(chunk)
        self._data += chunk
        if len(self._data) > self._limit:
            del self._data[: len(self._data) - self._limit]

    @property
    def truncated(self) -> bool:
        return self.total > len(self._data)

    def data(self) -> bytes:
        return bytes(self._data)


def _drain(stream, buffer: _TailBuffer) -> None:
    """Copy one pipe into a tail buffer until EOF; reader-thread body."""

    try:
        while True:
            chunk = stream.read(_DRAIN_CHUNK_BYTES)
            if not chunk:
                break
            buffer.write(chunk)
    except (OSError, ValueError):
        pass
    finally:
        try:
            stream.close()
        except OSError:
            pass


def _write_capture(path: Path, buffer: _TailBuffer) -> None:
    """Persist one captured stream; capture-level truncation is explicit."""

    path.parent.mkdir(parents=True, exist_ok=True)
    data = buffer.data()
    if buffer.truncated:
        marker = (
            f"[capture-truncated: kept last {len(data)} of"
            f" {buffer.total} bytes]\n"
        ).encode()
        path.write_bytes(marker + data)
    else:
        path.write_bytes(data)


def run_isolated_worker(
    command: Sequence[str],
    *,
    name: str,
    timeout_seconds: float,
    cancel: Callable[[], bool],
    stdout_path: Path,
    stderr_path: Path,
    stop_log_path: Path,
    capture_limit_bytes: int = DEFAULT_CAPTURE_LIMIT_BYTES,
) -> ContainerRunResult:
    """Run one hardened docker command under timeout and cancellation.

    Both streams are drained by reader threads into bounded memory tail
    buffers (host disk usage for raw output is capped at
    ``capture_limit_bytes`` per stream, with an explicit capture-truncation
    marker when exceeded).  A timeout or a ``cancel()`` callback tears the
    container down through the confirmed stop/kill chain; if the stop cannot
    be confirmed the result says so via ``stop_confirmed=False`` instead of
    pretending the container is gone, and an interrupted run reports
    ``returncode=None`` rather than trusting the killed exit.
    """

    started = time.monotonic()
    out_buffer = _TailBuffer(capture_limit_bytes)
    err_buffer = _TailBuffer(capture_limit_bytes)
    try:
        process = subprocess.Popen(  # noqa: S603, S607 - docker CLI, fixed argv
            list(command),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except OSError as exc:
        raise ContainerExecutionError(
            f"docker-invocation-failed:{name}"
        ) from exc
    readers = [
        threading.Thread(
            target=_drain, args=(process.stdout, out_buffer), daemon=True
        ),
        threading.Thread(
            target=_drain, args=(process.stderr, err_buffer), daemon=True
        ),
    ]
    for reader in readers:
        reader.start()
    timed_out = False
    cancelled = False
    while process.poll() is None:
        if cancel():
            cancelled = True
            break
        if time.monotonic() - started >= timeout_seconds:
            timed_out = True
            break
        time.sleep(_POLL_INTERVAL_SECONDS)
    stop_confirmed = True
    if timed_out or cancelled:
        stop_confirmed = stop_container_with_confirmation(name, stop_log_path)
        if not stop_confirmed:
            with stop_log_path.open("a", encoding="utf8") as log:
                log.write(
                    f"stop-unconfirmed:{name}: container may still hold"
                    " the work copy\n"
                )
        try:
            process.wait(timeout=_STOP_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    for reader in readers:
        reader.join(timeout=_STOP_GRACE_SECONDS)
    _write_capture(stdout_path, out_buffer)
    _write_capture(stderr_path, err_buffer)
    interrupted = timed_out or cancelled
    return ContainerRunResult(
        returncode=None if interrupted else process.returncode,
        timed_out=timed_out,
        cancelled=cancelled,
        elapsed_seconds=time.monotonic() - started,
        stop_confirmed=stop_confirmed,
        stdout_truncated=out_buffer.truncated,
        stderr_truncated=err_buffer.truncated,
    )
