"""Shell-free, streaming process execution inside verified Landlock snapshots."""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import BinaryIO

from . import sandbox
from .config import MAX_ARGUMENT_BYTES, MAX_ARGUMENTS_PER_STEP
from .snapshot import PreparedSnapshot

CLEAN_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "HOME": "/tmp/analyzer-home",  # noqa: S108 - fixed container-only path
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
    "TMPDIR": "/work/tmp",
}
OUTPUT_DIGEST_DOMAIN = b"LIMA-TOOL-OUTPUT-SHA256-v1\0stdout\0"
_STDERR_DIGEST_TAG = b"\0stderr\0"
_READ_CHUNK_BYTES = 64 * 1024


def _combined_digest(stdout_sha256: str, stderr_sha256: str) -> str:
    """Hash tagged binary stream digests without concatenating the raw streams."""

    digest = hashlib.sha256()
    digest.update(OUTPUT_DIGEST_DOMAIN)
    digest.update(bytes.fromhex(stdout_sha256))
    digest.update(_STDERR_DIGEST_TAG)
    digest.update(bytes.fromhex(stderr_sha256))
    return digest.hexdigest()


@dataclass(frozen=True)
class StreamCapture:
    """Internal bounded capture result; digests cover complete drained streams."""

    returncode: int
    timed_out: bool
    stdout: bytes
    stderr: bytes
    stdout_sha256: str
    stderr_sha256: str
    output_truncated: bool

    @property
    def output_sha256(self) -> str:
        return _combined_digest(self.stdout_sha256, self.stderr_sha256)


@dataclass(frozen=True)
class ToolExecution:
    """Public bounded subprocess result with full-stream cryptographic summaries."""

    status: str
    returncode: int | None
    stdout: str
    stderr: str
    stdout_sha256: str
    stderr_sha256: str
    output_sha256: str
    output_truncated: bool
    diagnostic: str = ""


class _PrefixBudget:
    def __init__(self, maximum: int) -> None:
        self._remaining = maximum
        self._lock = threading.Lock()

    def retain(self, data: bytes) -> bytes:
        with self._lock:
            length = min(self._remaining, len(data))
            self._remaining -= length
            return data[:length]


class _StreamState:
    def __init__(self, budget: _PrefixBudget) -> None:
        self._budget = budget
        self._digest = hashlib.sha256()
        self._retained = bytearray()
        self._total_bytes = 0
        self._lock = threading.Lock()

    def feed(self, data: bytes) -> None:
        retained = self._budget.retain(data)
        with self._lock:
            self._digest.update(data)
            self._total_bytes += len(data)
            self._retained.extend(retained)

    def snapshot(self) -> tuple[bytes, str, int]:
        with self._lock:
            return bytes(self._retained), self._digest.copy().hexdigest(), self._total_bytes


def _drain(stream: BinaryIO, state: _StreamState) -> None:
    try:
        while True:
            chunk = stream.read(_READ_CHUNK_BYTES)
            if not chunk:
                return
            state.feed(chunk)
    except (OSError, ValueError):
        return
    finally:
        stream.close()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if sys.platform == "linux":
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
        process.wait(timeout=1)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass
    try:
        if sys.platform == "linux":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def _stream_process(
    process: subprocess.Popen[bytes], timeout_seconds: int, max_output_bytes: int
) -> StreamCapture:
    """Drain both pipes concurrently while retaining one shared bounded prefix."""

    if process.stdout is None or process.stderr is None:
        raise ValueError("streaming process must expose stdout and stderr pipes")
    budget = _PrefixBudget(max_output_bytes)
    stdout_state = _StreamState(budget)
    stderr_state = _StreamState(budget)
    threads = (
        threading.Thread(
            target=_drain,
            args=(process.stdout, stdout_state),
            name="cxx-tool-stdout",
            daemon=True,
        ),
        threading.Thread(
            target=_drain,
            args=(process.stderr, stderr_state),
            name="cxx-tool-stderr",
            daemon=True,
        ),
    )
    for thread in threads:
        thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process(process)
    for thread in threads:
        thread.join(timeout=2)

    stdout, stdout_sha256, stdout_bytes = stdout_state.snapshot()
    stderr, stderr_sha256, stderr_bytes = stderr_state.snapshot()
    drain_incomplete = any(thread.is_alive() for thread in threads)
    returncode = process.poll()
    if returncode is None:
        _terminate_process(process)
        returncode = process.poll()
    return StreamCapture(
        returncode=returncode if returncode is not None else -1,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        output_truncated=(
            stdout_bytes + stderr_bytes > max_output_bytes or drain_incomplete
        ),
    )


def _bounded_text(value: bytes, budget: int) -> str:
    if budget <= 0:
        return ""
    text = value[:budget].decode("utf-8", errors="replace")
    while len(text.encode("utf-8")) > budget:
        text = text[:-1]
    return text


def _validate_argv(argv: Sequence[str]) -> list[str]:
    if isinstance(argv, str | bytes) or not isinstance(argv, Sequence):
        raise ValueError("tool command must be an argv sequence")
    if not argv or len(argv) > MAX_ARGUMENTS_PER_STEP:
        raise ValueError("tool argv must contain a bounded non-empty argument list")
    result: list[str] = []
    for argument in argv:
        if not isinstance(argument, str):
            raise ValueError("tool argv values must be strings")
        if "\0" in argument:
            raise ValueError("tool argv values must not contain NUL")
        if len(argument.encode("utf-8")) > MAX_ARGUMENT_BYTES:
            raise ValueError("tool argv value exceeds the byte limit")
        result.append(argument)
    if not result[0]:
        raise ValueError("tool executable must not be empty")
    return result


def _empty_execution(status: str, diagnostic: str) -> ToolExecution:
    empty_sha256 = hashlib.sha256(b"").hexdigest()
    return ToolExecution(
        status=status,
        returncode=None,
        stdout="",
        stderr="",
        stdout_sha256=empty_sha256,
        stderr_sha256=empty_sha256,
        output_sha256=_combined_digest(empty_sha256, empty_sha256),
        output_truncated=False,
        diagnostic=diagnostic,
    )


def run_step(
    argv: Sequence[str],
    snapshot: PreparedSnapshot,
    cwd: str | os.PathLike[str],
    timeout_seconds: int,
    max_output_bytes: int,
    env: Mapping[str, str] | None,
) -> ToolExecution:
    """Run one argv step inside a live snapshot and a fail-closed Landlock policy."""

    arguments = _validate_argv(argv)
    if not isinstance(snapshot, PreparedSnapshot):
        raise ValueError("tool execution requires a prepared snapshot")
    working_directory = snapshot.resolve_cwd(cwd)
    if not isinstance(timeout_seconds, int) or timeout_seconds < 1:
        raise ValueError("tool timeout must be a positive integer")
    if not isinstance(max_output_bytes, int) or max_output_bytes < 1:
        raise ValueError("tool output limit must be a positive integer")
    if env is not None and not isinstance(env, Mapping):
        raise ValueError("tool environment must be a mapping")
    sandbox.build_policy(snapshot.root)
    try:
        landlock_version = sandbox.landlock_abi()
    except OSError:
        return _empty_execution(
            "sandbox-unavailable", "filesystem sandbox unavailable"
        )
    if landlock_version < sandbox.MIN_LANDLOCK_ABI:
        return _empty_execution(
            "sandbox-unavailable", "filesystem sandbox unavailable"
        )

    status_read_fd, status_write_fd = os.pipe()
    os.set_inheritable(status_write_fd, True)
    launcher_argv = sandbox.build_launcher_argv(
        arguments, snapshot.root, status_write_fd
    )
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed launcher, no shell
                launcher_argv,
                cwd=working_directory,
                env=dict(CLEAN_ENVIRONMENT),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                pass_fds=(status_write_fd,),
                start_new_session=True,
            )
        except OSError:
            return _empty_execution(
                "sandbox-unavailable", "filesystem sandbox unavailable"
            )
        finally:
            os.close(status_write_fd)
        captured = _stream_process(process, timeout_seconds, max_output_bytes)
        setup_report = os.read(status_read_fd, 2)
    finally:
        os.close(status_read_fd)

    if setup_report != b"R":
        return ToolExecution(
            status="sandbox-failed",
            returncode=captured.returncode,
            stdout="",
            stderr="",
            stdout_sha256=captured.stdout_sha256,
            stderr_sha256=captured.stderr_sha256,
            output_sha256=captured.output_sha256,
            output_truncated=captured.output_truncated,
            diagnostic="filesystem sandbox setup failed",
        )
    status = (
        "timed-out"
        if captured.timed_out
        else "completed" if captured.returncode == 0 else "failed"
    )
    return ToolExecution(
        status=status,
        returncode=None if captured.timed_out else captured.returncode,
        stdout=_bounded_text(captured.stdout, max_output_bytes),
        stderr=_bounded_text(captured.stderr, max_output_bytes - len(captured.stdout)),
        stdout_sha256=captured.stdout_sha256,
        stderr_sha256=captured.stderr_sha256,
        output_sha256=captured.output_sha256,
        output_truncated=captured.output_truncated,
    )
