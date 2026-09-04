"""Shell-free, streaming process execution inside verified Landlock snapshots."""

from __future__ import annotations

import hashlib
import os
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import BinaryIO

from . import sandbox
from .config import MAX_ARGUMENT_BYTES, MAX_ARGUMENTS_PER_STEP
from .deadline import AnalysisDeadline
from .snapshot import PreparedSnapshot

CLEAN_ENVIRONMENT = {
    "PATH": "/usr/local/bin:/usr/bin:/bin",
    "LANG": "C.UTF-8",
    "LC_ALL": "C.UTF-8",
}
SANITIZER_ENVIRONMENT = {
    "CC": "clang-14",
    "CXX": "clang++-14",
    "CFLAGS": "-fsanitize=address -fno-omit-frame-pointer -g",
    "CXXFLAGS": "-fsanitize=address -fno-omit-frame-pointer -g",
    "LDFLAGS": "-fsanitize=address",
    # abort_on_error would route every report through tgkill, which the
    # process-isolation denylist blocks; a plain nonzero exit keeps the
    # report complete without the sandboxed abort path.
    "ASAN_OPTIONS": "abort_on_error=0:detect_leaks=0:color=never",
}
# The analyzer image ships no default cc/c++ compiler, so plain CMake builds
# must name the audited drivers explicitly instead of relying on detection.
BUILD_ENVIRONMENT = {
    "CC": "clang-14",
    "CXX": "clang++-14",
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
    digests_complete: bool = True

    def __post_init__(self) -> None:
        if not self.digests_complete and (self.stdout_sha256 or self.stderr_sha256):
            raise ValueError("incomplete stream capture must not expose digest claims")

    @property
    def output_sha256(self) -> str:
        if not self.digests_complete:
            return ""
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
    digests_complete: bool = True
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


def _signal_process_group(process_group: int, signal_number: int) -> None:
    try:
        os.killpg(process_group, signal_number)
    except ProcessLookupError:
        pass


_CLEANUP_GRACE_SECONDS = 2.0
_DRAIN_GRACE_SECONDS = 2.0
_SUBREAPER_INSTALLED = False


def _install_subreaper_once() -> None:
    """Adopt orphaned descendants once so teardown can always reap them."""

    global _SUBREAPER_INSTALLED
    if _SUBREAPER_INSTALLED or sys.platform != "linux":
        return
    sandbox.install_subreaper()
    _SUBREAPER_INSTALLED = True


def _reap_process_group(process_group: int, *, deadline: float) -> tuple[int, ...]:
    """Reap dead members of one process group without stealing other children.

    Each request's leader owns a session (start_new_session), so the pgid is
    exclusive to this boundary; only sub-second PID-reuse after a reaped
    leader could ever route another request's child here. A killed descendant
    can reparent to this subreaper microseconds after its leader was reaped,
    so ECHILD is only trusted after bounded retries.
    """

    reaped: list[int] = []
    echild_retries = 0
    while True:
        try:
            pid, _ = os.waitpid(-process_group, os.WNOHANG)
        except ChildProcessError:
            if echild_retries < 3 and time.monotonic() < deadline:
                echild_retries += 1
                time.sleep(0.01)
                continue
            return tuple(reaped)
        except InterruptedError:
            continue
        if pid == 0:
            if time.monotonic() >= deadline:
                return tuple(reaped)
            echild_retries = 0
            time.sleep(0.005)
            continue
        reaped.append(pid)


@dataclass(frozen=True)
class CleanupResult:
    """Leader outcome plus the descendants one teardown could verify as gone."""

    leader_returncode: int | None
    reaped_pids: tuple[int, ...]
    deadline_exceeded: bool


def terminate_execution_boundary(
    process: subprocess.Popen[bytes], *, deadline: float | None = None
) -> CleanupResult:
    """Tear one tool session down: signal the group, reap leader and orphans."""

    limit = deadline if deadline is not None else time.monotonic() + _CLEANUP_GRACE_SECONDS
    if sys.platform == "linux":
        leader_exited = process.poll() is not None
        if not leader_exited:
            _signal_process_group(process.pid, signal.SIGTERM)
            term_budget = time.monotonic() + 0.1
            if term_budget > limit:
                term_budget = limit
            try:
                # Wait without reaping: the leader PID stays reserved while
                # the group is signaled, leaving no PID-reuse misfire window.
                leader_exited = _wait_linux_leader_without_reaping(
                    process, term_budget
                )
            except RuntimeError:
                leader_exited = True
        # Descendants may outlive the leader: always hard-kill the group.
        _signal_process_group(process.pid, signal.SIGKILL)
        try:
            process.wait(timeout=max(0.0, min(0.5, limit - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
        reaped = _reap_process_group(process.pid, deadline=limit)
    else:
        if process.poll() is None:
            try:
                process.terminate()
                process.wait(
                    timeout=max(0.0, min(0.5, limit - time.monotonic()))
                )
            except (OSError, subprocess.TimeoutExpired):
                try:
                    process.kill()
                except OSError:
                    pass
        try:
            process.wait(timeout=max(0.0, min(0.5, limit - time.monotonic())))
        except subprocess.TimeoutExpired:
            pass
        reaped = ()
    return CleanupResult(process.poll(), tuple(reaped), time.monotonic() > limit)


def _wait_linux_leader_without_reaping(
    process: subprocess.Popen[bytes], deadline: float
) -> bool:
    """Keep the leader PID reserved until its whole process group is killed."""

    wait_flags = os.WEXITED | os.WNOHANG | os.WNOWAIT
    while True:
        try:
            status = os.waitid(os.P_PID, process.pid, wait_flags)
        except ChildProcessError as exc:
            raise RuntimeError("tool leader was reaped outside its supervisor") from exc
        if status is not None:
            return True
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        time.sleep(min(0.01, remaining))


def _join_drains_until(threads: tuple[threading.Thread, ...], deadline: float) -> bool:
    while any(thread.is_alive() for thread in threads):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return False
        for thread in threads:
            if thread.is_alive():
                thread.join(timeout=min(0.05, remaining))
    return True


def _teardown_limit(
    absolute_deadline: float | None, grace_seconds: float
) -> float:
    """One teardown budget clamped by the request deadline when present."""

    budget = time.monotonic() + grace_seconds
    if absolute_deadline is not None:
        budget = min(budget, absolute_deadline)
    return budget


def _stream_process(
    process: subprocess.Popen[bytes],
    timeout_seconds: int,
    max_output_bytes: int,
    *,
    absolute_deadline: float | None = None,
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

    deadline = time.monotonic() + timeout_seconds
    if sys.platform == "linux":
        leader_exited = _wait_linux_leader_without_reaping(process, deadline)
        if leader_exited:
            # Descendants may still hold the pipe write ends and stream
            # output after the leader exits; drain to EOF or the deadline
            # instead of truncating their pending bytes.
            leader_exited = _join_drains_until(threads, deadline)
        timed_out = not leader_exited
        terminate_execution_boundary(
            process,
            deadline=_teardown_limit(absolute_deadline, _CLEANUP_GRACE_SECONDS),
        )
    else:
        timed_out = False
        try:
            process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
        terminate_execution_boundary(
            process,
            deadline=_teardown_limit(absolute_deadline, _CLEANUP_GRACE_SECONDS),
        )
    drains_complete = _join_drains_until(
        threads, _teardown_limit(absolute_deadline, _DRAIN_GRACE_SECONDS)
    )

    stdout, stdout_sha256, stdout_bytes = stdout_state.snapshot()
    stderr, stderr_sha256, stderr_bytes = stderr_state.snapshot()
    returncode = process.poll()
    if returncode is None:
        terminate_execution_boundary(
            process,
            deadline=_teardown_limit(absolute_deadline, _CLEANUP_GRACE_SECONDS),
        )
        returncode = process.poll()
    if not drains_complete:
        stdout_sha256 = ""
        stderr_sha256 = ""
    return StreamCapture(
        returncode=returncode if returncode is not None else -1,
        timed_out=timed_out,
        stdout=stdout,
        stderr=stderr,
        stdout_sha256=stdout_sha256,
        stderr_sha256=stderr_sha256,
        output_truncated=(
            stdout_bytes + stderr_bytes > max_output_bytes or not drains_complete
        ),
        digests_complete=drains_complete,
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
        digests_complete=True,
        diagnostic=diagnostic,
    )


def clean_environment(snapshot: PreparedSnapshot) -> dict[str, str]:
    """Build a request-private environment without inheriting server secrets."""

    if not isinstance(snapshot, PreparedSnapshot):
        raise ValueError("tool environment requires a prepared snapshot")
    snapshot.resolve_cwd(".")
    home = snapshot.scratch_root / "home"
    temporary = snapshot.scratch_root / "tmp"
    for path in (home, temporary):
        metadata = path.lstat()
        if not path.is_dir() or path.is_symlink():
            raise ValueError("request-private tool directory is unavailable")
        if metadata.st_uid != snapshot.scratch_root.lstat().st_uid:
            raise ValueError("request-private tool directory changed ownership")
    return {
        **CLEAN_ENVIRONMENT,
        "HOME": str(home),
        "TMPDIR": str(temporary),
    }


def final_diagnostic(
    deadline: AnalysisDeadline | None, digests_complete: bool
) -> str:
    """Map one step outcome to its stable diagnostic identifier."""

    if deadline is not None and deadline.remaining() <= 0:
        return "request-deadline-exceeded"
    return "" if digests_complete else "tool output drain incomplete"


def run_step(
    argv: Sequence[str],
    snapshot: PreparedSnapshot,
    cwd: str | os.PathLike[str],
    timeout_seconds: int,
    max_output_bytes: int,
    env: Mapping[str, str] | None,
    *,
    deadline: AnalysisDeadline | None = None,
) -> ToolExecution:
    """Run one argv step inside a live snapshot and a fail-closed Landlock policy.

    Teardown and drain budgets are clamped by the caller's request deadline;
    they never open a second full budget.
    """

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
    if env not in (None, {}, SANITIZER_ENVIRONMENT, BUILD_ENVIRONMENT):
        raise ValueError("tool environment is not an analyzer-owned fixed environment")
    if deadline is not None and not isinstance(deadline, AnalysisDeadline):
        raise ValueError("tool deadline must be an AnalysisDeadline")
    sandbox.build_policy(snapshot.root, snapshot.writable_roots)
    if not sandbox.process_isolation_available():
        return _empty_execution(
            "sandbox-unavailable", "process sandbox unavailable"
        )
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
    try:
        _install_subreaper_once()
    except OSError:
        return _empty_execution(
            "sandbox-unavailable", "process supervisor unavailable"
        )

    status_read_fd, status_write_fd = os.pipe()
    os.set_inheritable(status_write_fd, True)
    launcher_argv = sandbox.build_launcher_argv(
        arguments,
        snapshot.root,
        status_write_fd,
        snapshot.writable_roots,
    )
    try:
        try:
            process = subprocess.Popen(  # noqa: S603 - fixed launcher, no shell
                launcher_argv,
                cwd=working_directory,
                env=dict(clean_environment(snapshot) | (dict(env) if env else {})),
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
        captured = _stream_process(
            process,
            timeout_seconds,
            max_output_bytes,
            absolute_deadline=(
                deadline.expires_at if deadline is not None else None
            ),
        )
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
            digests_complete=captured.digests_complete,
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
        digests_complete=captured.digests_complete,
        diagnostic=final_diagnostic(deadline, captured.digests_complete),
    )
