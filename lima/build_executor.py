"""Bounded isolated build executor for the repository build agent (slice 1).

One :meth:`BuildExecutor.execute` call is one attempt of a frozen
:class:`~lima.build_recipe.BuildRecipe` against a repository snapshot.  The
snapshot is never touched: the executor copies it into a disposable working
directory, hands that copy to an injected isolated session (one hardened
``docker run`` per interaction in production, network off, capabilities
dropped), and records every step as bounded sanitized evidence under the
attempt directory.  Step output references are relative paths inside that
directory, so host paths never leak into task or model context.

A single monotonic deadline set at entry bounds the whole attempt - copy,
steps, io and export all consume the same remaining time.  Interruptions are
results, not exceptions: a step that times out or is cancelled reaches the
evidence pipeline as a structured outcome, an unconfirmed container stop is
recorded on the result instead of assumed clean, and cancellation is
re-checked before the export and before the final publication, so a
cancelled attempt never publishes a success record.  Retry semantics live
with the caller: a new ``execute`` call always starts from a fresh copy.
Whether an exported package is usable downstream is slice 4A's job.
"""

from __future__ import annotations

import dataclasses
import shutil
import tempfile
import time
import uuid
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Final, Protocol

from lima.build_recipe import (
    LIST_GLOBS_SCRIPT,
    BuildRecipe,
    BuildRecipeError,
    export_context_package,
)
from lima.container_execution import (
    CANCEL_MARKER,
    ContainerExecutionError,
    ContainerLimits,
    ContainerRunResult,
    bounded_text,
    docker_run_argv,
    run_isolated_worker,
    save_record,
    stop_container_with_confirmation,
)

__all__ = [
    "BuildExecutor",
    "BuildExecutorError",
    "BuildExecutionResult",
    "BuildLimits",
    "BuildStepResult",
    "DockerIsolatedSession",
    "DockerIsolatedSessionFactory",
    "IsolatedSession",
    "IsolatedSessionFactory",
    "IsolatedStepOutcome",
]

_MAX_STEP_BYTES: Final = 1024 * 1024
_IO_TIMEOUT_SECONDS: Final = 300.0
# Product transfers (cat/glob) must never be silently trimmed: anything
# larger than this hard cap is rejected loudly instead of truncated.
_FILE_READ_LIMIT_BYTES: Final = 64 * 1024 * 1024
_HOST_PATH_PLACEHOLDER: Final = "<attempt>"

FAILURE_CANCELLED: Final = "cancelled"
FAILURE_STEP_TIMEOUT: Final = "step-timeout"
FAILURE_STEP_FAILED: Final = "configure-step-failed"
FAILURE_BUDGET_EXHAUSTED: Final = "budget-exhausted"
FAILURE_EXPORT_FAILED: Final = "export-failed"
FAILURE_EXPORT_INTERRUPTED: Final = "export-interrupted"


class BuildExecutorError(ValueError):
    """Fail-closed executor contract violation with a stable reason string."""

    reason: str

    def __init__(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise TypeError("reason must be a non-empty str")
        self.reason = reason
        super().__init__(reason)


@dataclasses.dataclass(frozen=True, slots=True)
class BuildLimits:
    """Time, output and container budgets for one attempt.

    ``total_seconds`` bounds the whole attempt wall clock from entry -
    copy, configure steps, container io and export all consume the same
    deadline, and each step additionally gets at most ``step_seconds``.
    ``max_output_bytes`` bounds each captured stdout/stderr stream kept as
    evidence.
    """

    total_seconds: float = 1800.0
    step_seconds: float = 300.0
    max_output_bytes: int = _MAX_STEP_BYTES
    memory: str = "10g"
    cpus: str = "6"
    pids_limit: int = 1024


@dataclasses.dataclass(frozen=True, slots=True)
class BuildStepResult:
    """Evidence for one executed configure step.

    ``stdout_ref``/``stderr_ref`` are paths relative to the attempt directory;
    they are never absolute host paths.
    """

    step_id: str
    argv: tuple[str, ...]
    exit_code: int | None
    stdout_ref: str
    stderr_ref: str
    elapsed_seconds: float
    timed_out: bool
    cancelled: bool


@dataclasses.dataclass(frozen=True, slots=True)
class BuildExecutionResult:
    """Outcome of one attempt; ``ok`` never claims downstream usability.

    ``package_path`` is a host-absolute path meant for in-process consumers
    only: it must never be copied into task records, evidence JSON or model
    context, which only hold attempt-relative references.  ``stop_unconfirmed``
    lists steps whose container teardown could not be confirmed and may still
    hold the work copy.
    """

    ok: bool
    steps: tuple[BuildStepResult, ...]
    image: str
    image_digest: str | None
    package_path: str | None
    failure_code: str | None
    stop_unconfirmed: tuple[str, ...] = ()


class IsolatedStepOutcome:
    """What one session step reports back to the executor.

    Timeouts and cancellations are delivered as data (``timed_out``/
    ``cancelled`` with ``exit_code=None``) so the evidence pipeline can
    record them; ``stop_confirmed=False`` means the container teardown
    could not be verified and the container may still be alive.
    """

    def __init__(
        self,
        *,
        returncode: int | None,
        stdout: str,
        stderr: str,
        elapsed_seconds: float,
        timed_out: bool = False,
        cancelled: bool = False,
        stop_confirmed: bool = True,
        stdout_truncated: bool = False,
        stderr_truncated: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.elapsed_seconds = elapsed_seconds
        self.timed_out = timed_out
        self.cancelled = cancelled
        self.stop_confirmed = stop_confirmed
        self.stdout_truncated = stdout_truncated
        self.stderr_truncated = stderr_truncated


class IsolatedSession(Protocol):
    """The container interaction surface the executor depends on.

    All reads target the disposable work copy mounted at the recipe's source
    mount; production uses one hardened docker run per call (never a shell).
    """

    def run_step(
        self, argv: Sequence[str], *, step_id: str, timeout_seconds: float
    ) -> IsolatedStepOutcome: ...

    def read_file(self, container_path: str) -> bytes: ...

    def list_globs(self, pattern: str) -> list[str]: ...

    def close(self) -> None: ...


class IsolatedSessionFactory(Protocol):
    def open(
        self,
        *,
        image: str,
        work_dir: Path,
        source_mount: str,
        limits: BuildLimits,
        cancel: Callable[[], bool],
        attempt_dir: Path,
        deadline: float | None = None,
    ) -> IsolatedSession: ...


def _read_tail(path: Path, limit: int) -> bytes:
    """Read at most the last ``limit`` bytes without loading the file.

    Captured streams on disk are bounded by the capture limit, but the tail
    read still seeks instead of materializing the whole file.
    """

    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - limit))
        return handle.read()


class DockerIsolatedSession:
    """Production session: one hardened docker run per interaction.

    The disposable work copy is the only host directory mounted (writable, at
    the recipe's source mount); the network is off and resources are bounded
    by :class:`BuildLimits`.  Step log capture is bounded per stream and
    sanitized (host work-copy and attempt paths are replaced before the raw
    copies land under ``<attempt>/io/``); product reads (``cat``/glob) use a
    separate full-transfer path that rejects oversized payloads instead of
    trimming them.  ``deadline`` (a ``time.monotonic()`` instant) bounds
    every io interaction together with the steps.  Containers whose stop
    could not be confirmed are retried on :meth:`close`.
    """

    def __init__(
        self,
        *,
        image: str,
        work_dir: Path,
        source_mount: str,
        limits: BuildLimits,
        cancel: Callable[[], bool],
        attempt_dir: Path,
        deadline: float | None = None,
    ) -> None:
        self.image = image
        self.image_digest: str | None = None
        # Resolve to absolute paths: sanitization replaces these exact
        # strings in diagnostic copies, and a relative output directory
        # name would otherwise become an accidental generic substring
        # rewrite (review round 3, F7).
        self.work_dir = Path(work_dir).resolve()
        self.source_mount = source_mount
        self.limits = limits
        self.cancel = cancel
        self.attempt_dir = Path(attempt_dir).resolve()
        self._deadline = deadline
        self._io_dir = self.attempt_dir / "io"
        self._stop_log = self._io_dir / "container-stop.log"
        self._io_dir.mkdir(parents=True, exist_ok=True)
        self._unconfirmed_containers: set[str] = set()

    def _container_limits(self) -> ContainerLimits:
        return ContainerLimits(
            memory=self.limits.memory,
            cpus=self.limits.cpus,
            pids_limit=self.limits.pids_limit,
            network=False,
        )

    def _capture_head_room(self) -> int:
        # A few evidence budgets of raw capture per stream; the evidence copy
        # is bounded again by max_output_bytes when written to logs/.
        return max(1, self.limits.max_output_bytes * 4)

    def _mount(self) -> str:
        return (
            "type=bind,"
            f"source={self.work_dir.resolve().as_posix()},"
            f"target={self.source_mount}"
        )

    def _spawn(
        self,
        argv: Sequence[str],
        *,
        name: str,
        stdout_path: Path,
        stderr_path: Path,
        timeout_seconds: float,
        capture_limit: int,
        sanitize: bool = True,
    ) -> ContainerRunResult:
        command = docker_run_argv(
            image=self.image,
            name=name,
            mounts=[self._mount()],
            workdir=self.source_mount,
            argv=list(argv),
            limits=self._container_limits(),
        )
        result = run_isolated_worker(
            command,
            name=name,
            timeout_seconds=timeout_seconds,
            cancel=self.cancel,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            stop_log_path=self._stop_log,
            capture_limit_bytes=capture_limit,
        )
        # Sanitization is for diagnostic copies only: product transfers
        # (cat/glob payloads consumed as package members) must keep their
        # exact original bytes (review round 3, F7).
        if sanitize:
            self._sanitize_capture(stdout_path)
            self._sanitize_capture(stderr_path)
        if not result.stop_confirmed:
            self._unconfirmed_containers.add(name)
        return result

    def _sanitize_capture(self, path: Path) -> None:
        """Replace host paths in a raw captured stream before it rests."""

        try:
            data = path.read_bytes()
        except OSError:
            return
        replacements = (
            (str(self.work_dir).encode("utf8"), b"<work-copy>"),
            (self.work_dir.as_posix().encode("utf8"), b"<work-copy>"),
            (str(self.attempt_dir).encode("utf8"), b"<attempt>"),
        )
        for old, new in replacements:
            data = data.replace(old, new)
        path.write_bytes(data)

    def _io_timeout_remaining(self) -> float:
        """Remaining shared-deadline time for one io interaction."""

        if self._deadline is None:
            return _IO_TIMEOUT_SECONDS
        remaining = self._deadline - time.monotonic()
        if remaining <= 0:
            raise BuildRecipeError("io-deadline-exceeded")
        return min(_IO_TIMEOUT_SECONDS, remaining)

    def run_step(
        self, argv: Sequence[str], *, step_id: str, timeout_seconds: float
    ) -> IsolatedStepOutcome:
        name = "lima-agent-step-" + uuid.uuid4().hex[:12]
        stdout_path = self._io_dir / f"{step_id}.stdout.log"
        stderr_path = self._io_dir / f"{step_id}.stderr.log"
        result = self._spawn(
            list(argv),
            name=name,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=timeout_seconds,
            capture_limit=self._capture_head_room(),
        )
        head_room = self._capture_head_room()
        return IsolatedStepOutcome(
            returncode=result.returncode,
            stdout=_read_tail(stdout_path, head_room).decode(
                "utf8", errors="replace"
            ),
            stderr=_read_tail(stderr_path, head_room).decode(
                "utf8", errors="replace"
            ),
            elapsed_seconds=result.elapsed_seconds,
            timed_out=result.timed_out,
            cancelled=result.cancelled,
            stop_confirmed=result.stop_confirmed,
            stdout_truncated=result.stdout_truncated,
            stderr_truncated=result.stderr_truncated,
        )

    def _transfer(
        self, argv: Sequence[str], *, error_label: str
    ) -> tuple[ContainerRunResult, bytes]:
        """Full transfer of a product read; oversize is rejected, not cut.

        The payload is consumed verbatim as package members, so the capture
        copy must never be sanitized.
        """

        name = "lima-agent-" + uuid.uuid4().hex[:12]
        stdout_path = self._io_dir / f"{name}.stdout.log"
        stderr_path = self._io_dir / f"{name}.stderr.log"
        result = self._spawn(
            list(argv),
            name=name,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            timeout_seconds=self._io_timeout_remaining(),
            capture_limit=_FILE_READ_LIMIT_BYTES,
            sanitize=False,
        )
        if result.timed_out or result.cancelled:
            raise ContainerExecutionError(
                f"isolated-io-interrupted:{argv[0]}"
            )
        data = stdout_path.read_bytes()
        if result.stdout_truncated:
            raise BuildRecipeError(
                f"{error_label}-too-large:{argv[-1]}"
            )
        return result, data

    def read_file(self, container_path: str) -> bytes:
        result, stdout = self._transfer(
            ["cat", container_path], error_label="container-read"
        )
        if result.returncode != 0:
            raise BuildRecipeError(f"container-read-failed:{container_path}")
        return stdout

    def list_globs(self, pattern: str) -> list[str]:
        result, stdout = self._transfer(
            ["python3", "-c", LIST_GLOBS_SCRIPT, pattern],
            error_label="container-glob",
        )
        if result.returncode != 0:
            raise BuildRecipeError(f"container-glob-failed:{pattern}")
        return [
            line
            for line in stdout.decode("utf8", errors="replace").splitlines()
            if line
        ]

    def close(self) -> None:
        """Retry teardown for containers whose stop was never confirmed."""

        while self._unconfirmed_containers:
            name = self._unconfirmed_containers.pop()
            stop_container_with_confirmation(name, self._stop_log)


class DockerIsolatedSessionFactory:
    def open(
        self,
        *,
        image: str,
        work_dir: Path,
        source_mount: str,
        limits: BuildLimits,
        cancel: Callable[[], bool],
        attempt_dir: Path,
        deadline: float | None = None,
    ) -> DockerIsolatedSession:
        return DockerIsolatedSession(
            image=image,
            work_dir=work_dir,
            source_mount=source_mount,
            limits=limits,
            cancel=cancel,
            attempt_dir=attempt_dir,
            deadline=deadline,
        )


def _sanitize(text: str, tmp_root: Path) -> str:
    """Replace the disposable host working root with a placeholder."""

    return text.replace(str(tmp_root), _HOST_PATH_PLACEHOLDER)


class BuildExecutor:
    """Runs single attempts; every call starts from a clean disposable copy."""

    def __init__(
        self, *, session_factory: IsolatedSessionFactory | None = None
    ) -> None:
        self._session_factory = session_factory

    def execute(
        self,
        recipe: BuildRecipe,
        snapshot_dir: Path,
        output_dir: Path,
        *,
        limits: BuildLimits | None = None,
        cancel: Callable[[], bool] = lambda: False,
        revision: str = "unknown",
    ) -> BuildExecutionResult:
        # Contract validation happens before anything is created on disk.
        if not isinstance(recipe, BuildRecipe):
            raise BuildExecutorError("recipe-invalid")
        snapshot = Path(snapshot_dir)
        if not snapshot.is_dir():
            raise BuildExecutorError("snapshot-directory-missing")
        attempt = Path(output_dir)
        if attempt.exists() and any(attempt.iterdir()):
            raise BuildExecutorError("attempt-directory-not-empty")
        if limits is None:
            limits = BuildLimits()
        if not isinstance(limits, BuildLimits):
            raise BuildExecutorError("limits-invalid")
        if not callable(cancel):
            raise BuildExecutorError("cancel-invalid")
        if not isinstance(revision, str):
            raise BuildExecutorError("revision-invalid")

        # One deadline for the whole attempt: copy, steps, io and export.
        deadline = time.monotonic() + limits.total_seconds
        logs_dir = attempt / "logs"
        steps_dir = attempt / "steps"
        logs_dir.mkdir(parents=True, exist_ok=True)
        steps_dir.mkdir(parents=True, exist_ok=True)
        tmp_root = Path(tempfile.mkdtemp(prefix="lima-build-attempt-"))
        work_copy = tmp_root / "src"
        shutil.copytree(snapshot, work_copy)

        steps: list[BuildStepResult] = []
        stop_unconfirmed: list[str] = []
        failure_code: str | None = None
        package_rel: str | None = None
        factory = self._session_factory or DockerIsolatedSessionFactory()
        session: IsolatedSession | None = None
        try:
            session = factory.open(
                image=recipe.image,
                work_dir=work_copy,
                source_mount=recipe.source_mount,
                limits=limits,
                cancel=cancel,
                attempt_dir=attempt,
                deadline=deadline,
            )
            for index, argv in enumerate(recipe.configure):
                if cancel():
                    failure_code = FAILURE_CANCELLED
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    failure_code = FAILURE_BUDGET_EXHAUSTED
                    break
                step_timeout = min(limits.step_seconds, remaining)
                step_id = f"step-{index:03d}"
                outcome = session.run_step(
                    list(argv),
                    step_id=step_id,
                    timeout_seconds=step_timeout,
                )
                if not getattr(outcome, "stop_confirmed", True):
                    stop_unconfirmed.append(step_id)
                stdout_text, stdout_cut = bounded_text(
                    _sanitize(outcome.stdout, tmp_root), limits.max_output_bytes
                )
                stderr_text, stderr_cut = bounded_text(
                    _sanitize(outcome.stderr, tmp_root), limits.max_output_bytes
                )
                stdout_ref = f"logs/{step_id}.stdout.log"
                stderr_ref = f"logs/{step_id}.stderr.log"
                (attempt / stdout_ref).write_text(stdout_text, encoding="utf8")
                (attempt / stderr_ref).write_text(stderr_text, encoding="utf8")
                step = BuildStepResult(
                    step_id=step_id,
                    argv=tuple(argv),
                    exit_code=outcome.returncode,
                    stdout_ref=stdout_ref,
                    stderr_ref=stderr_ref,
                    elapsed_seconds=outcome.elapsed_seconds,
                    timed_out=outcome.timed_out,
                    cancelled=outcome.cancelled,
                )
                steps.append(step)
                save_record(
                    steps_dir,
                    {
                        "step_id": step.step_id,
                        "argv": list(step.argv),
                        "exit_code": step.exit_code,
                        "stdout_ref": step.stdout_ref,
                        "stderr_ref": step.stderr_ref,
                        "elapsed_seconds": step.elapsed_seconds,
                        "timed_out": step.timed_out,
                        "cancelled": step.cancelled,
                        "stdout_truncated": stdout_cut
                        or bool(getattr(outcome, "stdout_truncated", False)),
                        "stderr_truncated": stderr_cut
                        or bool(getattr(outcome, "stderr_truncated", False)),
                        "stop_unconfirmed": not getattr(
                            outcome, "stop_confirmed", True
                        ),
                    },
                    filename=f"{step.step_id}.json",
                )
                if outcome.cancelled:
                    failure_code = FAILURE_CANCELLED
                    break
                if outcome.timed_out:
                    failure_code = FAILURE_STEP_TIMEOUT
                    break
                if outcome.returncode != 0:
                    failure_code = FAILURE_STEP_FAILED
                    break
            if failure_code is None:
                # Export only while uncancelled and inside the deadline; the
                # deadline also bounds the export's own container io.
                if cancel():
                    failure_code = FAILURE_CANCELLED
                elif time.monotonic() >= deadline:
                    failure_code = FAILURE_BUDGET_EXHAUSTED
                else:
                    pkg_dir = attempt / "package"
                    try:
                        export_context_package(
                            recipe, session, pkg_dir, revision=revision
                        )
                    except BuildRecipeError:
                        failure_code = FAILURE_EXPORT_FAILED
                    except ContainerExecutionError:
                        failure_code = (
                            FAILURE_CANCELLED
                            if cancel()
                            else FAILURE_EXPORT_INTERRUPTED
                        )
                    else:
                        package_rel = "package"
                        # A finished export still has to beat cancellation
                        # and the deadline (review round 3, F8): parsing,
                        # manifest and package writes consume wall clock
                        # after the last container io.
                        if cancel():
                            package_rel = None
                            failure_code = FAILURE_CANCELLED
                        elif time.monotonic() >= deadline:
                            package_rel = None
                            failure_code = FAILURE_BUDGET_EXHAUSTED
        finally:
            if session is not None:
                session.close()
            shutil.rmtree(tmp_root, ignore_errors=True)

        # Final publication gate (review round 3, F9): cleanup (stop retries,
        # large copy removal) opens a window where cancellation or the
        # deadline can land after the last check; both outrank any
        # not-yet-published result, and cancellation wins over everything.
        if failure_code != FAILURE_CANCELLED and cancel():
            failure_code = FAILURE_CANCELLED
            package_rel = None
        if failure_code is None and time.monotonic() >= deadline:
            failure_code = FAILURE_BUDGET_EXHAUSTED
            package_rel = None

        if failure_code == FAILURE_CANCELLED:
            # The shared rule: a cancelled attempt never publishes a result
            # record; the pending-cancellation marker outranks any late write.
            (attempt / CANCEL_MARKER).write_text(
                '{"reason": "cancel-callback"}\n', encoding="utf8"
            )
        else:
            save_record(
                attempt,
                {
                    "ok": failure_code is None,
                    "failure_code": failure_code,
                    "image": recipe.image,
                    "package": package_rel,
                    "steps": [
                        {
                            "step_id": step.step_id,
                            "exit_code": step.exit_code,
                            "timed_out": step.timed_out,
                            "cancelled": step.cancelled,
                        }
                        for step in steps
                    ],
                    "stop_unconfirmed": stop_unconfirmed,
                    "elapsed_seconds": time.monotonic()
                    - (deadline - limits.total_seconds),
                },
                filename="attempt.json",
            )
        return BuildExecutionResult(
            ok=failure_code is None,
            steps=tuple(steps),
            image=recipe.image,
            image_digest=getattr(session, "image_digest", None),
            package_path=str(attempt / package_rel) if package_rel else None,
            failure_code=failure_code,
            stop_unconfirmed=tuple(stop_unconfirmed),
        )
