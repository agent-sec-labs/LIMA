"""Bounded isolated build executor for the repository build agent (slice 1).

One :meth:`BuildExecutor.execute` call is one attempt of a frozen
:class:`~lima.build_recipe.BuildRecipe` against a repository snapshot.  The
snapshot is never touched: the executor copies it into a disposable working
directory, hands that copy to an injected isolated session (one hardened
``docker run`` per interaction in production, network off, capabilities
dropped), and records every step as bounded sanitized evidence under the
attempt directory.  Step output references are relative paths inside that
directory, so host paths never leak into task or model context.

Retry semantics live with the caller: a new ``execute`` call always starts
from a fresh copy, so a previous attempt's generated files can never leak
into the next one.  A successful ``BuildExecutionResult`` means the configure
steps ran and a package was exported; whether the package is usable by
downstream consumers is decided elsewhere (slice 4A).
"""

from __future__ import annotations

import dataclasses
import shutil
import tempfile
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
_HOST_PATH_PLACEHOLDER: Final = "<attempt>"

FAILURE_CANCELLED: Final = "cancelled"
FAILURE_STEP_TIMEOUT: Final = "step-timeout"
FAILURE_STEP_FAILED: Final = "configure-step-failed"
FAILURE_BUDGET_EXHAUSTED: Final = "budget-exhausted"
FAILURE_EXPORT_FAILED: Final = "export-failed"


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

    ``total_seconds`` bounds the whole attempt wall clock; each step gets at
    most ``step_seconds`` and never more than the remaining total, so a long
    step cannot silently eat the budget of the next one.  ``max_output_bytes``
    bounds each captured stdout/stderr stream kept as evidence.
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
    context, which only hold attempt-relative references.
    """

    ok: bool
    steps: tuple[BuildStepResult, ...]
    image: str
    image_digest: str | None
    package_path: str | None
    failure_code: str | None


class IsolatedStepOutcome:
    """What one session step reports back to the executor."""

    def __init__(
        self,
        *,
        returncode: int | None,
        stdout: str,
        stderr: str,
        elapsed_seconds: float,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.elapsed_seconds = elapsed_seconds
        self.timed_out = timed_out
        self.cancelled = cancelled


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
    ) -> IsolatedSession: ...


class DockerIsolatedSession:
    """Production session: one hardened docker run per interaction.

    The disposable work copy is the only host directory mounted (writable, at
    the recipe's source mount); the network is off and resources are bounded
    by :class:`BuildLimits`.  Raw container output lands under
    ``<attempt>/io/`` and the confirmed stop/kill teardown handles timeout
    and cancellation.
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
    ) -> None:
        self.image = image
        self.image_digest: str | None = None
        self.work_dir = Path(work_dir)
        self.source_mount = source_mount
        self.limits = limits
        self.cancel = cancel
        self.attempt_dir = Path(attempt_dir)
        self._io_dir = self.attempt_dir / "io"
        self._stop_log = self._io_dir / "container-stop.log"
        self._io_dir.mkdir(parents=True, exist_ok=True)

    def _container_limits(self) -> ContainerLimits:
        return ContainerLimits(
            memory=self.limits.memory,
            cpus=self.limits.cpus,
            pids_limit=self.limits.pids_limit,
            network=False,
        )

    def _run(
        self,
        argv: Sequence[str],
        *,
        name: str,
        stdout_path: Path,
        stderr_path: Path,
        timeout_seconds: float,
    ) -> tuple[ContainerRunResult, bytes, bytes]:
        mount = (
            "type=bind,"
            f"source={self.work_dir.resolve().as_posix()},"
            f"target={self.source_mount}"
        )
        command = docker_run_argv(
            image=self.image,
            name=name,
            mounts=[mount],
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
        )
        if result.timed_out or result.cancelled:
            raise ContainerExecutionError(
                f"isolated-interaction-interrupted:{argv[0]}"
            )
        # Keep at most a few evidence budgets in memory for text consumers,
        # reading the tail by seek so host memory never scales with the log.
        head_room = max(1, self.limits.max_output_bytes * 4)
        return (
            result,
            _read_tail(stdout_path, head_room),
            _read_tail(stderr_path, head_room),
        )

    def run_step(
        self, argv: Sequence[str], *, step_id: str, timeout_seconds: float
    ) -> IsolatedStepOutcome:
        name = "lima-agent-step-" + uuid.uuid4().hex[:12]
        result, stdout, stderr = self._run(
            list(argv),
            name=name,
            stdout_path=self._io_dir / f"{step_id}.stdout.log",
            stderr_path=self._io_dir / f"{step_id}.stderr.log",
            timeout_seconds=timeout_seconds,
        )
        return IsolatedStepOutcome(
            returncode=result.returncode,
            stdout=stdout.decode("utf8", errors="replace"),
            stderr=stderr.decode("utf8", errors="replace"),
            elapsed_seconds=result.elapsed_seconds,
            timed_out=result.timed_out,
            cancelled=result.cancelled,
        )

    def read_file(self, container_path: str) -> bytes:
        name = "lima-agent-" + uuid.uuid4().hex[:12]
        result, stdout, _stderr = self._run(
            ["cat", container_path],
            name=name,
            stdout_path=self._io_dir / f"{name}.stdout.log",
            stderr_path=self._io_dir / f"{name}.stderr.log",
            timeout_seconds=_IO_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise BuildRecipeError(f"container-read-failed:{container_path}")
        return stdout

    def list_globs(self, pattern: str) -> list[str]:
        name = "lima-agent-" + uuid.uuid4().hex[:12]
        result, stdout, _stderr = self._run(
            ["python3", "-c", LIST_GLOBS_SCRIPT, pattern],
            name=name,
            stdout_path=self._io_dir / f"{name}.stdout.log",
            stderr_path=self._io_dir / f"{name}.stderr.log",
            timeout_seconds=_IO_TIMEOUT_SECONDS,
        )
        if result.returncode != 0:
            raise BuildRecipeError(f"container-glob-failed:{pattern}")
        return [
            line
            for line in stdout.decode("utf8", errors="replace").splitlines()
            if line
        ]

    def close(self) -> None:
        return None


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
    ) -> DockerIsolatedSession:
        return DockerIsolatedSession(
            image=image,
            work_dir=work_dir,
            source_mount=source_mount,
            limits=limits,
            cancel=cancel,
            attempt_dir=attempt_dir,
        )


def _read_tail(path: Path, limit: int) -> bytes:
    """Read at most the last ``limit`` bytes without loading the file.

    A step log is written unbounded straight to disk, so the host must seek
    near the end instead of materializing a potentially huge stream just to
    slice its tail.
    """

    size = path.stat().st_size
    with path.open("rb") as handle:
        handle.seek(max(0, size - limit))
        return handle.read()


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

        logs_dir = attempt / "logs"
        steps_dir = attempt / "steps"
        logs_dir.mkdir(parents=True, exist_ok=True)
        steps_dir.mkdir(parents=True, exist_ok=True)
        tmp_root = Path(tempfile.mkdtemp(prefix="lima-build-attempt-"))
        work_copy = tmp_root / "src"
        shutil.copytree(snapshot, work_copy)

        steps: list[BuildStepResult] = []
        failure_code: str | None = None
        package_rel: str | None = None
        elapsed_total = 0.0
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
            )
            for index, argv in enumerate(recipe.configure):
                if cancel():
                    failure_code = FAILURE_CANCELLED
                    break
                remaining = limits.total_seconds - elapsed_total
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
                elapsed_total += outcome.elapsed_seconds
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
                        "stdout_truncated": stdout_cut,
                        "stderr_truncated": stderr_cut,
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
                pkg_dir = attempt / "package"
                try:
                    export_context_package(
                        recipe, session, pkg_dir, revision=revision
                    )
                except BuildRecipeError:
                    failure_code = FAILURE_EXPORT_FAILED
                else:
                    package_rel = "package"
        finally:
            if session is not None:
                session.close()
            shutil.rmtree(tmp_root, ignore_errors=True)

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
                    "elapsed_seconds": elapsed_total,
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
        )
