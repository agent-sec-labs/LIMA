"""Bounded isolated build executor tests (build agent slice 1).

The executor runs one attempt of a frozen :class:`BuildRecipe` against a
disposable copy of the repository snapshot.  Every step goes through an
injected isolated session (never Docker in tests), evidence lands under the
attempt directory as relative references with bounded sanitized logs, and each
new attempt starts from a clean copy while the original snapshot bytes stay
untouched.  These tests freeze the shared worker-evidence rule together with
the executor contract the build agent (slice 3) will consume.
"""

import json
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from lima.build_executor import (
    BuildExecutor,
    BuildExecutorError,
    BuildLimits,
    DockerIsolatedSession,
    _read_tail,
)
from lima.build_recipe import BuildRecipe
from lima.container_execution import (
    ContainerExecutionError,
    ContainerRunResult,
    _TailBuffer,
    publish_verified_worker_record,
    run_isolated_worker,
)
from lima.context_package import read_package

RECIPE_YAML = """\
schema_version: 1
name: agent-fixture
image: lima-agent-fixture:latest
repository: Fixtures/AgentRepo
source_mount: /src
configure:
  - ["cmake", "-S", ".", "-B", "build", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"]
  - ["cmake", "--build", "build", "--target", "codegen"]
compdb_path: "build/compile_commands.json"
generated_globs:
  - "build/*.h"
include_roots:
  - {container: "/usr/include/fixture", package: "headers/fixture"}
"""

CODEGEN_ARGV = ("cmake", "--build", "build", "--target", "codegen")
CONFIGURE_ARGV = (
    "cmake",
    "-S",
    ".",
    "-B",
    "build",
    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
)


def make_recipe() -> BuildRecipe:
    return BuildRecipe.from_yaml(RECIPE_YAML)


def make_compdb() -> list[dict]:
    return [
        {
            "directory": "/src/app",
            "arguments": [
                "/usr/bin/c++",
                "-I/usr/include/fixture",
                "-c",
                "app/main.cpp",
            ],
            "file": "/src/app/main.cpp",
        }
    ]


class Outcome:
    """One fake step outcome, mirroring the isolated-session contract."""

    def __init__(
        self,
        returncode: int | None = 0,
        stdout: str = "",
        stderr: str = "",
        elapsed_seconds: float = 1.0,
        timed_out: bool = False,
        cancelled: bool = False,
    ) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr
        self.elapsed_seconds = elapsed_seconds
        self.timed_out = timed_out
        self.cancelled = cancelled


def fake_configure(session, argv, timeout_seconds):
    """Configure exports the compdb and one generated header into the copy."""

    session.saw_prior_build = (session.work_dir / "build").exists()
    build = session.work_dir / "build"
    build.mkdir(parents=True, exist_ok=True)
    (build / "config.h").write_text("#define FIXTURE 1\n", encoding="utf8")
    session.files["/src/build/compile_commands.json"] = json.dumps(
        make_compdb()
    ).encode("utf8")
    session.files["/src/build/config.h"] = b"#define FIXTURE 1\n"
    session.files["/usr/include/fixture/lib.h"] = b"// lib\n"
    return Outcome(stdout="configured")


def fake_codegen(session, argv, timeout_seconds):
    """The second step only succeeds when the generated header is visible."""

    session.generated_seen = (session.work_dir / "build" / "config.h").is_file()
    if not session.generated_seen:
        return Outcome(returncode=2, stderr="generated header missing\n")
    return Outcome(stdout="built")


def default_script() -> dict[tuple[str, ...], object]:
    return {
        CONFIGURE_ARGV: fake_configure,
        CODEGEN_ARGV: fake_codegen,
    }


def glob_regex(pattern: str) -> re.Pattern[str]:
    parts: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*" and index + 1 < len(pattern) and pattern[index + 1] == "*":
            parts.append(".*")
            index += 2
            continue
        if char == "*":
            parts.append("[^/]*")
        elif char == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(char))
        index += 1
    return re.compile("".join(parts) + r"\Z")


class FakeSession:
    """In-memory isolated session: zero Docker, script-driven steps."""

    def __init__(self, *, work_dir, source_mount, script, limits, cancel):
        self.work_dir = Path(work_dir)
        self.source_mount = source_mount
        self.script = script
        self.limits = limits
        self.cancel = cancel
        self.files: dict[str, bytes] = {}
        self.step_timeouts: list[float] = []
        self.saw_prior_build: bool | None = None
        self.generated_seen: bool | None = None
        self.closed = False

    def run_step(self, argv, *, step_id, timeout_seconds):
        self.step_timeouts.append(timeout_seconds)
        action = self.script[tuple(argv)]
        return action(self, tuple(argv), timeout_seconds)

    def read_file(self, container_path: str) -> bytes:
        return self.files[container_path]

    def list_globs(self, pattern: str) -> list[str]:
        regex = glob_regex(pattern)
        return sorted(path for path in self.files if regex.match(path))

    def run(self, argv, mounts=()):
        return 0, ""

    def close(self):
        self.closed = True


class FakeSessionFactory:
    def __init__(self, script=None, session_cls=FakeSession):
        self.script = script if script is not None else default_script()
        self.session_cls = session_cls
        self.sessions: list[FakeSession] = []

    def open(
        self,
        *,
        image,
        work_dir,
        source_mount,
        limits,
        cancel,
        attempt_dir,
        deadline=None,
    ):
        session = self.session_cls(
            work_dir=work_dir,
            source_mount=source_mount,
            script=self.script,
            limits=limits,
            cancel=cancel,
        )
        self.sessions.append(session)
        return session


def write_snapshot(tmp: str) -> Path:
    snapshot = Path(tmp) / "snapshot"
    (snapshot / "app").mkdir(parents=True)
    (snapshot / "app" / "main.cpp").write_text("int main(void) { return 0; }\n")
    return snapshot


def tree_digest(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class BuildExecutorTest(unittest.TestCase):
    def execute(
        self,
        factory: FakeSessionFactory,
        snapshot: Path,
        attempt: Path,
        *,
        limits: BuildLimits | None = None,
        cancel=lambda: False,
    ):
        executor = BuildExecutor(session_factory=factory)
        return executor.execute(
            make_recipe(),
            snapshot,
            attempt,
            limits=limits or BuildLimits(),
            cancel=cancel,
        )

    def test_generated_file_survives_configure_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            factory = FakeSessionFactory()
            attempt = Path(tmp) / "attempt-1"

            result = self.execute(factory, snapshot, attempt)

            self.assertTrue(result.ok)
            self.assertIsNone(result.failure_code)
            session = factory.sessions[0]
            # The second step observed the header the first step generated in
            # the same disposable copy, and the export vendored it.
            self.assertTrue(session.generated_seen)
            package = read_package(Path(result.package_path))
            self.assertEqual(
                package.manifest.generated_headers, ("build/config.h",)
            )
            self.assertEqual(package.manifest.totals.header_file_count, 1)
            # The snapshot itself is never the mounted work directory.
            self.assertNotEqual(session.work_dir, snapshot.resolve())
            self.assertTrue(session.closed)

    def test_retry_starts_clean_and_snapshot_unchanged(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            before = tree_digest(snapshot)
            factory = FakeSessionFactory()

            first = self.execute(factory, snapshot, Path(tmp) / "attempt-1")
            second = self.execute(factory, snapshot, Path(tmp) / "attempt-2")

            self.assertTrue(first.ok)
            self.assertTrue(second.ok)
            # Two attempts used two distinct disposable copies; neither saw a
            # build tree from an earlier attempt, and both copies were removed.
            self.assertNotEqual(
                factory.sessions[0].work_dir, factory.sessions[1].work_dir
            )
            for session in factory.sessions:
                self.assertFalse(session.saw_prior_build)
                self.assertFalse(session.work_dir.exists())
            self.assertEqual(tree_digest(snapshot), before)

    def test_timeout_cancel_and_stderr_are_recorded(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            attempt = Path(tmp) / "attempt"
            script = dict(default_script())
            script[CODEGEN_ARGV] = lambda session, argv, timeout: Outcome(
                returncode=None,
                stdout="A" * 200,
                stderr="E" * 300 + f" boom tail at {session.work_dir}\n",
                timed_out=True,
            )
            factory = FakeSessionFactory(script)
            limits = BuildLimits(max_output_bytes=64)

            result = self.execute(factory, snapshot, attempt, limits=limits)

            self.assertFalse(result.ok)
            self.assertEqual(result.failure_code, "step-timeout")
            self.assertEqual(len(result.steps), 2)
            step = result.steps[1]
            self.assertTrue(step.timed_out)
            self.assertIsNone(step.exit_code)
            stderr_path = attempt / step.stderr_ref
            self.assertTrue(stderr_path.is_file())
            stderr_text = stderr_path.read_text(encoding="utf8")
            # Bounded: only the explicit truncation marker plus the kept tail
            # survive; host work-copy paths never appear in evidence.
            self.assertIn("truncated", stderr_text)
            self.assertIn("boom tail", stderr_text)
            self.assertLessEqual(
                len(stderr_text.encode("utf8")), 64 + 200
            )
            self.assertNotIn(
                str(factory.sessions[0].work_dir.parent), stderr_text
            )
            step_json = json.loads(
                (attempt / "steps" / "step-001.json").read_text(encoding="utf8")
            )
            self.assertTrue(step_json["stdout_truncated"])
            self.assertEqual(step_json["argv"], list(CODEGEN_ARGV))
            summary = json.loads(
                (attempt / "attempt.json").read_text(encoding="utf8")
            )
            self.assertEqual(summary["failure_code"], "step-timeout")
            self.assertEqual(summary["package"], None)

            # Cancellation before any step stops without publishing a result.
            cancel_attempt = Path(tmp) / "attempt-cancel"
            cancel_factory = FakeSessionFactory()
            cancelled = self.execute(
                cancel_factory, snapshot, cancel_attempt, cancel=lambda: True
            )
            self.assertFalse(cancelled.ok)
            self.assertEqual(cancelled.failure_code, "cancelled")
            self.assertEqual(cancel_factory.sessions[0].step_timeouts, [])
            self.assertFalse((cancel_attempt / "attempt.json").exists())
            self.assertTrue(
                (cancel_attempt / "cancel-requested.json").exists()
            )

    def test_worker_result_not_published_after_cancel(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            attempt = Path(tmp)
            (attempt / "worker-result.json").write_text(
                json.dumps({"status": "completed"}), encoding="utf8"
            )
            (attempt / "cancel-requested.json").write_text("{}", encoding="utf8")
            with self.assertRaises(ValueError):
                publish_verified_worker_record(attempt)
            (attempt / "cancel-requested.json").unlink()
            record = publish_verified_worker_record(attempt)
            self.assertEqual(record["status"], "completed")

    def test_remaining_budget_bounds_each_step_timeout(self) -> None:
        # The deadline is a real monotonic clock covering the whole attempt
        # (review F5): a step that really spends time shrinks what the next
        # step gets, regardless of what runtimes report.
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            script = dict(default_script())

            def slow_configure(session, argv, timeout_seconds):
                outcome = fake_configure(session, argv, timeout_seconds)
                time.sleep(0.35)
                return outcome

            script[CONFIGURE_ARGV] = slow_configure
            limits = BuildLimits(total_seconds=0.5, step_seconds=300.0)
            factory = FakeSessionFactory(script)

            result = self.execute(
                factory, snapshot, Path(tmp) / "attempt", limits=limits
            )

            self.assertTrue(result.ok)
            timeouts = factory.sessions[0].step_timeouts
            self.assertAlmostEqual(timeouts[0], 0.5, delta=0.1)
            self.assertAlmostEqual(timeouts[1], 0.15, delta=0.1)

    def test_read_tail_is_bounded(self) -> None:
        # Raw step logs are written unbounded to disk; the host must take the
        # tail by seek so memory never scales with the log size.
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "big.log"
            payload = bytes(range(256)) * 128  # 32 KiB
            path.write_bytes(payload)
            self.assertEqual(_read_tail(path, 1024), payload[-1024:])
            self.assertEqual(_read_tail(path, 100_000), payload)
            self.assertEqual(_read_tail(path, 0), b"")

    def test_run_step_surfaces_real_timeout_without_raising(self) -> None:
        # The production session must deliver timeouts and cancellations as
        # data (review F1): an interrupted step still reaches evidence.
        with tempfile.TemporaryDirectory() as tmp:
            attempt = Path(tmp) / "attempt"
            session = DockerIsolatedSession(
                image="img",
                work_dir=Path(tmp) / "work",
                source_mount="/src",
                limits=BuildLimits(),
                cancel=lambda: False,
                attempt_dir=attempt,
            )

            def interrupted_worker(command, **kwargs):
                kwargs["stdout_path"].parent.mkdir(parents=True, exist_ok=True)
                kwargs["stdout_path"].write_bytes(b"halfway output")
                kwargs["stderr_path"].write_bytes(b"boom")
                return ContainerRunResult(
                    returncode=None,
                    timed_out=True,
                    cancelled=False,
                    elapsed_seconds=5.0,
                    stop_confirmed=False,
                    stdout_truncated=True,
                )

            with mock.patch(
                "lima.build_executor.run_isolated_worker",
                side_effect=interrupted_worker,
            ):
                outcome = session.run_step(
                    ("cmake",), step_id="step-000", timeout_seconds=5.0
                )
            self.assertTrue(outcome.timed_out)
            self.assertIsNone(outcome.returncode)
            self.assertFalse(outcome.stop_confirmed)
            self.assertTrue(outcome.stdout_truncated)
            self.assertEqual(outcome.stdout, "halfway output")

    def test_cancel_after_last_step_never_publishes(self) -> None:
        # Cancellation landing between the last step and publication must
        # still suppress the success record (review F6).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            flags = {"cancel": False}
            script = dict(default_script())

            def codegen_then_cancel(session, argv, timeout_seconds):
                outcome = fake_codegen(session, argv, timeout_seconds)
                flags["cancel"] = True
                return outcome

            script[CODEGEN_ARGV] = codegen_then_cancel
            factory = FakeSessionFactory(script)
            attempt = Path(tmp) / "attempt"

            result = self.execute(
                factory,
                snapshot,
                attempt,
                cancel=lambda: flags["cancel"],
            )

            self.assertFalse(result.ok)
            self.assertEqual(result.failure_code, "cancelled")
            self.assertFalse((attempt / "attempt.json").exists())
            self.assertTrue((attempt / "cancel-requested.json").exists())

    def test_export_interruption_is_terminal(self) -> None:
        # An interrupted container read during export is a terminal outcome,
        # not an escaping exception (review F1).
        class InterruptingSession(FakeSession):
            def read_file(self, container_path: str) -> bytes:
                raise ContainerExecutionError(
                    f"isolated-io-interrupted:cat:{container_path}"
                )

        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            factory = FakeSessionFactory(session_cls=InterruptingSession)
            attempt = Path(tmp) / "attempt"

            result = self.execute(factory, snapshot, attempt)

            self.assertFalse(result.ok)
            self.assertEqual(result.failure_code, "export-interrupted")
            summary = json.loads(
                (attempt / "attempt.json").read_text(encoding="utf8")
            )
            self.assertEqual(summary["failure_code"], "export-interrupted")
            self.assertIsNone(summary["package"])

    def test_budget_deadline_blocks_export(self) -> None:
        # The entry deadline covers every phase: a spent budget must stop
        # the export from ever starting (review F5).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            factory = FakeSessionFactory()
            attempt = Path(tmp) / "attempt"

            result = self.execute(
                factory,
                snapshot,
                attempt,
                limits=BuildLimits(total_seconds=0.0),
            )

            self.assertFalse(result.ok)
            self.assertEqual(result.failure_code, "budget-exhausted")
            self.assertIsNone(result.package_path)
            self.assertFalse((attempt / "package").exists())

    def test_tail_buffer_keeps_tail_within_limit(self) -> None:
        buffer = _TailBuffer(10)
        buffer.write(b"1234567890")
        buffer.write(b"abcdef")
        self.assertEqual(buffer.data(), b"7890abcdef")
        self.assertTrue(buffer.truncated)
        self.assertEqual(buffer.total, 16)
        small = _TailBuffer(10)
        small.write(b"short")
        self.assertEqual(small.data(), b"short")
        self.assertFalse(small.truncated)

    def test_run_isolated_worker_unconfirmed_stop_is_visible(self) -> None:
        # A stop that cannot be confirmed is reported, not assumed clean
        # (review F2).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            stop_log = root / "stop.log"
            with mock.patch(
                "lima.container_execution."
                "stop_container_with_confirmation",
                return_value=False,
            ):
                result = run_isolated_worker(
                    [sys.executable, "-c", "import time; time.sleep(1)"],
                    name="probe",
                    timeout_seconds=60.0,
                    cancel=lambda: True,
                    stdout_path=root / "out.log",
                    stderr_path=root / "err.log",
                    stop_log_path=stop_log,
                )
            self.assertTrue(result.cancelled)
            self.assertFalse(result.stop_confirmed)
            self.assertIn(
                "stop-unconfirmed",
                stop_log.read_text(encoding="utf8"),
            )

    def test_run_isolated_worker_capture_limit_marks_truncation(self) -> None:
        # Raw streams are captured into bounded tail buffers with an
        # explicit marker (review F3): host disk never scales with output.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            result = run_isolated_worker(
                [sys.executable, "-c", "print('A' * 200_000)"],
                name="probe",
                timeout_seconds=60.0,
                cancel=lambda: False,
                stdout_path=root / "out.log",
                stderr_path=root / "err.log",
                stop_log_path=root / "stop.log",
                capture_limit_bytes=1024,
            )
            self.assertTrue(result.stdout_truncated)
            data = (root / "out.log").read_bytes()
            self.assertIn(b"capture-truncated", data)
            self.assertLessEqual(len(data), 1024 + 200)

    def test_argument_contract_is_enforced(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot = write_snapshot(tmp)
            executor = BuildExecutor(session_factory=FakeSessionFactory())
            attempt = Path(tmp) / "attempt"
            with self.assertRaises(BuildExecutorError):
                executor.execute("not-a-recipe", snapshot, attempt)
            with self.assertRaises(BuildExecutorError):
                executor.execute(make_recipe(), Path(tmp) / "missing", attempt)
            # Validation happens before the attempt directory is created.
            self.assertFalse(attempt.exists())
            attempt.mkdir()
            (attempt / "stale.txt").write_text("evidence", encoding="utf8")
            with self.assertRaises(BuildExecutorError):
                executor.execute(make_recipe(), snapshot, attempt)
            self.assertEqual(
                (attempt / "stale.txt").read_text(encoding="utf8"), "evidence"
            )


if __name__ == "__main__":
    unittest.main()
