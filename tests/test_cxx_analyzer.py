import copy
import hashlib
import http.client
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import ANY, Mock, patch

import cxx_analyzer.server as analyzer_server
import cxx_analyzer.source_scan as source_scan
from cxx_analyzer.config import AnalyzerSettings, parse_steps_json
from cxx_analyzer.deadline import AnalysisDeadline
from cxx_analyzer.execution import (
    CLEAN_ENVIRONMENT,
    StreamCapture,
    ToolExecution,
    _stream_process,
    run_step,
)
from cxx_analyzer.normalizers import (
    NormalizedFinding,
    conservative_identity,
)
from cxx_analyzer.sandbox import (
    MIN_LANDLOCK_ABI,
    build_launcher_argv,
    build_policy,
    landlock_abi,
)
from cxx_analyzer.snapshot import prepare_snapshot
from cxx_analyzer.source_scan import LayerResult, parse_semgrep_json, run_source_scan
from lima.workspace import RepositoryWorkspace


def _expected_cmake_steps():
    return (
        (
            "cmake",
            "-S",
            ".",
            "-B",
            "build",
            "-DCMAKE_BUILD_TYPE=Debug",
            "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
        ),
        ("cmake", "--build", "build", "--parallel", "2"),
    )


def _dockerfile_instructions(dockerfile: str) -> list[tuple[str, str]]:
    instructions: list[tuple[str, str]] = []
    pending = ""
    for raw_line in dockerfile.splitlines():
        line = raw_line.strip()
        if not pending and (not line or line.startswith("#")):
            continue
        pending = f"{pending} {line}".strip() if pending else line
        if pending.endswith("\\"):
            pending = pending[:-1].rstrip()
            continue
        parts = pending.split(maxsplit=1)
        if len(parts) != 2:
            raise ValueError("Dockerfile instruction is incomplete")
        instructions.append((parts[0].upper(), parts[1]))
        pending = ""
    if pending:
        raise ValueError("Dockerfile continuation is incomplete")
    return instructions


def _validate_sidecar_dockerfile_contract(dockerfile: str) -> None:
    instructions = _dockerfile_instructions(dockerfile)
    pinned_image = (
        "public.ecr.aws/docker/library/python:3.11-slim@sha256:"
        "9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"
    )
    expected_first = ("FROM", f"{pinned_image} AS base")
    if not instructions or instructions[0] != expected_first:
        raise ValueError("analyzer base image is not pinned")

    stages: dict[str, tuple[str, list[tuple[str, str]]]] = {}
    current_stage: str | None = None
    for operation, value in instructions:
        if operation == "FROM":
            match = re.fullmatch(r"(\S+)\s+AS\s+([A-Za-z0-9_.-]+)", value, re.IGNORECASE)
            if match is None:
                raise ValueError("every Dockerfile stage must be named")
            base, name = match.groups()
            if name in stages:
                raise ValueError("Dockerfile stage name is duplicated")
            stages[name] = (base, [])
            current_stage = name
            continue
        if current_stage is None:
            raise ValueError("Dockerfile instruction appears before FROM")
        stages[current_stage][1].append((operation, value))

    if set(stages) != {"base", "runtime", "test"}:
        raise ValueError("Dockerfile stages do not match the analyzer contract")
    if stages["base"][0] != pinned_image:
        raise ValueError("base stage image is not pinned")
    if stages["runtime"][0] != "base" or stages["test"][0] != "base":
        raise ValueError("runtime and test stages must inherit the pinned base")

    def inherited(stage: str, chain: tuple[str, ...] = ()) -> list[tuple[str, str]]:
        if stage in chain:
            raise ValueError("Dockerfile stage inheritance is cyclic")
        parent, own = stages[stage]
        parent_instructions = inherited(parent, (*chain, stage)) if parent in stages else []
        return [*parent_instructions, *own]

    runtime = inherited("runtime")
    test = inherited("test")
    if any(operation == "ARG" for operation, _ in runtime):
        raise ValueError("runtime ancestry accepts build arguments")

    run_values = [value for operation, value in runtime if operation == "RUN"]
    run_contract = "\n".join(run_values)
    for required in (
        'python -m pip install "semgrep==1.130.0"',
        '"clang-14"',
        '"clang-tools-14"',
        '"llvm-14"',
        'grep --quiet "^cmake version 3\\."',
        "groupadd --gid 10002 analyzer",
        "useradd --uid 10002 --gid 10002",
    ):
        if required not in run_contract:
            raise ValueError(f"runtime is missing fixed contract: {required}")

    content_instructions = [
        (operation, value) for operation, value in runtime if operation in {"COPY", "ADD"}
    ]
    if content_instructions != [("COPY", "--chown=analyzer:analyzer cxx_analyzer ./cxx_analyzer")]:
        raise ValueError("runtime COPY/ADD boundary is not analyzer-only")

    runtime_users = [value for operation, value in runtime if operation == "USER"]
    test_users = [value for operation, value in test if operation == "USER"]
    if not runtime_users or runtime_users[-1] != "analyzer:analyzer":
        raise ValueError("runtime effective user is not analyzer")
    if not test_users or test_users[-1] != "analyzer:analyzer":
        raise ValueError("test effective user is not analyzer")


class AnalyzerBoundaryTests(unittest.TestCase):
    def _repository(self, temporary: str) -> tuple[Path, Path, Path]:
        base = Path(temporary)
        import_root = base / "imports"
        repository = import_root / "team" / "project"
        work_root = base / "work"
        repository.mkdir(parents=True)
        work_root.mkdir()
        return import_root, repository, work_root

    def test_parse_steps_json_accepts_only_bounded_argv_arrays(self):
        self.assertEqual(
            (("cmake", "-S", ".", "-B", "build"),),
            parse_steps_json(
                "LIMA_CXX_BUILD_STEPS_JSON",
                '[["cmake", "-S", ".", "-B", "build"]]',
            ),
        )

        invalid_values = {
            "string command": '"cmake -S . -B build"',
            "step is string": '["cmake"]',
            "empty argv": "[[]]",
            "non-string argument": '[["cmake", 2]]',
            "NUL argument": '[["cmake", "bad\\u0000arg"]]',
            "too many steps": str([["true"]] * 65).replace("'", '"'),
            "too many arguments": str([["tool"] * 129]).replace("'", '"'),
            "argument too large": str([["x" * 4097]]).replace("'", '"'),
        }
        for description, raw in invalid_values.items():
            with self.subTest(description=description):
                with self.assertRaises(ValueError):
                    parse_steps_json("LIMA_CXX_BUILD_STEPS_JSON", raw)

    def test_settings_are_admin_environment_only_and_have_safe_defaults(self):
        with patch.dict(os.environ, {"LIMA_DATABASE_URL": "postgres://secret"}, clear=True):
            settings = AnalyzerSettings.from_env()

        self.assertTrue(settings.auto_cmake)
        self.assertEqual((), settings.build_steps)
        self.assertEqual((), settings.test_steps)
        self.assertEqual(2048, settings.max_memory_mb)
        self.assertEqual(128, settings.max_processes)
        self.assertEqual(1_048_576, settings.max_output_bytes)
        self.assertEqual(120, settings.step_timeout_seconds)
        self.assertEqual(300, settings.total_timeout_seconds)
        self.assertEqual(5_000, settings.repository_scan_max_files)
        self.assertEqual(512 * 1024, settings.repository_scan_max_file_bytes)
        self.assertEqual(20 * 1024 * 1024, settings.repository_scan_max_total_bytes)
        self.assertNotIn("postgres://secret", repr(settings))
        with self.assertRaises(FrozenInstanceError):
            settings.max_output_bytes = 10

    def test_settings_parse_all_sidecar_limits_strictly(self):
        environment = {
            "LIMA_CXX_AUTO_CMAKE": "false",
            "LIMA_CXX_BUILD_STEPS_JSON": '[["cmake", "--build", "build"]]',
            "LIMA_CXX_TEST_STEPS_JSON": '[["ctest", "--test-dir", "build"]]',
            "LIMA_CXX_MAX_MEMORY_MB": "1024",
            "LIMA_CXX_MAX_PROCESSES": "32",
            "LIMA_CXX_MAX_OUTPUT_BYTES": "8192",
            "LIMA_CXX_STEP_TIMEOUT_SECONDS": "30",
            "LIMA_CXX_TOTAL_TIMEOUT_SECONDS": "90",
            "LIMA_REPOSITORY_SCAN_MAX_FILES": "17",
            "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES": "4096",
            "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES": "16384",
        }
        with patch.dict(os.environ, environment, clear=True):
            settings = AnalyzerSettings.from_env()

        self.assertFalse(settings.auto_cmake)
        self.assertEqual((("cmake", "--build", "build"),), settings.build_steps)
        self.assertEqual((("ctest", "--test-dir", "build"),), settings.test_steps)
        self.assertEqual(1024, settings.max_memory_mb)
        self.assertEqual(32, settings.max_processes)
        self.assertEqual(8192, settings.max_output_bytes)
        self.assertEqual(30, settings.step_timeout_seconds)
        self.assertEqual(90, settings.total_timeout_seconds)
        self.assertEqual(17, settings.repository_scan_max_files)
        self.assertEqual(4096, settings.repository_scan_max_file_bytes)
        self.assertEqual(16384, settings.repository_scan_max_total_bytes)

    def test_settings_reject_invalid_boolean_and_nonpositive_limits(self):
        for name, value in (
            ("LIMA_CXX_AUTO_CMAKE", "sometimes"),
            ("LIMA_CXX_MAX_MEMORY_MB", "0"),
            ("LIMA_CXX_MAX_PROCESSES", "-1"),
            ("LIMA_CXX_MAX_OUTPUT_BYTES", "not-an-int"),
            ("LIMA_CXX_STEP_TIMEOUT_SECONDS", "0"),
            ("LIMA_CXX_TOTAL_TIMEOUT_SECONDS", "-5"),
            ("LIMA_REPOSITORY_SCAN_MAX_FILES", "0"),
        ):
            with self.subTest(name=name):
                with patch.dict(os.environ, {name: value}, clear=True):
                    with self.assertRaises(ValueError):
                        AnalyzerSettings.from_env()

    def test_prepare_snapshot_copies_only_the_matching_bounded_inventory(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            files = {
                "src/main.cpp": "int main() { return 0; }\n",
                "CMakeLists.txt": "add_executable(app src/main.cpp)\n",
                "cmake/toolchain.cmake": "set(CMAKE_CXX_STANDARD 17)\n",
                "configure.ac": "AC_INIT([app], [1])\n",
                "Makefile.am": "bin_PROGRAMS = app\n",
                "config.h.in": "#undef APP_FEATURE\n",
                "m4/app.m4": "AC_DEFUN([APP_CHECK], [])\n",
                "po/messages.po": "msgid \"\"\nmsgstr \"\"\n",
                "po/messages.pot": "msgid \"\"\nmsgstr \"\"\n",
                "resources/app.css": "body { color: black; }\n",
                "resources/tpls.html": "<main></main>\n",
                "config/browsers.list": "Browser\n",
                "config/app.conf": "enabled=true\n",
                "lib/Makefile.inc": "CSOURCES = main.c\n",
                "po/LINGUAS": "en\n",
                "po/Makevars": "DOMAIN = app\n",
                "Makefile": "all:\n\t@true\n",
                "config.mk": "FEATURE = yes\n",
                "notes.txt": "not inventoried\n",
                "run-tool": "not inventoried\n",
                "configure": "not inventoried\n",
                ".env": "TOKEN=secret\n",
                "build/generated.cpp": "int generated;\n",
            }
            for relative, content in files.items():
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            source_before = {
                path.relative_to(repository).as_posix(): (
                    path.read_bytes(),
                    path.stat().st_mtime_ns,
                )
                for path in repository.rglob("*")
                if path.is_file()
            }
            expected = RepositoryWorkspace(repository).inventory().fingerprint()

            snapshot = prepare_snapshot(import_root, "team/project", expected, work_root)
            self.addCleanup(snapshot.cleanup)

            self.assertEqual(expected, snapshot.sha256)
            self.assertEqual(work_root.resolve(), snapshot.root.parent.parent)
            self.assertEqual("source", snapshot.root.name)
            self.assertEqual(
                [
                    "CMakeLists.txt",
                    "Makefile",
                    "Makefile.am",
                    "cmake/toolchain.cmake",
                    "config.h.in",
                    "config.mk",
                    "config/app.conf",
                    "config/browsers.list",
                    "configure.ac",
                    "lib/Makefile.inc",
                    "m4/app.m4",
                    "po/LINGUAS",
                    "po/Makevars",
                    "po/messages.po",
                    "po/messages.pot",
                    "resources/app.css",
                    "resources/tpls.html",
                    "src/main.cpp",
                ],
                sorted(snapshot.files),
            )
            self.assertEqual(
                sorted(snapshot.files),
                sorted(
                    path.relative_to(snapshot.root).as_posix()
                    for path in snapshot.root.rglob("*")
                    if path.is_file()
                ),
            )
            self.assertEqual(
                source_before,
                {
                    path.relative_to(repository).as_posix(): (
                        path.read_bytes(),
                        path.stat().st_mtime_ns,
                    )
                    for path in repository.rglob("*")
                    if path.is_file()
                },
            )

    def test_prepare_snapshot_rejects_unsafe_repository_keys(self):
        invalid_keys = (
            "",
            "/absolute/project",
            "team\\project",
            ".",
            "..",
            "team/./project",
            "team/../project",
            ".hidden/project",
            "team/.hidden",
            "team/proj\0ect",
        )
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            for key in invalid_keys:
                with self.subTest(key=repr(key)):
                    with self.assertRaises(ValueError):
                        prepare_snapshot(import_root, key, "0" * 64, work_root)

    def test_prepare_snapshot_rejects_fingerprint_and_budget_drift(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "a.cpp").write_text("int a;\n", encoding="utf-8")
            (repository / "b.cpp").write_text("int bbbbbbbbb;\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()

            with self.assertRaisesRegex(ValueError, "fingerprint"):
                prepare_snapshot(import_root, "team/project", "0" * 64, work_root)
            with patch.dict(os.environ, {"LIMA_REPOSITORY_SCAN_MAX_FILES": "1"}, clear=False):
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    prepare_snapshot(import_root, "team/project", expected, work_root)
            with patch.dict(
                os.environ,
                {"LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES": "8"},
                clear=False,
            ):
                with self.assertRaisesRegex(ValueError, "fingerprint"):
                    prepare_snapshot(import_root, "team/project", expected, work_root)

    def test_prepare_snapshot_rejects_symlink_files(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (outside / "outside.cpp").write_text("int outside;\n", encoding="utf-8")
            try:
                (repository / "linked.cpp").symlink_to(outside / "outside.cpp")
            except OSError as exc:
                self.skipTest(f"platform denied symlink creation: {exc}")

            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                prepare_snapshot(import_root, "team/project", expected, work_root)

    def test_prepare_snapshot_rejects_symlink_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            outside = Path(temporary) / "outside"
            outside.mkdir()
            (outside / "outside.cpp").write_text("int outside;\n", encoding="utf-8")
            try:
                (repository / "linked-dir").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"platform denied symlink creation: {exc}")

            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                prepare_snapshot(import_root, "team/project", expected, work_root)

    def test_prepare_snapshot_rejects_repository_key_through_symlink(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            import_root.mkdir()
            real_team = base / "real-team"
            repository = real_team / "project"
            repository.mkdir(parents=True)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            work_root = base / "work"
            work_root.mkdir()
            try:
                (import_root / "team").symlink_to(real_team, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"platform denied symlink creation: {exc}")

            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                prepare_snapshot(import_root, "team/project", expected, work_root)

    @patch("cxx_analyzer.execution._stream_process")
    @patch("cxx_analyzer.execution.subprocess.Popen")
    @patch("cxx_analyzer.execution.sandbox.process_isolation_available", return_value=True)
    @patch("cxx_analyzer.execution.sandbox.landlock_abi", return_value=3)
    def test_run_step_uses_launcher_snapshot_cwd_and_clean_env(
        self, _abi, _process_isolation, popen, stream
    ):
        process = Mock()
        process.pid = 1234
        popen.return_value = process
        stdout = b"cmake ok\n"
        stream.return_value = StreamCapture(
            returncode=0,
            timed_out=False,
            stdout=stdout,
            stderr=b"",
            stdout_sha256=hashlib.sha256(stdout).hexdigest(),
            stderr_sha256=hashlib.sha256(b"").hexdigest(),
            output_truncated=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            source = repository / "src" / "main.cpp"
            source.parent.mkdir()
            source.write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                status_read, status_write = os.pipe()
                os.write(status_write, b"R")
                with patch(
                    "cxx_analyzer.execution.os.pipe",
                    return_value=(status_read, status_write),
                ):
                    result = run_step(
                        ("cmake", "--version"),
                        snapshot,
                        "src",
                        timeout_seconds=17,
                        max_output_bytes=1024,
                        env={},
                    )

        self.assertEqual("completed", result.status)
        self.assertEqual(0, result.returncode)
        self.assertEqual("cmake ok\n", result.stdout)
        called_argv = popen.call_args.args[0]
        called_options = popen.call_args.kwargs
        self.assertIsInstance(called_argv, list)
        self.assertEqual(["cmake", "--version"], called_argv[-2:])
        self.assertTrue(Path(called_argv[1]).is_absolute())
        self.assertEqual("sandbox.py", Path(called_argv[1]).name)
        self.assertFalse(called_options["shell"])
        self.assertEqual(snapshot.root / "src", Path(called_options["cwd"]))
        self.assertEqual(
            {
                **CLEAN_ENVIRONMENT,
                "HOME": str(snapshot.scratch_root / "home"),
                "TMPDIR": str(snapshot.scratch_root / "tmp"),
            },
            called_options["env"],
        )
        self.assertEqual(subprocess.DEVNULL, called_options["stdin"])
        self.assertEqual(subprocess.PIPE, called_options["stdout"])
        self.assertEqual(subprocess.PIPE, called_options["stderr"])
        self.assertTrue(called_options["close_fds"])
        self.assertTrue(called_options["start_new_session"])
        self.assertEqual(1, len(called_options["pass_fds"]))
        stream.assert_called_once_with(process, 17, 1024)

    def test_stream_process_bounds_high_throughput_output_and_hashes_all_bytes(self):
        stdout = b"A" * (2 * 1024 * 1024 + 17)
        stderr = b"B" * (2 * 1024 * 1024 + 31)
        script = (
            f"import os\nos.write(1, b'A' * {len(stdout)})\nos.write(2, b'B' * {len(stderr)})\n"
        )
        process = subprocess.Popen(  # noqa: S603 - fixed local test child
            [sys.executable, "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )

        captured = _stream_process(process, timeout_seconds=10, max_output_bytes=4096)

        self.assertEqual(0, captured.returncode)
        self.assertFalse(captured.timed_out)
        self.assertLessEqual(len(captured.stdout) + len(captured.stderr), 4096)
        self.assertTrue(captured.output_truncated)
        self.assertEqual(hashlib.sha256(stdout).hexdigest(), captured.stdout_sha256)
        self.assertEqual(hashlib.sha256(stderr).hexdigest(), captured.stderr_sha256)
        self.assertLess(len(captured.stdout), len(stdout))
        self.assertLess(len(captured.stderr), len(stderr))
        self.assertTrue(process.stdout.closed)
        self.assertTrue(process.stderr.closed)

    def test_stream_process_timeout_terminates_and_returns_bounded_prefix(self):
        script = (
            "import os, time\n"
            "os.write(1, b'prefix-sensitive-tail')\n"
            "os.write(2, b'diagnostic-secret')\n"
            "time.sleep(30)\n"
        )
        process = subprocess.Popen(  # noqa: S603 - fixed local test child
            [sys.executable, "-c", script],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            close_fds=True,
            start_new_session=True,
        )

        captured = _stream_process(process, timeout_seconds=1, max_output_bytes=8)

        self.assertTrue(captured.timed_out)
        self.assertIsNotNone(captured.returncode)
        self.assertLessEqual(len(captured.stdout) + len(captured.stderr), 8)
        self.assertNotIn(b"sensitive-tail", captured.stdout)
        self.assertNotIn(b"diagnostic-secret", captured.stderr)

    def test_stream_timeout_kills_group_after_leader_exits_and_hashes_to_eof(self):
        if sys.platform != "linux":
            self.skipTest("process-group descendant regression requires Linux")
        stdout = b"descendant-stdout"
        stderr = b"descendant-stderr"
        child_code = (
            f"import os,time; os.write(1, {stdout!r}); os.write(2, {stderr!r}); time.sleep(30)"
        )
        with tempfile.TemporaryDirectory() as temporary:
            pid_file = Path(temporary) / "descendant.pid"
            script = (
                "import pathlib,subprocess,sys,time; "
                f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid)); "
                "time.sleep(30)"
            )
            process = subprocess.Popen(  # noqa: S603 - fixed local test child
                [sys.executable, "-c", script],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False,
                close_fds=True,
                start_new_session=True,
            )

            def kill_descendant() -> None:
                try:
                    os.kill(int(pid_file.read_text()), 9)
                except (OSError, ValueError):
                    pass

            self.addCleanup(kill_descendant)
            started = time.monotonic()
            captured = _stream_process(process, timeout_seconds=1, max_output_bytes=1024)
            elapsed = time.monotonic() - started

        self.assertTrue(captured.timed_out)
        self.assertTrue(captured.digests_complete)
        self.assertLess(elapsed, 5)
        self.assertEqual(stdout, captured.stdout)
        self.assertEqual(stderr, captured.stderr)
        self.assertEqual(hashlib.sha256(stdout).hexdigest(), captured.stdout_sha256)
        self.assertEqual(hashlib.sha256(stderr).hexdigest(), captured.stderr_sha256)

    def test_output_digest_uses_tagged_complete_stream_digests(self):
        stdout = b"stdout beyond retained prefix"
        stderr = b"stderr beyond retained prefix"
        stdout_sha256 = hashlib.sha256(stdout).hexdigest()
        stderr_sha256 = hashlib.sha256(stderr).hexdigest()
        expected = hashlib.sha256(
            b"LIMA-TOOL-OUTPUT-SHA256-v1\0stdout\0"
            + bytes.fromhex(stdout_sha256)
            + b"\0stderr\0"
            + bytes.fromhex(stderr_sha256)
        ).hexdigest()
        capture = StreamCapture(
            returncode=0,
            timed_out=False,
            stdout=stdout[:3],
            stderr=b"",
            stdout_sha256=stdout_sha256,
            stderr_sha256=stderr_sha256,
            output_truncated=True,
        )
        self.assertEqual(expected, capture.output_sha256)

    def test_incomplete_stream_capture_rejects_partial_digest_claims(self):
        partial_sha256 = hashlib.sha256(b"partial").hexdigest()
        with self.assertRaisesRegex(ValueError, "incomplete stream"):
            StreamCapture(
                returncode=-1,
                timed_out=True,
                stdout=b"partial",
                stderr=b"",
                stdout_sha256=partial_sha256,
                stderr_sha256=hashlib.sha256(b"").hexdigest(),
                output_truncated=True,
                digests_complete=False,
            )

    @patch("cxx_analyzer.execution.subprocess.Popen")
    @patch("cxx_analyzer.execution.sandbox.process_isolation_available", return_value=True)
    @patch("cxx_analyzer.execution.sandbox.landlock_abi", return_value=0)
    def test_run_step_fails_closed_without_landlock(
        self, _abi, _process_isolation, popen
    ):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                result = run_step(["tool"], snapshot, ".", 3, 8, {})

        self.assertEqual("sandbox-unavailable", result.status)
        self.assertIsNone(result.returncode)
        self.assertEqual("filesystem sandbox unavailable", result.diagnostic)
        self.assertEqual("", result.stderr)
        popen.assert_not_called()

    @patch("cxx_analyzer.execution.subprocess.Popen")
    @patch("cxx_analyzer.execution.sandbox.process_isolation_available", return_value=True)
    @patch(
        "cxx_analyzer.execution.sandbox.landlock_abi",
        side_effect=PermissionError("seccomp denied Landlock query"),
    )
    def test_run_step_fails_closed_when_landlock_query_is_denied(
        self, _abi, _process_isolation, popen
    ):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                result = run_step(["tool"], snapshot, ".", 3, 8, {})

        self.assertEqual("sandbox-unavailable", result.status)
        self.assertEqual("filesystem sandbox unavailable", result.diagnostic)
        popen.assert_not_called()

    def test_sandbox_policy_and_launcher_exclude_import_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                policy = build_policy(snapshot.root)
                launcher = build_launcher_argv(["cmake", "--version"], snapshot.root, status_fd=9)

        allowed = {str(rule.path) for rule in policy.rules}
        self.assertIn(str(snapshot.root), allowed)
        self.assertNotIn(str(import_root), allowed)
        self.assertNotIn(str(repository), allowed)
        self.assertEqual(["cmake", "--version"], launcher[-2:])
        self.assertTrue(Path(launcher[1]).is_absolute())
        self.assertEqual("sandbox.py", Path(launcher[1]).name)
        self.assertNotIn("-m", launcher[:3])
        self.assertIn("--status-fd", launcher)
        self.assertIn("--snapshot-root", launcher)

    @patch("cxx_analyzer.execution._stream_process")
    @patch("cxx_analyzer.execution.subprocess.Popen")
    @patch("cxx_analyzer.execution.sandbox.process_isolation_available", return_value=True)
    @patch("cxx_analyzer.execution.sandbox.landlock_abi", return_value=3)
    def test_run_step_fails_closed_when_launcher_never_reports_ready(
        self, _abi, _process_isolation, popen, stream
    ):
        popen.return_value = Mock(pid=1234)
        empty_sha256 = hashlib.sha256(b"").hexdigest()
        stream.return_value = StreamCapture(
            returncode=1,
            timed_out=False,
            stdout=b"",
            stderr=b"launcher failed",
            stdout_sha256=empty_sha256,
            stderr_sha256=hashlib.sha256(b"launcher failed").hexdigest(),
            output_truncated=False,
        )
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                result = run_step(["tool"], snapshot, ".", 3, 64, {})

        self.assertEqual("sandbox-failed", result.status)
        self.assertEqual("filesystem sandbox setup failed", result.diagnostic)
        self.assertEqual("", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertNotIn("launcher failed", repr(result))

    def test_run_step_rejects_non_snapshot_absolute_dotdot_and_cleaned_cwd(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            source = repository / "src" / "main.cpp"
            source.parent.mkdir()
            source.write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            snapshot = prepare_snapshot(import_root, "team/project", expected, work_root)

            invalid_calls = (
                (["tool"], work_root, ".", 1, 1, {}),
                (["tool"], snapshot, str(snapshot.root), 1, 1, {}),
                (["tool"], snapshot, "../", 1, 1, {}),
                (["tool"], snapshot, "src/../../", 1, 1, {}),
                (["tool"], snapshot, "missing", 1, 1, {}),
            )
            for arguments in invalid_calls:
                with self.subTest(arguments=arguments[1:3]):
                    with self.assertRaises(ValueError):
                        run_step(*arguments)

            snapshot.cleanup()
            with self.assertRaisesRegex(ValueError, "no longer live"):
                run_step(["tool"], snapshot, ".", 1, 1, {})

    def test_run_step_rejects_symlink_cwd_inside_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            source = repository / "src" / "main.cpp"
            source.parent.mkdir()
            source.write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                try:
                    (snapshot.root / "linked-cwd").symlink_to(
                        snapshot.root / "src", target_is_directory=True
                    )
                except OSError as exc:
                    self.skipTest(f"platform denied symlink creation: {exc}")
                with self.assertRaisesRegex(ValueError, "symbolic link"):
                    run_step(["tool"], snapshot, "linked-cwd", 1, 1, {})

    def test_landlock_child_reads_snapshot_but_denies_outside_sentinel(self):
        if sys.platform != "linux":
            self.skipTest("real Landlock test requires Linux")
        abi = landlock_abi()
        if abi < MIN_LANDLOCK_ABI:
            self.skipTest(f"Landlock ABI {abi} is below required {MIN_LANDLOCK_ABI}")
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("snapshot-ok\n", encoding="utf-8")
            outside = Path(temporary) / "outside-sentinel.txt"
            outside.write_text("outside-secret\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            code = (
                "from pathlib import Path; import sys; "
                "print(Path('main.cpp').read_text().strip(), end='|'); "
                "\ntry: Path(sys.argv[1]).read_text()"
                "\nexcept PermissionError: print('outside-denied')"
                "\nelse: print('outside-readable'); raise SystemExit(9)"
            )
            with prepare_snapshot(import_root, "team/project", expected, work_root) as snapshot:
                # Environments such as GitHub-hosted runners may report a Landlock
                # ABI yet reject ruleset creation; the analyzer fails closed there
                # (covered by test_run_step_fails_closed_without_landlock), so this
                # positive test only runs where enforcement actually works.
                probe = run_step(
                    [sys.executable, "-c", "print('probe-ok', end='')"],
                    snapshot,
                    ".",
                    timeout_seconds=10,
                    max_output_bytes=1024,
                    env={},
                )
                if probe.status != "completed":
                    self.skipTest(
                        "Landlock enforcement unavailable in this environment: "
                        f"{probe.diagnostic}"
                    )
                result = run_step(
                    [sys.executable, "-c", code, str(outside)],
                    snapshot,
                    ".",
                    timeout_seconds=10,
                    max_output_bytes=1024,
                    env={},
                )

        self.assertEqual("completed", result.status, result.diagnostic)
        self.assertEqual("snapshot-ok|outside-denied\n", result.stdout)

    def test_run_step_rejects_non_argv_and_nonpositive_bounds(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            snapshot = prepare_snapshot(import_root, "team/project", expected, work_root)
            self.addCleanup(snapshot.cleanup)
            for argv, timeout, output_limit in (
                ("tool --flag", 1, 1),
                ([], 1, 1),
                (["tool", "bad\0arg"], 1, 1),
                (["tool"], 0, 1),
                (["tool"], 1, 0),
            ):
                with self.subTest(argv=argv, timeout=timeout, output=output_limit):
                    with self.assertRaises(ValueError):
                        run_step(argv, snapshot, ".", timeout, output_limit, {})


class AnalyzerServiceTests(unittest.TestCase):
    REQUEST_ID = "123e4567-e89b-42d3-a456-426614174000"
    SNAPSHOT_SHA256 = "a" * 64

    @staticmethod
    def _settings() -> AnalyzerSettings:
        return AnalyzerSettings(
            auto_cmake=True,
            build_steps=(),
            test_steps=(),
            max_memory_mb=1024,
            max_processes=32,
            max_output_bytes=8192,
            step_timeout_seconds=17,
            total_timeout_seconds=90,
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )

    def _payload(self, **changes):
        payload = {
            "request_id": self.REQUEST_ID,
            "repository_key": "team/project",
            "snapshot_sha256": self.SNAPSHOT_SHA256,
            "requested_layers": ["source-only"],
        }
        payload.update(changes)
        return payload

    @patch("cxx_analyzer.server.prepare_snapshot")
    def test_request_schema_rejects_every_invalid_payload_before_snapshot(self, prepare):
        missing = self._payload()
        missing.pop("snapshot_sha256")
        invalid_payloads = (
            ("non-object", []),
            ("missing field", missing),
            ("unknown field", self._payload(extra=True)),
            ("client path", self._payload(path="/repo")),
            ("client command", self._payload(command=["cmake"])),
            ("client environment", self._payload(environment={"TOKEN": "secret"})),
            ("invalid UUID", self._payload(request_id="not-a-uuid")),
            ("duplicate layer", self._payload(requested_layers=["source-only", "source-only"])),
            ("unknown layer", self._payload(requested_layers=["run-command"])),
            ("empty layers", self._payload(requested_layers=[])),
            ("non-list layers", self._payload(requested_layers="source-only")),
            ("unsafe repository key", self._payload(repository_key="../project")),
            ("absolute repository key", self._payload(repository_key="/team/project")),
            ("uppercase digest", self._payload(snapshot_sha256="A" * 64)),
            ("short digest", self._payload(snapshot_sha256="a" * 63)),
        )

        for description, payload in invalid_payloads:
            with self.subTest(description=description):
                prepare.reset_mock()
                with self.assertRaises(analyzer_server.RequestError) as caught:
                    analyzer_server.analyze_request(payload, self._settings())
                self.assertEqual("invalid_request", caught.exception.code)
                prepare.assert_not_called()

    @patch("cxx_analyzer.server.run_source_scan")
    @patch("cxx_analyzer.server.prepare_snapshot")
    def test_analyze_request_returns_fixed_schema_and_completed_layer_diagnostics(
        self, prepare, source_scan_runner
    ):
        snapshot = prepare.return_value.__enter__.return_value
        snapshot.files = ("src/main.cpp", "include/main.hpp")
        source_scan_runner.return_value = LayerResult(
            (),
            ("Semgrep source scan did not complete",),
            ({"tool": "semgrep", "status": "failed"},),
        )

        result = analyzer_server.analyze_request(self._payload(), self._settings())

        self.assertEqual(
            {
                "schema_version",
                "request_id",
                "status",
                "snapshot_sha256",
                "tool_runs",
                "findings",
                "coverage",
                "diagnostics",
            },
            set(result),
        )
        self.assertEqual("completed", result["status"])
        self.assertEqual(self.REQUEST_ID, result["request_id"])
        self.assertEqual(self.SNAPSHOT_SHA256, result["snapshot_sha256"])
        self.assertEqual([{"tool": "semgrep", "status": "failed"}], result["tool_runs"])
        self.assertEqual([], result["findings"])
        self.assertEqual(["Semgrep source scan did not complete"], result["diagnostics"])
        self.assertEqual({"source_files": 2, "snapshot_files": 2}, result["coverage"])
        prepare.assert_called_once_with(
            analyzer_server.IMPORT_ROOT,
            "team/project",
            self.SNAPSHOT_SHA256,
            analyzer_server.WORK_ROOT,
            deadline=ANY,
        )
        source_scan_runner.assert_called_once_with(
            snapshot, self._settings(), deadline=ANY
        )

    def test_dispatch_rejects_http_boundary_errors_with_sanitized_payloads(self):
        valid_body = json.dumps(self._payload()).encode("utf-8")
        cases = (
            ("GET", "/v1/analyze", "application/json", valid_body, 405, "method_not_allowed"),
            ("POST", "/wrong", "application/json", valid_body, 404, "not_found"),
            ("POST", "/v1/analyze", "text/plain", valid_body, 415, "unsupported_media_type"),
            (
                "POST",
                "/v1/analyze",
                "application/json",
                b"x" * (analyzer_server.MAX_REQUEST_BYTES + 1),
                413,
                "request_too_large",
            ),
            ("POST", "/v1/analyze", "application/json", b"{", 400, "invalid_json"),
            (
                "POST",
                "/v1/analyze",
                "application/json",
                json.dumps(self._payload(command=["echo", "secret"])).encode("utf-8"),
                400,
                "invalid_request",
            ),
        )

        for method, path, content_type, body, expected_status, expected_code in cases:
            with self.subTest(code=expected_code):
                status, response = analyzer_server.dispatch_request(
                    method, path, content_type, body, self._settings()
                )
                self.assertEqual(expected_status, status)
                self.assertEqual({"error", "request_id"}, set(response))
                self.assertEqual(expected_code, response["error"])
                rendered = json.dumps(response)
                self.assertNotIn("echo", rendered)
                self.assertNotIn("secret", rendered)
                self.assertNotIn("Traceback", rendered)

    @patch("cxx_analyzer.server.analyze_request")
    def test_dispatch_rejects_whole_oversized_response_with_minimal_error(self, analyze):
        analyze.return_value = {"findings": ["x" * (2 * 1024 * 1024 + 1)]}
        body = json.dumps(self._payload()).encode("utf-8")

        status, response = analyzer_server.dispatch_request(
            "POST", "/v1/analyze", "application/json", body, self._settings()
        )

        self.assertEqual(500, status)
        self.assertEqual(
            {"error": "response_too_large", "request_id": self.REQUEST_ID},
            response,
        )
        self.assertLess(len(json.dumps(response).encode("utf-8")), 1024)

    @patch("cxx_analyzer.server.shutil.which")
    def test_health_discloses_only_schema_and_tool_availability(self, which):
        which.side_effect = lambda tool: ("/usr/bin/" + tool if tool != "clang" else None)

        status, payload = analyzer_server.dispatch_request(
            "GET", "/health", "", b"", self._settings()
        )

        self.assertEqual(200, status)
        self.assertEqual(
            {
                "schema_version": 1,
                "tools": {"semgrep": True, "cmake": True, "clang": True},
                "configuration": {"source": True, "build": True, "test": False},
            },
            payload,
        )

    @patch("cxx_analyzer.server.run_build_scan")
    @patch("cxx_analyzer.server.run_source_scan")
    @patch("cxx_analyzer.server.prepare_snapshot")
    def test_requested_build_or_clang_failure_is_completed_and_preserves_source(
        self, prepare, source_scan_runner, build_scan_runner
    ):
        snapshot = prepare.return_value.__enter__.return_value
        snapshot.files = ("src/main.cpp",)
        candidate = NormalizedFinding.create(
            rule_id="cxx.source.oob-write.constant-index",
            severity="high",
            title="Potential out-of-bounds write",
            explanation="A source candidate.",
            path="src/main.cpp",
            line=7,
            evidence="values[2] = 1",
            fix="",
            test="Exercise the boundary.",
            confidence=0.5,
            cwe="CWE-787",
            tool="semgrep",
            evidence_kind="line",
            verification_state="candidate",
            language="c++",
            symbol="write_value",
            analysis_mode="source-only",
            diagnostics=[],
        )
        source_scan_runner.return_value = LayerResult(
            (candidate,), (), ({"tool": "semgrep", "status": "completed"},)
        )
        for tool, tool_status, diagnostic in (
            ("cmake", "build_failed", "build_failed"),
            ("clang", "failed", "clang_failed"),
        ):
            with self.subTest(tool=tool):
                build_scan_runner.reset_mock()
                build_scan_runner.return_value = LayerResult(
                    (),
                    (diagnostic,),
                    ({"tool": tool, "status": tool_status},),
                )

                result = analyzer_server.analyze_request(
                    self._payload(requested_layers=["source-only", "build-backed"]),
                    self._settings(),
                )

                self.assertEqual("completed", result["status"])
                self.assertEqual([candidate.to_dict()], result["findings"])
                self.assertEqual([diagnostic], result["diagnostics"])
                self.assertEqual(
                    [
                        {"tool": "semgrep", "status": "completed"},
                        {"tool": tool, "status": tool_status},
                    ],
                    result["tool_runs"],
                )
                build_scan_runner.assert_called_once_with(
                    snapshot, self._settings(), deadline=ANY
                )

    def test_http_handler_reads_exactly_the_declared_content_length(self):
        class ExactBody:
            def read(self, size):
                if size != 2:
                    raise AssertionError(f"read requested {size} bytes instead of 2")
                return b"{}"

        received = []
        handler = object.__new__(analyzer_server.AnalyzerRequestHandler)
        handler.headers = {"Content-Length": "2"}
        handler.rfile = ExactBody()
        handler._handle = received.append

        handler.do_POST()

        self.assertEqual([b"{}"], received)

    def test_real_http_handler_routes_every_method_through_stable_json_boundary(self):
        handler_type = type(
            "ConfiguredAnalyzerHandler",
            (analyzer_server.AnalyzerRequestHandler,),
            {"analyzer_settings": self._settings()},
        )
        server = analyzer_server.ThreadingHTTPServer(("127.0.0.1", 0), handler_type)
        server.daemon_threads = True
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        host, port = server.server_address
        try:
            for method in (
                "GET",
                "HEAD",
                "PUT",
                "PATCH",
                "DELETE",
                "OPTIONS",
                "TRACE",
                "CONNECT",
                "BREW",
            ):
                with self.subTest(method=method):
                    connection = http.client.HTTPConnection(host, port, timeout=2)
                    try:
                        connection.request(method, "/v1/analyze")
                        response = connection.getresponse()
                        body = response.read()
                    finally:
                        connection.close()
                    self.assertEqual(405, response.status)
                    self.assertEqual("application/json", response.getheader("Content-Type"))
                    if method == "HEAD":
                        self.assertEqual(b"", body)
                        self.assertGreater(int(response.getheader("Content-Length")), 0)
                    else:
                        self.assertEqual(
                            {"error": "method_not_allowed", "request_id": None},
                            json.loads(body),
                        )

            connection = http.client.HTTPConnection(host, port, timeout=2)
            try:
                connection.request("GET", "/health")
                response = connection.getresponse()
                health = json.loads(response.read())
            finally:
                connection.close()
            self.assertEqual(200, response.status)
            self.assertEqual(1, health["schema_version"])
            self.assertEqual({"semgrep", "cmake", "clang"}, set(health["tools"]))
            self.assertTrue(all(type(value) is bool for value in health["tools"].values()))
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


class AnalyzerComposeSecurityTests(unittest.TestCase):
    @staticmethod
    def _compose():
        import yaml

        compose_path = Path(__file__).parents[1] / "docker-compose.yml"
        return yaml.safe_load(compose_path.read_text(encoding="utf-8"))

    def test_cxx_analyzer_is_an_internal_non_root_read_only_sidecar(self):
        compose = self._compose()
        service = compose["services"]["cxx-analyzer"]

        self.assertNotIn("ports", service)
        self.assertTrue(service["read_only"])
        self.assertEqual(["ALL"], service["cap_drop"])
        self.assertIn("no-new-privileges:true", service["security_opt"])
        self.assertEqual("10002:10002", service["user"])
        self.assertEqual("${LIMA_CXX_MAX_PROCESSES:-128}", service["pids_limit"])
        self.assertEqual("${LIMA_CXX_MAX_MEMORY_MB:-2048}m", service["mem_limit"])
        self.assertEqual("2.0", service["cpus"])
        self.assertEqual({"cxx_analysis"}, set(service["networks"]))
        self.assertTrue(compose["networks"]["cxx_analysis"]["internal"])

        volumes = service.get("volumes", [])
        self.assertTrue(any(str(item).endswith(":/repositories:ro") for item in volumes))
        self.assertFalse(any("/var/run/docker.sock" in str(item) for item in volumes))
        self.assertFalse(
            any(
                "/var/run/docker.sock" in str(item)
                for item in compose["services"]["lima"].get("volumes", [])
            )
        )
        tmpfs = service["tmpfs"]
        self.assertEqual(
            {
                "/tmp": {  # noqa: S108 - Bounded container tmpfs contract.
                    "size": "64m",
                    "mode": "0700",
                    "uid": "10002",
                    "gid": "10002",
                },
                "/work": {
                    "size": "512m",
                    "mode": "0700",
                    "uid": "10002",
                    "gid": "10002",
                },
            },
            {
                str(item).split(":", 1)[0]: dict(
                    option.split("=", 1) for option in str(item).split(":", 1)[1].split(",")
                )
                for item in tmpfs
            },
        )

    def test_compose_passes_only_admin_configuration_and_shared_snapshot_limits(self):
        compose = self._compose()
        lima = compose["services"]["lima"]
        analyzer = compose["services"]["cxx-analyzer"]
        self.assertEqual({"default", "cxx_analysis"}, set(lima["networks"]))
        self.assertEqual({"cxx_analysis"}, set(analyzer["networks"]))

        main_configuration = {
            "LIMA_CXX_MEMORY_MODE",
            "LIMA_CXX_ANALYZER_URL",
            "LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS",
            "LIMA_CXX_MAX_RESPONSE_BYTES",
        }
        sidecar_configuration = {
            "LIMA_CXX_AUTO_CMAKE",
            "LIMA_CXX_BUILD_STEPS_JSON",
            "LIMA_CXX_TEST_STEPS_JSON",
            "LIMA_CXX_MAX_MEMORY_MB",
            "LIMA_CXX_MAX_PROCESSES",
            "LIMA_CXX_MAX_OUTPUT_BYTES",
        }
        self.assertTrue(main_configuration <= set(lima["environment"]))
        snapshot_limits = {
            "LIMA_REPOSITORY_SCAN_MAX_FILES",
            "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES",
            "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES",
        }
        self.assertEqual(
            sidecar_configuration | snapshot_limits,
            set(analyzer["environment"]),
        )
        self.assertFalse(
            any(
                marker in name
                for name in analyzer["environment"]
                for marker in ("DATABASE", "POSTGRES", "REDIS", "GITHUB", "TOKEN", "SECRET", "KEY")
            )
        )
        self.assertEqual(
            "${LIMA_CXX_ANALYZER_URL:-http://cxx-analyzer:8090}",
            lima["environment"]["LIMA_CXX_ANALYZER_URL"],
        )
        self.assertEqual(
            "${LIMA_CXX_BUILD_STEPS_JSON:-[]}",
            analyzer["environment"]["LIMA_CXX_BUILD_STEPS_JSON"],
        )
        self.assertEqual(
            "${LIMA_CXX_TEST_STEPS_JSON:-[]}",
            analyzer["environment"]["LIMA_CXX_TEST_STEPS_JSON"],
        )
        for name in (
            "LIMA_REPOSITORY_SCAN_MAX_FILES",
            "LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES",
            "LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES",
        ):
            self.assertEqual(lima["environment"][name], analyzer["environment"][name])

    def test_sidecar_dockerfile_pins_runtime_identity_tools_and_copy_boundary(self):
        dockerfile = (Path(__file__).parents[1] / "cxx_analyzer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        _validate_sidecar_dockerfile_contract(dockerfile)

    def test_sidecar_dockerfile_installs_pinned_public_case_build_dependencies(self):
        dockerfile = (Path(__file__).parents[1] / "cxx_analyzer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        for package in ("libfreetype6-dev", "libxml2-dev", "zlib1g-dev"):
            with self.subTest(package=package):
                self.assertRegex(dockerfile, rf"(?m)^\s+{package}\s*\\?$")

    def test_sidecar_dockerfile_contract_rejects_late_root_and_add_mutations(self):
        dockerfile = (Path(__file__).parents[1] / "cxx_analyzer" / "Dockerfile").read_text(
            encoding="utf-8"
        )
        mutations = {
            "late runtime root": dockerfile.replace(
                "USER analyzer:analyzer\nCMD",
                "USER analyzer:analyzer\nUSER root\nCMD",
                1,
            ),
            "runtime ADD escape": dockerfile.replace(
                "FROM base AS runtime\nUSER analyzer:analyzer",
                "FROM base AS runtime\nADD . /app\nUSER analyzer:analyzer",
                1,
            ),
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name):
                self.assertNotEqual(dockerfile, mutated)
                with self.assertRaises(ValueError):
                    _validate_sidecar_dockerfile_contract(mutated)


class SourceScanTests(unittest.TestCase):
    @staticmethod
    def _settings() -> AnalyzerSettings:
        return AnalyzerSettings(
            auto_cmake=True,
            build_steps=(),
            test_steps=(),
            max_memory_mb=1024,
            max_processes=32,
            max_output_bytes=8192,
            step_timeout_seconds=17,
            total_timeout_seconds=90,
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )

    @staticmethod
    def _execution(status="completed", stdout="", truncated=False, complete=True):
        return ToolExecution(
            status=status,
            returncode=0 if status == "completed" else None,
            stdout=stdout,
            stderr="",
            stdout_sha256="a" * 64 if complete else "",
            stderr_sha256="b" * 64 if complete else "",
            output_sha256="c" * 64 if complete else "",
            output_truncated=truncated,
            digests_complete=complete,
            diagnostic="",
        )

    @patch("cxx_analyzer.source_scan.run_step")
    def test_source_scan_stages_rules_outside_snapshot_and_preserves_colliding_file(self, run_tool):
        sample = (
            Path(__file__).parent / "fixtures" / "cxx_memory" / "semgrep-sample.json"
        ).read_text(encoding="utf-8")
        run_tool.return_value = self._execution(stdout=sample)
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "imports" / "team" / "project"
            repository.mkdir(parents=True)
            (repository / "src").mkdir()
            (repository / "src" / "buffer.c").write_text(
                "void write_value(int *values) { values[8] = 1; }\n",
                encoding="utf-8",
            )
            colliding = repository / ".lima-semgrep-rules.yml"
            original = "rules: []\n"
            colliding.write_text(original, encoding="utf-8")
            work_root = base / "work"
            work_root.mkdir()
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                base / "imports", "team/project", fingerprint, work_root
            ) as snapshot:
                stage_root = base / "rule-stage"
                stage_root.mkdir()
                with patch.object(source_scan, "RULES_TEMP_ROOT", stage_root):
                    result = run_source_scan(snapshot, self._settings())

                self.assertEqual(original, (snapshot.root / colliding.name).read_text())
                call = run_tool.call_args
                self.assertEqual(
                    (
                        "semgrep",
                        "--json",
                        "--quiet",
                        "--config",
                        call.args[0][4],
                        "--include",
                        "*.c",
                        "--include",
                        "*.cc",
                        "--include",
                        "*.cpp",
                        "--include",
                        "*.cxx",
                        "--include",
                        "*.h",
                        "--include",
                        "*.hh",
                        "--include",
                        "*.hpp",
                        "--include",
                        "*.hxx",
                        ".",
                    ),
                    call.args[0],
                )
                self.assertIs(snapshot, call.args[1])
                self.assertEqual(".", call.args[2])
                self.assertEqual(17, call.kwargs["timeout_seconds"])
                self.assertEqual(8192, call.kwargs["max_output_bytes"])
                self.assertEqual({}, call.kwargs["env"])
                self.assertFalse(Path(call.args[0][4]).resolve().is_relative_to(snapshot.root))
                self.assertEqual(1, len(result.findings))
                self.assertEqual([], list(stage_root.iterdir()))

    @patch("cxx_analyzer.source_scan.run_step")
    def test_source_scan_never_emits_findings_for_unusable_tool_or_parser_output(self, run_tool):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            repository = base / "imports" / "team" / "project"
            repository.mkdir(parents=True)
            (repository / "source.c").write_text("int source(void) { return 0; }\n")
            work_root = base / "work"
            work_root.mkdir()
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                base / "imports", "team/project", fingerprint, work_root
            ) as snapshot:
                stage_root = base / "rule-stage"
                stage_root.mkdir()
                cases = (
                    (
                        "failed",
                        self._execution(status="failed"),
                        "Semgrep source scan did not complete",
                    ),
                    (
                        "timed-out",
                        self._execution(status="timed-out"),
                        "Semgrep source scan did not complete",
                    ),
                    (
                        "truncated",
                        self._execution(stdout="{}", truncated=True),
                        "Semgrep output was incomplete or truncated",
                    ),
                    (
                        "digest-incomplete",
                        self._execution(stdout="{}", complete=False),
                        "Semgrep output was incomplete or truncated",
                    ),
                    (
                        "parser-failure",
                        self._execution(stdout='{"results": [{"bad": true}]}'),
                        "Semgrep JSON was rejected",
                    ),
                )
                for name, execution, diagnostic in cases:
                    with self.subTest(name=name):
                        run_tool.return_value = execution
                        with patch.object(source_scan, "RULES_TEMP_ROOT", stage_root):
                            result = run_source_scan(snapshot, self._settings())
                        self.assertEqual((), result.findings)
                        self.assertEqual((diagnostic,), result.diagnostics)
                        self.assertEqual(1, len(result.tool_runs))
                        expected_status = (
                            "failed"
                            if not execution.digests_complete
                            else execution.status
                        )
                        self.assertEqual(expected_status, result.tool_runs[0]["status"])
                        self.assertEqual(
                            execution.digests_complete,
                            result.tool_runs[0]["digests_complete"],
                        )
                        self.assertEqual([], list(stage_root.iterdir()))

    def test_normalized_finding_enforces_the_client_schema_and_bounds_text(self):
        diagnostics = []
        finding = NormalizedFinding.create(
            rule_id="cxx.source.oob-write",
            severity="high",
            title="Potential out-of-bounds write",
            explanation="A narrow source pattern found an unchecked write.",
            path="src/buffer.c",
            line=7,
            evidence="x" * 10_000,
            fix="",
            test="Exercise the boundary.",
            confidence=0.5,
            cwe="CWE-787",
            tool="semgrep",
            evidence_kind="line",
            verification_state="candidate",
            language="c",
            symbol="write_value",
            analysis_mode="source-only",
            trace="y" * 10_000,
            diagnostics=diagnostics,
        )

        self.assertEqual(
            (
                "rule_id",
                "severity",
                "title",
                "explanation",
                "path",
                "line",
                "evidence",
                "fix",
                "test",
                "confidence",
                "cwe",
                "tool",
                "evidence_kind",
                "verification_state",
                "language",
                "symbol",
                "analysis_mode",
            ),
            tuple(finding.to_dict()),
        )
        self.assertLess(len(finding.evidence), 10_000)
        self.assertLess(len(finding.trace), 10_000)
        self.assertTrue(diagnostics)
        self.assertEqual(
            ("CWE-787", "src/buffer.c", "write_value", 7),
            conservative_identity(finding),
        )
        title_diagnostics = []
        title_bounded = NormalizedFinding.create(
            **{**finding.to_dict(), "title": "z" * 10_000},
            trace="",
            diagnostics=title_diagnostics,
        )
        self.assertLess(len(title_bounded.title), 10_000)
        self.assertTrue(title_diagnostics)
        for identity_field, value in (
            ("rule_id", "r" * 2049),
            ("cwe", "CWE-" + "1" * 2045),
            ("path", "a" * 2047 + "/b.c"),
            ("symbol", "s" * 2049),
        ):
            with self.subTest(identity_field=identity_field):
                with self.assertRaises(ValueError):
                    NormalizedFinding.create(
                        **{**finding.to_dict(), identity_field: value},
                        trace="",
                        diagnostics=[],
                    )

        for changes in (
            {"cwe": "CWE-119"},
            {"severity": "urgent"},
            {"path": "../escape.c"},
            {"line": 0},
            {"verification_state": "confirmed"},
            {"fix": "Apply an automatic source rewrite."},
        ):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    NormalizedFinding.create(
                        **{**finding.to_dict(), **changes}, trace="", diagnostics=[]
                    )

    def test_parse_semgrep_json_rejects_untrusted_results_and_yields_candidates(self):
        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        valid = json.loads((fixture_root / "semgrep-sample.json").read_text(encoding="utf-8"))
        findings, diagnostics = parse_semgrep_json(json.dumps(valid), {"src/buffer.c"})

        self.assertEqual([], diagnostics)
        self.assertEqual(1, len(findings))
        self.assertEqual("candidate", findings[0].verification_state)
        self.assertEqual("source-only", findings[0].analysis_mode)
        self.assertEqual("write_value", findings[0].symbol)

        invalid = copy.deepcopy(valid)
        invalid["results"][0]["extra"]["metadata"].pop("cwe")
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps(invalid), {"src/buffer.c"})
        invalid = copy.deepcopy(valid)
        invalid["results"][0]["path"] = "../escape.c"
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps(invalid), {"src/buffer.c"})
        invalid = copy.deepcopy(valid)
        invalid["results"][0]["start"]["line"] = 0
        with self.assertRaises(ValueError):
            parse_semgrep_json(json.dumps(invalid), {"src/buffer.c"})


class BuildScanTests(unittest.TestCase):
    @staticmethod
    def _settings(*, auto_cmake=True, build_steps=(), total_timeout_seconds=90):
        return AnalyzerSettings(
            auto_cmake=auto_cmake,
            build_steps=build_steps,
            test_steps=(),
            max_memory_mb=1024,
            max_processes=32,
            max_output_bytes=8192,
            step_timeout_seconds=17,
            total_timeout_seconds=total_timeout_seconds,
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )

    @staticmethod
    def _execution(status="completed", returncode=0):
        return ToolExecution(
            status=status,
            returncode=returncode,
            stdout="",
            stderr="",
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            output_sha256="c" * 64,
            output_truncated=False,
            digests_complete=True,
            diagnostic="",
        )

    def _run_completed_budget_fixture(self, unit_count):
        import cxx_analyzer.build_scan as build_scan

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        sample = (fixture_root / "clang-sample.plist").read_text(encoding="utf-8")
        sample = sample.replace("cwe-787/vulnerable-1.c", "src/unit-0.c")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            sources = []
            for index in range(unit_count):
                source = root / "src" / f"unit-{index}.c"
                source.write_text("int value(void) { return 0; }\n", encoding="utf-8")
                sources.append(source)
            output_root = root / "tool-output"
            output_root.mkdir()
            snapshot = Mock(
                root=root,
                files=tuple(f"src/unit-{index}.c" for index in range(unit_count)),
            )

            def completed_tool(argv, *args, **kwargs):
                if argv[0] == "configure":
                    (root / "compile_commands.json").write_text(
                        json.dumps(
                            [
                                {
                                    "directory": str(root),
                                    "file": str(source),
                                    "arguments": ["cc", "-c", str(source)],
                                }
                                for source in sources
                            ]
                        ),
                        encoding="utf-8",
                    )
                elif argv[0] == "clang-14":
                    Path(argv[-1]).write_text(sample, encoding="utf-8")
                return self._execution()

            with patch("cxx_analyzer.build_scan.run_step", side_effect=completed_tool) as run_tool:
                with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", output_root):
                    result = build_scan.run_build_scan(
                        snapshot,
                        self._settings(
                            auto_cmake=False,
                            build_steps=(("configure",),),
                        ),
                    )
            return result, run_tool.call_count

    def test_build_plan_uses_only_fixed_cmake_or_admin_argv(self):
        from cxx_analyzer.build_scan import select_build_steps

        cmake_snapshot = Mock(files=("CMakeLists.txt", "src/main.cpp"))
        self.assertEqual(
            (
                (
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    "build",
                    "-DCMAKE_BUILD_TYPE=Debug",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                ),
                ("cmake", "--build", "build", "--parallel", "2"),
            ),
            select_build_steps(cmake_snapshot, self._settings()),
        )

        admin_steps = (("ninja", "-C", "out"),)
        script_snapshot = Mock(files=("src/main.cpp", "build.sh"))
        self.assertEqual(
            admin_steps,
            select_build_steps(
                script_snapshot,
                self._settings(build_steps=admin_steps),
            ),
        )
        self.assertEqual((), select_build_steps(script_snapshot, self._settings()))

    @patch("cxx_analyzer.build_scan.run_step")
    def test_build_nonzero_and_timeout_are_bounded_layer_results(self, run_tool):
        from cxx_analyzer.build_scan import run_build_scan

        snapshot = Mock()
        snapshot.files = ("CMakeLists.txt", "src/main.cpp")
        for execution, expected_status in (
            (self._execution("failed", 2), "build_failed"),
            (self._execution("timed-out", None), "timed-out"),
        ):
            with self.subTest(status=execution.status):
                run_tool.reset_mock()
                run_tool.return_value = execution
                result = run_build_scan(snapshot, self._settings())
                self.assertEqual((), result.findings)
                self.assertEqual((expected_status,), result.diagnostics)
                self.assertEqual(expected_status, result.tool_runs[0]["status"])
                self.assertLessEqual(len(result.diagnostics[0].encode("utf-8")), 2048)
                self.assertEqual(1, run_tool.call_count)

    @patch("cxx_analyzer.build_scan.run_step")
    def test_sanitizer_requested_build_uses_only_fixed_compiler_environment(self, run_tool):
        from cxx_analyzer.build_scan import run_build_scan
        from cxx_analyzer.execution import SANITIZER_ENVIRONMENT

        snapshot = Mock(files=("CMakeLists.txt", "src/main.cpp"))
        run_tool.return_value = self._execution("failed", 2)

        result = run_build_scan(snapshot, self._settings(), sanitizer_enabled=True)

        self.assertEqual(("build_failed",), result.diagnostics)
        self.assertEqual(SANITIZER_ENVIRONMENT, run_tool.call_args.kwargs["env"])

    @patch("cxx_analyzer.deadline.time.monotonic")
    @patch("cxx_analyzer.build_scan.run_step")
    def test_total_deadline_stops_later_build_steps(self, run_tool, monotonic):
        from cxx_analyzer.build_scan import run_build_scan

        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Mock(root=Path(temporary), files=("src/main.cpp",))
            settings = self._settings(
                auto_cmake=False,
                build_steps=(("first-build",), ("second-build",)),
                total_timeout_seconds=2,
            )
            monotonic.side_effect = (0.0, 0.1, 2.1)
            run_tool.return_value = self._execution()

            result = run_build_scan(snapshot, settings)

        self.assertEqual(1, run_tool.call_count)
        self.assertEqual(("timed-out",), result.diagnostics)
        self.assertEqual(
            ("completed", "timed-out"),
            tuple(item["status"] for item in result.tool_runs),
        )
        self.assertEqual("build-step", result.tool_runs[-1]["tool"])

    @patch("cxx_analyzer.deadline.time.monotonic")
    @patch("cxx_analyzer.build_scan.run_step")
    def test_total_deadline_stops_later_clang_units(self, run_tool, monotonic):
        import cxx_analyzer.build_scan as build_scan

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        sample = (fixture_root / "clang-sample.plist").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            sources = (root / "src" / "main.c", root / "src" / "other.c")
            for source in sources:
                source.write_text("int value(void) { return 0; }\n", encoding="utf-8")
            output_root = root / "tool-output"
            output_root.mkdir()
            snapshot = Mock(
                root=root,
                files=("src/main.c", "src/other.c"),
            )

            def completed_tool(argv, *args, **kwargs):
                if argv[0] == "configure":
                    (root / "compile_commands.json").write_text(
                        json.dumps(
                            [
                                {
                                    "directory": str(root),
                                    "file": str(source),
                                    "arguments": ["cc", "-c", str(source)],
                                }
                                for source in sources
                            ]
                        ),
                        encoding="utf-8",
                    )
                elif argv[0] == "clang-14":
                    Path(argv[-1]).write_text(
                        sample.replace("cwe-787/vulnerable-1.c", "src/main.c"),
                        encoding="utf-8",
                    )
                return self._execution()

            run_tool.side_effect = completed_tool
            monotonic.side_effect = (0.0, 0.1, 0.2, 2.1)
            settings = self._settings(
                auto_cmake=False,
                build_steps=(("configure",),),
                total_timeout_seconds=2,
            )
            with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", output_root):
                result = build_scan.run_build_scan(snapshot, settings)

        self.assertEqual(2, run_tool.call_count)
        self.assertEqual("timed-out", result.diagnostics[-1])
        self.assertEqual("timed-out", result.tool_runs[-1]["status"])
        self.assertEqual("clang", result.tool_runs[-1]["tool"])

    def test_global_scan_budgets_stop_units_tool_runs_bytes_and_result_growth(self):
        import cxx_analyzer.build_scan as build_scan

        cases = (
            ("units", {"MAX_COMPILATION_UNITS": 1}, 1),
            ("tool-runs", {"MAX_TOOL_RUNS": 1}, 1),
            ("aggregate-bytes", {"MAX_AGGREGATE_PLIST_BYTES": 32}, 2),
            (
                "findings-and-diagnostics",
                {"MAX_FINDINGS": 1, "MAX_DIAGNOSTICS": 2},
                2,
            ),
        )
        for name, limits, maximum_calls in cases:
            with self.subTest(name=name):
                patches = [patch.object(build_scan, key, value) for key, value in limits.items()]
                for active_patch in patches:
                    active_patch.start()
                try:
                    result, call_count = self._run_completed_budget_fixture(2)
                finally:
                    for active_patch in reversed(patches):
                        active_patch.stop()

                self.assertLessEqual(call_count, maximum_calls)
                self.assertLessEqual(len(result.tool_runs), limits.get("MAX_TOOL_RUNS", 999))
                self.assertLessEqual(len(result.findings), limits.get("MAX_FINDINGS", 999))
                self.assertLessEqual(len(result.diagnostics), limits.get("MAX_DIAGNOSTICS", 999))
                self.assertIn("analysis-budget-exhausted", result.diagnostics)

    def test_diagnostic_budget_stops_direct_clang_failures(self):
        import cxx_analyzer.build_scan as build_scan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            (root / "tool-output").mkdir()
            sources = tuple(root / "src" / f"unit-{index}.c" for index in range(2))
            for source in sources:
                source.write_text("int value(void) { return 0; }\n", encoding="utf-8")
            snapshot = Mock(
                root=root,
                files=tuple(f"src/unit-{index}.c" for index in range(2)),
            )

            def failing_tool(argv, *args, **kwargs):
                if argv[0] == "configure":
                    (root / "compile_commands.json").write_text(
                        json.dumps(
                            [
                                {
                                    "directory": str(root),
                                    "file": str(source),
                                    "arguments": ["cc", "-c", str(source)],
                                }
                                for source in sources
                            ]
                        ),
                        encoding="utf-8",
                    )
                    return self._execution()
                return self._execution(status="sandbox-unavailable", returncode=None)

            with patch("cxx_analyzer.build_scan.run_step", side_effect=failing_tool) as run_tool:
                with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", root / "tool-output"):
                    with patch.object(build_scan, "MAX_DIAGNOSTICS", 1):
                        result = build_scan.run_build_scan(
                            snapshot,
                            self._settings(
                                auto_cmake=False,
                                build_steps=(("configure",),),
                            ),
                        )

        self.assertEqual(2, run_tool.call_count)
        self.assertEqual(("analysis-budget-exhausted",), result.diagnostics)

    def test_aggregate_plist_budget_counts_rejected_outputs(self):
        import cxx_analyzer.build_scan as build_scan

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            (root / "tool-output").mkdir()
            sources = tuple(root / "src" / f"unit-{index}.c" for index in range(3))
            for source in sources:
                source.write_text("int value(void) { return 0; }\n", encoding="utf-8")
            snapshot = Mock(
                root=root,
                files=tuple(f"src/unit-{index}.c" for index in range(3)),
            )

            def invalid_output_tool(argv, *args, **kwargs):
                if argv[0] == "configure":
                    (root / "compile_commands.json").write_text(
                        json.dumps(
                            [
                                {
                                    "directory": str(root),
                                    "file": str(source),
                                    "arguments": ["cc", "-c", str(source)],
                                }
                                for source in sources
                            ]
                        ),
                        encoding="utf-8",
                    )
                else:
                    Path(argv[-1]).write_bytes(b"x" * 32)
                return self._execution()

            with patch(
                "cxx_analyzer.build_scan.run_step", side_effect=invalid_output_tool
            ) as run_tool:
                with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", root / "tool-output"):
                    with patch.object(build_scan, "_MAX_PLIST_BYTES", 32):
                        with patch.object(build_scan, "MAX_AGGREGATE_PLIST_BYTES", 64):
                            result = build_scan.run_build_scan(
                                snapshot,
                                self._settings(
                                    auto_cmake=False,
                                    build_steps=(("configure",),),
                                ),
                            )

        self.assertEqual(3, run_tool.call_count)
        self.assertEqual(("analysis-budget-exhausted",), result.diagnostics[-1:])

    def test_build_not_configured_never_executes_repository_script(self):
        from cxx_analyzer.build_scan import run_build_scan

        snapshot = Mock(files=("src/main.cpp", "configure", "build.sh"))
        with patch("cxx_analyzer.build_scan.run_step") as run_tool:
            result = run_build_scan(snapshot, self._settings())
        self.assertEqual((), result.findings)
        self.assertEqual(("build-not-configured",), result.diagnostics)
        self.assertEqual((), result.tool_runs)
        run_tool.assert_not_called()

    def test_compile_database_rejects_command_strings_and_escaping_paths(self):
        from cxx_analyzer.build_scan import load_compilation_database

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            (root / "include").mkdir()
            source = root / "src" / "main.cpp"
            source.write_text("int main() { return 0; }\n", encoding="utf-8")
            database = root / "compile_commands.json"
            snapshot = Mock(root=root, files=("src/main.cpp",))

            valid = [
                {
                    "directory": str(root),
                    "file": str(source),
                    "arguments": [
                        "clang++",
                        "-c",
                        "-DDEBUG=1",
                        "-std=c++20",
                        "-Wall",
                        "-O2",
                        "-I",
                        str(root / "include"),
                        f"-fmodule-file={root / 'modules' / 'safe.pcm'}",
                        f"-fprofile-use={root / 'profiles' / 'safe.profdata'}",
                        str(source),
                    ],
                }
            ]
            database.write_text(json.dumps(valid), encoding="utf-8")
            units = load_compilation_database(snapshot, database)
            self.assertEqual(("src/main.cpp",), tuple(unit.file for unit in units))
            self.assertEqual(tuple(valid[0]["arguments"]), units[0].arguments)

            invalid_entries = (
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "command": f"clang++ -c {source}",
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(root.parent / "escape.cpp"),
                        "arguments": ["clang++", "-c", "../escape.cpp"],
                    }
                ],
                [
                    {
                        "directory": str(root.parent),
                        "file": str(source),
                        "arguments": ["clang++", "-c", str(source)],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", "-c", "../escape.cpp"],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", "-I", str(root.parent), str(source)],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", "@../outside.rsp"],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", f"-fmodule-file={root.parent / 'outside.pcm'}"],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": [
                            "clang++",
                            "-fmodule-file",
                            f"named={root.parent.as_posix()}/outside.pcm",
                        ],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": [
                            "clang++",
                            f"-fprofile-use={root.parent / 'outside.profdata'}",
                        ],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": [
                            "clang++",
                            "-fmodule-map-file",
                            str(root.parent / "outside.modulemap"),
                        ],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", "-Xclang", "-fplugin=/outside/plugin.so"],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", "-Xclang=-load"],
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "arguments": ["clang++", f"-B{root.parent}"],
                    }
                ],
            )
            for payload in invalid_entries:
                with self.subTest(payload=payload):
                    database.write_text(json.dumps(payload), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        load_compilation_database(snapshot, database)

    def test_structured_clang_plist_maps_four_cwes_and_bounds_trace_paths(self):
        from cxx_analyzer.build_scan import parse_clang_plist

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        raw = (fixture_root / "clang-sample.plist").read_bytes()
        snapshot = Mock(
            root=fixture_root.resolve(),
            files=(
                "cwe-787/vulnerable-1.c",
                "cwe-125/vulnerable-1.c",
                "cwe-416/vulnerable-1.c",
                "cwe-415/vulnerable-1.c",
            ),
        )

        findings, diagnostics = parse_clang_plist(raw, snapshot)

        self.assertEqual([], diagnostics)
        self.assertEqual(
            {"CWE-787", "CWE-125", "CWE-416", "CWE-415"},
            {finding.cwe for finding in findings},
        )
        self.assertTrue(
            all(
                finding.analysis_mode == "build-backed"
                and finding.verification_state == "build-verified"
                and finding.tool == "clang"
                and finding.fix == ""
                for finding in findings
            )
        )
        for finding in findings:
            trace = json.loads(finding.trace)
            self.assertTrue(trace)
            self.assertTrue(
                all(
                    frame["path"] in snapshot.files and not Path(frame["path"]).is_absolute()
                    for frame in trace
                )
            )

    def test_clang_plist_resolves_unit_cwd_and_structured_control_edges(self):
        from cxx_analyzer.build_scan import parse_clang_plist

        fixture = (
            Path(__file__).parent / "fixtures" / "cxx_memory" / "clang-relative-control.plist"
        ).read_bytes()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "build").mkdir()
            (root / "src").mkdir()
            (root / "src" / "main.c").write_text(
                "int write_value(void) { return 0; }\n", encoding="utf-8"
            )
            snapshot = Mock(root=root, files=("src/main.c",))

            findings, diagnostics = parse_clang_plist(fixture, snapshot, relative_cwd="build")

        self.assertEqual([], diagnostics)
        self.assertEqual(1, len(findings))
        self.assertEqual("src/main.c", findings[0].path)
        self.assertEqual(5, findings[0].line)
        trace = json.loads(findings[0].trace)
        self.assertEqual([2, 3, 5], [frame["line"] for frame in trace])
        self.assertEqual(
            ["control-start", "control-end", "event"],
            [frame["kind"] for frame in trace],
        )
        self.assertTrue(all(frame["path"] == "src/main.c" for frame in trace))
        self.assertNotIn("escape.c", json.dumps(trace))

    def test_fusion_promotes_only_matching_conservative_identity(self):
        from cxx_analyzer.build_scan import parse_clang_plist
        from cxx_analyzer.normalizers import fuse_findings

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        snapshot = Mock(
            root=fixture_root.resolve(),
            files=("cwe-787/vulnerable-1.c",),
        )
        build_findings, _ = parse_clang_plist(
            (fixture_root / "clang-sample.plist").read_bytes(), snapshot
        )
        build = build_findings[0]
        candidate = NormalizedFinding.create(
            rule_id="cxx.source.oob-write.constant-index",
            severity="high",
            title="Potential out-of-bounds write",
            explanation="A source candidate.",
            path=build.path,
            line=build.line,
            evidence="values[2] = 1",
            fix="",
            test="Exercise the boundary.",
            confidence=0.5,
            cwe=build.cwe,
            tool="semgrep",
            evidence_kind="line",
            verification_state="candidate",
            language=build.language,
            symbol=build.symbol,
            analysis_mode="source-only",
            diagnostics=[],
        )
        different_line = NormalizedFinding.create(
            **{**candidate.to_dict(), "line": candidate.line + 1},
            diagnostics=[],
        )

        fused = fuse_findings((candidate, different_line), (build,))

        self.assertEqual(3, len(fused))
        self.assertIn(build, fused)
        self.assertIn(different_line, fused)
        self.assertIn(candidate, fused)

    @patch("cxx_analyzer.build_scan.run_step")
    def test_clang_runs_only_after_successful_build_and_valid_database(self, run_tool):
        import cxx_analyzer.build_scan as build_scan

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        sample = (fixture_root / "clang-sample.plist").read_text(encoding="utf-8")
        first_diagnostic = sample.replace("cwe-787/vulnerable-1.c", "src/main.c")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "src").mkdir()
            source = root / "src" / "main.c"
            source.write_text(
                "void oob_write_array(void) { int values[2]; values[2] = 1; }\n",
                encoding="utf-8",
            )
            temp_root = root / "tool-output"
            temp_root.mkdir()
            snapshot = Mock(
                root=root,
                files=("CMakeLists.txt", "src/main.c"),
            )

            def successful_tool(argv, *args, **kwargs):
                if argv[:3] == ("cmake", "--build", "build"):
                    build = root / "build"
                    build.mkdir(exist_ok=True)
                    (build / "compile_commands.json").write_text(
                        json.dumps(
                            [
                                {
                                    "directory": str(root),
                                    "file": str(source),
                                    "arguments": ["cc", "-c", str(source), "-o", "main.o"],
                                }
                            ]
                        ),
                        encoding="utf-8",
                    )
                if argv[0] == "clang-14":
                    Path(argv[-1]).write_text(first_diagnostic, encoding="utf-8")
                return self._execution()

            run_tool.side_effect = successful_tool
            with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", temp_root):
                result = build_scan.run_build_scan(snapshot, self._settings())

            self.assertEqual(3, run_tool.call_count)
            self.assertEqual(
                _expected_cmake_steps(), tuple(call.args[0] for call in run_tool.call_args_list[:2])
            )
            clang_call = run_tool.call_args_list[2]
            self.assertEqual("clang-14", clang_call.args[0][0])
            self.assertIn("--analyze", clang_call.args[0])
            self.assertIn(
                "-analyzer-checker=core,unix,alpha.security.ArrayBoundV2",
                clang_call.args[0],
            )
            self.assertIs(snapshot, clang_call.args[1])
            self.assertEqual(".", clang_call.args[2])
            self.assertEqual(1, len(result.findings))
            self.assertEqual("build-verified", result.findings[0].verification_state)

            (root / "build" / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(root),
                            "file": str(source),
                            "command": f"cc -c {source}",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            run_tool.reset_mock()
            run_tool.side_effect = [self._execution(), self._execution()]
            with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", temp_root):
                rejected = build_scan.run_build_scan(snapshot, self._settings())
            self.assertEqual(2, run_tool.call_count)
        self.assertEqual(("compile-commands-rejected",), rejected.diagnostics)


class BuildScanContainerTests(unittest.TestCase):
    def test_build_backed_fixture_coverage_lists_every_uncovered_identity(self):
        if sys.platform != "linux":
            self.skipTest("build-backed container regression requires Linux")
        if shutil.which("cmake") is None or shutil.which("clang-14") is None:
            self.skipTest("CMake and clang-14 are required for build-backed fixtures")

        import cxx_analyzer.build_scan as build_scan

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        manifest = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))
        with tempfile.TemporaryDirectory(dir="/work/tmp") as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            sources = []
            for item in manifest:
                source = fixture_root / item["path"]
                target = repository / item["path"]
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, target)
                sources.append(item["path"])
            cmake_sources = "\n  ".join(f'"{path}"' for path in sources)
            (repository / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\n"
                "project(lima_cxx_memory_fixtures LANGUAGES C CXX)\n"
                f"add_library(fixtures OBJECT\n  {cmake_sources}\n)\n",
                encoding="utf-8",
            )
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", fingerprint, work_root) as snapshot:
                tool_output = base / "tool-output"
                tool_output.mkdir()
                with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", tool_output):
                    result = build_scan.run_build_scan(snapshot, BuildScanTests._settings())

        found = {(finding.cwe, finding.path, finding.symbol) for finding in result.findings}
        expected = {
            (item["cwe"], item["path"], item["symbol"])
            for item in manifest
            if item["clang_expected"]
        }
        safe = {
            (item["cwe"], item["path"], item["symbol"])
            for item in manifest
            if not item["vulnerable"]
        }
        uncovered = sorted(expected - found)
        print(f"uncovered build-backed fixture identities: {uncovered}")
        self.assertFalse(
            uncovered,
            f"uncovered build-backed fixture identities: {uncovered}; "
            f"diagnostics: {result.diagnostics}",
        )
        self.assertTrue(found.isdisjoint(safe), f"safe identities reported: {found & safe}")
        self.assertTrue(
            all(
                finding.verification_state == "build-verified" and finding.fix == ""
                for finding in result.findings
            )
        )


class SanitizerScanTests(unittest.TestCase):
    @staticmethod
    def _settings(*, test_steps=(), total_timeout_seconds=90):
        return AnalyzerSettings(
            auto_cmake=False,
            build_steps=(("configure",),),
            test_steps=test_steps,
            max_memory_mb=1024,
            max_processes=32,
            max_output_bytes=8192,
            step_timeout_seconds=17,
            total_timeout_seconds=total_timeout_seconds,
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )

    @staticmethod
    def _execution(status="failed", returncode=1, *, stderr="", truncated=False):
        return ToolExecution(
            status=status,
            returncode=returncode,
            stdout="",
            stderr=stderr,
            stdout_sha256="a" * 64,
            stderr_sha256="b" * 64,
            output_sha256="c" * 64,
            output_truncated=truncated,
            digests_complete=True,
            diagnostic="",
        )

    def _snapshot(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name).resolve()
        (root / "src").mkdir()
        (root / "src" / "memory.c").write_text("int main(void) { return 0; }\n")
        snapshot = Mock(root=root, files=("src/memory.c",))
        snapshot.resolve_cwd.return_value = root
        return temporary, snapshot

    def test_parser_maps_only_complete_structured_asan_reports_to_four_cwes(self):
        from cxx_analyzer.sanitizer_scan import parse_asan_log

        temporary, snapshot = self._snapshot()
        try:
            root = str(snapshot.root).replace("\\", "/")
            cases = (
                ("heap-buffer-overflow", "WRITE", "CWE-787"),
                ("stack-buffer-overflow", "READ", "CWE-125"),
                ("global-buffer-overflow", "WRITE", "CWE-787"),
                ("heap-use-after-free", "READ", "CWE-416"),
                ("attempting double-free", "FREE", "CWE-415"),
            )
            for error_type, access, expected_cwe in cases:
                with self.subTest(error_type=error_type):
                    access_line = (
                        "attempting double-free on 0x1"
                        if access == "FREE"
                        else f"{access} of size 4 at 0x1 thread T0"
                    )
                    summary_error = (
                        "double-free" if error_type == "attempting double-free" else error_type
                    )
                    text = (
                        f"==12==ERROR: AddressSanitizer: {error_type} on address 0x1\n"
                        f"{access_line}\n"
                        f"    #0 0x123 in \x1b[31mreport_memory\x1b[0m {root}/src/memory.c:9:3\n"
                        "SUMMARY: AddressSanitizer: "
                        f"{summary_error} "
                        f"{root}/src/memory.c:9\n"
                    )
                    findings, diagnostics = parse_asan_log(text, snapshot)
                    self.assertEqual([], diagnostics)
                    self.assertEqual(1, len(findings))
                    finding = findings[0]
                    self.assertEqual(expected_cwe, finding.cwe)
                    self.assertEqual("sanitizer-confirmed", finding.analysis_mode)
                    self.assertEqual("confirmed", finding.verification_state)
                    self.assertEqual("src/memory.c", finding.path)
                    self.assertEqual("report_memory", finding.symbol)
                    self.assertEqual("", finding.fix)
                    self.assertNotIn("\\x1b", finding.evidence + finding.trace)
        finally:
            temporary.cleanup()

    def test_parser_rejects_incomplete_unknown_external_and_sensitive_logs(self):
        from cxx_analyzer.sanitizer_scan import parse_asan_log

        temporary, snapshot = self._snapshot()
        try:
            root = str(snapshot.root).replace("\\", "/")
            cases = (
                "ordinary test failed with exit status 1",
                "==1==ERROR: LeakSanitizer: detected memory leaks",
                "AddressSanitizer:DEADLYSIGNAL\nSEGV",
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                "WRITE of size 4 at 0x1\n"
                "#0 0x1 in foreign /tmp/secret/repo.c:5\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow /tmp/secret/repo.c:5",
                f"==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                f"WRITE of size 4 at 0x1\n#0 0x1 in report {root}/src/memory.c:5\n",
            )
            for text in cases:
                with self.subTest(text=text[:32]):
                    findings, diagnostics = parse_asan_log(text, snapshot)
                    self.assertEqual([], findings)
                    self.assertEqual(["needs-human-review"], diagnostics)
            sensitive = (
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                f"WRITE of size 4 at 0x1\n#0 0x1 in report {root}/src/memory.c:5\n"
                "env TOKEN=top-secret /sensitive/temporary\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow"
            )
            findings, _ = parse_asan_log(sensitive, snapshot)
            rendered = json.dumps(findings[0].to_dict())
            self.assertNotIn("top-secret", rendered)
            self.assertNotIn("/sensitive/temporary", rendered)
            self.assertNotIn(str(snapshot.root), rendered)
        finally:
            temporary.cleanup()

    def test_parser_rejects_mismatched_summary_and_snapshot_only_auxiliary_frame(self):
        from cxx_analyzer.sanitizer_scan import parse_asan_log

        temporary, snapshot = self._snapshot()
        try:
            root = str(snapshot.root).replace("\\", "/")
            mismatch = (
                "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
                "READ of size 4 at 0x1\n"
                f"#0 0x1 in report {root}/src/memory.c:5\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow\n"
            )
            auxiliary = (
                "==1==ERROR: AddressSanitizer: heap-use-after-free on address 0x1\n"
                "READ of size 4 at 0x1\n"
                "#0 0x1 in external /usr/lib/libforeign.so:5\n"
                "freed by thread T0 here:\n"
                f"#0 0x1 in report {root}/src/memory.c:9\n"
                "SUMMARY: AddressSanitizer: heap-use-after-free\n"
            )
            for text in (mismatch, auxiliary):
                with self.subTest(text=text.splitlines()[0]):
                    findings, diagnostics = parse_asan_log(text, snapshot)
                    self.assertEqual([], findings)
                    self.assertEqual(["needs-human-review"], diagnostics)
        finally:
            temporary.cleanup()

    @patch("cxx_analyzer.sanitizer_scan.run_step")
    def test_runtime_gate_requires_test_steps_and_matching_successful_build_context(self, run_tool):
        from cxx_analyzer.build_scan import BuildContext
        from cxx_analyzer.sanitizer_scan import run_sanitizer_scan

        temporary, snapshot = self._snapshot()
        try:
            no_steps = run_sanitizer_scan(snapshot, self._settings(), None)
            self.assertEqual(("sanitizer-not-configured",), no_steps.diagnostics)
            bad_context = run_sanitizer_scan(
                snapshot,
                self._settings(test_steps=(("test",),)),
                BuildContext(snapshot.root.parent, snapshot.files),
            )
            self.assertEqual(("sanitizer-build-context-unavailable",), bad_context.diagnostics)
            uninstrumented = run_sanitizer_scan(
                snapshot,
                self._settings(test_steps=(("test",),)),
                BuildContext(snapshot.root, snapshot.files),
            )
            self.assertEqual(("sanitizer-build-context-unavailable",), uninstrumented.diagnostics)
            run_tool.assert_not_called()
        finally:
            temporary.cleanup()

    @patch("cxx_analyzer.deadline.time.monotonic")
    @patch("cxx_analyzer.sanitizer_scan.run_step")
    def test_shared_build_deadline_blocks_expired_and_later_test_steps(self, run_tool, monotonic):
        from cxx_analyzer.build_scan import BuildContext
        from cxx_analyzer.sanitizer_scan import run_sanitizer_scan

        temporary, snapshot = self._snapshot()
        try:
            monotonic.side_effect = (5.0, 0.0, 1.0)
            expired = run_sanitizer_scan(
                snapshot,
                self._settings(test_steps=(("first",),)),
                BuildContext(
                    snapshot.root,
                    snapshot.files,
                    sanitizer_enabled=True,
                    deadline=AnalysisDeadline(4.0),
                ),
            )
            self.assertEqual(("timed-out",), expired.diagnostics)
            run_tool.assert_not_called()

            run_tool.return_value = self._execution(status="completed", returncode=0)
            later = run_sanitizer_scan(
                snapshot,
                self._settings(test_steps=(("first",), ("second",))),
                BuildContext(
                    snapshot.root,
                    snapshot.files,
                    sanitizer_enabled=True,
                    deadline=AnalysisDeadline(1.0),
                ),
            )
            self.assertEqual(1, run_tool.call_count)
            self.assertEqual(("needs-human-review", "timed-out"), later.diagnostics)
        finally:
            temporary.cleanup()

    @patch("cxx_analyzer.sanitizer_scan.run_step")
    def test_sanitizer_runs_fixed_env_and_nonzero_without_asan_is_only_diagnostic(self, run_tool):
        from cxx_analyzer.build_scan import BuildContext
        from cxx_analyzer.execution import SANITIZER_ENVIRONMENT
        from cxx_analyzer.sanitizer_scan import run_sanitizer_scan

        temporary, snapshot = self._snapshot()
        try:
            run_tool.return_value = self._execution(stderr="assertion failed")
            result = run_sanitizer_scan(
                snapshot,
                self._settings(test_steps=(("ctest", "--test-dir", "build"),)),
                BuildContext(
                    snapshot.root,
                    snapshot.files,
                    sanitizer_enabled=True,
                    deadline=AnalysisDeadline.start(90),
                ),
            )
            self.assertEqual((), result.findings)
            self.assertEqual(("test-failed-without-sanitizer-evidence",), result.diagnostics)
            self.assertEqual(SANITIZER_ENVIRONMENT, run_tool.call_args.kwargs["env"])
            self.assertEqual(("ctest", "--test-dir", "build"), run_tool.call_args.args[0])
        finally:
            temporary.cleanup()

    @patch("cxx_analyzer.sanitizer_scan.run_step")
    def test_truncated_or_timed_out_asan_output_never_confirms_a_finding(self, run_tool):
        from cxx_analyzer.build_scan import BuildContext
        from cxx_analyzer.sanitizer_scan import run_sanitizer_scan

        temporary, snapshot = self._snapshot()
        try:
            root = str(snapshot.root).replace("\\", "/")
            report = (
                "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x1\n"
                f"WRITE of size 4 at 0x1\n#0 0x1 in report {root}/src/memory.c:5\n"
                "SUMMARY: AddressSanitizer: heap-buffer-overflow"
            )
            for execution in (
                self._execution(stderr=report, truncated=True),
                self._execution(status="timed-out", returncode=None, stderr=report),
            ):
                with self.subTest(status=execution.status):
                    run_tool.return_value = execution
                    result = run_sanitizer_scan(
                        snapshot,
                        self._settings(test_steps=(("test",),)),
                        BuildContext(
                            snapshot.root,
                            snapshot.files,
                            sanitizer_enabled=True,
                            deadline=AnalysisDeadline.start(90),
                        ),
                    )
                    self.assertEqual((), result.findings)
                    self.assertIn("needs-human-review", result.diagnostics)
        finally:
            temporary.cleanup()

    @patch("cxx_analyzer.server.run_sanitizer_scan")
    @patch("cxx_analyzer.server.run_build_scan")
    @patch("cxx_analyzer.server.run_source_scan")
    @patch("cxx_analyzer.server.prepare_snapshot")
    def test_server_runs_dynamic_layer_and_fuses_by_conservative_identity(
        self, prepare, source_runner, build_runner, sanitizer_runner
    ):
        from cxx_analyzer.build_scan import BuildContext

        snapshot = prepare.return_value.__enter__.return_value
        snapshot.root = Path("/work/snapshots/one")
        snapshot.files = ("src/memory.c",)
        candidate = NormalizedFinding.create(
            rule_id="cxx.source.oob-write",
            severity="high",
            title="candidate",
            explanation="candidate evidence",
            path="src/memory.c",
            line=5,
            evidence="value[2]",
            fix="",
            test="exercise",
            confidence=0.5,
            cwe="CWE-787",
            tool="semgrep",
            evidence_kind="line",
            verification_state="candidate",
            language="c",
            symbol="report",
            analysis_mode="source-only",
            diagnostics=[],
        )
        confirmed = NormalizedFinding.create(
            rule_id="cxx.asan.oob-write",
            severity="high",
            title="confirmed",
            explanation="ASan report",
            path="src/memory.c",
            line=5,
            evidence="AddressSanitizer reported heap-buffer-overflow (WRITE).",
            fix="",
            test="exercise",
            confidence=1.0,
            cwe="CWE-787",
            tool="asan",
            evidence_kind="sanitizer",
            verification_state="confirmed",
            language="c",
            symbol="report",
            analysis_mode="sanitizer-confirmed",
            diagnostics=[],
        )
        source_runner.return_value = LayerResult(
            (candidate,), (), ({"tool": "semgrep", "status": "completed"},)
        )
        context = BuildContext(snapshot.root, snapshot.files, sanitizer_enabled=True)
        build_runner.return_value = LayerResult((), (), (), context)
        sanitizer_runner.return_value = LayerResult(
            (confirmed,), (), ({"tool": "asan-test", "status": "completed"},)
        )
        settings = self._settings(test_steps=(("test",),))

        result = analyzer_server.analyze_request(
            AnalyzerServiceTests()._payload(
                requested_layers=["source-only", "build-backed", "sanitizer-confirmed"]
            ),
            settings,
        )

        build_runner.assert_called_once_with(
            snapshot, settings, sanitizer_enabled=True, deadline=ANY
        )
        sanitizer_runner.assert_called_once_with(
            snapshot, settings, context, deadline=ANY
        )
        self.assertEqual([candidate.to_dict(), confirmed.to_dict()], result["findings"])
        self.assertEqual(
            [
                {"tool": "semgrep", "status": "completed"},
                {"tool": "asan-test", "status": "completed"},
            ],
            result["tool_runs"],
        )

    def test_executor_rejects_request_style_environment_instead_of_inheriting_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            (repository / "main.cpp").write_text("int main() { return 0; }\n")
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(import_root, "team/project", fingerprint, work_root) as snapshot:
                with self.assertRaisesRegex(ValueError, "analyzer-owned fixed"):
                    run_step(("tool",), snapshot, ".", 1, 128, {"TOKEN": "secret"})

    def test_server_response_budgets_keep_confirmed_evidence_and_bound_all_lists(self):
        low = NormalizedFinding.create(
            rule_id="cxx.source.oob-write",
            severity="high",
            title="candidate",
            explanation="candidate",
            path="src/memory.c",
            line=5,
            evidence="x",
            fix="",
            test="test",
            confidence=0.5,
            cwe="CWE-787",
            tool="semgrep",
            evidence_kind="line",
            verification_state="candidate",
            language="c",
            symbol="report",
            analysis_mode="source-only",
            diagnostics=[],
        )
        high = NormalizedFinding.create(
            rule_id="cxx.asan.oob-write",
            severity="high",
            title="confirmed",
            explanation="confirmed",
            path="src/memory.c",
            line=5,
            evidence="x",
            fix="",
            test="test",
            confidence=1.0,
            cwe="CWE-787",
            tool="asan",
            evidence_kind="sanitizer",
            verification_state="confirmed",
            language="c",
            symbol="report",
            analysis_mode="sanitizer-confirmed",
            diagnostics=[],
        )
        with patch.object(analyzer_server, "MAX_FINDINGS", 1):
            with patch.object(analyzer_server, "MAX_DIAGNOSTICS", 1):
                with patch.object(analyzer_server, "MAX_TOOL_RUNS", 1):
                    findings, diagnostics, tool_runs = analyzer_server._bound_response_lists(
                        (low, high),
                        ["source", "asan"],
                        [
                            {"tool": "semgrep", "status": "completed"},
                            {"tool": "asan-test", "status": "completed"},
                        ],
                    )
        self.assertEqual((high,), findings)
        self.assertEqual(("analysis-budget-exhausted",), diagnostics)
        self.assertEqual(({"tool": "asan-test", "status": "completed"},), tool_runs)


class SanitizerContainerTests(unittest.TestCase):
    def test_asan_fixture_subset_confirms_vulnerable_c_and_not_safe_c(self):
        if sys.platform != "linux":
            self.skipTest("ASan container regression requires Linux")
        if shutil.which("cmake") is None or shutil.which("clang-14") is None:
            self.skipTest("CMake and clang-14 are required for ASan fixtures")

        from cxx_analyzer.build_scan import run_build_scan
        from cxx_analyzer.sanitizer_scan import run_sanitizer_scan

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        manifest = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))
        selected = (
            "cwe-787/vulnerable-1.c",
            "cwe-125/vulnerable-1.c",
            "cwe-416/vulnerable-1.c",
            "cwe-415/vulnerable-1.c",
            "cwe-787/safe-1.c",
            "cwe-125/safe-1.c",
            "cwe-416/safe-1.c",
            "cwe-415/safe-1.c",
        )
        symbols = {item["path"]: item["symbol"] for item in manifest if item["path"] in selected}
        with tempfile.TemporaryDirectory(dir="/work/tmp") as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            targets = []
            for index, path in enumerate(selected):
                target = repository / path
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(fixture_root / path, target)
                runner = repository / "runner" / f"runner-{index}.c"
                runner.parent.mkdir(exist_ok=True)
                symbol = symbols[path]
                runner.write_text(
                    f"void {symbol}(void); int main(void) {{ (void){symbol}(); return 0; }}\n",
                    encoding="utf-8",
                )
                targets.append(
                    f'add_executable(case_{index} "{path}" '
                    f'"runner/runner-{index}.c")\n'
                    f"add_test(NAME case_{index} COMMAND case_{index})"
                )
            (repository / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\nproject(asan_cases C)\nenable_testing()\n"
                + "\n".join(targets),
                encoding="utf-8",
            )
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            settings = SanitizerScanTests._settings(
                test_steps=(("ctest", "--test-dir", "build", "--output-on-failure"),),
                total_timeout_seconds=120,
            )
            with prepare_snapshot(import_root, "team/project", fingerprint, work_root) as snapshot:
                build = run_build_scan(snapshot, settings, sanitizer_enabled=True)
                result = run_sanitizer_scan(snapshot, settings, build.build_context)

        found = {(item.cwe, item.path, item.symbol) for item in result.findings}
        expected = {
            (item["cwe"], item["path"], item["symbol"])
            for item in manifest
            if item["path"] in selected and item["asan_expected"]
        }
        safe = {
            (item["cwe"], item["path"], item["symbol"])
            for item in manifest
            if item["path"] in selected and not item["vulnerable"]
        }
        print(f"uncovered ASan fixture identities: {sorted(expected - found)}")
        self.assertFalse(expected - found, f"diagnostics: {result.diagnostics}")
        self.assertTrue(found.isdisjoint(safe), f"safe identities reported: {found & safe}")
        self.assertTrue(
            all(
                item.verification_state == "confirmed" and item.fix == ""
                for item in result.findings
            )
        )


class SourceScanContainerTests(unittest.TestCase):
    def test_fixture_manifest_is_complete_and_semgrep_marks_only_candidates(self):
        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        manifest = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(24, len(manifest))
        self.assertTrue(
            all(
                set(item)
                == {
                    "id",
                    "cwe",
                    "path",
                    "symbol",
                    "vulnerable",
                    "allowed_layers",
                    "asan_expected",
                    "clang_expected",
                }
                for item in manifest
            )
        )
        self.assertEqual(
            {"CWE-787", "CWE-125", "CWE-416", "CWE-415"},
            {item["cwe"] for item in manifest},
        )
        semgrep_path = shutil.which("semgrep")
        if semgrep_path is None:
            self.skipTest("Semgrep is not installed on this host")

        completed = subprocess.run(  # noqa: S603 - fixed local Semgrep regression tool.
            [
                semgrep_path,
                "--json",
                "--quiet",
                "--config",
                str(Path("cxx_analyzer/rules/cxx-memory.yml").resolve()),
                ".",
            ],
            cwd=fixture_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
        if source_scan.recognized_host_semgrep_unavailability(
            completed.returncode, completed.stderr
        ):
            self.skipTest("Semgrep is installed but unavailable on this host")
        self.assertEqual(0, completed.returncode, completed.stderr)
        findings, _ = parse_semgrep_json(
            completed.stdout,
            {item["path"] for item in manifest},
        )
        self.assertTrue(all(item.verification_state == "candidate" for item in findings))
        hit_paths = {item.path for item in findings}
        self.assertTrue(all(item["path"] in hit_paths for item in manifest if item["vulnerable"]))
        self.assertTrue(
            all(item["path"] not in hit_paths for item in manifest if not item["vulnerable"])
        )


class SourceRuleTests(unittest.TestCase):
    def test_rules_tie_three_distinct_oob_shapes_to_known_object_bounds(self):
        import yaml

        rule_path = Path("cxx_analyzer/rules/cxx-memory.yml")
        rules = {item["id"]: item for item in yaml.safe_load(rule_path.read_text())["rules"]}
        oob_write = rules["cxx.source.oob-write.constant-index"]
        oob_text = str(oob_write["patterns"])
        self.assertIn("int $ARRAY[2]", oob_text)
        self.assertIn("malloc(sizeof(int) * 2)", oob_text)
        self.assertNotIn("$ARRAY[8] = $VALUE", oob_text)
        self.assertIn("std::array<int, 2>", oob_text)
        self.assertIn(
            "(int *)malloc(sizeof(int) * 2)",
            str(rules["cxx.source.oob-read.fixed-return"]["patterns"]),
        )

    def test_release_rules_exclude_same_pointer_rebinding_controls(self):
        import yaml

        rule_path = Path("cxx_analyzer/rules/cxx-memory.yml")
        rules = {item["id"]: item for item in yaml.safe_load(rule_path.read_text())["rules"]}
        uaf_text = str(
            rules["cxx.source.use-after-free.reused-pointer"]["patterns"][1]["pattern-either"]
        )
        double_free_text = str(
            rules["cxx.source.double-free.same-pointer"]["patterns"][1]["pattern-either"]
        )
        self.assertIn("pattern-not", uaf_text)
        self.assertIn("$PTR = ...", uaf_text)
        self.assertIn("pattern-not", double_free_text)
        self.assertIn("$PTR = ...", double_free_text)
        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        for relative_path, rebind in (
            ("cwe-416/safe-1.c", "data = malloc"),
            ("cwe-416/safe-2.cpp", "data = new int"),
            ("cwe-416/safe-3.cpp", "data = static_cast"),
            ("cwe-415/safe-1.c", "data = malloc"),
            ("cwe-415/safe-2.cpp", "data = new int"),
            ("cwe-415/safe-3.cpp", "data = static_cast"),
        ):
            with self.subTest(path=relative_path):
                self.assertIn(
                    rebind,
                    (fixture_root / relative_path).read_text(encoding="utf-8"),
                )


if __name__ == "__main__":
    unittest.main()
