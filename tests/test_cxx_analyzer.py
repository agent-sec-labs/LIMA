import copy
import hashlib
import http.client
import io
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

import cxx_analyzer.repro as repro
import cxx_analyzer.server as analyzer_server
import cxx_analyzer.source_scan as source_scan
from cxx_analyzer.config import AnalyzerSettings, parse_steps_json
from cxx_analyzer.deadline import AnalysisDeadline, AnalysisDeadlineExceeded
from cxx_analyzer.execution import (
    CLEAN_ENVIRONMENT,
    SANITIZER_ENVIRONMENT,
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
        "b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250"
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

        self.assertFalse(settings.auto_cmake)
        self.assertFalse(settings.trusted_build_context_generation)
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
            "LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION": "true",
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
        self.assertTrue(settings.trusted_build_context_generation)
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
            ("LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION", "sometimes"),
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
                # Inline-implementation headers must be inventoried and
                # copied into isolated snapshots (real ResInsight finding:
                # a missing cvfObject.inl broke every prepared TU).
                "src/detail.inl": "inline int f() { return 1; }\n",
                "src/detail.ipp": "inline int g() { return 2; }\n",
                "src/detail.tpp": "template <class T> int h() { return 3; }\n",
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
                    "src/detail.inl",
                    "src/detail.ipp",
                    "src/detail.tpp",
                    "src/main.cpp",
                ],
                sorted(snapshot.files),
            )
            self.assertEqual(
                sorted(snapshot.files),
                sorted(
                    path.relative_to(snapshot.root).as_posix()
                    for path in snapshot.root.rglob("*")
                    if path.is_file() and path.name != ".semgrepignore"
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

    def test_prepare_snapshot_disables_semgrep_default_ignore_table(self):
        """阶段 B 强制跟进项：生产快照必须自带 .semgrepignore。

        Semgrep applies its built-in default ignore table (tests/, doc/, ...)
        only when the scan root has no .semgrepignore. A production snapshot
        without the file would silently skip those directories while coverage
        still counts them, so the scan set and the verified inventory diverge.
        The prepared snapshot therefore carries a comment-only .semgrepignore
        that disables the default table without adding ignore patterns, and
        the file stays outside the inventory and its fingerprint.
        """

        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "src").mkdir()
            (repository / "src" / "main.c").write_text(
                "int main(void) { return 0; }\n", encoding="utf-8"
            )
            (repository / "tests").mkdir()
            (repository / "tests" / "regression.c").write_text(
                "int regression(void) { return 1; }\n", encoding="utf-8"
            )
            expected = RepositoryWorkspace(repository).inventory().fingerprint()

            snapshot = prepare_snapshot(import_root, "team/project", expected, work_root)
            self.addCleanup(snapshot.cleanup)

            ignore_path = snapshot.root / ".semgrepignore"
            self.assertTrue(ignore_path.is_file())
            self.assertNotIn(".semgrepignore", snapshot.files)
            content = ignore_path.read_text(encoding="utf-8")
            patterns = [
                line
                for line in content.splitlines()
                if line.strip() and not line.lstrip().startswith("#")
            ]
            self.assertEqual([], patterns)
            self.assertEqual(["src/main.c", "tests/regression.c"], sorted(snapshot.files))
            snapshot.verify_inventory()

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
                    request_deadline = AnalysisDeadline.start(30)
                    result = run_step(
                        ("cmake", "--version"),
                        snapshot,
                        "src",
                        timeout_seconds=17,
                        max_output_bytes=1024,
                        env={},
                        deadline=request_deadline,
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
        stream.assert_called_once_with(
            process,
            17,
            1024,
            absolute_deadline=request_deadline.expires_at,
        )

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
                "import pathlib,subprocess,sys; "
                f"child=subprocess.Popen([sys.executable,'-c',{child_code!r}]); "
                f"pathlib.Path({str(pid_file)!r}).write_text(str(child.pid))"
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
    def _settings(*, trusted_build_context_generation: bool = False) -> AnalyzerSettings:
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
            trusted_build_context_generation=trusted_build_context_generation,
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

    @patch("cxx_analyzer.server.sandbox.process_isolation_available", return_value=True)
    @patch("cxx_analyzer.server.sandbox.landlock_abi", return_value=4)
    @patch("cxx_analyzer.server.shutil.which")
    def test_health_discloses_only_probed_executability(
        self, which, _landlock, _isolation
    ):
        which.side_effect = lambda tool: "/usr/bin/" + tool

        status, payload = analyzer_server.dispatch_request(
            "GET", "/health", "", b"", self._settings()
        )

        self.assertEqual(200, status)
        self.assertEqual(
            {
                "schema_version": 1,
                "source_available": True,
                "build_available": False,
                "test_configured": False,
                "clang_c_available": True,
                "clang_cxx_available": True,
                "cmake_available": True,
                "landlock_available": True,
                "process_isolation_available": True,
                "trusted_build_context_generation_available": False,
            },
            payload,
        )

        # With the admin gate enabled the same probes report a usable build.
        status, payload = analyzer_server.dispatch_request(
            "GET",
            "/health",
            "",
            b"",
            self._settings(trusted_build_context_generation=True),
        )
        self.assertEqual(200, status)
        self.assertTrue(payload["build_available"])
        self.assertTrue(payload["trusted_build_context_generation_available"])

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
            producer_run_ids=("run-semgrep-1",),
        )
        source_scan_runner.return_value = LayerResult(
            (candidate,),
            (),
            ({"run_id": "run-semgrep-1", "tool": "semgrep", "status": "completed"},),
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
                    ({"run_id": f"run-{tool}", "tool": tool, "status": tool_status},),
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
                        {"run_id": "run-semgrep-1", "tool": "semgrep", "status": "completed"},
                        {"run_id": f"run-{tool}", "tool": tool, "status": tool_status},
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
            capability_fields = set(health) - {"schema_version"}
            self.assertEqual(9, len(capability_fields))
            self.assertTrue(
                all(type(health[field]) is bool for field in capability_fields)
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


def _tmpfs_options(specification: str) -> dict[str, str]:
    """Parse one Compose tmpfs spec, mapping valueless flags to empty strings."""

    options: dict[str, str] = {}
    for part in specification.split(":", 1)[1].split(","):
        key, _, value = part.partition("=")
        options[key] = value
    return options


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
                    "exec": "",
                    "size": "512m",
                    "mode": "0700",
                    "uid": "10002",
                    "gid": "10002",
                },
            },
            {
                str(item).split(":", 1)[0]: _tmpfs_options(str(item))
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
                        "--no-rewrite-rule-ids",
                        "--config",
                        call.args[0][5],
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
                self.assertFalse(Path(call.args[0][5]).resolve().is_relative_to(snapshot.root))
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
                "producer_run_ids",
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


class BoundsDirectionTests(unittest.TestCase):
    """The ArrayBoundV2 read/write classifier stays conservative or drops."""

    @staticmethod
    def direction(line: str, column: int):
        from cxx_analyzer.build_scan import _bounds_direction

        return _bounds_direction(line, column)

    @staticmethod
    def _column(line: str, marker: str, offset: int = 0) -> int:
        return line.index(marker, offset) + 1

    def test_simple_directions(self):
        write_line = "void f(void) { int values[2] = {0}; values[2] = 1; }"
        read_line = "int f(void) { int values[2] = {0}; return values[2]; }"
        for line, column, expected in (
            (write_line, self._column(write_line, "values", 30), "write"),
            (read_line, self._column(read_line, "values", 30), "read"),
            ("x = values[2];", 5, "read"),
            ("values[2] += 1;", 1, "write"),
            ("values[2]++;", 1, "write"),
            ("++values[2];", 3, "write"),
            ("values[2] = 1 + values[0];", 1, "write"),
        ):
            with self.subTest(line=line):
                self.assertEqual(expected, self.direction(line, column))

    def test_ambiguous_shapes_are_dropped(self):
        for line, column in (
            ("values[2] <<= 1;", 1),          # shift assignment
            ("if (values[2] == 3) { go(); }", 5),  # brackets after expression
            ("use(values[2], 1);", 5),         # argument position
            ("int r = f(values[2], (x = 1));", 13),
            ("values[2] +", 1),                # statement continues past line
            ("return values[2] +", 8),
            ("return value;", 8),              # no subscript at all
        ):
            with self.subTest(line=line):
                self.assertIsNone(self.direction(line, column))

    def test_reads_survive_common_shapes(self):
        for line, column in (
            ("int *p = &values[2];", 11),
            ("x <<= values[2];", 8),
            ("return values[2];", 8),
        ):
            with self.subTest(line=line):
                self.assertEqual("read", self.direction(line, column))


class BuildScanTests(unittest.TestCase):
    @staticmethod
    def _settings(
        *,
        auto_cmake=True,
        build_steps=(),
        total_timeout_seconds=90,
        trusted_build_context_generation=False,
    ):
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
            trusted_build_context_generation=trusted_build_context_generation,
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
        # Adapter selection is not authorization: without the admin trust
        # gate the CMake plan is empty and never falls back to build_steps.
        self.assertEqual((), select_build_steps(cmake_snapshot, self._settings()))
        with patch(
            "cxx_analyzer.build_scan.trust.generation_allowed", return_value=True
        ):
            self.assertEqual(
                _expected_cmake_steps(),
                select_build_steps(
                    cmake_snapshot,
                    self._settings(trusted_build_context_generation=True),
                ),
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
                with patch(
                    "cxx_analyzer.build_scan.trust.generation_allowed",
                    return_value=True,
                ):
                    result = run_build_scan(
                        snapshot,
                        self._settings(trusted_build_context_generation=True),
                    )
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

        with patch(
            "cxx_analyzer.build_scan.trust.generation_allowed", return_value=True
        ):
            result = run_build_scan(
                snapshot,
                self._settings(trusted_build_context_generation=True),
                sanitizer_enabled=True,
            )

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

            command_source = str(source).replace("\\", "/")
            cmake_style = [
                {
                    "directory": str(root),
                    "file": str(source),
                    "command": f"clang++ -c -DDEBUG=1 {command_source}",
                }
            ]
            database.write_text(json.dumps(cmake_style), encoding="utf-8")
            converted = load_compilation_database(snapshot, database)
            self.assertEqual(
                cmake_style[0]["command"].split(), list(converted[0].arguments)
            )

            invalid_entries = (
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "command": 'clang++ -c "unterminated',
                    }
                ],
                [
                    {
                        "directory": str(root),
                        "file": str(source),
                        "command": "clang++ -c /definitely/outside/escape.cpp",
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
                "int write_value(void)\n"
                "{\n"
                "    int values[2];\n"
                "\n"
                "      values[2] = 1;\n"
                "    return 0;\n"
                "}\n",
                encoding="utf-8",
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
                "void oob_write_array(void) { int values[2] = {0}; values[2] = 1; }\n",
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
                with patch(
                    "cxx_analyzer.build_scan.trust.generation_allowed",
                    return_value=True,
                ):
                    result = build_scan.run_build_scan(
                        snapshot,
                        self._settings(trusted_build_context_generation=True),
                    )

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
                            "file": str(root.parent / "escape.cpp"),
                            "arguments": ["cc", "-c", str(root.parent / "escape.cpp")],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            run_tool.reset_mock()
            run_tool.side_effect = [self._execution(), self._execution()]
            with patch.object(build_scan, "_ANALYZER_TEMP_ROOT", temp_root):
                with patch(
                    "cxx_analyzer.build_scan.trust.generation_allowed",
                    return_value=True,
                ):
                    rejected = build_scan.run_build_scan(
                        snapshot,
                        self._settings(trusted_build_context_generation=True),
                    )
            self.assertEqual(2, run_tool.call_count)
        self.assertEqual(("compile-commands-rejected",), rejected.diagnostics)


class TrustedGenerationGateTests(unittest.TestCase):
    """Task 0: untrusted CMake execution sits behind the admin trust gate."""

    @staticmethod
    def _settings(**changes: object) -> AnalyzerSettings:
        values: dict[str, object] = {
            "auto_cmake": True,
            "build_steps": (),
            "test_steps": (),
            "max_memory_mb": 1024,
            "max_processes": 32,
            "max_output_bytes": 8192,
            "step_timeout_seconds": 17,
            "total_timeout_seconds": 90,
            "repository_scan_max_files": 100,
            "repository_scan_max_file_bytes": 4096,
            "repository_scan_max_total_bytes": 16384,
        }
        values.update(changes)
        return AnalyzerSettings(**values)  # type: ignore[arg-type]

    @staticmethod
    def _all_probes_true() -> list:
        probes = (
            "landlock_available",
            "process_isolation_available",
            "running_as_non_root",
            "network_isolated",
            "snapshot_mount_readonly",
        )
        return [
            patch(f"cxx_analyzer.trust.{probe}", return_value=True)
            for probe in probes
        ]

    def test_default_config_does_not_execute_cmake_for_cmake_lists_snapshot(self):
        from cxx_analyzer.build_scan import run_build_scan, select_build_steps

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\n"
                "execute_process(COMMAND touch pwned-marker.txt)\n",
                encoding="utf-8",
            )
            snapshot = Mock(root=root, files=("CMakeLists.txt", "src/main.cpp"))

            with patch.dict(os.environ, {}, clear=True):
                settings = AnalyzerSettings.from_env()
            self.assertFalse(settings.auto_cmake)
            self.assertFalse(settings.trusted_build_context_generation)
            self.assertEqual((), select_build_steps(snapshot, settings))

            def hostile_side_effect(argv, *args, **kwargs):
                (root / "pwned-marker.txt").write_text("side effect", encoding="utf-8")
                return BuildScanTests._execution()

            with patch(
                "cxx_analyzer.build_scan.run_step",
                side_effect=hostile_side_effect,
            ) as run_tool:
                result = run_build_scan(snapshot, settings)
            self.assertEqual(("build-not-configured",), result.diagnostics)
            self.assertEqual(0, run_tool.call_count)
            self.assertFalse((root / "pwned-marker.txt").exists())

            # Gate open (admin switch plus every probe mocked true) selects
            # the fixed CMake argv adapter; nothing has executed yet here.
            trusted = self._settings(trusted_build_context_generation=True)
            with patch(
                "cxx_analyzer.build_scan.trust.generation_allowed",
                return_value=True,
            ):
                self.assertEqual(
                    _expected_cmake_steps(), select_build_steps(snapshot, trusted)
                )

    def test_auto_cmake_true_alone_cannot_enable_generation(self):
        from cxx_analyzer import trust
        from cxx_analyzer.build_scan import select_build_steps

        snapshot = Mock(files=("CMakeLists.txt", "src/main.cpp"))
        settings = self._settings(
            auto_cmake=True, trusted_build_context_generation=False
        )
        enabled = self._all_probes_true()
        for active in enabled:
            active.start()
        try:
            # Even with every machine capability present, the admin-level
            # switch alone authorizes generation; auto_cmake never does.
            self.assertFalse(trust.generation_allowed(settings))
            self.assertEqual((), select_build_steps(snapshot, settings))
        finally:
            for active in enabled:
                active.stop()

    def test_missing_any_isolation_capability_fails_closed(self):
        from cxx_analyzer import trust
        from cxx_analyzer.build_scan import select_build_steps

        probes = (
            "landlock_available",
            "process_isolation_available",
            "running_as_non_root",
            "network_isolated",
            "snapshot_mount_readonly",
        )
        snapshot = Mock(files=("CMakeLists.txt",))
        settings = self._settings(
            auto_cmake=True, trusted_build_context_generation=True
        )
        for missing in probes:
            with self.subTest(missing=missing):
                active_patches = [
                    patch(
                        f"cxx_analyzer.trust.{probe}",
                        return_value=probe != missing,
                    )
                    for probe in probes
                ]
                for active in active_patches:
                    active.start()
                try:
                    self.assertFalse(trust.generation_allowed(settings))
                    self.assertEqual((), select_build_steps(snapshot, settings))
                finally:
                    for active in active_patches:
                        active.stop()

    def test_compose_static_guarantees_documented(self):
        from cxx_analyzer import trust

        self.assertEqual(
            frozenset(
                {
                    "snapshot-and-import-mounts-are-read-only",
                    "no-docker-socket-host-path-or-credential-mounts",
                    "scratch-and-build-directories-are-ephemeral-tmpfs",
                    "cpu-memory-pid-output-filesize-and-wallclock-limits-configured",
                }
            ),
            trust.COMPOSE_STATIC_GUARANTEES,
        )
        module_documentation = trust.__doc__ or ""
        self.assertIn("machine-provable", module_documentation.lower())
        for guarantee in trust.COMPOSE_STATIC_GUARANTEES:
            self.assertIn(guarantee, module_documentation)


class BuildScanContainerTests(unittest.TestCase):
    def test_build_backed_fixture_coverage_lists_every_uncovered_identity(self):
        if sys.platform != "linux":
            self.skipTest("build-backed container regression requires Linux")
        if shutil.which("cmake") is None or shutil.which("clang-14") is None:
            self.skipTest("CMake and clang-14 are required for build-backed fixtures")

        import cxx_analyzer.build_scan as build_scan

        fixture_root = Path(__file__).parent / "fixtures" / "cxx_memory"
        manifest = json.loads((fixture_root / "manifest.json").read_text(encoding="utf-8"))
        try:
            Path("/work/tmp").mkdir(parents=True, exist_ok=True)
        except OSError:
            self.skipTest("requires a writable container work root")
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
                # No analyzer temp root override: plists must be staged in the
                # sandbox-writable scratch, exactly like production. The
                # coverage run exercises the administrator-trusted generation
                # path; the default-off gate itself is covered by
                # TrustedGenerationContainerTests.
                result = build_scan.run_build_scan(
                    snapshot,
                    BuildScanTests._settings(trusted_build_context_generation=True),
                )

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


class TrustedGenerationContainerTests(unittest.TestCase):
    def test_default_container_runs_no_cmake(self):
        if sys.platform != "linux":
            self.skipTest("trusted-generation container regression requires Linux")
        if shutil.which("cmake") is None or shutil.which("clang-14") is None:
            self.skipTest("CMake and clang-14 are required for the container fixture")

        import cxx_analyzer.build_scan as build_scan

        try:
            Path("/work/tmp").mkdir(parents=True, exist_ok=True)
        except OSError:
            self.skipTest("requires a writable container work root")
        with tempfile.TemporaryDirectory(dir="/work/tmp") as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            (repository / "src").mkdir()
            (repository / "src" / "main.cpp").write_text(
                "int main() { return 0; }\n", encoding="utf-8"
            )
            (repository / "CMakeLists.txt").write_text(
                "cmake_minimum_required(VERSION 3.16)\n"
                "execute_process(COMMAND touch ${CMAKE_SOURCE_DIR}/pwned-marker.txt)\n",
                encoding="utf-8",
            )
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with patch.dict(os.environ, {}, clear=True):
                settings = AnalyzerSettings.from_env()
            with prepare_snapshot(
                import_root, "team/project", fingerprint, work_root
            ) as snapshot:
                result = build_scan.run_build_scan(snapshot, settings)
                marker = snapshot.root.joinpath("pwned-marker.txt")

        self.assertEqual(("build-not-configured",), result.diagnostics)
        self.assertEqual((), result.tool_runs)
        self.assertFalse(marker.exists())


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
        candidate = candidate.bind_producer("run-semgrep")
        confirmed = confirmed.bind_producer("run-asan")
        source_runner.return_value = LayerResult(
            (candidate,),
            (),
            ({"run_id": "run-semgrep", "tool": "semgrep", "status": "completed"},),
        )
        context = BuildContext(snapshot.root, snapshot.files, sanitizer_enabled=True)
        build_runner.return_value = LayerResult((), (), (), context)
        sanitizer_runner.return_value = LayerResult(
            (confirmed,),
            (),
            ({"run_id": "run-asan", "tool": "asan-test", "status": "completed"},),
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
                {"run_id": "run-semgrep", "tool": "semgrep", "status": "completed"},
                {"run_id": "run-asan", "tool": "asan-test", "status": "completed"},
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
            producer_run_ids=("run-asan",),
        )
        with patch.object(analyzer_server, "MAX_FINDINGS", 1):
            with patch.object(analyzer_server, "MAX_DIAGNOSTICS", 1):
                with patch.object(analyzer_server, "MAX_TOOL_RUNS", 1):
                    findings, diagnostics, tool_runs = analyzer_server._bound_response_lists(
                        (low, high),
                        ["source", "asan"],
                        [
                            {"run_id": "run-semgrep", "tool": "semgrep", "status": "completed"},
                            {"run_id": "run-asan", "tool": "asan-test", "status": "completed"},
                        ],
                    )
        self.assertEqual((high,), findings)
        self.assertEqual(("analysis-budget-exhausted",), diagnostics)
        self.assertEqual(
            ({"run_id": "run-asan", "tool": "asan-test", "status": "completed"},),
            tool_runs,
        )


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
        try:
            Path("/work/tmp").mkdir(parents=True, exist_ok=True)
        except OSError:
            self.skipTest("requires a writable container work root")
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
            import dataclasses

            settings = dataclasses.replace(
                SanitizerScanTests._settings(
                    test_steps=(("ctest", "--test-dir", "build", "--output-on-failure"),),
                    total_timeout_seconds=240,
                ),
                auto_cmake=True,
                build_steps=(),
                step_timeout_seconds=90,
                max_output_bytes=1_048_576,
                trusted_build_context_generation=True,
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
                "--no-rewrite-rule-ids",
                "--config",
                str(Path("cxx_analyzer/rules/cxx-memory.yml").resolve()),
                ".",
            ],
            cwd=fixture_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            env={**os.environ, "HOME": tempfile.gettempdir()},
        )
        if source_scan.recognized_host_semgrep_unavailability(
            completed.returncode, completed.stderr
        ):
            self.skipTest("Semgrep is installed but unavailable on this host")
        self.assertEqual(0, completed.returncode, completed.stderr)
        # Windows host Semgrep emits OS separators in result paths while the
        # analyzer contract (and the Linux Sidecar) only accepts posix paths.
        document = json.loads(completed.stdout)
        for result in document["results"]:
            result["path"] = result["path"].replace("\\", "/")
        findings, _ = parse_semgrep_json(
            json.dumps(document),
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


class BuildContextResolverTests(unittest.TestCase):
    """Task 3: the build context resolver pins compile semantics fail-closed.

    Red lines under test: the default path never generates a compilation
    database (no CMake/Make/script execution), trusted generation stays
    configure-only and is unimplemented (``unavailable``), a heuristic
    context is always ``incomplete`` and can never reach ``fact-verified``,
    and repository compiler argv is filtered with explicit rejections
    (response files, plugins, path escapes) instead of being trusted.
    """

    _FIXTURES = Path(__file__).parent / "fixtures" / "uaf_build_context"

    # The five machine-provable capability names frozen by Task 0
    # (cxx_analyzer.trust.build_generation_capabilities).
    _CAPABILITY_NAMES = (
        "landlock",
        "process_isolation",
        "non_root",
        "network_isolated",
        "snapshot_readonly",
    )

    def _settings(self, **changes: object) -> AnalyzerSettings:
        values: dict[str, object] = {
            "auto_cmake": True,
            "build_steps": (),
            "test_steps": (),
            "max_memory_mb": 1024,
            "max_processes": 32,
            "max_output_bytes": 8192,
            "step_timeout_seconds": 17,
            "total_timeout_seconds": 90,
            "repository_scan_max_files": 100,
            "repository_scan_max_file_bytes": 4096,
            "repository_scan_max_total_bytes": 16384,
            "trusted_build_context_generation": False,
        }
        values.update(changes)
        return AnalyzerSettings(**values)

    def _fixture(self, name: str) -> Path:
        """Copy a static fixture into a private temporary snapshot root."""

        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "snapshot"
        shutil.copytree(self._FIXTURES / name, root)
        return root

    @staticmethod
    def _file_set(root: Path) -> list[str]:
        return sorted(
            path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
        )

    @staticmethod
    def _expected_context_hash(
        translation_unit: str, semantic_arguments: list[str], workdir: str = "."
    ) -> str:
        material = {
            "tu": translation_unit,
            "source_kind": "repository-compdb",
            "args": semantic_arguments,
            "workdir": workdir,
        }
        encoded = json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def _all_capabilities(self) -> dict[str, bool]:
        return {name: True for name in self._CAPABILITY_NAMES}

    def test_default_paths_never_generate_compdb(self):
        from cxx_analyzer.build_context import resolve_build_context

        cases = (
            ("default settings", self._settings(), None),
            (
                "untrusted gate with full capabilities",
                self._settings(trusted_build_context_generation=False),
                self._all_capabilities(),
            ),
            (
                "trusted gate without the cmake adapter selection",
                self._settings(trusted_build_context_generation=True, auto_cmake=False),
                self._all_capabilities(),
            ),
        )
        for description, settings, capabilities in cases:
            with self.subTest(case=description):
                root = self._fixture("evil-cmake")
                before = self._file_set(root)
                resolution = resolve_build_context(root, "src/main.c", settings, capabilities)
                self.assertEqual("incomplete", resolution.status)
                self.assertEqual("heuristic", resolution.source_kind)
                self.assertEqual(("heuristic-context",), resolution.diagnostics)
                self.assertNotIn(
                    "generation-not-implemented-in-this-task", resolution.diagnostics
                )
                self.assertEqual(before, self._file_set(root))
                self.assertFalse((root / "pwned.txt").exists())

    def test_trusted_generation_requires_all_capabilities(self):
        from cxx_analyzer.build_context import resolve_build_context

        for missing in self._CAPABILITY_NAMES:
            with self.subTest(missing_capability=missing):
                capabilities = self._all_capabilities()
                capabilities[missing] = False
                root = self._fixture("evil-cmake")
                resolution = resolve_build_context(
                    root,
                    "src/main.c",
                    self._settings(trusted_build_context_generation=True),
                    capabilities,
                )
                # Any missing capability fails closed: the generation path is
                # not entered and the plain heuristic fallback applies.
                self.assertEqual("incomplete", resolution.status)
                self.assertEqual("heuristic", resolution.source_kind)
                self.assertNotIn(
                    "generation-not-implemented-in-this-task", resolution.diagnostics
                )
        root = self._fixture("evil-cmake")
        resolution = resolve_build_context(
            root,
            "src/main.c",
            self._settings(trusted_build_context_generation=True),
            self._all_capabilities(),
        )
        self.assertEqual("unavailable", resolution.status)
        self.assertEqual("cmake-export", resolution.source_kind)

    def test_cmake_adapter_configures_only_no_build(self):
        from cxx_analyzer import build_context
        from cxx_analyzer.build_context import resolve_build_context

        self.assertIs(True, build_context.GENERATION_CONFIGURE_ONLY)
        self.assertIn(
            "GENERATION_CONFIGURE_ONLY",
            build_context.resolve_build_context.__doc__ or "",
        )
        self.assertIn("configure-only", build_context.resolve_build_context.__doc__ or "")

        root = self._fixture("evil-cmake")
        before = self._file_set(root)
        resolution = resolve_build_context(
            root,
            "src/main.c",
            self._settings(trusted_build_context_generation=True),
            self._all_capabilities(),
        )
        self.assertEqual("unavailable", resolution.status)
        self.assertEqual("cmake-export", resolution.source_kind)
        self.assertIn("generation-not-implemented-in-this-task", resolution.diagnostics)
        self.assertEqual("", resolution.context_hash)
        self.assertEqual(before, self._file_set(root))
        self.assertFalse((root / "pwned.txt").exists())

        # Without CMakeLists.txt but with another build system present, the
        # adapter tier is the build-adapter source kind; still unavailable.
        (root / "CMakeLists.txt").unlink()
        (root / "Makefile").write_text("all:\n\ttrue\n", encoding="utf-8")
        adapter = resolve_build_context(
            root,
            "src/main.c",
            self._settings(trusted_build_context_generation=True),
            self._all_capabilities(),
        )
        self.assertEqual("unavailable", adapter.status)
        self.assertEqual("build-adapter", adapter.source_kind)
        self.assertIn("generation-not-implemented-in-this-task", adapter.diagnostics)

    def test_root_and_build_dir_compdb_priority(self):
        from cxx_analyzer.build_context import resolve_build_context

        root = self._fixture("ok")
        baseline = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("resolved", baseline.status)

        build_dir = root / "build"
        build_dir.mkdir()
        build_entry = {
            "directory": ".",
            "file": "src/main.c",
            "arguments": [
                "clang",
                "-c",
                "-DBUILD_LAYER=1",
                "-std=c99",
                "src/main.c",
                "-o",
                "build/main.o",
            ],
        }
        (build_dir / "compile_commands.json").write_text(
            json.dumps([build_entry]), encoding="utf-8"
        )
        with_build = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("resolved", with_build.status)
        # build/compile_commands.json wins over the root database.
        self.assertEqual(
            self._expected_context_hash("src/main.c", ["-DBUILD_LAYER=1", "-std=c99"]),
            with_build.context_hash,
        )
        self.assertNotEqual(baseline.context_hash, with_build.context_hash)

        # Removing the losing root database does not change the resolution.
        (root / "compile_commands.json").unlink()
        without_root = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual(with_build.context_hash, without_root.context_hash)

    def test_unique_subdirectory_compdb(self):
        from cxx_analyzer.build_context import resolve_build_context

        root = self._fixture("nested-unique")
        resolution = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("resolved", resolution.status)
        self.assertEqual("repository-compdb", resolution.source_kind)
        self.assertEqual(
            self._expected_context_hash("src/main.c", ["-DNESTED=1"]),
            resolution.context_hash,
        )
        self.assertEqual((), resolution.diagnostics)

    def test_ambiguous_tu_entries_are_incomplete(self):
        from cxx_analyzer.build_context import resolve_build_context

        root = self._fixture("ambiguous")
        resolution = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("incomplete", resolution.status)
        self.assertEqual("repository-compdb", resolution.source_kind)
        self.assertIn("ambiguous-tu-entry", resolution.diagnostics)
        self.assertEqual("", resolution.context_hash)

    def test_response_file_and_escape_arguments_rejected(self):
        from cxx_analyzer.build_context import resolve_build_context, validate_compiler_argv

        root = self._fixture("escape-args")
        cases = {
            "src/a.c": "path-escapes-snapshot",
            "src/b.c": "response-file-forbidden",
            "src/c.c": "forbidden-passthrough-option",
        }
        for translation_unit, expected_rejection in cases.items():
            with self.subTest(translation_unit=translation_unit):
                resolution = resolve_build_context(root, translation_unit, self._settings())
                self.assertEqual("incomplete", resolution.status)
                self.assertEqual("repository-compdb", resolution.source_kind)
                self.assertIn(expected_rejection, resolution.diagnostics)
                self.assertEqual("", resolution.context_hash)

        # The shared pure validator used by the build scan layer agrees.
        normalized, rejections = validate_compiler_argv(
            ["clang", "-c", "@resp.rsp", "src/b.c"]
        )
        self.assertEqual([], normalized)
        self.assertIn("response-file-forbidden", rejections)
        normalized, rejections = validate_compiler_argv(
            ["clang", "-c", "../escape.h"],
            root=root,
            working_directory=root,
        )
        self.assertEqual([], normalized)
        self.assertIn("path-escapes-snapshot", rejections)
        normalized, rejections = validate_compiler_argv(["clang", "-c", "-Xclang", "-load"])
        self.assertEqual([], normalized)
        self.assertIn("forbidden-passthrough-option", rejections)

    def test_missing_generated_header_is_incomplete(self):
        from cxx_analyzer.build_context import resolve_build_context

        root = self._fixture("missing-generated-header")
        resolution = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("incomplete", resolution.status)
        self.assertEqual("repository-compdb", resolution.source_kind)
        self.assertIn("missing-referenced-path", resolution.diagnostics)
        self.assertEqual("", resolution.context_hash)

    def test_heuristic_is_already_incomplete_and_forbids_fact_verified(self):
        from cxx_analyzer.build_context import (
            heuristic_compiler_argv,
            resolve_build_context,
        )
        from lima.uaf_models import ExtractionCoverage, proof_readiness

        root = self._fixture("evil-cmake")
        resolution = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("incomplete", resolution.status)
        self.assertEqual("heuristic", resolution.source_kind)
        self.assertIn("heuristic-context", resolution.diagnostics)
        self.assertEqual("", resolution.context_hash)
        readiness = proof_readiness(
            resolution,
            ExtractionCoverage(ast_complete=True, cfg_complete=True),
            False,
        )
        self.assertIs(False, readiness.complete)

        self.assertEqual(
            ("clang-14", "-fsyntax-only", "src/main.c"),
            heuristic_compiler_argv("src/main.c"),
        )
        self.assertEqual(
            ("clang++-14", "-fsyntax-only", "src/b.cpp"),
            heuristic_compiler_argv("src/b.cpp"),
        )

    def test_context_hash_stable_and_sensitive_to_semantic_flags(self):
        from cxx_analyzer.build_context import resolve_build_context

        root = self._fixture("ok")
        database_path = root / "compile_commands.json"
        document = json.loads(database_path.read_text(encoding="utf-8"))

        def rewrite(arguments: list[str]) -> None:
            document[0]["arguments"] = arguments
            database_path.write_text(json.dumps(document), encoding="utf-8")

        original = list(document[0]["arguments"])
        first = resolve_build_context(root, "src/main.c", self._settings())
        second = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("resolved", first.status)
        self.assertEqual(first.context_hash, second.context_hash)
        self.assertEqual(
            self._expected_context_hash(
                "src/main.c", ["-I", "include", "-DFOO=1", "-std=c11"]
            ),
            first.context_hash,
        )

        # Changing the language standard is a semantic change.
        rewritten = list(original)
        rewritten[rewritten.index("-std=c11")] = "-std=c99"
        rewrite(rewritten)
        changed_standard = resolve_build_context(root, "src/main.c", self._settings())
        self.assertNotEqual(first.context_hash, changed_standard.context_hash)

        # Changing output artifacts is not.
        rewrite(original)
        output_only = list(original)
        output_only[output_only.index("-o") + 1] = "build/other.o"
        rewrite(output_only)
        changed_output = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual(first.context_hash, changed_output.context_hash)

        # Adding a non-semantic optimization flag is not either.
        with_optimization = [*original, "-O2"]
        rewrite(with_optimization)
        unchanged = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual(first.context_hash, unchanged.context_hash)

        # Macro vocabulary is semantic on both sides (-D/-U).
        with_undefine = [*original, "-UFOO"]
        rewrite(with_undefine)
        changed_macro = resolve_build_context(root, "src/main.c", self._settings())
        self.assertNotEqual(first.context_hash, changed_macro.context_hash)

    def test_command_string_form_parsed_via_shlex(self):
        from cxx_analyzer.build_context import resolve_build_context

        root = self._fixture("command-string")
        resolution = resolve_build_context(root, "src/main.c", self._settings())
        self.assertEqual("resolved", resolution.status)
        self.assertEqual("repository-compdb", resolution.source_kind)
        self.assertEqual(
            self._expected_context_hash("src/main.c", ["-DFOO=1", "-std=c11"]),
            resolution.context_hash,
        )
        self.assertEqual((), resolution.diagnostics)

    def test_build_scan_behavior_unchanged_after_extraction(self):
        from cxx_analyzer import build_context, build_scan

        # The build scan layer reuses the extracted search verbatim.
        self.assertIs(build_context.find_compile_databases, build_scan.find_compile_databases)

        scenarios = (
            # (description, with build/, with root database, extra subdirectories,
            #  expected priority order)
            (
                "build-root-and-two-subdirs",
                True,
                True,
                ("out1", "out2"),
                ["build/compile_commands.json", "compile_commands.json"],
            ),
            (
                "build-root-and-unique-subdir",
                True,
                True,
                ("out1",),
                [
                    "build/compile_commands.json",
                    "compile_commands.json",
                    "out1/compile_commands.json",
                ],
            ),
            (
                "root-and-unique-subdir",
                False,
                True,
                ("out1",),
                ["compile_commands.json", "out1/compile_commands.json"],
            ),
            (
                "root-and-two-subdirs-glob-ambiguous",
                False,
                True,
                ("out1", "out2"),
                ["compile_commands.json"],
            ),
            (
                "build-and-root-only",
                True,
                True,
                (),
                ["build/compile_commands.json", "compile_commands.json"],
            ),
            (
                "build-only-no-root-database",
                True,
                False,
                (),
                ["build/compile_commands.json"],
            ),
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name, with_build, with_root, subdirectories, expected in scenarios:
                with self.subTest(scenario=name):
                    directories = (
                        (*subdirectories, "build") if with_build else subdirectories
                    )
                    for directory in directories:
                        (root / directory).mkdir(exist_ok=True)
                        (root / directory / "compile_commands.json").write_text(
                            "[]", encoding="utf-8"
                        )
                    if with_root:
                        (root / "compile_commands.json").write_text("[]", encoding="utf-8")
                    actual = build_context.find_compile_databases(root)
                    self.assertEqual(
                        expected,
                        [path.relative_to(root).as_posix() for path in actual],
                    )
                    snapshot = Mock(root=root)
                    self.assertEqual(
                        actual[0] if actual else None,
                        build_scan._find_database(snapshot),
                    )
                    for directory in dict.fromkeys(directories):
                        shutil.rmtree(root / directory)
                    if with_root:
                        (root / "compile_commands.json").unlink()


# --------------------------------------------------------------------------
# UAF v2 Task 4: AST / restricted-CFG fact extraction
# --------------------------------------------------------------------------
# Host tests drive the pure extractor over minimal mock AST JSON built with
# the ``_ast_*`` helpers (only the fields the extractor reads).  Clang is
# never executed on the host: ``extract_ast_json`` is exercised against a
# mocked ``execution.run_step``.  The container class at the end runs the
# real clang-14 inside the analyzer container and asserts semantics only.

_UAF_FIXTURES = Path(__file__).parent / "fixtures" / "uaf_v2"


def _ast_loc(line, col, toklen=1):
    return {
        "offset": (line - 1) * 100 + col,
        "line": line,
        "col": col,
        "tokLen": toklen,
    }


def _ast_range(begin, end=None):
    end = end or begin
    return {"begin": _ast_loc(*begin), "end": _ast_loc(*end)}


def _ast_node(kind, inner=None, rng=None, **attrs):
    node = {"kind": kind}
    if rng is not None:
        node["loc"] = dict(rng["begin"])
        node["range"] = rng
    node.update(attrs)
    if inner is not None:
        node["inner"] = list(inner)
    return node


def _ast_decl_ref(name, qual="int *", rng=None):
    return _ast_node(
        "DeclRefExpr",
        rng=rng,
        referencedDecl={"kind": "VarDecl", "name": name},
        type={"qualType": qual},
    )


def _ast_new_expr(rng, *, array=False):
    attrs = {"type": {"qualType": "int *"}}
    if array:
        attrs["isArray"] = True
    return _ast_node("CXXNewExpr", rng=rng, **attrs)


def _ast_delete_expr(name, rng):
    return _ast_node(
        "CXXDeleteExpr", rng=rng, inner=[_ast_decl_ref(name)], type={"qualType": "void"}
    )


def _ast_deref(name, rng):
    return _ast_node(
        "UnaryOperator",
        rng=rng,
        opcode="*",
        type={"qualType": "int"},
        inner=[_ast_decl_ref(name)],
    )


def _ast_member_arrow(name, rng):
    return _ast_node(
        "MemberExpr",
        rng=rng,
        isArrow=True,
        type={"qualType": "int"},
        inner=[_ast_decl_ref(name)],
    )


def _ast_call(callee_name, arguments, rng, *, callee_kind="FunctionDecl"):
    if callee_name is None:
        callee = _ast_node(
            "DeclRefExpr", rng=rng, type={"qualType": "void (*())(int *)"}
        )
    else:
        callee = _ast_node(
            "DeclRefExpr",
            rng=rng,
            referencedDecl={"kind": callee_kind, "name": callee_name},
            type={"qualType": "void (int *)"},
        )
    return _ast_node(
        "CallExpr",
        rng=rng,
        type={"qualType": "void"},
        inner=[_ast_node("ImplicitCastExpr", inner=[callee]), *arguments],
    )


def _ast_assign(lhs, rhs, rng):
    return _ast_node(
        "BinaryOperator",
        rng=rng,
        opcode="=",
        type={"qualType": "int *"},
        inner=[lhs, rhs],
    )


def _ast_decl_stmt(var_decls, rng):
    return _ast_node("DeclStmt", rng=rng, inner=list(var_decls))


def _ast_var_decl(name, qual, init=None, rng=None):
    return _ast_node(
        "VarDecl",
        rng=rng or _ast_range((1, 5)),
        name=name,
        type={"qualType": qual},
        inner=[init] if init is not None else None,
    )


def _ast_compound(stmts, rng=None):
    return _ast_node("CompoundStmt", rng=rng, inner=list(stmts))


def _ast_function(name, body, rng):
    return _ast_node(
        "FunctionDecl",
        rng=rng,
        name=name,
        type={"qualType": "void ()"},
        inner=[body],
    )


def _ast_if(cond, then_stmt, else_stmt=None, rng=None):
    inner = [cond, then_stmt] + ([else_stmt] if else_stmt is not None else [])
    return _ast_node("IfStmt", rng=rng, inner=inner)


def _ast_binary(opcode, lhs, rhs, rng, qual="int"):
    return _ast_node(
        "BinaryOperator",
        rng=rng,
        opcode=opcode,
        type={"qualType": qual},
        inner=[lhs, rhs],
    )


def _ast_paren(expr, rng):
    return _ast_node("ParenExpr", rng=rng, type={"qualType": "int *"}, inner=[expr])


def _ast_translation_unit(decls, *, diagnostics=None):
    unit = _ast_node("TranslationUnitDecl", inner=list(decls))
    if diagnostics is not None:
        unit["diagnostics"] = diagnostics
    return unit


def _fact_kinds(result):
    return [fact["kind"] for fact in result["facts"]]


def _facts_of_kind(result, kind):
    return [fact for fact in result["facts"] if fact["kind"] == kind]


def _walk_all(node):
    yield node
    for child in node.get("inner") or []:
        yield from _walk_all(child)


class _UafFakeResponse:
    def __init__(self, stream):
        self._stream = stream

    def read(self, size=-1):
        return self._stream.read(size)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        return False


REQUEST_ID_UAF = "00000000-0000-0000-0000-000000000004"


class UafFactExtractionTests(unittest.TestCase):
    """Task 4: UAF facts + restricted-CFG completeness over mock clang ASTs."""

    _TU = "src/new_delete_deref.cpp"

    def _extract(self, ast, tu=_TU, line_offsets=None):
        from cxx_analyzer import uaf_scan

        return uaf_scan.extract_uaf_facts(ast, tu, tu, line_offsets=line_offsets)

    # ------------------------------------------------------------ positives

    def test_new_delete_deref_facts(self):
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "use_after_free",
                    _ast_compound(
                        [
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "p",
                                        "int *",
                                        init=_ast_new_expr(_ast_range((2, 14))),
                                        rng=_ast_range((2, 5)),
                                    )
                                ],
                                rng=_ast_range((2, 5)),
                            ),
                            _ast_delete_expr("p", _ast_range((3, 5))),
                            _ast_deref("p", _ast_range((4, 5))),
                        ],
                        rng=_ast_range((1, 22), (5, 1)),
                    ),
                    rng=_ast_range((1, 1)),
                )
            ]
        )
        result = self._extract(ast)
        self.assertTrue(result["coverage"]["ast_complete"])
        self.assertTrue(result["coverage"]["cfg_complete"])
        self.assertEqual(["usr-synthesized"], result["coverage"]["semantic_gaps"])

        allocations = _facts_of_kind(result, "allocation")
        self.assertEqual(1, len(allocations))
        allocation = allocations[0]
        self.assertEqual("new", allocation["allocation_api"])
        self.assertEqual("p", allocation["pointer_id"])
        self.assertEqual([2, 2], allocation["source_range"])
        self.assertEqual(
            "src/new_delete_deref.cpp#use_after_free@1", allocation["function_usr"]
        )
        self.assertEqual(self._TU, allocation["translation_unit"])
        self.assertEqual(self._TU, allocation["canonical_path"])

        releases = _facts_of_kind(result, "release")
        self.assertEqual(1, len(releases))
        release = releases[0]
        self.assertEqual("delete", release["release_api"])
        self.assertEqual("p", release["pointer_id"])
        self.assertEqual([3, 3], release["source_range"])
        self.assertEqual([allocation["fact_id"]], release["related_fact_ids"])

        dereferences = _facts_of_kind(result, "dereference")
        self.assertEqual(1, len(dereferences))
        self.assertEqual("p", dereferences[0]["pointer_id"])
        self.assertEqual([4, 4], dereferences[0]["source_range"])

        self.assertEqual(
            ["allocation", "points-to", "release", "dereference"],
            _fact_kinds(result),
        )
        blocks = [fact["cfg_block"] for fact in result["facts"]]
        self.assertEqual(blocks, sorted(blocks))
        for fact in result["facts"]:
            self.assertRegex(fact["fact_id"], r"^[0-9a-f]{64}$")
        # Deterministic: identical ASTs produce identical fact ids.
        again = self._extract(ast)
        self.assertEqual(
            [fact["fact_id"] for fact in result["facts"]],
            [fact["fact_id"] for fact in again["facts"]],
        )

    def test_malloc_free_member_facts(self):
        malloc_call = _ast_call(
            "malloc", [_ast_decl_ref("item", qual="unsigned long")], _ast_range((8, 38))
        )
        cast = _ast_node(
            "CStyleCastExpr",
            rng=_ast_range((8, 21)),
            type={"qualType": "struct item *"},
            inner=[malloc_call],
        )
        member_read = _ast_assign(
            _ast_member_arrow("p", _ast_range((9, 5))),
            _ast_node(
                "IntegerLiteral", rng=_ast_range((9, 16)), type={"qualType": "int"}
            ),
            _ast_range((9, 5)),
        )
        free_call = _ast_call("free", [_ast_decl_ref("p")], _ast_range((10, 5)))
        member_write = _ast_assign(
            _ast_member_arrow("p", _ast_range((11, 5))),
            _ast_node(
                "IntegerLiteral", rng=_ast_range((11, 16)), type={"qualType": "int"}
            ),
            _ast_range((11, 5)),
        )
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "use_after_free",
                    _ast_compound(
                        [
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "p",
                                        "struct item *",
                                        init=cast,
                                        rng=_ast_range((8, 5)),
                                    )
                                ],
                                rng=_ast_range((8, 5)),
                            ),
                            member_read,
                            free_call,
                            member_write,
                        ],
                        rng=_ast_range((7, 24), (12, 1)),
                    ),
                    rng=_ast_range((7, 1)),
                )
            ]
        )
        result = self._extract(ast, tu="src/malloc_free_member.c")

        allocations = _facts_of_kind(result, "allocation")
        self.assertEqual(1, len(allocations))
        self.assertEqual("malloc", allocations[0]["allocation_api"])
        self.assertEqual([8, 8], allocations[0]["source_range"])

        releases = _facts_of_kind(result, "release")
        self.assertEqual(1, len(releases))
        self.assertEqual("free", releases[0]["release_api"])
        self.assertEqual("p", releases[0]["pointer_id"])
        self.assertEqual([allocations[0]["fact_id"]], releases[0]["related_fact_ids"])

        accesses = _facts_of_kind(result, "member-access")
        self.assertEqual(2, len(accesses))
        self.assertEqual({"p"}, {fact["pointer_id"] for fact in accesses})
        self.assertEqual([], _facts_of_kind(result, "dereference"))
        self.assertTrue(result["coverage"]["cfg_complete"])

    def test_alias_chain_facts(self):
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "alias_chain_use",
                    _ast_compound(
                        [
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "p",
                                        "int *",
                                        init=_ast_new_expr(_ast_range((2, 14))),
                                        rng=_ast_range((2, 5)),
                                    )
                                ],
                                rng=_ast_range((2, 5)),
                            ),
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "q",
                                        "int *",
                                        init=_ast_decl_ref("p"),
                                        rng=_ast_range((3, 5)),
                                    )
                                ],
                                rng=_ast_range((3, 5)),
                            ),
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "r",
                                        "int *",
                                        init=_ast_decl_ref("q"),
                                        rng=_ast_range((4, 5)),
                                    )
                                ],
                                rng=_ast_range((4, 5)),
                            ),
                            _ast_delete_expr("p", _ast_range((5, 5))),
                            _ast_deref("r", _ast_range((6, 5))),
                        ],
                        rng=_ast_range((1, 20), (7, 1)),
                    ),
                    rng=_ast_range((1, 1)),
                )
            ]
        )
        result = self._extract(ast, tu="src/alias_chain.cpp")

        copies = _facts_of_kind(result, "alias-copy")
        self.assertEqual(2, len(copies))
        self.assertEqual(("q", "p"), (copies[0]["pointer_id"], copies[0]["source_pointer_id"]))
        self.assertEqual(("r", "q"), (copies[1]["pointer_id"], copies[1]["source_pointer_id"]))
        dereferences = _facts_of_kind(result, "dereference")
        self.assertEqual(1, len(dereferences))
        self.assertEqual("r", dereferences[0]["pointer_id"])
        self.assertTrue(result["coverage"]["cfg_complete"])

    def test_rebind_after_release_facts(self):
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "rebind_use",
                    _ast_compound(
                        [
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "p",
                                        "int *",
                                        init=_ast_new_expr(_ast_range((2, 14))),
                                        rng=_ast_range((2, 5)),
                                    )
                                ],
                                rng=_ast_range((2, 5)),
                            ),
                            _ast_delete_expr("p", _ast_range((3, 5))),
                            _ast_assign(
                                _ast_decl_ref("p"),
                                _ast_new_expr(_ast_range((4, 9))),
                                _ast_range((4, 5)),
                            ),
                            _ast_deref("p", _ast_range((5, 5))),
                        ],
                        rng=_ast_range((1, 16), (6, 1)),
                    ),
                    rng=_ast_range((1, 1)),
                )
            ]
        )
        result = self._extract(ast, tu="src/rebind.cpp")

        self.assertEqual(2, len(_facts_of_kind(result, "allocation")))
        rebinds = _facts_of_kind(result, "rebind")
        self.assertEqual(1, len(rebinds))
        self.assertEqual("p", rebinds[0]["pointer_id"])
        self.assertEqual([4, 4], rebinds[0]["source_range"])
        self.assertEqual(1, len(_facts_of_kind(result, "dereference")))
        self.assertTrue(result["coverage"]["cfg_complete"])

    def test_guard_region_single_if_stays_complete(self):
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "guarded_use",
                    _ast_compound(
                        [
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "p",
                                        "int *",
                                        init=_ast_new_expr(_ast_range((2, 14))),
                                        rng=_ast_range((2, 5)),
                                    )
                                ],
                                rng=_ast_range((2, 5)),
                            ),
                            _ast_if(
                                _ast_decl_ref("flag", qual="bool"),
                                _ast_compound(
                                    [
                                        _ast_delete_expr("p", _ast_range((4, 9))),
                                        _ast_deref("p", _ast_range((5, 9))),
                                    ],
                                    rng=_ast_range((3, 15), (6, 5)),
                                ),
                                rng=_ast_range((3, 5)),
                            ),
                        ],
                        rng=_ast_range((1, 24), (7, 1)),
                    ),
                    rng=_ast_range((1, 1)),
                )
            ]
        )
        result = self._extract(ast, tu="src/guard_region.cpp")
        self.assertTrue(result["coverage"]["cfg_complete"])
        self.assertEqual(["usr-synthesized"], result["coverage"]["semantic_gaps"])
        releases = _facts_of_kind(result, "release")
        self.assertEqual([4], [fact["source_range"][0] for fact in releases])
        blocks = [fact["cfg_block"] for fact in result["facts"]]
        self.assertEqual(blocks, sorted(blocks))

    # ---------------------------------------------------------- CFG negatives

    def test_loop_is_cfg_gap(self):
        body = _ast_compound([_ast_deref("p", _ast_range((5, 9)))], rng=_ast_range((4, 30), (6, 5)))
        loop = _ast_node(
            "ForStmt",
            rng=_ast_range((4, 5)),
            inner=[
                _ast_decl_stmt(
                    [_ast_var_decl("i", "int", rng=_ast_range((4, 10)))],
                    rng=_ast_range((4, 10)),
                ),
                _ast_binary(
                    "<",
                    _ast_decl_ref("i", qual="int"),
                    _ast_decl_ref("n", qual="int"),
                    _ast_range((4, 19)),
                ),
                _ast_node(
                    "UnaryOperator",
                    rng=_ast_range((4, 26)),
                    opcode="++",
                    type={"qualType": "int"},
                    inner=[_ast_decl_ref("i", qual="int")],
                ),
                body,
            ],
        )
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "loop_use",
                        _ast_compound(
                            [
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "p",
                                            "int *",
                                            init=_ast_new_expr(_ast_range((2, 14))),
                                            rng=_ast_range((2, 5)),
                                        )
                                    ],
                                    rng=_ast_range((2, 5)),
                                ),
                                _ast_delete_expr("p", _ast_range((3, 5))),
                                loop,
                            ],
                            rng=_ast_range((1, 19), (7, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/loop.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("cfg-loop", result["coverage"]["semantic_gaps"])
        self.assertIn("dereference", _fact_kinds(result))

    def test_switch_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "switch_use",
                        _ast_compound(
                            [
                                _ast_node(
                                    "SwitchStmt",
                                    rng=_ast_range((3, 5)),
                                    inner=[
                                        _ast_decl_ref("n", qual="int"),
                                        _ast_node(
                                            "CaseStmt",
                                            rng=_ast_range((4, 5)),
                                            inner=[
                                                _ast_node(
                                                    "IntegerLiteral",
                                                    rng=_ast_range((4, 10)),
                                                    type={"qualType": "int"},
                                                ),
                                                _ast_deref("p", _ast_range((5, 9))),
                                                _ast_node("BreakStmt", rng=_ast_range((6, 9))),
                                            ],
                                        ),
                                        _ast_node("DefaultStmt", rng=_ast_range((7, 5)), inner=[]),
                                    ],
                                )
                            ],
                            rng=_ast_range((1, 20), (10, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/switch.c",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("cfg-switch", result["coverage"]["semantic_gaps"])

    def test_goto_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "goto_use",
                        _ast_compound(
                            [
                                _ast_if(
                                    _ast_binary(
                                        ">",
                                        _ast_decl_ref("n", qual="int"),
                                        _ast_node(
                                            "IntegerLiteral",
                                            rng=_ast_range((3, 15)),
                                            type={"qualType": "int"},
                                        ),
                                        _ast_range((3, 13)),
                                    ),
                                    _ast_compound(
                                        [
                                            _ast_node(
                                                "GotoStmt", rng=_ast_range((4, 9)), name="cleanup"
                                            )
                                        ],
                                        rng=_ast_range((3, 21), (5, 5)),
                                    ),
                                    rng=_ast_range((3, 5)),
                                ),
                                _ast_deref("p", _ast_range((6, 5))),
                                _ast_node(
                                    "LabelStmt", rng=_ast_range((7, 1)), name="cleanup"
                                ),
                                _ast_call("free", [_ast_decl_ref("p")], _ast_range((8, 5))),
                            ],
                            rng=_ast_range((1, 19), (9, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/goto.c",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("cfg-goto", result["coverage"]["semantic_gaps"])

    def test_short_circuit_side_effect_is_cfg_gap(self):
        condition = _ast_binary(
            "&&",
            _ast_decl_ref("p"),
            _ast_binary(
                "!=",
                _ast_paren(
                    _ast_assign(
                        _ast_decl_ref("q"),
                        _ast_decl_ref("p"),
                        _ast_range((3, 17)),
                    ),
                    _ast_range((3, 16)),
                ),
                _ast_node(
                    "IntegerLiteral", rng=_ast_range((3, 27)), type={"qualType": "int"}
                ),
                _ast_range((3, 15)),
            ),
            _ast_range((3, 13)),
        )
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "shortcircuit_use",
                        _ast_compound(
                            [
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "p",
                                            "int *",
                                            init=_ast_new_expr(_ast_range((2, 14))),
                                            rng=_ast_range((2, 5)),
                                        )
                                    ],
                                    rng=_ast_range((2, 5)),
                                ),
                                _ast_if(
                                    condition,
                                    _ast_compound(
                                        [_ast_deref("q", _ast_range((4, 9)))],
                                        rng=_ast_range((3, 32), (5, 5)),
                                    ),
                                    rng=_ast_range((3, 5)),
                                ),
                                _ast_delete_expr("p", _ast_range((6, 5))),
                            ],
                            rng=_ast_range((1, 28), (7, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/shortcircuit.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("short-circuit-side-effect", result["coverage"]["semantic_gaps"])

    def test_try_catch_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "try_use",
                        _ast_compound(
                            [
                                _ast_node(
                                    "CXXTryStmt",
                                    rng=_ast_range((3, 5)),
                                    inner=[
                                        _ast_compound(
                                            [_ast_deref("p", _ast_range((4, 9)))],
                                            rng=_ast_range((3, 9), (5, 5)),
                                        ),
                                        _ast_node(
                                            "CXXCatchStmt",
                                            rng=_ast_range((5, 7)),
                                            inner=[
                                                _ast_compound([], rng=_ast_range((5, 20), (5, 21)))
                                            ],
                                        ),
                                    ],
                                ),
                                _ast_delete_expr("p", _ast_range((6, 5))),
                            ],
                            rng=_ast_range((1, 16), (7, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/try.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("cfg-exception", result["coverage"]["semantic_gaps"])

    def test_raii_destructor_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "raii_use",
                        _ast_compound(
                            [
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "g", "Guard", rng=_ast_range((6, 5))
                                        )
                                    ],
                                    rng=_ast_range((6, 5)),
                                ),
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "p",
                                            "int *",
                                            init=_ast_new_expr(_ast_range((7, 14))),
                                            rng=_ast_range((7, 5)),
                                        )
                                    ],
                                    rng=_ast_range((7, 5)),
                                ),
                                _ast_delete_expr("p", _ast_range((8, 5))),
                                _ast_deref("p", _ast_range((9, 5))),
                            ],
                            rng=_ast_range((5, 15), (10, 1)),
                        ),
                        rng=_ast_range((5, 1)),
                    )
                ]
            ),
            tu="src/raii.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("destructor-control-flow", result["coverage"]["semantic_gaps"])

    def test_lambda_body_is_cfg_gap(self):
        lambda_expr = _ast_node(
            "LambdaExpr",
            rng=_ast_range((3, 19)),
            inner=[
                _ast_compound(
                    [_ast_deref("p", _ast_range((3, 27)))], rng=_ast_range((3, 25), (3, 29))
                ),
            ],
        )
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "lambda_use",
                        _ast_compound(
                            [
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "p",
                                            "int *",
                                            init=_ast_new_expr(_ast_range((2, 14))),
                                            rng=_ast_range((2, 5)),
                                        )
                                    ],
                                    rng=_ast_range((2, 5)),
                                ),
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "capture",
                                            "(lambda at src/lambda.cpp:3:10)",
                                            init=lambda_expr,
                                            rng=_ast_range((3, 10)),
                                        )
                                    ],
                                    rng=_ast_range((3, 10)),
                                ),
                                _ast_call("capture", [], _ast_range((4, 5)), callee_kind="VarDecl"),
                                _ast_delete_expr("p", _ast_range((5, 5))),
                            ],
                            rng=_ast_range((1, 18), (6, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/lambda.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("lambda-body", result["coverage"]["semantic_gaps"])
        # No facts may be extracted from inside the lambda body.
        self.assertEqual([], _facts_of_kind(result, "dereference"))

    def test_coroutine_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "coro_use",
                        _ast_node(
                            "CoroutineBodyStmt",
                            rng=_ast_range((1, 1), (4, 1)),
                            inner=[
                                _ast_deref("p", _ast_range((2, 5))),
                                _ast_node("ReturnStmt", rng=_ast_range((3, 5))),
                            ],
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/coroutine.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("coroutine", result["coverage"]["semantic_gaps"])

    def test_indirect_call_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "indirect_use",
                        _ast_compound(
                            [
                                _ast_call(None, [_ast_decl_ref("p")], _ast_range((2, 5))),
                            ],
                            rng=_ast_range((1, 20), (3, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/indirect.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("indirect-call", result["coverage"]["semantic_gaps"])
        self.assertNotIn("release", _fact_kinds(result))

    def test_template_instantiation_is_cfg_gap(self):
        pattern_body = _ast_compound(
            [
                _ast_decl_stmt(
                    [
                        _ast_var_decl(
                            "p",
                            "int *",
                            init=_ast_new_expr(_ast_range((3, 14))),
                            rng=_ast_range((3, 5)),
                        )
                    ],
                    rng=_ast_range((3, 5)),
                ),
                _ast_deref("p", _ast_range((4, 5))),
            ],
            rng=_ast_range((2, 26), (5, 1)),
        )
        pattern = _ast_node(
            "FunctionTemplateDecl",
            rng=_ast_range((2, 1)),
            inner=[
                _ast_function("template_use", pattern_body, rng=_ast_range((2, 20))),
            ],
        )
        instantiation = _ast_function(
            "instantiate",
            _ast_compound(
                [
                    _ast_call(
                        "template_use",
                        [_ast_decl_ref("value", qual="int")],
                        _ast_range((8, 5)),
                    )
                ],
                rng=_ast_range((7, 21), (9, 1)),
            ),
            rng=_ast_range((7, 1)),
        )
        result = self._extract(
            _ast_translation_unit([pattern, instantiation]),
            tu="src/template.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("template-instantiation", result["coverage"]["semantic_gaps"])

    def test_macro_expansion_is_cfg_gap(self):
        macro_range = _ast_range((6, 5), (6, 15))
        function_body = _ast_compound(
            [
                _ast_decl_stmt(
                    [
                        _ast_var_decl(
                            "p",
                            "int *",
                            init=_ast_new_expr(_ast_range((5, 14))),
                            rng=_ast_range((5, 5)),
                        )
                    ],
                    rng=_ast_range((5, 5)),
                ),
                _ast_node(
                    "CXXDeleteExpr",
                    rng=macro_range,
                    inner=[_ast_decl_ref("p")],
                    type={"qualType": "void"},
                ),
                _ast_deref("p", _ast_range((7, 5))),
            ],
            rng=_ast_range((4, 16), (8, 1)),
        )
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_node(
                        "MacroExpansion",
                        rng=_ast_range((6, 5), (6, 15)),
                        name="RELEASE",
                    ),
                    _ast_function("macro_use", function_body, rng=_ast_range((4, 1))),
                ]
            ),
            tu="src/macro.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("macro-expansion", result["coverage"]["semantic_gaps"])

    # -------------------------------------------------- fact-level semantics

    def test_array_new_records_gap_without_allocation_fact(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "array_use",
                        _ast_compound(
                            [
                                _ast_decl_stmt(
                                    [
                                        _ast_var_decl(
                                            "p",
                                            "int *",
                                            init=_ast_new_expr(
                                                _ast_range((2, 14)), array=True
                                            ),
                                            rng=_ast_range((2, 5)),
                                        )
                                    ],
                                    rng=_ast_range((2, 5)),
                                )
                            ],
                            rng=_ast_range((1, 17), (3, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/array.cpp",
        )
        self.assertEqual([], _facts_of_kind(result, "allocation"))
        self.assertIn("array-new", result["coverage"]["semantic_gaps"])

    def test_error_diagnostic_forces_ast_incomplete(self):
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "plain",
                    _ast_compound(
                        [_ast_deref("p", _ast_range((2, 5)))], rng=_ast_range((1, 14), (3, 1))
                    ),
                    rng=_ast_range((1, 1)),
                )
            ],
            diagnostics=[{"severity": "error", "message": "unknown type name 'p'"}],
        )
        result = self._extract(ast, tu="src/broken.cpp")
        self.assertFalse(result["coverage"]["ast_complete"])
        self.assertIn("ast-error-diagnostic", result["coverage"]["semantic_gaps"])

    def test_unsupported_statement_is_cfg_gap(self):
        result = self._extract(
            _ast_translation_unit(
                [
                    _ast_function(
                        "exotic",
                        _ast_compound(
                            [_ast_node("StmtExpr", rng=_ast_range((2, 5)), inner=[])],
                            rng=_ast_range((1, 14), (3, 1)),
                        ),
                        rng=_ast_range((1, 1)),
                    )
                ]
            ),
            tu="src/exotic.cpp",
        )
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("cfg-unsupported", result["coverage"]["semantic_gaps"])

    def test_line_offsets_fallback_derives_lines(self):
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "plain",
                    _ast_compound(
                        [_ast_deref("p", _ast_range((4, 5)))], rng=_ast_range((1, 20), (5, 1))
                    ),
                    rng=_ast_range((1, 1)),
                )
            ]
        )
        # Strip the "line" keys the primary path uses; offsets must recover them.
        for node in _walk_all(ast):
            node.get("range", {}).get("begin", {}).pop("line", None)
            node.get("range", {}).get("end", {}).pop("line", None)
            node.get("loc", {}).pop("line", None)
        from cxx_analyzer import uaf_scan

        # Lines of exactly 99 chars + newline: line k starts at (k-1)*100,
        # matching the helper's offset scheme (line 4 -> offset 305).
        offsets = uaf_scan.build_line_offsets((b"x" * 99 + b"\n") * 4)
        result = self._extract(ast, tu="src/plain.cpp", line_offsets=offsets)
        dereferences = _facts_of_kind(result, "dereference")
        self.assertEqual(1, len(dereferences))
        self.assertEqual([4, 4], dereferences[0]["source_range"])

    # ------------------------------------------------- AST acquisition stage

    def test_extract_ast_json_uses_managed_run_step_with_dump_argv(self):
        from cxx_analyzer import uaf_scan
        from cxx_analyzer.execution import ToolExecution

        ast = _ast_translation_unit([])
        stdout = json.dumps(ast)
        digest = hashlib.sha256(stdout.encode()).hexdigest()
        captured = {}

        def fake_run_step(
            argv, snapshot, cwd, timeout_seconds, max_output_bytes, env, *, deadline=None
        ):
            captured["argv"] = argv
            captured["cwd"] = cwd
            captured["timeout"] = timeout_seconds
            captured["max_output_bytes"] = max_output_bytes
            captured["env"] = env
            return ToolExecution(
                status="completed",
                returncode=0,
                stdout=stdout,
                stderr="",
                stdout_sha256=digest,
                stderr_sha256=hashlib.sha256(b"").hexdigest(),
                output_sha256=digest,
                output_truncated=False,
            )

        with patch("cxx_analyzer.uaf_scan.run_step", side_effect=fake_run_step):
            parsed, diagnostics = uaf_scan.extract_ast_json(
                Mock(),
                "src/use_after_free.cpp",
                ("clang++", "-c", "-std=c++17", "-I", "include", "-DFEATURE=1",
                 "src/use_after_free.cpp", "-o", "build/obj.o"),
                ".",
                None,
                timeout_seconds=17,
            )
        self.assertIsNone(diagnostics)
        self.assertEqual("TranslationUnitDecl", parsed["kind"])
        self.assertEqual(
            [
                "clang++-14",
                "-fsyntax-only",
                "-Xclang",
                "-ast-dump=json",
                "-Xclang",
                "-detailed-preprocessing-record",
                "-std=c++17",
                "-I",
                "include",
                "-DFEATURE=1",
                "src/use_after_free.cpp",
            ],
            captured["argv"],
        )
        self.assertEqual(".", captured["cwd"])
        self.assertEqual(17, captured["timeout"])
        self.assertEqual(uaf_scan.MAX_AST_JSON_BYTES, captured["max_output_bytes"])
        self.assertIsNone(captured["env"])

    def test_extract_ast_json_maps_failures_to_diagnostics(self):
        from cxx_analyzer import uaf_scan
        from cxx_analyzer.execution import ToolExecution

        def execution(**overrides):
            values = {
                "status": "completed",
                "returncode": 0,
                "stdout": "{}",
                "stderr": "",
                "stdout_sha256": hashlib.sha256(b"{}").hexdigest(),
                "stderr_sha256": hashlib.sha256(b"").hexdigest(),
                "output_sha256": "a" * 64,
                "output_truncated": False,
            }
            values.update(overrides)
            return ToolExecution(**values)

        with patch("cxx_analyzer.uaf_scan.run_step", return_value=execution(status="timed-out")):
            parsed, diagnostics = uaf_scan.extract_ast_json(
                Mock(), "src/a.cpp", ("clang", "-c", "src/a.cpp"), ".", None, timeout_seconds=17
            )
        self.assertIsNone(parsed)
        self.assertEqual(["ast-unavailable"], diagnostics)

        with patch(
            "cxx_analyzer.uaf_scan.run_step",
            return_value=execution(
                stdout="not json",
                stdout_sha256=hashlib.sha256(b"not json").hexdigest(),
            ),
        ):
            parsed, diagnostics = uaf_scan.extract_ast_json(
                Mock(), "src/a.cpp", ("clang", "-c", "src/a.cpp"), ".", None, timeout_seconds=17
            )
        self.assertIsNone(parsed)
        self.assertEqual(["ast-json-invalid"], diagnostics)

        with patch("cxx_analyzer.uaf_scan.run_step", return_value=execution(output_truncated=True)):
            parsed, diagnostics = uaf_scan.extract_ast_json(
                Mock(), "src/a.cpp", ("clang", "-c", "src/a.cpp"), ".", None, timeout_seconds=17
            )
        self.assertIsNone(parsed)
        self.assertEqual(["ast-output-limit"], diagnostics)

    # ------------------------------------------------- wire build context

    def test_wire_resolution_vocabulary_matches_typed_contract(self):
        from cxx_analyzer import build_context
        from lima.uaf_models import RESOLUTION_SOURCE_KINDS, RESOLUTION_STATUSES

        self.assertEqual(set(RESOLUTION_STATUSES), set(build_context.WIRE_RESOLUTION_STATUSES))
        self.assertEqual(
            set(RESOLUTION_SOURCE_KINDS), set(build_context.WIRE_SOURCE_KINDS)
        )

    def test_resolve_build_context_wire_matches_typed_resolution(self):
        from cxx_analyzer import build_context

        settings = AnalyzerSettings(
            auto_cmake=False,
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
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "snapshot"
            (root / "src").mkdir(parents=True)
            (root / "src" / "main.c").write_text("int main(void) { return 0; }\n", encoding="utf-8")
            (root / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": ".",
                            "file": "src/main.c",
                            "arguments": [
                                "clang",
                                "-c",
                                "-std=c11",
                                "src/main.c",
                                "-o",
                                "build/main.o",
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            typed = build_context.resolve_build_context(root, "src/main.c", settings)
            wire = build_context.resolve_build_context_wire(root, "src/main.c", settings)
            execution = build_context.resolve_build_context_execution(
                root, "src/main.c", settings
            )
        self.assertEqual("resolved", typed.status)
        self.assertEqual(
            {
                "status": typed.status,
                "source_kind": typed.source_kind,
                "context_hash": typed.context_hash,
                "diagnostics": list(typed.diagnostics),
            },
            wire,
        )
        self.assertEqual(wire, execution.wire)
        self.assertEqual("resolved", execution.status)
        self.assertEqual(tuple(typed.diagnostics), execution.diagnostics)
        self.assertEqual((".",), (execution.relative_directory,))
        self.assertIn("src/main.c", execution.arguments)

        missing = build_context.resolve_build_context_wire(
            root, "src/other.c", settings
        )
        self.assertEqual("incomplete", missing["status"])
        self.assertIn("heuristic-context", missing["diagnostics"])
        self.assertEqual("", missing["context_hash"])

    # ---------------------------------------------------- server integration

    def _compdb_snapshot(self, tu_source, tu, argv):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name) / "snapshot"
        (root / "src").mkdir(parents=True)
        (root / tu).parent.mkdir(parents=True, exist_ok=True)
        (root / tu).write_text(tu_source, encoding="utf-8")
        (root / "compile_commands.json").write_text(
            json.dumps([{"directory": ".", "file": tu, "arguments": list(argv)}]),
            encoding="utf-8",
        )
        return root

    @staticmethod
    def _settings():
        return AnalyzerSettings(
            auto_cmake=False,
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
    def _fake_prepared(root):
        snapshot = Mock()
        snapshot.root = root
        snapshot.verify_inventory = Mock()
        prepared = Mock()
        prepared.__enter__ = Mock(return_value=snapshot)
        prepared.__exit__ = Mock(return_value=False)
        prepared.cleanup = Mock()
        return prepared

    def test_server_completed_bundle_roundtrips_through_client(self):
        from lima.cxx_memory import CxxMemoryAnalyzerClient

        tu = "src/use_after_free.cpp"
        root = self._compdb_snapshot(
            "void use_after_free() {\n    int* p = new int(1);\n    delete p;\n    *p = 2;\n}\n",
            tu,
            ["clang++", "-std=c++17", "-c", tu, "-o", "build/obj.o"],
        )
        ast = _ast_translation_unit(
            [
                _ast_function(
                    "use_after_free",
                    _ast_compound(
                        [
                            _ast_decl_stmt(
                                [
                                    _ast_var_decl(
                                        "p",
                                        "int *",
                                        init=_ast_new_expr(_ast_range((2, 14))),
                                        rng=_ast_range((2, 5)),
                                    )
                                ],
                                rng=_ast_range((2, 5)),
                            ),
                            _ast_delete_expr("p", _ast_range((3, 5))),
                            _ast_deref("p", _ast_range((4, 5))),
                        ],
                        rng=_ast_range((1, 22), (5, 1)),
                    ),
                    rng=_ast_range((1, 1)),
                )
            ]
        )
        with (
            patch(
                "cxx_analyzer.server.prepare_snapshot",
                return_value=self._fake_prepared(root),
            ),
            patch(
                "cxx_analyzer.uaf_scan.extract_ast_json",
                return_value=(ast, None),
            ),
        ):
            response = analyzer_server.uaf_facts_request(
                {
                    "schema_version": 1,
                    "request_id": REQUEST_ID_UAF,
                    "repository_key": "team/project",
                    "snapshot_sha256": "a" * 64,
                    "translation_units": [tu],
                    "build_context": {"mode": "snapshot-compdb"},
                },
                self._settings(),
            )

        self.assertEqual(1, len(response["tool_runs"]))
        self.assertEqual("completed", response["tool_runs"][0]["status"])
        self.assertEqual(1, len(response["translation_units"]))
        entry = response["translation_units"][0]
        self.assertEqual("completed", entry["extraction"])
        self.assertEqual("resolved", entry["build_context"]["status"])
        self.assertTrue(entry["coverage"]["ast_complete"])
        self.assertTrue(entry["coverage"]["cfg_complete"])
        self.assertIn("usr-synthesized", entry["coverage"]["semantic_gaps"])
        self.assertEqual(
            {"allocation", "points-to", "release", "dereference"},
            {fact["kind"] for fact in entry["facts"]},
        )
        material = json.dumps(
            {"translation_units": response["translation_units"]},
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        self.assertEqual(hashlib.sha256(material).hexdigest(), response["bundle_sha256"])

        # The strict main-process client must accept the served bundle.  The
        # fake transport echoes the client's own fresh request_id (the
        # bundle digest covers only the translation units, so it is stable).
        class Opener:
            def __call__(self, request, timeout):
                served = json.loads(json.dumps(response))
                requested = json.loads(request.data.decode("utf-8"))
                served["request_id"] = requested["request_id"]
                return _UafFakeResponse(io.BytesIO(json.dumps(served).encode("utf-8")))

        client = CxxMemoryAnalyzerClient(
            "http://cxx-analyzer:8090",
            timeout_seconds=8,
            max_response_bytes=1024 * 1024,
            opener=Opener(),
        )
        result = client.analyze_uaf_facts("team/project", "a" * 64, (tu,), "snapshot-compdb")
        self.assertEqual("completed", result.tool_runs[0]["status"])
        self.assertEqual(4, len(result.translation_units[0]["facts"]))

    def test_server_unresolved_context_stays_unavailable(self):
        tu = "src/unlisted.cpp"
        root = self._compdb_snapshot(
            "int main(void) { return 0; }\n",
            "src/listed.c",
            ["clang", "-c", "src/listed.c", "-o", "build/obj.o"],
        )
        with patch(
            "cxx_analyzer.server.prepare_snapshot",
            return_value=self._fake_prepared(root),
        ):
            response = analyzer_server.uaf_facts_request(
                {
                    "schema_version": 1,
                    "request_id": REQUEST_ID_UAF,
                    "repository_key": "team/project",
                    "snapshot_sha256": "a" * 64,
                    "translation_units": [tu],
                    "build_context": {"mode": "snapshot-compdb"},
                },
                self._settings(),
            )
        entry = response["translation_units"][0]
        self.assertEqual("unavailable", entry["extraction"])
        self.assertEqual("incomplete", entry["build_context"]["status"])
        self.assertEqual([], entry["facts"])
        self.assertFalse(entry["coverage"]["ast_complete"])
        self.assertFalse(entry["coverage"]["cfg_complete"])
        self.assertIn("heuristic-context", entry["coverage"]["semantic_gaps"])
        self.assertEqual("unavailable", response["tool_runs"][0]["status"])

    def test_server_snapshot_preparation_failure_maps_to_request_error(self):
        with patch(
            "cxx_analyzer.server.prepare_snapshot",
            side_effect=OSError("repository is missing"),
        ):
            with self.assertRaises(analyzer_server.RequestError) as caught:
                analyzer_server.uaf_facts_request(
                    {
                        "schema_version": 1,
                        "request_id": REQUEST_ID_UAF,
                        "repository_key": "team/project",
                        "snapshot_sha256": "a" * 64,
                        "translation_units": ["src/anything.cpp"],
                        "build_context": {"mode": "heuristic"},
                    },
                    self._settings(),
                )
        self.assertEqual("snapshot_rejected", caught.exception.code)


class UafFactExtractionContainerTests(unittest.TestCase):
    """Real clang-14 extraction inside the analyzer container (semantic asserts)."""

    def _settings(self):
        return AnalyzerSettings(
            auto_cmake=False,
            build_steps=(),
            test_steps=(),
            max_memory_mb=1024,
            max_processes=32,
            max_output_bytes=1024 * 1024,
            step_timeout_seconds=120,
            total_timeout_seconds=300,
            repository_scan_max_files=100,
            repository_scan_max_file_bytes=4096,
            repository_scan_max_total_bytes=16384,
        )

    def _extract_fixture(self, fixture_name, language_standard):
        from cxx_analyzer import build_context, uaf_scan

        if sys.platform != "linux":
            self.skipTest("UAF fact extraction container regression requires Linux")
        if shutil.which("clang-14") is None or shutil.which("clang++-14") is None:
            self.skipTest("clang-14 and clang++-14 are required for UAF fixtures")
        try:
            Path("/work/tmp").mkdir(parents=True, exist_ok=True)
        except OSError:
            self.skipTest("requires a writable container work root")

        tu = f"src/{fixture_name}"
        driver = "clang++" if fixture_name.endswith(".cpp") else "clang"
        with tempfile.TemporaryDirectory(dir="/work/tmp") as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            (repository / "src").mkdir()
            shutil.copy2(_UAF_FIXTURES / fixture_name, repository / tu)
            (repository / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": ".",
                            "file": tu,
                            "arguments": [
                                driver,
                                "-c",
                                language_standard,
                                tu,
                                "-o",
                                "build/obj.o",
                            ],
                        }
                    ]
                ),
                encoding="utf-8",
            )
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                import_root, "team/project", fingerprint, work_root
            ) as snapshot:
                context = build_context.resolve_build_context_execution(
                    snapshot.root, tu, self._settings()
                )
                self.assertEqual("resolved", context.status)
                deadline = AnalysisDeadline.start(self._settings().total_timeout_seconds)
                source_bytes = snapshot.root.joinpath(tu).read_bytes()
                ast_json, diagnostics = uaf_scan.extract_ast_json(
                    snapshot,
                    tu,
                    context.arguments,
                    context.relative_directory,
                    deadline,
                    timeout_seconds=self._settings().step_timeout_seconds,
                )
                self.assertIsNone(
                    diagnostics, f"unexpected extraction diagnostics: {diagnostics}"
                )
                offsets = uaf_scan.build_line_offsets(source_bytes)
                return uaf_scan.extract_uaf_facts(ast_json, tu, tu, line_offsets=offsets)

    def test_container_new_delete_deref_facts(self):
        result = self._extract_fixture("new_delete_deref.cpp", "-std=c++17")
        self.assertTrue(result["coverage"]["ast_complete"])
        self.assertTrue(result["coverage"]["cfg_complete"])
        self.assertIn("usr-synthesized", result["coverage"]["semantic_gaps"])
        allocations = _facts_of_kind(result, "allocation")
        self.assertEqual(1, len(allocations))
        self.assertEqual("new", allocations[0]["allocation_api"])
        self.assertEqual("p", allocations[0]["pointer_id"])
        self.assertEqual(2, allocations[0]["source_range"][0])
        releases = _facts_of_kind(result, "release")
        self.assertEqual(1, len(releases))
        self.assertEqual("delete", releases[0]["release_api"])
        self.assertEqual(3, releases[0]["source_range"][0])
        self.assertEqual([allocations[0]["fact_id"]], releases[0]["related_fact_ids"])
        dereferences = _facts_of_kind(result, "dereference")
        self.assertEqual(1, len(dereferences))
        self.assertEqual(4, dereferences[0]["source_range"][0])

    def test_container_malloc_free_member_facts(self):
        result = self._extract_fixture("malloc_free_member.c", "-std=c11")
        self.assertTrue(result["coverage"]["cfg_complete"])
        allocations = _facts_of_kind(result, "allocation")
        self.assertEqual(1, len(allocations))
        self.assertEqual("malloc", allocations[0]["allocation_api"])
        releases = _facts_of_kind(result, "release")
        self.assertEqual(1, len(releases))
        self.assertEqual("free", releases[0]["release_api"])
        self.assertEqual(10, releases[0]["source_range"][0])
        self.assertTrue(_facts_of_kind(result, "member-access"))

    def test_container_loop_is_cfg_gap(self):
        result = self._extract_fixture("loop.cpp", "-std=c++17")
        self.assertFalse(result["coverage"]["cfg_complete"])
        self.assertIn("cfg-loop", result["coverage"]["semantic_gaps"])
        self.assertIn("dereference", _fact_kinds(result))


_REPRO_FIXTURES = Path(__file__).parent / "fixtures" / "repro"
# Realistic AddressSanitizer stderr for a heap-use-after-free hit (matching
# clang-14 output under the analyzer's SANITIZER_ENVIRONMENT: color=never,
# abort_on_error=0, frames with -g).  Used as the parser's embedded fixture.
_REPRO_UAF_STDERR = """\
==4728==ERROR: AddressSanitizer: heap-use-after-free on address 0x602000000010 at pc 0x561f7b3a2e61
READ of size 4 at 0x602000000010 thread T0
    #0 0x561f7b3a2e60 in use_after_free_read vuln_lib.cpp:8:12
    #1 0x561f7b3a2f04 in main build/repro_driver_ab12cd34.cpp:6:28
    #2 0x7f2c0e429d8f in __libc_start_main ../csu/libc-start.c:308

0x602000000010 is located 0 bytes inside of 4-byte region [0x602000000010,0x602000000014)
freed by thread T0 here:
    #0 0x561f7b3a2c9d in free vuln_lib.cpp:7:5
    #1 0x561f7b3a2e60 in use_after_free_read vuln_lib.cpp:7:5

previously allocated by thread T0 here:
    #0 0x561f7b3a2d31 in malloc vuln_lib.cpp:5:38
    #1 0x561f7b3a2e60 in use_after_free_read vuln_lib.cpp:5:38

SUMMARY: AddressSanitizer: heap-use-after-free vuln_lib.cpp:8 in use_after_free_read
"""
_REPRO_UAF_NO_COLUMN_STDERR = """\
==9==ERROR: AddressSanitizer: heap-use-after-free on address 0x60200000fe10
READ of size 4 at 0x60200000fe10 thread T0
    #0 0x40098e in main src/driver.cpp:13
freed by thread T0 here:
    #0 0x4008ff in main src/driver.cpp:10
previously allocated by thread T0 here:
    #0 0x4008ca in main src/driver.cpp:9
SUMMARY: AddressSanitizer: heap-use-after-free src/driver.cpp:13 in main
"""


def _repro_raw_report_digest(stderr_text):
    """The raw-report digest rule: sha256 over the ERROR..SUMMARY block,
    ending at (excluding) the newline after the SUMMARY line."""
    start = stderr_text.index("==4728==ERROR: AddressSanitizer:")
    summary = stderr_text.index("SUMMARY: AddressSanitizer:", start)
    end = stderr_text.index("\n", summary)
    return hashlib.sha256(stderr_text[start:end].encode("utf-8")).hexdigest()


class ReproTests(unittest.TestCase):
    """Host-side reproduction workbench units with mocked sandbox execution."""

    def _settings(self):
        return AnalyzerSettings(
            auto_cmake=False,
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

    def _prepared_snapshot(self, temporary, files):
        from lima.workspace import RepositoryWorkspace

        base = Path(temporary)
        import_root = base / "imports"
        repository = import_root / "team" / "project"
        work_root = base / "snapshots"
        repository.mkdir(parents=True)
        work_root.mkdir()
        for relative, content in files.items():
            path = repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")
        fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
        return prepare_snapshot(import_root, "team/project", fingerprint, work_root)

    def _tool_execution(
        self,
        status="completed",
        returncode=0,
        stdout="",
        stderr="",
        output_truncated=False,
        diagnostic="",
    ):
        return ToolExecution(
            status=status,
            returncode=None if status == "timed-out" else returncode,
            stdout=stdout,
            stderr=stderr,
            stdout_sha256=hashlib.sha256(stdout.encode("utf-8")).hexdigest(),
            stderr_sha256=hashlib.sha256(stderr.encode("utf-8")).hexdigest(),
            output_sha256=hashlib.sha256(
                (stdout + stderr).encode("utf-8")
            ).hexdigest(),
            output_truncated=output_truncated,
            digests_complete=True,
            diagnostic=diagnostic,
        )

    def _recorded_run_step(self, calls, responses, snapshot):
        def execute(
            argv,
            step_snapshot,
            cwd,
            timeout_seconds,
            max_output_bytes,
            env,
            *,
            deadline=None,
        ):
            self.assertIs(snapshot, step_snapshot)
            calls.append(
                {
                    "argv": list(argv),
                    "cwd": cwd,
                    "timeout_seconds": timeout_seconds,
                    "max_output_bytes": max_output_bytes,
                    "env": env,
                    "deadline": deadline,
                }
            )
            outcome = responses[len(calls) - 1]
            if outcome.get("produce_binary"):
                # Emulate the compiler writing its artifact into the
                # snapshot's writable build root.
                binary = snapshot.build_root / outcome["produce_binary"]
                binary.write_bytes(b"\x7fELF fake repro binary")
            return self._tool_execution(**outcome["execution"])

        return execute

    # ------------------------------------------------------- parser units

    def test_parse_asan_report_heap_use_after_free(self):
        report = repro.parse_asan_report(_REPRO_UAF_STDERR)
        self.assertIsNotNone(report)
        self.assertEqual("heap-use-after-free", report["error_type"])
        self.assertEqual("READ", report["access"])
        self.assertEqual(4, report["access_size"])
        self.assertEqual(
            {
                "function": "use_after_free_read",
                "file": "vuln_lib.cpp",
                "line": 8,
                "column": 12,
            },
            report["faulting_frame"],
        )
        self.assertEqual(
            {"function": "free", "file": "vuln_lib.cpp", "line": 7, "column": 5},
            report["freed_by_frame"],
        )
        self.assertEqual(
            {"function": "malloc", "file": "vuln_lib.cpp", "line": 5, "column": 38},
            report["allocated_by_frame"],
        )
        self.assertEqual(
            _repro_raw_report_digest(_REPRO_UAF_STDERR), report["raw_report_sha256"]
        )

    def test_parse_asan_report_accepts_file_line_without_column(self):
        report = repro.parse_asan_report(_REPRO_UAF_NO_COLUMN_STDERR)
        self.assertIsNotNone(report)
        self.assertEqual("heap-use-after-free", report["error_type"])
        self.assertEqual("READ", report["access"])
        self.assertEqual(4, report["access_size"])
        self.assertEqual(
            {"function": "main", "file": "src/driver.cpp", "line": 13, "column": None},
            report["faulting_frame"],
        )
        self.assertEqual(10, report["freed_by_frame"]["line"])
        self.assertEqual(9, report["allocated_by_frame"]["line"])

    def test_parse_asan_report_returns_none_for_clean_output(self):
        self.assertIsNone(repro.parse_asan_report("hello\nworld\n"))
        self.assertIsNone(repro.parse_asan_report(""))
        self.assertIsNone(repro.parse_asan_report(
            "SUMMARY: AddressSanitizer: 0 byte(s) leaked in 0 allocation(s).\n"
        ))

    def test_parse_asan_report_returns_none_for_incomplete_report(self):
        without_summary = "\n".join(
            line
            for line in _REPRO_UAF_STDERR.splitlines()
            if not line.startswith("SUMMARY: AddressSanitizer:")
        )
        self.assertIsNone(repro.parse_asan_report(without_summary))
        self.assertIsNone(
            repro.parse_asan_report("==1==ERROR: AddressSanitizer: heap-use-after-free")
        )
        self.assertIsNone(repro.parse_asan_report("Segmentation fault (core dumped)"))

        mismatched = _REPRO_UAF_STDERR.replace(
            "SUMMARY: AddressSanitizer: heap-use-after-free",
            "SUMMARY: AddressSanitizer: double-free",
        )
        self.assertIsNone(repro.parse_asan_report(mismatched))

    def test_parse_asan_report_tolerates_stdout_noise(self):
        noisy = "PoC stage one\nno crash yet\n" + _REPRO_UAF_STDERR
        report = repro.parse_asan_report(noisy)
        self.assertIsNotNone(report)
        self.assertEqual("heap-use-after-free", report["error_type"])

    # ------------------------------------------------------- argv builders

    def test_compile_argv_is_pinned_and_deterministic(self):
        argv = repro.build_compile_argv(
            ("src/a.cpp", "src/b.cpp"), "build/d.cpp", "build/out"
        )
        self.assertEqual(
            [
                "clang++-14",
                "-fsanitize=address",
                "-g",
                "-O1",
                "src/a.cpp",
                "src/b.cpp",
                "build/d.cpp",
                "-o",
                "build/out",
            ],
            argv,
        )
        self.assertEqual(
            argv,
            repro.build_compile_argv(
                ("src/a.cpp", "src/b.cpp"), "build/d.cpp", "build/out"
            ),
        )
        self.assertEqual(
            ["build/repro_bin_x"], repro.build_run_argv("build/repro_bin_x")
        )

    def test_driver_path_escape_rejected(self):
        escapes = (
            "../evil.cpp",
            "/abs/driver.cpp",
            "build\\driver.cpp",
            "",
            ".",
            "build/./driver.cpp",
            "a/\x00b.cpp",
        )
        for driver in escapes:
            with self.subTest(path=driver):
                with self.assertRaises(ValueError):
                    repro.build_compile_argv(("v.cpp",), driver, "build/out")
                with self.assertRaises(ValueError):
                    repro.build_run_argv(driver)
        for sources in ([], ("../evil.cpp",), ("/abs.cpp",), ("a\\b.cpp",)):
            with self.subTest(sources=sources):
                with self.assertRaises(ValueError):
                    repro.build_compile_argv(sources, "build/d.cpp", "build/out")

    # ------------------------------------------------------- run_repro flow

    def test_run_repro_compiles_runs_and_parses_report(self):
        driver_code = (_REPRO_FIXTURES / "driver_uaf.cpp").read_text(encoding="utf-8")
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        driver_relative = f"build/repro_driver_{tag}.cpp"
        binary_relative = f"build/repro_bin_{tag}"
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(
                temporary,
                {"vuln_lib.cpp": (_REPRO_FIXTURES / "vuln_lib.cpp").read_text(
                    encoding="utf-8"
                )},
            ) as snapshot:
                calls = []
                responses = (
                    {
                        "execution": {"status": "completed", "returncode": 0},
                        "produce_binary": f"repro_bin_{tag}",
                    },
                    {
                        "execution": {
                            "status": "failed",
                            "returncode": 1,
                            "stderr": _REPRO_UAF_STDERR,
                        },
                        "produce_binary": f"repro_bin_{tag}",
                    },
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step(calls, responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=30,
                    )

        self.assertEqual("run", result.stage)
        self.assertIs(False, result.ok)
        self.assertEqual(1, result.exit_code)
        self.assertIsNotNone(result.asan_report)
        self.assertEqual("heap-use-after-free", result.asan_report["error_type"])
        self.assertEqual(8, result.asan_report["faulting_frame"]["line"])
        self.assertEqual((), result.diagnostics)
        self.assertEqual(
            {
                "driver_path": driver_relative,
                "binary_path": binary_relative,
                "driver_sha256": hashlib.sha256(
                    driver_code.encode("utf-8")
                ).hexdigest(),
                "binary_sha256": hashlib.sha256(
                    b"\x7fELF fake repro binary"
                ).hexdigest(),
            },
            result.artifacts,
        )
        self.assertGreaterEqual(result.elapsed_seconds, 0.0)

        self.assertEqual(2, len(calls))
        self.assertEqual(
            [
                "clang++-14",
                "-fsanitize=address",
                "-g",
                "-O1",
                "vuln_lib.cpp",
                driver_relative,
                "-o",
                binary_relative,
            ],
            calls[0]["argv"],
        )
        self.assertEqual([binary_relative], calls[1]["argv"])
        for call in calls:
            self.assertEqual(".", call["cwd"])
            self.assertIs(SANITIZER_ENVIRONMENT, call["env"])
            self.assertEqual(1024 * 1024, call["max_output_bytes"])
            self.assertEqual(30, call["timeout_seconds"])
            self.assertIs(deadline, call["deadline"])

    def test_compile_failure_returns_diagnostics_not_crash(self):
        driver_code = "#include <cstdio>\nint main() { missing(); }\n"
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(
                temporary, {"vuln_lib.cpp": "extern \"C\" int f(void) { return 0; }\n"}
            ) as snapshot:
                calls = []
                responses = (
                    {
                        "execution": {
                            "status": "failed",
                            "returncode": 1,
                            "stderr": (
                                f"build/repro_driver_{tag}.cpp:2:20: error: "
                                "use of undeclared identifier 'missing'"
                            ),
                        }
                    },
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step(calls, responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=30,
                    )

        self.assertEqual("compile", result.stage)
        self.assertIs(False, result.ok)
        self.assertEqual(1, result.exit_code)
        self.assertIsNone(result.asan_report)
        self.assertEqual("", result.artifacts["binary_sha256"])
        self.assertTrue(
            any("use of undeclared identifier" in item for item in result.diagnostics),
            result.diagnostics,
        )
        self.assertEqual(1, len(calls))

    def test_run_timeout_reports_no_exit_code(self):
        driver_code = (_REPRO_FIXTURES / "driver_infinite_loop.cpp").read_text(
            encoding="utf-8"
        )
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                calls = []
                responses = (
                    {"execution": {"status": "completed", "returncode": 0},
                     "produce_binary": f"repro_bin_{tag}"},
                    {"execution": {"status": "timed-out"}},
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step(calls, responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=5,
                    )

        self.assertEqual("run", result.stage)
        self.assertIs(False, result.ok)
        self.assertIsNone(result.exit_code)
        self.assertIsNone(result.asan_report)
        self.assertIn("repro-step-timed-out", result.diagnostics)

    def test_run_repro_retries_asan_renderer_segv_and_recovers(self):
        driver_code = (_REPRO_FIXTURES / "driver_uaf.cpp").read_text(encoding="utf-8")
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                calls = []
                responses = (
                    {
                        "execution": {"status": "completed", "returncode": 0},
                        "produce_binary": f"repro_bin_{tag}",
                    },
                    {"execution": {"status": "failed", "returncode": -11}},
                    {"execution": {"status": "failed", "returncode": -11}},
                    {
                        "execution": {
                            "status": "failed",
                            "returncode": 1,
                            "stderr": _REPRO_UAF_STDERR,
                        }
                    },
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step(calls, responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=30,
                    )

        self.assertEqual("run", result.stage)
        self.assertIsNotNone(result.asan_report)
        self.assertEqual("heap-use-after-free", result.asan_report["error_type"])
        self.assertEqual(1, result.exit_code)
        self.assertIn("asan-runtime-segv-retried", result.diagnostics)
        # One compile step plus three run attempts (two noise, one decisive).
        self.assertEqual(4, len(calls))
        for call in calls[1:]:
            self.assertEqual([f"build/repro_bin_{tag}"], call["argv"])

    def test_run_repro_all_segv_attempts_report_instrument_noise(self):
        driver_code = "int main() { return 0; }\n"
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                calls = []
                responses = (
                    {
                        "execution": {"status": "completed", "returncode": 0},
                        "produce_binary": f"repro_bin_{tag}",
                    },
                    {"execution": {"status": "failed", "returncode": -11}},
                    {"execution": {"status": "failed", "returncode": -11}},
                    {"execution": {"status": "failed", "returncode": -11}},
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step(calls, responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=30,
                    )

        self.assertEqual("run", result.stage)
        self.assertIs(False, result.ok)
        self.assertIsNone(result.asan_report)
        self.assertEqual(-11, result.exit_code)
        self.assertIn("asan-runtime-segv-retried", result.diagnostics)
        # The retry budget is bounded: exactly first run + two retries.
        self.assertEqual(4, len(calls))

    def test_run_repro_segv_with_report_is_not_retried(self):
        driver_code = "int main() { return 0; }\n"
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        deadline = AnalysisDeadline.start(90)
        segv_report = _REPRO_UAF_STDERR.replace(
            "==4728==ERROR: AddressSanitizer: heap-use-after-free",
            "==4728==ERROR: AddressSanitizer: SEGV",
        ).replace(
            "SUMMARY: AddressSanitizer: heap-use-after-free",
            "SUMMARY: AddressSanitizer: SEGV",
        )
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                calls = []
                responses = (
                    {
                        "execution": {"status": "completed", "returncode": 0},
                        "produce_binary": f"repro_bin_{tag}",
                    },
                    {
                        "execution": {
                            "status": "failed",
                            "returncode": -11,
                            "stderr": segv_report,
                        }
                    },
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step(calls, responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=30,
                    )

        self.assertIsNotNone(result.asan_report)
        self.assertEqual("SEGV", result.asan_report["error_type"])
        self.assertEqual(-11, result.exit_code)
        self.assertNotIn("asan-runtime-segv-retried", result.diagnostics)
        self.assertEqual(2, len(calls))

    def test_oversized_output_truncated_flagged(self):
        driver_code = "int main() { return 0; }\n"
        tag = hashlib.sha256(driver_code.encode("utf-8")).hexdigest()[:8]
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                responses = (
                    {"execution": {"status": "completed", "returncode": 0},
                     "produce_binary": f"repro_bin_{tag}"},
                    {
                        "execution": {
                            "status": "completed",
                            "returncode": 0,
                            "stdout": "x" * 4096,
                            "output_truncated": True,
                        }
                    },
                )
                with patch(
                    "cxx_analyzer.repro.run_step",
                    side_effect=self._recorded_run_step([], responses, snapshot),
                ):
                    result = repro.run_repro(
                        snapshot,
                        ("vuln_lib.cpp",),
                        driver_code,
                        deadline=deadline,
                        timeout_seconds=30,
                    )

        self.assertEqual("run", result.stage)
        self.assertIs(False, result.ok)
        self.assertEqual(0, result.exit_code)
        self.assertIsNone(result.asan_report)
        self.assertIn("repro-output-truncated", result.diagnostics)

    def test_source_file_must_be_in_snapshot_inventory(self):
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                with patch("cxx_analyzer.repro.run_step") as step:
                    with self.assertRaises(ValueError):
                        repro.run_repro(
                            snapshot,
                            ("absent.cpp",),
                            "int main() { return 0; }\n",
                            deadline=deadline,
                            timeout_seconds=30,
                        )
        step.assert_not_called()

    def test_driver_and_source_budgets_rejected(self):
        deadline = AnalysisDeadline.start(90)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(
                temporary, {"vuln_lib.cpp": "int x;\n", "src/other.cpp": "int y;\n"}
            ) as snapshot:
                bad_drivers = (
                    "",
                    "x" * (256 * 1024 + 1),
                    "int\x00main() {}\n",
                    42,
                    None,
                )
                for driver in bad_drivers:
                    with self.subTest(driver=repr(driver)[:24]):
                        with self.assertRaises(ValueError):
                            repro.run_repro(
                                snapshot,
                                ("vuln_lib.cpp",),
                                driver,
                                deadline=deadline,
                                timeout_seconds=30,
                            )
                bad_sources = (
                    (),
                    [f"src/f{index}.cpp" for index in range(17)],
                    ("vuln_lib.cpp", "vuln_lib.cpp"),
                    ("../escape.cpp",),
                    ("src/other.cpp", "../escape.cpp"),
                    ("/abs/other.cpp",),
                    ("src\\other.cpp",),
                )
                for sources in bad_sources:
                    with self.subTest(sources=sources):
                        with self.assertRaises(ValueError):
                            repro.run_repro(
                                snapshot,
                                sources,
                                "int main() { return 0; }\n",
                                deadline=deadline,
                                timeout_seconds=30,
                            )

    def test_deadline_exceeded_fails_before_execution(self):
        expired = AnalysisDeadline(expires_at=time.monotonic() - 1.0)
        with tempfile.TemporaryDirectory() as temporary:
            with self._prepared_snapshot(temporary, {"vuln_lib.cpp": "int x;\n"}) as snapshot:
                with patch("cxx_analyzer.repro.run_step") as step:
                    with self.assertRaises(AnalysisDeadlineExceeded):
                        repro.run_repro(
                            snapshot,
                            ("vuln_lib.cpp",),
                            "int main() { return 0; }\n",
                            deadline=expired,
                            timeout_seconds=30,
                        )
        step.assert_not_called()


class ReproContainerTests(unittest.TestCase):
    """Real clang-14 + AddressSanitor execution inside the analyzer container."""

    def _repro_fixture(self, driver_name, *, timeout_seconds=30,
                       source_name="vuln_lib.cpp"):
        from lima.workspace import RepositoryWorkspace

        if sys.platform != "linux":
            self.skipTest("repro container regression requires Linux")
        if shutil.which("clang-14") is None or shutil.which("clang++-14") is None:
            self.skipTest("clang-14 and clang++-14 are required for repro fixtures")
        try:
            Path("/work/tmp").mkdir(parents=True, exist_ok=True)
        except OSError:
            self.skipTest("requires a writable container work root")

        with tempfile.TemporaryDirectory(dir="/work/tmp") as temporary:
            base = Path(temporary)
            import_root = base / "imports"
            repository = import_root / "team" / "project"
            work_root = base / "snapshots"
            repository.mkdir(parents=True)
            work_root.mkdir()
            shutil.copy2(_REPRO_FIXTURES / source_name, repository / source_name)
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                import_root, "team/project", fingerprint, work_root
            ) as snapshot:
                return repro.run_repro(
                    snapshot,
                    (source_name,),
                    (_REPRO_FIXTURES / driver_name).read_text(encoding="utf-8"),
                    deadline=AnalysisDeadline.start(240),
                    timeout_seconds=timeout_seconds,
                )

    def test_container_uaf_driver_hits_report(self):
        # run_repro retries the run stage in place when the ASan runtime
        # dies with SIGSEGV and no report (renderer noise under the
        # restricted container), so this single experiment already covers
        # the observed ~30% flake.
        result = self._repro_fixture("driver_uaf.cpp")

        self.assertEqual("run", result.stage)
        self.assertIsNotNone(result.asan_report)
        self.assertEqual("heap-use-after-free", result.asan_report["error_type"])
        self.assertEqual("READ", result.asan_report["access"])
        self.assertEqual(4, result.asan_report["access_size"])
        faulting = result.asan_report["faulting_frame"]
        self.assertIsNotNone(faulting)
        self.assertEqual(8, faulting["line"])
        self.assertTrue(faulting["file"].endswith("vuln_lib.cpp"))
        freed = result.asan_report["freed_by_frame"]
        self.assertIsNotNone(freed)
        self.assertEqual(7, freed["line"])
        self.assertTrue(freed["file"].endswith("vuln_lib.cpp"))
        allocated = result.asan_report["allocated_by_frame"]
        self.assertIsNotNone(allocated)
        self.assertEqual(5, allocated["line"])
        self.assertTrue(allocated["file"].endswith("vuln_lib.cpp"))
        self.assertIs(False, result.ok)
        self.assertNotEqual(0, result.exit_code)
        self.assertEqual(64, len(result.artifacts["binary_sha256"]))

    def test_container_clean_driver_no_report(self):
        result = self._repro_fixture("driver_clean.cpp", source_name="unused_lib.cpp")
        if (
            result.asan_report is None
            and result.exit_code is not None
            and result.exit_code < 0
        ):
            # run_repro's internal retry budget was exhausted by
            # renderer noise (SIGSEGV, empty stream): one fresh experiment
            # re-judges the clean run instead of failing on the noise.
            result = self._repro_fixture(
                "driver_clean.cpp", source_name="unused_lib.cpp"
            )

        self.assertEqual("run", result.stage)
        self.assertIs(True, result.ok)
        self.assertEqual(0, result.exit_code)
        self.assertIsNone(result.asan_report)
        self.assertEqual((), result.diagnostics)
        self.assertEqual(64, len(result.artifacts["binary_sha256"]))

    def test_container_compile_failure_returns_diagnostics(self):
        result = self._repro_fixture("driver_compile_error.cpp")

        self.assertEqual("compile", result.stage)
        self.assertIs(False, result.ok)
        self.assertIsNone(result.asan_report)
        self.assertNotEqual(0, result.exit_code)
        self.assertEqual("", result.artifacts["binary_sha256"])
        self.assertTrue(
            any("error" in item for item in result.diagnostics), result.diagnostics
        )

    def test_container_timeout_kills_run(self):
        result = self._repro_fixture(
            "driver_infinite_loop.cpp", source_name="unused_lib.cpp",
            timeout_seconds=5,
        )

        self.assertEqual("run", result.stage)
        self.assertIs(False, result.ok)
        self.assertIsNone(result.exit_code)
        self.assertIn("repro-step-timed-out", result.diagnostics)


if __name__ == "__main__":
    unittest.main()
