import hashlib
import os
import subprocess
import sys
import tempfile
import time
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import Mock, patch

from cxx_analyzer.config import AnalyzerSettings, parse_steps_json
from cxx_analyzer.execution import (
    CLEAN_ENVIRONMENT,
    StreamCapture,
    _stream_process,
    run_step,
)
from cxx_analyzer.sandbox import (
    MIN_LANDLOCK_ABI,
    build_launcher_argv,
    build_policy,
    landlock_abi,
)
from cxx_analyzer.snapshot import prepare_snapshot
from lima.workspace import RepositoryWorkspace


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
        with patch.dict(
            os.environ, {"LIMA_DATABASE_URL": "postgres://secret"}, clear=True
        ):
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
                "notes.txt": "not inventoried\n",
                ".env": "TOKEN=secret\n",
                "build/generated.cpp": "int generated;\n",
            }
            for relative, content in files.items():
                path = repository / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            source_before = {
                path.relative_to(repository).as_posix(): (
                    path.read_bytes(), path.stat().st_mtime_ns
                )
                for path in repository.rglob("*")
                if path.is_file()
            }
            expected = RepositoryWorkspace(repository).inventory().fingerprint()

            snapshot = prepare_snapshot(
                import_root, "team/project", expected, work_root
            )
            self.addCleanup(snapshot.cleanup)

            self.assertEqual(expected, snapshot.sha256)
            self.assertEqual(work_root.resolve(), snapshot.root.parent)
            self.assertEqual(
                ["CMakeLists.txt", "cmake/toolchain.cmake", "src/main.cpp"],
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
                        path.read_bytes(), path.stat().st_mtime_ns
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
            with patch.dict(
                os.environ, {"LIMA_REPOSITORY_SCAN_MAX_FILES": "1"}, clear=False
            ):
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
    @patch("cxx_analyzer.execution.sandbox.landlock_abi", return_value=3)
    def test_run_step_uses_launcher_snapshot_cwd_and_clean_env(
        self, _abi, popen, stream
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
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
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
                        env={
                            "PATH": "C:/attacker/bin",
                            "HTTP_PROXY": "http://proxy.invalid",
                            "LIMA_DATABASE_URL": "postgres://secret",
                            "TOKEN": "secret",
                        },
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
        self.assertEqual(CLEAN_ENVIRONMENT, called_options["env"])
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
            "import os\n"
            f"os.write(1, b'A' * {len(stdout)})\n"
            f"os.write(2, b'B' * {len(stderr)})\n"
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
            "import os,time; "
            f"os.write(1, {stdout!r}); "
            f"os.write(2, {stderr!r}); "
            "time.sleep(30)"
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
            captured = _stream_process(
                process, timeout_seconds=1, max_output_bytes=1024
            )
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
    @patch("cxx_analyzer.execution.sandbox.landlock_abi", return_value=0)
    def test_run_step_fails_closed_without_landlock(self, _abi, popen):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
                result = run_step(["tool"], snapshot, ".", 3, 8, {})

        self.assertEqual("sandbox-unavailable", result.status)
        self.assertIsNone(result.returncode)
        self.assertEqual("filesystem sandbox unavailable", result.diagnostic)
        self.assertEqual("", result.stderr)
        popen.assert_not_called()

    @patch("cxx_analyzer.execution.subprocess.Popen")
    @patch(
        "cxx_analyzer.execution.sandbox.landlock_abi",
        side_effect=PermissionError("seccomp denied Landlock query"),
    )
    def test_run_step_fails_closed_when_landlock_query_is_denied(self, _abi, popen):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
                result = run_step(["tool"], snapshot, ".", 3, 8, {})

        self.assertEqual("sandbox-unavailable", result.status)
        self.assertEqual("filesystem sandbox unavailable", result.diagnostic)
        popen.assert_not_called()

    def test_sandbox_policy_and_launcher_exclude_import_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
                policy = build_policy(snapshot.root)
                launcher = build_launcher_argv(
                    ["cmake", "--version"], snapshot.root, status_fd=9
                )

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
    @patch("cxx_analyzer.execution.sandbox.landlock_abi", return_value=3)
    def test_run_step_fails_closed_when_launcher_never_reports_ready(
        self, _abi, popen, stream
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
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
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
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
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
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
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


if __name__ == "__main__":
    unittest.main()
