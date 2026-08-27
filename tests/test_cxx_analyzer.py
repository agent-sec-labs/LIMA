import hashlib
import os
import subprocess
import tempfile
import unittest
from dataclasses import FrozenInstanceError
from pathlib import Path
from unittest.mock import patch

from cxx_analyzer.config import AnalyzerSettings, parse_steps_json
from cxx_analyzer.execution import CLEAN_ENVIRONMENT, run_step
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

    @patch("cxx_analyzer.execution.subprocess.run")
    def test_run_step_uses_argv_shell_false_snapshot_cwd_and_clean_env(self, run):
        run.return_value = subprocess.CompletedProcess(
            ["cmake", "--version"], 0, stdout=b"cmake ok\n", stderr=b""
        )
        with tempfile.TemporaryDirectory() as temporary:
            import_root, repository, work_root = self._repository(temporary)
            (repository / "main.cpp").write_text("int main() {}\n", encoding="utf-8")
            expected = RepositoryWorkspace(repository).inventory().fingerprint()
            with prepare_snapshot(
                import_root, "team/project", expected, work_root
            ) as snapshot:
                result = run_step(
                    ("cmake", "--version"),
                    snapshot.root,
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
        called_argv = run.call_args.args[0]
        called_options = run.call_args.kwargs
        self.assertIsInstance(called_argv, list)
        self.assertEqual(["cmake", "--version"], called_argv)
        self.assertFalse(called_options["shell"])
        self.assertEqual(snapshot.root, Path(called_options["cwd"]))
        self.assertEqual(CLEAN_ENVIRONMENT, called_options["env"])
        self.assertEqual(subprocess.DEVNULL, called_options["stdin"])
        self.assertEqual(17, called_options["timeout"])
        self.assertTrue(called_options["capture_output"])
        self.assertFalse(called_options["check"])

    @patch("cxx_analyzer.execution.subprocess.run")
    def test_run_step_bounds_combined_output_and_hashes_the_full_log(self, run):
        stdout = b"abcdefgh"
        stderr = b"WXYZ"
        run.return_value = subprocess.CompletedProcess(
            ["tool"], 7, stdout=stdout, stderr=stderr
        )
        with tempfile.TemporaryDirectory() as cwd:
            result = run_step(
                ["tool"], cwd, timeout_seconds=5, max_output_bytes=6, env={}
            )

        self.assertEqual("failed", result.status)
        self.assertEqual(7, result.returncode)
        self.assertEqual("abcdef", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertLessEqual(
            len(result.stdout.encode("utf-8")) + len(result.stderr.encode("utf-8")),
            6,
        )
        self.assertTrue(result.output_truncated)
        self.assertEqual(hashlib.sha256(stdout).hexdigest(), result.stdout_sha256)
        self.assertEqual(hashlib.sha256(stderr).hexdigest(), result.stderr_sha256)
        self.assertEqual(
            hashlib.sha256(stdout + b"\0" + stderr).hexdigest(),
            result.output_sha256,
        )

    @patch("cxx_analyzer.execution.subprocess.run")
    def test_run_step_timeout_returns_only_bounded_log_summary(self, run):
        output = b"prefix-" + b"sensitive-tail" * 100
        run.side_effect = subprocess.TimeoutExpired(
            ["tool"], 3, output=output, stderr=b"diagnostic-secret"
        )
        with tempfile.TemporaryDirectory() as cwd:
            result = run_step(
                ["tool"], cwd, timeout_seconds=3, max_output_bytes=8, env={}
            )

        self.assertEqual("timed-out", result.status)
        self.assertIsNone(result.returncode)
        self.assertEqual("prefix-s", result.stdout)
        self.assertEqual("", result.stderr)
        self.assertTrue(result.output_truncated)
        self.assertNotIn("sensitive-tail", repr(result))
        self.assertNotIn("diagnostic-secret", repr(result))
        self.assertEqual(hashlib.sha256(output).hexdigest(), result.stdout_sha256)

    def test_run_step_rejects_non_argv_and_nonpositive_bounds(self):
        with tempfile.TemporaryDirectory() as cwd:
            for argv, timeout, output_limit in (
                ("tool --flag", 1, 1),
                ([], 1, 1),
                (["tool", "bad\0arg"], 1, 1),
                (["tool"], 0, 1),
                (["tool"], 1, 0),
            ):
                with self.subTest(argv=argv, timeout=timeout, output=output_limit):
                    with self.assertRaises(ValueError):
                        run_step(argv, cwd, timeout, output_limit, {})


if __name__ == "__main__":
    unittest.main()
