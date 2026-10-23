"""Acceptance guards for LIMA's full-build path (no Docker needed)."""
# ruff: noqa: S603, S607
# Tests use fixed Git argv against disposable local fixtures.

import importlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


class ContainerBuildTests(unittest.TestCase):
    def module(self):
        return importlib.import_module("lima.container_build")

    def recipe(self):
        return {
            "schema_version": 1,
            "name": "fixture",
            "image": "fixture:local",
            "configure": [["cmake", "-S", "/work/src", "-B", "/work/build"]],
            "build": [["cmake", "--build", "/work/build", "--parallel", "{jobs}"]],
            "test": [["ctest", "--test-dir", "/work/build", "--no-tests=error"]],
            "install": [["cmake", "--install", "/work/build"]],
        }

    def test_optional_setup_environment_and_verify_are_validated(self):
        mod = self.module()
        value = self.recipe()
        value.update(
            setup=[["bootstrap"]],
            verify=[["version"]],
            environment={"PARALLEL": "{jobs}"},
            test_reports=["tests/application.xml"],
        )
        mod.validate_recipe(value)
        value["test_reports"] = ["../old.xml"]
        with self.assertRaises(ValueError):
            mod.validate_recipe(value)
        value["test_reports"] = ["tests.xml"]
        value["environment"] = {"BAD=KEY": "bad"}
        with self.assertRaises(ValueError):
            mod.validate_recipe(value)

    def test_setup_failure_prevents_configuration(self):
        mod = self.module()
        seen = []

        def execute(argv, **kwargs):
            seen.append(argv[0])
            return subprocess.CompletedProcess(argv, 9)

        with tempfile.TemporaryDirectory() as directory:
            recipe = self.recipe()
            recipe["setup"] = [["bootstrap"]]
            record = mod.execute_phases(recipe, Path(directory), jobs=2, execute=execute)
            self.assertEqual(record["status"], "failed")
            self.assertEqual(seen, ["bootstrap"])

    def test_multiple_reports_count_disabled_tests_separately(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "first.xml").write_text(
                '<testsuites><testsuite tests="5" disabled="1" '
                'failures="0" errors="0"/></testsuites>'
            )
            (output / "second.xml").write_text('<testsuite tests="3" failures="0" skipped="1"/>')
            totals = mod.summarize_reports(output, ["first.xml", "second.xml"])
            self.assertEqual(totals["tests"], 8)
            self.assertEqual(totals["disabled"], 1)
            self.assertEqual(totals["passed"], 6)
            (output / "second.xml").write_text('<testsuite tests="1" failures="1"/>')
            with self.assertRaises(ValueError):
                mod.summarize_reports(output, ["first.xml", "second.xml"])

    def test_junit_failure_elements_and_parent_suite_failures_are_rejected(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            cases = {
                "failure-element.xml": (
                    '<testsuite tests="1"><testcase name="fixture">'
                    "<failure message=\"boom\"/></testcase></testsuite>"
                ),
                "error-element.xml": (
                    '<testsuite tests="1"><testcase name="fixture">'
                    "<error message=\"boom\"/></testcase></testsuite>"
                ),
                "parent-failure.xml": (
                    '<testsuites><testsuite name="parent" tests="1" failures="1">'
                    '<testsuite name="child" tests="1"><testcase name="fixture"/>'
                    "</testsuite></testsuite></testsuites>"
                ),
            }
            for name, report in cases.items():
                with self.subTest(report=name):
                    (output / name).write_text(report)
                    with self.assertRaises(ValueError):
                        mod.summarize_reports(output, [name])

    def test_junit_reports_cannot_overlap_reserved_output_artifacts(self):
        mod = self.module()
        reserved = (
            "build-result.json",
            "build-result.json/report.xml",
            "build-result.tmp",
            "worker-result.json",
            "worker-result.tmp",
            "invocation.json",
            "image-build.log",
            "container-stop.log",
            "cancel-requested.json",
            "compile_commands.json",
            "install_manifest.txt",
            "install-linux-x64.tar.gz",
            "logs",
            "logs/test-0.log",
            "Testing",
            "Testing/report.xml",
        )
        for path in reserved:
            with self.subTest(path=path), self.assertRaises(ValueError):
                mod.validate_recipe(dict(self.recipe(), test_reports=[path]))

    def test_pending_cancellation_blocks_worker_result_publication(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "cancel-requested.json").write_text("{}")
            mod.save_record(
                output, {"status": "completed", "steps": []}, filename="worker-result.json"
            )
            with self.assertRaises(ValueError):
                mod.publish_worker_record(output)
            self.assertFalse((output / "build-result.json").exists())

    def test_late_worker_completion_cannot_replace_cancelled_host_result(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "cancel-requested.json").write_text("{}")
            mod.save_record(output, {"status": "failed", "error": "host stopped container"})

            # This models the worker reaching its previous final-result write
            # after the host has confirmed cancellation and persisted failure.
            mod.save_record(
                output,
                {"status": "completed", "steps": []},
                filename="worker-result.json",
            )

            canonical = json.loads((output / "build-result.json").read_text())
            worker = json.loads((output / "worker-result.json").read_text())
            self.assertEqual(canonical["status"], "failed")
            self.assertEqual(worker["status"], "completed")
            with self.assertRaises(ValueError):
                mod.publish_worker_record(output)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            mod.save_record(
                output,
                {"status": "completed", "steps": []},
                filename="worker-result.json",
            )
            mod.publish_worker_record(output)
            self.assertEqual(
                json.loads((output / "build-result.json").read_text())["status"], "completed"
            )

    def test_recipe_requires_real_build_and_tests(self):
        mod = self.module()
        for key in ("build", "test", "install"):
            value = self.recipe()
            del value[key]
            with self.subTest(key=key), self.assertRaises(ValueError):
                mod.validate_recipe(value)
        value = self.recipe()
        value["test"] = []
        with self.assertRaises(ValueError):
            mod.validate_recipe(value)

    def test_failed_build_does_not_run_tests_or_install(self):
        mod = self.module()
        seen = []

        def execute(argv, **kwargs):
            seen.append(argv[0])
            return subprocess.CompletedProcess(argv, 7 if argv[0] == "build" else 0)

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            commands = {phase: [[phase]] for phase in ("configure", "build", "test", "install")}
            record = mod.execute_phases(commands, output, jobs=3, execute=execute)
            self.assertEqual(record["status"], "failed")
            self.assertEqual(seen, ["configure", "build"])
            self.assertEqual(record["steps"][-1]["returncode"], 7)
            self.assertEqual(
                json.loads((output / "build-result.json").read_text())["status"], "failed"
            )

    def test_success_records_every_phase_and_substitutes_jobs(self):
        mod = self.module()
        seen = []

        def execute(argv, **kwargs):
            seen.append(argv)
            return subprocess.CompletedProcess(argv, 0)

        with tempfile.TemporaryDirectory() as directory:
            record = mod.execute_phases(self.recipe(), Path(directory), jobs=6, execute=execute)
            self.assertEqual(record["status"], "completed")
            self.assertEqual(
                [step["phase"] for step in record["steps"]],
                ["configure", "build", "test", "install"],
            )
            self.assertEqual(seen[1][-1], "6")

    def test_original_source_mount_is_readonly_and_no_docker_socket(self):
        mod = self.module()
        command = mod.container_command(
            image="fixture:local",
            name="lima-build-fixture",
            volume="lima-build-volume",
            source=Path("/source"),
            output=Path("/output"),
            recipe=Path("/recipe.json"),
            worker=Path("/worker.py"),
            revision="a" * 40,
            jobs=6,
        )
        source_mount = next(value for value in command if "target=/input" in value)
        self.assertTrue(source_mount.endswith(",readonly"))
        self.assertNotIn("--privileged", command)
        self.assertNotIn("docker.sock", " ".join(command))
        self.assertIn("--rm", command)

    def test_nonempty_output_is_rejected_before_any_artifact_is_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "old.tar.gz").write_bytes(b"previous build")
            with self.assertRaises(ValueError):
                self.module().prepare_output(output)
            self.assertEqual((output / "old.tar.gz").read_bytes(), b"previous build")

    def test_interruption_closes_running_step(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "build-result.json").write_text(
                json.dumps(
                    {"status": "running", "steps": [{"phase": "build", "status": "running"}]}
                )
            )
            self.module().mark_interrupted(output)
            record = json.loads((output / "build-result.json").read_text())
            self.assertEqual(record["status"], "interrupted")
            self.assertEqual(record["steps"][0]["status"], "interrupted")
            self.assertEqual(record["returncode"], 130)

    def test_external_container_failure_does_not_leave_running_status(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            (output / "build-result.json").write_text(
                json.dumps({"status": "running", "steps": [{"phase": "test", "status": "running"}]})
            )
            self.module().mark_container_failure(output, 137)
            record = json.loads((output / "build-result.json").read_text())
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["steps"][0]["returncode"], 137)

    def test_image_build_failure_has_same_terminal_result_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            self.module().record_image_failure(output, self.recipe(), "a" * 40, 1)
            record = json.loads((output / "build-result.json").read_text())
            self.assertEqual(record["status"], "failed")
            self.assertEqual(record["steps"][0]["phase"], "image")
            self.assertEqual(record["steps"][0]["returncode"], 1)

    def test_interrupted_image_build_records_terminal_image_step(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            recipe_path = root / "full-build.json"
            recipe_path.write_text(json.dumps(self.recipe()))
            output = root / "output"

            def check_output(argv, **kwargs):
                if argv[-1] == "-z" or "ls-files" in argv[-1]:
                    return b""
                if argv[-1] == "HEAD":
                    return "a" * 40 + "\n"
                return ""

            with mock.patch.object(mod.subprocess, "check_output", side_effect=check_output):
                with mock.patch.object(mod.subprocess, "run", side_effect=KeyboardInterrupt):
                    try:
                        result = mod.main(
                            [
                                "--source",
                                str(source),
                                "--recipe",
                                str(recipe_path),
                                "--output",
                                str(output),
                            ]
                        )
                    except KeyboardInterrupt:
                        self.fail("Image-build interruption must produce a terminal result")
            self.assertEqual(result, 130)
            record = json.loads((output / "build-result.json").read_text())
            self.assertEqual(record["status"], "interrupted")
            self.assertEqual(record["returncode"], 130)
            self.assertEqual(record["steps"][0]["phase"], "image")
            self.assertEqual(record["steps"][0]["status"], "interrupted")

    def test_unconfirmed_docker_stop_does_not_report_interrupted(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            recipe_path = root / "full-build.json"
            recipe_path.write_text(json.dumps(self.recipe()))
            output = root / "output"

            def check_output(argv, **kwargs):
                if argv[-1] == "-z" or "ls-files" in argv[-1]:
                    return b""
                if argv[-1] == "HEAD":
                    return "a" * 40 + "\n"
                if argv[1:3] == ["image", "inspect"]:
                    return "sha256:fixture\n"
                return ""

            def run(argv, **kwargs):
                if argv[:2] == ["docker", "run"]:
                    raise KeyboardInterrupt
                if argv[:2] in (["docker", "stop"], ["docker", "kill"]):
                    return subprocess.CompletedProcess(argv, 1)
                return subprocess.CompletedProcess(argv, 0)

            with mock.patch.object(mod.subprocess, "check_output", side_effect=check_output):
                with mock.patch.object(mod.subprocess, "run", side_effect=run):
                    result = mod.main(
                        [
                            "--source",
                            str(source),
                            "--recipe",
                            str(recipe_path),
                            "--output",
                            str(output),
                            "--skip-image-build",
                        ]
                    )
            record = json.loads((output / "build-result.json").read_text())
            self.assertIn(result, (1, 130))
            self.assertIn(record["status"], ("failed", "stop_unconfirmed"))
            self.assertRegex(json.dumps(record), r"(?i)(stop.*confirm|confirm.*stop)")

    def test_failed_docker_stop_with_successful_kill_is_interrupted(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir()
            recipe_path = root / "full-build.json"
            recipe_path.write_text(json.dumps(self.recipe()))
            output = root / "output"

            def check_output(argv, **kwargs):
                if argv[-1] == "-z" or "ls-files" in argv[-1]:
                    return b""
                if argv[-1] == "HEAD":
                    return "a" * 40 + "\n"
                if argv[1:3] == ["image", "inspect"]:
                    return "sha256:fixture\n"
                return ""

            def run(argv, **kwargs):
                if argv[:2] == ["docker", "run"]:
                    raise KeyboardInterrupt
                if argv[:2] == ["docker", "stop"]:
                    return subprocess.CompletedProcess(argv, 1)
                return subprocess.CompletedProcess(argv, 0)

            with mock.patch.object(mod.subprocess, "check_output", side_effect=check_output):
                with mock.patch.object(mod.subprocess, "run", side_effect=run):
                    self.assertEqual(
                        mod.main(
                            [
                                "--source",
                                str(source),
                                "--recipe",
                                str(recipe_path),
                                "--output",
                                str(output),
                                "--skip-image-build",
                            ]
                        ),
                        130,
                    )
            record = json.loads((output / "build-result.json").read_text())
            self.assertEqual(record["status"], "interrupted")
            self.assertEqual(record["returncode"], 130)

    def test_partial_install_or_missing_test_report_is_not_accepted(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory) / "work"
            output = Path(directory) / "output"
            (work / "build").mkdir(parents=True)
            (work / "install/lib").mkdir(parents=True)
            output.mkdir()
            library = work / "install/lib/libfixture.a"
            (work / "build/install_manifest.txt").write_text(str(library))
            with self.assertRaises(ValueError):
                mod.validate_installation(work, output)
            library.write_bytes(b"archive")
            with self.assertRaises(ValueError):
                mod.validate_installation(work, output)
            (output / "ctest-results.xml").write_text(
                '<testsuite tests="1" failures="0" errors="0"/>'
            )
            self.assertEqual(mod.validate_installation(work, output)["tests"], 1)

    def test_real_failed_test_command_stops_install(self):
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            marker = output / "installed"
            recipe = {
                "test": [[sys.executable, "-c", "raise SystemExit(3)"]],
                "install": [[sys.executable, "-c", f'open({str(marker)!r}, "w").write("bad")']],
            }
            record = mod.execute_phases(recipe, output, jobs=1)
            self.assertEqual(record["status"], "failed")
            self.assertFalse(marker.exists())

    def test_dirty_or_incomplete_cached_checkout_is_rejected(self):
        if shutil.which("git") is None:
            self.skipTest("Git is not installed in the slim runtime test image")
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            with self.assertRaises(ValueError):
                mod.validate_cached_checkout(source)
            (source / "tracked").write_text("original")
            subprocess.run(["git", "-C", str(source), "add", "."], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            mod.validate_cached_checkout(source)
            (source / "tracked").write_text("changed")
            with self.assertRaises(ValueError):
                mod.validate_cached_checkout(source)
            (source / "tracked").write_text("original")
            (source / "extra").write_text("untracked")
            with self.assertRaises(ValueError):
                mod.validate_cached_checkout(source)

    def test_skip_worktree_hidden_cached_checkout_change_is_rejected(self):
        if shutil.which("git") is None:
            self.skipTest("Git is not installed in the slim runtime test image")
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            (source / "tracked").write_text("original")
            subprocess.run(["git", "-C", str(source), "add", "tracked"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "update-index", "--skip-worktree", "tracked"],
                check=True,
            )
            (source / "tracked").write_text("hidden change")
            with self.assertRaises(ValueError):
                mod.validate_cached_checkout(source)
            with self.assertRaises(ValueError):
                mod.validate_source_index(source)

    def test_dirty_real_submodule_is_rejected_despite_git_ignore_settings(self):
        if shutil.which("git") is None:
            self.skipTest("Git is not installed in the slim runtime test image")
        mod = self.module()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            submodule = root / "submodule"
            source = root / "source"
            subprocess.run(["git", "init", "-q", str(submodule)], check=True)
            (submodule / "tracked").write_text("original")
            subprocess.run(["git", "-C", str(submodule), "add", "tracked"], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(submodule),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "fixture submodule",
                ],
                check=True,
            )
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "protocol.file.allow=always",
                    "submodule",
                    "add",
                    str(submodule),
                    "vendor/submodule",
                ],
                check=True,
            )
            subprocess.run(
                [
                    "git",
                    "-C",
                    str(source),
                    "-c",
                    "user.name=Test",
                    "-c",
                    "user.email=test@example.invalid",
                    "commit",
                    "-qm",
                    "fixture source",
                ],
                check=True,
            )
            nested = source / "vendor/submodule"
            subprocess.run(
                ["git", "-C", str(nested), "update-index", "--skip-worktree", "tracked"],
                check=True,
            )
            (nested / "tracked").write_text("hidden change")

            with self.assertRaises(ValueError):
                mod.validate_cached_checkout(source)
            with self.assertRaises(ValueError):
                mod.validate_source_index(source)

            subprocess.run(
                ["git", "-C", str(nested), "update-index", "--no-skip-worktree", "tracked"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "submodule.vendor/submodule.ignore", "all"],
                check=True,
            )
            self.assertFalse(
                subprocess.check_output(
                    ["git", "-C", str(source), "status", "--porcelain"], text=True
                ).strip()
            )
            self.assertTrue(
                subprocess.check_output(
                    ["git", "-C", str(source), "status", "--porcelain", "--ignore-submodules=none"],
                    text=True,
                ).strip()
            )
            mod.validate_source_index(source)
            recipe_path = root / "full-build.json"
            recipe_path.write_text(json.dumps(self.recipe()))
            with self.assertRaises(SystemExit) as raised:
                mod.main(
                    [
                        "--source", str(source),
                        "--recipe", str(recipe_path),
                        "--output", str(root / "output"),
                    ]
                )
            self.assertEqual(raised.exception.code, 2)
            self.assertFalse((root / "output").exists())


if __name__ == "__main__":
    unittest.main()
