"""Acceptance guards for LIMA's full-build path (no Docker needed)."""
# ruff: noqa: S603, S607
# Tests use fixed Git argv against disposable local fixtures.

import importlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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

    def test_standard_project_catalog_resolves_both_full_builds(self):
        mod = self.module()
        self.assertEqual(set(mod.project_catalog()), {"resinsight", "opm-common"})
        for name in mod.project_catalog():
            value = json.loads(mod.resolve_project(name).read_text())
            mod.validate_recipe(value)
        with self.assertRaises(ValueError):
            mod.resolve_project("../resinsight")

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


if __name__ == "__main__":
    unittest.main()
