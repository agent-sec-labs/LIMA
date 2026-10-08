"""A green C++ suite must have actual passes for every required regression."""

import io
import tempfile
import unittest
from dataclasses import dataclass, field
from pathlib import Path
from unittest.mock import patch

from scripts import run_cxx_container_tests as runner


class RequiredCoverageTests(unittest.TestCase):
    def result(self):
        result = runner.RequiredExecutionResult(
            unittest.runner._WritelnDecorator(io.StringIO()), True, 2
        )
        result.testsRun = len(runner.EXPECTED_METHODS)
        result.passed_methods = set(runner.EXPECTED_METHODS)
        return result

    def test_all_expected_passes_are_accepted(self):
        self.assertTrue(runner.required_execution_succeeded(self.result()))

    def test_green_unittest_with_a_skip_is_rejected(self):
        result = self.result()
        result.skipped = [("build-backed", "snapshot_readonly unavailable")]
        self.assertTrue(result.wasSuccessful())
        self.assertFalse(runner.required_execution_succeeded(result))

    def test_missing_or_unexpected_test_is_rejected(self):
        result = self.result()
        result.passed_methods.remove("test_container_timeout_kills_run")
        result.passed_methods.add("unrelated_test")
        self.assertFalse(runner.required_execution_succeeded(result))
        result = self.result()
        result.testsRun -= 1
        self.assertFalse(runner.required_execution_succeeded(result))

    def test_failed_test_is_rejected(self):
        result = self.result()
        result.failures = [("repro", "assertion failure")]
        self.assertFalse(runner.required_execution_succeeded(result))

    def test_fixture_source_must_be_readonly_and_build_output_writable(self):
        from cxx_analyzer import trust

        for source_ro, build_ro in ((False, False), (True, True)):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                snapshot = _Snapshot(root, root / "build")
                manifest = {
                    "snapshots": {
                        "build-backed": {"sha256": "a" * 64},
                        "asan": {"sha256": "b" * 64},
                    }
                }
                adapter = runner.readonly_snapshot_adapter(
                    lambda snapshot=snapshot: snapshot, root, manifest
                )
                with patch.object(
                    trust, "_longest_mount_readonly", side_effect=[source_ro, build_ro]
                ):
                    with self.assertRaises(RuntimeError):
                        adapter()
                self.assertTrue(snapshot.cleaned)

    def test_staged_sources_are_checked_against_the_original_inventory(self):
        from cxx_analyzer import trust

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "build-backed/source").mkdir(parents=True)
            snapshot = _Snapshot(root, root / "build")
            manifest = {
                "snapshots": {"build-backed": {"sha256": "a" * 64}, "asan": {"sha256": "b" * 64}}
            }
            adapter = runner.readonly_snapshot_adapter(lambda: snapshot, root, manifest)
            with patch.object(trust, "_longest_mount_readonly", side_effect=[True, False]):
                mounted = adapter()
            self.assertEqual(mounted.root, root / "build-backed/source")
            self.assertEqual(mounted.build_root, mounted.root / "build")
            self.assertEqual(mounted.checked, [mounted.root])
            snapshot.checked.clear()
            snapshot.corrupt = True
            with patch.object(trust, "_longest_mount_readonly", side_effect=[True, False]):
                with self.assertRaisesRegex(ValueError, "inventory mismatch"):
                    adapter()
            self.assertTrue(snapshot.cleaned)

    def test_workflow_has_real_readonly_snapshot_and_two_ephemeral_build_mounts(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
        section = workflow.split("  cxx-sidecar-integration:", 1)[1]
        self.assertIn("scripts/run_cxx_container_tests.py stage", section)
        self.assertIn("target=/work/snapshots,readonly", section)
        for label in ("build-backed", "asan"):
            self.assertIn("/work/snapshots/" + label + "/source/build:rw,exec", section)
        self.assertIn("scripts/run_cxx_container_tests.py run", section)
        self.assertIn("--cap-drop ALL --security-opt no-new-privileges:true", section)


@dataclass
class _Snapshot:
    root: Path
    build_root: Path
    sha256: str = "a" * 64
    _root_identity: tuple = (0, 0)
    checked: list = field(default_factory=list)
    cleaned: bool = False
    corrupt: bool = False

    def verify_inventory(self):
        if self.corrupt:
            raise ValueError("inventory mismatch")
        self.checked.append(self.root)

    def cleanup(self):
        self.cleaned = True


if __name__ == "__main__":
    unittest.main()
