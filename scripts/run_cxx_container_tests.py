"""Stage fixed fixtures, then require actual C++ container test execution.

Only the two CMake fixtures need staged, read-only sources. Staging invokes
their fixture construction and real snapshot verification, and stops BEFORE
the analyzer body. Execution uses the unchanged trust probes and assertions.
No staging result is counted as a test pass. See docs/CXX_CI_COVERAGE.md.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

SNAPSHOTS = Path("/work/snapshots")
TEST_CLASSES = (
    "SourceScanContainerTests",
    "BuildScanContainerTests",
    "SanitizerContainerTests",
    "ReproContainerTests",
    "TrustedGenerationContainerTests",
    "UafFactExtractionContainerTests",
)
EXPECTED_METHODS = frozenset(
    {
        "test_fixture_manifest_is_complete_and_semgrep_marks_only_candidates",
        "test_build_backed_fixture_coverage_lists_every_uncovered_identity",
        "test_asan_fixture_subset_confirms_vulnerable_c_and_not_safe_c",
        "test_container_clean_driver_no_report",
        "test_container_compile_failure_returns_diagnostics",
        "test_container_timeout_kills_run",
        "test_container_uaf_driver_hits_report",
        "test_default_container_runs_no_cmake",
        "test_container_loop_is_cfg_gap",
        "test_container_malloc_free_member_facts",
        "test_container_new_delete_deref_facts",
    }
)


class _FixtureStaged(BaseException):
    """Controlled setup terminator; never handled as a successful test."""


def stage_fixtures(root: Path = SNAPSHOTS) -> None:
    from tests import test_cxx_analyzer as cases

    if any(root.iterdir()):
        raise ValueError("staging root must be empty")
    original = cases.prepare_snapshot
    staged = {}
    selections = (
        (
            "build-backed",
            cases.BuildScanContainerTests,
            "test_build_backed_fixture_coverage_lists_every_uncovered_identity",
        ),
        (
            "asan",
            cases.SanitizerContainerTests,
            "test_asan_fixture_subset_confirms_vulnerable_c_and_not_safe_c",
        ),
    )
    for label, test_class, method in selections:

        def capture(*args, label=label, **kwargs):
            with original(*args, **kwargs) as snapshot:
                snapshot.verify_inventory()
                shutil.copytree(snapshot.root, root / label / "source")
                staged[label] = {"sha256": snapshot.sha256}
            raise _FixtureStaged()

        # Setup only: this phase copies inert, repository-owned fixtures. It
        # never calls CMake/Clang or run_build_scan, and provides no test verdict.
        with (
            patch.object(cases, "prepare_snapshot", side_effect=capture),
            patch.object(
                cases.BuildScanContainerTests, "_skip_unless_trusted_generation_supported"
            ),
        ):
            try:
                getattr(test_class(method), method)()
            except _FixtureStaged:
                pass
            else:
                raise RuntimeError("fixture setup did not reach the verified snapshot boundary")
    (root / "manifest.json").write_text(
        json.dumps({"schema_version": 1, "snapshots": staged}), encoding="utf-8"
    )
    print("STAGED 2 verified source fixtures; no tests executed")


def readonly_snapshot_adapter(original, root: Path, manifest: dict):
    """Retain real prepare_snapshot validation, scratch and cleanup ownership."""
    from cxx_analyzer import trust

    by_digest = {item["sha256"]: label for label, item in manifest["snapshots"].items()}
    if set(by_digest.values()) != {"build-backed", "asan"}:
        raise ValueError("both staged fixture identities are required")

    def prepare(*args, **kwargs):
        snapshot = original(*args, **kwargs)
        label = by_digest.get(snapshot.sha256)
        if label is None:
            return snapshot
        try:
            source = root / label / "source"
            build = source / "build"
            if not trust._longest_mount_readonly(str(source)):
                raise RuntimeError("fixture source is not on a read-only mount")
            if trust._longest_mount_readonly(str(build)):
                raise RuntimeError("fixture build output must use its dedicated writable tmpfs")
            metadata = source.lstat()
            mounted = replace(
                snapshot,
                root=source,
                build_root=build,
                _root_identity=(metadata.st_dev, metadata.st_ino),
            )
            # The original test-generated inventory checks every staged byte.
            # It is not replaced by an unverified manifest's claimed inventory.
            mounted.verify_inventory()
            return mounted
        except BaseException:
            snapshot.cleanup()
            raise

    return prepare


class RequiredExecutionResult(unittest.TextTestResult):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.passed_methods = set()

    def addSuccess(self, test):
        self.passed_methods.add(test.id().rsplit(".", 1)[-1])
        super().addSuccess(test)


def required_execution_succeeded(result) -> bool:
    return (
        result.wasSuccessful()
        and not result.skipped
        and result.testsRun == len(EXPECTED_METHODS)
        and result.passed_methods == EXPECTED_METHODS
    )


def run_required_tests(root: Path = SNAPSHOTS) -> bool:
    from cxx_analyzer.trust import build_generation_capabilities
    from tests import test_cxx_analyzer as cases

    capabilities = build_generation_capabilities()
    print("Generation capabilities: " + json.dumps(capabilities, sort_keys=True), flush=True)
    if not capabilities or not all(capabilities.values()):
        raise RuntimeError(
            "required execution environment does not satisfy the existing trust gate"
        )
    manifest = json.loads((root / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1 or set(manifest.get("snapshots", {})) != {
        "build-backed",
        "asan",
    }:
        raise ValueError("invalid staged fixture manifest")
    adapter = readonly_snapshot_adapter(cases.prepare_snapshot, root, manifest)
    suite = unittest.defaultTestLoader.loadTestsFromNames(
        ["tests.test_cxx_analyzer." + name for name in TEST_CLASSES]
    )
    with patch.object(cases, "prepare_snapshot", side_effect=adapter):
        result = unittest.TextTestRunner(verbosity=2, resultclass=RequiredExecutionResult).run(
            suite
        )
    success = required_execution_succeeded(result)
    print(
        json.dumps(
            {
                "required_tests": len(EXPECTED_METHODS),
                "run": result.testsRun,
                "passed": len(result.passed_methods),
                "skipped": len(result.skipped),
                "result": "PASS" if success else "FAIL",
            }
        ),
        flush=True,
    )
    return success


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("stage", "run"))
    args = parser.parse_args()
    if args.phase == "stage":
        stage_fixtures()
        return 0
    return 0 if run_required_tests() else 1


if __name__ == "__main__":
    raise SystemExit(main())
