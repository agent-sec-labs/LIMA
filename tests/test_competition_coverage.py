"""Offline E04 acceptance tests; all bundles below are synthetic."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

from lima.competition_coverage import CoverageInputError, render_markdown, summarize_bundle

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "summarize_competition_coverage.py"


def write_demo_bundles(root: Path) -> tuple[Path, Path]:
    """Create two tiny inputs for the documented manual acceptance commands."""
    current = root / "current"
    legacy = root / "legacy"
    vulnerable = {
        "file_coverage": 0.5,
        "byte_coverage": 0.25,
        "unreviewed_units": ["src/b.c"],
        "diagnostics": [
            "coverage gap: BUDGET",
            "coverage gap: BUDGET",
            "provider-unavailable",
        ],
        "findings": [],
    }
    fixed = {
        "file_coverage": 1.0,
        "byte_coverage": 1.0,
        "unreviewed_units": [],
        "diagnostics": [],
        "findings": [],
    }
    for directory, document in (
        (current, {
            "case_id": "synthetic-current",
            "status": "failed",
            "vulnerable": vulnerable,
            "fixed": fixed,
        }),
        (legacy, {
            "case_id": "synthetic-legacy",
            "status": "inconclusive",
            "vulnerable": {"file_coverage": 1.0, "byte_coverage": 1.0, "findings": []},
            "fixed": {},
        }),
    ):
        directory.mkdir(parents=True, exist_ok=False)
        (directory / "summary.json").write_text(
            json.dumps(document, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
    (current / "vulnerable").mkdir()
    (current / "vulnerable" / "platform.json").write_text(
        json.dumps(vulnerable, indent=2) + "\n", encoding="utf-8",
    )
    return current, legacy


class CompetitionCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bundle, self.legacy = write_demo_bundles(self.root)

    def _summary(self):
        return json.loads((self.bundle / "summary.json").read_text(encoding="utf-8"))

    def _write_summary(self, document):
        (self.bundle / "summary.json").write_text(
            json.dumps(document, ensure_ascii=False), encoding="utf-8",
        )

    def _remove_platform(self):
        (self.bundle / "vulnerable" / "platform.json").unlink()

    def _cli(self, *args):
        # The stock Docker test image contains lima/, not this new script.
        # Exercise the same shared main via the package; Docker acceptance
        # below separately runs the standalone script for every E2E case.
        return subprocess.run(  # noqa: S603 - fixed local script, synthetic input
            [sys.executable, "-m", "lima.competition_coverage",
             "--bundle", str(self.bundle), *args],
            env={**os.environ, "PYTHONPATH": str(ROOT), "PYTHONUTF8": "1"},
            cwd=self.root, capture_output=True, text=True, encoding="utf-8", check=False,
        )

    def _fingerprints(self):
        return {
            str(path.relative_to(self.bundle)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in self.bundle.rglob("*") if path.is_file()
        }

    def test_complete_fields_and_sources_remain_separate_per_side(self):
        report = summarize_bundle(self.bundle)
        self.assertEqual(1, report["schema_version"])
        self.assertEqual("synthetic-current", report["case_id"])
        self.assertEqual("failed", report["validation_status"])
        vulnerable, fixed = report["vulnerable"], report["fixed"]
        self.assertEqual(0.5, vulnerable["snapshot_file_coverage"])
        self.assertEqual(0.25, vulnerable["snapshot_byte_coverage"])
        self.assertEqual(["src/b.c"], vulnerable["unreviewed_units"])
        self.assertEqual(1, vulnerable["unreviewed_count"])
        self.assertEqual(1.0, fixed["snapshot_file_coverage"])
        self.assertEqual([], fixed["unreviewed_units"])
        self.assertEqual(0, fixed["unreviewed_count"])
        self.assertEqual(
            ["summary.json#/vulnerable/file_coverage", "vulnerable/platform.json#/file_coverage"],
            vulnerable["field_sources"]["snapshot_file_coverage"],
        )
        self.assertEqual(["summary.json#/status"], report["field_sources"]["validation_status"])
        for side in (vulnerable, fixed):
            for key in ("expected_tu_count", "reviewed_tu_count", "semantic_review_coverage"):
                self.assertIsNone(side[key])
                self.assertEqual([], side["field_sources"][key])
                self.assertIn(key, side["field_notes"])
        json.dumps(report, allow_nan=False)

    def test_legacy_absence_is_unknown_not_zero(self):
        report = summarize_bundle(self.legacy)
        for key in ("unreviewed_units", "unreviewed_count", "coverage_gaps", "diagnostics"):
            self.assertIsNone(report["vulnerable"][key])
        self.assertIsNone(report["fixed"]["snapshot_file_coverage"])
        self.assertEqual([], report["fixed"]["field_sources"]["snapshot_file_coverage"])
        self.assertIn("未记录", render_markdown(report))
        self.assertNotIn("0 个未审阅", render_markdown(report))

    def test_empty_units_and_no_findings_do_not_prove_semantic_coverage(self):
        document = self._summary()
        document["fixed"].update(expected_tu_count=9, reviewed_tu_count=9)
        self._write_summary(document)
        (self.bundle / "case.json").write_text(
            json.dumps({"translation_units": ["src/a.c"]}), encoding="utf-8",
        )
        fixed = summarize_bundle(self.bundle)["fixed"]
        self.assertEqual([], fixed["unreviewed_units"])
        self.assertEqual(0, fixed["unreviewed_count"])
        self.assertIsNone(fixed["expected_tu_count"])
        self.assertIsNone(fixed["reviewed_tu_count"])
        self.assertIsNone(fixed["semantic_review_coverage"])
        markdown = render_markdown(summarize_bundle(self.bundle))
        self.assertIn("不可计算", markdown)
        self.assertNotIn("全部代码安全", markdown)

    def test_gap_exact_prefix_dedup_sort_and_other_diagnostics(self):
        self._remove_platform()
        document = self._summary()
        document["vulnerable"]["diagnostics"] = [
            "coverage gap: Z", "coverage gap: A", "coverage gap: Z",
            " coverage gap: Z", "Coverage gap: A", "prefix coverage gap: A",
            "coverage gap:A", "coverage gap: A ", "other", "other",
        ]
        document["fixed"]["diagnostics"] = ["coverage gap: Z"]
        self._write_summary(document)
        report = summarize_bundle(self.bundle)
        self.assertEqual(["A", "A ", "Z"], report["vulnerable"]["coverage_gaps"])
        self.assertEqual(3, report["vulnerable"]["coverage_gap_count"])
        self.assertEqual(["Z"], report["fixed"]["coverage_gaps"])
        self.assertEqual(1, report["fixed"]["coverage_gap_count"])
        self.assertEqual(
            [" coverage gap: Z", "Coverage gap: A", "prefix coverage gap: A",
             "coverage gap:A", "other", "other"],
            report["vulnerable"]["diagnostics"],
        )
        self.assertEqual(
            ["summary.json#/vulnerable/diagnostics"],
            report["vulnerable"]["field_sources"]["coverage_gap_count"],
        )

    def test_unreviewed_units_preserve_recorded_list_and_count(self):
        self._remove_platform()
        document = self._summary()
        document["vulnerable"]["unreviewed_units"] = ["b.c", "a.c", "b.c"]
        self._write_summary(document)
        side = summarize_bundle(self.bundle)["vulnerable"]
        self.assertEqual(["b.c", "a.c", "b.c"], side["unreviewed_units"])
        self.assertEqual(3, side["unreviewed_count"])

    def test_invalid_ratios_fail_with_file_and_field(self):
        self._remove_platform()
        original = self._summary()
        for field in ("file_coverage", "byte_coverage"):
            for invalid in (-0.1, 1.1, float("nan"), float("inf"), -float("inf"),
                            True, "0.5", [], {}):
                with self.subTest(field=field, invalid=invalid):
                    document = copy.deepcopy(original)
                    document["fixed"][field] = invalid
                    self._write_summary(document)
                    with self.assertRaises(CoverageInputError) as caught:
                        summarize_bundle(self.bundle)
                    self.assertIn(f"summary.json#/fixed/{field}", str(caught.exception))

    def test_explicit_null_fields_remain_unknown_with_sources(self):
        self._remove_platform()
        document = self._summary()
        document["fixed"] = dict.fromkeys(
            ("file_coverage", "byte_coverage", "unreviewed_units", "diagnostics"),
        )
        self._write_summary(document)
        side = summarize_bundle(self.bundle)["fixed"]
        for key in ("snapshot_file_coverage", "snapshot_byte_coverage", "unreviewed_units",
                    "unreviewed_count", "coverage_gaps", "coverage_gap_count", "diagnostics"):
            self.assertIsNone(side[key])
            self.assertTrue(side["field_sources"][key])

    def test_ratio_boundaries_numeric_agreement_and_unknown_status(self):
        document = self._summary()
        document["status"] = "future-status"
        document["vulnerable"].update(file_coverage=0, byte_coverage=1)
        self._write_summary(document)
        platform = copy.deepcopy(document["vulnerable"])
        platform.update(file_coverage=0.0, byte_coverage=1.0)
        (self.bundle / "vulnerable" / "platform.json").write_text(
            json.dumps(platform), encoding="utf-8",
        )
        report = summarize_bundle(self.bundle)
        self.assertEqual("future-status", report["validation_status"])
        self.assertEqual(0, report["vulnerable"]["snapshot_file_coverage"])
        self.assertEqual(1, report["vulnerable"]["snapshot_byte_coverage"])
        self.assertIn("0%", render_markdown(report))

    def test_non_finite_exponent_has_precise_field_location(self):
        (self.bundle / "summary.json").write_text(
            '{"fixed":{"byte_coverage":1e400}}', encoding="utf-8",
        )
        with self.assertRaises(CoverageInputError) as caught:
            summarize_bundle(self.bundle)
        self.assertIn("summary.json#/fixed/byte_coverage", str(caught.exception))

    def test_unreadable_document_reports_file(self):
        with patch("lima.competition_coverage.Path.read_text", side_effect=PermissionError):
            with self.assertRaises(CoverageInputError) as caught:
                summarize_bundle(self.bundle)
        self.assertIn("summary.json#", str(caught.exception))
        self.assertIn("PermissionError", str(caught.exception))

    def test_does_not_consume_case_or_manifest_as_denominator_or_validator(self):
        for name in ("case.json", "SHA256SUMS.json"):
            (self.bundle / name).write_text("deliberately not JSON", encoding="utf-8")
        report = summarize_bundle(self.bundle)
        self.assertIsNone(report["vulnerable"]["expected_tu_count"])
        self.assertIsNone(report["fixed"]["semantic_review_coverage"])

    def test_conflicts_list_all_overlapping_fields(self):
        platform_path = self.bundle / "vulnerable" / "platform.json"
        platform = json.loads(platform_path.read_text(encoding="utf-8"))
        platform.update(file_coverage=0.75, unreviewed_units=[], diagnostics=[], findings=[{}])
        platform_path.write_text(json.dumps(platform), encoding="utf-8")
        with self.assertRaises(CoverageInputError) as caught:
            summarize_bundle(self.bundle)
        for key in ("file_coverage", "unreviewed_units", "diagnostics", "findings"):
            self.assertIn(f"summary.json#/vulnerable/{key}", str(caught.exception))
            self.assertIn(f"vulnerable/platform.json#/{key}", str(caught.exception))

    def test_invalid_platform_value_is_not_hidden_by_equal_numeric_summary(self):
        document = self._summary()
        document["vulnerable"]["file_coverage"] = 1
        self._write_summary(document)
        path = self.bundle / "vulnerable" / "platform.json"
        platform = json.loads(path.read_text(encoding="utf-8"))
        platform["file_coverage"] = True
        path.write_text(json.dumps(platform), encoding="utf-8")
        with self.assertRaises(CoverageInputError) as caught:
            summarize_bundle(self.bundle)
        self.assertIn("vulnerable/platform.json#/file_coverage", str(caught.exception))

    def test_platform_only_fields_have_platform_sources(self):
        document = self._summary()
        del document["vulnerable"]
        self._write_summary(document)
        side = summarize_bundle(self.bundle)["vulnerable"]
        self.assertEqual(0.5, side["snapshot_file_coverage"])
        self.assertEqual(["vulnerable/platform.json#/file_coverage"],
                         side["field_sources"]["snapshot_file_coverage"])

    def test_unknown_metadata_and_fields_are_not_guessed(self):
        self._remove_platform()
        self._write_summary({"unknown": {"version": 999}, "vulnerable": {"new_metric": 3}})
        report = summarize_bundle(self.bundle)
        self.assertIsNone(report["case_id"])
        self.assertIsNone(report["validation_status"])
        self.assertIsNone(report["vulnerable"]["snapshot_file_coverage"])

    def test_invalid_projected_types_are_rejected(self):
        self._remove_platform()
        original = self._summary()
        for field, value in (("unreviewed_units", "a.c"), ("unreviewed_units", [1]),
                             ("diagnostics", {}), ("diagnostics", [None])):
            with self.subTest(field=field, value=value):
                document = copy.deepcopy(original)
                document["fixed"][field] = value
                self._write_summary(document)
                with self.assertRaises(CoverageInputError) as caught:
                    summarize_bundle(self.bundle)
                self.assertIn(f"summary.json#/fixed/{field}", str(caught.exception))
        for key, value in (("vulnerable", []), ("fixed", None), ("status", 42), ("case_id", [])):
            with self.subTest(key=key):
                document = copy.deepcopy(original)
                document[key] = value
                self._write_summary(document)
                with self.assertRaises(CoverageInputError) as caught:
                    summarize_bundle(self.bundle)
                self.assertIn(f"summary.json#/{key}", str(caught.exception))

    def test_bad_json_roots_encoding_and_missing_files(self):
        path = self.bundle / "summary.json"
        for contents in (b'{"broken":', b'[]', b'null', b'\xff',
                         b'{"status":"failed","status":"passed"}'):
            with self.subTest(contents=contents):
                path.write_bytes(contents)
                with self.assertRaises(CoverageInputError) as caught:
                    summarize_bundle(self.bundle)
                self.assertIn("summary.json#", str(caught.exception))
        path.unlink()
        with self.assertRaises(CoverageInputError):
            summarize_bundle(self.bundle)

    def test_existing_broken_platform_is_not_treated_as_absent(self):
        path = self.bundle / "vulnerable" / "platform.json"
        for contents in ("{bad", "[]"):
            with self.subTest(contents=contents):
                path.write_text(contents, encoding="utf-8")
                with self.assertRaises(CoverageInputError) as caught:
                    summarize_bundle(self.bundle)
                self.assertIn("vulnerable/platform.json#", str(caught.exception))

    def test_markdown_and_json_share_values_and_preserve_failed_status(self):
        before = self._fingerprints()
        json_run = self._cli("--format", "json")
        markdown_run = self._cli("--format", "markdown")
        self.assertEqual(0, json_run.returncode, json_run.stderr)
        self.assertEqual(0, markdown_run.returncode, markdown_run.stderr)
        report = json.loads(json_run.stdout)
        self.assertEqual(summarize_bundle(self.bundle), report)
        self.assertEqual(render_markdown(report), markdown_run.stdout)
        self.assertEqual("failed", report["validation_status"])
        self.assertIn("failed", markdown_run.stdout)
        self.assertIn("50%", markdown_run.stdout)
        self.assertIn("25%", markdown_run.stdout)
        self.assertIn("summary.json#/vulnerable/file_coverage", markdown_run.stdout)
        self.assertEqual(before, self._fingerprints())

    def test_cli_bad_input_has_nonzero_exit_stderr_and_no_partial_stdout(self):
        before = self._fingerprints()
        (self.bundle / "summary.json").write_text('{"fixed":{"file_coverage":2}}',
                                                 encoding="utf-8")
        damaged = self._fingerprints()
        for format_name in ("json", "markdown"):
            result = self._cli("--format", format_name)
            self.assertEqual(2, result.returncode)
            self.assertEqual("", result.stdout)
            self.assertIn("summary.json#/fixed/file_coverage", result.stderr)
        self.assertEqual(damaged, self._fingerprints())
        self.assertNotEqual(before, damaged)

    def test_markdown_escapes_bundle_text(self):
        self._remove_platform()
        document = self._summary()
        document["case_id"] = "<script>alert(1)</script> | row\nnext *bold*"
        self._write_summary(document)
        markdown = render_markdown(summarize_bundle(self.bundle))
        self.assertNotIn("<script>", markdown)
        self.assertIn("&lt;script&gt;", markdown)
        self.assertNotIn("*bold*", markdown)


def run_docker_acceptance(output: Path) -> int:
    """Run E04 acceptance in Linux Docker and retain raw, synthetic evidence.

    Invoke with ``python -m tests.test_competition_coverage --docker-acceptance
    --output /evidence/run``. The output directory must not already exist.
    The caller supplies a non-root container, read-only rootfs and no network.
    """
    output.mkdir(parents=True, exist_ok=False)
    report = {
        "status": "failed",
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": {
            "python": sys.version,
            "platform": platform.platform(),
            "uid": os.getuid() if hasattr(os, "getuid") else None,
        },
        "source_sha256": {
            relative: hashlib.sha256((ROOT / relative).read_bytes()).hexdigest()
            for relative in (
                "lima/competition_coverage.py",
                "scripts/summarize_competition_coverage.py",
                "tests/test_competition_coverage.py",
            )
        },
        "suites": {},
        "cli_runs": [],
        "checks": [],
    }

    def require(condition, name):
        if not condition:
            raise AssertionError(name)
        report["checks"].append(name)

    def fingerprint(directory):
        return {
            str(path.relative_to(directory)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(directory.rglob("*")) if path.is_file()
        }

    def run_suite(label, modules, expected):
        stream = io.StringIO()
        with contextlib.redirect_stdout(stream), contextlib.redirect_stderr(stream):
            suite = unittest.defaultTestLoader.loadTestsFromNames(modules)
            result = unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)
        (output / f"{label}.log").write_text(stream.getvalue(), encoding="utf-8")
        report["suites"][label] = {
            "run": result.testsRun, "failures": len(result.failures),
            "errors": len(result.errors), "skipped": len(result.skipped),
        }
        require(result.wasSuccessful() and result.testsRun == expected and not result.skipped,
                f"{label}: {expected} tests passed with zero skips")

    def freeze(directory):
        for path in directory.rglob("*"):
            path.chmod(0o555 if path.is_dir() else 0o444)
        directory.chmod(0o555)

    def thaw(directory):
        directory.chmod(0o755)
        for path in directory.rglob("*"):
            path.chmod(0o755 if path.is_dir() else 0o644)

    try:
        require(sys.platform == "linux" and Path("/.dockerenv").is_file(),
                "running inside Linux Docker")
        require(report["environment"]["uid"] != 0, "container user is non-root")
        run_suite("unit-tests", ["tests.test_competition_coverage"], 21)
        run_suite("regression-tests", [
            "tests.test_openharmony_validation", "tests.test_ci_contract",
        ], 70)

        from tests.test_openharmony_validation import BundleWriterTests

        fixture = BundleWriterTests("test_bundle_layout_digests_and_summary")
        try:
            fixture.setUp()
            bundle = fixture._write()
            before = fingerprint(bundle)
            projected = summarize_bundle(bundle)
            (output / "writer-summary.json").write_text(
                json.dumps(projected, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
            )
            require(projected["validation_status"] == fixture.result.status.value,
                    "real bundle writer: validation status preserved")
            require(all(
                len(projected[side]["field_sources"]["snapshot_file_coverage"]) == 2
                and projected[side]["semantic_review_coverage"] is None
                for side in ("vulnerable", "fixed")
            ), "real bundle writer: both sources agree, semantic coverage stays unknown")
            require(before == fingerprint(bundle), "real bundle writer: input unchanged")
        finally:
            fixture.doCleanups()

        with tempfile.TemporaryDirectory(prefix="e04-docker-") as temporary:
            temp_root = Path(temporary)
            current, legacy = write_demo_bundles(temp_root)
            empty = temp_root / "empty"
            shutil.copytree(legacy, empty)
            (empty / "summary.json").write_text(json.dumps({
                "status": "failed", "vulnerable": {
                    "file_coverage": 1, "byte_coverage": 1, "unreviewed_units": [],
                    "diagnostics": [], "findings": [],
                }, "fixed": {},
            }), encoding="utf-8")
            gaps = temp_root / "per-side-gaps"
            gaps.mkdir()
            (gaps / "summary.json").write_text(json.dumps({
                "status": "inconclusive",
                "vulnerable": {"diagnostics": [
                    "coverage gap: Z", "coverage gap: A", "coverage gap: Z", "other",
                ]},
                "fixed": {"diagnostics": ["coverage gap: Z"]},
            }), encoding="utf-8")
            conflict = temp_root / "conflict"
            shutil.copytree(current, conflict)
            path = conflict / "vulnerable" / "platform.json"
            changed = json.loads(path.read_text(encoding="utf-8"))
            changed["file_coverage"] = 0.75
            path.write_text(json.dumps(changed), encoding="utf-8")
            invalid = {
                "out-of-range": ('{"fixed":{"file_coverage":2}}',
                                 "summary.json#/fixed/file_coverage"),
                "nan": ('{"fixed":{"byte_coverage":NaN}}',
                        "summary.json#/fixed/byte_coverage"),
                "broken-json": ('{"broken":', "summary.json#"),
                "missing-summary": (None, "summary.json#"),
            }
            for name, (contents, _error) in invalid.items():
                directory = temp_root / name
                directory.mkdir()
                if contents is not None:
                    (directory / "summary.json").write_text(contents, encoding="utf-8")
            expected_errors = {
                "conflict": "summary.json#/vulnerable/file_coverage",
                **{name: error for name, (_contents, error) in invalid.items()},
            }
            expected_errors["conflict"] += " != vulnerable/platform.json#/file_coverage"
            destinations = output / "cli"
            destinations.mkdir()
            for directory in sorted(temp_root.iterdir()):
                shutil.copytree(directory, output / "inputs" / directory.name)
                before = fingerprint(directory)
                freeze(directory)
                try:
                    try:
                        (directory / "write-probe").touch()
                    except PermissionError:
                        pass
                    else:
                        raise AssertionError(f"{directory.name}: input not read-only")
                    for format_name, suffix in (("json", "json"), ("markdown", "md")):
                        run = subprocess.run(  # noqa: S603 - fixed CLI and synthetic paths
                            [sys.executable, str(SCRIPT), "--bundle", str(directory),
                             "--format", format_name],
                            cwd="/tmp", capture_output=True, text=True,
                            encoding="utf-8", timeout=30, check=False,
                        )
                        name = f"{directory.name}.{suffix}"
                        (destinations / name).write_text(run.stdout, encoding="utf-8")
                        (destinations / f"{name}.stderr.txt").write_text(
                            run.stderr, encoding="utf-8",
                        )
                        expected_error = expected_errors.get(directory.name)
                        report["cli_runs"].append({
                            "case": directory.name, "format": format_name,
                            "exit_code": run.returncode,
                            "expected_exit_code": 2 if expected_error else 0,
                        })
                        if expected_error:
                            require(run.returncode == 2 and not run.stdout
                                    and expected_error in run.stderr,
                                    f"{name}: exit 2, no stdout, precise error location")
                        else:
                            require(run.returncode == 0 and not run.stderr,
                                    f"{name}: CLI succeeded")
                            if format_name == "json":
                                value = json.loads(run.stdout)
                                require(all(value[side][key] is None
                                            for side in ("vulnerable", "fixed")
                                            for key in ("expected_tu_count", "reviewed_tu_count",
                                                        "semantic_review_coverage")),
                                        f"{name}: no invented TU denominator or coverage")
                    require(before == fingerprint(directory),
                            f"{directory.name}: input files and bytes unchanged")
                finally:
                    thaw(directory)

            def result(name):
                return json.loads((destinations / f"{name}.json").read_text(encoding="utf-8"))

            first, old, empty_result, gap_result = (
                result(name) for name in ("current", "legacy", "empty", "per-side-gaps")
            )
            markdown = (destinations / "current.md").read_text(encoding="utf-8")
            require(first["vulnerable"]["snapshot_file_coverage"] == 0.5
                    and "| 快照文件覆盖率 | 50% | 100% |" in markdown,
                    "AC-01: JSON ratio 0.5, Markdown percentage 50%, sides separate")
            require(first["validation_status"] == "failed" and "validation_status：failed" in markdown,
                    "failed status preserved despite 100% fixed snapshot coverage")
            require(old["vulnerable"]["unreviewed_units"] is None
                    and old["vulnerable"]["unreviewed_count"] is None
                    and "| 未审阅条目数 | 未记录 | 未记录 |" in (
                        destinations / "legacy.md").read_text(encoding="utf-8"),
                    "AC-02: missing units remain null and unrecorded")
            require(empty_result["vulnerable"]["unreviewed_units"] == []
                    and empty_result["vulnerable"]["unreviewed_count"] == 0
                    and empty_result["vulnerable"]["semantic_review_coverage"] is None,
                    "AC-02: empty units do not imply semantic completeness")
            require(first["vulnerable"]["coverage_gap_count"] == 1
                    and gap_result["vulnerable"]["coverage_gaps"] == ["A", "Z"]
                    and gap_result["fixed"]["coverage_gaps"] == ["Z"]
                    and gap_result["vulnerable"]["coverage_gap_count"] == 2
                    and gap_result["fixed"]["coverage_gap_count"] == 1,
                    "AC-03: gap kinds deduplicated, sorted and separate per side")
        report["status"] = "passed"
    except Exception as exc:
        report["error"] = f"{type(exc).__name__}: {exc}"
    finally:
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8",
        )
    print(json.dumps({
        "status": report["status"], "suites": report["suites"],
        "cli_runs": len(report["cli_runs"]), "checks_passed": len(report["checks"]),
        "report": str(output / "report.json"), "error": report.get("error"),
    }, ensure_ascii=False, indent=2))
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    if "--docker-acceptance" in sys.argv:
        import argparse

        parser = argparse.ArgumentParser(description="Offline E04 Docker acceptance runner")
        parser.add_argument("--docker-acceptance", action="store_true", required=True)
        parser.add_argument("--output", required=True, type=Path)
        args = parser.parse_args()
        raise SystemExit(run_docker_acceptance(args.output))
    unittest.main()
