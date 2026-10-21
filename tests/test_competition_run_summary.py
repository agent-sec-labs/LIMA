"""Synthetic test-first contract and repeatable demo for Issue #312."""

from __future__ import annotations

import contextlib
import copy
import csv
import hashlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from lima.competition_run_summary import main


def write_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False), encoding="utf-8")


def bundle(path, status="failed", case_id="synthetic-pair"):
    case = {"case_id": case_id, "vulnerable": {"commit": "a" * 40},
            "fixed": {"commit": "b" * 40}}
    vulnerable = {"status": status, "findings": [
        {"state": "runtime-confirmed"}, {"state": "semantic-supported"},
        {"state": "semantic-supported"}], "diagnostics": ["provider-unavailable"]}
    fixed = {"status": "passed", "findings": [], "diagnostics": []}
    summary = {"case_id": case_id, "status": status,
               "reason_codes": [] if status == "passed" else ["vulnerable-replay-unstable"],
               "vulnerable": vulnerable, "fixed": fixed, "total_elapsed_seconds": 12.5}
    write_json(path / "case.json", case)
    write_json(path / "summary.json", summary)
    for side in ("vulnerable", "fixed"):
        write_json(path / side / "platform.json", summary[side])
    return summary


def tree_bytes(root):
    return {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in root.rglob("*") if p.is_file()}


def write_demo(root):
    """Create two small bundles and an explicit manifest, without overwriting."""
    root.mkdir(parents=True, exist_ok=False)
    bundle(root / "round-passed", "passed")
    bundle(root / "round-failed", "failed")
    write_json(root / "performance.json", {
        "schema_version": 1, "wall_time_seconds": 13.25,
        "host": {"sampled_peak_rss_bytes": 1048576,
                 "measurement_source": "synthetic psutil sample", "complete": True},
    })
    write_json(root / "runs.json", {"schema_version": 1, "runs": [
        {"run_label": "round-passed", "bundle_dir": "round-passed",
         "performance_file": "performance.json", "execution_label": "synthetic"},
        {"run_label": "round-failed", "bundle_dir": "round-failed"},
    ]})


class RunSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "runs.json"
        self.output = self.root / "result"
        self.summary = bundle(self.root / "one")
        self.entries = [{"run_label": "round-1", "bundle_dir": "one"}]

    def run_tool(self, entries=None, output=None, manifest=None):
        write_json(self.input, manifest if manifest is not None else {
            "schema_version": 1, "runs": self.entries if entries is None else entries})
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr), contextlib.redirect_stdout(io.StringIO()):
            result = main(["--inputs", str(self.input), "--output-dir",
                           str(output or self.output)])
        self.stderr = stderr.getvalue()
        return result

    def rows(self):
        with (self.output / "summary.csv").open(encoding="utf-8", newline="") as stream:
            return list(csv.DictReader(stream))

    def errors(self):
        return json.loads((self.output / "errors.json").read_text(encoding="utf-8"))["errors"]

    def test_same_case_two_runs_stable_and_preserved(self):
        bundle(self.root / "two", "passed")
        entries = [dict(self.entries[0], run_label="z-failed"),
                   {"run_label": "a-passed", "bundle_dir": "two"}]
        self.assertEqual(self.run_tool(entries), 0)
        rows = self.rows()
        self.assertEqual([r["run_label"] for r in rows], ["a-passed", "z-failed"])
        self.assertEqual([r["case_id"] for r in rows], ["synthetic-pair"] * 2)
        self.assertEqual([r["validation_status"] for r in rows], ["passed", "failed"])
        self.assertEqual(json.loads(rows[1]["reason_codes"]), ["vulnerable-replay-unstable"])
        original = (self.output / "summary.csv").read_bytes()
        other = self.root / "again"
        self.assertEqual(self.run_tool(list(reversed(entries)), other), 0)
        self.assertEqual(original, (other / "summary.csv").read_bytes())

    def test_side_counts_commits_hash_and_sources(self):
        raw = (self.root / "one" / "summary.json").read_bytes()
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["vulnerable_commit"], "a" * 40)
        self.assertEqual(row["fixed_commit"], "b" * 40)
        self.assertEqual(json.loads(row["vulnerable_findings_by_state"]),
                         {"runtime-confirmed": 1, "semantic-supported": 2})
        self.assertEqual(json.loads(row["fixed_findings_by_state"]), {})
        self.assertEqual(row["summary_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(float(row["total_elapsed_seconds"]), 12.5)
        self.assertIn("summary.json", row["field_sources"])
        self.assertNotIn("integrity_valid", row)
        self.assertIn("not verified", (self.output / "summary.md").read_text())
        self.assertEqual(self.errors(), [])

    def test_legacy_missing_null_and_unknown_identity(self):
        write_json(self.root / "one" / "summary.json", {"status": "inconclusive"})
        (self.root / "one" / "case.json").unlink()
        for side in ("vulnerable", "fixed"):
            (self.root / "one" / side / "platform.json").unlink()
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["validation_status"], "inconclusive")
        for field in ("case_id", "fixed_commit", "vulnerable_findings_by_state",
                      "total_elapsed_seconds", "performance_wall_time_seconds"):
            self.assertEqual(row[field], "null", field)
            self.assertIn(field, row["unknown_reasons"])
        self.assertEqual(row["execution_mode"], "unknown")
        self.assertEqual(row["model_identity"], "unknown")

    def test_state_does_not_prove_model_or_execution(self):
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["execution_mode"], "unknown")
        self.assertEqual(row["model_identity"], "unknown")

    def test_explicit_execution_identity_and_label_separate(self):
        self.summary.update(execution_mode="paired-validation", model_identity="synthetic-model")
        write_json(self.root / "one" / "summary.json", self.summary)
        self.entries[0]["execution_label"] = "operator label"
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["execution_mode"], "paired-validation")
        self.assertEqual(row["model_identity"], "synthetic-model")
        self.assertEqual(row["execution_label"], "operator label")

    def test_partial_bad_json_and_missing_summary_keep_rows(self):
        bundle(self.root / "bad")
        (self.root / "bad" / "summary.json").write_text('{"secret":', encoding="utf-8")
        entries = self.entries + [{"run_label": "bad", "bundle_dir": "bad"},
                                  {"run_label": "missing", "bundle_dir": "absent"}]
        self.assertEqual(self.run_tool(entries), 2)
        self.assertEqual(len(self.rows()), 3)
        self.assertEqual({e["run_label"] for e in self.errors()}, {"bad", "missing"})
        self.assertEqual(next(r for r in self.rows() if r["run_label"] == "bad")["row_status"],
                         "error")
        self.assertNotIn("secret", json.dumps(self.errors()))

    def test_duplicate_keys_rejected_in_every_document(self):
        for file in ("case.json", "summary.json", "vulnerable/platform.json", "fixed/platform.json"):
            with self.subTest(file=file):
                bundle(self.root / "one")
                (self.root / "one" / file).write_text('{"x":1,"x":2}', encoding="utf-8")
                self.assertEqual(self.run_tool(output=self.root / file.replace("/", "-")), 2)

    def test_manifest_duplicate_keys_and_versions_are_usage_errors(self):
        for value in ({"schema_version": 2, "runs": self.entries},
                      {"schema_version": True, "runs": self.entries}, {"runs": []},
                      {"schema_version": 1, "runs": [{"run_label": "x"}]}):
            self.assertEqual(self.run_tool(manifest=value), 3)
            self.assertFalse(self.output.exists())
        self.input.write_text('{"runs":[],"runs":[]}', encoding="utf-8")
        self.assertEqual(main(["--inputs", str(self.input), "--output-dir", str(self.output)]), 3)

    def test_conflicts_named_and_no_side_fallback(self):
        changes = [("case.json", {"case_id": "different"}),
                   ("case.json", {"vulnerable": {"commit": "c" * 40}}),
                   ("vulnerable/platform.json", {"findings": []}),
                   ("fixed/platform.json", {"status": "failed"})]
        for index, (file, changeset) in enumerate(changes):
            bundle(self.root / "one")
            p = self.root / "one" / file
            value = json.loads(p.read_text())
            value.update(changeset)
            if "vulnerable" in changeset:
                self.summary["vulnerable"]["commit"] = "a" * 40
                write_json(self.root / "one" / "summary.json", self.summary)
            write_json(p, value)
            out = self.root / f"conflict-{index}"
            self.assertEqual(self.run_tool(output=out), 2)
            errors = json.loads((out / "errors.json").read_text())["errors"]
            self.assertIn("field_conflict", str(errors))
            self.assertIn(file, str(errors))

    def test_missing_side_never_borrows_opposite_side(self):
        self.summary.pop("fixed")
        write_json(self.root / "one" / "summary.json", self.summary)
        (self.root / "one" / "fixed" / "platform.json").unlink()
        self.assertEqual(self.run_tool(), 0)
        self.assertEqual(self.rows()[0]["fixed_findings_by_state"], "null")

    def test_missing_performance_is_nonfatal_unknown(self):
        self.entries[0]["performance_file"] = "gone.json"
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["performance_wall_time_seconds"], "null")
        self.assertEqual(row["host_sampled_peak_rss_bytes"], "null")
        self.assertIn("performance_unavailable", row["unknown_reasons"])

    def test_performance_schema_one_projection_and_source(self):
        write_json(self.root / "perf.json", {
            "schema_version": 1, "wall_time_seconds": 0,
            "host": {"sampled_peak_rss_bytes": 2048, "measurement_source": "mock RSS",
                     "complete": False},
            "container": {"sampled_peak_memory_bytes": 1024, "measurement_source": "mock stats"},
            "private": str(self.root)})
        self.entries[0]["performance_file"] = "perf.json"
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["performance_wall_time_seconds"], "0")
        self.assertEqual(row["host_sampled_peak_rss_bytes"], "2048")
        self.assertEqual(row["host_sampling_complete"], "false")
        self.assertEqual(row["host_measurement_source"], "mock RSS")
        self.assertEqual(row["container_sampled_peak_memory_bytes"], "1024")

    def test_incompatible_performance_nonfatal_duplicate_invalid_fatal(self):
        self.entries[0]["performance_file"] = "perf.json"
        for index, version in enumerate((2, "1", True)):
            write_json(self.root / "perf.json", {"schema_version": version})
            out = self.root / f"version-{index}"
            self.assertEqual(self.run_tool(output=out), 0)
            self.assertIn("performance_schema_unsupported", (out / "summary.csv").read_text())
        (self.root / "perf.json").write_text('{"schema_version":1,"host":{},"host":{}}')
        self.assertEqual(self.run_tool(), 2)

    def test_duplicate_labels_and_resolved_bundle_paths_reject(self):
        for entries in (self.entries * 2,
                        self.entries + [{"run_label": "another", "bundle_dir": "one/../one"}]):
            self.assertEqual(self.run_tool(entries), 3)
            self.assertFalse(self.output.exists())
            self.assertIn("round-1", self.stderr)

    def test_output_existing_input_nested_and_ancestor_rejected(self):
        before = tree_bytes(self.root / "one")
        self.output.mkdir()
        self.assertEqual(self.run_tool(), 3)
        for out in (self.root / "one" / "new", self.root / "one"):
            self.assertEqual(self.run_tool(output=out), 3)
        self.assertEqual(before, tree_bytes(self.root / "one"))

    def test_formula_injection_and_markdown_escaping(self):
        for index, prefix in enumerate(("=", "+", "-", "@", "\t")):
            output = self.root / f"formula-{index}"
            self.assertEqual(self.run_tool([dict(self.entries[0], run_label=prefix + "x|y\nz")],
                                           output), 0)
            with (output / "summary.csv").open(newline="", encoding="utf-8") as stream:
                row = next(csv.DictReader(stream))
            self.assertEqual(row["run_label"], "'" + prefix + "x|y\nz")
            md = (output / "summary.md").read_text()
            self.assertIn("x\\|y<br>z", md)

    def test_absolute_inputs_relative_evidence_and_input_unchanged(self):
        before = tree_bytes(self.root / "one")
        self.entries[0]["bundle_dir"] = str(self.root / "one")
        self.assertEqual(self.run_tool(), 0)
        self.assertEqual(before, tree_bytes(self.root / "one"))
        for file in self.output.iterdir():
            text = file.read_text(encoding="utf-8")
            self.assertNotIn(str(self.root), text)
            self.assertNotIn(self.root.as_posix(), text)
        self.assertIn("bundle:round-1/summary.json", self.rows()[0]["summary_ref"])

    def test_invalid_types_numbers_and_json_roots(self):
        mutations = [{"total_elapsed_seconds": True}, {"total_elapsed_seconds": -1},
                     {"total_elapsed_seconds": float("inf")}, {"reason_codes": "no"},
                     {"vulnerable": {"findings": [{"state": 3}]}},
                     {"vulnerable": {"findings": [None]}}, {"case_id": []}]
        for index, mutation in enumerate(mutations):
            bundle(self.root / "one")
            data = copy.deepcopy(self.summary)
            data.update(mutation)
            write_json(self.root / "one" / "summary.json", data)
            self.assertEqual(self.run_tool(output=self.root / f"invalid-{index}"), 2)
        (self.root / "one" / "summary.json").write_text("[]", encoding="utf-8")
        self.assertEqual(self.run_tool(), 2)

    def test_csv_markdown_same_cells_no_metrics_or_integrity_claim(self):
        self.assertEqual(self.run_tool(), 0)
        md = (self.output / "summary.md").read_text()
        self.assertIn("failed", md)
        self.assertIn("vulnerable-replay-unstable", md)
        self.assertIn("12.5", md)
        self.assertIn(self.rows()[0]["summary_sha256"], md)
        self.assertNotIn("precision", self.rows()[0])
        self.assertNotIn("recall", self.rows()[0])

    def test_cli_real_module_exit_codes_and_usage(self):
        write_json(self.input, {"schema_version": 1, "runs": self.entries})
        args = [sys.executable, "-m", "lima.competition_run_summary", "--inputs",
                str(self.input), "--output-dir", str(self.output)]
        run = subprocess.run(args, capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(subprocess.run(args, capture_output=True, check=False).returncode, 3)
        self.assertEqual(subprocess.run(args[:3], capture_output=True, check=False).returncode, 3)

    def test_synthetic_demo_reproducible(self):
        demo = self.root / "demo"
        write_demo(demo)
        before = tree_bytes(demo)
        self.assertEqual(main(["--inputs", str(demo / "runs.json"), "--output-dir",
                               str(self.output)]), 0)
        self.assertEqual(before, tree_bytes(demo))
        self.assertEqual({r["validation_status"] for r in self.rows()}, {"failed", "passed"})

    def test_numeric_equivalence_across_both_sides_and_nested_values(self):
        for side in ("vulnerable", "fixed"):
            self.summary[side].update(
                file_coverage=1, byte_coverage=0, elapsed_seconds=12,
                budget_usage={"calls": 1, "nested": [0.5, {"bytes": 2048}]})
            platform = copy.deepcopy(self.summary[side])
            platform.update(
                file_coverage=1.0, byte_coverage=0.0, elapsed_seconds=12.0,
                budget_usage={"nested": [0.5, {"bytes": 2048.0}], "calls": 1.0})
            write_json(self.root / "one" / side / "platform.json", platform)
        write_json(self.root / "one" / "summary.json", self.summary)
        before = tree_bytes(self.root / "one")
        self.assertEqual(self.run_tool(), 0)
        row = self.rows()[0]
        self.assertEqual(row["row_status"], "parsed")
        self.assertEqual(row["validation_status"], "failed")
        self.assertEqual(json.loads(row["vulnerable_findings_by_state"]),
                         {"runtime-confirmed": 1, "semantic-supported": 2})
        self.assertEqual(self.errors(), [])
        self.assertEqual(before, tree_bytes(self.root / "one"))

    def test_signed_zero_and_object_order_are_equivalent(self):
        self.summary["vulnerable"]["budget_usage"] = {"zero": 0, "items": [1, 2.5]}
        platform = copy.deepcopy(self.summary["vulnerable"])
        platform["budget_usage"] = {"items": [1.0, 2.5], "zero": -0.0}
        write_json(self.root / "one" / "summary.json", self.summary)
        write_json(self.root / "one/vulnerable/platform.json", platform)
        self.assertEqual(self.run_tool(), 0)
        self.assertEqual(self.errors(), [])

    def test_real_numeric_differences_remain_conflicts(self):
        values = [(1, 0.5), ({"calls": [1]}, {"calls": [2.0]}),
                  (2 ** 53 + 1, float(2 ** 53))]
        for index, (left, right) in enumerate(values):
            with self.subTest(left=left, right=right):
                self.summary["vulnerable"]["budget_usage"] = left
                platform = copy.deepcopy(self.summary["vulnerable"])
                platform["budget_usage"] = right
                write_json(self.root / "one/summary.json", self.summary)
                write_json(self.root / "one/vulnerable/platform.json", platform)
                out = self.root / f"numeric-conflict-{index}"
                self.assertEqual(self.run_tool(output=out), 2)
                error = json.loads((out / "errors.json").read_text())["errors"][0]
                self.assertEqual(error["code"], "field_conflict")
                self.assertEqual(error["field"], "vulnerable/budget_usage")

    def test_booleans_and_numbers_remain_distinct_at_every_depth(self):
        values = [(True, 1), (False, 0.0), (1.0, True),
                  ({"calls": [True]}, {"calls": [1.0]}),
                  ([{"complete": False}], [{"complete": 0}])]
        for index, (left, right) in enumerate(values):
            with self.subTest(left=left, right=right):
                self.summary["vulnerable"]["budget_usage"] = left
                platform = copy.deepcopy(self.summary["vulnerable"])
                platform["budget_usage"] = right
                write_json(self.root / "one/summary.json", self.summary)
                write_json(self.root / "one/vulnerable/platform.json", platform)
                out = self.root / f"boolean-conflict-{index}"
                self.assertEqual(self.run_tool(output=out), 2)
                errors = json.loads((out / "errors.json").read_text())["errors"]
                self.assertEqual(errors[0]["code"], "field_conflict")

    def test_list_order_and_object_fields_remain_conflicts(self):
        values = [([1, 2], [2.0, 1.0]), ({"calls": 1}, {"calls": 1.0, "bytes": 0}),
                  ({"calls": None}, {}), ({"calls": 1}, {"calls": "1"}),
                  (None, 0), ([1], [1.0, 2])]
        for index, (left, right) in enumerate(values):
            with self.subTest(left=left, right=right):
                self.summary["vulnerable"]["budget_usage"] = left
                platform = copy.deepcopy(self.summary["vulnerable"])
                platform["budget_usage"] = right
                write_json(self.root / "one/summary.json", self.summary)
                write_json(self.root / "one/vulnerable/platform.json", platform)
                out = self.root / f"structure-conflict-{index}"
                self.assertEqual(self.run_tool(output=out), 2)
                errors = json.loads((out / "errors.json").read_text())["errors"]
                self.assertEqual(errors[0]["code"], "field_conflict")

    def test_module_gbk_diagnostic_retains_unicode_labels(self):
        label = "round-\U0001f9ea"
        entries = [dict(self.entries[0], run_label=label)] * 2
        write_json(self.input, {"schema_version": 1, "runs": entries})
        result = subprocess.run(
            [sys.executable, "-m", "lima.competition_run_summary", "--inputs",
             str(self.input), "--output-dir", str(self.output)],
            env=dict(os.environ, PYTHONIOENCODING="gbk", PYTHONUTF8="0"),
            capture_output=True, check=False)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout, b"")
        diagnostic = json.loads(result.stderr.decode("gbk"))
        self.assertEqual(diagnostic["code"], "duplicate_run_label")
        self.assertEqual(diagnostic["ref"], "run:" + label)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--write-demo":
        write_demo(Path(sys.argv[2]))
    else:
        unittest.main()
