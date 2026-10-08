"""Fail-closed evidence regression tests; no GitHub or model credentials required."""

from __future__ import annotations

import contextlib
import copy
import hashlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_ci_evidence as verifier

SHA = "a" * 40
REPO = "agent-sec-labs/LIMA"
RUN_ID = 123
API_URL = f"https://api.github.com/repos/{REPO}/actions/runs/{RUN_ID}"


def fixtures(names=("unit", "merge-gate")):
    run = {
        "id": RUN_ID, "run_attempt": 2, "head_sha": SHA, "event": "pull_request",
        "repository": {"full_name": REPO}, "url": API_URL,
        "status": "completed", "conclusion": "success",
    }
    jobs = [
        {"id": i + 1, "run_id": RUN_ID, "run_attempt": 2, "head_sha": SHA,
         "run_url": API_URL, "name": name, "status": "completed", "conclusion": "success"}
        for i, name in enumerate(names)
    ]
    expected = verifier.ExpectedRun(REPO, RUN_ID, SHA, "pull_request", 2, tuple(names))
    return run, [{"total_count": len(jobs), "jobs": jobs}], expected


class SnapshotTests(unittest.TestCase):
    def test_exact_counts_and_failed_jobs(self):
        names = tuple(f"job-{i}" for i in range(10)) + ("frontend-tests", "merge-gate")
        run, pages, expected = fixtures(names)
        run["conclusion"] = "failure"
        for job in pages[0]["jobs"][-2:]:
            job["conclusion"] = "failure"
        report = verifier.verify_snapshot(run, pages, expected)
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["counts"], {"total": 12, "success": 10, "failed": 2, "pending": 0})
        self.assertEqual(report["failed_jobs"], ["frontend-tests", "merge-gate"])
        self.assertEqual(report["identity"]["event"], "pull_request")
        self.assertNotIn("READY-FOR-MERGE", json.dumps(report))

    def test_multi_page_success(self):
        run, pages, expected = fixtures()
        jobs = pages[0]["jobs"]
        report = verifier.verify_snapshot(run, [
            {"total_count": 2, "jobs": jobs[:1]}, {"total_count": 2, "jobs": jobs[1:]},
        ], expected)
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(report["counts"]["success"], 2)

    def test_binding_mismatches_rejected(self):
        for key, value in (("id", 999), ("run_attempt", 1), ("head_sha", "b" * 40),
                           ("event", "push"), ("url", API_URL.replace("LIMA", "other")),
                           ("repository", {"full_name": "other/repo"})):
            with self.subTest(key=key):
                run, pages, expected = fixtures()
                run[key] = value
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages, expected)

    def test_mixed_job_identity_rejected(self):
        for key, value in (("run_id", 999), ("run_attempt", 1), ("head_sha", "b" * 40),
                           ("run_url", API_URL.replace("LIMA", "other"))):
            with self.subTest(key=key):
                run, pages, expected = fixtures()
                pages[0]["jobs"][1][key] = value
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages, expected)

    def test_missing_job_attempt_is_not_inferred(self):
        run, pages, expected = fixtures()
        del pages[0]["jobs"][0]["run_attempt"]
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_snapshot(run, pages, expected)

    def test_missing_page_incomplete(self):
        run, pages, expected = fixtures()
        pages[0]["jobs"].pop()
        report = verifier.verify_snapshot(run, pages, expected)
        self.assertEqual(report["decision"], "incomplete")
        self.assertIn("pagination-incomplete", report["reasons"])

    def test_duplicate_jobs_rejected(self):
        for duplicate in ("id", "name"):
            with self.subTest(duplicate=duplicate):
                run, pages, expected = fixtures()
                jobs = pages[0]["jobs"]
                jobs[1][duplicate] = jobs[0][duplicate]
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages, expected)

    def test_duplicate_page_and_conflicting_total_rejected(self):
        run, pages, expected = fixtures()
        for extra in (copy.deepcopy(pages[0]), {"total_count": 3, "jobs": []}):
            with self.subTest(extra=extra):
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages + [extra], expected)

    def test_non_success_conclusions_fail_closed(self):
        for conclusion in ("failure", "skipped", "neutral", "cancelled", "timed_out",
                           "action_required", "stale", "startup_failure"):
            with self.subTest(conclusion=conclusion):
                run, pages, expected = fixtures()
                run["conclusion"] = "failure"
                pages[0]["jobs"][0]["conclusion"] = conclusion
                self.assertEqual(verifier.verify_snapshot(run, pages, expected)["decision"], "fail")

    def test_pending_and_missing_required_incomplete(self):
        run, pages, expected = fixtures()
        run.update(status="in_progress", conclusion=None)
        pages[0]["jobs"][0].update(status="queued", conclusion=None)
        report = verifier.verify_snapshot(run, pages, expected)
        self.assertEqual(report["decision"], "incomplete")
        self.assertEqual(report["counts"]["pending"], 1)
        run, pages, expected = fixtures()
        pages[0]["jobs"].pop()
        pages[0]["total_count"] = 1
        report = verifier.verify_snapshot(run, pages, expected)
        self.assertEqual(report["missing_required_jobs"], ["merge-gate"])
        self.assertEqual(report["decision"], "incomplete")

    def test_status_contradiction_and_unknown_values_rejected(self):
        for target, changes in (("job", {"status": "completed", "conclusion": None}),
                                ("job", {"status": "queued", "conclusion": "success"}),
                                ("job", {"conclusion": "secret-unknown"}),
                                ("run", {"status": "unknown"})):
            with self.subTest(target=target, changes=changes):
                run, pages, expected = fixtures()
                obj = run if target == "run" else pages[0]["jobs"][0]
                obj.update(changes)
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages, expected)

    def test_boolean_ids_and_incorrect_container_types_rejected(self):
        for target, key, value in (("run", "id", True), ("job", "run_attempt", True),
                                   ("page", "total_count", True), ("page", "jobs", {})):
            with self.subTest(target=target, key=key):
                run, pages, expected = fixtures()
                obj = {"run": run, "job": pages[0]["jobs"][0], "page": pages[0]}[target]
                obj[key] = value
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages, expected)

    def test_expected_policy_requires_gate_and_unique_nonempty_names(self):
        run, pages, _ = fixtures()
        for names in ((), ("unit",), ("merge-gate", "merge-gate"), ("merge-gate", "")):
            with self.subTest(names=names):
                expected = verifier.ExpectedRun(REPO, RUN_ID, SHA, "pull_request", 2, names)
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, pages, expected)

    def test_inputs_not_mutated_and_unknown_payload_not_copied(self):
        run, pages, expected = fixtures()
        run["unknown_metadata"] = "DO-NOT-ECHO"
        pages[0]["jobs"][0]["steps"] = [{"name": "DO-NOT-ECHO"}]
        original = copy.deepcopy((run, pages))
        report = verifier.verify_snapshot(run, pages, expected)
        self.assertEqual(original, (run, pages))
        self.assertNotIn("DO-NOT-ECHO", json.dumps(report))

    def test_run_failure_and_extra_failed_job_prevent_pass(self):
        run, pages, expected = fixtures()
        run["conclusion"] = "failure"
        self.assertEqual(verifier.verify_snapshot(run, pages, expected)["decision"], "fail")
        run, pages, expected = fixtures()
        extra = dict(pages[0]["jobs"][0], id=3, name="extra", conclusion="failure")
        pages[0]["jobs"].append(extra)
        pages[0]["total_count"] = 3
        report = verifier.verify_snapshot(run, pages, expected)
        self.assertEqual(report["decision"], "fail")
        self.assertEqual(report["failed_jobs"], ["extra"])

    def test_missing_conclusion_never_becomes_pending_null(self):
        run, pages, expected = fixtures()
        job = pages[0]["jobs"][0]
        job["status"] = "queued"
        del job["conclusion"]
        with self.assertRaises(verifier.EvidenceError):
            verifier.verify_snapshot(run, pages, expected)

    def test_resource_limits_and_total_overflow_rejected(self):
        run, pages, expected = fixtures()
        for candidate in ([{"total_count": 0, "jobs": pages[0]["jobs"]}],
                          [{"total_count": verifier.MAX_JOBS + 1, "jobs": []}],
                          [{"total_count": 0, "jobs": []}] * (verifier.MAX_PAGES + 1)):
            with self.subTest(pages=len(candidate)):
                with self.assertRaises(verifier.EvidenceError):
                    verifier.verify_snapshot(run, candidate, expected)


class CliTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        run, pages, _ = fixtures()
        self.run = self.root / "run.json"
        self.jobs = self.root / "jobs.json"
        self.run.write_text(json.dumps(run), encoding="utf-8")
        self.jobs.write_text(json.dumps(pages[0]), encoding="utf-8")
        self.args = ["--run", str(self.run), "--jobs", str(self.jobs), "--repository", REPO,
                     "--run-id", str(RUN_ID), "--head-sha", SHA, "--event", "pull_request",
                     "--attempt", "2", "--required-job", "unit", "--required-job", "merge-gate"]

    def invoke(self, args=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = verifier.main(self.args if args is None else args)
        return code, stdout.getvalue(), stderr.getvalue()

    def test_success_cli_records_raw_byte_digests(self):
        code, stdout, stderr = self.invoke()
        self.assertEqual((code, stderr), (0, ""))
        report = json.loads(stdout)
        self.assertEqual(report["decision"], "pass")
        self.assertEqual(len(report["source_sha256"]), 2)
        self.assertTrue(all(len(item["sha256"]) == 64 for item in report["source_sha256"]))
        self.assertEqual(report["source_sha256"][0]["sha256"],
                         hashlib.sha256(self.run.read_bytes()).hexdigest())

    def test_fail_and_incomplete_exit_codes(self):
        run, pages, _ = fixtures()
        run["conclusion"] = "failure"
        pages[0]["jobs"][0]["conclusion"] = "failure"
        self.run.write_text(json.dumps(run), encoding="utf-8")
        self.jobs.write_text(json.dumps(pages[0]), encoding="utf-8")
        self.assertEqual(self.invoke()[0], 1)
        pages[0]["jobs"].pop()
        self.jobs.write_text(json.dumps(pages[0]), encoding="utf-8")
        self.assertEqual(self.invoke()[0], 3)

    def test_total_input_budget_is_enforced(self):
        with patch.object(verifier, "MAX_TOTAL_BYTES", self.run.stat().st_size):
            code, stdout, _ = self.invoke()
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(stdout)["error"]["code"], "input-budget-exceeded")

    def test_path_resolution_failure_is_value_free(self):
        with patch.object(Path, "resolve", side_effect=RuntimeError("SENSITIVE")):
            code, stdout, stderr = self.invoke(self.args + ["--output", str(self.root / "out")])
        self.assertEqual(code, 2)
        self.assertNotIn("SENSITIVE", stdout + stderr)
        self.assertEqual(json.loads(stdout)["decision"], "invalid")

    def test_duplicate_json_keys_and_nonfinite_rejected_without_echo(self):
        for content in ('{"id":123,"id":999,"secret":"SENSITIVE"}', '{"secret":NaN}',
                        '{"secret":Infinity}', '{"secret":"SENSITIVE"', '[' * 2000):
            with self.subTest(content=content[:30]):
                self.run.write_text(content, encoding="utf-8")
                code, stdout, stderr = self.invoke()
                self.assertEqual(code, 2)
                self.assertNotIn("SENSITIVE", stdout + stderr)
                self.assertEqual(json.loads(stdout)["decision"], "invalid")

    def test_non_utf8_and_oversized_rejected(self):
        for raw in (b"\xff", b" " * (verifier.MAX_INPUT_BYTES + 1)):
            with self.subTest(size=len(raw)):
                self.run.write_bytes(raw)
                self.assertEqual(self.invoke()[0], 2)

    def test_output_created_once_and_input_never_overwritten(self):
        output = self.root / "report.json"
        before = (self.run.read_bytes(), self.jobs.read_bytes())
        code, stdout, _ = self.invoke(self.args + ["--output", str(output)])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(output.read_text(encoding="utf-8")), json.loads(stdout))
        saved = output.read_bytes()
        self.assertEqual(self.invoke(self.args + ["--output", str(output)])[0], 2)
        self.assertEqual(output.read_bytes(), saved)
        self.assertEqual(self.invoke(self.args + ["--output", str(self.run)])[0], 2)
        self.assertEqual(before, (self.run.read_bytes(), self.jobs.read_bytes()))

    def test_usage_error_returns_2_without_raw_values(self):
        code, stdout, stderr = self.invoke(["--attempt", "SENSITIVE"])
        self.assertEqual(code, 2)
        self.assertNotIn("SENSITIVE", stdout + stderr)


if __name__ == "__main__":
    unittest.main()
