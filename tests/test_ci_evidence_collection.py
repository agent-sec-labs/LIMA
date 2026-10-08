"""Exercise collection and offline replay without credentials or network access."""

from __future__ import annotations

import contextlib
import http.client
import io
import json
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, Mock, patch

from scripts import collect_ci_evidence as collector
from scripts import verify_ci_evidence as verifier
from tests.test_ci_evidence import API_URL, RUN_ID, SHA, fixtures


class CollectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.target = self.root / "evidence"
        self.run, self.pages, self.expected = fixtures()
        self.run["path"] = collector.WORKFLOW_PATH

    def download(self):
        raw = [json.dumps(obj).encode("utf-8") for obj in [self.run, *self.pages]]
        return patch.object(collector, "_download", side_effect=raw)

    def cli(self):
        stdout = io.StringIO()
        with contextlib.redirect_stdout(stdout):
            code = collector.main([
                "--run-id", str(RUN_ID), "--attempt", "2", "--head-sha", SHA,
                "--event", "pull_request", "--evidence-dir", str(self.target),
            ])
        return code, json.loads(stdout.getvalue())

    def test_one_command_saves_replayable_raw_responses_and_report(self):
        with self.download() as fetch:
            code, report = self.cli()
        self.assertEqual((code, report["decision"]), (0, "pass"))
        self.assertEqual(report["required_jobs"], ["merge-gate"])
        self.assertEqual(report["counts"]["success"], 2)
        self.assertEqual([call.args[0] for call in fetch.call_args_list], [
            f"{API_URL}/attempts/2", f"{API_URL}/attempts/2/jobs?per_page=100&page=1",
        ])
        run, source, _ = verifier._read_json(self.target / "run.json", "run", 100_000)
        page, _, _ = verifier._read_json(self.target / "jobs-1.json", "jobs[0]", 100_000)
        replay = verifier.verify_snapshot(run, [page], replace(self.expected,
                                                              required_jobs=("merge-gate",)))
        self.assertEqual(replay["counts"], report["counts"])
        self.assertEqual(replay["decision"], report["decision"])
        self.assertEqual(report["source_sha256"][0], source)
        self.assertEqual(json.loads((self.target / "report.json").read_text()), report)

    def test_all_pages_are_collected_from_the_same_attempt(self):
        run, pages, expected = fixtures(tuple(f"unit-{i}" for i in range(100)) + ("merge-gate",))
        run["path"] = collector.WORKFLOW_PATH
        self.run = run
        self.pages = [{"total_count": 101, "jobs": pages[0]["jobs"][:100]},
                      {"total_count": 101, "jobs": pages[0]["jobs"][100:]}]
        with self.download() as fetch:
            report = collector.collect_snapshot(expected, self.target)
        self.assertEqual(report["counts"]["total"], 101)
        self.assertEqual(fetch.call_count, 3)
        self.assertTrue(fetch.call_args.args[0].endswith("/attempts/2/jobs?per_page=100&page=2"))

    def test_failure_and_partial_response_do_not_become_pass(self):
        self.run["conclusion"] = "failure"
        self.pages[0]["jobs"][0]["conclusion"] = "failure"
        with self.download():
            code, report = self.cli()
        self.assertEqual((code, report["failed_jobs"]), (1, ["unit"]))
        self.target = self.root / "partial"
        self.pages[0]["jobs"].pop()
        with self.download():
            code, report = self.cli()
        self.assertEqual((code, report["decision"]), (3, "incomplete"))

    def test_inherited_success_is_valid_but_never_claimed_as_rerun(self):
        # Failed-job reruns can return inherited jobs with earlier execution times
        # and the requested run_attempt. Trust that binding, not invented rerun counts.
        self.run["run_started_at"] = "2026-10-08T04:36:00Z"
        self.pages[0]["jobs"][0]["started_at"] = "2026-10-08T04:00:00Z"
        with self.download():
            _, report = self.cli()
        self.assertEqual(report["decision"], "pass")
        self.assertNotIn("rerun", json.dumps(report))
        self.target = self.root / "wrong-attempt"
        self.pages[0]["jobs"][0]["run_attempt"] = 1
        with self.download():
            code, report = self.cli()
        self.assertEqual((code, report["error"]["code"]), (2, "binding-mismatch"))
        self.assertFalse((self.target / "report.json").exists())

    def test_wrong_workflow_or_identity_stops_before_jobs(self):
        for key, value in (("path", ".github/workflows/other.yml"), ("head_sha", "b" * 40)):
            with self.subTest(key=key):
                self.target = self.root / key
                self.run, self.pages, _ = fixtures()
                self.run["path"] = collector.WORKFLOW_PATH
                self.run[key] = value
                with self.download() as fetch:
                    code, report = self.cli()
                self.assertEqual((code, report["error"]["code"]), (2, "binding-mismatch"))
                self.assertEqual(fetch.call_count, 1)

    def test_existing_evidence_is_preserved_without_requests(self):
        self.target.mkdir()
        saved = self.target / "run.json"
        saved.write_bytes(b"existing evidence")
        with self.download() as fetch:
            code, _ = self.cli()
        self.assertEqual(code, 2)
        fetch.assert_not_called()
        self.assertEqual(saved.read_bytes(), b"existing evidence")

    def test_bad_parameters_are_rejected_before_directory_or_network(self):
        self.expected = replace(self.expected, repository="../other/repo")
        with self.download() as fetch:
            with self.assertRaises(verifier.EvidenceError):
                collector.collect_snapshot(self.expected, self.target)
        fetch.assert_not_called()
        self.assertFalse(self.target.exists())


class DownloadTests(unittest.TestCase):
    def invoke(self):
        return collector._download(f"{API_URL}/attempts/2", 100, time.monotonic() + 30)

    def test_https_get_has_timeout_and_no_authorization(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"{}"
        connection = Mock(spec=http.client.HTTPSConnection)
        connection.getresponse.return_value = response
        with patch.object(collector.http.client, "HTTPSConnection",
                          return_value=connection) as connect:
            self.assertEqual(self.invoke(), b"{}")
        self.assertEqual(connect.call_args.args[0], "api.github.com")
        self.assertLessEqual(connect.call_args.kwargs["timeout"], collector.REQUEST_TIMEOUT)
        self.assertEqual(connection.request.call_args.args,
                         ("GET", f"/repos/agent-sec-labs/LIMA/actions/runs/{RUN_ID}/attempts/2"))
        self.assertNotIn("Authorization", connection.request.call_args.kwargs["headers"])
        response.read.assert_called_once_with(101)
        connection.close.assert_called_once_with()

    def test_oversized_response_and_timeout_rejected(self):
        response = MagicMock()
        response.status = 200
        response.read.return_value = b"x" * 101
        connection = Mock(spec=http.client.HTTPSConnection)
        connection.getresponse.return_value = response
        with patch.object(collector.http.client, "HTTPSConnection", return_value=connection):
            with self.assertRaisesRegex(verifier.EvidenceError, "input-budget-exceeded"):
                self.invoke()
            with self.assertRaisesRegex(verifier.EvidenceError, "collection-timeout"):
                collector._download(f"{API_URL}/attempts/2", 100, time.monotonic() - 1)

    def test_network_errors_and_redirects_do_not_echo_remote_values(self):
        for error in (OSError("SENSITIVE"), http.client.BadStatusLine("SENSITIVE")):
            with self.subTest(error=type(error).__name__):
                with patch.object(collector.http.client, "HTTPSConnection", side_effect=error):
                    with self.assertRaises(verifier.EvidenceError) as caught:
                        self.invoke()
                self.assertNotIn("SENSITIVE", str(caught.exception))
        response = MagicMock()
        connection = Mock(spec=http.client.HTTPSConnection)
        connection.getresponse.return_value = response
        for status, code in ((302, "github-redirect-rejected"), (403, "github-http-403")):
            response.status = status
            with patch.object(collector.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaisesRegex(verifier.EvidenceError, code):
                    self.invoke()
        with self.assertRaisesRegex(verifier.EvidenceError, "github-url-rejected"):
            collector._download("http://api.github.com/repos/x/y", 100, time.monotonic() + 30)


if __name__ == "__main__":
    unittest.main()
