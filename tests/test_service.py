import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from lima.config import Settings
from lima.cxx_memory import REQUESTED_LAYERS, SUPPORTED_CWES
from lima.service import ReviewService
from lima.workspace import (
    CXX_BUILD_EXTENSIONS,
    CXX_SOURCE_EXTENSIONS,
    DEFAULT_FILENAMES,
)


class ServiceTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.settings = Settings(
            host="127.0.0.1", port=8080, db_path=self.path, max_diff_bytes=10000,
            max_steps=8, timeout_seconds=10, llm_base_url="", llm_api_key="", llm_model="",
            github_webhook_secret="", github_token="", auto_post_review=False,
        )

    def tearDown(self):
        os.unlink(self.path)

    def test_end_to_end_review(self):
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"
        service = ReviewService(self.settings)
        result = service.create_review("org/repo", diff, 1)
        task = service.store.get(result["task_id"])
        service.queue.close()
        self.assertEqual("SUCCESS", result["state"])
        self.assertEqual("SEC-EVAL", result["report"]["findings"][0]["rule_id"])
        self.assertEqual(
            "plan-challenge-revise-evidence-verify-arbitrate",
            result["report"]["collaboration"]["protocol"],
        )
        self.assertGreater(result["report"]["collaboration"]["messages"], 0)
        self.assertIn(
            "arbitration_decision", {item["kind"] for item in task["collaboration"]}
        )

    def test_rejects_large_diff(self):
        service = ReviewService(self.settings)
        with self.assertRaises(ValueError):
            service.create_review("org/repo", "x" * 10001)

    @patch("lima.service.CxxMemoryAnalyzerClient")
    def test_service_injects_configured_cxx_analyzer_client(self, client_class):
        client = client_class.return_value

        service = ReviewService(self.settings)
        try:
            client_class.assert_called_once_with(
                self.settings.cxx_analyzer_url,
                timeout_seconds=self.settings.cxx_analysis_timeout_seconds,
                max_response_bytes=self.settings.cxx_max_response_bytes,
            )
            self.assertIs(client, service.repository_scanner.cxx_memory_adapter)
            self.assertEqual("auto", service.repository_scanner.cxx_memory_mode)
        finally:
            service.queue.close()

    @patch("lima.service.CxxMemoryAnalyzerClient")
    def test_service_does_not_construct_cxx_client_when_disabled(self, client_class):
        settings = replace(self.settings, cxx_memory_mode="off")

        service = ReviewService(settings)
        try:
            client_class.assert_not_called()
            self.assertIsNone(service.repository_scanner.cxx_memory_adapter)
        finally:
            service.queue.close()

    def test_repository_scan_capabilities_describe_cxx_layers_without_url(self):
        service = ReviewService(self.settings)
        try:
            capabilities = service.repository_scan_capabilities()
            cxx = capabilities["cxx_memory"]

            self.assertEqual("auto", cxx["mode"])
            self.assertTrue(cxx["analyzer_configured"])
            self.assertEqual(sorted(CXX_SOURCE_EXTENSIONS), cxx["supported_extensions"])
            self.assertEqual(
                sorted(CXX_BUILD_EXTENSIONS), cxx["build_metadata_extensions"]
            )
            self.assertEqual(sorted(DEFAULT_FILENAMES), cxx["build_metadata_filenames"])
            self.assertEqual(sorted(SUPPORTED_CWES), cxx["supported_cwes"])
            self.assertEqual(list(REQUESTED_LAYERS), cxx["layers"])
            self.assertEqual("sidecar-managed", cxx["build_configuration_status"])
            self.assertEqual("sidecar-managed", cxx["test_configuration_status"])
            self.assertFalse(cxx["automatic_repair"])
            self.assertNotIn(self.settings.cxx_analyzer_url, str(capabilities))
        finally:
            service.queue.close()

    def test_repository_scan_forwards_normalized_repository_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary, "team", "project")
            repository.mkdir(parents=True)
            (repository / "app.py").write_text("safe = True\n", encoding="utf-8")
            settings = replace(
                self.settings,
                repository_import_root=temporary,
                repository_scan_sast_mode="off",
                cxx_memory_mode="off",
            )
            service = ReviewService(settings)
            try:
                with patch.object(
                    service.repository_scanner,
                    "scan",
                    wraps=service.repository_scanner.scan,
                ) as scan:
                    created = service.enqueue_repository_scan("team/project")
                    for _ in range(200):
                        task = service.store.get(created["task_id"])
                        if task and task["state"] in {"SUCCESS", "FAILED"}:
                            break
                        time.sleep(0.01)

                self.assertEqual("SUCCESS", task["state"])
                self.assertEqual("team/project", scan.call_args.kwargs["repository_key"])
            finally:
                service.queue.close()

    def test_completed_review_feedback_is_persisted_and_listed_per_task(self):
        diff = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+eval(data)\n"
        service = ReviewService(self.settings)
        result = service.create_review("org/repo", diff, 1)
        task_id = result["task_id"]

        feedback = service.record_feedback(
            task_id, "false_positive", result["report"]["findings"][0], "不是实际风险",
        )

        self.assertEqual({"recorded": True, "category": "false_positive"}, feedback)
        cases = service.store.list_task_failure_cases(task_id, "default")
        self.assertEqual(1, len(cases))
        self.assertEqual("false_positive", cases[0]["category"])
        self.assertEqual("SEC-EVAL", cases[0]["payload"]["finding"]["rule_id"])
        service.queue.close()


if __name__ == "__main__":
    unittest.main()
