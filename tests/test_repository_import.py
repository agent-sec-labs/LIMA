import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from lima.adjudication import finalize_adjudication
from lima.config import Settings
from lima.repository_import import RepositoryImportPolicy
from lima.repository_triage import RepositoryTriageOutcome
from lima.service import ReviewService


def settings_for(db_path: str, import_root: str = "") -> Settings:
    return Settings(
        host="127.0.0.1",
        port=8080,
        db_path=db_path,
        max_diff_bytes=10000,
        max_steps=8,
        timeout_seconds=120,
        llm_base_url="",
        llm_api_key="",
        llm_model="",
        github_webhook_secret="",
        github_token="",
        auto_post_review=False,
        repository_import_root=import_root,
        repository_scan_sast_mode="off",
    )


class RepositoryImportPolicyTests(unittest.TestCase):
    def test_resolves_only_bounded_repository_keys(self):
        with tempfile.TemporaryDirectory() as root:
            repository = Path(root, "团队", "project-1")
            repository.mkdir(parents=True)
            policy = RepositoryImportPolicy(root)

            self.assertEqual(repository.resolve(), policy.resolve("团队/project-1"))

    def test_rejects_absolute_traversal_hidden_and_windows_paths(self):
        policy = RepositoryImportPolicy("unused")

        for value in (
            "/etc",
            "../secret",
            "team/../../secret",
            ".hidden/repo",
            "team/.git",
            "C:/repo",
            "team\\repo",
            "",
        ):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    policy.normalize_key(value)

    def test_disabled_policy_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "disabled"):
            RepositoryImportPolicy().resolve("team/repo")

    def test_directory_link_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as outside:
            link = Path(root, "linked")
            if os.name == "nt":
                created = subprocess.run(
                    ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), outside],
                    text=True,
                    capture_output=True,
                    encoding="utf-8",
                    errors="replace",
                    check=False,
                )
                self.assertEqual(
                    0, created.returncode,
                    "Windows junction creation failed: %s" % created.stderr,
                )
            else:
                os.symlink(outside, link, target_is_directory=True)
            try:
                with self.assertRaisesRegex(ValueError, "escapes"):
                    RepositoryImportPolicy(root).resolve("linked")
            finally:
                if link.is_symlink():
                    link.unlink()
                else:
                    # Windows directory junctions are reparse-point directories,
                    # not pathlib symlinks, and must be removed as directories.
                    link.rmdir()


class RepositoryScanServiceTests(unittest.TestCase):
    @staticmethod
    def _wait_for_task(service, task_id, tenant_id):
        task = None
        for _ in range(200):
            task = service.store.get(task_id, tenant_id)
            if task and task["state"] in {"SUCCESS", "FAILED"}:
                break
            time.sleep(0.01)
        return task

    def test_async_repository_scan_is_persisted_without_host_path(self):
        with tempfile.TemporaryDirectory() as root:
            repository = Path(root, "team", "project")
            repository.mkdir(parents=True)
            repository.joinpath("app.py").write_text(
                "from executor import evaluate_expression\n"
                "\n"
                "@app.post('/evaluate')\n"
                "def run(user_input):\n"
                "    return evaluate_expression(user_input)\n",
                encoding="utf-8",
            )
            repository.joinpath("executor.py").write_text(
                "def evaluate_expression(value):\n"
                "    return eval(value)\n",
                encoding="utf-8",
            )
            db_path = str(Path(root, "state.db"))
            service = ReviewService(settings_for(db_path, root))
            try:
                created = service.enqueue_repository_scan("team/project", "tenant-a")
                task = None
                for _ in range(200):
                    task = service.store.get(created["task_id"], "tenant-a")
                    if task and task["state"] in {"SUCCESS", "FAILED"}:
                        break
                    time.sleep(0.01)

                self.assertIsNotNone(task)
                self.assertEqual("SUCCESS", task["state"])
                self.assertEqual("repository_scan", task["input"]["task_type"])
                self.assertEqual("team/project", task["report"]["repository"])
                self.assertEqual("SEC-EVAL", task["report"]["findings"][0]["rule_id"])
                self.assertEqual(
                    "dataflow-verified",
                    task["report"]["findings"][0]["verification_state"],
                )
                self.assertEqual(
                    "alert", task["report"]["adjudication"]["overall_disposition"]
                )
                self.assertEqual(
                    "source-to-sink-risk-evidence",
                    task["report"]["adjudication"]["decisions"][0]["reason"],
                )
                self.assertFalse(task["report"]["adjudication"]["auto_clear"])
                self.assertEqual(
                    "disabled",
                    task["report"]["collaboration"]["semantic_triage"]["status"],
                )
                self.assertEqual(
                    1, task["report"]["collaboration"]["interprocedural_call_edges"]
                )
                self.assertEqual(
                    1, task["report"]["collaboration"]["cross_file_call_edges"]
                )
                self.assertNotIn(str(Path(root).resolve()), str(task))
                listed = service.store.list_tasks(10, "tenant-a")
                self.assertEqual("repository_scan", listed[0]["task_type"])
                self.assertEqual(
                    ["PLANNING", "EXECUTING", "SUCCESS"],
                    [event["state"] for event in task["trace"]],
                )
            finally:
                service.queue.close()

    def test_verified_repair_preview_is_read_only_and_snapshot_pinned(self):
        with tempfile.TemporaryDirectory() as root:
            repository = Path(root, "team", "repairable")
            repository.mkdir(parents=True)
            source = (
                "import subprocess\n"
                "@app.post('/run')\n"
                "def run(value):\n"
                "    return subprocess.run('echo ' + value, shell=True)\n"
            )
            target = repository.joinpath("app.py")
            target.write_text(source, encoding="utf-8")
            service = ReviewService(settings_for(str(Path(root, "state.db")), root))
            try:
                created = service.enqueue_repository_scan("team/repairable", "tenant-a")
                task = self._wait_for_task(
                    service, created["task_id"], "tenant-a"
                )
                self.assertEqual("SUCCESS", task["state"])
                self.assertTrue(
                    task["report"]["collaboration"]["import_policy"]["snapshot_sha256"]
                )

                preview = service.create_repair_preview(
                    created["task_id"], "tenant-a"
                )

                self.assertEqual("verified-preview", preview["status"])
                self.assertTrue(preview["verification"]["passed"])
                self.assertFalse(preview["publication_ready"])
                self.assertIn("shell=False", preview["patches"][0]["diff"])
                self.assertEqual(source, target.read_text(encoding="utf-8"))

                target.write_text(source + "# changed after scan\n", encoding="utf-8")
                with self.assertRaisesRegex(ValueError, "changed after scanning"):
                    service.create_repair_preview(created["task_id"], "tenant-a")
            finally:
                service.queue.close()

    def test_repository_scan_capability_is_disabled_without_root(self):
        handle, db_path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        service = ReviewService(settings_for(db_path))
        try:
            capabilities = service.repository_scan_capabilities()
            self.assertFalse(capabilities["enabled"])
            self.assertEqual("repository-static-imports", capabilities["dataflow_scope"])
            self.assertTrue(capabilities["cross_file_dataflow"])
            self.assertEqual(4, capabilities["dataflow_max_call_depth"])
            self.assertEqual(
                ["CWE-22", "CWE-78", "CWE-89"],
                capabilities["verified_repair_cwes"],
            )
            self.assertIn("security-oracle", capabilities["repair_gates"])
            self.assertTrue(capabilities["repair_preview_supported"])
            self.assertFalse(capabilities["repair_preview_writes_repository"])
            self.assertTrue(capabilities["repair_preview_snapshot_pinned"])
            self.assertFalse(capabilities["repair_tests_configured"])
            self.assertEqual("off", capabilities["semantic_triage_mode"])
            self.assertFalse(capabilities["semantic_triage_enabled"])
            with self.assertRaisesRegex(ValueError, "disabled"):
                service.enqueue_repository_scan("team/project")
        finally:
            service.queue.close()
            os.unlink(db_path)

    def test_semantic_triage_outcome_is_persisted_without_secret(self):
        class SemanticTriageStub:
            @staticmethod
            def run(_root, _baseline, _findings):
                return RepositoryTriageOutcome(
                    adjudication=finalize_adjudication([{
                        "path": "app.py",
                        "symbol": "safe_join",
                        "disposition": "clear",
                        "reason": "mitigation-invariant-and-llm-agree",
                        "invariant_statuses": ["mitigation"],
                        "llm_is_vulnerable": False,
                    }]),
                    diagnostics={
                        "mode": "auto",
                        "status": "completed",
                        "provider": "test-provider",
                        "usage": {"total_tokens": 120},
                        "secret_persisted": False,
                    },
                )

        with tempfile.TemporaryDirectory() as root:
            repository = Path(root, "team", "safe-project")
            repository.mkdir(parents=True)
            repository.joinpath("app.py").write_text(
                "def safe_join(root, value):\n"
                "    candidate = (root / value).resolve()\n"
                "    candidate.relative_to(root.resolve())\n"
                "    return candidate\n",
                encoding="utf-8",
            )
            settings = Settings(**{
                **settings_for(str(Path(root, "state.db")), root).__dict__,
                "repository_scan_llm_mode": "auto",
            })
            service = ReviewService(settings)
            service.repository_semantic_triage = SemanticTriageStub()
            try:
                created = service.enqueue_repository_scan(
                    "team/safe-project", "tenant-a"
                )
                task = self._wait_for_task(
                    service, created["task_id"], "tenant-a"
                )

                self.assertEqual("SUCCESS", task["state"])
                self.assertEqual(
                    "clear", task["report"]["adjudication"]["overall_disposition"]
                )
                self.assertTrue(task["report"]["adjudication"]["auto_clear"])
                semantic = task["report"]["collaboration"]["semantic_triage"]
                self.assertEqual("completed", semantic["status"])
                self.assertFalse(semantic["secret_persisted"])
                self.assertNotIn("api_key", str(task).lower())
                self.assertEqual(
                    "auto", task["input"]["semantic_triage_mode"]
                )
            finally:
                service.queue.close()


if __name__ == "__main__":
    unittest.main()
