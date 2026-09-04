import os
import tempfile
import unittest

from lima.config import Settings
from lima.diff_parser import parse_unified_diff
from lima.service import ReviewService
from lima.skill_evolution import (
    DeclarativeSkillReviewer,
    SkillEvolutionEngine,
    validate_artifact,
)
from lima.store import TaskStore


RISK_DIFF = "--- a/a.py\n+++ b/a.py\n@@ -1 +1 @@\n-old\n+dangerous_call(data)\n"
CLEAN_DIFF = "--- a/b.py\n+++ b/b.py\n@@ -1 +1 @@\n-old\n+safe_call(data)\n"


def artifact(match="dangerous_call(data)"):
    return {
        "name": "evolved-review",
        "description": "Learns confirmed dangerous calls",
        "rules": [{
            "rule_id": "SEC-DANGEROUS-CALL",
            "severity": "high",
            "match": match,
            "title": "Dangerous call",
            "explanation": "The confirmed dangerous API was added.",
            "fix": "Use safe_call instead.",
            "test": "Add a regression test.",
        }],
    }


class SkillEvolutionTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.store = TaskStore(self.path)

    def tearDown(self):
        os.unlink(self.path)

    def seed_cases(self):
        self.store.save_evaluation_case(
            "danger-validation", "validation", RISK_DIFF,
            [{
                "path": "a.py", "line": 1, "rule_id": "SEC-DANGEROUS-CALL",
                "min_severity": "high",
            }], "test",
        )
        self.store.save_evaluation_case(
            "clean-holdout", "holdout", CLEAN_DIFF, [], "test",
        )

    def engine(self):
        return SkillEvolutionEngine(
            self.store, min_cases=1, max_cases=10, min_improvement=.01,
            min_holdout_cases=1,
        )

    def test_declarative_artifact_executes_without_code_loading(self):
        normalized = validate_artifact(artifact(), "evolved-review")
        self.assertEqual([], normalized["permissions"])
        reviewer = DeclarativeSkillReviewer(normalized, 2)
        findings = reviewer.review(RISK_DIFF, parse_unified_diff(RISK_DIFF))
        self.assertEqual("evolved-review@2", reviewer.name)
        self.assertEqual(["SEC-DANGEROUS-CALL"], [item.rule_id for item in findings])
        with self.assertRaisesRegex(ValueError, "start with 'evolved-'"):
            validate_artifact({"name": "security-review", "rules": []}, "security-review")

    def test_candidate_replay_activates_and_persists_artifact_version(self):
        self.seed_cases()
        result = self.engine().propose("evolved-review", artifact())

        self.assertEqual("activated", result["decision"])
        self.assertTrue(result["gates"]["validation_improvement"])
        self.assertTrue(result["gates"]["holdout_non_regression"])
        active = self.store.get_active_skill_artifact("evolved-review")
        self.assertEqual(1, active["version"])
        self.assertEqual("SEC-DANGEROUS-CALL", active["artifact"]["rules"][0]["rule_id"])
        run = self.store.list_skill_evolution_runs()[0]
        self.assertNotIn("case_results", run["metrics"]["candidate_holdout"])
        self.assertEqual(active["artifact_sha256"], run["metrics"]["reproducibility"]["candidate_artifact_sha256"])
        rejected = self.engine().propose(
            "evolved-review", {"name": "evolved-review", "rules": []}
        )
        self.assertEqual("rejected", rejected["decision"])
        self.assertFalse(self.engine().rollback(
            "evolved-review", rejected["version"]["version"]
        ))

    def test_auto_evolution_learns_literal_rule_from_confirmed_feedback(self):
        self.seed_cases()
        self.store.create("task", "org/repo", 1, {"source": "test"})
        self.store.save_task_payload("task", RISK_DIFF)
        self.store.record_failure_case("task", "missed_issue", {"finding": {
            "rule_id": "SEC-DANGEROUS-CALL", "severity": "high",
            "path": "a.py", "line": 1,
        }})

        result = self.engine().auto_propose("evolved-review")

        self.assertEqual("activated", result["decision"])
        self.assertEqual(["SEC-DANGEROUS-CALL"], result["learned_rule_ids"])
        self.assertEqual("dangerous_call(data)", self.store.get_active_skill_artifact(
            "evolved-review"
        )["artifact"]["rules"][0]["match"])
        self.assertTrue(self.store.list_failure_cases()[0]["resolved"])

    def test_service_loads_active_evolved_skill_into_review_graph(self):
        self.store.save_skill_artifact("evolved-review", validate_artifact(
            artifact(), "evolved-review"
        ), 1.0, True)
        with tempfile.TemporaryDirectory() as skills_dir:
            settings = Settings(
                host="127.0.0.1", port=8080, db_path=self.path,
                max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
                llm_base_url="", llm_api_key="", llm_model="",
                github_webhook_secret="", github_token="", auto_post_review=False,
                skills_dir=skills_dir, eval_min_holdout_cases=0,
            )
            service = ReviewService(settings)
            try:
                info = {item["name"]: item for item in service.list_skills("default")}
                self.assertEqual("evolved-db", info["evolved-review"]["source"])
                result = service.create_review("org/repo", RISK_DIFF)
                self.assertIn(
                    "SEC-DANGEROUS-CALL",
                    [item["rule_id"] for item in result["report"]["findings"]],
                )
            finally:
                service.queue.close()

    def test_active_evolved_skills_are_tenant_isolated(self):
        self.store.save_skill_artifact(
            "evolved-review", validate_artifact(artifact(), "evolved-review"),
            1.0, True, "tenant-a",
        )
        with tempfile.TemporaryDirectory() as skills_dir:
            settings = Settings(
                host="127.0.0.1", port=8080, db_path=self.path,
                max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
                llm_base_url="", llm_api_key="", llm_model="",
                github_webhook_secret="", github_token="", auto_post_review=False,
                skills_dir=skills_dir, eval_min_holdout_cases=0,
            )
            service = ReviewService(settings)
            try:
                self.assertIn(
                    "evolved-review", {item["name"] for item in service.list_skills("tenant-a")}
                )
                self.assertNotIn(
                    "evolved-review", {item["name"] for item in service.list_skills("tenant-b")}
                )
                self.assertEqual(1, service.store.dashboard_stats("tenant-a")["active_skill_versions"])
                self.assertEqual(0, service.store.dashboard_stats("tenant-b")["active_skill_versions"])
                report_a = service.create_review(
                    "org/repo", RISK_DIFF, tenant_id="tenant-a"
                )["report"]
                report_b = service.create_review(
                    "org/repo", RISK_DIFF, tenant_id="tenant-b"
                )["report"]
                self.assertIn(
                    "SEC-DANGEROUS-CALL", [item["rule_id"] for item in report_a["findings"]]
                )
                self.assertNotIn(
                    "SEC-DANGEROUS-CALL", [item["rule_id"] for item in report_b["findings"]]
                )
            finally:
                service.queue.close()


if __name__ == "__main__":
    unittest.main()
