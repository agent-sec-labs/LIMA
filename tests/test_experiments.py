import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lima.config import Settings
from lima.experiments import ExperimentRunner
from lima.real_world_evaluation import RealWorldSecurityEvaluator
from lima.store import TaskStore
from lima.task_queue import TaskQueue


class FakeEvaluator:
    def __init__(self, *, llm=False, fail_once=""):
        self.llm = llm
        self.fail_once = fail_once
        self.failed = set()
        self.case_calls = []
        self.fetch_calls = []
        self.aggregate_calls = 0

    def fetch(self, dataset):
        case_id = dataset["cases"][0]["id"]
        self.fetch_calls.append(case_id)
        return {"schema_version": 2, "snapshots": [{"case_id": case_id}]}

    def run(self, dataset, *, mode, completed_cases=None):
        if completed_cases is not None:
            self.aggregate_calls += 1
            return {
                "schema_version": 2,
                "mode": mode,
                "metrics": {"cases": len(completed_cases)},
                "failure_categories": {},
                "cases": [completed_cases[item["id"]] for item in dataset["cases"]],
            }
        case_id = dataset["cases"][0]["id"]
        self.case_calls.append(case_id)
        if case_id == self.fail_once and case_id not in self.failed:
            self.failed.add(case_id)
            raise RuntimeError("simulated worker interruption")
        case_result = {"id": case_id, "llm": None}
        if self.llm:
            response = {
                "status": "completed", "contract_valid": True,
                "usage": {
                    "prompt_tokens": 10, "completion_tokens": 5,
                    "total_tokens": 15,
                },
            }
            case_result["llm"] = {
                "vulnerable": dict(response), "fixed": dict(response),
                "paired_correct": True,
            }
        return {"cases": [case_result]}


class ExperimentRunnerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.datasets = self.root / "datasets"
        self.artifacts = self.root / "artifacts"
        self.datasets.mkdir()
        self.dataset_path = self.datasets / "holdout.json"
        self.dataset_path.write_text("{}\n", encoding="utf-8")
        self.dataset = {
            "schema_version": 2,
            "name": "test-holdout",
            "evaluation_role": "development",
            "cases": [{"id": "case-a"}, {"id": "case-b"}],
        }
        self.store = TaskStore(str(self.root / "tasks.db"))

    def tearDown(self):
        self.temp.cleanup()

    def runner(self, evaluator, *, llm=False):
        return ExperimentRunner(
            self.store, self.datasets, self.artifacts, lambda _mode: evaluator,
            llm_available=llm,
            llm_identity={"provider": "fake", "model": "fake-model"},
            dataset_loader=lambda _path: json.loads(json.dumps(self.dataset)),
            analyzer_identity=lambda: "a" * 64,
        )

    def test_runs_without_a_supervising_process_and_persists_artifacts(self):
        evaluator = FakeEvaluator()
        runner = self.runner(evaluator)
        created = runner.create("holdout.json", "retrieval", "tenant-a")

        completed = runner.run(created["id"])

        self.assertEqual("SUCCEEDED", completed["state"])
        self.assertEqual(["case-a", "case-b"], evaluator.case_calls)
        self.assertEqual(1, evaluator.aggregate_calls)
        self.assertEqual(2, completed["progress"]["completed_cases"])
        run_dir = self.artifacts / created["id"]
        self.assertTrue((run_dir / "manifest.json").is_file())
        self.assertTrue((run_dir / "cases" / "case-a" / "result.json").is_file())
        self.assertTrue((run_dir / "reports" / "summary.json").is_file())
        self.assertTrue((run_dir / "checksums.sha256").is_file())
        self.assertTrue((run_dir / "COMPLETE.json").is_file())
        manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
        self.assertFalse(manifest["secret_persisted"])
        listed = self.store.list_experiments(10, "tenant-a")[0]
        self.assertTrue(listed["result_available"])
        self.assertNotIn("result", listed)

    def test_catalog_exposes_safe_metadata_without_case_labels(self):
        evaluator = FakeEvaluator()
        runner = self.runner(evaluator, llm=True)

        catalog = runner.catalog()

        self.assertEqual(1, len(catalog))
        self.assertEqual("holdout.json", catalog[0]["path"])
        self.assertEqual("test-holdout", catalog[0]["name"])
        self.assertEqual(2, catalog[0]["case_count"])
        self.assertIn("llm-retrieval", catalog[0]["modes"])
        self.assertNotIn("cases", catalog[0])
        self.assertNotIn("case_ids", catalog[0])

    def test_deterministic_failure_resumes_without_repeating_completed_cases(self):
        evaluator = FakeEvaluator(fail_once="case-b")
        runner = self.runner(evaluator)
        created = runner.create("holdout.json", "retrieval")

        failed = runner.run(created["id"])
        self.assertEqual("FAILED", failed["state"])
        self.assertEqual(["case-a", "case-b"], evaluator.case_calls)

        runner.prepare_resume(created["id"], "default")
        completed = runner.run(created["id"])

        self.assertEqual("SUCCEEDED", completed["state"])
        self.assertEqual(1, evaluator.case_calls.count("case-a"))
        self.assertEqual(2, evaluator.case_calls.count("case-b"))

    def test_ambiguous_llm_failure_requires_explicit_retry_approval(self):
        evaluator = FakeEvaluator(llm=True, fail_once="case-a")
        runner = self.runner(evaluator, llm=True)
        created = runner.create("holdout.json", "llm-retrieval")

        interrupted = runner.run(created["id"])
        self.assertEqual("NEEDS_ATTENTION", interrupted["state"])
        self.assertEqual("AMBIGUOUS", interrupted["cases"][0]["status"])
        runner.run(created["id"])
        self.assertEqual(1, evaluator.case_calls.count("case-a"))
        with self.assertRaisesRegex(ValueError, "explicit retry"):
            runner.prepare_resume(created["id"], "default")

        runner.prepare_resume(
            created["id"], "default", allow_ambiguous_retry=True
        )
        completed = runner.run(created["id"], allow_ambiguous_retry=True)

        self.assertEqual("SUCCEEDED", completed["state"])
        self.assertEqual(2, evaluator.case_calls.count("case-a"))
        self.assertEqual(6, completed["progress"]["llm_calls"])
        self.assertEqual(60, completed["progress"]["total_tokens"])

    def test_llm_call_budget_stops_before_the_next_pair(self):
        evaluator = FakeEvaluator(llm=True)
        runner = self.runner(evaluator, llm=True)
        created = runner.create(
            "holdout.json", "llm-retrieval", max_llm_calls=2
        )

        stopped = runner.run(created["id"])

        self.assertEqual("BUDGET_EXHAUSTED", stopped["state"])
        self.assertEqual(["case-a"], evaluator.case_calls)
        self.assertEqual(2, stopped["progress"]["llm_calls"])
        with self.assertRaisesRegex(ValueError, "budgets are immutable"):
            runner.prepare_resume(created["id"], "default")

    def test_dataset_drift_fails_closed_before_fetching(self):
        evaluator = FakeEvaluator()
        runner = self.runner(evaluator)
        created = runner.create("holdout.json", "retrieval")
        self.dataset_path.write_text('{"changed": true}\n', encoding="utf-8")

        failed = runner.run(created["id"])

        self.assertEqual("FAILED", failed["state"])
        self.assertIn("dataset file changed", failed["error"])
        self.assertEqual([], evaluator.fetch_calls)

    def test_rejects_dataset_escape_and_namespaces_the_queue(self):
        evaluator = FakeEvaluator()
        runner = self.runner(evaluator)
        with self.assertRaisesRegex(ValueError, "relative JSON"):
            runner.create(str(self.dataset_path.resolve()), "retrieval")
        self.dataset["cases"][0]["id"] = "../escape"
        with self.assertRaisesRegex(ValueError, "path-safe"):
            runner.create("holdout.json", "retrieval")
        queue = TaskQueue(
            lambda _payload: None, workers=1,
            stream="lima:test:experiment", dead_letter_stream="lima:test:dlq",
            group="lima-test-workers",
        )
        try:
            self.assertEqual("lima:test:experiment", queue.stream)
            self.assertEqual("lima:test:dlq", queue.dead_letter_stream)
            self.assertEqual("lima-test-workers", queue.group)
        finally:
            queue.close()

    def test_checksum_manifest_matches_committed_files(self):
        evaluator = FakeEvaluator()
        runner = self.runner(evaluator)
        created = runner.create("holdout.json", "retrieval")
        runner.run(created["id"])
        run_dir = self.artifacts / created["id"]
        rows = (run_dir / "checksums.sha256").read_text(encoding="utf-8").splitlines()
        for row in rows:
            expected, relative = row.split("  ", 1)
            actual = hashlib.sha256((run_dir / relative).read_bytes()).hexdigest()
            self.assertEqual(expected, actual, relative)

    def test_experiment_configuration_is_loaded_with_bounded_defaults(self):
        environment = {
            "LIMA_EXPERIMENT_WORKERS": "2",
            "LIMA_EXPERIMENT_QUEUE_LEASE_SECONDS": "7200",
            "LIMA_EXPERIMENT_DATASET_ROOT": "datasets-v2",
            "LIMA_EXPERIMENT_ARTIFACT_ROOT": "artifacts-v2",
            "LIMA_EXPERIMENT_CACHE_ROOT": "cache-v2",
            "LIMA_EXPERIMENT_MAX_LLM_CALLS": "12",
            "LIMA_EXPERIMENT_MAX_TOTAL_TOKENS": "50000",
        }
        with patch.dict("os.environ", environment, clear=True):
            settings = Settings.from_env()
        self.assertEqual(2, settings.experiment_workers)
        self.assertEqual(7200, settings.experiment_queue_lease_seconds)
        self.assertEqual("datasets-v2", settings.experiment_dataset_root)
        self.assertEqual("artifacts-v2", settings.experiment_artifact_root)
        self.assertEqual("cache-v2", settings.experiment_cache_root)
        self.assertEqual(12, settings.experiment_max_llm_calls)
        self.assertEqual(50000, settings.experiment_max_total_tokens)

    def test_real_evaluator_aggregates_completed_case_without_reexecution(self):
        class RejectingSnapshotStore:
            def acquire(self, *_args, **_kwargs):
                raise AssertionError("completed cases must not reacquire snapshots")

        completed = {
            "id": "case-a",
            "deterministic": {
                "vulnerable_hit": True,
                "fixed_clean": True,
                "paired_discrimination": True,
                "verified_evidence": True,
                "scan_latency_ms": {"vulnerable": 1.0, "fixed": 2.0},
            },
            "repair": {"attempted": False, "verified_patch": False},
            "expected_repair_policy": "abstain",
            "oracle": {"configured": False, "executed": False, "paired_pass": None},
            "retrieval": None,
            "llm": None,
        }
        evaluator = RealWorldSecurityEvaluator(RejectingSnapshotStore())

        result = evaluator.run(
            {"schema_version": 2, "name": "resume-test", "cases": [{"id": "case-a"}]},
            mode="deterministic", completed_cases={"case-a": completed},
        )

        self.assertEqual(1, result["metrics"]["cases"])
        self.assertEqual(1.0, result["metrics"]["paired_discrimination_rate"])
        self.assertEqual({}, result["failure_categories"])


if __name__ == "__main__":
    unittest.main()
