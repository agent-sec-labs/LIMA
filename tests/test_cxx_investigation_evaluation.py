"""Paired-strategy evaluation contracts for the investigation slice (T12)."""

import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.uaf_orchestrator import UAF_FINDING_STATES

ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_platform_evaluation.py"
CASES_PATH = ROOT / "evaluation_data" / "platform_cases" / "cases.json"

STRATEGIES = ("pipeline", "investigator", "team")


def load_evaluation_module():
    spec = importlib.util.spec_from_file_location(
        "platform_evaluation_strategy", SCRIPT_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("evaluation module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class StrategyEvaluationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def _record(self, case_id, revision, strategy, **overrides):
        record = {
            "case_id": case_id,
            "revision": revision,
            "counted": True,
            "strategy": strategy,
            "llm_transport": "fake",
            "build_context_source": "repository-compdb",
            "translation_units": ["src/a.cpp"],
            "coverage_gaps": [],
            "leads": 0,
            "targets": [],
            "finding_count": 0,
            "experiment_count": 0,
            "poc_stability": None,
            "llm": {
                "scout_calls": 0,
                "specialist_calls": 0,
                "critic_calls": 0,
                "reply_bytes": 0,
            },
            "elapsed_seconds": 0.0,
            "diagnostics": [],
        }
        record.update(overrides)
        return record

    def _investigated_target(self, state, *, stop_reason, actions, children=0,
                             hypotheses=1, strategy="investigator"):
        return {
            "target_id": "lead-001",
            "path": "src/a.cpp",
            "line": 8,
            "cwe": "CWE-416",
            "state": state,
            "finding": state in UAF_FINDING_STATES,
            "proof_verdict": "",
            "rejected_reason": "",
            "experiment_log": [],
            "driver_sha256": "",
            "investigation": {
                "strategy": strategy,
                "stop_reason": stop_reason,
                "action_count": actions,
                "child_count": children,
                "hypothesis_count": hypotheses,
            },
        }

    def test_three_strategies_use_same_case_identity(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "compare.json"
            code = self.module.main([
                "--cases", str(CASES_PATH),
                "--case-id", "uaf-direct",
                "--output", str(output),
                "--fake-llm",
                "--compare-strategies",
            ])
            self.assertEqual(0, code)
            report = json.loads(output.read_text(encoding="utf8"))
        self.assertTrue(report["comparison"])
        self.assertEqual(
            set(STRATEGIES), set(report["strategies"]),
            "the comparison must cover exactly the three strategies",
        )
        identities = {
            name: report["strategies"][name]["identity"]
            for name in STRATEGIES
        }
        shared = (
            "case_data_sha256", "platform_pipeline_sha256", "mode", "model",
            "llm_transport", "timeout_seconds",
        )
        for field in shared:
            values = {identities[name][field] for name in STRATEGIES}
            self.assertEqual(
                1, len(values),
                f"strategy runs must share {field}; got {values}",
            )
        self.assertEqual(
            set(STRATEGIES),
            {identities[name]["strategy"] for name in STRATEGIES},
        )
        for name in STRATEGIES:
            self.assertEqual(name, report["strategies"][name]["strategy"])

    def test_labels_never_enter_model_context(self):
        module = self.module
        captured: list[str] = []
        original_platform = module.scripted_platform_transport
        original_scout = module.scripted_scout_transport

        def recording_platform(case_id, counter):
            inner = original_platform(case_id, counter)

            def transport(provider, base_url, api_key, payload, timeout,
                          **kwargs):
                for message in payload["messages"]:
                    captured.append(str(message["content"]))
                return inner(
                    provider, base_url, api_key, payload, timeout, **kwargs
                )

            return transport

        def recording_scout(counter):
            inner = original_scout(counter)

            def transport(provider, base_url, api_key, payload, timeout,
                          **kwargs):
                for message in payload["messages"]:
                    captured.append(str(message["content"]))
                return inner(
                    provider, base_url, api_key, payload, timeout, **kwargs
                )

            return transport

        case = next(
            case for case in module.load_case_document(CASES_PATH)["cases"]
            if case["id"] == "uaf-direct"
        )
        with mock.patch.object(
            module, "scripted_platform_transport", recording_platform
        ), mock.patch.object(
            module, "scripted_scout_transport", recording_scout
        ):
            record = module.run_revision(
                case, "vulnerable", strategy="team", fake_llm=True,
            )
        self.assertEqual("team", record["strategy"])
        self.assertTrue(captured, "the scripted run must exercise the model")
        corpus = "\n".join(captured)
        for label in (
            "final_state", "pair_correct", "non_security", "detection_rate",
            "revisable", "false_positive_rate",
        ):
            self.assertNotIn(
                label, corpus,
                f"evaluation-side label {label!r} leaked into model context",
            )

    def test_budget_and_incomplete_cases_remain_in_denominator(self):
        module = self.module
        cases = module.load_case_document(CASES_PATH)["cases"]
        pipeline_records = {}
        investigator_records = {}
        for case in cases:
            for revision in module.REVISIONS:
                pipeline_records[(case["id"], revision)] = self._record(
                    case["id"], revision, "pipeline",
                )
                investigator_records[(case["id"], revision)] = self._record(
                    case["id"], revision, "investigator",
                    targets=[self._investigated_target(
                        "abstain", stop_reason="budget-exhausted", actions=24,
                    )],
                    diagnostics=["investigation lead-001: budget-exhausted"],
                )
        pipeline_report = module.run_evaluation(
            cases, pipeline_records, strategy="pipeline",
        )
        investigator_report = module.run_evaluation(
            cases, investigator_records, strategy="investigator",
        )
        self.assertEqual(
            pipeline_report["detection_rate"]["total"],
            investigator_report["detection_rate"]["total"],
            "budget-exhausted runs must stay in the detection denominator",
        )
        self.assertEqual(
            pipeline_report["case_count"],
            investigator_report["case_count"],
            "no case may be dropped for a degraded strategy run",
        )
        self.assertEqual(
            len(pipeline_report["cases"]),
            len(investigator_report["cases"]),
        )
        self.assertEqual(
            len(cases) * len(module.REVISIONS),
            investigator_report["investigation_metrics"]["budget_exhausted_runs"],
        )
        self.assertEqual(
            0, pipeline_report["investigation_metrics"]["budget_exhausted_runs"],
        )

    def test_trace_metrics_derive_from_records(self):
        module = self.module
        cases = module.load_case_document(CASES_PATH)["cases"]
        two = cases[:2]
        records = {}
        for case in two:
            records[(case["id"], "vulnerable")] = self._record(
                case["id"], "vulnerable", "team",
                targets=[
                    self._investigated_target(
                        "runtime-confirmed", stop_reason="final", actions=7,
                        children=1, hypotheses=2, strategy="team",
                    ),
                    self._investigated_target(
                        "needs-human-review",
                        stop_reason="protocol-error", actions=5,
                    ),
                ],
            )
            records[(case["id"], "fixed")] = self._record(
                case["id"], "fixed", "team",
                targets=[self._investigated_target(
                    "abstain", stop_reason="final", actions=3,
                )],
            )
        metrics = module.run_evaluation(two, records, strategy="team")[
            "investigation_metrics"
        ]
        self.assertEqual(6, metrics["targets_with_investigation"])
        self.assertEqual(4, metrics["stop_reasons"]["final"])
        self.assertEqual(2, metrics["stop_reasons"]["protocol-error"])
        self.assertEqual(2, metrics["runtime_confirmed_targets"])
        self.assertEqual(2, metrics["needs_review_targets"])
        self.assertEqual(30, metrics["action_total"])
        self.assertEqual(2, metrics["child_total"])
        self.assertEqual(0, metrics["budget_exhausted_runs"])
        # Metrics follow the records alone: mutate one and recompute.
        first_key = (two[0]["id"], "vulnerable")
        mutated = dict(records)
        mutated[first_key] = self._record(
            two[0]["id"], "vulnerable", "team",
            targets=[self._investigated_target(
                "abstain", stop_reason="budget-exhausted", actions=9,
            )],
        )
        recomputed = module.run_evaluation(two, mutated, strategy="team")[
            "investigation_metrics"
        ]
        self.assertEqual(27, recomputed["action_total"])
        self.assertEqual(1, recomputed["budget_exhausted_runs"])
        self.assertEqual(1, recomputed["runtime_confirmed_targets"])

    def test_scripted_results_carry_fake_marker(self):
        module = self.module
        case = next(
            case for case in module.load_case_document(CASES_PATH)["cases"]
            if case["id"] == "uaf-direct"
        )
        record = module.run_revision(
            case, "vulnerable", strategy="investigator", fake_llm=True,
        )
        self.assertEqual("fake", record["llm_transport"])
        self.assertEqual("investigator", record["strategy"])
        with self.assertRaisesRegex(ValueError, "llm_transport"):
            module.validate_record(self._record(
                "uaf-direct", "vulnerable", "investigator",
                llm_transport="bogus",
            ))


if __name__ == "__main__":
    unittest.main()
