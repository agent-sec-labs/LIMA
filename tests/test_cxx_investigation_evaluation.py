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

    def test_report_strategy_is_inferred_from_real_records(self):
        module = self.module
        case = next(case for case in module.load_case_document(CASES_PATH)["cases"]
                    if case["id"] == "uaf-direct")
        for strategy in STRATEGIES:
            with self.subTest(strategy=strategy):
                records = {
                    (case["id"], revision): module.run_revision(
                        case, revision, strategy=strategy, fake_llm=True,
                    ) for revision in module.REVISIONS
                }
                before = json.dumps(list(records.values()), sort_keys=True)
                report = module.run_evaluation([case], records)
                self.assertEqual(strategy, report["strategy"])
                self.assertEqual(before, json.dumps(list(records.values()), sort_keys=True))

    def test_mismatched_and_mixed_record_strategies_are_rejected(self):
        module = self.module
        case = next(case for case in module.load_case_document(CASES_PATH)["cases"]
                    if case["id"] == "uaf-direct")
        records = {
            (case["id"], revision): module.run_revision(
                case, revision, strategy="investigator", fake_llm=True,
            ) for revision in module.REVISIONS
        }
        for selected in ("pipeline", "team", "unknown"):
            with self.subTest(explicit=selected):
                with self.assertRaisesRegex(ValueError, "strategy"):
                    module.run_evaluation([case], records, strategy=selected)
        fixed = module.run_revision(case, "fixed", strategy="pipeline", fake_llm=True)
        for counted in (True, False):
            mixed = {**records, (case["id"], "fixed"): {**fixed, "counted": counted}}
            for selected in (None, "pipeline", "investigator"):
                with self.subTest(counted=counted, explicit=selected):
                    with self.assertRaisesRegex(ValueError, "strategy"):
                        module.run_evaluation([case], mixed, strategy=selected)

    def test_legacy_strategy_defaults_to_pipeline_without_mutation(self):
        module = self.module
        case = module.load_case_document(CASES_PATH)["cases"][0]
        records = {}
        for revision in module.REVISIONS:
            record = self._record(case["id"], revision, "pipeline")
            del record["strategy"]
            del record["llm_transport"]
            records[(case["id"], revision)] = record
        before = json.dumps(list(records.values()), sort_keys=True)
        for selected in (None, "pipeline"):
            with self.subTest(explicit=selected):
                report = module.run_evaluation([case], records, strategy=selected)
                self.assertEqual("pipeline", report["strategy"])
                self.assertEqual(before, json.dumps(list(records.values()), sort_keys=True))
        with self.assertRaisesRegex(ValueError, "strategy"):
            module.run_evaluation([case], records, strategy="investigator")

    def test_hypothesis_counts_follow_real_investigation_history(self):
        module = self.module
        case = next(case for case in module.load_case_document(CASES_PATH)["cases"]
                    if case["id"] == "uaf-direct")
        for strategy in ("investigator", "team"):
            with self.subTest(strategy=strategy):
                records = {
                    (case["id"], revision): module.run_revision(
                        case, revision, strategy=strategy, fake_llm=True,
                    ) for revision in module.REVISIONS
                }
                vulnerable = records[(case["id"], "vulnerable")]
                self.assertEqual(1, vulnerable["targets"][0]["investigation"]["hypothesis_count"])
                report = module.run_evaluation([case], records, strategy=strategy)
                self.assertEqual(1, report["investigation_metrics"]["hypothesis_total"])

    def test_pipeline_fingerprint_covers_investigation_runtime_sources(self):
        module = self.module
        baseline = module.platform_pipeline_fingerprint()
        original_read = Path.read_bytes
        for name in ("cxx_investigator.py", "cxx_scout_exploration.py", "runtime.py",
                     "cxx_agent_tools.py", "cxx_agent_models.py"):
            with self.subTest(component=name):
                def changed_source(path):
                    payload = original_read(path)
                    if path == ROOT / "lima" / name:
                        return payload + b"\n# changed investigation implementation\n"
                    return payload

                with mock.patch.object(Path, "read_bytes", changed_source):
                    self.assertNotEqual(baseline, module.platform_pipeline_fingerprint())

    def test_scout_budget_exhaustion_is_counted_without_targets(self):
        module = self.module
        case = next(case for case in module.load_case_document(CASES_PATH)["cases"]
                    if case["id"] == "uaf-direct")
        fixed = module.run_revision(case, "fixed", strategy="investigator", fake_llm=True)
        with mock.patch.object(module, "_fresh_review_budget", side_effect=lambda:
                               module.CxxAgentBudget(max_calls=1)):
            vulnerable = module.run_revision(
                case, "vulnerable", strategy="investigator", fake_llm=True,
            )
        self.assertEqual([], vulnerable["targets"])
        self.assertIn("scout: budget-exhausted", vulnerable["diagnostics"])
        self.assertTrue(vulnerable.get("budget_exhausted"))
        report = module.run_evaluation([case], {
            (case["id"], "vulnerable"): vulnerable,
            (case["id"], "fixed"): fixed,
        }, strategy="investigator")
        self.assertEqual(1, report["investigation_metrics"]["budget_exhausted_runs"])
        self.assertEqual(2, report["counted_revision_count"])

    def test_run_budget_marker_is_optional_validated_and_counted_once(self):
        module = self.module
        case = module.load_case_document(CASES_PATH)["cases"][0]
        legacy = self._record(case["id"], "fixed", "investigator")
        self.assertIs(legacy, module.validate_record(legacy))
        self.assertNotIn("budget_exhausted", legacy)
        for invalid in (1, "true", None):
            with self.subTest(invalid=invalid):
                with self.assertRaisesRegex(ValueError, "budget_exhausted"):
                    module.validate_record({**legacy, "budget_exhausted": invalid})
        exhausted = self._record(
            case["id"], "vulnerable", "investigator", budget_exhausted=True,
            diagnostics=["scout: budget-exhausted"],
            targets=[self._investigated_target(
                "abstain", stop_reason="budget-exhausted", actions=1,
            )],
        )
        report = module.run_evaluation([case], {
            (case["id"], "vulnerable"): exhausted,
            (case["id"], "fixed"): legacy,
        }, strategy="investigator")
        self.assertEqual(1, report["investigation_metrics"]["budget_exhausted_runs"])

    def test_exploration_exhaustion_survives_zero_target_projection(self):
        module = self.module
        outcome = module.agent_orchestrator._empty_outcome((), ("src/a.cpp",))
        outcome = module.replace(outcome, scout_exploration={
            "stop_reason": "budget-exhausted", "actions": [],
        })
        record = module._record_from_outcome(
            "uaf-direct", "vulnerable", 0, [], outcome, module.new_counter(), 0.0,
            strategy="investigator", llm_transport="fake",
        )
        self.assertTrue(record["budget_exhausted"])
        self.assertEqual([], record["targets"])
        self.assertIs(record, module.validate_record(record))

    def test_missing_required_record_and_target_fields_are_rejected(self):
        module = self.module
        record = self._record("uaf-direct", "vulnerable", "investigator")
        for name in module._RECORD_KEYS:
            with self.subTest(record_field=name):
                incomplete = dict(record)
                del incomplete[name]
                with self.assertRaises(ValueError):
                    module.validate_record(incomplete)
        target = self._investigated_target("abstain", stop_reason="final", actions=0)
        for name in module._TARGET_KEYS:
            with self.subTest(target_field=name):
                incomplete = dict(target)
                del incomplete[name]
                with self.assertRaises(ValueError):
                    module.validate_record({**record, "targets": [incomplete]})

    def test_cli_rejects_source_drift_during_run_and_preserves_existing_output(self):
        module = self.module
        original_read = Path.read_bytes
        original_run = module.run_revision
        for options in (["--compare-strategies"], ["--strategy", "pipeline"]):
            with self.subTest(options=options), tempfile.TemporaryDirectory() as temporary:
                output = Path(temporary) / "report.json"
                output.write_text("previous report", encoding="utf8")
                completed = []

                def changed_source(path):
                    payload = original_read(path)
                    if completed and path == ROOT / "lima" / "agent_orchestrator.py":
                        return payload + b"\n# source changed during evaluation\n"
                    return payload

                def run_then_change(*args, **kwargs):
                    record = original_run(*args, **kwargs)
                    completed.append(kwargs["strategy"])
                    return record

                with mock.patch.object(Path, "read_bytes", changed_source), mock.patch.object(
                    module, "run_revision", run_then_change,
                ):
                    with self.assertRaisesRegex(SystemExit, "identity changed"):
                        module.main([
                            "--case-id", "uaf-direct", "--fake-llm",
                            "--output", str(output), *options,
                        ])
                self.assertEqual(["pipeline"], completed)
                self.assertEqual("previous report", output.read_text(encoding="utf8"))

    def test_identity_is_checked_before_first_run(self):
        module = self.module
        fingerprints = iter(("a" * 64, "b" * 64))
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            with mock.patch.object(
                module, "platform_pipeline_fingerprint", side_effect=lambda: next(fingerprints),
            ), mock.patch.object(
                module, "run_revision", side_effect=AssertionError("started after source drift"),
            ):
                with self.assertRaisesRegex(SystemExit, "identity changed"):
                    module.main([
                        "--case-id", "uaf-direct", "--fake-llm", "--compare-strategies",
                        "--output", str(output),
                    ])
            self.assertFalse(output.exists())

    def test_case_identity_uses_the_same_bytes_as_case_parsing(self):
        module = self.module
        original_read = Path.read_bytes
        reads = []

        def changed_manifest(path):
            payload = original_read(path)
            if path == CASES_PATH:
                reads.append(path)
                if len(reads) > 1:
                    return payload + b"\n"
            return payload

        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            with mock.patch.object(Path, "read_bytes", changed_manifest), mock.patch.object(
                module, "run_revision", side_effect=AssertionError("started after manifest drift"),
            ):
                with self.assertRaisesRegex(SystemExit, "identity changed"):
                    module.main([
                        "--cases", str(CASES_PATH), "--case-id", "uaf-direct", "--fake-llm",
                        "--output", str(output),
                    ])
            self.assertFalse(output.exists())
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
