"""Unlabeled paired-benchmark contract for the UAF v2 pipeline (plan Task 12).

All tests run fully offline: the Sidecar is a fake ``analyze_uaf_facts``
serving canned wire bundles per committed case, the semantic branch
transport is a scripted fake, and the evaluation assets never enter the
``review_uaf`` input path.  Red lines pinned here (design section 16):

- the committed manifest carries a vulnerable/fixed pair per code shape and
  at least one deterministic proof UNKNOWN that genuinely needs the
  Specialist/Critic branch;
- zero denominators are ``null`` plus a diagnostic, never a fake zero;
- every aggregate metric is recomputable from the embedded records;
- no case label (id, title, rationale, license, expected verdicts) reaches
  the workspace, the fact wire, the analyzer request or the model context;
- the Proof Obligation Failure Distribution stays an independent top-level
  P1-P7 structure with slices, never a collapsed single score.
"""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.uaf_orchestrator import UAF_FINDING_STATES, UAF_POSITIVE_STATES
from lima.workspace import RepositoryWorkspace

ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_uaf_v2_evaluation.py"
CASES_PATH = ROOT / "evaluation_data" / "uaf_v2_cases.json"
PAIRS_ROOT = ROOT / "tests" / "fixtures" / "uaf_v2_pairs"

REQUIRED_KINDS = frozenset(
    {
        "direct-uaf",
        "guarded-same-block-uaf",
        "rebind-counterexample",
        "unreachable-use",
        "predicated-unknown",
        "deterministic-unknown-needs-llm",
    }
)
SEMANTIC_CASE_KIND = "deterministic-unknown-needs-llm"
OBLIGATIONS = tuple(f"P{index}" for index in range(1, 8))


def load_evaluation_module():
    spec = importlib.util.spec_from_file_location("uaf_v2_evaluation", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("evaluation module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_fake_evaluation(module, case_ids=None, mode="auto"):
    """Run the committed pairs end to end with the fake sidecar + fake LLM."""

    document = module.load_case_document(CASES_PATH)
    cases = document["cases"]
    if case_ids is not None:
        cases = [case for case in cases if case["id"] in case_ids]
    records = {}
    for case in cases:
        for revision in module.REVISIONS:
            records[(case["id"], revision)] = module.run_revision(
                case, revision, mode=mode, fake_llm=True, timeout=60
            )
    return module.run_evaluation(cases, records)


# ------------------------------------------------------------------- schema


class ManifestSchemaTests(unittest.TestCase):
    """The committed manifest is valid, pinned, and covers the shapes."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()
        cls.document = cls.module.load_case_document(CASES_PATH)
        cls.cases = {case["id"]: case for case in cls.document["cases"]}

    def test_committed_manifest_validates_and_pins_existing_files(self):
        self.module.validate_case_document(copy.deepcopy(self.document))
        self.assertGreaterEqual(len(self.document["cases"]), 6)
        for case in self.document["cases"]:
            for revision in ("vulnerable", "fixed"):
                self.assertEqual("source-pair", case[revision]["kind"])
                for relative, digest in case[revision]["files"].items():
                    pinned = PAIRS_ROOT / case["id"] / revision / relative
                    self.assertTrue(
                        pinned.is_file(), f"missing pinned fixture {pinned}"
                    )
                    actual = self.module.file_digest(pinned)
                    self.assertEqual(
                        digest,
                        actual,
                        f"pin drift for {pinned}",
                    )

    def test_manifest_covers_the_required_code_shapes(self):
        kinds = {case["kind"] for case in self.document["cases"]}
        self.assertTrue(
            REQUIRED_KINDS <= kinds,
            f"manifest is missing required code shapes: {REQUIRED_KINDS - kinds}",
        )

    def test_manifest_contains_the_mandatory_deterministic_unknown_case(self):
        # Design section 16 hard rule: without a fixed deterministic proof
        # UNKNOWN case that genuinely needs Specialist/Critic, a real-model
        # run may not claim the integration is verified.
        semantic = [
            case
            for case in self.document["cases"]
            if case["kind"] == SEMANTIC_CASE_KIND
        ]
        self.assertEqual(1, len(semantic))
        expected = semantic[0]["expected"]["vulnerable"]
        self.assertEqual("UNKNOWN", expected["verdict"])
        self.assertEqual("semantic-supported", expected["final_state"])
        self.assertGreaterEqual(expected["candidates"], 1)

    def test_schema_rejects_malformed_cases(self):
        module = self.module
        base = self.document

        def mutated(mutator):
            document = copy.deepcopy(base)
            mutator(document)
            return document

        def set_kind(document):
            document["cases"][0]["kind"] = "mystery-shape"

        def set_final_state(document):
            first = document["cases"][0]["expected"]["vulnerable"]
            first["final_state"] = "auto-verified"

        def set_verdict(document):
            document["cases"][0]["expected"]["vulnerable"]["verdict"] = "MAYBE"

        def drop_key(document):
            del document["cases"][0]["selection_rationale"]

        def add_key(document):
            document["cases"][0]["ground_truth"] = "leak line 9"

        def drift_pin(document):
            first = document["cases"][0]
            side = "vulnerable" if first["vulnerable"]["files"] else "fixed"
            key = sorted(first[side]["files"])[0]
            first[side]["files"][key] = "0" * 64

        def duplicate_id(document):
            document["cases"].append(copy.deepcopy(document["cases"][0]))

        def escape_path(document):
            first = document["cases"][0]
            key = sorted(first["vulnerable"]["files"])[0]
            first["vulnerable"]["files"]["../" + key] = first[
                "vulnerable"
            ]["files"].pop(key)

        def wrong_version(document):
            document["schema_version"] = 2

        def empty_cases(document):
            document["cases"] = []

        def drop_semantic_case(document):
            document["cases"] = [
                case
                for case in document["cases"]
                if case["kind"] != SEMANTIC_CASE_KIND
            ]

        for mutator in (
            set_kind,
            set_final_state,
            set_verdict,
            drop_key,
            add_key,
            drift_pin,
            duplicate_id,
            escape_path,
            wrong_version,
            empty_cases,
            drop_semantic_case,
        ):
            with self.subTest(mutator=mutator.__name__):
                document = mutated(mutator)
                if mutator is drift_pin:
                    with self.assertRaises(ValueError):
                        module.verify_version_pins(document["cases"][0], "vulnerable")
                else:
                    with self.assertRaises(ValueError):
                        module.validate_case_document(document)

    def test_expected_domain_is_frozen(self):
        verdicts = set()
        states = set()
        for case in self.document["cases"]:
            for revision in ("vulnerable", "fixed"):
                expected = case["expected"][revision]
                verdicts.add(expected["verdict"])
                states.add(expected["final_state"])
        self.assertTrue(verdicts <= {"PASS", "REFUTED", "UNKNOWN", "none"})
        self.assertTrue(
            states
            <= {
                "fact-verified",
                "rejected",
                "abstain",
                "semantic-supported",
                "none",
            }
        )


# --------------------------------------------------------------- zero denom


class ZeroDenominatorTests(unittest.TestCase):
    """Null plus diagnostic for empty denominators, never fake zeros."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def _record(self, case_id, revision, **overrides):
        record = {
            "case_id": case_id,
            "revision": revision,
            "counted": True,
            "build_context_source": "repository-compdb",
            "translation_units": ["src/a.c"],
            "coverage_gaps": [],
            "candidates": [],
            "candidate_count": 0,
            "llm": {"calls": 0, "invoked_candidates": 0, "reply_bytes": 0},
            "elapsed_seconds": 0.0,
            "diagnostics": [],
        }
        record.update(overrides)
        return record

    def _candidate_record(self, state, verdict, obligations):
        return {
            "candidate_id": "a" * 64,
            "state": state,
            "proof_verdict": verdict,
            "obligations": dict(obligations),
            "p5": None,
            "rejected_reason": "",
            "llm_invoked": False,
            "llm_calls": 0,
        }

    def _case(self, case_id, verdict, state, kind="direct-uaf", candidates=1):
        return {
            "id": case_id,
            "kind": kind,
            "origin": "synthetic",
            "language_standard": "c11",
            "expected": {
                "vulnerable": {
                    "verdict": verdict,
                    "final_state": state,
                    "candidates": candidates,
                },
                "fixed": {"verdict": "none", "final_state": "none", "candidates": 0},
            },
        }

    def test_zero_denominator_ratios_are_null_with_diagnostics(self):
        module = self.module
        # All-abstain manifest: no positive predictions and no expected
        # positives, so both fact-verified denominators are zero while the
        # abstention and pair rates stay honest ones.
        case = self._case(
            "abstain-case", "UNKNOWN", "abstain", kind="predicated-unknown"
        )
        abstaining = self._candidate_record("abstain", "UNKNOWN", {"P5": "unknown"})
        records = {
            ("abstain-case", "vulnerable"): self._record(
                "abstain-case",
                "vulnerable",
                candidates=[abstaining],
                candidate_count=1,
            ),
            ("abstain-case", "fixed"): self._record("abstain-case", "fixed"),
        }
        report = module.run_evaluation([case], records)
        self.assertIsNone(report["fact_verified_precision"])
        self.assertIsNone(report["fact_verified_recall"])
        self.assertEqual(
            {"tp": 0, "fp": 0, "fn": 0, "tn": 2}, report["fact_verified_confusion"]
        )
        self.assertEqual(1.0, report["candidate_recall"])
        self.assertAlmostEqual(1.0, report["abstention_correctness"]["rate"])
        self.assertAlmostEqual(1.0, report["paired_accuracy"])
        self.assertTrue(
            any("denominator" in item for item in report["diagnostics"]),
            report["diagnostics"],
        )

    def test_missed_expected_positive_keeps_recall_honest(self):
        module = self.module
        # vulnerable expects fact-verified but abstains: precision has no
        # positive predictions (tp + fp == 0 -> null) while recall is an
        # honest 0.0 and the pair counts as incorrect.
        case = self._case("zero-denom-case", "PASS", "fact-verified")
        abstaining = self._candidate_record("abstain", "UNKNOWN", {"P2": "unknown"})
        records = {
            ("zero-denom-case", "vulnerable"): self._record(
                "zero-denom-case",
                "vulnerable",
                candidates=[abstaining],
                candidate_count=1,
            ),
            ("zero-denom-case", "fixed"): self._record("zero-denom-case", "fixed"),
        }
        report = module.run_evaluation([case], records)
        self.assertIsNone(report["fact_verified_precision"])
        self.assertEqual(0.0, report["fact_verified_recall"])
        self.assertAlmostEqual(0.0, report["paired_accuracy"])
        self.assertTrue(
            any("denominator" in item for item in report["diagnostics"]),
            report["diagnostics"],
        )

    def test_degraded_revision_makes_the_pair_ineligible(self):
        module = self.module
        case = self._case("degraded-case", "PASS", "fact-verified")
        records = {
            ("degraded-case", "vulnerable"): self._record(
                "degraded-case", "vulnerable", counted=False
            ),
            ("degraded-case", "fixed"): self._record("degraded-case", "fixed"),
        }
        report = module.run_evaluation([case], records)
        self.assertIsNone(report["paired_accuracy"])
        self.assertIsNone(report["candidate_recall"])
        self.assertTrue(
            any("degraded" in item for item in report["diagnostics"]),
            report["diagnostics"],
        )

    def test_empty_obligation_slice_ratios_are_null_with_diagnostics(self):
        module = self.module
        case = self._case("no-candidates-case", "UNKNOWN", "abstain")
        records = {
            ("no-candidates-case", "vulnerable"): self._record(
                "no-candidates-case", "vulnerable"
            ),
            ("no-candidates-case", "fixed"): self._record("no-candidates-case", "fixed"),
        }
        report = module.run_evaluation([case], records)
        distribution = report["proof_obligation_distribution"]
        overall = distribution["overall"]["P1"]
        self.assertEqual(0, overall["total"])
        self.assertIsNone(overall["unknown_ratio"])
        self.assertIsNone(overall["refuted_ratio"])
        self.assertTrue(
            any("P1" in item for item in report["diagnostics"]),
            report["diagnostics"],
        )


# --------------------------------------------------------------- recompute


class RecordsRecomputeTests(unittest.TestCase):
    """Every aggregate is recomputable from records plus the case labels."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()
        cls.document = cls.module.load_case_document(CASES_PATH)
        cls.cases = cls.document["cases"]
        cls.report = run_fake_evaluation(cls.module)
        cls.records = {
            (record["case_id"], record["revision"]): record
            for record in cls.report["records"]
        }

    def _observed_state(self, record):
        states = [candidate["state"] for candidate in record["candidates"]]
        if not states:
            return "none"
        return states[0] if len(set(states)) == 1 else "mixed"

    def test_records_recompute_every_aggregate_metric(self):
        module = self.module
        report = self.report
        cases = self.cases

        # candidate recall
        eligible = [
            case
            for case in cases
            if case["expected"]["vulnerable"]["candidates"] >= 1
        ]
        hits = [
            case
            for case in eligible
            if self.records[(case["id"], "vulnerable")]["candidate_count"] >= 1
        ]
        expected_recall = len(hits) / len(eligible)
        self.assertAlmostEqual(expected_recall, report["candidate_recall"])

        # fact-verified confusion
        confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for case in cases:
            for revision in module.REVISIONS:
                record = self.records[(case["id"], revision)]
                expected_fv = (
                    case["expected"][revision]["final_state"] == "fact-verified"
                )
                observed_fv = any(
                    candidate["state"] == "fact-verified"
                    for candidate in record["candidates"]
                )
                key = (
                    "tp" if expected_fv and observed_fv
                    else "fn" if expected_fv
                    else "fp" if observed_fv
                    else "tn"
                )
                confusion[key] += 1
        self.assertEqual(confusion, report["fact_verified_confusion"])
        precision = confusion["tp"] / (confusion["tp"] + confusion["fp"])
        recall = confusion["tp"] / (confusion["tp"] + confusion["fn"])
        self.assertAlmostEqual(precision, report["fact_verified_precision"])
        self.assertAlmostEqual(recall, report["fact_verified_recall"])

        # abstention correctness (exact non-positive-state match)
        total = correct = 0
        for case in cases:
            for revision in module.REVISIONS:
                expected_state = case["expected"][revision]["final_state"]
                if expected_state in UAF_POSITIVE_STATES:
                    continue
                total += 1
                correct += int(self._observed_state(
                    self.records[(case["id"], revision)]
                ) == expected_state)
        self.assertEqual(total, report["abstention_correctness"]["total"])
        self.assertEqual(correct, report["abstention_correctness"]["correct"])
        self.assertAlmostEqual(correct / total, report["abstention_correctness"]["rate"])

        # paired accuracy (double correctness per pair)
        eligible_pairs = 0
        correct_pairs = 0
        for case in cases:
            both = all(
                self.records[(case["id"], revision)]["counted"]
                for revision in module.REVISIONS
            )
            if not both:
                continue
            eligible_pairs += 1
            pair_ok = all(
                self._observed_state(self.records[(case["id"], revision)])
                == case["expected"][revision]["final_state"]
                for revision in module.REVISIONS
            )
            correct_pairs += int(pair_ok)
        self.assertEqual(eligible_pairs, report["pair_eligible_count"])
        self.assertAlmostEqual(
            correct_pairs / eligible_pairs, report["paired_accuracy"]
        )

        # coverage gap rate
        counted = [
            record
            for case in cases
            for revision in module.REVISIONS
            if (record := self.records[(case["id"], revision)])["counted"]
        ]
        with_gaps = [record for record in counted if record["coverage_gaps"]]
        self.assertEqual(len(counted), report["coverage_gap_rate"]["revisions_counted"])
        self.assertEqual(
            len(with_gaps), report["coverage_gap_rate"]["revisions_with_gaps"]
        )

        # llm usage and latency
        calls = sum(record["llm"]["calls"] for record in self.records.values())
        invoked = sum(
            record["llm"]["invoked_candidates"] for record in self.records.values()
        )
        reply_bytes = sum(
            record["llm"]["reply_bytes"] for record in self.records.values()
        )
        latency = sum(record["elapsed_seconds"] for record in self.records.values())
        self.assertEqual(calls, report["llm_usage"]["calls_total"])
        self.assertEqual(invoked, report["llm_usage"]["invoked_candidates_total"])
        self.assertEqual(reply_bytes, report["llm_usage"]["reply_bytes_total"])
        self.assertAlmostEqual(latency, report["latency_seconds"]["total"], places=5)

    def test_distribution_recomputes_from_candidate_records(self):
        report = self.report
        tallies = {
            obligation: {"satisfied": 0, "unknown": 0, "refuted": 0, "total": 0}
            for obligation in OBLIGATIONS
        }
        for record in self.records.values():
            for candidate in record["candidates"]:
                for obligation, verdict in candidate["obligations"].items():
                    tallies[obligation][verdict] += 1
                    tallies[obligation]["total"] += 1
        overall = report["proof_obligation_distribution"]["overall"]
        for obligation in OBLIGATIONS:
            for key in ("satisfied", "unknown", "refuted", "total"):
                self.assertEqual(
                    tallies[obligation][key],
                    overall[obligation][key],
                    f"{obligation}.{key} drifts from the records",
                )
            if tallies[obligation]["total"]:
                self.assertAlmostEqual(
                    tallies[obligation]["unknown"] / tallies[obligation]["total"],
                    overall[obligation]["unknown_ratio"],
                )

    def test_distribution_slices_are_independent_structures(self):
        distribution = self.report["proof_obligation_distribution"]
        slices = distribution["slices"]
        for name in (
            "by_case_kind",
            "by_build_context_source",
            "by_language_standard",
            "by_project",
        ):
            self.assertIn(name, slices)
            self.assertTrue(slices[name], f"slice {name} must not be empty")
        kinds = set(distribution["slices"]["by_case_kind"])
        self.assertEqual(kinds, {case["kind"] for case in self.cases})
        # No collapsed total score anywhere in the distribution.
        encoded = json.dumps(distribution)
        self.assertNotIn("failure_score", encoded)
        self.assertNotIn("total_score", encoded)
        for obligation in OBLIGATIONS:
            self.assertIn(obligation, distribution["overall"])


# ---------------------------------------------------------------- isolation


class UnlabeledIsolationTests(unittest.TestCase):
    """Evaluation assets never enter the review_uaf input path."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_pipeline_inputs_carry_no_case_metadata(self):
        module = self.module
        document = module.load_case_document(CASES_PATH)
        case = next(
            item
            for item in document["cases"]
            if item["kind"] == SEMANTIC_CASE_KIND
        )
        marker_pin = case["vulnerable"]["files"][
            sorted(case["vulnerable"]["files"])[0]
        ]
        markers = [
            case["id"],
            case["title"],
            case["license"]["note"],
            marker_pin,
            "selection_rationale",
            "final_state",
            "ground_truth",
        ]

        wire_snapshots = []
        llm_payloads = []
        repository_keys = []

        class RecordingSidecar(module.FakeUafSidecar):
            def analyze_uaf_facts(
                self, repository_key, snapshot_sha256, translation_units,
                build_context_mode,
            ):
                repository_keys.append(repository_key)
                response = super().analyze_uaf_facts(
                    repository_key, snapshot_sha256, translation_units,
                    build_context_mode,
                )
                wire_snapshots.append(json.dumps(
                    list(response.translation_units), sort_keys=True,
                ))
                return response

        counter = {"calls": 0, "bytes": 0}
        base_transport = module.scripted_semantic_transport(case["id"], counter)

        def capturing_transport(*args, **kwargs):
            llm_payloads.append(args[3])
            return base_transport(*args, **kwargs)

        with module.pinned_workspace(case, "vulnerable") as (root, units):
            workspace = RepositoryWorkspace(root)
            snapshot = workspace.inventory().fingerprint()
            analyzer = RecordingSidecar(
                module.build_fake_wire(case["id"], units[0], "vulnerable")
            )
            with mock.patch.object(
                module.uaf_llm_branch,
                "post_chat_completion_text",
                capturing_transport,
            ):
                outcome = module.review_uaf(
                    analyzer,
                    workspace,
                    repository_key=module.evaluation_repository_key("vulnerable"),
                    snapshot_hash=snapshot,
                    translation_units=units,
                    mode="auto",
                    llm_config=dict(module.FAKE_LLM_CONFIG),
                    timeout=60,
                )

        fixture_root = PAIRS_ROOT / case["id"] / "vulnerable"
        texts = [
            path.read_text(encoding="utf-8")
            for path in sorted(fixture_root.rglob("*"))
            if path.is_file()
        ]
        surfaces = {
            "workspace": "".join(texts),
            "fact_wire": "".join(wire_snapshots),
            "llm_context": "".join(
                json.dumps(payload, sort_keys=True) for payload in llm_payloads
            ),
            "candidates": json.dumps(
                [item.state for item in outcome.candidates]
            ),
        }
        for surface_name, surface in surfaces.items():
            for marker in markers:
                self.assertNotIn(
                    marker,
                    surface,
                    f"case label {marker!r} leaked into the {surface_name}",
                )
        self.assertTrue(wire_snapshots)
        for key in repository_keys:
            self.assertNotIn(case["id"], key)


# ---------------------------------------------------------- fake-llm e2e


class FakeLlmEndToEndTests(unittest.TestCase):
    """The full deterministic pipeline behaves per design over the pairs."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_direct_pair_reaches_fact_verified_with_zero_llm_calls(self):
        module = self.module
        document = module.load_case_document(CASES_PATH)
        case = next(
            item
            for item in document["cases"]
            if item["id"] == "direct-new-delete-uaf"
        )
        for mode in ("off", "auto", "required"):
            with self.subTest(mode=mode):
                record = module.run_revision(
                    case, "vulnerable", mode=mode, fake_llm=True, timeout=60
                )
                self.assertEqual(1, record["candidate_count"])
                candidate = record["candidates"][0]
                self.assertEqual("fact-verified", candidate["state"])
                self.assertEqual("PASS", candidate["proof_verdict"])
                self.assertEqual(
                    {obligation: "satisfied" for obligation in OBLIGATIONS},
                    candidate["obligations"],
                )
                self.assertEqual(0, record["llm"]["calls"])
                self.assertEqual(0, record["llm"]["reply_bytes"])

    def test_fixed_revisions_produce_no_candidates(self):
        module = self.module
        document = module.load_case_document(CASES_PATH)
        for case in document["cases"]:
            record = module.run_revision(
                case, "fixed", mode="auto", fake_llm=True, timeout=60
            )
            with self.subTest(case=case["id"]):
                self.assertEqual(0, record["candidate_count"])
                self.assertEqual([], record["candidates"])
                self.assertEqual(0, record["llm"]["calls"])

    def test_rebind_counterexample_is_rejected_with_p6_audit(self):
        module = self.module
        case = next(
            item
            for item in self.module.load_case_document(CASES_PATH)["cases"]
            if item["kind"] == "rebind-counterexample"
        )
        record = module.run_revision(
            case, "vulnerable", mode="auto", fake_llm=True, timeout=60
        )
        candidate = record["candidates"][0]
        self.assertEqual("rejected", candidate["state"])
        self.assertNotIn(candidate["state"], UAF_FINDING_STATES)
        self.assertEqual("REFUTED", candidate["proof_verdict"])
        self.assertEqual("refuted", candidate["obligations"]["P6"])
        self.assertIn("P6", candidate["rejected_reason"])
        self.assertEqual(0, record["llm"]["calls"])

    def test_unreachable_use_is_refuted_by_structural_p5(self):
        module = self.module
        case = next(
            item
            for item in self.module.load_case_document(CASES_PATH)["cases"]
            if item["kind"] == "unreachable-use"
        )
        record = module.run_revision(
            case, "vulnerable", mode="auto", fake_llm=True, timeout=60
        )
        candidate = record["candidates"][0]
        self.assertEqual("rejected", candidate["state"])
        self.assertEqual("REFUTED", candidate["proof_verdict"])
        self.assertEqual("refuted", candidate["obligations"]["P5"])
        self.assertIsNotNone(candidate["p5"])
        self.assertEqual("refuted", candidate["p5"]["structural_reachability"])
        self.assertEqual(0, record["llm"]["calls"])

    def test_predicated_unknown_abstains_off_with_zero_and_auto_with_calls(self):
        module = self.module
        case = next(
            item
            for item in self.module.load_case_document(CASES_PATH)["cases"]
            if item["kind"] == "predicated-unknown"
        )
        off_record = module.run_revision(
            case, "vulnerable", mode="off", fake_llm=True, timeout=60
        )
        candidate = off_record["candidates"][0]
        self.assertEqual("UNKNOWN", candidate["proof_verdict"])
        self.assertEqual("unknown", candidate["obligations"]["P5"])
        self.assertEqual("abstain", candidate["state"])
        self.assertEqual(0, off_record["llm"]["calls"])

        auto_record = module.run_revision(
            case, "vulnerable", mode="auto", fake_llm=True, timeout=60
        )
        auto_candidate = auto_record["candidates"][0]
        self.assertEqual("UNKNOWN", auto_candidate["proof_verdict"])
        # The honest scripted specialist/critic both abstain: the two
        # independent predicates are not resolvable from the facts.
        self.assertEqual("abstain", auto_candidate["state"])
        self.assertGreaterEqual(auto_record["llm"]["calls"], 2)
        self.assertEqual(1, auto_record["llm"]["invoked_candidates"])

    def test_semantic_unknown_reaches_semantic_supported_with_fake_supports(self):
        module = self.module
        case = next(
            item
            for item in self.module.load_case_document(CASES_PATH)["cases"]
            if item["kind"] == SEMANTIC_CASE_KIND
        )
        record = module.run_revision(
            case, "vulnerable", mode="auto", fake_llm=True, timeout=60
        )
        candidate = record["candidates"][0]
        self.assertEqual("UNKNOWN", candidate["proof_verdict"])
        self.assertEqual("unknown", candidate["obligations"]["P2"])
        self.assertEqual("semantic-supported", candidate["state"])
        self.assertGreaterEqual(record["llm"]["calls"], 2)
        self.assertGreater(record["llm"]["reply_bytes"], 0)

        off_record = module.run_revision(
            case, "vulnerable", mode="off", fake_llm=True, timeout=60
        )
        self.assertEqual("abstain", off_record["candidates"][0]["state"])
        self.assertEqual(0, off_record["llm"]["calls"])

    def test_guarded_same_block_pair_measured_fact_verified(self):
        module = self.module
        case = next(
            item
            for item in self.module.load_case_document(CASES_PATH)["cases"]
            if item["kind"] == "guarded-same-block-uaf"
        )
        # Task 7 whitelist (a): release and use share one cfg block with no
        # conditional edge between them -> measured PASS.  This test locks
        # the measured expected value written into the manifest.
        record = module.run_revision(
            case, "vulnerable", mode="auto", fake_llm=True, timeout=60
        )
        candidate = record["candidates"][0]
        self.assertEqual(
            case["expected"]["vulnerable"]["final_state"], candidate["state"]
        )
        self.assertEqual("PASS", candidate["proof_verdict"])
        self.assertEqual("satisfied", candidate["p5"]["path_feasibility"])

    def test_full_fake_run_reports_every_metric(self):
        report = run_fake_evaluation(self.module)
        self.assertEqual(7, report["case_count"])
        self.assertEqual(14, len(report["records"]))
        self.assertEqual(7, report["pair_eligible_count"])
        self.assertEqual(1.0, report["candidate_recall"])
        self.assertEqual(1.0, report["fact_verified_precision"])
        self.assertEqual(1.0, report["fact_verified_recall"])
        self.assertEqual(1.0, report["paired_accuracy"])
        self.assertEqual(1.0, report["abstention_correctness"]["rate"])
        self.assertIn("proof_obligation_distribution", report)


# ---------------------------------------------------------- paired accuracy


class PairedAccuracyTests(unittest.TestCase):
    """Paired accuracy is the double-correct rate over eligible pairs."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def _candidate(self, state, verdict="PASS", number=1):
        return {
            "candidate_id": format(number, "064x"),
            "state": state,
            "proof_verdict": verdict,
            "obligations": {},
            "p5": None,
            "rejected_reason": "",
            "llm_invoked": False,
            "llm_calls": 0,
        }

    def _record(self, case_id, revision, candidates=()):
        return {
            "case_id": case_id,
            "revision": revision,
            "counted": True,
            "build_context_source": "repository-compdb",
            "translation_units": ["src/a.c"],
            "coverage_gaps": [],
            "candidates": list(candidates),
            "candidate_count": len(candidates),
            "llm": {"calls": 0, "invoked_candidates": 0, "reply_bytes": 0},
            "elapsed_seconds": 0.0,
            "diagnostics": [],
        }

    def _case(self, case_id):
        return {
            "id": case_id,
            "kind": "direct-uaf",
            "origin": "synthetic",
            "language_standard": "c11",
            "expected": {
                "vulnerable": {
                    "verdict": "PASS",
                    "final_state": "fact-verified",
                    "candidates": 1,
                },
                "fixed": {"verdict": "none", "final_state": "none", "candidates": 0},
            },
        }

    def test_pair_counts_only_when_both_sides_are_exact(self):
        module = self.module
        good = self._case("pair-good")
        wrong = self._case("pair-wrong")
        records = {
            ("pair-good", "vulnerable"): self._record(
                "pair-good", "vulnerable", [self._candidate("fact-verified")]
            ),
            ("pair-good", "fixed"): self._record("pair-good", "fixed"),
            ("pair-wrong", "vulnerable"): self._record(
                "pair-wrong", "vulnerable", [self._candidate("abstain", "UNKNOWN")]
            ),
            ("pair-wrong", "fixed"): self._record("pair-wrong", "fixed"),
        }
        report = module.run_evaluation([good, wrong], records)
        self.assertEqual(2, report["pair_eligible_count"])
        self.assertAlmostEqual(0.5, report["paired_accuracy"])
        by_id = {case["case_id"]: case for case in report["cases"]}
        self.assertTrue(by_id["pair-good"]["pair_correct"])
        self.assertFalse(by_id["pair-wrong"]["pair_correct"])
        self.assertEqual(
            "fact-verified",
            by_id["pair-good"]["revisions"]["vulnerable"]["observed_final_state"],
        )


# ------------------------------------------------------------- CLI/provider


class ProviderAndCliTests(unittest.TestCase):
    """CLI surface and provider resolution mirror the Task 20 pattern."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_cli_exposes_exactly_the_fixed_parameters(self):
        parser = self.module.build_parser()
        self.assertEqual(
            {
                "cases",
                "case_id",
                "output",
                "mode",
                "fake_llm",
                "timeout",
                "provider_url",
                "provider_key",
                "model",
            },
            {action.dest for action in parser._actions if action.dest != "help"},
        )

    def test_fake_llm_mode_needs_no_provider_environment(self):
        args = self.module.build_parser().parse_args(
            ["--cases", str(CASES_PATH), "--output", "out.json", "--fake-llm"]
        )
        llm_config, provider, model = self.module.build_llm_config(args, env={})
        self.assertTrue(llm_config["base_url"])
        self.assertEqual("fake", provider)

    def test_real_mode_refuses_without_provider_before_any_run(self):
        module = self.module
        args = module.build_parser().parse_args(
            ["--cases", str(CASES_PATH), "--output", "out.json"]
        )
        with self.assertRaises(module.ProviderNotConfigured):
            module.build_llm_config(args, env={})

    def test_real_mode_resolves_arguments_then_environment(self):
        module = self.module
        args = module.build_parser().parse_args(
            [
                "--cases", str(CASES_PATH), "--output", "out.json",
                "--provider-url", "https://llm.example.invalid/v1",
                "--provider-key", "k",
                "--model", "uaf-model",
            ]
        )
        llm_config, provider, model = module.build_llm_config(args, env={})
        self.assertEqual("https://llm.example.invalid/v1", llm_config["base_url"])
        self.assertEqual("k", llm_config["api_key"])
        self.assertEqual("uaf-model", model)
        self.assertEqual("custom", provider)

        env = {
            "LIMA_LLM_BASE_URL": "https://env.example.invalid/v1",
            "LIMA_LLM_PROVIDER": "deepseek",
            "LIMA_LLM_MODEL": "env-model",
        }
        env_args = module.build_parser().parse_args(
            ["--cases", str(CASES_PATH), "--output", "out.json"]
        )
        llm_config, provider, model = module.build_llm_config(env_args, env=env)
        self.assertEqual("https://env.example.invalid/v1", llm_config["base_url"])
        self.assertEqual("deepseek", provider)
        self.assertEqual("env-model", model)

    def test_main_fake_run_writes_a_complete_report(self):
        module = self.module
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "uaf-v2-evaluation.json"
            exit_code = module.main(
                [
                    "--cases", str(CASES_PATH),
                    "--case-id", "direct-new-delete-uaf",
                    "--output", str(output),
                    "--fake-llm",
                    "--mode", "auto",
                ]
            )
            self.assertEqual(0, exit_code)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(1, report["case_count"])
        self.assertEqual("fake", report["llm_transport"])
        self.assertIn("proof_obligation_distribution", report)
        self.assertIn("identity", report)
        self.assertIn("case_data_sha256", report["identity"])


if __name__ == "__main__":
    unittest.main()
