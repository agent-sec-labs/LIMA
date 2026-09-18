"""Unlabeled paired-benchmark contract for the agent vulnerability platform.

Plan Task 10 (design section 11,
``docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md``).  All
tests run fully offline: the Sidecar is a fake ``analyze_uaf_facts`` serving
canned wire bundles per committed case, the triage layer is a canned lead
table, the reproduction workbench is a scripted ``run_experiment`` double
that judges a driver by its content hash, and the Scout/Specialist/Critic
transport is a scripted fake.  Red lines pinned here:

- the committed manifest carries a vulnerable/fixed pair per code shape,
  including a revisable case that only confirms after the Critic-guided
  experiment revision (design section 11);
- competition metric mapping (detection rate, false-positive rate,
  non-security filter rate, experiment convergence, PoC stability) is
  collected and recomputable from the embedded records;
- zero denominators are ``null`` plus a diagnostic, never a fake zero;
- no case label (id, title, rationale, license, expected verdicts) reaches
  the workspace, the fact wire, the leads, the analyzer request or any
  model context;
- the false-positive discipline is mechanized: clean pairs and non-security
  pairs must finish with zero Findings (competition notes 3/6).
"""

import copy
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.uaf_orchestrator import UAF_FINDING_STATES
from lima.workspace import RepositoryWorkspace

ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_platform_evaluation.py"
CASES_PATH = ROOT / "evaluation_data" / "platform_cases" / "cases.json"
PAIRS_ROOT = ROOT / "tests" / "fixtures" / "platform_cases"

REQUIRED_KINDS = frozenset({"direct", "revisable", "clean"})
EXPECTED_STATES = frozenset(
    {
        "runtime-confirmed",
        "semantic-supported",
        "fact-verified",
        "tool-corroborated",
        "needs-human-review",
        "abstain",
        "rejected",
        "none",
    }
)


def load_evaluation_module():
    spec = importlib.util.spec_from_file_location("platform_evaluation", SCRIPT_PATH)
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


def observed_state(record):
    """The record-level observed state (Task 12 convention)."""

    states = [target["state"] for target in record["targets"]]
    if not states:
        return "none"
    return states[0] if len(set(states)) == 1 else "mixed"


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
                    pinned = (
                        PAIRS_ROOT / case["id"] / revision / relative
                    )
                    self.assertTrue(
                        pinned.is_file(), f"missing pinned fixture {pinned}"
                    )
                    self.assertEqual(
                        digest,
                        self.module.file_digest(pinned),
                        f"pin drift for {pinned}",
                    )

    def test_manifest_covers_the_required_case_kinds(self):
        kinds = {case["kind"] for case in self.document["cases"]}
        self.assertTrue(
            REQUIRED_KINDS <= kinds,
            f"manifest is missing required kinds: {REQUIRED_KINDS - kinds}",
        )
        self.assertTrue(
            any(case["non_security"] for case in self.document["cases"]),
            "the manifest must contain a non-security filter case",
        )

    def test_positive_expectations_require_executed_experiments(self):
        positive = self.module.PLATFORM_POSITIVE_STATES
        for case in self.document["cases"]:
            for revision in ("vulnerable", "fixed"):
                expected = case["expected"][revision]
                if expected["final_state"] in positive:
                    self.assertTrue(
                        case["requires_experiment"],
                        f"{case['id']} expects a positive state without "
                        "requiring an experiment",
                    )
                    self.assertIn(case["kind"], {"direct", "revisable"})
        runtime = [
            case
            for case in self.document["cases"]
            if case["expected"]["vulnerable"]["final_state"]
            == "runtime-confirmed"
        ]
        self.assertGreaterEqual(
            len(runtime), 1, "detection-rate denominator must not be empty"
        )

    def test_expected_state_domain_is_frozen(self):
        states = set()
        for case in self.document["cases"]:
            for revision in ("vulnerable", "fixed"):
                states.add(case["expected"][revision]["final_state"])
        self.assertTrue(states <= EXPECTED_STATES)

    def test_schema_rejects_malformed_cases(self):
        module = self.module
        base = self.document

        def mutated(mutator):
            document = copy.deepcopy(base)
            mutator(document)
            return document

        def set_kind(document):
            document["cases"][0]["kind"] = "memory-shape"

        def set_final_state(document):
            first = document["cases"][0]["expected"]["vulnerable"]
            first["final_state"] = "auto-verified"

        def set_findings(document):
            document["cases"][0]["expected"]["vulnerable"]["findings"] = -1

        def set_cwe(document):
            document["cases"][0]["cwe"] = "CWE-9999"

        def set_vuln_pack(document):
            document["cases"][0]["vuln_pack"] = "network"

        def set_driver_hint(document):
            document["cases"][0]["vulnerable"]["driver_hint"] = "fork-bomb"

        def drop_key(document):
            del document["cases"][0]["notes"]

        def add_key(document):
            document["cases"][0]["ground_truth"] = "line 11"

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
            first["vulnerable"]["files"]["../" + key] = first["vulnerable"][
                "files"
            ].pop(key)

        def wrong_version(document):
            document["schema_version"] = 2

        def empty_cases(document):
            document["cases"] = []

        def drop_clean_cases(document):
            document["cases"] = [
                case for case in document["cases"] if case["kind"] != "clean"
            ]

        def drop_revisable_cases(document):
            document["cases"] = [
                case
                for case in document["cases"]
                if case["kind"] != "revisable"
            ]

        def positive_without_experiment(document):
            document["cases"][0]["requires_experiment"] = False

        def clean_case_with_positive_expectation(document):
            clean = next(
                case
                for case in document["cases"]
                if case["kind"] == "clean"
            )
            clean["expected"]["vulnerable"]["final_state"] = (
                "runtime-confirmed"
            )
            clean["requires_experiment"] = True

        def non_security_with_wrong_kind(document):
            nonsec = next(
                case
                for case in document["cases"]
                if case["non_security"]
            )
            nonsec["kind"] = "direct"

        for mutator in (
            set_kind,
            set_final_state,
            set_findings,
            set_cwe,
            set_vuln_pack,
            set_driver_hint,
            drop_key,
            add_key,
            drift_pin,
            duplicate_id,
            escape_path,
            wrong_version,
            empty_cases,
            drop_clean_cases,
            drop_revisable_cases,
            positive_without_experiment,
            clean_case_with_positive_expectation,
            non_security_with_wrong_kind,
        ):
            with self.subTest(mutator=mutator.__name__):
                document = mutated(mutator)
                if mutator is drift_pin:
                    with self.assertRaises(ValueError):
                        module.verify_version_pins(
                            document["cases"][0], "vulnerable"
                        )
                else:
                    with self.assertRaises(ValueError):
                        module.validate_case_document(document)


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

    def _target(self, state, finding):
        return {
            "target_id": "lead-001",
            "path": "src/a.cpp",
            "line": 8,
            "cwe": "CWE-416",
            "state": state,
            "finding": finding,
            "proof_verdict": "",
            "rejected_reason": "",
            "experiment_log": [],
            "driver_sha256": "",
        }

    def _case(self, case_id, vuln_state, fixed_state="none", kind="direct"):
        return {
            "id": case_id,
            "title": "synthetic scoring case",
            "vuln_pack": "memory",
            "cwe": "CWE-416",
            "kind": kind,
            "requires_experiment": True,
            "non_security": False,
            "expected": {
                "vulnerable": {"final_state": vuln_state, "findings": 1},
                "fixed": {"final_state": fixed_state, "findings": 0},
            },
        }

    def test_zero_denominator_rates_are_null_with_diagnostics(self):
        module = self.module
        # All-abstain manifest: no expected-positive vulnerable revision, no
        # revisable case, no executed hit and no non-security case, so four
        # rate denominators are zero while the false-positive rate stays an
        # honest 0.0 over its non-empty denominator.
        case = self._case("abstain-case", "abstain", fixed_state="abstain")
        records = {
            ("abstain-case", "vulnerable"): self._record(
                "abstain-case",
                "vulnerable",
                targets=[self._target("abstain", False)],
            ),
            ("abstain-case", "fixed"): self._record(
                "abstain-case", "fixed", targets=[self._target("abstain", False)]
            ),
        }
        report = module.run_evaluation([case], records)
        self.assertIsNone(report["detection_rate"]["rate"])
        self.assertIsNone(report["experiment_convergence"]["rate"])
        self.assertIsNone(report["poc_stability"]["rate"])
        self.assertIsNone(report["non_security_filter_rate"]["rate"])
        self.assertIsNotNone(report["false_positive_rate"]["rate"])
        self.assertEqual(0.0, report["false_positive_rate"]["rate"])
        diagnostics = json.dumps(report["diagnostics"])
        self.assertIn("denominator", diagnostics)

    def test_missed_expected_positive_keeps_detection_honest(self):
        module = self.module
        case = self._case("missed-case", "runtime-confirmed")
        records = {
            ("missed-case", "vulnerable"): self._record(
                "missed-case",
                "vulnerable",
                targets=[self._target("abstain", False)],
            ),
            ("missed-case", "fixed"): self._record("missed-case", "fixed"),
        }
        report = module.run_evaluation([case], records)
        self.assertEqual(0.0, report["detection_rate"]["rate"])
        self.assertAlmostEqual(0.0, report["paired_detection"]["rate"])
        self.assertEqual(0, report["detection_rate"]["detected"])

    def test_false_positive_counts_any_finding_on_negative_sides(self):
        module = self.module
        case = self._case("fp-case", "runtime-confirmed", fixed_state="none")
        records = {
            ("fp-case", "vulnerable"): self._record(
                "fp-case",
                "vulnerable",
                targets=[self._target("runtime-confirmed", True)],
                finding_count=1,
                poc_stability={"runs": 3, "hits": 3, "stable": True},
            ),
            ("fp-case", "fixed"): self._record(
                "fp-case",
                "fixed",
                targets=[self._target("semantic-supported", True)],
                finding_count=1,
            ),
        }
        report = module.run_evaluation([case], records)
        self.assertEqual(1.0, report["false_positive_rate"]["rate"])
        self.assertEqual(1, report["false_positive_rate"]["false_positives"])

    def test_degraded_revision_makes_the_pair_ineligible(self):
        module = self.module
        case = self._case("degraded-case", "runtime-confirmed")
        records = {
            ("degraded-case", "vulnerable"): self._record(
                "degraded-case", "vulnerable", counted=False
            ),
            ("degraded-case", "fixed"): self._record("degraded-case", "fixed"),
        }
        report = module.run_evaluation([case], records)
        self.assertIsNone(report["paired_detection"]["rate"])
        self.assertTrue(
            any("degraded" in item for item in report["diagnostics"]),
            report["diagnostics"],
        )

    def test_records_validate_against_the_record_schema(self):
        module = self.module
        good = self._record("case-a", "vulnerable")
        self.assertEqual(module.validate_record(good), good)

        def mutated(mutator):
            record = copy.deepcopy(good)
            mutator(record)
            return record

        def extra_key(record):
            record["ground_truth"] = "leak"

        def bad_state(record):
            record["targets"].append(self._target("auto-verified", False))

        def bad_bool(record):
            record["targets"].append(self._target("abstain", "yes"))

        def bad_llm(record):
            record["llm"]["reply_bytes"] = -1

        def bad_elapsed(record):
            record["elapsed_seconds"] = -0.5

        def bad_stability(record):
            record["poc_stability"] = {"runs": 1, "hits": 3, "stable": True}

        def hit_without_stability(record):
            record["targets"].append(
                {
                    **self._target("runtime-confirmed", True),
                    "experiment_log": [{"round": 1, "hit": True,
                                        "error_type": "heap-use-after-free",
                                        "stage": "run"}],
                }
            )

        def bad_revision(record):
            record["revision"] = "original"

        for mutator in (
            extra_key,
            bad_state,
            bad_bool,
            bad_llm,
            bad_elapsed,
            bad_stability,
            hit_without_stability,
            bad_revision,
        ):
            with self.subTest(mutator=mutator.__name__):
                with self.assertRaises(ValueError):
                    module.validate_record(mutated(mutator))


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

    def test_records_recompute_every_competition_metric(self):
        module = self.module
        report = self.report
        positive = module.PLATFORM_POSITIVE_STATES
        cases = self.cases

        # Detection rate: exact expected-state match on positive vuln sides.
        eligible = detected = 0
        for case in cases:
            expected = case["expected"]["vulnerable"]
            if expected["final_state"] not in positive:
                continue
            eligible += 1
            record = self.records[(case["id"], "vulnerable")]
            detected += int(observed_state(record) == expected["final_state"])
        self.assertEqual(eligible, report["detection_rate"]["total"])
        self.assertEqual(detected, report["detection_rate"]["detected"])
        self.assertAlmostEqual(detected / eligible, report["detection_rate"]["rate"])

        # False-positive rate: any finding on a non-positive revision.
        negative = false_positives = 0
        for case in cases:
            for revision in module.REVISIONS:
                expected = case["expected"][revision]
                if expected["final_state"] in positive:
                    continue
                negative += 1
                record = self.records[(case["id"], revision)]
                false_positives += int(record["finding_count"] > 0)
        self.assertEqual(negative, report["false_positive_rate"]["total"])
        self.assertEqual(
            false_positives, report["false_positive_rate"]["false_positives"]
        )
        self.assertAlmostEqual(
            false_positives / negative, report["false_positive_rate"]["rate"]
        )

        # Non-security filter rate: zero findings on both revisions.
        nonsec = filtered = 0
        for case in cases:
            if not case["non_security"]:
                continue
            nonsec += 1
            clean = all(
                self.records[(case["id"], revision)]["finding_count"] == 0
                for revision in module.REVISIONS
            )
            filtered += int(clean)
        self.assertEqual(nonsec, report["non_security_filter_rate"]["total"])
        self.assertEqual(filtered, report["non_security_filter_rate"]["filtered"])
        if nonsec:
            self.assertAlmostEqual(
                filtered / nonsec, report["non_security_filter_rate"]["rate"]
            )

        # Experiment convergence: revisable cases hitting within the budget.
        budget = report["experiment_convergence"]["round_budget"]
        revisable = converged = 0
        for case in cases:
            if case["kind"] != "revisable":
                continue
            revisable += 1
            record = self.records[(case["id"], "vulnerable")]
            rounds = [
                entry["round"]
                for target in record["targets"]
                for entry in target["experiment_log"]
                if entry["hit"]
            ]
            converged += int(bool(rounds) and min(rounds) <= budget)
        self.assertEqual(revisable, report["experiment_convergence"]["total"])
        self.assertEqual(
            converged, report["experiment_convergence"]["converged"]
        )
        if revisable:
            self.assertAlmostEqual(
                converged / revisable, report["experiment_convergence"]["rate"]
            )

        # PoC stability: executed-hit revisions whose repeat runs all hit.
        hit_revisions = stable_pocs = 0
        for case in cases:
            for revision in module.REVISIONS:
                record = self.records[(case["id"], revision)]
                hit = any(
                    entry["hit"]
                    for target in record["targets"]
                    for entry in target["experiment_log"]
                )
                if not hit:
                    continue
                hit_revisions += 1
                stability = record["poc_stability"]
                self.assertIsNotNone(stability)
                stable_pocs += int(stability["stable"])
        self.assertEqual(
            hit_revisions, report["poc_stability"]["total"]
        )
        self.assertEqual(stable_pocs, report["poc_stability"]["stable"])
        if hit_revisions:
            self.assertAlmostEqual(
                stable_pocs / hit_revisions, report["poc_stability"]["rate"]
            )

        # Paired detection: both revisions exact.
        pairs = correct = 0
        for case in cases:
            counted = all(
                self.records[(case["id"], revision)]["counted"]
                for revision in module.REVISIONS
            )
            if not counted:
                continue
            pairs += 1
            exact = all(
                observed_state(self.records[(case["id"], revision)])
                == case["expected"][revision]["final_state"]
                for revision in module.REVISIONS
            )
            correct += int(exact)
        self.assertEqual(pairs, report["paired_detection"]["total"])
        self.assertAlmostEqual(
            correct / pairs, report["paired_detection"]["rate"]
        )

        # LLM usage and latency.
        records = list(self.records.values())
        self.assertEqual(
            sum(record["llm"]["scout_calls"] for record in records),
            report["llm_usage"]["scout_calls_total"],
        )
        self.assertEqual(
            sum(record["llm"]["specialist_calls"] for record in records),
            report["llm_usage"]["specialist_calls_total"],
        )
        self.assertEqual(
            sum(record["llm"]["critic_calls"] for record in records),
            report["llm_usage"]["critic_calls_total"],
        )
        self.assertEqual(
            sum(record["llm"]["reply_bytes"] for record in records),
            report["llm_usage"]["reply_bytes_total"],
        )
        self.assertAlmostEqual(
            sum(record["elapsed_seconds"] for record in records),
            report["latency_seconds"]["total"],
            places=5,
        )

    def test_every_case_gets_two_records_and_validates(self):
        module = self.module
        self.assertEqual(len(self.cases), self.report["case_count"])
        self.assertEqual(2 * len(self.cases), len(self.report["records"]))
        for record in self.report["records"]:
            module.validate_record(record)
        ids = {record["case_id"] for record in self.report["records"]}
        self.assertEqual(ids, {case["id"] for case in self.cases})

    def test_report_never_contains_case_labels_outside_labels(self):
        # Aggregates and boundaries must not smuggle titles or rationales
        # into the report beyond the labeled per-case sections.
        report = json.dumps(
            {
                key: value
                for key, value in self.report.items()
                if key not in {"cases", "records"}
            }
        )
        for case in self.cases:
            self.assertNotIn(case["title"], report)
            self.assertNotIn(case["selection_rationale"], report)


# ---------------------------------------------------------------- isolation


class UnlabeledIsolationTests(unittest.TestCase):
    """Evaluation assets never enter the run_platform_review input path."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def _run_case_revision(self, module, case, revision):
        """Run one revision manually, capturing every pipeline surface."""

        case_id = case["id"]
        wire_snapshots = []
        scout_payloads = []
        llm_payloads = []
        repository_keys = []

        class RecordingSidecar(module.FakePlatformSidecar):
            def analyze_uaf_facts(
                self, repository_key, snapshot_sha256, translation_units,
                build_context_mode,
            ):
                repository_keys.append(repository_key)
                response = super().analyze_uaf_facts(
                    repository_key, snapshot_sha256, translation_units,
                    build_context_mode,
                )
                wire_snapshots.append(
                    json.dumps(
                        list(response.translation_units), sort_keys=True,
                    )
                )
                return response

        def wrapped(transport, sink):
            def inner(provider, base_url, api_key, payload, timeout,
                      extra_headers=None, max_bytes=None):
                sink.append(payload)
                return transport(
                    provider, base_url, api_key, payload, timeout,
                    extra_headers=extra_headers, max_bytes=max_bytes,
                )

            return inner

        counter = module.new_counter()
        scout_transport = wrapped(
            module.scripted_scout_transport(counter), scout_payloads,
        )
        platform_transport = wrapped(
            module.scripted_platform_transport(case_id, counter), llm_payloads,
        )

        with module.pinned_workspace(case, revision) as (root, units):
            workspace = RepositoryWorkspace(root)
            snapshot = workspace.inventory().fingerprint()
            analyzer = RecordingSidecar(
                module.build_fake_wire(case_id, units[0], revision)
            )
            with mock.patch.object(
                module.agent_scout,
                "post_chat_completion_text",
                scout_transport,
            ), mock.patch.object(
                module.uaf_llm_branch,
                "post_chat_completion_text",
                platform_transport,
            ):
                outcome = module.run_platform_review(
                    analyzer,
                    workspace,
                    repository_key=module.evaluation_repository_key(revision),
                    snapshot_hash=snapshot,
                    translation_units=units,
                    mode="auto",
                    llm_config=dict(module.FAKE_LLM_CONFIG),
                    repro_workbench=module.FakePlatformWorkbench(
                        case_id, revision
                    ),
                    leads=module.build_leads(case_id, units[0], revision),
                    timeout=60,
                )

        fixture_root = PAIRS_ROOT / case_id / revision
        texts = [
            path.read_text(encoding="utf-8")
            for path in sorted(fixture_root.rglob("*"))
            if path.is_file()
        ]
        surfaces = {
            "workspace": "".join(texts),
            "fact_wire": "".join(wire_snapshots),
            "leads": json.dumps(
                module.build_fake_leads(case_id, units[0], revision),
                sort_keys=True,
            ),
            "llm_context": "".join(
                json.dumps(payload, sort_keys=True)
                for payload in scout_payloads + llm_payloads
            ),
            "targets": json.dumps(
                [item.state for item in outcome.targets]
            ),
        }
        return surfaces, repository_keys

    def test_pipeline_inputs_carry_no_case_metadata(self):
        module = self.module
        document = module.load_case_document(CASES_PATH)
        for case_id in ("uaf-direct", "non-security-filter"):
            with self.subTest(case=case_id):
                case = next(
                    item for item in document["cases"] if item["id"] == case_id
                )
                marker_pin = case["vulnerable"]["files"][
                    sorted(case["vulnerable"]["files"])[0]
                ]
                markers = [
                    case["id"],
                    case["title"],
                    case["license"]["note"],
                    case["notes"],
                    marker_pin,
                    "selection_rationale",
                    "final_state",
                    "ground_truth",
                ]
                surfaces, repository_keys = self._run_case_revision(
                    module, case, "vulnerable"
                )
                for surface_name, surface in surfaces.items():
                    for marker in markers:
                        self.assertNotIn(
                            marker,
                            surface,
                            f"case label {marker!r} leaked into "
                            f"the {surface_name}",
                        )
                self.assertTrue(surfaces["llm_context"])
                for key in repository_keys:
                    self.assertNotIn(case["id"], key)
                    self.assertTrue(key.startswith("platform-evaluation/"))


# ---------------------------------------------------------- fake-llm e2e


class FakeLlmEndToEndTests(unittest.TestCase):
    """The full platform chain behaves per design over the committed pairs."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()
        cls.document = cls.module.load_case_document(CASES_PATH)

    def _case(self, case_id):
        return next(
            item for item in self.document["cases"] if item["id"] == case_id
        )

    def _run(self, case_id, revision, **kwargs):
        return self.module.run_revision(
            self._case(case_id), revision, mode="auto", fake_llm=True,
            timeout=60, **kwargs,
        )

    def test_uaf_direct_pair_confirms_on_the_vulnerable_side(self):
        record = self._run("uaf-direct", "vulnerable")
        self.assertEqual(1, record["finding_count"])
        target = record["targets"][0]
        self.assertEqual("runtime-confirmed", target["state"])
        self.assertIn(target["state"], UAF_FINDING_STATES)
        # The facts instrument was consulted (candidate matched the target):
        # the PASS proof travels with the finding but never gates the agent.
        self.assertEqual("PASS", target["proof_verdict"])
        self.assertEqual(1, len(target["experiment_log"]))
        self.assertTrue(target["experiment_log"][0]["hit"])
        self.assertEqual("heap-use-after-free",
                         target["experiment_log"][0]["error_type"])
        self.assertEqual(0, record["llm"]["critic_calls"])
        self.assertEqual(
            {"runs": 3, "hits": 3, "stable": True}, record["poc_stability"]
        )

        fixed = self._run("uaf-direct", "fixed")
        self.assertEqual(0, fixed["finding_count"])
        self.assertEqual([], fixed["targets"])
        self.assertEqual(0, fixed["llm"]["scout_calls"])
        self.assertEqual(0, fixed["llm"]["specialist_calls"])

    def test_null_deref_pair_confirms_without_certified_facts(self):
        record = self._run("null-deref-direct", "vulnerable")
        self.assertEqual(1, record["finding_count"])
        target = record["targets"][0]
        self.assertEqual("runtime-confirmed", target["state"])
        self.assertEqual("CWE-476", target["cwe"])
        self.assertEqual("", target["proof_verdict"])
        entry = target["experiment_log"][0]
        self.assertTrue(entry["hit"])
        self.assertIn("SEGV on unknown address", entry["error_type"])

        fixed = self._run("null-deref-direct", "fixed")
        self.assertEqual(0, fixed["finding_count"])
        self.assertEqual("none", observed_state(fixed))

    def test_overflow_pair_confirms_with_the_write_class(self):
        record = self._run("overflow-direct", "vulnerable")
        self.assertEqual(1, record["finding_count"])
        target = record["targets"][0]
        self.assertEqual("runtime-confirmed", target["state"])
        self.assertEqual("CWE-787", target["cwe"])
        entry = target["experiment_log"][0]
        self.assertTrue(entry["hit"])
        self.assertIn("buffer-overflow", entry["error_type"])

        fixed = self._run("overflow-direct", "fixed")
        self.assertEqual(0, fixed["finding_count"])

    def test_revisable_pair_needs_the_critic_revision_to_hit(self):
        record = self._run("rebind-revisable", "vulnerable")
        self.assertEqual(1, record["finding_count"])
        target = record["targets"][0]
        self.assertEqual("runtime-confirmed", target["state"])
        self.assertEqual(2, len(target["experiment_log"]))
        self.assertFalse(target["experiment_log"][0]["hit"])
        self.assertTrue(target["experiment_log"][1]["hit"])
        self.assertEqual(
            "heap-use-after-free", target["experiment_log"][1]["error_type"]
        )
        self.assertEqual(2, record["experiment_count"])
        # The revision ran a different driver and it is the stable PoC.
        self.assertNotEqual(
            target["experiment_log"][0], target["experiment_log"][1]
        )
        self.assertEqual(1, record["llm"]["critic_calls"])
        self.assertEqual(
            {"runs": 3, "hits": 3, "stable": True}, record["poc_stability"]
        )

        fixed = self._run("rebind-revisable", "fixed")
        self.assertEqual(0, fixed["finding_count"])
        self.assertEqual("none", observed_state(fixed))

    def test_clean_pair_abstains_with_zero_findings(self):
        for revision in self.module.REVISIONS:
            with self.subTest(revision=revision):
                record = self._run("clean-function", revision)
                self.assertEqual(0, record["finding_count"])
                self.assertEqual("abstain", observed_state(record))
                target = record["targets"][0]
                self.assertFalse(target["finding"])
                self.assertEqual("critic-veto", target["rejected_reason"])
                self.assertEqual(1, record["experiment_count"])

    def test_non_security_pair_is_filtered_by_the_hypothesis_contract(self):
        module = self.module
        # Fixture premise: the scripted specialist proposes a CWE outside the
        # registry vocabulary -- exactly the closed-vocabulary rejection the
        # design pins for competition note 3.
        script = module._SPECIALIST_SCRIPTS["non-security-filter"]
        self.assertNotIn(script["cwe"], module._allowed_case_cwes())
        for revision in module.REVISIONS:
            with self.subTest(revision=revision):
                record = self._run("non-security-filter", revision)
                self.assertEqual(0, record["finding_count"])
                self.assertEqual("abstain", observed_state(record))
                self.assertTrue(
                    any(
                        "invalid-reply" in item
                        for item in record["diagnostics"]
                    ),
                    record["diagnostics"],
                )
                # Initial reply plus exactly one format repair, never a
                # Critic round: the contract rejected the hypothesis.
                self.assertEqual(2, record["llm"]["specialist_calls"])
                self.assertEqual(0, record["llm"]["critic_calls"])
                self.assertEqual(0, record["experiment_count"])

    def test_full_fake_run_reports_every_competition_metric(self):
        report = run_fake_evaluation(self.module)
        self.assertEqual(6, report["case_count"])
        self.assertEqual(12, len(report["records"]))
        self.assertEqual(1.0, report["detection_rate"]["rate"])
        self.assertEqual(0.0, report["false_positive_rate"]["rate"])
        self.assertEqual(1.0, report["non_security_filter_rate"]["rate"])
        self.assertEqual(1.0, report["experiment_convergence"]["rate"])
        self.assertEqual(1.0, report["poc_stability"]["rate"])
        self.assertEqual(1.0, report["paired_detection"]["rate"])
        self.assertEqual(
            2, report["experiment_convergence"]["round_budget"]
        )
        self.assertIn("llm_usage", report)
        self.assertIn("latency_seconds", report)


# ------------------------------------------------------------- CLI/provider


class ProviderAndCliTests(unittest.TestCase):
    """CLI surface and provider resolution mirror the Task 12 pattern."""

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
        llm_config, provider, _model = self.module.build_llm_config(args, env={})
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
                "--model", "platform-model",
            ]
        )
        llm_config, provider, model = module.build_llm_config(args, env={})
        self.assertEqual("https://llm.example.invalid/v1", llm_config["base_url"])
        self.assertEqual("k", llm_config["api_key"])
        self.assertEqual("platform-model", model)
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
            output = Path(tmp) / "platform-evaluation.json"
            exit_code = module.main(
                [
                    "--cases", str(CASES_PATH),
                    "--case-id", "uaf-direct",
                    "--output", str(output),
                    "--fake-llm",
                    "--mode", "auto",
                ]
            )
            self.assertEqual(0, exit_code)
            report = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(1, report["case_count"])
        self.assertEqual("fake", report["llm_transport"])
        self.assertEqual(1.0, report["detection_rate"]["rate"])
        self.assertIn("identity", report)
        self.assertIn("case_data_sha256", report["identity"])
        self.assertIn("platform_pipeline_sha256", report["identity"])
        self.assertTrue(report["validity_boundaries"])


if __name__ == "__main__":
    unittest.main()
