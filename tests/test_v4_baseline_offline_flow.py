"""Frozen acceptance tests for IP-0031: offline flow, synthetic markers, decision pack.

Contract under test (frozen by Coordinator Assignment CA-IP-0031-v1.0 of
2026-09-27; see docs/LIMA_Implementation_Packet_IP-0031_Offline_Budget_Gate.md):

- The Implementation deliverable is ``benchmarks/v4/baseline/offline_flow.py``
  composing the frozen upstream faces read-only: the suite runs 5 cold + 5 warm
  attempts (default ``repeat=5``, covering the 3/5 minimal-sufficient gate of
  ``lima.baseline_run_result``) through ``orchestrate.run_repeats`` with a
  guarded fake evaluator (budget reserve before invoke, usage recording after,
  failure accounting with the taxonomy samples retained), materializes the
  IP-0030 fixture into an internal temp workspace (never the output dir),
  builds and persists the IP-0029 report, writes the canonical synthetic
  marker sidecar ``{digest16}-synthetic-{n}.json`` after ``run_repeats``
  returns, and returns ``OfflineSuiteResult`` with ``synthetic=True``.
- The synthetic marker schema, its declaration closure, byte-identical rewrite
  idempotency, and next-slot behavior for differing bytes are frozen; the
  run/report documents themselves must stay free of any synthetic field (the
  frozen report declarations stay exactly the single IP-0029 value).
- The budget decision pack ``docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md``
  must exist with the eleven frozen section headings, UNKNOWN annotations in
  place, and no digit-adjacent currency literals (anti-fabrication scan; the
  scanner pattern is built by token concatenation and validated against a
  positive control and this file's own source, PC1).
- Offline hygiene: ``offline_flow.py`` has no network imports and no
  environment reads; a suite-level budget refusal performs zero evaluator
  calls (injected call counter).

Expected RED before implementation: the behavior tests fail on the missing
deliverable -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.offline_flow'``
(lazy per-test import); ``benchmarks.v4.baseline.budget`` is imported the same
lazy way by the arrange helpers. The tests that deliberately avoid the new
modules (decision-pack static checks and the PC2 arrange validations that feed
frozen upstream validators directly) pass while only the C1 documents exist;
this is by design and recorded in the RED evidence. The suite is offline and
secretless: stdlib plus the frozen upstream modules only, tempdir isolation,
no network, no environment reads, no paid calls.
"""

import ast
import hashlib
import inspect
import json
import pathlib
import re
import tempfile
import unittest

from benchmarks.v4.baseline import collect, orchestrate, report
from benchmarks.v4.baseline import fixtures as fixtures_module
from benchmarks.v4.baseline.run import FROZEN_DATASET_BINDINGS, validate_role_bindings
from lima.baseline_run_result import (
    _COLD_MIN_SUCCESSES,
    _SAMPLE_FIELDS,
    _WARM_MIN_SUCCESSES,
)
from lima.baseline_run_spec import from_mapping as spec_from_mapping
from lima.baseline_run_spec import validate_baseline_manifest
from lima.contracts.codec import canonical_encode, compute_content_digest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PACKET_RELATIVE_PATH = "docs/LIMA_Implementation_Packet_IP-0031_Offline_Budget_Gate.md"
_DECISION_PACK_RELATIVE_PATH = "docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md"
_FLOW_MODULE_RELATIVE_PATH = "benchmarks/v4/baseline/offline_flow.py"
_MANIFEST_RELATIVE_PATH = "evaluation_data/v4/baseline_manifest.json"

_DEFAULT_FIXTURE_KEY = "archetype/minimal-python-repository"
_SYNTHETIC_PAYLOAD_NAME = "lima-offline-synthetic-e2e"

_FLOW_ALL = (
    "EvaluatorOutcome",
    "FakeEvaluator",
    "OfflineSuiteResult",
    "make_fake_evaluator",
    "run_offline_baseline_suite",
    "synthetic_call_usage",
    "synthetic_e2e_payload",
    "write_synthetic_marker",
)

_MARKER_DECLARATIONS = [
    "excluded-from-v5-and-immutable-baseline",
    "not-real-acceptance-evidence",
    "offline-fake-evaluator",
    "synthetic-usage",
]

_MARKER_FIELDS = {
    "marker_version",
    "marker_type",
    "run_spec_digest",
    "aggregate_sha256",
    "attempt_count",
    "budget_ledger_digest",
    "declarations",
}

_DECISION_PACK_SECTIONS = (
    "## 1. Document Header",
    "## 2. Candidate Models",
    "## 3. Pricing Sources and Dates",
    "## 4. Per-Run Estimates",
    "## 5. Recommended Caps",
    "## 6. Over-Cap Behavior",
    "## 7. Machine Profile",
    "## 8. Failed Run Handling",
    "## 9. Auditable Budget Formulas",
    "## 10. UNKNOWN Ledger",
    "## 11. Authorization Request Checklist",
)

_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")

# Test-local arrange payload: the frozen synthetic e2e literal (Packet 8.3).
_TEST_PAYLOAD = {
    "schema_version": 1,
    "name": _SYNTHETIC_PAYLOAD_NAME,
    "metrics": {"tp": 3, "fp": 1, "fn": 2},
    "by_split": {
        "validation": {"tp": 3, "fp": 1, "fn": 2},
        "holdout": {"tp": 3, "fp": 1, "fn": 2},
    },
    "case_results": [],
    "dataset": {
        "name": "lima-offline-synthetic-e2e-dataset",
        "source_kinds": ["synthetic"],
    },
}

_NOMINAL_MACHINE_PROFILE = {
    "profile_id": "lima-baseline-profile-001",
    "cpu_arch": "x86_64",
    "cpu_model": "declared-baseline-cpu",
    "cores": 8,
    "ram_gb": 32,
    "os_family": "linux",
    "python_version": "3.12.4",
    "gpu_summary": "none",
}


def _oracle_usage(index):
    """Independent mirror of the frozen synthetic usage formula (Packet 8.4)."""
    return {
        "prompt_tokens": 1000 + 10 * index,
        "completion_tokens": 500 + 5 * index,
        "cost_micro_usd": 10 + index,
        "wall_ms": 50 + index,
    }


def _forbidden_network_roots():
    """First-level import roots that must never be imported by offline_flow."""
    return {"sock" + "et", "url" + "lib", "requ" + "ests", "http"}


def _network_import_roots(source):
    """First-level import roots of a python source string (AST parse, no exec)."""
    tree = ast.parse(source)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def _environ_token():
    """The forbidden environment-read token, built by concatenation (PC1)."""
    return "os." + "environ"


def _currency_digit_patterns():
    """Anti-fabrication scanners for digit-adjacent currency literals (PC1).

    Both patterns are assembled from concatenated token pieces so that this
    test file never contains a contiguous match of its own scanners.
    """
    unit = "(?:" + "U" + "SD|us" + "d)"
    micro = "(?:mic" + "ro\\s*-)?"
    adjacent = re.compile(r"(?<![A-Za-z0-9_])\d[\d,._\s]*" + micro + unit + r"\b")
    prefixed = re.compile(r"\$\d")
    return adjacent, prefixed


def _fixed_sources(durations_ms):
    """Injectable platform sources with fixed per-attempt wall/cpu durations."""
    durations = [value * 1_000_000 for value in durations_ms]
    wall_reads = []
    wall_base = 1_000_000_000
    for span in durations:
        wall_reads.extend((wall_base, wall_base + span))
        wall_base += span + 1_000_000
    cpu_reads = []
    cpu_base = 500_000_000
    for _ in durations:
        cpu_reads.extend((cpu_base, cpu_base + 100_000_000))
        cpu_base += 200_000_000
    wall = iter(wall_reads)
    cpu = iter(cpu_reads)
    return collect.PlatformSources(
        wall_ns=lambda: next(wall),
        cpu_ns=lambda: next(cpu),
        peak_rss_bytes=lambda: 4096,
        io_read_bytes=lambda: 512,
        io_write_bytes=lambda: 256,
    )


class _CountingExecute:
    """Execution body double that only records how often it was invoked."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return None


class _OfflineFlowTestCase(unittest.TestCase):
    """Shared arrange helpers (no collected test methods)."""

    def flow(self):
        import benchmarks.v4.baseline.offline_flow as flow_module

        return flow_module

    def budget(self):
        import benchmarks.v4.baseline.budget as budget_module

        return budget_module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def load_manifest(self):
        path = _REPO_ROOT / _MANIFEST_RELATIVE_PATH
        if not path.is_file():
            self.fail(f"required frozen manifest artifact is missing: {_MANIFEST_RELATIVE_PATH}")
        return json.loads(path.read_bytes().decode("utf-8"))

    def spec_mapping(self):
        manifest = self.load_manifest()
        repositories = [
            {"identity": entry["repository"], "commit_sha": entry["commit_sha"]}
            for dataset in manifest["datasets"]
            for entry in dataset["entries"]
        ]
        datasets = [
            {
                "name": dataset["name"],
                "fingerprint": dataset["fingerprint"],
                "role": dataset["role"],
            }
            for dataset in manifest["datasets"]
        ]
        return {
            "schema_version": 1,
            "repositories": repositories,
            "datasets": datasets,
            "analyzer_fingerprint": "a" * 64,
            "config_digest": "b" * 64,
            "seed": 20260925,
            "machine_profile": dict(_NOMINAL_MACHINE_PROFILE),
        }

    def suite_budget(self, zero=False):
        module = self.budget()
        if zero:
            per_run = module.BudgetLimits(
                cost_micro_usd=0,
                calls=0,
                prompt_tokens=0,
                completion_tokens=0,
                wall_ms=0,
                download_bytes=0,
                storage_bytes=0,
            )
            batch = module.BudgetLimits(
                cost_micro_usd=0,
                calls=0,
                prompt_tokens=0,
                completion_tokens=0,
                wall_ms=0,
                download_bytes=0,
                storage_bytes=0,
            )
        else:
            per_run = module.BudgetLimits(
                cost_micro_usd=2_000,
                calls=2,
                prompt_tokens=2_000,
                completion_tokens=1_000,
                wall_ms=10_000_000,
                download_bytes=100,
                storage_bytes=100,
            )
            batch = module.BudgetLimits(
                cost_micro_usd=20_000,
                calls=10,
                prompt_tokens=20_000,
                completion_tokens=10_000,
                wall_ms=100_000_000,
                download_bytes=1_000,
                storage_bytes=1_000,
            )
        spec = module.BudgetSpec(per_run=per_run, batch=batch)
        pricing = module.Pricing(
            prompt_token_price_micro_usd_per_million=1_000_000,
            completion_token_price_micro_usd_per_million=1_000_000,
        )
        return spec, pricing

    def run_suite(self, directory, *, evaluator=None, failures=None, zero_budget=False):
        flow = self.flow()
        if evaluator is None:
            evaluator = flow.make_fake_evaluator(failures=failures)
        budget_spec, pricing = self.suite_budget(zero=zero_budget)
        result = flow.run_offline_baseline_suite(
            self.spec_mapping(),
            output_dir=pathlib.Path(directory),
            evaluator=evaluator,
            budget_spec=budget_spec,
            pricing=pricing,
            sources=_fixed_sources([100] * 5 + [80] * 5),
        )
        return result, evaluator


class TestOfflineSuiteEndToEnd(_OfflineFlowTestCase):
    """AC-1 / FR-01: the full offline typed data flow with the frozen default repeat."""

    def test_default_repeat_produces_ten_attempts_and_four_file_families(self):
        flow = self.flow()
        self.assertEqual(tuple(flow.__all__), _FLOW_ALL)
        parameters = inspect.signature(flow.run_offline_baseline_suite).parameters
        self.assertEqual(parameters["repeat"].default, 5)
        self.assertEqual(parameters["fixture_key"].default, _DEFAULT_FIXTURE_KEY)
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            repeat = 5
            self.assertEqual(result.attempt_count, 2 * repeat)
            self.assertEqual(result.status, "sufficient_sample")
            self.assertIs(result.synthetic, True)
            digest16 = result.run_spec_digest[:16]
            names = sorted(path.name for path in pathlib.Path(directory).iterdir())
            expected = sorted(
                [f"{digest16}-run-{n}.json" for n in range(1, 2 * repeat + 2)]
                + [f"{digest16}-report-1.json", f"{digest16}-synthetic-1.json"]
            )
            self.assertEqual(names, expected)
            self.assertEqual(
                [path.name for path in result.result_paths],
                [f"{digest16}-run-{n}.json" for n in range(1, 2 * repeat + 1)],
            )
            self.assertEqual(result.aggregate_path.name, f"{digest16}-run-{2 * repeat + 1}.json")
            aggregate = json.loads(result.aggregate_path.read_bytes().decode("utf-8"))
            samples = aggregate["samples"]
            self.assertEqual(
                [sample["attempt_index"] for sample in samples], list(range(2 * repeat))
            )
            self.assertEqual(
                [sample["mode"] for sample in samples], ["cold"] * repeat + ["warm"] * repeat
            )
            self.assertEqual({sample["outcome"] for sample in samples}, {"success"})
            cold = sum(
                1
                for sample in samples
                if sample["mode"] == "cold" and sample["outcome"] == "success"
            )
            warm = sum(
                1
                for sample in samples
                if sample["mode"] == "warm" and sample["outcome"] == "success"
            )
            self.assertEqual((_COLD_MIN_SUCCESSES, _WARM_MIN_SUCCESSES), (3, 5))
            self.assertGreaterEqual(cold, _COLD_MIN_SUCCESSES)
            self.assertGreaterEqual(warm, _WARM_MIN_SUCCESSES)

    def test_report_round_trips_through_frozen_from_mapping(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            document = json.loads(result.report_path.read_bytes().decode("utf-8"))
            refrozen = report.from_mapping(document)
            self.assertEqual(refrozen.canonical_bytes(), result.report_path.read_bytes())

    def test_ledger_consumed_equals_sum_of_synthetic_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            result, evaluator = self.run_suite(directory)
            snapshot = result.ledger_snapshot
            attempts = result.attempt_count
            for dimension in ("prompt_tokens", "completion_tokens", "cost_micro_usd", "wall_ms"):
                expected = sum(_oracle_usage(index)[dimension] for index in range(attempts))
                self.assertEqual(snapshot.batch["consumed"][dimension], expected)
            self.assertEqual(snapshot.batch["calls"], attempts)
            self.assertEqual(snapshot.violations, 0)
            for books in snapshot.per_run.values():
                self.assertEqual(set(books["reserved"].values()), {0})
            self.assertEqual(result.evaluator_calls, attempts)
            self.assertEqual(evaluator.calls, attempts)

    def test_registry_consumed_read_only_and_fixture_materialized_outside_output(self):
        registry = fixtures_module.load_registry()
        entries = registry["fixtures"]
        self.assertEqual(len(entries), len(fixtures_module.FIXTURE_KEYS))
        self.assertEqual(
            len(fixtures_module.SYNTHETIC_FIXTURE_KEYS), len(fixtures_module.FIXTURE_KEYS) - 1
        )
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            self.assertEqual(result.fixture_key, _DEFAULT_FIXTURE_KEY)
            self.assertIn(result.fixture_key, fixtures_module.SYNTHETIC_FIXTURE_KEYS)
            entry = next(item for item in entries if item["key"] == result.fixture_key)
            self.assertEqual(result.fixture_fingerprint, entry["fingerprint"])
            self.assertEqual(result.fixture_file_count, entry["file_count"])
            digest16 = result.run_spec_digest[:16]
            families = (f"{digest16}-run-", f"{digest16}-report-", f"{digest16}-synthetic-")
            for path in sorted(pathlib.Path(directory).iterdir()):
                self.assertTrue(path.name.endswith(".json"))
                self.assertTrue(path.name.startswith(families), path.name)

    def test_arrange_spec_and_manifest_pass_frozen_validators(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping()
        spec_object = spec_from_mapping(mapping)
        validate_baseline_manifest(manifest, spec_object)
        validate_role_bindings(spec_object, manifest)
        self.assertEqual(len(manifest["datasets"]), len(FROZEN_DATASET_BINDINGS))

    def test_arrange_payload_passes_frozen_e2e_report_path(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self.load_manifest()
            execute = _CountingExecute()
            summary = orchestrate.run_repeats(
                self.spec_mapping(),
                manifest,
                execute,
                directory,
                repeat=5,
                sources=_fixed_sources([100] * 5 + [80] * 5),
            )
            self.assertEqual(execute.calls, 10)
            built = report.build_baseline_report(summary, _TEST_PAYLOAD)
            document = built.to_canonical_value()
            metrics = _TEST_PAYLOAD["metrics"]
            self.assertEqual(
                document["compression_chain"]["raw_candidates"], metrics["tp"] + metrics["fp"]
            )
            self.assertEqual(document["attempt_count"], 10)


class TestFailureRetention(_OfflineFlowTestCase):
    """AC-3 / FR-04: failure samples retained, insufficient sample, digest linkage."""

    def test_injected_failures_retained_with_taxonomy_codes(self):
        failures = {
            0: RuntimeError("synthetic-failure-cold"),
            2: TimeoutError("synthetic-timeout"),
        }
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory, failures=failures)
            aggregate = json.loads(result.aggregate_path.read_bytes().decode("utf-8"))
            codes = {
                sample["attempt_index"]: sample["failure_code"] for sample in aggregate["samples"]
            }
            self.assertEqual(codes[0], "EXECUTION_ERROR")
            self.assertEqual(codes[2], "EXECUTION_TIMEOUT")
            self.assertIsNone(codes[1])
            self.assertEqual(result.status, "sufficient_sample")

    def test_all_cold_failures_yield_insufficient_sample(self):
        failures = {index: RuntimeError("synthetic-cold-failure") for index in range(5)}
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory, failures=failures)
            self.assertEqual(result.status, "insufficient_sample")
            self.assertEqual(result.attempt_count, 10)
            aggregate = json.loads(result.aggregate_path.read_bytes().decode("utf-8"))
            cold = sum(
                1
                for sample in aggregate["samples"]
                if sample["mode"] == "cold" and sample["outcome"] == "success"
            )
            self.assertLess(cold, _COLD_MIN_SUCCESSES)
            self.assertTrue(result.marker_path.is_file())

    def test_identity_digests_aggregate_across_marker_and_report(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            spec_digest = spec_from_mapping(self.spec_mapping()).content_digest()
            marker = json.loads(result.marker_path.read_bytes().decode("utf-8"))
            report_doc = json.loads(result.report_path.read_bytes().decode("utf-8"))
            self.assertEqual(result.run_spec_digest, spec_digest)
            self.assertEqual(marker["run_spec_digest"], spec_digest)
            self.assertEqual(report_doc["run_spec_digest"], spec_digest)
            self.assertEqual(marker["aggregate_sha256"], result.aggregate_sha256)
            self.assertEqual(report_doc["aggregate_sha256"], result.aggregate_sha256)


class TestSyntheticMarkerContract(_OfflineFlowTestCase):
    """AC-3 / FR-04: the synthetic sidecar schema, idempotency, and isolation."""

    def test_marker_schema_field_set_and_declarations_closure(self):
        flow = self.flow()
        self.assertEqual(flow.synthetic_e2e_payload(), _TEST_PAYLOAD)
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            marker = json.loads(result.marker_path.read_bytes().decode("utf-8"))
            self.assertEqual(set(marker), _MARKER_FIELDS)
            self.assertEqual(marker["marker_version"], 1)
            self.assertEqual(marker["marker_type"], "synthetic-offline-run")
            self.assertEqual(marker["declarations"], _MARKER_DECLARATIONS)
            self.assertTrue(_HEX64_PATTERN.match(marker["run_spec_digest"]))
            self.assertTrue(_HEX64_PATTERN.match(marker["aggregate_sha256"]))
            self.assertTrue(_HEX64_PATTERN.match(marker["budget_ledger_digest"]))
            self.assertEqual(marker["attempt_count"], result.attempt_count)
            expected = compute_content_digest(
                {
                    "per_run": result.ledger_snapshot.per_run,
                    "batch": result.ledger_snapshot.batch,
                    "violations": result.ledger_snapshot.violations,
                }
            )
            self.assertEqual(marker["budget_ledger_digest"], expected)

    def test_marker_file_is_canonical_json(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            raw = result.marker_path.read_bytes()
            document = json.loads(raw.decode("utf-8"))
            self.assertEqual(canonical_encode(document), raw)
            self.assertEqual(hashlib.sha256(raw).hexdigest(), result.marker_sha256)

    def test_byte_identical_rewrite_is_idempotent(self):
        flow = self.flow()
        document = {
            "marker_version": 1,
            "marker_type": "synthetic-offline-run",
            "run_spec_digest": "a" * 64,
            "aggregate_sha256": "b" * 64,
            "attempt_count": 10,
            "budget_ledger_digest": "c" * 64,
            "declarations": list(_MARKER_DECLARATIONS),
        }
        with tempfile.TemporaryDirectory() as directory:
            first = flow.write_synthetic_marker(document, directory)
            second = flow.write_synthetic_marker(document, directory)
            self.assertEqual(first, second)
            synthetic_files = [
                path.name
                for path in pathlib.Path(directory).iterdir()
                if "-synthetic-" in path.name
            ]
            self.assertEqual(synthetic_files, ["a" * 16 + "-synthetic-1.json"])

    def test_differing_bytes_occupy_next_sequence_slot(self):
        flow = self.flow()
        document = {
            "marker_version": 1,
            "marker_type": "synthetic-offline-run",
            "run_spec_digest": "a" * 64,
            "aggregate_sha256": "b" * 64,
            "attempt_count": 10,
            "budget_ledger_digest": "c" * 64,
            "declarations": list(_MARKER_DECLARATIONS),
        }
        with tempfile.TemporaryDirectory() as directory:
            first = flow.write_synthetic_marker(document, directory)
            mutated = dict(document)
            mutated["attempt_count"] = document["attempt_count"] + 1
            second = flow.write_synthetic_marker(mutated, directory)
            self.assertEqual(first.name, "a" * 16 + "-synthetic-1.json")
            self.assertEqual(second.name, "a" * 16 + "-synthetic-2.json")

    def test_run_and_report_documents_carry_no_synthetic_fields(self):
        with tempfile.TemporaryDirectory() as directory:
            result, _evaluator = self.run_suite(directory)
            aggregate = json.loads(result.aggregate_path.read_bytes().decode("utf-8"))
            for sample in aggregate["samples"]:
                self.assertEqual(set(sample), set(_SAMPLE_FIELDS))
            report_doc = json.loads(result.report_path.read_bytes().decode("utf-8"))
            self.assertEqual(
                report_doc["declarations"], list(report.BASELINE_REPORT_DECLARATIONS)
            )
            self.assertNotIn("synthetic", json.dumps(aggregate))
            self.assertNotIn("synthetic", json.dumps(report_doc))


class TestDecisionPackArtifact(_OfflineFlowTestCase):
    """AC-4 / FR-05: the budget decision pack exists, structured, and unfabricated."""

    def test_packet_and_decision_pack_documents_exist(self):
        for relative in (_PACKET_RELATIVE_PATH, _DECISION_PACK_RELATIVE_PATH):
            path = _REPO_ROOT / relative
            if not path.is_file():
                self.fail(f"required deliverable document is missing: {relative}")

    def test_decision_pack_has_all_frozen_section_headings(self):
        text = (_REPO_ROOT / _DECISION_PACK_RELATIVE_PATH).read_text(encoding="utf-8")
        for heading in _DECISION_PACK_SECTIONS:
            self.assertIn(heading, text)
        self.assertIn("DRAFT-PENDING-AUTHORIZATION", text)

    def test_decision_pack_marks_unknown_values_in_place(self):
        text = (_REPO_ROOT / _DECISION_PACK_RELATIVE_PATH).read_text(encoding="utf-8")
        self.assertIn("| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |", text)
        self.assertIn("Prompt tokens per call: UNKNOWN.", text)
        self.assertIn("| cpu_model | UNKNOWN |", text)
        self.assertIn("Minimal authorization action", text)

    def test_decision_pack_has_no_fabricated_currency_numbers(self):
        adjacent, prefixed = _currency_digit_patterns()
        self.assertIsNotNone(adjacent.search("5" + " USD"))
        self.assertIsNotNone(adjacent.search("5 micro" + "-USD"))
        self.assertIsNotNone(prefixed.search("$" + "5"))
        own_source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertIsNone(adjacent.search(own_source))
        self.assertIsNone(prefixed.search(own_source))
        text = (_REPO_ROOT / _DECISION_PACK_RELATIVE_PATH).read_text(encoding="utf-8")
        self.assertIsNone(adjacent.search(text))
        self.assertIsNone(prefixed.search(text))


class TestOfflineHygiene(_OfflineFlowTestCase):
    """AC-1: offline source guarantees and the suite-level refusal proof."""

    def test_offline_flow_module_has_no_network_imports(self):
        forbidden = _forbidden_network_roots()
        violating_source = "import " + "url" + "lib.request\n"
        self.assertTrue(_network_import_roots(violating_source) & forbidden)
        own_roots = _network_import_roots(pathlib.Path(__file__).read_text(encoding="utf-8"))
        self.assertFalse(own_roots & forbidden)
        roots = _network_import_roots(self.product_source(_FLOW_MODULE_RELATIVE_PATH))
        self.assertFalse(roots & forbidden)

    def test_offline_flow_module_has_no_environment_reads(self):
        token = _environ_token()
        self.assertIn(token, "value = " + token + "['X']\n")
        own_source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertNotIn(token, own_source)
        self.assertNotIn(token, self.product_source(_FLOW_MODULE_RELATIVE_PATH))

    def test_suite_level_refusal_performs_zero_evaluator_calls(self):
        with tempfile.TemporaryDirectory() as directory:
            result, evaluator = self.run_suite(directory, zero_budget=True)
            self.assertEqual(evaluator.calls, 0)
            self.assertEqual(result.evaluator_calls, 0)
            self.assertEqual(result.status, "insufficient_sample")
            aggregate = json.loads(result.aggregate_path.read_bytes().decode("utf-8"))
            codes = {sample["failure_code"] for sample in aggregate["samples"]}
            self.assertEqual(codes, {"EXECUTION_ERROR"})
            snapshot = result.ledger_snapshot
            self.assertEqual(snapshot.batch["calls"], 0)
            for book in ("reserved", "consumed", "released"):
                self.assertEqual(set(snapshot.batch[book].values()), {0})
            self.assertEqual(set(snapshot.per_run), set())
            self.assertEqual(snapshot.violations, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
