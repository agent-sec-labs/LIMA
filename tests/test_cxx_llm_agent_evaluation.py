"""Unlabeled evaluation contract for the C/C++ LLM agent pipeline (Task 20).

All tests run fully offline: the model is a scripted fake client, the pipeline
is the real ``RepositoryScanner`` + ``CxxAgentCoordinator`` chain, and the
evaluation assets never enter the retrieval or agent input path.
"""

import hashlib
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.cxx_agent_models import CxxAgentCandidate
from lima.cxx_agents import (
    ROLE_CRITIC,
    ROLE_EVIDENCE,
    ROLE_MEMORY_LIFETIME,
    ROLE_PLANNER,
    ROLE_VERIFIER,
)
from lima.cxx_llm import AgentStep

ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_cxx_llm_agent_evaluation.py"
CASES_PATH = ROOT / "evaluation_data" / "cxx_llm_agent_cases.json"
FIXTURE_FOREST = ROOT / "tests" / "fixtures" / "cxx_llm_agent"


def load_evaluation_module():
    spec = importlib.util.spec_from_file_location("cxx_llm_agent_evaluation", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("evaluation module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def symbol_definition_line(text: str, symbol: str) -> int:
    for number, line in enumerate(text.splitlines(), start=1):
        if symbol in line and "(" in line and not line.strip().startswith("//"):
            return number
    raise AssertionError(f"symbol {symbol!r} not found in fixture text")


# ---------------------------------------------------------------- fake clients


class ScriptedAgentClient:
    """Offline stand-in for ``CxxLLMClient`` with per-role step scripts."""

    def __init__(self, scripts, model="fake-cxx-model"):
        self.scripts = dict(scripts)
        self.model = model
        self.calls = []

    def step(self, role, managed_context, tools, budget, read_paths=None):
        self.calls.append({"role": role, "context": managed_context})
        script = self.scripts.get(role) or []
        if not script:
            raise AssertionError(f"unexpected LLM call for role {role!r}")
        return script.pop(0)


class SilentAgentClient:
    """Client that must never be called (zero-candidate revisions)."""

    model = "silent-cxx-model"

    def step(self, role, managed_context, tools, budget, read_paths=None):
        raise AssertionError(f"revision without candidates called role {role!r}")


def honest_scripts(case):
    """Read-then-report script: one real candidate at the expected identity."""

    path = case["affected"]["path"]
    symbol = case["affected"]["symbol"]
    source = (FIXTURE_FOREST / case["id"] / "vulnerable" / path).read_text(encoding="utf-8")
    start_line = symbol_definition_line(source, symbol)
    candidate_json = {
        "cwe": case["cwe"],
        "path": path,
        "line": start_line,
        "symbol": symbol,
        "title": "memory hazard",
        "mechanism": "the synthetic vulnerable revision releases or overruns the buffer",
        "trigger_path": [symbol, "free", "use"],
        "confidence": 0.9,
    }
    candidate = CxxAgentCandidate.from_untrusted_json(candidate_json)
    anchor_json = dict(candidate_json)
    anchor_json.update({
        "title": "anchor selection",
        "mechanism": "anchor selection only; rebuilt deterministically",
        "trigger_path": [symbol],
        "confidence": 0.5,
    })
    anchor = CxxAgentCandidate.from_untrusted_json(anchor_json)

    def final(item):
        return AgentStep(action="final", candidates=(item,))

    def snippet():
        return AgentStep(
            action="tool",
            tool="read_code_snippet",
            arguments=(("path", path), ("start_line", 1), ("end_line", len(source.splitlines()))),
            reason="read the assigned function body",
        )

    return {
        ROLE_PLANNER: [final(anchor)],
        ROLE_MEMORY_LIFETIME: [snippet(), final(candidate)],
        ROLE_CRITIC: [final(candidate)],
        ROLE_EVIDENCE: [final(candidate)],
        ROLE_VERIFIER: [final(candidate)],
    }


def pipeline_result(
    findings=(),
    *,
    status="completed",
    elapsed=1.0,
    usage=None,
    snapshot="b" * 64,
    collaboration=None,
):
    return {
        "status": status,
        "collaboration": collaboration
        if collaboration is not None
        else {"mode": "auto", "status": status, "model": "fake-cxx-model"},
        "agent_findings": list(findings),
        "snapshot_sha256": snapshot,
        "usage": usage
        if usage is not None
        else {"calls": 5, "context_files": 1, "context_lines": 40, "output_bytes": 900},
        "elapsed_seconds": elapsed,
    }


def finding(cwe, state="llm-candidate", path="src/session.c", symbol="session_release"):
    return {
        "cwe": cwe,
        "path": path,
        "symbol": symbol,
        "line": 3,
        "verification_state": state,
        "automatic_repair": False,
    }


def synthetic_case(case_id="cwe-416-session-release-uaf", cwe="CWE-416"):
    return {
        "id": case_id,
        "title": "Synthetic use-after-free pair",
        "cwe": cwe,
        "origin": "synthetic",
        "affected": {"path": "src/session.c", "symbol": "session_release"},
        "versions": {
            "vulnerable": {
                "kind": "local",
                "source_dir": f"tests/fixtures/cxx_llm_agent/{case_id}/vulnerable",
                "content_sha256": "a" * 64,
            },
            "fixed": {
                "kind": "local",
                "source_dir": f"tests/fixtures/cxx_llm_agent/{case_id}/fixed",
                "content_sha256": "b" * 64,
            },
        },
        "selection_rationale": (
            "Synthetic pair: the vulnerable revision uses the buffer after releasing "
            "it and the fixed revision removes the dynamic release entirely."
        ),
        "license": {
            "spdx": "Apache-2.0",
            "note": "Synthetic fixture authored in this repository; no third-party code.",
        },
    }


def repository_case():
    case = synthetic_case("cwe-125-sample-window-oob-read", "CWE-125")
    case["origin"] = "repository"
    case["project"] = "owner/project"
    case["affected"] = {"path": "src/sample_window.c", "symbol": "sample_window_first"}
    case.pop("versions")
    case["commits"] = {"vulnerable": "1" * 40, "fixed": "2" * 40}
    case["archives"] = {
        "vulnerable": {
            "url": "https://codeload.github.com/owner/project/tar.gz/" + "1" * 40,
            "sha256": "3" * 64,
        },
        "fixed": {
            "url": "https://codeload.github.com/owner/project/tar.gz/" + "2" * 40,
            "sha256": "4" * 64,
        },
    }
    return case


def committed_document():
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


def document_replacing(case):
    """A valid full document with the same-CWE committed case swapped out."""

    document = committed_document()
    document["cases"] = [
        case if item["cwe"] == case["cwe"] else item for item in document["cases"]
    ]
    return document


def document_with(case, *companions):
    return {"schema_version": 1, "cases": [case, *companions]}


class ManifestSchemaTests(unittest.TestCase):
    """The committed manifest pins exact bytes, identities and licenses."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()
        cls.document = json.loads(CASES_PATH.read_text(encoding="utf-8"))

    def test_committed_manifest_pins_one_synthetic_pair_per_supported_cwe(self):
        self.module.validate_case_document(self.document)
        self.assertEqual(1, self.document["schema_version"])
        cases = self.document["cases"]
        self.assertEqual(4, len(cases))
        self.assertEqual(
            {"CWE-787", "CWE-125", "CWE-416", "CWE-415"},
            {case["cwe"] for case in cases},
        )
        self.assertEqual(len(cases), len({case["id"] for case in cases}))
        for case in cases:
            self.assertEqual("synthetic", case["origin"])
            self.assertIn(case["cwe"].lower(), case["id"])
            self.assertNotIn("cve", case["id"].lower())
            self.assertNotIn("cve", case["title"].lower())
            self.assertGreaterEqual(len(case["selection_rationale"].strip()), 40)

    def test_local_versions_pin_existing_fixture_directories_by_content_digest(self):
        for case in self.document["cases"]:
            affected_path = case["affected"]["path"]
            for revision, version in case["versions"].items():
                self.assertEqual("local", version["kind"])
                source_dir = ROOT / version["source_dir"]
                self.assertTrue(source_dir.is_dir(), source_dir)
                self.assertTrue((source_dir / affected_path).is_file())
                self.assertEqual(
                    version["content_sha256"],
                    self.module.canonical_tree_digest(source_dir),
                    f"{case['id']} {revision} digest drift",
                )

    def test_schema_rejects_malformed_or_drifted_cases(self):
        module = self.module
        base = synthetic_case()
        other = synthetic_case("cwe-787-scratch-store-oob-write", "CWE-787")
        other["affected"] = {"path": "src/scratch_store.c", "symbol": "scratch_store_write"}
        mutations = {
            "bad digest": lambda item: item["versions"]["vulnerable"].update(
                content_sha256="zz" * 32
            ),
            "traversal source dir": lambda item: item["versions"]["vulnerable"].update(
                source_dir="tests/fixtures/../escape"
            ),
            "absolute source dir": lambda item: item["versions"]["vulnerable"].update(
                source_dir="C:/tmp/pair"
            ),
            "unknown kind": lambda item: item["versions"]["vulnerable"].update(kind="git"),
            "missing fixed": lambda item: item["versions"].pop("fixed"),
            "unknown origin": lambda item: item.update(origin="scraped"),
            "unsupported cwe": lambda item: item.update(cwe="CWE-89"),
            "extra field": lambda item: item.update(cve_description="secret truth"),
            "unsafe affected path": lambda item: item["affected"].update(path="../escape.c"),
            "empty symbol": lambda item: item["affected"].update(symbol=""),
            "short rationale": lambda item: item.update(selection_rationale="too short"),
            "license missing": lambda item: item.pop("license"),
            "license extra": lambda item: item["license"].update(upstream="https://x"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = json.loads(json.dumps(base))
                mutate(case)
                with self.assertRaises(ValueError):
                    module.validate_case_document(document_with(case, other))

    def test_duplicate_case_ids_are_rejected(self):
        case = synthetic_case()
        with self.assertRaises(ValueError):
            self.module.validate_case_document(document_with(case, json.loads(json.dumps(case))))

    def test_document_must_cover_every_supported_cwe(self):
        with self.assertRaises(ValueError):
            self.module.validate_case_document(document_with(synthetic_case()))

    def test_repository_form_is_validated_but_not_runnable(self):
        module = self.module
        case = repository_case()
        module.validate_case_document(document_replacing(case))
        with self.assertRaisesRegex(ValueError, "repository"):
            module.scan_revision(case, "vulnerable", lambda: None, 1)


class UnlabeledIsolationTests(unittest.TestCase):
    """Evaluation assets must never enter the retrieval or agent input path."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_retrieval_input_is_the_workspace_only_and_carries_no_labels(self):
        from lima import repository_scanner as scanner_module
        from lima.cxx_context import CxxContextIndex

        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        case = next(item for item in document["cases"] if item["cwe"] == "CWE-415")

        built = []

        class RecordingIndex(CxxContextIndex):
            @classmethod
            def build(cls, workspace, inventory):
                built.append(
                    {
                        "source_root": workspace.root,
                        "inventory_paths": [item.path for item in inventory.files],
                    }
                )
                return super().build(workspace, inventory)

        contexts = []

        class ContextCapturingClient(ScriptedAgentClient):
            def step(self, role, managed_context, tools, budget, read_paths=None):
                contexts.append(managed_context)
                return super().step(role, managed_context, tools, budget, read_paths)

        client = ContextCapturingClient(honest_scripts(case))

        label_markers = [
            case["id"],
            case["versions"]["vulnerable"]["content_sha256"],
            case["license"]["note"],
            "selection_rationale",
            str(CASES_PATH),
        ]

        with mock.patch.object(scanner_module, "CxxContextIndex", RecordingIndex):
            record = self.module.scan_revision(case, "vulnerable", lambda: client, 5)

        self.assertEqual(1, len(built))
        fixture_root = ROOT / case["versions"]["vulnerable"]["source_dir"]
        self.assertEqual(fixture_root.resolve(), built[0]["source_root"].resolve())
        self.assertEqual(
            {
                path.relative_to(fixture_root).as_posix()
                for path in fixture_root.rglob("*")
                if path.is_file()
            },
            set(built[0]["inventory_paths"]),
        )
        self.assertIn(case["affected"]["path"], built[0]["inventory_paths"])
        self.assertTrue(contexts)
        for context in contexts:
            for marker in label_markers:
                self.assertNotIn(marker, context)
            for label_field in ("expected", "affected", "ground_truth"):
                self.assertNotIn(f'"{label_field}":', context)
        self.assertTrue(record["agent_findings"])


class MetricTests(unittest.TestCase):
    """Honest confusion math, zero denominators, and full recomputability."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def _cases(self):
        second = synthetic_case("cwe-415-buffer-teardown-double-free", "CWE-415")
        second["affected"] = {
            "path": "src/buffer_teardown.c",
            "symbol": "buffer_teardown",
        }
        return [
            synthetic_case("cwe-416-session-release-uaf", "CWE-416"),
            second,
        ]

    def test_full_quadrant_counts_with_raw_and_verified_matrices(self):
        module = self.module
        first, second = self._cases()
        verified_hit = finding(first["cwe"], "tool-corroborated")
        buffer_identity = dict(
            finding(second["cwe"], "llm-candidate"),
            path="src/buffer_teardown.c",
            symbol="buffer_teardown",
        )
        results = {
            ("cwe-416-session-release-uaf", "vulnerable"): pipeline_result([verified_hit]),
            ("cwe-416-session-release-uaf", "fixed"): pipeline_result([]),
            ("cwe-415-buffer-teardown-double-free", "vulnerable"): pipeline_result([]),
            ("cwe-415-buffer-teardown-double-free", "fixed"): pipeline_result([buffer_identity]),
        }

        report = module.run_evaluation(
            self._cases(), lambda case, revision: results[(case["id"], revision)]
        )

        self.assertEqual({"tp": 1, "fp": 1, "fn": 1, "tn": 1}, report["confusion_matrix"])
        self.assertEqual(
            {"tp": 1, "fp": 0, "fn": 1, "tn": 2}, report["verified_confusion_matrix"]
        )
        self.assertEqual(0.5, report["precision"])
        self.assertEqual(0.5, report["recall"])
        self.assertEqual(0.5, report["f1"])
        self.assertEqual(0.5, report["pair_accuracy"])
        self.assertEqual(1.0, report["completed_coverage"])

    def test_fixed_side_report_splits_raw_and_verified_confusion(self):
        module = self.module
        only = self._cases()[0]
        results = {
            ("cwe-416-session-release-uaf", "vulnerable"): pipeline_result(
                [finding(only["cwe"], "llm-candidate")]
            ),
            ("cwe-416-session-release-uaf", "fixed"): pipeline_result(
                [finding(only["cwe"], "llm-candidate")]
            ),
        }

        report = module.run_evaluation(
            [only], lambda case, revision: results[(case["id"], revision)]
        )

        self.assertEqual({"tp": 1, "fp": 1, "fn": 0, "tn": 0}, report["confusion_matrix"])
        self.assertEqual(
            {"tp": 0, "fp": 0, "fn": 1, "tn": 1}, report["verified_confusion_matrix"]
        )
        self.assertFalse(report["cases"][0]["pair_correct"])
        self.assertIsNone(report["verified_precision"])

    def test_target_scoring_ignores_off_identity_findings(self):
        module = self.module
        only = self._cases()[0]
        off_identity = finding(only["cwe"], path="src/other.c")
        results = {
            ("cwe-416-session-release-uaf", "vulnerable"): pipeline_result([off_identity]),
            ("cwe-416-session-release-uaf", "fixed"): pipeline_result([]),
        }

        report = module.run_evaluation(
            [only], lambda case, revision: results[(case["id"], revision)]
        )

        self.assertEqual({"tp": 0, "fp": 0, "fn": 1, "tn": 1}, report["confusion_matrix"])
        self.assertEqual(
            0, report["cases"][0]["revisions"]["vulnerable"]["target_finding_count"]
        )

    def test_zero_denominators_are_null_with_diagnostics_not_perfect_scores(self):
        report = self.module.run_evaluation([], lambda case, revision: None)
        for key in (
            "precision",
            "recall",
            "f1",
            "verified_precision",
            "verified_recall",
            "verified_f1",
            "pair_accuracy",
            "completed_coverage",
        ):
            self.assertIsNone(report[key], key)
        self.assertIsNone(report["usage"]["calls_mean"])
        self.assertIsNone(report["latency_seconds"]["mean"])
        self.assertIsNone(report["cost_usd"])
        self.assertEqual(0.0, report["latency_seconds"]["total"])
        self.assertGreaterEqual(len(report["diagnostics"]), 8)

    def test_degraded_revisions_are_counted_as_uncompleted_not_as_quiet(self):
        module = self.module
        only = self._cases()[0]
        degraded = pipeline_result(
            status="llm-unavailable",
            usage={"calls": 0, "context_files": 0, "context_lines": 0, "output_bytes": 0},
        )
        results = {
            ("cwe-416-session-release-uaf", "vulnerable"): degraded,
            ("cwe-416-session-release-uaf", "fixed"): pipeline_result([]),
        }

        report = module.run_evaluation(
            [only], lambda case, revision: results[(case["id"], revision)]
        )

        self.assertFalse(report["cases"][0]["revisions"]["vulnerable"]["counted"])
        self.assertEqual({"tp": 0, "fp": 0, "fn": 0, "tn": 1}, report["confusion_matrix"])
        self.assertIsNone(report["precision"])
        self.assertIn("precision denominator is zero", report["diagnostics"])
        self.assertEqual(0.5, report["completed_coverage"])

    def test_unknown_status_and_red_line_violations_are_rejected(self):
        module = self.module
        only = self._cases()[0]
        with self.assertRaises(ValueError):
            module.run_evaluation(
                [only], lambda case, revision: pipeline_result(status="unheard-status")
            )
        with self.assertRaises(ValueError):
            module.run_evaluation(
                [only],
                lambda case, revision: pipeline_result(
                    findings=[dict(finding(only["cwe"]), automatic_repair=True)]
                ),
            )
        with self.assertRaises(ValueError):
            module.run_evaluation(
                [only],
                lambda case, revision: pipeline_result(
                    findings=[dict(finding(only["cwe"]), verification_state="confirmed-by-vibes")]
                ),
            )

    def test_revision_records_recompute_every_aggregate_metric(self):
        module = self.module
        cases = self._cases()
        results = {
            ("cwe-416-session-release-uaf", "vulnerable"): pipeline_result(
                [finding("CWE-416", "llm-candidate")], elapsed=1.25
            ),
            ("cwe-416-session-release-uaf", "fixed"): pipeline_result(
                [],
                elapsed=2.0,
                usage={"calls": 0, "context_files": 0, "context_lines": 0, "output_bytes": 0},
            ),
            ("cwe-415-buffer-teardown-double-free", "vulnerable"): pipeline_result(
                [finding("CWE-415", "tool-corroborated")],
                elapsed=3.5,
                status="llm-unavailable",
                usage={"calls": 2, "context_files": 1, "context_lines": 10, "output_bytes": 100},
            ),
            ("cwe-415-buffer-teardown-double-free", "fixed"): pipeline_result(
                [finding("CWE-415", "needs-human-review", symbol="buffer_teardown")],
                elapsed=4.0,
            ),
        }

        report = module.run_evaluation(
            cases, lambda case, revision: results[(case["id"], revision)]
        )

        records = [
            record
            for case in report["cases"]
            for record in case["revisions"].values()
        ]
        for record in records:
            self.assertEqual(
                {
                    "expected_vulnerable",
                    "counted",
                    "status",
                    "predicted_vulnerable",
                    "verified_hit",
                    "target_identity",
                    "target_finding_count",
                    "verified_target_finding_count",
                    "agent_findings",
                    "verification_state_counts",
                    "verified_only",
                    "usage",
                    "elapsed_seconds",
                    "snapshot_sha256",
                    "collaboration",
                },
                set(record),
            )

        def confusion(key):
            matrix = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
            for record in records:
                if not record["counted"]:
                    continue
                expected = record["expected_vulnerable"]
                predicted = record[key]
                matrix[
                    "tp" if expected and predicted
                    else "fn" if expected
                    else "fp" if predicted
                    else "tn"
                ] += 1
            return matrix

        self.assertEqual(report["confusion_matrix"], confusion("predicted_vulnerable"))
        self.assertEqual(report["verified_confusion_matrix"], confusion("verified_hit"))
        self.assertEqual(
            report["completed_coverage"],
            sum(record["counted"] for record in records) / len(records),
        )
        self.assertEqual(
            report["usage"]["calls_total"],
            sum(record["usage"]["calls"] for record in records),
        )
        self.assertEqual(
            report["usage"]["output_bytes_total"],
            sum(record["usage"]["output_bytes"] for record in records),
        )
        self.assertEqual(
            report["latency_seconds"]["total"],
            sum(record["elapsed_seconds"] for record in records),
        )
        self.assertEqual(
            report["latency_seconds"]["mean"],
            sum(record["elapsed_seconds"] for record in records) / len(records),
        )
        states = {}
        for record in records:
            for state, count in record["verification_state_counts"].items():
                states[state] = states.get(state, 0) + count
        self.assertEqual(report["verification_state_counts"], states)
        self.assertEqual(
            report["verified_only_total"],
            sum(record["verified_only"] for record in records),
        )
        self.assertIsNone(report["cost_usd"])
        self.assertIn("bytes-proxy", report["usage"]["token_accounting"])


class EndToEndTests(unittest.TestCase):
    """Fake-LLM end-to-end: the real pipeline produces every metric offline."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()
        cls.document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        cls.case = next(item for item in cls.document["cases"] if item["cwe"] == "CWE-415")

    def test_fake_llm_end_to_end_reports_the_full_metric_set(self):
        module = self.module
        case = self.case
        client = ScriptedAgentClient(honest_scripts(case))
        records = {
            "vulnerable": module.scan_revision(case, "vulnerable", lambda: client, 5),
            "fixed": module.scan_revision(case, "fixed", lambda: SilentAgentClient(), 5),
        }

        report = module.run_evaluation([case], lambda case, revision: records[revision])
        raw_cases = CASES_PATH.read_bytes()
        report = module.add_report_metadata(
            report, raw_cases, model="fake-cxx-model", provider="custom"
        )

        self.assertEqual(1, report["case_count"])
        self.assertEqual({"tp": 1, "fp": 0, "fn": 0, "tn": 1}, report["confusion_matrix"])
        self.assertEqual(1.0, report["precision"])
        self.assertEqual(1.0, report["recall"])
        self.assertEqual(1.0, report["f1"])
        self.assertEqual(1.0, report["pair_accuracy"])
        self.assertEqual(1.0, report["completed_coverage"])
        self.assertIsNone(report["cost_usd"])
        vulnerable = report["cases"][0]["revisions"]["vulnerable"]
        self.assertGreater(vulnerable["usage"]["calls"], 0)
        # time.monotonic() on Windows py3.11 has ~15.6ms granularity; a fast
        # fake-model run can legitimately measure 0.0. The script contract
        # is "finite non-negative", so assert against the contract.
        self.assertGreaterEqual(vulnerable["elapsed_seconds"], 0.0)
        self.assertEqual({"llm-candidate": 1}, vulnerable["verification_state_counts"])

        identity = report["identity"]
        self.assertEqual("fake-cxx-model", identity["model"])
        self.assertEqual("custom", identity["provider"])
        self.assertEqual("lima-cxx-agent-system-v1", identity["prompt"]["template"])
        self.assertEqual(
            hashlib.sha256(raw_cases).hexdigest(), identity["case_data_sha256"]
        )
        self.assertIn(
            "Synthetic and pinned pairs do not measure production detection capability",
            report["validity_boundaries"][0],
        )

    def test_identity_manifest_pins_model_prompt_and_pipeline_hashes(self):
        from lima.cxx_llm import _STEP_SCHEMA, _UNTRUSTED_DATA_RULE
        from lima.real_world_evaluation import analyzer_fingerprint

        manifest = self.module.build_identity_manifest(
            model="m", provider="custom", raw_case_data=b"{}"
        )
        self.assertEqual("m", manifest["model"])
        self.assertEqual("custom", manifest["provider"])
        self.assertEqual("lima-cxx-agent-system-v1", manifest["prompt"]["template"])
        self.assertEqual(
            hashlib.sha256(_STEP_SCHEMA.encode("utf-8")).hexdigest(),
            manifest["prompt"]["step_schema_sha256"],
        )
        self.assertEqual(
            hashlib.sha256(_UNTRUSTED_DATA_RULE.encode("utf-8")).hexdigest(),
            manifest["prompt"]["untrusted_data_rule_sha256"],
        )
        self.assertEqual(analyzer_fingerprint(), manifest["analyzer_fingerprint"])
        self.assertEqual(hashlib.sha256(b"{}").hexdigest(), manifest["case_data_sha256"])
        self.assertEqual(64, len(manifest["cxx_agent_pipeline_sha256"]))

    def test_fixture_digest_drift_is_rejected_before_any_scan(self):
        module = self.module
        case = json.loads(json.dumps(self.case))
        case["versions"]["vulnerable"]["content_sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "digest"):
            module.scan_revision(case, "vulnerable", lambda: SilentAgentClient(), 5)


class ProviderAndCliTests(unittest.TestCase):
    """The CLI builds the real client only when a provider is configured."""

    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_cli_exposes_exactly_the_eight_fixed_parameters(self):
        parser = self.module.build_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
            if option not in {"-h", "--help"}
        }
        self.assertEqual(
            {
                "--cases",
                "--case-id",
                "--provider-url",
                "--provider-key",
                "--model",
                "--output",
                "--timeout",
                "--max-cases",
            },
            options,
        )

    def test_case_selection_filters_by_id_and_bounds_case_count(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        selected = self.module.select_evaluation_cases(document, None, None)
        self.assertEqual(len(document["cases"]), len(selected))
        first = document["cases"][0]
        self.assertEqual(
            [first], self.module.select_evaluation_cases(document, first["id"], None)
        )
        self.assertEqual(2, len(self.module.select_evaluation_cases(document, None, 2)))
        with self.assertRaisesRegex(ValueError, "case id"):
            self.module.select_evaluation_cases(document, "missing-case", None)
        with self.assertRaisesRegex(ValueError, "max-cases"):
            self.module.select_evaluation_cases(document, None, 0)

    def test_build_provider_prefers_arguments_then_environment(self):
        module = self.module
        args = module.build_parser().parse_args([
            "--cases", "cases.json",
            "--output", "report.json",
            "--provider-url", "https://provider.example/v1",
            "--provider-key", "key-123",
            "--model", "model-x",
        ])
        resolved = module.build_provider(args, env={})
        self.assertEqual("custom", resolved["provider"])
        self.assertEqual("https://provider.example/v1", resolved["base_url"])
        self.assertEqual("key-123", resolved["api_key"])
        self.assertEqual("model-x", resolved["model"])

        args = module.build_parser().parse_args(
            ["--cases", "cases.json", "--output", "report.json"]
        )
        resolved = module.build_provider(args, env={
            "LIMA_LLM_BASE_URL": "https://env.example/v1",
            "LIMA_LLM_API_KEY": "env-key",
            "LIMA_LLM_MODEL": "env-model",
        })
        self.assertEqual("env-model", resolved["model"])

        resolved = module.build_provider(args, env={
            "LIMA_LLM_PROVIDER": "deepseek",
            "LIMA_DEEPSEEK_API_KEY": "ds-key",
            "LIMA_LLM_MODEL": "ds-model",
        })
        self.assertEqual("deepseek", resolved["provider"])
        self.assertEqual("https://api.deepseek.com", resolved["base_url"])

        args = module.build_parser().parse_args(
            ["--cases", "cases.json", "--output", "report.json", "--model", "only-model"]
        )
        with self.assertRaisesRegex(ValueError, "provider"):
            module.build_provider(args, env={})

    def test_client_factory_builds_the_real_strict_client_without_network(self):
        module = self.module
        factory = module.build_client_factory(
            {
                "provider": "custom",
                "base_url": "https://x",
                "api_key": "k",
                "model": "m",
                "headers": {},
            },
            timeout_seconds=7,
        )
        client = factory()
        self.assertEqual("m", client.model)
        self.assertEqual(7, client._timeout)

    def test_main_refuses_to_run_without_a_provider_before_any_scan(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        case_id = document["cases"][0]["id"]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "report.json"
            with mock.patch.dict("os.environ", {}, clear=True):
                with self.assertRaisesRegex(ValueError, "provider"):
                    self.module.main([
                        "--cases", str(CASES_PATH),
                        "--case-id", case_id,
                        "--output", str(output),
                    ])
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
