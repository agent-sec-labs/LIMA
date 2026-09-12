"""Six-state scenario fixture tests (IP-0011 packet sections 1.2, 10 and 17).

Every test method first touches the scenario fixture files, so the module is RED
(FileNotFoundError on tests/contracts/fixtures/scenarios/) until the deliverables
exist. Validation path is single-answer: module decode full chain; the PR3
mini-validator is a supplementary structural pass only.
"""

import hashlib
import json
import unittest
from pathlib import Path

import lima.contracts.aep as aep
import lima.contracts.rvr as rvr
import lima.contracts.summary as summary
import lima.contracts.vep as vep
import lima.contracts.workflow as workflow
from lima.contracts.codec import compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError
from tests.contracts.test_schema_export import load_schema, mini_validate

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCENARIOS = FIXTURES / "scenarios"
UPSTREAM = FIXTURES

V4 = SchemaVersion(4, 0)

FROZEN_SCENARIO_DIGESTS = {
    "scenario_no_hypothesis_v4.json": (
        5179, "061dcccd3b39889ddfd6b79e5f7f9333247a74fb20969430cf4b6109e2c74b3e"),
    "scenario_blocked_v4.json": (
        1878, "d832ea8ac90491094892d63eee480e47cb313095153953debd6c5b4186619de9"),
    "scenario_refuted_v4.json": (
        3117, "212e4a8d27430b0b3113e9bbd14e50ab0cc89fbaf2be956a5ee791613487af84"),
    "scenario_verified_v4.json": (
        3042, "b05d365cac98386436d36b53799c951ea4c28b5b3c818bd1cbc392371d0ccbb0"),
    "scenario_unsupported_v4.json": (
        3035, "f5278ad78d684648c73f163499fede835a7c11b154c5565a0dbc0748436c9fe6"),
    "scenario_verified_patch_v4.json": (
        3679, "8887c5f235f69f6884ba6c9189386486e6c105c578a343690f4835d0e4136705"),
}

BUNDLE_KEYS = {
    "scenario_no_hypothesis_v4.json": ["aep", "security_outcome", "workflow_summary"],
    "scenario_blocked_v4.json": ["stage_attempt", "failure_report", "security_outcome",
                                 "workflow_summary"],
    "scenario_refuted_v4.json": ["vep", "security_outcome", "workflow_summary"],
    "scenario_verified_v4.json": ["vep", "security_outcome", "workflow_summary"],
    "scenario_unsupported_v4.json": ["vep", "security_outcome", "workflow_summary"],
    "scenario_verified_patch_v4.json": ["rvr", "security_outcome", "workflow_summary"],
}

DECODERS = {
    "aep": lambda p: aep.decode_aep_payload(p, schema_version=V4),
    "vep": lambda p: vep.decode_vep_payload(p, schema_version=V4),
    "rvr": lambda p: rvr.decode_rvr_payload(p, schema_version=V4),
    "stage_attempt": lambda p: workflow.decode_stage_attempt_payload(p, schema_version=V4),
    "security_outcome": lambda p: workflow.decode_security_outcome_payload(
        p, schema_version=V4),
    "workflow_summary": lambda p: summary.decode_workflow_summary_payload(
        p, schema_version=V4),
    "failure_report": lambda p: summary.decode_failure_report_payload(p, schema_version=V4),
}

SCHEMA_FOR_KEY = {
    "aep": "lima.audit-evidence-package",
    "vep": "lima.vulnerability-evidence-package",
    "rvr": "lima.repair-verification-report",
    "stage_attempt": "lima.stage-attempt",
    "security_outcome": "lima.security-outcome",
    "workflow_summary": "lima.workflow-summary",
    "failure_report": "lima.failure-report",
}

STATE_MARKERS = {
    "scenario_no_hypothesis_v4.json": {
        ("aep", "audit_outcome"): "no_actionable_hypothesis",
        ("security_outcome", "kind"): "no_actionable_hypothesis",
        ("workflow_summary", "execution_status"): "succeeded",
    },
    "scenario_blocked_v4.json": {
        ("stage_attempt", "status"): "blocked",
        ("failure_report", "failure_kind"): "environment",
        ("failure_report", "disposition"): "transient",
        ("security_outcome", "kind"): "mining_blocked_environment",
        ("workflow_summary", "execution_status"): "failed",
    },
    "scenario_refuted_v4.json": {
        ("vep", "verification_verdict"): "refuted_scope",
        ("security_outcome", "kind"): "hypothesis_not_reproduced",
        ("workflow_summary", "execution_status"): "failed",
    },
    "scenario_verified_v4.json": {
        ("vep", "verification_verdict"): "verified",
        ("security_outcome", "kind"): "vulnerability_verified",
        ("workflow_summary", "execution_status"): "succeeded",
    },
    "scenario_unsupported_v4.json": {
        ("security_outcome", "kind"): "repair_unsupported",
        ("workflow_summary", "execution_status"): "failed",
    },
    "scenario_verified_patch_v4.json": {
        ("security_outcome", "kind"): "verified_patch",
        ("workflow_summary", "execution_status"): "succeeded",
    },
}

UPSTREAM_GOLDENS = {
    "workflow_v4_golden.json", "audit_evidence_package_v4_golden.json",
    "vulnerability_evidence_package_v4_golden.json",
    "repair_verification_report_v4_golden.json", "security_outcome_v4_golden.json",
    "workflow_summary_v4_golden.json", "run_manifest_v4_golden.json",
    "stage_attempt_v4_golden.json", "stage_attempt_alternates_v4_golden.json",
    "failure_report_v4_golden.json",
}


def load_scenario(name):
    return json.loads((SCENARIOS / name).read_text(encoding="utf-8"))


def golden_digest_map():
    digests = {}
    for name in UPSTREAM_GOLDENS:
        payload = json.loads((UPSTREAM / name).read_text(encoding="utf-8"))
        entries = payload if isinstance(payload, list) else [payload]
        for entry in entries:
            digests[compute_content_digest(entry)] = name
    return digests


def collect_links(node, found):
    if isinstance(node, dict):
        if {"kind", "artifact_id", "content_digest"} <= set(node):
            found.append(node)
        for value in node.values():
            collect_links(value, found)
    elif isinstance(node, list):
        for item in node:
            collect_links(item, found)


class ScenarioInventoryTests(unittest.TestCase):
    def test_six_scenario_files_exist_with_frozen_digests(self):
        for name, (size, digest) in sorted(FROZEN_SCENARIO_DIGESTS.items()):
            data = (SCENARIOS / name).read_bytes()
            self.assertEqual(len(data), size, name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)

    def test_bundle_keys_match_frozen_map(self):
        for name, keys in BUNDLE_KEYS.items():
            bundle = load_scenario(name)
            self.assertEqual(sorted(bundle.keys()), sorted(keys), name)

    def test_verified_patch_bundle_is_pure_golden_reuse(self):
        bundle = load_scenario("scenario_verified_patch_v4.json")
        for key, golden in (("rvr", "repair_verification_report_v4_golden.json"),
                            ("security_outcome", "security_outcome_v4_golden.json"),
                            ("workflow_summary", "workflow_summary_v4_golden.json")):
            golden_payload = json.loads((UPSTREAM / golden).read_text(encoding="utf-8"))
            self.assertEqual(bundle[key], golden_payload, key)

    def test_all_bundles_decode_via_modules(self):
        for name in FROZEN_SCENARIO_DIGESTS:
            bundle = load_scenario(name)
            for key, payload in bundle.items():
                try:
                    DECODERS[key](payload)
                except ContractError as err:
                    self.fail(f"{name}.{key}: {err.code} {err.field_path}")

    def test_digest_chains_recompute_via_codec(self):
        for name in FROZEN_SCENARIO_DIGESTS:
            bundle = load_scenario(name)
            internal = {compute_content_digest(p): key for key, p in bundle.items()}
            for key, payload in bundle.items():
                links = []
                collect_links(payload, links)
                for link in links:
                    digest = link["content_digest"]
                    self.assertTrue(digest in internal or
                                    digest in golden_digest_map(),
                                    f"{name}.{key}: dangling link {link['artifact_id']}")

    def test_upstream_anchors_match_existing_goldens(self):
        upstream = golden_digest_map()
        for name in FROZEN_SCENARIO_DIGESTS:
            bundle = load_scenario(name)
            links = []
            for payload in bundle.values():
                collect_links(payload, links)
            anchored = [lk for lk in links if lk["content_digest"] in upstream]
            self.assertTrue(anchored, name)

    def test_state_markers_match_frozen_table(self):
        for name, markers in STATE_MARKERS.items():
            bundle = load_scenario(name)
            for (key, field), expected in markers.items():
                self.assertEqual(bundle[key][field], expected, f"{name}.{key}.{field}")

    def test_summary_execution_status_polarity(self):
        polarity = {"succeeded": {"scenario_no_hypothesis_v4.json",
                                  "scenario_verified_v4.json",
                                  "scenario_verified_patch_v4.json"},
                    "failed": {"scenario_blocked_v4.json", "scenario_refuted_v4.json",
                               "scenario_unsupported_v4.json"}}
        for status, names in polarity.items():
            for name in names:
                bundle = load_scenario(name)
                self.assertEqual(
                    bundle["workflow_summary"]["execution_status"], status, name)


class _StateTestBase:
    scenario_name = None

    def bundle(self):
        return load_scenario(self.scenario_name)

    def test_decode_and_markers(self):
        bundle = self.bundle()
        for key, payload in bundle.items():
            DECODERS[key](payload)
        for (key, field), expected in STATE_MARKERS[self.scenario_name].items():
            self.assertEqual(bundle[key][field], expected, f"{key}.{field}")

    def test_round_trip_preserves_payloads(self):
        bundle = self.bundle()
        for key, payload in bundle.items():
            decoded = DECODERS[key](payload)
            self.assertEqual(decoded.to_dict(), payload, key)

    def test_schema_structural_pass(self):
        bundle = self.bundle()
        for key, payload in bundle.items():
            schema = load_schema(SCHEMA_FOR_KEY[key])
            errors = mini_validate(payload, schema)
            self.assertEqual(errors, [], f"{key}: {errors[:3]}")


class NoHypothesisTests(_StateTestBase, unittest.TestCase):
    scenario_name = "scenario_no_hypothesis_v4.json"

    def test_eligibility_empty_and_aep_evidence_link(self):
        bundle = self.bundle()
        self.assertEqual(bundle["aep"]["mining_eligible_hypothesis_ids"], [])
        so_evidence = bundle["security_outcome"]["evidence"]
        self.assertEqual([lk["kind"] for lk in so_evidence],
                         ["lima.audit-evidence-package"])
        self.assertEqual(so_evidence[0]["content_digest"],
                         compute_content_digest(bundle["aep"]))


class BlockedTests(_StateTestBase, unittest.TestCase):
    scenario_name = "scenario_blocked_v4.json"

    def test_attempt_failure_kind_coupling(self):
        bundle = self.bundle()
        self.assertEqual(bundle["stage_attempt"]["status"], "blocked")
        self.assertEqual(bundle["stage_attempt"]["failure_kind"], "environment")
        self.assertIsNone(bundle["stage_attempt"]["skip_reason"])


class RefutedTests(_StateTestBase, unittest.TestCase):
    scenario_name = "scenario_refuted_v4.json"

    def test_refutation_scope_required(self):
        bundle = self.bundle()
        self.assertEqual(bundle["vep"]["verification_verdict"], "refuted_scope")
        self.assertIsInstance(bundle["vep"]["refutation_scope"], str)
        self.assertTrue(bundle["vep"]["refutation_scope"])
        polarities = [(r["level"], r["polarity"]) for r in bundle["vep"]["evidence"]]
        self.assertIn(("D4", "refutes"), polarities)


class VerifiedTests(_StateTestBase, unittest.TestCase):
    scenario_name = "scenario_verified_v4.json"

    def test_vep_is_golden_unchanged(self):
        golden = json.loads((UPSTREAM / "vulnerability_evidence_package_v4_golden.json")
                            .read_text(encoding="utf-8"))
        self.assertEqual(self.bundle()["vep"], golden)


class UnsupportedTests(_StateTestBase, unittest.TestCase):
    scenario_name = "scenario_unsupported_v4.json"

    def test_vep_required_rvr_forbidden(self):
        bundle = self.bundle()
        kinds = [lk["kind"] for lk in bundle["security_outcome"]["evidence"]]
        self.assertIn("lima.vulnerability-evidence-package", kinds)
        self.assertNotIn("lima.repair-verification-report", kinds)


class VerifiedPatchTests(_StateTestBase, unittest.TestCase):
    scenario_name = "scenario_verified_patch_v4.json"

    def test_rvr_contains_verified_patch_candidate(self):
        verdicts = [c["verdict"] for c in self.bundle()["rvr"]["candidates"]]
        self.assertIn("verified_patch", verdicts)


if __name__ == "__main__":
    unittest.main()
