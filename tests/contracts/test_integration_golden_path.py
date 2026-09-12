"""IP-0014 Golden Path integration tests (Packet §D2, §D7, §D8).

Both aggregate fixtures are loaded at module import time, so this module is
RED (collection error on tests/contracts/fixtures/integration/) until the two
phase-2 deliverable fixtures exist — the frozen RED anchor face (4 code/fixture
deliverable files as a whole). Path A walks the chain profile -> aep -> vep ->
rvr -> workflow/execution -> CHAIN WorkflowSummary with every hop digest
recomputed by the IP-0001 codec; Path B walks legacy ReviewReport -> compat ->
EvidenceDomainBundle + LEGACY_AUDIT WorkflowSummary -> Finding round-trip.
Negative classes (>= 6) assert frozen error codes and field paths, zero new
codes. Scratch GREEN gate (PI-DR3) was proven before freezing.
"""

import copy
import hashlib
import json
import unittest
from pathlib import Path

import lima.contracts.aep as aep
import lima.contracts.evidence as evidence
import lima.contracts.execution as execution
import lima.contracts.profile as profile
import lima.contracts.rvr as rvr
import lima.contracts.summary as summary
import lima.contracts.vep as vep
import lima.contracts.workflow as workflow
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.compat import (
    domain_to_finding,
    finding_to_domain_bundle,
    review_report_to_workflow_summary,
)
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.models import Finding, ReviewReport

FIXTURES = Path(__file__).resolve().parent / "fixtures"
INTEGRATION = FIXTURES / "integration"
SCENARIOS = FIXTURES / "scenarios"

V4 = SchemaVersion(4, 0)

# Frozen byte digests of the two aggregate fixtures (P&V, codec-generated).
FROZEN_FIXTURE_SHA256 = {
    "golden_path_chain_v4_golden.json": (
        14968, "fd2ca2a798c07869e8e3bc0a97d946ef928334bec7953c491459e7ed39d04736"),
    "golden_path_legacy_audit_v4_golden.json": (
        4531, "984eca43f28a5bbd95bf5d25e707bfcbad18e6356d7290fe3c4da4cf698f13eb"),
}

CHAIN_FIXTURE = json.loads(
    (INTEGRATION / "golden_path_chain_v4_golden.json").read_text(encoding="utf-8"))
LEGACY_FIXTURE = json.loads(
    (INTEGRATION / "golden_path_legacy_audit_v4_golden.json").read_text(
        encoding="utf-8"))

CHAIN = CHAIN_FIXTURE["chain"]
CHAIN_DIGESTS = CHAIN_FIXTURE["content_digests"]

CHAIN_DECODERS = {
    "repository_profile": lambda p: profile.decode_profile_payload(
        p, schema_version=V4),
    "audit_evidence_package": lambda p: aep.decode_aep_payload(
        p, schema_version=V4),
    "vulnerability_evidence_package": lambda p: vep.decode_vep_payload(
        p, schema_version=V4),
    "repair_verification_report": lambda p: rvr.decode_rvr_payload(
        p, schema_version=V4),
    "plan": lambda p: execution.decode_plan_payload(p, schema_version=V4),
    "workflow": lambda p: workflow.decode_workflow_payload(
        p, schema_version=V4),
    "stage_attempt": lambda p: workflow.decode_stage_attempt_payload(
        p, schema_version=V4),
    "run_manifest": lambda p: execution.decode_run_manifest_payload(
        p, schema_version=V4),
    "security_outcome": lambda p: workflow.decode_security_outcome_payload(
        p, schema_version=V4),
    "workflow_summary": lambda p: summary.decode_workflow_summary_payload(
        p, schema_version=V4),
}

CHAIN_ENCODERS = {
    "repository_profile": lambda d: profile.encode_profile_payload(d),
    "audit_evidence_package": lambda d: aep.encode_aep_payload(d),
    "vulnerability_evidence_package": lambda d: vep.encode_vep_payload(d),
    "repair_verification_report": lambda d: rvr.encode_rvr_payload(d),
    "plan": lambda d: execution.encode_plan_payload(d),
    "workflow": lambda d: workflow.encode_workflow_payload(d),
    "stage_attempt": lambda d: workflow.encode_stage_attempt_payload(d),
    "run_manifest": lambda d: execution.encode_run_manifest_payload(d),
    "security_outcome": lambda d: workflow.encode_security_outcome_payload(d),
    "workflow_summary": lambda d: summary.encode_workflow_summary_payload(d),
}


def codec_digest(payload):
    return compute_content_digest(canonical_encode(payload))


class PathAChainGoldenPathTests(unittest.TestCase):
    """§D2 Path A: fixture-pinned chain walk with per-hop digest equality."""

    def test_fixture_bytes_pinned_and_codec_canonical(self):
        for name, (size, sha) in FROZEN_FIXTURE_SHA256.items():
            if name != "golden_path_chain_v4_golden.json":
                continue
            data = (INTEGRATION / name).read_bytes()
            self.assertEqual(len(data), size)
            self.assertEqual(
                hashlib.sha256(data).hexdigest(), sha)
        # The chain aggregate is codec-canonical: raw bytes == canonical form.
        raw = (INTEGRATION / "golden_path_chain_v4_golden.json").read_bytes()
        self.assertEqual(raw, canonical_encode(CHAIN_FIXTURE))

    def test_every_chain_artifact_decodes_via_module(self):
        for key, decode in CHAIN_DECODERS.items():
            with self.subTest(artifact=key):
                domain = decode(CHAIN[key])
                self.assertEqual(domain.schema_version, V4)

    def test_fixture_digests_recomputed_by_codec_for_every_artifact(self):
        for key, payload in CHAIN.items():
            with self.subTest(artifact=key):
                self.assertEqual(codec_digest(payload), CHAIN_DIGESTS[key])

    def test_hop_vep_references_aep_digest(self):
        aep_obj = aep.decode_aep_payload(
            CHAIN["audit_evidence_package"], schema_version=V4)
        vep_obj = vep.decode_vep_payload(
            CHAIN["vulnerability_evidence_package"], schema_version=V4)
        recomputed = codec_digest(aep.encode_aep_payload(aep_obj))
        self.assertEqual(recomputed, vep_obj.source_aep.content_digest)
        self.assertEqual(recomputed, CHAIN_DIGESTS["audit_evidence_package"])
        self.assertEqual(vep_obj.source_aep.artifact_id, "aep-0001")
        self.assertEqual(vep_obj.source_aep_revision, 1)

    def test_hop_rvr_references_vep_digest(self):
        vep_obj = vep.decode_vep_payload(
            CHAIN["vulnerability_evidence_package"], schema_version=V4)
        rvr_obj = rvr.decode_rvr_payload(
            CHAIN["repair_verification_report"], schema_version=V4)
        recomputed = codec_digest(vep.encode_vep_payload(vep_obj))
        self.assertEqual(recomputed, rvr_obj.source_vep.content_digest)
        self.assertEqual(recomputed, CHAIN_DIGESTS["vulnerability_evidence_package"])

    def test_hop_run_manifest_references_plan_workflow_and_stage_attempt(self):
        rm = execution.decode_run_manifest_payload(
            CHAIN["run_manifest"], schema_version=V4)
        self.assertEqual(
            rm.plan.content_digest, CHAIN_DIGESTS["plan"])
        self.assertEqual(rm.plan.artifact_id, "plan-0002")
        self.assertEqual(rm.plan_revision, 2)
        self.assertEqual(
            rm.workflow.content_digest, CHAIN_DIGESTS["workflow"])
        by_id = {link.artifact_id: link for link in rm.stage_attempts}
        self.assertEqual(
            by_id["attempt-profile-0001"].content_digest,
            CHAIN_DIGESTS["stage_attempt"])
        # The audit attempt is referenced by digest only in the frozen chain
        # (payload not among golden files): both spine artifacts agree on it.
        wf = workflow.decode_workflow_payload(CHAIN["workflow"], schema_version=V4)
        wf_by_id = {link.artifact_id: link for link in wf.stage_attempts}
        self.assertEqual(
            wf_by_id["attempt-audit-0001"].content_digest,
            by_id["attempt-audit-0001"].content_digest)

    def test_hop_security_outcome_references_workflow(self):
        so = workflow.decode_security_outcome_payload(
            CHAIN["security_outcome"], schema_version=V4)
        self.assertEqual(
            so.workflow.content_digest, CHAIN_DIGESTS["workflow"])
        self.assertEqual(so.workflow.artifact_id, "wf-0001")

    def test_summary_typed_links_all_resolved_to_chain_digests(self):
        ws = summary.decode_workflow_summary_payload(
            CHAIN["workflow_summary"], schema_version=V4)
        self.assertEqual(ws.source.value, "chain")
        self.assertEqual(ws.execution_status.value, "succeeded")
        self.assertEqual(ws.legacy_artifact_ids, ())
        self.assertEqual(
            ws.workflow.content_digest, CHAIN_DIGESTS["workflow"])
        self.assertEqual(
            ws.run_manifest.content_digest, CHAIN_DIGESTS["run_manifest"])
        self.assertEqual(
            ws.security_outcome.content_digest,
            CHAIN_DIGESTS["security_outcome"])
        by_artifact = {link.artifact_id: link for link in ws.stage_attempts}
        self.assertEqual(
            by_artifact["attempt-profile-0001"].content_digest,
            codec_digest(CHAIN["stage_attempt"]))
        evidence_by_kind = {link.kind.value: link for link in ws.evidence}
        self.assertEqual(
            evidence_by_kind["lima.vulnerability-evidence-package"]
            .content_digest,
            CHAIN_DIGESTS["vulnerability_evidence_package"])
        self.assertEqual(
            evidence_by_kind["lima.repair-verification-report"].content_digest,
            CHAIN_DIGESTS["repair_verification_report"])

    def test_chain_round_trip_preserves_every_payload(self):
        for key, payload in CHAIN.items():
            with self.subTest(artifact=key):
                domain = CHAIN_DECODERS[key](payload)
                self.assertEqual(CHAIN_ENCODERS[key](domain), payload)
                self.assertEqual(
                    codec_digest(CHAIN_ENCODERS[key](domain)),
                    CHAIN_DIGESTS[key])


class PathBLegacyAuditGoldenPathTests(unittest.TestCase):
    """§D2 Path B: legacy -> compat -> bundle + LEGACY_AUDIT summary -> back."""

    def test_fixture_bytes_pinned(self):
        name = "golden_path_legacy_audit_v4_golden.json"
        size, sha = FROZEN_FIXTURE_SHA256[name]
        data = (INTEGRATION / name).read_bytes()
        self.assertEqual(len(data), size)
        self.assertEqual(hashlib.sha256(data).hexdigest(), sha)
        # Legacy inputs carry float `confidence` (rejected by canonical JSON
        # v4.0): byte-pinned sorted-compact, per IP-0013 frozen precedent.
        self.assertEqual(
            data, json.dumps(LEGACY_FIXTURE, sort_keys=True,
                             separators=(",", ":"), ensure_ascii=False)
            .encode("utf-8"))

    def test_bundle_recomputed_from_legacy_finding(self):
        finding = Finding(**LEGACY_FIXTURE["inputs"]["findings"][0])
        bundle = finding_to_domain_bundle(finding)
        recomputed = evidence.encode_evidence_payload(bundle)
        self.assertEqual(
            recomputed, LEGACY_FIXTURE["outputs"]["evidence_domain_bundle"])
        self.assertEqual(
            codec_digest(recomputed),
            LEGACY_FIXTURE["content_digests"]["evidence_domain_bundle"])

    def test_summary_recomputed_from_review_report(self):
        meta = LEGACY_FIXTURE["inputs"]["review_report"]
        report = ReviewReport(
            repository=meta["repository"],
            pull_request=meta["pull_request"],
            summary=meta["summary"],
            risk=meta["risk"],
            findings=[Finding(**raw)
                      for raw in LEGACY_FIXTURE["inputs"]["findings"]],
            reviewer=meta["reviewer"],
        )
        ws = review_report_to_workflow_summary(report)
        self.assertEqual(ws.source.value, "legacy_audit")
        self.assertEqual(ws.execution_status.value, "succeeded")
        recomputed = summary.encode_workflow_summary_payload(ws)
        self.assertEqual(
            recomputed, LEGACY_FIXTURE["outputs"]["workflow_summary"])
        self.assertEqual(
            codec_digest(recomputed),
            LEGACY_FIXTURE["content_digests"]["workflow_summary"])

    def test_legacy_artifact_ids_sorted_dedup_and_typed_links_absent(self):
        meta = LEGACY_FIXTURE["inputs"]["review_report"]
        findings = [Finding(**raw)
                    for raw in LEGACY_FIXTURE["inputs"]["findings"]]
        report = ReviewReport(
            repository=meta["repository"],
            pull_request=meta["pull_request"],
            summary=meta["summary"],
            risk=meta["risk"],
            findings=[findings[1], findings[0], findings[1]],
            reviewer=meta["reviewer"],
        )
        ws = review_report_to_workflow_summary(report)
        fingerprints = [f.fingerprint for f in (findings[1], findings[0],
                                               findings[1])]
        self.assertEqual(list(ws.legacy_artifact_ids),
                         sorted(set(fingerprints)))
        # Structural None/() sentinels: no chain typed links on legacy path.
        self.assertIsNone(ws.workflow)
        self.assertIsNone(ws.run_manifest)
        self.assertIsNone(ws.security_outcome)
        self.assertEqual(ws.stage_attempts, ())
        self.assertEqual(ws.evidence, ())

    def test_round_trip_finding_fingerprint_identity_both_inputs(self):
        for raw in LEGACY_FIXTURE["inputs"]["findings"]:
            with self.subTest(fingerprint=raw["fingerprint"]):
                original = Finding(**raw)
                bundle = finding_to_domain_bundle(original)
                self.assertEqual(
                    domain_to_finding(bundle).fingerprint,
                    original.fingerprint)

    def test_output_digests_match_frozen_map(self):
        outputs = LEGACY_FIXTURE["outputs"]
        for key, payload in outputs.items():
            with self.subTest(output=key):
                self.assertEqual(
                    codec_digest(payload),
                    LEGACY_FIXTURE["content_digests"][key])


class GoldenPathNegativeTests(unittest.TestCase):
    """§D1 negative matrix (>= 6 classes), frozen codes and field paths only."""

    def assert_rejected(self, payload, decode, code, field_path):
        with self.assertRaises(ContractError) as ctx:
            decode(payload)
        self.assertEqual(ctx.exception.code, code)
        self.assertEqual(ctx.exception.field_path, field_path)

    def test_vep_source_aep_digest_bad_hex_rejected(self):
        payload = copy.deepcopy(
            CHAIN["vulnerability_evidence_package"])
        payload["source_aep"]["content_digest"] = "z" * 64
        self.assert_rejected(
            payload,
            lambda p: vep.decode_vep_payload(p, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE, "$.source_aep.content_digest")

    def test_vep_source_aep_digest_short_hex_rejected(self):
        payload = copy.deepcopy(
            CHAIN["vulnerability_evidence_package"])
        payload["source_aep"]["content_digest"] = "abcd"
        self.assert_rejected(
            payload,
            lambda p: vep.decode_vep_payload(p, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE, "$.source_aep.content_digest")

    def test_vep_source_aep_major_mismatch_rejected(self):
        payload = copy.deepcopy(
            CHAIN["vulnerability_evidence_package"])
        payload["source_aep"]["schema_version"] = "9.0"
        self.assert_rejected(
            payload,
            lambda p: vep.decode_vep_payload(p, schema_version=V4),
            ContractErrorCode.SCHEMA_UNKNOWN_MAJOR, "$.source_aep.major")

    def test_legacy_audit_summary_with_typed_link_rejected(self):
        payload = copy.deepcopy(
            LEGACY_FIXTURE["outputs"]["workflow_summary"])
        payload["workflow"] = {
            "artifact_id": "wf-0001",
            "content_digest": CHAIN_DIGESTS["workflow"],
            "kind": "lima.workflow",
            "schema_version": "4.0",
        }
        self.assert_rejected(
            payload,
            lambda p: summary.decode_workflow_summary_payload(
                p, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE, "$.workflow")

    def test_chain_summary_missing_run_manifest_rejected(self):
        payload = copy.deepcopy(CHAIN["workflow_summary"])
        del payload["run_manifest"]
        self.assert_rejected(
            payload,
            lambda p: summary.decode_workflow_summary_payload(
                p, schema_version=V4),
            ContractErrorCode.REQUIRED_FIELD_MISSING, "$.run_manifest")

    def test_cross_scenario_outcome_kind_evidence_mismatch_rejected(self):
        no_hypothesis = json.loads(
            (SCENARIOS / "scenario_no_hypothesis_v4.json").read_text(
                encoding="utf-8"))
        verified = json.loads(
            (SCENARIOS / "scenario_verified_v4.json").read_text(
                encoding="utf-8"))
        payload = copy.deepcopy(no_hypothesis["security_outcome"])
        payload["evidence"] = verified["security_outcome"]["evidence"]
        self.assert_rejected(
            payload,
            lambda p: workflow.decode_security_outcome_payload(
                p, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE, "$.kind")

    def test_legacy_audit_summary_empty_legacy_ids_rejected(self):
        payload = copy.deepcopy(
            LEGACY_FIXTURE["outputs"]["workflow_summary"])
        payload["legacy_artifact_ids"] = []
        self.assert_rejected(
            payload,
            lambda p: summary.decode_workflow_summary_payload(
                p, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE, "$.legacy_artifact_ids")


if __name__ == "__main__":
    unittest.main()
