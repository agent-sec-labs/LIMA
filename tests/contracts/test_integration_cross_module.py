"""IP-0014 cross-module integration matrix tests (Packet §D1 M1..M9, §D8).

Organized as chain segments (M1..M7) plus two cross-cutting slices (M8 codec
across the 13 modules + compat frozen face, M9 version compatibility matrix).
Every test consumes real frozen fixtures (existing goldens/scenarios/compat
fixtures) and every digest is recomputed by the IP-0001 codec — no hand-written
digests. Together with test_integration_golden_path.py this module is part of
the phase-2 deliverable anchor face (4 code/fixture files as a whole).
"""

import hashlib
import json
import unittest
from pathlib import Path

import lima.contracts.aep as aep
import lima.contracts.compat as compat
import lima.contracts.evidence as evidence
import lima.contracts.execution as execution
import lima.contracts.manifests as manifests
import lima.contracts.profile as profile
import lima.contracts.rvr as rvr
import lima.contracts.summary as summary
import lima.contracts.vep as vep
import lima.contracts.workflow as workflow
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.models import Finding, ReviewReport

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SCENARIOS = FIXTURES / "scenarios"
SCHEMAS = Path(__file__).resolve().parents[2] / "schemas" / "v4"

V4 = SchemaVersion(4, 0)
FUTURE_MINOR = SchemaVersion(4, 1)


def load(name):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def load_scenario(name):
    return json.loads((SCENARIOS / name).read_text(encoding="utf-8"))


def codec_digest(payload):
    return compute_content_digest(canonical_encode(payload))


GOLDEN = {
    name: load(f"{name}_v4_golden.json")
    for name in (
        "repository_profile", "evidence_domain_bundle",
        "audit_evidence_package", "vulnerability_evidence_package",
        "repair_verification_report", "workflow", "stage_attempt",
        "security_outcome", "run_manifest", "workflow_summary",
        "failure_report", "task_manifest", "tool_bundle",
        "dependency_manifest", "sandbox_run", "plan_full_chain",
        "legacy_finding_domain",
    )
}

# Frozen six-scenario kind<->source mapping (IP-0011 §17 markers; §D1 M7).
SCENARIO_MARKERS = {
    "scenario_no_hypothesis_v4.json": (
        "no_actionable_hypothesis", "succeeded"),
    "scenario_blocked_v4.json": ("mining_blocked_environment", "failed"),
    "scenario_refuted_v4.json": ("hypothesis_not_reproduced", "failed"),
    "scenario_verified_v4.json": ("vulnerability_verified", "succeeded"),
    "scenario_unsupported_v4.json": ("repair_unsupported", "failed"),
    "scenario_verified_patch_v4.json": ("verified_patch", "succeeded"),
}


class M1LegacyEntryTests(unittest.TestCase):
    """M1: models (read-only) -> compat -> evidence bundle."""

    def test_finding_to_bundle_structure_identity_and_digest(self):
        finding = Finding(**load("legacy_finding_full.json"))
        bundle = compat.finding_to_domain_bundle(finding)
        # 1 Signal / 1 SecurityIssue / 1+N EvidenceRecord, subject binding:
        # the primary `evidence` string binds the Signal, and each legacy
        # evidence_records entry binds the SecurityIssue (N = 2 here).
        self.assertEqual(len(bundle.signals), 1)
        self.assertEqual(len(bundle.security_issues), 1)
        self.assertEqual(len(bundle.evidence), 3)
        self.assertEqual(
            bundle.evidence[0].subject_kind.value, "signal")
        self.assertEqual(
            bundle.evidence[1].subject_kind.value, "security_issue")
        self.assertEqual(
            bundle.evidence[2].subject_kind.value, "security_issue")
        # Identity derivation == legacy material digest.
        material = (f"{finding.rule_id}\0{finding.path}\0{finding.line}\0"
                    f"{finding.evidence}")
        expected = hashlib.sha256(material.encode("utf-8")).hexdigest()
        self.assertEqual(bundle.signals[0].fingerprint, expected)
        self.assertEqual(bundle.security_issues[0].identity_digest, expected)
        # Round-trip fingerprint identity.
        self.assertEqual(
            compat.domain_to_finding(bundle).fingerprint, finding.fingerprint)
        # Bundle payload digest recomputed by codec against the compat golden.
        payload = evidence.encode_evidence_payload(bundle)
        self.assertEqual(payload, GOLDEN["legacy_finding_domain"])
        self.assertEqual(
            codec_digest(payload), codec_digest(GOLDEN["legacy_finding_domain"]))


class M2LegacyAuditEndpointTests(unittest.TestCase):
    """M2: models -> compat -> summary (LEGACY_AUDIT terminal)."""

    def test_report_to_summary_shape(self):
        findings = [Finding(**load("legacy_finding_full.json")),
                    Finding(**load("legacy_finding_minimal.json"))]
        report = ReviewReport(
            repository="lima", pull_request=145, summary="s", risk="high",
            findings=[findings[1], findings[0], findings[1]])
        ws = compat.review_report_to_workflow_summary(report)
        self.assertEqual(ws.source.value, "legacy_audit")
        self.assertEqual(ws.execution_status.value, "succeeded")
        ids = [f.fingerprint for f in (findings[1], findings[0], findings[1])]
        self.assertEqual(list(ws.legacy_artifact_ids), sorted(set(ids)))
        # Typed links structurally None/() on the legacy path.
        self.assertIsNone(ws.workflow)
        self.assertIsNone(ws.run_manifest)
        self.assertIsNone(ws.security_outcome)
        self.assertEqual(ws.stage_attempts, ())
        self.assertEqual(ws.evidence, ())


class M3StaticDomainIntoAuditTests(unittest.TestCase):
    """M3: evidence(bundle) -> aep (embedded bundle + profile reference)."""

    def test_aep_embeds_bundle_and_references_profile(self):
        aep_obj = aep.decode_aep_payload(
            GOLDEN["audit_evidence_package"], schema_version=V4)
        bundle_obj = evidence.decode_evidence_payload(
            GOLDEN["evidence_domain_bundle"], schema_version=V4)
        self.assertEqual(aep_obj.evidence, bundle_obj)
        self.assertEqual(
            evidence.encode_evidence_payload(aep_obj.evidence),
            GOLDEN["evidence_domain_bundle"])
        self.assertEqual(
            list(aep_obj.repository_profile_artifact_ids), ["profile-0001"])
        # The referenced repository profile decodes from the frozen golden.
        profile_obj = profile.decode_profile_payload(
            GOLDEN["repository_profile"], schema_version=V4)
        self.assertEqual(profile_obj.schema_version, V4)


class M4AuditIntoVerificationTests(unittest.TestCase):
    """M4: aep -> vep with digest-chain cross-check."""

    def test_vep_source_aep_digest_chain(self):
        for payload in (GOLDEN["vulnerability_evidence_package"],
                        load_scenario("scenario_verified_v4.json")["vep"]):
            with self.subTest(artifact="vep"):
                vep_obj = vep.decode_vep_payload(payload, schema_version=V4)
                aep_obj = aep.decode_aep_payload(
                    GOLDEN["audit_evidence_package"], schema_version=V4)
                recomputed = codec_digest(
                    aep.encode_aep_payload(aep_obj))
                self.assertEqual(
                    recomputed, vep_obj.source_aep.content_digest)
                self.assertEqual(vep_obj.source_aep_revision, 1)


class M5VerificationIntoRepairTests(unittest.TestCase):
    """M5: vep -> rvr (digest chain + per-candidate gate matrix)."""

    def test_rvr_source_vep_digest_chain_and_gates(self):
        vep_obj = vep.decode_vep_payload(
            GOLDEN["vulnerability_evidence_package"], schema_version=V4)
        rvr_obj = rvr.decode_rvr_payload(
            GOLDEN["repair_verification_report"], schema_version=V4)
        self.assertEqual(
            codec_digest(vep.encode_vep_payload(vep_obj)),
            rvr_obj.source_vep.content_digest)
        self.assertEqual(rvr_obj.source_vep.artifact_id, "vep-0001")
        # Candidate references the verified hypothesis via source vep.
        self.assertEqual(vep_obj.hypothesis_id, "hypothesis-0001")
        self.assertGreaterEqual(len(rvr_obj.candidates), 1)
        for candidate in rvr_obj.candidates:
            gate_kinds = {gate.gate.value for gate in candidate.gates}
            self.assertEqual(
                gate_kinds,
                {"functional_preservation", "security_preservation"})


class M6ExecutionSpineTests(unittest.TestCase):
    """M6: workflow + execution orchestration and ArtifactLink forms."""

    def test_spine_links_consistent_across_workflow_run_manifest_outcome(self):
        wf = workflow.decode_workflow_payload(
            GOLDEN["workflow"], schema_version=V4)
        rm = execution.decode_run_manifest_payload(
            GOLDEN["run_manifest"], schema_version=V4)
        so = workflow.decode_security_outcome_payload(
            GOLDEN["security_outcome"], schema_version=V4)
        plan = execution.decode_plan_payload(
            GOLDEN["plan_full_chain"], schema_version=V4)
        self.assertEqual(
            [link.artifact_id for link in wf.stage_attempts],
            [link.artifact_id for link in rm.stage_attempts])
        self.assertEqual(
            [link.artifact_id for link in wf.stage_attempts],
            ["attempt-audit-0001", "attempt-profile-0001"])
        for link in wf.stage_attempts:
            self.assertEqual(link.kind.value, "lima.stage-attempt")
        # Workflow digest agreed by run manifest and security outcome.
        self.assertEqual(
            rm.workflow.content_digest, so.workflow.content_digest)
        self.assertEqual(
            rm.workflow.content_digest, codec_digest(GOLDEN["workflow"]))
        # Plan/RunManifest ArtifactLink reference form.
        self.assertEqual(rm.plan.kind.value, "lima.plan")
        self.assertEqual(rm.plan.artifact_id, "plan-0002")
        self.assertEqual(rm.plan_revision, plan.revision)
        self.assertEqual(
            rm.plan.content_digest, codec_digest(GOLDEN["plan_full_chain"]))
        # Workflow orchestration covers the planned spine stages.
        self.assertEqual(
            GOLDEN["plan_full_chain"]["planned_stages"],
            ["profile", "audit", "mine", "repair", "summarize"])


class M7ChainEndpointScenariosTests(unittest.TestCase):
    """M7: chain endpoint — six scenarios, kind<->source mapping per scenario."""

    def test_six_scenarios_summary_outcome_mapping_and_chain_shape(self):
        for name, (kind, status) in SCENARIO_MARKERS.items():
            with self.subTest(scenario=name):
                bundle = load_scenario(name)
                so = workflow.decode_security_outcome_payload(
                    bundle["security_outcome"], schema_version=V4)
                ws = summary.decode_workflow_summary_payload(
                    bundle["workflow_summary"], schema_version=V4)
                self.assertEqual(so.kind.value, kind)
                self.assertEqual(ws.execution_status.value, status)
                self.assertEqual(ws.source.value, "chain")
                self.assertEqual(ws.legacy_artifact_ids, ())
                # Typed links: workflow/security_outcome always present on the
                # chain path; run_manifest only once a spine run completed
                # (verified_patch); legacy links structurally absent.
                self.assertIsNotNone(ws.workflow)
                self.assertIsNotNone(ws.security_outcome)
                if name == "scenario_verified_patch_v4.json":
                    self.assertIsNotNone(ws.run_manifest)
                else:
                    self.assertIsNone(ws.run_manifest)
                # Summary evidence links: only verified_patch carries the
                # vep+rvr pair; all other scenarios are structurally empty.
                # The vep link itself lives on the security outcome.
                actual = sorted(link.kind.value for link in ws.evidence)
                if name == "scenario_verified_patch_v4.json":
                    self.assertEqual(actual, [
                        "lima.repair-verification-report",
                        "lima.vulnerability-evidence-package"])
                else:
                    self.assertEqual(actual, [])
                so_evidence_kinds = sorted(
                    link.kind.value for link in so.evidence)
                if "vep" in bundle:
                    self.assertIn(
                        "lima.vulnerability-evidence-package", so_evidence_kinds)
                if "rvr" in bundle:
                    self.assertIn(
                        "lima.repair-verification-report", so_evidence_kinds)
                elif "vep" in bundle:
                    self.assertNotIn(
                        "lima.repair-verification-report", so_evidence_kinds)
                # security_outcome payload decodes and matches its summary link.
                self.assertEqual(
                    codec_digest(bundle["security_outcome"]),
                    ws.security_outcome.content_digest)


class M8CodecAcrossModulesTests(unittest.TestCase):
    """M8: codec across all 13 modules + compat; schema_name vs schemas/v4."""

    # 12 domain payloads with a schemas/v4 binding + 4 manifest payloads that
    # are module-enforced only (matrix rows = 13 = these 12 + envelope).
    SCHEMA_BOUNDED_NAMES = {
        "lima.repository-profile", "lima.evidence-domain",
        "lima.audit-evidence-package", "lima.vulnerability-evidence-package",
        "lima.repair-verification-report", "lima.workflow",
        "lima.stage-attempt", "lima.security-outcome", "lima.run-manifest",
        "lima.plan", "lima.workflow-summary", "lima.failure-report",
    }
    SCHEMA_PAYLOAD_ROUNDTRIPS = (
        ("lima.repository-profile", "repository_profile",
         lambda p: profile.decode_profile_payload(p, schema_version=V4),
         profile.encode_profile_payload),
        ("lima.evidence-domain", "evidence_domain_bundle",
         lambda p: evidence.decode_evidence_payload(p, schema_version=V4),
         evidence.encode_evidence_payload),
        ("lima.audit-evidence-package", "audit_evidence_package",
         lambda p: aep.decode_aep_payload(p, schema_version=V4),
         aep.encode_aep_payload),
        ("lima.vulnerability-evidence-package",
         "vulnerability_evidence_package",
         lambda p: vep.decode_vep_payload(p, schema_version=V4),
         vep.encode_vep_payload),
        ("lima.repair-verification-report", "repair_verification_report",
         lambda p: rvr.decode_rvr_payload(p, schema_version=V4),
         rvr.encode_rvr_payload),
        ("lima.workflow", "workflow",
         lambda p: workflow.decode_workflow_payload(p, schema_version=V4),
         workflow.encode_workflow_payload),
        ("lima.stage-attempt", "stage_attempt",
         lambda p: workflow.decode_stage_attempt_payload(p, schema_version=V4),
         workflow.encode_stage_attempt_payload),
        ("lima.security-outcome", "security_outcome",
         lambda p: workflow.decode_security_outcome_payload(p, schema_version=V4),
         workflow.encode_security_outcome_payload),
        ("lima.run-manifest", "run_manifest",
         lambda p: execution.decode_run_manifest_payload(p, schema_version=V4),
         execution.encode_run_manifest_payload),
        ("lima.plan", "plan_full_chain",
         lambda p: execution.decode_plan_payload(p, schema_version=V4),
         execution.encode_plan_payload),
        ("lima.workflow-summary", "workflow_summary",
         lambda p: summary.decode_workflow_summary_payload(p, schema_version=V4),
         summary.encode_workflow_summary_payload),
        ("lima.failure-report", "failure_report",
         lambda p: summary.decode_failure_report_payload(p, schema_version=V4),
         summary.encode_failure_report_payload),
        ("lima.task-manifest", "task_manifest",
         lambda p: manifests.decode_task_manifest_payload(p, schema_version=V4),
         manifests.encode_task_manifest_payload),
        ("lima.tool-bundle", "tool_bundle",
         lambda p: manifests.decode_tool_bundle_payload(p, schema_version=V4),
         manifests.encode_tool_bundle_payload),
        ("lima.dependency-manifest", "dependency_manifest",
         lambda p: manifests.decode_dependency_manifest_payload(
             p, schema_version=V4),
         manifests.encode_dependency_manifest_payload),
        ("lima.sandbox-run", "sandbox_run",
         lambda p: manifests.decode_sandbox_run_payload(p, schema_version=V4),
         manifests.encode_sandbox_run_payload),
    )

    def test_schema_names_cover_matrix_and_roundtrip_digests_stable(self):
        matrix = json.loads(
            (SCHEMAS / "version_compatibility_matrix.json").read_text(
                encoding="utf-8"))
        matrix_names = {row["schema_name"] for row in matrix["schemas"]}
        self.assertEqual(len(matrix["schemas"]), 13)
        self.assertIn("lima.artifact-envelope", matrix_names)
        self.assertEqual(
            matrix_names,
            self.SCHEMA_BOUNDED_NAMES | {"lima.artifact-envelope"})
        for name in self.SCHEMA_BOUNDED_NAMES:
            self.assertTrue((SCHEMAS / f"{name}.json").exists())
        for name, key, decode, encode in self.SCHEMA_PAYLOAD_ROUNDTRIPS:
            with self.subTest(schema=name):
                payload = GOLDEN[key]
                domain = decode(payload)
                re_encoded = encode(domain)
                self.assertEqual(re_encoded, payload)
                self.assertEqual(
                    codec_digest(re_encoded), codec_digest(payload))


class M9MatrixCompatSliceTests(unittest.TestCase):
    """M9: version_compatibility_matrix behavior rows + compat regression."""

    def test_matrix_global_behaviors_match_module_behavior(self):
        matrix = json.loads(
            (SCHEMAS / "version_compatibility_matrix.json").read_text(
                encoding="utf-8"))
        behaviors = {row["id"]: row for row in matrix["global_behaviors"]}
        self.assertEqual(matrix["current_minor"], "4.0")
        # future_minor_extension_roundtrip: unknown fields preserved.
        payload = dict(GOLDEN["vulnerability_evidence_package"])
        payload["future_extension_probe"] = {"kept": True}
        decoded = vep.decode_vep_payload(
            payload, schema_version=FUTURE_MINOR)
        re_encoded = vep.encode_vep_payload(decoded)
        self.assertEqual(re_encoded["future_extension_probe"], {"kept": True})
        self.assertIsNone(
            behaviors["future_minor_extension_roundtrip"]["code"])
        # current_minor_unknown_field: reject with UNKNOWN_FIELD.
        probe = dict(GOLDEN["vulnerability_evidence_package"])
        probe["future_extension_probe"] = {"kept": True}
        with self.assertRaises(ContractError) as ctx:
            vep.decode_vep_payload(probe, schema_version=V4)
        self.assertEqual(
            ctx.exception.code, ContractErrorCode.UNKNOWN_FIELD)
        self.assertEqual(
            behaviors["current_minor_unknown_field"]["code"],
            "UNKNOWN_FIELD")
        # unknown_major: reject with SCHEMA_UNKNOWN_MAJOR.
        with self.assertRaises(ContractError) as ctx:
            vep.decode_vep_payload(
                GOLDEN["vulnerability_evidence_package"],
                schema_version=SchemaVersion(9, 0))
        self.assertEqual(
            ctx.exception.code, ContractErrorCode.SCHEMA_UNKNOWN_MAJOR)
        self.assertEqual(
            behaviors["unknown_major"]["code"], "SCHEMA_UNKNOWN_MAJOR")

    def test_compat_frozen_surface_regression(self):
        # compat input regression anchors (current/future-minor readability).
        self.assertEqual(compat.LEGACY_SOURCE_ARTIFACT_ID, "legacy-finding")
        self.assertEqual(compat.LEGACY_REASON_CODE, "LEGACY_MIGRATED")
        finding = Finding(**load("legacy_finding_full.json"))
        bundle = compat.finding_to_domain_bundle(finding)
        back = compat.domain_to_finding(bundle)
        self.assertEqual(back.fingerprint, finding.fingerprint)
        # Round-trip bundle payload is readable at future minor unchanged.
        payload = evidence.encode_evidence_payload(bundle)
        self.assertEqual(payload, GOLDEN["legacy_finding_domain"])
        decoded = evidence.decode_evidence_payload(
            payload, schema_version=FUTURE_MINOR)
        self.assertEqual(
            evidence.encode_evidence_payload(decoded), payload)


if __name__ == "__main__":
    unittest.main()
