"""PR3 artifact consistency tests: JSON Schema exports vs frozen runtime contracts.

Every test method first touches the exported artifact files, so the whole module is
RED (FileNotFoundError on schemas/v4/...) until the IP-0010 deliverables exist.
"""

import hashlib
import json
import re
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
from lima.contracts.common import (
    ArtifactClassification,
    RetentionClass,
    SchemaVersion,
    decode_envelope,
)
from lima.contracts.errors import ContractError, ContractErrorCode

REPO_ROOT = Path(__file__).resolve().parents[2]
SCHEMA_DIR = REPO_ROOT / "schemas" / "v4"
ADR_PATH = REPO_ROOT / "docs" / "adr" / "0027-version-compatibility-policy.md"
FIXTURES = Path(__file__).resolve().parent / "fixtures"

V4 = SchemaVersion(4, 0)

FROZEN_ARTIFACT_DIGESTS = {
    "lima.artifact-envelope.json": (
        1902,
        "9caa48cd5e60536d78f3e37479327caa2fab7553f9bb01ed7a301809845de21d",
    ),
    "lima.evidence-domain.json": (
        615,
        "224a13d304e8011ae8e80653cba65be54e1afcba6b847f52961fbaf4de8f7b8a",
    ),
    "lima.repository-profile.json": (
        1963,
        "7b684654227fcb5cd774bd5e9a02c9ba31e4e8383c2bc77115d85413bdbdf9a1",
    ),
    "lima.audit-evidence-package.json": (
        1055,
        "a4491c085d8f857b68c596207e0204b4f3cda19cc416cef3c6535977ea19c676",
    ),
    "lima.vulnerability-evidence-package.json": (
        1329,
        "ab0b1604c9875b09fdb59163ca06584724d51b7735d5df96b507ad91a487b6a4",
    ),
    "lima.repair-verification-report.json": (
        365,
        "29f400ab05ea5df24e5e2b66f51aba4faffdab4f2fd267957dc6082e9d210c95",
    ),
    "lima.workflow.json": (
        1345,
        "149608611bf8b6de4222fe35daf29953cd9b3b23a31e1509136ed8ce8098397d",
    ),
    "lima.stage-attempt.json": (
        2076,
        "db39996cb83c1d9ce72a7cbb7139751c74fd81ce6deea12c1737cffda0c4514d",
    ),
    "lima.security-outcome.json": (
        1734,
        "ee66e8a34f344d446a54ab3ff1746c535af971bc9d229d26e08bdc3d41e44883",
    ),
    "lima.plan.json": (
        990,
        "48d242383901fafc24736acbef6effcc6390acff7b5ebb17929dd9e15ba8a73f",
    ),
    "lima.run-manifest.json": (
        1796,
        "53b451de36bb77d5397d4576b3f9ae108f661ef483dc4b128824725d9648af68",
    ),
    "lima.workflow-summary.json": (
        3560,
        "b72041f6921540a94f1eda7ea77b189fe4e5cb59fdfabfd36aa2bb651014970b",
    ),
    "lima.failure-report.json": (
        1925,
        "63dc94fb92211717df0a8fd7a2e5852da6ea824fabf04c7ff075befe65de8e0f",
    ),
    "version_compatibility_matrix.json": (
        2876,
        "a0aa11f6906805790f8654dd33e48ab67a773e4b0f05c552d06cad53dc980588",
    ),
}

SCHEMA_NAMES = sorted(name[:-5] for name in FROZEN_ARTIFACT_DIGESTS
                      if name != "version_compatibility_matrix.json")
ADR_DIGEST = ("d96ccca7b10b02d058b35d417ed126dcd84c6a03a6f037f16da670bde16c47d4", 2528)

GOLDENS = {
    "lima.artifact-envelope": ["artifact_envelope_v4_golden.json"],
    "lima.evidence-domain": ["evidence_domain_bundle_v4_golden.json"],
    "lima.repository-profile": ["repository_profile_v4_golden.json"],
    "lima.audit-evidence-package": ["audit_evidence_package_v4_golden.json"],
    "lima.vulnerability-evidence-package": ["vulnerability_evidence_package_v4_golden.json"],
    "lima.repair-verification-report": ["repair_verification_report_v4_golden.json"],
    "lima.workflow": ["workflow_v4_golden.json"],
    "lima.stage-attempt": ["stage_attempt_v4_golden.json",
                           "stage_attempt_alternates_v4_golden.json"],
    "lima.security-outcome": ["security_outcome_v4_golden.json"],
    "lima.plan": ["plan_v4_golden.json", "plan_full_chain_v4_golden.json"],
    "lima.run-manifest": ["run_manifest_v4_golden.json"],
    "lima.workflow-summary": ["workflow_summary_v4_golden.json",
                              "workflow_summary_legacy_v4_golden.json"],
    "lima.failure-report": ["failure_report_v4_golden.json",
                            "failure_report_alternates_v4_golden.json"],
}

DECODE = {
    "lima.evidence-domain": lambda p, v=V4: evidence.decode_evidence_payload(
        p, schema_version=v),
    "lima.repository-profile": lambda p, v=V4: profile.decode_profile_payload(
        p, schema_version=v),
    "lima.audit-evidence-package": lambda p, v=V4: aep.decode_aep_payload(
        p, schema_version=v),
    "lima.vulnerability-evidence-package": lambda p, v=V4: vep.decode_vep_payload(
        p, schema_version=v),
    "lima.repair-verification-report": lambda p, v=V4: rvr.decode_rvr_payload(
        p, schema_version=v),
    "lima.workflow": lambda p, v=V4: workflow.decode_workflow_payload(
        p, schema_version=v),
    "lima.stage-attempt": lambda p, v=V4: workflow.decode_stage_attempt_payload(
        p, schema_version=v),
    "lima.security-outcome": lambda p, v=V4: workflow.decode_security_outcome_payload(
        p, schema_version=v),
    "lima.plan": lambda p, v=V4: execution.decode_plan_payload(p, schema_version=v),
    "lima.run-manifest": lambda p, v=V4: execution.decode_run_manifest_payload(
        p, schema_version=v),
    "lima.workflow-summary": lambda p, v=V4: summary.decode_workflow_summary_payload(
        p, schema_version=v),
    "lima.failure-report": lambda p, v=V4: summary.decode_failure_report_payload(
        p, schema_version=v),
}

ENUM_SOURCES = {
    "lima.artifact-envelope": {"classification": ArtifactClassification,
                               "retention_class": RetentionClass},
    "lima.evidence-domain": {},
    "lima.repository-profile": {},
    "lima.audit-evidence-package": {"package_status": aep.AuditPackageStatus,
                                    "audit_depth": aep.AuditDepth,
                                    "audit_outcome": aep.AuditOutcome},
    "lima.vulnerability-evidence-package": {
        "verification_verdict": vep.VerificationVerdict, "claim_kind": vep.ClaimKind},
    "lima.repair-verification-report": {},
    "lima.workflow": {"workflow_mode": workflow.WorkflowMode,
                      "status": workflow.WorkflowStatus,
                      "stage_attempts.items.kind": workflow.ArtifactKind},
    "lima.stage-attempt": {"stage_type": workflow.StageType,
                           "status": workflow.AttemptStatus,
                           "skip_reason": workflow.SkipReason,
                           "failure_kind": workflow.FailureKind,
                           "inputs.items.kind": workflow.ArtifactKind,
                           "outputs.items.kind": workflow.ArtifactKind},
    "lima.security-outcome": {"kind": workflow.SecurityOutcomeKind,
                              "workflow.kind": workflow.ArtifactKind,
                              "evidence.items.kind": workflow.ArtifactKind},
    "lima.plan": {"workflow_mode": execution.PlanMode,
                  "planned_stages.items": execution.PlanStageType,
                  "inputs.items.kind": execution.ReferenceKind},
    "lima.run-manifest": {"plan.kind": execution.ReferenceKind,
                          "workflow.kind": execution.ReferenceKind,
                          "stage_attempts.items.kind": execution.ReferenceKind},
    "lima.workflow-summary": {"source": summary.SummarySourceKind,
                              "execution_status": summary.ExecutionStatus,
                              "workflow.kind": summary.SummaryReferenceKind,
                              "security_outcome.kind": summary.SummaryReferenceKind,
                              "run_manifest.kind": summary.SummaryReferenceKind,
                              "stage_attempts.items.kind": summary.SummaryReferenceKind,
                              "evidence.items.kind": summary.SummaryReferenceKind},
    "lima.failure-report": {"failure_kind": summary.FailureKind,
                            "scope": summary.FailureScope,
                            "disposition": summary.FailureDisposition,
                            "workflow.kind": summary.SummaryReferenceKind,
                            "stage_attempt.kind": summary.SummaryReferenceKind},
}


def load_schema(name):
    return json.loads((SCHEMA_DIR / f"{name}.json").read_text(encoding="utf-8"))


def load_goldens(name):
    payloads = []
    for golden in GOLDENS[name]:
        data = json.loads((FIXTURES / golden).read_text(encoding="utf-8"))
        if isinstance(data, list):
            payloads.extend(data)
        else:
            payloads.append(data)
    return payloads


def mini_validate(instance, schema, path="$"):
    errors = []
    if "oneOf" in schema:
        if not any(not mini_validate(instance, sub, path) for sub in schema["oneOf"]):
            errors.append(f"{path}: no oneOf branch matched")
        return errors
    declared = schema.get("type")
    if declared:
        allowed = declared if isinstance(declared, list) else [declared]
        py = {"object": dict, "array": list, "string": str, "integer": int,
              "null": type(None)}
        if not any(isinstance(instance, py[kind]) for kind in allowed):
            return [f"{path}: expected type {declared}"]
    if "enum" in schema and instance not in schema["enum"]:
        errors.append(f"{path}: value not in enum")
    if "pattern" in schema and isinstance(instance, str):
        if re.search(schema["pattern"], instance) is None:
            errors.append(f"{path}: pattern mismatch")
    if "const" in schema and instance != schema["const"]:
        errors.append(f"{path}: const mismatch")
    if isinstance(instance, dict):
        for req in schema.get("required", []):
            if req not in instance:
                errors.append(f"{path}: missing required {req}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in instance:
                if key not in props:
                    errors.append(f"{path}: unknown property {key}")
        for key, sub in props.items():
            if key in instance:
                errors += mini_validate(instance[key], sub, f"{path}.{key}")
    if isinstance(instance, list):
        if "minItems" in schema and len(instance) < schema["minItems"]:
            errors.append(f"{path}: minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            errors.append(f"{path}: maxItems")
        if "items" in schema:
            for index, item in enumerate(instance):
                errors += mini_validate(item, schema["items"], f"{path}[{index}]")
    if "minimum" in schema and isinstance(instance, int) and instance < schema["minimum"]:
        errors.append(f"{path}: minimum")
    return errors


def probe_required(name, payload):
    decode = DECODE[name] if name in DECODE else None
    required = []
    for key in list(payload.keys()):
        stripped = {k: v for k, v in payload.items() if k != key}
        try:
            if decode is None:
                decode_envelope(json.dumps(stripped).encode("utf-8"))
            else:
                decode(stripped)
        except ContractError as err:
            if err.code is ContractErrorCode.REQUIRED_FIELD_MISSING:
                required.append(key)
        except (ValueError, TypeError):
            continue
    return sorted(required)


def resolve_enum_node(properties, field):
    node = {"properties": properties}
    for part in field.split("."):
        if part == "items":
            node = node.get("items", {})
        else:
            node = node.get("properties", {}).get(part, node.get(part, {}))
        if "oneOf" in node:
            node = node["oneOf"][0]
    return node


class SchemaExportInventoryTests(unittest.TestCase):
    def test_fifteen_artifacts_exist_with_frozen_digests(self):
        for name, (size, digest) in sorted(FROZEN_ARTIFACT_DIGESTS.items()):
            data = (SCHEMA_DIR / name).read_bytes()
            self.assertEqual(len(data), size, name)
            self.assertEqual(hashlib.sha256(data).hexdigest(), digest, name)
        adr = ADR_PATH.read_bytes()
        self.assertEqual(len(adr), ADR_DIGEST[1])
        self.assertEqual(hashlib.sha256(adr).hexdigest(), ADR_DIGEST[0])

    def test_schema_ids_and_draft_are_exact(self):
        for name in SCHEMA_NAMES:
            schema = load_schema(name)
            self.assertEqual(schema["$schema"],
                             "https://json-schema.org/draft/2020-12/schema", name)
            self.assertEqual(schema["$id"], f"urn:lima:v4:{name}", name)
            self.assertEqual(schema["title"], name, name)
            self.assertIs(schema["additionalProperties"], False, name)

    def test_envelope_schema_required_set_matches_module_probe(self):
        schema = load_schema("lima.artifact-envelope")
        golden = json.loads(
            (FIXTURES / "artifact_envelope_v4_golden.json").read_text(encoding="utf-8")
        )
        probed = probe_required("lima.artifact-envelope", golden)
        self.assertEqual(sorted(schema["required"]), probed)


class SchemaContractTests(unittest.TestCase):
    def _assert_contract(self, name):
        schema = load_schema(name)
        for payload in load_goldens(name):
            errors = mini_validate(payload, schema)
            self.assertEqual(errors, [], f"{name}: {errors[:3]}")
        probed = probe_required(name, load_goldens(name)[0])
        self.assertEqual(sorted(schema["required"]), probed, name)
        for field, enum_cls in ENUM_SOURCES[name].items():
            node = resolve_enum_node(schema["properties"], field)
            self.assertEqual(node.get("enum"), [m.value for m in enum_cls],
                             f"{name}.{field}")

    def test_artifact_envelope_schema_matches_runtime_contract(self):
        self._assert_contract("lima.artifact-envelope")

    def test_evidence_domain_schema_matches_runtime_contract(self):
        self._assert_contract("lima.evidence-domain")

    def test_repository_profile_schema_matches_runtime_contract(self):
        self._assert_contract("lima.repository-profile")

    def test_audit_evidence_package_schema_matches_runtime_contract(self):
        self._assert_contract("lima.audit-evidence-package")

    def test_vulnerability_evidence_package_schema_matches_runtime_contract(self):
        self._assert_contract("lima.vulnerability-evidence-package")

    def test_repair_verification_report_schema_matches_runtime_contract(self):
        self._assert_contract("lima.repair-verification-report")

    def test_workflow_schema_matches_runtime_contract(self):
        self._assert_contract("lima.workflow")

    def test_stage_attempt_schema_matches_runtime_contract(self):
        self._assert_contract("lima.stage-attempt")

    def test_security_outcome_schema_matches_runtime_contract(self):
        self._assert_contract("lima.security-outcome")

    def test_plan_schema_matches_runtime_contract(self):
        self._assert_contract("lima.plan")

    def test_run_manifest_schema_matches_runtime_contract(self):
        self._assert_contract("lima.run-manifest")

    def test_workflow_summary_schema_matches_runtime_contract(self):
        self._assert_contract("lima.workflow-summary")

    def test_failure_report_schema_matches_runtime_contract(self):
        self._assert_contract("lima.failure-report")


class MiniValidatorNegativeTests(unittest.TestCase):
    def test_mini_validator_rejects_unknown_top_level_field(self):
        schema = load_schema("lima.workflow")
        payload = load_goldens("lima.workflow")[0]
        payload["future_top"] = 1
        errors = mini_validate(payload, schema)
        self.assertTrue(any("unknown property" in e for e in errors), errors)
        with self.assertRaises(ContractError) as ctx:
            DECODE["lima.workflow"](payload)
        self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_FIELD)

    def test_mini_validator_rejects_unknown_enum_and_missing_required(self):
        schema = load_schema("lima.plan")
        payload = load_goldens("lima.plan")[0]
        tampered = dict(payload, workflow_mode="chaos")
        errors = mini_validate(tampered, schema)
        self.assertTrue(any("enum" in e for e in errors), errors)
        stripped = {k: v for k, v in payload.items() if k != "revision"}
        errors = mini_validate(stripped, schema)
        self.assertTrue(any("missing required" in e for e in errors), errors)
        with self.assertRaises(ContractError) as ctx:
            DECODE["lima.plan"](tampered)
        self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_ENUM_VALUE)


if __name__ == "__main__":
    unittest.main()
