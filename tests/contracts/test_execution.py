"""Execution-intent pair payload tests (IP-0008 packet sections 10-14 and 18.1)."""

import json
import unittest
from pathlib import Path

from lima.contracts.codec import canonical_decode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.execution import (
    ArtifactLink,
    Plan,
    PlanMode,
    PlanStageType,
    ReferenceKind,
    RunManifest,
)

V4 = SchemaVersion(4, 0)
V42 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

VEP_D = "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
PLAN_GOLDEN_D = "4e49b63d3f3cb50ef302781296cabbb02e4267b0675b7922a9bd1eae4077495a"
PLAN_FC_D = "9390344cd8018f450d115b085b577a7c723fb0abf214c552bd2cc9de6711851c"
RM_GOLDEN_D = "213fbebd48a966ee9071b5a19f385731e833b17f4d8c7c653c55b2c19eaf9cd7"

VEP = ReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE
WFK = ReferenceKind.WORKFLOW
SAK = ReferenceKind.STAGE_ATTEMPT
PLN = ReferenceKind.PLAN

# Wire values must stay value-equal to lima.contracts.workflow's WorkflowMode /
# StageType / (schema literals) without importing that module (packet section 18.1).
WORKFLOW_MODE_WIRE = ["full_chain", "audit_only", "verify_vep", "repair_from_vep"]
STAGE_TYPE_WIRE = ["profile", "audit", "mine", "repair", "summarize"]

FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {"confidence", "severity", "risk_score", "is_safe", "vulnerability_resolved", "safe", "clear"}
)


def _link(kind, artifact_id, digest):
    return ArtifactLink(
        kind=kind,
        artifact_id=artifact_id,
        content_digest=digest,
        schema_version=V4,
    )


def _link_wire(kind="lima.vulnerability-evidence-package", artifact_id="vep-0001", digest=VEP_D):
    return {
        "kind": kind,
        "artifact_id": artifact_id,
        "content_digest": digest,
        "schema_version": "4.0",
    }


def _plan_wire():
    return {
        "workflow_mode": "full_chain",
        "revision": 1,
        "planned_stages": ["profile"],
        "inputs": [],
    }


def _manifest_wire():
    return {
        "plan": _link_wire(kind="lima.plan", artifact_id="plan-0002", digest=PLAN_FC_D),
        "plan_revision": 1,
        "workflow": _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest="1" * 64),
        "stage_attempts": [],
        "resource_artifact_ids": [],
    }


def _collect_keys(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            _collect_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect_keys(item, found)


class ExecutionEnumTests(unittest.TestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            [member.value for member in PlanMode], WORKFLOW_MODE_WIRE
        )
        self.assertEqual(
            [member.value for member in PlanStageType], STAGE_TYPE_WIRE
        )
        self.assertEqual(
            [member.value for member in ReferenceKind],
            [
                "lima.vulnerability-evidence-package",
                "lima.workflow",
                "lima.stage-attempt",
                "lima.plan",
            ],
        )


class ArtifactLinkTests(unittest.TestCase):
    def test_round_trip_has_exact_wire_shape(self):
        link = _link(PLN, "plan-0002", PLAN_FC_D)
        self.assertEqual(
            link.to_dict(),
            {
                "kind": "lima.plan",
                "artifact_id": "plan-0002",
                "content_digest": PLAN_FC_D,
                "schema_version": "4.0",
            },
        )
        decoded = ArtifactLink.from_dict(link.to_dict(), schema_version=V4)
        self.assertEqual(decoded, link)
        self.assertEqual(decoded.to_dict(), link.to_dict())

    def test_rejects_missing_invalid_and_mismatched_fields(self):
        with self.assertRaises(ContractError) as ctx:
            ArtifactLink.from_dict(
                {
                    "artifact_id": "vep-0001",
                    "content_digest": VEP_D,
                    "schema_version": "4.0",
                },
                schema_version=V4,
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.REQUIRED_FIELD_MISSING)
        self.assertEqual(ctx.exception.field_path, "$.kind")
        wire = _link_wire()
        wire["content_digest"] = "XYZ"
        with self.assertRaises(ContractError) as ctx:
            ArtifactLink.from_dict(wire, schema_version=V4)
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
        wire = _link_wire(kind="lima.not-frozen")
        with self.assertRaises(ContractError) as ctx:
            ArtifactLink.from_dict(wire, schema_version=V4)
        self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_ENUM_VALUE)
        wire = _link_wire()
        wire["schema_version"] = 40
        with self.assertRaises(ContractError) as ctx:
            ArtifactLink.from_dict(wire, schema_version=V4)
        self.assertIs(ctx.exception.code, ContractErrorCode.SCHEMA_VERSION_INVALID)
        wire = _link_wire()
        wire["extra"] = 1
        with self.assertRaises(ContractError) as ctx:
            ArtifactLink.from_dict(wire, schema_version=V4)
        self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_FIELD)
        with self.assertRaises(ContractError) as ctx:
            ArtifactLink(kind=VEP, artifact_id="bad id!", content_digest=VEP_D, schema_version=V4)
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)


class PlanTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_full_chain_plan_round_trip_is_valid(self):
        plan = Plan(
            schema_version=V4,
            workflow_mode=PlanMode.FULL_CHAIN,
            revision=1,
            planned_stages=(PlanStageType.PROFILE,),
        )
        self.assertEqual(
            plan.to_dict(),
            {
                "workflow_mode": "full_chain",
                "revision": 1,
                "planned_stages": ["profile"],
                "inputs": [],
            },
        )
        decoded = Plan.from_dict(plan.to_dict(), schema_version=V4)
        self.assertEqual(decoded, plan)

    def test_golden_verify_vep_plan_round_trip_and_digest(self):
        raw = (FIXTURES / "plan_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 264)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), PLAN_GOLDEN_D)
        plan = Plan.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(plan.workflow_mode, PlanMode.VERIFY_VEP)
        self.assertEqual(plan.revision, 1)
        self.assertEqual(plan.planned_stages, (PlanStageType.SUMMARIZE,))
        self.assertEqual(len(plan.inputs), 1)
        self.assertEqual(plan.inputs[0].content_digest, VEP_D)
        self.assertEqual(compute_content_digest(plan.to_dict()), PLAN_GOLDEN_D)
        self.assertEqual(Plan.from_dict(plan.to_dict(), schema_version=V4), plan)

    def test_golden_full_chain_plan_round_trip_and_digest(self):
        raw = (FIXTURES / "plan_full_chain_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 120)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), PLAN_FC_D)
        plan = Plan.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(plan.workflow_mode, PlanMode.FULL_CHAIN)
        self.assertEqual(plan.revision, 2)
        self.assertEqual(
            plan.planned_stages,
            (
                PlanStageType.PROFILE,
                PlanStageType.AUDIT,
                PlanStageType.MINE,
                PlanStageType.REPAIR,
                PlanStageType.SUMMARIZE,
            ),
        )
        self.assertEqual(plan.inputs, ())
        self.assertEqual(compute_content_digest(plan.to_dict()), PLAN_FC_D)
        self.assertEqual(Plan.from_dict(plan.to_dict(), schema_version=V4), plan)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: Plan.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for field in ("workflow_mode", "revision", "planned_stages", "inputs"):
            wire = _plan_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire, field=field: Plan.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        wire = _plan_wire()
        wire["workflow_mode"] = "chaos"
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.workflow_mode",
        )
        wire = _plan_wire()
        wire["revision"] = "1"
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.revision",
        )
        wire = _plan_wire()
        wire["planned_stages"] = "profile"
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.planned_stages",
        )

    def test_rejects_invalid_revision(self):
        for bad in (0, -1):
            wire = _plan_wire()
            wire["revision"] = bad
            self._assert_rejected(
                lambda wire=wire: Plan.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.revision",
            )
        for bad in (True, 1.5):
            wire = _plan_wire()
            wire["revision"] = bad
            self._assert_rejected(
                lambda wire=wire: Plan.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_TYPE,
                "$.revision",
            )

    def test_rejects_duplicate_unknown_and_empty_planned_stages(self):
        wire = _plan_wire()
        wire["planned_stages"] = []
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.planned_stages",
        )
        wire = _plan_wire()
        wire["planned_stages"] = ["deploy"]
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.planned_stages[0]",
        )
        wire = _plan_wire()
        wire["planned_stages"] = ["audit", "audit"]
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_audit_only_mode_with_mining_or_repair_stages(self):
        for stage in ("mine", "repair"):
            wire = _plan_wire()
            wire["workflow_mode"] = "audit_only"
            wire["planned_stages"] = ["profile", stage]
            self._assert_rejected(
                lambda wire=wire, stage=stage: Plan.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.planned_stages[1]",
            )
        wire = _plan_wire()
        wire["workflow_mode"] = "audit_only"
        wire["planned_stages"] = ["profile", "audit", "summarize"]
        Plan.from_dict(wire, schema_version=V4)
        wire = _plan_wire()
        wire["planned_stages"] = ["profile", "mine"]
        Plan.from_dict(wire, schema_version=V4)

    def test_mode_governs_vep_inputs_required_and_forbidden(self):
        for mode in ("verify_vep", "repair_from_vep"):
            wire = _plan_wire()
            wire["workflow_mode"] = mode
            wire["planned_stages"] = ["summarize"]
            self._assert_rejected(
                lambda wire=wire, mode=mode: Plan.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.inputs",
            )
            wire = _plan_wire()
            wire["workflow_mode"] = mode
            wire["planned_stages"] = ["summarize"]
            wire["inputs"] = [_link_wire()]
            Plan.from_dict(wire, schema_version=V4)
        for mode in ("full_chain", "audit_only"):
            wire = _plan_wire()
            wire["workflow_mode"] = mode
            wire["inputs"] = [_link_wire()]
            self._assert_rejected(
                lambda wire=wire, mode=mode: Plan.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.inputs[0].kind",
            )
        wire = _plan_wire()
        wire["workflow_mode"] = "verify_vep"
        wire["planned_stages"] = ["summarize"]
        wire["inputs"] = [
            _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest="2" * 64)
        ]
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.inputs[0].kind",
        )

    def test_rejects_inputs_outside_vocabulary_or_unsorted(self):
        wire = _plan_wire()
        wire["workflow_mode"] = "verify_vep"
        wire["planned_stages"] = ["summarize"]
        wire["inputs"] = [
            _link_wire(artifact_id="z-vep-0002", digest="2" * 64),
            _link_wire(artifact_id="a-vep-0001", digest="3" * 64),
        ]
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _plan_wire()
        wire["workflow_mode"] = "verify_vep"
        wire["planned_stages"] = ["summarize"]
        wire["inputs"] = [_link_wire(), _link_wire()]
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _plan_wire()
        wire["workflow_mode"] = "verify_vep"
        wire["planned_stages"] = ["summarize"]
        wire["inputs"] = [_link_wire()]
        wire["future_top"] = {"note": "reserved"}
        wire["inputs"][0]["future_link"] = 2
        decoded = Plan.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], {"note": "reserved"})
        self.assertEqual(encoded["inputs"][0]["future_link"], 2)
        self.assertEqual(Plan.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _plan_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )
        wire = _plan_wire()
        wire["inputs"] = [_link_wire()]
        wire["inputs"][0]["future_link"] = 1
        self._assert_rejected(
            lambda: Plan.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        inputs = [_link(VEP, "vep-0001", VEP_D)]
        stages = [PlanStageType.PROFILE]
        extensions = {"note": 1}
        plan = Plan(
            schema_version=V4,
            workflow_mode=PlanMode.VERIFY_VEP,
            revision=1,
            planned_stages=stages,
            inputs=inputs,
            extensions=extensions,
        )
        inputs.append(_link(VEP, "vep-0002", "2" * 64))
        stages.append(PlanStageType.AUDIT)
        extensions["note"] = 2
        self.assertEqual(len(plan.inputs), 1)
        self.assertEqual(plan.planned_stages, (PlanStageType.PROFILE,))
        self.assertEqual(plan.extensions, {"note": 1})

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        payloads = [
            json.loads((FIXTURES / "plan_v4_golden.json").read_text(encoding="utf-8")),
            json.loads((FIXTURES / "plan_full_chain_v4_golden.json").read_text(encoding="utf-8")),
            Plan(
                schema_version=V4,
                workflow_mode=PlanMode.FULL_CHAIN,
                revision=1,
                planned_stages=(PlanStageType.PROFILE,),
            ).to_dict(),
        ]
        for payload in payloads:
            found: set[str] = set()
            _collect_keys(payload, found)
            self.assertEqual(found & FORBIDDEN_PAYLOAD_KEYS, set())


class RunManifestTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_empty_manifest_round_trip_is_valid(self):
        manifest = RunManifest(
            schema_version=V4,
            plan=_link(PLN, "plan-0002", PLAN_FC_D),
            plan_revision=1,
            workflow=_link(WFK, "wf-0001", "1" * 64),
        )
        self.assertEqual(
            manifest.to_dict(),
            {
                "plan": _link_wire(kind="lima.plan", artifact_id="plan-0002", digest=PLAN_FC_D),
                "plan_revision": 1,
                "workflow": _link_wire(
                    kind="lima.workflow", artifact_id="wf-0001", digest="1" * 64
                ),
                "stage_attempts": [],
                "resource_artifact_ids": [],
            },
        )
        decoded = RunManifest.from_dict(manifest.to_dict(), schema_version=V4)
        self.assertEqual(decoded, manifest)

    def test_golden_manifest_round_trip_and_digest(self):
        raw = (FIXTURES / "run_manifest_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 776)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), RM_GOLDEN_D)
        manifest = RunManifest.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(manifest.plan.content_digest, PLAN_FC_D)
        self.assertEqual(manifest.plan_revision, 2)
        self.assertEqual(manifest.workflow.artifact_id, "wf-0001")
        self.assertEqual(len(manifest.stage_attempts), 2)
        self.assertEqual(manifest.resource_artifact_ids, ("sandbox-run-0001", "tool-bundle-0001"))
        self.assertEqual(compute_content_digest(manifest.to_dict()), RM_GOLDEN_D)
        self.assertEqual(RunManifest.from_dict(manifest.to_dict(), schema_version=V4), manifest)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: RunManifest.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for field in ("plan", "plan_revision", "workflow", "stage_attempts",
                      "resource_artifact_ids"):
            wire = _manifest_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire, field=field: RunManifest.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        wire = _manifest_wire()
        wire["plan_revision"] = "2"
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.plan_revision",
        )
        wire = _manifest_wire()
        wire["stage_attempts"] = "nope"
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.stage_attempts",
        )
        wire = _manifest_wire()
        wire["plan"] = "plan-0002"
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.plan",
        )

    def test_rejects_invalid_plan_revision(self):
        for bad in (0, -3):
            wire = _manifest_wire()
            wire["plan_revision"] = bad
            self._assert_rejected(
                lambda wire=wire: RunManifest.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.plan_revision",
            )
        wire = _manifest_wire()
        wire["plan_revision"] = True
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.plan_revision",
        )

    def test_plan_and_workflow_link_kinds_are_required_and_exact(self):
        wire = _manifest_wire()
        wire["plan"] = _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest="1" * 64)
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.plan.kind",
        )
        wire = _manifest_wire()
        wire["workflow"] = _link_wire(kind="lima.plan", artifact_id="plan-0002", digest=PLAN_FC_D)
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow.kind",
        )

    def test_rejects_unsorted_duplicate_and_oversize_stage_attempts(self):
        wire = _manifest_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="b-attempt", digest="1" * 64),
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="2" * 64),
        ]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _manifest_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="1" * 64),
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="1" * 64),
        ]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _manifest_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.workflow", artifact_id="z-attempt", digest="3" * 64)
        ]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempts[0].kind",
        )
        wire = _manifest_wire()
        wire["stage_attempts"] = [
            _link_wire(
                kind="lima.stage-attempt", artifact_id=f"attempt-{index:04d}", digest="4" * 64
            )
            for index in range(257)
        ]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.stage_attempts",
        )

    def test_resource_ids_follow_identifier_rules_sorted_unique_capped(self):
        wire = _manifest_wire()
        wire["resource_artifact_ids"] = ["has space"]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.resource_artifact_ids[0]",
        )
        wire = _manifest_wire()
        wire["resource_artifact_ids"] = ["b-run-0002", "a-run-0001"]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _manifest_wire()
        wire["resource_artifact_ids"] = ["run-0001", "run-0001"]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _manifest_wire()
        wire["resource_artifact_ids"] = [f"run-{index:04d}" for index in range(257)]
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.resource_artifact_ids",
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _manifest_wire()
        wire["future_top"] = ["reserved"]
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="attempt-0001", digest="1" * 64)
        ]
        wire["stage_attempts"][0]["future_link"] = 1
        decoded = RunManifest.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], ["reserved"])
        self.assertEqual(encoded["stage_attempts"][0]["future_link"], 1)
        self.assertEqual(RunManifest.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _manifest_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )
        wire = _manifest_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="attempt-0001", digest="1" * 64)
        ]
        wire["stage_attempts"][0]["future_link"] = 1
        self._assert_rejected(
            lambda: RunManifest.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        attempts = [_link(SAK, "attempt-0001", "1" * 64)]
        resources = ["run-0001"]
        extensions = {"note": 1}
        manifest = RunManifest(
            schema_version=V4,
            plan=_link(PLN, "plan-0002", PLAN_FC_D),
            plan_revision=1,
            workflow=_link(WFK, "wf-0001", "2" * 64),
            stage_attempts=attempts,
            resource_artifact_ids=resources,
            extensions=extensions,
        )
        attempts.append(_link(SAK, "attempt-0002", "3" * 64))
        resources.append("run-0002")
        extensions["note"] = 2
        self.assertEqual(len(manifest.stage_attempts), 1)
        self.assertEqual(manifest.resource_artifact_ids, ("run-0001",))
        self.assertEqual(manifest.extensions, {"note": 1})

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        payloads = [
            json.loads((FIXTURES / "run_manifest_v4_golden.json").read_text(encoding="utf-8")),
            RunManifest(
                schema_version=V4,
                plan=_link(PLN, "plan-0002", PLAN_FC_D),
                plan_revision=1,
                workflow=_link(WFK, "wf-0001", "1" * 64),
                resource_artifact_ids=("run-0001",),
            ).to_dict(),
        ]
        for payload in payloads:
            found: set[str] = set()
            _collect_keys(payload, found)
            self.assertEqual(found & FORBIDDEN_PAYLOAD_KEYS, set())


if __name__ == "__main__":
    unittest.main()
