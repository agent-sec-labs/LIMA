"""Workflow spine schema payload tests (IP-0007 packet sections 10-14 and 18.1)."""

import json
import unittest
from pathlib import Path

from lima.contracts.workflow import (
    ArtifactKind,
    ArtifactLink,
    AttemptStatus,
    FailureKind,
    SecurityOutcome,
    SecurityOutcomeKind,
    SkipReason,
    StageAttempt,
    StageType,
    Workflow,
    WorkflowMode,
    WorkflowStatus,
)

from lima.contracts.codec import canonical_decode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode

V4 = SchemaVersion(4, 0)
V42 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

PROFILE_D = "ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc"
AEP_D = "f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0"
VEP_D = "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
RVR_D = "a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac"
SA_GOLDEN_D = "34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259"
ALT_ARRAY_D = "01cf64fc7c63249abe52a95f2c9065d96ff24424332b8c2adb237c2af61cd416"
WF_GOLDEN_D = "3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146"
SO_GOLDEN_D = "bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831"

RP = ArtifactKind.REPOSITORY_PROFILE
AEP = ArtifactKind.AUDIT_EVIDENCE_PACKAGE
VEP = ArtifactKind.VULNERABILITY_EVIDENCE_PACKAGE
RVR = ArtifactKind.REPAIR_VERIFICATION_REPORT
WFK = ArtifactKind.WORKFLOW
SAK = ArtifactKind.STAGE_ATTEMPT

# Packet 14.2-O3: kind -> (required evidence kinds, forbidden evidence kinds).
KIND_MATRIX = {
    "no_supported_attack_surface": (("lima.audit-evidence-package",),
                                    ("lima.vulnerability-evidence-package",
                                     "lima.repair-verification-report")),
    "no_actionable_hypothesis": (("lima.audit-evidence-package",),
                                 ("lima.vulnerability-evidence-package",
                                  "lima.repair-verification-report")),
    "mining_skipped_by_request": (("lima.audit-evidence-package",),
                                  ("lima.vulnerability-evidence-package",
                                   "lima.repair-verification-report")),
    "mining_skipped_by_policy": (("lima.audit-evidence-package",),
                                 ("lima.vulnerability-evidence-package",
                                  "lima.repair-verification-report")),
    "mining_blocked_environment": (("lima.audit-evidence-package",),
                                   ("lima.vulnerability-evidence-package",
                                    "lima.repair-verification-report")),
    "hypothesis_not_reproduced": (("lima.vulnerability-evidence-package",),
                                  ("lima.repair-verification-report",)),
    "vulnerability_verified": (("lima.vulnerability-evidence-package",),
                               ("lima.repair-verification-report",)),
    "repair_unsupported": (("lima.vulnerability-evidence-package",),
                           ("lima.repair-verification-report",)),
    "repair_blocked_environment": (("lima.vulnerability-evidence-package",),
                                   ("lima.repair-verification-report",)),
    "no_candidate_passed": (("lima.repair-verification-report",), ()),
    "verified_patch": (("lima.repair-verification-report",), ()),
    "full_chain_incomplete": ((), ()),
}

NON_CONCLUSION_KINDS = frozenset(
    {
        "mining_skipped_by_request",
        "mining_skipped_by_policy",
        "mining_blocked_environment",
        "repair_blocked_environment",
        "full_chain_incomplete",
    }
)

AUDIT_ONLY_FORBIDDEN_STATUSES = (
    "mining_planning",
    "mining_env_preparing",
    "mining_running",
    "mining_adjudicating",
    "repair_gate",
    "repair_planning",
    "repair_candidate_generation",
    "repair_verifying",
)

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


def _link_wire(kind="lima.repository-profile", artifact_id="profile-0001", digest=PROFILE_D):
    return {
        "kind": kind,
        "artifact_id": artifact_id,
        "content_digest": digest,
        "schema_version": "4.0",
    }


def _workflow_wire():
    return {
        "workflow_id": "workflow-0001",
        "workflow_mode": "full_chain",
        "status": "accepted",
        "revision": 1,
        "stage_attempts": [],
    }


def _attempt_wire():
    return {
        "workflow_id": "workflow-0001",
        "stage_attempt_id": "attempt-audit-0001",
        "stage_type": "audit",
        "attempt_number": 1,
        "status": "not_started",
        "inputs": [],
        "outputs": [],
        "skip_reason": None,
        "failure_kind": None,
    }


def _outcome_wire():
    return {
        "workflow_id": "workflow-0001",
        "kind": "full_chain_incomplete",
        "workflow": _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest=WF_GOLDEN_D),
        "evidence": [],
    }


def _collect_keys(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            _collect_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect_keys(item, found)


class WorkflowEnumTests(unittest.TestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            [member.value for member in WorkflowMode],
            ["full_chain", "audit_only", "verify_vep", "repair_from_vep"],
        )
        self.assertEqual(
            [member.value for member in WorkflowStatus],
            [
                "accepted",
                "classifying",
                "materializing",
                "auditing",
                "audit_adjudicating",
                "audit_gate",
                "mining_planning",
                "mining_env_preparing",
                "mining_running",
                "mining_adjudicating",
                "repair_gate",
                "repair_planning",
                "repair_candidate_generation",
                "repair_verifying",
                "summarizing",
                "terminal",
            ],
        )
        self.assertEqual(
            [member.value for member in StageType],
            ["profile", "audit", "mine", "repair", "summarize"],
        )
        self.assertEqual(
            [member.value for member in ArtifactKind],
            [
                "lima.repository-profile",
                "lima.audit-evidence-package",
                "lima.vulnerability-evidence-package",
                "lima.repair-verification-report",
                "lima.workflow",
                "lima.stage-attempt",
            ],
        )
        self.assertEqual(
            [member.value for member in AttemptStatus],
            ["not_started", "running", "succeeded", "skipped", "blocked", "failed", "cancelled"],
        )
        self.assertEqual(
            [member.value for member in SkipReason],
            ["by_request", "by_policy"],
        )
        self.assertEqual(
            [member.value for member in FailureKind],
            ["environment", "tool_error", "timeout", "out_of_memory", "policy_denied", "internal"],
        )
        self.assertEqual(
            [member.value for member in SecurityOutcomeKind],
            [
                "no_supported_attack_surface",
                "no_actionable_hypothesis",
                "mining_skipped_by_request",
                "mining_skipped_by_policy",
                "mining_blocked_environment",
                "hypothesis_not_reproduced",
                "vulnerability_verified",
                "repair_unsupported",
                "repair_blocked_environment",
                "no_candidate_passed",
                "verified_patch",
                "full_chain_incomplete",
            ],
        )


class ArtifactLinkTests(unittest.TestCase):
    def test_round_trip_has_exact_wire_shape(self):
        link = _link(RP, "profile-0001", PROFILE_D)
        self.assertEqual(
            link.to_dict(),
            {
                "kind": "lima.repository-profile",
                "artifact_id": "profile-0001",
                "content_digest": PROFILE_D,
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
                    "artifact_id": "profile-0001",
                    "content_digest": PROFILE_D,
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
            ArtifactLink(
                kind=RP,
                artifact_id="bad id!",
                content_digest=PROFILE_D,
                schema_version=V4,
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)


class WorkflowTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_empty_workflow_round_trip_is_valid(self):
        workflow = Workflow(
            schema_version=V4,
            workflow_id="workflow-0001",
            workflow_mode=WorkflowMode.FULL_CHAIN,
            status=WorkflowStatus.ACCEPTED,
            revision=1,
            stage_attempts=(),
        )
        self.assertEqual(
            workflow.to_dict(),
            {
                "workflow_id": "workflow-0001",
                "workflow_mode": "full_chain",
                "status": "accepted",
                "revision": 1,
                "stage_attempts": [],
            },
        )
        decoded = Workflow.from_dict(workflow.to_dict(), schema_version=V4)
        self.assertEqual(decoded, workflow)

    def test_golden_workflow_round_trip_and_digest(self):
        raw = (FIXTURES / "workflow_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 460)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), WF_GOLDEN_D)
        payload = json.loads(raw.decode("utf-8"))
        workflow = Workflow.from_dict(payload, schema_version=V4)
        self.assertEqual(workflow.workflow_mode, WorkflowMode.FULL_CHAIN)
        self.assertEqual(workflow.status, WorkflowStatus.AUDIT_GATE)
        self.assertEqual(workflow.revision, 2)
        self.assertEqual(len(workflow.stage_attempts), 2)
        self.assertEqual(compute_content_digest(workflow.to_dict()), WF_GOLDEN_D)
        self.assertEqual(Workflow.from_dict(workflow.to_dict(), schema_version=V4), workflow)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: Workflow.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for field in ("workflow_id", "workflow_mode", "status", "revision", "stage_attempts"):
            wire = _workflow_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire: Workflow.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        wire = _workflow_wire()
        wire["status"] = "zombie"
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.status",
        )
        wire = _workflow_wire()
        wire["workflow_mode"] = 7
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.workflow_mode",
        )
        wire = _workflow_wire()
        wire["stage_attempts"] = "nope"
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.stage_attempts",
        )

    def test_rejects_unsorted_duplicate_and_oversize_stage_attempts(self):
        wire = _workflow_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="b-attempt", digest="1" * 64),
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="2" * 64),
        ]
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _workflow_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="1" * 64),
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="1" * 64),
        ]
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _workflow_wire()
        wire["stage_attempts"] = [
            _link_wire(
                kind="lima.stage-attempt", artifact_id=f"attempt-{index:04d}", digest="3" * 64
            )
            for index in range(257)
        ]
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.stage_attempts",
        )

    def test_rejects_non_stage_attempt_link_kinds(self):
        wire = _workflow_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest=WF_GOLDEN_D)
        ]
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempts[0].kind",
        )

    def test_rejects_audit_only_mode_with_mining_or_repair_status(self):
        for status in AUDIT_ONLY_FORBIDDEN_STATUSES:
            wire = _workflow_wire()
            wire["workflow_mode"] = "audit_only"
            wire["status"] = status
            self._assert_rejected(
                lambda wire=wire, status=status: Workflow.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.status",
            )
        for status in ("accepted", "audit_gate", "summarizing", "terminal"):
            wire = _workflow_wire()
            wire["workflow_mode"] = "audit_only"
            wire["status"] = status
            Workflow.from_dict(wire, schema_version=V4)
        wire = _workflow_wire()
        wire["status"] = "mining_running"
        Workflow.from_dict(wire, schema_version=V4)

    def test_rejects_invalid_revision(self):
        for bad in (0, -1):
            wire = _workflow_wire()
            wire["revision"] = bad
            self._assert_rejected(
                lambda wire=wire: Workflow.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.revision",
            )
        for bad in ("2", 1.0, True):
            wire = _workflow_wire()
            wire["revision"] = bad
            self._assert_rejected(
                lambda wire=wire: Workflow.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_TYPE,
                "$.revision",
            )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _workflow_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="attempt-a", digest="1" * 64)
        ]
        wire["future_top"] = {"note": "reserved"}
        wire["stage_attempts"][0]["future_link"] = 2
        decoded = Workflow.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], {"note": "reserved"})
        self.assertEqual(encoded["stage_attempts"][0]["future_link"], 2)
        self.assertEqual(Workflow.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _workflow_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )
        wire = _workflow_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="attempt-a", digest="1" * 64)
        ]
        wire["stage_attempts"][0]["future_link"] = 2
        self._assert_rejected(
            lambda: Workflow.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        links = [_link(SAK, "attempt-a", "1" * 64)]
        extensions = {"note": 1}
        workflow = Workflow(
            schema_version=V4,
            workflow_id="workflow-0001",
            workflow_mode=WorkflowMode.FULL_CHAIN,
            status=WorkflowStatus.ACCEPTED,
            revision=1,
            stage_attempts=links,
            extensions=extensions,
        )
        links.append(_link(SAK, "attempt-b", "2" * 64))
        extensions["note"] = 2
        self.assertEqual(len(workflow.stage_attempts), 1)
        self.assertEqual(workflow.extensions, {"note": 1})

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        payloads = [
            json.loads((FIXTURES / "workflow_v4_golden.json").read_text(encoding="utf-8")),
            Workflow(
                schema_version=V4,
                workflow_id="workflow-0001",
                workflow_mode=WorkflowMode.AUDIT_ONLY,
                status=WorkflowStatus.TERMINAL,
                revision=1,
            ).to_dict(),
        ]
        for payload in payloads:
            found: set[str] = set()
            _collect_keys(payload, found)
            self.assertEqual(found & FORBIDDEN_PAYLOAD_KEYS, set())


class StageAttemptTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_not_started_attempt_round_trip_is_valid(self):
        attempt = StageAttempt(
            schema_version=V4,
            workflow_id="workflow-0001",
            stage_attempt_id="attempt-audit-0001",
            stage_type=StageType.AUDIT,
            attempt_number=1,
            status=AttemptStatus.NOT_STARTED,
        )
        self.assertEqual(
            attempt.to_dict(),
            {
                "workflow_id": "workflow-0001",
                "stage_attempt_id": "attempt-audit-0001",
                "stage_type": "audit",
                "attempt_number": 1,
                "status": "not_started",
                "inputs": [],
                "outputs": [],
                "skip_reason": None,
                "failure_kind": None,
            },
        )
        decoded = StageAttempt.from_dict(attempt.to_dict(), schema_version=V4)
        self.assertEqual(decoded, attempt)

    def test_golden_stage_attempt_round_trip_and_digest(self):
        raw = (FIXTURES / "stage_attempt_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 370)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), SA_GOLDEN_D)
        attempt = StageAttempt.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(attempt.stage_type, StageType.PROFILE)
        self.assertEqual(attempt.status, AttemptStatus.SUCCEEDED)
        self.assertEqual(compute_content_digest(attempt.to_dict()), SA_GOLDEN_D)
        self.assertEqual(StageAttempt.from_dict(attempt.to_dict(), schema_version=V4), attempt)

    def test_alternates_golden_round_trip_and_digest(self):
        raw = (FIXTURES / "stage_attempt_alternates_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 1498)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), ALT_ARRAY_D)
        alternates = json.loads(raw.decode("utf-8"))
        self.assertEqual(len(alternates), 4)
        expected = [
            ("audit", "succeeded", None, None),
            ("mine", "blocked", None, "environment"),
            ("repair", "failed", None, "tool_error"),
            ("mine", "skipped", "by_request", None),
        ]
        for payload, (stage_type, status, skip_reason, failure_kind) in zip(
            alternates, expected, strict=True
        ):
            attempt = StageAttempt.from_dict(payload, schema_version=V4)
            self.assertEqual(attempt.stage_type.value, stage_type)
            self.assertEqual(attempt.status.value, status)
            self.assertEqual(
                None if attempt.skip_reason is None else attempt.skip_reason.value, skip_reason
            )
            self.assertEqual(
                None if attempt.failure_kind is None else attempt.failure_kind.value, failure_kind
            )
            self.assertEqual(attempt.to_dict(), payload)
            self.assertEqual(compute_content_digest(attempt.to_dict()),
                             compute_content_digest(payload))

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: StageAttempt.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        fields = (
            "workflow_id",
            "stage_attempt_id",
            "stage_type",
            "attempt_number",
            "status",
            "inputs",
            "outputs",
            "skip_reason",
            "failure_kind",
        )
        for field in fields:
            wire = _attempt_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire, field=field: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        for field, bad in (
            ("stage_type", "deploy"),
            ("status", "paused"),
            ("skip_reason", "by_magic"),
            ("failure_kind", "act_of_god"),
        ):
            wire = _attempt_wire()
            wire["status"] = "skipped" if field == "skip_reason" else "blocked"
            wire[field] = bad
            if field == "skip_reason":
                wire["failure_kind"] = None
            else:
                wire["skip_reason"] = None
            self._assert_rejected(
                lambda wire=wire, field=field: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.UNKNOWN_ENUM_VALUE,
                f"$.{field}",
            )
        wire = _attempt_wire()
        wire["attempt_number"] = "1"
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.attempt_number",
        )

    def test_rejects_invalid_workflow_and_attempt_identifiers(self):
        for field, bad in (
            ("workflow_id", "has space"),
            ("workflow_id", "x" * 129),
            ("stage_attempt_id", ""),
            ("stage_attempt_id", "tab\tchar"),
        ):
            wire = _attempt_wire()
            wire[field] = bad
            self._assert_rejected(
                lambda wire=wire, field=field: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.{field}",
            )

    def test_rejects_attempt_number_out_of_range(self):
        for bad in (0, -1, 2**63):
            wire = _attempt_wire()
            wire["attempt_number"] = bad
            self._assert_rejected(
                lambda wire=wire: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.attempt_number",
            )
        wire = _attempt_wire()
        wire["attempt_number"] = True
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.attempt_number",
        )

    def test_succeeded_stage_type_requires_input_and_output_kinds(self):
        valid_variants = {
            "profile": ((), (_link(RP, "profile-0001", PROFILE_D),)),
            "audit": (
                (_link(RP, "profile-0001", PROFILE_D),),
                (_link(AEP, "aep-0001", AEP_D),),
            ),
            "mine": (
                (_link(AEP, "aep-0001", AEP_D),),
                (_link(VEP, "vep-0001", VEP_D),),
            ),
            "repair": (
                (_link(VEP, "vep-0001", VEP_D),),
                (_link(RVR, "rvr-0001", RVR_D),),
            ),
        }
        for stage_type, (inputs, outputs) in valid_variants.items():
            attempt = StageAttempt(
                schema_version=V4,
                workflow_id="workflow-0001",
                stage_attempt_id=f"attempt-{stage_type}-0001",
                stage_type=StageType(stage_type),
                attempt_number=1,
                status=AttemptStatus.SUCCEEDED,
                inputs=inputs,
                outputs=outputs,
            )
            self.assertEqual(attempt.status, AttemptStatus.SUCCEEDED)
        StageAttempt(
            schema_version=V4,
            workflow_id="workflow-0001",
            stage_attempt_id="attempt-summarize-0001",
            stage_type=StageType.SUMMARIZE,
            attempt_number=1,
            status=AttemptStatus.SUCCEEDED,
        )
        missing_output = {
            "profile": ((), ()),
            "audit": ((_link(RP, "profile-0001", PROFILE_D),), ()),
            "mine": ((_link(AEP, "aep-0001", AEP_D),), ()),
            "repair": ((_link(VEP, "vep-0001", VEP_D),), ()),
        }
        for stage_type, (inputs, outputs) in missing_output.items():
            with self.assertRaises(ContractError) as ctx:
                StageAttempt(
                    schema_version=V4,
                    workflow_id="workflow-0001",
                    stage_attempt_id=f"attempt-{stage_type}-0001",
                    stage_type=StageType(stage_type),
                    attempt_number=1,
                    status=AttemptStatus.SUCCEEDED,
                    inputs=inputs,
                    outputs=outputs,
                )
            self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
            self.assertEqual(ctx.exception.field_path, "$.outputs")
        for stage_type in ("audit", "mine", "repair"):
            with self.assertRaises(ContractError) as ctx:
                StageAttempt(
                    schema_version=V4,
                    workflow_id="workflow-0001",
                    stage_attempt_id=f"attempt-{stage_type}-0001",
                    stage_type=StageType(stage_type),
                    attempt_number=1,
                    status=AttemptStatus.SUCCEEDED,
                    inputs=(),
                    outputs=valid_variants[stage_type][1],
                )
            self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
            self.assertEqual(ctx.exception.field_path, "$.inputs")

    def test_rejects_inputs_outside_stage_vocabulary(self):
        cases = (
            ("audit", "lima.vulnerability-evidence-package"),
            ("mine", "lima.repository-profile"),
            ("repair", "lima.audit-evidence-package"),
            ("profile", "lima.repository-profile"),
            ("summarize", "lima.workflow"),
        )
        for stage_type, kind in cases:
            wire = _attempt_wire()
            wire["stage_type"] = stage_type
            wire["inputs"] = [_link_wire(kind=kind, artifact_id="z-input", digest="1" * 64)]
            self._assert_rejected(
                lambda wire=wire: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.inputs[0].kind",
            )

    def test_rejects_outputs_outside_stage_vocabulary_or_non_empty_when_not_succeeded(self):
        cases = (
            ("mine", "lima.repair-verification-report"),
            ("audit", "lima.vulnerability-evidence-package"),
            ("summarize", "lima.repository-profile"),
        )
        for stage_type, kind in cases:
            wire = _attempt_wire()
            wire["stage_type"] = stage_type
            wire["status"] = "succeeded"
            wire["outputs"] = [_link_wire(kind=kind, artifact_id="z-output", digest="1" * 64)]
            self._assert_rejected(
                lambda wire=wire: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.outputs[0].kind",
            )
        for status in ("not_started", "running", "skipped", "blocked", "failed", "cancelled"):
            wire = _attempt_wire()
            wire["status"] = status
            if status in ("blocked", "failed"):
                wire["failure_kind"] = "environment"
            if status == "skipped":
                wire["skip_reason"] = "by_request"
            wire["outputs"] = [
                _link_wire(
                    kind="lima.audit-evidence-package", artifact_id="z-output", digest="1" * 64
                )
            ]
            self._assert_rejected(
                lambda wire=wire, status=status: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.outputs",
            )

    def test_skip_reason_required_iff_skipped(self):
        wire = _attempt_wire()
        wire["status"] = "skipped"
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.skip_reason",
        )
        for status in ("not_started", "running", "succeeded", "blocked", "failed", "cancelled"):
            wire = _attempt_wire()
            wire["status"] = status
            if status in ("blocked", "failed"):
                wire["failure_kind"] = "environment"
            wire["skip_reason"] = "by_request"
            if status == "succeeded":
                wire["stage_type"] = "summarize"
            self._assert_rejected(
                lambda wire=wire, status=status: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.skip_reason",
            )

    def test_failure_kind_required_iff_blocked_or_failed(self):
        for status in ("blocked", "failed"):
            wire = _attempt_wire()
            wire["status"] = status
            self._assert_rejected(
                lambda wire=wire, status=status: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.failure_kind",
            )
        for status in ("not_started", "running", "succeeded", "skipped", "cancelled"):
            wire = _attempt_wire()
            wire["status"] = status
            if status == "skipped":
                wire["skip_reason"] = "by_request"
            if status == "succeeded":
                wire["stage_type"] = "summarize"
            wire["failure_kind"] = "timeout"
            self._assert_rejected(
                lambda wire=wire, status=status: StageAttempt.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.failure_kind",
            )
        wire = _attempt_wire()
        wire["status"] = "blocked"
        wire["skip_reason"] = "by_request"
        wire["failure_kind"] = "environment"
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_unsorted_duplicate_and_oversize_references(self):
        wire = _attempt_wire()
        wire["stage_type"] = "summarize"
        wire["status"] = "succeeded"
        wire["inputs"] = [
            _link_wire(kind="lima.repository-profile", artifact_id="b-ref", digest="1" * 64),
            _link_wire(kind="lima.repository-profile", artifact_id="a-ref", digest="2" * 64),
        ]
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _attempt_wire()
        wire["stage_type"] = "summarize"
        wire["status"] = "succeeded"
        wire["inputs"] = [
            _link_wire(kind="lima.repository-profile", artifact_id="a-ref", digest="1" * 64),
            _link_wire(kind="lima.repository-profile", artifact_id="a-ref", digest="1" * 64),
        ]
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _attempt_wire()
        wire["stage_type"] = "summarize"
        wire["status"] = "succeeded"
        wire["inputs"] = [
            _link_wire(
                kind="lima.repository-profile", artifact_id=f"ref-{index:04d}", digest="3" * 64
            )
            for index in range(65)
        ]
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.inputs",
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _attempt_wire()
        wire["inputs"] = [_link_wire(artifact_id="profile-0001")]
        wire["status"] = "succeeded"
        wire["stage_type"] = "audit"
        wire["outputs"] = [_link_wire(kind="lima.audit-evidence-package",
                                      artifact_id="aep-0001", digest=AEP_D)]
        wire["future_top"] = "reserved"
        wire["inputs"][0]["future_link"] = 1
        decoded = StageAttempt.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], "reserved")
        self.assertEqual(encoded["inputs"][0]["future_link"], 1)
        self.assertEqual(StageAttempt.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _attempt_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )
        wire = _attempt_wire()
        wire["inputs"] = [_link_wire()]
        wire["inputs"][0]["future_link"] = 1
        self._assert_rejected(
            lambda: StageAttempt.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        inputs = [_link(RP, "profile-0001", PROFILE_D)]
        outputs = [_link(AEP, "aep-0001", AEP_D)]
        extensions = {"note": 1}
        attempt = StageAttempt(
            schema_version=V4,
            workflow_id="workflow-0001",
            stage_attempt_id="attempt-audit-0001",
            stage_type=StageType.AUDIT,
            attempt_number=1,
            status=AttemptStatus.SUCCEEDED,
            inputs=inputs,
            outputs=outputs,
            extensions=extensions,
        )
        inputs.append(_link(AEP, "aep-0002", "2" * 64))
        outputs.clear()
        extensions["note"] = 2
        self.assertEqual(len(attempt.inputs), 1)
        self.assertEqual(len(attempt.outputs), 1)
        self.assertEqual(attempt.extensions, {"note": 1})


class SecurityOutcomeTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_full_chain_incomplete_outcome_round_trip_is_valid(self):
        outcome = SecurityOutcome(
            schema_version=V4,
            workflow_id="workflow-0001",
            kind=SecurityOutcomeKind.FULL_CHAIN_INCOMPLETE,
            workflow=_link(WFK, "wf-0001", WF_GOLDEN_D),
        )
        self.assertEqual(
            outcome.to_dict(),
            {
                "workflow_id": "workflow-0001",
                "kind": "full_chain_incomplete",
                "workflow": _link_wire(kind="lima.workflow", artifact_id="wf-0001",
                                       digest=WF_GOLDEN_D),
                "evidence": [],
            },
        )
        decoded = SecurityOutcome.from_dict(outcome.to_dict(), schema_version=V4)
        self.assertEqual(decoded, outcome)

    def test_golden_security_outcome_round_trip_and_digest(self):
        raw = (FIXTURES / "security_outcome_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 589)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), SO_GOLDEN_D)
        outcome = SecurityOutcome.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(outcome.kind, SecurityOutcomeKind.VERIFIED_PATCH)
        self.assertEqual(len(outcome.evidence), 2)
        self.assertEqual(compute_content_digest(outcome.to_dict()), SO_GOLDEN_D)
        self.assertEqual(SecurityOutcome.from_dict(outcome.to_dict(), schema_version=V4), outcome)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for field in ("workflow_id", "kind", "workflow", "evidence"):
            wire = _outcome_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire, field=field: SecurityOutcome.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        wire = _outcome_wire()
        wire["kind"] = "safe"
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.kind",
        )
        wire = _outcome_wire()
        wire["evidence"] = "nope"
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.evidence",
        )
        wire = _outcome_wire()
        wire["workflow"] = "wf-0001"
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.workflow",
        )

    def test_workflow_link_kind_is_required_and_exact(self):
        wire = _outcome_wire()
        wire["workflow"] = _link_wire(kind="lima.stage-attempt", artifact_id="attempt-0001",
                                      digest="1" * 64)
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow.kind",
        )

    def test_kind_evidence_matrix_required_and_forbidden_sets(self):
        for kind, (required, forbidden) in KIND_MATRIX.items():
            wire = _outcome_wire()
            wire["kind"] = kind
            if required:
                self._assert_rejected(
                    lambda wire=wire, kind=kind: SecurityOutcome.from_dict(wire, schema_version=V4),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    "$.kind",
                )
                evidence = [_link_wire(kind=required[0], artifact_id="a-required", digest="1" * 64)]
                wire = _outcome_wire()
                wire["kind"] = kind
                wire["evidence"] = evidence
                SecurityOutcome.from_dict(wire, schema_version=V4)
            else:
                SecurityOutcome.from_dict(wire, schema_version=V4)
            for forbidden_kind in forbidden:
                base = _link_wire(kind=required[0] if required else "lima.repository-profile",
                                  artifact_id="a-required", digest="1" * 64)
                wire = _outcome_wire()
                wire["kind"] = kind
                wire["evidence"] = [
                    base,
                    _link_wire(kind=forbidden_kind, artifact_id="z-forbidden", digest="2" * 64),
                ]
                self._assert_rejected(
                    lambda wire=wire, kind=kind: SecurityOutcome.from_dict(wire, schema_version=V4),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    "$.evidence[1].kind",
                )

    def test_conclusion_kinds_require_their_evidence_kinds(self):
        for kind in KIND_MATRIX:
            if kind in NON_CONCLUSION_KINDS:
                continue
            wire = _outcome_wire()
            wire["kind"] = kind
            self._assert_rejected(
                lambda wire=wire, kind=kind: SecurityOutcome.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.kind",
            )
        wire = _outcome_wire()
        wire["kind"] = "full_chain_incomplete"
        SecurityOutcome.from_dict(wire, schema_version=V4)

    def test_outcome_vocabulary_never_encodes_failure_as_safety(self):
        attempt_values = {member.value for member in AttemptStatus}
        failure_values = {member.value for member in FailureKind}
        outcome_values = {member.value for member in SecurityOutcomeKind}
        self.assertEqual(attempt_values & outcome_values, set())
        self.assertEqual(failure_values & outcome_values, set())
        self.assertEqual(attempt_values & failure_values, set())
        for value in attempt_values | failure_values | outcome_values:
            self.assertNotIn("safe", value)
            self.assertNotIn("clear", value)
            self.assertNotIn("not_vulnerable", value)
        self.assertEqual(
            outcome_values & NON_CONCLUSION_KINDS,
            NON_CONCLUSION_KINDS,
        )
        self.assertEqual(len(NON_CONCLUSION_KINDS), 5)
        self.assertEqual(len(outcome_values) - len(NON_CONCLUSION_KINDS), 7)
        for execution_only in ("blocked", "failed", "cancelled"):
            self.assertIn(execution_only, attempt_values)
            self.assertNotIn(execution_only, outcome_values)
            self.assertNotIn(execution_only, failure_values)

    def test_rejects_unsorted_duplicate_and_oversize_evidence(self):
        wire = _outcome_wire()
        wire["kind"] = "verified_patch"
        wire["evidence"] = [
            _link_wire(
                kind="lima.repair-verification-report", artifact_id="b-rvr", digest="1" * 64
            ),
            _link_wire(
                kind="lima.repair-verification-report", artifact_id="a-rvr", digest="2" * 64
            ),
        ]
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _outcome_wire()
        wire["kind"] = "verified_patch"
        wire["evidence"] = [
            _link_wire(
                kind="lima.repair-verification-report", artifact_id="a-rvr", digest="1" * 64
            ),
            _link_wire(
                kind="lima.repair-verification-report", artifact_id="a-rvr", digest="1" * 64
            ),
        ]
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _outcome_wire()
        wire["kind"] = "verified_patch"
        wire["evidence"] = [
            _link_wire(kind="lima.repair-verification-report", artifact_id=f"rvr-{index:04d}",
                       digest="3" * 64)
            for index in range(65)
        ]
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.evidence",
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _outcome_wire()
        wire["future_top"] = ["reserved"]
        wire["evidence"] = [
            _link_wire(kind="lima.repair-verification-report", artifact_id="rvr-0001", digest=RVR_D)
        ]
        wire["kind"] = "verified_patch"
        wire["evidence"][0]["future_link"] = 1
        decoded = SecurityOutcome.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], ["reserved"])
        self.assertEqual(encoded["evidence"][0]["future_link"], 1)
        self.assertEqual(SecurityOutcome.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _outcome_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )
        wire = _outcome_wire()
        wire["evidence"] = [
            _link_wire(kind="lima.repair-verification-report", artifact_id="rvr-0001", digest=RVR_D)
        ]
        wire["kind"] = "verified_patch"
        wire["evidence"][0]["future_link"] = 1
        self._assert_rejected(
            lambda: SecurityOutcome.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        evidence = [_link(RVR, "rvr-0001", RVR_D)]
        extensions = {"note": 1}
        outcome = SecurityOutcome(
            schema_version=V4,
            workflow_id="workflow-0001",
            kind=SecurityOutcomeKind.VERIFIED_PATCH,
            workflow=_link(WFK, "wf-0001", WF_GOLDEN_D),
            evidence=evidence,
            extensions=extensions,
        )
        evidence.append(_link(VEP, "vep-0001", VEP_D))
        extensions["note"] = 2
        self.assertEqual(len(outcome.evidence), 1)
        self.assertEqual(outcome.extensions, {"note": 1})

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        payloads = [
            json.loads((FIXTURES / "security_outcome_v4_golden.json").read_text(encoding="utf-8")),
            SecurityOutcome(
                schema_version=V4,
                workflow_id="workflow-0001",
                kind=SecurityOutcomeKind.MINING_BLOCKED_ENVIRONMENT,
                workflow=_link(WFK, "wf-0001", WF_GOLDEN_D),
                evidence=(_link(AEP, "aep-0001", AEP_D),),
            ).to_dict(),
        ]
        for payload in payloads:
            found: set[str] = set()
            _collect_keys(payload, found)
            self.assertEqual(found & FORBIDDEN_PAYLOAD_KEYS, set())


if __name__ == "__main__":
    unittest.main()
