"""Summary + Failure payload tests (IP-0009 packet sections 10-14 and 18.1)."""

import json
import unittest
from pathlib import Path

from lima.contracts.codec import canonical_decode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.summary import (
    ArtifactLink,
    ExecutionStatus,
    FailureDisposition,
    FailureKind,
    FailureReport,
    FailureScope,
    SummaryReferenceKind,
    SummarySourceKind,
    WorkflowSummary,
)

V4 = SchemaVersion(4, 0)
V42 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

SO_D = "bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831"
WF_D = "3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146"
VEP_D = "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
RVR_D = "a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac"
SUM_GOLDEN_D = "5df80cd44cf3af456d153f967508e46b8d2a0f0595b3bb306a8fe41638cd0e34"
SUM_LEG_D = "18c1faa3e058b4d5b293fd4148fa3ad5834a804c84928f868c5cc9a8b6a097d4"
FR_GOLDEN_D = "05a2005fd4856ff2e8e098ed6989a29aa24146b0672af086a9c3b62c07935539"
FR_ALT_D = "3a016bfa5b338894e989707f516b2d3535a421be90652f75318ce0ab98e20c95"

WFK = SummaryReferenceKind.WORKFLOW
SAK = SummaryReferenceKind.STAGE_ATTEMPT
SOK = SummaryReferenceKind.SECURITY_OUTCOME
RMK = SummaryReferenceKind.RUN_MANIFEST
VEP = SummaryReferenceKind.VULNERABILITY_EVIDENCE_PACKAGE
RVR = SummaryReferenceKind.REPAIR_VERIFICATION_REPORT

# Wire-value registries kept as hardcoded lists so the frozen tests never import
# lima.contracts.workflow (packet section 18.1 interface discipline).
WORKFLOW_FAILURE_KIND_WIRE = [
    "environment", "tool_error", "timeout", "out_of_memory", "policy_denied", "internal",
]
SECURITY_OUTCOME_KIND_WIRE = [
    "no_supported_attack_surface", "no_actionable_hypothesis", "mining_skipped_by_request",
    "mining_skipped_by_policy", "mining_blocked_environment", "hypothesis_not_reproduced",
    "vulnerability_verified", "repair_unsupported", "repair_blocked_environment",
    "no_candidate_passed", "verified_patch", "full_chain_incomplete",
]

FORBIDDEN_PAYLOAD_KEYS = frozenset(
    {"confidence", "severity", "risk_score", "is_safe", "vulnerability_resolved", "safe", "clear"}
)


def _link(kind, artifact_id, digest):
    return ArtifactLink(
        kind=kind, artifact_id=artifact_id, content_digest=digest, schema_version=V4
    )


def _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest=WF_D):
    return {
        "kind": kind,
        "artifact_id": artifact_id,
        "content_digest": digest,
        "schema_version": "4.0",
    }


def _summary_wire():
    return {
        "source": "chain",
        "execution_status": "succeeded",
        "workflow": _link_wire(),
        "security_outcome": _link_wire(kind="lima.security-outcome", artifact_id="sec-0001",
                                       digest=SO_D),
        "run_manifest": None,
        "stage_attempts": [],
        "evidence": [],
        "legacy_artifact_ids": [],
    }


def _legacy_summary_wire():
    return {
        "source": "legacy_audit",
        "execution_status": "succeeded",
        "workflow": None,
        "security_outcome": None,
        "run_manifest": None,
        "stage_attempts": [],
        "evidence": [],
        "legacy_artifact_ids": ["legacy-report-0001"],
    }


def _failure_wire():
    return {
        "failure_kind": "environment",
        "scope": "workflow",
        "disposition": "transient",
        "owner": "lima-orchestrator",
        "workflow": _link_wire(),
        "stage_attempt": None,
        "evidence_artifact_ids": [],
    }


def _collect_keys(value, found):
    if isinstance(value, dict):
        for key, item in value.items():
            found.add(key)
            _collect_keys(item, found)
    elif isinstance(value, list):
        for item in value:
            _collect_keys(item, found)


class SummaryEnumTests(unittest.TestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(
            [member.value for member in SummarySourceKind], ["chain", "legacy_audit"]
        )
        self.assertEqual(
            [member.value for member in ExecutionStatus],
            ["succeeded", "failed", "cancelled"],
        )
        self.assertEqual(
            [member.value for member in FailureKind], WORKFLOW_FAILURE_KIND_WIRE
        )
        self.assertEqual(
            [member.value for member in FailureScope], ["workflow", "stage_attempt"]
        )
        self.assertEqual(
            [member.value for member in FailureDisposition], ["permanent", "transient"]
        )
        self.assertEqual(
            [member.value for member in SummaryReferenceKind],
            [
                "lima.repository-profile",
                "lima.audit-evidence-package",
                "lima.vulnerability-evidence-package",
                "lima.repair-verification-report",
                "lima.workflow",
                "lima.stage-attempt",
                "lima.security-outcome",
                "lima.run-manifest",
            ],
        )


class ArtifactLinkTests(unittest.TestCase):
    def test_round_trip_has_exact_wire_shape(self):
        link = _link(SOK, "sec-0001", SO_D)
        self.assertEqual(
            link.to_dict(),
            {
                "kind": "lima.security-outcome",
                "artifact_id": "sec-0001",
                "content_digest": SO_D,
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
                    "artifact_id": "wf-0001",
                    "content_digest": WF_D,
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
            ArtifactLink(kind=WFK, artifact_id="bad id!", content_digest=WF_D, schema_version=V4)
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)


class WorkflowSummaryTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_chain_summary_round_trip_is_valid(self):
        summary = WorkflowSummary(
            schema_version=V4,
            source=SummarySourceKind.CHAIN,
            execution_status=ExecutionStatus.SUCCEEDED,
            workflow=_link(WFK, "wf-0001", WF_D),
            security_outcome=_link(SOK, "sec-0001", SO_D),
        )
        self.assertEqual(
            summary.to_dict(),
            {
                "source": "chain",
                "execution_status": "succeeded",
                "workflow": _link_wire(),
                "security_outcome": _link_wire(
                    kind="lima.security-outcome", artifact_id="sec-0001", digest=SO_D
                ),
                "run_manifest": None,
                "stage_attempts": [],
                "evidence": [],
                "legacy_artifact_ids": [],
            },
        )
        decoded = WorkflowSummary.from_dict(summary.to_dict(), schema_version=V4)
        self.assertEqual(decoded, summary)

    def test_golden_chain_summary_round_trip_and_digest(self):
        raw = (FIXTURES / "workflow_summary_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 1333)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), SUM_GOLDEN_D)
        summary = WorkflowSummary.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(summary.source, SummarySourceKind.CHAIN)
        self.assertEqual(summary.execution_status, ExecutionStatus.SUCCEEDED)
        self.assertEqual(summary.workflow.content_digest, WF_D)
        self.assertEqual(summary.security_outcome.content_digest, SO_D)
        self.assertEqual(len(summary.stage_attempts), 2)
        self.assertEqual(len(summary.evidence), 2)
        self.assertEqual(compute_content_digest(summary.to_dict()), SUM_GOLDEN_D)
        self.assertEqual(WorkflowSummary.from_dict(summary.to_dict(), schema_version=V4), summary)

    def test_golden_legacy_summary_round_trip_and_digest(self):
        raw = (FIXTURES / "workflow_summary_legacy_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 218)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), SUM_LEG_D)
        summary = WorkflowSummary.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(summary.source, SummarySourceKind.LEGACY_AUDIT)
        self.assertIsNone(summary.workflow)
        self.assertIsNone(summary.security_outcome)
        self.assertEqual(summary.legacy_artifact_ids,
                         ("legacy-report-0001", "legacy-scan-log-0001"))
        self.assertEqual(compute_content_digest(summary.to_dict()), SUM_LEG_D)
        self.assertEqual(WorkflowSummary.from_dict(summary.to_dict(), schema_version=V4), summary)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for field in ("source", "execution_status", "workflow", "security_outcome",
                      "run_manifest", "stage_attempts", "evidence", "legacy_artifact_ids"):
            wire = _summary_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire, field=field: WorkflowSummary.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        wire = _summary_wire()
        wire["source"] = "hybrid"
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.source",
        )
        wire = _summary_wire()
        wire["execution_status"] = "queued"
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.execution_status",
        )
        wire = _summary_wire()
        wire["stage_attempts"] = "nope"
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.stage_attempts",
        )

    def test_chain_requires_workflow_and_security_outcome_links(self):
        wire = _summary_wire()
        wire["workflow"] = None
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow",
        )
        wire = _summary_wire()
        wire["security_outcome"] = None
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.security_outcome",
        )

    def test_legacy_forbids_every_typed_link(self):
        for field, value in (
            ("workflow", _link_wire()),
            ("security_outcome", _link_wire(kind="lima.security-outcome",
                                            artifact_id="sec-0001", digest=SO_D)),
            ("run_manifest", _link_wire(kind="lima.run-manifest", artifact_id="run-0001",
                                        digest="1" * 64)),
        ):
            wire = _legacy_summary_wire()
            wire[field] = value
            self._assert_rejected(
                lambda wire=wire, field=field: WorkflowSummary.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.{field}",
            )
        wire = _legacy_summary_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="2" * 64)
        ]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _legacy_summary_wire()
        wire["evidence"] = [
            _link_wire(kind="lima.vulnerability-evidence-package", artifact_id="vep-0001",
                       digest=VEP_D)
        ]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_legacy_requires_at_least_one_legacy_id(self):
        wire = _legacy_summary_wire()
        wire["legacy_artifact_ids"] = []
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.legacy_artifact_ids",
        )

    def test_chain_forbids_legacy_ids(self):
        wire = _summary_wire()
        wire["legacy_artifact_ids"] = ["legacy-report-0001"]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.legacy_artifact_ids",
        )

    def test_rejects_links_outside_field_vocabulary(self):
        wire = _summary_wire()
        wire["workflow"] = _link_wire(kind="lima.stage-attempt", artifact_id="a-0001",
                                     digest="1" * 64)
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow.kind",
        )
        wire = _summary_wire()
        wire["security_outcome"] = _link_wire(artifact_id="wf-0002", digest="2" * 64)
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.security_outcome.kind",
        )
        wire = _summary_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.security-outcome", artifact_id="sec-0001", digest=SO_D)
        ]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempts[0].kind",
        )
        wire = _summary_wire()
        wire["evidence"] = [
            _link_wire(kind="lima.workflow", artifact_id="wf-0001", digest=WF_D)
        ]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.evidence[0].kind",
        )

    def test_rejects_unsorted_duplicate_and_oversize_arrays(self):
        wire = _summary_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="b-attempt", digest="1" * 64),
            _link_wire(kind="lima.stage-attempt", artifact_id="a-attempt", digest="2" * 64),
        ]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _summary_wire()
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id=f"attempt-{index:04d}",
                       digest="3" * 64)
            for index in range(257)
        ]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.stage_attempts",
        )
        wire = _legacy_summary_wire()
        wire["legacy_artifact_ids"] = ["b-legacy", "a-legacy"]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _legacy_summary_wire()
        wire["legacy_artifact_ids"] = [f"legacy-{index:04d}" for index in range(257)]
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.legacy_artifact_ids",
        )

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _summary_wire()
        wire["future_top"] = {"note": "reserved"}
        wire["stage_attempts"] = [
            _link_wire(kind="lima.stage-attempt", artifact_id="attempt-0001", digest="1" * 64)
        ]
        wire["stage_attempts"][0]["future_link"] = 2
        decoded = WorkflowSummary.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], {"note": "reserved"})
        self.assertEqual(encoded["stage_attempts"][0]["future_link"], 2)
        self.assertEqual(WorkflowSummary.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _summary_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )
        wire = _summary_wire()
        wire["evidence"] = [
            _link_wire(kind="lima.repair-verification-report", artifact_id="rvr-0001",
                       digest=RVR_D)
        ]
        wire["evidence"][0]["future_link"] = 1
        self._assert_rejected(
            lambda: WorkflowSummary.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        attempts = [_link(SAK, "attempt-0001", "1" * 64)]
        legacy = ["legacy-report-0001"]
        extensions = {"note": 1}
        chain = WorkflowSummary(
            schema_version=V4,
            source=SummarySourceKind.CHAIN,
            execution_status=ExecutionStatus.SUCCEEDED,
            workflow=_link(WFK, "wf-0001", WF_D),
            security_outcome=_link(SOK, "sec-0001", SO_D),
            stage_attempts=attempts,
            extensions=extensions,
        )
        attempts.append(_link(SAK, "attempt-0002", "2" * 64))
        extensions["note"] = 2
        self.assertEqual(len(chain.stage_attempts), 1)
        self.assertEqual(chain.extensions, {"note": 1})
        legacy_summary = WorkflowSummary(
            schema_version=V4,
            source=SummarySourceKind.LEGACY_AUDIT,
            execution_status=ExecutionStatus.SUCCEEDED,
            legacy_artifact_ids=legacy,
        )
        legacy.append("legacy-extra")
        self.assertEqual(legacy_summary.legacy_artifact_ids, ("legacy-report-0001",))

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        payloads = [
            json.loads((FIXTURES / "workflow_summary_v4_golden.json").read_text(encoding="utf-8")),
            json.loads(
                (FIXTURES / "workflow_summary_legacy_v4_golden.json").read_text(encoding="utf-8")
            ),
        ]
        for payload in payloads:
            found: set[str] = set()
            _collect_keys(payload, found)
            self.assertEqual(found & FORBIDDEN_PAYLOAD_KEYS, set())


class FailureReportTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_minimal_workflow_scope_failure_round_trip_is_valid(self):
        failure = FailureReport(
            schema_version=V4,
            failure_kind=FailureKind.ENVIRONMENT,
            scope=FailureScope.WORKFLOW,
            disposition=FailureDisposition.TRANSIENT,
            owner="lima-orchestrator",
            workflow=_link(WFK, "wf-0001", WF_D),
        )
        self.assertEqual(
            failure.to_dict(),
            {
                "failure_kind": "environment",
                "scope": "workflow",
                "disposition": "transient",
                "owner": "lima-orchestrator",
                "workflow": _link_wire(),
                "stage_attempt": None,
                "evidence_artifact_ids": [],
            },
        )
        decoded = FailureReport.from_dict(failure.to_dict(), schema_version=V4)
        self.assertEqual(decoded, failure)

    def test_golden_failure_report_round_trip_and_digest(self):
        raw = (FIXTURES / "failure_report_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 535)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), FR_GOLDEN_D)
        failure = FailureReport.from_dict(json.loads(raw.decode("utf-8")), schema_version=V4)
        self.assertEqual(failure.failure_kind, FailureKind.ENVIRONMENT)
        self.assertEqual(failure.scope, FailureScope.STAGE_ATTEMPT)
        self.assertEqual(failure.disposition, FailureDisposition.TRANSIENT)
        self.assertEqual(failure.evidence_artifact_ids,
                         ("sandbox-log-0001", "sandbox-run-0001"))
        self.assertEqual(compute_content_digest(failure.to_dict()), FR_GOLDEN_D)
        self.assertEqual(FailureReport.from_dict(failure.to_dict(), schema_version=V4), failure)

    def test_alternates_golden_round_trip_and_digest(self):
        raw = (FIXTURES / "failure_report_alternates_v4_golden.json").read_bytes()
        self.assertEqual(len(raw), 681)
        self.assertEqual(compute_content_digest(canonical_decode(raw)), FR_ALT_D)
        alternates = json.loads(raw.decode("utf-8"))
        self.assertEqual(len(alternates), 2)
        expected = [
            ("timeout", "workflow", "permanent", "lima-orchestrator", True),
            ("tool_error", "stage_attempt", "transient", "lima-mining-harness", False),
        ]
        for payload, (kind, scope, disposition, owner, has_workflow) in zip(
            alternates, expected, strict=True
        ):
            failure = FailureReport.from_dict(payload, schema_version=V4)
            self.assertEqual(failure.failure_kind.value, kind)
            self.assertEqual(failure.scope.value, scope)
            self.assertEqual(failure.disposition.value, disposition)
            self.assertEqual(failure.owner, owner)
            self.assertEqual(failure.workflow is not None, has_workflow)
            self.assertEqual(failure.to_dict(), payload)

    def test_rejects_wrong_container_and_missing_required_fields(self):
        self._assert_rejected(
            lambda: FailureReport.from_dict([], schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$",
        )
        for field in ("failure_kind", "scope", "disposition", "owner", "workflow",
                      "stage_attempt", "evidence_artifact_ids"):
            wire = _failure_wire()
            del wire[field]
            self._assert_rejected(
                lambda wire=wire, field=field: FailureReport.from_dict(wire, schema_version=V4),
                ContractErrorCode.REQUIRED_FIELD_MISSING,
                f"$.{field}",
            )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        for field, bad in (
            ("failure_kind", "act_of_god"),
            ("scope", "task"),
            ("disposition", "maybe"),
        ):
            wire = _failure_wire()
            wire[field] = bad
            self._assert_rejected(
                lambda wire=wire, field=field: FailureReport.from_dict(wire, schema_version=V4),
                ContractErrorCode.UNKNOWN_ENUM_VALUE,
                f"$.{field}",
            )
        wire = _failure_wire()
        wire["owner"] = 7
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.owner",
        )
        wire = _failure_wire()
        wire["workflow"] = "wf-0001"
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.workflow",
        )

    def test_workflow_scope_requires_workflow_link_and_forbids_attempt_link(self):
        wire = _failure_wire()
        wire["workflow"] = None
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow",
        )
        wire = _failure_wire()
        wire["stage_attempt"] = _link_wire(kind="lima.stage-attempt",
                                          artifact_id="attempt-0001", digest="1" * 64)
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempt",
        )

    def test_attempt_scope_requires_attempt_link(self):
        wire = _failure_wire()
        wire["scope"] = "stage_attempt"
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempt",
        )
        wire = _failure_wire()
        wire["scope"] = "stage_attempt"
        wire["workflow"] = None
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempt",
        )
        wire = _failure_wire()
        wire["scope"] = "stage_attempt"
        wire["stage_attempt"] = _link_wire(kind="lima.stage-attempt",
                                          artifact_id="attempt-0001", digest="1" * 64)
        FailureReport.from_dict(wire, schema_version=V4)

    def test_rejects_wrong_link_kinds(self):
        wire = _failure_wire()
        wire["workflow"] = _link_wire(kind="lima.run-manifest", artifact_id="run-0001",
                                     digest="1" * 64)
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow.kind",
        )
        wire = _failure_wire()
        wire["scope"] = "stage_attempt"
        wire["stage_attempt"] = _link_wire(artifact_id="wf-0001", digest=WF_D)
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempt.kind",
        )

    def test_owner_follows_identifier_rules(self):
        for bad in ("has space", "", "x" * 129, "tab\tchar"):
            wire = _failure_wire()
            wire["owner"] = bad
            self._assert_rejected(
                lambda wire=wire, bad=bad: FailureReport.from_dict(wire, schema_version=V4),
                ContractErrorCode.INVALID_FIELD_VALUE,
                "$.owner",
            )

    def test_rejects_unsorted_duplicate_and_oversize_evidence_ids(self):
        wire = _failure_wire()
        wire["evidence_artifact_ids"] = ["b-run-0002", "a-run-0001"]
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _failure_wire()
        wire["evidence_artifact_ids"] = ["run-0001", "run-0001"]
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        wire = _failure_wire()
        wire["evidence_artifact_ids"] = [f"run-{index:04d}" for index in range(257)]
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            "$.evidence_artifact_ids",
        )

    def test_failure_vocabulary_never_encodes_safety(self):
        failure_values = {member.value for member in FailureKind}
        outcome_values = set(SECURITY_OUTCOME_KIND_WIRE)
        self.assertEqual(failure_values & outcome_values, set())
        self.assertEqual(failure_values, set(WORKFLOW_FAILURE_KIND_WIRE))
        for value in failure_values:
            self.assertNotIn("safe", value)
            self.assertNotIn("clear", value)
            self.assertNotIn("not_vulnerable", value)
        self.assertNotIn("verified", failure_values)
        self.assertNotIn("refuted", failure_values)

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _failure_wire()
        wire["future_top"] = ["reserved"]
        wire["stage_attempt"] = None
        decoded = FailureReport.from_dict(wire, schema_version=V42)
        encoded = decoded.to_dict()
        self.assertEqual(encoded["future_top"], ["reserved"])
        self.assertEqual(FailureReport.from_dict(encoded, schema_version=V42), decoded)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        wire = _failure_wire()
        wire["future_top"] = 1
        self._assert_rejected(
            lambda: FailureReport.from_dict(wire, schema_version=V4),
            ContractErrorCode.UNKNOWN_FIELD,
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        evidence = ["run-0001"]
        extensions = {"note": 1}
        failure = FailureReport(
            schema_version=V4,
            failure_kind=FailureKind.TIMEOUT,
            scope=FailureScope.WORKFLOW,
            disposition=FailureDisposition.PERMANENT,
            owner="lima-orchestrator",
            workflow=_link(WFK, "wf-0001", WF_D),
            evidence_artifact_ids=evidence,
            extensions=extensions,
        )
        evidence.append("run-0002")
        extensions["note"] = 2
        self.assertEqual(failure.evidence_artifact_ids, ("run-0001",))
        self.assertEqual(failure.extensions, {"note": 1})

    def test_payload_has_no_confidence_severity_or_verdict_bypass_fields(self):
        payloads = [
            json.loads((FIXTURES / "failure_report_v4_golden.json").read_text(encoding="utf-8")),
            json.loads(
                (FIXTURES / "failure_report_alternates_v4_golden.json").read_text(encoding="utf-8")
            ),
        ]
        for payload in payloads:
            found: set[str] = set()
            _collect_keys(payload, found)
            self.assertEqual(found & FORBIDDEN_PAYLOAD_KEYS, set())


if __name__ == "__main__":
    unittest.main()
