"""Workflow spine schema envelope binding tests (IP-0007 packet sections 15 and 17.5)."""

import unittest
from pathlib import Path

from lima.contracts.workflow import (
    SECURITY_OUTCOME_SCHEMA_NAME,
    STAGE_ATTEMPT_SCHEMA_NAME,
    WORKFLOW_SCHEMA_NAME,
    SecurityOutcomeKind,
    decode_security_outcome_envelope,
    decode_security_outcome_payload,
    decode_stage_attempt_envelope,
    decode_stage_attempt_payload,
    decode_workflow_envelope,
    decode_workflow_payload,
    encode_security_outcome_envelope,
    encode_stage_attempt_envelope,
    encode_workflow_envelope,
)

from lima.contracts.codec import canonical_decode, compute_content_digest
from lima.contracts.common import (
    ArtifactBlobReference,
    ArtifactClassification,
    ArtifactEnvelope,
    ArtifactReference,
    RetentionClass,
    SchemaVersion,
    encode_envelope,
)
from lima.contracts.errors import ContractError, ContractErrorCode

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

PROFILE_D = "ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc"
AEP_D = "f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0"
VEP_D = "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
RVR_D = "a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac"
ALT_AUDIT_D = "418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4"
SA_GOLDEN_D = "34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259"
WF_GOLDEN_D = "3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146"
SO_GOLDEN_D = "bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831"

# Distinguish "caller did not pass payload/supersedes" from an explicit None
# arrange value (DR-IP-0007-IMPL-01 fix, checklist item 6).
_UNSET = object()


def _ref(schema_name, artifact_id, content_digest, **overrides):
    kwargs = {
        "schema_name": schema_name,
        "schema_version": VERSION_4_0,
        "artifact_id": artifact_id,
        "tenant_id": "tenant-1",
        "repository_snapshot_digest": "3" * 64,
        "content_digest": content_digest,
    }
    kwargs.update(overrides)
    return ArtifactReference(**kwargs)


def _workflow_payload():
    return canonical_decode((FIXTURES / "workflow_v4_golden.json").read_bytes())


def _attempt_payload():
    return canonical_decode((FIXTURES / "stage_attempt_v4_golden.json").read_bytes())


def _outcome_payload():
    return canonical_decode((FIXTURES / "security_outcome_v4_golden.json").read_bytes())


def _workflow_lineage(extra=()):
    return [
        _ref("lima.stage-attempt", "attempt-audit-0001", ALT_AUDIT_D),
        _ref("lima.stage-attempt", "attempt-profile-0001", SA_GOLDEN_D),
        *extra,
    ]


def _attempt_lineage(extra=()):
    return [_ref("lima.repository-profile", "profile-0001", PROFILE_D), *extra]


def _outcome_lineage(extra=()):
    return [
        _ref("lima.workflow", "wf-0001", WF_GOLDEN_D),
        _ref("lima.vulnerability-evidence-package", "vep-0001", VEP_D),
        _ref("lima.repair-verification-report", "rvr-0001", RVR_D),
        *extra,
    ]


def _envelope(**overrides):
    kwargs = {
        "schema_name": STAGE_ATTEMPT_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "attempt-profile-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-0001",
        "stage_attempt_id": "attempt-profile-0001",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-orchestrator",
        "created_at": "2026-09-05T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": SA_GOLDEN_D,
        "classification": ArtifactClassification.INTERNAL,
        "retention_class": RetentionClass.STANDARD,
        "payload": _attempt_payload(),
        "lineage": _attempt_lineage(),
        "supersedes": None,
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


def _workflow_envelope(payload=_UNSET, content_digest=WF_GOLDEN_D, lineage=None, supersedes=_UNSET,
                       classification=ArtifactClassification.INTERNAL,
                       retention=RetentionClass.STANDARD, schema_name=WORKFLOW_SCHEMA_NAME,
                       blob_ref=None):
    return _envelope(
        schema_name=schema_name,
        artifact_id="wf-0001",
        stage_attempt_id="attempt-audit-0001",
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_workflow_payload() if payload is _UNSET else payload,
        lineage=_workflow_lineage() if lineage is None else lineage,
        supersedes=(
            _ref("lima.workflow", "wf-0000", "0" * 64) if supersedes is _UNSET else supersedes
        ),
        blob_ref=blob_ref,
    )


def _attempt_envelope(**overrides):
    return _envelope(**overrides)


def _outcome_envelope(payload=_UNSET, content_digest=SO_GOLDEN_D, lineage=None,
                      classification=ArtifactClassification.SENSITIVE,
                      retention=RetentionClass.AUDIT, schema_name=SECURITY_OUTCOME_SCHEMA_NAME,
                      blob_ref=None):
    return _envelope(
        schema_name=schema_name,
        artifact_id="sec-0001",
        stage_attempt_id="attempt-repair-0002",
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_outcome_payload() if payload is _UNSET else payload,
        lineage=_outcome_lineage() if lineage is None else lineage,
        blob_ref=blob_ref,
    )


class _RejectionMixin:
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class WorkflowEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        envelope = _workflow_envelope()
        workflow = decode_workflow_payload(_workflow_payload(), schema_version=VERSION_4_0)
        first = encode_workflow_envelope(envelope, workflow)
        decoded_envelope, decoded_workflow = decode_workflow_envelope(first)
        second = encode_workflow_envelope(decoded_envelope, decoded_workflow)
        self.assertEqual(first, second)
        self.assertEqual(decoded_envelope.artifact_id, "wf-0001")
        self.assertEqual(decoded_workflow.revision, 2)
        self.assertEqual(len(decoded_workflow.stage_attempts), 2)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _workflow_envelope(schema_name=STAGE_ATTEMPT_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        workflow = decode_workflow_payload(_workflow_payload(), schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_workflow_envelope(_workflow_envelope(), workflow),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_payload_workflow_id_mismatch_with_envelope(self):
        payload = _workflow_payload()
        payload["workflow_id"] = "workflow-0002"
        envelope = _workflow_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow_id",
        )

    def test_rejects_blob_backed_workflow(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0001",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _workflow_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_revision_supersedes_coupling_enforced(self):
        payload = _workflow_payload()
        payload["revision"] = 1
        envelope = _workflow_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _workflow_envelope(supersedes=None)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _workflow_envelope(
            supersedes=_ref("lima.stage-attempt", "wf-0000", "0" * 64)
        )
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        decode_workflow_envelope(encode_envelope(_workflow_envelope()))

    def test_rejects_missing_or_mistyped_stage_attempt_lineage(self):
        lineage = [_ref("lima.stage-attempt", "attempt-profile-0001", SA_GOLDEN_D)]
        envelope = _workflow_envelope(lineage=lineage)
        exception = self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload"))
        lineage = [
            _ref("lima.workflow", "attempt-audit-0001", ALT_AUDIT_D),
            _ref("lima.stage-attempt", "attempt-profile-0001", SA_GOLDEN_D),
        ]
        envelope = _workflow_envelope(lineage=lineage)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        lineage = [
            _ref("lima.stage-attempt", "attempt-audit-0001", "7" * 64),
            _ref("lima.stage-attempt", "attempt-profile-0001", SA_GOLDEN_D),
        ]
        envelope = _workflow_envelope(lineage=lineage)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_allows_additional_valid_lineage(self):
        envelope = _workflow_envelope(
            lineage=_workflow_lineage(
                extra=(_ref("lima.repository-profile", "profile-0001", PROFILE_D),)
            )
        )
        decoded_envelope, workflow = decode_workflow_envelope(encode_envelope(envelope))
        self.assertEqual(len(decoded_envelope.lineage), 3)
        self.assertEqual(workflow.workflow_id, "workflow-0001")

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _workflow_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _workflow_envelope(retention=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_workflow_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )


class StageAttemptEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        attempt = decode_stage_attempt_payload(_attempt_payload(), schema_version=VERSION_4_0)
        first = encode_stage_attempt_envelope(_attempt_envelope(), attempt)
        decoded_envelope, decoded_attempt = decode_stage_attempt_envelope(first)
        second = encode_stage_attempt_envelope(decoded_envelope, decoded_attempt)
        self.assertEqual(first, second)
        self.assertEqual(decoded_attempt.stage_attempt_id, "attempt-profile-0001")
        self.assertEqual(decoded_attempt.status.value, "succeeded")

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _attempt_envelope(schema_name=WORKFLOW_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        attempt = decode_stage_attempt_payload(_attempt_payload(), schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_stage_attempt_envelope(_attempt_envelope(), attempt),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_payload_identity_mismatch_with_envelope(self):
        payload = _attempt_payload()
        payload["workflow_id"] = "workflow-0002"
        envelope = _attempt_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow_id",
        )
        payload = _attempt_payload()
        payload["stage_attempt_id"] = "attempt-audit-0009"
        envelope = _attempt_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.stage_attempt_id",
        )

    def test_rejects_blob_backed_stage_attempt(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0002",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _attempt_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_missing_or_mistyped_input_output_lineage(self):
        envelope = _attempt_envelope(lineage=[])
        exception = self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload"))
        envelope = _attempt_envelope(
            lineage=[_ref("lima.audit-evidence-package", "profile-0001", PROFILE_D)]
        )
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        envelope = _attempt_envelope(
            lineage=[_ref("lima.repository-profile", "profile-0001", "7" * 64)]
        )
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection(self):
        with self.assertRaises(ContractError) as ctx:
            _attempt_envelope(
                lineage=[_ref("lima.repository-profile", "profile-0001", PROFILE_D,
                              tenant_id="tenant-2")]
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.LINEAGE_TENANT_MISMATCH)
        with self.assertRaises(ContractError) as ctx:
            _attempt_envelope(
                lineage=[
                    _ref("lima.repository-profile", "profile-0001", PROFILE_D,
                         repository_snapshot_digest="4" * 64)
                ]
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH)
        with self.assertRaises(ContractError) as ctx:
            _attempt_envelope(
                lineage=[_ref("lima.repository-profile", "attempt-profile-0001", PROFILE_D)]
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.LINEAGE_SELF_REFERENCE)

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _attempt_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _attempt_envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        payload = _attempt_payload()
        payload["status"] = "zzz"
        envelope = _attempt_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_stage_attempt_envelope(encode_envelope(envelope)),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.status",
        )


class SecurityOutcomeEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        outcome = decode_security_outcome_payload(
            _outcome_payload(), schema_version=VERSION_4_0
        )
        first = encode_security_outcome_envelope(_outcome_envelope(), outcome)
        decoded_envelope, decoded_outcome = decode_security_outcome_envelope(first)
        second = encode_security_outcome_envelope(decoded_envelope, decoded_outcome)
        self.assertEqual(first, second)
        self.assertEqual(decoded_outcome.kind, SecurityOutcomeKind.VERIFIED_PATCH)
        self.assertEqual(decoded_envelope.artifact_id, "sec-0001")

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _outcome_envelope(schema_name=WORKFLOW_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        outcome = decode_security_outcome_payload(
            _outcome_payload(), schema_version=VERSION_4_2
        )
        self._assert_rejected(
            lambda: encode_security_outcome_envelope(_outcome_envelope(), outcome),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_payload_workflow_id_mismatch_with_envelope(self):
        payload = _outcome_payload()
        payload["workflow_id"] = "workflow-0002"
        envelope = _outcome_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.workflow_id",
        )

    def test_rejects_blob_backed_security_outcome(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0003",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _outcome_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_missing_or_mistyped_workflow_and_evidence_lineage(self):
        envelope = _outcome_envelope(
            lineage=[
                _ref("lima.vulnerability-evidence-package", "vep-0001", VEP_D),
                _ref("lima.repair-verification-report", "rvr-0001", RVR_D),
            ]
        )
        exception = self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload"))
        envelope = _outcome_envelope(
            lineage=[
                _ref("lima.stage-attempt", "wf-0001", WF_GOLDEN_D),
                _ref("lima.vulnerability-evidence-package", "vep-0001", VEP_D),
                _ref("lima.repair-verification-report", "rvr-0001", RVR_D),
            ]
        )
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        envelope = _outcome_envelope(
            lineage=[
                _ref("lima.workflow", "wf-0001", "7" * 64),
                _ref("lima.vulnerability-evidence-package", "vep-0001", VEP_D),
                _ref("lima.repair-verification-report", "rvr-0001", RVR_D),
            ]
        )
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _outcome_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _outcome_envelope(retention=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        payload = _outcome_payload()
        payload["kind"] = "mostly_harmless"
        envelope = _outcome_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_security_outcome_envelope(encode_envelope(envelope)),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.kind",
        )


if __name__ == "__main__":
    unittest.main()
