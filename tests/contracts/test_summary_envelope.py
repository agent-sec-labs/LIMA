"""Summary + Failure envelope binding tests (IP-0009 packet sections 15 and 17.5)."""

import unittest
from pathlib import Path

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
from lima.contracts.summary import (
    FAILURE_REPORT_SCHEMA_NAME,
    WORKFLOW_SUMMARY_SCHEMA_NAME,
    decode_failure_report_envelope,
    decode_failure_report_payload,
    decode_workflow_summary_envelope,
    decode_workflow_summary_payload,
    encode_failure_report_envelope,
    encode_workflow_summary_envelope,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

WF_D = "3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146"
SO_D = "bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831"
VEP_D = "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
RVR_D = "a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac"
SA_D = "34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259"
ALT_AUDIT_D = "418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4"
SUM_GOLDEN_D = "5df80cd44cf3af456d153f967508e46b8d2a0f0595b3bb306a8fe41638cd0e34"
SUM_LEG_D = "18c1faa3e058b4d5b293fd4148fa3ad5834a804c84928f868c5cc9a8b6a097d4"
FR_GOLDEN_D = "05a2005fd4856ff2e8e098ed6989a29aa24146b0672af086a9c3b62c07935539"

# Distinguish "caller did not pass payload" from an explicit None arrange value
# (DR-IP-0007-IMPL-01 fix pattern; mandatory checklist item 6).
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


def _summary_payload():
    return canonical_decode((FIXTURES / "workflow_summary_v4_golden.json").read_bytes())


def _legacy_summary_payload():
    return canonical_decode((FIXTURES / "workflow_summary_legacy_v4_golden.json").read_bytes())


def _failure_payload():
    return canonical_decode((FIXTURES / "failure_report_v4_golden.json").read_bytes())


def _summary_lineage(extra=()):
    return [
        _ref("lima.workflow", "wf-0001", WF_D),
        _ref("lima.security-outcome", "sec-0001", SO_D),
        _ref("lima.run-manifest", "run-0001", "1" * 64),
        _ref("lima.stage-attempt", "attempt-audit-0001", ALT_AUDIT_D),
        _ref("lima.stage-attempt", "attempt-profile-0001", SA_D),
        _ref("lima.vulnerability-evidence-package", "vep-0001", VEP_D),
        _ref("lima.repair-verification-report", "rvr-0001", RVR_D),
        *extra,
    ]


def _legacy_summary_lineage(extra=()):
    return [
        _ref("lima.legacy-report", "legacy-report-0001", "7" * 64),
        _ref("lima.legacy-scan-log", "legacy-scan-log-0001", "8" * 64),
        *extra,
    ]


def _failure_lineage(extra=()):
    return [
        _ref("lima.workflow", "wf-0001", WF_D),
        _ref("lima.stage-attempt", "attempt-profile-0001", SA_D),
        _ref("lima.sandbox-log", "sandbox-log-0001", "7" * 64),
        _ref("lima.sandbox-run", "sandbox-run-0001", "9" * 64),
        *extra,
    ]


def _envelope(**overrides):
    kwargs = {
        "schema_name": WORKFLOW_SUMMARY_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "summary-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-0001",
        "stage_attempt_id": "summarize-emit-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-orchestrator",
        "created_at": "2026-09-06T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": SUM_GOLDEN_D,
        "classification": ArtifactClassification.INTERNAL,
        "retention_class": RetentionClass.AUDIT,
        "payload": _summary_payload(),
        "lineage": _summary_lineage(),
        "supersedes": None,
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


def _summary_envelope(payload=_UNSET, content_digest=SUM_GOLDEN_D, lineage=None,
                      classification=ArtifactClassification.INTERNAL,
                      retention=RetentionClass.AUDIT, schema_name=WORKFLOW_SUMMARY_SCHEMA_NAME,
                      blob_ref=None):
    return _envelope(
        schema_name=schema_name,
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_summary_payload() if payload is _UNSET else payload,
        lineage=_summary_lineage() if lineage is None else lineage,
        blob_ref=blob_ref,
    )


def _legacy_summary_envelope(payload=_UNSET, content_digest=SUM_LEG_D, lineage=None,
                             classification=ArtifactClassification.INTERNAL,
                             retention=RetentionClass.STANDARD,
                             schema_name=WORKFLOW_SUMMARY_SCHEMA_NAME, blob_ref=None):
    return _envelope(
        artifact_id="summary-legacy-0001",
        schema_name=schema_name,
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_legacy_summary_payload() if payload is _UNSET else payload,
        lineage=_legacy_summary_lineage() if lineage is None else lineage,
        blob_ref=blob_ref,
    )


def _failure_envelope(payload=_UNSET, content_digest=FR_GOLDEN_D, lineage=None,
                      classification=ArtifactClassification.SENSITIVE,
                      retention=RetentionClass.AUDIT, schema_name=FAILURE_REPORT_SCHEMA_NAME,
                      blob_ref=None):
    return _envelope(
        schema_name=schema_name,
        artifact_id="failure-0001",
        stage_attempt_id="attempt-profile-0001",
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_failure_payload() if payload is _UNSET else payload,
        lineage=_failure_lineage() if lineage is None else lineage,
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


class WorkflowSummaryEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        summary = decode_workflow_summary_payload(
            _summary_payload(), schema_version=VERSION_4_0
        )
        first = encode_workflow_summary_envelope(_summary_envelope(), summary)
        decoded_envelope, decoded_summary = decode_workflow_summary_envelope(first)
        second = encode_workflow_summary_envelope(decoded_envelope, decoded_summary)
        self.assertEqual(first, second)
        self.assertEqual(decoded_envelope.artifact_id, "summary-0001")
        self.assertEqual(decoded_summary.source.value, "chain")
        self.assertEqual(len(decoded_summary.stage_attempts), 2)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _summary_envelope(schema_name=FAILURE_REPORT_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        summary = decode_workflow_summary_payload(
            _summary_payload(), schema_version=VERSION_4_2
        )
        self._assert_rejected(
            lambda: encode_workflow_summary_envelope(_summary_envelope(), summary),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_summary(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0001",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _summary_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_missing_or_mistyped_typed_lineage(self):
        envelope = _summary_envelope(
            lineage=[entry for entry in _summary_lineage()
                     if entry.artifact_id != "sec-0001"]
        )
        exception = self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.security_outcome"))
        envelope = _summary_envelope(
            lineage=[_ref("lima.workflow", "sec-0001", SO_D),
                     *[entry for entry in _summary_lineage()
                       if entry.artifact_id != "sec-0001"]]
        )
        self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        envelope = _summary_envelope(
            lineage=[_ref("lima.security-outcome", "sec-0001", "7" * 64),
                     *[entry for entry in _summary_lineage()
                       if entry.artifact_id != "sec-0001"]]
        )
        self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_rejects_missing_legacy_id_lineage(self):
        envelope = _legacy_summary_envelope(
            lineage=[entry for entry in _legacy_summary_lineage()
                     if entry.artifact_id != "legacy-scan-log-0001"]
        )
        exception = self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.legacy_artifact_ids"))
        decode_workflow_summary_envelope(
            encode_envelope(_legacy_summary_envelope())
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _summary_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _summary_envelope(retention=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_workflow_summary_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )


class FailureReportEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        failure = decode_failure_report_payload(_failure_payload(), schema_version=VERSION_4_0)
        first = encode_failure_report_envelope(_failure_envelope(), failure)
        decoded_envelope, decoded_failure = decode_failure_report_envelope(first)
        second = encode_failure_report_envelope(decoded_envelope, decoded_failure)
        self.assertEqual(first, second)
        self.assertEqual(decoded_envelope.artifact_id, "failure-0001")
        self.assertEqual(decoded_failure.owner, "lima-sandbox-supervisor")

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _failure_envelope(schema_name=WORKFLOW_SUMMARY_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        failure = decode_failure_report_payload(
            _failure_payload(), schema_version=VERSION_4_2
        )
        self._assert_rejected(
            lambda: encode_failure_report_envelope(_failure_envelope(), failure),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_failure_report(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0002",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _failure_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_missing_or_mistyped_scope_links_lineage(self):
        envelope = _failure_envelope(
            lineage=[entry for entry in _failure_lineage()
                     if entry.artifact_id != "attempt-profile-0001"]
        )
        exception = self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.stage_attempt"))
        envelope = _failure_envelope(
            lineage=[_ref("lima.stage-attempt", "wf-0001", WF_D),
                     *[entry for entry in _failure_lineage()
                       if entry.artifact_id != "wf-0001"]]
        )
        self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_missing_evidence_id_lineage(self):
        envelope = _failure_envelope(
            lineage=[entry for entry in _failure_lineage()
                     if entry.artifact_id != "sandbox-run-0001"]
        )
        exception = self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.evidence_artifact_ids"))

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _failure_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _failure_envelope(retention=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        payload = _failure_payload()
        payload["failure_kind"] = "act_of_god"
        envelope = _failure_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_failure_report_envelope(encode_envelope(envelope)),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.failure_kind",
        )


if __name__ == "__main__":
    unittest.main()
