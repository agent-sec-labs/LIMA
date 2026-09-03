"""Repair verification report envelope binding tests (IP-0006 packet sections 15 and 17.1)."""

import unittest
from pathlib import Path

from lima.contracts.codec import (
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
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
from lima.contracts.rvr import (
    REPAIR_VERIFICATION_REPORT_SCHEMA_NAME,
    decode_rvr_envelope,
    decode_rvr_payload,
    encode_rvr_envelope,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "repair_verification_report_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac"
)


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


def _vep_reference(**overrides):
    return _ref(
        "lima.vulnerability-evidence-package",
        "vep-0001",
        "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01",
        **overrides,
    )


def _golden_payload():
    return canonical_decode(FIXTURE.read_bytes())


def _golden_report():
    return decode_rvr_payload(_golden_payload(), schema_version=VERSION_4_0)


def _full_lineage():
    return [
        _vep_reference(),
        _ref("lima.candidate-patch", "patch-0001", "1" * 64),
        _ref("lima.candidate-patch", "patch-0002", "2" * 64),
        _ref("lima.gate-log", "sec-oracle-0001", "3" * 64),
        _ref("lima.gate-log", "sec-oracle-0002", "4" * 64),
        _ref("lima.gate-log", "diff-0001", "7" * 64),
        _ref("lima.gate-log", "test-run-0001", "8" * 64),
        _ref("lima.gate-log", "test-run-0002", "9" * 64),
    ]


def _envelope(**overrides):
    kwargs = {
        "schema_name": REPAIR_VERIFICATION_REPORT_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "rvr-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-1",
        "stage_attempt_id": "repair-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-repair-verifier",
        "created_at": "2026-09-02T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": GOLDEN_PAYLOAD_DIGEST,
        "classification": ArtifactClassification.SENSITIVE,
        "retention_class": RetentionClass.AUDIT,
        "payload": _golden_payload(),
        "lineage": _full_lineage(),
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


class RvrEnvelopeTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        envelope = _envelope()
        report = _golden_report()
        data = encode_rvr_envelope(envelope, report)
        decoded_envelope, decoded_report = decode_rvr_envelope(data)
        self.assertEqual(decoded_report, report)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(encode_rvr_envelope(decoded_envelope, decoded_report), data)
        self.assertEqual(decoded_envelope.content_digest, GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(
            compute_content_digest(decoded_envelope.payload), GOLDEN_PAYLOAD_DIGEST
        )
        self.assertIsNone(decoded_envelope.blob_ref)
        self.assertEqual(len(decoded_envelope.lineage), 8)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        report = _golden_report()
        wrong_name = _envelope(schema_name="lima.vulnerability-evidence-package")
        self._assert_rejected(
            lambda: encode_rvr_envelope(wrong_name, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        self._assert_rejected(
            lambda: decode_rvr_envelope(encode_envelope(wrong_name)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        future_envelope = _envelope(schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_rvr_envelope(future_envelope, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_rvr(self):
        report = _golden_report()
        blob_envelope = _envelope(
            payload=None,
            content_digest="4" * 64,
            blob_ref=ArtifactBlobReference(
                blob_id="blob-1",
                content_digest="4" * 64,
                size_bytes=1709,
                media_type="application/json",
            ),
        )
        self._assert_rejected(
            lambda: encode_rvr_envelope(blob_envelope, report),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )
        self._assert_rejected(
            lambda: decode_rvr_envelope(encode_envelope(blob_envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_payload_report_and_content_digest_mismatch(self):
        modified_payload = _golden_payload()
        modified_payload["candidates"] = []
        mismatched = decode_rvr_payload(modified_payload, schema_version=VERSION_4_0)
        self._assert_rejected(
            lambda: encode_rvr_envelope(_envelope(), mismatched),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload",
        )
        self._assert_rejected(
            lambda: _envelope(content_digest="0" * 64),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )

    def test_rejects_missing_vep_lineage_reference(self):
        report = _golden_report()
        no_vep = _envelope(lineage=[ref for ref in _full_lineage()[1:]])
        error = self._assert_rejected(
            lambda: encode_rvr_envelope(no_vep, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.source_vep"), error.field_path
        )
        self._assert_rejected(
            lambda: decode_rvr_envelope(encode_envelope(no_vep)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_vep_lineage_entry_with_wrong_schema_name_or_digest(self):
        report = _golden_report()
        lineage = _full_lineage()
        mis_typed = [_vep_reference(schema_name="lima.tool-run")] + lineage[1:]
        error = self._assert_rejected(
            lambda: encode_rvr_envelope(_envelope(lineage=mis_typed), report),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.source_vep.artifact_id"),
            error.field_path,
        )
        wrong_digest = [_vep_reference(content_digest="9" * 64)] + lineage[1:]
        self._assert_rejected(
            lambda: encode_rvr_envelope(_envelope(lineage=wrong_digest), report),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload.source_vep.content_digest",
        )

    def test_rejects_missing_patch_and_gate_evidence_lineage_references(self):
        report = _golden_report()
        keep_evidence = [
            ref
            for ref in _full_lineage()[1:]
            if ref.artifact_id.startswith(("sec-", "diff-", "test-"))
        ]
        no_patches = _envelope(lineage=[_vep_reference()] + keep_evidence)
        error = self._assert_rejected(
            lambda: encode_rvr_envelope(no_patches, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.candidates[0].patch"),
            error.field_path,
        )
        only_vep_and_patches = _envelope(
            lineage=[_vep_reference()]
            + [ref for ref in _full_lineage()[1:3]]
        )
        error = self._assert_rejected(
            lambda: encode_rvr_envelope(only_vep_and_patches, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.candidates[0].gates["),
            error.field_path,
        )

    def test_allows_additional_valid_lineage(self):
        report = _golden_report()
        extra = _ref("lima.gate-log", "extra-log-0001", "a" * 64)
        envelope = _envelope(lineage=_full_lineage() + [extra])
        data = encode_rvr_envelope(envelope, report)
        decoded_envelope, decoded_report = decode_rvr_envelope(data)
        self.assertEqual(decoded_report, report)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(len(decoded_envelope.lineage), 9)

    def test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection(self):
        self._assert_rejected(
            lambda: _envelope(lineage=[_vep_reference(tenant_id="tenant-2")]),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
            "$.lineage[0].tenant_id",
        )
        self._assert_rejected(
            lambda: _envelope(
                lineage=[_vep_reference(repository_snapshot_digest="9" * 64)]
            ),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
            "$.lineage[0].repository_snapshot_digest",
        )
        self._assert_rejected(
            lambda: _envelope(lineage=[_vep_reference(artifact_id="rvr-0001")]),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
            "$.lineage[0].artifact_id",
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        report = _golden_report()
        public = _envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: encode_rvr_envelope(public, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        self._assert_rejected(
            lambda: decode_rvr_envelope(encode_envelope(public)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        ephemeral = _envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: encode_rvr_envelope(ephemeral, report),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )
        self._assert_rejected(
            lambda: decode_rvr_envelope(encode_envelope(ephemeral)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        data = encode_rvr_envelope(_envelope(), _golden_report())
        wire = canonical_decode(data)
        wire["payload"]["candidates"] = []
        tampered = canonical_encode(wire)
        self._assert_rejected(
            lambda: decode_rvr_envelope(tampered),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )


if __name__ == "__main__":
    unittest.main()
