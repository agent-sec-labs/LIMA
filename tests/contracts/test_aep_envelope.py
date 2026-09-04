"""Audit evidence package envelope binding tests (IP-0004 packet sections 15 and 17.1)."""

import unittest
from pathlib import Path

from lima.contracts.aep import (
    AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME,
    decode_aep_envelope,
    decode_aep_payload,
    encode_aep_envelope,
)
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

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "audit_evidence_package_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0"
)


def _profile_reference(**overrides):
    kwargs = {
        "schema_name": "lima.repository-profile",
        "schema_version": VERSION_4_0,
        "artifact_id": "profile-0001",
        "tenant_id": "tenant-1",
        "repository_snapshot_digest": "3" * 64,
        "content_digest": "ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc",
    }
    kwargs.update(overrides)
    return ArtifactReference(**kwargs)


def _tool_run_reference(**overrides):
    kwargs = {
        "schema_name": "lima.tool-run",
        "schema_version": VERSION_4_0,
        "artifact_id": "tool-run-0001",
        "tenant_id": "tenant-1",
        "repository_snapshot_digest": "3" * 64,
        "content_digest": "4" * 64,
    }
    kwargs.update(overrides)
    return ArtifactReference(**kwargs)


def _golden_payload():
    return canonical_decode(FIXTURE.read_bytes())


def _golden_package():
    return decode_aep_payload(_golden_payload(), schema_version=VERSION_4_0)


def _envelope(**overrides):
    kwargs = {
        "schema_name": AUDIT_EVIDENCE_PACKAGE_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "aep-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-1",
        "stage_attempt_id": "audit-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-audit",
        "created_at": "2026-09-02T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": GOLDEN_PAYLOAD_DIGEST,
        "classification": ArtifactClassification.SENSITIVE,
        "retention_class": RetentionClass.AUDIT,
        "payload": _golden_payload(),
        "lineage": [_profile_reference(), _tool_run_reference()],
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


class AepEnvelopeTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        envelope = _envelope()
        package = _golden_package()
        data = encode_aep_envelope(envelope, package)
        decoded_envelope, decoded_package = decode_aep_envelope(data)
        self.assertEqual(decoded_package, package)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(encode_aep_envelope(decoded_envelope, decoded_package), data)
        self.assertEqual(decoded_envelope.content_digest, GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(
            compute_content_digest(decoded_envelope.payload), GOLDEN_PAYLOAD_DIGEST
        )
        self.assertIsNone(decoded_envelope.blob_ref)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        package = _golden_package()
        wrong_name = _envelope(schema_name="lima.evidence-domain")
        self._assert_rejected(
            lambda: encode_aep_envelope(wrong_name, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(wrong_name)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        future_envelope = _envelope(schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_aep_envelope(future_envelope, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_aep(self):
        package = _golden_package()
        blob_envelope = _envelope(
            payload=None,
            content_digest="4" * 64,
            blob_ref=ArtifactBlobReference(
                blob_id="blob-1",
                content_digest="4" * 64,
                size_bytes=4235,
                media_type="application/json",
            ),
        )
        self._assert_rejected(
            lambda: encode_aep_envelope(blob_envelope, package),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(blob_envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_payload_package_and_content_digest_mismatch(self):
        modified_payload = _golden_payload()
        modified_payload["revision"] = 2
        mismatched = decode_aep_payload(modified_payload, schema_version=VERSION_4_0)
        self._assert_rejected(
            lambda: encode_aep_envelope(_envelope(), mismatched),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload",
        )
        self._assert_rejected(
            lambda: _envelope(content_digest="0" * 64),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )

    def test_rejects_missing_profile_lineage_reference(self):
        package = _golden_package()
        no_profile = _envelope(lineage=[_tool_run_reference()])
        error = self._assert_rejected(
            lambda: encode_aep_envelope(no_profile, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.repository_profile_artifact_ids"),
            error.field_path,
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(no_profile)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_profile_lineage_entry_with_wrong_schema_name(self):
        package = _golden_package()
        mis_typed = _envelope(
            lineage=[
                _profile_reference(schema_name="lima.tool-run"),
                _tool_run_reference(),
            ]
        )
        error = self._assert_rejected(
            lambda: encode_aep_envelope(mis_typed, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.repository_profile_artifact_ids"),
            error.field_path,
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(mis_typed)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_missing_evidence_source_lineage(self):
        package = _golden_package()
        no_tool_run = _envelope(lineage=[_profile_reference()])
        error = self._assert_rejected(
            lambda: encode_aep_envelope(no_tool_run, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.evidence_domain.evidence"),
            error.field_path,
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(no_tool_run)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_allows_additional_valid_lineage(self):
        package = _golden_package()
        extra = _tool_run_reference(artifact_id="tool-run-0002", content_digest="7" * 64)
        envelope = _envelope(
            lineage=[_profile_reference(), _tool_run_reference(), extra]
        )
        data = encode_aep_envelope(envelope, package)
        decoded_envelope, decoded_package = decode_aep_envelope(data)
        self.assertEqual(decoded_package, package)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(len(decoded_envelope.lineage), 3)

    def test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection(self):
        self._assert_rejected(
            lambda: _envelope(lineage=[_profile_reference(tenant_id="tenant-2")]),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
            "$.lineage[0].tenant_id",
        )
        self._assert_rejected(
            lambda: _envelope(
                lineage=[_profile_reference(repository_snapshot_digest="9" * 64)]
            ),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
            "$.lineage[0].repository_snapshot_digest",
        )
        self._assert_rejected(
            lambda: _envelope(lineage=[_profile_reference(artifact_id="aep-0001")]),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
            "$.lineage[0].artifact_id",
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        package = _golden_package()
        public = _envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: encode_aep_envelope(public, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(public)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        ephemeral = _envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: encode_aep_envelope(ephemeral, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )
        self._assert_rejected(
            lambda: decode_aep_envelope(encode_envelope(ephemeral)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        data = encode_aep_envelope(_envelope(), _golden_package())
        wire = canonical_decode(data)
        wire["payload"]["revision"] = 2
        tampered = canonical_encode(wire)
        self._assert_rejected(
            lambda: decode_aep_envelope(tampered),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )


if __name__ == "__main__":
    unittest.main()
