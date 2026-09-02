"""Repository profile envelope binding tests (IP-0003 packet sections 15 and 17.1)."""

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
from lima.contracts.profile import (
    REPOSITORY_PROFILE_SCHEMA_NAME,
    decode_profile_envelope,
    decode_profile_payload,
    encode_profile_envelope,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent / "fixtures" / "repository_profile_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc"
)


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


def _golden_profile():
    return decode_profile_payload(_golden_payload(), schema_version=VERSION_4_0)


def _envelope(**overrides):
    kwargs = {
        "schema_name": REPOSITORY_PROFILE_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "profile-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-1",
        "stage_attempt_id": "classify-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-profile-classifier",
        "created_at": "2026-09-02T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": GOLDEN_PAYLOAD_DIGEST,
        "classification": ArtifactClassification.INTERNAL,
        "retention_class": RetentionClass.STANDARD,
        "payload": _golden_payload(),
        "lineage": [_tool_run_reference()],
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


class ProfileEnvelopeTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        envelope = _envelope()
        profile = _golden_profile()
        data = encode_profile_envelope(envelope, profile)
        decoded_envelope, decoded_profile = decode_profile_envelope(data)
        self.assertEqual(decoded_profile, profile)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(encode_profile_envelope(decoded_envelope, decoded_profile), data)
        self.assertEqual(decoded_envelope.content_digest, GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(
            compute_content_digest(decoded_envelope.payload), GOLDEN_PAYLOAD_DIGEST
        )
        self.assertIsNone(decoded_envelope.blob_ref)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        profile = _golden_profile()
        wrong_name = _envelope(schema_name="lima.evidence-domain")
        self._assert_rejected(
            lambda: encode_profile_envelope(wrong_name, profile),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        self._assert_rejected(
            lambda: decode_profile_envelope(encode_envelope(wrong_name)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        future_envelope = _envelope(schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_profile_envelope(future_envelope, profile),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_profile(self):
        profile = _golden_profile()
        blob_envelope = _envelope(
            payload=None,
            content_digest="4" * 64,
            blob_ref=ArtifactBlobReference(
                blob_id="blob-1",
                content_digest="4" * 64,
                size_bytes=8,
                media_type="application/json",
            ),
        )
        self._assert_rejected(
            lambda: encode_profile_envelope(blob_envelope, profile),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )
        self._assert_rejected(
            lambda: decode_profile_envelope(encode_envelope(blob_envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_payload_profile_and_content_digest_mismatch(self):
        modified_payload = _golden_payload()
        modified_payload["file_count"] = 43
        mismatched = decode_profile_payload(modified_payload, schema_version=VERSION_4_0)
        self._assert_rejected(
            lambda: encode_profile_envelope(_envelope(), mismatched),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload",
        )
        self._assert_rejected(
            lambda: _envelope(content_digest="0" * 64),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )

    def test_rejects_missing_source_artifact_lineage(self):
        profile = _golden_profile()
        no_lineage = _envelope(lineage=[])
        error = self._assert_rejected(
            lambda: encode_profile_envelope(no_lineage, profile),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(error.field_path.startswith("$.payload."), error.field_path)
        self._assert_rejected(
            lambda: decode_profile_envelope(encode_envelope(no_lineage)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_allows_additional_valid_lineage(self):
        profile = _golden_profile()
        extra = _tool_run_reference(artifact_id="tool-run-0002", content_digest="7" * 64)
        envelope = _envelope(lineage=[_tool_run_reference(), extra])
        data = encode_profile_envelope(envelope, profile)
        decoded_envelope, decoded_profile = decode_profile_envelope(data)
        self.assertEqual(decoded_profile, profile)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(len(decoded_envelope.lineage), 2)

    def test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection(self):
        self._assert_rejected(
            lambda: _envelope(lineage=[_tool_run_reference(tenant_id="tenant-2")]),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
            "$.lineage[0].tenant_id",
        )
        self._assert_rejected(
            lambda: _envelope(
                lineage=[_tool_run_reference(repository_snapshot_digest="9" * 64)]
            ),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
            "$.lineage[0].repository_snapshot_digest",
        )
        self._assert_rejected(
            lambda: _envelope(lineage=[_tool_run_reference(artifact_id="profile-0001")]),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
            "$.lineage[0].artifact_id",
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        profile = _golden_profile()
        public = _envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: encode_profile_envelope(public, profile),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        self._assert_rejected(
            lambda: decode_profile_envelope(encode_envelope(public)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        ephemeral = _envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: encode_profile_envelope(ephemeral, profile),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )
        self._assert_rejected(
            lambda: decode_profile_envelope(encode_envelope(ephemeral)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        data = encode_profile_envelope(_envelope(), _golden_profile())
        wire = canonical_decode(data)
        wire["payload"]["file_count"] = 43
        tampered = canonical_encode(wire)
        self._assert_rejected(
            lambda: decode_profile_envelope(tampered),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )


if __name__ == "__main__":
    unittest.main()
