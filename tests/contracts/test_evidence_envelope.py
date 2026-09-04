"""Evidence domain envelope binding tests (IP-0002 sections 15 and 17.1)."""

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
from lima.contracts.evidence import (
    EVIDENCE_DOMAIN_SCHEMA_NAME,
    EvidenceDomainBundle,
    decode_evidence_envelope,
    encode_evidence_envelope,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "evidence_domain_bundle_v4_golden.json"
GOLDEN_PAYLOAD_DIGEST = "1b313f8ce082fd1721805c4eb6d232e104dabaa9e427f9a3f4699659b3796c51"


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


def _golden_bundle():
    return EvidenceDomainBundle.from_dict(_golden_payload(), schema_version=VERSION_4_0)


def _envelope(**overrides):
    kwargs = {
        "schema_name": EVIDENCE_DOMAIN_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "aep-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-1",
        "stage_attempt_id": "audit-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-audit",
        "created_at": "2026-09-01T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": GOLDEN_PAYLOAD_DIGEST,
        "classification": ArtifactClassification.SENSITIVE,
        "retention_class": RetentionClass.AUDIT,
        "payload": _golden_payload(),
        "lineage": [_tool_run_reference()],
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


class EvidenceEnvelopeTests(unittest.TestCase):
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception

    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        envelope = _envelope()
        bundle = _golden_bundle()
        data = encode_evidence_envelope(envelope, bundle)
        decoded_envelope, decoded_bundle = decode_evidence_envelope(data)
        self.assertEqual(decoded_bundle, bundle)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(encode_evidence_envelope(decoded_envelope, decoded_bundle), data)
        self.assertEqual(decoded_envelope.content_digest, GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(
            compute_content_digest(decoded_envelope.payload), GOLDEN_PAYLOAD_DIGEST
        )
        self.assertIsNone(decoded_envelope.blob_ref)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        bundle = _golden_bundle()
        wrong_name = _envelope(schema_name="lima.other-domain")
        self._assert_rejected(
            lambda: encode_evidence_envelope(wrong_name, bundle),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        self._assert_rejected(
            lambda: decode_evidence_envelope(encode_envelope(wrong_name)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        future_envelope = _envelope(schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_evidence_envelope(future_envelope, bundle),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_evidence_domain(self):
        blob_envelope = _envelope(
            payload=None,
            content_digest="4" * 64,
            blob_ref=ArtifactBlobReference(
                blob_id="blob-0001",
                content_digest="4" * 64,
                size_bytes=3740,
                media_type="application/json",
            ),
        )
        self._assert_rejected(
            lambda: decode_evidence_envelope(encode_envelope(blob_envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )
        self._assert_rejected(
            lambda: encode_evidence_envelope(blob_envelope, _golden_bundle()),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_payload_bundle_and_content_digest_mismatch(self):
        divergent_payload = _golden_payload()
        divergent_payload["signals"][0]["rule_id"] = "B603"
        divergent = _envelope(
            payload=divergent_payload,
            content_digest=compute_content_digest(divergent_payload),
        )
        self._assert_rejected(
            lambda: encode_evidence_envelope(divergent, _golden_bundle()),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload",
        )

    def test_rejects_missing_source_artifact_lineage(self):
        no_lineage = _envelope(lineage=[])
        self._assert_rejected(
            lambda: decode_evidence_envelope(encode_envelope(no_lineage)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.payload.evidence[0].source_artifact_ids[0]",
        )
        self._assert_rejected(
            lambda: encode_evidence_envelope(no_lineage, _golden_bundle()),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.payload.evidence[0].source_artifact_ids[0]",
        )

    def test_allows_additional_valid_lineage(self):
        extended = _envelope(
            lineage=[
                _tool_run_reference(),
                _tool_run_reference(artifact_id="tool-run-0002", content_digest="7" * 64),
            ]
        )
        envelope, bundle = decode_evidence_envelope(
            encode_evidence_envelope(extended, _golden_bundle())
        )
        self.assertEqual(len(envelope.lineage), 2)
        self.assertEqual(bundle, _golden_bundle())

    def _tampered_lineage(self, old, new):
        envelope = _envelope()
        data = encode_evidence_envelope(envelope, _golden_bundle())
        head, sep, tail = data.partition(old)
        self.assertTrue(sep, old)
        return head + new + tail

    def test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection(self):
        self._assert_rejected(
            lambda: decode_evidence_envelope(
                self._tampered_lineage(
                    b'"tenant_id":"tenant-1"', b'"tenant_id":"tenant-2"'
                )
            ),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
        )
        self._assert_rejected(
            lambda: decode_evidence_envelope(
                self._tampered_lineage(
                    b'"repository_snapshot_digest":"' + b"3" * 64 + b'"',
                    b'"repository_snapshot_digest":"' + b"9" * 64 + b'"',
                )
            ),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
        )
        self._assert_rejected(
            lambda: decode_evidence_envelope(
                self._tampered_lineage(
                    b'"artifact_id":"tool-run-0001"', b'"artifact_id":"aep-0001"'
                )
            ),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        public = _envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_evidence_envelope(encode_envelope(public)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        self._assert_rejected(
            lambda: encode_evidence_envelope(public, _golden_bundle()),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        ephemeral = _envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_evidence_envelope(encode_envelope(ephemeral)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )
        self._assert_rejected(
            lambda: encode_evidence_envelope(ephemeral, _golden_bundle()),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        envelope = _envelope()
        data = encode_evidence_envelope(envelope, _golden_bundle())
        marker = b'"level":"D0"'
        self.assertIn(marker, data)
        tampered = data.replace(marker, b'"level":"D1"', 1)
        self.assertNotEqual(tampered, data)
        exception = self._assert_rejected(
            lambda: decode_evidence_envelope(tampered),
            ContractErrorCode.DIGEST_MISMATCH,
        )
        self.assertNotIn("rule_id", str(exception))
        self.assertNotIn("B602", str(exception))


if __name__ == "__main__":
    unittest.main()
