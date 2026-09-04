"""Vulnerability evidence package envelope binding tests (IP-0005 packet sections 15 and 17.1)."""

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
from lima.contracts.vep import (
    VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME,
    decode_vep_envelope,
    decode_vep_payload,
    encode_vep_envelope,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURE = (
    Path(__file__).resolve().parent
    / "fixtures"
    / "vulnerability_evidence_package_v4_golden.json"
)
GOLDEN_PAYLOAD_DIGEST = (
    "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
)


def _aep_reference(**overrides):
    kwargs = {
        "schema_name": "lima.audit-evidence-package",
        "schema_version": VERSION_4_0,
        "artifact_id": "aep-0001",
        "tenant_id": "tenant-1",
        "repository_snapshot_digest": "3" * 64,
        "content_digest": "f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0",
    }
    kwargs.update(overrides)
    return ArtifactReference(**kwargs)


def _oracle_reference(**overrides):
    kwargs = {
        "schema_name": "lima.oracle-script",
        "schema_version": VERSION_4_0,
        "artifact_id": "oracle-0001",
        "tenant_id": "tenant-1",
        "repository_snapshot_digest": "3" * 64,
        "content_digest": "7" * 64,
    }
    kwargs.update(overrides)
    return ArtifactReference(**kwargs)


def _run_reference(**overrides):
    kwargs = {
        "schema_name": "lima.sandbox-run",
        "schema_version": VERSION_4_0,
        "artifact_id": "run-0001",
        "tenant_id": "tenant-1",
        "repository_snapshot_digest": "3" * 64,
        "content_digest": "8" * 64,
    }
    kwargs.update(overrides)
    return ArtifactReference(**kwargs)


def _golden_payload():
    return canonical_decode(FIXTURE.read_bytes())


def _golden_package():
    return decode_vep_payload(_golden_payload(), schema_version=VERSION_4_0)


def _envelope(**overrides):
    kwargs = {
        "schema_name": VULNERABILITY_EVIDENCE_PACKAGE_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "vep-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-1",
        "stage_attempt_id": "mining-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-mining",
        "created_at": "2026-09-02T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": GOLDEN_PAYLOAD_DIGEST,
        "classification": ArtifactClassification.SENSITIVE,
        "retention_class": RetentionClass.AUDIT,
        "payload": _golden_payload(),
        "lineage": [_aep_reference(), _oracle_reference(), _run_reference()],
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


class VepEnvelopeTests(unittest.TestCase):
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
        data = encode_vep_envelope(envelope, package)
        decoded_envelope, decoded_package = decode_vep_envelope(data)
        self.assertEqual(decoded_package, package)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(encode_vep_envelope(decoded_envelope, decoded_package), data)
        self.assertEqual(decoded_envelope.content_digest, GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(
            compute_content_digest(decoded_envelope.payload), GOLDEN_PAYLOAD_DIGEST
        )
        self.assertIsNone(decoded_envelope.blob_ref)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        package = _golden_package()
        wrong_name = _envelope(schema_name="lima.audit-evidence-package")
        self._assert_rejected(
            lambda: encode_vep_envelope(wrong_name, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        self._assert_rejected(
            lambda: decode_vep_envelope(encode_envelope(wrong_name)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        future_envelope = _envelope(schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_vep_envelope(future_envelope, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_vep(self):
        package = _golden_package()
        blob_envelope = _envelope(
            payload=None,
            content_digest="4" * 64,
            blob_ref=ArtifactBlobReference(
                blob_id="blob-1",
                content_digest="4" * 64,
                size_bytes=2091,
                media_type="application/json",
            ),
        )
        self._assert_rejected(
            lambda: encode_vep_envelope(blob_envelope, package),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )
        self._assert_rejected(
            lambda: decode_vep_envelope(encode_envelope(blob_envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_payload_package_and_content_digest_mismatch(self):
        modified_payload = _golden_payload()
        modified_payload["impact"] = "A different impact statement."
        mismatched = decode_vep_payload(modified_payload, schema_version=VERSION_4_0)
        self._assert_rejected(
            lambda: encode_vep_envelope(_envelope(), mismatched),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload",
        )
        self._assert_rejected(
            lambda: _envelope(content_digest="0" * 64),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )

    def test_rejects_missing_aep_lineage_reference(self):
        package = _golden_package()
        no_aep = _envelope(lineage=[_oracle_reference(), _run_reference()])
        error = self._assert_rejected(
            lambda: encode_vep_envelope(no_aep, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.source_aep"), error.field_path
        )
        self._assert_rejected(
            lambda: decode_vep_envelope(encode_envelope(no_aep)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_aep_lineage_entry_with_wrong_schema_name_or_digest(self):
        package = _golden_package()
        wrong_schema = _envelope(
            lineage=[
                _aep_reference(schema_name="lima.tool-run"),
                _oracle_reference(),
                _run_reference(),
            ]
        )
        error = self._assert_rejected(
            lambda: encode_vep_envelope(wrong_schema, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.source_aep.artifact_id"),
            error.field_path,
        )
        wrong_digest = _envelope(
            lineage=[
                _aep_reference(content_digest="9" * 64),
                _oracle_reference(),
                _run_reference(),
            ]
        )
        self._assert_rejected(
            lambda: encode_vep_envelope(wrong_digest, package),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.payload.source_aep.content_digest",
        )

    def test_rejects_missing_oracle_and_run_lineage_references(self):
        package = _golden_package()
        no_oracle = _envelope(lineage=[_aep_reference(), _run_reference()])
        error = self._assert_rejected(
            lambda: encode_vep_envelope(no_oracle, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.oracle.oracle_artifact_id"),
            error.field_path,
        )
        no_run = _envelope(lineage=[_aep_reference(), _oracle_reference()])
        error = self._assert_rejected(
            lambda: encode_vep_envelope(no_run, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            error.field_path.startswith("$.payload.reproduction_runs"),
            error.field_path,
        )

    def test_allows_additional_valid_lineage(self):
        package = _golden_package()
        extra = _run_reference(artifact_id="run-0002", content_digest="9" * 64)
        envelope = _envelope(
            lineage=[_aep_reference(), _oracle_reference(), _run_reference(), extra]
        )
        data = encode_vep_envelope(envelope, package)
        decoded_envelope, decoded_package = decode_vep_envelope(data)
        self.assertEqual(decoded_package, package)
        self.assertEqual(decoded_envelope, envelope)
        self.assertEqual(len(decoded_envelope.lineage), 4)

    def test_inherits_cross_tenant_cross_snapshot_and_self_reference_rejection(self):
        self._assert_rejected(
            lambda: _envelope(lineage=[_aep_reference(tenant_id="tenant-2")]),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
            "$.lineage[0].tenant_id",
        )
        self._assert_rejected(
            lambda: _envelope(
                lineage=[_aep_reference(repository_snapshot_digest="9" * 64)]
            ),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
            "$.lineage[0].repository_snapshot_digest",
        )
        self._assert_rejected(
            lambda: _envelope(lineage=[_aep_reference(artifact_id="vep-0001")]),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
            "$.lineage[0].artifact_id",
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        package = _golden_package()
        public = _envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: encode_vep_envelope(public, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        self._assert_rejected(
            lambda: decode_vep_envelope(encode_envelope(public)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        ephemeral = _envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: encode_vep_envelope(ephemeral, package),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )
        self._assert_rejected(
            lambda: decode_vep_envelope(encode_envelope(ephemeral)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        data = encode_vep_envelope(_envelope(), _golden_package())
        wire = canonical_decode(data)
        wire["payload"]["impact"] = "Tampered impact statement."
        tampered = canonical_encode(wire)
        self._assert_rejected(
            lambda: decode_vep_envelope(tampered),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )


if __name__ == "__main__":
    unittest.main()
