"""Execution-intent pair envelope binding tests (IP-0008 packet sections 15 and 17.4)."""

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
from lima.contracts.execution import (
    PLAN_SCHEMA_NAME,
    RUN_MANIFEST_SCHEMA_NAME,
    decode_plan_envelope,
    decode_plan_payload,
    decode_run_manifest_envelope,
    decode_run_manifest_payload,
    encode_plan_envelope,
    encode_run_manifest_envelope,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)
FIXTURES = Path(__file__).resolve().parent / "fixtures"

VEP_D = "cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01"
WF_D = "3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146"
ALT_AUDIT_D = "418c461a1d82fcc9cbf6b60d1caad21e76491abe2d4f4a0a3a1a178cb15e8fb4"
SA_GOLDEN_D = "34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259"
PLAN_GOLDEN_D = "4e49b63d3f3cb50ef302781296cabbb02e4267b0675b7922a9bd1eae4077495a"
PLAN_FC_D = "9390344cd8018f450d115b085b577a7c723fb0abf214c552bd2cc9de6711851c"
RM_GOLDEN_D = "213fbebd48a966ee9071b5a19f385731e833b17f4d8c7c653c55b2c19eaf9cd7"

# Distinguish "caller did not pass payload/supersedes" from an explicit None
# arrange value (DR-IP-0007-IMPL-01 fix pattern; checklist item 6).
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


def _plan_payload():
    return canonical_decode((FIXTURES / "plan_v4_golden.json").read_bytes())


def _plan_fc_payload():
    return canonical_decode((FIXTURES / "plan_full_chain_v4_golden.json").read_bytes())


def _manifest_payload():
    return canonical_decode((FIXTURES / "run_manifest_v4_golden.json").read_bytes())


def _plan_lineage(extra=()):
    return [_ref("lima.vulnerability-evidence-package", "vep-0001", VEP_D), *extra]


def _manifest_lineage(extra=()):
    return [
        _ref("lima.plan", "plan-0002", PLAN_FC_D),
        _ref("lima.workflow", "wf-0001", WF_D),
        _ref("lima.stage-attempt", "attempt-audit-0001", ALT_AUDIT_D),
        _ref("lima.stage-attempt", "attempt-profile-0001", SA_GOLDEN_D),
        _ref("lima.sandbox-run", "sandbox-run-0001", "7" * 64),
        _ref("lima.tool-bundle", "tool-bundle-0001", "8" * 64),
        *extra,
    ]


def _envelope(**overrides):
    kwargs = {
        "schema_name": PLAN_SCHEMA_NAME,
        "schema_version": VERSION_4_0,
        "artifact_id": "plan-0001",
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-0001",
        "stage_attempt_id": "plan-emit-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-planner",
        "created_at": "2026-09-06T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": PLAN_GOLDEN_D,
        "classification": ArtifactClassification.INTERNAL,
        "retention_class": RetentionClass.STANDARD,
        "payload": _plan_payload(),
        "lineage": _plan_lineage(),
        "supersedes": None,
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


def _plan_envelope(payload=_UNSET, content_digest=PLAN_GOLDEN_D, lineage=None,
                   supersedes=_UNSET, classification=ArtifactClassification.INTERNAL,
                   retention=RetentionClass.STANDARD, schema_name=PLAN_SCHEMA_NAME,
                   blob_ref=None):
    return _envelope(
        schema_name=schema_name,
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_plan_payload() if payload is _UNSET else payload,
        lineage=_plan_lineage() if lineage is None else lineage,
        supersedes=None if supersedes is _UNSET else supersedes,
        blob_ref=blob_ref,
    )


def _manifest_envelope(payload=_UNSET, content_digest=RM_GOLDEN_D, lineage=None,
                       classification=ArtifactClassification.SENSITIVE,
                       retention=RetentionClass.AUDIT,
                       schema_name=RUN_MANIFEST_SCHEMA_NAME, blob_ref=None):
    return _envelope(
        schema_name=schema_name,
        artifact_id="run-0001",
        stage_attempt_id="summarize-emit-1",
        content_digest=content_digest,
        classification=classification,
        retention_class=retention,
        payload=_manifest_payload() if payload is _UNSET else payload,
        lineage=_manifest_lineage() if lineage is None else lineage,
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


class PlanEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        plan = decode_plan_payload(_plan_payload(), schema_version=VERSION_4_0)
        first = encode_plan_envelope(_plan_envelope(), plan)
        decoded_envelope, decoded_plan = decode_plan_envelope(first)
        second = encode_plan_envelope(decoded_envelope, decoded_plan)
        self.assertEqual(first, second)
        self.assertEqual(decoded_envelope.artifact_id, "plan-0001")
        self.assertEqual(decoded_plan.workflow_mode.value, "verify_vep")
        self.assertEqual(len(decoded_plan.inputs), 1)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _plan_envelope(schema_name=RUN_MANIFEST_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        plan = decode_plan_payload(_plan_payload(), schema_version=VERSION_4_2)
        self._assert_rejected(
            lambda: encode_plan_envelope(_plan_envelope(), plan),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_plan(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0001",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _plan_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_revision_supersedes_coupling_enforced(self):
        envelope = _plan_envelope(supersedes=_ref("lima.plan", "plan-0000", "0" * 64))
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _plan_envelope(
            payload=_plan_fc_payload(), content_digest=PLAN_FC_D
        )
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _plan_envelope(
            payload=_plan_fc_payload(),
            content_digest=PLAN_FC_D,
            supersedes=_ref("lima.workflow", "plan-0000", "0" * 64),
        )
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _plan_envelope(
            payload=_plan_fc_payload(),
            content_digest=PLAN_FC_D,
            supersedes=_ref("lima.plan", "plan-0000", "0" * 64),
        )
        decode_plan_envelope(encode_envelope(envelope))

    def test_rejects_missing_or_mistyped_vep_lineage(self):
        envelope = _plan_envelope(lineage=[])
        exception = self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload"))
        envelope = _plan_envelope(
            lineage=[_ref("lima.workflow", "vep-0001", VEP_D)]
        )
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        envelope = _plan_envelope(
            lineage=[_ref("lima.vulnerability-evidence-package", "vep-0001", "7" * 64)]
        )
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _plan_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _plan_envelope(retention=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_plan_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )


class RunManifestEnvelopeTests(_RejectionMixin, unittest.TestCase):
    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        manifest = decode_run_manifest_payload(
            _manifest_payload(), schema_version=VERSION_4_0
        )
        first = encode_run_manifest_envelope(_manifest_envelope(), manifest)
        decoded_envelope, decoded_manifest = decode_run_manifest_envelope(first)
        second = encode_run_manifest_envelope(decoded_envelope, decoded_manifest)
        self.assertEqual(first, second)
        self.assertEqual(decoded_envelope.artifact_id, "run-0001")
        self.assertEqual(decoded_manifest.plan_revision, 2)
        self.assertEqual(len(decoded_manifest.stage_attempts), 2)

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _manifest_envelope(schema_name=PLAN_SCHEMA_NAME)
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        manifest = decode_run_manifest_payload(
            _manifest_payload(), schema_version=VERSION_4_2
        )
        self._assert_rejected(
            lambda: encode_run_manifest_envelope(_manifest_envelope(), manifest),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_rejects_blob_backed_run_manifest(self):
        blob = ArtifactBlobReference(
            blob_id="blob-0002",
            content_digest="9" * 64,
            size_bytes=16,
            media_type="application/json",
        )
        envelope = _manifest_envelope(payload=None, blob_ref=blob, content_digest="9" * 64)
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_TYPE,
            "$.payload",
        )

    def test_rejects_missing_or_mistyped_plan_workflow_and_attempt_lineage(self):
        def drop(predicate):
            return [entry for entry in _manifest_lineage() if not predicate(entry)]

        envelope = _manifest_envelope(
            lineage=drop(lambda entry: entry.artifact_id == "plan-0002")
        )
        exception = self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.plan"))
        envelope = _manifest_envelope(
            lineage=[
                _ref("lima.stage-attempt", "plan-0002", PLAN_FC_D),
                *drop(lambda entry: entry.artifact_id == "plan-0002"),
            ]
        )
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        envelope = _manifest_envelope(
            lineage=drop(lambda entry: entry.artifact_id == "wf-0001")
        )
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        envelope = _manifest_envelope(
            lineage=[
                *drop(lambda entry: entry.artifact_id == "attempt-audit-0001"),
                _ref("lima.stage-attempt", "attempt-audit-0001", "4" * 64),
            ]
        )
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_rejects_missing_resource_artifact_lineage(self):
        envelope = _manifest_envelope(
            lineage=[
                entry
                for entry in _manifest_lineage()
                if entry.artifact_id != "tool-bundle-0001"
            ]
        )
        exception = self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            exception.field_path.startswith("$.payload.resource_artifact_ids")
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _manifest_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _manifest_envelope(retention=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )

    def test_tampered_payload_fails_before_domain_promotion(self):
        payload = _manifest_payload()
        payload["plan"]["kind"] = "lima.run-manifest"
        envelope = _manifest_envelope(
            payload=payload, content_digest=compute_content_digest(payload)
        )
        self._assert_rejected(
            lambda: decode_run_manifest_envelope(encode_envelope(envelope)),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            "$.plan.kind",
        )


if __name__ == "__main__":
    unittest.main()
