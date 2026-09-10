"""Manifests domain envelope binding tests (IP-0012 packet sections 8 and 13).

Envelope checks are isomorphic to the execution pair: schema_name match, inline
payload, double-computed content_digest comparison, protected classification /
retention, per-link lineage double-check (schema_name + schema_version equality
and hmac digest comparison), existence-only checks for untyped id lists, and
the Task revision/supersedes coupling.

The module under test is imported in ``setUpClass`` so that in the RED state
(before ``lima/contracts/manifests.py`` is delivered) every test fails with
``ModuleNotFoundError: No module named 'lima.contracts.manifests'``.
"""

import unittest
from pathlib import Path

from lima.contracts.codec import canonical_decode, compute_content_digest
from lima.contracts.common import (
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

D_TASK_FULL = "4f877245988a8fda3a4347e21f5c222960ea285a0c15ba35881ef4daf0bf6c7c"
D_TB_FULL = "11d92b92c8da9ff61a4ebc8c65bcb26ad1c8f7d208074c0251910c215c327ccc"
D_TB_MIN = "50b8e53b62946b5dcb01a972754aad4b1bf6c69f05bc9525c7e0ee6aa7490ff6"
D_DEP_MIN = "eaab702a3530635dd7b096c93990d3bc76117f04b89dd2163a5c16bed6e70e61"
D_SB_FULL = "398929c2277b99d45b30d28920921d787ee11112e44ec7b08e13bbb1ce8b066f"


def _ref(schema_name, artifact_id, content_digest):
    return ArtifactReference(
        schema_name=schema_name,
        schema_version=VERSION_4_0,
        artifact_id=artifact_id,
        tenant_id="tenant-1",
        repository_snapshot_digest="3" * 64,
        content_digest=content_digest,
    )


def _task_full_payload():
    return canonical_decode((FIXTURES / "task_manifest_full_v4_golden.json").read_bytes())


def _tb_min_payload():
    return canonical_decode((FIXTURES / "tool_bundle_v4_golden.json").read_bytes())


def _dep_min_payload():
    return canonical_decode((FIXTURES / "dependency_manifest_v4_golden.json").read_bytes())


def _sb_full_payload():
    return canonical_decode((FIXTURES / "sandbox_run_full_v4_golden.json").read_bytes())


def _task_lineage():
    return [
        _ref("lima.tool-bundle", "tool-bundle-0001", D_TB_FULL),
        _ref("lima.dependency-manifest", "dependency-manifest-0001", D_DEP_MIN),
        _ref("lima.hypothesis", "hyp-0001", "7" * 64),
        _ref("lima.hypothesis", "hyp-0002", "8" * 64),
    ]


def _sb_lineage():
    return [
        _ref("lima.task-manifest", "task-manifest-0001", D_TASK_FULL),
        _ref("lima.tool-bundle", "tool-bundle-0001", D_TB_FULL),
        _ref("lima.stage-attempt", "log-0001", "1" * 64),
        _ref("lima.stage-attempt", "log-0002", "2" * 64),
    ]


def _envelope(schema_name, artifact_id, content_digest, payload, lineage, **overrides):
    kwargs = {
        "schema_name": schema_name,
        "schema_version": VERSION_4_0,
        "artifact_id": artifact_id,
        "tenant_id": "tenant-1",
        "task_id": "task-1",
        "workflow_id": "workflow-0001",
        "stage_attempt_id": "mine-emit-1",
        "repository_snapshot_digest": "3" * 64,
        "producer": "lima-planner",
        "created_at": "2026-09-10T00:00:00Z",
        "policy_digest": "5" * 64,
        "toolchain_digest": "6" * 64,
        "content_digest": content_digest,
        "classification": ArtifactClassification.INTERNAL,
        "retention_class": RetentionClass.STANDARD,
        "payload": payload,
        "lineage": lineage,
        "supersedes": None,
    }
    kwargs.update(overrides)
    return ArtifactEnvelope(**kwargs)


def _task_envelope(**overrides):
    kwargs = {
        "schema_name": "lima.task-manifest",
        "artifact_id": "task-manifest-0001",
        "content_digest": D_TASK_FULL,
        "payload": _task_full_payload(),
        "lineage": _task_lineage(),
    }
    kwargs.update(overrides)
    return _envelope(**kwargs)


def _tb_envelope(**overrides):
    kwargs = {
        "schema_name": "lima.tool-bundle",
        "artifact_id": "tool-bundle-0001",
        "content_digest": D_TB_MIN,
        "payload": _tb_min_payload(),
        "lineage": [],
    }
    kwargs.update(overrides)
    return _envelope(**kwargs)


def _dep_envelope(**overrides):
    kwargs = {
        "schema_name": "lima.dependency-manifest",
        "artifact_id": "dependency-manifest-0001",
        "content_digest": D_DEP_MIN,
        "payload": _dep_min_payload(),
        "lineage": [],
    }
    kwargs.update(overrides)
    return _envelope(**kwargs)


def _sb_envelope(**overrides):
    kwargs = {
        "schema_name": "lima.sandbox-run",
        "artifact_id": "sandbox-run-0001",
        "stage_attempt_id": "mine-emit-2",
        "content_digest": D_SB_FULL,
        "payload": _sb_full_payload(),
        "lineage": _sb_lineage(),
    }
    kwargs.update(overrides)
    return _envelope(**kwargs)


class _RejectionMixin:
    def _assert_rejected(self, invoke, code, field_path=None):
        with self.assertRaises(ContractError) as ctx:
            invoke()
        self.assertIs(ctx.exception.code, code)
        if field_path is not None:
            self.assertEqual(ctx.exception.field_path, field_path)
        return ctx.exception


class TaskManifestEnvelopeTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        task = self.manifests.decode_task_manifest_payload(
            _task_full_payload(), schema_version=VERSION_4_0
        )
        first = self.manifests.encode_task_manifest_envelope(_task_envelope(), task)
        decoded_envelope, decoded_task = self.manifests.decode_task_manifest_envelope(first)
        second = self.manifests.encode_task_manifest_envelope(
            decoded_envelope, decoded_task
        )
        self.assertEqual(first, second)
        self.assertEqual(decoded_envelope.artifact_id, "task-manifest-0001")
        self.assertEqual(decoded_task.tool_bundles[0].artifact_id, "tool-bundle-0001")

    def test_rejects_wrong_schema_name_and_version_mismatch(self):
        envelope = _task_envelope(schema_name="lima.sandbox-run")
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )
        task = self.manifests.decode_task_manifest_payload(
            _task_full_payload(), schema_version=VERSION_4_2
        )
        self._assert_rejected(
            lambda: self.manifests.encode_task_manifest_envelope(
                _task_envelope(), task
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_version",
        )

    def test_revision_supersedes_coupling_enforced(self):
        payload = _task_full_payload()
        payload["revision"] = 2
        digest = compute_content_digest(payload)
        base = {"payload": payload, "content_digest": digest}
        envelope = _task_envelope(**base)
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _task_envelope(
            **base, supersedes=_ref("lima.workflow", "task-manifest-0000", "0" * 64)
        )
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.supersedes",
        )
        envelope = _task_envelope(
            **base,
            supersedes=_ref("lima.task-manifest", "task-manifest-0000", "0" * 64),
        )
        self.manifests.decode_task_manifest_envelope(encode_envelope(envelope))

    def test_rejects_missing_or_mismatched_link_lineage(self):
        envelope = _task_envelope(
            lineage=[e for e in _task_lineage() if e.artifact_id != "tool-bundle-0001"]
        )
        exception = self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.tool_bundles"))
        envelope = _task_envelope(
            lineage=[
                _ref("lima.tool-bundle", "tool-bundle-0001", "9" * 64),
                *[
                    e
                    for e in _task_lineage()
                    if e.artifact_id != "tool-bundle-0001"
                ],
            ]
        )
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_hypothesis_ids_are_lineage_existence_checked_only(self):
        envelope = _task_envelope(
            lineage=[e for e in _task_lineage() if e.artifact_id != "hyp-0002"]
        )
        exception = self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            exception.field_path.startswith("$.payload.hypothesis_ids")
        )
        # Existence-only: the lineage schema literal of an untyped id is not
        # compared against a manifest schema_name (resource-id precedent).
        envelope = _task_envelope(
            lineage=[
                _ref("lima.sandbox-run", "hyp-0002", "8" * 64),
                *[e for e in _task_lineage() if e.artifact_id != "hyp-0002"],
            ]
        )
        self.manifests.decode_task_manifest_envelope(encode_envelope(envelope))

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _task_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _task_envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: self.manifests.decode_task_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )


class SandboxRunEnvelopeTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_frozen_envelope_encode_decode_is_byte_stable(self):
        run = self.manifests.decode_sandbox_run_payload(
            _sb_full_payload(), schema_version=VERSION_4_0
        )
        first = self.manifests.encode_sandbox_run_envelope(_sb_envelope(), run)
        decoded_envelope, decoded_run = self.manifests.decode_sandbox_run_envelope(first)
        second = self.manifests.encode_sandbox_run_envelope(
            decoded_envelope, decoded_run
        )
        self.assertEqual(first, second)
        self.assertIs(decoded_run.exit_code, None)

    def test_rejects_missing_task_lineage_and_digest_mismatch(self):
        envelope = _sb_envelope(
            lineage=[
                e for e in _sb_lineage() if e.artifact_id != "task-manifest-0001"
            ]
        )
        exception = self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(exception.field_path.startswith("$.payload.task"))
        envelope = _sb_envelope(
            lineage=[
                _ref("lima.task-manifest", "task-manifest-0001", "9" * 64),
                *[
                    e
                    for e in _sb_lineage()
                    if e.artifact_id != "task-manifest-0001"
                ],
            ]
        )
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_log_artifact_ids_are_lineage_existence_checked(self):
        envelope = _sb_envelope(
            lineage=[e for e in _sb_lineage() if e.artifact_id != "log-0002"]
        )
        exception = self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertTrue(
            exception.field_path.startswith("$.payload.log_artifact_ids")
        )

    def test_rejects_public_classification_and_ephemeral_retention(self):
        envelope = _sb_envelope(classification=ArtifactClassification.PUBLIC)
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.classification",
        )
        envelope = _sb_envelope(retention_class=RetentionClass.EPHEMERAL)
        self._assert_rejected(
            lambda: self.manifests.decode_sandbox_run_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.retention_class",
        )


class ToolBundleAndDependencyEnvelopeTests(_RejectionMixin, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import lima.contracts.manifests

        cls.manifests = lima.contracts.manifests

    def test_tool_bundle_envelope_round_trip_and_schema_name_rejection(self):
        bundle = self.manifests.decode_tool_bundle_payload(
            _tb_min_payload(), schema_version=VERSION_4_0
        )
        first = self.manifests.encode_tool_bundle_envelope(_tb_envelope(), bundle)
        decoded_envelope, decoded_bundle = self.manifests.decode_tool_bundle_envelope(
            first
        )
        second = self.manifests.encode_tool_bundle_envelope(
            decoded_envelope, decoded_bundle
        )
        self.assertEqual(first, second)
        envelope = _tb_envelope(schema_name="lima.task-manifest")
        self._assert_rejected(
            lambda: self.manifests.decode_tool_bundle_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            "$.schema_name",
        )

    def test_dependency_manifest_envelope_round_trip_and_tampered_digest(self):
        manifest = self.manifests.decode_dependency_manifest_payload(
            _dep_min_payload(), schema_version=VERSION_4_0
        )
        first = self.manifests.encode_dependency_manifest_envelope(
            _dep_envelope(), manifest
        )
        decoded_envelope, decoded_manifest = (
            self.manifests.decode_dependency_manifest_envelope(first)
        )
        self.assertEqual(
            first,
            self.manifests.encode_dependency_manifest_envelope(
                decoded_envelope, decoded_manifest
            ),
        )
        envelope = _dep_envelope(content_digest="0" * 64)
        self._assert_rejected(
            lambda: self.manifests.decode_dependency_manifest_envelope(
                encode_envelope(envelope)
            ),
            ContractErrorCode.DIGEST_MISMATCH,
            "$.content_digest",
        )


if __name__ == "__main__":
    unittest.main()
