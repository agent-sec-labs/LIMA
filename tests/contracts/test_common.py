"""Common contract tests: SchemaVersion, references, and ArtifactEnvelope behavior."""

import unittest
from pathlib import Path

from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.contracts.common import (
    CURRENT_SCHEMA_MAJOR,
    CURRENT_SCHEMA_MINOR,
    ArtifactBlobReference,
    ArtifactClassification,
    ArtifactEnvelope,
    ArtifactReference,
    RetentionClass,
    SchemaVersion,
    decode_envelope,
    encode_envelope,
)
from lima.contracts.errors import ContractError, ContractErrorCode

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "artifact_envelope_v4_golden.json"
GOLDEN_DIGEST = "567791dedb5a4052163ab8fcc5e7abc3ff71008fa1ec690c8fa739dfe14822d7"

BASE_PAYLOAD = {"kind": "unit-test"}

ENVELOPE_WIRE_FIELDS = frozenset(
    {
        "schema_name",
        "schema_version",
        "artifact_id",
        "tenant_id",
        "task_id",
        "workflow_id",
        "stage_attempt_id",
        "repository_snapshot_digest",
        "producer",
        "created_at",
        "policy_digest",
        "toolchain_digest",
        "content_digest",
        "classification",
        "retention_class",
        "payload",
        "blob_ref",
        "lineage",
        "supersedes",
        "coverage_gaps",
    }
)

ALWAYS_REQUIRED_FIELDS = tuple(
    name
    for name in (
        "schema_name",
        "schema_version",
        "artifact_id",
        "tenant_id",
        "task_id",
        "workflow_id",
        "stage_attempt_id",
        "repository_snapshot_digest",
        "producer",
        "created_at",
        "policy_digest",
        "toolchain_digest",
        "content_digest",
        "classification",
        "retention_class",
        "lineage",
        "supersedes",
        "coverage_gaps",
    )
)


def _base_wire(**overrides):
    wire = {
        "schema_name": "lima.test_envelope",
        "schema_version": "4.0",
        "artifact_id": "artifact-0001",
        "tenant_id": "tenant-a",
        "task_id": "task-a",
        "workflow_id": "workflow-a",
        "stage_attempt_id": "stage-attempt-a",
        "repository_snapshot_digest": "1" * 64,
        "producer": "lima.contracts.tests",
        "created_at": "2026-09-01T00:00:00.000000Z",
        "policy_digest": "2" * 64,
        "toolchain_digest": "3" * 64,
        "content_digest": compute_content_digest(BASE_PAYLOAD),
        "classification": "internal",
        "retention_class": "standard",
        "payload": {"kind": "unit-test"},
        "lineage": [],
        "supersedes": None,
        "coverage_gaps": [],
    }
    wire.update(overrides)
    return wire


def _reference_wire(artifact_id="artifact-parent", **overrides):
    reference = {
        "schema_name": "lima.test_reference",
        "schema_version": "4.0",
        "artifact_id": artifact_id,
        "tenant_id": "tenant-a",
        "repository_snapshot_digest": "1" * 64,
        "content_digest": "a" * 64,
    }
    reference.update(overrides)
    return reference


def _blob_wire(**overrides):
    blob = {
        "blob_id": "blob-0001",
        "content_digest": "b" * 64,
        "size_bytes": 42,
        "media_type": "application/vnd.lima.test+json",
    }
    blob.update(overrides)
    return blob


def _blob_envelope_wire(**overrides):
    wire = _base_wire()
    wire.pop("payload")
    wire["content_digest"] = "b" * 64
    wire["blob_ref"] = _blob_wire()
    wire.update(overrides)
    return wire


class SchemaVersionTests(unittest.TestCase):
    def test_parses_and_renders_4_0(self):
        self.assertEqual(CURRENT_SCHEMA_MAJOR, 4)
        self.assertEqual(CURRENT_SCHEMA_MINOR, 0)
        version = SchemaVersion.parse("4.0")
        self.assertEqual(version, SchemaVersion(4, 0))
        self.assertEqual(str(version), "4.0")
        future = SchemaVersion.parse("4.12")
        self.assertEqual(future, SchemaVersion(4, 12))
        self.assertEqual(str(future), "4.12")

    def test_rejects_bool_negative_malformed_and_unknown_major(self):
        SV = SchemaVersion
        cases = [
            (lambda: SV.parse(True), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse(4), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse(None), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse("4"), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse("4."), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse(".0"), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse("4.0.0"), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse("v4.0"), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse("4.x"), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse(""), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV(0, 0), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV(4, -1), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV(True, 0), ContractErrorCode.SCHEMA_VERSION_INVALID),
            (lambda: SV.parse("5.0"), ContractErrorCode.SCHEMA_UNKNOWN_MAJOR),
            (lambda: SV.parse("3.2"), ContractErrorCode.SCHEMA_UNKNOWN_MAJOR),
            (lambda: SV(9, 1), ContractErrorCode.SCHEMA_UNKNOWN_MAJOR),
        ]
        for invoke, code in cases:
            with self.subTest(code=code.value):
                with self.assertRaises(ContractError) as ctx:
                    invoke()
                self.assertIs(ctx.exception.code, code)


class ArtifactEnvelopeTests(unittest.TestCase):
    def _decode(self, wire):
        return decode_envelope(canonical_encode(wire))

    def _assert_rejected(self, wire, code):
        with self.assertRaises(ContractError) as ctx:
            self._decode(wire)
        self.assertIs(ctx.exception.code, code)
        return ctx.exception

    def _envelope_kwargs(self, **overrides):
        kwargs = {
            "schema_name": "lima.test_envelope",
            "schema_version": SchemaVersion(4, 0),
            "artifact_id": "artifact-0001",
            "tenant_id": "tenant-a",
            "task_id": "task-a",
            "workflow_id": "workflow-a",
            "stage_attempt_id": "stage-attempt-a",
            "repository_snapshot_digest": "1" * 64,
            "producer": "lima.contracts.tests",
            "created_at": "2026-09-01T00:00:00Z",
            "policy_digest": "2" * 64,
            "toolchain_digest": "3" * 64,
            "content_digest": compute_content_digest({"kind": "unit-test"}),
            "classification": ArtifactClassification.INTERNAL,
            "retention_class": RetentionClass.STANDARD,
            "payload": {"kind": "unit-test"},
        }
        kwargs.update(overrides)
        return kwargs

    def test_golden_inline_envelope_round_trip(self):
        raw = FIXTURE.read_bytes()
        envelope = decode_envelope(raw)
        self.assertEqual(encode_envelope(envelope), raw)
        self.assertEqual(compute_content_digest(envelope.payload), envelope.content_digest)
        self.assertEqual(envelope.content_digest, GOLDEN_DIGEST)
        self.assertEqual(envelope.schema_name, "lima.contract_foundation_fixture")
        self.assertEqual(envelope.schema_version, SchemaVersion(4, 0))
        self.assertEqual(envelope.classification, ArtifactClassification.INTERNAL)
        self.assertEqual(envelope.retention_class, RetentionClass.STANDARD)
        self.assertIsNone(envelope.blob_ref)
        self.assertIsNone(envelope.supersedes)
        self.assertEqual(envelope.lineage, ())
        self.assertEqual(envelope.coverage_gaps, ())
        self.assertEqual(envelope.extensions, {})

    def test_blob_reference_round_trip(self):
        envelope = self._decode(_blob_envelope_wire())
        self.assertIsNone(envelope.payload)
        self.assertIsInstance(envelope.blob_ref, ArtifactBlobReference)
        self.assertEqual(envelope.blob_ref.blob_id, "blob-0001")
        self.assertEqual(envelope.blob_ref.content_digest, "b" * 64)
        self.assertEqual(envelope.blob_ref.size_bytes, 42)
        self.assertEqual(envelope.blob_ref.media_type, "application/vnd.lima.test+json")
        wire = envelope.to_dict()
        self.assertIn("blob_ref", wire)
        self.assertNotIn("payload", wire)
        self.assertEqual(
            envelope.blob_ref.to_dict(),
            {
                "blob_id": "blob-0001",
                "content_digest": "b" * 64,
                "size_bytes": 42,
                "media_type": "application/vnd.lima.test+json",
            },
        )
        again = decode_envelope(encode_envelope(envelope))
        self.assertEqual(again, envelope)
        self.assertEqual(encode_envelope(again), encode_envelope(envelope))

    def test_requires_exactly_one_inline_or_blob(self):
        wire = _base_wire()
        wire.pop("payload")
        self._assert_rejected(wire, ContractErrorCode.INLINE_OR_BLOB_REQUIRED)
        both = _blob_envelope_wire()
        both["payload"] = {"kind": "unit-test"}
        self._assert_rejected(both, ContractErrorCode.INLINE_AND_BLOB_CONFLICT)
        with self.assertRaises(ContractError) as ctx:
            ArtifactEnvelope(**self._envelope_kwargs(payload=None))
        self.assertIs(ctx.exception.code, ContractErrorCode.INLINE_OR_BLOB_REQUIRED)
        blob_kwargs = self._envelope_kwargs(payload=None)
        blob_kwargs["blob_ref"] = ArtifactBlobReference.from_dict(
            _blob_wire(), envelope_version=SchemaVersion(4, 0)
        )
        blob_kwargs["content_digest"] = "b" * 64
        envelope = ArtifactEnvelope(**blob_kwargs)
        self.assertIsNone(envelope.payload)
        with self.assertRaises(ContractError) as ctx:
            ArtifactEnvelope(**self._envelope_kwargs(blob_ref=blob_kwargs["blob_ref"]))
        self.assertIs(ctx.exception.code, ContractErrorCode.INLINE_AND_BLOB_CONFLICT)

    def test_rejects_missing_required_and_unknown_current_minor_field(self):
        for name in ALWAYS_REQUIRED_FIELDS:
            with self.subTest(missing=name):
                wire = _base_wire()
                del wire[name]
                self._assert_rejected(wire, ContractErrorCode.REQUIRED_FIELD_MISSING)
        self._assert_rejected(
            _base_wire(artifact_type="lima.typo"), ContractErrorCode.UNKNOWN_FIELD
        )
        self._assert_rejected(
            _base_wire(future_field=True), ContractErrorCode.UNKNOWN_FIELD
        )
        with self.assertRaises(ContractError) as ctx:
            ArtifactEnvelope(**self._envelope_kwargs(extensions={"future_field": 1}))
        self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_FIELD)
        with self.assertRaises(ContractError) as ctx:
            ArtifactReference(
                schema_name="lima.test_reference",
                schema_version=SchemaVersion(4, 0),
                artifact_id="artifact-parent",
                tenant_id="tenant-a",
                repository_snapshot_digest="1" * 64,
                content_digest="a" * 64,
                extensions={"future_field": 1},
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.UNKNOWN_FIELD)

    def test_future_minor_preserves_unknown_optional_fields(self):
        wire = _base_wire(
            schema_version="4.2",
            trace_probability_hint={"band": "high"},
            retry_count=3,
            lineage=[_reference_wire(schema_version="4.2", confidence_band="high")],
        )
        envelope = self._decode(wire)
        self.assertEqual(envelope.schema_version, SchemaVersion(4, 2))
        self.assertEqual(
            envelope.extensions,
            {"trace_probability_hint": {"band": "high"}, "retry_count": 3},
        )
        self.assertEqual(envelope.lineage[0].extensions, {"confidence_band": "high"})
        self.assertIn("trace_probability_hint", envelope.to_dict())
        self.assertIn("confidence_band", envelope.to_dict()["lineage"][0])
        again = decode_envelope(encode_envelope(envelope))
        self.assertEqual(again, envelope)
        self.assertEqual(again.extensions, envelope.extensions)
        self.assertEqual(again.lineage[0].extensions, {"confidence_band": "high"})

        blob_wire = _blob_envelope_wire()
        blob_wire["schema_version"] = "4.1"
        blob_wire["blob_ref"] = _blob_wire(compression="gzip")
        blob_envelope = self._decode(blob_wire)
        self.assertEqual(blob_envelope.blob_ref.extensions, {"compression": "gzip"})
        blob_again = decode_envelope(encode_envelope(blob_envelope))
        self.assertEqual(blob_again, blob_envelope)
        self.assertEqual(blob_again.blob_ref.extensions, {"compression": "gzip"})

    def test_rejects_unknown_enum_and_invalid_identifier(self):
        self._assert_rejected(
            _base_wire(classification="top-secret"), ContractErrorCode.UNKNOWN_ENUM_VALUE
        )
        self._assert_rejected(
            _base_wire(classification=7), ContractErrorCode.INVALID_FIELD_TYPE
        )
        self._assert_rejected(
            _base_wire(retention_class="forever"), ContractErrorCode.UNKNOWN_ENUM_VALUE
        )
        self._assert_rejected(
            _base_wire(schema_name="Bad_Name"), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(schema_name="1schema"), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(schema_name="lima..double"), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(schema_name="s" * 129), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(artifact_id="../etc/passwd"), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(artifact_id=""), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(tenant_id="tenant a"), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(producer="p" * 129), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(repository_snapshot_digest="X" * 64),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _base_wire(repository_snapshot_digest="a" * 63),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertIsNotNone(self._decode(_base_wire(schema_name="s" * 128)))
        self.assertIsNotNone(self._decode(_base_wire(producer="p" * 128)))

        blob_cases = [
            (_blob_wire(media_type="APPLICATION/JSON"), ContractErrorCode.INVALID_FIELD_VALUE),
            (
                _blob_wire(media_type="application/json; charset=utf-8"),
                ContractErrorCode.INVALID_FIELD_VALUE,
            ),
            (_blob_wire(blob_id="C:\\path"), ContractErrorCode.INVALID_FIELD_VALUE),
            (_blob_wire(size_bytes=-1), ContractErrorCode.INVALID_FIELD_VALUE),
            (_blob_wire(size_bytes="42"), ContractErrorCode.INVALID_FIELD_TYPE),
            (_blob_wire(size_bytes=True), ContractErrorCode.INVALID_FIELD_TYPE),
        ]
        for blob, code in blob_cases:
            with self.subTest(blob=blob):
                self._assert_rejected(_blob_envelope_wire(blob_ref=blob), code)
        with self.assertRaises(ContractError) as ctx:
            ArtifactBlobReference(
                blob_id="blob-0001",
                content_digest="b" * 64,
                size_bytes=2**63,
                media_type="application/json",
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)
        self.assertIsNotNone(self._decode(_blob_envelope_wire(blob_ref=_blob_wire(size_bytes=0))))
        self.assertIsNotNone(
            self._decode(_blob_envelope_wire(blob_ref=_blob_wire(size_bytes=2**63 - 1)))
        )
        max_media_type = "a" * 63 + "/" + "b" * 63
        self.assertIsNotNone(
            self._decode(_blob_envelope_wire(blob_ref=_blob_wire(media_type=max_media_type)))
        )

    def test_normalizes_equivalent_timezone_to_utc_microseconds(self):
        for raw, expected in [
            ("2026-09-01T00:00:00Z", "2026-09-01T00:00:00.000000Z"),
            ("2026-09-01T08:00:00+08:00", "2026-09-01T00:00:00.000000Z"),
            ("2026-09-01T01:00:00+01:00", "2026-09-01T00:00:00.000000Z"),
            ("2026-09-01T00:00:00-00:00", "2026-09-01T00:00:00.000000Z"),
            ("2026-09-01T00:00:00+00:00", "2026-09-01T00:00:00.000000Z"),
            ("2026-09-01T00:00:00.5Z", "2026-09-01T00:00:00.500000Z"),
            ("2026-09-01T00:00:00.123456Z", "2026-09-01T00:00:00.123456Z"),
            ("2026-12-31T23:59:59.999999Z", "2026-12-31T23:59:59.999999Z"),
        ]:
            with self.subTest(raw=raw):
                envelope = self._decode(_base_wire(created_at=raw))
                self.assertEqual(envelope.created_at, expected)
        first = self._decode(_base_wire(created_at="2026-09-01T00:00:00.5Z"))
        second = self._decode(_base_wire(created_at="2026-09-01T00:00:00.500000Z"))
        self.assertEqual(first, second)
        self.assertEqual(encode_envelope(first), encode_envelope(second))

    def test_rejects_naive_or_invalid_datetime(self):
        for raw in (
            "2026-09-01T00:00:00",
            "2026-09-01 00:00:00Z",
            "2026-09-01T00:00:00z",
            "2026-09-01T00:00:00.1234567Z",
            "2026-09-01T00:00:60Z",
            "2026-09-01T00:00:00+0800",
            "2026-09-01T00:00:00+08:00:30",
            "2026-13-01T00:00:00Z",
            "2026-09-01T24:00:00Z",
            "2026-09-31T00:00:00Z",
            "not-a-datetime",
        ):
            with self.subTest(raw=raw):
                self._assert_rejected(
                    _base_wire(created_at=raw), ContractErrorCode.INVALID_FIELD_VALUE
                )
        self._assert_rejected(
            _base_wire(created_at=12345), ContractErrorCode.INVALID_FIELD_TYPE
        )

    def test_rejects_inline_and_blob_digest_mismatch(self):
        self._assert_rejected(
            _base_wire(content_digest="c" * 64), ContractErrorCode.DIGEST_MISMATCH
        )
        self._assert_rejected(
            _blob_envelope_wire(content_digest="c" * 64), ContractErrorCode.DIGEST_MISMATCH
        )
        self._assert_rejected(
            _blob_envelope_wire(blob_ref=_blob_wire(content_digest="c" * 64)),
            ContractErrorCode.DIGEST_MISMATCH,
        )

    def test_rejects_lineage_self_duplicate_and_conflicting_identity(self):
        self._assert_rejected(
            _base_wire(lineage=[_reference_wire(artifact_id="artifact-0001")]),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
        )
        self._assert_rejected(
            _base_wire(supersedes=_reference_wire(artifact_id="artifact-0001")),
            ContractErrorCode.LINEAGE_SELF_REFERENCE,
        )
        reference = _reference_wire()
        self._assert_rejected(
            _base_wire(lineage=[reference, dict(reference)]),
            ContractErrorCode.LINEAGE_DUPLICATE,
        )
        self._assert_rejected(
            _base_wire(
                lineage=[
                    _reference_wire(),
                    _reference_wire(content_digest="b" * 64),
                ]
            ),
            ContractErrorCode.LINEAGE_CONFLICT,
        )
        self._assert_rejected(
            _base_wire(
                lineage=[
                    _reference_wire(),
                    _reference_wire(schema_name="lima.other_reference"),
                ]
            ),
            ContractErrorCode.LINEAGE_CONFLICT,
        )
        self._assert_rejected(
            _base_wire(
                lineage=[_reference_wire()],
                supersedes=_reference_wire(content_digest="b" * 64),
            ),
            ContractErrorCode.LINEAGE_CONFLICT,
        )
        self.assertIsNotNone(
            self._decode(
                _base_wire(lineage=[_reference_wire()], supersedes=_reference_wire())
            )
        )
        many = [
            _reference_wire(artifact_id=f"artifact-ref-{index:04d}") for index in range(129)
        ]
        self._assert_rejected(
            _base_wire(lineage=many), ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED
        )
        ok = [
            _reference_wire(artifact_id=f"artifact-ref-{index:04d}") for index in range(128)
        ]
        self.assertIsNotNone(self._decode(_base_wire(lineage=ok)))

    def test_rejects_cross_tenant_and_cross_snapshot_reference(self):
        exception = self._assert_rejected(
            _base_wire(lineage=[_reference_wire(tenant_id="tenant-b")]),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
        )
        self.assertEqual(exception.field_path, "$.lineage[0].tenant_id")
        exception = self._assert_rejected(
            _base_wire(lineage=[_reference_wire(repository_snapshot_digest="9" * 64)]),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
        )
        self.assertEqual(exception.field_path, "$.lineage[0].repository_snapshot_digest")
        self._assert_rejected(
            _base_wire(supersedes=_reference_wire(tenant_id="tenant-b")),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
        )
        self._assert_rejected(
            _base_wire(supersedes=_reference_wire(repository_snapshot_digest="9" * 64)),
            ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
        )
        self._assert_rejected(
            _base_wire(
                lineage=[
                    _reference_wire(artifact_id="artifact-x"),
                    _reference_wire(artifact_id="artifact-y", tenant_id="tenant-b"),
                ]
            ),
            ContractErrorCode.LINEAGE_TENANT_MISMATCH,
        )

    def test_rejects_duplicate_and_oversize_coverage_gap(self):
        self._assert_rejected(
            _base_wire(coverage_gaps=["gap-a", "gap-a"]),
            ContractErrorCode.COVERAGE_GAP_DUPLICATE,
        )
        self._assert_rejected(
            _base_wire(coverage_gaps=["gap-e\u0301", "gap-\u00e9"]),
            ContractErrorCode.COVERAGE_GAP_DUPLICATE,
        )
        self._assert_rejected(
            _base_wire(coverage_gaps=[""]), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(coverage_gaps=["bad\x01gap"]), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _base_wire(coverage_gaps=["x" * 1025]),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )
        self.assertIsNotNone(self._decode(_base_wire(coverage_gaps=["x" * 1024])))
        self.assertIsNotNone(
            self._decode(_base_wire(coverage_gaps=["gap-e\u0301"]))
        )
        self._assert_rejected(
            _base_wire(coverage_gaps=[f"gap-{index:03d}" for index in range(257)]),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
        )
        self.assertIsNotNone(
            self._decode(_base_wire(coverage_gaps=[f"gap-{index:03d}" for index in range(256)]))
        )

    def test_defensive_copy_prevents_post_construction_mutation(self):
        payload = {"kind": "unit-test", "nested": {"items": [1, 2]}}
        lineage = [ArtifactReference.from_dict(_reference_wire())]
        coverage = ["gap-a", "gap-b"]
        envelope = ArtifactEnvelope(
            **self._envelope_kwargs(
                payload=payload,
                lineage=lineage,
                coverage_gaps=coverage,
                content_digest=compute_content_digest(payload),
            )
        )
        before = envelope.to_dict()
        payload["kind"] = "mutated"
        payload["nested"]["items"].append(3)
        lineage.append(
            ArtifactReference.from_dict(_reference_wire(artifact_id="artifact-other"))
        )
        coverage.append("gap-c")
        coverage[0] = "gap-x"
        self.assertEqual(envelope.to_dict(), before)
        self.assertEqual(compute_content_digest(envelope.payload), envelope.content_digest)
        self.assertEqual(len(envelope.lineage), 1)
        self.assertEqual(envelope.coverage_gaps, ("gap-a", "gap-b"))
        rendered = envelope.to_dict()
        rendered["payload"]["kind"] = "mutated-again"
        rendered["lineage"].append(_reference_wire())
        self.assertNotEqual(envelope.to_dict()["payload"]["kind"], "mutated-again")
        self.assertEqual(len(envelope.to_dict()["lineage"]), 1)
        self.assertEqual(envelope.to_dict(), before)

        blob_extensions = {"compression": "gzip"}
        reference_extensions = {"confidence_band": "high"}
        blob = ArtifactBlobReference(
            blob_id="blob-0001",
            content_digest="b" * 64,
            size_bytes=42,
            media_type="application/vnd.lima.test+json",
            extensions=blob_extensions,
        )
        future_reference = ArtifactReference(
            schema_name="lima.test_reference",
            schema_version=SchemaVersion(4, 2),
            artifact_id="artifact-parent",
            tenant_id="tenant-a",
            repository_snapshot_digest="1" * 64,
            content_digest="a" * 64,
            extensions=reference_extensions,
        )
        future_envelope = ArtifactEnvelope(
            **self._envelope_kwargs(
                schema_version=SchemaVersion(4, 2),
                payload=None,
                blob_ref=blob,
                content_digest="b" * 64,
                lineage=[future_reference],
            )
        )
        blob_extensions["compression"] = "mutated"
        reference_extensions["confidence_band"] = "mutated"
        self.assertEqual(future_envelope.blob_ref.extensions, {"compression": "gzip"})
        self.assertEqual(
            future_envelope.lineage[0].extensions, {"confidence_band": "high"}
        )
        again = decode_envelope(encode_envelope(future_envelope))
        self.assertEqual(again, future_envelope)

    def test_wire_shape_has_no_artifact_type_alias(self):
        envelope = decode_envelope(FIXTURE.read_bytes())
        wire = envelope.to_dict()
        self.assertEqual(set(wire), ENVELOPE_WIRE_FIELDS - {"blob_ref"})
        self.assertNotIn("artifact_type", wire)
        blob_wire = self._decode(_blob_envelope_wire()).to_dict()
        self.assertEqual(set(blob_wire), ENVELOPE_WIRE_FIELDS - {"payload"})
        self.assertNotIn("artifact_type", blob_wire)
        self._assert_rejected(
            _base_wire(artifact_type="lima.test"), ContractErrorCode.UNKNOWN_FIELD
        )


if __name__ == "__main__":
    unittest.main()
