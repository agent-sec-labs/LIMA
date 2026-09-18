# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0 (DESIGN-FROZEN)
# Anchor IDs refer to Issue #94 [V5-N05].
# Frozen Test Commit v2 (DR-IP-0015-03 erratum 2026-09-12): converted from
# v1 bare-function style to unittest.TestCase style 1:1; assertions,
# boundary values, and requirement-ID anchors are unchanged from v1 (97e0b63).
"""Model construction & validation tests (Packet section 8.1).

Interpretive note (recorded by P&V): Packet section 8.2 step 3 requires
``sanitize_for_sink`` (frozen 3-arg signature) to validate tenant_id and
tenant_key, therefore SinkContext carries ``tenant_id: str = ""`` and
``tenant_key: bytes = b""``.
"""

from __future__ import annotations

import dataclasses
import unittest

from lima.evidence_privacy import (
    ClassificationManifest,
    EvidencePayload,
    FingerprintRecord,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyLimits,
    SanitizedPayload,
    SinkContext,
)
from lima.evidence_privacy.models import (
    ClassificationManifest as ModelsClassificationManifest,
)

from lima.contracts.common import ArtifactClassification, RetentionClass


class ModelsTests(unittest.TestCase):
    def test_evidence_payload_accepts_three_kinds(self):
        # FR-N05-01 / Packet 8.1: payload_kind must accept structured_json, text, bytes.
        EvidencePayload(payload_kind="structured_json", value={"a": 1})
        EvidencePayload(payload_kind="text", value="hello")
        EvidencePayload(payload_kind="bytes", value=b"\x00\x01")

    def test_evidence_payload_rejects_unknown_kind(self):
        # FR-N05-01 / Packet 8.2 step 6 contract: unsupported kind fails closed.
        with self.assertRaises(PrivacyError) as ei:
            EvidencePayload(payload_kind="yaml", value="x")
        self.assertEqual(ei.exception.code, PrivacyErrorCode.UNSUPPORTED_PAYLOAD_KIND)

    def test_evidence_payload_default_media_type_empty(self):
        # Packet 8.1: media_type defaults to "" and is informational only.
        p = EvidencePayload(payload_kind="text", value="v")
        self.assertEqual(p.media_type, "")

    def test_sink_context_unknown_sink_rejected(self):
        # FR-N05-02: unknown sink_kind must be rejected with UNKNOWN_SINK.
        with self.assertRaises(PrivacyError) as ei:
            SinkContext(sink_kind="vault", tenant_id="t1", tenant_key=b"k" * 16)
        self.assertEqual(ei.exception.code, PrivacyErrorCode.UNKNOWN_SINK)

    def test_sink_context_valid_fields(self):
        # FR-N05-02 / Packet 8.1: SinkContext carries sink_kind, purpose,
        # tenant_id, tenant_key (interpretive note in module docstring).
        sc = SinkContext(
            sink_kind="log", purpose="debug", tenant_id="tenant-a", tenant_key=b"k" * 16
        )
        self.assertEqual(sc.sink_kind, "log")
        self.assertEqual(sc.purpose, "debug")
        self.assertEqual(sc.tenant_id, "tenant-a")
        self.assertEqual(sc.tenant_key, b"k" * 16)

    def test_privacy_limits_positive_int_validation(self):
        # NFR-N05-02 / Packet 8.1: all limits positive ints, validated at construction.
        with self.assertRaises(PrivacyError) as ei:
            PrivacyLimits(max_depth=0)
        self.assertEqual(ei.exception.code, PrivacyErrorCode.INVALID_FIELD_VALUE)
        with self.assertRaises(PrivacyError):
            PrivacyLimits(max_string_bytes=-1)
        with self.assertRaises(PrivacyError):
            PrivacyLimits(max_items="many")  # type: ignore[arg-type]

    def test_fingerprint_record_defaults_and_fields(self):
        # FR-N05-03 / Packet 8.1: FingerprintRecord fields fingerprint/value_kind/
        # length/preview; preview defaults to None.
        fr = FingerprintRecord(
            fingerprint="a" * 32, value_kind="string", length=11
        )
        self.assertIsNone(fr.preview)
        self.assertTrue(dataclasses.is_dataclass(fr))

    def test_classification_manifest_defaults_and_members(self):
        # FR-N05-01 / NFR-N05-04 / Packet 8.1: manifest carries #58 enums,
        # policy_version, policy_digest (64 hex), entries tuple, created_at.
        fr = FingerprintRecord(fingerprint="b" * 32, value_kind="string", length=8)
        m = ClassificationManifest(
            classification=ArtifactClassification.SENSITIVE,
            retention_class=RetentionClass.STANDARD,
            policy_version="v1",
            policy_digest="c" * 64,
            entries=(fr,),
            created_at="2026-09-12T00:00:00+00:00",
        )
        self.assertIsInstance(m, ModelsClassificationManifest)
        self.assertEqual(m.entries, (fr,))
        self.assertEqual(m.retention_class, RetentionClass.STANDARD)

    def test_sanitized_payload_shape(self):
        # Packet 8.1: SanitizedPayload carries sink_kind/tenant_id/manifest/redacted_value.
        m = ClassificationManifest(
            classification=ArtifactClassification.INTERNAL,
            retention_class=RetentionClass.STANDARD,
            policy_version="v1",
            policy_digest="e" * 64,
            entries=(),
            created_at="2026-09-12T00:00:00+00:00",
        )
        sp = SanitizedPayload(
            sink_kind="storage", tenant_id="tenant-a", manifest=m, redacted_value={}
        )
        self.assertEqual(sp.sink_kind, "storage")
        self.assertEqual(sp.tenant_id, "tenant-a")
        self.assertIs(sp.manifest, m)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
