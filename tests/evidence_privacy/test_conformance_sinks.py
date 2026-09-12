# IP-0017 Content Conformance - frozen acceptance tests (P&V owned, phase 2).
# Packet: docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md v1.0
# Scope: AC/T-N05-01 five-sink conformance (Packet 8.2, ruling O-3 frozen
# reading: one interface x five SinkContext kinds -> identical safe output,
# only sink_kind differs; no per-sink behavior). unittest.TestCase style,
# no pytest-only APIs (Packet 10.4 PI-DR6-bis).
"""Five-sink conformance suite (Packet 8.2; FR-N05-02 conformance side)."""

from __future__ import annotations

import unittest
from dataclasses import replace

from lima.contracts.common import ArtifactClassification
from lima.evidence_privacy import (
    EvidencePayload,
    PrivacyError,
    PrivacyErrorCode,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)
from lima.evidence_privacy.policy import SINK_KINDS, policy_digest

KEY = b"\x33" * 32
KEY_B = b"\xab" * 32
SINK_ORDER = ("storage", "log", "prompt", "api", "export")
URL_CRED = "https://deploy:Hunt3rPass@ci.example.internal/build"  # noqa: S105 - synthetic


def _sink(kind, tenant_id="tenant-a", tenant_key=KEY, purpose=""):
    return SinkContext(
        sink_kind=kind, tenant_id=tenant_id, tenant_key=tenant_key, purpose=purpose
    )


def _policy(**kw):
    return TenantPolicy.resolve(policy_version="v1", **kw)


def _manifest_key(sp: SanitizedPayload):
    """Manifest comparison key with the volatile created_at blanked (8.2.1)."""
    return replace(sp.manifest, created_at="")


class FiveSinkCongruenceTests(unittest.TestCase):
    def _assert_congruent(self, first: SanitizedPayload, other: SanitizedPayload):
        # AC/T-N05-01 8.2.1: same input x five sink kinds -> manifest (except
        # created_at) equal field by field, redacted_value equal, only
        # sink_kind varies.
        self.assertNotEqual(first.sink_kind, other.sink_kind)
        self.assertEqual(_manifest_key(first), _manifest_key(other))
        self.assertEqual(first.redacted_value, other.redacted_value)
        self.assertEqual(first.tenant_id, other.tenant_id)

    def test_structured_json_congruence_all_five_sinks(self):
        # AC/T-N05-01 8.2.1 / FR-N05-02: structured payload with nested
        # sensitive keys, a RESTRICTED URL credential value, and benign data.
        value = {
            "user": {"id": 7, "name": "ada", "api_token": "tok-1234567890"},
            "ci_url": URL_CRED,
            "flags": [True, None, 3],
        }
        payload = EvidencePayload(payload_kind="structured_json", value=value)
        outputs = [
            sanitize_for_sink(payload, _sink(kind), _policy()) for kind in SINK_ORDER
        ]
        for sp, kind in zip(outputs, SINK_ORDER, strict=True):
            with self.subTest(kind=kind):
                self.assertEqual(sp.sink_kind, kind)
        for other in outputs[1:]:
            self._assert_congruent(outputs[0], other)
        # FR-N05-02: severity merge still applies uniformly.
        self.assertEqual(
            outputs[0].manifest.classification, ArtifactClassification.RESTRICTED
        )
        self.assertTrue(outputs[0].manifest.entries)

    def test_text_congruence_all_five_sinks(self):
        # AC/T-N05-01 8.2.1 / FR-N05-05: text form congruence.
        payload = EvidencePayload(
            payload_kind="text", value="log line auth_token=zz-nope event=start"
        )
        outputs = [
            sanitize_for_sink(payload, _sink(kind), _policy()) for kind in SINK_ORDER
        ]
        for other in outputs[1:]:
            self._assert_congruent(outputs[0], other)
        self.assertEqual(
            outputs[0].manifest.classification, ArtifactClassification.SENSITIVE
        )

    def test_bytes_congruence_all_five_sinks(self):
        # AC/T-N05-01 8.2.1 / FR-N05-05: bytes form congruence (8.5.3).
        payload = EvidencePayload(payload_kind="bytes", value=b"\xde\xad\xbe\xef" * 16)
        outputs = [
            sanitize_for_sink(payload, _sink(kind), _policy()) for kind in SINK_ORDER
        ]
        for other in outputs[1:]:
            self._assert_congruent(outputs[0], other)
        self.assertEqual(
            outputs[0].manifest.classification, ArtifactClassification.SENSITIVE
        )

    def test_sink_kind_set_is_exactly_five_frozen_values(self):
        # FR-N05-02 / 8.1: SINK_KINDS is the frozen five-value set.
        self.assertEqual(SINK_KINDS, frozenset(SINK_ORDER))
        self.assertEqual(len(SINK_KINDS), 5)

    def test_deterministic_repeat_calls_same_output(self):
        # FR-N05-02 conformance side: repeated identical calls give identical
        # manifests (except created_at) and redacted values per sink kind.
        payload = EvidencePayload(
            payload_kind="structured_json", value={"password": "pw-987654321"}
        )
        for kind in SINK_ORDER:
            with self.subTest(kind=kind):
                first = sanitize_for_sink(payload, _sink(kind), _policy())
                second = sanitize_for_sink(payload, _sink(kind), _policy())
                self.assertEqual(_manifest_key(first), _manifest_key(second))
                self.assertEqual(first.redacted_value, second.redacted_value)

    def test_purpose_field_is_informational(self):
        # AC/T-N05-01 8.2.1: SinkContext.purpose must not change the output.
        payload = EvidencePayload(payload_kind="text", value="plain diagnostic line")
        base = sanitize_for_sink(payload, _sink("log"), _policy())
        varied = sanitize_for_sink(
            payload, _sink("log", purpose="incident-42"), _policy()
        )
        self.assertEqual(_manifest_key(base), _manifest_key(varied))
        self.assertEqual(base.redacted_value, varied.redacted_value)

    def test_manifest_carries_policy_digest_of_same_policy(self):
        # FR-N05-02: manifest.policy_digest equals policy_digest(policy)
        # identically across all five sinks (O-1 module-path consumption).
        policy = _policy()
        payload = EvidencePayload(payload_kind="structured_json", value={"n": 1})
        for kind in SINK_ORDER:
            with self.subTest(kind=kind):
                sp = sanitize_for_sink(payload, _sink(kind), policy)
                self.assertEqual(sp.manifest.policy_digest, policy_digest(policy))
                self.assertEqual(sp.manifest.policy_version, "v1")


class AllowlistAndTenantTests(unittest.TestCase):
    def test_allowlist_reduction_rejects_removed_kind_for_all_five(self):
        # AC/T-N05-01 8.2.2: removing k from sink_allowlist -> UNKNOWN_SINK for
        # sink_kind=k, asserted once per frozen sink value.
        payload = EvidencePayload(payload_kind="structured_json", value={"a": 1})
        for kind in SINK_ORDER:
            with self.subTest(kind=kind):
                reduced = SINK_KINDS - {kind}
                with self.assertRaises(PrivacyError) as ei:
                    sanitize_for_sink(
                        payload,
                        _sink(kind),
                        _policy(sink_allowlist=reduced),
                    )
                self.assertIs(ei.exception.code, PrivacyErrorCode.UNKNOWN_SINK)

    def test_tenant_key_isolation_holds_across_all_five_sinks(self):
        # AC/T-N05-01 8.2.3: changing tenant_key changes the fingerprint at
        # the same position for every sink kind (DI-004 semantics).
        payload = EvidencePayload(
            payload_kind="structured_json", value={"client_secret": "s-0123456789"}
        )
        for kind in SINK_ORDER:
            with self.subTest(kind=kind):
                sp_a = sanitize_for_sink(payload, _sink(kind, tenant_key=KEY), _policy())
                sp_b = sanitize_for_sink(payload, _sink(kind, tenant_key=KEY_B), _policy())
                fp_a = [rec.fingerprint for rec in sp_a.manifest.entries]
                fp_b = [rec.fingerprint for rec in sp_b.manifest.entries]
                self.assertEqual(len(fp_a), 1)
                self.assertNotEqual(fp_a, fp_b)
                for fp in fp_a + fp_b:
                    self.assertEqual(len(fp), 32)
                    self.assertEqual(fp, fp.lower())

    def test_tenant_key_isolation_cross_sink_fingerprint_stability(self):
        # AC/T-N05-01 8.2.3: with the same tenant credentials the fingerprint
        # at the same position is identical across all five sink kinds.
        payload = EvidencePayload(payload_kind="text", value="token leak in a log line")
        fingerprints = [
            sanitize_for_sink(payload, _sink(kind), _policy()).manifest.entries[
                0
            ].fingerprint
            for kind in SINK_ORDER
        ]
        self.assertEqual(len(set(fingerprints)), 1)

    def test_output_tenant_id_follows_context(self):
        # FR-N05-02: SanitizedPayload.tenant_id mirrors SinkContext.tenant_id
        # for every sink kind while classification stays congruent.
        payload = EvidencePayload(payload_kind="structured_json", value={"k": "v"})
        sp_a = sanitize_for_sink(payload, _sink("api", tenant_id="tenant-a"), _policy())
        sp_b = sanitize_for_sink(payload, _sink("export", tenant_id="tenant-b"), _policy())
        self.assertEqual(sp_a.tenant_id, "tenant-a")
        self.assertEqual(sp_b.tenant_id, "tenant-b")
        self.assertEqual(_manifest_key(sp_a).entries, _manifest_key(sp_b).entries)


class SinkUniformityNegativeTests(unittest.TestCase):
    def test_over_limit_rejected_with_same_code_for_all_five_sinks(self):
        # AC/T-N05-01 / 8.2 (appendix A negative row): resource-limit negative
        # inputs get the identical typed failure across all five sink kinds.
        from lima.evidence_privacy import PrivacyLimits

        payload = EvidencePayload(payload_kind="text", value="z" * 65)
        limits = PrivacyLimits(max_string_bytes=64)
        for kind in SINK_ORDER:
            with self.subTest(kind=kind):
                with self.assertRaises(PrivacyError) as ei:
                    sanitize_for_sink(
                        payload,
                        _sink(kind),
                        _policy(limits=limits),
                    )
                self.assertIs(
                    ei.exception.code, PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED
                )

    def test_sensitive_keyword_detection_uniform_across_sinks(self):
        # FR-N05-02 / 8.5.2 (frozen whole-value rule): a text value carrying a
        # sensitive keyword is SENSITIVE for every sink kind with one record.
        payload = EvidencePayload(payload_kind="text", value="rotate password now")
        for kind in SINK_ORDER:
            with self.subTest(kind=kind):
                sp = sanitize_for_sink(payload, _sink(kind), _policy())
                self.assertEqual(
                    sp.manifest.classification, ArtifactClassification.SENSITIVE
                )
                self.assertEqual(len(sp.manifest.entries), 1)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
