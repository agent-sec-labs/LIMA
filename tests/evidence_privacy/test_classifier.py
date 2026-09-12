# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
# Frozen Test Commit v2 (DR-IP-0015-03 erratum 2026-09-12): converted from
# v1 bare-function style to unittest.TestCase style 1:1; assertions,
# boundary values, and requirement-ID anchors are unchanged from v1 (97e0b63).
"""Classification core tests (Packet section 8.7; FR-N05-01, AC/T-N05-03 core)."""

from __future__ import annotations

import unittest

from lima.evidence_privacy import (
    EvidencePayload,
    TenantPolicy,
    classify_payload,
)

from lima.contracts.common import ArtifactClassification

POLICY = TenantPolicy(policy_version="v1")


def _manifest(value):
    return classify_payload(EvidencePayload(payload_kind="structured_json", value=value), POLICY)


class ClassifierTests(unittest.TestCase):
    def test_enum_comes_from_contracts(self):
        # FR-N05-01: no parallel enum; classification values come from #58 DI-001.
        self.assertEqual(ArtifactClassification.PUBLIC.value, "public")
        self.assertEqual(ArtifactClassification.RESTRICTED.value, "restricted")
        m = _manifest({"note": "hello world"})
        self.assertIsInstance(m.classification, ArtifactClassification)

    def test_plain_internal_payload_defaults_internal(self):
        # Packet 8.7: no sensitive key / PEM / URL credential -> INTERNAL default.
        m = _manifest({"note": "just a normal sentence"})
        self.assertEqual(m.classification, ArtifactClassification.INTERNAL)
        self.assertEqual(m.entries, ())

    def test_sensitive_key_pattern_matches_case_insensitive(self):
        # FR-N05-01 / Packet 8.7: secret/token/key/password/credential/private_key
        # key-name match (case-insensitive) -> SENSITIVE.
        for key in ("api_token", "DB_PASSWORD", "secretValue", "private_key", "Credential"):
            with self.subTest(key=key):
                m = _manifest({key: "abcdefghijklmnop"})
                self.assertEqual(m.classification, ArtifactClassification.SENSITIVE, key)
                self.assertEqual(len(m.entries), 1)
                self.assertEqual(m.entries[0].value_kind, "string")

    def test_url_credential_classified_restricted(self):
        # FR-N05-01 / Appendix A: scheme://user:pass@ text -> RESTRICTED.
        m = _manifest({"endpoint": "https://user:supersecretpw@example.com/p"})
        self.assertEqual(m.classification, ArtifactClassification.RESTRICTED)
        self.assertGreater(m.entries[0].length, 0)

    def test_pem_private_key_classified_restricted(self):
        # FR-N05-01 / Appendix A: PEM header -> RESTRICTED.
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----\n"
        m = _manifest({"body": pem})
        self.assertEqual(m.classification, ArtifactClassification.RESTRICTED)

    def test_overall_classification_is_max_of_entries(self):
        # Packet 8.7: envelope classification = highest entry level
        # (public < internal < sensitive < restricted, #58 enum order).
        m = _manifest({"note": "ok", "api_secret": "abcdefghijklmnop"})
        self.assertEqual(m.classification, ArtifactClassification.SENSITIVE)
        m2 = _manifest({"api_secret": "abcdefghijklmnop", "body": "https://u:pw1234@h/x"})
        self.assertEqual(m2.classification, ArtifactClassification.RESTRICTED)

    def test_enum_ordering_follows_contracts(self):
        # Packet 8.7: ordering is the #58 enum definition order.
        order = [e.name for e in ArtifactClassification]
        self.assertLess(order.index("PUBLIC"), order.index("INTERNAL"))
        self.assertLess(order.index("INTERNAL"), order.index("SENSITIVE"))
        self.assertLess(order.index("SENSITIVE"), order.index("RESTRICTED"))

    def test_text_payload_whole_value_fingerprinted(self):
        # Appendix A: unstructured text handled conservatively (whole-value).
        m = classify_payload(
            EvidencePayload(payload_kind="text", value="line with secret inside"), POLICY
        )
        self.assertIn(
            m.classification,
            (ArtifactClassification.SENSITIVE, ArtifactClassification.RESTRICTED),
        )
        self.assertGreaterEqual(len(m.entries), 1)

    def test_bytes_payload_classified_sensitive(self):
        # Appendix A: binary secret blob -> SENSITIVE entry with bytes kind.
        m = classify_payload(
            EvidencePayload(payload_kind="bytes", value=b"\x00\x11binaryblob"), POLICY
        )
        self.assertEqual(m.classification, ArtifactClassification.SENSITIVE)
        self.assertEqual(m.entries[0].value_kind, "bytes")
        self.assertEqual(m.entries[0].length, len(b"\x00\x11binaryblob"))

    def test_manifest_carries_policy_version_and_digest(self):
        # NFR-N05-04: manifest always carries policy_version and 64-hex digest.
        m = _manifest({"api_key": "abcdefghijklmnop"})
        self.assertEqual(m.policy_version, "v1")
        self.assertEqual(len(m.policy_digest), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in m.policy_digest))
        self.assertTrue(m.created_at)  # UTC ISO-8601 NFC string present


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
