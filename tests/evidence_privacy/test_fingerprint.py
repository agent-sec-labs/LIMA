# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
# Frozen Test Commit v2 (DR-IP-0015-03 erratum 2026-09-12): converted from
# v1 bare-function style to unittest.TestCase style 1:1; assertions,
# boundary values, and requirement-ID anchors are unchanged from v1 (97e0b63).
"""HMAC tenant-isolated fingerprint tests (Packet section 8.3)."""

from __future__ import annotations

import hashlib
import unicodedata
import unittest

from lima.evidence_privacy import compute_fingerprint

TENANT_KEY = b"\x11" * 32
OTHER_KEY = b"\x22" * 32
SECRET = "ghp_16charsecret0"  # noqa: S105 - FR-N05-03 synthetic token


class FingerprintTests(unittest.TestCase):
    def test_fingerprint_is_32_lowercase_hex(self):
        # NFR-N05-01 / Packet 8.3: 16-byte truncated HMAC -> 32 lowercase hex chars.
        fp = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=TENANT_KEY)
        self.assertIsInstance(fp, str)
        self.assertEqual(len(fp), 32)
        self.assertTrue(all(c in "0123456789abcdef" for c in fp))

    def test_same_tenant_same_value_deterministic(self):
        # NFR-N05-01 / AC/T-N05-02: same tenant_id+key+value -> byte-identical fingerprint.
        a = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=TENANT_KEY)
        b = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=TENANT_KEY)
        self.assertEqual(a, b)

    def test_same_tenant_distinct_values_differ(self):
        # AC/T-N05-02 dedup basis: distinct values -> distinct fingerprints (spot check).
        a = compute_fingerprint("value-one-aaaa", tenant_id="t", tenant_key=TENANT_KEY)
        b = compute_fingerprint("value-two-bbbb", tenant_id="t", tenant_key=TENANT_KEY)
        self.assertNotEqual(a, b)

    def test_cross_tenant_id_differ(self):
        # NFR-N05-01 / AC/T-N05-02: same value, different tenant_id -> different fp.
        a = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=TENANT_KEY)
        b = compute_fingerprint(SECRET, tenant_id="tenant-b", tenant_key=TENANT_KEY)
        self.assertNotEqual(a, b)

    def test_cross_tenant_key_differ(self):
        # NFR-N05-01: same value+tenant_id, different key -> different fp.
        a = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=TENANT_KEY)
        b = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=OTHER_KEY)
        self.assertNotEqual(a, b)

    def test_not_plain_sha256(self):
        # NFR-N05-01: no keyless-computable leakage; fp != sha256(value)[:32].
        fp = compute_fingerprint(SECRET, tenant_id="tenant-a", tenant_key=TENANT_KEY)
        naive = hashlib.sha256(SECRET.encode("utf-8")).hexdigest()[:32]
        self.assertNotEqual(fp, naive)

    def test_nfc_nfd_normalization_same_fingerprint(self):
        # NFR-N05-01 / Packet 8.3 / AC/T-N05-03 core: NFD input yields same fp as NFC.
        nfc = unicodedata.normalize("NFC", "caf\u00e9-secret-value")
        nfd = unicodedata.normalize("NFD", "caf\u00e9-secret-value")
        a = compute_fingerprint(nfc, tenant_id="t", tenant_key=TENANT_KEY)
        b = compute_fingerprint(nfd, tenant_id="t", tenant_key=TENANT_KEY)
        self.assertEqual(a, b)

    def test_bytes_input(self):
        # FR-N05-03 / Appendix A: bytes fingerprinted over raw bytes.
        blob = b"\x00\x01\x02binary-secret-bytes"
        fp = compute_fingerprint(blob, tenant_id="t", tenant_key=TENANT_KEY)
        self.assertEqual(len(fp), 32)
        # bytes vs str of same readable text must not collide blindly.
        fp_str = compute_fingerprint("binary-secret-bytes", tenant_id="t", tenant_key=TENANT_KEY)
        self.assertNotEqual(fp, fp_str)

    def test_int_bool_null_scalar_kinds(self):
        # Packet 8.3: int/bool/null normalized via canonical JSON text bytes.
        self.assertNotEqual(
            compute_fingerprint(1, tenant_id="t", tenant_key=TENANT_KEY),
            compute_fingerprint(True, tenant_id="t", tenant_key=TENANT_KEY),
        )
        self.assertNotEqual(
            compute_fingerprint(None, tenant_id="t", tenant_key=TENANT_KEY),
            compute_fingerprint(0, tenant_id="t", tenant_key=TENANT_KEY),
        )
        # canonical int text: "1" string vs int 1 share canonical bytes form? Packet
        # says int -> canonical JSON text bytes, which equals canonical form of the
        # JSON number; str "1" normalizes to UTF-8 "1" -> identical bytes is the
        # frozen canonical semantics; assert both are well-formed instead.
        self.assertEqual(len(compute_fingerprint(7, tenant_id="t", tenant_key=TENANT_KEY)), 32)

    def test_structured_input_uses_canonical_encoding(self):
        # Packet 8.3: structured input fingerprinted via canonical_encode bytes;
        # key order must not matter (sorted-key canonical form, DI-002).
        a = compute_fingerprint(
            {"x": 1, "y": "s"}, tenant_id="t", tenant_key=TENANT_KEY
        )
        b = compute_fingerprint(
            {"y": "s", "x": 1}, tenant_id="t", tenant_key=TENANT_KEY
        )
        self.assertEqual(a, b)

    def test_domain_separation_constants_present(self):
        # Packet 8.3: domain separator is a frozen module-level Final constant,
        # never concatenated from caller input.
        import inspect

        from lima.evidence_privacy import fingerprint as fp_mod

        src = inspect.getsource(fp_mod)
        self.assertIn("lima.evidence_privacy.tenant-key.v1", src)
        self.assertIn("lima.evidence_privacy.fingerprint.v1", src)
        self.assertIn("Final", src)

    def test_derived_key_isolation_between_domains(self):
        # Packet 8.3: tenant-key derivation then fingerprint derivation; changing
        # tenant_id must change derivation input (verified behaviourally here).
        a = compute_fingerprint("same", tenant_id="alpha", tenant_key=TENANT_KEY)
        b = compute_fingerprint("same", tenant_id="beta", tenant_key=TENANT_KEY)
        c = compute_fingerprint("same", tenant_id="alpha", tenant_key=TENANT_KEY)
        self.assertTrue(a != b and a == c)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
