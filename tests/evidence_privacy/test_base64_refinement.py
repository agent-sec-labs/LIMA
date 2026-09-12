# IP-0017 Content Conformance - frozen acceptance tests (P&V owned, phase 2).
# Packet: docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md v1.0
# Scope: AC/T-N05-03 full scenario set + DR-IP-0015-02 bare Base64 default
# level refinement (Packet 8.4): predicate, default SENSITIVE level,
# four-layer precedence RESTRICTED > sensitive key > bare base64 > INTERNAL,
# [[REDACTED:32hex]] span form, and the text paragraph-scan branch applying
# only to inputs the whole-value rules judge INTERNAL.
# unittest.TestCase style, no pytest-only APIs.
"""Bare Base64 refinement suite (Packet 8.4; AC/T-N05-03, DR-IP-0015-02)."""

from __future__ import annotations

import base64
import unittest

from lima.contracts.common import ArtifactClassification
from lima.evidence_privacy import (
    EvidencePayload,
    FingerprintRecord,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

KEY = b"\x33" * 32
B64_SECRET = base64.b64encode(b"0" * 24).decode()  # 32 chars, decodes cleanly
B64_PADDED = base64.b64encode(b"x" * 26).decode()  # 36 chars incl one '='
B64_SHORT = base64.b64encode(b"0" * 21).decode()  # 28 chars: below threshold
URL_CRED = "https://deploy:Hunt3rPass@ci.example.internal/build"  # noqa: S105


def _sink(kind="storage"):
    return SinkContext(sink_kind=kind, tenant_id="tenant-a", tenant_key=KEY)


def _policy():
    return TenantPolicy.resolve(policy_version="v1")


def _sanitize(kind, payload_kind, value):
    return sanitize_for_sink(
        EvidencePayload(payload_kind=payload_kind, value=value),
        _sink(kind),
        _policy(),
    )


class ContentScanModuleContractTests(unittest.TestCase):
    def test_module_exports_frozen_symbols(self):
        # AC/T-N05-03 7.1: content_scan module path carries the frozen
        # symbols with the frozen shapes (O-1: consumed via module path).
        from lima.evidence_privacy import content_scan

        self.assertEqual(content_scan.BASE64_MIN_LENGTH, 32)
        self.assertTrue(callable(content_scan.is_bare_base64_secret))
        self.assertTrue(callable(content_scan.find_base64_spans))
        self.assertTrue(callable(content_scan.redact_text_segments))

    def test_redacted_segment_template_form(self):
        # AC/T-N05-03 8.4.4: template renders [[REDACTED:<32hex>]] spans.
        from lima.evidence_privacy import content_scan

        rendered = content_scan.REDACTED_SEGMENT_TEMPLATE.format(
            fingerprint="a" * 32
        )
        self.assertEqual(rendered, f"[[REDACTED:{'a' * 32}]]")

    def test_predicate_accepts_valid_candidates(self):
        # AC/T-N05-03 8.4.1: NFC length >= 32, strict alphabet, len % 4 == 0,
        # b64decode(validate=True) succeeds; padding of 1-2 '=' allowed.
        from lima.evidence_privacy import content_scan

        self.assertTrue(content_scan.is_bare_base64_secret(B64_SECRET))
        self.assertTrue(content_scan.is_bare_base64_secret(B64_PADDED))

    def test_predicate_rejects_non_candidates(self):
        # AC/T-N05-03 8.4.1: below threshold, wrong charset, len % 4 != 0,
        # and undecodable forms are all rejected.
        from lima.evidence_privacy import content_scan

        self.assertFalse(content_scan.is_bare_base64_secret(B64_SHORT))  # 28 chars
        self.assertFalse(
            content_scan.is_bare_base64_secret("!!!!" + "A" * 36)
        )  # bad charset
        self.assertFalse(
            content_scan.is_bare_base64_secret("A" * 33)
        )  # len % 4 != 0
        self.assertFalse(
            content_scan.is_bare_base64_secret("A" * 29 + "===")
        )  # 3 pads -> invalid

    def test_find_base64_spans_maximal_left_to_right(self):
        # AC/T-N05-03 8.4.4: spans are maximal candidates in NFC text,
        # non-overlapping, left to right; non-candidate text untouched.
        from lima.evidence_privacy import content_scan

        text = f"pre {B64_SECRET} mid {B64_SECRET} post"
        spans = content_scan.find_base64_spans(text)
        self.assertEqual(len(spans), 2)
        for start, end in spans:
            self.assertEqual(text[start:end], B64_SECRET)
        self.assertEqual(spans[0][0], text.index(B64_SECRET))


class PrecedenceAndLevelTests(unittest.TestCase):
    def test_structured_bare_base64_default_sensitive(self):
        # AC/T-N05-03 8.4.2: no sensitive-key context + predicate satisfied ->
        # SENSITIVE, position replaced by a FingerprintRecord (value_kind
        # "string"), severity merged by the frozen enum order.
        sp = _sanitize("api", "structured_json", {"blob": B64_SECRET})
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        red = sp.redacted_value["blob"]
        self.assertIsInstance(red, FingerprintRecord)
        self.assertEqual(red.value_kind, "string")
        self.assertEqual(red.length, 32)
        self.assertEqual(red.fingerprint, sp.manifest.entries[0].fingerprint)

    def test_restricted_shape_wins_over_base64(self):
        # AC/T-N05-03 8.4.3 layer 1: RESTRICTED value shapes (PEM header /
        # URL credential) beat every other rule, base64 included.
        sp = _sanitize(
            "storage", "structured_json", {"endpoint": URL_CRED + "?" + B64_SECRET}
        )
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.RESTRICTED
        )
        self.assertIsInstance(sp.redacted_value["endpoint"], FingerprintRecord)

    def test_sensitive_key_context_wins_level_not_shape(self):
        # AC/T-N05-03 8.4.3 layer 2: sensitive key context -> SENSITIVE
        # regardless of whether the value itself is Base64; the record is
        # the whole value (frozen existing behavior).
        sp = _sanitize("storage", "structured_json", {"api_key": B64_SECRET})
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertEqual(len(sp.manifest.entries), 1)
        self.assertEqual(sp.manifest.entries[0].length, 32)

    def test_short_or_undecodable_base64_stays_internal(self):
        # AC/T-N05-03 8.4.3 layer 4: below 32 chars or not decodable ->
        # INTERNAL default, value preserved (NFC) in the redacted output.
        # ("A" * 33 is NOT used here: its 32-char prefix is itself a valid
        # span candidate per 8.4.4.)
        sp = _sanitize("api", "structured_json", {"blob": B64_SHORT})
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.INTERNAL
        )
        self.assertEqual(sp.redacted_value["blob"], B64_SHORT)
        sp2 = _sanitize("api", "structured_json", {"blob": "not-base64-" * 4})
        self.assertEqual(
            sp2.manifest.classification, ArtifactClassification.INTERNAL
        )
        self.assertEqual(sp2.redacted_value["blob"], "not-base64-" * 4)

    def test_unicode_short_value_stays_internal(self):
        # AC/T-N05-03: short/Unicode values without other signals remain
        # INTERNAL (refinement must not over-trigger).
        sp = _sanitize("export", "structured_json", {"note": "caf\u00e9 tiny"})
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.INTERNAL
        )

    def test_bytes_whole_value_still_sensitive(self):
        # AC/T-N05-03: binary payloads keep the conservative whole-value
        # SENSITIVE rule (Appendix A "binary secret"); base64 refinement is
        # a str-value rule.
        sp = _sanitize("api", "bytes", b"0" * 24)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )


class TextParagraphScanTests(unittest.TestCase):
    def test_text_span_scan_applies_only_after_whole_value_rules(self):
        # AC/T-N05-03 8.5.2: a text input the frozen whole-value rules judge
        # INTERNAL (no PEM, no keyword) but carrying a base64 span becomes
        # SENSITIVE with the span replaced; a keyword-bearing text keeps the
        # whole-value record (scan does not preempt frozen rules).
        plain = f"context blob {B64_SECRET} end"
        sp = _sanitize("storage", "text", plain)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertIsInstance(sp.redacted_value, str)
        self.assertIn("[[REDACTED:", sp.redacted_value)
        self.assertNotIn(B64_SECRET, sp.redacted_value)
        self.assertTrue(sp.redacted_value.startswith("context blob "))
        self.assertTrue(sp.redacted_value.endswith(" end"))
        self.assertEqual(len(sp.manifest.entries), 1)
        self.assertIn(sp.manifest.entries[0].fingerprint, sp.redacted_value)

        keyword = "rotate password soon"
        sp2 = _sanitize("storage", "text", keyword)
        self.assertIsInstance(sp2.redacted_value, FingerprintRecord)

    def test_text_without_candidate_span_stays_internal(self):
        # AC/T-N05-03 8.5.2: no candidate span -> INTERNAL, NFC text back.
        sp = _sanitize("prompt", "text", f"small chunk {B64_SHORT} only")
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.INTERNAL
        )
        self.assertEqual(sp.redacted_value, f"small chunk {B64_SHORT} only")

    def test_redact_text_segments_tenant_isolation(self):
        # AC/T-N05-03 8.4.4 / DI-004: span fingerprints are tenant-isolated -
        # redact_text_segments with a different tenant_key yields a
        # different fingerprint for the same span.
        from lima.evidence_privacy import content_scan

        text_a, records_a = content_scan.redact_text_segments(
            f"v={B64_SECRET}", _policy(), tenant_id="t1", tenant_key=b"\x11" * 32
        )
        text_b, records_b = content_scan.redact_text_segments(
            f"v={B64_SECRET}", _policy(), tenant_id="t1", tenant_key=b"\x22" * 32
        )
        self.assertEqual(len(records_a), 1)
        self.assertEqual(len(records_b), 1)
        self.assertNotEqual(records_a[0].fingerprint, records_b[0].fingerprint)
        self.assertNotIn(B64_SECRET, text_a)
        self.assertIn(records_a[0].fingerprint, text_a)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
