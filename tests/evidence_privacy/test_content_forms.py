# IP-0017 Content Conformance - frozen acceptance tests (P&V owned, phase 2).
# Packet: docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md v1.0
# Scope: FR-N05-05 multi content-form adaptation (Packet 8.5): structured_json
# nested matrix (8.5.1), text form-family logfmt/diff/prompt/traceback with
# one shared predicate family (8.5.2), bytes conformance matrix (8.5.3).
# unittest.TestCase style, no pytest-only APIs.
"""Content-form adaptation conformance suite (Packet 8.5; FR-N05-05)."""

from __future__ import annotations

import base64
import unicodedata
import unittest

from lima.contracts.common import ArtifactClassification
from lima.evidence_privacy import (
    EvidencePayload,
    FingerprintRecord,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyLimits,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

KEY = b"\x33" * 32
B64_SECRET = base64.b64encode(b"0" * 24).decode()  # 32 chars, decodable
URL_CRED = "https://deploy:Hunt3rPass@ci.example.internal/build"  # noqa: S105
PEM_TEXT = (
    "-----BEGIN RSA PRIVATE KEY-----\nMIIfX4 robes of entropy\n"
    "-----END RSA PRIVATE KEY-----\n"
)


def _sink(kind="storage"):
    return SinkContext(sink_kind=kind, tenant_id="tenant-a", tenant_key=KEY)


def _policy(**limit_kw):
    limits = PrivacyLimits(**limit_kw) if limit_kw else None
    return TenantPolicy.resolve(
        policy_version="v1", limits=limits
    ) if limits is not None else TenantPolicy.resolve(policy_version="v1")


def _sanitize(kind, payload_kind, value, **limit_kw):
    return sanitize_for_sink(
        EvidencePayload(payload_kind=payload_kind, value=value),
        _sink(kind),
        _policy(**limit_kw),
    )


def _nested(depth, leaf_key, leaf_value):
    node = {leaf_key: leaf_value}
    for _ in range(depth - 1):
        node = {"child": node}
    return node


class StructuredJsonFormTests(unittest.TestCase):
    def test_deep_nested_sensitive_key_detected(self):
        # FR-N05-05 8.5.1: sensitive detection survives deep dict nesting.
        sp = _sanitize("storage", "structured_json", _nested(30, "api_token", "t-1"))
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertEqual(len(sp.manifest.entries), 1)
        self.assertEqual(sp.manifest.entries[0].value_kind, "string")

    def test_list_of_dict_of_list_matrix(self):
        # FR-N05-05 8.5.1: nested list-of-dict-of-list traversal consistency;
        # classify and build_redacted_value agree position by position.
        value = {
            "rows": [
                {"cells": [1, "a"], "auth": [{"private_key": "pk-123456"}]},
                {"cells": ["b", None], "auth": []},
            ]
        }
        sp = _sanitize("api", "structured_json", value)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        red = sp.redacted_value
        record = red["rows"][0]["auth"][0]["private_key"]
        self.assertIsInstance(record, FingerprintRecord)
        self.assertEqual(
            record.fingerprint, sp.manifest.entries[0].fingerprint
        )

    def test_same_key_multiple_forms(self):
        # FR-N05-05 8.5.1: same key name with different value shapes.
        value = {
            "entries": [
                {"key": "plain-string"},
                {"key": 42},
                {"key": None},
                {"key": ["nested"]},
            ]
        }
        sp = _sanitize("log", "structured_json", value)
        # "key" is a sensitive token: every string/int/null position flagged.
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertEqual(len(sp.manifest.entries), 4)

    def test_deep_bare_base64_value_detected(self):
        # FR-N05-05 8.5.1 + 8.4.2: base64 refinement applies uniformly at any
        # depth - a deep bare Base64 value with no sensitive-key context is
        # SENSITIVE with a position record.
        sp = _sanitize(
            "storage", "structured_json", _nested(30, "blob", B64_SECRET)
        )
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertEqual(len(sp.manifest.entries), 1)
        record = sp.manifest.entries[0]
        self.assertEqual(record.value_kind, "string")
        self.assertEqual(record.length, 32)

    def test_structured_partial_base64_span_replaced(self):
        # FR-N05-05 8.5.1 + 8.4.4: a longer string embedding a base64
        # candidate keeps non-candidate parts; only the span becomes
        # [[REDACTED:<32hex>]]; the position yields per-span records.
        value = {"description": f"header {B64_SECRET} trailer"}
        sp = _sanitize("api", "structured_json", value)
        red = sp.redacted_value["description"]
        self.assertIsInstance(red, str)
        self.assertIn("[[REDACTED:", red)
        self.assertNotIn(B64_SECRET, red)
        self.assertTrue(red.startswith("header ") and red.endswith(" trailer"))
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertEqual(len(sp.manifest.entries), 1)
        self.assertIn(sp.manifest.entries[0].fingerprint, red)


class TextFormFamilyTests(unittest.TestCase):
    def test_logfmt_line_keyword_whole_value(self):
        # FR-N05-05 8.5.2 frozen: logfmt "token=abc" is covered by the
        # sensitive-keyword whole-value rule (SENSITIVE, no logfmt parsing).
        sp = _sanitize("log", "text", "lvl=info auth_token=zz component=http")
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertEqual(len(sp.manifest.entries), 1)
        self.assertIsInstance(sp.redacted_value, FingerprintRecord)

    def test_unified_diff_with_pem_block_restricted(self):
        # FR-N05-05 8.5.2 frozen: unified diff text containing a PEM block is
        # RESTRICTED whole-value regardless of media_type.
        diff = (
            "--- a/id_rsa\n+++ b/id_rsa\n@@ -1 +1 @@\n"
            f"+{PEM_TEXT}"
        )
        sp = _sanitize("storage", "text", diff, )
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.RESTRICTED
        )
        self.assertIsInstance(sp.redacted_value, FingerprintRecord)

    def test_prompt_fragment_with_url_credential_restricted(self):
        # FR-N05-05 8.5.2 frozen: prompt fragment carrying a URL credential
        # is RESTRICTED whole-value.
        prompt = f"Assistant, fetch {URL_CRED} and summarize the result."
        sp = _sanitize("prompt", "text", prompt)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.RESTRICTED
        )

    def test_traceback_text_base64_span_scanned(self):
        # FR-N05-05 8.5.2 new branch: traceback without PEM/keyword but with
        # an embedded bare Base64 span -> SENSITIVE, span replaced by
        # [[REDACTED:32hex]], one record per replaced span.
        tb = (
            "Traceback (most recent call last):\n"
            '  File "app.py", line 10, in handler\n'
            f"    raise ValueError(dump={B64_SECRET})\n"
            "ValueError: failed\n"
        )
        sp = _sanitize("storage", "text", tb)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertIsInstance(sp.redacted_value, str)
        self.assertNotIn(B64_SECRET, sp.redacted_value)
        self.assertIn("[[REDACTED:", sp.redacted_value)
        self.assertIn("Traceback (most recent call last):", sp.redacted_value)
        self.assertEqual(len(sp.manifest.entries), 1)

    def test_text_span_redacted_value_remains_str(self):
        # FR-N05-05 8.5.2 / DI-005: text redacted_value stays a str even when
        # only a span was replaced (SanitizedPayload.redacted_value shape).
        sp = _sanitize("prompt", "text", f"context: {B64_SECRET} end")
        self.assertIsInstance(sp.redacted_value, str)

    def test_text_nfc_normalization_preserved(self):
        # FR-N05-05 8.5.2 frozen: no-candidate text returns the NFC-normalized
        # original with classification INTERNAL.
        raw = "caf\u0065\u0301 naive"  # NFD form of cafe + combining acute
        sp = _sanitize("log", "text", raw)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.INTERNAL
        )
        self.assertEqual(sp.redacted_value, unicodedata.normalize("NFC", raw))

    def test_text_keyword_wins_over_span_replacement(self):
        # FR-N05-05 8.5.2 frozen ordering: whole-value keyword rule fires
        # before the new span branch (keyword text -> whole-value record).
        text = f"rotate password then blob={B64_SECRET}"
        sp = _sanitize("storage", "text", text)
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertIsInstance(sp.redacted_value, FingerprintRecord)

    def test_text_form_family_shared_predicates(self):
        # FR-N05-05 8.5.2: logfmt / diff / prompt / traceback shapes all hit
        # the same predicate family (here: keyword) - media_type informative.
        samples = {
            "log": "token rotation started",
            "diff": "+token rotation started",
            "prompt": "user asked to rotate token",
            "traceback": "ValueError: token expired",
        }
        for media, text in samples.items():
            with self.subTest(media=media):
                payload = EvidencePayload(
                    payload_kind="text", value=text, media_type=media
                )
                sp = sanitize_for_sink(payload, _sink(), _policy())
                self.assertEqual(
                    sp.manifest.classification, ArtifactClassification.SENSITIVE
                )


class BytesFormTests(unittest.TestCase):
    def test_bytes_pem_sensitive_whole_value(self):
        # FR-N05-05 8.5.3 frozen: bytes are conservatively whole-value
        # SENSITIVE with value_kind="bytes".
        sp = _sanitize("export", "bytes", PEM_TEXT.encode())
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )
        self.assertIsInstance(sp.redacted_value, FingerprintRecord)
        self.assertEqual(sp.manifest.entries[0].value_kind, "bytes")
        self.assertEqual(sp.manifest.entries[0].length, len(PEM_TEXT.encode()))

    def test_bytes_high_entropy_sensitive(self):
        # FR-N05-05 8.5.3: high-entropy bytes stay SENSITIVE.
        sp = _sanitize("api", "bytes", bytes(range(256)))
        self.assertEqual(
            sp.manifest.classification, ArtifactClassification.SENSITIVE
        )

    def test_bytes_empty_and_boundary_lengths(self):
        # FR-N05-05 8.5.3: empty and boundary-length bytes succeed.
        for blob in (b"", b"a", b"\x00" * 64):
            with self.subTest(length=len(blob)):
                sp = _sanitize("storage", "bytes", blob)
                self.assertEqual(
                    sp.manifest.classification,
                    ArtifactClassification.SENSITIVE,
                )

    def test_bytes_over_payload_limit_rejected(self):
        # FR-N05-05 8.5.3 matrix: over max_payload_bytes bytes ->
        # RESOURCE_LIMIT_EXCEEDED.
        with self.assertRaises(PrivacyError) as ei:
            _sanitize("log", "bytes", b"\x01" * 65, max_payload_bytes=64)
        self.assertIs(ei.exception.code, PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
