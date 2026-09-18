# IP-0017 Content Conformance - frozen acceptance tests (P&V owned, phase 2).
# Packet: docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md v1.0
# Scope: AC/T-N05-05 fixture no-leak verification (Packet 8.6): API-response
# and export-bundle shaped fixtures sanitized through sanitize_for_sink must
# not leak any >=4-char raw-secret substring anywhere in the returned object
# (str/repr of every node, canonical encoding of redacted_value), and the
# error paths for every negative family must stay value-free.
# unittest.TestCase style, no pytest-only APIs.
"""API/export fixture no-leak suite (Packet 8.6; AC/T-N05-05)."""

from __future__ import annotations

import base64
import unittest
from dataclasses import replace

from lima.contracts.codec import canonical_encode
from lima.evidence_privacy import (
    EvidencePayload,
    FingerprintRecord,
    PrivacyError,
    PrivacyLimits,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

KEY = b"\x33" * 32
SECRET_SHORT = "ghp_s0h0rt"  # noqa: S105 - synthetic fixture token
TOKEN = "tok-998877665544"  # noqa: S105 - synthetic fixture token
URL_PASSWORD = "Hunt3rPass"  # noqa: S105 - synthetic fixture credential
URL_CRED = f"https://deploy:{URL_PASSWORD}@ci.example.internal/build"
PEM_BLOCK = (
    "-----BEGIN EC PRIVATE KEY-----\nMHc synthetic body\n"
    "-----END EC PRIVATE KEY-----\n"
)
B64_SECRET = base64.b64encode(b"\x5a" * 24).decode()  # 32-char candidate
BINARY_B64 = base64.b64encode(bytes(range(64))).decode()  # 88-char candidate

# >=4-char raw-secret fragments that must never appear in any output node.
SECRET_FRAGMENTS = (
    SECRET_SHORT,
    TOKEN,
    URL_PASSWORD,
    "deploy",
    "PRIVATE KEY-----",
    PEM_BLOCK.splitlines()[1],
    B64_SECRET,
    B64_SECRET[:16],
    BINARY_B64,
    BINARY_B64[:16],
)


def _sink(kind):
    return SinkContext(sink_kind=kind, tenant_id="tenant-a", tenant_key=KEY)


def _policy(limits=None, sink_allowlist=None, **kw):
    if limits is not None:
        kw["limits"] = limits
    if sink_allowlist is not None:
        kw["sink_allowlist"] = sink_allowlist
    return TenantPolicy.resolve(policy_version="v1", **kw)


def _jsonify(node):
    # Replace FingerprintRecord nodes with their fingerprint text so the
    # fixture can be canonically encoded (records are already checked via
    # str/repr in _assert_no_leak).
    if isinstance(node, FingerprintRecord):
        return f"<fingerprint:{node.fingerprint}>"
    if isinstance(node, dict):
        return {key: _jsonify(item) for key, item in node.items()}
    if isinstance(node, (list, tuple)):
        return [_jsonify(item) for item in node]
    return node


def _api_fixture():
    # 8.6 API-response shape: nested user objects + one secret of every
    # class (short secret / token / URL credential / PEM / bare base64 /
    # binary media as embedded base64 text).
    return {
        "request_id": "req-0001",
        "user": {
            "id": 42,
            "profile": {"display_name": "ada", "locale": "en"},
            "client_secret": SECRET_SHORT,
            "auth": {"access_token": TOKEN, "refresh": None},
        },
        "ci": {"endpoint": URL_CRED, "signed_by": PEM_BLOCK},
        "attachments": [
            {"media_type": "application/octet-stream", "content_b64": BINARY_B64},
            {"media_type": "text/plain", "content_b64": "c2hvcnQ="},
        ],
        "diag": {"blob": B64_SECRET, "ok": True},
    }


def _export_fixture():
    # 8.6 export-bundle shape: metadata header + multi-record array with the
    # same secret classes.
    return {
        "bundle_version": 1,
        "metadata": {"tenant": "tenant-a", "kind": "export"},
        "records": [
            {"id": "r-1", "secret": {"password": SECRET_SHORT, "note": "ok"}},
            {"id": "r-2", "endpoint": URL_CRED},
            {"id": "r-3", "material": PEM_BLOCK, "blob": B64_SECRET},
        ],
    }


def _iter_nodes(node):
    yield node
    if isinstance(node, dict):
        for key, item in node.items():
            yield key
            yield from _iter_nodes(item)
    elif isinstance(node, (list, tuple)):
        for item in node:
            yield from _iter_nodes(item)


def _assert_no_leak(test, sp: SanitizedPayload):
    # 8.6: recursive traversal of every node (dict/list/str/bytes/record),
    # checking str() and repr() plus the canonical encoding of
    # redacted_value, for >=4-char raw-secret fragments.
    for node in _iter_nodes(sp):
        node_str = node if isinstance(node, str) else str(node)
        for fragment in SECRET_FRAGMENTS:
            test.assertNotIn(fragment, node_str, f"leak in str: {node_str[:60]!r}")
            test.assertNotIn(
                fragment, repr(node), f"leak in repr: {repr(node)[:60]!r}"
            )
    encoded = canonical_encode(_jsonify(sp.redacted_value))
    for fragment in SECRET_FRAGMENTS:
        test.assertNotIn(fragment.encode("utf-8"), encoded)


class FixtureNoLeakTests(unittest.TestCase):
    def test_api_fixture_recursive_no_leak(self):
        # AC/T-N05-05 8.6: api sink over the API-response fixture.
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=_api_fixture()),
            _sink("api"),
            _policy(),
        )
        _assert_no_leak(self, sp)
        # Sensitive positions must actually be replaced by records.
        red = sp.redacted_value
        self.assertIsInstance(red["user"]["client_secret"], FingerprintRecord)
        self.assertIsInstance(red["diag"]["blob"], FingerprintRecord)
        self.assertIsInstance(red["attachments"][0]["content_b64"], FingerprintRecord)

    def test_export_fixture_recursive_no_leak(self):
        # AC/T-N05-05 8.6: export sink over the export-bundle fixture.
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=_export_fixture()),
            _sink("export"),
            _policy(),
        )
        _assert_no_leak(self, sp)
        red = sp.redacted_value
        # "secret" is itself a sensitive key: the whole sub-object becomes
        # one record (frozen whole-position rule).
        self.assertIsInstance(red["records"][0]["secret"], FingerprintRecord)
        self.assertIsInstance(red["records"][2]["blob"], FingerprintRecord)

    def test_api_export_congruence_only_sink_kind_differs(self):
        # AC/T-N05-05 8.6 + 8.2.1: api and export over the same fixture are
        # congruent except for sink_kind (no per-sink behavior).
        payload = EvidencePayload(payload_kind="structured_json", value=_api_fixture())
        api = sanitize_for_sink(payload, _sink("api"), _policy())
        export = sanitize_for_sink(payload, _sink("export"), _policy())
        self.assertEqual(api.sink_kind, "api")
        self.assertEqual(export.sink_kind, "export")
        self.assertEqual(
            replace(api.manifest, created_at=""), replace(export.manifest, created_at="")
        )
        self.assertEqual(api.redacted_value, export.redacted_value)

    def test_manifest_entries_value_free(self):
        # AC/T-N05-05 8.6: FingerprintRecord entries (incl. previews) carry
        # no raw-secret material.
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=_api_fixture()),
            _sink("api"),
            _policy(preview_enabled=True, preview_max_chars=2),
        )
        for record in sp.manifest.entries:
            for fragment in SECRET_FRAGMENTS:
                self.assertNotIn(fragment, str(record))
                self.assertNotIn(fragment, repr(record))
                self.assertNotIn(fragment, record.fingerprint)
                if record.preview is not None:
                    self.assertNotIn(fragment, record.preview)


class ErrorPathNoLeakTests(unittest.TestCase):
    def test_over_depth_error_no_leak(self):
        # AC/T-N05-05 8.6 error path: over-depth rejection carries no value.
        node = {"secret": SECRET_SHORT}
        for _ in range(8):
            node = {"child": node}
        with self.assertRaises(PrivacyError) as ei:
            sanitize_for_sink(
                EvidencePayload(payload_kind="structured_json", value=node),
                _sink("api"),
                _policy(limits=PrivacyLimits(max_depth=4)),
            )
        for fragment in SECRET_FRAGMENTS:
            self.assertNotIn(fragment, str(ei.exception))
            self.assertNotIn(fragment, repr(ei.exception))

    def test_over_items_error_no_leak(self):
        # AC/T-N05-05 8.6 error path: over-items rejection carries no value.
        value = [TOKEN, SECRET_SHORT, 1, 2, 3]
        with self.assertRaises(PrivacyError) as ei:
            sanitize_for_sink(
                EvidencePayload(payload_kind="structured_json", value=value),
                _sink("export"),
                _policy(limits=PrivacyLimits(max_items=4)),
            )
        self.assertNotIn(TOKEN, str(ei.exception))
        self.assertNotIn(SECRET_SHORT, repr(ei.exception))

    def test_unknown_sink_error_no_leak(self):
        # AC/T-N05-05 8.6 error path: unknown-sink rejection carries no value.
        with self.assertRaises(PrivacyError) as ei:
            sanitize_for_sink(
                EvidencePayload(payload_kind="text", value=f"leak {TOKEN} here"),
                SinkContext(
                    sink_kind="log", tenant_id="t", tenant_key=KEY
                ),
                _policy(sink_allowlist=frozenset({"storage"})),
            )
        self.assertNotIn(TOKEN, str(ei.exception))

    def test_cycle_error_no_leak(self):
        # AC/T-N05-05 8.6 error path + 8.3.4: cyclic input rejection is a
        # typed PrivacyError whose str/repr carry no value material.
        cyclic: dict = {"secret": SECRET_SHORT, "n": 1}
        cyclic["self"] = cyclic
        try:
            sanitize_for_sink(
                EvidencePayload(payload_kind="structured_json", value=cyclic),
                _sink("api"),
                _policy(
                    limits=PrivacyLimits(
                        max_depth=100_000, max_items=1_000_000, max_processing_ms=600_000
                    )
                ),
            )
        except PrivacyError as exc:
            self.assertNotIn(SECRET_SHORT, str(exc))
            self.assertNotIn(SECRET_SHORT, repr(exc))
        except RecursionError:  # pragma: no cover - the D-1 violation itself
            self.fail("bare RecursionError escaped sanitize_for_sink (Packet 8.3)")
        else:  # pragma: no cover - cyclic input must be rejected
            self.fail("cyclic input was accepted (Packet 8.3.1)")

    def test_time_budget_error_no_leak(self):
        # AC/T-N05-05 8.6 error path: time-budget rejection stays value-free
        # even on a fixture containing secrets.
        value = [SECRET_SHORT, TOKEN, URL_CRED] * 70_000
        with self.assertRaises(PrivacyError) as ei:
            sanitize_for_sink(
                EvidencePayload(payload_kind="structured_json", value=value),
                _sink("api"),
                _policy(
                    limits=PrivacyLimits(max_processing_ms=1, max_items=10_000_000)
                ),
            )
        self.assertNotIn(SECRET_SHORT, str(ei.exception))
        self.assertNotIn(TOKEN, str(ei.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
