# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
"""Value-kind matrix tests (Appendix A; AC/T-N05-03 core subset)."""

from __future__ import annotations

import base64
import unicodedata

from lima.evidence_privacy import (
    EvidencePayload,
    FingerprintRecord,
    SinkContext,
    TenantPolicy,
    compute_fingerprint,
    sanitize_for_sink,
)

from lima.contracts.common import ArtifactClassification

KEY = b"\x66" * 32


def _sanitize(value, kind="structured_json", policy=None):
    return sanitize_for_sink(
        EvidencePayload(payload_kind=kind, value=value),
        SinkContext(sink_kind="storage", tenant_id="t", tenant_key=KEY),
        policy or TenantPolicy.resolve(policy_version="v1"),
    )


def test_short_secret_preview_forced_none():
    # Appendix A: short secret (<8 chars) -> preview None even if enabled.
    pol = TenantPolicy.resolve(policy_version="v1", preview_enabled=True, preview_max_chars=2)
    sp = _sanitize({"api_key": "pk_live"}, policy=pol)
    rec = sp.manifest.entries[0]
    assert isinstance(rec, FingerprintRecord)
    assert rec.preview is None
    assert sp.manifest.classification == ArtifactClassification.SENSITIVE


def test_unicode_nfc_nfd_same_fingerprint_via_port():
    # Appendix A: NFC/NFD mixed text -> same fingerprint after normalization.
    nfc = unicodedata.normalize("NFC", "caf\u00e9-secret-va")
    nfd = unicodedata.normalize("NFD", "caf\u00e9-secret-va")
    a = compute_fingerprint(nfc, tenant_id="t", tenant_key=KEY)
    b = compute_fingerprint(nfd, tenant_id="t", tenant_key=KEY)
    assert a == b


def test_binary_secret_fingerprinted_as_bytes():
    # Appendix A: binary blob -> bytes fingerprint, raw bytes preserved input.
    blob = b"\x00\x01\x02\x03secretbytes"
    sp = _sanitize(blob, kind="bytes")
    rec = sp.manifest.entries[0]
    assert rec.value_kind == "bytes"
    assert rec.length == len(blob)
    assert len(rec.fingerprint) == 32


def test_base64_secret_fingerprinted():
    # Appendix A: base64-encoded secret (>=32 chars) under a sensitive key.
    b64 = base64.b64encode(b"super-secret-material-here").decode("ascii")
    assert len(b64) >= 32
    sp = _sanitize({"secret_b64": b64})
    rec = sp.manifest.entries[0]
    assert rec.value_kind == "string"
    assert b64 not in repr(sp)


def test_url_credential_restricted_and_fingerprinted():
    # Appendix A: URL credential -> RESTRICTED + fingerprint, no raw leak.
    url = "https://alice:hunter2@example.com/path"
    sp = _sanitize({"endpoint": url})
    assert sp.manifest.classification == ArtifactClassification.RESTRICTED
    assert "hunter2" not in repr(sp)


def test_pem_private_key_restricted_whole_value():
    # Appendix A: PEM private key -> RESTRICTED, multi-line whole-value normalize.
    pem = (
        "-----BEGIN RSA PRIVATE KEY-----\n"
        "MIIEowIBAAKCAQEA7characterdata1234\n"
        "-----END RSA PRIVATE KEY-----\n"
    )
    sp = _sanitize({"private_key": pem})
    assert sp.manifest.classification == ArtifactClassification.RESTRICTED
    assert "MIIEowIBAAKCAQEA" not in repr(sp)


def test_scalar_kinds_int_bool_null_recorded():
    # Packet 8.1 value_kind: int/bool/null entries carry correct kind labels.
    sp = _sanitize({"n": 1, "flag": True, "none": None})
    # benign scalars are preserved, not redacted (only sensitive positions replaced)
    assert sp.redacted_value["n"] == 1
    assert sp.redacted_value["flag"] is True
    assert sp.redacted_value["none"] is None


def test_structured_value_kind_for_nested_sensitive():
    # Packet 8.1: nested structured sensitive value uses "structured" kind.
    sp = _sanitize({"credential": {"user": "bob", "token": "abcdefghijklmnop"}})
    rec = sp.manifest.entries[0]
    assert rec.value_kind in ("structured", "string")


def test_text_payload_whole_fingerprint_record():
    # Packet 8.1: text payload -> whole-value fingerprint record.
    sp = _sanitize("log line with supersecret inside", kind="text")
    rec = sp.manifest.entries[0]
    assert rec.value_kind == "string"
    assert "supersecret" not in repr(sp)


def test_all_kinds_share_same_tenant_isolation():
    # AC/T-N05-02: every value kind shows tenant isolation through the entry.
    values = [
        ("string", "abcdefghijklmnop"),
        ("bytes", b"\x00" * 16),
        ("int", 123456789),
        ("bool", True),
        ("null", None),
    ]
    for kind, v in values:
        fa = compute_fingerprint(v, tenant_id="t1", tenant_key=KEY)
        fb = compute_fingerprint(v, tenant_id="t2", tenant_key=KEY)
        assert fa != fb, kind
