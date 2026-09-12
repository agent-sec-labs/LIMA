# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
"""Unified fail-closed entry sanitize_for_sink tests (Packet 8.2; FR-N05-02,
FR-N05-07, AC/T-N05-04, SEC-N05-02/03)."""

from __future__ import annotations

import pytest
from lima.evidence_privacy import (
    EvidencePayload,
    FingerprintRecord,
    PrivacyError,
    PrivacyErrorCode,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

from lima.contracts.common import ArtifactClassification

KEY = b"\x33" * 32
SECRET = "ghp_abcdefghijklmnop"  # noqa: S105 - synthetic test token


def _sink(kind="storage", tenant_id="tenant-a", tenant_key=KEY):
    return SinkContext(sink_kind=kind, tenant_id=tenant_id, tenant_key=tenant_key)


def _policy(**kw):
    return TenantPolicy.resolve(policy_version="v1", **kw)


def test_success_within_sink_kinds():
    # FR-N05-02: every frozen sink kind succeeds on a benign payload.
    for kind in ("storage", "log", "prompt", "api", "export"):
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value={"n": 1}),
            _sink(kind),
            _policy(),
        )
        assert isinstance(sp, SanitizedPayload)
        assert sp.sink_kind == kind and sp.tenant_id == "tenant-a"


def test_unknown_sink_rejected():
    # FR-N05-02 fail-closed: sink not in allowlist -> UNKNOWN_SINK.
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8),
            SinkContext(sink_kind="vault", tenant_id="t", tenant_key=KEY),
            _policy(),
        )
    assert ei.value.code == PrivacyErrorCode.UNKNOWN_SINK


def test_allowlist_shrink_enforced():
    # FR-N05-02: policy allowlist may shrink SINK_KINDS; others rejected.
    sp = sanitize_for_sink(
        EvidencePayload(payload_kind="text", value="x" * 8),
        _sink("storage"),
        _policy(sink_allowlist=frozenset({"storage"})),
    )
    assert sp.sink_kind == "storage"
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8),
            _sink("log"),
            _policy(sink_allowlist=frozenset({"storage"})),
        )
    assert ei.value.code == PrivacyErrorCode.UNKNOWN_SINK


def test_missing_tenant_key():
    # SEC-N05-01: missing/empty/non-bytes tenant key -> MISSING_TENANT_KEY.
    for bad in (b"", None):
        with pytest.raises(PrivacyError) as ei:
            sanitize_for_sink(
                EvidencePayload(payload_kind="text", value="x" * 8),
                _sink(tenant_key=bad),
                _policy(),
            )
        assert ei.value.code == PrivacyErrorCode.MISSING_TENANT_KEY


def test_invalid_tenant_id():
    # Packet 8.2 step 3: empty or >128-byte tenant_id -> INVALID_FIELD_VALUE.
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8),
            _sink(tenant_id=""),
            _policy(),
        )
    assert ei.value.code == PrivacyErrorCode.INVALID_FIELD_VALUE
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8),
            _sink(tenant_id="x" * 129),
            _policy(),
        )
    assert ei.value.code == PrivacyErrorCode.INVALID_FIELD_VALUE


def test_invalid_argument_types():
    # Packet 8.2 step 1: non-model args -> INVALID_FIELD_TYPE.
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink({"n": 1}, _sink(), _policy())  # type: ignore[arg-type]
    assert ei.value.code == PrivacyErrorCode.INVALID_FIELD_TYPE
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8), "log", _policy()  # type: ignore[arg-type]
        )
    assert ei.value.code == PrivacyErrorCode.INVALID_FIELD_TYPE


def test_sensitive_positions_replaced_by_fingerprint_records():
    # FR-N05-03 / Packet 8.2 step 7: sensitive dict values become FingerprintRecord.
    sp = sanitize_for_sink(
        EvidencePayload(payload_kind="structured_json", value={"api_key": SECRET, "n": 2}),
        _sink(),
        _policy(),
    )
    assert isinstance(sp.redacted_value, dict)
    assert isinstance(sp.redacted_value["api_key"], FingerprintRecord)
    assert sp.redacted_value["n"] == 2
    assert sp.manifest.classification == ArtifactClassification.SENSITIVE


def test_no_leak_in_result_repr_or_entries():
    # Packet 8.2 step 8 / NFR-N05-03: >=4-char sensitive substrings absent
    # from result object, repr(), and serialized forms.
    sp = sanitize_for_sink(
        EvidencePayload(payload_kind="structured_json", value={"password": SECRET}),
        _sink(),
        _policy(),
    )
    blob = repr(sp) + repr(sp.manifest) + "".join(repr(e) for e in sp.manifest.entries)
    assert SECRET not in blob
    assert SECRET[:4] not in blob


def test_preview_policy_controls_fingerprint_preview():
    # FR-N05-03 / Packet 8.1: preview only when enabled and length >= 8.
    sp_on = sanitize_for_sink(
        EvidencePayload(payload_kind="structured_json", value={"password": SECRET}),
        _sink(),
        _policy(preview_enabled=True, preview_max_chars=2),
    )
    rec = sp_on.manifest.entries[0]
    assert rec.preview is not None and rec.preview.endswith("\u2026")
    assert len(rec.preview) == 3  # 2 chars + ellipsis
    sp_off = sanitize_for_sink(
        EvidencePayload(payload_kind="structured_json", value={"password": SECRET}),
        _sink(),
        _policy(),
    )
    assert sp_off.manifest.entries[0].preview is None


def test_policy_error_surface():
    # FR-N05-07: policy resolution failure -> POLICY_ERROR, no partial output.
    class Exploding(TenantPolicy):
        def digest_source(self):
            raise RuntimeError("boom")

    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8),
            _sink(),
            Exploding(policy_version="v1"),
        )
    assert ei.value.code == PrivacyErrorCode.POLICY_ERROR


def test_internal_failure_wrapped(monkeypatch):
    # FR-N05-07 / AC/T-N05-04 / SEC-N05-02: unexpected internal exception is
    # wrapped as INTERNAL_REDACTION_FAILURE, no raw traceback value leak.
    import lima.evidence_privacy.port as port_mod

    def boom(*a, **k):
        raise ZeroDivisionError("unexpected " + SECRET)

    monkeypatch.setattr(port_mod, "classify_payload", boom)
    with pytest.raises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="x" * 8),
            _sink(),
            _policy(),
        )
    assert ei.value.code == PrivacyErrorCode.INTERNAL_REDACTION_FAILURE
    assert SECRET not in str(ei.value)


def test_failure_returns_no_value():
    # FR-N05-07: fail-closed means no fallback to raw value on any failure.
    with pytest.raises(PrivacyError):
        sanitize_for_sink(
            EvidencePayload(payload_kind="text", value=SECRET),
            SinkContext(sink_kind="vault", tenant_id="t", tenant_key=KEY),
            _policy(),
        )


def test_deterministic_output_same_inputs():
    # NFR: pure function; same inputs -> same fingerprints across calls.
    payload = EvidencePayload(payload_kind="structured_json", value={"api_key": SECRET})
    a = sanitize_for_sink(payload, _sink(), _policy())
    b = sanitize_for_sink(payload, _sink(), _policy())
    assert a.manifest.entries == b.manifest.entries
    assert a.redacted_value["api_key"].fingerprint == b.redacted_value["api_key"].fingerprint


def test_tenant_isolation_through_port():
    # SEC-N05-01 / AC/T-N05-02: same payload, different tenants -> different fp.
    p = EvidencePayload(payload_kind="structured_json", value={"api_key": SECRET})
    a = sanitize_for_sink(p, _sink(tenant_id="t1"), _policy())
    b = sanitize_for_sink(p, _sink(tenant_id="t2"), _policy())
    assert (
        a.redacted_value["api_key"].fingerprint
        != b.redacted_value["api_key"].fingerprint
    )


def test_tenant_key_never_in_output():
    # SEC-N05-01: tenant_key must not appear in output or errors.
    sp = sanitize_for_sink(
        EvidencePayload(payload_kind="structured_json", value={"api_key": SECRET}),
        _sink(),
        _policy(),
    )
    assert KEY not in repr(sp).encode("utf-8", "backslashreplace")
    assert KEY.hex() not in repr(sp)
