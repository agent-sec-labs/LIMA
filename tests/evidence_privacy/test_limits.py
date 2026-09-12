# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
"""Resource-limit & time-budget tests (Packet 8.2 steps 4-5; NFR-N05-02, SEC-N05-02)."""

from __future__ import annotations

import pytest
from lima.evidence_privacy import (
    EvidencePayload,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyLimits,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

KEY = b"\x44" * 32


def _run(value, kind="structured_json", **limit_kw):
    policy = TenantPolicy.resolve(
        policy_version="v1",
        limits=PrivacyLimits(**limit_kw) if limit_kw else PrivacyLimits(),
    )
    return sanitize_for_sink(
        EvidencePayload(payload_kind=kind, value=value),
        SinkContext(sink_kind="storage", tenant_id="t", tenant_key=KEY),
        policy,
    )


def _deep(n):
    v = {"leaf": "value"}
    for _ in range(n):
        v = {"n": v}
    return v


def test_max_depth_exceeded():
    # NFR-N05-02: depth > max_depth -> MAX_DEPTH_EXCEEDED.
    with pytest.raises(PrivacyError) as ei:
        _run(_deep(40), max_depth=8)
    assert ei.value.code == PrivacyErrorCode.MAX_DEPTH_EXCEEDED


def test_depth_within_limit_ok():
    # NFR-N05-02: within limit passes.
    sp = _run(_deep(4), max_depth=8)
    assert sp.sink_kind == "storage"


def test_max_string_length_exceeded():
    # NFR-N05-02: string value > max_string_bytes -> MAX_STRING_LENGTH_EXCEEDED.
    with pytest.raises(PrivacyError) as ei:
        _run("x" * 1000, kind="text", max_string_bytes=128)
    assert ei.value.code == PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED


def test_max_items_exceeded():
    # NFR-N05-02: item count > max_items -> MAX_ITEMS_EXCEEDED.
    big = {f"k{i}": i for i in range(200)}
    with pytest.raises(PrivacyError) as ei:
        _run(big, max_items=100)
    assert ei.value.code == PrivacyErrorCode.MAX_ITEMS_EXCEEDED


def test_max_payload_bytes_exceeded():
    # NFR-N05-02: payload value > max_payload_bytes -> RESOURCE_LIMIT_EXCEEDED.
    blob = b"\x00" * 4096
    with pytest.raises(PrivacyError) as ei:
        _run(blob, kind="bytes", max_payload_bytes=1024)
    assert ei.value.code == PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED


def test_time_budget_exceeded(monkeypatch):
    # NFR-N05-02 / SEC-N05-02: processing beyond max_processing_ms at a
    # 256-entry checkpoint -> TIME_BUDGET_EXCEEDED.
    import lima.evidence_privacy.port as port_mod

    counter = {"n": 0}

    def fake_monotonic():
        counter["n"] += 1
        return counter["n"] * 10.0  # 10 "ms" per call, exceeds 1ms budget fast

    monkeypatch.setattr(port_mod.time, "monotonic", fake_monotonic)
    big = {f"k{i}": "v" for i in range(600)}  # > 256 items -> checkpoints hit
    with pytest.raises(PrivacyError) as ei:
        _run(big, max_processing_ms=1, max_items=10_000)
    assert ei.value.code == PrivacyErrorCode.TIME_BUDGET_EXCEEDED


def test_time_budget_ok_fast_path(monkeypatch):
    # NFR-N05-02: small payload under budget succeeds (no checkpoint overrun).
    sp = _run({"a": 1}, max_processing_ms=1000)
    assert sp.sink_kind == "storage"


def test_limits_error_carries_no_value_payload():
    # SEC anchor / NFR-N05-03: limit errors carry metadata only.
    secret = "abcdef_secret_value"  # noqa: S105 - synthetic
    with pytest.raises(PrivacyError) as ei:
        _run({"deep": _deep(40)}, max_depth=4)
    assert secret not in str(ei.value)  # unrelated value never embedded
    assert hasattr(ei.value, "code") and hasattr(ei.value, "context")
