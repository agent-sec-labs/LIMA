# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
"""Error hygiene & static resource-contract tests (Packet 8.5/8.6; NFR-N05-03, SEC-N05-01/03)."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import pytest
from lima.evidence_privacy import (
    EvidencePayload,
    PrivacyError,
    PrivacyErrorCode,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

SECRET = "ghp_abcdefghijklmnop"  # noqa: S105 - synthetic test token
KEY = b"\x55" * 32

EXPECTED_CODES = {
    "INVALID_FIELD_TYPE",
    "INVALID_FIELD_VALUE",
    "UNKNOWN_SINK",
    "MISSING_TENANT_KEY",
    "POLICY_ERROR",
    "RESOURCE_LIMIT_EXCEEDED",
    "MAX_DEPTH_EXCEEDED",
    "MAX_ITEMS_EXCEEDED",
    "MAX_STRING_LENGTH_EXCEEDED",
    "TIME_BUDGET_EXCEEDED",
    "UNSUPPORTED_PAYLOAD_KIND",
    "INTERNAL_REDACTION_FAILURE",
}


def test_error_code_enum_frozen():
    # Packet 8.6: PrivacyErrorCode values are the frozen uppercase set.
    values = {c.value for c in PrivacyErrorCode}
    assert values == EXPECTED_CODES


def test_error_str_has_code_field_path_only():
    # Packet 8.6 / NFR-N05-03: __str__ carries code/field_path, no raw values.
    err = PrivacyError(
        PrivacyErrorCode.INVALID_FIELD_VALUE,
        field_path="value",
        context={"value_length": 18, "value_kind": "string"},
    )
    s = str(err)
    assert "INVALID_FIELD_VALUE" in s
    assert SECRET not in s
    assert hasattr(err, "code") and hasattr(err, "field_path") and hasattr(err, "context")


def test_error_context_metadata_only():
    # Packet 8.6: context may carry only non-value metadata (length/kind).
    err = PrivacyError(
        PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        context={"value_length": 9, "value_kind": "string"},
    )
    assert all(k in ("value_length", "value_kind") for k in err.context)


def test_real_errors_do_not_leak_secret():
    # NFR-N05-03 / SEC-N05-03: all rejection paths keep the raw value out of
    # str(exc) and repr(exc).
    cases = [
        # (payload, bad sink kwargs)
        (EvidencePayload(payload_kind="structured_json", value={"password": SECRET}),
         {"sink_kind": "vault", "tenant_id": "t", "tenant_key": KEY}),
        (EvidencePayload(payload_kind="text", value=SECRET),
         {"sink_kind": "log", "tenant_id": "t", "tenant_key": b""}),
    ]
    for payload, sink_kwargs in cases:
        with pytest.raises(PrivacyError) as ei:
            sanitize_for_sink(
                payload,
                SinkContext(**sink_kwargs),
                TenantPolicy.resolve(policy_version="v1"),
            )
        assert SECRET not in str(ei.value)
        assert SECRET[:4] not in repr(ei.value)


def test_error_is_exception_and_typed():
    # Packet 8.6: PrivacyError is Exception subclass with typed code.
    assert issubclass(PrivacyError, Exception)
    err = PrivacyError(PrivacyErrorCode.UNKNOWN_SINK)
    assert isinstance(err.code, PrivacyErrorCode)


def test_static_no_logging_or_env_or_fs_write():
    # SEC-N05-01 / Packet 8.5: package source contains no logging, no
    # os.environ, no file-open, no subprocess, no socket.
    import lima.evidence_privacy as pkg

    banned = ("import logging", "getLogger", "os.environ", "open(", "subprocess", "socket")
    for mod_info in pkgutil.iter_modules(pkg.__path__):
        mod = importlib.import_module(f"lima.evidence_privacy.{mod_info.name}")
        src = inspect.getsource(mod)
        for token in banned:
            assert token not in src, (mod_info.name, token)


def test_no_module_level_mutating_globals():
    # Packet 8.2: no global mutable state; reimport keeps behaviour (spot).
    import lima.evidence_privacy as pkg

    src = inspect.getsource(pkg)
    assert "tenant_key" not in src.split("\n")[0]  # no key at module header
    import importlib as il

    il.reload(pkg)
    assert callable(pkg.sanitize_for_sink)


def test_wrapped_internal_error_stable_no_traceback_values():
    # AC/T-N05-04 / SEC-N05-02: wrapped error message is stable & value-free.
    import lima.evidence_privacy.port as port_mod

    original = port_mod.classify_payload

    def boom(*a, **k):
        raise ValueError("ctx contains " + SECRET)

    port_mod.classify_payload = boom
    try:
        with pytest.raises(PrivacyError) as ei:
            sanitize_for_sink(
                EvidencePayload(payload_kind="text", value="x" * 8),
                SinkContext(sink_kind="log", tenant_id="t", tenant_key=KEY),
                TenantPolicy.resolve(policy_version="v1"),
            )
        assert ei.value.code == PrivacyErrorCode.INTERNAL_REDACTION_FAILURE
        assert SECRET not in str(ei.value)
    finally:
        port_mod.classify_payload = original
