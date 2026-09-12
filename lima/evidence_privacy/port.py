"""Unified fail-closed entry point ``sanitize_for_sink`` (Packet IP-0015 §8.2).

Pure, thread-safe, IO-free orchestration: type checks, sink allowlist, tenant
credential checks, resource pre-scan, time budget, policy digest, then
classification + fingerprinting and output assembly. Any failure raises a
stable :class:`PrivacyError`; there is no partial output and no fallback to the
raw value.
"""

from __future__ import annotations

import time
from typing import Final

from lima.evidence_privacy.classifier import build_redacted_value, classify_payload
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.models import (
    EvidencePayload,
    PrivacyLimits,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
)
from lima.evidence_privacy.policy import policy_digest

__all__ = ["sanitize_for_sink"]

_TIME_CHECKPOINT_ITEMS: Final[int] = 256
_MS_PER_SECOND: Final[float] = 1000.0
_MAX_TENANT_ID_BYTES: Final[int] = 128


def _require_type(obj: object, expected: type, field_path: str) -> None:
    if not isinstance(obj, expected):
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_TYPE,
            field_path=field_path,
            context={"value_kind": type(obj).__name__},
        )


def _validate_sink(sink: SinkContext, policy: TenantPolicy) -> None:
    if sink.sink_kind not in policy.sink_allowlist:
        raise PrivacyError(
            PrivacyErrorCode.UNKNOWN_SINK,
            field_path="sink_kind",
            context={"sink_kind_length": len(sink.sink_kind)},
        )


def _validate_tenant(sink: SinkContext) -> tuple[str, bytes]:
    tenant_key = sink.tenant_key
    if not isinstance(tenant_key, bytes) or not tenant_key:
        raise PrivacyError(PrivacyErrorCode.MISSING_TENANT_KEY, field_path="tenant_key")
    tenant_id = sink.tenant_id
    if (
        not isinstance(tenant_id, str)
        or not tenant_id
        or len(tenant_id.encode("utf-8")) > _MAX_TENANT_ID_BYTES
    ):
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_VALUE,
            field_path="tenant_id",
            context={"value_kind": type(tenant_id).__name__},
        )
    return tenant_id, tenant_key


def _prescan(
    value: object, limits: PrivacyLimits, started_monotonic: float
) -> None:
    """Enforce size/depth/item budgets with 256-entry time checkpoints (§8.2 steps 4-5)."""
    state = {"items": 0}

    def _check_budget() -> None:
        if state["items"] > limits.max_items:
            raise PrivacyError(
                PrivacyErrorCode.MAX_ITEMS_EXCEEDED,
                field_path="value",
                context={"limit": limits.max_items, "actual": state["items"]},
            )
        if state["items"] % _TIME_CHECKPOINT_ITEMS == 0:
            elapsed_ms = (time.monotonic() - started_monotonic) * _MS_PER_SECOND
            if elapsed_ms > limits.max_processing_ms:
                raise PrivacyError(
                    PrivacyErrorCode.TIME_BUDGET_EXCEEDED,
                    field_path="value",
                    context={"limit_ms": limits.max_processing_ms},
                )

    def _walk(node: object, depth: int) -> None:
        if node is None or type(node) is bool or type(node) is int:
            state["items"] += 1
            _check_budget()
            return
        if isinstance(node, str):
            size = len(node.encode("utf-8"))
            if size > limits.max_string_bytes:
                raise PrivacyError(
                    PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED,
                    field_path="value",
                    context={"limit": limits.max_string_bytes, "actual": size},
                )
            if size > limits.max_payload_bytes:
                raise PrivacyError(
                    PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    field_path="value",
                    context={"limit": limits.max_payload_bytes, "actual": size},
                )
            state["items"] += 1
            _check_budget()
            return
        if isinstance(node, bytes):
            if len(node) > limits.max_payload_bytes:
                raise PrivacyError(
                    PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED,
                    field_path="value",
                    context={"limit": limits.max_payload_bytes, "actual": len(node)},
                )
            state["items"] += 1
            _check_budget()
            return
        if isinstance(node, (dict, list)):
            if depth > limits.max_depth:
                raise PrivacyError(
                    PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
                    field_path="value",
                    context={"limit": limits.max_depth, "actual": depth},
                )
            children = node.values() if isinstance(node, dict) else node
            for child in children:
                state["items"] += 1
                _check_budget()
                _walk(child, depth + 1)
            return
        raise PrivacyError(
            PrivacyErrorCode.UNSUPPORTED_PAYLOAD_KIND,
            field_path="value",
            context={"value_kind": type(node).__name__},
        )

    _walk(value, 1)


def sanitize_for_sink(
    payload: EvidencePayload, sink: SinkContext, policy: TenantPolicy
) -> SanitizedPayload:
    """Sanitize ``payload`` for ``sink`` under ``policy``; fail closed on any error."""
    started_monotonic = time.monotonic()
    _require_type(payload, EvidencePayload, "payload")
    _require_type(sink, SinkContext, "sink")
    _require_type(policy, TenantPolicy, "policy")
    _validate_sink(sink, policy)
    tenant_id, tenant_key = _validate_tenant(sink)
    _prescan(payload.value, policy.limits, started_monotonic)
    # Policy digest is validated eagerly so policy failures surface as
    # POLICY_ERROR before any classification work (FR-N05-07).
    try:
        policy_digest(policy)
    except PrivacyError:
        raise
    except Exception as exc:  # noqa: BLE001 -- policy resolution failure
        raise PrivacyError(
            PrivacyErrorCode.POLICY_ERROR,
            field_path="policy",
            context={"exception_type": type(exc).__name__},
        ) from exc
    try:
        manifest = classify_payload(
            payload, policy, tenant_id=tenant_id, tenant_key=tenant_key
        )
        redacted_value = build_redacted_value(
            payload, policy, tenant_id=tenant_id, tenant_key=tenant_key
        )
    except PrivacyError:
        raise
    except Exception as exc:  # noqa: BLE001 -- fail-closed wrapping (AC/T-N05-04)
        raise PrivacyError(
            PrivacyErrorCode.INTERNAL_REDACTION_FAILURE,
            field_path="value",
            context={"exception_type": type(exc).__name__},
        ) from exc
    return SanitizedPayload(
        sink_kind=sink.sink_kind,
        tenant_id=tenant_id,
        manifest=manifest,
        redacted_value=redacted_value,
    )
