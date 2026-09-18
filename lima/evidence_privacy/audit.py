"""Value-free read-only audit models and pure scan entry points (IP-0020 §8.2).

Every public callable here is a pure function: no IO, no network, no
environment reads, no process spawning. Findings carry only position, tenant-isolated
fingerprint, value kind, and length -- never a preview, never any audited
content, and never a writable or executable recommendation.

Position model v2 (Packet §17.D1'.1, DR-IP-0020-4R): ``field_path`` is a
deterministic member-ordinal path -- ``m<n>`` for the n-th (0-based) JSON
object member in document order, ``[n]`` for the n-th array element, joined
with ``.`` between object segments and no separator before array segments
(``m0[2].m1``). Key names and values never appear in a path. Scalar roots
(str/int/bool/null/bytes) carry ``field_path=None`` and are located by span
alone, exactly like text mode. ``span`` is a half-open ``(start, end)``
code-point interval over the NFC-normalized string.

Manual reproduction semantics (Packet §17.D1'.1, canonical text): to locate a
finding, count members along the ordinal path from the root container --
``m<n>`` is the n-th (0-based) member of the current object in document order,
``[n]`` is the n-th (0-based) element of the current array; the span is the
half-open code-point interval inside that member's NFC-normalized string
value. ``source_path`` is the artifact index (``a<n>``) assigned by the
caller (Packet §17.D1'.2/D1'.3).

Tenant boundary v2 (Packet §17.D2'): :class:`TenantAuditContext` is the sole
tenant entry for all three scan/report callables (the legacy keyword-only
``tenant_id``/``tenant_key`` parameters are removed at signature level).
Each finding carries an internal ``_tenant_tag`` (64 hex, domain-separated
HMAC) used only to reject mixed-tenant aggregation; it is excluded from repr
and from every serialization surface.

Library budgets (Packet §17.F5'): traversal deeper than
``PrivacyLimits.max_depth`` raises a typed ``MAX_DEPTH_EXCEEDED`` (no bare
``RecursionError``); one scan producing more than ``PrivacyLimits.max_items``
findings raises ``RESOURCE_LIMIT_EXCEEDED``.

Consumed via the module path ``lima.evidence_privacy.audit``; the package
``__all__`` stays at its frozen 13 symbols (Packet §7.2, DR-IP-0020-1;
``TenantAuditContext`` is authorized for this module's ``__all__`` by
DR-IP-0020-4R §17.D2').
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final

from lima.evidence_privacy.content_scan import (
    find_base64_spans,
    is_bare_base64_secret,
)
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.fingerprint import _derive_tenant_key, compute_fingerprint
from lima.evidence_privacy.models import TenantPolicy
from lima.evidence_privacy.policy import policy_digest

__all__ = [
    "AuditFinding",
    "AuditLocation",
    "AuditReport",
    "TenantAuditContext",
    "audit_report_to_json",
    "audit_structured",
    "audit_text",
    "build_audit_report",
]

# Packet §8.2.6: the only sanctioned migration guidance is this constant text;
# reports never carry callbacks, commands, or paths that could execute.
_RECOMMENDED_ACTION: Final[str] = "manual-review-and-approved-migration-issue"
_VALUE_KIND_STRING: Final[str] = "string"

# R4/R6 §17.D1'.3 (frozen): the only legal artifact identifier is ``a`` + a
# 0..9999 decimal without leading zeros -- the same domain as the script's
# artifact indices, structurally incapable of carrying a secret, a file name,
# or any caller free text.
_SOURCE_PATH_PATTERN: Final[re.Pattern[str]] = re.compile(r"a(0|[1-9][0-9]{0,3})")

# R5 §17.D2'-R5 (frozen): the tenant tag is domain-separated from both the
# fingerprint domain and the tenant-key derivation domain, so tags cannot be
# correlated with either.
_TENANT_TAG_DOMAIN: Final[bytes] = b"audit.tenant-tag.v1"

_MAX_TENANT_ID_BYTES: Final[int] = 128


def _validate_source_path(source_path: object) -> None:
    """R4/R6 §17.D1'.3: entry validation of every artifact identifier.

    Rejects anything outside ``a0``-``a9999`` with a value-free
    ``INVALID_FIELD_VALUE`` whose context carries only length metadata.
    """
    valid = isinstance(source_path, str) and _SOURCE_PATH_PATTERN.fullmatch(
        source_path
    ) is not None
    if not valid:
        raise PrivacyError(
            PrivacyErrorCode.INVALID_FIELD_VALUE,
            field_path="source_path",
            context={
                "len": len(source_path) if isinstance(source_path, str) else None,
                "reason": "artifact-id",
            },
        )


def _tenant_tag(tenant_id: str, tenant_key: bytes) -> str:
    """R5 §17.D2'-R5: internal 64-hex tag, never part of any output surface.

    ``derived_key = HMAC-SHA256(tenant_key, tenant-key-domain + tenant_id)``
    reuses :func:`lima.evidence_privacy.fingerprint._derive_tenant_key`
    verbatim; the tag then HMACs a distinct domain under that derived key.
    """
    derived_key = _derive_tenant_key(tenant_key, tenant_id)
    return hmac.new(
        derived_key, _TENANT_TAG_DOMAIN + tenant_id.encode("utf-8"), hashlib.sha256
    ).hexdigest()


@dataclass(frozen=True, slots=True, repr=False)
class TenantAuditContext:
    """Sole tenant entry for audit calls (Packet §17.D2', DR-IP-0020-4R).

    Construction validates fail-closed (reusing existing error codes), and the
    repr carries length metadata only -- never the tenant id plaintext and
    never any key byte (R1 §17.D2'-R1). ``str()`` falls back to ``__repr__``.
    """

    tenant_id: str
    tenant_key: bytes

    def __repr__(self) -> str:
        return (
            f"TenantAuditContext(tenant_id_len={len(self.tenant_id)}, "
            f"tenant_key_len={len(self.tenant_key)})"
        )

    def __post_init__(self) -> None:
        key = self.tenant_key
        if not isinstance(key, bytes) or not key:
            raise PrivacyError(
                PrivacyErrorCode.MISSING_TENANT_KEY, field_path="tenant_key"
            )
        tenant_id = self.tenant_id
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


@dataclass(frozen=True, slots=True)
class AuditLocation:
    """Unified frozen position model (Packet §8.2.2 + §17.D1'.1); three fields."""

    source_path: str
    field_path: str | None = None
    span: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """Value-free stand-in for one detected sensitive position (Packet §8.2.3).

    ``_tenant_tag`` (R5 §17.D2') exists only for mixed-tenant detection in
    :func:`build_audit_report`; it is ``repr=False`` and excluded from every
    serialization whitelist, so it never reaches any output surface.
    """

    location: AuditLocation
    fingerprint: str
    value_kind: str
    length: int
    _tenant_tag: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Policy-evidenced aggregation of findings; no tenant fields (Packet §17.D2')."""

    policy_version: str
    policy_digest: str
    findings: tuple[AuditFinding, ...]
    artifact_count: int
    recommended_action: str = _RECOMMENDED_ACTION
    status: str = "complete"
    incomplete_reasons: tuple[str, ...] = ()


def _make_finding(
    source_path: str,
    field_path: str | None,
    segment: str,
    start: int,
    end: int,
    *,
    tenant_id: str,
    tenant_key: bytes,
    tag: str,
) -> AuditFinding:
    """Build one finding for ``segment`` at ``(start, end)`` (fingerprint = HMAC)."""
    return AuditFinding(
        location=AuditLocation(
            source_path=source_path, field_path=field_path, span=(start, end)
        ),
        fingerprint=compute_fingerprint(
            segment, tenant_id=tenant_id, tenant_key=tenant_key
        ),
        value_kind=_VALUE_KIND_STRING,
        length=end - start,
        _tenant_tag=tag,
    )


def _scan_string_value(
    source_path: str,
    field_path: str | None,
    value: str,
    findings: list[AuditFinding],
    *,
    tenant_id: str,
    tenant_key: bytes,
    tag: str,
) -> None:
    """Append findings for one string: whole-value predicate first, then spans."""
    normalized = unicodedata.normalize("NFC", value)
    if is_bare_base64_secret(normalized):
        # The entire value is one candidate; its inner sub-spans are contained
        # by this whole-value finding and are not reported separately.
        findings.append(
            _make_finding(
                source_path,
                field_path,
                normalized,
                0,
                len(normalized),
                tenant_id=tenant_id,
                tenant_key=tenant_key,
                tag=tag,
            )
        )
        return
    for start, end in find_base64_spans(normalized):
        segment = normalized[start:end]
        if is_bare_base64_secret(segment):
            findings.append(
                _make_finding(
                    source_path,
                    field_path,
                    segment,
                    start,
                    end,
                    tenant_id=tenant_id,
                    tenant_key=tenant_key,
                    tag=tag,
                )
            )


def _walk_structured(
    source_path: str,
    node: object,
    field_path: str | None,
    depth: int,
    max_depth: int,
    findings: list[AuditFinding],
    *,
    tenant_id: str,
    tenant_key: bytes,
    tag: str,
) -> None:
    """Depth-first read-only traversal with ordinal paths (§8.2.4 + §17.D1'.1).

    Container entry deeper than ``max_depth`` raises the typed
    ``MAX_DEPTH_EXCEEDED`` budget error before Python recursion could fail
    bare (§17.F5').
    """
    if isinstance(node, str):
        _scan_string_value(
            source_path,
            field_path,
            node,
            findings,
            tenant_id=tenant_id,
            tenant_key=tenant_key,
            tag=tag,
        )
        return
    if isinstance(node, dict):
        if depth > max_depth:
            raise PrivacyError(
                PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
                field_path=field_path,
                context={"depth": depth, "max_depth": max_depth},
            )
        for index, item in enumerate(node.values()):
            child = f"{field_path}.m{index}" if field_path else f"m{index}"
            _walk_structured(
                source_path,
                item,
                child,
                depth + 1,
                max_depth,
                findings,
                tenant_id=tenant_id,
                tenant_key=tenant_key,
                tag=tag,
            )
    elif isinstance(node, list):
        if depth > max_depth:
            raise PrivacyError(
                PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
                field_path=field_path,
                context={"depth": depth, "max_depth": max_depth},
            )
        for index, item in enumerate(node):
            child = f"{field_path}[{index}]" if field_path else f"[{index}]"
            _walk_structured(
                source_path,
                item,
                child,
                depth + 1,
                max_depth,
                findings,
                tenant_id=tenant_id,
                tenant_key=tenant_key,
                tag=tag,
            )


def _check_findings_budget(count: int, max_items: int) -> None:
    """F5' §17.F5': one scan may not produce more than ``max_items`` findings."""
    if count > max_items:
        raise PrivacyError(
            PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED,
            field_path="findings",
            context={"max_items": max_items},
        )


def audit_text(
    source_path: str,
    text: str,
    policy: TenantPolicy,
    *,
    context: TenantAuditContext,
) -> tuple[AuditFinding, ...]:
    """Scan unstructured ``text`` and return one finding per predicate span.

    Detection consumes ``find_base64_spans`` filtered by
    ``is_bare_base64_secret`` (Packet §8.2.4). ``source_path`` must be a legal
    artifact index (``a0``-``a9999``, §17.D1'.3); ``context`` is the sole
    tenant entry (§17.D2'); ``policy`` supplies the findings budget. Pure: the
    input text is never modified.
    """
    _validate_source_path(source_path)
    max_items = policy.limits.max_items
    tag = _tenant_tag(context.tenant_id, context.tenant_key)
    normalized = unicodedata.normalize("NFC", text)
    findings: list[AuditFinding] = []
    for start, end in find_base64_spans(normalized):
        segment = normalized[start:end]
        if is_bare_base64_secret(segment):
            findings.append(
                _make_finding(
                    source_path,
                    None,
                    segment,
                    start,
                    end,
                    tenant_id=context.tenant_id,
                    tenant_key=context.tenant_key,
                    tag=tag,
                )
            )
            _check_findings_budget(len(findings), max_items)
    return tuple(findings)


def audit_structured(
    source_path: str,
    value: object,
    policy: TenantPolicy,
    *,
    context: TenantAuditContext,
) -> tuple[AuditFinding, ...]:
    """Deep-scan a structured ``value`` (dict/list) for sensitive strings.

    Positions use member-ordinal paths (``m<n>``/``[n]``, document order; no
    key names, no values -- §17.D1'.1); whole-value candidates use span
    ``(0, len(value))`` and partial candidates the span inside the string.
    Scalar roots carry ``field_path=None``. Traversal deeper than
    ``max_depth`` and scans over ``max_items`` findings fail closed with typed
    budget errors (§17.F5'). Pure: the audited object is never mutated.
    """
    _validate_source_path(source_path)
    limits = policy.limits
    tag = _tenant_tag(context.tenant_id, context.tenant_key)
    findings: list[AuditFinding] = []
    _walk_structured(
        source_path,
        value,
        None,
        1,
        limits.max_depth,
        findings,
        tenant_id=context.tenant_id,
        tenant_key=context.tenant_key,
        tag=tag,
    )
    _check_findings_budget(len(findings), limits.max_items)
    return tuple(findings)


def build_audit_report(
    context: TenantAuditContext,
    findings: Mapping[str, tuple[AuditFinding, ...]],
    policy: TenantPolicy,
) -> AuditReport:
    """Aggregate per-artifact findings into one policy-evidenced report.

    Keys are artifact indices (validated ``a0``-``a9999``, §17.D1'.3) and must
    all originate from ``context``: every finding's internal tenant tag must
    match the context-derived tag, otherwise the batch is mixed-tenant and
    fails closed with ``POLICY_ERROR`` at ``report.tenant_mixing``
    (§17.D2'). An empty mapping still binds (and thereby validates) the
    context. Deterministic order: artifacts sorted by source path.
    """
    if not isinstance(context, TenantAuditContext):
        raise TypeError(
            "build_audit_report requires a TenantAuditContext as its first "
            "argument (Packet §17.D2' signature revision)"
        )
    expected_tag = _tenant_tag(context.tenant_id, context.tenant_key)
    distinct_tags = {expected_tag}
    for batch in findings.values():
        for finding in batch:
            distinct_tags.add(finding._tenant_tag)
    if len(distinct_tags) > 1:
        raise PrivacyError(
            PrivacyErrorCode.POLICY_ERROR,
            field_path="report.tenant_mixing",
            context={"distinct_tenant_tags": len(distinct_tags)},
        )
    ordered: list[AuditFinding] = []
    for source_path in sorted(findings):
        _validate_source_path(source_path)
        ordered.extend(findings[source_path])
    return AuditReport(
        policy_version=policy.policy_version,
        policy_digest=policy_digest(policy),
        findings=tuple(ordered),
        artifact_count=len(findings),
    )


def _finding_payload(finding: AuditFinding) -> dict[str, object]:
    """Value-free JSON mapping of one finding (whitelisted fields only).

    The whitelist deliberately excludes the internal tenant tag (§17.D2').
    """
    location = finding.location
    return {
        "fingerprint": finding.fingerprint,
        "length": finding.length,
        "location": {
            "field_path": location.field_path,
            "source_path": location.source_path,
            "span": (
                [location.span[0], location.span[1]]
                if location.span is not None
                else None
            ),
        },
        "value_kind": finding.value_kind,
    }


def audit_report_to_json(report: AuditReport) -> str:
    """Serialize ``report`` to canonical value-free JSON (Packet §8.2.3).

    Canonical form mirrors the repo codec: sorted keys, compact separators,
    UTF-8 text without ASCII escaping. Output contains positions, digests,
    kinds, lengths, completion status, and skip reasons only -- never tenant
    material and never audited content.
    """
    payload = {
        "artifact_count": report.artifact_count,
        "findings": [_finding_payload(finding) for finding in report.findings],
        "incomplete_reasons": list(report.incomplete_reasons),
        "policy_digest": report.policy_digest,
        "policy_version": report.policy_version,
        "recommended_action": report.recommended_action,
        "status": report.status,
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
