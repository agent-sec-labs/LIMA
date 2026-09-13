"""Value-free read-only audit models and pure scan entry points (Packet IP-0020 §8.2).

Every public callable here is a pure function: no IO, no network, no
environment reads, no process spawning. Findings carry only position, tenant-isolated
fingerprint, value kind, and length -- never a preview, never any audited
content, and never a writable or executable recommendation. Positions are
expressed by the single frozen :class:`AuditLocation` model (source artifact,
dotted structured field path, half-open NFC code-point span).

Consumed via the module path ``lima.evidence_privacy.audit``; the package
``__all__`` stays at its frozen 13 symbols (Packet §7.2, DR-IP-0020-1).
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from lima.evidence_privacy.content_scan import (
    find_base64_spans,
    is_bare_base64_secret,
)
from lima.evidence_privacy.fingerprint import compute_fingerprint
from lima.evidence_privacy.models import TenantPolicy
from lima.evidence_privacy.policy import policy_digest

__all__ = [
    "AuditFinding",
    "AuditLocation",
    "AuditReport",
    "audit_report_to_json",
    "audit_structured",
    "audit_text",
    "build_audit_report",
]

# Packet §8.2.6: the only sanctioned migration guidance is this constant text;
# reports never carry callbacks, commands, or paths that could execute.
_RECOMMENDED_ACTION: Final[str] = "manual-review-and-approved-migration-issue"
_VALUE_KIND_STRING: Final[str] = "string"


@dataclass(frozen=True, slots=True)
class AuditLocation:
    """Unified frozen position model (Packet §8.2.2); three fields, terminal."""

    source_path: str
    field_path: str | None = None
    span: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True)
class AuditFinding:
    """Value-free stand-in for one detected sensitive position (Packet §8.2.3)."""

    location: AuditLocation
    fingerprint: str
    value_kind: str
    length: int


@dataclass(frozen=True, slots=True)
class AuditReport:
    """Policy-evidenced aggregation of findings; no tenant fields (Packet §8.2.5)."""

    policy_version: str
    policy_digest: str
    findings: tuple[AuditFinding, ...]
    artifact_count: int
    recommended_action: str = _RECOMMENDED_ACTION


def _make_finding(
    source_path: str,
    field_path: str | None,
    segment: str,
    start: int,
    end: int,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> AuditFinding:
    """Build one finding for ``segment`` at ``(start, end)`` (fingerprint = HMAC)."""
    return AuditFinding(
        location=AuditLocation(
            source_path=source_path, field_path=field_path, span=(start, end)
        ),
        fingerprint=compute_fingerprint(segment, tenant_id=tenant_id, tenant_key=tenant_key),
        value_kind=_VALUE_KIND_STRING,
        length=end - start,
    )


def _scan_string_value(
    source_path: str,
    field_path: str | None,
    value: str,
    findings: list[AuditFinding],
    *,
    tenant_id: str,
    tenant_key: bytes,
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
                )
            )


def _walk_structured(
    source_path: str,
    node: object,
    field_path: str | None,
    findings: list[AuditFinding],
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> None:
    """Depth-first read-only traversal of dict/list containers (Packet §8.2.4)."""
    if isinstance(node, str):
        _scan_string_value(
            source_path,
            field_path,
            node,
            findings,
            tenant_id=tenant_id,
            tenant_key=tenant_key,
        )
        return
    if isinstance(node, dict):
        for key, item in node.items():
            child = f"{field_path}.{key}" if field_path else str(key)
            _walk_structured(
                source_path,
                item,
                child,
                findings,
                tenant_id=tenant_id,
                tenant_key=tenant_key,
            )
    elif isinstance(node, list):
        for index, item in enumerate(node):
            child = f"{field_path}[{index}]" if field_path else f"[{index}]"
            _walk_structured(
                source_path,
                item,
                child,
                findings,
                tenant_id=tenant_id,
                tenant_key=tenant_key,
            )


def audit_text(
    source_path: str,
    text: str,
    policy: TenantPolicy,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> tuple[AuditFinding, ...]:
    """Scan unstructured ``text`` and return one finding per predicate span.

    Detection consumes ``find_base64_spans`` filtered by
    ``is_bare_base64_secret`` (Packet §8.2.4); ``policy`` is part of the frozen
    signature and its evidence is embedded when the report is built. Pure:
    the input text is never modified.
    """
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
                    tenant_id=tenant_id,
                    tenant_key=tenant_key,
                )
            )
    return tuple(findings)


def audit_structured(
    source_path: str,
    value: object,
    policy: TenantPolicy,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> tuple[AuditFinding, ...]:
    """Deep-scan a structured ``value`` (dict/list) for sensitive strings.

    String positions report the dotted ``field_path``; whole-value candidates
    use span ``(0, len(value))`` and partial candidates the span inside the
    string (Packet §8.2.2/§8.2.4). Pure: the audited object is never mutated.
    """
    findings: list[AuditFinding] = []
    _walk_structured(
        source_path,
        value,
        None,
        findings,
        tenant_id=tenant_id,
        tenant_key=tenant_key,
    )
    return tuple(findings)


def build_audit_report(
    findings: Mapping[str, tuple[AuditFinding, ...]],
    policy: TenantPolicy,
) -> AuditReport:
    """Aggregate per-artifact findings into one policy-evidenced report.

    Keys are artifact source paths; the report embeds the policy's actual
    version and its frozen-order digest (Packet §8.2.5). Deterministic order:
    artifacts sorted by source path.
    """
    ordered: list[AuditFinding] = []
    for source_path in sorted(findings):
        ordered.extend(findings[source_path])
    return AuditReport(
        policy_version=policy.policy_version,
        policy_digest=policy_digest(policy),
        findings=tuple(ordered),
        artifact_count=len(findings),
    )


def _finding_payload(finding: AuditFinding) -> dict[str, object]:
    """Value-free JSON mapping of one finding (whitelisted fields only)."""
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
    kinds, and lengths only.
    """
    payload = {
        "artifact_count": report.artifact_count,
        "findings": [_finding_payload(finding) for finding in report.findings],
        "policy_digest": report.policy_digest,
        "policy_version": report.policy_version,
        "recommended_action": report.recommended_action,
    }
    return json.dumps(
        payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
