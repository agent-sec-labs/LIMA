"""Classification core (Packet IP-0015 §8.7; FR-N05-01, AC/T-N05-03 core subset).

Frozen minimal-credible defaults:
- structured_json: top-level key names matching the sensitive pattern
  (``secret/token/key/password/credential/private_key``, case-insensitive) are
  SENSITIVE; string values carrying a PEM private-key header or a URL
  credential form are RESTRICTED (value shape wins over key pattern, matching
  the max-merge rule); everything else defaults to INTERNAL (DR-IP-0015-02:
  no promise is made for bare Base64 without sensitive-key context).
- text: unstructured text cannot be located structurally, so per Appendix A the
  conservative whole-value rule applies -- RESTRICTED when a PEM header or URL
  credential form is present, SENSITIVE when a sensitive keyword occurs, else
  INTERNAL with the NFC-normalized text preserved.
- bytes: conservative whole-value SENSITIVE (Appendix A "binary secret").

The overall classification is the maximum of entry severities in the #58 enum
definition order (public < internal < sensitive < restricted); no parallel
enum is defined in this package.

Interpretive note: ``classify_payload`` keeps its frozen two-positional public
signature, but accepts keyword-only ``tenant_id``/``tenant_key`` so the port
can request tenant-isolated fingerprints; standalone calls default to the
empty tenant context (deterministic classification-only mode).
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime
from typing import Final

from lima.contracts.codec import JSONValue, canonical_encode
from lima.contracts.common import ArtifactClassification, RetentionClass
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.fingerprint import compute_fingerprint
from lima.evidence_privacy.models import (
    ClassificationManifest,
    EvidencePayload,
    FingerprintRecord,
    TenantPolicy,
)
from lima.evidence_privacy.policy import policy_digest

__all__ = ["classify_payload"]

SENSITIVE_KEY_TOKENS: Final[tuple[str, ...]] = (
    "secret",
    "token",
    "key",
    "password",
    "credential",
    "private_key",
)

_PEM_PRIVATE_KEY_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----"
)
_URL_CREDENTIAL_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z][A-Za-z0-9+.\-]*://[^\s/:@]+:[^\s/@]+@"
)

_MIN_PREVIEW_LENGTH = 8
_PREVIEW_SUFFIX: Final[str] = "\u2026"

_SEVERITY_ORDER: Final[tuple[ArtifactClassification, ...]] = tuple(
    ArtifactClassification
)


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower()
    return any(token in lowered for token in SENSITIVE_KEY_TOKENS)


def _has_sensitive_token(text: str) -> bool:
    return _is_sensitive_key(text)


def _is_restricted_text(text: str) -> bool:
    return bool(
        _PEM_PRIVATE_KEY_PATTERN.search(text) or _URL_CREDENTIAL_PATTERN.search(text)
    )


def _value_kind(value: object) -> str:
    if isinstance(value, str):
        return "string"
    if isinstance(value, bytes):
        return "bytes"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if value is None:
        return "null"
    return "structured"


def _value_length(value: object) -> int:
    if isinstance(value, str):
        return len(unicodedata.normalize("NFC", value))
    if isinstance(value, bytes):
        return len(value)
    # int/bool/null -> canonical JSON text length; containers -> canonical bytes.
    return len(canonical_encode(value))  # type: ignore[arg-type]


def _make_record(
    value: object,
    policy: TenantPolicy,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> FingerprintRecord:
    kind = _value_kind(value)
    preview: str | None = None
    if (
        policy.preview_enabled
        and isinstance(value, str)
        and _value_length(value) >= _MIN_PREVIEW_LENGTH
    ):
        normalized = unicodedata.normalize("NFC", value)
        preview = normalized[: policy.preview_max_chars] + _PREVIEW_SUFFIX
    return FingerprintRecord(
        fingerprint=compute_fingerprint(
            value, tenant_id=tenant_id, tenant_key=tenant_key  # type: ignore[arg-type]
        ),
        value_kind=kind,
        length=_value_length(value),
        preview=preview,
    )


def _entry_severity(value: object) -> ArtifactClassification:
    """Value shape wins over key pattern; restricted shape is the max severity."""
    if isinstance(value, str) and _is_restricted_text(value):
        return ArtifactClassification.RESTRICTED
    return ArtifactClassification.SENSITIVE


def _merge_severity(
    current: ArtifactClassification, candidate: ArtifactClassification
) -> ArtifactClassification:
    if _SEVERITY_ORDER.index(candidate) > _SEVERITY_ORDER.index(current):
        return candidate
    return current


def _collect_entries(
    value: JSONValue | str | bytes,
    policy: TenantPolicy,
    entries: list[FingerprintRecord],
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> ArtifactClassification:
    """Walk structured values and append one record per flagged position."""
    severity = ArtifactClassification.INTERNAL
    if isinstance(value, dict):
        for key, item in value.items():
            key_sensitive = _is_sensitive_key(key)
            if key_sensitive or (isinstance(item, str) and _is_restricted_text(item)):
                entries.append(
                    _make_record(item, policy, tenant_id=tenant_id, tenant_key=tenant_key)
                )
                severity = _merge_severity(
                    severity, _entry_severity(item)
                )
            elif isinstance(item, (dict, list)):
                severity = _merge_severity(
                    severity,
                    _collect_entries(
                        item, policy, entries, tenant_id=tenant_id, tenant_key=tenant_key
                    ),
                )
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, str) and _is_restricted_text(item):
                entries.append(
                    _make_record(item, policy, tenant_id=tenant_id, tenant_key=tenant_key)
                )
                severity = _merge_severity(severity, ArtifactClassification.RESTRICTED)
            elif isinstance(item, (dict, list)):
                severity = _merge_severity(
                    severity,
                    _collect_entries(
                        item, policy, entries, tenant_id=tenant_id, tenant_key=tenant_key
                    ),
                )
    elif isinstance(value, str) and _is_restricted_text(value):
        entries.append(
            _make_record(value, policy, tenant_id=tenant_id, tenant_key=tenant_key)
        )
        severity = _merge_severity(severity, ArtifactClassification.RESTRICTED)
    return severity


def classify_payload(
    payload: EvidencePayload,
    policy: TenantPolicy,
    *,
    tenant_id: str = "",
    tenant_key: bytes = b"",
) -> ClassificationManifest:
    """Classify ``payload`` and return its manifest (Packet §8.7)."""
    entries: list[FingerprintRecord] = []
    if payload.payload_kind == "structured_json":
        severity = _collect_entries(
            payload.value, policy, entries, tenant_id=tenant_id, tenant_key=tenant_key
        )
    elif payload.payload_kind == "text":
        text = payload.value if isinstance(payload.value, str) else ""
        if _is_restricted_text(text):
            severity = ArtifactClassification.RESTRICTED
            entries.append(
                _make_record(text, policy, tenant_id=tenant_id, tenant_key=tenant_key)
            )
        elif _has_sensitive_token(text):
            severity = ArtifactClassification.SENSITIVE
            entries.append(
                _make_record(text, policy, tenant_id=tenant_id, tenant_key=tenant_key)
            )
        else:
            severity = ArtifactClassification.INTERNAL
    elif payload.payload_kind == "bytes":
        severity = ArtifactClassification.SENSITIVE
        entries.append(
            _make_record(payload.value, policy, tenant_id=tenant_id, tenant_key=tenant_key)
        )
    else:  # pragma: no cover - models validation makes this unreachable
        raise PrivacyError(
            PrivacyErrorCode.UNSUPPORTED_PAYLOAD_KIND, field_path="payload_kind"
        )
    return ClassificationManifest(
        classification=severity,
        retention_class=RetentionClass.STANDARD,
        policy_version=policy.policy_version,
        policy_digest=policy_digest(policy),
        entries=tuple(entries),
        created_at=datetime.now(UTC).isoformat(),
    )


def _redact_node(
    value: JSONValue | str | bytes,
    policy: TenantPolicy,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> JSONValue | str | bytes | FingerprintRecord:
    """Return the value-free output form of one structured node (Packet §8.2 step 7)."""
    if isinstance(value, dict):
        redacted: dict[str, JSONValue | FingerprintRecord] = {}
        for key, item in value.items():
            normalized_key = unicodedata.normalize("NFC", key)
            if _is_sensitive_key(key) or (
                isinstance(item, str) and _is_restricted_text(item)
            ):
                redacted[normalized_key] = _make_record(
                    item, policy, tenant_id=tenant_id, tenant_key=tenant_key
                )
            else:
                redacted[normalized_key] = _redact_node(
                    item, policy, tenant_id=tenant_id, tenant_key=tenant_key
                )
        return redacted
    if isinstance(value, list):
        redacted_list: list[JSONValue | FingerprintRecord] = []
        for item in value:
            if isinstance(item, str) and _is_restricted_text(item):
                redacted_list.append(
                    _make_record(item, policy, tenant_id=tenant_id, tenant_key=tenant_key)
                )
            else:
                redacted_list.append(
                    _redact_node(
                        item, policy, tenant_id=tenant_id, tenant_key=tenant_key
                    )
                )
        return redacted_list
    if isinstance(value, str):
        if _is_restricted_text(value):
            return _make_record(value, policy, tenant_id=tenant_id, tenant_key=tenant_key)
        return unicodedata.normalize("NFC", value)
    return value


def build_redacted_value(
    payload: EvidencePayload,
    policy: TenantPolicy,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> JSONValue | str | bytes | FingerprintRecord:
    """Build ``SanitizedPayload.redacted_value`` with the same predicates as classify.

    Records produced here are byte-identical (deterministic HMAC) to the ones in
    ``ClassificationManifest.entries``; recomputation keeps the public
    ``classify_payload`` signature untouched while giving the port its output.
    """
    if payload.payload_kind == "structured_json":
        return _redact_node(
            payload.value, policy, tenant_id=tenant_id, tenant_key=tenant_key
        )
    if payload.payload_kind == "bytes":
        return _make_record(
            payload.value, policy, tenant_id=tenant_id, tenant_key=tenant_key
        )
    text = payload.value if isinstance(payload.value, str) else ""
    if _is_restricted_text(text) or _has_sensitive_token(text):
        return _make_record(text, policy, tenant_id=tenant_id, tenant_key=tenant_key)
    return unicodedata.normalize("NFC", text)
