"""Frozen data models for the evidence privacy core (Packet IP-0015 §8.1).

Interpretive note (recorded per DR-IP-0015-01): with the frozen three-argument
``sanitize_for_sink(payload, sink, policy)`` signature, the only self-consistent
mount point for tenant credentials is :class:`SinkContext`, which therefore
carries ``tenant_id: str = ""`` and ``tenant_key: bytes = b""``. Tenant
credentials are validated by the port (Packet §8.2 step 3), not here, so that
constructing a context for validation purposes stays side-effect free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Final

from lima.contracts.codec import JSONValue
from lima.contracts.common import ArtifactClassification, RetentionClass
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode

__all__ = [
    "ClassificationManifest",
    "EvidencePayload",
    "FingerprintRecord",
    "PrivacyLimits",
    "SanitizedPayload",
    "SinkContext",
    "TenantPolicy",
]

PAYLOAD_KINDS: Final[tuple[str, ...]] = ("structured_json", "text", "bytes")

_MAX_TENANT_ID_BYTES = 128
_PREVIEW_MAX_CHARS_MIN = 0
_PREVIEW_MAX_CHARS_MAX = 4


def _sink_kinds() -> frozenset[str]:
    """Return the frozen sink-kind set (lazy import keeps models import-cycle free)."""
    from lima.evidence_privacy.policy import SINK_KINDS  # noqa: PLC0415 (cycle break)

    return SINK_KINDS


@dataclass(frozen=True, slots=True)
class EvidencePayload:
    """Immutable evidence input to be sanitized before reaching a sink."""

    payload_kind: str
    value: JSONValue | str | bytes
    media_type: str = ""

    def __post_init__(self) -> None:
        if self.payload_kind not in PAYLOAD_KINDS:
            raise PrivacyError(
                PrivacyErrorCode.UNSUPPORTED_PAYLOAD_KIND,
                field_path="payload_kind",
                context={"supported_kinds": len(PAYLOAD_KINDS)},
            )


@dataclass(frozen=True, slots=True)
class SinkContext:
    """Target sink description; sole carrier of tenant credentials (DR-IP-0015-01)."""

    sink_kind: str
    purpose: str = ""
    tenant_id: str = ""
    tenant_key: bytes = b""

    def __post_init__(self) -> None:
        if self.sink_kind not in _sink_kinds():
            raise PrivacyError(
                PrivacyErrorCode.UNKNOWN_SINK,
                field_path="sink_kind",
                context={"sink_kind_length": len(self.sink_kind)},
            )


@dataclass(frozen=True, slots=True)
class PrivacyLimits:
    """Resource ceilings enforced by the port; all values must be positive ints."""

    max_depth: int = 32
    max_payload_bytes: int = 1_048_576
    max_string_bytes: int = 262_144
    max_items: int = 10_000
    max_processing_ms: int = 1_000

    def __post_init__(self) -> None:
        for name in (
            "max_depth",
            "max_payload_bytes",
            "max_string_bytes",
            "max_items",
            "max_processing_ms",
        ):
            value = getattr(self, name)
            # Exact type check: bool is an int subclass and must still be rejected.
            if type(value) is not int or value <= 0:
                raise PrivacyError(
                    PrivacyErrorCode.INVALID_FIELD_VALUE,
                    field_path=name,
                    context={"value_kind": type(value).__name__},
                )


@dataclass(frozen=True, slots=True)
class TenantPolicy:
    """Tenant-scoped sanitization policy; digest source has a frozen field order."""

    policy_version: str
    limits: PrivacyLimits = field(default_factory=PrivacyLimits)
    preview_enabled: bool = False
    preview_max_chars: int = 2
    sink_allowlist: frozenset[str] = field(default_factory=_sink_kinds)

    def __post_init__(self) -> None:
        version = self.policy_version
        if type(version) is not str or not version or not version.isascii():
            raise PrivacyError(
                PrivacyErrorCode.INVALID_FIELD_VALUE,
                field_path="policy_version",
                context={"value_kind": type(version).__name__},
            )
        if not version.isprintable():
            raise PrivacyError(
                PrivacyErrorCode.INVALID_FIELD_VALUE, field_path="policy_version"
            )
        if not isinstance(self.limits, PrivacyLimits):
            raise PrivacyError(
                PrivacyErrorCode.INVALID_FIELD_TYPE,
                field_path="limits",
                context={"value_kind": type(self.limits).__name__},
            )
        if type(self.preview_enabled) is not bool:
            raise PrivacyError(
                PrivacyErrorCode.INVALID_FIELD_TYPE, field_path="preview_enabled"
            )
        chars = self.preview_max_chars
        if type(chars) is not int or not (
            _PREVIEW_MAX_CHARS_MIN <= chars <= _PREVIEW_MAX_CHARS_MAX
        ):
            raise PrivacyError(
                PrivacyErrorCode.INVALID_FIELD_VALUE, field_path="preview_max_chars"
            )
        allowlist = self.sink_allowlist
        if not isinstance(allowlist, frozenset) or not all(
            type(item) is str for item in allowlist
        ):
            raise PrivacyError(
                PrivacyErrorCode.INVALID_FIELD_TYPE, field_path="sink_allowlist"
            )

    @classmethod
    def resolve(
        cls,
        *,
        policy_version: str,
        limits: PrivacyLimits | None = None,
        preview_enabled: bool = False,
        preview_max_chars: int = 2,
        sink_allowlist: frozenset[str] | None = None,
    ) -> TenantPolicy:
        """Validated factory: construction fails closed on any invalid field."""
        return cls(
            policy_version=policy_version,
            limits=limits if limits is not None else PrivacyLimits(),
            preview_enabled=preview_enabled,
            preview_max_chars=preview_max_chars,
            sink_allowlist=(
                sink_allowlist if sink_allowlist is not None else _sink_kinds()
            ),
        )

    def digest_source(self) -> dict[str, JSONValue]:
        """Return the frozen-order field dict consumed by ``policy_digest``."""
        return {
            "policy_version": self.policy_version,
            "limits": {
                "max_depth": self.limits.max_depth,
                "max_payload_bytes": self.limits.max_payload_bytes,
                "max_string_bytes": self.limits.max_string_bytes,
                "max_items": self.limits.max_items,
                "max_processing_ms": self.limits.max_processing_ms,
            },
            "preview_enabled": self.preview_enabled,
            "preview_max_chars": self.preview_max_chars,
            "sink_allowlist": sorted(self.sink_allowlist),
        }


@dataclass(frozen=True, slots=True)
class FingerprintRecord:
    """Value-free stand-in for a redacted position (Packet §8.1)."""

    fingerprint: str
    value_kind: str
    length: int
    preview: str | None = None


@dataclass(frozen=True, slots=True)
class ClassificationManifest:
    """Classification + fingerprint metadata attached to every sanitized output."""

    classification: ArtifactClassification
    retention_class: RetentionClass
    policy_version: str
    policy_digest: str
    entries: tuple[FingerprintRecord, ...]
    created_at: str


@dataclass(frozen=True, slots=True)
class SanitizedPayload:
    """The only value-bearing object allowed to leave ``sanitize_for_sink``."""

    sink_kind: str
    tenant_id: str
    manifest: ClassificationManifest
    redacted_value: JSONValue | str | bytes | FingerprintRecord
