"""Common artifact contract objects for the LIMA contract foundation.

Implements the frozen v4.0 wire shapes: :class:`SchemaVersion`,
:class:`ArtifactClassification`, :class:`RetentionClass`,
:class:`ArtifactReference`, :class:`ArtifactBlobReference`, and
:class:`ArtifactEnvelope`, plus the envelope byte-level helpers. All
validation is deterministic, in-memory, and fail-closed: unknown fields,
unknown enum values, digest mismatches, and cross-tenant or cross-snapshot
references are rejected instead of being coerced or defaulted.
"""

import copy
import hmac
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta, timezone
from enum import Enum
from typing import Final

from lima.contracts.codec import (
    DEFAULT_LIMITS,
    ContractLimits,
    JSONValue,
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.errors import ContractError, ContractErrorCode

__all__ = [
    "CURRENT_SCHEMA_MAJOR",
    "CURRENT_SCHEMA_MINOR",
    "SchemaVersion",
    "ArtifactClassification",
    "RetentionClass",
    "ArtifactReference",
    "ArtifactBlobReference",
    "ArtifactEnvelope",
    "decode_envelope",
    "encode_envelope",
]

CURRENT_SCHEMA_MAJOR: Final[int] = 4
CURRENT_SCHEMA_MINOR: Final[int] = 0

_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_SCHEMA_NAME_BYTES: Final[int] = 128
_MAX_IDENTIFIER_BYTES: Final[int] = 128
_MAX_MEDIA_TYPE_BYTES: Final[int] = 127
_MAX_LINEAGE_ITEMS: Final[int] = 128
_MAX_COVERAGE_GAPS: Final[int] = 256
_MAX_COVERAGE_GAP_BYTES: Final[int] = 1024

_SCHEMA_VERSION_PATTERN: Final = re.compile(r"([0-9]+)\.([0-9]+)")
_SCHEMA_NAME_PATTERN: Final = re.compile(r"[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*")
_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_MEDIA_TYPE_PATTERN: Final = re.compile(
    r"[a-z0-9][a-z0-9!#$&^_.+-]{0,62}/[a-z0-9][a-z0-9!#$&^_.+-]{0,62}"
)
_CREATED_AT_PATTERN: Final = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,6}))?(Z|[+-]\d{2}:\d{2})"
)

_REFERENCE_WIRE_FIELDS: Final = (
    "schema_name",
    "schema_version",
    "artifact_id",
    "tenant_id",
    "repository_snapshot_digest",
    "content_digest",
)
_BLOB_WIRE_FIELDS: Final = (
    "blob_id",
    "content_digest",
    "size_bytes",
    "media_type",
)
_ENVELOPE_BASE_FIELDS: Final = (
    "schema_name",
    "schema_version",
    "artifact_id",
    "tenant_id",
    "task_id",
    "workflow_id",
    "stage_attempt_id",
    "repository_snapshot_digest",
    "producer",
    "created_at",
    "policy_digest",
    "toolchain_digest",
    "content_digest",
    "classification",
    "retention_class",
)
_ENVELOPE_WIRE_FIELDS: Final = frozenset(
    _ENVELOPE_BASE_FIELDS
    + ("payload", "blob_ref", "lineage", "supersedes", "coverage_gaps")
)
_ENVELOPE_REQUIRED_FIELDS: Final = _ENVELOPE_BASE_FIELDS + (
    "lineage",
    "supersedes",
    "coverage_gaps",
)


def _is_current_minor(version: "SchemaVersion") -> bool:
    return (
        version.major == CURRENT_SCHEMA_MAJOR and version.minor == CURRENT_SCHEMA_MINOR
    )


def _as_mapping(value: object, code: ContractErrorCode) -> Mapping[str, JSONValue]:
    if not isinstance(value, Mapping):
        raise ContractError(code, "$")
    return value


def _repath(error: ContractError, prefix: str) -> ContractError:
    field_path = error.field_path
    if field_path.startswith("$."):
        return ContractError(error.code, prefix + field_path[1:])
    if field_path:
        return ContractError(error.code, prefix + "." + field_path)
    return ContractError(error.code, prefix)


def _validate_schema_name(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _SCHEMA_NAME_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(value.encode("utf-8")) > _MAX_SCHEMA_NAME_BYTES:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validate_identifier(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _IDENTIFIER_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(value.encode("utf-8")) > _MAX_IDENTIFIER_BYTES:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validate_digest(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validate_media_type(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _MEDIA_TYPE_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(value.encode("ascii")) > _MAX_MEDIA_TYPE_BYTES:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _normalize_created_at(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    match = _CREATED_AT_PATTERN.fullmatch(value)
    if match is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    year, month, day, hour, minute, second, fraction, offset = match.groups()
    microsecond = int((fraction or "").ljust(6, "0"))
    try:
        if offset == "Z":
            tzinfo = UTC
        else:
            sign = 1 if offset[0] == "+" else -1
            tzinfo = timezone(
                sign * timedelta(hours=int(offset[1:3]), minutes=int(offset[4:6]))
            )
        moment = datetime(
            int(year),
            int(month),
            int(day),
            int(hour),
            int(minute),
            int(second),
            microsecond,
            tzinfo,
        )
    except ValueError as exc:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path) from exc
    utc = moment.astimezone(UTC)
    return (
        f"{utc.year:04d}-{utc.month:02d}-{utc.day:02d}"
        f"T{utc.hour:02d}:{utc.minute:02d}:{utc.second:02d}"
        f".{utc.microsecond:06d}Z"
    )


def _validate_coverage_gap(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(ContractErrorCode.INVALID_UTF8, path) from exc
    if len(encoded) > _MAX_COVERAGE_GAP_BYTES:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    return normalized


def _validated_extensions(
    extensions: object,
    *,
    known_fields: frozenset[str] | tuple[str, ...],
    version: "SchemaVersion | None",
    path: str,
) -> dict[str, JSONValue]:
    if not isinstance(extensions, dict):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if version is not None and _is_current_minor(version) and extensions:
        raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)
    normalized: dict[str, JSONValue] = {}
    for key, value in extensions.items():
        if not isinstance(key, str):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
        normalized_key = unicodedata.normalize("NFC", key)
        try:
            normalized_key.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ContractError(ContractErrorCode.INVALID_UTF8, path) from exc
        if normalized_key in normalized or normalized_key in known_fields:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD, path)
        normalized[normalized_key] = copy.deepcopy(value)
    return normalized


def _split_extensions(
    data: Mapping[str, JSONValue],
    known_fields: tuple[str, ...],
) -> dict[str, JSONValue]:
    extensions: dict[str, JSONValue] = {}
    for key, value in data.items():
        if key in known_fields:
            continue
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in known_fields or normalized_key in extensions:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD, "$")
        extensions[normalized_key] = value
    return extensions


def _reject_current_minor_extensions(
    extensions: dict[str, JSONValue], version: "SchemaVersion"
) -> None:
    if _is_current_minor(version) and extensions:
        raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.{sorted(extensions)[0]}")


def _enum_from_wire(value: object, enum_type: type, path: str):
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(ContractErrorCode.UNKNOWN_ENUM_VALUE, path) from exc


@dataclass(frozen=True, slots=True)
class SchemaVersion:
    """Artifact schema version; the implementation currently supports 4.x only."""

    major: int
    minor: int

    def __post_init__(self) -> None:
        for name in ("major", "minor"):
            if type(getattr(self, name)) is not int:
                raise ContractError(ContractErrorCode.SCHEMA_VERSION_INVALID, name)
        if self.major < 1:
            raise ContractError(ContractErrorCode.SCHEMA_VERSION_INVALID, "major")
        if self.minor < 0:
            raise ContractError(ContractErrorCode.SCHEMA_VERSION_INVALID, "minor")
        if self.major != CURRENT_SCHEMA_MAJOR:
            raise ContractError(ContractErrorCode.SCHEMA_UNKNOWN_MAJOR, "major")

    @classmethod
    def parse(cls, value: object) -> "SchemaVersion":
        if not isinstance(value, str):
            raise ContractError(ContractErrorCode.SCHEMA_VERSION_INVALID)
        match = _SCHEMA_VERSION_PATTERN.fullmatch(value)
        if match is None:
            raise ContractError(ContractErrorCode.SCHEMA_VERSION_INVALID)
        return cls(int(match.group(1)), int(match.group(2)))

    def __str__(self) -> str:
        return f"{self.major}.{self.minor}"


class ArtifactClassification(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0001 §9.2
    """Sensitivity classification carried by every artifact envelope."""

    PUBLIC = "public"
    INTERNAL = "internal"
    SENSITIVE = "sensitive"
    RESTRICTED = "restricted"


class RetentionClass(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0001 §9.3
    """Retention policy carried by every artifact envelope."""

    EPHEMERAL = "ephemeral"
    STANDARD = "standard"
    AUDIT = "audit"
    LEGAL_HOLD = "legal_hold"


@dataclass(frozen=True, slots=True)
class ArtifactReference:
    """Identity of another artifact, scoped to one tenant and one snapshot."""

    schema_name: str
    schema_version: SchemaVersion
    artifact_id: str
    tenant_id: str
    repository_snapshot_digest: str
    content_digest: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        object.__setattr__(
            self, "schema_name", _validate_schema_name(self.schema_name, "$.schema_name")
        )
        object.__setattr__(
            self, "artifact_id", _validate_identifier(self.artifact_id, "$.artifact_id")
        )
        object.__setattr__(
            self, "tenant_id", _validate_identifier(self.tenant_id, "$.tenant_id")
        )
        object.__setattr__(
            self,
            "repository_snapshot_digest",
            _validate_digest(
                self.repository_snapshot_digest, "$.repository_snapshot_digest"
            ),
        )
        object.__setattr__(
            self,
            "content_digest",
            _validate_digest(self.content_digest, "$.content_digest"),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_REFERENCE_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, JSONValue]) -> "ArtifactReference":
        data = _as_mapping(value, ContractErrorCode.INVALID_FIELD_TYPE)
        missing = [name for name in _REFERENCE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        version = SchemaVersion.parse(data["schema_version"])
        extensions = _split_extensions(data, _REFERENCE_WIRE_FIELDS)
        _reject_current_minor_extensions(extensions, version)
        return cls(
            schema_name=data["schema_name"],
            schema_version=version,
            artifact_id=data["artifact_id"],
            tenant_id=data["tenant_id"],
            repository_snapshot_digest=data["repository_snapshot_digest"],
            content_digest=data["content_digest"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "schema_name": self.schema_name,
            "schema_version": str(self.schema_version),
            "artifact_id": self.artifact_id,
            "tenant_id": self.tenant_id,
            "repository_snapshot_digest": self.repository_snapshot_digest,
            "content_digest": self.content_digest,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


@dataclass(frozen=True, slots=True)
class ArtifactBlobReference:
    """Logical pointer to out-of-line blob content owned by a future registry."""

    blob_id: str
    content_digest: str
    size_bytes: int
    media_type: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if type(self.size_bytes) is not int:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.size_bytes")
        if not 0 <= self.size_bytes <= _INT64_MAX:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.size_bytes")
        object.__setattr__(
            self, "blob_id", _validate_identifier(self.blob_id, "$.blob_id")
        )
        object.__setattr__(
            self,
            "content_digest",
            _validate_digest(self.content_digest, "$.content_digest"),
        )
        object.__setattr__(
            self,
            "media_type",
            _validate_media_type(self.media_type, "$.media_type"),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_BLOB_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls,
        value: Mapping[str, JSONValue],
        *,
        envelope_version: SchemaVersion,
    ) -> "ArtifactBlobReference":
        data = _as_mapping(value, ContractErrorCode.INVALID_FIELD_TYPE)
        missing = [name for name in _BLOB_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(data, _BLOB_WIRE_FIELDS)
        _reject_current_minor_extensions(extensions, envelope_version)
        return cls(
            blob_id=data["blob_id"],
            content_digest=data["content_digest"],
            size_bytes=data["size_bytes"],
            media_type=data["media_type"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "blob_id": self.blob_id,
            "content_digest": self.content_digest,
            "size_bytes": self.size_bytes,
            "media_type": self.media_type,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


@dataclass(frozen=True, slots=True)
class ArtifactEnvelope:
    """Versioned, digest-protected artifact container for all LIMA stages."""

    schema_name: str
    schema_version: SchemaVersion
    artifact_id: str
    tenant_id: str
    task_id: str
    workflow_id: str
    stage_attempt_id: str
    repository_snapshot_digest: str
    producer: str
    created_at: str
    policy_digest: str
    toolchain_digest: str
    content_digest: str
    classification: ArtifactClassification
    retention_class: RetentionClass
    payload: dict[str, JSONValue] | None = None
    blob_ref: ArtifactBlobReference | None = None
    lineage: tuple[ArtifactReference, ...] = ()
    supersedes: ArtifactReference | None = None
    coverage_gaps: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.classification, ArtifactClassification):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.classification")
        if not isinstance(self.retention_class, RetentionClass):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.retention_class")
        if self.payload is not None and not isinstance(self.payload, dict):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.payload")
        if self.blob_ref is not None and not isinstance(self.blob_ref, ArtifactBlobReference):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.blob_ref")
        if self.supersedes is not None and not isinstance(self.supersedes, ArtifactReference):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.supersedes")
        try:
            lineage_items = tuple(self.lineage)
        except TypeError as exc:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.lineage") from exc
        for index, reference in enumerate(lineage_items):
            if not isinstance(reference, ArtifactReference):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.lineage[{index}]"
                )
        try:
            coverage_items = tuple(self.coverage_gaps)
        except TypeError as exc:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.coverage_gaps"
            ) from exc
        if len(lineage_items) > _MAX_LINEAGE_ITEMS:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.lineage"
            )
        if len(coverage_items) > _MAX_COVERAGE_GAPS:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.coverage_gaps"
            )

        object.__setattr__(
            self, "schema_name", _validate_schema_name(self.schema_name, "$.schema_name")
        )
        for name in (
            "artifact_id",
            "tenant_id",
            "task_id",
            "workflow_id",
            "stage_attempt_id",
            "producer",
        ):
            object.__setattr__(
                self, name, _validate_identifier(getattr(self, name), f"$.{name}")
            )
        for name in (
            "repository_snapshot_digest",
            "policy_digest",
            "toolchain_digest",
            "content_digest",
        ):
            object.__setattr__(
                self, name, _validate_digest(getattr(self, name), f"$.{name}")
            )
        object.__setattr__(
            self,
            "created_at",
            _normalize_created_at(self.created_at, "$.created_at"),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_ENVELOPE_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )
        if _is_current_minor(self.schema_version) and self.blob_ref is not None:
            if self.blob_ref.extensions:
                raise ContractError(ContractErrorCode.UNKNOWN_FIELD, "$.blob_ref")

        if self.payload is None and self.blob_ref is None:
            raise ContractError(ContractErrorCode.INLINE_OR_BLOB_REQUIRED, "$")
        if self.payload is not None and self.blob_ref is not None:
            raise ContractError(ContractErrorCode.INLINE_AND_BLOB_CONFLICT, "$")

        if self.payload is not None:
            actual_digest = compute_content_digest(self.payload)
            if not hmac.compare_digest(actual_digest, self.content_digest):
                raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
        elif not hmac.compare_digest(self.blob_ref.content_digest, self.content_digest):
            raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")

        identities: dict[str, tuple[str, int, int, str]] = {}
        for index, reference in enumerate(lineage_items):
            if reference.artifact_id == self.artifact_id:
                raise ContractError(
                    ContractErrorCode.LINEAGE_SELF_REFERENCE,
                    f"$.lineage[{index}].artifact_id",
                )
            if reference.tenant_id != self.tenant_id:
                raise ContractError(
                    ContractErrorCode.LINEAGE_TENANT_MISMATCH,
                    f"$.lineage[{index}].tenant_id",
                )
            if reference.repository_snapshot_digest != self.repository_snapshot_digest:
                raise ContractError(
                    ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
                    f"$.lineage[{index}].repository_snapshot_digest",
                )
            identity = (
                reference.schema_name,
                reference.schema_version.major,
                reference.schema_version.minor,
                reference.content_digest,
            )
            existing = identities.get(reference.artifact_id)
            if existing is not None:
                if existing == identity:
                    raise ContractError(
                        ContractErrorCode.LINEAGE_DUPLICATE, f"$.lineage[{index}]"
                    )
                raise ContractError(
                    ContractErrorCode.LINEAGE_CONFLICT, f"$.lineage[{index}]"
                )
            identities[reference.artifact_id] = identity
        if self.supersedes is not None:
            supersedes = self.supersedes
            if supersedes.artifact_id == self.artifact_id:
                raise ContractError(
                    ContractErrorCode.LINEAGE_SELF_REFERENCE, "$.supersedes.artifact_id"
                )
            if supersedes.tenant_id != self.tenant_id:
                raise ContractError(
                    ContractErrorCode.LINEAGE_TENANT_MISMATCH, "$.supersedes.tenant_id"
                )
            if supersedes.repository_snapshot_digest != self.repository_snapshot_digest:
                raise ContractError(
                    ContractErrorCode.LINEAGE_SNAPSHOT_MISMATCH,
                    "$.supersedes.repository_snapshot_digest",
                )
            supersedes_identity = (
                supersedes.schema_name,
                supersedes.schema_version.major,
                supersedes.schema_version.minor,
                supersedes.content_digest,
            )
            existing = identities.get(supersedes.artifact_id)
            if existing is not None and existing != supersedes_identity:
                raise ContractError(
                    ContractErrorCode.LINEAGE_CONFLICT, "$.supersedes"
                )

        normalized_coverage: list[str] = []
        seen_coverage: set[str] = set()
        for index, gap in enumerate(coverage_items):
            normalized = _validate_coverage_gap(gap, f"$.coverage_gaps[{index}]")
            if normalized in seen_coverage:
                raise ContractError(
                    ContractErrorCode.COVERAGE_GAP_DUPLICATE, f"$.coverage_gaps[{index}]"
                )
            seen_coverage.add(normalized)
            normalized_coverage.append(normalized)

        object.__setattr__(self, "payload", copy.deepcopy(self.payload))
        object.__setattr__(self, "blob_ref", copy.deepcopy(self.blob_ref))
        object.__setattr__(self, "supersedes", copy.deepcopy(self.supersedes))
        object.__setattr__(
            self, "lineage", tuple(copy.deepcopy(item) for item in lineage_items)
        )
        object.__setattr__(self, "coverage_gaps", tuple(normalized_coverage))

    @classmethod
    def from_dict(cls, value: Mapping[str, JSONValue]) -> "ArtifactEnvelope":
        data = _as_mapping(value, ContractErrorCode.TOP_LEVEL_NOT_OBJECT)
        missing = [name for name in _ENVELOPE_REQUIRED_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        version = SchemaVersion.parse(data["schema_version"])
        extensions = _split_extensions(data, tuple(_ENVELOPE_WIRE_FIELDS))
        _reject_current_minor_extensions(extensions, version)

        lineage_raw = data["lineage"]
        if not isinstance(lineage_raw, list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.lineage")
        lineage: list[ArtifactReference] = []
        for index, item in enumerate(lineage_raw):
            try:
                lineage.append(ArtifactReference.from_dict(item))
            except ContractError as error:
                raise _repath(error, f"$.lineage[{index}]") from error
        supersedes = None
        if data["supersedes"] is not None:
            try:
                supersedes = ArtifactReference.from_dict(data["supersedes"])
            except ContractError as error:
                raise _repath(error, "$.supersedes") from error
        blob_ref = None
        if data.get("blob_ref") is not None:
            try:
                blob_ref = ArtifactBlobReference.from_dict(
                    data["blob_ref"], envelope_version=version
                )
            except ContractError as error:
                raise _repath(error, "$.blob_ref") from error
        return cls(
            schema_name=data["schema_name"],
            schema_version=version,
            artifact_id=data["artifact_id"],
            tenant_id=data["tenant_id"],
            task_id=data["task_id"],
            workflow_id=data["workflow_id"],
            stage_attempt_id=data["stage_attempt_id"],
            repository_snapshot_digest=data["repository_snapshot_digest"],
            producer=data["producer"],
            created_at=data["created_at"],
            policy_digest=data["policy_digest"],
            toolchain_digest=data["toolchain_digest"],
            content_digest=data["content_digest"],
            classification=_enum_from_wire(
                data["classification"], ArtifactClassification, "$.classification"
            ),
            retention_class=_enum_from_wire(
                data["retention_class"], RetentionClass, "$.retention_class"
            ),
            payload=data.get("payload"),
            blob_ref=blob_ref,
            lineage=lineage,
            supersedes=supersedes,
            coverage_gaps=data["coverage_gaps"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "schema_name": self.schema_name,
            "schema_version": str(self.schema_version),
            "artifact_id": self.artifact_id,
            "tenant_id": self.tenant_id,
            "task_id": self.task_id,
            "workflow_id": self.workflow_id,
            "stage_attempt_id": self.stage_attempt_id,
            "repository_snapshot_digest": self.repository_snapshot_digest,
            "producer": self.producer,
            "created_at": self.created_at,
            "policy_digest": self.policy_digest,
            "toolchain_digest": self.toolchain_digest,
            "content_digest": self.content_digest,
            "classification": self.classification.value,
            "retention_class": self.retention_class.value,
            "lineage": [reference.to_dict() for reference in self.lineage],
            "supersedes": (
                self.supersedes.to_dict() if self.supersedes is not None else None
            ),
            "coverage_gaps": list(self.coverage_gaps),
        }
        if self.payload is not None:
            result["payload"] = copy.deepcopy(self.payload)
        if self.blob_ref is not None:
            result["blob_ref"] = self.blob_ref.to_dict()
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def decode_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> ArtifactEnvelope:
    """Decode canonical bytes into a fully validated :class:`ArtifactEnvelope`."""
    return ArtifactEnvelope.from_dict(canonical_decode(data, limits=limits))


def encode_envelope(
    envelope: ArtifactEnvelope, *, limits: ContractLimits = DEFAULT_LIMITS
) -> bytes:
    """Encode an envelope to canonical bytes."""
    return canonical_encode(envelope.to_dict(), limits=limits)
