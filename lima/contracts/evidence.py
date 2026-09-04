"""Deterministic Evidence Domain contracts for LIMA (IP-0002).

Module-only leaf contracts on top of the IP-0001 artifact foundation:
``Signal -> SecurityIssue -> VulnerabilityHypothesis`` linked by
``EvidenceRecord`` supports/refutes relations, validated as one
``EvidenceDomainBundle`` graph and bound to an ``ArtifactEnvelope`` inline
payload. Pure in-memory, stdlib-only, fail-closed: dangling references,
cycles, level inversions, D3/D4 promotion attempts, status inconsistencies,
and envelope binding violations are rejected, never coerced.
"""

import copy
import hmac
import re
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Final

from lima.contracts.codec import (
    DEFAULT_LIMITS,
    ContractLimits,
    JSONValue,
    compute_content_digest,
)
from lima.contracts.common import (
    ArtifactClassification,
    ArtifactEnvelope,
    RetentionClass,
    SchemaVersion,
    decode_envelope,
    encode_envelope,
)
from lima.contracts.errors import ContractError, ContractErrorCode

__all__ = [
    "EVIDENCE_DOMAIN_SCHEMA_NAME",
    "EvidenceLevel",
    "EvidencePolarity",
    "EvidenceSubjectKind",
    "HypothesisStatus",
    "RequiredProofKind",
    "SourceLocation",
    "EvidenceRecord",
    "Signal",
    "SecurityIssue",
    "VulnerabilityHypothesis",
    "EvidenceDomainBundle",
    "decode_evidence_payload",
    "encode_evidence_payload",
    "decode_evidence_envelope",
    "encode_evidence_envelope",
]

EVIDENCE_DOMAIN_SCHEMA_NAME = "lima.evidence-domain"

_MAX_PATH_BYTES: Final[int] = 1024
_MAX_SYMBOL_BYTES: Final[int] = 512
_MAX_TEXT_BYTES: Final[int] = 4096
_MAX_INDEPENDENCE_KEY_BYTES: Final[int] = 512
_MAX_LINE_VALUE: Final[int] = 2147483647

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_RULE_ID_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+/-]{0,255}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_CWE_PATTERN: Final = re.compile(r"CWE-[1-9][0-9]{0,5}")
_REASON_CODE_PATTERN: Final = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_DRIVE_PREFIX_PATTERN: Final = re.compile(r"[A-Za-z]:")


def _is_current_minor(version: SchemaVersion) -> bool:
    return version == SchemaVersion(4, 0)


def _as_mapping(value: object) -> Mapping[str, JSONValue]:
    if not isinstance(value, Mapping):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$")
    return value


def _repath(error: ContractError, prefix: str) -> ContractError:
    field_path = error.field_path
    if field_path.startswith("$."):
        return ContractError(error.code, prefix + field_path[1:])
    if field_path:
        return ContractError(error.code, prefix + "." + field_path)
    return ContractError(error.code, prefix)


def _utf8_bytes(value: str, path: str) -> bytes:
    try:
        return value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(ContractErrorCode.INVALID_UTF8, path) from exc


def _validated_identifier(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_rule_id(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _RULE_ID_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_digest(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_bounded_text(value: object, path: str, *, max_bytes: int) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    encoded = _utf8_bytes(normalized, path)
    if not normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if normalized != normalized.strip():
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(encoded) > max_bytes:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    return normalized


def _validated_path(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    encoded = _utf8_bytes(normalized, path)
    if not normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(encoded) > _MAX_PATH_BYTES:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if normalized.startswith("/") or "\\" in normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if _DRIVE_PREFIX_PATTERN.match(normalized) is not None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    for segment in normalized.split("/"):
        if segment in ("", ".", ".."):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_line(value: object, path: str) -> int:
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if not 1 <= value <= _MAX_LINE_VALUE:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_extensions(
    extensions: object,
    *,
    known_fields: tuple[str, ...],
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
        _utf8_bytes(normalized_key, path)
        if normalized_key in normalized or normalized_key in known_fields:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD, path)
        normalized[normalized_key] = copy.deepcopy(value)
    return normalized


def _split_extensions(
    data: Mapping[str, JSONValue],
    *,
    known_fields: tuple[str, ...],
    schema_version: SchemaVersion,
) -> dict[str, JSONValue]:
    extensions: dict[str, JSONValue] = {}
    for key, value in data.items():
        if key in known_fields:
            continue
        normalized_key = unicodedata.normalize("NFC", key)
        _utf8_bytes(normalized_key, "$")
        if normalized_key in known_fields or normalized_key in extensions:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD, "$")
        extensions[normalized_key] = value
    if _is_current_minor(schema_version) and extensions:
        raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.{sorted(extensions)[0]}")
    return extensions


def _wire_enum(value: object, enum_type: type, path: str):
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    try:
        return enum_type(value)
    except ValueError as exc:
        raise ContractError(ContractErrorCode.UNKNOWN_ENUM_VALUE, path) from exc


class EvidenceLevel(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0002 §9
    """Depth of an evidence record; D3/D4 stay wire-only until the VEP packet."""

    D0 = "D0"
    D1 = "D1"
    D2 = "D2"
    D3 = "D3"
    D4 = "D4"


class EvidencePolarity(str, Enum):  # noqa: UP042 -- frozen by IP-0002 §9
    """Direction of an evidence record relative to its subject."""

    SUPPORTS = "supports"
    REFUTES = "refutes"


class EvidenceSubjectKind(str, Enum):  # noqa: UP042 -- frozen by IP-0002 §9
    """Which domain object an evidence record is bound to."""

    SIGNAL = "signal"
    SECURITY_ISSUE = "security_issue"
    VULNERABILITY_HYPOTHESIS = "vulnerability_hypothesis"


class HypothesisStatus(str, Enum):  # noqa: UP042 -- frozen by IP-0002 §9
    """Static-evidence status; none of these values means runtime verification."""

    PROPOSED = "proposed"
    STATICALLY_SUPPORTED = "statically_supported"
    STATICALLY_REFUTED = "statically_refuted"
    CONFLICTING_STATIC_EVIDENCE = "conflicting_static_evidence"
    INSUFFICIENT_STATIC_EVIDENCE = "insufficient_static_evidence"


class RequiredProofKind(str, Enum):  # noqa: UP042 -- frozen by IP-0002 §9
    """What kind of proof would settle a hypothesis."""

    RUNTIME_BEHAVIOR = "runtime_behavior"
    STATIC_PROPERTY = "static_property"
    CONFIGURATION_STATE = "configuration_state"
    EXTERNAL_MANUAL_REQUIRED = "external_manual_required"


_SOURCE_LOCATION_WIRE_FIELDS: Final = (
    "path",
    "start_line",
    "end_line",
    "start_column",
    "end_column",
    "symbol",
)


@dataclass(frozen=True, slots=True)
class SourceLocation:
    """Repository-relative code position; all wire fields are required."""

    path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    symbol: str | None = None
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _validated_path(self.path, "$.path"))
        object.__setattr__(
            self, "start_line", _validated_line(self.start_line, "$.start_line")
        )
        object.__setattr__(self, "end_line", _validated_line(self.end_line, "$.end_line"))
        if self.end_line < self.start_line:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.end_line")
        if (self.start_column is None) != (self.end_column is None):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.start_column")
        if self.start_column is not None:
            object.__setattr__(
                self,
                "start_column",
                _validated_line(self.start_column, "$.start_column"),
            )
            object.__setattr__(
                self,
                "end_column",
                _validated_line(self.end_column, "$.end_column"),
            )
            if (
                self.start_line == self.end_line
                and self.end_column < self.start_column
            ):
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.end_column")
        if self.symbol is not None:
            object.__setattr__(
                self,
                "symbol",
                _validated_bounded_text(self.symbol, "$.symbol", max_bytes=_MAX_SYMBOL_BYTES),
            )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_SOURCE_LOCATION_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "SourceLocation":
        data = _as_mapping(value)
        missing = [name for name in _SOURCE_LOCATION_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_SOURCE_LOCATION_WIRE_FIELDS, schema_version=schema_version
        )
        return cls(
            path=data["path"],
            start_line=data["start_line"],
            end_line=data["end_line"],
            start_column=data["start_column"],
            end_column=data["end_column"],
            symbol=data["symbol"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "path": self.path,
            "start_line": self.start_line,
            "end_line": self.end_line,
            "start_column": self.start_column,
            "end_column": self.end_column,
            "symbol": self.symbol,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _validated_cwe(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _CWE_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_reason_code(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _REASON_CODE_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_sorted_str_array(
    items: object,
    path: str,
    *,
    cap: int,
    allow_empty: bool,
    item_validator,
) -> tuple[str, ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    if not items and not allow_empty:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    normalized = [
        item_validator(item, f"{path}[{index}]") for index, item in enumerate(items)
    ]
    for index in range(1, len(normalized)):
        if normalized[index] <= normalized[index - 1]:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]")
    return tuple(normalized)


def _validated_sorted_text_array(
    items: object,
    path: str,
    *,
    cap: int,
) -> tuple[str, ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    normalized = [
        _validated_bounded_text(item, f"{path}[{index}]", max_bytes=_MAX_TEXT_BYTES)
        for index, item in enumerate(items)
    ]
    encoded = [item.encode("utf-8") for item in normalized]
    for index in range(1, len(normalized)):
        if encoded[index] <= encoded[index - 1]:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]")
    return tuple(normalized)


def _validated_location(item: object, path: str) -> "SourceLocation":
    if not isinstance(item, SourceLocation):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    return copy.deepcopy(item)


def _validated_location_tuple(
    items: object,
    path: str,
    *,
    cap: int,
) -> tuple["SourceLocation", ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    return tuple(
        _validated_location(item, f"{path}[{index}]") for index, item in enumerate(items)
    )


_EVIDENCE_WIRE_FIELDS: Final = (
    "evidence_id",
    "subject_kind",
    "subject_id",
    "level",
    "polarity",
    "analysis_family",
    "producer",
    "independence_key",
    "summary",
    "source_artifact_ids",
    "reason_codes",
    "location",
    "depends_on_evidence_ids",
)


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """One supports/refutes fact bound to exactly one domain subject."""

    evidence_id: str
    subject_kind: EvidenceSubjectKind
    subject_id: str
    level: EvidenceLevel
    polarity: EvidencePolarity
    analysis_family: str
    producer: str
    independence_key: str
    summary: str
    source_artifact_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    location: "SourceLocation | None" = None
    depends_on_evidence_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "evidence_id", _validated_identifier(self.evidence_id, "$.evidence_id")
        )
        if not isinstance(self.subject_kind, EvidenceSubjectKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.subject_kind")
        object.__setattr__(
            self, "subject_id", _validated_identifier(self.subject_id, "$.subject_id")
        )
        if not isinstance(self.level, EvidenceLevel):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.level")
        if not isinstance(self.polarity, EvidencePolarity):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.polarity")
        object.__setattr__(
            self,
            "analysis_family",
            _validated_identifier(self.analysis_family, "$.analysis_family"),
        )
        object.__setattr__(
            self, "producer", _validated_identifier(self.producer, "$.producer")
        )
        object.__setattr__(
            self,
            "independence_key",
            _validated_bounded_text(
                self.independence_key,
                "$.independence_key",
                max_bytes=_MAX_INDEPENDENCE_KEY_BYTES,
            ),
        )
        object.__setattr__(
            self,
            "summary",
            _validated_bounded_text(self.summary, "$.summary", max_bytes=_MAX_TEXT_BYTES),
        )
        object.__setattr__(
            self,
            "source_artifact_ids",
            _validated_sorted_str_array(
                self.source_artifact_ids,
                "$.source_artifact_ids",
                cap=32,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "reason_codes",
            _validated_sorted_str_array(
                self.reason_codes,
                "$.reason_codes",
                cap=64,
                allow_empty=False,
                item_validator=_validated_reason_code,
            ),
        )
        if self.location is not None:
            object.__setattr__(
                self, "location", _validated_location(self.location, "$.location")
            )
        object.__setattr__(
            self,
            "depends_on_evidence_ids",
            _validated_sorted_str_array(
                self.depends_on_evidence_ids,
                "$.depends_on_evidence_ids",
                cap=64,
                allow_empty=True,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_EVIDENCE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "EvidenceRecord":
        data = _as_mapping(value)
        missing = [name for name in _EVIDENCE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_EVIDENCE_WIRE_FIELDS, schema_version=schema_version
        )
        subject_kind = _wire_enum(
            data["subject_kind"], EvidenceSubjectKind, "$.subject_kind"
        )
        level = _wire_enum(data["level"], EvidenceLevel, "$.level")
        polarity = _wire_enum(data["polarity"], EvidencePolarity, "$.polarity")
        location = None
        if data["location"] is not None:
            try:
                location = SourceLocation.from_dict(
                    data["location"], schema_version=schema_version
                )
            except ContractError as error:
                raise _repath(error, "$.location") from error
        return cls(
            evidence_id=data["evidence_id"],
            subject_kind=subject_kind,
            subject_id=data["subject_id"],
            level=level,
            polarity=polarity,
            analysis_family=data["analysis_family"],
            producer=data["producer"],
            independence_key=data["independence_key"],
            summary=data["summary"],
            source_artifact_ids=data["source_artifact_ids"],
            reason_codes=data["reason_codes"],
            location=location,
            depends_on_evidence_ids=data["depends_on_evidence_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "evidence_id": self.evidence_id,
            "subject_kind": self.subject_kind.value,
            "subject_id": self.subject_id,
            "level": self.level.value,
            "polarity": self.polarity.value,
            "analysis_family": self.analysis_family,
            "producer": self.producer,
            "independence_key": self.independence_key,
            "summary": self.summary,
            "source_artifact_ids": list(self.source_artifact_ids),
            "reason_codes": list(self.reason_codes),
            "location": self.location.to_dict() if self.location is not None else None,
            "depends_on_evidence_ids": list(self.depends_on_evidence_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_SIGNAL_WIRE_FIELDS: Final = (
    "signal_id",
    "fingerprint",
    "rule_id",
    "analysis_family",
    "evidence_kind",
    "location",
    "evidence_ids",
    "reason_codes",
    "cwe_ids",
)


@dataclass(frozen=True, slots=True)
class Signal:
    """Raw tool or semantic observation pinned to one code location."""

    signal_id: str
    fingerprint: str
    rule_id: str
    analysis_family: str
    evidence_kind: str
    location: SourceLocation
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    cwe_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "signal_id", _validated_identifier(self.signal_id, "$.signal_id")
        )
        object.__setattr__(
            self, "fingerprint", _validated_digest(self.fingerprint, "$.fingerprint")
        )
        object.__setattr__(
            self, "rule_id", _validated_rule_id(self.rule_id, "$.rule_id")
        )
        object.__setattr__(
            self,
            "analysis_family",
            _validated_identifier(self.analysis_family, "$.analysis_family"),
        )
        object.__setattr__(
            self,
            "evidence_kind",
            _validated_identifier(self.evidence_kind, "$.evidence_kind"),
        )
        object.__setattr__(
            self, "location", _validated_location(self.location, "$.location")
        )
        object.__setattr__(
            self,
            "evidence_ids",
            _validated_sorted_str_array(
                self.evidence_ids,
                "$.evidence_ids",
                cap=1024,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "reason_codes",
            _validated_sorted_str_array(
                self.reason_codes,
                "$.reason_codes",
                cap=64,
                allow_empty=False,
                item_validator=_validated_reason_code,
            ),
        )
        object.__setattr__(
            self,
            "cwe_ids",
            _validated_sorted_str_array(
                self.cwe_ids,
                "$.cwe_ids",
                cap=32,
                allow_empty=True,
                item_validator=_validated_cwe,
            ),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_SIGNAL_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "Signal":
        data = _as_mapping(value)
        missing = [name for name in _SIGNAL_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_SIGNAL_WIRE_FIELDS, schema_version=schema_version
        )
        try:
            location = SourceLocation.from_dict(
                data["location"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.location") from error
        return cls(
            signal_id=data["signal_id"],
            fingerprint=data["fingerprint"],
            rule_id=data["rule_id"],
            analysis_family=data["analysis_family"],
            evidence_kind=data["evidence_kind"],
            location=location,
            evidence_ids=data["evidence_ids"],
            reason_codes=data["reason_codes"],
            cwe_ids=data["cwe_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "signal_id": self.signal_id,
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "analysis_family": self.analysis_family,
            "evidence_kind": self.evidence_kind,
            "location": self.location.to_dict(),
            "evidence_ids": list(self.evidence_ids),
            "reason_codes": list(self.reason_codes),
            "cwe_ids": list(self.cwe_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_SECURITY_ISSUE_WIRE_FIELDS: Final = (
    "issue_id",
    "identity_digest",
    "root_cause_class",
    "sink_identity",
    "trust_boundary",
    "primary_location",
    "signal_ids",
    "evidence_ids",
    "reason_codes",
    "cwe_ids",
)


@dataclass(frozen=True, slots=True)
class SecurityIssue:
    """Investigation unit for one root cause, sink, or trust boundary."""

    issue_id: str
    identity_digest: str
    root_cause_class: str
    sink_identity: str
    trust_boundary: str
    primary_location: SourceLocation
    signal_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    cwe_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "issue_id", _validated_identifier(self.issue_id, "$.issue_id")
        )
        object.__setattr__(
            self,
            "identity_digest",
            _validated_digest(self.identity_digest, "$.identity_digest"),
        )
        object.__setattr__(
            self,
            "root_cause_class",
            _validated_identifier(self.root_cause_class, "$.root_cause_class"),
        )
        object.__setattr__(
            self,
            "sink_identity",
            _validated_identifier(self.sink_identity, "$.sink_identity"),
        )
        object.__setattr__(
            self,
            "trust_boundary",
            _validated_identifier(self.trust_boundary, "$.trust_boundary"),
        )
        object.__setattr__(
            self,
            "primary_location",
            _validated_location(self.primary_location, "$.primary_location"),
        )
        object.__setattr__(
            self,
            "signal_ids",
            _validated_sorted_str_array(
                self.signal_ids,
                "$.signal_ids",
                cap=1024,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "evidence_ids",
            _validated_sorted_str_array(
                self.evidence_ids,
                "$.evidence_ids",
                cap=1024,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "reason_codes",
            _validated_sorted_str_array(
                self.reason_codes,
                "$.reason_codes",
                cap=64,
                allow_empty=False,
                item_validator=_validated_reason_code,
            ),
        )
        object.__setattr__(
            self,
            "cwe_ids",
            _validated_sorted_str_array(
                self.cwe_ids,
                "$.cwe_ids",
                cap=32,
                allow_empty=True,
                item_validator=_validated_cwe,
            ),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_SECURITY_ISSUE_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "SecurityIssue":
        data = _as_mapping(value)
        missing = [name for name in _SECURITY_ISSUE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_SECURITY_ISSUE_WIRE_FIELDS, schema_version=schema_version
        )
        try:
            primary_location = SourceLocation.from_dict(
                data["primary_location"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.primary_location") from error
        return cls(
            issue_id=data["issue_id"],
            identity_digest=data["identity_digest"],
            root_cause_class=data["root_cause_class"],
            sink_identity=data["sink_identity"],
            trust_boundary=data["trust_boundary"],
            primary_location=primary_location,
            signal_ids=data["signal_ids"],
            evidence_ids=data["evidence_ids"],
            reason_codes=data["reason_codes"],
            cwe_ids=data["cwe_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "issue_id": self.issue_id,
            "identity_digest": self.identity_digest,
            "root_cause_class": self.root_cause_class,
            "sink_identity": self.sink_identity,
            "trust_boundary": self.trust_boundary,
            "primary_location": self.primary_location.to_dict(),
            "signal_ids": list(self.signal_ids),
            "evidence_ids": list(self.evidence_ids),
            "reason_codes": list(self.reason_codes),
            "cwe_ids": list(self.cwe_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_HYPOTHESIS_WIRE_FIELDS: Final = (
    "hypothesis_id",
    "issue_id",
    "status",
    "claim",
    "security_invariant",
    "required_proof_kind",
    "capability_requirements",
    "target_location",
    "source_locations",
    "critical_path",
    "trigger_conditions",
    "input_constraints",
    "evidence_ids",
    "reason_codes",
    "cwe_ids",
)


@dataclass(frozen=True, slots=True)
class VulnerabilityHypothesis:
    """A verifiable security proposition about one SecurityIssue."""

    hypothesis_id: str
    issue_id: str
    status: HypothesisStatus
    claim: str
    security_invariant: str
    required_proof_kind: RequiredProofKind
    capability_requirements: tuple[str, ...]
    target_location: SourceLocation
    source_locations: tuple[SourceLocation, ...]
    critical_path: tuple[SourceLocation, ...]
    trigger_conditions: tuple[str, ...]
    input_constraints: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    reason_codes: tuple[str, ...]
    cwe_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "hypothesis_id",
            _validated_identifier(self.hypothesis_id, "$.hypothesis_id"),
        )
        object.__setattr__(
            self, "issue_id", _validated_identifier(self.issue_id, "$.issue_id")
        )
        if not isinstance(self.status, HypothesisStatus):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.status")
        object.__setattr__(
            self,
            "claim",
            _validated_bounded_text(self.claim, "$.claim", max_bytes=_MAX_TEXT_BYTES),
        )
        object.__setattr__(
            self,
            "security_invariant",
            _validated_bounded_text(
                self.security_invariant, "$.security_invariant", max_bytes=_MAX_TEXT_BYTES
            ),
        )
        if not isinstance(self.required_proof_kind, RequiredProofKind):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.required_proof_kind"
            )
        object.__setattr__(
            self,
            "capability_requirements",
            _validated_sorted_str_array(
                self.capability_requirements,
                "$.capability_requirements",
                cap=32,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "target_location",
            _validated_location(self.target_location, "$.target_location"),
        )
        object.__setattr__(
            self,
            "source_locations",
            _validated_location_tuple(
                self.source_locations, "$.source_locations", cap=64
            ),
        )
        object.__setattr__(
            self,
            "critical_path",
            _validated_location_tuple(self.critical_path, "$.critical_path", cap=256),
        )
        object.__setattr__(
            self,
            "trigger_conditions",
            _validated_sorted_text_array(
                self.trigger_conditions, "$.trigger_conditions", cap=64
            ),
        )
        object.__setattr__(
            self,
            "input_constraints",
            _validated_sorted_text_array(
                self.input_constraints, "$.input_constraints", cap=64
            ),
        )
        object.__setattr__(
            self,
            "evidence_ids",
            _validated_sorted_str_array(
                self.evidence_ids,
                "$.evidence_ids",
                cap=1024,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        object.__setattr__(
            self,
            "reason_codes",
            _validated_sorted_str_array(
                self.reason_codes,
                "$.reason_codes",
                cap=64,
                allow_empty=False,
                item_validator=_validated_reason_code,
            ),
        )
        object.__setattr__(
            self,
            "cwe_ids",
            _validated_sorted_str_array(
                self.cwe_ids,
                "$.cwe_ids",
                cap=32,
                allow_empty=True,
                item_validator=_validated_cwe,
            ),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_HYPOTHESIS_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "VulnerabilityHypothesis":
        data = _as_mapping(value)
        missing = [name for name in _HYPOTHESIS_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_HYPOTHESIS_WIRE_FIELDS, schema_version=schema_version
        )
        status = _wire_enum(data["status"], HypothesisStatus, "$.status")
        required_proof_kind = _wire_enum(
            data["required_proof_kind"], RequiredProofKind, "$.required_proof_kind"
        )
        try:
            target_location = SourceLocation.from_dict(
                data["target_location"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.target_location") from error
        source_locations: list[SourceLocation] = []
        for index, item in enumerate(data["source_locations"]):
            try:
                source_locations.append(
                    SourceLocation.from_dict(item, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.source_locations[{index}]") from error
        critical_path: list[SourceLocation] = []
        for index, item in enumerate(data["critical_path"]):
            try:
                critical_path.append(
                    SourceLocation.from_dict(item, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.critical_path[{index}]") from error
        return cls(
            hypothesis_id=data["hypothesis_id"],
            issue_id=data["issue_id"],
            status=status,
            claim=data["claim"],
            security_invariant=data["security_invariant"],
            required_proof_kind=required_proof_kind,
            capability_requirements=data["capability_requirements"],
            target_location=target_location,
            source_locations=source_locations,
            critical_path=critical_path,
            trigger_conditions=data["trigger_conditions"],
            input_constraints=data["input_constraints"],
            evidence_ids=data["evidence_ids"],
            reason_codes=data["reason_codes"],
            cwe_ids=data["cwe_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "hypothesis_id": self.hypothesis_id,
            "issue_id": self.issue_id,
            "status": self.status.value,
            "claim": self.claim,
            "security_invariant": self.security_invariant,
            "required_proof_kind": self.required_proof_kind.value,
            "capability_requirements": list(self.capability_requirements),
            "target_location": self.target_location.to_dict(),
            "source_locations": [location.to_dict() for location in self.source_locations],
            "critical_path": [location.to_dict() for location in self.critical_path],
            "trigger_conditions": list(self.trigger_conditions),
            "input_constraints": list(self.input_constraints),
            "evidence_ids": list(self.evidence_ids),
            "reason_codes": list(self.reason_codes),
            "cwe_ids": list(self.cwe_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _level_number(level: EvidenceLevel) -> int:
    return int(level.value[1:])


def _object_tuple(
    items: object,
    item_cls: type,
    array_name: str,
    *,
    cap: int,
) -> tuple:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"$.{array_name}")
    if len(items) > cap:
        raise ContractError(
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, f"$.{array_name}"
        )
    result = []
    for index, item in enumerate(items):
        if not isinstance(item, item_cls):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, f"$.{array_name}[{index}]"
            )
        result.append(copy.deepcopy(item))
    return tuple(result)


def _object_list(
    items: object,
    item_cls: type,
    array_name: str,
    schema_version: SchemaVersion,
) -> list:
    if not isinstance(items, list):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"$.{array_name}")
    result = []
    for index, item in enumerate(items):
        try:
            result.append(item_cls.from_dict(item, schema_version=schema_version))
        except ContractError as error:
            raise _repath(error, f"$.{array_name}[{index}]") from error
    return result


def _reject_current_minor_nested_extensions(
    *,
    signals: tuple,
    issues: tuple,
    hypotheses: tuple,
    evidence: tuple,
    version: SchemaVersion,
) -> None:
    if not _is_current_minor(version):
        return

    def check(container: dict, path: str) -> None:
        if container:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)

    for index, signal in enumerate(signals):
        check(signal.extensions, f"$.signals[{index}]")
        check(signal.location.extensions, f"$.signals[{index}].location")
    for index, issue in enumerate(issues):
        check(issue.extensions, f"$.security_issues[{index}]")
        check(
            issue.primary_location.extensions,
            f"$.security_issues[{index}].primary_location",
        )
    for index, hypothesis in enumerate(hypotheses):
        check(hypothesis.extensions, f"$.vulnerability_hypotheses[{index}]")
        check(
            hypothesis.target_location.extensions,
            f"$.vulnerability_hypotheses[{index}].target_location",
        )
        for position, location in enumerate(hypothesis.source_locations):
            check(
                location.extensions,
                f"$.vulnerability_hypotheses[{index}].source_locations[{position}]",
            )
        for position, location in enumerate(hypothesis.critical_path):
            check(
                location.extensions,
                f"$.vulnerability_hypotheses[{index}].critical_path[{position}]",
            )
    for index, record in enumerate(evidence):
        check(record.extensions, f"$.evidence[{index}]")
        if record.location is not None:
            check(record.location.extensions, f"$.evidence[{index}].location")


_BUNDLE_WIRE_FIELDS: Final = (
    "signals",
    "security_issues",
    "vulnerability_hypotheses",
    "evidence",
)
_AUDIT_ALLOWED_LEVELS: Final = (
    EvidenceLevel.D0,
    EvidenceLevel.D1,
    EvidenceLevel.D2,
)


@dataclass(frozen=True, slots=True)
class EvidenceDomainBundle:
    """The complete evidence graph for one artifact payload.

    Validates identity uniqueness across all four ID namespaces, exact
    subject/evidence binding, reference existence, the dependency DAG
    (no self edges, no cycles, no higher-level dependencies), and static
    status consistency. Audit bundles admit D0-D2 only.
    """

    schema_version: SchemaVersion
    signals: tuple[Signal, ...] = ()
    security_issues: tuple[SecurityIssue, ...] = ()
    vulnerability_hypotheses: tuple[VulnerabilityHypothesis, ...] = ()
    evidence: tuple[EvidenceRecord, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        signals = _object_tuple(self.signals, Signal, "signals", cap=10_000)
        issues = _object_tuple(
            self.security_issues, SecurityIssue, "security_issues", cap=2_048
        )
        hypotheses = _object_tuple(
            self.vulnerability_hypotheses,
            VulnerabilityHypothesis,
            "vulnerability_hypotheses",
            cap=2_048,
        )
        evidence = _object_tuple(self.evidence, EvidenceRecord, "evidence", cap=10_000)
        for array, array_name, id_field in (
            (signals, "signals", "signal_id"),
            (issues, "security_issues", "issue_id"),
            (hypotheses, "vulnerability_hypotheses", "hypothesis_id"),
            (evidence, "evidence", "evidence_id"),
        ):
            for index in range(1, len(array)):
                if getattr(array[index], id_field) <= getattr(array[index - 1], id_field):
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.{array_name}[{index}].{id_field}",
                    )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_BUNDLE_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )
        _reject_current_minor_nested_extensions(
            signals=signals,
            issues=issues,
            hypotheses=hypotheses,
            evidence=evidence,
            version=self.schema_version,
        )
        for index, record in enumerate(evidence):
            if record.level not in _AUDIT_ALLOWED_LEVELS:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.evidence[{index}].level"
                )

        seen_ids: set[str] = set()
        for array, array_name, id_field in (
            (signals, "signals", "signal_id"),
            (issues, "security_issues", "issue_id"),
            (hypotheses, "vulnerability_hypotheses", "hypothesis_id"),
            (evidence, "evidence", "evidence_id"),
        ):
            for index, item in enumerate(array):
                identifier = getattr(item, id_field)
                if identifier in seen_ids:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.{array_name}[{index}].{id_field}",
                    )
                seen_ids.add(identifier)

        signal_ids = {signal.signal_id for signal in signals}
        issues_by_id = {issue.issue_id: issue for issue in issues}
        bound_records: dict[tuple[EvidenceSubjectKind, str], list[EvidenceRecord]] = {}
        for record in evidence:
            bound_records.setdefault(
                (record.subject_kind, record.subject_id), []
            ).append(record)
        declared: dict[tuple[EvidenceSubjectKind, str], tuple[str, int, tuple[str, ...]]] = {}
        for index, signal in enumerate(signals):
            declared[(EvidenceSubjectKind.SIGNAL, signal.signal_id)] = (
                "signals",
                index,
                signal.evidence_ids,
            )
        for index, issue in enumerate(issues):
            declared[(EvidenceSubjectKind.SECURITY_ISSUE, issue.issue_id)] = (
                "security_issues",
                index,
                issue.evidence_ids,
            )
        for index, hypothesis in enumerate(hypotheses):
            declared[(EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS, hypothesis.hypothesis_id)] = (
                "vulnerability_hypotheses",
                index,
                hypothesis.evidence_ids,
            )
        for key, (array_name, index, evidence_ids) in declared.items():
            actual = {record.evidence_id for record in bound_records.get(key, [])}
            if set(evidence_ids) != actual:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.{array_name}[{index}].evidence_ids",
                )
        for index, record in enumerate(evidence):
            if (record.subject_kind, record.subject_id) not in declared:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.evidence[{index}].subject_id",
                )

        for index, issue in enumerate(issues):
            for position, referenced in enumerate(issue.signal_ids):
                if referenced not in signal_ids:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.security_issues[{index}].signal_ids[{position}]",
                    )
        for index, hypothesis in enumerate(hypotheses):
            if hypothesis.issue_id not in issues_by_id:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.vulnerability_hypotheses[{index}].issue_id",
                )
            issue_cwe = set(issues_by_id[hypothesis.issue_id].cwe_ids)
            if hypothesis.cwe_ids and not issue_cwe:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.vulnerability_hypotheses[{index}].cwe_ids[0]",
                )
            for position, cwe in enumerate(hypothesis.cwe_ids):
                if cwe not in issue_cwe:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.vulnerability_hypotheses[{index}].cwe_ids[{position}]",
                    )

        dependencies: dict[str, tuple[str, ...]] = {
            record.evidence_id: record.depends_on_evidence_ids for record in evidence
        }
        evidence_by_id = {record.evidence_id: record for record in evidence}
        index_of = {
            record.evidence_id: position for position, record in enumerate(evidence)
        }
        for index, record in enumerate(evidence):
            for position, dependency in enumerate(record.depends_on_evidence_ids):
                path = f"$.evidence[{index}].depends_on_evidence_ids[{position}]"
                if dependency == record.evidence_id:
                    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
                target = evidence_by_id.get(dependency)
                if target is None:
                    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
                if _level_number(target.level) > _level_number(record.level):
                    raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
        state: dict[str, int] = {}
        for record in evidence:
            if state.get(record.evidence_id, 0):
                continue
            stack = [(record.evidence_id, iter(dependencies[record.evidence_id]))]
            state[record.evidence_id] = 1
            while stack:
                node, iterator = stack[-1]
                successor = next(iterator, None)
                if successor is None:
                    state[node] = 2
                    stack.pop()
                    continue
                if state.get(successor, 0) == 1:
                    position = dependencies[node].index(successor)
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.evidence[{index_of[node]}].depends_on_evidence_ids[{position}]",
                    )
                if state.get(successor, 0) == 0:
                    state[successor] = 1
                    stack.append((successor, iter(dependencies[successor])))

        for index, hypothesis in enumerate(hypotheses):
            records = bound_records.get(
                (EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS, hypothesis.hypothesis_id),
                [],
            )
            has_d2_supports = any(
                item.level is EvidenceLevel.D2
                and item.polarity is EvidencePolarity.SUPPORTS
                for item in records
            )
            has_d2_refutes = any(
                item.level is EvidenceLevel.D2
                and item.polarity is EvidencePolarity.REFUTES
                for item in records
            )
            if has_d2_supports and has_d2_refutes:
                expected = HypothesisStatus.CONFLICTING_STATIC_EVIDENCE
            elif has_d2_supports:
                expected = HypothesisStatus.STATICALLY_SUPPORTED
            elif has_d2_refutes:
                expected = HypothesisStatus.STATICALLY_REFUTED
            else:
                if hypothesis.status in (
                    HypothesisStatus.PROPOSED,
                    HypothesisStatus.INSUFFICIENT_STATIC_EVIDENCE,
                ):
                    continue
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.vulnerability_hypotheses[{index}].status",
                )
            if hypothesis.status is not expected:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.vulnerability_hypotheses[{index}].status",
                )

        object.__setattr__(self, "signals", signals)
        object.__setattr__(self, "security_issues", issues)
        object.__setattr__(self, "vulnerability_hypotheses", hypotheses)
        object.__setattr__(self, "evidence", evidence)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "EvidenceDomainBundle":
        data = _as_mapping(value)
        missing = [name for name in _BUNDLE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_BUNDLE_WIRE_FIELDS, schema_version=schema_version
        )
        return cls(
            schema_version=schema_version,
            signals=_object_list(data["signals"], Signal, "signals", schema_version),
            security_issues=_object_list(
                data["security_issues"], SecurityIssue, "security_issues", schema_version
            ),
            vulnerability_hypotheses=_object_list(
                data["vulnerability_hypotheses"],
                VulnerabilityHypothesis,
                "vulnerability_hypotheses",
                schema_version,
            ),
            evidence=_object_list(
                data["evidence"], EvidenceRecord, "evidence", schema_version
            ),
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "signals": [signal.to_dict() for signal in self.signals],
            "security_issues": [issue.to_dict() for issue in self.security_issues],
            "vulnerability_hypotheses": [
                hypothesis.to_dict() for hypothesis in self.vulnerability_hypotheses
            ],
            "evidence": [record.to_dict() for record in self.evidence],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_evidence_schema_name(envelope: ArtifactEnvelope) -> None:
    if envelope.schema_name != EVIDENCE_DOMAIN_SCHEMA_NAME:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_name")


def _require_inline_payload(envelope: ArtifactEnvelope) -> None:
    if envelope.payload is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.payload")


def _require_protected_envelope(envelope: ArtifactEnvelope) -> None:
    if envelope.classification is ArtifactClassification.PUBLIC:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.classification")
    if envelope.retention_class is RetentionClass.EPHEMERAL:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.retention_class")


def _require_source_lineage(envelope: ArtifactEnvelope, bundle: EvidenceDomainBundle) -> None:
    lineage_ids = {reference.artifact_id for reference in envelope.lineage}
    for index, record in enumerate(bundle.evidence):
        for position, artifact_id in enumerate(record.source_artifact_ids):
            if artifact_id not in lineage_ids:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.payload.evidence[{index}].source_artifact_ids[{position}]",
                )


def decode_evidence_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> EvidenceDomainBundle:
    """Decode a validated payload mapping into an EvidenceDomainBundle."""
    return EvidenceDomainBundle.from_dict(value, schema_version=schema_version)


def encode_evidence_payload(bundle: EvidenceDomainBundle) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated bundle."""
    if not isinstance(bundle, EvidenceDomainBundle):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return bundle.to_dict()


def decode_evidence_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> "tuple[ArtifactEnvelope, EvidenceDomainBundle]":
    """Decode envelope bytes and return the envelope with its evidence bundle."""
    envelope = decode_envelope(data, limits=limits)
    _require_evidence_schema_name(envelope)
    _require_inline_payload(envelope)
    bundle = EvidenceDomainBundle.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_source_lineage(envelope, bundle)
    _require_protected_envelope(envelope)
    return envelope, bundle


def encode_evidence_envelope(
    envelope: ArtifactEnvelope,
    bundle: EvidenceDomainBundle,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full evidence binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(bundle, EvidenceDomainBundle):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_evidence_schema_name(envelope)
    _require_inline_payload(envelope)
    if envelope.schema_version != bundle.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_evidence_payload(bundle)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    _require_source_lineage(envelope, bundle)
    return encode_envelope(envelope, limits=limits)
