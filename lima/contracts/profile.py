"""Deterministic Repository Profile / RAM foundation contracts for LIMA (IP-0003).

Module-only leaf contracts on top of the IP-0001 artifact foundation: the
frozen classification vocabulary (repository kinds, code roles, support
level, detection method), technology declarations with provenance, code-role
assignments (file or directory-prefix scope), the five attack-surface
inventories, execution capability, structural metrics in basis points, and
the ``RepositoryProfile`` payload bound to an ``ArtifactEnvelope``. Pure
in-memory, stdlib-only, fail-closed: invalid paths, unsorted or duplicate
inventories, kind contradictions, impossible metrics, missing provenance,
and envelope binding violations are rejected, never coerced. This module
never imports :mod:`lima.contracts.evidence`; cross-artifact facts travel
only through IP-0001 ``ArtifactReference`` lineage.
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
    "REPOSITORY_PROFILE_SCHEMA_NAME",
    "RepositoryKind",
    "CodeRole",
    "SupportLevel",
    "DetectionMethod",
    "ExecutionCapability",
    "TechnologyDeclaration",
    "CodeRoleAssignment",
    "AttackSurfaceEntry",
    "ProfileCoverageGap",
    "RepositoryProfile",
    "decode_profile_payload",
    "encode_profile_payload",
    "decode_profile_envelope",
    "encode_profile_envelope",
]

REPOSITORY_PROFILE_SCHEMA_NAME = "lima.repository-profile"

_MAX_PATH_BYTES: Final[int] = 1024
_MAX_SYMBOL_BYTES: Final[int] = 512
_MAX_DETAIL_BYTES: Final[int] = 4096
_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_BASIS_POINTS: Final[int] = 10_000

_TECHNOLOGY_NAME_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,127}")
_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
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


def _validated_technology_name(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _TECHNOLOGY_NAME_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_identifier(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_reason_code(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _REASON_CODE_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


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


def _validated_bool(value: object, path: str) -> bool:
    if type(value) is not bool:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    return value


def _validated_int(
    value: object,
    path: str,
    *,
    minimum: int,
    maximum: int,
) -> int:
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if not minimum <= value <= maximum:
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


class RepositoryKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0003 §10
    """Repository shape classification; multiple kinds per profile are legal."""

    APPLICATION = "application"
    LIBRARY = "library"
    CLI = "cli"
    DOCS_CONTENT = "docs_content"
    MONOREPO = "monorepo"
    DATASET_ASSET = "dataset_asset"
    UNKNOWN = "unknown"


class CodeRole(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0003 §10
    """Role a path (file or directory prefix) plays for analysis scoping."""

    PRODUCTION = "production"
    TEST = "test"
    EXAMPLE = "example"
    DEV_TOOL = "dev_tool"
    GENERATED = "generated"
    VENDORED = "vendored"
    CONFIG = "config"
    DOCUMENTATION = "documentation"


class SupportLevel(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0003 §10
    """Platform support commitment; explicitly not a security verdict."""

    SUPPORTED = "supported"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"


class DetectionMethod(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0003 §10
    """How a technology declaration was established."""

    DECLARED = "declared"
    INFERRED = "inferred"


_EXECUTION_CAPABILITY_WIRE_FIELDS: Final = (
    "buildable",
    "testable",
    "requires_network",
    "requires_services",
    "requires_gpu",
    "requires_external_credentials",
)


@dataclass(frozen=True, slots=True)
class ExecutionCapability:
    """Six required execution facts; all are exact bools with no defaults."""

    buildable: bool
    testable: bool
    requires_network: bool
    requires_services: bool
    requires_gpu: bool
    requires_external_credentials: bool
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        for name in _EXECUTION_CAPABILITY_WIRE_FIELDS:
            object.__setattr__(
                self, name, _validated_bool(getattr(self, name), f"$.{name}")
            )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_EXECUTION_CAPABILITY_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "ExecutionCapability":
        data = _as_mapping(value)
        missing = [
            name for name in _EXECUTION_CAPABILITY_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_EXECUTION_CAPABILITY_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            buildable=data["buildable"],
            testable=data["testable"],
            requires_network=data["requires_network"],
            requires_services=data["requires_services"],
            requires_gpu=data["requires_gpu"],
            requires_external_credentials=data["requires_external_credentials"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "buildable": self.buildable,
            "testable": self.testable,
            "requires_network": self.requires_network,
            "requires_services": self.requires_services,
            "requires_gpu": self.requires_gpu,
            "requires_external_credentials": self.requires_external_credentials,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_TECHNOLOGY_DECLARATION_WIRE_FIELDS: Final = (
    "name",
    "detection",
    "source_artifact_ids",
)


@dataclass(frozen=True, slots=True)
class TechnologyDeclaration:
    """One language/framework/package-manager/build-system entry with provenance."""

    name: str
    detection: DetectionMethod
    source_artifact_ids: tuple[str, ...]
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "name", _validated_technology_name(self.name, "$.name")
        )
        if not isinstance(self.detection, DetectionMethod):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.detection")
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
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_TECHNOLOGY_DECLARATION_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "TechnologyDeclaration":
        data = _as_mapping(value)
        missing = [
            name for name in _TECHNOLOGY_DECLARATION_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_TECHNOLOGY_DECLARATION_WIRE_FIELDS,
            schema_version=schema_version,
        )
        detection = _wire_enum(data["detection"], DetectionMethod, "$.detection")
        return cls(
            name=data["name"],
            detection=detection,
            source_artifact_ids=data["source_artifact_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "name": self.name,
            "detection": self.detection.value,
            "source_artifact_ids": list(self.source_artifact_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_CODE_ROLE_ASSIGNMENT_WIRE_FIELDS: Final = (
    "role",
    "path",
    "reason_codes",
    "source_artifact_ids",
)


@dataclass(frozen=True, slots=True)
class CodeRoleAssignment:
    """Role assigned to a file path or directory prefix with combined evidence."""

    role: CodeRole
    path: str
    reason_codes: tuple[str, ...]
    source_artifact_ids: tuple[str, ...]
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.role, CodeRole):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.role")
        object.__setattr__(self, "path", _validated_path(self.path, "$.path"))
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
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_CODE_ROLE_ASSIGNMENT_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "CodeRoleAssignment":
        data = _as_mapping(value)
        missing = [
            name for name in _CODE_ROLE_ASSIGNMENT_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_CODE_ROLE_ASSIGNMENT_WIRE_FIELDS,
            schema_version=schema_version,
        )
        role = _wire_enum(data["role"], CodeRole, "$.role")
        return cls(
            role=role,
            path=data["path"],
            reason_codes=data["reason_codes"],
            source_artifact_ids=data["source_artifact_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "role": self.role.value,
            "path": self.path,
            "reason_codes": list(self.reason_codes),
            "source_artifact_ids": list(self.source_artifact_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_ATTACK_SURFACE_ENTRY_WIRE_FIELDS: Final = (
    "path",
    "reason_codes",
    "source_artifact_ids",
    "symbol",
)


@dataclass(frozen=True, slots=True)
class AttackSurfaceEntry:
    """One inventory entry across the five attack-surface lists."""

    path: str
    reason_codes: tuple[str, ...]
    source_artifact_ids: tuple[str, ...]
    symbol: str | None = None
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "path", _validated_path(self.path, "$.path"))
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
            "source_artifact_ids",
            _validated_sorted_str_array(
                self.source_artifact_ids,
                "$.source_artifact_ids",
                cap=32,
                allow_empty=False,
                item_validator=_validated_identifier,
            ),
        )
        if self.symbol is not None:
            object.__setattr__(
                self,
                "symbol",
                _validated_bounded_text(
                    self.symbol, "$.symbol", max_bytes=_MAX_SYMBOL_BYTES
                ),
            )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_ATTACK_SURFACE_ENTRY_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "AttackSurfaceEntry":
        data = _as_mapping(value)
        missing = [
            name for name in _ATTACK_SURFACE_ENTRY_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_ATTACK_SURFACE_ENTRY_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            path=data["path"],
            reason_codes=data["reason_codes"],
            source_artifact_ids=data["source_artifact_ids"],
            symbol=data["symbol"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "path": self.path,
            "reason_codes": list(self.reason_codes),
            "source_artifact_ids": list(self.source_artifact_ids),
            "symbol": self.symbol,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_PROFILE_COVERAGE_GAP_WIRE_FIELDS: Final = ("gap_code", "detail")


@dataclass(frozen=True, slots=True)
class ProfileCoverageGap:
    """Machine-readable coverage limitation of this profile."""

    gap_code: str
    detail: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "gap_code", _validated_reason_code(self.gap_code, "$.gap_code")
        )
        object.__setattr__(
            self,
            "detail",
            _validated_bounded_text(
                self.detail, "$.detail", max_bytes=_MAX_DETAIL_BYTES
            ),
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_PROFILE_COVERAGE_GAP_WIRE_FIELDS,
                version=None,
                path="$",
            ),
        )

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "ProfileCoverageGap":
        data = _as_mapping(value)
        missing = [
            name for name in _PROFILE_COVERAGE_GAP_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data,
            known_fields=_PROFILE_COVERAGE_GAP_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            gap_code=data["gap_code"],
            detail=data["detail"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "gap_code": self.gap_code,
            "detail": self.detail,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_PROFILE_WIRE_FIELDS: Final = (
    "repository_kinds",
    "languages",
    "frameworks",
    "package_managers",
    "build_systems",
    "code_roles",
    "entrypoints",
    "external_inputs",
    "trust_boundaries",
    "sensitive_operations",
    "deployment_surface",
    "execution_capability",
    "support_level",
    "component_path",
    "file_count",
    "total_bytes",
    "max_file_bytes",
    "code_density_bp",
    "binary_ratio_bp",
    "generated_ratio_bp",
    "coverage_gaps",
)
_CODE_KINDS_REQUIRING_LANGUAGES: Final = (
    RepositoryKind.APPLICATION,
    RepositoryKind.LIBRARY,
    RepositoryKind.CLI,
    RepositoryKind.MONOREPO,
)


def _object_tuple(items, item_cls, array_name, *, cap):
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


def _object_list(items, item_cls, array_name, schema_version):
    if not isinstance(items, list):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"$.{array_name}")
    result = []
    for index, item in enumerate(items):
        try:
            result.append(item_cls.from_dict(item, schema_version=schema_version))
        except ContractError as error:
            raise _repath(error, f"$.{array_name}[{index}]") from error
    return result


def _require_sorted_by_key(items, key_function, path):
    for index in range(1, len(items)):
        if key_function(items[index]) <= key_function(items[index - 1]):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]"
            )


def _reject_current_minor_nested_extensions(
    *,
    execution_capability,
    languages,
    frameworks,
    package_managers,
    build_systems,
    code_roles,
    entrypoints,
    external_inputs,
    trust_boundaries,
    sensitive_operations,
    deployment_surface,
    coverage_gaps,
    version,
):
    if not _is_current_minor(version):
        return

    def check(container, path):
        if container:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, path)

    check(execution_capability.extensions, "$.execution_capability")
    for array_name, array in (
        ("languages", languages),
        ("frameworks", frameworks),
        ("package_managers", package_managers),
        ("build_systems", build_systems),
        ("code_roles", code_roles),
        ("entrypoints", entrypoints),
        ("external_inputs", external_inputs),
        ("trust_boundaries", trust_boundaries),
        ("sensitive_operations", sensitive_operations),
        ("deployment_surface", deployment_surface),
        ("coverage_gaps", coverage_gaps),
    ):
        for index, item in enumerate(array):
            check(item.extensions, f"$.{array_name}[{index}]")


@dataclass(frozen=True, slots=True)
class RepositoryProfile:
    """Versioned, provenance-complete classification of one repository scope."""

    schema_version: SchemaVersion
    repository_kinds: tuple[RepositoryKind, ...]
    execution_capability: ExecutionCapability
    support_level: SupportLevel
    component_path: str | None
    file_count: int
    total_bytes: int
    max_file_bytes: int
    code_density_bp: int
    binary_ratio_bp: int
    generated_ratio_bp: int
    languages: tuple[TechnologyDeclaration, ...] = ()
    frameworks: tuple[TechnologyDeclaration, ...] = ()
    package_managers: tuple[TechnologyDeclaration, ...] = ()
    build_systems: tuple[TechnologyDeclaration, ...] = ()
    code_roles: tuple[CodeRoleAssignment, ...] = ()
    entrypoints: tuple[AttackSurfaceEntry, ...] = ()
    external_inputs: tuple[AttackSurfaceEntry, ...] = ()
    trust_boundaries: tuple[AttackSurfaceEntry, ...] = ()
    sensitive_operations: tuple[AttackSurfaceEntry, ...] = ()
    deployment_surface: tuple[AttackSurfaceEntry, ...] = ()
    coverage_gaps: tuple[ProfileCoverageGap, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        kinds = self._validated_kinds()
        if not isinstance(self.execution_capability, ExecutionCapability):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.execution_capability"
            )
        execution_capability = copy.deepcopy(self.execution_capability)
        if not isinstance(self.support_level, SupportLevel):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.support_level")
        if self.component_path is not None:
            object.__setattr__(
                self,
                "component_path",
                _validated_path(self.component_path, "$.component_path"),
            )
        file_count = _validated_int(
            self.file_count, "$.file_count", minimum=0, maximum=_INT64_MAX
        )
        total_bytes = _validated_int(
            self.total_bytes, "$.total_bytes", minimum=0, maximum=_INT64_MAX
        )
        max_file_bytes = _validated_int(
            self.max_file_bytes, "$.max_file_bytes", minimum=0, maximum=_INT64_MAX
        )
        code_density_bp = _validated_int(
            self.code_density_bp,
            "$.code_density_bp",
            minimum=0,
            maximum=_MAX_BASIS_POINTS,
        )
        binary_ratio_bp = _validated_int(
            self.binary_ratio_bp,
            "$.binary_ratio_bp",
            minimum=0,
            maximum=_MAX_BASIS_POINTS,
        )
        generated_ratio_bp = _validated_int(
            self.generated_ratio_bp,
            "$.generated_ratio_bp",
            minimum=0,
            maximum=_MAX_BASIS_POINTS,
        )
        languages = _object_tuple(
            self.languages, TechnologyDeclaration, "languages", cap=64
        )
        frameworks = _object_tuple(
            self.frameworks, TechnologyDeclaration, "frameworks", cap=64
        )
        package_managers = _object_tuple(
            self.package_managers, TechnologyDeclaration, "package_managers", cap=32
        )
        build_systems = _object_tuple(
            self.build_systems, TechnologyDeclaration, "build_systems", cap=32
        )
        code_roles = _object_tuple(
            self.code_roles, CodeRoleAssignment, "code_roles", cap=2048
        )
        entrypoints = _object_tuple(
            self.entrypoints, AttackSurfaceEntry, "entrypoints", cap=256
        )
        external_inputs = _object_tuple(
            self.external_inputs, AttackSurfaceEntry, "external_inputs", cap=256
        )
        trust_boundaries = _object_tuple(
            self.trust_boundaries, AttackSurfaceEntry, "trust_boundaries", cap=256
        )
        sensitive_operations = _object_tuple(
            self.sensitive_operations, AttackSurfaceEntry, "sensitive_operations", cap=256
        )
        deployment_surface = _object_tuple(
            self.deployment_surface, AttackSurfaceEntry, "deployment_surface", cap=256
        )
        coverage_gaps = _object_tuple(
            self.coverage_gaps, ProfileCoverageGap, "coverage_gaps", cap=256
        )
        for array, array_name in (
            (languages, "languages"),
            (frameworks, "frameworks"),
            (package_managers, "package_managers"),
            (build_systems, "build_systems"),
        ):
            _require_sorted_by_key(array, lambda item: item.name, f"$.{array_name}")
        _require_sorted_by_key(
            code_roles,
            lambda item: (item.role.value, item.path),
            "$.code_roles",
        )
        for array, array_name in (
            (entrypoints, "entrypoints"),
            (external_inputs, "external_inputs"),
            (trust_boundaries, "trust_boundaries"),
            (sensitive_operations, "sensitive_operations"),
            (deployment_surface, "deployment_surface"),
        ):
            _require_sorted_by_key(
                array,
                lambda item: (item.path, item.symbol if item.symbol is not None else ""),
                f"$.{array_name}",
            )
        _require_sorted_by_key(
            coverage_gaps,
            lambda item: (item.gap_code, item.detail.encode("utf-8")),
            "$.coverage_gaps",
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_PROFILE_WIRE_FIELDS,
                version=self.schema_version,
                path="$",
            ),
        )
        _reject_current_minor_nested_extensions(
            execution_capability=execution_capability,
            languages=languages,
            frameworks=frameworks,
            package_managers=package_managers,
            build_systems=build_systems,
            code_roles=code_roles,
            entrypoints=entrypoints,
            external_inputs=external_inputs,
            trust_boundaries=trust_boundaries,
            sensitive_operations=sensitive_operations,
            deployment_surface=deployment_surface,
            coverage_gaps=coverage_gaps,
            version=self.schema_version,
        )
        if RepositoryKind.UNKNOWN in kinds and len(kinds) > 1:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE,
                f"$.repository_kinds[{kinds.index(RepositoryKind.UNKNOWN)}]",
            )
        if not languages and any(
            kind in _CODE_KINDS_REQUIRING_LANGUAGES for kind in kinds
        ):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.languages")
        if max_file_bytes > total_bytes:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.max_file_bytes")
        if file_count == 0 and total_bytes != 0:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.total_bytes")
        if file_count == 0 and max_file_bytes != 0:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.max_file_bytes")
        object.__setattr__(self, "repository_kinds", kinds)
        object.__setattr__(self, "execution_capability", execution_capability)
        object.__setattr__(self, "file_count", file_count)
        object.__setattr__(self, "total_bytes", total_bytes)
        object.__setattr__(self, "max_file_bytes", max_file_bytes)
        object.__setattr__(self, "code_density_bp", code_density_bp)
        object.__setattr__(self, "binary_ratio_bp", binary_ratio_bp)
        object.__setattr__(self, "generated_ratio_bp", generated_ratio_bp)
        object.__setattr__(self, "languages", languages)
        object.__setattr__(self, "frameworks", frameworks)
        object.__setattr__(self, "package_managers", package_managers)
        object.__setattr__(self, "build_systems", build_systems)
        object.__setattr__(self, "code_roles", code_roles)
        object.__setattr__(self, "entrypoints", entrypoints)
        object.__setattr__(self, "external_inputs", external_inputs)
        object.__setattr__(self, "trust_boundaries", trust_boundaries)
        object.__setattr__(self, "sensitive_operations", sensitive_operations)
        object.__setattr__(self, "deployment_surface", deployment_surface)
        object.__setattr__(self, "coverage_gaps", coverage_gaps)

    def _validated_kinds(self) -> tuple[RepositoryKind, ...]:
        kinds = self.repository_kinds
        if not isinstance(kinds, (list, tuple)):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.repository_kinds"
            )
        if len(kinds) > 8:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.repository_kinds"
            )
        for index, kind in enumerate(kinds):
            if not isinstance(kind, RepositoryKind):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.repository_kinds[{index}]"
                )
        if not kinds:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.repository_kinds"
            )
        wire_values = [kind.value for kind in kinds]
        for index in range(1, len(wire_values)):
            if wire_values[index] <= wire_values[index - 1]:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.repository_kinds[{index}]",
                )
        return tuple(kinds)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "RepositoryProfile":
        data = _as_mapping(value)
        missing = [name for name in _PROFILE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        extensions = _split_extensions(
            data, known_fields=_PROFILE_WIRE_FIELDS, schema_version=schema_version
        )
        if not isinstance(data["repository_kinds"], list):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.repository_kinds"
            )
        kinds = [
            _wire_enum(kind, RepositoryKind, f"$.repository_kinds[{index}]")
            for index, kind in enumerate(data["repository_kinds"])
        ]
        if not isinstance(data["execution_capability"], Mapping):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.execution_capability"
            )
        try:
            execution_capability = ExecutionCapability.from_dict(
                data["execution_capability"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.execution_capability") from error
        support_level = _wire_enum(data["support_level"], SupportLevel, "$.support_level")
        return cls(
            schema_version=schema_version,
            repository_kinds=kinds,
            execution_capability=execution_capability,
            support_level=support_level,
            component_path=data["component_path"],
            file_count=data["file_count"],
            total_bytes=data["total_bytes"],
            max_file_bytes=data["max_file_bytes"],
            code_density_bp=data["code_density_bp"],
            binary_ratio_bp=data["binary_ratio_bp"],
            generated_ratio_bp=data["generated_ratio_bp"],
            languages=_object_list(
                data["languages"], TechnologyDeclaration, "languages", schema_version
            ),
            frameworks=_object_list(
                data["frameworks"], TechnologyDeclaration, "frameworks", schema_version
            ),
            package_managers=_object_list(
                data["package_managers"],
                TechnologyDeclaration,
                "package_managers",
                schema_version,
            ),
            build_systems=_object_list(
                data["build_systems"],
                TechnologyDeclaration,
                "build_systems",
                schema_version,
            ),
            code_roles=_object_list(
                data["code_roles"], CodeRoleAssignment, "code_roles", schema_version
            ),
            entrypoints=_object_list(
                data["entrypoints"], AttackSurfaceEntry, "entrypoints", schema_version
            ),
            external_inputs=_object_list(
                data["external_inputs"],
                AttackSurfaceEntry,
                "external_inputs",
                schema_version,
            ),
            trust_boundaries=_object_list(
                data["trust_boundaries"],
                AttackSurfaceEntry,
                "trust_boundaries",
                schema_version,
            ),
            sensitive_operations=_object_list(
                data["sensitive_operations"],
                AttackSurfaceEntry,
                "sensitive_operations",
                schema_version,
            ),
            deployment_surface=_object_list(
                data["deployment_surface"],
                AttackSurfaceEntry,
                "deployment_surface",
                schema_version,
            ),
            coverage_gaps=_object_list(
                data["coverage_gaps"], ProfileCoverageGap, "coverage_gaps", schema_version
            ),
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "repository_kinds": [kind.value for kind in self.repository_kinds],
            "languages": [item.to_dict() for item in self.languages],
            "frameworks": [item.to_dict() for item in self.frameworks],
            "package_managers": [
                item.to_dict() for item in self.package_managers
            ],
            "build_systems": [item.to_dict() for item in self.build_systems],
            "code_roles": [item.to_dict() for item in self.code_roles],
            "entrypoints": [item.to_dict() for item in self.entrypoints],
            "external_inputs": [item.to_dict() for item in self.external_inputs],
            "trust_boundaries": [item.to_dict() for item in self.trust_boundaries],
            "sensitive_operations": [
                item.to_dict() for item in self.sensitive_operations
            ],
            "deployment_surface": [
                item.to_dict() for item in self.deployment_surface
            ],
            "execution_capability": self.execution_capability.to_dict(),
            "support_level": self.support_level.value,
            "component_path": self.component_path,
            "file_count": self.file_count,
            "total_bytes": self.total_bytes,
            "max_file_bytes": self.max_file_bytes,
            "code_density_bp": self.code_density_bp,
            "binary_ratio_bp": self.binary_ratio_bp,
            "generated_ratio_bp": self.generated_ratio_bp,
            "coverage_gaps": [item.to_dict() for item in self.coverage_gaps],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_profile_schema_name(envelope: ArtifactEnvelope) -> None:
    if envelope.schema_name != REPOSITORY_PROFILE_SCHEMA_NAME:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_name")


def _require_inline_payload(envelope: ArtifactEnvelope) -> None:
    if envelope.payload is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.payload")


def _require_protected_envelope(envelope: ArtifactEnvelope) -> None:
    if envelope.classification is ArtifactClassification.PUBLIC:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.classification")
    if envelope.retention_class is RetentionClass.EPHEMERAL:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.retention_class")


def _require_source_lineage(
    envelope: ArtifactEnvelope, profile: RepositoryProfile
) -> None:
    lineage_ids = {reference.artifact_id for reference in envelope.lineage}
    provenance_arrays = (
        ("languages", profile.languages),
        ("frameworks", profile.frameworks),
        ("package_managers", profile.package_managers),
        ("build_systems", profile.build_systems),
        ("code_roles", profile.code_roles),
        ("entrypoints", profile.entrypoints),
        ("external_inputs", profile.external_inputs),
        ("trust_boundaries", profile.trust_boundaries),
        ("sensitive_operations", profile.sensitive_operations),
        ("deployment_surface", profile.deployment_surface),
    )
    for array_name, array in provenance_arrays:
        for index, item in enumerate(array):
            for position, artifact_id in enumerate(item.source_artifact_ids):
                if artifact_id not in lineage_ids:
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE,
                        f"$.payload.{array_name}[{index}]"
                        f".source_artifact_ids[{position}]",
                    )


def decode_profile_payload(
    value: Mapping[str, JSONValue],
    *,
    schema_version: SchemaVersion,
) -> RepositoryProfile:
    """Decode a validated payload mapping into a RepositoryProfile."""
    return RepositoryProfile.from_dict(value, schema_version=schema_version)


def encode_profile_payload(profile: RepositoryProfile) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated profile."""
    if not isinstance(profile, RepositoryProfile):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return profile.to_dict()


def decode_profile_envelope(
    data: bytes,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> "tuple[ArtifactEnvelope, RepositoryProfile]":
    """Decode envelope bytes and return the envelope with its repository profile."""
    envelope = decode_envelope(data, limits=limits)
    _require_profile_schema_name(envelope)
    _require_inline_payload(envelope)
    profile = RepositoryProfile.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_source_lineage(envelope, profile)
    _require_protected_envelope(envelope)
    return envelope, profile


def encode_profile_envelope(
    envelope: ArtifactEnvelope,
    profile: RepositoryProfile,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full profile binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(profile, RepositoryProfile):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_profile_schema_name(envelope)
    _require_inline_payload(envelope)
    if envelope.schema_version != profile.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_profile_payload(profile)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    _require_source_lineage(envelope, profile)
    return encode_envelope(envelope, limits=limits)
