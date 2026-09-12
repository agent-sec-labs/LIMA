"""Manifest domain contracts for LIMA (IP-0012).

Module-only leaf contracts on top of the IP-0001 artifact foundation for
the four manifest schemas of FR-02: ``TaskManifest`` (mining intent),
``ToolBundle`` (tool inventory), ``DependencyManifest`` (lock snapshot),
and ``SandboxRun`` (execution record). All payloads carry zero floats,
zero timestamps, zero free text, and zero runtime state. Every
cross-artifact reference travels through the local :class:`ManifestLink`
value type (ManifestReferenceKind literal + artifact_id + content_digest
+ schema_version) and is double-checked against typed envelope lineage;
untyped id lists (hypothesis ids, log artifact ids) are
lineage-existence-checked only. Pure in-memory, stdlib-only, fail-closed.
Dependency direction is fixed: this module may import only
``codec``/``common``/``errors`` — never any other domain module. The
schema_name wire values ``lima.task-manifest``, ``lima.tool-bundle``,
``lima.dependency-manifest``, and ``lima.sandbox-run`` are frozen string
literals (IP-0012 Packet section 7, decision D1).

Vocabulary clarifications frozen by the IP-0012 decision records:
DR-IP-0012-LIMIT-01 (identifier/version/license byte caps are carried by
their closed character classes and report ``INVALID_FIELD_VALUE`` at the
boundary, while the argv/mount 512-byte word gate is an independent
explicit length gate reporting ``MAX_STRING_LENGTH_EXCEEDED``),
DR-IP-0012-FROZEN-CONFLICT-01 ruling DR-1 C1 (the command word class is
the Packet class plus U+0020, with a leading ``/`` still rejected as an
absolute path), and ruling DR-2 (the task/sandbox ``network_policy``
consistency is expressed at the envelope digest binding layer, not
inside the single-payload decode, whose contract-layer duty is the
closed vocabulary only).
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
    "TASK_MANIFEST_SCHEMA_NAME",
    "TOOL_BUNDLE_SCHEMA_NAME",
    "DEPENDENCY_MANIFEST_SCHEMA_NAME",
    "SANDBOX_RUN_SCHEMA_NAME",
    "ManifestReferenceKind",
    "OracleKind",
    "NetworkPolicy",
    "ManifestLink",
    "TaskManifest",
    "ToolBundle",
    "DependencyManifest",
    "SandboxRun",
    "decode_task_manifest_payload",
    "encode_task_manifest_payload",
    "decode_task_manifest_envelope",
    "encode_task_manifest_envelope",
    "decode_tool_bundle_payload",
    "encode_tool_bundle_payload",
    "decode_tool_bundle_envelope",
    "encode_tool_bundle_envelope",
    "decode_dependency_manifest_payload",
    "encode_dependency_manifest_payload",
    "decode_dependency_manifest_envelope",
    "encode_dependency_manifest_envelope",
    "decode_sandbox_run_payload",
    "encode_sandbox_run_payload",
    "decode_sandbox_run_envelope",
    "encode_sandbox_run_envelope",
]

TASK_MANIFEST_SCHEMA_NAME = "lima.task-manifest"
TOOL_BUNDLE_SCHEMA_NAME = "lima.tool-bundle"
DEPENDENCY_MANIFEST_SCHEMA_NAME = "lima.dependency-manifest"
SANDBOX_RUN_SCHEMA_NAME = "lima.sandbox-run"

_INT64_MAX: Final[int] = (1 << 63) - 1
_MAX_HYPOTHESIS_IDS: Final[int] = 32
_MAX_TASK_TOOL_BUNDLES: Final[int] = 8
_MAX_TASK_DEPENDENCIES: Final[int] = 8
_MAX_TOOL_ENTRIES: Final[int] = 256
_MAX_DEPENDENCY_ENTRIES: Final[int] = 512
_MAX_SANDBOX_TOOL_BUNDLES: Final[int] = 8
_MAX_MOUNTS: Final[int] = 64
_MAX_COMMANDS: Final[int] = 16
_MAX_WORDS_PER_COMMAND: Final[int] = 32
_MAX_LOG_ARTIFACT_IDS: Final[int] = 4
_MAX_WORD_BYTES: Final[int] = 512
_CPU_SECONDS_MAX: Final[int] = (1 << 31) - 1
_MEMORY_MB_MAX: Final[int] = 1 << 21
_MAX_PROCESSES_MAX: Final[int] = 4096
_EXIT_CODE_MIN: Final[int] = -128
_EXIT_CODE_MAX: Final[int] = 255

_IDENTIFIER_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_DIGEST_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
_LICENSE_WORD_PATTERN: Final = re.compile(r"[A-Za-z0-9.-]{1,64}")
_VERSION_STR_PATTERN: Final = re.compile(r"[A-Za-z0-9.+*!~-]{1,128}")
# DR-1 C1: the Packet command word class plus U+0020; leading "/" stays
# rejected by the absolute-path rule below.
_WORD_PATTERN: Final = re.compile(r"[A-Za-z0-9_./:=, -]+")
_MOUNT_PATTERN: Final = re.compile(r"[A-Za-z0-9_./-]+")


class ManifestReferenceKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0012 §7
    """Referable manifest kinds; each wire value is the schema_name literal."""

    TASK_MANIFEST = "lima.task-manifest"
    TOOL_BUNDLE = "lima.tool-bundle"
    DEPENDENCY_MANIFEST = "lima.dependency-manifest"
    SANDBOX_RUN = "lima.sandbox-run"


class OracleKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0012 §8
    """Minimal vocabulary of the task mining oracle declaration."""

    DETERMINISTIC_EXIT = "deterministic_exit"
    DIFFERENTIAL_OUTPUT = "differential_output"
    PROPERTY_ASSERTION = "property_assertion"


class NetworkPolicy(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0012 §8
    """Closed network posture vocabulary shared by task and sandbox run."""

    DENY_ALL = "deny_all"
    EGRESS_ALLOWLIST = "egress_allowlist"


class _SourceKind(str, Enum):  # noqa: UP042 -- wire values frozen by IP-0012 §8
    """Closed dependency source vocabulary; private (not on the 28-symbol face)."""

    REGISTRY = "registry"
    VCS = "vcs"
    PATH = "path"


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
    # The {0,127} quantifier carries the 128-byte field cap; reaching it is a
    # vocabulary violation (DR-IP-0012-LIMIT-01), not a separate length gate.
    if _IDENTIFIER_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_digest(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if _DIGEST_PATTERN.fullmatch(value) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_license_word(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _LICENSE_WORD_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_version_str(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _VERSION_STR_PATTERN.fullmatch(normalized) is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return normalized


def _validated_word(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _WORD_PATTERN.fullmatch(normalized) is None or normalized.startswith("/"):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    # Independent explicit length gate for argv/mount words (Packet section 12;
    # DR-IP-0012-LIMIT-01 reserves this code for the pattern-free gate).
    if len(normalized.encode("utf-8")) > _MAX_WORD_BYTES:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    return normalized


def _validated_mount(value: object, path: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    normalized = unicodedata.normalize("NFC", value)
    if _MOUNT_PATTERN.fullmatch(normalized) is None or normalized.startswith("/"):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if ".." in normalized.split("/"):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    if len(normalized.encode("utf-8")) > _MAX_WORD_BYTES:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED, path)
    return normalized


def _validated_revision(value: object, path: str) -> int:
    # Exact type check: bool is an int subclass and must still be rejected.
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if not 1 <= value <= _INT64_MAX:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, path)
    return value


def _validated_ranged_int(
    value: object, path: str, *, minimum: int, maximum: int
) -> int:
    # Exact type check: bool is an int subclass and must still be rejected.
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if not minimum <= value <= maximum:
        raise ContractError(ContractErrorCode.INTEGER_OUT_OF_RANGE, path)
    return value


def _validated_extensions(
    extensions: object,
    *,
    known_fields: tuple[str, ...],
    path: str,
) -> dict[str, JSONValue]:
    if not isinstance(extensions, dict):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
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


def _validated_sorted_unique(
    items: object,
    path: str,
    *,
    cap: int,
    validate_item,
) -> tuple:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    validated = [
        validate_item(item, f"{path}[{index}]") for index, item in enumerate(items)
    ]
    for index in range(1, len(validated)):
        if validated[index] <= validated[index - 1]:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]"
            )
    return tuple(validated)


_MANIFEST_LINK_WIRE_FIELDS: Final = (
    "kind",
    "artifact_id",
    "content_digest",
    "schema_version",
)


@dataclass(frozen=True, slots=True)
class ManifestLink:
    """Typed local reference to another manifest: kind literal + identity triple."""

    kind: ManifestReferenceKind
    artifact_id: str
    content_digest: str
    schema_version: SchemaVersion
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ManifestReferenceKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.kind")
        artifact_id = _validated_identifier(self.artifact_id, "$.artifact_id")
        content_digest = _validated_digest(self.content_digest, "$.content_digest")
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_MANIFEST_LINK_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "artifact_id", artifact_id)
        object.__setattr__(self, "content_digest", content_digest)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "ManifestLink":
        data = _as_mapping(value)
        missing = [name for name in _MANIFEST_LINK_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data,
            known_fields=_MANIFEST_LINK_WIRE_FIELDS,
            schema_version=schema_version,
        )
        kind = _wire_enum(data["kind"], ManifestReferenceKind, "$.kind")
        return cls(
            kind=kind,
            artifact_id=data["artifact_id"],
            content_digest=data["content_digest"],
            schema_version=SchemaVersion.parse(data["schema_version"]),
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "kind": self.kind.value,
            "artifact_id": self.artifact_id,
            "content_digest": self.content_digest,
            "schema_version": str(self.schema_version),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _parse_link_array(
    items: object,
    path: str,
    *,
    schema_version: SchemaVersion,
) -> list[ManifestLink]:
    if not isinstance(items, list):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    links: list[ManifestLink] = []
    for index, item in enumerate(items):
        if not isinstance(item, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"{path}[{index}]")
        try:
            links.append(ManifestLink.from_dict(item, schema_version=schema_version))
        except ContractError as error:
            raise _repath(error, f"{path}[{index}]") from error
    return links


def _validated_link_tuple(
    items: object,
    path: str,
    *,
    cap: int,
) -> tuple[ManifestLink, ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > cap:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    links = []
    for index, item in enumerate(items):
        if not isinstance(item, ManifestLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"{path}[{index}]")
        links.append(copy.deepcopy(item))
    result = tuple(links)
    for index in range(1, len(result)):
        if result[index].artifact_id <= result[index - 1].artifact_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}].artifact_id"
            )
    return result


def _validated_command_tuple(
    items: object, path: str
) -> tuple[tuple[str, ...], ...]:
    if not isinstance(items, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(items) > _MAX_COMMANDS:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    commands: list[tuple[str, ...]] = []
    for index, command in enumerate(items):
        commands.append(_validated_single_command(command, f"{path}[{index}]"))
    return tuple(commands)


def _validated_single_command(command: object, path: str) -> tuple[str, ...]:
    if not isinstance(command, (list, tuple)):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, path)
    if len(command) > _MAX_WORDS_PER_COMMAND:
        raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, path)
    return tuple(
        _validated_word(word, f"{path}[{word_index}]")
        for word_index, word in enumerate(command)
    )


_TASK_WIRE_FIELDS: Final = (
    "revision",
    "hypothesis_ids",
    "tool_bundles",
    "dependencies",
    "harness_commands",
    "oracle_kind",
    "network_policy",
)


@dataclass(frozen=True, slots=True)
class TaskManifest:
    """Mining task declaration: hypotheses, tool/dependency links, harness plan."""

    schema_version: SchemaVersion
    revision: int
    oracle_kind: OracleKind
    network_policy: NetworkPolicy
    hypothesis_ids: tuple[str, ...] = ()
    tool_bundles: tuple[ManifestLink, ...] = ()
    dependencies: tuple[ManifestLink, ...] = ()
    harness_commands: tuple[tuple[str, ...], ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        revision = _validated_revision(self.revision, "$.revision")
        hypothesis_ids = _validated_sorted_unique(
            self.hypothesis_ids,
            "$.hypothesis_ids",
            cap=_MAX_HYPOTHESIS_IDS,
            validate_item=_validated_identifier,
        )
        tool_bundles = _validated_link_tuple(
            self.tool_bundles, "$.tool_bundles", cap=_MAX_TASK_TOOL_BUNDLES
        )
        for index, link in enumerate(tool_bundles):
            if link.kind is not ManifestReferenceKind.TOOL_BUNDLE:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.tool_bundles[{index}].kind",
                )
        dependencies = _validated_link_tuple(
            self.dependencies, "$.dependencies", cap=_MAX_TASK_DEPENDENCIES
        )
        for index, link in enumerate(dependencies):
            if link.kind is not ManifestReferenceKind.DEPENDENCY_MANIFEST:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.dependencies[{index}].kind",
                )
        harness_commands = _validated_command_tuple(
            self.harness_commands, "$.harness_commands"
        )
        if not isinstance(self.oracle_kind, OracleKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.oracle_kind")
        if not isinstance(self.network_policy, NetworkPolicy):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.network_policy")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_TASK_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "hypothesis_ids", hypothesis_ids)
        object.__setattr__(self, "tool_bundles", tool_bundles)
        object.__setattr__(self, "dependencies", dependencies)
        object.__setattr__(self, "harness_commands", harness_commands)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "TaskManifest":
        data = _as_mapping(value)
        missing = [name for name in _TASK_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_TASK_WIRE_FIELDS, schema_version=schema_version
        )
        return cls(
            schema_version=schema_version,
            revision=data["revision"],
            oracle_kind=_wire_enum(data["oracle_kind"], OracleKind, "$.oracle_kind"),
            network_policy=_wire_enum(
                data["network_policy"], NetworkPolicy, "$.network_policy"
            ),
            hypothesis_ids=data["hypothesis_ids"],
            tool_bundles=_parse_link_array(
                data["tool_bundles"], "$.tool_bundles", schema_version=schema_version
            ),
            dependencies=_parse_link_array(
                data["dependencies"], "$.dependencies", schema_version=schema_version
            ),
            harness_commands=data["harness_commands"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "revision": self.revision,
            "hypothesis_ids": list(self.hypothesis_ids),
            "tool_bundles": [link.to_dict() for link in self.tool_bundles],
            "dependencies": [link.to_dict() for link in self.dependencies],
            "harness_commands": [list(command) for command in self.harness_commands],
            "oracle_kind": self.oracle_kind.value,
            "network_policy": self.network_policy.value,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_TOOL_BUNDLE_WIRE_FIELDS: Final = ("revision", "entries")
_TOOL_ENTRY_WIRE_FIELDS: Final = (
    "name",
    "checksum",
    "size_bytes",
    "executable",
    "license_word",
)


@dataclass(frozen=True, slots=True)
class _ToolBundleEntry:
    """One frozen tool file record; private (not on the 28-symbol face)."""

    name: str
    checksum: str
    size_bytes: int
    executable: bool
    license_word: str
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        name = _validated_identifier(self.name, "$.name")
        checksum = _validated_digest(self.checksum, "$.checksum")
        size_bytes = _validated_ranged_int(
            self.size_bytes, "$.size_bytes", minimum=0, maximum=_INT64_MAX
        )
        if type(self.executable) is not bool:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.executable")
        license_word = _validated_license_word(self.license_word, "$.license_word")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_TOOL_ENTRY_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "name", name)
        object.__setattr__(self, "checksum", checksum)
        object.__setattr__(self, "size_bytes", size_bytes)
        object.__setattr__(self, "license_word", license_word)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "_ToolBundleEntry":
        data = _as_mapping(value)
        missing = [name for name in _TOOL_ENTRY_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_TOOL_ENTRY_WIRE_FIELDS, schema_version=schema_version
        )
        return cls(
            name=data["name"],
            checksum=data["checksum"],
            size_bytes=data["size_bytes"],
            executable=data["executable"],
            license_word=data["license_word"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "name": self.name,
            "checksum": self.checksum,
            "size_bytes": self.size_bytes,
            "executable": self.executable,
            "license_word": self.license_word,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


@dataclass(frozen=True, slots=True)
class ToolBundle:
    """Tool inventory: sorted unique file entries with sha256 checksums."""

    schema_version: SchemaVersion
    revision: int
    entries: tuple[_ToolBundleEntry, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        revision = _validated_revision(self.revision, "$.revision")
        items = self.entries
        if not isinstance(items, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.entries")
        if len(items) > _MAX_TOOL_ENTRIES:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.entries"
            )
        entries = []
        for index, item in enumerate(items):
            if not isinstance(item, _ToolBundleEntry):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.entries[{index}]"
                )
            entries.append(copy.deepcopy(item))
        result = tuple(entries)
        for index in range(1, len(result)):
            if result[index].name <= result[index - 1].name:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.entries[{index}].name"
                )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_TOOL_BUNDLE_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "entries", result)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "ToolBundle":
        data = _as_mapping(value)
        missing = [name for name in _TOOL_BUNDLE_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_TOOL_BUNDLE_WIRE_FIELDS, schema_version=schema_version
        )
        raw_entries = data["entries"]
        if not isinstance(raw_entries, list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.entries")
        entries: list[_ToolBundleEntry] = []
        for index, item in enumerate(raw_entries):
            if not isinstance(item, Mapping):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.entries[{index}]"
                )
            try:
                entries.append(
                    _ToolBundleEntry.from_dict(item, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.entries[{index}]") from error
        return cls(
            schema_version=schema_version,
            revision=data["revision"],
            entries=entries,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "revision": self.revision,
            "entries": [entry.to_dict() for entry in self.entries],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_DEPENDENCY_MANIFEST_WIRE_FIELDS: Final = ("revision", "lock_digest", "entries")
_DEPENDENCY_ENTRY_WIRE_FIELDS: Final = (
    "package",
    "version_str",
    "source_kind",
    "checksum",
    "offline_replay",
)


@dataclass(frozen=True, slots=True)
class _DependencyEntry:
    """One frozen dependency record; private (not on the 28-symbol face)."""

    package: str
    version_str: str
    source_kind: _SourceKind
    checksum: str
    offline_replay: bool
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        package = _validated_identifier(self.package, "$.package")
        version_str = _validated_version_str(self.version_str, "$.version_str")
        if not isinstance(self.source_kind, _SourceKind):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.source_kind")
        _validated_digest(self.checksum, "$.checksum")
        if type(self.offline_replay) is not bool:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.offline_replay")
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_DEPENDENCY_ENTRY_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "package", package)
        object.__setattr__(self, "version_str", version_str)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "_DependencyEntry":
        data = _as_mapping(value)
        missing = [name for name in _DEPENDENCY_ENTRY_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data,
            known_fields=_DEPENDENCY_ENTRY_WIRE_FIELDS,
            schema_version=schema_version,
        )
        return cls(
            package=data["package"],
            version_str=data["version_str"],
            source_kind=_wire_enum(data["source_kind"], _SourceKind, "$.source_kind"),
            checksum=data["checksum"],
            offline_replay=data["offline_replay"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "package": self.package,
            "version_str": self.version_str,
            "source_kind": self.source_kind.value,
            "checksum": self.checksum,
            "offline_replay": self.offline_replay,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


@dataclass(frozen=True, slots=True)
class DependencyManifest:
    """Lock snapshot: whole-lock digest plus sorted unique package entries."""

    schema_version: SchemaVersion
    revision: int
    lock_digest: str
    entries: tuple[_DependencyEntry, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        revision = _validated_revision(self.revision, "$.revision")
        lock_digest = _validated_digest(self.lock_digest, "$.lock_digest")
        items = self.entries
        if not isinstance(items, (list, tuple)):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.entries")
        if len(items) > _MAX_DEPENDENCY_ENTRIES:
            raise ContractError(
                ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED, "$.entries"
            )
        entries = []
        for index, item in enumerate(items):
            if not isinstance(item, _DependencyEntry):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.entries[{index}]"
                )
            entries.append(copy.deepcopy(item))
        result = tuple(entries)
        for index in range(1, len(result)):
            if result[index].package <= result[index - 1].package:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE, f"$.entries[{index}].package"
                )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_DEPENDENCY_MANIFEST_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "revision", revision)
        object.__setattr__(self, "lock_digest", lock_digest)
        object.__setattr__(self, "entries", result)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "DependencyManifest":
        data = _as_mapping(value)
        missing = [
            name for name in _DEPENDENCY_MANIFEST_WIRE_FIELDS if name not in data
        ]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data,
            known_fields=_DEPENDENCY_MANIFEST_WIRE_FIELDS,
            schema_version=schema_version,
        )
        raw_entries = data["entries"]
        if not isinstance(raw_entries, list):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.entries")
        entries: list[_DependencyEntry] = []
        for index, item in enumerate(raw_entries):
            if not isinstance(item, Mapping):
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_TYPE, f"$.entries[{index}]"
                )
            try:
                entries.append(
                    _DependencyEntry.from_dict(item, schema_version=schema_version)
                )
            except ContractError as error:
                raise _repath(error, f"$.entries[{index}]") from error
        return cls(
            schema_version=schema_version,
            revision=data["revision"],
            lock_digest=data["lock_digest"],
            entries=entries,
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "revision": self.revision,
            "lock_digest": self.lock_digest,
            "entries": [entry.to_dict() for entry in self.entries],
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_RESOURCE_LIMIT_FIELDS: Final = ("cpu_seconds", "memory_mb", "max_processes")


@dataclass(frozen=True, slots=True)
class _ResourceLimits:
    """Declarative sandbox ceilings; private (not on the 28-symbol face)."""

    cpu_seconds: int
    memory_mb: int
    max_processes: int
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        cpu_seconds = _validated_ranged_int(
            self.cpu_seconds, "$.cpu_seconds", minimum=1, maximum=_CPU_SECONDS_MAX
        )
        memory_mb = _validated_ranged_int(
            self.memory_mb, "$.memory_mb", minimum=1, maximum=_MEMORY_MB_MAX
        )
        max_processes = _validated_ranged_int(
            self.max_processes, "$.max_processes", minimum=1, maximum=_MAX_PROCESSES_MAX
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_RESOURCE_LIMIT_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "cpu_seconds", cpu_seconds)
        object.__setattr__(self, "memory_mb", memory_mb)
        object.__setattr__(self, "max_processes", max_processes)

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "_ResourceLimits":
        data = _as_mapping(value)
        missing = [name for name in _RESOURCE_LIMIT_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_RESOURCE_LIMIT_FIELDS, schema_version=schema_version
        )
        return cls(
            cpu_seconds=data["cpu_seconds"],
            memory_mb=data["memory_mb"],
            max_processes=data["max_processes"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "cpu_seconds": self.cpu_seconds,
            "memory_mb": self.memory_mb,
            "max_processes": self.max_processes,
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


_SANDBOX_RUN_WIRE_FIELDS: Final = (
    "task",
    "image_digest",
    "tool_bundles",
    "mounts",
    "commands",
    "resource_limits",
    "network_policy",
    "exit_code",
    "log_artifact_ids",
)


@dataclass(frozen=True, slots=True)
class SandboxRun:
    """Execution record: bound task, image, sandbox constraints, exit fact."""

    schema_version: SchemaVersion
    task: ManifestLink
    image_digest: str
    resource_limits: _ResourceLimits
    network_policy: NetworkPolicy
    exit_code: int | None
    tool_bundles: tuple[ManifestLink, ...] = ()
    mounts: tuple[str, ...] = ()
    commands: tuple[tuple[str, ...], ...] = ()
    log_artifact_ids: tuple[str, ...] = ()
    extensions: dict[str, JSONValue] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not isinstance(self.schema_version, SchemaVersion):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
        if not isinstance(self.task, ManifestLink):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.task")
        if self.task.kind is not ManifestReferenceKind.TASK_MANIFEST:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.task.kind")
        task = copy.deepcopy(self.task)
        image_digest = _validated_digest(self.image_digest, "$.image_digest")
        tool_bundles = _validated_link_tuple(
            self.tool_bundles, "$.tool_bundles", cap=_MAX_SANDBOX_TOOL_BUNDLES
        )
        for index, link in enumerate(tool_bundles):
            if link.kind is not ManifestReferenceKind.TOOL_BUNDLE:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    f"$.tool_bundles[{index}].kind",
                )
        mounts = _validated_sorted_unique(
            self.mounts,
            "$.mounts",
            cap=_MAX_MOUNTS,
            validate_item=_validated_mount,
        )
        commands = _validated_command_tuple(self.commands, "$.commands")
        if not isinstance(self.resource_limits, _ResourceLimits):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.resource_limits"
            )
        resource_limits = copy.deepcopy(self.resource_limits)
        if not isinstance(self.network_policy, NetworkPolicy):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.network_policy")
        exit_code = self._validated_exit_code()
        log_artifact_ids = _validated_sorted_unique(
            self.log_artifact_ids,
            "$.log_artifact_ids",
            cap=_MAX_LOG_ARTIFACT_IDS,
            validate_item=_validated_identifier,
        )
        object.__setattr__(
            self,
            "extensions",
            _validated_extensions(
                self.extensions,
                known_fields=_SANDBOX_RUN_WIRE_FIELDS,
                path="$",
            ),
        )
        object.__setattr__(self, "task", task)
        object.__setattr__(self, "image_digest", image_digest)
        object.__setattr__(self, "tool_bundles", tool_bundles)
        object.__setattr__(self, "mounts", mounts)
        object.__setattr__(self, "commands", commands)
        object.__setattr__(self, "resource_limits", resource_limits)
        object.__setattr__(self, "exit_code", exit_code)
        object.__setattr__(self, "log_artifact_ids", log_artifact_ids)

    def _validated_exit_code(self) -> "int | None":
        if self.exit_code is None:
            return None
        # Exact type check: bool is an int subclass and must still be rejected.
        if type(self.exit_code) is not int:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.exit_code")
        if not _EXIT_CODE_MIN <= self.exit_code <= _EXIT_CODE_MAX:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.exit_code")
        return self.exit_code

    @classmethod
    def from_dict(
        cls, value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
    ) -> "SandboxRun":
        data = _as_mapping(value)
        missing = [name for name in _SANDBOX_RUN_WIRE_FIELDS if name not in data]
        if missing:
            raise ContractError(ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}")
        extensions = _split_extensions(
            data, known_fields=_SANDBOX_RUN_WIRE_FIELDS, schema_version=schema_version
        )
        if not isinstance(data["task"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.task")
        try:
            task = ManifestLink.from_dict(data["task"], schema_version=schema_version)
        except ContractError as error:
            raise _repath(error, "$.task") from error
        if not isinstance(data["resource_limits"], Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.resource_limits")
        try:
            resource_limits = _ResourceLimits.from_dict(
                data["resource_limits"], schema_version=schema_version
            )
        except ContractError as error:
            raise _repath(error, "$.resource_limits") from error
        return cls(
            schema_version=schema_version,
            task=task,
            image_digest=data["image_digest"],
            resource_limits=resource_limits,
            network_policy=_wire_enum(
                data["network_policy"], NetworkPolicy, "$.network_policy"
            ),
            exit_code=data["exit_code"],
            tool_bundles=_parse_link_array(
                data["tool_bundles"], "$.tool_bundles", schema_version=schema_version
            ),
            mounts=data["mounts"],
            commands=data["commands"],
            log_artifact_ids=data["log_artifact_ids"],
            extensions=extensions,
        )

    def to_dict(self) -> dict[str, JSONValue]:
        result: dict[str, JSONValue] = {
            "task": self.task.to_dict(),
            "image_digest": self.image_digest,
            "tool_bundles": [link.to_dict() for link in self.tool_bundles],
            "mounts": list(self.mounts),
            "commands": [list(command) for command in self.commands],
            "resource_limits": self.resource_limits.to_dict(),
            "network_policy": self.network_policy.value,
            "exit_code": self.exit_code,
            "log_artifact_ids": list(self.log_artifact_ids),
        }
        for key, value in self.extensions.items():
            result[key] = copy.deepcopy(value)
        return result


def _require_schema_name(envelope: ArtifactEnvelope, schema_name: str) -> None:
    if envelope.schema_name != schema_name:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_name")


def _require_inline_payload(envelope: ArtifactEnvelope) -> None:
    if envelope.payload is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.payload")


def _require_protected_envelope(envelope: ArtifactEnvelope) -> None:
    if envelope.classification is ArtifactClassification.PUBLIC:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.classification")
    if envelope.retention_class is RetentionClass.EPHEMERAL:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.retention_class")


def _lineage_index(envelope: ArtifactEnvelope) -> dict[str, object]:
    return {reference.artifact_id: reference for reference in envelope.lineage}


def _require_link_lineage(
    lineage_by_id: Mapping[str, object], link: ManifestLink, path: str
) -> None:
    entry = lineage_by_id.get(link.artifact_id)
    if (
        entry is None
        or entry.schema_name != link.kind.value
        or entry.schema_version != link.schema_version
    ):
        raise ContractError(
            ContractErrorCode.INVALID_FIELD_VALUE, f"{path}.artifact_id"
        )
    if not hmac.compare_digest(entry.content_digest, link.content_digest):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, f"{path}.content_digest")


def _require_id_existence(
    lineage_by_id: Mapping[str, object], artifact_ids: tuple[str, ...], path: str
) -> None:
    for index, artifact_id in enumerate(artifact_ids):
        if artifact_id not in lineage_by_id:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, f"{path}[{index}]"
            )


def _require_task_manifest_binding(
    envelope: ArtifactEnvelope, task: TaskManifest
) -> None:
    if task.revision > 1 and envelope.supersedes is None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    if task.revision == 1 and envelope.supersedes is not None:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    if (
        envelope.supersedes is not None
        and envelope.supersedes.schema_name != TASK_MANIFEST_SCHEMA_NAME
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.supersedes")
    lineage_by_id = _lineage_index(envelope)
    for index, link in enumerate(task.tool_bundles):
        _require_link_lineage(lineage_by_id, link, f"$.payload.tool_bundles[{index}]")
    for index, link in enumerate(task.dependencies):
        _require_link_lineage(lineage_by_id, link, f"$.payload.dependencies[{index}]")
    _require_id_existence(
        lineage_by_id, task.hypothesis_ids, "$.payload.hypothesis_ids"
    )


def _require_sandbox_run_binding(
    envelope: ArtifactEnvelope, run: SandboxRun
) -> None:
    lineage_by_id = _lineage_index(envelope)
    _require_link_lineage(lineage_by_id, run.task, "$.payload.task")
    for index, link in enumerate(run.tool_bundles):
        _require_link_lineage(lineage_by_id, link, f"$.payload.tool_bundles[{index}]")
    _require_id_existence(
        lineage_by_id, run.log_artifact_ids, "$.payload.log_artifact_ids"
    )


def decode_task_manifest_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> TaskManifest:
    """Decode a validated payload mapping into a TaskManifest."""
    return TaskManifest.from_dict(value, schema_version=schema_version)


def encode_task_manifest_payload(task: TaskManifest) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated task manifest."""
    if not isinstance(task, TaskManifest):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return task.to_dict()


def decode_task_manifest_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, TaskManifest]:
    """Decode envelope bytes and return the envelope with its task manifest."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, TASK_MANIFEST_SCHEMA_NAME)
    _require_inline_payload(envelope)
    task = TaskManifest.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_task_manifest_binding(envelope, task)
    _require_protected_envelope(envelope)
    return envelope, task


def encode_task_manifest_envelope(
    envelope: ArtifactEnvelope,
    task: TaskManifest,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full task binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(task, TaskManifest):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, TASK_MANIFEST_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != task.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_task_manifest_payload(task)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_task_manifest_binding(envelope, task)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_tool_bundle_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> ToolBundle:
    """Decode a validated payload mapping into a ToolBundle."""
    return ToolBundle.from_dict(value, schema_version=schema_version)


def encode_tool_bundle_payload(bundle: ToolBundle) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated tool bundle."""
    if not isinstance(bundle, ToolBundle):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return bundle.to_dict()


def decode_tool_bundle_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, ToolBundle]:
    """Decode envelope bytes and return the envelope with its tool bundle."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, TOOL_BUNDLE_SCHEMA_NAME)
    _require_inline_payload(envelope)
    bundle = ToolBundle.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_protected_envelope(envelope)
    return envelope, bundle


def encode_tool_bundle_envelope(
    envelope: ArtifactEnvelope,
    bundle: ToolBundle,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the tool-bundle binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(bundle, ToolBundle):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, TOOL_BUNDLE_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != bundle.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_tool_bundle_payload(bundle)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_dependency_manifest_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> DependencyManifest:
    """Decode a validated payload mapping into a DependencyManifest."""
    return DependencyManifest.from_dict(value, schema_version=schema_version)


def encode_dependency_manifest_payload(
    manifest: DependencyManifest,
) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated dependency manifest."""
    if not isinstance(manifest, DependencyManifest):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return manifest.to_dict()


def decode_dependency_manifest_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, DependencyManifest]:
    """Decode envelope bytes and return the envelope with its dependency manifest."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, DEPENDENCY_MANIFEST_SCHEMA_NAME)
    _require_inline_payload(envelope)
    manifest = DependencyManifest.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_protected_envelope(envelope)
    return envelope, manifest


def encode_dependency_manifest_envelope(
    envelope: ArtifactEnvelope,
    manifest: DependencyManifest,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the dependency binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(manifest, DependencyManifest):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, DEPENDENCY_MANIFEST_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != manifest.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_dependency_manifest_payload(manifest)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)


def decode_sandbox_run_payload(
    value: Mapping[str, JSONValue], *, schema_version: SchemaVersion
) -> SandboxRun:
    """Decode a validated payload mapping into a SandboxRun."""
    return SandboxRun.from_dict(value, schema_version=schema_version)


def encode_sandbox_run_payload(run: SandboxRun) -> dict[str, JSONValue]:
    """Return the canonical wire payload of a validated sandbox run."""
    if not isinstance(run, SandboxRun):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    return run.to_dict()


def decode_sandbox_run_envelope(
    data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> tuple[ArtifactEnvelope, SandboxRun]:
    """Decode envelope bytes and return the envelope with its sandbox run."""
    envelope = decode_envelope(data, limits=limits)
    _require_schema_name(envelope, SANDBOX_RUN_SCHEMA_NAME)
    _require_inline_payload(envelope)
    run = SandboxRun.from_dict(
        envelope.payload, schema_version=envelope.schema_version
    )
    _require_sandbox_run_binding(envelope, run)
    _require_protected_envelope(envelope)
    return envelope, run


def encode_sandbox_run_envelope(
    envelope: ArtifactEnvelope,
    run: SandboxRun,
    *,
    limits: ContractLimits = DEFAULT_LIMITS,
) -> bytes:
    """Verify the full sandbox-run binding and encode the envelope canonically."""
    if not isinstance(envelope, ArtifactEnvelope):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if not isinstance(run, SandboxRun):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    _require_schema_name(envelope, SANDBOX_RUN_SCHEMA_NAME)
    _require_inline_payload(envelope)
    if envelope.schema_version != run.schema_version:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
    payload = encode_sandbox_run_payload(run)
    if envelope.payload != payload:
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.payload")
    if not hmac.compare_digest(
        compute_content_digest(payload, limits=limits), envelope.content_digest
    ):
        raise ContractError(ContractErrorCode.DIGEST_MISMATCH, "$.content_digest")
    _require_sandbox_run_binding(envelope, run)
    _require_protected_envelope(envelope)
    return encode_envelope(envelope, limits=limits)
