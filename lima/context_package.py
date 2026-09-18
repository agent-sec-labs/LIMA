"""Analysis context package format (frozen schema v1) and its codec.

Workstream A, task A1.  A build container (one per repository) exports an
"analysis context package" once; the dependency-free analysis sandbox then
consumes the package for AST analysis.  This module freezes the on-disk
format and provides the only reader/writer:

Layout::

    <pkg_dir>/
        context_manifest.json    -- the manifest contract (this module)
        compile_commands.json    -- cmake-exported compilation database,
                                    paths already rewritten, stored verbatim
        generated/<relpath>      -- cmake configure-generated headers
        <header_root>/...        -- vendored third-party headers, placed at
                                    their rewritten package-relative paths

Pipeline contract: the build recipe exports the compilation database with
repository-relative ``directory``/``file`` values and absolute third-party
include paths.  :func:`rewrite_compdb_paths` then maps the include prefixes
into the package; :func:`build_manifest` freezes the result; and
:func:`write_package` finalizes byte totals and writes the directory
atomically.  :func:`read_package` re-verifies everything fail-closed: a
package whose context hash, files, or totals disagree with the manifest is
rejected, never guessed at.

Canonicalization and digesting reuse the public ``lima.contracts`` codec;
no canonical implementation is duplicated here.  The numeric bounds
(4 MiB compdb, 2048 entries) intentionally mirror
``cxx_analyzer.build_context`` so a package entry list is always consumable
by the repository-compdb resolver path (A4 wires that consumption).
"""

import dataclasses
import hmac
import json
import os
import re
import shlex
import shutil
import unicodedata
import uuid
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from lima.contracts.codec import (
    ContractLimits,
    JSONValue,
    canonical_decode,
)
from lima.contracts.common import canonical_encode, compute_content_digest
from lima.contracts.errors import ContractError, ContractErrorCode

__all__ = [
    "CURRENT_PACKAGE_SCHEMA_VERSION",
    "MAX_COMPDB_BYTES",
    "MAX_COMPDB_ENTRIES",
    "MAX_MANIFEST_BYTES",
    "MAX_MEMBER_FILE_BYTES",
    "MAX_PACKAGE_TOTAL_BYTES",
    "CompdbBlock",
    "ContextManifest",
    "ContextPackage",
    "ContextPackageError",
    "PackageTotals",
    "build_manifest",
    "read_package",
    "rewrite_compdb_paths",
    "write_package",
]

CURRENT_PACKAGE_SCHEMA_VERSION: Final[int] = 1

MANIFEST_FILENAME: Final = "context_manifest.json"
COMPDB_FILENAME: Final = "compile_commands.json"
GENERATED_DIRNAME: Final = "generated"

MAX_COMPDB_BYTES: Final = 4 * 1024 * 1024
MAX_MEMBER_FILE_BYTES: Final = 2 * 1024 * 1024
MAX_PACKAGE_TOTAL_BYTES: Final = 256 * 1024 * 1024
MAX_COMPDB_ENTRIES: Final = 2048
MAX_MANIFEST_BYTES: Final = 1024 * 1024
MAX_TEXT_FIELD_BYTES: Final = 512
MAX_PATH_BYTES: Final = 1024

_RESERVED_ROOT_NAMES: Final = frozenset(
    {MANIFEST_FILENAME, COMPDB_FILENAME, GENERATED_DIRNAME}
)
_HEX64_PATTERN: Final = re.compile(r"[0-9a-f]{64}")
# A token head preceding a rewritten prefix must be empty (a bare path) or a
# joined compiler option such as ``-I``, ``-isystem`` or ``--sysroot=``.
_OPTION_HEAD_PATTERN: Final = re.compile(r"-[A-Za-z0-9+.\-]*=?")

# The hash material embeds the whole canonical compdb (bounded by
# MAX_COMPDB_BYTES) so it needs a wider input ceiling than the codec default.
_HASH_LIMITS: Final[ContractLimits] = ContractLimits(max_input_bytes=2 * MAX_COMPDB_BYTES)
_COMPDB_DECODE_LIMITS: Final[ContractLimits] = ContractLimits(
    max_input_bytes=MAX_COMPDB_BYTES
)


class ContextPackageError(ValueError):
    """Fail-closed analysis context package violation with a stable reason."""

    reason: str

    def __init__(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise TypeError("reason must be a non-empty str")
        self.reason = reason
        super().__init__(reason)


# ----------------------------------------------------------------- validation


def _nfc_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, field)
    normalized = unicodedata.normalize("NFC", value)
    if not normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if len(normalized.encode("utf-8")) > MAX_TEXT_FIELD_BYTES:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    return normalized


def _safe_relative_path(value: object, field: str) -> str:
    """Validate a package-relative posix path segment string (fail-closed)."""

    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, field)
    normalized = unicodedata.normalize("NFC", value)
    if not normalized or "\\" in normalized or ":" in normalized:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if normalized.startswith("/") or any(
        unicodedata.category(char) == "Cc" for char in normalized
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if len(normalized.encode("utf-8")) > MAX_PATH_BYTES:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    segments = normalized.split("/")
    if any(segment in {"", ".", ".."} for segment in segments):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    return normalized


def _absolute_prefix(value: object, field: str) -> str:
    """Validate an absolute posix path prefix such as ``/usr/include/qt5``."""

    if not isinstance(value, str):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, field)
    normalized = unicodedata.normalize("NFC", value)
    if (
        not normalized.startswith("/")
        or normalized == "/"
        or normalized.endswith("/")
        or "\\" in normalized
        or ":" in normalized
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if any(unicodedata.category(char) == "Cc" for char in normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if len(normalized.encode("utf-8")) > MAX_PATH_BYTES:
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if any(segment in {"", ".", ".."} for segment in normalized.split("/")[1:]):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    return normalized


def _strict_int(value: object, field: str) -> int:
    # Exact type check: bool is an int subclass and must still be rejected.
    if type(value) is not int:
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, field)
    return value


def _sorted_unique_paths(
    values: object, field: str, *, reserved_roots: bool
) -> tuple[str, ...]:
    if not isinstance(values, list | tuple):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, field)
    normalized = tuple(
        _safe_relative_path(value, f"{field}[{index}]")
        for index, value in enumerate(values)
    )
    if list(normalized) != sorted(normalized) or len(set(normalized)) != len(normalized):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    if reserved_roots and any(
        value.split("/")[0] in _RESERVED_ROOT_NAMES for value in normalized
    ):
        raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, field)
    return normalized


# --------------------------------------------------------------- wire objects


@dataclasses.dataclass(frozen=True, slots=True)
class CompdbBlock:
    """The ``compdb`` block of the manifest contract."""

    entry_count: int
    tu_list: tuple[str, ...]
    path_prefix_rewrite: dict[str, str]

    def __post_init__(self) -> None:
        if type(self.entry_count) is not int:
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.compdb.entry_count")
        if not 1 <= self.entry_count <= MAX_COMPDB_ENTRIES:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.compdb.entry_count")
        object.__setattr__(
            self,
            "tu_list",
            _sorted_unique_paths(
                tuple(self.tu_list), "$.compdb.tu_list", reserved_roots=False
            ),
        )
        if len(self.tu_list) != self.entry_count:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.compdb.tu_list")
        rewrite = self.path_prefix_rewrite
        if not isinstance(rewrite, Mapping):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.compdb.path_prefix_rewrite"
            )
        normalized_rewrite: dict[str, str] = {}
        for original, package in rewrite.items():
            key = _absolute_prefix(original, "$.compdb.path_prefix_rewrite")
            value = _safe_relative_path(package, "$.compdb.path_prefix_rewrite")
            if value.split("/")[0] in _RESERVED_ROOT_NAMES:
                raise ContractError(
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    "$.compdb.path_prefix_rewrite",
                )
            normalized_rewrite[key] = value
        object.__setattr__(self, "path_prefix_rewrite", normalized_rewrite)

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "entry_count": self.entry_count,
            "tu_list": list(self.tu_list),
            "path_prefix_rewrite": dict(self.path_prefix_rewrite),
        }

    @classmethod
    def from_dict(cls, value: object) -> "CompdbBlock":
        if not isinstance(value, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.compdb")
        known = ("entry_count", "tu_list", "path_prefix_rewrite")
        missing = [name for name in known if name not in value]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.compdb.{missing[0]}"
            )
        unknown = [name for name in value if name not in known]
        if unknown:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.compdb.{unknown[0]}")
        rewrite = value["path_prefix_rewrite"]
        if not isinstance(rewrite, Mapping):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_TYPE, "$.compdb.path_prefix_rewrite"
            )
        return cls(
            entry_count=value["entry_count"],
            tu_list=tuple(value["tu_list"]),
            path_prefix_rewrite=dict(rewrite),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class PackageTotals:
    """The ``totals`` block: exact counts and payload bytes of one package."""

    compdb_entries: int
    generated_header_count: int
    header_file_count: int
    total_bytes: int

    def __post_init__(self) -> None:
        for name, minimum, maximum in (
            ("compdb_entries", 1, MAX_COMPDB_ENTRIES),
            ("generated_header_count", 0, MAX_COMPDB_ENTRIES),
            ("header_file_count", 0, None),
            ("total_bytes", 0, MAX_PACKAGE_TOTAL_BYTES),
        ):
            value = getattr(self, name)
            if type(value) is not int:
                raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, f"$.totals.{name}")
            if value < minimum or (maximum is not None and value > maximum):
                raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, f"$.totals.{name}")

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "compdb_entries": self.compdb_entries,
            "generated_header_count": self.generated_header_count,
            "header_file_count": self.header_file_count,
            "total_bytes": self.total_bytes,
        }

    @classmethod
    def from_dict(cls, value: object) -> "PackageTotals":
        if not isinstance(value, Mapping):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.totals")
        known = (
            "compdb_entries",
            "generated_header_count",
            "header_file_count",
            "total_bytes",
        )
        missing = [name for name in known if name not in value]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.totals.{missing[0]}"
            )
        unknown = [name for name in value if name not in known]
        if unknown:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.totals.{unknown[0]}")
        return cls(
            compdb_entries=value["compdb_entries"],
            generated_header_count=value["generated_header_count"],
            header_file_count=value["header_file_count"],
            total_bytes=value["total_bytes"],
        )


_MANIFEST_FIELDS: Final = (
    "schema_version",
    "repository",
    "revision",
    "context_hash",
    "created_by",
    "compdb",
    "generated_headers",
    "header_roots",
    "totals",
)


@dataclasses.dataclass(frozen=True, slots=True)
class ContextManifest:
    """The frozen ``context_manifest.json`` contract of a context package."""

    schema_version: int
    repository: str
    revision: str
    context_hash: str
    created_by: str
    compdb: CompdbBlock
    generated_headers: tuple[str, ...]
    header_roots: tuple[str, ...]
    totals: PackageTotals

    def __post_init__(self) -> None:
        if _strict_int(self.schema_version, "$.schema_version") != (
            CURRENT_PACKAGE_SCHEMA_VERSION
        ):
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.schema_version")
        object.__setattr__(self, "repository", _nfc_text(self.repository, "$.repository"))
        object.__setattr__(self, "revision", _nfc_text(self.revision, "$.revision"))
        object.__setattr__(self, "created_by", _nfc_text(self.created_by, "$.created_by"))
        if not isinstance(self.context_hash, str) or _HEX64_PATTERN.fullmatch(
            self.context_hash
        ) is None:
            raise ContractError(ContractErrorCode.INVALID_FIELD_VALUE, "$.context_hash")
        if not isinstance(self.compdb, CompdbBlock):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.compdb")
        if not isinstance(self.totals, PackageTotals):
            raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "$.totals")
        object.__setattr__(
            self,
            "generated_headers",
            _sorted_unique_paths(
                tuple(self.generated_headers), "$.generated_headers", reserved_roots=False
            ),
        )
        object.__setattr__(
            self,
            "header_roots",
            _sorted_unique_paths(
                tuple(self.header_roots), "$.header_roots", reserved_roots=True
            ),
        )
        # No header root may nest inside another (files would double-count).
        roots = self.header_roots
        for index, root in enumerate(roots):
            for other_index, other in enumerate(roots):
                if other_index != index and other.startswith(root + "/"):
                    raise ContractError(
                        ContractErrorCode.INVALID_FIELD_VALUE, "$.header_roots"
                    )
        if self.totals.compdb_entries != self.compdb.entry_count:
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.totals.compdb_entries"
            )
        if self.totals.generated_header_count != len(self.generated_headers):
            raise ContractError(
                ContractErrorCode.INVALID_FIELD_VALUE, "$.totals.generated_header_count"
            )

    def to_dict(self) -> dict[str, JSONValue]:
        return {
            "schema_version": self.schema_version,
            "repository": self.repository,
            "revision": self.revision,
            "context_hash": self.context_hash,
            "created_by": self.created_by,
            "compdb": self.compdb.to_dict(),
            "generated_headers": list(self.generated_headers),
            "header_roots": list(self.header_roots),
            "totals": self.totals.to_dict(),
        }

    @classmethod
    def from_dict(cls, value: object) -> "ContextManifest":
        if not isinstance(value, Mapping):
            raise ContractError(ContractErrorCode.TOP_LEVEL_NOT_OBJECT, "$")
        missing = [name for name in _MANIFEST_FIELDS if name not in value]
        if missing:
            raise ContractError(
                ContractErrorCode.REQUIRED_FIELD_MISSING, f"$.{missing[0]}"
            )
        unknown = [name for name in value if name not in _MANIFEST_FIELDS]
        if unknown:
            raise ContractError(ContractErrorCode.UNKNOWN_FIELD, f"$.{unknown[0]}")
        return cls(
            schema_version=value["schema_version"],
            repository=value["repository"],
            revision=value["revision"],
            context_hash=value["context_hash"],
            created_by=value["created_by"],
            compdb=CompdbBlock.from_dict(value["compdb"]),
            generated_headers=tuple(value["generated_headers"]),
            header_roots=tuple(value["header_roots"]),
            totals=PackageTotals.from_dict(value["totals"]),
        )


# ------------------------------------------------------------- hash material


def _hash_material(
    compdb_document: JSONValue,
    generated_headers: Sequence[str],
    header_roots: Sequence[str],
    rewrites: Mapping[str, str],
) -> dict[str, JSONValue]:
    return {
        "compdb": compdb_document,
        "generated": sorted(generated_headers),
        "header_roots": sorted(header_roots),
        "rewrites": dict(rewrites),
    }


def _compute_context_hash(material: dict[str, JSONValue]) -> str:
    return compute_content_digest(material, limits=_HASH_LIMITS)


# ------------------------------------------------------------- build manifest


def _entry_list(compdb: Mapping[str, object] | Sequence[object]) -> list[Mapping[str, object]]:
    if isinstance(compdb, Mapping):
        values = list(compdb.values())
    elif isinstance(compdb, list | tuple):
        values = list(compdb)
    else:
        raise ContextPackageError("compdb-must-be-entry-sequence")
    if len(values) > MAX_COMPDB_ENTRIES:
        raise ContextPackageError("compdb-too-many-entries")
    files: list[str] = []
    for entry in values:
        if not isinstance(entry, Mapping):
            raise ContextPackageError("compdb-entry-not-object")
        try:
            file_value = _safe_relative_path(entry.get("file"), "file")
            _safe_relative_path(entry.get("directory"), "directory")
        except ContractError as exc:
            raise ContextPackageError("compdb-entry-path-invalid") from exc
        arguments = entry.get("arguments")
        command = entry.get("command")
        has_arguments = isinstance(arguments, list) and bool(arguments)
        has_command = isinstance(command, str) and bool(command)
        if not (has_arguments or has_command):
            raise ContextPackageError("compdb-entry-without-arguments")
        if has_arguments and any(not isinstance(item, str) for item in arguments):
            raise ContextPackageError("compdb-entry-argument-invalid")
        if file_value in files:
            raise ContextPackageError("compdb-entry-duplicate-file")
        files.append(file_value)
    return values


def build_manifest(
    repository: str,
    revision: str,
    compdb: Mapping[str, object] | Sequence[object],
    generated: Sequence[str],
    header_roots: Sequence[str],
    rewrites: Mapping[str, str],
    created_by: str,
) -> ContextManifest:
    """Assemble the manifest from build outputs; the context hash is
    ``sha256(canonical_encode({"compdb": entries, "generated": sorted,
    "header_roots": sorted, "rewrites": mapping}))`` and therefore
    deterministic for identical inputs.

    ``compdb`` is the parsed (already path-rewritten) compilation database:
    a sequence of entry objects, or a mapping whose values are the entries.
    ``totals.header_file_count`` and ``totals.total_bytes`` are not derivable
    here; they stay zero and are finalized by :func:`write_package` from the
    actual payload.
    """

    entries = _entry_list(compdb)
    tu_list = sorted(
        str(entry["file"]) for entry in entries if isinstance(entry.get("file"), str)
    )
    context_hash = _compute_context_hash(
        _hash_material(entries, generated, header_roots, rewrites)
    )
    return ContextManifest(
        schema_version=CURRENT_PACKAGE_SCHEMA_VERSION,
        repository=repository,
        revision=revision,
        context_hash=context_hash,
        created_by=created_by,
        compdb=CompdbBlock(
            entry_count=len(entries),
            tu_list=tuple(tu_list),
            path_prefix_rewrite=dict(rewrites),
        ),
        generated_headers=tuple(sorted(generated)),
        header_roots=tuple(sorted(header_roots)),
        totals=PackageTotals(
            compdb_entries=len(entries),
            generated_header_count=len(generated),
            header_file_count=0,
            total_bytes=0,
        ),
    )


# -------------------------------------------------------------- compdb rewrite


def _validate_rewrites(rewrites: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(rewrites, Mapping):
        raise ContextPackageError("rewrite-map-invalid")
    normalized: dict[str, str] = {}
    for original, package in rewrites.items():
        try:
            key = _absolute_prefix(original, "original")
            value = _safe_relative_path(package, "package")
        except ContractError as exc:
            raise ContextPackageError("rewrite-map-invalid") from exc
        normalized[key] = value
    return normalized


def _rewrite_token(token: str, ordered: Sequence[tuple[str, str]]) -> str:
    """Rewrite the first path-boundary occurrence of any original prefix.

    A match is only accepted at a path boundary (end of token or ``/``) and
    behind an empty or joined-option head (``-I``, ``-isystem``,
    ``--sysroot=``), so substrings of unrelated paths are never rewritten
    and the transform stays idempotent.
    """

    for original, package in ordered:
        index = token.find(original)
        while index != -1:
            end = index + len(original)
            head = token[:index]
            head_ok = head == "" or _OPTION_HEAD_PATTERN.fullmatch(head) is not None
            if (end == len(token) or token[end] == "/") and head_ok:
                return token[:index] + package + token[end:]
            index = token.find(original, index + 1)
    return token


def rewrite_compdb_paths(compdb_text: str, rewrites: Mapping[str, str]) -> str:
    """Rewrite original absolute prefixes to package prefixes in a compdb.

    Both the ``arguments`` array form and the ``command`` shell-string form
    are handled; the command is split with posix quoting rules, rewritten
    token-wise and re-joined, so quoting is preserved semantically.  Longer
    originals win over shorter ones and the transform is idempotent.
    """

    if not isinstance(compdb_text, str):
        raise ContextPackageError("compdb-text-invalid")
    normalized_rewrites = _validate_rewrites(rewrites)
    ordered = sorted(
        normalized_rewrites.items(), key=lambda item: (-len(item[0]), item[0])
    )
    try:
        document = canonical_decode(
            compdb_text.encode("utf-8"), limits=_COMPDB_DECODE_LIMITS
        )
    except ContractError as exc:
        raise ContextPackageError("compdb-text-invalid") from exc
    if not isinstance(document, list):
        raise ContextPackageError("compdb-not-array")
    for entry in document:
        if not isinstance(entry, dict):
            raise ContextPackageError("compdb-entry-not-object")
        if "arguments" in entry:
            arguments = entry["arguments"]
            if not isinstance(arguments, list) or any(
                not isinstance(item, str) for item in arguments
            ):
                raise ContextPackageError("compdb-entry-argument-invalid")
            entry["arguments"] = [
                _rewrite_token(argument, ordered) for argument in arguments
            ]
        if "command" in entry:
            command = entry["command"]
            if not isinstance(command, str) or not command:
                raise ContextPackageError("compdb-entry-command-invalid")
            try:
                argv = shlex.split(command, posix=True)
            except ValueError as exc:
                raise ContextPackageError("compdb-entry-command-invalid") from exc
            entry["command"] = shlex.join(
                [_rewrite_token(argument, ordered) for argument in argv]
            )
    return json.dumps(document, ensure_ascii=False, indent=2)


# --------------------------------------------------------------- package read


@dataclasses.dataclass(frozen=True, slots=True)
class ContextPackage:
    """A verified analysis context package loaded from disk.

    ``compdb`` is the parsed compilation database (a tuple of entry
    mappings, the frozen wire shape being a JSON array), ``generated_files``
    carries ``(package_relative_path, content)`` pairs sorted by path, and
    ``header_roots`` are the resolved on-disk header root directories.
    """

    manifest: ContextManifest
    compdb: tuple[Mapping[str, JSONValue], ...]
    compdb_bytes: bytes
    generated_files: tuple[tuple[str, bytes], ...]
    header_roots: tuple[Path, ...]


def _read_bounded(path: Path, limit: int, reason: str) -> bytes:
    try:
        with path.open("rb") as stream:
            raw = stream.read(limit + 1)
    except OSError as exc:
        raise ContextPackageError(reason) from exc
    if len(raw) > limit:
        raise ContextPackageError(reason)
    return raw


def _directory_files(root: Path) -> list[tuple[str, int]]:
    """All regular files under ``root`` as ``(posix_relative, size)`` pairs."""

    results: list[tuple[str, int]] = []
    try:
        candidates = list(root.rglob("*"))
    except OSError as exc:
        raise ContextPackageError("package-entry-unreadable") from exc
    for path in candidates:
        try:
            if path.is_file():
                results.append(
                    (path.relative_to(root).as_posix(), path.stat().st_size)
                )
        except OSError as exc:
            raise ContextPackageError("package-entry-unreadable") from exc
    # Sort by posix text so the order matches the manifest's string-sorted lists.
    return sorted(results)


def read_package(pkg_dir: Path) -> ContextPackage:
    """Load and fully verify one analysis context package (fail-closed).

    Rejects with :class:`ContextPackageError` when the manifest contract is
    violated, the recomputed context hash disagrees, the compilation
    database is missing or invalid, generated or header files are missing or
    unexpected, or the declared totals disagree with the actual payload.
    """

    package_dir = Path(pkg_dir)
    if not package_dir.is_dir():
        raise ContextPackageError("package-directory-missing")
    try:
        manifest = ContextManifest.from_dict(
            canonical_decode(
                _read_bounded(
                    package_dir / MANIFEST_FILENAME,
                    MAX_MANIFEST_BYTES,
                    "manifest-unreadable",
                )
            )
        )
    except ContractError as exc:
        raise ContextPackageError("manifest-contract-violation") from exc

    compdb_bytes = _read_bounded(
        package_dir / COMPDB_FILENAME, MAX_COMPDB_BYTES, "compdb-unreadable"
    )
    try:
        document = canonical_decode(compdb_bytes, limits=_COMPDB_DECODE_LIMITS)
    except ContractError as exc:
        raise ContextPackageError("compdb-invalid") from exc
    if not isinstance(document, list):
        raise ContextPackageError("compdb-not-array")

    files: list[str] = []
    for entry in document:
        if not isinstance(entry, dict) or not isinstance(entry.get("file"), str):
            raise ContextPackageError("compdb-entry-invalid")
        files.append(entry["file"])
    if len(document) != manifest.compdb.entry_count or sorted(files) != list(
        manifest.compdb.tu_list
    ):
        raise ContextPackageError("compdb-tu-list-mismatch")
    if not hmac.compare_digest(
        _compute_context_hash(
            _hash_material(
                document,
                manifest.generated_headers,
                manifest.header_roots,
                manifest.compdb.path_prefix_rewrite,
            )
        ),
        manifest.context_hash,
    ):
        raise ContextPackageError("context-hash-mismatch")

    allowed_top_level = {MANIFEST_FILENAME, COMPDB_FILENAME, GENERATED_DIRNAME} | {
        root.split("/")[0] for root in manifest.header_roots
    }
    try:
        top_level = list(package_dir.iterdir())
    except OSError as exc:
        raise ContextPackageError("package-entry-unreadable") from exc
    for entry in top_level:
        if entry.name not in allowed_top_level:
            raise ContextPackageError("unexpected-package-entry")

    generated_dir = package_dir / GENERATED_DIRNAME
    generated_files: list[tuple[str, bytes]] = []
    generated_disk = _directory_files(generated_dir) if generated_dir.is_dir() else []
    if [path for path, _ in generated_disk] != list(manifest.generated_headers):
        raise ContextPackageError("generated-file-mismatch")
    for relative, _ in generated_disk:
        try:
            generated_files.append(
                (relative, (generated_dir / relative).read_bytes())
            )
        except OSError as exc:
            raise ContextPackageError("generated-file-unreadable") from exc

    header_count = 0
    header_bytes = 0
    for root in manifest.header_roots:
        root_dir = package_dir / root
        if not root_dir.is_dir():
            raise ContextPackageError("header-root-missing")
        found = _directory_files(root_dir)
        header_count += len(found)
        header_bytes += sum(size for _, size in found)

    totals = manifest.totals
    if header_count != totals.header_file_count:
        raise ContextPackageError("totals-header-count-mismatch")
    actual_total = (
        len(compdb_bytes)
        + sum(len(content) for _, content in generated_files)
        + header_bytes
    )
    if actual_total != totals.total_bytes:
        raise ContextPackageError("totals-byte-count-mismatch")
    if totals.generated_header_count != len(generated_files):
        raise ContextPackageError("totals-generated-count-mismatch")

    return ContextPackage(
        manifest=manifest,
        compdb=tuple(document),
        compdb_bytes=compdb_bytes,
        generated_files=tuple(sorted(generated_files)),
        header_roots=tuple(package_dir / root for root in manifest.header_roots),
    )


# -------------------------------------------------------------- package write


def _atomic_replace_directory(source: Path, target: Path) -> None:
    backup: Path | None = None
    if target.exists():
        backup = target.with_name(f"{target.name}.old-{uuid.uuid4().hex}")
        os.replace(target, backup)
    try:
        os.replace(source, target)
    except BaseException:
        if backup is not None:
            os.replace(backup, target)
        raise
    if backup is not None:
        if backup.is_dir():
            shutil.rmtree(backup, ignore_errors=True)
        else:
            backup.unlink(missing_ok=True)


def write_package(
    pkg_dir: Path,
    manifest: ContextManifest,
    compdb_bytes: bytes,
    generated_files: Mapping[str, bytes],
    header_files: Mapping[str, bytes],
) -> ContextManifest:
    """Write one package directory atomically (temp dir + rename).

    Enforces the size caps (compdb <= 4 MiB, member file <= 2 MiB, total
    <= 256 MiB) and the manifest/payload consistency, finalizes the byte
    totals from the actual payload and returns the finalized manifest --
    the manifest that was written and that :func:`read_package` verifies.
    """

    package_dir = Path(pkg_dir)
    if not isinstance(compdb_bytes, bytes):
        raise ContextPackageError("compdb-bytes-invalid")
    if not isinstance(generated_files, Mapping) or not isinstance(header_files, Mapping):
        raise ContextPackageError("package-files-invalid")

    if len(compdb_bytes) > MAX_COMPDB_BYTES:
        raise ContextPackageError("size-limit-compdb-exceeded")
    for _name, content in generated_files.items():
        if len(content) > MAX_MEMBER_FILE_BYTES:
            raise ContextPackageError("size-limit-file-exceeded")
    for _name, content in header_files.items():
        if len(content) > MAX_MEMBER_FILE_BYTES:
            raise ContextPackageError("size-limit-file-exceeded")
    total_payload = (
        len(compdb_bytes)
        + sum(len(content) for content in generated_files.values())
        + sum(len(content) for content in header_files.values())
    )
    if total_payload > MAX_PACKAGE_TOTAL_BYTES:
        raise ContextPackageError("size-limit-total-exceeded")

    if sorted(generated_files) != list(manifest.generated_headers):
        raise ContextPackageError("generated-file-mismatch")
    for key in generated_files:
        _safe_relative_or_package_error(key)
    for key in header_files:
        _safe_relative_or_package_error(key)
        if not any(
            key.startswith(root + "/") for root in manifest.header_roots
        ):
            raise ContextPackageError("header-file-outside-root")

    try:
        document = canonical_decode(compdb_bytes, limits=_COMPDB_DECODE_LIMITS)
    except ContractError as exc:
        raise ContextPackageError("compdb-invalid") from exc
    if not isinstance(document, list):
        raise ContextPackageError("compdb-not-array")
    files = [
        entry["file"]
        for entry in document
        if isinstance(entry, dict) and isinstance(entry.get("file"), str)
    ]
    if len(document) != manifest.compdb.entry_count or sorted(files) != list(
        manifest.compdb.tu_list
    ):
        raise ContextPackageError("compdb-tu-list-mismatch")
    if not hmac.compare_digest(
        _compute_context_hash(
            _hash_material(
                document,
                manifest.generated_headers,
                manifest.header_roots,
                manifest.compdb.path_prefix_rewrite,
            )
        ),
        manifest.context_hash,
    ):
        raise ContextPackageError("context-hash-mismatch")

    finalized = dataclasses.replace(
        manifest,
        totals=PackageTotals(
            compdb_entries=manifest.compdb.entry_count,
            generated_header_count=len(generated_files),
            header_file_count=len(header_files),
            total_bytes=total_payload,
        ),
    )
    manifest_encoded = canonical_encode(finalized.to_dict())

    package_dir.parent.mkdir(parents=True, exist_ok=True)
    staging = package_dir.with_name(f"{package_dir.name}.tmp-{uuid.uuid4().hex}")
    try:
        staging.mkdir()
        (staging / MANIFEST_FILENAME).write_bytes(manifest_encoded)
        (staging / COMPDB_FILENAME).write_bytes(compdb_bytes)
        for relative, content in sorted(generated_files.items()):
            target = staging / GENERATED_DIRNAME / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        for relative, content in sorted(header_files.items()):
            target = staging / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ContextPackageError("package-write-failed") from exc
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    try:
        _atomic_replace_directory(staging, package_dir)
    except OSError as exc:
        shutil.rmtree(staging, ignore_errors=True)
        raise ContextPackageError("package-write-failed") from exc
    return finalized


def _safe_relative_or_package_error(value: object) -> None:
    try:
        _safe_relative_path(value, "path")
    except ContractError as exc:
        raise ContextPackageError("path-unsafe") from exc
