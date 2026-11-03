"""Sealed-package derivation for wire-registered verified views (#351).

The registration envelope carries the sealed package members plus the
claimed identity; every consumed semantic -- TU projection, working
directories, context identity, snapshot binding -- is DERIVED from the
sealed ``context_manifest.json`` and ``compile_commands.json`` members
and cross-checked, never taken from independent envelope fields
(PR #352 review round 1, P1).  The mirrors below stay byte-compatible
with the lima originals (``lima.context_package`` manifest hashing and
``lima.build_context_view`` entry projection); the equivalence is
pinned by parity tests, and this module stays lima-free.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import posixpath
import shlex
import unicodedata
from typing import Final

MANIFEST_MEMBER: Final = "context_manifest.json"
COMPDB_MEMBER: Final = "compile_commands.json"
_GENERATED_PACKAGE_ROOT: Final = "generated"

# Mirror of the lima option sets (build_context_view): which flags take
# a separate path value, a separate file value, or a plain operand.
_DIR_VALUE_OPTIONS: Final = frozenset(
    {"-I", "-isystem", "-iquote", "-idirafter", "-stdlib++-isystem"}
)
_FILE_VALUE_OPTIONS: Final = frozenset({"-include", "-imacros"})
_TAKES_VALUE_OPTIONS: Final = frozenset(
    {"-x", "-D", "-U", "-target", "-arch", "-isysroot", "--sysroot", "-B",
     "-MF", "-MT", "-MQ"}
)

# Mirror of the lima decode ceilings (contracts codec + package
# limits): the manifest and compdb members parse under the same bounds
# read_package enforces, so a wire package cannot smuggle structure the
# in-process path would refuse.
_MAX_COMPDB_BYTES: Final = 4 * 1024 * 1024
_MAX_MEMBER_JSON_BYTES: Final = 4 * 1024 * 1024
_MAX_HASH_INPUT_BYTES: Final = 2 * _MAX_COMPDB_BYTES
_MAX_DEPTH: Final = 32
_MAX_ARRAY_ITEMS: Final = 10_000
_MAX_OBJECT_FIELDS: Final = 1_000
_MAX_STRING_BYTES: Final = 262_144
_INT64_MIN: Final = -(2**63)
_INT64_MAX: Final = 2**63 - 1
_PACKAGE_SCHEMA_VERSION: Final = 1

_HEX_DIGITS: Final = frozenset("0123456789abcdef")


class WireViewError(ValueError):
    """One sealed package failed derivation; the registry stays untouched."""


def _reject_float(text: str) -> float:
    raise WireViewError("non-json-number")


def _parse_int(text: str) -> int:
    if len(text) > 20:
        raise WireViewError("integer-out-of-range")
    value = int(text)
    if not _INT64_MIN <= value <= _INT64_MAX:
        raise WireViewError("integer-out-of-range")
    return value


def _object_pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen: set[str] = set()
    normalized: dict[str, object] = {}
    for key, _ in pairs:
        if key in seen:
            raise WireViewError("duplicate-field")
        seen.add(key)
    for key, value in pairs:
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise WireViewError("duplicate-semantic-field")
        normalized[normalized_key] = value
    return normalized


def _walk(value: object, depth: int) -> object:
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        return value
    if type(value) is str:
        normalized = unicodedata.normalize("NFC", value)
        if len(normalized.encode("utf-8")) > _MAX_STRING_BYTES:
            raise WireViewError("string-too-long")
        return normalized
    if type(value) is list:
        if depth > _MAX_DEPTH or len(value) > _MAX_ARRAY_ITEMS:
            raise WireViewError("structure-budget")
        return [_walk(item, depth + 1) for item in value]
    if type(value) is dict:
        if depth > _MAX_DEPTH or len(value) > _MAX_OBJECT_FIELDS:
            raise WireViewError("structure-budget")
        normalized: dict[str, object] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise WireViewError("non-string-key")
            normalized[unicodedata.normalize("NFC", key)] = _walk(
                item, depth + 1
            )
        return normalized
    raise WireViewError("unsupported-value-type")


def _decode_member(data: bytes) -> object:
    """Parse one sealed JSON member under the mirrored decode bounds."""

    if len(data) > _MAX_MEMBER_JSON_BYTES:
        raise WireViewError("member-too-large")
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise WireViewError("invalid-utf8") from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_pairs_hook,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except WireViewError:
        raise
    except ValueError as exc:
        raise WireViewError("invalid-json") from exc
    return _walk(parsed, 1)


def _canonical_bytes(value: object) -> bytes:
    """Mirror of lima's canonical_encode: NFC, sorted keys, compact."""

    text = json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    encoded = text.encode("utf-8")
    if len(encoded) > _MAX_HASH_INPUT_BYTES:
        raise WireViewError("hash-material-too-large")
    return encoded


def _compute_context_hash(
    compdb_document: object, generated: list[str], header_roots: list[str],
    rewrites: dict[str, str],
) -> str:
    material = {
        "compdb": compdb_document,
        "generated": sorted(generated),
        "header_roots": sorted(header_roots),
        "rewrites": dict(rewrites),
    }
    return hashlib.sha256(_canonical_bytes(_walk(material, 1))).hexdigest()


def _hex64(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in _HEX_DIGITS for character in value)
    )


def _normjoin(directory: str, value: str) -> str:
    return posixpath.normpath(posixpath.join(directory, value))


def _project_entry(
    entry: dict[str, object], package_roots: frozenset[str]
) -> tuple[tuple[str, ...], str]:
    """Mirror of lima's _project_entry: argv -> projected flags + cwd.

    The compiler token, -c, -o and the source file are stripped; known
    operand-taking options keep their values; path options are mapped
    package-relative or refused when they escape the repository root; a
    bare token that is not the entry's source file refuses the entry.
    """

    directory = entry.get("directory")
    if not isinstance(directory, str) or not directory:
        directory = "."
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        argv = [item for item in arguments if isinstance(item, str)]
    else:
        command = entry.get("command")
        if not isinstance(command, str) or not command:
            raise WireViewError("compdb-command-missing")
        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise WireViewError("compdb-command-unparseable") from exc
    if not argv:
        raise WireViewError("compdb-command-empty")

    file_value = entry.get("file")
    source_candidates: set[str] = set()
    if isinstance(file_value, str) and file_value:
        source_candidates.add(file_value)
        source_candidates.add(_normjoin(directory, file_value))
        try:
            source_candidates.add(posixpath.relpath(file_value, directory))
        except ValueError:
            pass

    def map_path(value: str) -> str:
        for root in package_roots:
            if value == root or value.startswith(root + "/"):
                return value
        normalized = posixpath.normpath(value)
        if normalized == ".." or normalized.startswith("../"):
            raise WireViewError("compdb-include-escape")
        return normalized

    projected: list[str] = []
    index = 1
    while index < len(argv):
        argument = argv[index]
        if argument == "-o":
            index += 2
            continue
        if argument.startswith("-o") and len(argument) > 2:
            index += 1
            continue
        if argument == "-c":
            index += 1
            continue
        if not argument.startswith("-"):
            if argument in source_candidates:
                index += 1
                continue
            raise WireViewError("compdb-unexpected-positional")
        if argument in _DIR_VALUE_OPTIONS or argument in _FILE_VALUE_OPTIONS:
            if index + 1 >= len(argv):
                raise WireViewError("compdb-command-malformed-option")
            projected.append(argument)
            projected.append(map_path(argv[index + 1]))
            index += 2
            continue
        if argument in _TAKES_VALUE_OPTIONS:
            if index + 1 >= len(argv):
                raise WireViewError("compdb-command-malformed-option")
            projected.append(argument)
            projected.append(argv[index + 1])
            index += 2
            continue
        if argument.startswith("-I") and len(argument) > 2:
            projected.append("-I" + map_path(argument[2:]))
            index += 1
            continue
        projected.append(argument)
        index += 1
    return tuple(projected), directory


class WireVerifiedView:
    """A view whose every semantic is derived from sealed package bytes."""

    def __init__(
        self,
        *,
        artifact_digest: str,
        context_hash: str,
        target_units: tuple[str, ...],
        tu_flags: dict[str, tuple[str, ...]],
        tu_directories: dict[str, str],
        sealed_members: dict[str, bytes],
    ) -> None:
        self.artifact_digest = artifact_digest
        self.context_hash = context_hash
        self.target_units = target_units
        self._tu_flags = tu_flags
        self._tu_directories = tu_directories
        self._sealed_members = sealed_members

    @property
    def member_paths(self) -> tuple[str, ...]:
        """The sealed package members, in canonical posix order."""

        return tuple(sorted(self._sealed_members))

    def read_member(self, path: str) -> bytes:
        return self._sealed_members[path]

    def flags_for_tu(self, tu: str) -> tuple[str, ...]:
        return self._tu_flags[tu]

    def working_directory_for_tu(self, tu: str) -> str:
        return self._tu_directories[tu]


def derive_wire_view(
    snapshot_sha256: str,
    artifact_digest: str,
    target_units: object,
    members: dict[str, bytes],
) -> WireVerifiedView:
    """Validate one sealed package and derive its view, fail-closed.

    Checks: core members present; manifest structure and schema; the
    revision binds the package to the claimed snapshot; the manifest's
    compdb block agrees with the sealed compdb member; the manifest's
    context hash re-derives from the sealed compdb and root blocks; the
    declared target units exist in the compilation database; every
    compile command projects.  Any failure raises :class:`WireViewError`
    before the caller touches its registry.
    """

    manifest_bytes = members.get(MANIFEST_MEMBER)
    compdb_bytes = members.get(COMPDB_MEMBER)
    if manifest_bytes is None or compdb_bytes is None:
        raise WireViewError("core-member-missing")
    if len(compdb_bytes) > _MAX_COMPDB_BYTES:
        raise WireViewError("compdb-too-large")

    manifest = _decode_member(manifest_bytes)
    if not isinstance(manifest, dict):
        raise WireViewError("manifest-not-object")
    if manifest.get("schema_version") != _PACKAGE_SCHEMA_VERSION:
        raise WireViewError("manifest-schema-unsupported")
    if not isinstance(manifest.get("repository"), str):
        raise WireViewError("manifest-repository-missing")
    revision = manifest.get("revision")
    if not _hex64(revision) or revision != snapshot_sha256:
        raise WireViewError("snapshot-not-bound")
    declared_context_hash = manifest.get("context_hash")
    if not _hex64(declared_context_hash):
        raise WireViewError("manifest-context-hash-invalid")
    compdb_block = manifest.get("compdb")
    if not isinstance(compdb_block, dict):
        raise WireViewError("manifest-compdb-block-missing")
    entry_count = compdb_block.get("entry_count")
    tu_list = compdb_block.get("tu_list")
    rewrites = compdb_block.get("path_prefix_rewrite")
    if (
        type(entry_count) is not int
        or not isinstance(tu_list, list)
        or not isinstance(rewrites, dict)
        or any(
            not isinstance(unit, str) or not unit for unit in tu_list
        )
        or any(
            not isinstance(key, str) or not isinstance(value, str)
            for key, value in rewrites.items()
        )
    ):
        raise WireViewError("manifest-compdb-block-invalid")
    generated = manifest.get("generated_headers")
    header_roots = manifest.get("header_roots")
    if (
        not isinstance(generated, list)
        or not isinstance(header_roots, list)
        or any(not isinstance(item, str) for item in generated)
        or any(not isinstance(item, str) for item in header_roots)
    ):
        raise WireViewError("manifest-roots-invalid")

    compdb_document = _decode_member(compdb_bytes)
    if not isinstance(compdb_document, list):
        raise WireViewError("compdb-not-array")
    if len(compdb_document) != entry_count:
        raise WireViewError("compdb-entry-count-mismatch")
    entries: dict[str, dict[str, object]] = {}
    for entry in compdb_document:
        if not isinstance(entry, dict):
            raise WireViewError("compdb-entry-not-object")
        file_value = entry.get("file")
        if isinstance(file_value, str) and file_value and (
            file_value not in entries
        ):
            entries[file_value] = entry
    if sorted(entries) != sorted(tu_list):
        raise WireViewError("compdb-tu-list-mismatch")
    if not hmac.compare_digest(
        _compute_context_hash(
            compdb_document,
            [item for item in generated],
            [item for item in header_roots],
            {key: value for key, value in rewrites.items()},
        ),
        declared_context_hash,
    ):
        raise WireViewError("context-hash-mismatch")

    if (
        type(target_units) is not list
        or not target_units
        or len(target_units) > len(tu_list)
        or any(
            not isinstance(unit, str) or not unit for unit in target_units
        )
        or len(set(target_units)) != len(target_units)
    ):
        raise WireViewError("target-units-invalid")
    for unit in target_units:
        if unit not in entries:
            raise WireViewError("target-tu-not-declared")

    package_roots = frozenset(header_roots) | {_GENERATED_PACKAGE_ROOT}
    projected: dict[str, tuple[tuple[str, ...], str]] = {}
    for unit in target_units:
        projected[unit] = _project_entry(entries[unit], package_roots)
    return WireVerifiedView(
        artifact_digest=artifact_digest,
        context_hash=declared_context_hash,
        target_units=tuple(target_units),
        tu_flags={unit: projected[unit][0] for unit in target_units},
        tu_directories={
            unit: projected[unit][1] for unit in target_units
        },
        sealed_members=members,
    )
