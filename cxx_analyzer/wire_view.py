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
_MAX_MANIFEST_BYTES: Final = 1024 * 1024
_MAX_MEMBER_FILE_BYTES: Final = 2 * 1024 * 1024
_MAX_PACKAGE_TOTAL_BYTES: Final = 256 * 1024 * 1024
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
_MANIFEST_FIELDS: Final = frozenset(
    {
        "schema_version", "repository", "revision", "context_hash", "created_by",
        "compdb", "generated_headers", "header_roots", "totals",
    }
)
_COMPDB_FIELDS: Final = frozenset(
    {"entry_count", "tu_list", "path_prefix_rewrite"}
)
_TOTALS_FIELDS: Final = frozenset(
    {"compdb_entries", "generated_header_count", "header_file_count", "total_bytes"}
)
_RESERVED_ROOT_NAMES: Final = frozenset(
    {MANIFEST_MEMBER, COMPDB_MEMBER, _GENERATED_PACKAGE_ROOT}
)


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
        try:
            encoded = normalized.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise WireViewError("invalid-unicode") from exc
        if len(encoded) > _MAX_STRING_BYTES:
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
            normalized_key = _walk(key, depth + 1)
            if normalized_key in normalized:
                raise WireViewError("duplicate-semantic-field")
            normalized[normalized_key] = _walk(item, depth + 1)
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
    except (RecursionError, ValueError) as exc:
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


def _nfc_text(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and not any(unicodedata.category(character) == "Cc" for character in value)
        and len(value.encode("utf-8")) <= maximum
    )


def _safe_relative_path(value: object) -> bool:
    if not _nfc_text(value, 1024):
        return False
    assert isinstance(value, str)
    segments = value.split("/")
    return (
        "\\" not in value
        and ":" not in value
        and not value.startswith("/")
        and all(segment not in {"", ".", ".."} for segment in segments)
    )


def _absolute_prefix(value: object) -> bool:
    if not _nfc_text(value, 1024):
        return False
    assert isinstance(value, str)
    return (
        value.startswith("/")
        and value != "/"
        and not value.endswith("/")
        and "\\" not in value
        and ":" not in value
        and all(segment not in {"", ".", ".."} for segment in value.split("/")[1:])
    )


def _sorted_unique_paths(values: object, *, reserved_roots: bool) -> bool:
    if not isinstance(values, list) or any(not _safe_relative_path(value) for value in values):
        return False
    assert all(isinstance(value, str) for value in values)
    return (
        values == sorted(values)
        and len(values) == len(set(values))
        and (
            not reserved_roots
            or all(value.split("/", 1)[0] not in _RESERVED_ROOT_NAMES for value in values)
        )
    )


def _validate_manifest(manifest: dict[str, object]) -> tuple[
    dict[str, object], list[str], list[str], dict[str, str]
]:
    """Mirror the closed ContextManifest contract without importing lima."""

    if set(manifest) != _MANIFEST_FIELDS:
        raise WireViewError("manifest-fields-invalid")
    if type(manifest["schema_version"]) is not int or (
        manifest["schema_version"] != _PACKAGE_SCHEMA_VERSION
    ):
        raise WireViewError("manifest-schema-unsupported")
    for field in ("repository", "revision", "created_by"):
        if not _nfc_text(manifest[field], 512):
            raise WireViewError("manifest-text-invalid")
    if not _hex64(manifest["context_hash"]):
        raise WireViewError("manifest-context-hash-invalid")

    compdb = manifest["compdb"]
    if not isinstance(compdb, dict) or set(compdb) != _COMPDB_FIELDS:
        raise WireViewError("manifest-compdb-block-invalid")
    entry_count = compdb["entry_count"]
    tu_list = compdb["tu_list"]
    rewrites = compdb["path_prefix_rewrite"]
    if (
        type(entry_count) is not int
        or not 1 <= entry_count <= 2048
        or not _sorted_unique_paths(tu_list, reserved_roots=False)
        or not isinstance(rewrites, dict)
    ):
        raise WireViewError("manifest-compdb-block-invalid")
    assert isinstance(tu_list, list)
    if len(tu_list) != entry_count:
        raise WireViewError("manifest-compdb-block-invalid")
    for original, package in rewrites.items():
        if not _absolute_prefix(original) or not _safe_relative_path(package):
            raise WireViewError("manifest-compdb-block-invalid")
        assert isinstance(package, str)
        if package.split("/", 1)[0] in _RESERVED_ROOT_NAMES:
            raise WireViewError("manifest-compdb-block-invalid")

    generated = manifest["generated_headers"]
    roots = manifest["header_roots"]
    if not _sorted_unique_paths(generated, reserved_roots=False) or not _sorted_unique_paths(
        roots, reserved_roots=True
    ):
        raise WireViewError("manifest-roots-invalid")
    assert isinstance(generated, list) and isinstance(roots, list)
    if any(other.startswith(root + "/") for root in roots for other in roots if other != root):
        raise WireViewError("manifest-roots-invalid")

    totals = manifest["totals"]
    if not isinstance(totals, dict) or set(totals) != _TOTALS_FIELDS:
        raise WireViewError("manifest-totals-invalid")
    ranges = {
        "compdb_entries": (1, 2048),
        "generated_header_count": (0, 2048),
        "header_file_count": (0, None),
        "total_bytes": (0, _MAX_PACKAGE_TOTAL_BYTES),
    }
    for field, (minimum, maximum) in ranges.items():
        value = totals[field]
        if type(value) is not int or value < minimum or (
            maximum is not None and value > maximum
        ):
            raise WireViewError("manifest-totals-invalid")
    if (
        totals["compdb_entries"] != entry_count
        or totals["generated_header_count"] != len(generated)
    ):
        raise WireViewError("manifest-totals-invalid")
    return compdb, generated, roots, rewrites


def _validate_package_members(
    members: dict[str, bytes], generated: list[str], roots: list[str], totals: dict[str, object]
) -> None:
    """Mirror read_package's inventory and payload-total verification."""

    if any(
        not _safe_relative_path(path) or not isinstance(data, bytes)
        for path, data in members.items()
    ):
        raise WireViewError("package-member-invalid")
    generated_members: dict[str, bytes] = {}
    header_members: dict[str, bytes] = {}
    root_seen = {root: False for root in roots}
    for path, data in members.items():
        if path in {MANIFEST_MEMBER, COMPDB_MEMBER}:
            continue
        if path.startswith(_GENERATED_PACKAGE_ROOT + "/"):
            relative = path[len(_GENERATED_PACKAGE_ROOT) + 1 :]
            if not _safe_relative_path(relative) or len(data) > _MAX_MEMBER_FILE_BYTES:
                raise WireViewError("generated-member-invalid")
            generated_members[relative] = data
            continue
        matching_roots = [root for root in roots if path.startswith(root + "/")]
        if len(matching_roots) != 1 or len(data) > _MAX_MEMBER_FILE_BYTES:
            raise WireViewError("header-member-invalid")
        header_members[path] = data
        root_seen[matching_roots[0]] = True
    if sorted(generated_members) != generated:
        raise WireViewError("generated-file-mismatch")
    if not all(root_seen.values()):
        raise WireViewError("header-root-missing")
    header_count = len(header_members)
    total_bytes = (
        len(members[COMPDB_MEMBER])
        + sum(len(data) for data in generated_members.values())
        + sum(len(data) for data in header_members.values())
    )
    if total_bytes > _MAX_PACKAGE_TOTAL_BYTES:
        raise WireViewError("package-too-large")
    if totals["header_file_count"] != header_count or totals["total_bytes"] != total_bytes:
        raise WireViewError("package-totals-mismatch")


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
    if (
        not isinstance(manifest_bytes, bytes)
        or not isinstance(compdb_bytes, bytes)
    ):
        raise WireViewError("core-member-missing")
    if len(manifest_bytes) > _MAX_MANIFEST_BYTES:
        raise WireViewError("manifest-too-large")
    if len(compdb_bytes) > _MAX_COMPDB_BYTES:
        raise WireViewError("compdb-too-large")

    manifest = _decode_member(manifest_bytes)
    if not isinstance(manifest, dict):
        raise WireViewError("manifest-not-object")
    compdb_block, generated, header_roots, rewrites = _validate_manifest(manifest)
    revision = manifest.get("revision")
    if not _hex64(revision) or revision != snapshot_sha256:
        raise WireViewError("snapshot-not-bound")
    declared_context_hash = manifest.get("context_hash")
    assert isinstance(declared_context_hash, str)
    assert isinstance(compdb_block["entry_count"], int)
    assert isinstance(compdb_block["tu_list"], list)
    assert isinstance(manifest["totals"], dict)
    entry_count = compdb_block["entry_count"]
    tu_list = compdb_block["tu_list"]
    _validate_package_members(members, generated, header_roots, manifest["totals"])

    compdb_document = _decode_member(compdb_bytes)
    if not isinstance(compdb_document, list):
        raise WireViewError("compdb-not-array")
    if len(compdb_document) != entry_count:
        raise WireViewError("compdb-entry-count-mismatch")
    entries: dict[str, dict[str, object]] = {}
    files: list[str] = []
    for entry in compdb_document:
        if not isinstance(entry, dict):
            raise WireViewError("compdb-entry-not-object")
        file_value = entry.get("file")
        if not _safe_relative_path(file_value) or file_value in entries:
            raise WireViewError("compdb-entry-invalid")
        assert isinstance(file_value, str)
        entries[file_value] = entry
        files.append(file_value)
    if sorted(files) != tu_list:
        raise WireViewError("compdb-tu-list-mismatch")
    if not hmac.compare_digest(
        _compute_context_hash(
            compdb_document,
            generated,
            header_roots,
            rewrites,
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
    # create_analysis_view projects the complete compilation database before
    # selecting requested TUs.  Keep that fail-closed boundary here too: an
    # invalid non-target command must not yield a wire view that the local
    # verified-package path would refuse to construct.
    projected = {
        unit: _project_entry(entry, package_roots)
        for unit, entry in entries.items()
    }
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
