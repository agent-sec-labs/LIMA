"""Verified build artifacts and the read-only analysis view (slice 4A).

This module is the downstream trust boundary for build-agent context
packages.  :func:`verify_build_artifact` re-reads the package through the
fail-closed package reader and adds the two checks it does not cover: a
per-file byte digest (``artifact_digest`` over every member's canonical
path, length and SHA-256, so a same-length header swap is caught even
though the structural ``context_hash`` is not) and the binding to the
requesting snapshot.  :func:`create_analysis_view` then re-verifies every
identity at view-construction time - a package directory is mutable
between the two calls, so the artifact digest, manifest revision and
context hash are re-checked, and the snapshot directory itself must
re-fingerprint to the bound identity.  The resulting view is a read-only
projection: overlay conflicts, path escapes, undeclared or missing target
units and unparseable compile commands all refuse to create a view, and
the snapshot bytes are never written through the view.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import posixpath
import shlex
from collections.abc import Mapping
from pathlib import Path
from typing import Final

from lima.context_package import (
    ContextManifest,
    ContextPackageError,
    JSONValue,
    read_package,
)
from lima.workspace import RepositoryWorkspace

__all__ = [
    "AnalysisContextView",
    "BuildContextViewError",
    "VerifiedBuildArtifact",
    "compute_artifact_digest",
    "create_analysis_view",
    "snapshot_fingerprint",
    "verify_build_artifact",
]

# Options whose (separate) value is a path that participates in the
# include semantics of the compile command.
_DIR_VALUE_OPTIONS: Final = frozenset(
    {"-I", "-isystem", "-iquote", "-idirafter", "-stdlib++-isystem"}
)
_FILE_VALUE_OPTIONS: Final = frozenset({"-include", "-imacros"})
# Options whose separate value is a plain operand (language, macro,
# target triple, dependency file): the value belongs to the command and
# must never be mistaken for the source file.
_TAKES_VALUE_OPTIONS: Final = frozenset(
    {"-x", "-D", "-U", "-target", "-arch", "-isysroot", "--sysroot", "-B",
     "-MF", "-MT", "-MQ"}
)
_GENERATED_PACKAGE_ROOT: Final = "generated"
# Sealing bound: the view holds package member bytes in memory so the
# original mutable directory stops being the authoritative source.
_MAX_SEALED_BYTES: Final = 64 * 1024 * 1024


class BuildContextViewError(ValueError):
    """Fail-closed view violation with a stable reason string."""

    reason: str

    def __init__(self, reason: str) -> None:
        if not isinstance(reason, str) or not reason:
            raise TypeError("reason must be a non-empty str")
        self.reason = reason
        super().__init__(reason)


def _member_files(package_dir: Path) -> list[tuple[str, bytes]]:
    """Every regular package member as ``(posix_relative, bytes)``.

    Symlinks are rejected: a package is plain files, and anything else is
    an attempted escape rather than evidence.
    """

    if not package_dir.is_dir():
        raise BuildContextViewError("package-directory-missing")
    try:
        paths = sorted(
            package_dir.rglob("*"),
            key=lambda path: path.relative_to(package_dir).as_posix(),
        )
    except OSError as exc:
        raise BuildContextViewError("package-entry-unreadable") from exc
    members: list[tuple[str, bytes]] = []
    for path in paths:
        if path.is_symlink():
            raise BuildContextViewError(
                f"package-entry-symlink:{path.name}"
            )
        if not path.is_file():
            continue
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise BuildContextViewError("package-entry-unreadable") from exc
        members.append(
            (path.relative_to(package_dir).as_posix(), data)
        )
    return members


def compute_artifact_digest(package_dir: Path) -> str:
    """Per-file byte digest over every package member.

    Each member contributes its canonical posix path, byte length and
    SHA-256; the sorted member list is hashed into one digest.  Two
    byte-identical packages hash equal and any single-byte change does
    not - including swaps that keep every length identical.
    """

    material = [
        {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for relative, data in _member_files(Path(package_dir))
    ]
    payload = json.dumps(material, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(payload.encode("utf8")).hexdigest()


def _snapshot_inventory(snapshot_dir: Path):
    """The deterministic workspace inventory of a source directory."""

    try:
        workspace = RepositoryWorkspace(str(snapshot_dir))
    except (ValueError, OSError) as exc:
        raise BuildContextViewError("snapshot-directory-missing") from exc
    return workspace.inventory()


def snapshot_fingerprint(snapshot_dir: Path) -> str:
    """The control-plane snapshot identity of a source directory.

    Uses the same rule the repository workspace inventory defines
    (per-file path, size and SHA-256 over the deterministic inventory).
    The inventory is filtered and bounded, so this identity covers exactly
    the files it lists - consumers must check coverage, not assume it.
    """

    return _snapshot_inventory(snapshot_dir).fingerprint()


@dataclasses.dataclass(frozen=True, slots=True)
class VerifiedBuildArtifact:
    """A package whose structure, bytes and snapshot binding all verified."""

    package_dir: Path
    manifest: ContextManifest
    snapshot_hash: str
    context_hash: str
    artifact_digest: str


def verify_build_artifact(
    package_dir: Path,
    expected_snapshot_hash: str,
    expected_artifact_digest: str,
) -> VerifiedBuildArtifact:
    """Verify one package against its declared snapshot and byte digest.

    Runs the fail-closed package reader (structure, context hash, member
    inventory), then re-checks the snapshot binding and the per-file
    artifact digest.  Any violation raises before a view can exist.
    """

    package_dir = Path(package_dir)
    try:
        package = read_package(package_dir)
    except ContextPackageError as exc:
        raise BuildContextViewError(f"package-invalid:{exc}") from exc
    if package.manifest.revision != expected_snapshot_hash:
        raise BuildContextViewError("snapshot-mismatch")
    actual = compute_artifact_digest(package_dir)
    if not hmac.compare_digest(actual, expected_artifact_digest):
        raise BuildContextViewError("artifact-digest-mismatch")
    return VerifiedBuildArtifact(
        package_dir=package_dir,
        manifest=package.manifest,
        snapshot_hash=expected_snapshot_hash,
        context_hash=package.manifest.context_hash,
        artifact_digest=actual,
    )


@dataclasses.dataclass(frozen=True, slots=True)
class AnalysisContextView:
    """A read-only projection of one verified package over one snapshot.

    The package members are sealed into the view at construction: package
    bytes are consumed through :meth:`read_member`, never through a
    mutable package directory, so the verified ``artifact_digest`` keeps
    constraining the bytes a consumer actually sees.  The view also
    exposes the declared target units, the package identity hashes and
    the per-TU working directory and projected arguments; it never writes
    the snapshot or the package.  Downstream TU resolution records its
    own TU-level hash separately - the package ``context_hash`` and
    ``artifact_digest`` never masquerade as it.
    """

    snapshot_dir: Path
    target_units: tuple[str, ...]
    context_hash: str
    artifact_digest: str
    _tu_flags: Mapping[str, tuple[str, ...]]
    _tu_directories: Mapping[str, str]
    _sealed_members: Mapping[str, bytes]

    @property
    def member_paths(self) -> tuple[str, ...]:
        """The sealed package members, in canonical posix order."""

        return tuple(sorted(self._sealed_members))

    def read_member(self, path: str) -> bytes:
        """Read one package member from the sealed, verified copy."""

        try:
            return self._sealed_members[path]
        except KeyError:
            raise BuildContextViewError(f"member-not-sealed:{path}") from None

    def working_directory_for_tu(self, tu: str) -> str:
        """The compile command's working directory, repository-relative."""

        try:
            return self._tu_directories[tu]
        except KeyError:
            raise BuildContextViewError(f"tu-not-declared:{tu}") from None

    def flags_for_tu(self, tu: str) -> tuple[str, ...]:
        """Projected arguments for one declared target unit.

        The compiler token, the ``-c`` flag, the ``-o`` output (separate or
        joined) and the source file are stripped.  Values of known
        operand-taking options are preserved; a bare token that does not
        match the entry's source file under directory semantics refuses
        the view instead of being silently dropped.  Include and
        forced-include paths stay package-relative when they point into
        the package roots (vendored headers, generated files); other
        non-absolute paths are already repository-relative - the slice-1
        producer relativizes them - and are only normalized, never
        re-prefixed with the working directory.
        """

        try:
            return self._tu_flags[tu]
        except KeyError:
            raise BuildContextViewError(f"tu-not-declared:{tu}") from None


def _normjoin(directory: str, value: str) -> str:
    return posixpath.normpath(posixpath.join(directory, value))


def _project_entry(
    entry: Mapping[str, JSONValue],
    package_roots: frozenset[str],
) -> tuple[tuple[str, ...], str]:
    """Project one compdb entry to ``(flags, working directory)``.

    An unparseable compile command is a hard error, never an empty flag
    list, and a bare token that is neither a known option operand nor the
    entry's source file (under directory semantics) refuses the view
    rather than being dropped silently.
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
            raise BuildContextViewError("compdb-command-missing")
        try:
            argv = shlex.split(command, posix=True)
        except ValueError as exc:
            raise BuildContextViewError("compdb-command-unparseable") from exc
    if not argv:
        raise BuildContextViewError("compdb-command-empty")

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
        # Slice-1 producers resolve include values against the original
        # compile directory before relativizing, so a non-absolute,
        # non-package value is already repository-relative: normalize
        # only, never re-prefix it with the working directory - and a
        # value that still escapes the repository root is refused.
        for root in package_roots:
            if value == root or value.startswith(root + "/"):
                return value
        normalized = posixpath.normpath(value)
        if normalized == ".." or normalized.startswith("../"):
            raise BuildContextViewError(f"compdb-include-escape:{value}")
        return normalized

    projected: list[str] = []
    index = 1  # the compiler token is not a flag
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
            raise BuildContextViewError(
                f"compdb-unexpected-positional:{argument}"
            )
        if argument in _DIR_VALUE_OPTIONS or argument in _FILE_VALUE_OPTIONS:
            if index + 1 >= len(argv):
                raise BuildContextViewError("compdb-command-malformed-option")
            projected.append(argument)
            projected.append(map_path(argv[index + 1]))
            index += 2
            continue
        if argument in _TAKES_VALUE_OPTIONS:
            if index + 1 >= len(argv):
                raise BuildContextViewError("compdb-command-malformed-option")
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


def create_analysis_view(
    snapshot_dir: Path,
    artifact: VerifiedBuildArtifact,
    target_units: tuple[str, ...],
) -> AnalysisContextView:
    """Lay one verified artifact over a fixed snapshot, read-only.

    Nothing between :func:`verify_build_artifact` and this call is
    trusted: the package directory is re-read, its current artifact
    digest, manifest revision and context hash must all still match the
    verified artifact, and the snapshot directory must re-fingerprint to
    the bound snapshot identity.  The package's generated headers must
    not collide with existing snapshot files, every requested target unit
    must be declared in the compilation database and present as a source
    file inside the snapshot, and every compile command must parse.
    Anything else refuses to create a view; the snapshot is only read.
    """

    snapshot = Path(snapshot_dir)
    if not snapshot.is_dir():
        raise BuildContextViewError("snapshot-directory-missing")
    if not isinstance(artifact, VerifiedBuildArtifact):
        raise BuildContextViewError("artifact-invalid")
    if not target_units:
        raise BuildContextViewError("target-units-empty")
    inventory = _snapshot_inventory(snapshot)
    if inventory.fingerprint() != artifact.snapshot_hash:
        raise BuildContextViewError("snapshot-directory-mismatch")
    covered = {item.path for item in inventory.files}

    # Re-verify the mutable package directory at view-construction time.
    try:
        package = read_package(artifact.package_dir)
    except ContextPackageError as exc:
        raise BuildContextViewError(f"package-invalid:{exc}") from exc
    if package.manifest.revision != artifact.snapshot_hash:
        raise BuildContextViewError("snapshot-mismatch")
    if not hmac.compare_digest(
        package.manifest.context_hash, artifact.context_hash
    ):
        raise BuildContextViewError("context-hash-mismatch")
    sealed_members = dict(_member_files(artifact.package_dir))
    sealed_bytes = sum(len(data) for data in sealed_members.values())
    digest_material = [
        {
            "path": relative,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        for relative, data in sorted(sealed_members.items())
    ]
    current_digest = hashlib.sha256(
        json.dumps(digest_material, sort_keys=True, ensure_ascii=False).encode(
            "utf8"
        )
    ).hexdigest()
    if not hmac.compare_digest(current_digest, artifact.artifact_digest):
        raise BuildContextViewError("artifact-digest-mismatch")
    if sealed_bytes > _MAX_SEALED_BYTES:
        raise BuildContextViewError("package-too-large-to-seal")

    for generated in package.manifest.generated_headers:
        if (snapshot / generated).exists():
            raise BuildContextViewError(f"overlay-conflict:{generated}")

    package_roots = frozenset(package.manifest.header_roots) | {
        _GENERATED_PACKAGE_ROOT
    }
    entries: dict[str, tuple[tuple[str, ...], str]] = {}
    for entry in package.compdb:
        file_value = entry.get("file")
        if isinstance(file_value, str) and file_value not in entries:
            entries[file_value] = _project_entry(entry, package_roots)
    declared = set(entries)
    for tu in target_units:
        if tu not in declared:
            raise BuildContextViewError(f"target-tu-missing:{tu}")
        if tu not in covered:
            # The fingerprint only covers the deterministic inventory; a
            # target outside it could change without changing the bound
            # identity, so it is refused rather than waved through.
            raise BuildContextViewError(f"target-tu-not-covered:{tu}")
        if not (snapshot / tu).is_file():
            raise BuildContextViewError(f"target-tu-missing-in-snapshot:{tu}")
    return AnalysisContextView(
        snapshot_dir=snapshot,
        target_units=tuple(target_units),
        context_hash=artifact.context_hash,
        artifact_digest=artifact.artifact_digest,
        _tu_flags={tu: entries[tu][0] for tu in target_units},
        _tu_directories={tu: entries[tu][1] for tu in target_units},
        _sealed_members=sealed_members,
    )
