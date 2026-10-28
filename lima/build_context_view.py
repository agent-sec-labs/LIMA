"""Verified build artifacts and the read-only analysis view (slice 4A).

This module is the downstream trust boundary for build-agent context
packages.  :func:`verify_build_artifact` re-reads the package through the
fail-crozen package reader and adds the two checks it does not cover: a
per-file byte digest (``artifact_digest`` over every member's canonical
path, length and SHA-256, so a same-length header swap is caught even
though the structural ``context_hash`` is not) and the binding to the
requesting snapshot.  Only a verified artifact can feed
:func:`create_analysis_view`, which lays the package over a fixed snapshot
directory as a read-only projection: overlay conflicts, path escapes and
undeclared target units refuse to create a view at all, and the snapshot
bytes are never written through the view.
"""

from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
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

__all__ = [
    "AnalysisContextView",
    "BuildContextViewError",
    "VerifiedBuildArtifact",
    "compute_artifact_digest",
    "create_analysis_view",
    "verify_build_artifact",
]

_OUTPUT_FLAG: Final = "-o"


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

    Exposes the declared target units, the package identity hashes and the
    per-TU projected compiler arguments; it never writes the snapshot or
    the package.  Downstream TU resolution records its own TU-level hash
    separately - the package ``context_hash`` and ``artifact_digest``
    never masquerade as it.
    """

    snapshot_dir: Path
    target_units: tuple[str, ...]
    context_hash: str
    artifact_digest: str
    package_dir: Path
    _tu_flags: Mapping[str, tuple[str, ...]]

    def flags_for_tu(self, tu: str) -> tuple[str, ...]:
        """Projected arguments for one declared target unit.

        The compiler token and the non-semantic ``-c``/``-o <output>``
        arguments are stripped; everything else (include paths, macros,
        language standard) reaches the consumer in package-relative form.
        """

        try:
            return self._tu_flags[tu]
        except KeyError:
            raise BuildContextViewError(f"tu-not-declared:{tu}") from None


def _project_flags(entry: Mapping[str, JSONValue]) -> tuple[str, ...]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        argv = [item for item in arguments if isinstance(item, str)]
    else:
        command = entry.get("command")
        if not isinstance(command, str) or not command:
            return ()
        try:
            argv = shlex.split(command, posix=True)
        except ValueError:
            return ()
    source_file = entry.get("file")
    arguments_tail = argv[1:]  # the compiler token is not a flag
    projected: list[str] = []
    index = 0
    while index < len(arguments_tail):
        argument = arguments_tail[index]
        if argument == _OUTPUT_FLAG:
            index += 2
            continue
        if argument == "-c" or (
            isinstance(source_file, str) and argument == source_file
        ):
            index += 1
            continue
        projected.append(argument)
        index += 1
    return tuple(projected)


def create_analysis_view(
    snapshot_dir: Path,
    artifact: VerifiedBuildArtifact,
    target_units: tuple[str, ...],
) -> AnalysisContextView:
    """Lay one verified artifact over a fixed snapshot, read-only.

    The package's generated headers must not collide with files already in
    the snapshot, and every requested target unit must be declared in the
    package's compilation database; anything else refuses to create a
    view.  The snapshot directory is only ever read.
    """

    snapshot = Path(snapshot_dir)
    if not snapshot.is_dir():
        raise BuildContextViewError("snapshot-directory-missing")
    if not isinstance(artifact, VerifiedBuildArtifact):
        raise BuildContextViewError("artifact-invalid")
    if not target_units:
        raise BuildContextViewError("target-units-empty")
    for generated in artifact.manifest.generated_headers:
        if (snapshot / generated).exists():
            raise BuildContextViewError(f"overlay-conflict:{generated}")
    try:
        package = read_package(artifact.package_dir)
    except ContextPackageError as exc:
        raise BuildContextViewError(f"package-invalid:{exc}") from exc
    entries = {}
    for entry in package.compdb:
        file_value = entry.get("file")
        if isinstance(file_value, str) and file_value not in entries:
            entries[file_value] = _project_flags(entry)
    declared = set(entries)
    for tu in target_units:
        if tu not in declared:
            raise BuildContextViewError(f"target-tu-missing:{tu}")
    return AnalysisContextView(
        snapshot_dir=snapshot,
        target_units=tuple(target_units),
        context_hash=artifact.context_hash,
        artifact_digest=artifact.artifact_digest,
        package_dir=artifact.package_dir,
        _tu_flags={tu: entries[tu] for tu in target_units},
    )
