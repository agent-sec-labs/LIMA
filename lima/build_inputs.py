"""Fail-closed collection of a repository snapshot's build inputs.

The build container must receive only regular, non-sensitive files which are
inside the supplied snapshot.  In particular, links and Windows junctions
are errors rather than an invitation to dereference host paths.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import shutil
import stat
import time
from collections.abc import Callable
from pathlib import Path
from typing import Protocol

__all__ = [
    "BuildInputError",
    "BuildInputManifest",
    "BuildInputMember",
    "collect_build_inputs",
    "compute_build_input_digest",
    "copy_build_inputs",
]


class _Limits(Protocol):
    max_input_files: int
    max_input_file_bytes: int
    max_input_total_bytes: int


class BuildInputError(ValueError):
    """A stable, non-path-bearing reason why an input snapshot was refused."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


@dataclasses.dataclass(frozen=True, slots=True)
class BuildInputMember:
    path: str
    bytes: int
    sha256: str


@dataclasses.dataclass(frozen=True, slots=True)
class BuildInputManifest:
    members: tuple[BuildInputMember, ...]
    digest: str

    def as_record(self) -> dict[str, object]:
        return {
            "algorithm": "sha256",
            "digest": self.digest,
            "members": [dataclasses.asdict(member) for member in self.members],
        }


_EXCLUDED_DIRS = frozenset({
    ".git", ".hg", ".svn", ".cache", ".ssh", ".venv", "venv",
    "__pycache__", ".mypy_cache", ".pytest_cache", "node_modules",
    "build", "_build", "dist", "out", "target",
})
_SENSITIVE_NAMES = frozenset({
    ".netrc", ".npmrc", ".pypirc", "id_rsa", "id_dsa", "id_ecdsa",
    "id_ed25519", "credentials", "credentials.json",
})


def _is_link_or_junction(path: Path) -> bool:
    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None and isjunction(path):
        return True
    try:
        attrs = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attrs & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _excluded(path: Path) -> bool:
    name = path.name.lower()
    return (
        name == ".env"
        or name.startswith(".env.")
        or name in _SENSITIVE_NAMES
        or name in _EXCLUDED_DIRS
    )


def _check_interrupt(*, deadline: float | None, cancel: Callable[[], bool]) -> None:
    if cancel():
        raise BuildInputError("cancelled")
    if deadline is not None and time.monotonic() >= deadline:
        raise BuildInputError("budget-exhausted")


def _walk_error(_error: OSError) -> None:
    """``os.walk`` otherwise silently omits unreadable directories."""

    raise BuildInputError("build-input-unreadable")


def _check_inside(root: Path, candidate: Path) -> None:
    """Reject links in every component and every resolved outside path."""

    if _is_link_or_junction(root):
        raise BuildInputError("build-input-link")
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise BuildInputError("build-input-outside-root") from exc
    current = root
    for component in relative.parts:
        current = current / component
        if _is_link_or_junction(current):
            raise BuildInputError("build-input-link")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except ValueError as exc:
        raise BuildInputError("build-input-outside-root") from exc
    except OSError as exc:
        raise BuildInputError("build-input-unreadable") from exc


def _digest(members: list[BuildInputMember]) -> str:
    payload = json.dumps(
        [dataclasses.asdict(member) for member in members],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf8")
    return hashlib.sha256(payload).hexdigest()


def collect_build_inputs(
    snapshot_dir: str | Path,
    limits: _Limits,
    *,
    deadline: float | None = None,
    cancel: Callable[[], bool] = lambda: False,
) -> BuildInputManifest:
    """Hash permitted files, rejecting every link/reparse point fail-closed."""

    root = Path(snapshot_dir)
    if _is_link_or_junction(root):
        raise BuildInputError("build-input-link")
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise BuildInputError("build-input-unreadable") from exc
    if not root.is_dir():
        raise BuildInputError("build-input-directory-missing")
    members: list[BuildInputMember] = []
    total = 0
    for current, directories, files in os.walk(
        root, topdown=True, followlinks=False, onerror=_walk_error
    ):
        _check_interrupt(deadline=deadline, cancel=cancel)
        base = Path(current)
        kept_dirs: list[str] = []
        for name in sorted(directories):
            candidate = base / name
            _check_inside(root, candidate)
            if name.lower() not in _EXCLUDED_DIRS:
                kept_dirs.append(name)
        directories[:] = kept_dirs
        for name in sorted(files):
            _check_interrupt(deadline=deadline, cancel=cancel)
            candidate = base / name
            _check_inside(root, candidate)
            if _excluded(candidate):
                continue
            try:
                relative = candidate.relative_to(root).as_posix()
                info = candidate.stat()
            except OSError as exc:
                raise BuildInputError("build-input-unreadable") from exc
            if not stat.S_ISREG(info.st_mode):
                raise BuildInputError("build-input-not-regular")
            if info.st_size > limits.max_input_file_bytes:
                raise BuildInputError("build-input-file-too-large")
            if len(members) >= limits.max_input_files:
                raise BuildInputError("build-input-file-limit")
            hasher = hashlib.sha256()
            actual_bytes = 0
            try:
                with candidate.open("rb") as handle:
                    while chunk := handle.read(1024 * 1024):
                        _check_interrupt(deadline=deadline, cancel=cancel)
                        actual_bytes += len(chunk)
                        total += len(chunk)
                        if actual_bytes > limits.max_input_file_bytes:
                            raise BuildInputError("build-input-file-too-large")
                        if total > limits.max_input_total_bytes:
                            raise BuildInputError("build-input-total-too-large")
                        hasher.update(chunk)
            except OSError as exc:
                raise BuildInputError("build-input-unreadable") from exc
            _check_inside(root, candidate)
            try:
                final_size = candidate.stat().st_size
            except OSError as exc:
                raise BuildInputError("build-input-unreadable") from exc
            if final_size > limits.max_input_file_bytes:
                raise BuildInputError("build-input-file-too-large")
            if actual_bytes != info.st_size or final_size != info.st_size:
                raise BuildInputError("build-input-mutated")
            members.append(BuildInputMember(relative, actual_bytes, hasher.hexdigest()))
    return BuildInputManifest(tuple(members), _digest(members))


def copy_build_inputs(
    manifest: BuildInputManifest,
    snapshot_dir: str | Path,
    destination: str | Path,
    *,
    deadline: float | None = None,
    cancel: Callable[[], bool] = lambda: False,
) -> None:
    """Copy exactly a previously hashed manifest, checking hash while copying."""

    root = Path(snapshot_dir)
    if _is_link_or_junction(root):
        raise BuildInputError("build-input-link")
    try:
        root = root.resolve(strict=True)
    except OSError as exc:
        raise BuildInputError("build-input-unreadable") from exc
    target = Path(destination)
    target.mkdir(parents=True, exist_ok=False)
    for member in manifest.members:
        _check_interrupt(deadline=deadline, cancel=cancel)
        source = root / Path(*member.path.split("/"))
        _check_inside(root, source)
        output = target / Path(*member.path.split("/"))
        output.parent.mkdir(parents=True, exist_ok=True)
        hasher = hashlib.sha256()
        copied = 0
        try:
            with source.open("rb") as input_handle, output.open("xb") as output_handle:
                while chunk := input_handle.read(1024 * 1024):
                    _check_interrupt(deadline=deadline, cancel=cancel)
                    copied += len(chunk)
                    if copied > member.bytes:
                        raise BuildInputError("build-input-file-too-large")
                    hasher.update(chunk)
                    output_handle.write(chunk)
            shutil.copystat(source, output, follow_symlinks=False)
        except OSError as exc:
            raise BuildInputError("build-input-unreadable") from exc
        _check_inside(root, source)
        if copied != member.bytes or hasher.hexdigest() != member.sha256:
            raise BuildInputError("build-input-mutated")


def compute_build_input_digest(
    snapshot_dir: str | Path,
    limits: _Limits | None = None,
    *,
    deadline: float | None = None,
    cancel: Callable[[], bool] = lambda: False,
) -> str:
    """Return the stable digest used to decide whether a build may be reused."""

    if limits is None:
        # Keep this independent from build_executor to avoid an import cycle.
        @dataclasses.dataclass(frozen=True, slots=True)
        class _DefaultLimits:
            max_input_files: int = 50_000
            max_input_file_bytes: int = 32 * 1024 * 1024
            max_input_total_bytes: int = 512 * 1024 * 1024

        limits = _DefaultLimits()
    return collect_build_inputs(snapshot_dir, limits, deadline=deadline, cancel=cancel).digest
