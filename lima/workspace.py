"""Bounded, read-only repository workspace used by security analysis tools."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path, PurePath
from typing import Iterable, Iterator, Optional

DEFAULT_EXTENSIONS = frozenset(
    {
        ".ac", ".am", ".c", ".cc", ".cmake", ".conf", ".cpp", ".css",
        ".cxx", ".go", ".h", ".hh", ".hpp", ".html", ".hxx", ".in",
        # C++ inline-implementation headers; must mirror the sidecar
        # inventory list so both fingerprints agree (real ResInsight
        # finding: a missing cvfObject.inl broke every prepared TU)
        ".inl", ".ipp", ".tpp",
        ".java", ".js", ".json", ".jsx", ".list", ".m4", ".php", ".po",
        ".pot", ".py", ".rb", ".rs", ".sh", ".toml", ".ts", ".tsx",
        ".yaml", ".yml",
    }
)
DEFAULT_FILENAMES = frozenset(
    {"CMakeLists.txt", "LINGUAS", "Makefile", "Makefile.inc", "Makevars", "config.mk"}
)
CXX_SOURCE_EXTENSIONS = frozenset(
    {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"}
)
CXX_BUILD_EXTENSIONS = frozenset({".cmake"})
DEFAULT_IGNORED_DIRECTORIES = frozenset(
    {
        ".git", ".hg", ".idea", ".mypy_cache", ".pytest_cache", ".ruff_cache",
        ".svn", ".tox", ".venv", "__pycache__", "build", "dist", "node_modules",
        "output", "repositories", "target", "vendor", "venv",
    }
)
DEFAULT_IGNORED_FILES = frozenset({".env", ".env.local", ".env.production"})
LOW_PRIORITY_DIRECTORIES = frozenset(
    {
        "benchmark", "benchmarks", "demo", "demos", "doc", "docs", "example",
        "examples", "fixture", "fixtures", "sample", "samples", "test", "tests",
        "testing",
    }
)
SOURCE_ROOT_DIRECTORIES = frozenset({"app", "lib", "package", "packages", "src"})


@dataclass(frozen=True)
class WorkspaceFile:
    path: str
    size: int
    sha256: str
    line_count: int


@dataclass
class WorkspaceInventory:
    root: str
    files: list[WorkspaceFile] = field(default_factory=list)
    skipped: dict[str, int] = field(default_factory=dict)
    total_bytes: int = 0
    discovered_files: int = 0
    discovered_bytes: int = 0
    truncated: bool = False

    @property
    def file_coverage(self) -> float:
        return len(self.files) / self.discovered_files if self.discovered_files else 1.0

    @property
    def byte_coverage(self) -> float:
        return self.total_bytes / self.discovered_bytes if self.discovered_bytes else 1.0

    def fingerprint(self) -> str:
        digest = hashlib.sha256()
        for item in sorted(self.files, key=lambda value: value.path):
            digest.update(item.path.encode("utf-8"))
            digest.update(b"\0")
            digest.update(str(item.size).encode("ascii"))
            digest.update(b"\0")
            digest.update(item.sha256.encode("ascii"))
            digest.update(b"\n")
        return digest.hexdigest()

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files": [
                {
                    "path": item.path,
                    "size": item.size,
                    "sha256": item.sha256,
                    "line_count": item.line_count,
                }
                for item in self.files
            ],
            "skipped": dict(sorted(self.skipped.items())),
            "total_bytes": self.total_bytes,
            "discovered_files": self.discovered_files,
            "discovered_bytes": self.discovered_bytes,
            "file_coverage": round(self.file_coverage, 6),
            "byte_coverage": round(self.byte_coverage, 6),
            "truncated": self.truncated,
            "fingerprint": self.fingerprint(),
        }


class RepositoryWorkspace:
    """Expose a deterministic subset of a repository without following symlinks."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        max_files: int = 5_000,
        max_file_bytes: int = 512 * 1024,
        max_total_bytes: int = 20 * 1024 * 1024,
        extensions: Optional[Iterable[str]] = None,
        ignored_directories: Optional[Iterable[str]] = None,
        admitted_files: Iterable[str] | None = None,
        metadata_files: Iterable[str] | None = None,
    ) -> None:
        candidate = Path(root).expanduser().resolve(strict=True)
        if not candidate.is_dir():
            raise ValueError("repository root must be a directory")
        if max_files < 1 or max_file_bytes < 1 or max_total_bytes < 1:
            raise ValueError("workspace limits must be positive")

        self.root = candidate
        self.max_files = max_files
        self.max_file_bytes = max_file_bytes
        self.max_total_bytes = max_total_bytes
        self.extensions = frozenset(
            item.lower() if item.startswith(".") else "." + item.lower()
            for item in (extensions or DEFAULT_EXTENSIONS)
        )
        self.ignored_directories = frozenset(
            set(DEFAULT_IGNORED_DIRECTORIES) | set(ignored_directories or ())
        )
        # IP-0023 W-1 (Packet v5.1 section 4.3.1, conditional shared-layer
        # additive whitelist): both default to None = unrestricted, in which
        # case every behaviour below stays byte-identical to the legacy view.
        self._admitted_files = (
            None if admitted_files is None else frozenset(admitted_files)
        )
        self._metadata_files = (
            None if metadata_files is None else frozenset(metadata_files)
        )
        # IP-0023 IR-03 (in-call-scope private read observation): both default
        # to None = observation disabled = behaviour byte-identical to the
        # legacy view. When set, each fires exactly once per real read
        # attempt at the actual read point with the successful byte count
        # (0 when the underlying read itself failed). Instance-scoped only:
        # no caching, no extra reads, no cross-call state.
        self._inventory_read_probe: Callable[[int], None] | None = None
        self._text_read_probe: Callable[[int], None] | None = None

    @property
    def admitted_files(self) -> frozenset[str] | None:
        """S1 source-view slice (workspace-relative POSIX paths; None = unrestricted)."""

        return self._admitted_files

    @property
    def metadata_files(self) -> frozenset[str] | None:
        """Own-manifest metadata view (None = unrestricted)."""

        return self._metadata_files

    def _read_admission(self) -> frozenset[str] | None:
        """Return the read-admission union, or None when the view is unrestricted."""

        if self._admitted_files is None and self._metadata_files is None:
            return None
        union: set[str] = set()
        for group in (self._admitted_files, self._metadata_files):
            if group is not None:
                union.update(group)
        return frozenset(union)

    def _record_skip(self, inventory: WorkspaceInventory, reason: str) -> None:
        inventory.skipped[reason] = inventory.skipped.get(reason, 0) + 1

    def _candidate_priority(self, path: Path) -> tuple[int, str]:
        """Prefer production source roots when a repository exceeds the byte budget."""
        relative = path.relative_to(self.root).as_posix()
        parts = tuple(part.lower() for part in PurePath(relative).parts[:-1])
        if any(part in LOW_PRIORITY_DIRECTORIES for part in parts):
            priority = 2
        elif parts and parts[0] in SOURCE_ROOT_DIRECTORIES:
            priority = 0
        else:
            priority = 1
        return priority, relative

    def _safe_path(self, relative_path: str | os.PathLike[str]) -> Path:
        raw = Path(relative_path)
        if raw.is_absolute():
            raise ValueError("workspace paths must be relative")
        resolved = (self.root / raw).resolve(strict=True)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise ValueError("workspace path escapes repository root") from exc
        if resolved.is_symlink() or not resolved.is_file():
            raise ValueError("workspace path must reference a regular file")
        return resolved

    def inventory(self) -> WorkspaceInventory:
        result = WorkspaceInventory(root=str(self.root))
        candidates: list[Path] = []

        for current_root, directory_names, file_names in os.walk(
            self.root, topdown=True, followlinks=False
        ):
            current = Path(current_root)
            kept_directories = []
            for name in sorted(directory_names):
                child = current / name
                if name in self.ignored_directories:
                    # Restricted views never re-count directory-level skips:
                    # the repository-level workspace already recorded them.
                    if self._admitted_files is None:
                        self._record_skip(result, "ignored-directory")
                elif child.is_symlink():
                    if self._admitted_files is None:
                        self._record_skip(result, "symlink")
                else:
                    kept_directories.append(name)
            directory_names[:] = kept_directories

            for name in sorted(file_names):
                path = current / name
                if self._admitted_files is not None:
                    restricted_relative = path.relative_to(self.root).as_posix()
                    if restricted_relative not in self._admitted_files:
                        # Outside the S1 slice: not discovered, not counted as
                        # skipped, and never part of any statistic (W-1).
                        continue
                if path.is_symlink():
                    self._record_skip(result, "symlink")
                elif name in DEFAULT_IGNORED_FILES or name.startswith(".env."):
                    self._record_skip(result, "sensitive-config")
                elif (
                    name not in DEFAULT_FILENAMES
                    and path.suffix.lower() not in self.extensions
                ):
                    self._record_skip(result, "unsupported-extension")
                else:
                    candidates.append(path)

        candidates.sort(key=self._candidate_priority)
        for path in candidates:
            try:
                size = path.stat().st_size
            except OSError:
                self._record_skip(result, "unreadable")
                continue
            if size > self.max_file_bytes:
                self._record_skip(result, "file-size-limit")
                continue
            result.discovered_files += 1
            result.discovered_bytes += size
            if len(result.files) >= self.max_files:
                result.truncated = True
                self._record_skip(result, "file-limit")
                continue
            if result.total_bytes + size > self.max_total_bytes:
                result.truncated = True
                self._record_skip(result, "total-size-limit")
                continue
            try:
                data = path.read_bytes()
            except OSError:
                if self._inventory_read_probe is not None:
                    self._inventory_read_probe(0)
                self._record_skip(result, "unreadable")
                continue
            if self._inventory_read_probe is not None:
                self._inventory_read_probe(len(data))
            if b"\x00" in data[:8_192]:
                self._record_skip(result, "binary")
                continue
            try:
                decoded = data.decode("utf-8")
            except UnicodeDecodeError:
                self._record_skip(result, "non-utf8")
                continue
            relative = path.relative_to(self.root).as_posix()
            result.files.append(
                WorkspaceFile(
                    relative,
                    size,
                    hashlib.sha256(data).hexdigest(),
                    len(decoded.splitlines()),
                )
            )
            result.total_bytes += size
        return result

    def _require_read_admission(self, resolved: Path) -> None:
        allowed = self._read_admission()
        if allowed is None:
            return
        relative = resolved.relative_to(self.root).as_posix()
        if relative not in allowed:
            raise ValueError(
                "workspace path is not admitted in the restricted view"
            )

    def read_text(self, relative_path: str | os.PathLike[str]) -> str:
        path = self._safe_path(relative_path)
        self._require_read_admission(path)
        if path.stat().st_size > self.max_file_bytes:
            raise ValueError("workspace file exceeds the per-file size limit")
        # Decode raw bytes without universal-newline translation: the
        # inventory hashes exact file bytes, so any newline normalisation
        # here would make CRLF files fail the index drift check (and would
        # also contradict the U+000A-only line-number convention).
        try:
            data = path.read_bytes()
        except OSError:
            if self._text_read_probe is not None:
                self._text_read_probe(0)
            raise
        if self._text_read_probe is not None:
            self._text_read_probe(len(data))
        return data.decode("utf-8")

    def absolute_file(self, relative_path: str | os.PathLike[str]) -> Path:
        """Resolve an inventoried file while enforcing the workspace boundary."""
        path = self._safe_path(relative_path)
        self._require_read_admission(path)
        return path

    def iter_text(self, inventory: Optional[WorkspaceInventory] = None) -> Iterator[tuple[str, str]]:
        snapshot = inventory or self.inventory()
        for item in snapshot.files:
            yield item.path, self.read_text(item.path)
