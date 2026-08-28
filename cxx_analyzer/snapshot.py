"""Independent repository identity verification and isolated snapshot copying."""

from __future__ import annotations

import hashlib
import os
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath

from .config import AnalyzerSettings

# These constants deliberately mirror lima.workspace without importing the application.
DEFAULT_EXTENSIONS = frozenset(
    {
        ".c", ".cc", ".cmake", ".cpp", ".cxx", ".go", ".h", ".hh", ".hpp",
        ".hxx", ".java", ".js", ".json", ".jsx", ".php", ".py", ".rb", ".rs",
        ".sh", ".toml", ".ts", ".tsx", ".yaml", ".yml",
    }
)
DEFAULT_FILENAMES = frozenset({"CMakeLists.txt"})
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
class _InventoryFile:
    path: str
    size: int
    sha256: str


@dataclass
class PreparedSnapshot:
    """A verified temporary tree containing only bounded inventory files."""

    root: Path
    sha256: str
    files: tuple[str, ...]
    _temporary_directory: tempfile.TemporaryDirectory[str]
    _root_identity: tuple[int, int]
    _closed: bool = field(default=False, init=False, repr=False)

    def cleanup(self) -> None:
        self._closed = True
        self._temporary_directory.cleanup()

    def resolve_cwd(self, relative_cwd: str | os.PathLike[str]) -> Path:
        """Resolve a real directory below this live snapshot without following links."""

        if self._closed:
            raise ValueError("prepared snapshot is no longer live")
        raw = Path(relative_cwd)
        if raw.is_absolute() or raw.drive or "\0" in os.fspath(relative_cwd):
            raise ValueError("tool cwd must be relative to the prepared snapshot")
        if ".." in raw.parts:
            raise ValueError("tool cwd must not contain parent traversal")
        try:
            root_metadata = self.root.lstat()
        except OSError as exc:
            raise ValueError("prepared snapshot is no longer live") from exc
        if (
            _is_symlink_or_reparse(self.root, root_metadata)
            or not stat.S_ISDIR(root_metadata.st_mode)
            or (root_metadata.st_dev, root_metadata.st_ino) != self._root_identity
        ):
            raise ValueError("prepared snapshot is no longer live")

        current = self.root
        for part in raw.parts:
            if part in {"", "."}:
                continue
            current = current / part
            try:
                metadata = current.lstat()
            except OSError as exc:
                raise ValueError("tool cwd must be an existing snapshot directory") from exc
            if _is_symlink_or_reparse(current, metadata):
                raise ValueError("tool cwd must not contain a symbolic link")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("tool cwd must reference a snapshot directory")
        try:
            resolved = current.resolve(strict=True)
            resolved.relative_to(self.root)
        except (OSError, ValueError) as exc:
            raise ValueError("tool cwd escapes the prepared snapshot") from exc
        return resolved

    def __enter__(self) -> PreparedSnapshot:
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        self.cleanup()


def _is_symlink_or_reparse(path: Path, metadata: os.stat_result | None = None) -> bool:
    info = metadata if metadata is not None else path.lstat()
    attributes = getattr(info, "st_file_attributes", 0)
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return stat.S_ISLNK(info.st_mode) or bool(attributes & reparse_flag)


def _normalize_repository_key(repository_key: str) -> str:
    if not isinstance(repository_key, str):
        raise ValueError("repository_key must be a string")
    key = repository_key.strip()
    if not key or len(key) > 240:
        raise ValueError("repository_key is required and must be at most 240 characters")
    if "\0" in key or "\\" in key:
        raise ValueError("repository_key must use safe forward-slash segments")
    raw_parts = key.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise ValueError("repository_key contains a forbidden path segment")
    path = PurePosixPath(key)
    parts = path.parts
    if path.is_absolute() or not parts or len(parts) > 16:
        raise ValueError("repository_key must be a bounded relative path")
    for part in parts:
        if part.startswith(".") or len(part) > 80:
            raise ValueError("repository_key contains a forbidden path segment")
        if not part[0].isalnum() or any(
            not (character.isalnum() or character in {"-", "_", "."})
            for character in part
        ):
            raise ValueError("repository_key contains unsupported characters")
    return "/".join(parts)


def _resolve_repository(import_root: str | os.PathLike[str], repository_key: str) -> Path:
    key = _normalize_repository_key(repository_key)
    try:
        root = Path(import_root).expanduser().resolve(strict=True)
        root_metadata = root.lstat()
    except OSError as exc:
        raise ValueError("repository import root is unavailable") from exc
    if _is_symlink_or_reparse(root, root_metadata) or not stat.S_ISDIR(root_metadata.st_mode):
        raise ValueError("repository import root must be a real directory")

    candidate = root
    for part in key.split("/"):
        candidate = candidate / part
        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise ValueError("repository_key does not reference an available repository") from exc
        if _is_symlink_or_reparse(candidate, metadata):
            raise ValueError("repository_key must not traverse a symbolic link")
        if not stat.S_ISDIR(metadata.st_mode):
            raise ValueError("repository_key must reference a directory")
    try:
        candidate.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("repository_key escapes the configured import root") from exc
    return candidate


def _priority(root: Path, path: Path) -> tuple[int, str]:
    relative = path.relative_to(root).as_posix()
    parts = tuple(part.lower() for part in PurePath(relative).parts[:-1])
    if any(part in LOW_PRIORITY_DIRECTORIES for part in parts):
        priority = 2
    elif parts and parts[0] in SOURCE_ROOT_DIRECTORIES:
        priority = 0
    else:
        priority = 1
    return priority, relative


def _path_within(root: Path, path: Path) -> None:
    try:
        path.resolve(strict=True).relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError("repository file escapes repository root") from exc


def _read_regular_file(root: Path, path: Path, max_file_bytes: int) -> bytes:
    _path_within(root, path)
    try:
        before = path.lstat()
    except OSError as exc:
        raise ValueError("repository file is unavailable") from exc
    if _is_symlink_or_reparse(path, before):
        raise ValueError("repository inventory contains a symbolic link")
    if not stat.S_ISREG(before.st_mode):
        raise ValueError("repository inventory contains a non-regular file")
    if before.st_size > max_file_bytes:
        raise ValueError("repository file changed across the inventory boundary")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened.st_mode):
                raise ValueError("repository inventory contains a non-regular file")
            if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
                raise ValueError("repository file identity changed while opening")
            data = handle.read(max_file_bytes + 1)
    except ValueError:
        raise
    except OSError as exc:
        raise ValueError("repository file is unreadable") from exc
    if len(data) > max_file_bytes:
        raise ValueError("repository file changed across the inventory boundary")

    try:
        after = path.lstat()
    except OSError as exc:
        raise ValueError("repository file changed while reading") from exc
    if _is_symlink_or_reparse(path, after) or not stat.S_ISREG(after.st_mode):
        raise ValueError("repository file changed type while reading")
    if (
        (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
        != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        or len(data) != before.st_size
    ):
        raise ValueError("repository file changed while reading")
    _path_within(root, path)
    return data


def _inventory(repository: Path, settings: AnalyzerSettings) -> tuple[_InventoryFile, ...]:
    candidates: list[Path] = []
    for current_root, directory_names, file_names in os.walk(
        repository, topdown=True, followlinks=False
    ):
        current = Path(current_root)
        kept_directories: list[str] = []
        for name in sorted(directory_names):
            child = current / name
            metadata = child.lstat()
            if _is_symlink_or_reparse(child, metadata):
                raise ValueError("repository inventory contains a symbolic link directory")
            if not stat.S_ISDIR(metadata.st_mode):
                raise ValueError("repository inventory contains a non-directory entry")
            if name not in DEFAULT_IGNORED_DIRECTORIES:
                kept_directories.append(name)
        directory_names[:] = kept_directories

        for name in sorted(file_names):
            path = current / name
            metadata = path.lstat()
            if _is_symlink_or_reparse(path, metadata):
                raise ValueError("repository inventory contains a symbolic link file")
            if not stat.S_ISREG(metadata.st_mode):
                raise ValueError("repository inventory contains a non-regular file")
            if name in DEFAULT_IGNORED_FILES or name.startswith(".env."):
                continue
            if name not in DEFAULT_FILENAMES and path.suffix.lower() not in DEFAULT_EXTENSIONS:
                continue
            candidates.append(path)

    candidates.sort(key=lambda path: _priority(repository, path))
    files: list[_InventoryFile] = []
    total_bytes = 0
    for path in candidates:
        try:
            metadata = path.lstat()
        except OSError:
            continue
        if metadata.st_size > settings.repository_scan_max_file_bytes:
            continue
        if len(files) >= settings.repository_scan_max_files:
            continue
        if total_bytes + metadata.st_size > settings.repository_scan_max_total_bytes:
            continue
        try:
            data = _read_regular_file(
                repository, path, settings.repository_scan_max_file_bytes
            )
        except ValueError as exc:
            if "unreadable" in str(exc):
                continue
            raise
        if b"\0" in data[:8192]:
            continue
        try:
            data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        relative = path.relative_to(repository).as_posix()
        files.append(_InventoryFile(relative, len(data), hashlib.sha256(data).hexdigest()))
        total_bytes += len(data)
    return tuple(files)


def _fingerprint(files: tuple[_InventoryFile, ...] | list[_InventoryFile]) -> str:
    digest = hashlib.sha256()
    for item in sorted(files, key=lambda value: value.path):
        digest.update(item.path.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(item.size).encode("ascii"))
        digest.update(b"\0")
        digest.update(item.sha256.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


def _copy_inventory_file(
    repository: Path,
    destination_root: Path,
    item: _InventoryFile,
    max_file_bytes: int,
) -> _InventoryFile:
    source = repository.joinpath(*PurePosixPath(item.path).parts)
    data = _read_regular_file(repository, source, max_file_bytes)
    if len(data) != item.size or hashlib.sha256(data).hexdigest() != item.sha256:
        raise ValueError("repository file changed after inventory verification")

    destination = destination_root.joinpath(*PurePosixPath(item.path).parts)
    destination.parent.mkdir(parents=True, exist_ok=True)
    try:
        destination.relative_to(destination_root)
        with destination.open("xb") as handle:
            handle.write(data)
        metadata = destination.lstat()
    except (OSError, ValueError) as exc:
        raise ValueError("snapshot file could not be copied safely") from exc
    if _is_symlink_or_reparse(destination, metadata) or not stat.S_ISREG(metadata.st_mode):
        raise ValueError("snapshot destination is not a regular file")
    copied = destination.read_bytes()
    copied_sha256 = hashlib.sha256(copied).hexdigest()
    if len(copied) != item.size or copied_sha256 != item.sha256:
        raise ValueError("snapshot file hash does not match inventory")
    return _InventoryFile(item.path, len(copied), copied_sha256)


def prepare_snapshot(
    import_root: str | os.PathLike[str],
    repository_key: str,
    expected_sha256: str,
    work_root: str | os.PathLike[str],
) -> PreparedSnapshot:
    """Verify repository identity and copy its bounded inventory to isolated storage."""

    if (
        not isinstance(expected_sha256, str)
        or len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        raise ValueError("expected snapshot fingerprint must be lowercase SHA-256")
    repository = _resolve_repository(import_root, repository_key)
    settings = AnalyzerSettings.from_env()
    inventory = _inventory(repository, settings)
    if _fingerprint(inventory) != expected_sha256:
        raise ValueError("repository fingerprint does not match expected snapshot")

    try:
        work = Path(work_root).expanduser().resolve(strict=True)
        work_metadata = work.lstat()
    except OSError as exc:
        raise ValueError("snapshot work root is unavailable") from exc
    if _is_symlink_or_reparse(work, work_metadata) or not stat.S_ISDIR(work_metadata.st_mode):
        raise ValueError("snapshot work root must be a real directory")

    temporary_directory = tempfile.TemporaryDirectory(prefix="lima-cxx-", dir=work)
    snapshot_root = Path(temporary_directory.name).resolve(strict=True)
    snapshot_metadata = snapshot_root.lstat()
    try:
        copied = [
            _copy_inventory_file(
                repository,
                snapshot_root,
                item,
                settings.repository_scan_max_file_bytes,
            )
            for item in inventory
        ]
        if _fingerprint(copied) != expected_sha256:
            raise ValueError("copied snapshot fingerprint does not match expected snapshot")
    except Exception:
        temporary_directory.cleanup()
        raise
    return PreparedSnapshot(
        root=snapshot_root,
        sha256=expected_sha256,
        files=tuple(item.path for item in copied),
        _temporary_directory=temporary_directory,
        _root_identity=(snapshot_metadata.st_dev, snapshot_metadata.st_ino),
    )
