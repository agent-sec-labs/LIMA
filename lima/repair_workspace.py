"""Disposable per-task repair workspaces over pinned repository snapshots.

A :class:`RepairWorkspace` copies the repair-relevant subset of a materialized
snapshot out of the repository cache into a fresh per-task scratch directory,
keeps the underlying cache entry pinned for its whole lifetime, and destroys
the directory when the task ends.  It never writes to the source snapshot, the
cache volume, or GitHub: composition is plain file copying — no git clone,
checkout or worktree — and the workspace itself is never published back into
the cache (issue #16 / T7).

Fail-closed properties:

- the scratch directory is fresh per task (``<base>/<task_id>``); an existing
  directory is refused instead of overwritten;
- source paths are resolved inside the snapshot root, symbolic links are
  rejected, and per-file / total budgets bound the copy phase;
- any failure during composition removes the partial directory and releases
  the pin before the error surfaces.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass
from pathlib import Path

from .repository_cache import CacheEntry, RepositoryCache
from .repository_source import parse_repository_source

DEFAULT_MAX_FILES = 5_000
DEFAULT_MAX_FILE_BYTES = 100 * 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 1024 * 1024 * 1024


class RepairWorkspaceError(RuntimeError):
    """Raised when a repair workspace cannot be composed or is misused."""


@dataclass(frozen=True)
class RepairWorkspaceLimits:
    max_files: int = DEFAULT_MAX_FILES
    max_file_bytes: int = DEFAULT_MAX_FILE_BYTES
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES


class RepairWorkspace:
    """A disposable scratch copy of the repair-relevant snapshot subset."""

    def __init__(self, root: Path, base: Path, pin) -> None:
        self.root = root
        self._base = base
        # contextlib 生成器上下文（来自 RepositoryCache.pin），由本对象托管
        self._pin = pin
        self._disposed = False

    # ------------------------------------------------------------------
    # Composition
    # ------------------------------------------------------------------

    @classmethod
    def compose(
        cls,
        cache: RepositoryCache,
        base_root: str | Path,
        task_id: str,
        entry: CacheEntry,
        requested_paths: list[str],
        *,
        limits: RepairWorkspaceLimits | None = None,
    ) -> RepairWorkspace:
        """Copy ``requested_paths`` out of a pinned cache entry.

        ``entry`` supplies both the snapshot identity (for the pin) and the
        snapshot root that files are copied from.  ``requested_paths`` are
        repository-relative paths such as the repair-preview candidate set.
        """

        limits = limits or RepairWorkspaceLimits()
        if not task_id or any(
            character in task_id for character in "/\\:*?\"<>|"
        ) or task_id in {".", ".."}:
            raise RepairWorkspaceError("task_id must be a safe directory name")
        base = Path(base_root).expanduser().resolve()
        root = base / task_id
        if root.exists():
            raise RepairWorkspaceError(
                "repair workspace directory already exists; refusing to "
                "overwrite anything outside a fresh directory"
            )

        source = parse_repository_source(entry.source)
        pin = cache.pin(source, entry.resolved_revision)
        pin.__enter__()
        workspace = cls(root, base, pin)
        snapshot_root = entry.path.resolve()
        try:
            base.mkdir(parents=True, exist_ok=True)
            root.mkdir(parents=True)
            workspace._copy_subset(
                snapshot_root, requested_paths, entry, limits
            )
        except Exception:
            workspace.dispose()
            raise
        return workspace

    def _copy_subset(
        self,
        snapshot_root: Path,
        requested_paths: list[str],
        entry: CacheEntry,
        limits: RepairWorkspaceLimits,
    ) -> None:
        unique_paths = sorted({item.strip() for item in requested_paths if item.strip()})
        if not unique_paths:
            raise RepairWorkspaceError(
                "refusing to compose a repair workspace without any files"
            )
        if len(unique_paths) > limits.max_files:
            raise RepairWorkspaceError(
                "repair subset exceeds the per-workspace file budget"
            )
        total = 0
        for relative in unique_paths:
            candidate = Path(relative)
            if candidate.is_absolute():
                raise RepairWorkspaceError(
                    f"repair subset path must be relative: {relative}"
                )
            # 先在未解析的原始路径上检测 symlink：resolve() 会消解链接，
            # 解析后再查 is_symlink() 将永远为 False（纵深防御缺陷）。
            raw_origin = snapshot_root / candidate
            if raw_origin.is_symlink():
                raise RepairWorkspaceError(
                    f"repair subset path is not a regular file in the "
                    f"snapshot: {relative}"
                )
            origin = raw_origin.resolve(strict=False)
            try:
                origin.relative_to(snapshot_root)
            except ValueError as exc:
                raise RepairWorkspaceError(
                    f"repair subset path escapes the snapshot root: {relative}"
                ) from exc
            if not origin.is_file():
                raise RepairWorkspaceError(
                    f"repair subset path is not a regular file in the "
                    f"snapshot: {relative}"
                )
            size = origin.stat().st_size
            if size > limits.max_file_bytes:
                raise RepairWorkspaceError(
                    f"repair subset file exceeds the per-file budget: {relative}"
                )
            total += size
            if total > limits.max_total_bytes:
                raise RepairWorkspaceError(
                    "repair subset exceeds the total workspace budget"
                )
            target = self.root / candidate
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(origin, target, follow_symlinks=False)

    # ------------------------------------------------------------------
    # Usage and disposal
    # ------------------------------------------------------------------

    def _ensure_active(self) -> None:
        if self._disposed:
            raise RepairWorkspaceError("repair workspace is already disposed")

    def read_text(self, relative_path: str) -> str:
        self._ensure_active()
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise RepairWorkspaceError("workspace paths must be relative")
        resolved = (self.root / candidate).resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise RepairWorkspaceError(
                "workspace path escapes the repair workspace"
            ) from exc
        if not resolved.is_file():
            raise RepairWorkspaceError(
                f"workspace file not found: {relative_path}"
            )
        return resolved.read_text(encoding="utf-8")

    def write_text(self, relative_path: str, content: str) -> None:
        self._ensure_active()
        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise RepairWorkspaceError("workspace paths must be relative")
        resolved = (self.root / candidate).resolve(strict=False)
        try:
            resolved.relative_to(self.root)
        except ValueError as exc:
            raise RepairWorkspaceError(
                "workspace path escapes the repair workspace"
            ) from exc
        resolved.parent.mkdir(parents=True, exist_ok=True)
        resolved.write_text(content, encoding="utf-8", newline="\n")

    def file_paths(self) -> list[str]:
        self._ensure_active()
        return sorted(
            item.relative_to(self.root).as_posix()
            for item in self.root.rglob("*")
            if item.is_file()
        )

    def dispose(self) -> None:
        """Remove the scratch directory and release the cache pin (idempotent)."""

        if self._disposed:
            return
        self._disposed = True
        shutil.rmtree(self.root, ignore_errors=True)
        try:
            # 只尝试移除空的 base 根（其他任务的工作区不受影响）。
            self._base.rmdir()
        except OSError:
            pass
        finally:
            self._pin.__exit__(None, None, None)

    def __enter__(self) -> RepairWorkspace:
        self._ensure_active()
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.dispose()


def repair_relevant_paths(report: dict, preview_cwes: set[str]) -> list[str]:
    """Derive the repair-relevant subset from a report's preview findings."""

    return sorted({
        str(item.get("path", ""))
        for item in report.get("findings", [])
        if str(item.get("path", ""))
        and str(item.get("cwe", "")).upper() in preview_cwes
    })


__all__ = [
    "RepairWorkspace",
    "RepairWorkspaceError",
    "RepairWorkspaceLimits",
    "repair_relevant_paths",
]
