"""Offline, opt-in retention maintenance for Build Agent artifacts.

This command deliberately has no background scheduler.  Operators stop all
workers, inspect the default dry-run, then acknowledge that condition before
requesting deletion.  The task store remains the authority for task state.
"""

from __future__ import annotations

import argparse
import dataclasses
import json
import os
import shutil
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Protocol

__all__ = [
    "ArtifactCleanupCandidate",
    "ArtifactCleanupError",
    "ArtifactCleanupPlan",
    "ArtifactCleanupSkip",
    "apply_cleanup",
    "main",
    "plan_cleanup",
]

_TERMINAL_STATES: Final = frozenset({"SUCCESS", "FAILED", "CANCELLED"})


class _TaskReader(Protocol):
    def get(self, task_id: str) -> dict[str, Any] | None: ...


class ArtifactCleanupError(ValueError):
    """Safe cleanup precondition failed."""


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactCleanupCandidate:
    task_id: str
    path: Path
    newest_at: datetime


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactCleanupSkip:
    task_id: str
    path: Path
    reason: str


@dataclasses.dataclass(frozen=True, slots=True)
class ArtifactCleanupPlan:
    root: Path
    candidates: tuple[ArtifactCleanupCandidate, ...]
    skipped: tuple[ArtifactCleanupSkip, ...]


def _is_link_or_junction(path: Path) -> bool:
    """Recognize symlinks and Windows reparse-point directories."""

    if path.is_symlink():
        return True
    isjunction = getattr(os.path, "isjunction", None)
    if isjunction is not None and isjunction(path):
        return True
    try:
        attributes = path.lstat().st_file_attributes
    except (AttributeError, OSError):
        return False
    return bool(attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _safe_root(value: str | Path) -> Path:
    raw_root = Path(value).expanduser()
    if _is_link_or_junction(raw_root):
        raise ArtifactCleanupError("artifacts-root-link")
    root = raw_root.resolve()
    if not root.is_absolute():
        raise ArtifactCleanupError("artifacts-root-not-absolute")
    if _is_link_or_junction(root):
        raise ArtifactCleanupError("artifacts-root-link")
    return root


def _raise_walk_error(error: OSError) -> None:
    raise error


def _tree_contains_link(root: Path) -> bool:
    for current, directories, files in os.walk(
        root, topdown=True, followlinks=False, onerror=_raise_walk_error
    ):
        base = Path(current)
        for name in [*directories, *files]:
            if _is_link_or_junction(base / name):
                return True
    return False


def _newest_tree_mtime(root: Path) -> datetime:
    newest = root.stat().st_mtime
    for current, directories, files in os.walk(
        root, topdown=True, followlinks=False, onerror=_raise_walk_error
    ):
        base = Path(current)
        for name in [*directories, *files]:
            newest = max(newest, (base / name).stat().st_mtime)
    return datetime.fromtimestamp(newest, tz=UTC)


def _parse_updated_at(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def plan_cleanup(
    artifacts_root: str | Path,
    store: _TaskReader,
    *,
    retention_days: int,
    now: datetime | None = None,
) -> ArtifactCleanupPlan:
    """Select safe, expired direct task directories without deleting them."""

    if type(retention_days) is not int or retention_days < 1:
        raise ArtifactCleanupError("retention-days-invalid")
    root = _safe_root(artifacts_root)
    if not root.exists():
        return ArtifactCleanupPlan(
            root=root,
            candidates=(),
            skipped=(ArtifactCleanupSkip("", root, "artifacts-root-missing"),),
        )
    if not root.is_dir():
        raise ArtifactCleanupError("artifacts-root-not-directory")
    moment = now or datetime.now(UTC)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=UTC)
    cutoff = moment.astimezone(UTC) - timedelta(days=retention_days)
    candidates: list[ArtifactCleanupCandidate] = []
    skipped: list[ArtifactCleanupSkip] = []
    for target in sorted(root.iterdir(), key=lambda item: item.name):
        task_id = target.name
        if _is_link_or_junction(target):
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-link"))
            continue
        if not target.is_dir():
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-not-directory"))
            continue
        try:
            resolved = target.resolve(strict=True)
        except OSError:
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-unresolvable"))
            continue
        if resolved == root or resolved.parent != root:
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-outside-root"))
            continue
        try:
            contains_link = _tree_contains_link(resolved)
        except OSError:
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-unreadable"))
            continue
        if contains_link:
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-tree-link"))
            continue
        task = store.get(task_id)
        if task is None:
            skipped.append(ArtifactCleanupSkip(task_id, target, "task-not-found"))
            continue
        if task.get("state") not in _TERMINAL_STATES:
            skipped.append(ArtifactCleanupSkip(task_id, target, "task-not-terminal"))
            continue
        updated_at = _parse_updated_at(task.get("updated_at"))
        if updated_at is None:
            skipped.append(ArtifactCleanupSkip(task_id, target, "task-updated-at-invalid"))
            continue
        try:
            newest_at = max(updated_at, _newest_tree_mtime(resolved))
        except OSError:
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-unreadable"))
            continue
        if newest_at >= cutoff:
            skipped.append(ArtifactCleanupSkip(task_id, target, "artifact-not-expired"))
            continue
        candidates.append(ArtifactCleanupCandidate(task_id, resolved, newest_at))
    return ArtifactCleanupPlan(root, tuple(candidates), tuple(skipped))


def apply_cleanup(plan: ArtifactCleanupPlan) -> tuple[str, ...]:
    """Delete the plan's candidates after repeating the path safety checks."""

    root = _safe_root(plan.root)
    if not root.is_dir():
        raise ArtifactCleanupError("artifacts-root-not-directory")
    deleted: list[str] = []
    for candidate in plan.candidates:
        target = candidate.path
        try:
            resolved = target.resolve(strict=True)
            safe = (
                resolved != root
                and resolved.parent == root
                and target.is_dir()
                and not _is_link_or_junction(target)
                and not _tree_contains_link(resolved)
                and _newest_tree_mtime(resolved) <= candidate.newest_at
            )
        except OSError:
            safe = False
        if not safe:
            continue
        shutil.rmtree(resolved)
        deleted.append(candidate.task_id)
    return tuple(deleted)


def _render(plan: ArtifactCleanupPlan, deleted: tuple[str, ...], apply: bool) -> str:
    return json.dumps(
        {
            "mode": "apply" if apply else "dry-run",
            "artifacts_root": str(plan.root),
            "candidates": [item.task_id for item in plan.candidates],
            "deleted": list(deleted),
            "skipped": [
                {"task_id": item.task_id, "path": str(item.path), "reason": item.reason}
                for item in plan.skipped
            ],
        },
        ensure_ascii=False,
        indent=2,
    ) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline Build Agent artifact retention maintenance."
    )
    parser.add_argument("--root", type=Path, help="override LIMA_BUILD_ARTIFACTS_ROOT")
    parser.add_argument("--db-path", help="use this SQLite task database")
    parser.add_argument(
        "--retention-days", type=int, help="override LIMA_BUILD_ARTIFACTS_RETENTION_DAYS"
    )
    parser.add_argument("--apply", action="store_true", help="delete selected directories")
    parser.add_argument(
        "--workers-stopped",
        action="store_true",
        help="operator acknowledgement that all workers are stopped",
    )
    args = parser.parse_args(argv)
    if args.apply and not args.workers_stopped:
        parser.error("--apply requires --workers-stopped")
    from lima.config import Settings
    from lima.postgres_store import create_store

    settings = Settings.from_env()
    root = args.root if args.root is not None else settings.build_artifacts_root
    retention_days = (
        args.retention_days
        if args.retention_days is not None
        else settings.build_artifacts_retention_days
    )
    # An explicit database path is intentionally a SQLite override, even if
    # the environment of the machine otherwise names a Postgres deployment.
    store = create_store(
        "" if args.db_path else settings.database_url,
        args.db_path or settings.db_path,
    )
    try:
        plan = plan_cleanup(root, store, retention_days=retention_days)
        deleted = apply_cleanup(plan) if args.apply else ()
    except ArtifactCleanupError as exc:
        print(f"build_artifact_cleanup_error: {exc}", file=sys.stderr)
        return 2
    sys.stdout.write(_render(plan, deleted, args.apply))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
