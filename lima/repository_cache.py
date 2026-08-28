"""Bounded, content-addressed cache for immutable repository snapshots.

This module implements the T3 layer of the repository acquisition chain
(``RepositorySource -> Materializer -> RepositorySnapshot -> RepositoryCache``).
It deliberately knows nothing about how snapshots are produced: the future
materializer (T2) reserves a staging directory, writes snapshot files into it
and publishes it atomically.  Consumers (T4 scan integration) only see
``lookup`` results and never touch the cache filesystem layout.

Invariants enforced here:

- A cache entry is identified by ``provider + canonical source identity +
  resolved_revision`` where the revision must be immutable (a commit SHA for
  GitHub sources or the deterministic repository fingerprint for local
  imports).  Moving refs are rejected outright.
- Published snapshots are never modified in place.  A duplicate publication
  keeps the entry that was published first; late publishers lose.
- Staging content is never visible to ``lookup``; publication happens through
  a single atomic directory rename.
- ``cleanup`` never evicts pinned (active) snapshots, expires entries older
  than the TTL, evicts least-recently-used entries beyond the quota and keeps
  the host filesystem above the configured free-space floor.
- Repair workspaces are not cache entries and must never be stored here.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import threading
import time
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .repository_source import RepositorySource, parse_repository_source

MANIFEST_NAME = "manifest.json"
MANIFEST_SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 14 * 24 * 3600
DEFAULT_QUOTA_BYTES = 2 * 1024 * 1024 * 1024
DEFAULT_MIN_FREE_BYTES = 512 * 1024 * 1024
DEFAULT_MATERIALIZATION_TIMEOUT_SECONDS = 3600
DEFAULT_PIN_TTL_SECONDS = 3600
MAX_MANIFEST_FILES = 2000
_REVISION_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")


class RepositoryCacheError(RuntimeError):
    """Base error for cache misuse."""


def _utc_now() -> float:
    return time.time()


def _fsync_directory(path: Path) -> None:
    try:
        handle = os.open(path, os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(handle)
    except OSError:
        pass
    finally:
        os.close(handle)


def _write_file_atomic(path: Path, payload: bytes) -> None:
    with open(path, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())


def _inventory_files(root: Path) -> list[tuple[str, int, str]]:
    """Return sorted ``(relative_path, size, sha256)`` records for a snapshot directory."""

    records: list[tuple[str, int, str]] = []
    for current, directory_names, file_names in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in sorted(directory_names):
            if (current_path / name).is_symlink():
                raise RepositoryCacheError(
                    "snapshot directories must not contain symbolic links"
                )
        directory_names[:] = sorted(
            name for name in directory_names
            if not (current_path / name).is_symlink()
        )
        for name in sorted(file_names):
            path = current_path / name
            if path.is_symlink():
                raise RepositoryCacheError(
                    "snapshot directories must not contain symbolic links"
                )
            relative = path.relative_to(root).as_posix()
            if relative == MANIFEST_NAME:
                continue
            data = path.read_bytes()
            records.append((relative, len(data), hashlib.sha256(data).hexdigest()))
    records.sort(key=lambda item: item[0])
    return records


def _content_fingerprint(records: list[tuple[str, int, str]]) -> str:
    digest = hashlib.sha256()
    for relative, size, file_hash in records:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        digest.update(file_hash.encode("ascii"))
        digest.update(b"\n")
    return digest.hexdigest()


@dataclass(frozen=True)
class CacheKeyIdentity:
    source: RepositorySource
    resolved_revision: str


def resolve_cache_identity(
    source: RepositorySource | dict[str, str], resolved_revision: str
) -> CacheKeyIdentity:
    """Validate and normalize the immutable identity of a cache entry."""

    normalized_source = parse_repository_source(source)
    revision = str(resolved_revision).strip().lower()
    if not _REVISION_PATTERN.fullmatch(revision):
        raise ValueError(
            "resolved_revision must be an immutable 40/64 hex commit SHA or "
            "repository fingerprint; resolve moving refs before caching"
        )
    return CacheKeyIdentity(normalized_source, revision)


def compute_cache_key(identity: CacheKeyIdentity) -> str:
    source = identity.source
    canonical = source.canonical_name or source.repository_key
    digest = hashlib.sha256()
    for part in (source.type, source.provider, canonical, identity.resolved_revision):
        digest.update(part.encode("utf-8"))
        digest.update(b"\0")
    return digest.hexdigest()


@dataclass(frozen=True)
class CacheEntry:
    key: str
    source: dict[str, str]
    resolved_revision: str
    path: Path
    created_at: float
    total_bytes: int
    file_count: int
    content_fingerprint: str

    @property
    def manifest_path(self) -> Path:
        return self.path / MANIFEST_NAME


@dataclass
class Reservation:
    """A materialization slot for one cache identity.

    ``owner=True`` means the caller must materialize the snapshot into
    ``staging_path`` and then ``publish`` it.  ``owner=False`` means another
    materializer is active; the caller should ``wait_for_publish`` (or simply
    treat the entry as a miss) instead of materializing a duplicate.
    """

    key: str
    source: dict[str, str]
    resolved_revision: str
    staging_path: Path | None = None
    owner: bool = False
    _cache: RepositoryCache | None = field(default=None, repr=False)

    def publish(self) -> CacheEntry:
        if self._cache is None:
            raise RepositoryCacheError("reservation is not bound to a cache")
        return self._cache.publish(self)

    def abort(self) -> None:
        if self._cache is None:
            raise RepositoryCacheError("reservation is not bound to a cache")
        self._cache.abort(self)

    def __enter__(self) -> Reservation:
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        # 未发布的预留一律释放：锁删除、staging 清空，不留半成品。
        if self.owner and self._cache is not None and self.staging_path is not None:
            self._cache.abort(self)


class RepositoryCache:
    """Bounded on-disk cache for immutable repository snapshots."""

    def __init__(
        self,
        root: str | os.PathLike[str],
        *,
        ttl_seconds: int = DEFAULT_TTL_SECONDS,
        quota_bytes: int = DEFAULT_QUOTA_BYTES,
        min_free_bytes: int = DEFAULT_MIN_FREE_BYTES,
        materialization_timeout_seconds: int = (
            DEFAULT_MATERIALIZATION_TIMEOUT_SECONDS
        ),
        pin_ttl_seconds: int = DEFAULT_PIN_TTL_SECONDS,
    ) -> None:
        if ttl_seconds < 1 or quota_bytes < 1 or min_free_bytes < 1:
            raise ValueError("cache limits must be positive")
        if materialization_timeout_seconds < 1 or pin_ttl_seconds < 1:
            raise ValueError("cache timeouts must be positive")
        self.root = Path(root).expanduser().resolve()
        self.entries_root = self.root / "entries"
        self.staging_root = self.root / "staging"
        self.locks_root = self.root / "locks"
        self.access_root = self.root / "access"
        self.pins_root = self.root / "pins"
        self.ttl_seconds = ttl_seconds
        self.quota_bytes = quota_bytes
        self.min_free_bytes = min_free_bytes
        self.materialization_timeout_seconds = materialization_timeout_seconds
        self.pin_ttl_seconds = pin_ttl_seconds
        self._key_locks: dict[str, threading.Lock] = {}
        self._registry_guard = threading.Lock()
        for directory in (
            self.entries_root, self.staging_root, self.locks_root,
            self.access_root, self.pins_root,
        ):
            directory.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Identity helpers
    # ------------------------------------------------------------------

    def cache_key(
        self,
        source: RepositorySource | dict[str, str],
        resolved_revision: str,
    ) -> str:
        return compute_cache_key(resolve_cache_identity(source, resolved_revision))

    def _entry_path(self, key: str) -> Path:
        return self.entries_root / key

    def _lock_path(self, key: str) -> Path:
        return self.locks_root / key

    def _access_path(self, key: str) -> Path:
        return self.access_root / key

    def _load_manifest(self, key: str) -> dict | None:
        manifest_path = self._entry_path(key) / MANIFEST_NAME
        try:
            value = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if not isinstance(value, dict) or value.get("key") != key:
            return None
        return value

    def _entry_from_manifest(self, key: str, manifest: dict) -> CacheEntry | None:
        entry_path = self._entry_path(key)
        if not entry_path.is_dir():
            return None
        source = manifest.get("source")
        revision = manifest.get("resolved_revision")
        if not isinstance(source, dict) or not isinstance(revision, str):
            return None
        try:
            return CacheEntry(
                key=key,
                source=source,
                resolved_revision=revision,
                path=entry_path,
                created_at=float(manifest["created_at"]),
                total_bytes=int(manifest["total_bytes"]),
                file_count=int(manifest["file_count"]),
                content_fingerprint=str(manifest["content_fingerprint"]),
            )
        except (KeyError, TypeError, ValueError):
            return None

    # ------------------------------------------------------------------
    # Lookup / touch
    # ------------------------------------------------------------------

    def lookup(
        self,
        source: RepositorySource | dict[str, str],
        resolved_revision: str,
        *,
        touch: bool = True,
    ) -> CacheEntry | None:
        """Return the published snapshot for an identity, or ``None`` on a miss."""

        key = self.cache_key(source, resolved_revision)
        manifest = self._load_manifest(key)
        if manifest is None:
            return None
        entry = self._entry_from_manifest(key, manifest)
        if entry is None:
            return None
        if touch:
            self.touch_key(key)
        return entry

    def touch_key(self, key: str) -> None:
        marker = self._access_path(key)
        try:
            marker.touch(exist_ok=True)
            current = time.time()
            os.utime(marker, (current, current))
        except OSError:
            pass

    def touch(
        self,
        source: RepositorySource | dict[str, str],
        resolved_revision: str,
    ) -> None:
        self.touch_key(self.cache_key(source, resolved_revision))

    def read_text(self, entry: CacheEntry, relative_path: str) -> str:
        """Read one file out of a published snapshot inside the cache boundary."""

        candidate = Path(relative_path)
        if candidate.is_absolute():
            raise ValueError("snapshot paths must be relative")
        resolved = (entry.path / candidate).resolve(strict=False)
        try:
            resolved.relative_to(entry.path)
        except ValueError as exc:
            raise ValueError("snapshot path escapes the cache entry") from exc
        if not resolved.is_file():
            raise ValueError("snapshot path must reference a regular file")
        return resolved.read_text(encoding="utf-8")

    # ------------------------------------------------------------------
    # Reservation / publication
    # ------------------------------------------------------------------

    def _key_lock(self, key: str) -> threading.Lock:
        with self._registry_guard:
            lock = self._key_locks.get(key)
            if lock is None:
                lock = threading.Lock()
                self._key_locks[key] = lock
            return lock

    def _acquire_cross_process_lock(self, key: str) -> bool:
        lock_path = self._lock_path(key)
        try:
            lock_path.mkdir()
            return True
        except FileExistsError:
            pass
        try:
            age = time.time() - lock_path.stat().st_mtime
        except OSError:
            return False
        if age <= self.materialization_timeout_seconds:
            return False
        # 陈旧锁：上一个物化者已崩溃，安全回收后重试一次。
        shutil.rmtree(lock_path, ignore_errors=True)
        try:
            lock_path.mkdir()
            return True
        except FileExistsError:
            return False

    def reserve(
        self,
        source: RepositorySource | dict[str, str],
        resolved_revision: str,
    ) -> Reservation:
        """Acquire the materialization slot for an identity.

        Concurrent callers for the same identity get ``owner=False`` and must
        not materialize a duplicate; they should wait for the owner's
        publication instead.
        """

        identity = resolve_cache_identity(source, resolved_revision)
        key = compute_cache_key(identity)
        with self._key_lock(key):
            if not self._acquire_cross_process_lock(key):
                return Reservation(
                    key=key,
                    source=identity.source.to_dict(),
                    resolved_revision=identity.resolved_revision,
                    owner=False,
                    _cache=self,
                )
            staging_dir = self.staging_root / key / uuid.uuid4().hex
            staging_dir.mkdir(parents=True)
            return Reservation(
                key=key,
                source=identity.source.to_dict(),
                resolved_revision=identity.resolved_revision,
                staging_path=staging_dir,
                owner=True,
                _cache=self,
            )

    def _free_bytes(self) -> int:
        try:
            return shutil.disk_usage(self.root).free
        except OSError:
            return self.min_free_bytes

    def publish(self, reservation: Reservation) -> CacheEntry:
        """Atomically publish a materialized snapshot; the first publisher wins."""

        if not reservation.owner or reservation.staging_path is None:
            raise RepositoryCacheError(
                "only the reservation owner can publish a snapshot"
            )
        if not reservation.staging_path.is_dir():
            raise RepositoryCacheError("reservation staging directory is gone")
        try:
            records = _inventory_files(reservation.staging_path)
        except RepositoryCacheError:
            # 任何发布失败都必须完全释放预留，不留下锁或半成品目录。
            self.abort(reservation)
            raise
        if not records:
            self.abort(reservation)
            raise RepositoryCacheError("refusing to publish an empty snapshot")
        total_bytes = sum(size for _, size, _ in records)
        if self._free_bytes() - total_bytes < self.min_free_bytes:
            self.cleanup()
            if self._free_bytes() - total_bytes < self.min_free_bytes:
                self.abort(reservation)
                raise RepositoryCacheError(
                    "insufficient free space below the cache floor to publish"
                )
        manifest = {
            "schema_version": MANIFEST_SCHEMA_VERSION,
            "key": reservation.key,
            "source": reservation.source,
            "resolved_revision": reservation.resolved_revision,
            "created_at": _utc_now(),
            "total_bytes": total_bytes,
            "file_count": len(records),
            "content_fingerprint": _content_fingerprint(records),
            "files": [
                {"path": path, "size": size, "sha256": digest}
                for path, size, digest in records[:MAX_MANIFEST_FILES]
            ],
        }
        _write_file_atomic(
            reservation.staging_path / MANIFEST_NAME,
            json.dumps(manifest, ensure_ascii=False, indent=2).encode("utf-8"),
        )
        entry_path = self._entry_path(reservation.key)
        try:
            os.rename(reservation.staging_path, entry_path)
        except OSError:
            # 目标已存在：并发发布先到者胜，本次重复内容被安全丢弃。
            shutil.rmtree(reservation.staging_path, ignore_errors=True)
            self._release_lock(reservation.key)
            reservation.staging_path = None
            reservation.owner = False
            existing = self._load_manifest(reservation.key)
            if existing is None:
                raise RepositoryCacheError(
                    "snapshot publication lost the race and no entry is readable"
                ) from None
            return self._entry_from_manifest(reservation.key, existing)  # type: ignore[return-value]
        _fsync_directory(self.entries_root)
        self._release_lock(reservation.key)
        # 发布成功后预留立即失效：staging 路径已指向正式条目，绝不能再被 abort 清理。
        reservation.staging_path = None
        reservation.owner = False
        self.touch_key(reservation.key)
        entry = self._entry_from_manifest(reservation.key, manifest)
        if entry is None:
            raise RepositoryCacheError("published entry is not readable")
        return entry

    def abort(self, reservation: Reservation) -> None:
        if reservation.staging_path is not None:
            shutil.rmtree(reservation.staging_path, ignore_errors=True)
            parent = reservation.staging_path.parent
            try:
                parent.rmdir()
            except OSError:
                pass
        if reservation.owner:
            self._release_lock(reservation.key)
        reservation.owner = False
        reservation.staging_path = None

    def _release_lock(self, key: str) -> None:
        shutil.rmtree(self._lock_path(key), ignore_errors=True)

    def wait_for_publish(
        self,
        source: RepositorySource | dict[str, str],
        resolved_revision: str,
        *,
        timeout_seconds: float = 60.0,
        poll_interval: float = 0.05,
    ) -> CacheEntry | None:
        """Poll until another materializer publishes the requested identity."""

        key = self.cache_key(source, resolved_revision)
        deadline = time.monotonic() + timeout_seconds
        while time.monotonic() < deadline:
            entry = self.lookup(source, resolved_revision)
            if entry is not None:
                return entry
            if not self._lock_path(key).exists():
                return None
            time.sleep(poll_interval)
        return self.lookup(source, resolved_revision)

    # ------------------------------------------------------------------
    # Pinning (active snapshots are never evicted)
    # ------------------------------------------------------------------

    @contextmanager
    def pin(
        self,
        source: RepositorySource | dict[str, str],
        resolved_revision: str,
    ) -> Iterator[CacheEntry]:
        # 先落 pin 标记再确认条目存在：标记一旦可见，并发 cleanup 就会跳过
        # 该条目；若条目本来就不存在，则回滚标记并拒绝 pin。
        key = self.cache_key(source, resolved_revision)
        token = uuid.uuid4().hex[:12]
        marker = self.pins_root / f"{key}.{token}"
        marker.write_text(str(os.getpid()), encoding="utf-8")
        entry = self.lookup(source, resolved_revision)
        if entry is None:
            try:
                marker.unlink()
            except OSError:
                pass
            raise RepositoryCacheError("cannot pin an unpublished snapshot")
        try:
            yield entry
        finally:
            try:
                marker.unlink()
            except OSError:
                pass

    def _entry_pins(self, key: str) -> list[Path]:
        if not self.pins_root.is_dir():
            return []
        return sorted(self.pins_root.glob(f"{key}.*"))

    def _has_fresh_pin(self, key: str, now: float) -> bool:
        for marker in self._entry_pins(key):
            try:
                age = now - marker.stat().st_mtime
            except OSError:
                continue
            if age <= self.pin_ttl_seconds:
                return True
        return False

    # ------------------------------------------------------------------
    # Cleanup: TTL, LRU quota, free-space floor, stale staging/locks/pins
    # ------------------------------------------------------------------

    def _iter_entries(self) -> Iterator[tuple[str, dict]]:
        if not self.entries_root.is_dir():
            return
        for child in sorted(self.entries_root.iterdir()):
            if not child.is_dir():
                continue
            manifest = self._load_manifest(child.name)
            if manifest is not None:
                yield child.name, manifest

    def _last_access(self, key: str, fallback: float) -> float:
        marker = self._access_path(key)
        try:
            return marker.stat().st_mtime
        except OSError:
            return fallback

    def _evict(self, key: str) -> int:
        manifest = self._load_manifest(key)
        size = int(manifest["total_bytes"]) if manifest else 0
        shutil.rmtree(self._entry_path(key), ignore_errors=True)
        for marker in self._entry_pins(key):
            try:
                marker.unlink()
            except OSError:
                pass
        try:
            self._access_path(key).unlink()
        except OSError:
            pass
        return size

    def cleanup(self) -> dict[str, int]:
        """Enforce TTL, quota and the free-space floor; drop incomplete leftovers."""

        now = _utc_now()
        report = {
            "stale_staging_removed": 0,
            "stale_locks_removed": 0,
            "stale_pins_removed": 0,
            "orphan_entries_removed": 0,
            "ttl_expired": 0,
            "lru_evicted": 0,
            "bytes_freed": 0,
        }

        # 1. 不完整条目：陈旧 staging、陈旧物化锁、孤儿 entries、陈旧 pin。
        if self.staging_root.is_dir():
            for key_dir in list(self.staging_root.iterdir()):
                if not key_dir.is_dir():
                    continue
                for staging in list(key_dir.iterdir()):
                    try:
                        age = now - staging.stat().st_mtime
                    except OSError:
                        continue
                    if age > self.materialization_timeout_seconds:
                        shutil.rmtree(staging, ignore_errors=True)
                        report["stale_staging_removed"] += 1
                try:
                    key_dir.rmdir()
                except OSError:
                    pass
        if self.locks_root.is_dir():
            for lock_path in list(self.locks_root.iterdir()):
                try:
                    age = now - lock_path.stat().st_mtime
                except OSError:
                    continue
                if age > self.materialization_timeout_seconds:
                    shutil.rmtree(lock_path, ignore_errors=True)
                    report["stale_locks_removed"] += 1
        for child in sorted(self.entries_root.iterdir()):
            if child.is_dir() and self._load_manifest(child.name) is None:
                shutil.rmtree(child, ignore_errors=True)
                report["orphan_entries_removed"] += 1
        if self.pins_root.is_dir():
            for marker in list(self.pins_root.iterdir()):
                try:
                    age = now - marker.stat().st_mtime
                except OSError:
                    continue
                if age > self.pin_ttl_seconds:
                    try:
                        marker.unlink()
                        report["stale_pins_removed"] += 1
                    except OSError:
                        pass

        # 2. 收集存活的已发布条目。
        candidates: list[tuple[float, float, int, str]] = []
        total = 0
        for key, manifest in self._iter_entries():
            try:
                created = float(manifest["created_at"])
                size = int(manifest["total_bytes"])
            except (KeyError, TypeError, ValueError):
                shutil.rmtree(self._entry_path(key), ignore_errors=True)
                report["orphan_entries_removed"] += 1
                continue
            total += size
            candidates.append((self._last_access(key, created), created, size, key))

        # 3. TTL：超期的未 pin 条目无条件删除。
        survivors: list[tuple[float, float, int, str]] = []
        for last_access, created, size, key in candidates:
            if now - created > self.ttl_seconds and not self._has_fresh_pin(key, now):
                report["bytes_freed"] += self._evict(key)
                report["ttl_expired"] += 1
                total -= size
            else:
                survivors.append((last_access, created, size, key))

        # 4. 配额 + 自由空间：按最近访问时间 LRU 驱逐未 pin 条目。
        survivors.sort(key=lambda item: item[0])
        for _last_access, _created, size, key in survivors:
            over_quota = total > self.quota_bytes
            below_floor = self._free_bytes() < self.min_free_bytes
            if not over_quota and not below_floor:
                break
            if self._has_fresh_pin(key, now):
                continue
            report["bytes_freed"] += self._evict(key)
            report["lru_evicted"] += 1
            total -= size
        return report

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def stats(self) -> dict[str, object]:
        entries = 0
        total_bytes = 0
        for _, manifest in self._iter_entries():
            entries += 1
            try:
                total_bytes += int(manifest["total_bytes"])
            except (KeyError, TypeError, ValueError):
                continue
        staging = sum(
            1
            for key_dir in self.staging_root.iterdir() if key_dir.is_dir()
            for _ in key_dir.iterdir()
        ) if self.staging_root.is_dir() else 0
        locks = sum(
            1 for child in self.locks_root.iterdir() if child.is_dir()
        ) if self.locks_root.is_dir() else 0
        return {
            "entries": entries,
            "total_bytes": total_bytes,
            "quota_bytes": self.quota_bytes,
            "staging": staging,
            "locks": locks,
            "free_bytes": self._free_bytes(),
            "min_free_bytes": self.min_free_bytes,
            "ttl_seconds": self.ttl_seconds,
        }


__all__ = [
    "CacheEntry",
    "CacheKeyIdentity",
    "RepositoryCache",
    "RepositoryCacheError",
    "Reservation",
    "compute_cache_key",
    "resolve_cache_identity",
]
