"""Scaling facilities for the agent vulnerability platform (plan Task 9).

Design section 8 (``docs/superpowers/specs/2026-09-12-agent-vuln-platform-
design.md``).  Three independent, dependency-free facilities:

- :class:`ResultCache` -- a deterministic file cache keyed by a namespace
  plus caller fingerprints (the caller must fold the ``snapshot_hash`` and
  the full semantic inputs into the fingerprints, design invariant 9.6).
  Entries are JSON objects written atomically (tmp file + rename); a corrupt
  entry is treated as a miss and deleted, so a cache can never poison a run.
- :func:`map_bounded` -- bounded parallelism over independent items.
  Parallelism changes the wall clock only: results are aggregated in
  ``order_key`` order (never completion order) and exceptions are collected
  as :class:`ScaledFailure` records instead of being swallowed, so the
  caller owns the failure semantics.
- :func:`detect_changed_files` -- pure three-way diff between two content
  inventories (``{path: content_sha256}``); the basis for incremental
  reruns, with no I/O of its own.

Nothing here reaches into orchestration internals: the caller wires these
facilities around its own loops and keeps their semantics.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import threading
from collections.abc import Callable, Iterable, Mapping
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path
from typing import Any

__all__ = [
    "ResultCache",
    "ScaledFailure",
    "detect_changed_files",
    "map_bounded",
]


def _require_text_mapping(inventory: Mapping[str, str], name: str) -> None:
    if not isinstance(inventory, Mapping):
        raise ValueError(f"{name} must be a mapping of path to content hash")
    for path, digest in inventory.items():
        if not isinstance(path, str) or not path:
            raise ValueError(f"{name} keys must be non-empty path strings")
        if not isinstance(digest, str) or not digest:
            raise ValueError(f"{name}[{path!r}] must map to non-empty text")


# ------------------------------------------------------------ ResultCache


class ResultCache:
    """Deterministic JSON file cache over ``namespace + fingerprints``.

    The key is ``SHA-256(namespace + sorted(fingerprints))``: identical
    inputs always produce the same key regardless of fingerprint order, and
    different namespaces never collide even over one shared directory.  The
    caller owns the key semantics -- the fingerprint set must contain the
    ``snapshot_hash`` and every input that changes the payload.
    """

    def __init__(self, cache_dir: Path, namespace: str) -> None:
        if not isinstance(namespace, str) or not namespace:
            raise ValueError("namespace must be non-empty text")
        self.cache_dir = Path(cache_dir)
        self.namespace = namespace
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def key_for(self, *fingerprints: str) -> str:
        """The stable hex key for one fingerprint set (order-insensitive)."""

        for fingerprint in fingerprints:
            if not isinstance(fingerprint, str) or not fingerprint:
                raise ValueError("fingerprints must be non-empty text")
        material = self.namespace + "|" + "\n".join(sorted(fingerprints))
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _entry_path(self, key: str) -> Path:
        if not isinstance(key, str) or not key:
            raise ValueError("cache keys must be non-empty text")
        return self.cache_dir / f"{key}.json"

    def get(self, key: str) -> dict[str, Any] | None:
        """Return the cached payload or ``None`` (missing or corrupt)."""

        path = self._entry_path(key)
        try:
            raw = path.read_bytes()
        except OSError:
            self._count(miss=True)
            return None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            payload = None
        if not isinstance(payload, dict):
            # Corrupt entries self-heal: treat as a miss and delete the file
            # so the next writer can replace it.
            with contextlib.suppress(OSError):
                path.unlink()
            self._count(miss=True)
            return None
        self._count(miss=False)
        return payload

    def put(self, key: str, payload: dict[str, Any]) -> None:
        """Atomically store one JSON object payload."""

        if not isinstance(payload, dict):
            raise ValueError("payload must be a JSON object (dict)")
        path = self._entry_path(key)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(
            f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp",
        )
        data = json.dumps(payload, sort_keys=True).encode("utf-8")
        try:
            tmp.write_bytes(data)
            os.replace(tmp, path)
        finally:
            with contextlib.suppress(OSError):
                tmp.unlink(missing_ok=True)

    def stats(self) -> dict[str, int]:
        """Hit/miss counters of this cache instance so far."""

        with self._lock:
            return {"hits": self._hits, "misses": self._misses}

    def _count(self, *, miss: bool) -> None:
        with self._lock:
            if miss:
                self._misses += 1
            else:
                self._hits += 1


# ------------------------------------------------------------ map_bounded


@dataclass(frozen=True)
class ScaledFailure:
    """One failed item of a :func:`map_bounded` run, never swallowed."""

    item: Any
    exception: BaseException


def map_bounded(
    fn: Callable[[Any], Any],
    items: Iterable[Any],
    parallelism: int,
    *,
    order_key: Callable[[Any], Any],
) -> tuple[list[Any], list[ScaledFailure]]:
    """Run ``fn`` over ``items`` under a thread cap, ordered by ``order_key``.

    The result lists are sorted by ``order_key(item)`` regardless of
    completion order, so parallelism changes the wall clock only.
    ``parallelism=1`` runs strictly sequentially.  Exceptions raised by
    ``fn`` are collected as :class:`ScaledFailure` records (also in
    ``order_key`` order); the caller decides their semantics.  At most
    ``min(parallelism, len(items))`` threads are started.
    """

    if callable(fn) is False:
        raise ValueError("fn must be callable")
    if (
        isinstance(parallelism, bool)
        or not isinstance(parallelism, int)
        or parallelism < 1
    ):
        raise ValueError("parallelism must be a positive integer")
    if callable(order_key) is False:
        raise ValueError("order_key must be callable")
    work = list(items)
    if not work:
        return [], []

    def _run(item: Any) -> tuple[Any, Any, Any]:
        key = order_key(item)
        try:
            return key, item, fn(item)
        except BaseException as exc:  # collected, never swallowed
            return key, item, exc

    if parallelism == 1:
        outcomes = [_run(item) for item in work]
    else:
        with ThreadPoolExecutor(
            max_workers=min(parallelism, len(work)),
        ) as pool:
            outcomes = list(pool.map(_run, work))
    outcomes.sort(key=lambda outcome: outcome[0])
    results: list[Any] = []
    failures: list[ScaledFailure] = []
    for _key, item, outcome in outcomes:
        if isinstance(outcome, BaseException):
            failures.append(ScaledFailure(item=item, exception=outcome))
        else:
            results.append(outcome)
    return results, failures


# ---------------------------------------------------- detect_changed_files


def detect_changed_files(
    old_inventory: Mapping[str, str],
    new_inventory: Mapping[str, str],
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    """Three-way diff of two ``{path: content_sha256}`` inventories.

    Returns ``(added, modified, removed)`` -- added paths exist only in the
    new inventory, modified paths have a different digest in both, removed
    paths exist only in the old inventory.  Every tuple is sorted, so the
    output is deterministic.  Pure data work: no I/O.
    """

    _require_text_mapping(old_inventory, "old_inventory")
    _require_text_mapping(new_inventory, "new_inventory")
    old_paths = set(old_inventory)
    new_paths = set(new_inventory)
    added = tuple(sorted(new_paths - old_paths))
    removed = tuple(sorted(old_paths - new_paths))
    modified = tuple(sorted(
        path for path in old_paths & new_paths
        if old_inventory[path] != new_inventory[path]
    ))
    return added, modified, removed
