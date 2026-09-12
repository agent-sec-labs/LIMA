"""Deterministic on-disk repository shapes for IP-0016 acceptance tests.

Fixtures are materialized inside a per-test temporary directory and wrapped in
a :class:`lima.workspace.RepositoryWorkspace`. Only stdlib and
``lima.workspace`` are imported here: the module under test (``lima.audit``)
is imported lazily by the tests so the module-absence RED anchor (PI-DR4)
stays observable per test case.
"""

from __future__ import annotations

import tempfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

from lima.workspace import RepositoryWorkspace

GOLDEN_LIBRARY_PROFILE = Path(__file__).resolve().parent / (
    "library_profile_golden.json"
)

_SENTINEL_EMPTY_DIGEST = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def sentinel_empty_digest() -> str:
    """Return the sha256(b"") sentinel pinned by Packet v1.1 (DR-IP-0016-01)."""
    return _SENTINEL_EMPTY_DIGEST


def profile_kwargs(**overrides: object) -> dict[str, object]:
    """Return standard ``build_repository_profile`` keyword arguments."""
    base: dict[str, object] = {
        "tenant_id": "tenant-test",
        "task_id": "task-test",
        "workflow_id": "workflow-test",
        "stage_attempt_id": "stage-attempt-test",
        "artifact_id": "artifact-profile-test",
        "repository_snapshot_digest": "1" * 64,
    }
    base.update(overrides)
    return base


@contextmanager
def workspace_with(
    files: Mapping[str, str | bytes],
    *,
    extensions: tuple[str, ...] | None = None,
    **workspace_limits: object,
) -> Iterator[RepositoryWorkspace]:
    """Materialize ``files`` (repo-relative path -> text or bytes) and yield a workspace."""
    with tempfile.TemporaryDirectory(prefix="lima-ip0016-") as tmp:
        root = Path(tmp)
        for rel in sorted(files):
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            content = files[rel]
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8")
        limits = dict(workspace_limits)
        if extensions is not None:
            limits["extensions"] = extensions
        yield RepositoryWorkspace(root, **limits)  # type: ignore[arg-type]
