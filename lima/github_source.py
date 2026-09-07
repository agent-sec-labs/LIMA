"""SHA-pinned pull-request source snapshots with bounded budgets.

This module is the evidence boundary for PR source code (design section 6
"PR 源码来源"). :meth:`GitHubSourceProvider.fetch` resolves one commit to a
:class:`GitHubSnapshot` in priority order:

1. an imported local workspace whose checked-out commit equals the head SHA
   exactly (:class:`LocalCommitSource`);
2. GitHub Contents-API reads bound to the full 40-character SHA;
3. a diff-only degraded snapshot when GitHub is unavailable.

Red lines implemented here:

- Every URL/API parameter binds the exact lowercase 40-hex commit SHA;
  branches, short SHAs, uppercase hex, and movable refs are rejected.
- Symlinks, submodules, directories, and unknown payload types are skipped,
  never followed or decoded; non-UTF-8 content is skipped, never guessed.
- Files are admitted whole or skipped: no truncated half-file is ever
  produced, and responses are read under a byte bound before decoding.
- A GitHub failure degrades to diff-only and discards any files already
  read, because pinned-SHA evidence is all-or-nothing. ``ValueError`` from
  input validation is never swallowed by that degradation.
- ``unavailable_reason`` is restricted to fixed vocabulary tokens joined by
  "+" in canonical order, so exception text, URLs, or response bodies (and
  therefore credentials) can never leak into a snapshot. No Authorization
  or token material is ever logged.
- Diff-only snapshots keep only new-side added line numbers for validated
  paths; context lines and removed code are never retained.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

from .cxx_retrieval import _validate_changed_path
from .github import ResponseTooLarge

MODE_LOCAL = "local"
MODE_GITHUB = "github"
MODE_DIFF_ONLY = "diff-only"
_MODES = frozenset({MODE_LOCAL, MODE_GITHUB, MODE_DIFF_ONLY})

REASON_LOCAL_MISS = "local-miss"
REASON_GITHUB_UNAVAILABLE = "github-unavailable"
REASON_DIFF_ONLY = "diff-only"
_REASON_ORDER = (REASON_LOCAL_MISS, REASON_GITHUB_UNAVAILABLE, REASON_DIFF_ONLY)

_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")
_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_HUNK_PATTERN = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# HTTP response read bound for one Contents-API call: base64 inflates the
# payload to at most ~4/3 of the decoded size (plus newline wrapping and the
# JSON envelope), so twice the remaining byte budget plus 8 KiB always admits
# any file that could still fit, while anything larger cannot fit and is
# skipped by the caller.
_RESPONSE_BOUND_SLACK = 8192

# Contents-API responses echo the full path in their url/html_url/download_url
# envelope fields, so an unbounded path could overflow the bounded response
# read even when the file itself fits the byte budget. 512 characters is far
# above any legitimate POSIX repository path in this pipeline, so longer
# operands are rejected as invalid input at this module's boundary instead of
# being fetched (the shared cxx_retrieval validation stays signature-identical
# for its own callers).
_MAX_PATH_LENGTH = 512


@dataclass(frozen=True)
class SourceFetchBudget:
    """Hard file-count and byte caps for one snapshot fetch."""

    max_files: int = 12
    max_total_bytes: int = 1_048_576

    def __post_init__(self) -> None:
        for name in ("max_files", "max_total_bytes"):
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{name} must be a positive integer, got {value!r}")


@dataclass(frozen=True)
class SnapshotFile:
    """One admitted file: exact content plus its derived integrity hash.

    ``sha256`` is the hex SHA-256 of the UTF-8 encoded ``content`` and
    ``size_bytes`` is its length in bytes; both are verified on construction
    so a snapshot can never carry inconsistent metadata.
    """

    path: str
    sha256: str
    content: str
    size_bytes: int

    @classmethod
    def from_content(cls, path: str, content: str) -> SnapshotFile:
        encoded = content.encode("utf-8")
        return cls(path, hashlib.sha256(encoded).hexdigest(), content, len(encoded))

    def __post_init__(self) -> None:
        encoded = self.content.encode("utf-8")
        if self.sha256 != hashlib.sha256(encoded).hexdigest():
            raise ValueError(f"sha256 does not match content for {self.path!r}")
        if self.size_bytes != len(encoded):
            raise ValueError(f"size_bytes does not match content for {self.path!r}")


@dataclass(frozen=True)
class GitHubSnapshot:
    """Immutable source snapshot; content and diff evidence never mix.

    ``mode`` selects the evidence kind: ``local``/``github`` snapshots carry
    verified file content only, ``diff-only`` snapshots carry only changed
    new-side line numbers and never any unread file content.
    ``unavailable_reason`` explains a degradation using fixed vocabulary
    tokens (see :data:`REASON_LOCAL_MISS` and friends) joined by "+" in
    canonical order; it is never free text.
    """

    repository: str
    commit: str
    mode: str
    files: tuple[SnapshotFile, ...] = ()
    changed_lines: tuple[tuple[str, tuple[int, ...]], ...] = ()
    skipped_files: int = 0
    skipped_bytes: int = 0
    unavailable_reason: str = ""

    def __post_init__(self) -> None:
        if self.mode not in _MODES:
            raise ValueError(f"unknown snapshot mode, got {self.mode!r}")
        if self.mode == MODE_DIFF_ONLY:
            if self.files:
                raise ValueError("diff-only snapshots must not carry file content")
            if not self.unavailable_reason:
                raise ValueError("diff-only snapshots must record unavailable_reason")
        else:
            if self.changed_lines:
                raise ValueError("only diff-only snapshots carry changed_lines")
            if self.unavailable_reason:
                raise ValueError("content snapshots must not carry unavailable_reason")
        _validate_reason(self.unavailable_reason)


@runtime_checkable
class LocalCommitSource(Protocol):
    """Admin-imported local workspace lookup.

    Implementations return ``{relative posix path: text}`` only when the
    repository is imported locally AND its checked-out commit equals
    ``commit_sha`` exactly; otherwise they return ``None``. The lookup is
    exact-SHA: implementations never resolve branches, shorten hashes, or
    fall back to a nearby commit -- an inexact match is a miss.
    """

    def snapshot(self, repository: str, commit_sha: str) -> Mapping[str, str] | None:
        """Return the tree for an exact commit match, else ``None``."""
        ...


def _validate_reason(reason: str) -> None:
    if not reason:
        return
    tokens = reason.split("+")
    if any(token not in _REASON_ORDER for token in tokens):
        raise ValueError(
            f"unavailable_reason must use the fixed vocabulary, got {reason!r}"
        )
    canonical = [token for token in _REASON_ORDER if token in tokens]
    if len(set(tokens)) != len(tokens) or tokens != canonical:
        raise ValueError(
            f"unavailable_reason tokens must be unique and canonical, got {reason!r}"
        )


def _compose_reason(tokens: Sequence[str]) -> str:
    return "+".join(token for token in _REASON_ORDER if token in tokens)


def _validate_repository(repository: str) -> None:
    if not isinstance(repository, str) or not _REPOSITORY_PATTERN.fullmatch(repository):
        raise ValueError(f"repository must look like 'owner/name', got {repository!r}")


def _validate_commit_sha(commit_sha: str) -> None:
    if not isinstance(commit_sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(commit_sha):
        raise ValueError(
            f"commit_sha must be a lowercase 40-hex commit SHA, got {commit_sha!r}"
        )


def _validate_snapshot_path(path: str) -> None:
    """Shared cxx_retrieval validation plus this module's length cap."""
    _validate_changed_path(path)
    if len(path) > _MAX_PATH_LENGTH:
        raise ValueError(
            f"path must be at most {_MAX_PATH_LENGTH} characters, "
            f"got {len(path)} characters"
        )


def _validate_paths(paths: Sequence[str]) -> tuple[str, ...]:
    """Validate every requested path; return it deduplicated and sorted.

    Deliberately reuses the exact POSIX-relative validation from
    :mod:`lima.cxx_retrieval` (plus a bounded length cap) so both entry
    points share one rule set. Non-iterable ``paths`` surface as
    ``TypeError`` from iteration.
    """
    unique: set[str] = set()
    for path in paths:
        _validate_snapshot_path(path)
        unique.add(path)
    return tuple(sorted(unique))


def _response_bound(remaining_bytes: int) -> int:
    return remaining_bytes * 2 + _RESPONSE_BOUND_SLACK


def _admit_payload(
    path: str, payload: object, remaining_bytes: int
) -> tuple[SnapshotFile | None, int]:
    """Admit one Contents-API payload whole, or skip it (never truncate).

    Returns ``(entry, 0)`` on success and ``(None, skipped_bytes)`` when the
    payload must be skipped; skipped bytes are reported only when measured.
    Unknown payload types (symlink/submodule/dir/anything else) are skipped
    without ever being decoded.
    """
    if not isinstance(payload, Mapping) or payload.get("type") != "file":
        return None, 0
    declared = payload.get("size")
    declared_known = isinstance(declared, int) and not isinstance(declared, bool)
    if declared_known and declared > remaining_bytes:
        return None, declared
    encoded = payload.get("content")
    if not isinstance(encoded, str):
        return None, declared if declared_known else 0
    try:
        raw = base64.b64decode(encoded)
    except (binascii.Error, ValueError):
        return None, declared if declared_known else 0
    if len(raw) > remaining_bytes:
        return None, len(raw)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None, len(raw)
    return SnapshotFile.from_content(path, text), 0


class GitHubSourceProvider:
    """Fetches bounded, SHA-pinned PR source snapshots.

    ``client`` only needs ``GitHubClient.get_file_at_commit`` (real or fake);
    ``local_source`` is any :class:`LocalCommitSource` and is optional.
    """

    def __init__(self, client, local_source: LocalCommitSource | None = None) -> None:
        self._client = client
        self._local_source = local_source

    def fetch(
        self,
        repository: str,
        commit_sha: str,
        paths: Sequence[str],
        budget: SourceFetchBudget,
    ) -> GitHubSnapshot:
        """Resolve the snapshot for one pinned commit under ``budget``.

        Order: validate inputs (``ValueError`` on any violation -- validation
        never degrades), prefer an exact local commit match, then read each
        path from GitHub bound to the full SHA, then degrade to a diff-only
        snapshot when GitHub fails. A degradation discards any files already
        read: pinned-SHA evidence is all-or-nothing.
        """
        _validate_repository(repository)
        _validate_commit_sha(commit_sha)
        requested = _validate_paths(paths)
        if not isinstance(budget, SourceFetchBudget):
            raise ValueError(f"budget must be a SourceFetchBudget, got {budget!r}")
        if self._local_source is not None:
            tree = self._local_source.snapshot(repository, commit_sha)
            if tree is not None:
                return self._local_snapshot(
                    repository, commit_sha, requested, tree, budget
                )
        return self._github_snapshot(repository, commit_sha, requested, budget)

    def _local_snapshot(
        self,
        repository: str,
        commit_sha: str,
        requested: tuple[str, ...],
        tree: Mapping[str, str],
        budget: SourceFetchBudget,
    ) -> GitHubSnapshot:
        files: list[SnapshotFile] = []
        skipped_files = 0
        skipped_bytes = 0
        used_bytes = 0
        for path in requested:
            content = tree.get(path)
            if not isinstance(content, str):
                skipped_files += 1
                continue
            size = len(content.encode("utf-8"))
            if len(files) >= budget.max_files or used_bytes + size > budget.max_total_bytes:
                skipped_files += 1
                skipped_bytes += size
                continue
            files.append(SnapshotFile.from_content(path, content))
            used_bytes += size
        return GitHubSnapshot(
            repository=repository,
            commit=commit_sha,
            mode=MODE_LOCAL,
            files=tuple(files),
            skipped_files=skipped_files,
            skipped_bytes=skipped_bytes,
        )

    def _github_snapshot(
        self,
        repository: str,
        commit_sha: str,
        requested: tuple[str, ...],
        budget: SourceFetchBudget,
    ) -> GitHubSnapshot:
        files: list[SnapshotFile] = []
        skipped_files = 0
        skipped_bytes = 0
        used_bytes = 0
        for path in requested:
            if len(files) >= budget.max_files:
                skipped_files += 1
                continue
            remaining_bytes = budget.max_total_bytes - used_bytes
            try:
                payload = self._client.get_file_at_commit(
                    repository, path, commit_sha,
                    max_response_bytes=_response_bound(remaining_bytes),
                )
            except ResponseTooLarge:
                # The bounded read refuses oversized bodies before decoding;
                # this is a per-file budget skip, not a provider failure.
                skipped_files += 1
                continue
            except RuntimeError:
                # 404, rate limit, or exhausted retries: pinned evidence is
                # all-or-nothing, so degrade and discard partial files.
                return self._degraded(repository, commit_sha)
            entry, skipped_size = _admit_payload(path, payload, remaining_bytes)
            if entry is None:
                skipped_files += 1
                skipped_bytes += skipped_size
                continue
            files.append(entry)
            used_bytes += entry.size_bytes
        return GitHubSnapshot(
            repository=repository,
            commit=commit_sha,
            mode=MODE_GITHUB,
            files=tuple(files),
            skipped_files=skipped_files,
            skipped_bytes=skipped_bytes,
        )

    def _degraded(self, repository: str, commit_sha: str) -> GitHubSnapshot:
        tokens = []
        if self._local_source is not None:
            tokens.append(REASON_LOCAL_MISS)
        tokens.append(REASON_GITHUB_UNAVAILABLE)
        return GitHubSnapshot(
            repository=repository,
            commit=commit_sha,
            mode=MODE_DIFF_ONLY,
            unavailable_reason=_compose_reason(tokens),
        )


class _DiffSection:
    """Mutable parse state for one ``diff --git`` file section."""

    __slots__ = (
        "added", "binary", "deleted", "hunk_error", "in_hunk",
        "new_left", "new_line", "new_path", "old_left",
    )

    def __init__(self) -> None:
        self.new_path: str | None = None
        self.deleted = False
        self.binary = False
        self.hunk_error = False
        self.in_hunk = False
        self.old_left = 0
        self.new_left = 0
        self.new_line = 0
        self.added: set[int] = set()


def snapshot_from_diff(
    repository: str,
    commit_sha: str,
    diff_text: str,
    budget: SourceFetchBudget,
) -> GitHubSnapshot:
    """Build a diff-only snapshot from an already-fetched unified diff.

    Module-level on purpose: parsing is a pure function over text that needs
    no client or local workspace, so orchestrators can degrade without
    holding a provider instance. ``budget`` is validated for signature
    symmetry with :meth:`GitHubSourceProvider.fetch` but consumes nothing:
    diff parsing produces line numbers, not bytes. Only new-side added line
    numbers are extracted for paths that pass validation; deleted files and
    sections with no textual change produce nothing, while binary sections,
    unparsable hunks, and quoted paths that carry hunks are counted in
    ``skipped_files`` instead of guessed; a quoted path without hunks
    produces neither changed_lines nor skipped counts. Context lines and
    removed code are never retained -- a diff-only snapshot must not turn
    unread old content into evidence.
    """
    _validate_repository(repository)
    _validate_commit_sha(commit_sha)
    if not isinstance(budget, SourceFetchBudget):
        raise ValueError(f"budget must be a SourceFetchBudget, got {budget!r}")
    if not isinstance(diff_text, str):
        raise ValueError(f"diff_text must be a string, got {diff_text!r}")
    changed: dict[str, set[int]] = {}
    skipped_files = _parse_diff(diff_text, changed)
    changed_lines = tuple(
        (path, tuple(sorted(lines))) for path, lines in sorted(changed.items())
    )
    return GitHubSnapshot(
        repository=repository,
        commit=commit_sha,
        mode=MODE_DIFF_ONLY,
        changed_lines=changed_lines,
        skipped_files=skipped_files,
        unavailable_reason=REASON_DIFF_ONLY,
    )


def _parse_diff(diff_text: str, changed: dict[str, set[int]]) -> int:
    """Parse a unified diff into ``changed``; return the skipped-file count.

    Hunk bodies are consumed by their declared line counts, so added or
    removed content that merely looks like a header (``--- x`` / ``+++ x``)
    can never be mistaken for one.
    """
    skipped = 0
    section: _DiffSection | None = None
    in_binary_body = False

    def close() -> None:
        nonlocal section, skipped
        if section is None:
            return
        if section.binary or section.hunk_error:
            skipped += 1
        elif section.new_path is not None and not section.deleted and section.added:
            try:
                _validate_snapshot_path(section.new_path)
            except ValueError:
                skipped += 1
            else:
                changed.setdefault(section.new_path, set()).update(section.added)
        section = None

    for line in diff_text.splitlines():
        if section is not None and section.in_hunk:
            _consume_hunk_line(section, line)
            if section.hunk_error:
                # Drop the file at the first unparsable hunk line instead of
                # letting the corrupt section absorb later file boundaries.
                close()
            continue
        if line.startswith("diff --git "):
            close()
            section = _DiffSection()
            in_binary_body = False
            continue
        if section is None:
            continue
        if in_binary_body:
            continue
        if line.startswith("Binary files ") or line == "GIT binary patch":
            section.binary = True
            in_binary_body = line == "GIT binary patch"
            continue
        if line.startswith("+++ "):
            raw = line[4:].split("\t", 1)[0]
            if raw == "/dev/null":
                section.deleted = True
            else:
                section.new_path = _diff_path(raw)
            continue
        if line.startswith("@@ "):
            match = _HUNK_PATTERN.match(line)
            if match is None or (section.new_path is None and not section.deleted):
                section.hunk_error = True
                close()
                continue
            section.in_hunk = True
            section.old_left = int(match.group(2)) if match.group(2) is not None else 1
            section.new_left = int(match.group(4)) if match.group(4) is not None else 1
            section.new_line = int(match.group(3))
            continue
        # Remaining header/decoration lines (---, index, mode, rename,
        # similarity) carry no new-side line evidence and are ignored.
    close()
    return skipped


def _consume_hunk_line(section: _DiffSection, line: str) -> None:
    if line.startswith("+"):
        section.added.add(section.new_line)
        section.new_line += 1
        section.new_left -= 1
    elif line.startswith("-"):
        section.old_left -= 1
    elif line.startswith(" ") or line == "":
        section.new_line += 1
        section.old_left -= 1
        section.new_left -= 1
    elif line.startswith("\\"):
        # "\ No newline at end of file" consumes no line on either side.
        pass
    else:
        # Anything else inside a declared hunk means the diff is not a well
        # formed unified diff; drop the file rather than guess.
        section.hunk_error = True
        section.in_hunk = False
        return
    if section.old_left <= 0 and section.new_left <= 0:
        section.in_hunk = False


def _diff_path(raw: str) -> str | None:
    """Map a ``+++`` header operand to a repo-relative path.

    Returns ``None`` when the operand cannot be interpreted without guessing
    (git C-quoted paths); any hunks in such a section then count once as
    skipped, while a hunkless section simply produces nothing.
    """
    path = raw.split("\t", 1)[0]
    if path.startswith('"'):
        return None
    if path.startswith("b/"):
        return path[2:]
    return path
