"""GitHub repository materializer: resolve refs, fetch pinned archives and
publish immutable snapshots into the :class:`~lima.repository_cache.RepositoryCache`.

This module is the T2 layer of the repository acquisition chain.  It speaks
only to ``RepositoryCache``'s public API (``lookup``/``reserve``/``publish``/
``abort``) and never manages the cache filesystem itself.  Network access is
restricted to HTTPS on github.com and its known archive/API hosts; public
repositories are fetched unauthenticated so no token surface is required, and
an optional token (private repositories only) is used strictly as a request
header — it must never reach logs, task records or snapshot metadata.

Hard budgets (issue #11): 120 s wall clock, a download buffer far below the
512 MiB memory ceiling, 10 000 archive members, 1 GiB decompressed in total,
100 MiB per single member and a nested-archive depth of one (inner archives
stay opaque files).  An interrupted materialization never publishes partial
data: the reservation is aborted and the next attempt redownloads from
scratch instead of trusting partial data.
"""

from __future__ import annotations

import hashlib
import io
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from collections.abc import Callable
from pathlib import Path, PurePosixPath
from typing import Any

from .repository_cache import CacheEntry, RepositoryCache
from .repository_source import (
    GITHUB_SOURCE_TYPE,
    RepositorySource,
    parse_repository_source,
)

ALLOWED_HOSTS = frozenset(
    {
        "github.com",
        "www.github.com",
        "codeload.github.com",
        "api.github.com",
        "objects.githubusercontent.com",
    }
)
API_BASE = "https://api.github.com"
CODELOAD_BASE = "https://codeload.github.com"
DEFAULT_TIMEOUT_SECONDS = 120
MAX_ARCHIVE_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 10_000
MAX_UNCOMPRESSED_BYTES = 1024 * 1024 * 1024
MAX_MEMBER_BYTES = 100 * 1024 * 1024
USER_AGENT = "LIMA-Materializer"
_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REPOSITORY_SLUG_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class RepositoryMaterializerError(RuntimeError):
    """Raised when a repository cannot be resolved, fetched or materialized."""


class _WhitelistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only inside the GitHub host allowlist."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = (urllib.parse.urlsplit(newurl).hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise RepositoryMaterializerError(
                "refusing to follow a redirect outside the GitHub host allowlist"
            )
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _default_opener() -> Callable[..., Any]:
    return urllib.request.build_opener(_WhitelistedRedirectHandler).open


def _validate_github_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme.lower() != "https" or host not in ALLOWED_HOSTS:
        raise RepositoryMaterializerError(
            "refusing a request outside the GitHub HTTPS host allowlist"
        )


def _deadline_error() -> RepositoryMaterializerError:
    return RepositoryMaterializerError("materialization budget exceeded")


class GitHubMaterializer:
    """Materialize GitHub repository snapshots into a bounded snapshot cache."""

    def __init__(
        self,
        cache: RepositoryCache,
        *,
        opener: Callable[..., Any] | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        auth_token: str = "",
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.cache = cache
        self.opener = opener or _default_opener()
        self.timeout_seconds = timeout_seconds
        # token 只作为请求头使用；不得写入返回值、日志或快照。
        self._auth_token = auth_token.strip()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def materialize(
        self, source: RepositorySource | dict[str, str], ref: str = ""
    ) -> dict:
        """Return a published cache entry for ``source`` at ``ref``.

        ``ref`` may be a moving branch/tag (resolved to an immutable commit
        SHA through api.github.com first) or a full commit SHA (no network
        resolution).  Cache hits return without any network access.
        """

        normalized = parse_repository_source(source)
        if normalized.type != GITHUB_SOURCE_TYPE:
            raise ValueError("GitHub materializer requires a GitHub repository source")
        requested_ref = (ref or normalized.requested_ref or "HEAD").strip()
        deadline = time.monotonic() + self.timeout_seconds

        if _COMMIT_SHA_PATTERN.fullmatch(requested_ref.lower()):
            revision = requested_ref.lower()
        else:
            revision = self._resolve_revision(
                normalized.canonical_name, requested_ref, deadline
            )

        entry = self.cache.lookup(normalized, revision)
        if entry is not None:
            return self._result(entry, requested_ref, revision, cache_hit=True)

        reservation = self.cache.reserve(normalized, revision)
        if not reservation.owner:
            published = self.cache.wait_for_publish(
                normalized, revision,
                timeout_seconds=max(1.0, deadline - time.monotonic()),
            )
            if published is None:
                raise RepositoryMaterializerError(
                    "concurrent materialization did not publish in time"
                )
            return self._result(published, requested_ref, revision, cache_hit=True)

        with reservation:
            archive, digest = self._download(
                normalized.canonical_name, revision, deadline
            )
            self._extract(archive, reservation.staging_path, deadline)
            entry = reservation.publish()
        return self._result(entry, requested_ref, revision, archive_sha256=digest)

    # ------------------------------------------------------------------
    # Network helpers
    # ------------------------------------------------------------------

    def _headers(self, accept: str) -> dict[str, str]:
        headers = {"Accept": accept, "User-Agent": USER_AGENT}
        if self._auth_token:
            headers["Authorization"] = "Bearer " + self._auth_token
        return headers

    def _resolve_revision(
        self, repository: str, ref: str, deadline: float
    ) -> str:
        if not _REPOSITORY_SLUG_PATTERN.fullmatch(repository):
            raise ValueError("invalid GitHub repository slug")
        url = f"{API_BASE}/repos/{repository}/commits/{urllib.parse.quote(ref, safe='/')}"
        _validate_github_url(url)
        if time.monotonic() >= deadline:
            raise _deadline_error()
        # S310 属预期抑制：URL 已由 _validate_github_url 强制 https + GitHub 白名单
        request = urllib.request.Request(  # noqa: S310
            url, headers=self._headers("application/vnd.github+json")
        )
        try:
            with self.opener(
                request, timeout=max(1, int(deadline - time.monotonic()))
            ) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            raise RepositoryMaterializerError(
                f"GitHub commit resolution failed with HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise RepositoryMaterializerError(
                f"GitHub commit resolution failed: {exc}"
            ) from exc
        try:
            value = json.loads(payload.decode("utf-8"))
            sha = str(value["sha"]).lower()
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise RepositoryMaterializerError(
                "GitHub commit resolution returned an invalid payload"
            ) from exc
        if not _COMMIT_SHA_PATTERN.fullmatch(sha):
            raise RepositoryMaterializerError(
                "GitHub commit resolution returned a moving reference"
            )
        return sha

    # ------------------------------------------------------------------
    # Download & extraction
    # ------------------------------------------------------------------

    def _download(
        self, repository: str, revision: str, deadline: float
    ) -> tuple[bytes, str]:
        url = f"{CODELOAD_BASE}/{repository}/zip/{revision}"
        _validate_github_url(url)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _deadline_error()
        request = urllib.request.Request(  # noqa: S310
            url, headers=self._headers("application/zip")
        )
        chunks: list[bytes] = []
        total = 0
        try:
            with self.opener(request, timeout=max(1, int(remaining))) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise RepositoryMaterializerError(
                            "repository archive exceeds the download limit"
                        )
                    if time.monotonic() >= deadline:
                        raise _deadline_error()
                    chunks.append(chunk)
        except RepositoryMaterializerError:
            raise
        except urllib.error.HTTPError as exc:
            raise RepositoryMaterializerError(
                f"GitHub archive download failed with HTTP {exc.code}"
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise RepositoryMaterializerError(
                f"GitHub archive download failed: {exc}"
            ) from exc
        archive = b"".join(chunks)
        if not archive:
            raise RepositoryMaterializerError("repository archive is empty")
        return archive, hashlib.sha256(archive).hexdigest()

    def _extract(self, archive: bytes, destination: Path, deadline: float) -> None:
        """Extract one codeload zip archive inside all hard budgets."""

        root = destination.resolve()
        try:
            bundle = zipfile.ZipFile(io.BytesIO(archive))
        except zipfile.BadZipFile as exc:
            raise RepositoryMaterializerError(
                "repository archive is not a valid zip file"
            ) from exc
        with bundle:
            members = bundle.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise RepositoryMaterializerError(
                    "repository archive contains too many entries"
                )
            if sum(item.file_size for item in members) > MAX_UNCOMPRESSED_BYTES:
                raise RepositoryMaterializerError(
                    "repository archive exceeds the decompression limit"
                )
            # codeload 归档总是包含单一顶层目录（<repo>-<ref>/）；快照以仓库根
            # 为根，因此统一剥除该前缀，且不共享前缀的归档视为非预期形态。
            prefixes = {
                PurePosixPath(item.filename).parts[0]
                for item in members
                if PurePosixPath(item.filename).parts
            }
            if len(prefixes) != 1:
                raise RepositoryMaterializerError(
                    "repository archive must contain a single top-level directory"
                )
            for member in members:
                if time.monotonic() >= deadline:
                    raise _deadline_error()
                if member.file_size > MAX_MEMBER_BYTES:
                    raise RepositoryMaterializerError(
                        "repository archive member exceeds the per-file limit"
                    )
                full_path = PurePosixPath(member.filename)
                if full_path.is_absolute() or ".." in full_path.parts:
                    raise RepositoryMaterializerError(
                        "repository archive contains an unsafe path"
                    )
                mode = member.external_attr >> 16
                if (mode & 0o170000) == 0o120000:
                    raise RepositoryMaterializerError(
                        "repository archive contains a symbolic link"
                    )
                stripped = full_path.parts[1:]
                if not stripped:
                    continue  # 顶层目录条目本身，剥除前缀后无内容
                target = (destination / Path(*stripped)).resolve()
                try:
                    target.relative_to(root)
                except ValueError as exc:
                    raise RepositoryMaterializerError(
                        "repository archive path escapes the extraction root"
                    ) from exc
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source_file, target.open("wb") as output:
                    while True:
                        if time.monotonic() >= deadline:
                            raise _deadline_error()
                        chunk = source_file.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)

    # ------------------------------------------------------------------
    # Result shaping
    # ------------------------------------------------------------------

    def _result(
        self,
        entry: CacheEntry,
        requested_ref: str,
        revision: str,
        *,
        cache_hit: bool = False,
        archive_sha256: str = "",
    ) -> dict:
        return {
            "key": entry.key,
            "path": str(entry.path),
            "source": entry.source,
            "requested_ref": requested_ref,
            "resolved_revision": revision,
            "content_fingerprint": entry.content_fingerprint,
            "file_count": entry.file_count,
            "total_bytes": entry.total_bytes,
            "archive_sha256": archive_sha256,
            "cache_hit": cache_hit,
        }


__all__ = [
    "ALLOWED_HOSTS",
    "GitHubMaterializer",
    "RepositoryMaterializerError",
]
