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

from .repository_cache import CacheEntry, RepositoryCache, RepositoryCacheError
from .repository_source import (
    GITHUB_SOURCE_TYPE,
    RepositorySource,
    parse_repository_source,
)
from .task_failure import (
    ARCHIVE_DECOMPRESSION_LIMIT,
    ARCHIVE_INVALID,
    ARCHIVE_MEMBER_TOO_LARGE,
    ARCHIVE_TOO_LARGE,
    ARCHIVE_TOO_MANY_FILES,
    ARCHIVE_UNSAFE_PATH,
    CACHE_LOCK_TIMEOUT,
    CACHE_NO_SPACE,
    CACHE_PUBLISH_FAILED,
    GITHUB_AUTH_REQUIRED,
    GITHUB_INVALID_REF,
    GITHUB_NETWORK_ERROR,
    GITHUB_NOT_FOUND,
    GITHUB_RATE_LIMITED,
    GITHUB_TIMEOUT,
    TaskFailure,
    TaskFailureError,
)
from .task_progress import (
    CHECKING_CACHE,
    DOWNLOADING_ARCHIVE,
    PREPARING_WORKSPACE,
    RESOLVING_REVISION,
    VALIDATING_ARCHIVE,
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
DOWNLOAD_PROGRESS_BYTES = 4 * 1024 * 1024
DOWNLOAD_PROGRESS_INTERVAL = 0.5
_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_REPOSITORY_SLUG_PATTERN = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+")


class RepositoryMaterializerError(RuntimeError):
    """Raised when a repository cannot be resolved, fetched or materialized."""


class _WhitelistedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only inside the GitHub host allowlist."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        host = (urllib.parse.urlsplit(newurl).hostname or "").lower()
        if host not in ALLOWED_HOSTS:
            raise TaskFailureError(
                TaskFailure.from_code(
                    GITHUB_NETWORK_ERROR,
                    technical_detail=(
                        "refusing to follow a redirect outside the GitHub "
                        "host allowlist"
                    ),
                    target_host=host,
                )
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


class GitHubMaterializer:
    """Materialize GitHub repository snapshots into a bounded snapshot cache."""

    def __init__(
        self,
        cache: RepositoryCache,
        *,
        opener: Callable[..., Any] | None = None,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
        auth_token: str = "",
        progress_throttle_bytes: int = DOWNLOAD_PROGRESS_BYTES,
        progress_throttle_interval: float = DOWNLOAD_PROGRESS_INTERVAL,
    ) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.cache = cache
        self.opener = opener or _default_opener()
        self.timeout_seconds = timeout_seconds
        self.progress_throttle_bytes = max(1, progress_throttle_bytes)
        self.progress_throttle_interval = max(0.0, progress_throttle_interval)
        # token 只作为请求头使用；不得写入返回值、日志或快照。
        self._auth_token = auth_token.strip()

    @staticmethod
    def _report(callback, stage: str, message: str, **detail: Any) -> None:
        if callback is not None:
            callback(stage, message, **detail)

    @staticmethod
    def _typed(code: str, stage: str, detail: str) -> TaskFailureError:
        return TaskFailureError(
            TaskFailure.from_code(code, stage=stage, technical_detail=detail)
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def materialize(
        self,
        source: RepositorySource | dict[str, str],
        ref: str = "",
        *,
        progress_callback: Callable[..., None] | None = None,
    ) -> dict:
        """Return a published cache entry for ``source`` at ``ref``.

        ``ref`` may be a moving branch/tag (resolved to an immutable commit
        SHA through api.github.com first) or a full commit SHA (no network
        resolution).  Cache hits return without any network access.

        ``progress_callback(stage, message, **detail)`` receives throttled
        stage updates for observability.  Symlink archive members are
        skipped (never created, never followed) and reported as coverage
        warnings instead of failing the whole repository.
        """

        normalized = parse_repository_source(source)
        if normalized.type != GITHUB_SOURCE_TYPE:
            raise ValueError("GitHub materializer requires a GitHub repository source")
        requested_ref = (ref or normalized.requested_ref or "HEAD").strip()
        deadline = time.monotonic() + self.timeout_seconds

        if _COMMIT_SHA_PATTERN.fullmatch(requested_ref.lower()):
            revision = requested_ref.lower()
        else:
            self._report(
                progress_callback, RESOLVING_REVISION,
                "正在解析 GitHub 仓库版本", requested_ref=requested_ref,
            )
            revision = self._resolve_revision(
                normalized.canonical_name, requested_ref, deadline
            )
        self._report(
            progress_callback, CHECKING_CACHE, "正在检查快照缓存",
            resolved_revision=revision,
        )

        entry = self.cache.lookup(normalized, revision)
        if entry is not None:
            self._report(
                progress_callback, CHECKING_CACHE, "命中快照缓存",
                cache_hit=True, resolved_revision=revision,
            )
            return self._result(
                entry, requested_ref, revision, cache_hit=True, warnings=[]
            )

        reservation = self.cache.reserve(normalized, revision)
        if not reservation.owner:
            self._report(
                progress_callback, VALIDATING_ARCHIVE, "等待并发物化完成",
            )
            published = self.cache.wait_for_publish(
                normalized, revision,
                timeout_seconds=max(1.0, deadline - time.monotonic()),
            )
            if published is None:
                raise self._typed(
                    CACHE_LOCK_TIMEOUT, VALIDATING_ARCHIVE,
                    "concurrent materialization did not publish in time",
                )
            return self._result(
                published, requested_ref, revision, cache_hit=True, warnings=[]
            )

        with reservation:
            archive, digest = self._download(
                normalized.canonical_name, revision, deadline, progress_callback
            )
            skipped = self._extract(
                archive, reservation.staging_path, deadline, progress_callback
            )
            self._report(
                progress_callback, PREPARING_WORKSPACE,
                "快照已发布到缓存", resolved_revision=revision,
            )
            try:
                entry = reservation.publish()
            except RepositoryCacheError as exc:
                text = str(exc)
                if "free space" in text:
                    raise self._typed(
                        CACHE_NO_SPACE, PREPARING_WORKSPACE, text
                    ) from exc
                raise self._typed(
                    CACHE_PUBLISH_FAILED, PREPARING_WORKSPACE, text
                ) from exc
        warnings = [
            {
                "code": "SYMLINK_SKIPPED",
                "category": "coverage",
                "path": name,
                "message": "符号链接未被跟随，已从快照中跳过。",
            }
            for name in skipped
        ]
        return self._result(
            entry, requested_ref, revision,
            archive_sha256=digest, warnings=warnings,
        )

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
            raise self._typed(
                GITHUB_TIMEOUT, RESOLVING_REVISION, "materialization budget exceeded"
            )
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
            code = {
                404: GITHUB_NOT_FOUND,
                401: GITHUB_AUTH_REQUIRED,
                403: GITHUB_AUTH_REQUIRED,
                429: GITHUB_RATE_LIMITED,
                408: GITHUB_TIMEOUT,
            }.get(exc.code)
            if code is None and exc.code >= 500:
                code = GITHUB_NETWORK_ERROR
            if code is None:
                code = GITHUB_NETWORK_ERROR
            raise self._typed(
                code, RESOLVING_REVISION,
                f"GitHub commit resolution failed with HTTP {exc.code}",
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise self._typed(
                GITHUB_NETWORK_ERROR, RESOLVING_REVISION,
                f"GitHub commit resolution failed: {exc}",
            ) from exc
        try:
            value = json.loads(payload.decode("utf-8"))
            sha = str(value["sha"]).lower()
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise self._typed(
                GITHUB_INVALID_REF, RESOLVING_REVISION,
                "GitHub commit resolution returned an invalid payload",
            ) from exc
        if not _COMMIT_SHA_PATTERN.fullmatch(sha):
            raise self._typed(
                GITHUB_INVALID_REF, RESOLVING_REVISION,
                "GitHub commit resolution returned a moving reference",
            )
        return sha

    # ------------------------------------------------------------------
    # Download & extraction
    # ------------------------------------------------------------------

    def _download(
        self,
        repository: str,
        revision: str,
        deadline: float,
        progress_callback=None,
    ) -> tuple[bytes, str]:
        url = f"{CODELOAD_BASE}/{repository}/zip/{revision}"
        _validate_github_url(url)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise self._typed(
                GITHUB_TIMEOUT, DOWNLOADING_ARCHIVE, "materialization budget exceeded"
            )
        request = urllib.request.Request(  # noqa: S310
            url, headers=self._headers("application/zip")
        )
        chunks: list[bytes] = []
        total = 0
        reported_bytes = 0
        reported_at = time.monotonic()
        self._report(
            progress_callback, DOWNLOADING_ARCHIVE, "正在下载仓库快照",
            current=0,
        )
        try:
            with self.opener(request, timeout=max(1, int(remaining))) as response:
                while True:
                    chunk = response.read(1024 * 1024)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > MAX_ARCHIVE_BYTES:
                        raise self._typed(
                            ARCHIVE_TOO_LARGE, DOWNLOADING_ARCHIVE,
                            "repository archive exceeds the download limit",
                        )
                    if time.monotonic() >= deadline:
                        raise self._typed(
                            GITHUB_TIMEOUT, DOWNLOADING_ARCHIVE,
                            "materialization budget exceeded",
                        )
                    chunks.append(chunk)
                    now = time.monotonic()
                    if (
                        total - reported_bytes >= self.progress_throttle_bytes
                        or now - reported_at >= self.progress_throttle_interval
                    ):
                        reported_bytes = total
                        reported_at = now
                        self._report(
                            progress_callback, DOWNLOADING_ARCHIVE,
                            "正在下载仓库快照", current=total,
                        )
        except TaskFailureError:
            raise
        except urllib.error.HTTPError as exc:
            raise self._typed(
                GITHUB_NETWORK_ERROR, DOWNLOADING_ARCHIVE,
                f"GitHub archive download failed with HTTP {exc.code}",
            ) from exc
        except (urllib.error.URLError, OSError) as exc:
            raise self._typed(
                GITHUB_NETWORK_ERROR, DOWNLOADING_ARCHIVE,
                f"GitHub archive download failed: {exc}",
            ) from exc
        archive = b"".join(chunks)
        if not archive:
            raise self._typed(
                ARCHIVE_INVALID, DOWNLOADING_ARCHIVE, "repository archive is empty"
            )
        self._report(
            progress_callback, DOWNLOADING_ARCHIVE, "仓库快照下载完成",
            current=total,
        )
        return archive, hashlib.sha256(archive).hexdigest()

    def _extract(
        self,
        archive: bytes,
        destination: Path,
        deadline: float,
        progress_callback=None,
    ) -> list[str]:
        """Extract one codeload zip archive inside all hard budgets.

        Symbolic-link members are skipped (never created, never followed) and
        their relative paths are returned as coverage warnings.  Unsafe
        paths, budget violations and invalid archives still fail closed with
        typed errors.
        """

        root = destination.resolve()
        try:
            bundle = zipfile.ZipFile(io.BytesIO(archive))
        except zipfile.BadZipFile as exc:
            raise self._typed(
                ARCHIVE_INVALID, VALIDATING_ARCHIVE,
                "repository archive is not a valid zip file",
            ) from exc
        with bundle:
            members = bundle.infolist()
            if len(members) > MAX_ARCHIVE_MEMBERS:
                raise self._typed(
                    ARCHIVE_TOO_MANY_FILES, VALIDATING_ARCHIVE,
                    "repository archive contains too many entries",
                )
            if sum(item.file_size for item in members) > MAX_UNCOMPRESSED_BYTES:
                raise self._typed(
                    ARCHIVE_DECOMPRESSION_LIMIT, VALIDATING_ARCHIVE,
                    "repository archive exceeds the decompression limit",
                )
            # codeload 归档总是包含单一顶层目录（<repo>-<ref>/）；快照以仓库根
            # 为根，因此统一剥除该前缀，且不共享前缀的归档视为非预期形态。
            prefixes = {
                PurePosixPath(item.filename).parts[0]
                for item in members
                if PurePosixPath(item.filename).parts
            }
            if len(prefixes) != 1:
                raise self._typed(
                    ARCHIVE_INVALID, VALIDATING_ARCHIVE,
                    "repository archive must contain a single top-level directory",
                )
            skipped: list[str] = []
            entries_total = len(members)
            for index, member in enumerate(members):
                if time.monotonic() >= deadline:
                    raise self._typed(
                        GITHUB_TIMEOUT, VALIDATING_ARCHIVE,
                        "materialization budget exceeded",
                    )
                if member.file_size > MAX_MEMBER_BYTES:
                    raise self._typed(
                        ARCHIVE_MEMBER_TOO_LARGE, VALIDATING_ARCHIVE,
                        "repository archive member exceeds the per-file limit",
                    )
                full_path = PurePosixPath(member.filename)
                if full_path.is_absolute() or ".." in full_path.parts:
                    raise self._typed(
                        ARCHIVE_UNSAFE_PATH, VALIDATING_ARCHIVE,
                        "repository archive contains an unsafe path",
                    )
                stripped = full_path.parts[1:]
                mode = member.external_attr >> 16
                if (mode & 0o170000) == 0o120000:
                    # 绝不创建、绝不跟随：记录为覆盖范围警告后跳过。
                    if stripped:
                        skipped.append("/".join(stripped))
                    continue
                if not stripped:
                    continue  # 顶层目录条目本身，剥除前缀后无内容
                target = (destination / Path(*stripped)).resolve()
                try:
                    target.relative_to(root)
                except ValueError as exc:
                    raise self._typed(
                        ARCHIVE_UNSAFE_PATH, VALIDATING_ARCHIVE,
                        "repository archive path escapes the extraction root",
                    ) from exc
                if member.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.open(member) as source_file, target.open("wb") as output:
                    while True:
                        if time.monotonic() >= deadline:
                            raise self._typed(
                                GITHUB_TIMEOUT, VALIDATING_ARCHIVE,
                                "materialization budget exceeded",
                            )
                        chunk = source_file.read(1024 * 1024)
                        if not chunk:
                            break
                        output.write(chunk)
                if progress_callback is not None and (
                    index % 500 == 0 or index == entries_total - 1
                ):
                    self._report(
                        progress_callback, VALIDATING_ARCHIVE,
                        "正在验证并解包仓库快照",
                        entries_processed=index + 1, entries_total=entries_total,
                    )
            return skipped

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
        warnings: list[dict] | None = None,
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
            "warnings": warnings or [],
        }


__all__ = [
    "ALLOWED_HOSTS",
    "GitHubMaterializer",
    "RepositoryMaterializerError",
]
