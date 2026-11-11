import hashlib
import hmac
import json
import urllib.error
import urllib.request
import urllib.parse
import base64
import random
import re
import os
import tempfile
import threading
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Dict

_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_REPOSITORY_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})/"
    r"[A-Za-z0-9](?:[A-Za-z0-9_.-]{0,99})"
)
_GIT_METADATA_MAX_BYTES = 1_000_000
_CONTENTS_RESPONSE_MAX_BYTES = 1_000_000
_DECODED_SOURCE_MAX_BYTES = 512 * 1024
_ARCHIVE_MAX_BYTES = 64 * 1024 * 1024
_ARCHIVE_READ_CHUNK_BYTES = 64 * 1024
_REGULAR_FILE_MODES = frozenset({"100644", "100755"})


def verify_signature(secret: str, body: bytes, signature: str) -> bool:
    if not secret or not signature.startswith("sha256="):
        return False
    expected = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)


def pull_request_commit_shas(payload: dict) -> "tuple[str, str]":
    """Extract ``(head_sha, base_sha)`` from a verified pull_request payload.

    Both commits must be exact lowercase 40-hex strings; branch names, short
    or uppercase SHAs are rejected with ``ValueError``, because every
    downstream source fetch binds these values as immutable refs and a moving
    ref must never stand in for the pinned commit (design section 6). Callers
    pass the already signature-verified webhook payload.
    """
    pull = (payload or {}).get("pull_request") if isinstance(payload, dict) else None
    if not isinstance(pull, dict):
        raise ValueError("invalid GitHub pull_request payload")
    shas: list[str] = []
    for field in ("head", "base"):
        side = pull.get(field)
        sha = side.get("sha") if isinstance(side, dict) else None
        if not isinstance(sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(sha):
            raise ValueError(
                f"pull_request.{field}.sha must be a lowercase 40-hex commit SHA"
            )
        shas.append(sha)
    return shas[0], shas[1]


class ResponseTooLarge(RuntimeError):
    """A bounded response exceeded the caller-provided byte limit.

    Subclasses :class:`RuntimeError` so callers that guard GitHub failures
    with ``except RuntimeError`` keep working unchanged.
    """


class GitHubHTTPError(RuntimeError):
    """Preserve status for read-after-write reconciliation without blind retries."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status


class GitHubClient:
    def __init__(self, token: str, timeout: int = 30, max_attempts: int = 4):
        self.token = token
        self.timeout = timeout
        self.max_attempts = max_attempts

    def _headers(self, accept: str = "application/vnd.github+json") -> Dict[str, str]:
        headers = {"Accept": accept, "User-Agent": "LIMA/0.1", "X-GitHub-Api-Version": "2022-11-28"}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        return headers

    def fetch_diff(self, url: str) -> str:
        body = self._request(
            "GET", url, accept="application/vnd.github.v3.diff", raw=True
        )
        return body.decode("utf-8", errors="replace")

    def fetch_diff_at_commits(
        self, repository: str, base_sha: str, head_sha: str, *, max_bytes: int,
    ) -> str:
        """Fetch a bounded raw diff between two immutable commits.

        The compare endpoint is addressed exclusively with full commit SHAs,
        allowing GitHub to resolve commits from a same-network fork without
        accepting mutable branch names.  Any inaccessible commit or compare
        failure propagates from :meth:`_request`; callers must not fall back
        to a webhook-supplied diff URL.
        """
        if not isinstance(repository, str) or not _REPOSITORY_PATTERN.fullmatch(repository):
            raise ValueError("repository must be a safe GitHub owner/name")
        for name, sha in (("base_sha", base_sha), ("head_sha", head_sha)):
            if not isinstance(sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(sha):
                raise ValueError(f"{name} must be a lowercase 40-hex commit SHA")
        body = self._request(
            "GET",
            f"https://api.github.com/repos/{repository}/compare/{base_sha}...{head_sha}",
            accept="application/vnd.github.v3.diff",
            raw=True,
            max_bytes=max_bytes,
        )
        return body.decode("utf-8", errors="replace")

    def post_comment(self, api_url: str, markdown: str) -> None:
        url = api_url.rstrip("/") + "/comments"
        request = urllib.request.Request(
            url,
            data=json.dumps({"body": markdown}).encode("utf-8"),
            headers=dict(self._headers(), **{"Content-Type": "application/json"}),
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout):
            return None

    def upsert_comment(self, api_url: str, markdown: str, marker: str) -> None:
        """Update this service's existing review comment instead of creating duplicates."""
        comments_url = api_url.rstrip("/") + "/comments"
        comments = self._json("GET", comments_url + "?per_page=100")
        body = marker + "\n" + markdown
        for comment in comments:
            if marker in str(comment.get("body", "")):
                self._json("PATCH", comment["url"], {"body": body})
                return
        self._json("POST", comments_url, {"body": body})

    def _json(self, method: str, url: str, payload=None, *, max_bytes: int | None = None):
        return self._request(method, url, payload, max_bytes=max_bytes)

    def _request(
        self, method: str, url: str, payload=None,
        accept: str = "application/vnd.github+json", raw: bool = False,
        max_bytes: int | None = None,
    ):
        if max_bytes is not None and (
            isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0
        ):
            raise ValueError(f"max_bytes must be a positive integer, got {max_bytes!r}")
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        for attempt in range(1, self.max_attempts + 1):
            request = urllib.request.Request(
                url, data=data,
                headers=dict(self._headers(accept), **{"Content-Type": "application/json"}),
                method=method,
            )
            try:
                with urllib.request.urlopen(request, timeout=self.timeout) as response:
                    if max_bytes is None:
                        body = response.read()
                    else:
                        # Read one byte past the bound so an oversized body is
                        # detected before any decoding happens.
                        body = response.read(max_bytes + 1)
                        if len(body) > max_bytes:
                            raise ResponseTooLarge(
                                f"GitHub API {method} {url} exceeded the "
                                f"{max_bytes} byte response limit"
                            )
                    if raw:
                        return body
                    if max_bytes is None:
                        return json.loads(body.decode("utf-8")) if body else {}
                    try:
                        return json.loads(body.decode("utf-8")) if body else {}
                    except ValueError as exc:
                        raise RuntimeError(
                            f"GitHub API {method} {url} returned malformed "
                            f"or truncated JSON"
                        ) from exc
            except urllib.error.HTTPError as exc:
                retryable = exc.code in {429, 500, 502, 503, 504}
                if exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0":
                    retryable = True
                if method not in {"GET", "HEAD"}:
                    retryable = False
                if not retryable or attempt >= self.max_attempts:
                    detail = exc.read(1000).decode("utf-8", errors="replace")
                    raise GitHubHTTPError(exc.code,
                        "GitHub API %s %s returned HTTP %d: %s"
                        % (method, url, exc.code, detail)
                    ) from exc
                retry_after = exc.headers.get("Retry-After")
                reset = exc.headers.get("X-RateLimit-Reset")
                if retry_after:
                    delay = float(retry_after)
                elif reset:
                    delay = max(0.0, float(reset) - time.time())
                else:
                    delay = min(2 ** (attempt - 1) + random.random(), 10)
                time.sleep(min(delay, 30))
            except (urllib.error.URLError, TimeoutError) as exc:
                if method not in {"GET", "HEAD"} or attempt >= self.max_attempts:
                    raise RuntimeError("GitHub API request failed: %s" % exc) from exc
                time.sleep(min(2 ** (attempt - 1) + random.random(), 10))

    def get_pull_request(self, repository: str, number: int) -> dict:
        return self._json("GET", "https://api.github.com/repos/%s/pulls/%d" % (repository, number))

    def get_file(self, repository: str, path: str, ref: str) -> dict:
        quoted = urllib.parse.quote(path, safe="/")
        url = "https://api.github.com/repos/%s/contents/%s?ref=%s" % (
            repository, quoted, urllib.parse.quote(ref, safe="")
        )
        result = self._json("GET", url, max_bytes=_CONTENTS_RESPONSE_MAX_BYTES)
        try:
            # Contents API payloads may wrap base64 text with newlines.
            decoded = base64.b64decode(result["content"])
        except (KeyError, TypeError, ValueError) as exc:
            raise RuntimeError("GitHub Contents response has invalid file content") from exc
        if len(decoded) > _DECODED_SOURCE_MAX_BYTES:
            raise ResponseTooLarge(
                "GitHub Contents response exceeded the "
                f"{_DECODED_SOURCE_MAX_BYTES} byte decoded source limit"
            )
        result["decoded_content"] = decoded.decode("utf-8")
        return result

    def get_file_at_commit(
        self, repository: str, path: str, commit_sha: str,
        max_response_bytes: int | None = None,
    ) -> dict:
        """Read one Contents-API entry pinned to an exact 40-character SHA.

        The ``ref`` query parameter always carries the full lowercase SHA, so
        the response can never drift to a moved branch. ``max_response_bytes``
        bounds the response read before decoding; when the body exceeds the
        bound, :class:`ResponseTooLarge` is raised instead of returning a
        truncated payload. Credentials are never logged or embedded in
        error messages.
        """
        if not isinstance(commit_sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(commit_sha):
            raise ValueError(
                f"commit_sha must be a lowercase 40-hex commit SHA, got {commit_sha!r}"
            )
        quoted = urllib.parse.quote(path, safe="/")
        return self._request(
            "GET",
            f"https://api.github.com/repos/{repository}/contents/{quoted}"
            f"?ref={urllib.parse.quote(commit_sha, safe='')}",
            max_bytes=max_response_bytes,
        )

    def get_repository(self, repository: str) -> dict:
        return self._json("GET", "https://api.github.com/repos/%s" % repository)

    def ensure_repository_access(self, repository: str) -> None:
        result = self.get_repository(repository)
        if str(result.get("full_name", "")).lower() != repository.lower():
            raise PermissionError("GitHub installation is not authorized for this repository")

    def create_branch(self, repository: str, branch: str, sha: str) -> None:
        self._json("POST", "https://api.github.com/repos/%s/git/refs" % repository,
                   {"ref": "refs/heads/" + branch, "sha": sha})

    def commit_file(self, repository: str, path: str, branch: str, content: str, sha: str, message: str) -> dict:
        quoted = urllib.parse.quote(path, safe="/")
        return self._json("PUT", "https://api.github.com/repos/%s/contents/%s" % (repository, quoted), {
            "message": message, "content": base64.b64encode(content.encode("utf-8")).decode("ascii"),
            "sha": sha, "branch": branch,
        })

    @staticmethod
    def _validate_repair_path(path: object) -> tuple[str, ...]:
        """Return safe Git tree components for one existing-file update."""
        if not isinstance(path, str) or not path or "\x00" in path or "\\" in path:
            raise ValueError("repair path must be a non-empty relative Git path")
        parts = tuple(path.split("/"))
        if any(part in {"", ".", ".."} for part in parts):
            raise ValueError("repair path must not contain empty, dot, or parent components")
        return parts

    @staticmethod
    def _tree_sha(value: object, description: str) -> str:
        if not isinstance(value, str) or not _COMMIT_SHA_PATTERN.fullmatch(value):
            raise ValueError(f"{description} must be a lowercase 40-hex Git object SHA")
        return value

    def _tree_entries(
        self, repository: str, tree_sha: str, cache: dict[str, list[dict]],
    ) -> list[dict]:
        """Read one non-recursive tree, rejecting incomplete metadata."""
        if tree_sha in cache:
            return cache[tree_sha]
        result = self._json(
            "GET", f"https://api.github.com/repos/{repository}/git/trees/{tree_sha}",
            max_bytes=_GIT_METADATA_MAX_BYTES,
        )
        if not isinstance(result, dict) or result.get("truncated") is not False:
            raise ValueError("parent Git tree metadata is truncated or unusable")
        entries = result.get("tree")
        if not isinstance(entries, list) or not all(isinstance(entry, dict) for entry in entries):
            raise ValueError("parent Git tree entries are unusable")
        cache[tree_sha] = entries
        return entries

    @staticmethod
    def _tree_entry(entries: list[dict], name: str) -> dict:
        matches = [entry for entry in entries if entry.get("path") == name]
        if len(matches) != 1:
            raise ValueError("modified path is missing or ambiguous in the parent Git tree")
        return matches[0]

    def _parent_file_mode(
        self, repository: str, root_tree_sha: str, path: str,
        tree_cache: dict[str, list[dict]],
    ) -> str:
        """Resolve a file's mode from the immutable parent tree only."""
        tree_sha = root_tree_sha
        parts = self._validate_repair_path(path)
        for component in parts[:-1]:
            entries = self._tree_entries(repository, tree_sha, tree_cache)
            entry = self._tree_entry(entries, component)
            if entry.get("type") != "tree" or entry.get("mode") != "040000":
                raise ValueError("modified path does not traverse a regular parent directory")
            tree_sha = self._tree_sha(entry.get("sha"), "parent directory tree SHA")

        entry = self._tree_entry(self._tree_entries(repository, tree_sha, tree_cache), parts[-1])
        if entry.get("type") != "blob" or entry.get("mode") not in _REGULAR_FILE_MODES:
            raise ValueError("modified path is not a regular file in the parent Git tree")
        self._tree_sha(entry.get("sha"), "parent file blob SHA")
        return entry["mode"]

    def create_atomic_commit(
        self, repository: str, branch: str, parent_sha: str,
        files: Dict[str, str], message: str,
    ) -> dict:
        if not isinstance(repository, str) or not _REPOSITORY_PATTERN.fullmatch(repository):
            raise ValueError("repository must be a safe GitHub owner/name")
        if not isinstance(parent_sha, str) or not _COMMIT_SHA_PATTERN.fullmatch(parent_sha):
            raise ValueError("parent_sha must be a lowercase 40-hex commit SHA")
        if not isinstance(branch, str) or not branch or "\x00" in branch:
            raise ValueError("branch must be a non-empty Git branch name")
        if not isinstance(files, dict) or not files:
            raise ValueError("files must be a non-empty mapping of existing paths to content")
        if not isinstance(message, str) or not message:
            raise ValueError("message must be a non-empty string")
        if any(
            not isinstance(path, str) or not isinstance(content, str)
            for path, content in files.items()
        ):
            raise ValueError("repair file paths and contents must be strings")
        for path in files:
            self._validate_repair_path(path)

        parent = self._json(
            "GET", "https://api.github.com/repos/%s/git/commits/%s"
            % (repository, parent_sha),
            max_bytes=_GIT_METADATA_MAX_BYTES,
        )
        if not isinstance(parent, dict) or not isinstance(parent.get("tree"), dict):
            raise ValueError("parent commit metadata is unusable")
        root_tree_sha = self._tree_sha(parent["tree"].get("sha"), "parent root tree SHA")

        # Resolve every mode before the first POST.  Each directory is fetched
        # separately so GitHub's recursive-tree truncation cannot hide a path.
        tree_cache: dict[str, list[dict]] = {}
        modes = {
            path: self._parent_file_mode(repository, root_tree_sha, path, tree_cache)
            for path in sorted(files)
        }
        tree = self._json(
            "POST", "https://api.github.com/repos/%s/git/trees" % repository,
            {
                "base_tree": root_tree_sha,
                "tree": [
                    {"path": path, "mode": modes[path], "type": "blob", "content": content}
                    for path, content in sorted(files.items())
                ],
            },
        )
        commit = self._json(
            "POST", "https://api.github.com/repos/%s/git/commits" % repository,
            {"message": message, "tree": tree["sha"], "parents": [parent_sha]},
        )
        self.create_branch(repository, branch, commit["sha"])
        return commit

    def create_draft_pull_request(
        self, repository: str, title: str, head: str, base: str, body: str,
    ) -> dict:
        return self._json(
            "POST", "https://api.github.com/repos/%s/pulls" % repository,
            {"title": title, "head": head, "base": base, "body": body, "draft": True},
        )

    def _repair_ref(self, repository: str, branch: str) -> str | None:
        try:
            value = self._json(
                "GET",
                f"https://api.github.com/repos/{repository}/git/ref/heads/"
                + urllib.parse.quote(branch, safe="/"),
                max_bytes=_GIT_METADATA_MAX_BYTES,
            )
        except GitHubHTTPError as exc:
            if exc.status == 404:
                return None
            raise
        obj = value.get("object") or {}
        if obj.get("type") != "commit":
            raise ValueError("repair branch is not a commit reference")
        return self._tree_sha(obj.get("sha"), "repair commit SHA")

    def _verify_repair_commit(self, repository, sha, parent_sha, files, message):
        root = f"https://api.github.com/repos/{repository}"
        commit = self._json("GET", f"{root}/git/commits/{sha}", max_bytes=_GIT_METADATA_MAX_BYTES)
        parents = commit.get("parents") or []
        if (
            len(parents) != 1
            or parents[0].get("sha") != parent_sha
            or str(commit.get("message", "")).rstrip("\n") != message.rstrip("\n")
        ):
            raise ValueError("repair branch provenance does not match its publication intent")
        parent = self._json(
            "GET", f"{root}/git/commits/{parent_sha}", max_bytes=_GIT_METADATA_MAX_BYTES
        )
        old_tree = self._tree_sha(parent["tree"]["sha"], "parent tree SHA")
        new_tree = self._tree_sha(commit["tree"]["sha"], "repair tree SHA")
        cache = {}
        for path in files:
            self._validate_repair_path(path)
        self._verify_repair_tree(repository, old_tree, new_tree, files, cache)

    def _verify_repair_tree(self, repository, old_sha, new_sha, files, cache):
        # Compare immutable tree edges, not a size-limited textual compare diff.
        # Unchanged subtrees must have identical hashes; changed subtrees recurse.
        def indexed(sha):
            entries = self._tree_entries(repository, sha, cache)
            result = {}
            for entry in entries:
                path = entry.get("path")
                if not isinstance(path, str) or "/" in path or path in result:
                    raise ValueError("repair tree has invalid or ambiguous entries")
                result[path] = entry
            return result

        old, new = indexed(old_sha), indexed(new_sha)
        if old.keys() != new.keys():
            raise ValueError("repair branch has unplanned additions or deletions")
        grouped = {}
        for path, content in files.items():
            name, _, rest = path.partition("/")
            grouped.setdefault(name, {})[rest] = content
        for name, original in old.items():
            candidate = new[name]
            updates = grouped.get(name)
            if updates is None:
                if any(original.get(key) != candidate.get(key) for key in ("mode", "type", "sha")):
                    raise ValueError("repair branch changed an unplanned path")
            elif "" in updates:
                if (
                    len(updates) != 1
                    or original.get("type") != "blob"
                    or original.get("mode") not in _REGULAR_FILE_MODES
                    or candidate.get("mode") != original["mode"]
                    or candidate.get("type") != "blob"
                ):
                    raise ValueError(
                        "repair branch file mode does not match its publication intent"
                    )
                content = updates[""].encode("utf-8")
                expected = hashlib.sha1(
                    b"blob " + str(len(content)).encode() + b"\0" + content, usedforsecurity=False
                ).hexdigest()
                if candidate.get("sha") != expected:
                    raise ValueError("repair branch content does not match its publication intent")
            else:
                if any(
                    row.get("type") != "tree" or row.get("mode") != "040000"
                    for row in (original, candidate)
                ):
                    raise ValueError(
                        "repair branch directory does not match its publication intent"
                    )
                self._verify_repair_tree(
                    repository,
                    self._tree_sha(original.get("sha"), "parent subtree"),
                    self._tree_sha(candidate.get("sha"), "repair subtree"),
                    updates,
                    cache,
                )
        if not set(grouped) <= set(old):
            raise ValueError("repair paths are missing from the parent tree")

    def ensure_repair_commit(
        self, repository, branch, parent_sha, files, message, *, allow_create=True
    ):
        sha = self._repair_ref(repository, branch)
        if sha is None:
            if not allow_create:
                raise ValueError("recorded repair branch is missing")
            try:
                self.create_atomic_commit(repository, branch, parent_sha, files, message)
            except Exception:
                # Unknown write outcome: only a verified existing ref may recover it.
                if self._repair_ref(repository, branch) is None:
                    raise
            sha = self._repair_ref(repository, branch)
            if sha is None:
                raise ValueError("repair branch outcome is unknown")
        self._verify_repair_commit(repository, sha, parent_sha, files, message)
        return {"sha": sha}

    def ensure_repair_pull(
        self, repository, title, branch, base, body, commit_sha, operation_id, *, allow_create=True
    ):
        marker = f"<!-- lima-repair:{operation_id} -->"

        def existing():
            query = urllib.parse.urlencode(
                {"state": "all", "head": repository.split("/")[0] + ":" + branch, "per_page": 100}
            )
            rows = self._json(
                "GET",
                f"https://api.github.com/repos/{repository}/pulls?{query}",
                max_bytes=_GIT_METADATA_MAX_BYTES,
            )
            if not isinstance(rows, list) or len(rows) > 1:
                raise ValueError("repair PR outcome is ambiguous")
            if not rows:
                return None
            row = rows[0]
            if (
                row.get("head", {}).get("ref") != branch
                or row.get("head", {}).get("sha") != commit_sha
                or row.get("head", {}).get("repo", {}).get("full_name") != repository
                or row.get("base", {}).get("ref") != base
                or marker not in str(row.get("body", ""))
            ):
                raise ValueError("repair PR does not match its publication intent")
            if (
                not isinstance(row.get("number"), int)
                or row["number"] < 1
                or row.get("html_url") != f"https://github.com/{repository}/pull/{row['number']}"
            ):
                raise ValueError("repair PR identity is invalid")
            return row

        result = existing()
        if result is None:
            if not allow_create:
                raise ValueError("recorded repair PR is missing")
            try:
                self.create_draft_pull_request(
                    repository, title, branch, base, marker + "\n" + body
                )
            except Exception:
                result = existing()
                if result is None:
                    raise
            result = existing()
            if result is None:
                raise ValueError("repair PR outcome is unknown")
        return result

    @staticmethod
    def _validate_response_limit(max_bytes: int) -> None:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes <= 0:
            raise ValueError(f"max_bytes must be a positive integer, got {max_bytes!r}")

    @staticmethod
    def _archive_url(repository: str, ref: str) -> str:
        return "https://api.github.com/repos/%s/zipball/%s" % (
            repository, urllib.parse.quote(ref, safe="")
        )

    @contextmanager
    def download_archive_file(
        self, repository: str, ref: str, *, max_bytes: int = _ARCHIVE_MAX_BYTES,
    ):
        """Yield a temporary archive file while enforcing an actual byte cap.

        Archive responses are read in fixed-size chunks instead of materializing
        their full body.  The Content-Length header is only an early rejection
        hint; the running byte count is authoritative, including when the header
        is absent, invalid, or false.  The temporary file is removed on every
        failure and when the caller leaves the context.
        """
        self._validate_response_limit(max_bytes)
        url = self._archive_url(repository, ref)
        archive_path: Path | None = None
        for attempt in range(1, self.max_attempts + 1):
            complete = False
            try:
                with urllib.request.urlopen(
                    urllib.request.Request(
                        url, headers=self._headers("application/vnd.github+json"), method="GET"
                    ), timeout=self.timeout,
                ) as response:
                    content_length = response.headers.get("Content-Length")
                    try:
                        declared_length = int(content_length) if content_length is not None else None
                    except (TypeError, ValueError):
                        declared_length = None
                    if declared_length is not None and declared_length > max_bytes:
                        raise ResponseTooLarge(
                            f"GitHub archive exceeded the {max_bytes} byte archive limit"
                        )

                    handle = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
                    archive_path = Path(handle.name)
                    try:
                        total = 0
                        with handle:
                            while chunk := response.read(min(
                                _ARCHIVE_READ_CHUNK_BYTES, max_bytes - total + 1,
                            )):
                                total += len(chunk)
                                if total > max_bytes:
                                    raise ResponseTooLarge(
                                        f"GitHub archive exceeded the {max_bytes} byte archive limit"
                                    )
                                handle.write(chunk)
                    except BaseException:
                        try:
                            os.unlink(archive_path)
                        except FileNotFoundError:
                            pass
                        archive_path = None
                        raise
                complete = True
                break
            except urllib.error.HTTPError as exc:
                retryable = exc.code in {429, 500, 502, 503, 504}
                if exc.code == 403 and exc.headers.get("X-RateLimit-Remaining") == "0":
                    retryable = True
                if not retryable or attempt >= self.max_attempts:
                    detail = exc.read(1000).decode("utf-8", errors="replace")
                    raise RuntimeError(
                        "GitHub API %s %s returned HTTP %d: %s" % ("GET", url, exc.code, detail)
                    ) from exc
                time.sleep(min(2 ** (attempt - 1) + random.random(), 10))
            except (urllib.error.URLError, TimeoutError) as exc:
                if attempt >= self.max_attempts:
                    raise RuntimeError("GitHub API request failed: %s" % exc) from exc
                time.sleep(min(2 ** (attempt - 1) + random.random(), 10))
            finally:
                if not complete and archive_path is not None:
                    try:
                        os.unlink(archive_path)
                    except FileNotFoundError:
                        pass
                    archive_path = None

        if archive_path is None:
            raise RuntimeError("GitHub archive download did not produce a temporary file")
        try:
            yield archive_path
        finally:
            try:
                os.unlink(archive_path)
            except FileNotFoundError:
                pass

    def download_archive(self, repository: str, ref: str) -> bytes:
        return self._request(
            "GET", self._archive_url(repository, ref),
            accept="application/vnd.github+json", raw=True,
            max_bytes=_ARCHIVE_MAX_BYTES,
        )


class GitHubAppAuthenticator:
    _cache = {}
    _lock = threading.Lock()
    def __init__(self, app_id: str, private_key_path: str):
        self.app_id = app_id
        self.private_key_path = private_key_path

    def app_jwt(self) -> str:
        try:
            import jwt
        except ImportError as exc:
            raise RuntimeError("GitHub App mode requires: pip install PyJWT[crypto]") from exc
        with open(self.private_key_path, "rb") as handle:
            key = handle.read()
        now = int(time.time())
        return jwt.encode({"iat": now - 60, "exp": now + 540, "iss": self.app_id}, key, algorithm="RS256")

    def installation_token(self, installation_id: int) -> str:
        cache_key = (self.app_id, int(installation_id))
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached and cached["expires_at"] > time.time() + 120:
                return cached["token"]
        request = urllib.request.Request(
            "https://api.github.com/app/installations/%d/access_tokens" % installation_id,
            data=b"{}", method="POST",
            headers={"Authorization": "Bearer " + self.app_jwt(), "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "LIMA/0.3",
                     "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            result = json.loads(response.read().decode("utf-8"))
        expires = result.get("expires_at", "")
        try:
            expires_at = datetime.fromisoformat(expires.replace("Z", "+00:00")).timestamp()
        except ValueError:
            expires_at = time.time() + 3000
        with self._lock:
            self._cache[cache_key] = {"token": result["token"], "expires_at": expires_at}
        return result["token"]
