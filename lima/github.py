import hashlib
import hmac
import json
import urllib.error
import urllib.request
import urllib.parse
import base64
import random
import re
import threading
import time
from datetime import datetime
from typing import Dict

_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")


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

    def _json(self, method: str, url: str, payload=None):
        return self._request(method, url, payload)

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
                if not retryable or attempt >= self.max_attempts:
                    detail = exc.read(1000).decode("utf-8", errors="replace")
                    raise RuntimeError(
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
                if attempt >= self.max_attempts:
                    raise RuntimeError("GitHub API request failed: %s" % exc) from exc
                time.sleep(min(2 ** (attempt - 1) + random.random(), 10))

    def get_pull_request(self, repository: str, number: int) -> dict:
        return self._json("GET", "https://api.github.com/repos/%s/pulls/%d" % (repository, number))

    def get_file(self, repository: str, path: str, ref: str) -> dict:
        quoted = urllib.parse.quote(path, safe="/")
        result = self._json("GET", "https://api.github.com/repos/%s/contents/%s?ref=%s" % (
            repository, quoted, urllib.parse.quote(ref, safe="")
        ))
        result["decoded_content"] = base64.b64decode(result["content"]).decode("utf-8")
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

    def create_atomic_commit(
        self, repository: str, branch: str, parent_sha: str,
        files: Dict[str, str], message: str,
    ) -> dict:
        parent = self._json(
            "GET", "https://api.github.com/repos/%s/git/commits/%s"
            % (repository, parent_sha)
        )
        tree = self._json(
            "POST", "https://api.github.com/repos/%s/git/trees" % repository,
            {
                "base_tree": parent["tree"]["sha"],
                "tree": [
                    {"path": path, "mode": "100644", "type": "blob", "content": content}
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

    def download_archive(self, repository: str, ref: str) -> bytes:
        return self._request(
            "GET", "https://api.github.com/repos/%s/zipball/%s"
            % (repository, urllib.parse.quote(ref, safe="")),
            accept="application/vnd.github+json", raw=True,
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
