"""Canonical, side-effect-free repository source descriptions.

This module deliberately stops at validation and normalization.  Turning a source into
files belongs to the repository materialization layer; source parsing must never perform
network access or resolve host filesystem paths.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .repository_import import RepositoryImportPolicy

GITHUB_SOURCE_TYPE = "github"
LOCAL_IMPORT_SOURCE_TYPE = "local-import"

_GITHUB_HOST = "github.com"
_GITHUB_OWNER_PATTERN = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?\Z"
)
_GITHUB_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,100}\Z")
_SERIALIZED_FIELDS = frozenset(
    {
        "type",
        "provider",
        "canonical_name",
        "requested_ref",
        "repository_key",
        # Task-input aliases.  They are normalized away during serialization.
        "url",
        "ref",
    }
)


def _required_string(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} is required")
    return normalized


def _optional_string(value: object, field_name: str) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{field_name} must not contain control characters")
    return value.strip()


def _normalize_requested_ref(value: object) -> str:
    requested_ref = _optional_string(value, "requested_ref")
    if len(requested_ref) > 240:
        raise ValueError("requested_ref must be at most 240 characters")
    if not requested_ref:
        return ""
    if (
        requested_ref == "@"
        or requested_ref.startswith("/")
        or requested_ref.endswith(("/", "."))
        or "//" in requested_ref
        or ".." in requested_ref
        or "@{" in requested_ref
        or any(character in " ~^:?*[\\" for character in requested_ref)
    ):
        raise ValueError("requested_ref has an invalid Git ref shape")
    if any(
        component.startswith(".") or component.lower().endswith(".lock")
        for component in requested_ref.split("/")
    ):
        raise ValueError("requested_ref has an invalid Git ref component")
    return requested_ref


def _github_path_from_url(parsed: SplitResult) -> str:
    if parsed.scheme.lower() != "https":
        raise ValueError("GitHub repository URLs must use https")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("GitHub repository URL contains an invalid port") from exc
    if (
        parsed.hostname is None
        or parsed.hostname.lower() != _GITHUB_HOST
        or parsed.username is not None
        or parsed.password is not None
        or port is not None
    ):
        raise ValueError("GitHub repository URLs must use the github.com host")
    if parsed.query or parsed.fragment:
        raise ValueError("GitHub repository URLs must not contain a query or fragment")
    if not parsed.path.startswith("/"):
        raise ValueError("GitHub repository URL contains an invalid path")

    path = parsed.path[:-1] if parsed.path.endswith("/") else parsed.path
    return path[1:]


def normalize_github_repository(value: str) -> str:
    """Return a lower-case ``owner/repository`` identity for a GitHub source.

    ``value`` may be either the canonical identity or an HTTPS github.com URL.  No other
    transport or host is accepted.  A conventional trailing ``.git`` suffix is removed.
    """

    candidate = _required_string(value, "GitHub repository")
    if len(candidate) > 2048:
        raise ValueError("GitHub repository input is too long")

    parsed = urlsplit(candidate)
    if parsed.scheme or parsed.netloc:
        path = _github_path_from_url(parsed)
    else:
        if candidate.startswith("/") or candidate.endswith("/"):
            raise ValueError("GitHub repository name must use owner/repository")
        path = candidate

    parts = path.split("/")
    if len(parts) != 2 or not all(parts):
        raise ValueError("GitHub repository name must use owner/repository")
    owner, repository = parts
    if repository.lower().endswith(".git"):
        repository = repository[:-4]
    if "--" in owner or not _GITHUB_OWNER_PATTERN.fullmatch(owner):
        raise ValueError("GitHub repository owner has an invalid shape")
    if (
        repository in {"", ".", ".."}
        or not _GITHUB_REPOSITORY_PATTERN.fullmatch(repository)
    ):
        raise ValueError("GitHub repository name has an invalid shape")
    return f"{owner.lower()}/{repository.lower()}"


def normalize_local_repository_key(repository_key: str) -> str:
    """Normalize a bounded logical key without resolving it on the filesystem."""

    return RepositoryImportPolicy.normalize_key(
        _required_string(repository_key, "repository_key")
    )


@dataclass(frozen=True)
class RepositorySource:
    """A normalized description of where repository contents originate."""

    type: str
    provider: str = ""
    canonical_name: str = ""
    requested_ref: str = ""
    repository_key: str = ""

    def __post_init__(self) -> None:
        source_type = _required_string(self.type, "repository source type").lower()
        provider = _optional_string(self.provider, "provider").lower()
        requested_ref = _normalize_requested_ref(self.requested_ref)

        if source_type == GITHUB_SOURCE_TYPE:
            if provider not in {"", "github"}:
                raise ValueError("GitHub repository sources must use the github provider")
            if _optional_string(self.repository_key, "repository_key"):
                raise ValueError("GitHub repository sources must not contain repository_key")
            canonical_name = normalize_github_repository(self.canonical_name)
            provider = "github"
            repository_key = ""
        elif source_type == LOCAL_IMPORT_SOURCE_TYPE:
            if provider not in {"", "local"}:
                raise ValueError("local-import repository sources must use the local provider")
            if _optional_string(self.canonical_name, "canonical_name"):
                raise ValueError("local-import sources must not contain canonical_name")
            if requested_ref:
                raise ValueError("local-import sources must not contain requested_ref")
            canonical_name = ""
            provider = "local"
            repository_key = normalize_local_repository_key(self.repository_key)
        else:
            raise ValueError(f"unsupported repository source type: {source_type}")

        object.__setattr__(self, "type", source_type)
        object.__setattr__(self, "provider", provider)
        object.__setattr__(self, "canonical_name", canonical_name)
        object.__setattr__(self, "requested_ref", requested_ref)
        object.__setattr__(self, "repository_key", repository_key)

    @classmethod
    def github(cls, repository: str, requested_ref: str = "") -> RepositorySource:
        """Build a GitHub source from an HTTPS URL or canonical repository name."""

        return cls(
            type=GITHUB_SOURCE_TYPE,
            provider="github",
            canonical_name=normalize_github_repository(repository),
            requested_ref=requested_ref,
        )

    @classmethod
    def local_import(cls, repository_key: str) -> RepositorySource:
        """Build a source for an administrator-provisioned local repository import."""

        return cls(
            type=LOCAL_IMPORT_SOURCE_TYPE,
            provider="local",
            repository_key=normalize_local_repository_key(repository_key),
        )

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> RepositorySource:
        """Parse either task-input aliases or the canonical serialized representation."""

        if not isinstance(value, Mapping):
            raise ValueError("repository source must be an object")
        unsupported_fields = set(value) - _SERIALIZED_FIELDS
        if unsupported_fields:
            names = ", ".join(sorted(str(item) for item in unsupported_fields))
            raise ValueError(f"repository source contains unsupported fields: {names}")

        source_type = _required_string(value.get("type"), "repository source type").lower()
        provider = _optional_string(value.get("provider"), "provider").lower()

        if source_type == GITHUB_SOURCE_TYPE:
            url = _optional_string(value.get("url"), "url")
            canonical_name = _optional_string(
                value.get("canonical_name"), "canonical_name"
            )
            if not url and not canonical_name:
                raise ValueError("GitHub repository source requires url or canonical_name")
            if url and canonical_name:
                if normalize_github_repository(url) != normalize_github_repository(
                    canonical_name
                ):
                    raise ValueError(
                        "GitHub url and canonical_name identify different repositories"
                    )
            if provider not in {"", "github"}:
                raise ValueError("GitHub repository sources must use the github provider")
            repository_key = _optional_string(
                value.get("repository_key"), "repository_key"
            )
            if repository_key:
                raise ValueError("GitHub repository sources must not contain repository_key")

            ref = _optional_string(value.get("ref"), "ref")
            requested_ref = _optional_string(
                value.get("requested_ref"), "requested_ref"
            )
            if ref and requested_ref and ref != requested_ref:
                raise ValueError("ref and requested_ref must match when both are provided")
            return cls.github(url or canonical_name, ref or requested_ref)

        if source_type == LOCAL_IMPORT_SOURCE_TYPE:
            if provider not in {"", "local"}:
                raise ValueError("local-import repository sources must use the local provider")
            if _optional_string(value.get("url"), "url"):
                raise ValueError("local-import sources must not contain url")
            if _optional_string(value.get("canonical_name"), "canonical_name"):
                raise ValueError("local-import sources must not contain canonical_name")
            if _optional_string(value.get("ref"), "ref") or _optional_string(
                value.get("requested_ref"), "requested_ref"
            ):
                raise ValueError("local-import sources must not contain a ref")
            return cls.local_import(
                _required_string(value.get("repository_key"), "repository_key")
            )

        raise ValueError(f"unsupported repository source type: {source_type}")

    def to_dict(self) -> dict[str, str]:
        """Serialize the canonical, credential-free source contract for task input."""

        return {
            "type": self.type,
            "provider": self.provider,
            "canonical_name": self.canonical_name,
            "requested_ref": self.requested_ref,
            "repository_key": self.repository_key,
        }


def parse_repository_source(
    value: RepositorySource | Mapping[str, Any],
) -> RepositorySource:
    """Return a normalized source from an existing source or task-input mapping."""

    if isinstance(value, RepositorySource):
        return value
    return RepositorySource.from_dict(value)


__all__ = [
    "GITHUB_SOURCE_TYPE",
    "LOCAL_IMPORT_SOURCE_TYPE",
    "RepositorySource",
    "normalize_github_repository",
    "normalize_local_repository_key",
    "parse_repository_source",
]
