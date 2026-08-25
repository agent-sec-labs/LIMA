"""Resolve administrator-provisioned repository keys without exposing host paths."""

from __future__ import annotations

from pathlib import Path, PurePosixPath


class RepositoryImportPolicy:
    """Map a bounded logical key to a directory below one configured read-only root."""

    def __init__(self, root: str = "") -> None:
        self.configured_root = root.strip()

    @property
    def enabled(self) -> bool:
        return bool(self.configured_root)

    def capabilities(self) -> dict:
        available = False
        if self.enabled:
            try:
                available = Path(self.configured_root).expanduser().resolve(strict=True).is_dir()
            except OSError:
                available = False
        return {
            "enabled": self.enabled and available,
            "key_format": "relative/path",
            "host_paths_accepted": False,
            "repository_code_executed": False,
        }

    @staticmethod
    def normalize_key(repository_key: str) -> str:
        key = repository_key.strip()
        if not key or len(key) > 240:
            raise ValueError("repository_key is required and must be at most 240 characters")
        if "\\" in key:
            raise ValueError("repository_key must use forward slashes")
        path = PurePosixPath(key)
        parts = path.parts
        if path.is_absolute() or not parts or len(parts) > 16:
            raise ValueError("repository_key must be a bounded relative path")
        for part in parts:
            if part in {".", ".."} or part.startswith(".") or len(part) > 80:
                raise ValueError("repository_key contains a forbidden path segment")
            if not part[0].isalnum() or any(
                not (character.isalnum() or character in {"-", "_", "."})
                for character in part
            ):
                raise ValueError("repository_key contains unsupported characters")
        return "/".join(parts)

    def resolve(self, repository_key: str) -> Path:
        if not self.enabled:
            raise ValueError(
                "repository scanning is disabled; configure LIMA_REPOSITORY_IMPORT_ROOT"
            )
        key = self.normalize_key(repository_key)
        try:
            root = Path(self.configured_root).expanduser().resolve(strict=True)
            candidate = root.joinpath(*key.split("/")).resolve(strict=True)
        except OSError as exc:
            raise ValueError("repository_key does not reference an available repository") from exc
        if not root.is_dir() or not candidate.is_dir():
            raise ValueError("repository_key must reference a directory")
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise ValueError("repository_key escapes the configured import root") from exc
        return candidate
