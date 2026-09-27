"""Shared untrusted-JSON and bounded-field primitives.

Retirement Task 2 trim: only the parsing and field-validation helpers the
platform chain, the UAF instruments and the sidecar client share remain
here. The legacy candidate/decision/consensus dataclasses and their
vocabulary constants served the retired seven-role chain and are gone.
"""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any, Final

MAX_TEXT_BYTES: Final = 2_048
MAX_PATH_BYTES: Final = 4_096

_HEX64 = frozenset("0123456789abcdef")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def parse_untrusted_json(raw: str | bytes) -> Any:
    """Parse one JSON document rejecting duplicate keys and odd numbers."""

    if isinstance(raw, bytes):
        try:
            raw = raw.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("payload is not UTF-8") from exc
    if not isinstance(raw, str):
        raise ValueError("payload must be text")
    try:
        return json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: (_ for _ in ()).throw(ValueError(value)),
        )
    except (json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("payload is not valid JSON") from exc


def _bounded_text(value: Any, field_name: str, maximum: int = MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be non-empty text")
    if len(value.encode("utf-8")) > maximum:
        raise ValueError(f"{field_name} exceeds the byte limit")
    return value


def _safe_relative_path(value: Any, field_name: str) -> str:
    text = _bounded_text(value, field_name, MAX_PATH_BYTES)
    parsed = PurePosixPath(text)
    if (
        parsed.is_absolute()
        or "\\" in text
        or "\0" in text
        or any(part in {"", ".", ".."} for part in text.split("/"))
        or text.startswith("/")
    ):
        raise ValueError(f"{field_name} must be a safe relative POSIX path")
    return text


def _hex_digest(value: Any, field_name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in _HEX64 for character in value)
    ):
        raise ValueError(f"{field_name} must be a lowercase SHA-256 digest")
    return value


__all__ = [
    "MAX_PATH_BYTES",
    "MAX_TEXT_BYTES",
    "parse_untrusted_json",
]
