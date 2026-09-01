"""Deterministic canonical JSON codec for the LIMA artifact contract (v4.0 subset).

The codec accepts only a portable JSON subset: ``null``/``bool``/``int``/``str``
values, ``list``/``dict`` containers with string keys, signed 64-bit integers,
and no floats of any kind. Decode normalizes every string and key to Unicode
NFC; encode emits sorted-key, compact, UTF-8 JSON without BOM or trailing
newline so that identical semantics always produce identical bytes and
SHA-256 digests.
"""

import hashlib
import json
import unicodedata
from dataclasses import dataclass
from typing import Final, TypeAlias

from lima.contracts.errors import ContractError, ContractErrorCode

__all__ = [
    "DEFAULT_LIMITS",
    "JSONValue",
    "ContractLimits",
    "canonical_decode",
    "canonical_encode",
    "compute_content_digest",
]

_INT64_MIN = -9223372036854775808
_INT64_MAX = 9223372036854775807
_MAX_INT64_TEXT_LENGTH = 20  # len("-9223372036854775808")

JSONValue: TypeAlias = None | bool | int | str | list["JSONValue"] | dict[str, "JSONValue"]


@dataclass(frozen=True, slots=True)
class ContractLimits:
    """Resource ceilings enforced by the codec; all values must be positive ints."""

    max_input_bytes: int = 1_048_576
    max_depth: int = 32
    max_array_items: int = 10_000
    max_object_fields: int = 1_000
    max_string_bytes: int = 262_144

    def __post_init__(self) -> None:
        for name in (
            "max_input_bytes",
            "max_depth",
            "max_array_items",
            "max_object_fields",
            "max_string_bytes",
        ):
            value = getattr(self, name)
            # Exact type check: bool is an int subclass and must still be rejected.
            if type(value) is not int or value <= 0:
                raise ContractError(ContractErrorCode.INVALID_LIMIT, name)


DEFAULT_LIMITS: Final[ContractLimits] = ContractLimits()


def _ensure_limits(limits: ContractLimits) -> None:
    if not isinstance(limits, ContractLimits):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE, "limits")


def _normalize_string(value: str, limits: ContractLimits) -> str:
    normalized = unicodedata.normalize("NFC", value)
    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ContractError(ContractErrorCode.INVALID_UTF8) from exc
    if len(encoded) > limits.max_string_bytes:
        raise ContractError(ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED)
    return normalized


def _walk(value: object, limits: ContractLimits, depth: int) -> JSONValue:
    """Validate one JSONValue subtree and return its NFC-normalized copy.

    ``depth`` is the container depth at which ``value`` itself sits: 1 for a
    top-level container, one more per nesting level. Top-level scalars are
    depth 0 and are never depth-checked.
    """
    if value is None or type(value) is bool:
        return value
    if type(value) is int:
        if not _INT64_MIN <= value <= _INT64_MAX:
            raise ContractError(ContractErrorCode.INTEGER_OUT_OF_RANGE)
        return value
    if type(value) is str:
        return _normalize_string(value, limits)
    if type(value) is list:
        if depth > limits.max_depth:
            raise ContractError(ContractErrorCode.MAX_DEPTH_EXCEEDED)
        if len(value) > limits.max_array_items:
            raise ContractError(ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED)
        return [_walk(item, limits, depth + 1) for item in value]
    if type(value) is dict:
        if depth > limits.max_depth:
            raise ContractError(ContractErrorCode.MAX_DEPTH_EXCEEDED)
        if len(value) > limits.max_object_fields:
            raise ContractError(ContractErrorCode.MAX_OBJECT_FIELDS_EXCEEDED)
        normalized: dict[str, JSONValue] = {}
        for key, item in value.items():
            if type(key) is not str:
                raise ContractError(ContractErrorCode.UNSUPPORTED_VALUE_TYPE)
            normalized_key = _normalize_string(key, limits)
            if normalized_key in normalized:
                raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD)
            normalized[normalized_key] = _walk(item, limits, depth + 1)
        return normalized
    raise ContractError(ContractErrorCode.UNSUPPORTED_VALUE_TYPE)


def _object_pairs_hook(pairs: list[tuple[str, object]]) -> dict[str, object]:
    seen_raw: set[str] = set()
    normalized: dict[str, object] = {}
    for key, _ in pairs:
        if key in seen_raw:
            raise ContractError(ContractErrorCode.DUPLICATE_FIELD)
        seen_raw.add(key)
    for key, value in pairs:
        normalized_key = unicodedata.normalize("NFC", key)
        if normalized_key in normalized:
            raise ContractError(ContractErrorCode.DUPLICATE_SEMANTIC_FIELD)
        normalized[normalized_key] = value
    return normalized


def _parse_int(text: str) -> int:
    if len(text) > _MAX_INT64_TEXT_LENGTH:
        raise ContractError(ContractErrorCode.INTEGER_OUT_OF_RANGE)
    value = int(text)
    if not _INT64_MIN <= value <= _INT64_MAX:
        raise ContractError(ContractErrorCode.INTEGER_OUT_OF_RANGE)
    return value


def _reject_float(text: str) -> float:
    raise ContractError(ContractErrorCode.UNSUPPORTED_VALUE_TYPE)


def canonical_decode(data: bytes, *, limits: ContractLimits = DEFAULT_LIMITS) -> JSONValue:
    """Decode raw UTF-8 JSON bytes into the validated NFC-normalized JSONValue subset."""
    _ensure_limits(limits)
    if not isinstance(data, bytes):
        raise ContractError(ContractErrorCode.INVALID_FIELD_TYPE)
    if len(data) > limits.max_input_bytes:
        raise ContractError(ContractErrorCode.RESOURCE_LIMIT_EXCEEDED)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ContractError(ContractErrorCode.INVALID_UTF8) from exc
    try:
        parsed = json.loads(
            text,
            object_pairs_hook=_object_pairs_hook,
            parse_int=_parse_int,
            parse_float=_reject_float,
            parse_constant=_reject_float,
        )
    except ContractError:
        raise
    except ValueError as exc:
        raise ContractError(ContractErrorCode.INVALID_JSON) from exc
    return _walk(parsed, limits, 1)


def canonical_encode(value: JSONValue, *, limits: ContractLimits = DEFAULT_LIMITS) -> bytes:
    """Encode a JSONValue to canonical bytes: UTF-8, NFC, sorted keys, compact."""
    _ensure_limits(limits)
    normalized = _walk(value, limits, 1)
    text = json.dumps(
        normalized,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    )
    encoded = text.encode("utf-8")
    if len(encoded) > limits.max_input_bytes:
        raise ContractError(ContractErrorCode.RESOURCE_LIMIT_EXCEEDED)
    return encoded


def compute_content_digest(
    value: JSONValue | bytes, *, limits: ContractLimits = DEFAULT_LIMITS
) -> str:
    """Return the lowercase hex SHA-256 of canonical bytes, or of raw ``bytes``."""
    _ensure_limits(limits)
    if isinstance(value, bytes):
        if len(value) > limits.max_input_bytes:
            raise ContractError(ContractErrorCode.RESOURCE_LIMIT_EXCEEDED)
        return hashlib.sha256(value).hexdigest()
    return hashlib.sha256(canonical_encode(value, limits=limits)).hexdigest()
