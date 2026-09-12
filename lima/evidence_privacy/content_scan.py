"""Content-form scanning helpers for bare Base64 secrets (Packet IP-0017 §7.1).

Implements the DR-IP-0015-02 refinement (Packet §8.4): a string is a "bare
Base64 secret candidate" when, after Unicode NFC normalization, it is at least
:class:`BASE64_MIN_LENGTH` code points long, uses the strict Base64 alphabet
with at most two trailing ``=`` padding characters, has a length divisible by
four, and decodes with ``base64.b64decode(..., validate=True)``. Decoded
content is never inspected further (nested encoded payloads are out of scope;
the conservative SENSITIVE level covers the residual risk).

Consumed via the module path ``lima.evidence_privacy.content_scan`` (O-1: the
package ``__all__`` stays at its frozen 13 symbols). Pure, in-memory, IO-free;
standard library plus this package only (Packet §8.8).
"""

from __future__ import annotations

import base64
import re
import unicodedata
from typing import Final

from lima.evidence_privacy.fingerprint import compute_fingerprint
from lima.evidence_privacy.models import FingerprintRecord, TenantPolicy

__all__ = [
    "BASE64_MIN_LENGTH",
    "REDACTED_SEGMENT_TEMPLATE",
    "find_base64_spans",
    "is_bare_base64_secret",
    "redact_text_segments",
]

BASE64_MIN_LENGTH: Final[int] = 32
REDACTED_SEGMENT_TEMPLATE: Final[str] = "[[REDACTED:{fingerprint}]]"

_BASE64_ALPHABET: Final[frozenset[str]] = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
)

# Maximal Base64-shaped runs: an alphabet run optionally terminated by one or
# two padding characters. Padding outside run-final position splits runs, so
# spans never straddle an interior ``=`` (Packet §8.4.1 alphabet rule).
_BASE64_RUN_PATTERN: Final[re.Pattern[str]] = re.compile(
    r"[A-Za-z0-9+/]+={1,2}|[A-Za-z0-9+/]+"
)


def _decodes(candidate: str) -> bool:
    """Return True when ``candidate`` decodes under strict validation."""
    try:
        base64.b64decode(candidate, validate=True)
    except ValueError:  # binascii.Error is a ValueError subclass
        return False
    return True


def is_bare_base64_secret(text: str) -> bool:
    """Return True when the NFC-normalized ``text`` is a bare Base64 candidate.

    Predicate (Packet §8.4.1, frozen): NFC length >= :data:`BASE64_MIN_LENGTH`,
    strict Base64 alphabet with at most two trailing ``=`` characters, length
    divisible by four, and a successful strict decode.
    """
    normalized = unicodedata.normalize("NFC", text)
    length = len(normalized)
    if length < BASE64_MIN_LENGTH or length % 4 != 0:
        return False
    stripped = normalized.rstrip("=")
    padding = length - len(stripped)
    if padding > 2 or not stripped:
        return False
    if not all(character in _BASE64_ALPHABET for character in stripped):
        return False
    return _decodes(normalized)


def find_base64_spans(text: str) -> tuple[tuple[int, int], ...]:
    """Return predicate-satisfying Base64 spans in NFC ``text`` (Packet §8.4.4).

    Spans are half-open ``(start, end)`` tuples over the NFC-normalized text,
    maximal candidates discovered left to right and non-overlapping: within
    each maximal Base64-shaped run the longest aligned candidate starting at
    the earliest position wins, and scanning resumes after it.
    """
    normalized = unicodedata.normalize("NFC", text)
    spans: list[tuple[int, int]] = []
    for run_match in _BASE64_RUN_PATTERN.finditer(normalized):
        run_text = run_match.group()
        run_start = run_match.start()
        offset = 0
        while offset <= len(run_text) - BASE64_MIN_LENGTH:
            available = len(run_text) - offset
            candidate_length = available - (available % 4)
            matched: int | None = None
            while candidate_length >= BASE64_MIN_LENGTH:
                if _decodes(run_text[offset : offset + candidate_length]):
                    matched = candidate_length
                    break
                candidate_length -= 4
            if matched is None:
                offset += 1
                continue
            spans.append((run_start + offset, run_start + offset + matched))
            offset += matched
    return tuple(spans)


def redact_text_segments(
    value: str,
    policy: TenantPolicy,
    *,
    tenant_id: str,
    tenant_key: bytes,
) -> tuple[str, tuple[FingerprintRecord, ...]]:
    """Replace candidate Base64 spans in ``value`` with fingerprint placeholders.

    Returns the NFC-normalized text with each satisfying span replaced by
    :data:`REDACTED_SEGMENT_TEMPLATE` and one value-free
    :class:`FingerprintRecord` per replaced span (fingerprint input is the span
    text; tenant isolation follows the frozen DI-004 semantics). Pure function;
    no preview is attached to segment records (Packet §8.4.4 fixes only the
    fingerprint, value kind, and length).
    """
    normalized = unicodedata.normalize("NFC", value)
    spans = find_base64_spans(normalized)
    if not spans:
        return normalized, ()
    pieces: list[str] = []
    records: list[FingerprintRecord] = []
    cursor = 0
    for start, end in spans:
        segment = normalized[start:end]
        pieces.append(normalized[cursor:start])
        fingerprint = compute_fingerprint(
            segment, tenant_id=tenant_id, tenant_key=tenant_key
        )
        records.append(
            FingerprintRecord(
                fingerprint=fingerprint,
                value_kind="string",
                length=end - start,
            )
        )
        pieces.append(REDACTED_SEGMENT_TEMPLATE.format(fingerprint=fingerprint))
        cursor = end
    pieces.append(normalized[cursor:])
    return "".join(pieces), tuple(records)
