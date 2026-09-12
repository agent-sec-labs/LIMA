"""Tenant-isolated HMAC fingerprints (Packet IP-0015 §8.3; NFR-N05-01, FR-N05-03).

Semantics (frozen):
- str values: Unicode NFC normalization then UTF-8 encoding (DI-002 semantics);
- bytes values: raw bytes, no normalization;
- int/bool/null: canonical JSON text bytes; structured: ``canonical_encode`` bytes.
- The HMAC key is derived per tenant: ``HMAC-SHA256(tenant_key,
  tenant-key-domain || tenant_id)``; the fingerprint is the first 16 bytes of
  ``HMAC-SHA256(derived_key, fingerprint-domain || normalized_value)``, hex
  encoded to 32 lowercase characters.

Domain separator constants are module-level ``Final`` values and are never
concatenated from caller input.
"""

from __future__ import annotations

import hashlib
import hmac
import unicodedata
from typing import Final

from lima.contracts.codec import JSONValue, canonical_encode

__all__ = ["compute_fingerprint"]

_TENANT_KEY_DOMAIN: Final[bytes] = b"lima.evidence_privacy.tenant-key.v1\x00"
_FINGERPRINT_DOMAIN: Final[bytes] = b"lima.evidence_privacy.fingerprint.v1\x00"
_FINGERPRINT_TRUNCATE_BYTES: Final[int] = 16
_SHA256: Final = hashlib.sha256


def _normalize_value(value: object) -> bytes:
    """Normalize one fingerprint input to its frozen byte form (Packet §8.3)."""
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        return unicodedata.normalize("NFC", value).encode("utf-8")
    # int/bool/null canonicalize to their JSON text form; containers to the
    # sorted-key canonical encoding (DI-002) -- never a locally written one.
    return canonical_encode(value)  # type: ignore[arg-type]


def _derive_tenant_key(tenant_key: bytes, tenant_id: str) -> bytes:
    """Derive the per-tenant HMAC key (domain-separated, tenant_id bound)."""
    return hmac.new(
        tenant_key, _TENANT_KEY_DOMAIN + tenant_id.encode("utf-8"), _SHA256
    ).digest()


def compute_fingerprint(
    value: str | bytes | JSONValue, *, tenant_id: str, tenant_key: bytes
) -> str:
    """Return the 32-char lowercase hex tenant-isolated fingerprint of ``value``."""
    derived_key = _derive_tenant_key(tenant_key, tenant_id)
    digest = hmac.new(
        derived_key, _FINGERPRINT_DOMAIN + _normalize_value(value), _SHA256
    ).digest()
    return digest[:_FINGERPRINT_TRUNCATE_BYTES].hex()
