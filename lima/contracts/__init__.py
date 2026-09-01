"""Deterministic, side-effect-free artifact contracts for LIMA (IP-0001).

This package is the frozen public API surface of the LIMA contract
foundation: the canonical JSON codec, schema versioning, artifact
references, and the artifact envelope. It is a stdlib-only, in-memory leaf
package; importing it must never pull in production service, store, queue,
network, database, Docker, or LLM modules. Re-export only — implementation
lives in :mod:`lima.contracts.errors`, :mod:`lima.contracts.codec`, and
:mod:`lima.contracts.common`.
"""

from lima.contracts.codec import (
    DEFAULT_LIMITS,
    ContractLimits,
    JSONValue,
    canonical_decode,
    canonical_encode,
    compute_content_digest,
)
from lima.contracts.common import (
    CURRENT_SCHEMA_MAJOR,
    CURRENT_SCHEMA_MINOR,
    ArtifactBlobReference,
    ArtifactClassification,
    ArtifactEnvelope,
    ArtifactReference,
    RetentionClass,
    SchemaVersion,
    decode_envelope,
    encode_envelope,
)
from lima.contracts.errors import ContractError, ContractErrorCode

__all__ = [
    "CURRENT_SCHEMA_MAJOR",
    "CURRENT_SCHEMA_MINOR",
    "DEFAULT_LIMITS",
    "JSONValue",
    "ContractErrorCode",
    "ContractError",
    "ContractLimits",
    "SchemaVersion",
    "ArtifactClassification",
    "RetentionClass",
    "ArtifactReference",
    "ArtifactBlobReference",
    "ArtifactEnvelope",
    "canonical_decode",
    "canonical_encode",
    "compute_content_digest",
    "decode_envelope",
    "encode_envelope",
]
