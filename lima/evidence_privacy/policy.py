"""Tenant policy resolution, digest, and the frozen sink-kind set (Packet §8.4).

``policy_digest`` reuses ``lima.contracts.codec.compute_content_digest`` (DI-002)
over the frozen-order ``TenantPolicy.digest_source()`` dict; no parallel digest
rule is defined here.
"""

from __future__ import annotations

from typing import Final

from lima.contracts.codec import compute_content_digest
from lima.evidence_privacy.models import TenantPolicy

__all__ = ["DEFAULT_POLICY", "SINK_KINDS", "policy_digest"]

SINK_KINDS: Final[frozenset[str]] = frozenset(
    {"storage", "log", "prompt", "api", "export"}
)

DEFAULT_POLICY_VERSION: Final[str] = "v1"

DEFAULT_POLICY: Final[TenantPolicy] = TenantPolicy.resolve(
    policy_version=DEFAULT_POLICY_VERSION
)


def policy_digest(policy: TenantPolicy) -> str:
    """Return the 64-hex content digest of the policy's frozen field order."""
    return compute_content_digest(policy.digest_source())
