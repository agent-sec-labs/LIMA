# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
"""Tenant policy resolution & policy digest tests (Packet 8.4; NFR-N05-04, SEC-N05-04)."""

from __future__ import annotations

import pytest
from lima.evidence_privacy import SINK_KINDS, PrivacyError, TenantPolicy
from lima.evidence_privacy.models import PrivacyLimits
from lima.evidence_privacy.policy import DEFAULT_POLICY, policy_digest

FROZEN_SINK_KINDS = frozenset({"storage", "log", "prompt", "api", "export"})


def test_sink_kinds_frozen_set():
    # Packet Appendix B: SINK_KINDS is exactly the frozen set; no "vault".
    assert SINK_KINDS == FROZEN_SINK_KINDS
    assert isinstance(SINK_KINDS, frozenset)


def test_default_policy_constant_exists_and_valid():
    # NFR-N05-04 / SEC-N05-04: DEFAULT_POLICY constant, usable out of the box.
    assert isinstance(DEFAULT_POLICY, TenantPolicy)
    assert DEFAULT_POLICY.policy_version
    assert DEFAULT_POLICY.sink_allowlist == SINK_KINDS


def test_resolve_factory_validates_inputs():
    # Packet 7 policy.py: TenantPolicy.resolve(...) classmethod factory,
    # validation at construction (fail-closed).
    p = TenantPolicy.resolve(policy_version="v1")
    assert isinstance(p, TenantPolicy)
    with pytest.raises(PrivacyError):
        TenantPolicy.resolve(policy_version="")
    with pytest.raises(PrivacyError):
        TenantPolicy.resolve(policy_version="v1\tbad")  # non-printable
    with pytest.raises(PrivacyError):
        TenantPolicy.resolve(policy_version="v1", preview_max_chars=5)


def test_policy_digest_semantic_stability():
    # NFR-N05-04: same semantic policy -> same digest.
    a = policy_digest(TenantPolicy.resolve(policy_version="v1"))
    b = policy_digest(TenantPolicy(policy_version="v1", limits=PrivacyLimits()))
    assert a == b
    assert len(a) == 64


def test_policy_digest_changes_on_any_field_change():
    # NFR-N05-04: changing any frozen digest_source field changes the digest.
    base = TenantPolicy.resolve(policy_version="v1")
    d0 = policy_digest(base)
    d1 = policy_digest(TenantPolicy.resolve(policy_version="v2"))
    d2 = policy_digest(
        TenantPolicy.resolve(policy_version="v1", limits=PrivacyLimits(max_depth=16))
    )
    d3 = policy_digest(TenantPolicy.resolve(policy_version="v1", preview_enabled=True))
    d4 = policy_digest(TenantPolicy.resolve(policy_version="v1", preview_max_chars=3))
    d5 = policy_digest(
        TenantPolicy.resolve(policy_version="v1", sink_allowlist=frozenset({"storage"}))
    )
    assert len({d0, d1, d2, d3, d4, d5}) == 6


def test_digest_source_frozen_key_order():
    # Packet 8.4: digest_source() exposes the frozen field order.
    src = TenantPolicy.resolve(policy_version="v1").digest_source()
    assert list(src.keys()) == [
        "policy_version",
        "limits",
        "preview_enabled",
        "preview_max_chars",
        "sink_allowlist",
    ]
    assert set(src["limits"].keys()) == {
        "max_depth",
        "max_payload_bytes",
        "max_string_bytes",
        "max_items",
        "max_processing_ms",
    }
    assert src["sink_allowlist"] == sorted(SINK_KINDS)
