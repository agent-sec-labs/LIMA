# IP-0015 Evidence Privacy Core - frozen acceptance tests (P&V owned).
# Packet: docs/LIMA_Implementation_Packet_IP-0015_Evidence_Privacy_Core.md v1.0
# Frozen Test Commit v2 (DR-IP-0015-03 erratum 2026-09-12): converted from
# v1 bare-function style to unittest.TestCase style 1:1; assertions,
# boundary values, and requirement-ID anchors are unchanged from v1 (97e0b63).
"""Tenant policy resolution & policy digest tests (Packet 8.4; NFR-N05-04, SEC-N05-04)."""

from __future__ import annotations

import unittest

from lima.evidence_privacy import SINK_KINDS, PrivacyError, TenantPolicy
from lima.evidence_privacy.models import PrivacyLimits
from lima.evidence_privacy.policy import DEFAULT_POLICY, policy_digest

FROZEN_SINK_KINDS = frozenset({"storage", "log", "prompt", "api", "export"})


class PolicyTests(unittest.TestCase):
    def test_sink_kinds_frozen_set(self):
        # Packet Appendix B: SINK_KINDS is exactly the frozen set; no "vault".
        self.assertEqual(SINK_KINDS, FROZEN_SINK_KINDS)
        self.assertIsInstance(SINK_KINDS, frozenset)

    def test_default_policy_constant_exists_and_valid(self):
        # NFR-N05-04 / SEC-N05-04: DEFAULT_POLICY constant, usable out of the box.
        self.assertIsInstance(DEFAULT_POLICY, TenantPolicy)
        self.assertTrue(DEFAULT_POLICY.policy_version)
        self.assertEqual(DEFAULT_POLICY.sink_allowlist, SINK_KINDS)

    def test_resolve_factory_validates_inputs(self):
        # Packet 7 policy.py: TenantPolicy.resolve(...) classmethod factory,
        # validation at construction (fail-closed).
        p = TenantPolicy.resolve(policy_version="v1")
        self.assertIsInstance(p, TenantPolicy)
        with self.assertRaises(PrivacyError):
            TenantPolicy.resolve(policy_version="")
        with self.assertRaises(PrivacyError):
            TenantPolicy.resolve(policy_version="v1\tbad")  # non-printable
        with self.assertRaises(PrivacyError):
            TenantPolicy.resolve(policy_version="v1", preview_max_chars=5)

    def test_policy_digest_semantic_stability(self):
        # NFR-N05-04: same semantic policy -> same digest.
        a = policy_digest(TenantPolicy.resolve(policy_version="v1"))
        b = policy_digest(TenantPolicy(policy_version="v1", limits=PrivacyLimits()))
        self.assertEqual(a, b)
        self.assertEqual(len(a), 64)

    def test_policy_digest_changes_on_any_field_change(self):
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
        self.assertEqual(len({d0, d1, d2, d3, d4, d5}), 6)

    def test_digest_source_frozen_key_order(self):
        # Packet 8.4: digest_source() exposes the frozen field order.
        src = TenantPolicy.resolve(policy_version="v1").digest_source()
        self.assertEqual(
            list(src.keys()),
            [
                "policy_version",
                "limits",
                "preview_enabled",
                "preview_max_chars",
                "sink_allowlist",
            ],
        )
        self.assertEqual(
            set(src["limits"].keys()),
            {
                "max_depth",
                "max_payload_bytes",
                "max_string_bytes",
                "max_items",
                "max_processing_ms",
            },
        )
        self.assertEqual(src["sink_allowlist"], sorted(SINK_KINDS))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
