# IP-0017 Content Conformance - frozen acceptance tests (P&V owned, phase 2).
# Packet: docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md v1.0
# Scope: NFR-N05-02 full resource-limit matrix (Packet 8.7): over-depth /
# over-string / over-payload / over-items / time budget (O-2) plus the
# legal-boundary row (no false rejection). unittest.TestCase style.
"""Resource limit matrix conformance suite (Packet 8.7; NFR-N05-02)."""

from __future__ import annotations

import unittest

from lima.evidence_privacy import (
    EvidencePayload,
    PrivacyError,
    PrivacyErrorCode,
    PrivacyLimits,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

KEY = b"\x33" * 32
SINKS = ("storage", "log", "prompt", "api", "export")
DEFAULT_MAX_STRING_BYTES = 262_144


def _sink(kind="storage"):
    return SinkContext(sink_kind=kind, tenant_id="tenant-a", tenant_key=KEY)


def _policy(limits=None):
    return TenantPolicy.resolve(
        policy_version="v1", limits=limits if limits is not None else PrivacyLimits()
    )


def _nested(depth, leaf="x"):
    node = {"leaf": leaf}
    for _ in range(depth - 1):
        node = {"child": node}
    return node


def _expect_code(test, payload, limits, code):
    with test.assertRaises(PrivacyError) as ei:
        sanitize_for_sink(
            EvidencePayload(payload_kind=payload.payload_kind, value=payload.value),
            _sink(),
            _policy(limits),
        )
    test.assertIs(ei.exception.code, code, str(ei.exception))


class DepthMatrixTests(unittest.TestCase):
    def test_depth_boundary_at_limit_one(self):
        # NFR-N05-02 8.7 / 8.5.1: max_depth=1 -> depth 1 legal, depth 2
        # rejected with MAX_DEPTH_EXCEEDED.
        limits = PrivacyLimits(max_depth=1)
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=_nested(1)),
            _sink(),
            _policy(limits),
        )
        self.assertIsInstance(sp, SanitizedPayload)
        _expect_code(
            self,
            EvidencePayload(payload_kind="structured_json", value=_nested(2)),
            limits,
            PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
        )

    def test_depth_boundary_at_limit_two(self):
        # NFR-N05-02 8.7: max_depth=2 boundary.
        limits = PrivacyLimits(max_depth=2)
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=_nested(2)),
            _sink(),
            _policy(limits),
        )
        self.assertIsInstance(sp, SanitizedPayload)
        _expect_code(
            self,
            EvidencePayload(payload_kind="structured_json", value=_nested(3)),
            limits,
            PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
        )

    def test_depth_boundary_31_32_33_sampling(self):
        # NFR-N05-02 8.5.1 frozen sampling d in {31, 32, 33} with
        # max_depth=32: 31 and 32 legal, 33 rejected.
        limits = PrivacyLimits(max_depth=32)
        for depth in (31, 32):
            with self.subTest(depth=depth):
                sp = sanitize_for_sink(
                    EvidencePayload(payload_kind="structured_json", value=_nested(depth)),
                    _sink(),
                    _policy(limits),
                )
                self.assertIsInstance(sp, SanitizedPayload)
        _expect_code(
            self,
            EvidencePayload(payload_kind="structured_json", value=_nested(33)),
            limits,
            PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
        )

    def test_over_depth_alternating_dict_list(self):
        # NFR-N05-02 8.7 over-depth with list mixing in the chain.
        node = {"leaf": "x"}
        for i in range(7):
            node = [node] if i % 2 else {"c": node}
        limits = PrivacyLimits(max_depth=8)
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=node),
            _sink(),
            _policy(limits),
        )
        self.assertIsInstance(sp, SanitizedPayload)
        node = [node]  # depth 9 now
        _expect_code(
            self,
            EvidencePayload(payload_kind="structured_json", value=node),
            limits,
            PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
        )

    def test_sensitive_value_at_max_legal_depth_still_detected(self):
        # NFR-N05-02 8.5.1: depth does not weaken detection - a secret at the
        # exact max_depth boundary is still flagged.
        limits = PrivacyLimits(max_depth=16)
        node = {"client_secret": "s-0123456789"}
        for _ in range(15):
            node = {"child": node}
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=node),
            _sink(),
            _policy(limits),
        )
        self.assertEqual(len(sp.manifest.entries), 1)


class SizeAndItemsMatrixTests(unittest.TestCase):
    def test_over_string_custom_limit(self):
        # NFR-N05-02 8.7: NFC byte length max_string_bytes+1 ->
        # MAX_STRING_LENGTH_EXCEEDED.
        limits = PrivacyLimits(max_string_bytes=64)
        _expect_code(
            self,
            EvidencePayload(payload_kind="text", value="a" * 65),
            limits,
            PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )

    def test_over_string_default_limit(self):
        # NFR-N05-02 8.7: frozen default max_string_bytes=262144.
        _expect_code(
            self,
            EvidencePayload(payload_kind="text", value="a" * (DEFAULT_MAX_STRING_BYTES + 1)),
            PrivacyLimits(),
            PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED,
        )

    def test_string_exactly_at_default_limit_accepted(self):
        # NFR-N05-02 8.7 legal-boundary row: exactly max_string_bytes is OK.
        # Varied content: long uniform runs trigger quadratic regex
        # backtracking in the current classifier (recorded in the RED report
        # as an observation, not an assertion target).
        value = ("word " * 52429)[:262144]
        self.assertEqual(len(value.encode("utf-8")), DEFAULT_MAX_STRING_BYTES)
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="text", value=value),
            _sink(),
            _policy(),
        )
        self.assertIsInstance(sp, SanitizedPayload)

    def test_over_payload_bytes_custom_limit(self):
        # NFR-N05-02 8.7: bytes length max_payload_bytes+1 ->
        # RESOURCE_LIMIT_EXCEEDED.
        limits = PrivacyLimits(max_payload_bytes=64)
        _expect_code(
            self,
            EvidencePayload(payload_kind="bytes", value=b"\x00" * 65),
            limits,
            PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED,
        )

    def test_over_items_and_exact_items_boundary(self):
        # NFR-N05-02 8.7: counted items over max_items -> MAX_ITEMS_EXCEEDED;
        # counted items exactly max_items is legal ("items > max_items"
        # comparison frozen). Items are counted per container child and per
        # leaf, so a flat list of N ints counts 2N items: with max_items=8 a
        # list of 4 ints is exactly at the boundary and a list of 5 exceeds.
        limits = PrivacyLimits(max_items=8)
        _expect_code(
            self,
            EvidencePayload(payload_kind="structured_json", value=[1, 2, 3, 4, 5]),
            limits,
            PrivacyErrorCode.MAX_ITEMS_EXCEEDED,
        )
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=[1, 2, 3, 4]),
            _sink(),
            _policy(limits),
        )
        self.assertIsInstance(sp, SanitizedPayload)


class TimeBudgetAndUniformityTests(unittest.TestCase):
    def test_time_budget_exceeded_o2_design(self):
        # NFR-N05-02 8.7 (O-2): max_processing_ms=1 + 200,000 small int items
        # (>256 so the checkpoint cadence is reachable) ->
        # TIME_BUDGET_EXCEEDED.
        limits = PrivacyLimits(max_processing_ms=1, max_items=1_000_000)
        _expect_code(
            self,
            EvidencePayload(payload_kind="structured_json", value=[7] * 200_000),
            limits,
            PrivacyErrorCode.TIME_BUDGET_EXCEEDED,
        )

    def test_legal_boundaries_no_false_rejection(self):
        # NFR-N05-02 8.7 legal row: depth, items, and string all exactly at
        # their limits succeed together (4 kv pairs count 8 items).
        limits = PrivacyLimits(max_depth=5, max_items=8, max_string_bytes=32)
        value = {"k" + str(i): "v" for i in range(4)}
        sp = sanitize_for_sink(
            EvidencePayload(payload_kind="structured_json", value=value),
            _sink(),
            _policy(limits),
        )
        self.assertIsInstance(sp, SanitizedPayload)
        sp_text = sanitize_for_sink(
            EvidencePayload(payload_kind="text", value="a" * 32),
            _sink(),
            _policy(limits),
        )
        self.assertIsInstance(sp_text, SanitizedPayload)

    def test_negative_codes_identical_across_all_five_sinks(self):
        # NFR-N05-02 / appendix A negative row: over-depth rejection carries
        # the same typed code for every sink kind.
        limits = PrivacyLimits(max_depth=4)
        payload = EvidencePayload(payload_kind="structured_json", value=_nested(5))
        for kind in SINKS:
            with self.subTest(kind=kind):
                with self.assertRaises(PrivacyError) as ei:
                    sanitize_for_sink(payload, _sink(kind), _policy(limits))
                self.assertIs(ei.exception.code, PrivacyErrorCode.MAX_DEPTH_EXCEEDED)

    def test_error_hygiene_on_limit_rejections(self):
        # NFR-N05-02 8.3.4 continuation: limit errors carry no value text.
        probes = (
            (
                EvidencePayload(payload_kind="text", value="SECRETVALUE" * 7),
                PrivacyLimits(max_string_bytes=64),
                PrivacyErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            ),
            (
                EvidencePayload(payload_kind="structured_json", value=_nested(9, "zz")),
                PrivacyLimits(max_depth=8),
                PrivacyErrorCode.MAX_DEPTH_EXCEEDED,
            ),
            (
                EvidencePayload(payload_kind="bytes", value=b"Q" * 65),
                PrivacyLimits(max_payload_bytes=64),
                PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED,
            ),
        )
        for payload, limits, code in probes:
            with self.subTest(code=code.value):
                with self.assertRaises(PrivacyError) as ei:
                    sanitize_for_sink(payload, _sink(), _policy(limits))
                self.assertIs(ei.exception.code, code)
                self.assertNotIn("SECRETVALUE", str(ei.exception))
                self.assertNotIn("SECRETVALUE", repr(ei.exception))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
