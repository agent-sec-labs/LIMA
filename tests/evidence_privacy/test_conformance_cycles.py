# IP-0017 Content Conformance - frozen acceptance tests (P&V owned, phase 2).
# Packet: docs/LIMA_Implementation_Packet_IP-0017_Content_Conformance.md v1.0
# Scope: NFR-N05-02 cyclic inputs + D-1 fix (Packet 8.3): any direct or
# indirect self-reference in payload.value must be rejected with a stable
# PrivacyError (MAX_DEPTH_EXCEEDED per DR-IP-0017-1) under ANY legal
# PrivacyLimits, and no bare RecursionError may ever escape
# sanitize_for_sink. unittest.TestCase style, no pytest-only APIs.
"""D-1 cycle handling conformance suite (Packet 8.3; NFR-N05-02)."""

from __future__ import annotations

import unittest

from lima.evidence_privacy import (
    EvidencePayload,
    PrivacyError,
    PrivacyErrorCode,
    SanitizedPayload,
    SinkContext,
    TenantPolicy,
    sanitize_for_sink,
)

KEY = b"\x33" * 32
# Deep/roomy limits so the depth guard cannot mask cycle detection (8.3.1).
DEEP_LIMITS_KW = {
    "max_depth": 100_000,
    "max_items": 1_000_000,
    "max_processing_ms": 600_000,
}
MARKER = "cycle-marker-value"


def _sink(kind="storage"):
    return SinkContext(sink_kind=kind, tenant_id="tenant-a", tenant_key=KEY)


def _policy(**limit_kw):
    from lima.evidence_privacy import PrivacyLimits

    limits = PrivacyLimits(**limit_kw) if limit_kw else None
    return TenantPolicy.resolve(
        policy_version="v1", limits=limits
    ) if limits is not None else TenantPolicy.resolve(policy_version="v1")


def _cyclic_dict():
    node: dict = {"note": MARKER, "n": 1}
    node["self"] = node
    return node


def _cyclic_list():
    node: list = [MARKER, 1]
    node.append(node)
    return node


def _mixed_cycle():
    inner: list = []
    top: dict = {"items": inner, "note": MARKER}
    inner.append(top)
    inner.append({"k": "v"})
    return top


def _nested_cycle():
    wrapper = {"header": "ok", "body": {"data": [1, 2]}, "tail": "end"}
    cyclic = {"next": None, "note": MARKER}
    cyclic["next"] = cyclic
    wrapper["body"]["cycle"] = cyclic
    return wrapper


def _assert_typed_depth_reject(test, value, **limit_kw):
    """Assert MAX_DEPTH_EXCEEDED typed rejection, never RecursionError (8.3)."""
    payload = EvidencePayload(payload_kind="structured_json", value=value)
    try:
        sp = sanitize_for_sink(payload, _sink(), _policy(**limit_kw))
    except PrivacyError as exc:
        test.assertIs(exc.code, PrivacyErrorCode.MAX_DEPTH_EXCEEDED, str(exc))
        return exc
    except RecursionError:  # pragma: no cover - the D-1 violation itself
        test.fail("bare RecursionError escaped sanitize_for_sink (Packet 8.3.2)")
    test.assertIsInstance(sp, SanitizedPayload)
    test.fail("cyclic input was accepted instead of being rejected (Packet 8.3.1)")
    return None


class CycleRejectionTests(unittest.TestCase):
    def test_self_referencing_dict_default_limits_rejected(self):
        # NFR-N05-02 8.3.1: dict cycle under default limits (depth guard first).
        _assert_typed_depth_reject(self, _cyclic_dict())

    def test_self_referencing_dict_deep_limits_rejected(self):
        # NFR-N05-02 8.3.1: dict cycle must still be MAX_DEPTH_EXCEEDED with
        # max_depth=100000 (cycle detection, not the depth guard).
        _assert_typed_depth_reject(self, _cyclic_dict(), **DEEP_LIMITS_KW)

    def test_self_referencing_list_deep_limits_rejected(self):
        # NFR-N05-02 8.3.1: list cycle under deep limits (D-1 probe form).
        _assert_typed_depth_reject(self, _cyclic_list(), **DEEP_LIMITS_KW)

    def test_mixed_dict_list_cycle_deep_limits_rejected(self):
        # NFR-N05-02 8.3.1: dict->list->dict indirect cycle under deep limits.
        _assert_typed_depth_reject(self, _mixed_cycle(), **DEEP_LIMITS_KW)

    def test_cycle_in_nested_position_deep_limits_rejected(self):
        # NFR-N05-02 8.3.1: cycle nested inside an otherwise benign tree.
        _assert_typed_depth_reject(self, _nested_cycle(), **DEEP_LIMITS_KW)

    def test_cycle_wins_over_item_budget(self):
        # NFR-N05-02 8.3.1: with a tiny max_items budget a cycle must still be
        # reported as MAX_DEPTH_EXCEEDED (a cycle is unbounded depth), not
        # MAX_ITEMS_EXCEEDED.
        exc = _assert_typed_depth_reject(
            self, _cyclic_dict(), max_depth=100_000, max_items=10
        )
        self.assertIsNotNone(exc)

    def test_noncyclic_3000_deep_no_recursion_error(self):
        # NFR-N05-02 8.3.2: non-cyclic nesting deeper than the interpreter
        # stack capacity: success or PrivacyError(MAX_DEPTH_EXCEEDED), never
        # a bare RecursionError (D-1 probe: current code escapes it).
        node = {"leaf": MARKER}
        for _ in range(3000):
            node = {"child": node}
        payload = EvidencePayload(payload_kind="structured_json", value=node)
        try:
            sp = sanitize_for_sink(payload, _sink(), _policy(**DEEP_LIMITS_KW))
        except PrivacyError as exc:
            self.assertIs(exc.code, PrivacyErrorCode.MAX_DEPTH_EXCEEDED, str(exc))
        except RecursionError:  # pragma: no cover - the D-1 violation itself
            self.fail("bare RecursionError escaped sanitize_for_sink (Packet 8.3.2)")
        else:
            self.assertIsInstance(sp, SanitizedPayload)


class CycleErrorHygieneTests(unittest.TestCase):
    def test_cycle_error_carries_no_value_material(self):
        # NFR-N05-02 8.3.4: the cycle rejection's str/repr/context contain no
        # substring of the raw value; context only {"limit","actual"}-style
        # metadata; no object repr of the cycle members.
        for value in (_cyclic_dict(), _cyclic_list(), _mixed_cycle(), _nested_cycle()):
            with self.subTest(shape=type(value).__name__):
                exc = _assert_typed_depth_reject(self, value, **DEEP_LIMITS_KW)
                assert exc is not None
                self.assertNotIn(MARKER, str(exc))
                self.assertNotIn(MARKER, repr(exc))
                self.assertNotIn("next", str(exc))
                self.assertNotIn("items", str(exc))
                for key in exc.context:
                    self.assertIn(key, {"limit", "actual", "limit_ms"})

    def test_cycle_rejection_uniform_across_sinks(self):
        # NFR-N05-02 / appendix A negative row: the cycle judgement is the
        # same typed failure for every sink kind.
        for kind in ("storage", "log", "prompt", "api", "export"):
            with self.subTest(kind=kind):
                payload = EvidencePayload(
                    payload_kind="structured_json", value=_cyclic_dict()
                )
                try:
                    sanitize_for_sink(payload, _sink(kind), _policy(**DEEP_LIMITS_KW))
                except PrivacyError as exc:
                    self.assertIs(exc.code, PrivacyErrorCode.MAX_DEPTH_EXCEEDED)
                except RecursionError:  # pragma: no cover - D-1 violation
                    self.fail("bare RecursionError escaped sanitize_for_sink")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
