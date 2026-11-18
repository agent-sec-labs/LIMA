"""Version-1 investigation contracts: strict parsing and evidence identity."""

import json
import unittest

from lima.cxx_investigation_models import (
    HYPOTHESIS_STATUSES,
    INVESTIGATION_STATUSES,
    SCHEMA_VERSION,
    InvestigationAction,
    InvestigationEvidence,
    InvestigationIdentity,
    InvestigationState,
    HypothesisRecord,
    parse_investigation_action,
    state_from_json,
    state_to_json,
    validate_evidence_reference,
    validate_final_action,
)

IDENTITY = InvestigationIdentity(
    tenant_id="tenant-a",
    task_id="task-1",
    investigation_id="inv-1",
    snapshot_hash="a" * 64,
    context_digest="b" * 64,
    config_digest="c" * 64,
)


def _evidence(evidence_id: str, identity: InvestigationIdentity = IDENTITY) -> InvestigationEvidence:
    return InvestigationEvidence(
        evidence_id=evidence_id,
        identity=identity,
        action_id="a1",
        tool_name="read_source",
        path="src/a.cpp",
        start_line=1,
        end_line=10,
        artifact_ref="",
        payload_digest="d" * 64,
        scope="snapshot",
        truncated=False,
    )


def _hypothesis(hypothesis_id: str = "h1") -> HypothesisRecord:
    return HypothesisRecord(
        hypothesis_id=hypothesis_id,
        revision=1,
        statement="a controlled use is unsafe",
        cwe="CWE-416",
        trigger_path=["src/a.cpp"],
        assumptions=[],
        status="active",
        evidence_ids=[],
    )


def _state() -> InvestigationState:
    return InvestigationState(
        schema_version=SCHEMA_VERSION,
        identity=IDENTITY,
        version=3,
        lead="lead-001",
        hypotheses=[_hypothesis()],
        evidence={"e1": _evidence("e1"), "e2": _evidence("e2")},
        open_questions=[],
        action_ids=["a1", "a2"],
        child_ids=[],
        status="running",
        stop_reason=None,
    )


class InvestigationActionTests(unittest.TestCase):
    def test_action_rejects_unknown_fields(self):
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            parse_investigation_action(
                json.dumps({
                    "action": "tool", "tool": "read_source",
                    "arguments": {}, "purpose": "read",
                    "unexpected": "field",
                })
            )
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            parse_investigation_action(
                json.dumps({
                    "action": "final", "hypothesis_id": "h1",
                    "evidence_ids": ["e1"], "unresolved_questions": [],
                    "extra": True,
                })
            )
        with self.assertRaisesRegex(ValueError, "action"):
            parse_investigation_action(
                json.dumps({"tool": "read_source", "arguments": {}, "purpose": ""})
            )

    def test_action_types_are_validated(self):
        with self.assertRaisesRegex(ValueError, "tool"):
            parse_investigation_action(
                json.dumps({"action": "tool", "tool": "", "arguments": {}, "purpose": "x"})
            )
        with self.assertRaisesRegex(ValueError, "arguments"):
            parse_investigation_action(
                json.dumps({"action": "tool", "tool": "read_source",
                            "arguments": [], "purpose": "x"})
            )
        with self.assertRaisesRegex(ValueError, "evidence_ids"):
            parse_investigation_action(
                json.dumps({"action": "final", "hypothesis_id": "h1",
                            "evidence_ids": "e1", "unresolved_questions": []})
            )


class EvidenceIdentityTests(unittest.TestCase):
    def test_evidence_rejects_foreign_snapshot(self):
        state = _state()
        foreign = IDENTITY.__class__(
            tenant_id="tenant-b",
            task_id="task-2",
            investigation_id="inv-2",
            snapshot_hash="e" * 64,
            context_digest="f" * 64,
            config_digest="9" * 64,
        )
        state.evidence["e3"] = _evidence("e3", identity=foreign)
        with self.assertRaisesRegex(ValueError, "foreign investigation identity"):
            validate_evidence_reference(state, "e3")
        self.assertIs(state.evidence["e1"], validate_evidence_reference(state, "e1"))
        with self.assertRaisesRegex(ValueError, "unknown evidence"):
            validate_evidence_reference(state, "e99")


class FinalActionTests(unittest.TestCase):
    def test_final_rejects_unobserved_evidence(self):
        state = _state()
        good = parse_investigation_action(
            json.dumps({
                "action": "final", "hypothesis_id": "h1",
                "evidence_ids": ["e1", "e2"], "unresolved_questions": [],
            })
        )
        validate_final_action(state, good)
        bad = parse_investigation_action(
            json.dumps({
                "action": "final", "hypothesis_id": "h1",
                "evidence_ids": ["e1", "e99"], "unresolved_questions": [],
            })
        )
        with self.assertRaisesRegex(ValueError, "unobserved evidence"):
            validate_final_action(state, bad)
        unknown_hypothesis = parse_investigation_action(
            json.dumps({
                "action": "final", "hypothesis_id": "h9",
                "evidence_ids": ["e1"], "unresolved_questions": [],
            })
        )
        with self.assertRaisesRegex(ValueError, "unknown hypothesis"):
            validate_final_action(state, unknown_hypothesis)


class StateRoundTripTests(unittest.TestCase):
    def test_state_json_roundtrip_preserves_versions(self):
        state = _state()
        state.hypotheses[0].evidence_ids.append("e1")
        raw = state_to_json(state)
        restored = state_from_json(raw)
        self.assertEqual(state, restored)
        self.assertEqual(3, restored.version)
        self.assertEqual(1, restored.hypotheses[0].revision)
        self.assertEqual(["e1"], restored.hypotheses[0].evidence_ids)
        # Roundtrip rejects duplicate keys and unknown fields outright.
        with self.assertRaises(ValueError):
            state_from_json('{"schema_version": 1, "schema_version": 1}')
        with self.assertRaisesRegex(ValueError, "fields do not match"):
            state_from_json(json.dumps({**json.loads(raw), "extra": 1}))

    def test_closed_vocabularies_and_digests_are_enforced(self):
        self.assertIn("needs_attention", INVESTIGATION_STATUSES)
        self.assertIn("refuted", HYPOTHESIS_STATUSES)
        with self.assertRaises(ValueError):
            state_from_json(json.dumps({
                **json.loads(state_to_json(_state())), "status": "paused",
            }))
        with self.assertRaises(ValueError):
            InvestigationIdentity(
                tenant_id="t", task_id="x", investigation_id="i",
                snapshot_hash="not-hex", context_digest="b" * 64,
                config_digest="c" * 64,
            )


if __name__ == "__main__":
    unittest.main()
