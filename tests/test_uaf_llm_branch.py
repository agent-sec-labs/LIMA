"""UNKNOWN-only LLM semantic branch tests (plan Task 8, design sections 10/12.2/13).

Zero-network: the shared chat transport is replaced by a canned callable
patched over ``lima.uaf_llm_branch.post_chat_completion_text`` (the name this
module imported, mirroring the ``tests.test_cxx_llm`` style). Red lines
pinned here:

- PASS/REFUTED never reach the LLM in any mode; UNKNOWN + ``off`` abstains
  with zero calls; UNKNOWN + ``required`` can never succeed with zero calls;
- forged fact ids / candidate ids reject the whole round (no partial
  acceptance, no repair for authorization failures);
- consensus is capped at ``(D1, SUPPORTS)`` -- never D2 -- and a positive
  conclusion without a real supporting fact id stays an unresolved
  assumption (final abstain);
- the Critic's non-supporting assessment vetoes the branch (final abstain);
- exactly one budget-charged format repair; budget timing is calls before
  send, bytes after arrival;
- the assembled LLM input never carries labels, CVE text or tool findings.
"""

import json
import unittest
from unittest.mock import patch

from lima.contracts.evidence import EvidenceLevel, EvidencePolarity
from lima.cxx_agent_tools import AgentBudgetExceeded, CxxAgentBudget
from lima.reviewer import LLMTransportError
from lima.uaf_llm_branch import (
    CRITIC_ROLE,
    SPECIALIST_ROLE,
    UafSemanticContractError,
    UafSemanticFormatError,
    UafSemanticReply,
    build_specialist_context,
    parse_uaf_semantic_reply,
    run_semantic_branch,
    send_semantic_request,
)
from lima.uaf_models import (
    ExtractionCoverage,
    ObligationVerdict,
    ProofObligation,
    ProofResult,
    UafCandidate,
    UafFact,
    UafFactKind,
)

PROVIDER = "custom"
BASE_URL = "https://llm.example.invalid/v1"
API_KEY = "sekrit-key"
MODEL = "test-model"
RESOLVED = {
    "provider": PROVIDER,
    "base_url": BASE_URL,
    "api_key": API_KEY,
    "model": MODEL,
    "headers": {"X-Title": "LIMA"},
}

SNIPPET = "p = new Widget();\ndelete p;\np->tick();\n"


def _hex(number: int) -> str:
    return format(number, "064x")


SNAPSHOT = _hex(0xEE)
CONTEXT = _hex(0xCD)
UNIT_A = "src/a.cpp"
USR_MAIN = "c:@F@main#"

ALLOC = _hex(1)
RELEASE = _hex(2)
USE = _hex(3)
EXTRA_FACT = _hex(4)  # valid hex shape but absent from the branch bundle
FORGED_ID = _hex(0xBAD)

CANDIDATE_ID = _hex(0xA0)
OBJECT_ID = _hex(0xB0)


def _fact(kind: UafFactKind, fact_id: str, line: int) -> UafFact:
    return UafFact(
        fact_id=fact_id,
        kind=kind,
        snapshot_hash=SNAPSHOT,
        build_context_hash=CONTEXT,
        translation_unit=UNIT_A,
        canonical_path=UNIT_A,
        function_usr=USR_MAIN,
        source_range=(line, line),
        cfg_block=line,
    )


BUNDLE_FACTS = (
    _fact(UafFactKind.ALLOCATION, ALLOC, 10),
    _fact(UafFactKind.RELEASE, RELEASE, 14),
    _fact(UafFactKind.DEREFERENCE, USE, 22),
)
KNOWN_FACT_IDS = frozenset(fact.fact_id for fact in BUNDLE_FACTS)

CANDIDATE = UafCandidate(
    candidate_id=CANDIDATE_ID,
    object_id=OBJECT_ID,
    allocation_fact_id=ALLOC,
    release_fact_id=RELEASE,
    use_fact_id=USE,
    canonical_path=UNIT_A,
    function_usr=USR_MAIN,
    release_range=(14, 14),
    use_range=(22, 23),
)

COVERAGE = ExtractionCoverage(
    ast_complete=True,
    cfg_complete=False,
    semantic_gaps=("cfg-loop-not-supported",),
)


def _obligation(code: str, verdict: str, fact_ids: tuple[str, ...] = ()) -> ObligationVerdict:
    return ObligationVerdict(
        ProofObligation(code), verdict, fact_ids, "fixture obligation reason"
    )


def _proof(verdict: str, overrides: dict[str, str] | None = None) -> ProofResult:
    verdicts = {
        "P1": "satisfied",
        "P2": "unknown",
        "P3": "satisfied",
        "P4": "satisfied",
        "P5": "unknown",
        "P6": "satisfied",
        "P7": "satisfied",
    }
    verdicts.update(overrides or {})
    return ProofResult(
        verdict,
        tuple(
            _obligation(code, state, (ALLOC,) if code == "P1" else ())
            for code, state in verdicts.items()
        ),
    )


UNKNOWN_PROOF = _proof("UNKNOWN")
PASS_PROOF = _proof("PASS")
REFUTED_PROOF = _proof("REFUTED", {"P6": "refuted"})


def semantic_json(
    candidate_id=CANDIDATE_ID,
    supporting=(ALLOC, RELEASE, USE),
    refuting=(),
    assumptions=(),
    assessment="supports-uaf",
    rationale="the pointer stays bound to the released object at the use site",
):
    def entries(value):
        # Pass malformed values through untouched (a plain string stays a
        # JSON string, not a character list).
        return value if isinstance(value, str) else list(value)

    return json.dumps({
        "candidate_id": candidate_id,
        "supporting_fact_ids": entries(supporting),
        "refuting_fact_ids": entries(refuting),
        "unresolved_assumptions": entries(assumptions),
        "semantic_assessment": assessment,
        "rationale": rationale,
    })


SP_SUPPORTS = semantic_json()
CRITIC_SUPPORTS = semantic_json(
    rationale="no rebind, guard or lifetime restart survives the provided facts",
)


class FakeTransport:
    """Canned transport recording every call; queue items are text or raises."""

    def __init__(self, *contents):
        self.contents = list(contents)
        self.calls = []

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append({
            "provider": provider, "base_url": base_url, "api_key": api_key,
            "payload": payload, "timeout": timeout,
            "extra_headers": extra_headers, "max_bytes": max_bytes,
        })
        item = self.contents.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


class GuardTransport:
    """Records and rejects any wire call; for zero-LLM red lines."""

    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("the semantic branch must not call the LLM")


class ProbingTransport:
    """Canned transport that snapshots the budget at each send."""

    def __init__(self, budget, *contents):
        self.budget = budget
        self.contents = list(contents)
        self.calls = []
        self.snapshots = []

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append(payload)
        self.snapshots.append(self.budget.remaining())
        return self.contents.pop(0)


def run_branch(
    transport,
    mode="auto",
    proof=UNKNOWN_PROOF,
    budget=None,
    rounds=1,
    role=SPECIALIST_ROLE,
    resolved=None,
    candidate=CANDIDATE,
    bundle_facts=BUNDLE_FACTS,
):
    budget = budget if budget is not None else CxxAgentBudget(
        max_calls=8, max_output_bytes=100_000,
    )
    with patch("lima.uaf_llm_branch.post_chat_completion_text", transport):
        outcome = run_semantic_branch(
            role, dict(resolved or RESOLVED), candidate, bundle_facts, proof,
            COVERAGE, SNIPPET, budget, mode, dialogue_rounds=rounds,
        )
    return outcome, budget, transport


class GateTests(unittest.TestCase):
    """PASS/REFUTED never invoke the LLM; mode gates are honored."""

    def test_pass_proof_skips_llm_in_all_modes(self):
        for proof in (PASS_PROOF, REFUTED_PROOF):
            for mode in ("off", "auto", "required"):
                with self.subTest(proof=proof.verdict, mode=mode):
                    transport = GuardTransport()
                    outcome, _, gated = run_branch(transport, mode=mode, proof=proof)
                    self.assertFalse(outcome.invoked)
                    self.assertEqual(0, outcome.calls)
                    self.assertEqual("abstain", outcome.verdict)
                    self.assertIsNone(outcome.level_polarity)
                    self.assertTrue(outcome.degradation.startswith("proof-"))
                    self.assertEqual([], gated.calls)

    def test_unknown_plus_off_abstains_without_calls(self):
        transport = GuardTransport()
        outcome, _, gated = run_branch(transport, mode="off")
        self.assertFalse(outcome.invoked)
        self.assertEqual(0, outcome.calls)
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("mode-off", outcome.degradation)
        self.assertEqual([], gated.calls)

    def test_mode_must_be_in_closed_vocabulary(self):
        transport = GuardTransport()
        with self.assertRaises(ValueError):
            run_branch(transport, mode="bogus")

    def test_role_must_be_the_specialist_anchor(self):
        transport = GuardTransport()
        with self.assertRaises(ValueError):
            run_branch(transport, mode="auto", role=CRITIC_ROLE)


class ModeFailureTests(unittest.TestCase):
    """Provider unavailability and budget exhaustion follow the mode."""

    def test_unknown_plus_auto_with_provider_unavailable_degrades_and_abstains(self):
        transport = FakeTransport(
            LLMTransportError(f"{PROVIDER} review request failed: refused"),
        )
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertTrue(outcome.invoked)
        self.assertEqual(1, outcome.calls)
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("llm-unavailable", outcome.degradation)
        self.assertIsNone(outcome.level_polarity)
        self.assertEqual(1, len(transport.calls))

    def test_unknown_plus_required_with_provider_unavailable_fails_task(self):
        transport = FakeTransport(
            LLMTransportError(f"{PROVIDER} review request failed: refused"),
        )
        with self.assertRaises(RuntimeError) as ctx:
            run_branch(transport, mode="required")
        self.assertNotIn(API_KEY, str(ctx.exception))
        self.assertEqual(1, len(transport.calls))

    def test_unknown_plus_required_cannot_succeed_with_zero_calls(self):
        transport = FakeTransport(SP_SUPPORTS, CRITIC_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="required")
        self.assertEqual("supports-uaf", outcome.verdict)
        self.assertTrue(outcome.invoked)
        self.assertGreaterEqual(outcome.calls, 1)

        guard = GuardTransport()
        outcome_off, _, gated = run_branch(guard, mode="off")
        self.assertEqual("abstain", outcome_off.verdict)
        self.assertEqual(0, outcome_off.calls)
        self.assertEqual([], gated.calls)

    def test_budget_exhaustion_degrades_in_auto_and_fails_in_required(self):
        budget = CxxAgentBudget(max_calls=1, max_output_bytes=100_000)
        transport = FakeTransport(SP_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="auto", budget=budget)
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("budget-exhausted", outcome.degradation)
        self.assertEqual(1, outcome.calls)

        budget = CxxAgentBudget(max_calls=1, max_output_bytes=100_000)
        transport = FakeTransport(SP_SUPPORTS)
        with self.assertRaises(AgentBudgetExceeded):
            run_branch(transport, mode="required", budget=budget)


class ContractViolationTests(unittest.TestCase):
    """Forged identities reject the whole round without repair."""

    def test_forged_fact_id_rejects_whole_round(self):
        forged = semantic_json(supporting=(EXTRA_FACT,))
        transport = FakeTransport(forged)
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("contract-violation", outcome.degradation)
        self.assertEqual(1, outcome.calls)
        self.assertEqual(1, len(transport.calls))

        transport = FakeTransport(forged)
        with self.assertRaises(RuntimeError) as ctx:
            run_branch(transport, mode="required")
        self.assertIn("contract", str(ctx.exception))
        self.assertEqual(1, len(transport.calls))

    def test_forged_candidate_id_rejected(self):
        forged = semantic_json(candidate_id=FORGED_ID)
        transport = FakeTransport(forged)
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("contract-violation", outcome.degradation)
        self.assertEqual(1, outcome.calls)
        self.assertEqual(1, len(transport.calls))

        transport = FakeTransport(forged)
        with self.assertRaises(RuntimeError):
            run_branch(transport, mode="required")
        self.assertEqual(1, len(transport.calls))


class ConsensusTests(unittest.TestCase):
    """Synthesis: critic veto, D1 cap, unsupported positives."""

    def test_consensus_capped_at_d1_semantic_supported(self):
        transport = FakeTransport(SP_SUPPORTS, CRITIC_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("supports-uaf", outcome.verdict)
        self.assertEqual(
            (EvidenceLevel.D1, EvidencePolarity.SUPPORTS), outcome.level_polarity,
        )
        self.assertNotEqual(EvidenceLevel.D2, outcome.level_polarity[0])
        self.assertEqual(2, outcome.calls)
        self.assertEqual("", outcome.degradation)
        self.assertEqual(CANDIDATE_ID, outcome.specialist_reply.candidate_id)
        self.assertEqual((ALLOC, RELEASE, USE), outcome.specialist_reply.supporting_fact_ids)

    def test_critic_veto_forces_abstain(self):
        for assessment in ("abstain", "refutes-uaf"):
            with self.subTest(critic=assessment):
                critic = semantic_json(
                    assessment=assessment,
                    refuting=(RELEASE,) if assessment == "refutes-uaf" else (),
                    rationale="a guard branch cannot be excluded from the given facts",
                )
                transport = FakeTransport(SP_SUPPORTS, critic)
                outcome, _, _ = run_branch(transport, mode="auto")
                self.assertEqual("abstain", outcome.verdict)
                self.assertIsNone(outcome.level_polarity)
                self.assertEqual("critic-veto", outcome.degradation)

    def test_supporting_without_fact_ids_stays_abstain(self):
        specialist = semantic_json(
            supporting=(),
            assumptions=("the pointer may be rebound before the use site",),
        )
        transport = FakeTransport(specialist, CRITIC_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("abstain", outcome.verdict)
        self.assertIsNone(outcome.level_polarity)
        self.assertEqual("unsupported-positive", outcome.degradation)
        self.assertEqual(
            ("the pointer may be rebound before the use site",),
            outcome.specialist_reply.unresolved_assumptions,
        )

    def test_specialist_not_supporting_is_no_consensus(self):
        specialist = semantic_json(
            assessment="abstain",
            supporting=(),
            assumptions=("control flow between release and use is unresolved",),
        )
        transport = FakeTransport(specialist, CRITIC_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("no-consensus", outcome.degradation)


class FormatRepairTests(unittest.TestCase):
    """Exactly one budget-charged repair; the second failure follows mode."""

    def repair_user_message(self, transport):
        messages = transport.calls[1]["payload"]["messages"]
        self.assertEqual(
            ["system", "user", "assistant", "user"],
            [item["role"] for item in messages],
        )
        return messages[3]["content"]

    def test_format_repair_once_then_succeeds(self):
        transport = FakeTransport("{not json", SP_SUPPORTS, CRITIC_SUPPORTS)
        outcome, budget, transport = run_branch(transport, mode="auto")
        self.assertEqual("supports-uaf", outcome.verdict)
        self.assertEqual(3, outcome.calls)
        self.assertEqual(3, len(transport.calls))
        repair = self.repair_user_message(transport)
        self.assertIn("not a valid semantic assessment", repair)
        self.assertIn("payload is not valid JSON", repair)
        self.assertEqual(5, budget.remaining().calls)

    def test_format_repair_once_then_fail_by_mode(self):
        transport = FakeTransport("{bad", "{worse")
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("invalid-reply", outcome.degradation)
        self.assertEqual(2, outcome.calls)
        self.assertEqual(2, len(transport.calls))

        transport = FakeTransport("{bad", "{worse")
        with self.assertRaises(RuntimeError) as ctx:
            run_branch(transport, mode="required")
        self.assertIn("invalid", str(ctx.exception))
        self.assertEqual(2, len(transport.calls))


class DialogueTests(unittest.TestCase):
    """dialogue_rounds actually bounds the specialist/critic round trips."""

    def test_dialogue_rounds_limit_round_trips(self):
        transport = FakeTransport(SP_SUPPORTS, CRITIC_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="auto", rounds=1)
        self.assertEqual(2, outcome.calls)
        self.assertEqual(2, len(transport.calls))

    def test_second_round_receives_first_specialist_reply(self):
        round_one_specialist = semantic_json(rationale="round one reasoning")
        round_two_specialist = semantic_json(rationale="round two reasoning")
        round_two_critic = semantic_json(
            assessment="abstain",
            rationale="round two found an unexcludable guard",
        )
        transport = FakeTransport(
            round_one_specialist, CRITIC_SUPPORTS,
            round_two_specialist, round_two_critic,
        )
        outcome, _, _ = run_branch(transport, mode="auto", rounds=2)
        self.assertEqual(4, outcome.calls)
        self.assertEqual(4, len(transport.calls))
        first_critic_user = transport.calls[1]["payload"]["messages"][1]["content"]
        second_critic_user = transport.calls[3]["payload"]["messages"][1]["content"]
        self.assertIn("round one reasoning", first_critic_user)
        self.assertNotIn("round one reasoning", second_critic_user)
        self.assertIn("round two reasoning", second_critic_user)
        # The last round decides: a round-two critic abstain vetoes the branch.
        self.assertEqual("abstain", outcome.verdict)
        self.assertEqual("critic-veto", outcome.degradation)

    def test_dialogue_rounds_must_be_positive(self):
        transport = GuardTransport()
        with self.assertRaises(ValueError):
            run_branch(transport, mode="auto", rounds=0)


class BudgetTimingTests(unittest.TestCase):
    """One call charged before each send, response bytes after arrival."""

    def test_budget_calls_charged_before_send_bytes_after(self):
        budget = CxxAgentBudget(max_calls=2, max_output_bytes=100_000)
        transport = ProbingTransport(budget, SP_SUPPORTS, CRITIC_SUPPORTS)
        outcome, budget, _ = run_branch(transport, mode="auto", budget=budget)
        self.assertEqual("supports-uaf", outcome.verdict)

        self.assertEqual(1, transport.snapshots[0].calls)
        # The specialist reply's bytes were charged on arrival, before the
        # critic send happened.
        self.assertEqual(
            100_000 - len(SP_SUPPORTS.encode("utf-8")),
            transport.snapshots[1].bytes_remaining,
        )
        self.assertEqual(0, transport.snapshots[1].calls)

        expected = sum(
            len(content.encode("utf-8")) for content in (SP_SUPPORTS, CRITIC_SUPPORTS)
        )
        self.assertEqual(0, budget.remaining().calls)
        self.assertEqual(100_000 - expected, budget.remaining().bytes_remaining)


class InputBoundaryTests(unittest.TestCase):
    """The assembled input never carries labels, CVE text or tool findings."""

    def test_inputs_never_include_labels_or_tool_findings(self):
        context = build_specialist_context(
            CANDIDATE,
            f"- {RELEASE} kind=release {UNIT_A}:14-14",
            f"- P3: satisfied facts={RELEASE}",
            ("cfg-loop-not-supported",),
            SNIPPET,
        )
        self.assertIn(CANDIDATE_ID, context)
        self.assertIn(RELEASE, context)
        self.assertIn(SNIPPET, context)
        lowered = context.lower()
        for forbidden in ("cve", "vulnerable", "fixed", "ground truth", "label"):
            self.assertNotIn(forbidden, lowered)

    def test_wire_user_message_is_the_assembled_context_only(self):
        transport = FakeTransport(SP_SUPPORTS, CRITIC_SUPPORTS)
        outcome, _, _ = run_branch(transport, mode="auto")
        self.assertEqual("supports-uaf", outcome.verdict)
        specialist_user = transport.calls[0]["payload"]["messages"][1]["content"]
        self.assertIn(CANDIDATE_ID, specialist_user)
        self.assertIn(SNIPPET, specialist_user)
        self.assertNotIn("CVE", specialist_user)
        system = transport.calls[0]["payload"]["messages"][0]["content"]
        self.assertIn(SPECIALIST_ROLE, system)
        self.assertIn("untrusted data", system)
        critic_system = transport.calls[1]["payload"]["messages"][0]["content"]
        self.assertIn(CRITIC_ROLE, critic_system)
        self.assertNotIn(SPECIALIST_ROLE, critic_system)
        self.assertEqual(
            "the pointer stays bound to the released object at the use site",
            outcome.specialist_reply.rationale,
        )


class SendRequestTests(unittest.TestCase):
    """The standalone wire helper charges calls before, bytes after."""

    def test_send_semantic_request_payload_and_budget_timing(self):
        budget = CxxAgentBudget(max_calls=1, max_output_bytes=100_000)
        transport = ProbingTransport(budget, SP_SUPPORTS)
        with patch("lima.uaf_llm_branch.post_chat_completion_text", transport):
            content = send_semantic_request(
                dict(RESOLVED), "system prompt", "user context", 9, budget,
            )
        self.assertEqual(SP_SUPPORTS, content)
        call = transport.calls[0]
        self.assertEqual(MODEL, call["model"])
        self.assertEqual(0, call["temperature"])
        self.assertEqual({"type": "json_object"}, call["response_format"])
        self.assertEqual(
            ["system", "user"], [m["role"] for m in call["messages"]],
        )
        # max_calls=1: the call is fully charged before the wire send fires.
        self.assertEqual(0, transport.snapshots[0].calls)
        self.assertEqual(100_000, transport.snapshots[0].bytes_remaining)
        self.assertEqual(
            100_000 - len(SP_SUPPORTS.encode("utf-8")),
            budget.remaining().bytes_remaining,
        )

    def test_send_semantic_request_requires_configured_provider(self):
        with self.assertRaises(ValueError):
            send_semantic_request({}, "s", "u", 9, CxxAgentBudget())


class ParseContractTests(unittest.TestCase):
    """The six-field reply contract, validated in isolation."""

    def test_valid_reply_round_trips(self):
        reply = parse_uaf_semantic_reply(SP_SUPPORTS, CANDIDATE_ID, KNOWN_FACT_IDS)
        self.assertIsInstance(reply, UafSemanticReply)
        self.assertEqual(CANDIDATE_ID, reply.candidate_id)
        self.assertEqual((ALLOC, RELEASE, USE), reply.supporting_fact_ids)
        self.assertEqual("supports-uaf", reply.semantic_assessment)

    def test_fenced_reply_is_unwrapped(self):
        fenced = "```json\n" + SP_SUPPORTS + "\n```"
        reply = parse_uaf_semantic_reply(fenced, CANDIDATE_ID, KNOWN_FACT_IDS)
        self.assertEqual("supports-uaf", reply.semantic_assessment)

    def test_field_set_must_match_exactly(self):
        extra = json.dumps({
            "candidate_id": CANDIDATE_ID, "supporting_fact_ids": [],
            "refuting_fact_ids": [], "unresolved_assumptions": [],
            "semantic_assessment": "abstain", "rationale": "r", "extra": 1,
        })
        missing = json.dumps({"candidate_id": CANDIDATE_ID, "rationale": "r"})
        for bad in (extra, missing, "[1, 2]", "42"):
            with self.subTest(bad=bad):
                with self.assertRaises(UafSemanticFormatError):
                    parse_uaf_semantic_reply(bad, CANDIDATE_ID, KNOWN_FACT_IDS)

    def test_forged_ids_raise_contract_error_not_format_error(self):
        forged_fact = semantic_json(supporting=(EXTRA_FACT,))
        with self.assertRaises(UafSemanticContractError):
            parse_uaf_semantic_reply(forged_fact, CANDIDATE_ID, KNOWN_FACT_IDS)
        forged_candidate = semantic_json(candidate_id=FORGED_ID)
        with self.assertRaises(UafSemanticContractError):
            parse_uaf_semantic_reply(forged_candidate, CANDIDATE_ID, KNOWN_FACT_IDS)

    def test_bad_vocabulary_and_types_are_format_errors(self):
        cases = [
            semantic_json(assessment="fact-verified"),
            semantic_json(rationale=""),
            semantic_json(supporting="not-a-list"),
            semantic_json(supporting=(42,)),
            semantic_json(assumptions=("x", 1)),
        ]
        for bad in cases:
            with self.subTest(bad=bad):
                with self.assertRaises(UafSemanticFormatError):
                    parse_uaf_semantic_reply(bad, CANDIDATE_ID, KNOWN_FACT_IDS)

    def test_duplicate_json_keys_rejected(self):
        raw = (
            f'{{"candidate_id":"{CANDIDATE_ID}","supporting_fact_ids":[],'
            '"supporting_fact_ids":[],"refuting_fact_ids":[],'
            '"unresolved_assumptions":[],'
            '"semantic_assessment":"abstain","rationale":"r"}'
        )
        with self.assertRaises(UafSemanticFormatError):
            parse_uaf_semantic_reply(raw, CANDIDATE_ID, KNOWN_FACT_IDS)


if __name__ == "__main__":
    unittest.main()
