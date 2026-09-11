"""UAF v2 Orchestrator, legacy isolation and deterministic Arbiter tests.

Plan Task 10 (design sections 12.1/12.2/12.3).  Zero network: the Sidecar is
a fake ``analyze_uaf_facts`` client returning canned ``UafFactsResponse``
wire bundles, and the semantic-branch transport is a canned callable patched
over ``lima.uaf_llm_branch.post_chat_completion_text``.  Red lines pinned
here:

- legacy candidates physically cannot carry CWE-416 any more (contract
  layer) and the scanner projection never emits a CWE-416 legacy finding
  (defense in depth);
- PASS/REFUTED proofs reach ``fact-verified``/``rejected`` with zero LLM
  calls in every agent mode; UNKNOWN + ``off`` abstains; UNKNOWN +
  ``required`` fails the task instead of succeeding without calls;
- Diff-only source mode and fallback (heuristic/incomplete) build contexts
  are never ``fact-verified``;
- REFUTED candidates keep an audit record with the refuted obligation and
  never become findings;
- strong-evidence conflicts force ``needs-human-review`` (Arbiter rule 1);
- deadline, parallelism and dialogue_rounds are enforced for real;
- scanner merge is keyed by the immutable finding identity.
"""

import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from lima.cxx_agent_models import CxxAgentCandidate
from lima.cxx_memory import (
    CxxAnalysisResult,
    UafFactsResponse,
    uaf_facts_bundle_sha256,
)
from lima.models import EvidenceRecord, Finding, Severity
from lima.repository_scanner import RepositoryScanner
from lima.reviewer import LLMTransportError
from lima.uaf_orchestrator import (
    UAF_FINDING_STATES,
    arbiter_state,
    review_uaf,
)
from lima.workspace import RepositoryWorkspace

REPO_KEY = "team/project"
SNAPSHOT = "a" * 64
CONTEXT = "c" * 64
RUN_ID = "run-uaf-1"
UNIT = "src/a.cpp"
USR = "C::leak"

RESOLVED_LLM = {
    "provider": "custom",
    "base_url": "https://llm.example.invalid/v1",
    "api_key": "k",
    "model": "test-model",
    "headers": {},
}


def _fid(number: int) -> str:
    return format(number, "064x")


ALLOC = _fid(1)
RELEASE = _fid(2)
USE = _fid(3)
REBIND = _fid(4)
RELEASE2 = _fid(5)


# ------------------------------------------------------------------ wire


def _wire_fact(
    kind,
    fact_id,
    line,
    *,
    api=None,
    pointer=None,
    source_pointer=None,
    related=None,
):
    fact = {
        "fact_id": fact_id,
        "kind": kind,
        "translation_unit": UNIT,
        "canonical_path": UNIT,
        "function_usr": USR,
        "source_range": [line, line],
        "cfg_block": 0,
    }
    if kind == "allocation":
        fact["allocation_api"] = api or "new"
        fact["pointer_id"] = pointer or "p"
    elif kind == "release":
        fact["release_api"] = api or "delete"
        fact["pointer_id"] = pointer or "p"
        fact["related_fact_ids"] = list(related or ())
    elif kind == "dereference":
        fact["pointer_id"] = pointer or "p"
    elif kind == "rebind":
        fact["pointer_id"] = pointer or "p"
        fact["source_pointer_id"] = source_pointer or "n"
        fact["related_fact_ids"] = list(related or ())
    return fact


def _straight_facts():
    return [
        _wire_fact("allocation", ALLOC, 10),
        _wire_fact("release", RELEASE, 20, related=(ALLOC,)),
        _wire_fact("dereference", USE, 30),
    ]


def _rebind_facts():
    return _straight_facts() + [
        _wire_fact("rebind", REBIND, 25, pointer="p", source_pointer="n",
                   related=(ALLOC,)),
    ]


def _two_release_facts():
    return [
        _wire_fact("allocation", ALLOC, 10),
        _wire_fact("release", RELEASE, 20, related=(ALLOC,)),
        _wire_fact("release", RELEASE2, 22, related=(ALLOC,)),
        _wire_fact("dereference", USE, 30),
    ]


def _unit_entry(facts, *, build=None, cfg_complete=True, gaps=()):
    if build is None:
        build = {
            "status": "resolved",
            "source_kind": "repository-compdb",
            "context_hash": CONTEXT,
            "diagnostics": [],
        }
    return {
        "translation_unit": UNIT,
        "extraction": "completed",
        "build_context": build,
        "coverage": {
            "ast_complete": True,
            "cfg_complete": cfg_complete,
            "semantic_gaps": list(gaps),
        },
        "facts": list(facts),
    }


def _resolved_unit(facts=None):
    return _unit_entry(_straight_facts() if facts is None else facts)


def _unknown_unit(facts=None):
    # Same complete facts, but CFG extraction is incomplete: P5 stays
    # unknown, so the proof is UNKNOWN.
    return _unit_entry(_straight_facts() if facts is None else facts,
                       cfg_complete=False)


def _fallback_unit():
    # Protocol-legal but unresolved context: heuristic is never complete,
    # so readiness is never complete regardless of how the facts look.
    build = {
        "status": "incomplete",
        "source_kind": "heuristic",
        "context_hash": CONTEXT,
        "diagnostics": [],
    }
    return _unit_entry(_straight_facts(), build=build)


def _payload(*units, snapshot=SNAPSHOT, run_id=RUN_ID):
    tool_run = {"run_id": run_id, "tool": "uaf-facts", "status": "completed"}
    return {
        "schema_version": 1,
        "request_id": "req-1",
        "repository_key": REPO_KEY,
        "snapshot_sha256": snapshot,
        "tool_runs": [tool_run],
        "translation_units": list(units),
        "bundle_sha256": uaf_facts_bundle_sha256(list(units)),
        "diagnostics": [],
    }


class FakeUafAnalyzer:
    """Offline ``CxxMemoryAnalyzerClient`` stand-in (facts + tool layers)."""

    def __init__(self, payload=None, tool_result=None):
        self.payload = payload
        self.tool_result = tool_result
        self.unit_calls = []

    def analyze(
        self, repository_key, snapshot_sha256, requested_layers, inventory=None,
    ):
        return self.tool_result or CxxAnalysisResult(
            "completed", [], [], {"files": 0}, [],
        )

    def analyze_uaf_facts(
        self, repository_key, snapshot_sha256, translation_units,
        build_context_mode,
    ):
        self.unit_calls.append((tuple(translation_units), build_context_mode))
        payload = dict(self.payload or _payload())
        payload["repository_key"] = repository_key
        payload["snapshot_sha256"] = snapshot_sha256
        payload["bundle_sha256"] = uaf_facts_bundle_sha256(
            payload["translation_units"]
        )
        return UafFactsResponse(
            request_id=payload["request_id"],
            repository_key=payload["repository_key"],
            snapshot_sha256=payload["snapshot_sha256"],
            tool_runs=tuple(payload["tool_runs"]),
            translation_units=tuple(payload["translation_units"]),
            bundle_sha256=payload["bundle_sha256"],
            diagnostics=tuple(payload["diagnostics"]),
        )


# ------------------------------------------------------------- transports


class GuardTransport:
    """Records and rejects any wire call; for zero-LLM red lines."""

    def __init__(self):
        self.calls = []

    def __call__(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        raise AssertionError("the review must not call the LLM")


def smart_semantic_transport(requests):
    """Echoes a supporting six-field semantic reply for every role turn."""

    def transport(provider, base_url, api_key, payload, timeout,
                  extra_headers=None, max_bytes=None):
        requests.append(payload)
        user = payload["messages"][1]["content"]
        candidate_id = ""
        fact_ids = []
        for line in user.splitlines():
            if line.startswith("- candidate_id: "):
                candidate_id = line.split(": ", 1)[1]
            elif line.startswith("- ") and " kind=" in line:
                fact_ids.append(line[2:].split(" ", 1)[0])
        return json.dumps({
            "candidate_id": candidate_id,
            "supporting_fact_ids": fact_ids[:1],
            "refuting_fact_ids": [],
            "unresolved_assumptions": [],
            "semantic_assessment": "supports-uaf",
            "rationale": "the recorded facts keep the pointer bound at the use",
        })

    return transport


class DeadTransport:
    """Provider transport that always fails."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise LLMTransportError("provider unreachable")


# ------------------------------------------------------------- workspaces


UAF_SOURCE = "\n".join(
    [
        "#include <cstdlib>",  # 1
        "",  # 2
        "struct Buf {",  # 3
        "    int value;",  # 4
        "};",  # 5
        "",  # 6
        "int leak(void) {",  # 7
        "    struct Buf *p = 0;",  # 8
        "",  # 9
        "    p = (struct Buf *)malloc(sizeof(struct Buf));",  # 10
        "    if (p == 0) {",  # 11
        "        return 1;",  # 12
        "    }",  # 13
        "    p->value = 7;",  # 14
        "    (void)p;",  # 15
        "    (void)p;",  # 16
        "    (void)p;",  # 17
        "    (void)p;",  # 18
        "    (void)p;",  # 19
        "    free(p);",  # 20
        "    (void)p;",  # 21
        "    (void)p;",  # 22
        "    (void)p;",  # 23
        "    (void)p;",  # 24
        "    (void)p;",  # 25
        "    (void)p;",  # 26
        "    (void)p;",  # 27
        "    (void)p;",  # 28
        "    (void)p;",  # 29
        "    return p->value;",  # 30
        "}",  # 31
    ]
) + "\n"


def _write_cxx_repo(root, name=UNIT, content=UAF_SOURCE):
    path = Path(root, name)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8"))
    return RepositoryWorkspace(root)


# ------------------------------------------------------------ unit helper


def _review(
    payload,
    *,
    mode="auto",
    llm_config=None,
    tool_analysis=None,
    snapshot=SNAPSHOT,
    **params,
):
    """Run one review_uaf call over a temp workspace and the fake sidecar."""

    root = tempfile.mkdtemp(suffix="-uaf-orchestrator")
    workspace = _write_cxx_repo(root)
    analyzer = FakeUafAnalyzer(payload)
    params.setdefault("build_context_mode", "snapshot-compdb")
    outcome = review_uaf(
        analyzer,
        workspace,
        repository_key=REPO_KEY,
        snapshot_hash=snapshot,
        translation_units=(UNIT,),
        mode=mode,
        tool_analysis=tool_analysis,
        llm_config=llm_config,
        **params,
    )
    return outcome, analyzer


def _asan_tool_analysis():
    """Canned Sidecar result with one ASan record bound to the use site."""

    finding = Finding(
        rule_id="asan.uaf", severity=Severity.HIGH,
        title="heap-use-after-free", explanation="read of freed pointer",
        path=UNIT, line=30, evidence="p->value read after free(p)",
        fix="", test="reproduce under ASan", cwe="CWE-416", source="asan",
        symbol="leak",
        evidence_records=[EvidenceRecord(
            source="asan", kind="runtime", path=UNIT, line=30,
            snippet="READ of size 4 ... freed by ... allocated by ...",
            rule_id="asan.uaf", cwe="CWE-416", symbol="leak",
            tool_run_id="asan-run-1",
        )],
    )
    return CxxAnalysisResult(
        status="completed",
        tool_runs=[{
            "run_id": "asan-run-1", "tool": "asan-test", "status": "completed",
        }],
        findings=[finding],
        coverage={"files": 1},
        diagnostics=[],
    )


def _semgrep_tool_analysis():
    finding = Finding(
        rule_id="mem.uaf", severity=Severity.HIGH,
        title="use after free", explanation="buffer used after free",
        path=UNIT, line=30, evidence="p->value = ...", fix="", test="",
        cwe="CWE-416", source="semgrep", symbol="leak",
        evidence_records=[EvidenceRecord(
            source="semgrep", kind="match", path=UNIT, line=30,
            snippet="return p->value;", rule_id="mem.uaf", cwe="CWE-416",
            symbol="leak", tool_run_id="semgrep-run-1",
        )],
    )
    return CxxAnalysisResult(
        status="completed",
        tool_runs=[{
            "run_id": "semgrep-run-1", "tool": "semgrep",
            "status": "completed",
        }],
        findings=[finding],
        coverage={"files": 1},
        diagnostics=[],
    )


# ------------------------------------------------- legacy isolation helpers


VULN_C = """#include <stdlib.h>

static char *g_buf = 0;

void leak(void) {
    char *buf = malloc(64);
    free(buf);
    buf[0] = 'a';
}
"""


def direct_cwe_416_candidate():
    """A CWE-416 candidate built past the (now closed) contract layer."""

    return CxxAgentCandidate(
        candidate_id="sha256-" + "4" * 64,
        cwe="CWE-416",
        path="vuln.c",
        line=8,
        symbol="leak",
        title="buf is used after free",
        mechanism="free(buf) releases the buffer before buf[0] is written",
        trigger_path=("leak", "free", "buf[0]"),
        confidence=0.9,
    )


# ------------------------------------------------------------- arbiter pure


def _broker_support(level, producer="semgrep"):
    from lima.contracts.evidence import EvidencePolarity
    from lima.uaf_broker import BrokerVerdict
    from lima.uaf_models import CandidateIdentity

    return BrokerVerdict(
        identity=CandidateIdentity(SNAPSHOT, _fid(9)),
        producer=producer,
        verdict="support",
        evidence_level=level,
        evidence_polarity=EvidencePolarity.SUPPORTS,
    )


def _broker_contradict(level, producer="clang"):
    from lima.contracts.evidence import EvidencePolarity
    from lima.uaf_broker import BrokerVerdict
    from lima.uaf_models import CandidateIdentity

    return BrokerVerdict(
        identity=CandidateIdentity(SNAPSHOT, _fid(9)),
        producer=producer,
        verdict="contradict",
        evidence_level=level,
        evidence_polarity=EvidencePolarity.REFUTES,
    )


def _arbiter_proof(verdict):
    from lima.uaf_models import ObligationVerdict, ProofObligation, ProofResult

    obligations = tuple(
        ObligationVerdict(
            obligation=obligation,
            verdict=(
                "refuted" if verdict == "REFUTED" and obligation.value == "P6"
                else "satisfied" if verdict == "PASS" else "unknown"
            ),
            fact_ids=(ALLOC,),
            reason="fixture obligation",
        )
        for obligation in ProofObligation
    )
    return ProofResult(verdict=verdict, obligations=obligations)


# ================================================================= tests


class LegacyCwe416IsolationTests(unittest.TestCase):
    """Design 12.1: the legacy pipeline cannot emit CWE-416 findings."""

    def test_legacy_pipeline_cannot_emit_cwe_416_findings(self):
        # Layer 1 (contract): the legacy candidate contract physically
        # rejects CWE-416; no legacy role can construct one from wire.
        with self.assertRaises(ValueError):
            CxxAgentCandidate.from_untrusted_json({
                "cwe": "CWE-416",
                "path": "vuln.c",
                "line": 8,
                "symbol": "leak",
                "title": "buf is used after free",
                "mechanism": "free before write",
                "trigger_path": ["leak", "free", "buf[0]"],
                "confidence": 0.9,
            })
        # CWE-416 is out of the legacy domain but stays a supported CWE for
        # the UAF v2 consumers.
        from lima.cxx_agent_models import LEGACY_AGENT_CWES, SUPPORTED_CWES

        self.assertEqual(
            frozenset({"CWE-787", "CWE-125", "CWE-415"}), LEGACY_AGENT_CWES
        )
        self.assertIn("CWE-416", SUPPORTED_CWES)

        # Layer 2 (projection): a legacy run whose scripted specialist
        # returns a CWE-416 candidate built past the contract still emits
        # no CWE-416 Finding, while the legacy pipeline itself completes.
        from lima.cxx_agents import ROLE_MEMORY_LIFETIME, ROLE_PLANNER

        root = tempfile.mkdtemp(suffix="-uaf-legacy-isolation")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root, name="vuln.c", content=VULN_C)

        class ScriptedClient:
            model = "fake-cxx-model"

            def step(self, role, managed_context, tools, budget,
                     read_paths=None):
                if role == ROLE_PLANNER:
                    return agent_final(from_json_candidate(
                        "CWE-415", "vuln.c", 5, "leak", "anchor",
                    ))
                if role == ROLE_MEMORY_LIFETIME:
                    return agent_final(direct_cwe_416_candidate())
                return agent_final(from_json_candidate(
                    "CWE-415", "vuln.c", 8, "leak", "peer view",
                ))

        workspace = _write_cxx_repo(root, name="vuln.c", content=VULN_C)
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="auto",
            cxx_memory_adapter=FakeUafAnalyzer(
                payload=_payload(_unavailable_unit("vuln.c")),
            ),
            cxx_agent_mode="auto",
            cxx_agent_client_factory=ScriptedClient,
        )
        result = scanner.scan(workspace)
        findings = result.report.to_dict()["findings"]
        cwe_416 = [item for item in findings if item["cwe"] == "CWE-416"]
        self.assertEqual([], cwe_416)
        # The legacy branch really ran and its non-416 candidates project.
        self.assertEqual(
            "completed", result.report.collaboration["cxx_agent"]["status"]
        )
        self.assertTrue(
            any(item["cwe"] == "CWE-415" for item in findings),
            "legacy CWE-415 candidates must keep flowing",
        )


class FactVerifiedZeroLLMTests(unittest.TestCase):
    """PASS proofs complete with zero LLM calls in every agent mode."""

    def test_simple_uaf_reaches_fact_verified_with_zero_llm_calls_in_all_modes(
        self,
    ):
        guard = GuardTransport()
        for mode in ("off", "auto", "required"):
            with self.subTest(mode=mode), patch(
                "lima.uaf_llm_branch.post_chat_completion_text", guard
            ):
                outcome, analyzer = _review(
                    _payload(_resolved_unit()), mode=mode,
                )
                self.assertEqual(1, len(outcome.candidates))
                item = outcome.candidates[0]
                self.assertEqual("fact-verified", item.state)
                self.assertEqual("PASS", item.proof.verdict)
                self.assertIsNone(item.llm)
                self.assertEqual(0, outcome.stats.llm_calls)
                self.assertEqual(0, outcome.stats.llm_invoked_count)
                self.assertEqual(1, outcome.stats.pass_count)
                self.assertEqual(1, outcome.stats.candidate_count)
                self.assertEqual(1, outcome.stats.tu_count)
        self.assertEqual([], guard.calls)
        self.assertEqual([((UNIT,), "snapshot-compdb")], analyzer.unit_calls)


class UnknownModeGateTests(unittest.TestCase):
    """UNKNOWN proofs obey the mode matrix of design 12.2."""

    def test_unknown_plus_required_fails_on_zero_llm_calls(self):
        # (a) required + no configured provider: task failure, zero calls.
        guard = GuardTransport()
        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text", guard
        ):
            with self.assertRaises(RuntimeError):
                _review(_payload(_unknown_unit()), mode="required",
                        llm_config=None)
        self.assertEqual([], guard.calls)

        # (b) required + configured but dead provider: task failure.
        dead = DeadTransport()
        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text", dead
        ):
            with self.assertRaises(RuntimeError):
                _review(_payload(_unknown_unit()), mode="required",
                        llm_config=dict(RESOLVED_LLM))
        self.assertEqual(1, dead.calls)

    def test_unknown_plus_off_abstains(self):
        guard = GuardTransport()
        with patch("lima.uaf_llm_branch.post_chat_completion_text", guard):
            outcome, _ = _review(_payload(_unknown_unit()), mode="off")
        item = outcome.candidates[0]
        self.assertEqual("abstain", item.state)
        self.assertEqual("UNKNOWN", item.proof.verdict)
        self.assertIsNone(item.llm)
        self.assertEqual(0, outcome.stats.llm_calls)
        self.assertEqual([], guard.calls)


class IncompleteInputTests(unittest.TestCase):
    """Diff-only and fallback contexts are never fact-verified."""

    def test_diff_only_never_fact_verified(self):
        guard = GuardTransport()
        with patch("lima.uaf_llm_branch.post_chat_completion_text", guard):
            outcome, _ = _review(
                _payload(_resolved_unit()), mode="auto",
                source_mode="diff-only",
            )
        item = outcome.candidates[0]
        self.assertNotEqual("fact-verified", item.state)
        self.assertEqual("needs-human-review", item.state)
        self.assertEqual(0, outcome.stats.llm_calls)

    def test_fallback_context_never_fact_verified(self):
        # Heuristic/incomplete build context: readiness is never complete,
        # so the proof is UNKNOWN and the auto mode without a provider
        # records a degradation instead of a verified state.
        guard = GuardTransport()
        with patch("lima.uaf_llm_branch.post_chat_completion_text", guard):
            outcome, _ = _review(_payload(_fallback_unit()), mode="auto",
                                 llm_config=None)
        item = outcome.candidates[0]
        self.assertEqual("UNKNOWN", item.proof.verdict)
        self.assertNotEqual("fact-verified", item.state)
        self.assertEqual("abstain", item.state)
        self.assertEqual(0, outcome.stats.llm_calls)


class RejectedAuditTests(unittest.TestCase):
    """REFUTED candidates keep an audit record and never become findings."""

    def test_rebind_counterexample_rejected_with_audit_record(self):
        guard = GuardTransport()
        with patch("lima.uaf_llm_branch.post_chat_completion_text", guard):
            outcome, _ = _review(_payload(_resolved_unit(_rebind_facts())),
                                 mode="auto")
        self.assertEqual(1, len(outcome.candidates))
        item = outcome.candidates[0]
        self.assertEqual("rejected", item.state)
        self.assertNotIn(item.state, UAF_FINDING_STATES)
        self.assertEqual("REFUTED", item.proof.verdict)
        self.assertTrue(item.rejected_reason)
        self.assertIn("P6", item.rejected_reason)
        self.assertEqual(1, outcome.stats.refuted_count)
        self.assertEqual(0, outcome.stats.llm_calls)


class ArbiterPriorityTests(unittest.TestCase):
    """Arbiter rule 1: strong conflicting evidence forces human review."""

    def test_arbiter_priority_conflict_forces_needs_human_review(self):
        # PASS proof + valid D2 REFUTES tool evidence -> needs-human-review.
        state = arbiter_state(
            _arbiter_proof("PASS"),
            (_broker_contradict(level="D2"),),
            None,
        )
        self.assertEqual("needs-human-review", state)

        # REFUTED proof + valid D2 SUPPORTS tool evidence -> ditto.
        state = arbiter_state(
            _arbiter_proof("REFUTED"),
            (_broker_support(level="D2"),),
            None,
        )
        self.assertEqual("needs-human-review", state)

        # Without the conflict the same inputs decide deterministically:
        self.assertEqual(
            "fact-verified", arbiter_state(_arbiter_proof("PASS"), (), None),
        )
        self.assertEqual(
            "rejected", arbiter_state(_arbiter_proof("REFUTED"), (), None),
        )
        self.assertEqual(
            "tool-corroborated",
            arbiter_state(_arbiter_proof("UNKNOWN"),
                          (_broker_support(level="D2"),), None),
        )


class RuntimeConfirmationTests(unittest.TestCase):
    """Arbiter rule 2 over the binder + broker pipeline (D3 SUPPORTS)."""

    def test_runtime_confirmed_via_asan_evidence(self):
        guard = GuardTransport()
        with patch("lima.uaf_llm_branch.post_chat_completion_text", guard):
            outcome, _ = _review(
                _payload(_resolved_unit()), mode="auto",
                tool_analysis=_asan_tool_analysis(),
            )
        item = outcome.candidates[0]
        self.assertEqual("runtime-confirmed", item.state)
        self.assertEqual(1, len(item.broker_verdicts))
        self.assertEqual("support", item.broker_verdicts[0].verdict)
        self.assertEqual("asan", item.broker_verdicts[0].producer)
        self.assertEqual(0, outcome.stats.llm_calls)


class BudgetEnforcementTests(unittest.TestCase):
    """Deadline, parallelism and dialogue rounds are enforced for real."""

    def test_deadline_parallelism_dialogue_rounds_enforced(self):
        # (a) a deadline in the past stops the review before any work:
        # zero candidates, a diagnostic, zero LLM calls.
        guard = GuardTransport()
        with patch("lima.uaf_llm_branch.post_chat_completion_text", guard):
            outcome, analyzer = _review(
                _payload(_unknown_unit()), mode="auto",
                llm_config=dict(RESOLVED_LLM),
                deadline=time.monotonic() - 1.0,
            )
        self.assertEqual(0, len(outcome.candidates))
        self.assertEqual(0, outcome.stats.llm_calls)
        self.assertTrue(
            any("deadline" in item for item in outcome.diagnostics),
            outcome.diagnostics,
        )
        self.assertEqual([], analyzer.unit_calls)

        # (b) dialogue_rounds is a real cap on Specialist/Critic turns:
        # rounds=0 clamps to a single exchange (2 wire calls), rounds=2
        # performs two exchanges (4 wire calls) for one UNKNOWN candidate.
        requests = []
        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text",
            smart_semantic_transport(requests),
        ):
            single, _ = _review(
                _payload(_unknown_unit()), mode="auto",
                llm_config=dict(RESOLVED_LLM), dialogue_rounds=0,
            )
        self.assertEqual(2, len(requests))
        self.assertEqual("semantic-supported", single.candidates[0].state)
        self.assertEqual(2, single.stats.llm_calls)

        requests = []
        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text",
            smart_semantic_transport(requests),
        ):
            doubled, _ = _review(
                _payload(_unknown_unit()), mode="auto",
                llm_config=dict(RESOLVED_LLM), dialogue_rounds=2,
            )
        self.assertEqual(4, len(requests))
        self.assertEqual("semantic-supported", doubled.candidates[0].state)
        self.assertEqual(4, doubled.stats.llm_calls)

        # (c) parallelism only affects the UNKNOWN LLM branches and never
        # the deterministic output order or the call count: two releases
        # on one object produce two UNKNOWN candidates.
        requests_one = []
        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text",
            smart_semantic_transport(requests_one),
        ):
            serial, _ = _review(
                _payload(_unknown_unit(_two_release_facts())), mode="auto",
                llm_config=dict(RESOLVED_LLM),
            )
        self.assertEqual(4, len(requests_one))
        self.assertEqual(
            ["semantic-supported", "semantic-supported"],
            [item.state for item in serial.candidates],
        )

        requests_two = []
        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text",
            smart_semantic_transport(requests_two),
        ):
            parallel, _ = _review(
                _payload(_unknown_unit(_two_release_facts())), mode="auto",
                llm_config=dict(RESOLVED_LLM), parallelism=2,
            )
        self.assertEqual(4, len(requests_two))
        self.assertEqual(
            [item.candidate.candidate_id for item in serial.candidates],
            [item.candidate.candidate_id for item in parallel.candidates],
        )
        self.assertEqual(
            [item.state for item in serial.candidates],
            [item.state for item in parallel.candidates],
        )


class ScannerMergeTests(unittest.TestCase):
    """Scanner-level merge by immutable finding identity and payloads."""

    def _scan(self, payload, tool_result=None, **kwargs):
        root = tempfile.mkdtemp(suffix="-uaf-scanner")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root)
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="auto",
            cxx_memory_adapter=FakeUafAnalyzer(payload, tool_result),
            cxx_agent_mode=kwargs.pop("cxx_agent_mode", "auto"),
            **kwargs,
        )
        return scanner.scan(RepositoryWorkspace(Path(root)))

    def test_merge_by_immutable_finding_identity_dedup(self):
        # Two candidates on the same object share the same finding identity
        # (CWE-416, path, symbol, use line) and the semgrep sidecar finding
        # shares it too: exactly one merged finding survives.
        semgrep = _semgrep_tool_analysis()
        result = self._scan(
            _payload(_resolved_unit(_two_release_facts())),
            tool_result=semgrep,
        )
        findings = [
            item for item in result.report.to_dict()["findings"]
            if item["cwe"] == "CWE-416"
        ]
        self.assertEqual(1, len(findings))
        merged = findings[0]
        self.assertEqual("cxx-uaf-v2+semgrep", merged["source"])
        self.assertEqual("fact-verified", merged["verification_state"])
        self.assertEqual(30, merged["line"])
        self.assertFalse(merged["automatic_repair"])

    def test_scanner_uaf_branch_records_collaboration_payload(self):
        result = self._scan(_payload(_resolved_unit()))
        payload = result.report.collaboration["uaf_v2"]
        self.assertEqual("auto", payload["mode"])
        self.assertEqual("completed", payload["status"])
        self.assertEqual(1, payload["stats"]["candidate_count"])
        self.assertEqual(1, payload["states"]["fact-verified"])
        self.assertEqual(0, payload["stats"]["llm_calls"])
        self.assertEqual(["src/a.cpp"], payload["translation_units"])
        projected = [
            item for item in result.report.to_dict()["findings"]
            if item["source"] == "cxx-uaf-v2"
        ]
        self.assertEqual(1, len(projected))
        self.assertEqual("fact-verified", projected[0]["verification_state"])
        self.assertEqual("CWE-416", projected[0]["cwe"])
        self.assertFalse(projected[0]["automatic_repair"])
        self.assertTrue(projected[0]["candidate_id"])
        self.assertTrue(projected[0]["trigger_path"])

        # Without a C/C++ analyzer there are no facts and no proof: the
        # branch skips and records that honestly (design 12.1 routing).
        bare_root = tempfile.mkdtemp(suffix="-uaf-scanner-bare")
        self.addCleanup(lambda: _rmtree(bare_root))
        _write_cxx_repo(bare_root)
        bare = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="off",
            cxx_memory_adapter=None,
            cxx_agent_mode="auto",
        )
        bare_result = bare.scan(RepositoryWorkspace(Path(bare_root)))
        self.assertEqual(
            "analyzer-not-configured",
            bare_result.report.collaboration["uaf_v2"]["status"],
        )
        self.assertEqual(
            [], [item for item in bare_result.report.to_dict()["findings"]
                 if item["source"] == "cxx-uaf-v2"],
        )


# ------------------------------------------------------- local utilities


def agent_final(candidate):
    from lima.cxx_llm import AgentStep

    return AgentStep(action="final", candidates=(candidate,))


def from_json_candidate(cwe, path, line, symbol, title):
    return CxxAgentCandidate.from_untrusted_json({
        "cwe": cwe,
        "path": path,
        "line": line,
        "symbol": symbol,
        "title": title,
        "mechanism": "model-described mechanism",
        "trigger_path": ["leak"],
        "confidence": 0.6,
    })


def _unavailable_unit(unit):
    return {
        "translation_unit": unit,
        "extraction": "unavailable",
        "build_context": {
            "status": "unavailable", "source_kind": "",
            "context_hash": "", "diagnostics": [],
        },
        "coverage": {
            "ast_complete": False, "cfg_complete": False,
            "semantic_gaps": ["context-not-resolved"],
        },
        "facts": [],
    }


def _rmtree(root):
    import shutil

    shutil.rmtree(root, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
