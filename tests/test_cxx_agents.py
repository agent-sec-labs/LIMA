"""Collaboration-protocol tests for the C/C++ multi-agent coordinator (Task 14).

Zero network, zero real LLM: the coordinator's client is a duck-typed
``ScriptedClient`` that records every ``(role, managed_context, tool names,
read_paths)`` tuple it is handed, charges the shared ``CxxAgentBudget`` exactly
like ``CxxLLMClient.step`` does (one call before the "wire"), and replays
scripted ``AgentStep`` objects or raises scripted exceptions.  Everything the
plan's RED list requires is asserted against those recordings:

* strict role order planner -> specialists -> critic -> evidence -> verifier
  (the arbiter is deterministic and never calls the client);
* specialists are peer-blind (no peer candidate titles/symbols/seeds in their
  contexts) and tool-blind (no evidence records, no evidence tool);
* the critic sees the specialist candidate union;
* only the evidence role's registry contains ``get_tool_evidence``;
* messages persist through a real temp-file ``TaskStore``;
* a failing specialist is retried exactly once, then replaced by its
  assignment passthrough;
* an out-of-set planner candidate triggers one format repair, then a
  deterministic degradation to retrieval-seed shells;
* the arbiter is deterministic across runs;
* PR contexts carry the changed-lines header, repository contexts do not;
* budget exhaustion degrades every later LLM role without a client call and
  still returns a complete result.
"""

import os
import tempfile
import unittest
from dataclasses import replace

from lima.cxx_agent_models import (
    AGENT_CONSENSUS_KEYS,
    CXX_AGENT_VERIFICATION_STATES,
    VERIFIED_STATES,
    CxxAgentCandidate,
    CxxAgentCoverage,
    agent_consensus_state,
    candidate_agreement,
    to_agent_finding_payload,
    verified_only_gate,
)
from lima.cxx_agent_tools import CxxAgentBudget
from lima.cxx_agents import (
    ROLE_ARBITER,
    ROLE_BOUNDS,
    ROLE_CRITIC,
    ROLE_EVIDENCE,
    ROLE_INTERPROCEDURAL,
    ROLE_MEMORY_LIFETIME,
    ROLE_ORDER,
    ROLE_PLANNER,
    ROLE_VERIFIER,
    SPECIALIST_ROLES,
    CxxAgentCoordinator,
    CxxAgentReviewResult,
    CxxRoleOutcome,
)
from lima.cxx_context import (
    ApiReference,
    CallEdge,
    CxxContextIndex,
    IndexCoverage,
    ResourceEvent,
    SymbolRecord,
    TypeRecord,
)
from lima.cxx_llm import AgentStep
from lima.cxx_memory import CxxAnalysisResult, bind_tool_evidence
from lima.cxx_retrieval import RetrievalCandidate, RetrievalRun
from lima.models import EvidenceRecord, Finding, Severity
from lima.store import TaskStore

SNAPSHOT = "c" * 64

FILES = {
    "src/session.cpp": (
        "#include <cstring>\n"
        "struct Session {\n"
        "  int handle;\n"
        "  void close();\n"
        "};\n"
        "void Session::read() { memcpy(buf, src, n); }\n"
    ),
    "src/wrapper.c": "\n".join(f"/* wrapper line {i} */" for i in range(1, 9)) + "\n",
    "src/buffer.c": "\n".join(f"/* buffer line {i} */" for i in range(1, 21)) + "\n",
    "src/other.cpp": "\n".join(f"// other line {i}" for i in range(1, 5)) + "\n",
}

ANCHORS = (
    RetrievalCandidate("src/session.cpp", 6, "Session::read", "allocation-event", 3),
    RetrievalCandidate("src/buffer.c", 10, "make_buffer", "release-event", 3),
    RetrievalCandidate("src/wrapper.c", 5, "read_wrapper", "length-api", 2),
    RetrievalCandidate("src/other.cpp", 1, "helper", "call-neighborhood", 1),
)

REVIEW_TOOLS = (
    "find_callees",
    "find_callers",
    "find_references",
    "get_type_definition",
    "read_code_snippet",
    "search_symbols",
)
EVIDENCE_TOOLS = (
    "find_callees",
    "find_callers",
    "find_references",
    "get_tool_evidence",
    "get_type_definition",
    "read_code_snippet",
    "search_symbols",
)

HAPPY_KINDS = {
    "assignment",
    "specialist_evidence",
    "peer_challenge",
    "evidence_report",
    "verification_decision",
    "arbitration_decision",
}


def make_candidate(path, line, symbol, title, confidence=0.8, cwe="CWE-415"):
    return CxxAgentCandidate.from_untrusted_json({
        "cwe": cwe,
        "path": path,
        "line": line,
        "symbol": symbol,
        "title": title,
        "mechanism": "model-described mechanism",
        "trigger_path": ["entry", "sink"],
        "confidence": confidence,
    })


PLAN_A = make_candidate("src/session.cpp", 6, "Session::read", "plan-session-anchor")
PLAN_B = make_candidate("src/buffer.c", 10, "make_buffer", "plan-buffer-anchor")
PLAN_C = make_candidate("src/wrapper.c", 5, "read_wrapper", "plan-wrapper-anchor")
PLAN_D = make_candidate("src/other.cpp", 1, "helper", "plan-other-anchor")

MEM_A = make_candidate("src/session.cpp", 6, "Session::read", "ALPHA-UAF-TITLE")
BOUNDS_A = make_candidate("src/wrapper.c", 5, "read_wrapper", "BETA-BOUNDS-TITLE")
INTER_A = make_candidate("src/other.cpp", 1, "helper", "GAMMA-INTER-TITLE")
GHOST = make_candidate("src/ghost.cpp", 9, "ghost_fn", "out-of-set location")


def make_claim(
    path,
    line,
    symbol,
    cwe="CWE-415",
    mechanism="callback retains an alias after owner deletion",
    trigger=("register_callback", "Session::close", "on_event"),
    confidence=0.8,
):
    return CxxAgentCandidate.from_untrusted_json({
        "cwe": cwe,
        "path": path,
        "line": line,
        "symbol": symbol,
        "title": "UAF claim title",
        "mechanism": mechanism,
        "trigger_path": list(trigger),
        "confidence": confidence,
    })


def make_shell_candidate(path, line, symbol):
    """Mirror the coordinator's degraded seed shell (direct construction)."""
    return CxxAgentCandidate(
        candidate_id="retrieval-test-" + f"{path}:{line}:{symbol}".replace("/", "-"),
        cwe="unreviewed",
        path=path,
        line=line,
        symbol=symbol,
        title="retrieval seed passthrough (allocation-event)",
        mechanism="degraded role output: unreviewed retrieval seed",
        trigger_path=(symbol,),
        confidence=0.0,
        verification_state="needs-human-review",
    )


def tool_run(run_id, tool="semgrep", status="completed"):
    return {
        "run_id": run_id,
        "tool": tool,
        "status": status,
        "returncode": 0 if status == "completed" else 1,
        "output_sha256": "b" * 64,
        "output_truncated": False,
        "digests_complete": True,
    }


def tool_finding(
    source,
    cwe="CWE-415",
    path="src/session.cpp",
    line=6,
    symbol="Session::read",
    run_id="",
):
    return Finding(
        rule_id=f"cxx.{source}.identity",
        severity=Severity.HIGH,
        title=f"{source} identity hit",
        explanation=f"{source} matched the candidate identity",
        path=path,
        line=line,
        evidence="memcpy(buf, src, n)",
        fix="",
        test="Reproduce under AddressSanitizer",
        confidence=0.9,
        cwe=cwe,
        source=source,
        evidence_kind="line",
        verification_state="candidate",
        language="c++",
        symbol=symbol,
        analysis_mode="tool",
        automatic_repair=False,
        evidence_records=[EvidenceRecord(
            source=source,
            kind="match",
            path=path,
            line=line,
            snippet="TOOL-MATCH",
            rule_id=f"cxx.{source}.identity",
            cwe=cwe,
            confidence=0.9,
            language="c++",
            symbol=symbol,
            analysis_mode="tool",
            tool_run_id=run_id,
        )],
    )


def make_analysis(findings, runs):
    return CxxAnalysisResult(
        status="completed",
        tool_runs=list(runs),
        findings=list(findings),
        coverage={"source_files": 3, "snapshot_files": 4},
        diagnostics=[],
    )


def step_final(*candidates):
    return AgentStep(action="final", candidates=tuple(candidates))


def step_tool(tool, **arguments):
    return AgentStep(action="tool", tool=tool, arguments=tuple(arguments.items()))


def make_index():
    symbols = (
        SymbolRecord(
            "Session::read", "src/session.cpp", 6, 6, kind="method", language="c++"
        ),
        SymbolRecord("make_buffer", "src/buffer.c", 10, 20, "function", "c"),
        SymbolRecord("read_wrapper", "src/wrapper.c", 5, 8, "function", "c"),
        SymbolRecord("helper", "src/other.cpp", 1, 4, "function", "c++"),
    )
    types = (TypeRecord("Session", "src/session.cpp", 2, 5, "struct"),)
    calls = (CallEdge("read_wrapper", "read", "src/wrapper.c", 6),)
    references = (ApiReference("memcpy", "Session::read", "src/session.cpp", 6),)
    resource_events = (
        ResourceEvent("allocate", "malloc", "make_buffer", "src/buffer.c", 12),
    )
    return CxxContextIndex(
        snapshot_sha256=SNAPSHOT,
        symbols=symbols,
        types=types,
        calls=calls,
        references=references,
        resource_events=resource_events,
        coverage=IndexCoverage(
            indexed=tuple(sorted(FILES)),
            parse_gaps=(),
            source_files_total=len(FILES),
            symbols_indexed=len(symbols),
            types_indexed=len(types),
            calls_indexed=len(calls),
            resource_events_indexed=len(resource_events),
        ),
    )


class FakeReader:
    def __init__(self, files=None):
        self.files = dict(files or FILES)

    def read_text(self, path):
        return self.files[path]


def make_run(candidates=ANCHORS):
    return RetrievalRun(
        candidates=tuple(candidates),
        context_files=(),
        context_lines=0,
        uncovered_candidates=0,
        uncovered_files=0,
        snapshot_sha256=SNAPSHOT,
    )


def make_evidence_record():
    return EvidenceRecord(
        source="semgrep",
        kind="match",
        path="src/session.cpp",
        line=6,
        snippet="TOOL-EVIDENCE-MARKER memcpy(buf, src, n)",
        rule_id="cxx.uaf",
        cwe="CWE-415",
        confidence=0.9,
        language="c++",
        symbol="Session::read",
        analysis_mode="tool",
    )


def happy_scripts():
    return {
        ROLE_PLANNER: [step_final(PLAN_A, PLAN_B, PLAN_C, PLAN_D)],
        ROLE_MEMORY_LIFETIME: [
            step_tool(
                "read_code_snippet", path="src/session.cpp", start_line=1, end_line=6
            ),
            step_final(MEM_A),
        ],
        ROLE_BOUNDS: [step_final(BOUNDS_A)],
        ROLE_INTERPROCEDURAL: [
            step_tool(
                "read_code_snippet", path="src/session.cpp", start_line=1, end_line=6
            ),
            step_final(INTER_A),
        ],
        ROLE_CRITIC: [step_final(MEM_A, BOUNDS_A)],
        ROLE_EVIDENCE: [
            step_tool("get_tool_evidence", candidate_id=MEM_A.candidate_id),
            step_final(MEM_A, BOUNDS_A),
        ],
        ROLE_VERIFIER: [step_final(MEM_A)],
    }


class ScriptedClient:
    """Duck-typed CxxLLMClient: records contexts, replays scripted steps.

    ``bytes_by_role`` optionally charges response bytes per role after the
    call charge, mirroring the real client's charge-on-arrival semantics for
    budget-exhaustion scenarios.
    """

    def __init__(self, responses_by_role, bytes_by_role=None):
        self._responses = {
            role: list(items) for role, items in responses_by_role.items()
        }
        self._bytes_by_role = dict(bytes_by_role or {})
        self.calls = []

    def step(self, role, managed_context, tools, budget, read_paths=None):
        self.calls.append({
            "role": role,
            "context": managed_context,
            "tools": tuple(tools.names()) if hasattr(tools, "names") else (),
            "read_paths": None if read_paths is None else frozenset(read_paths),
        })
        budget.consume(calls=1)
        byte_charge = self._bytes_by_role.get(role, 0)
        if byte_charge:
            budget.consume(bytes=byte_charge)
        item = self._responses[role].pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    def roles(self):
        return [call["role"] for call in self.calls]

    def calls_for(self, role):
        return [call for call in self.calls if call["role"] == role]


def keys_of(candidates):
    return {(item.path, item.line, item.symbol) for item in candidates}


class CoordinatorTestCase(unittest.TestCase):
    def setUp(self):
        self.index = make_index()
        self.reader = FakeReader()
        self.evidence_ids = []
        self.evidence_records = [make_evidence_record()]

    def evidence_lookup(self, candidate_id):
        self.evidence_ids.append(candidate_id)
        return list(self.evidence_records)

    def coordinator(self, client, **kwargs):
        kwargs.setdefault("evidence_lookup", self.evidence_lookup)
        return CxxAgentCoordinator(client, self.index, self.reader, **kwargs)

    def run_happy(self, **kwargs):
        client = ScriptedClient(happy_scripts())
        coordinator = self.coordinator(client, **kwargs)
        result = coordinator.review_repository(make_run())
        return client, result


class RoleSequenceTests(CoordinatorTestCase):
    def test_role_sequence_follows_protocol_order(self):
        client, result = self.run_happy()

        roles = client.roles()
        self.assertEqual(ROLE_PLANNER, roles[0])
        # The evidence script makes two client calls (tool request + final).
        self.assertEqual(
            [ROLE_CRITIC, ROLE_EVIDENCE, ROLE_EVIDENCE, ROLE_VERIFIER], roles[-4:]
        )
        specialists = roles[1:-4]
        # memory-lifetime and interprocedural script a tool call plus a final,
        # bounds scripts only a final; every specialist must appear.
        self.assertEqual(set(SPECIALIST_ROLES), set(specialists))
        self.assertEqual(
            sorted(
                [ROLE_BOUNDS, ROLE_INTERPROCEDURAL, ROLE_INTERPROCEDURAL,
                 ROLE_MEMORY_LIFETIME, ROLE_MEMORY_LIFETIME]
            ),
            sorted(specialists),
        )
        self.assertEqual(
            [ROLE_PLANNER] + list(SPECIALIST_ROLES) + [
                ROLE_CRITIC,
                ROLE_EVIDENCE,
                ROLE_VERIFIER,
                ROLE_ARBITER,
            ],
            [outcome.role for outcome in result.role_outcomes],
        )
        self.assertEqual(
            [outcome.status for outcome in result.role_outcomes],
            ["ok"] * len(ROLE_ORDER),
        )

    def test_specialist_read_paths_start_at_assignment_and_grow_with_reads(self):
        client, _result = self.run_happy()

        planner_call = client.calls_for(ROLE_PLANNER)[0]
        self.assertIsNone(planner_call["read_paths"])

        memory_calls = client.calls_for(ROLE_MEMORY_LIFETIME)
        self.assertEqual(
            frozenset({"src/session.cpp", "src/buffer.c"}),
            memory_calls[0]["read_paths"],
        )
        self.assertEqual(
            frozenset({"src/session.cpp", "src/buffer.c"}),
            memory_calls[1]["read_paths"],
        )

        inter_calls = client.calls_for(ROLE_INTERPROCEDURAL)
        self.assertEqual(frozenset({"src/other.cpp"}), inter_calls[0]["read_paths"])
        self.assertEqual(
            frozenset({"src/other.cpp", "src/session.cpp"}),
            inter_calls[1]["read_paths"],
        )

    def test_assignment_candidates_truncated_to_limit(self):
        extended = ANCHORS + (
            RetrievalCandidate("src/other.cpp", 2, "helper2", "length-api", 2),
            RetrievalCandidate("src/other.cpp", 3, "helper3", "length-api", 2),
        )
        client = ScriptedClient(happy_scripts())
        coordinator = self.coordinator(client, max_assignment_candidates=4)
        result = coordinator.review_repository(make_run(extended))

        planner_context = client.calls_for(ROLE_PLANNER)[0]["context"]
        for anchor in ANCHORS:
            self.assertIn(anchor.symbol, planner_context)
        self.assertNotIn("helper2", planner_context)
        self.assertNotIn("helper3", planner_context)
        self.assertEqual(4, result.coverage.candidates_generated)


class IsolationTests(CoordinatorTestCase):
    def test_specialists_are_peer_blind_and_tool_blind(self):
        client, _result = self.run_happy()

        peer_markers = {
            ROLE_MEMORY_LIFETIME: [
                "read_wrapper", "helper", "length-api", "call-neighborhood",
                "BETA-BOUNDS-TITLE", "GAMMA-INTER-TITLE", "TOOL-EVIDENCE-MARKER",
            ],
            ROLE_BOUNDS: [
                "Session::read", "make_buffer", "allocation-event", "release-event",
                "call-neighborhood", "ALPHA-UAF-TITLE", "GAMMA-INTER-TITLE",
                "TOOL-EVIDENCE-MARKER",
            ],
            ROLE_INTERPROCEDURAL: [
                "make_buffer", "allocation-event", "release-event", "length-api",
                "ALPHA-UAF-TITLE", "BETA-BOUNDS-TITLE", "TOOL-EVIDENCE-MARKER",
            ],
        }
        for role, markers in peer_markers.items():
            contexts = [call["context"] for call in client.calls_for(role)]
            self.assertTrue(contexts, role)
            for context in contexts:
                for marker in markers:
                    self.assertNotIn(marker, context, f"{role} leaked {marker!r}")
                self.assertNotIn("get_tool_evidence", context)

        planner_context = client.calls_for(ROLE_PLANNER)[0]["context"]
        self.assertNotIn("TOOL-EVIDENCE-MARKER", planner_context)
        self.assertNotIn("get_tool_evidence", planner_context)

    def test_critic_context_contains_specialist_candidates(self):
        client, _result = self.run_happy()

        critic_contexts = [call["context"] for call in client.calls_for(ROLE_CRITIC)]
        self.assertEqual(1, len(critic_contexts))
        context = critic_contexts[0]
        for title in ("ALPHA-UAF-TITLE", "BETA-BOUNDS-TITLE", "GAMMA-INTER-TITLE"):
            self.assertIn(title, context)
        for role in SPECIALIST_ROLES:
            self.assertIn(f"[{role}]", context)

    def test_evidence_role_exclusive_tool_access(self):
        client, result = self.run_happy()

        self.assertEqual((), client.calls_for(ROLE_PLANNER)[0]["tools"])
        for role in (
            ROLE_MEMORY_LIFETIME,
            ROLE_BOUNDS,
            ROLE_INTERPROCEDURAL,
            ROLE_CRITIC,
            ROLE_VERIFIER,
        ):
            for call in client.calls_for(role):
                self.assertEqual(REVIEW_TOOLS, call["tools"])
        for call in client.calls_for(ROLE_EVIDENCE):
            self.assertEqual(EVIDENCE_TOOLS, call["tools"])

        evidence_contexts = [
            call["context"] for call in client.calls_for(ROLE_EVIDENCE)
        ]
        self.assertIn("TOOL-EVIDENCE-MARKER", evidence_contexts[-1])
        self.assertEqual([MEM_A.candidate_id], self.evidence_ids)
        self.assertEqual((MEM_A,), result.candidates)

    def test_critic_and_verifier_do_not_see_specialist_raw_observations(self):
        client, _result = self.run_happy()

        # memory-lifetime reads session.cpp via read_code_snippet; those raw
        # observation lines must not leak into the critic's or the verifier's
        # managed context (the verifier only receives the evidence stage's own
        # observation summaries, whose record snippet is a different string).
        for role in (ROLE_CRITIC, ROLE_VERIFIER):
            contexts = [call["context"] for call in client.calls_for(role)]
            self.assertTrue(contexts, role)
            for context in contexts:
                self.assertNotIn("#include <cstring>", context)
                self.assertNotIn("struct Session {", context)
        critic_contexts = [call["context"] for call in client.calls_for(ROLE_CRITIC)]
        self.assertNotIn("memcpy(buf, src, n)", critic_contexts[-1])

    def test_non_evidence_tool_request_is_rejected_by_registry(self):
        client = ScriptedClient({
            **happy_scripts(),
            ROLE_CRITIC: [
                step_tool("get_tool_evidence", candidate_id="mid-evil"),
                step_final(MEM_A, BOUNDS_A),
            ],
        })
        result = self.coordinator(client).review_repository(make_run())

        critic_contexts = [call["context"] for call in client.calls_for(ROLE_CRITIC)]
        self.assertEqual(2, len(critic_contexts))
        self.assertIn("unknown agent tool: get_tool_evidence", critic_contexts[-1])
        self.assertEqual([MEM_A.candidate_id], self.evidence_ids)
        self.assertEqual((MEM_A,), result.candidates)


class PersistenceTests(CoordinatorTestCase):
    def test_messages_persist_via_task_store(self):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        try:
            store = TaskStore(path)
            store.create("cxx-agent-task", "org/repo", 1, {})
            client = ScriptedClient(happy_scripts())
            coordinator = CxxAgentCoordinator(
                client, self.index, self.reader,
                store=store, task_id="cxx-agent-task",
            )
            result = coordinator.review_repository(make_run())

            persisted = store.get("cxx-agent-task")["collaboration"]
            self.assertGreater(len(persisted), 0)
            self.assertEqual(result.message_count, len(persisted))
            kinds = {item["kind"] for item in persisted}
            self.assertEqual(HAPPY_KINDS, kinds)
            for item in persisted:
                self.assertTrue(item["sender"])
                self.assertTrue(item["recipient"])
                self.assertIsInstance(item["content"], dict)
            assignments = [
                item for item in persisted if item["kind"] == "assignment"
            ]
            self.assertEqual(
                sorted(SPECIALIST_ROLES),
                sorted(item["recipient"] for item in assignments),
            )
            # The arbitration keys match the existing lima.harness summary
            # consumer (approved_findings / rejected_findings).
            arbitration = next(
                item for item in persisted
                if item["kind"] == "arbitration_decision"
            )
            self.assertEqual(
                [MEM_A.candidate_id], arbitration["content"]["approved_findings"]
            )
            self.assertEqual(3, len(arbitration["content"]["rejected_findings"]))
        finally:
            os.unlink(path)


class RecoveryTests(CoordinatorTestCase):
    def test_specialist_retry_once_succeeds_marks_failed_retried(self):
        scripts = happy_scripts()
        scripts[ROLE_MEMORY_LIFETIME] = (
            [RuntimeError("simulated specialist crash")]
            + scripts[ROLE_MEMORY_LIFETIME]
        )
        client = ScriptedClient(scripts)
        result = self.coordinator(client).review_repository(make_run())

        self.assertEqual(3, len(client.calls_for(ROLE_MEMORY_LIFETIME)))
        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        self.assertEqual("failed-retried", outcomes[ROLE_MEMORY_LIFETIME].status)
        self.assertEqual((MEM_A,), outcomes[ROLE_MEMORY_LIFETIME].candidates)
        for role in (ROLE_BOUNDS, ROLE_INTERPROCEDURAL, ROLE_CRITIC):
            self.assertEqual("ok", outcomes[role].status)
        self.assertEqual((MEM_A,), result.candidates)

    def test_specialist_retry_exhaustion_passes_assignment_through(self):
        scripts = happy_scripts()
        scripts[ROLE_MEMORY_LIFETIME] = [
            RuntimeError("first failure"),
            RuntimeError("second failure"),
        ]
        client = ScriptedClient(scripts)
        result = self.coordinator(client).review_repository(make_run())

        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        self.assertEqual("failed-replaced", outcomes[ROLE_MEMORY_LIFETIME].status)
        self.assertIn("second failure", outcomes[ROLE_MEMORY_LIFETIME].error)
        self.assertEqual(
            keys_of(ANCHORS[:2]), keys_of(outcomes[ROLE_MEMORY_LIFETIME].candidates)
        )
        for shell in outcomes[ROLE_MEMORY_LIFETIME].candidates:
            self.assertEqual("unreviewed", shell.cwe)
        for role in (ROLE_BOUNDS, ROLE_INTERPROCEDURAL, ROLE_CRITIC):
            self.assertEqual("ok", outcomes[role].status)
        self.assertEqual((MEM_A,), result.candidates)
        critic_context = client.calls_for(ROLE_CRITIC)[0]["context"]
        self.assertIn("retrieval seed passthrough (allocation-event)", critic_context)
        self.assertIn("retrieval seed passthrough (release-event)", critic_context)

    def test_failure_messages_are_emitted_in_role_order(self):
        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        try:
            store = TaskStore(path)
            store.create("cxx-order-task", "org/repo", 1, {})
            scripts = {
                **happy_scripts(),
                ROLE_MEMORY_LIFETIME: [
                    RuntimeError("m1"), RuntimeError("m2"),
                ],
                ROLE_BOUNDS: [RuntimeError("b1"), RuntimeError("b2")],
            }
            client = ScriptedClient(scripts)
            CxxAgentCoordinator(
                client, self.index, self.reader,
                store=store, task_id="cxx-order-task",
                evidence_lookup=self.evidence_lookup,
            ).review_repository(make_run())

            transcript = [
                (item["kind"], item["sender"], item["recipient"])
                for item in store.get("cxx-order-task")["collaboration"]
            ]
            self.assertEqual([
                ("assignment", ROLE_PLANNER, ROLE_MEMORY_LIFETIME),
                ("assignment", ROLE_PLANNER, ROLE_BOUNDS),
                ("assignment", ROLE_PLANNER, ROLE_INTERPROCEDURAL),
                ("agent_failure", ROLE_MEMORY_LIFETIME, ROLE_PLANNER),
                ("retry_request", ROLE_PLANNER, ROLE_MEMORY_LIFETIME),
                ("agent_failure", ROLE_MEMORY_LIFETIME, ROLE_PLANNER),
                ("specialist_evidence", ROLE_MEMORY_LIFETIME, ROLE_CRITIC),
                ("agent_failure", ROLE_BOUNDS, ROLE_PLANNER),
                ("retry_request", ROLE_PLANNER, ROLE_BOUNDS),
                ("agent_failure", ROLE_BOUNDS, ROLE_PLANNER),
                ("specialist_evidence", ROLE_BOUNDS, ROLE_CRITIC),
                ("specialist_evidence", ROLE_INTERPROCEDURAL, ROLE_CRITIC),
                ("peer_challenge", ROLE_CRITIC, ROLE_EVIDENCE),
                ("evidence_report", ROLE_EVIDENCE, ROLE_VERIFIER),
                ("verification_decision", ROLE_VERIFIER, ROLE_ARBITER),
                ("arbitration_decision", ROLE_ARBITER, "review-report"),
            ], transcript)
        finally:
            os.unlink(path)


class PlannerTests(CoordinatorTestCase):
    def test_planner_out_of_bounds_degrades_to_seed_shells(self):
        client = ScriptedClient({
            **happy_scripts(),
            ROLE_PLANNER: [step_final(GHOST), step_final(GHOST)],
        })
        result = self.coordinator(client).review_repository(make_run())

        planner_calls = client.calls_for(ROLE_PLANNER)
        self.assertEqual(2, len(planner_calls))
        self.assertIn("FORMAT REPAIR", planner_calls[1]["context"])

        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        self.assertEqual("failed-replaced", outcomes[ROLE_PLANNER].status)
        shells = outcomes[ROLE_PLANNER].candidates
        self.assertEqual(keys_of(ANCHORS), keys_of(shells))
        for shell, anchor in zip(shells, ANCHORS, strict=True):
            self.assertEqual("unreviewed", shell.cwe)
            self.assertEqual(0.0, shell.confidence)
            self.assertEqual("needs-human-review", shell.verification_state)
            self.assertIn("retrieval seed passthrough", shell.title)
            self.assertIn(anchor.seed_reason, shell.title)
        self.assertEqual("ok", outcomes[ROLE_MEMORY_LIFETIME].status)
        self.assertEqual((MEM_A,), result.candidates)

    def test_planner_repair_success_marks_failed_retried(self):
        client = ScriptedClient({
            **happy_scripts(),
            ROLE_PLANNER: [step_final(GHOST), step_final(PLAN_A, PLAN_B, PLAN_C, PLAN_D)],
        })
        result = self.coordinator(client).review_repository(make_run())

        planner_calls = client.calls_for(ROLE_PLANNER)
        self.assertEqual(2, len(planner_calls))
        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        self.assertEqual("failed-retried", outcomes[ROLE_PLANNER].status)
        self.assertEqual(keys_of(ANCHORS), keys_of(outcomes[ROLE_PLANNER].candidates))
        for shell in outcomes[ROLE_PLANNER].candidates:
            self.assertEqual("unreviewed", shell.cwe)
            self.assertEqual("needs-human-review", shell.verification_state)
        self.assertEqual((MEM_A,), result.candidates)

    def test_planner_rewrite_is_replaced_by_anchor_projection(self):
        rewritten = make_candidate(
            "src/session.cpp", 6, "Session::read",
            "MODEL-REWRITTEN-TITLE", cwe="CWE-125",
        )
        client = ScriptedClient({
            **happy_scripts(),
            ROLE_PLANNER: [step_final(rewritten, PLAN_B)],
            ROLE_CRITIC: [step_final(MEM_A)],
            ROLE_EVIDENCE: [
                step_tool("get_tool_evidence", candidate_id=MEM_A.candidate_id),
                step_final(MEM_A),
            ],
            ROLE_VERIFIER: [step_final(MEM_A)],
        })
        result = self.coordinator(client).review_repository(make_run())

        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        shells = outcomes[ROLE_PLANNER].candidates
        # Same model-chosen subset and order, but every field comes from the
        # retrieval anchor projection, never from the model's wording.
        self.assertEqual(
            ("src/session.cpp", "src/buffer.c"),
            tuple(shell.path for shell in shells),
        )
        self.assertEqual(keys_of(ANCHORS[:2]), keys_of(shells))
        for shell in shells:
            self.assertEqual("unreviewed", shell.cwe)
            self.assertEqual("needs-human-review", shell.verification_state)
            self.assertTrue(shell.candidate_id.startswith("retrieval-"))
        self.assertNotIn("MODEL-REWRITTEN-TITLE", outcomes[ROLE_PLANNER].candidates[0].title)
        self.assertEqual((MEM_A,), result.candidates)


class DeterminismTests(CoordinatorTestCase):
    def test_arbiter_is_deterministic_across_runs(self):
        client_one, first = self.run_happy()
        self.evidence_ids = []
        client_two, second = self.run_happy()

        self.assertEqual(0, len(client_one.calls_for(ROLE_ARBITER)))
        self.assertEqual(first, second)
        self.assertEqual((MEM_A,), first.candidates)
        self.assertEqual(
            (
                "src/buffer.c:10:make_buffer: dropped-by-memory-lifetime",
                "src/other.cpp:1:helper: dropped-by-critic",
                "src/wrapper.c:5:read_wrapper: dropped-by-verifier",
            ),
            first.arbiter_rejections,
        )


class EntryModeTests(CoordinatorTestCase):
    def test_pull_request_context_header_differs_from_repository(self):
        repo_client = ScriptedClient(happy_scripts())
        self.coordinator(repo_client).review_repository(make_run())

        pr_client = ScriptedClient(happy_scripts())
        self.coordinator(pr_client).review_pull_request(
            make_run(), {"src/session.cpp": [6, 3]}
        )

        repo_context = repo_client.calls_for(ROLE_PLANNER)[0]["context"]
        pr_context = pr_client.calls_for(ROLE_PLANNER)[0]["context"]
        self.assertNotIn("changed line", repo_context)
        self.assertIn("Pull request changed lines", pr_context)
        self.assertIn("src/session.cpp: 2 changed line(s)", pr_context)
        self.assertIn(f"Snapshot: {SNAPSHOT}", pr_context)

    def test_pull_request_rejects_invalid_changed_lines(self):
        client = ScriptedClient(happy_scripts())
        coordinator = self.coordinator(client)
        with self.assertRaises(ValueError):
            coordinator.review_pull_request(make_run(), {"..\\escape.cpp": [1]})


class DegradationTests(CoordinatorTestCase):
    def test_bytes_cap_exhaustion_fails_specialist_before_step_budget(self):
        # The output-byte pool survives the planner response and the first
        # specialist model turn, but no code read fits any more.  AgentLoop
        # would swallow the tool's budget failure into an error observation;
        # the stepper pre-check must end the loop instead, so the specialist
        # fails with the budget cause and never reaches its step budget.
        scripts = {
            ROLE_PLANNER: [step_final(PLAN_A, PLAN_B)],
            ROLE_MEMORY_LIFETIME: [
                step_tool(
                    "read_code_snippet", path="src/session.cpp",
                    start_line=1, end_line=6,
                ),
                step_final(MEM_A),
            ],
            ROLE_BOUNDS: [step_final(BOUNDS_A)],
            ROLE_INTERPROCEDURAL: [step_final(INTER_A)],
            ROLE_CRITIC: [step_final(MEM_A)],
            ROLE_EVIDENCE: [step_final(MEM_A)],
            ROLE_VERIFIER: [step_final(MEM_A)],
        }
        client = ScriptedClient(
            scripts, bytes_by_role={ROLE_PLANNER: 40, ROLE_MEMORY_LIFETIME: 10},
        )
        coordinator = self.coordinator(
            client, budget=CxxAgentBudget(max_output_bytes=120)
        )
        result = coordinator.review_repository(make_run())

        self.assertEqual([ROLE_PLANNER, ROLE_MEMORY_LIFETIME], client.roles())
        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        self.assertEqual("failed-replaced", outcomes[ROLE_MEMORY_LIFETIME].status)
        self.assertIn(
            "agent tool budget exhausted", outcomes[ROLE_MEMORY_LIFETIME].error
        )
        self.assertNotIn("step budget", outcomes[ROLE_MEMORY_LIFETIME].error)
        self.assertNotIn("time budget", outcomes[ROLE_MEMORY_LIFETIME].error)
        # bounds/interprocedural have empty assignments here: they never call
        # the client whether the global flag reached them before or after
        # their entry check (ok-skip vs failed-replaced-skip race).
        for role in (ROLE_BOUNDS, ROLE_INTERPROCEDURAL):
            self.assertEqual([], client.calls_for(role))
            self.assertNotIn("step budget", outcomes[role].error)
            self.assertNotIn("time budget", outcomes[role].error)
        for role in (ROLE_CRITIC, ROLE_EVIDENCE, ROLE_VERIFIER):
            self.assertEqual("failed-replaced", outcomes[role].status)
            self.assertIn("budget", outcomes[role].error)
        self.assertTrue(result.coverage.candidates_budget_exhausted)
        self.assertEqual(
            sorted(keys_of(ANCHORS[:2])), sorted(keys_of(result.candidates))
        )

    def test_budget_exhaustion_degrades_remaining_roles(self):
        # Every specialist's scripted final covers its whole assignment, so the
        # surviving candidate keys are the full anchor set no matter which of
        # the three parallel specialists wins the last budget call.
        mem_b = make_candidate(
            "src/buffer.c", 10, "make_buffer", "ALPHA-DOUBLE-FREE-TITLE"
        )
        scripts = {
            ROLE_PLANNER: [step_final(PLAN_A, PLAN_B, PLAN_C, PLAN_D)],
            ROLE_MEMORY_LIFETIME: [step_final(MEM_A, mem_b)],
            ROLE_BOUNDS: [step_final(BOUNDS_A)],
            ROLE_INTERPROCEDURAL: [step_final(INTER_A)],
            ROLE_CRITIC: [step_final(MEM_A, mem_b, BOUNDS_A, INTER_A)],
            ROLE_EVIDENCE: [step_final(MEM_A, mem_b, BOUNDS_A, INTER_A)],
            ROLE_VERIFIER: [step_final(MEM_A, mem_b, BOUNDS_A, INTER_A)],
        }
        client = ScriptedClient(scripts)
        coordinator = self.coordinator(client, budget=CxxAgentBudget(max_calls=2))
        result = coordinator.review_repository(make_run())

        roles = client.roles()
        self.assertEqual(ROLE_PLANNER, roles[0])
        self.assertNotIn(ROLE_CRITIC, roles)
        self.assertNotIn(ROLE_EVIDENCE, roles)
        self.assertNotIn(ROLE_VERIFIER, roles)

        outcomes = {outcome.role: outcome for outcome in result.role_outcomes}
        specialist_statuses = [
            outcomes[role].status for role in SPECIALIST_ROLES
        ]
        self.assertEqual(1, specialist_statuses.count("ok"))
        self.assertEqual(2, specialist_statuses.count("failed-replaced"))
        for role in (ROLE_CRITIC, ROLE_EVIDENCE, ROLE_VERIFIER):
            self.assertEqual("failed-replaced", outcomes[role].status)
            self.assertIn("budget", outcomes[role].error)
        self.assertEqual(
            sorted(keys_of(ANCHORS)), sorted(keys_of(result.candidates))
        )
        self.assertTrue(result.coverage.candidates_budget_exhausted)
        self.assertGreater(result.message_count, 0)


class ContractTests(unittest.TestCase):
    def test_role_outcome_validates_role_and_status(self):
        CxxRoleOutcome(ROLE_PLANNER, "ok")
        CxxRoleOutcome(ROLE_MEMORY_LIFETIME, "failed-replaced", error="boom")
        with self.assertRaises(ValueError):
            CxxRoleOutcome("robot", "ok")
        with self.assertRaises(ValueError):
            CxxRoleOutcome(ROLE_PLANNER, "weird")

    def test_review_result_validates_role_order(self):
        def make_result(outcomes):
            return CxxAgentReviewResult(
                candidates=(),
                role_outcomes=tuple(outcomes),
                coverage=CxxAgentCoverage(
                    indexed_files=1,
                    indexed_symbols=1,
                    candidates_generated=0,
                    candidates_budget_exhausted=False,
                    context_files_used=0,
                    context_lines_sent=0,
                    unparsed_regions=(),
                    llm_unavailable=False,
                ),
                snapshot_sha256=SNAPSHOT,
                message_count=0,
            )

        ordered = [
            CxxRoleOutcome(role, "ok")
            for role in (
                ROLE_PLANNER,
                ROLE_MEMORY_LIFETIME,
                ROLE_BOUNDS,
                ROLE_INTERPROCEDURAL,
                ROLE_CRITIC,
                ROLE_EVIDENCE,
                ROLE_VERIFIER,
                ROLE_ARBITER,
            )
        ]
        make_result(ordered)
        with self.assertRaises(ValueError):
            make_result(ordered[:-1])
        with self.assertRaises(ValueError):
            make_result(list(reversed(ordered)))

    def test_coordinator_rejects_invalid_assignment_limit(self):
        with self.assertRaises(ValueError):
            CxxAgentCoordinator(
                ScriptedClient({}), make_index(), FakeReader(),
                max_assignment_candidates=0,
            )


class VerificationStateTests(CoordinatorTestCase):
    """Task 15 RED matrix: six exact verification states.

    Covers the pure state machine (consensus keys, independence, verified-only
    gate) and the deterministic arbiter wiring (tool binding, conflicts,
    Diff-only cap, degraded shells, human confirmation, constant repair ban).
    """

    # ------------------------------------------------------- pure state machine

    def test_candidate_agreement_requires_full_consensus_key_equality(self):
        base = make_claim("src/session.cpp", 6, "Session::read")
        self.assertTrue(candidate_agreement(
            base,
            make_claim(
                "src/session.cpp", 6, "Session::read",
                mechanism="  callback retains an alias\nafter owner deletion ",
            ),
        ))
        for mutated in (
            make_claim("src/session.cpp", 6, "Session::read", cwe="CWE-125"),
            make_claim("src/buffer.c", 6, "Session::read"),
            make_claim("src/session.cpp", 6, "read"),
            make_claim("src/session.cpp", 9, "Session::read"),
            make_claim(
                "src/session.cpp", 6, "Session::read",
                mechanism="double free on the error path",
            ),
            make_claim(
                "src/session.cpp", 6, "Session::read",
                trigger=("entry", "sink"),
            ),
        ):
            self.assertFalse(candidate_agreement(base, mutated))
        # Titles and confidence are not consensus keys: identical claims with a
        # different wording still agree (candidate ids already exclude them).
        self.assertTrue(candidate_agreement(
            base,
            make_claim("src/session.cpp", 6, "Session::read", confidence=0.5),
        ))

    def test_consensus_requires_two_independent_roles(self):
        # I-1 ruling, keep in mind when touching specialist validation:
        # specialist finals are deliberately NOT location-subset-checked.
        # Seed routing is a focus heuristic, not a knowledge boundary; a role
        # that really read code elsewhere (read_paths gate + indexed-path
        # tool checks) may report a location outside its assignment, and a
        # second role's six-key-agreeing claim at that location is exactly
        # the independent corroboration design section 9 requires.  Adding a
        # location-subset check to specialists would make cross-role
        # consensus architecturally unreachable.
        claim = make_claim("src/session.cpp", 6, "Session::read")

        same_role = agent_consensus_state({
            "memory-lifetime": [claim, claim],
        })
        self.assertEqual("llm-candidate", same_role[claim.candidate_id].state)
        self.assertEqual(("memory-lifetime",), same_role[claim.candidate_id].supporting_roles)

        two_roles = agent_consensus_state({
            "memory-lifetime": [claim],
            "bounds": [make_claim("src/session.cpp", 6, "Session::read")],
        })
        verdict = two_roles[claim.candidate_id]
        self.assertEqual("agent-corroborated", verdict.state)
        self.assertEqual(("bounds", "memory-lifetime"), verdict.supporting_roles)
        self.assertEqual(tuple(sorted(AGENT_CONSENSUS_KEYS)), verdict.agreement_keys)
        self.assertTrue(set(VERIFIED_STATES) <= CXX_AGENT_VERIFICATION_STATES)

    def test_degraded_shells_never_form_or_join_consensus(self):
        claim = make_claim("src/session.cpp", 6, "Session::read")
        shell = make_shell_candidate("src/session.cpp", 6, "Session::read")

        twin_shells = agent_consensus_state({
            "memory-lifetime": [shell],
            "bounds": [make_shell_candidate("src/session.cpp", 6, "Session::read")],
        })
        self.assertEqual("needs-human-review", twin_shells[shell.candidate_id].state)
        self.assertEqual((), twin_shells[shell.candidate_id].supporting_roles)

        mixed = agent_consensus_state({
            "memory-lifetime": [claim],
            "bounds": [shell],
        })
        self.assertEqual("llm-candidate", mixed[claim.candidate_id].state)
        self.assertEqual("needs-human-review", mixed[shell.candidate_id].state)

    def test_verified_only_gate_accepts_exactly_the_four_verified_states(self):
        states = (
            "llm-candidate",
            "agent-corroborated",
            "tool-corroborated",
            "runtime-confirmed",
            "human-confirmed",
            "needs-human-review",
        )
        stated = tuple(
            replace(
                make_claim(f"src/s{index}.cpp", 1, f"sym{index}", mechanism=f"m{index}"),
                verification_state=state,
            )
            for index, state in enumerate(states)
        )
        accepted, rejected = verified_only_gate(stated)

        self.assertEqual(
            ["agent-corroborated", "tool-corroborated", "runtime-confirmed", "human-confirmed"],
            [item.verification_state for item in accepted],
        )
        self.assertEqual(
            tuple(sorted(
                accepted,
                key=lambda item: (item.path, item.line, item.symbol, item.candidate_id),
            )),
            accepted,
        )
        self.assertEqual(
            ["llm-candidate", "needs-human-review"],
            [item.verification_state for item in rejected],
        )
        self.assertEqual(((), ()), verified_only_gate(()))

    def test_agent_finding_payload_never_allows_automatic_repair(self):
        for state in sorted(CXX_AGENT_VERIFICATION_STATES):
            candidate = replace(MEM_A, verification_state=state)
            payload = to_agent_finding_payload(candidate)
            self.assertIs(False, payload["automatic_repair"], state)

    # ------------------------------------------------------- arbiter wiring

    def test_single_agent_candidate_stays_llm_candidate_and_misses_gate(self):
        client, result = self.run_happy()

        self.assertEqual((MEM_A,), result.candidates)
        self.assertEqual("llm-candidate", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "llm-candidate"),), result.verification_states
        )
        self.assertEqual((), result.verified_only)

    def test_same_cwe_different_mechanism_never_corroborates(self):
        variant = make_claim(
            "src/session.cpp", 6, "Session::read",
            mechanism="double free on the error path", confidence=0.7,
        )
        self.assertFalse(candidate_agreement(MEM_A, variant))
        scripts = {
            **happy_scripts(),
            ROLE_BOUNDS: [step_final(variant)],
            ROLE_CRITIC: [step_final(MEM_A, variant)],
            ROLE_EVIDENCE: [step_final(MEM_A, variant)],
            ROLE_VERIFIER: [step_final(MEM_A, variant)],
        }
        result = self.coordinator(ScriptedClient(scripts)).review_repository(make_run())

        self.assertEqual(1, len(result.candidates))
        self.assertEqual("llm-candidate", result.candidates[0].verification_state)
        self.assertEqual((), result.verified_only)

    def test_full_independent_agreement_enters_verified_gate(self):
        # See the I-1 note on test_consensus_requires_two_independent_roles:
        # bounds returning a candidate at memory-lifetime's routed location is
        # the legitimate cross-role independent-discovery channel, not a bug.
        corroboration = make_candidate(
            "src/session.cpp", 6, "Session::read", "ALPHA-UAF-TITLE"
        )
        self.assertEqual(MEM_A.candidate_id, corroboration.candidate_id)
        scripts = {
            **happy_scripts(),
            ROLE_BOUNDS: [step_final(corroboration)],
            ROLE_CRITIC: [step_final(MEM_A)],
            ROLE_EVIDENCE: [step_final(MEM_A)],
            ROLE_VERIFIER: [step_final(MEM_A)],
        }
        result = self.coordinator(ScriptedClient(scripts)).review_repository(make_run())

        self.assertEqual(1, len(result.candidates))
        self.assertEqual("agent-corroborated", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "agent-corroborated"),), result.verification_states
        )
        self.assertEqual(1, len(result.verified_only))
        self.assertEqual(
            "agent-corroborated", result.verified_only[0].verification_state
        )

    def test_semgrep_and_clang_identity_hits_yield_tool_corroborated(self):
        for source in ("semgrep", "clang"):
            with self.subTest(source=source):
                analysis = make_analysis(
                    [tool_finding(source, run_id=f"run-{source}-1")],
                    [tool_run(f"run-{source}-1", source)],
                )
                result = self.coordinator(
                    ScriptedClient(happy_scripts()), tool_analysis=analysis
                ).review_repository(make_run())

                self.assertEqual(
                    "tool-corroborated", result.candidates[0].verification_state
                )
                self.assertEqual(
                    ((MEM_A.candidate_id, "tool-corroborated"),),
                    result.verification_states,
                )
                self.assertEqual(1, len(result.verified_only))

    def test_asan_exact_run_yields_runtime_confirmed(self):
        analysis = make_analysis(
            [tool_finding("asan", run_id="run-asan-1")],
            [tool_run("run-asan-1", "asan-test")],
        )
        result = self.coordinator(
            ScriptedClient(happy_scripts()), tool_analysis=analysis
        ).review_repository(make_run())

        self.assertEqual("runtime-confirmed", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "runtime-confirmed"),), result.verification_states
        )
        self.assertEqual(1, len(result.verified_only))

    def test_evidence_conflict_forces_needs_human_review(self):
        analysis = make_analysis(
            [
                tool_finding("semgrep", run_id="run-semgrep-1"),
                tool_finding("clang", cwe="CWE-125", run_id="run-clang-1"),
            ],
            [tool_run("run-semgrep-1", "semgrep"), tool_run("run-clang-1", "clang")],
        )
        result = self.coordinator(
            ScriptedClient(happy_scripts()), tool_analysis=analysis
        ).review_repository(make_run())

        self.assertEqual("needs-human-review", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "needs-human-review"),), result.verification_states
        )
        self.assertEqual((), result.verified_only)

    def test_asan_hit_without_completed_run_is_unsafe_binding(self):
        for label, runs in (
            ("failed-run", [tool_run("run-asan-1", "asan-test", status="failed")]),
            ("missing-run", []),
        ):
            with self.subTest(label=label):
                analysis = make_analysis(
                    [tool_finding("asan", run_id="run-asan-1")], runs
                )
                result = self.coordinator(
                    ScriptedClient(happy_scripts()), tool_analysis=analysis
                ).review_repository(make_run())

                self.assertEqual(
                    "needs-human-review", result.candidates[0].verification_state
                )
                self.assertEqual((), result.verified_only)

    def test_diff_only_caps_every_state_at_llm_candidate(self):
        corroboration = make_candidate(
            "src/session.cpp", 6, "Session::read", "ALPHA-UAF-TITLE"
        )
        scripts = {
            **happy_scripts(),
            ROLE_BOUNDS: [step_final(corroboration)],
            ROLE_CRITIC: [step_final(MEM_A)],
            ROLE_EVIDENCE: [step_final(MEM_A)],
            ROLE_VERIFIER: [step_final(MEM_A)],
        }
        analysis = make_analysis(
            [tool_finding("asan", run_id="run-asan-1")],
            [tool_run("run-asan-1", "asan-test")],
        )
        result = self.coordinator(
            ScriptedClient(scripts),
            tool_analysis=analysis,
            source_mode="diff-only",
        ).review_repository(make_run())

        self.assertEqual("llm-candidate", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "llm-candidate"),), result.verification_states
        )
        self.assertEqual((), result.verified_only)

    def test_conflict_overrides_diff_only_cap(self):
        analysis = make_analysis(
            [
                tool_finding("semgrep", run_id="run-semgrep-1"),
                tool_finding("clang", cwe="CWE-125", run_id="run-clang-1"),
            ],
            [tool_run("run-semgrep-1", "semgrep"), tool_run("run-clang-1", "clang")],
        )
        result = self.coordinator(
            ScriptedClient(happy_scripts()),
            tool_analysis=analysis,
            source_mode="diff-only",
        ).review_repository(make_run())

        self.assertEqual("needs-human-review", result.candidates[0].verification_state)
        self.assertEqual((), result.verified_only)

    def test_human_confirmation_survives_diff_only_cap(self):
        # The operator's confirmation is external authority; the verified-only
        # gate accepts human-confirmed unconditionally, so the Diff-only cap
        # must not silently downgrade it (I-2 ruling).
        result = self.coordinator(
            ScriptedClient(happy_scripts()),
            source_mode="diff-only",
            human_confirmed_ids=frozenset({MEM_A.candidate_id}),
        ).review_repository(make_run())

        self.assertEqual("human-confirmed", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "human-confirmed"),), result.verification_states
        )
        self.assertEqual(1, len(result.verified_only))

    def test_human_confirmed_ids_enter_verified_gate(self):
        result = self.coordinator(
            ScriptedClient(happy_scripts()),
            human_confirmed_ids=frozenset({MEM_A.candidate_id}),
        ).review_repository(make_run())

        self.assertEqual("human-confirmed", result.candidates[0].verification_state)
        self.assertEqual(
            ((MEM_A.candidate_id, "human-confirmed"),), result.verification_states
        )
        self.assertEqual(1, len(result.verified_only))

    def test_degraded_shells_stay_needs_human_review_under_tool_evidence(self):
        shell_session = make_shell_candidate("src/session.cpp", 6, "Session::read")
        shell_buffer = make_shell_candidate("src/buffer.c", 10, "make_buffer")
        scripts = {
            **happy_scripts(),
            ROLE_MEMORY_LIFETIME: [RuntimeError("m1"), RuntimeError("m2")],
            ROLE_CRITIC: [step_final(shell_session, shell_buffer)],
            ROLE_EVIDENCE: [step_final(shell_session, shell_buffer)],
            ROLE_VERIFIER: [step_final(shell_session, shell_buffer)],
        }
        analysis = make_analysis(
            [tool_finding("semgrep", run_id="run-semgrep-1")],
            [tool_run("run-semgrep-1", "semgrep")],
        )
        result = self.coordinator(
            ScriptedClient(scripts), tool_analysis=analysis
        ).review_repository(make_run())

        self.assertEqual(2, len(result.candidates))
        for candidate in result.candidates:
            self.assertEqual("unreviewed", candidate.cwe)
            self.assertEqual("needs-human-review", candidate.verification_state)
        self.assertEqual((), result.verified_only)

    def test_evidence_strength_priority_over_consensus(self):
        corroboration = make_candidate(
            "src/session.cpp", 6, "Session::read", "ALPHA-UAF-TITLE"
        )
        scripts = {
            **happy_scripts(),
            ROLE_BOUNDS: [step_final(corroboration)],
            ROLE_CRITIC: [step_final(MEM_A)],
            ROLE_EVIDENCE: [step_final(MEM_A)],
            ROLE_VERIFIER: [step_final(MEM_A)],
        }
        semgrep = make_analysis(
            [tool_finding("semgrep", run_id="run-semgrep-1")],
            [tool_run("run-semgrep-1", "semgrep")],
        )
        tool_result = self.coordinator(
            ScriptedClient(scripts), tool_analysis=semgrep
        ).review_repository(make_run())
        self.assertEqual("tool-corroborated", tool_result.candidates[0].verification_state)

        asan = make_analysis(
            [tool_finding("asan", run_id="run-asan-1")],
            [tool_run("run-asan-1", "asan-test")],
        )
        runtime_result = self.coordinator(
            ScriptedClient(scripts), tool_analysis=asan
        ).review_repository(make_run())
        self.assertEqual(
            "runtime-confirmed", runtime_result.candidates[0].verification_state
        )

    def test_unknown_source_mode_is_rejected(self):
        with self.assertRaises(ValueError):
            self.coordinator(ScriptedClient(happy_scripts()), source_mode="offline")

    def test_arbiter_defensively_drops_non_indexed_paths(self):
        # Defense in depth (I-1): all upstream gates only admit indexed
        # paths, so the arbiter must never see one.  Constructed directly
        # here to pin the arbiter's own guard: an out-of-index survivor is
        # dropped and recorded, not silently forwarded.
        coordinator = self.coordinator(ScriptedClient(happy_scripts()))
        final, rejections = coordinator._arbitrate(
            (),
            {},
            (frozenset(), frozenset(), frozenset(), frozenset(), frozenset()),
            (GHOST,),
        )

        self.assertEqual((), final)
        self.assertEqual(
            ("src/ghost.cpp:9:ghost_fn: path-not-indexed:defensive",), rejections
        )

    def test_tool_binding_matches_the_final_candidates_deterministically(self):
        analysis = make_analysis(
            [tool_finding("semgrep", run_id="run-semgrep-1")],
            [tool_run("run-semgrep-1", "semgrep")],
        )
        result = self.coordinator(
            ScriptedClient(happy_scripts()), tool_analysis=analysis
        ).review_repository(make_run())
        binding = bind_tool_evidence(result.candidates, analysis)

        self.assertEqual([MEM_A.candidate_id], sorted(binding))
        corroboration = binding[MEM_A.candidate_id]
        self.assertEqual("tool-corroborated", corroboration.state)
        self.assertEqual(("run-semgrep-1",), corroboration.tool_run_ids)
        self.assertFalse(corroboration.conflict)
        self.assertEqual(1, len(corroboration.matched))
        self.assertEqual(
            bind_tool_evidence(result.candidates, analysis), binding
        )


if __name__ == "__main__":
    unittest.main()
