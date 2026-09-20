"""Agent-first hypothesis-experiment-revision orchestration tests (plan Task 4).

Design sections 6/10/12 (``docs/superpowers/specs/2026-09-12-agent-vuln-platform-
design.md``).  Zero network: the scout transport is patched over
``lima.agent_scout.post_chat_completion_text``, the Specialist/Critic transport
over ``lima.uaf_llm_branch.post_chat_completion_text`` (the platform reuses the
preserved semantic wire path), the Sidecar is a fake ``analyze_uaf_facts``
client and the reproduction workbench is a scripted ``run_experiment`` double.
Red lines pinned here:

- The loop is the detection subject: Specialist hypothesis -> sandbox ASan
  experiment -> Critic-guided revision -> evidence arbitrated by the frozen
  :func:`arbiter_state` (runtime-confirmed > tool/fact > semantic > abstain,
  conflicts -> needs-human-review).
- ``runtime-confirmed`` is reachable only through an executed ASan experiment
  that hit the hypothesized bug class; anything less caps at
  ``semantic-supported`` (FP discipline) or abstains.
- Specialists run with no proof gate: the P1-P7 engine is a consultable
  instrument (PASS/REFUTED become evidence), never a precondition.
- Diff-only source mode never runs sandbox experiments and never confirms.
- Modes: ``off`` is a no-op, ``auto`` degrades honestly, ``required`` fails
  the task on LLM failures -- an experiment failure is information, not a
  task failure.
- The retired v2 proof-first orchestration has no production wiring: the
  scanner runs the single agent chain (source-level assertion) and the
  UNKNOWN-only gate is gone from the semantic branch.
"""

import inspect
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from lima.agent_repro_tools import ExperimentObservation, _observation_from_response
from lima.agent_scout import ScoutLead
from lima.cxx_agent_models import CxxAgentCandidate
from lima.cxx_agent_tools import CxxAgentBudget
from lima.cxx_memory import (
    CxxAnalysisResult,
    ReproResponse,
    UafFactsResponse,
    uaf_facts_bundle_sha256,
)
from lima.repository_scanner import RepositoryScanner
from lima.reviewer import LLMTransportError
from lima.uaf_llm_branch import (
    CRITIC_ROLE,
    SPECIALIST_ROLE,
    SemanticBranchOutcome,
    run_semantic_branch,
)
from lima.uaf_models import CandidateIdentity
from lima.uaf_orchestrator import UAF_FINDING_STATES, UAF_STATE_CONFIDENCE
from lima.workspace import RepositoryWorkspace

try:  # platform module under test (RED until implemented)
    from lima.agent_orchestrator import (
        PlatformFormatError,
        _experiment_hit,
        _platform_round,
        _repro_driver_relative_path,
        parse_hypothesis_reply,
        run_platform_review,
    )
except ImportError:  # pragma: no cover - RED phase
    run_platform_review = None

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

LEAD = ScoutLead(
    lead_id="lead-001",
    path=UNIT,
    line=30,
    summary="release of p at line 20 precedes the use at line 30",
    seed="uaf-release-event",
    score=0,
)


def _fid(number: int) -> str:
    return format(number, "064x")


ALLOC = _fid(1)
RELEASE = _fid(2)
USE = _fid(3)
REBIND = _fid(4)


# ------------------------------------------------------------------ wire


def _wire_fact(kind, fact_id, line, *, unit=UNIT, related=None):
    fact = {
        "fact_id": fact_id,
        "kind": kind,
        "translation_unit": unit,
        "canonical_path": unit,
        "function_usr": USR,
        "source_range": [line, line],
        "cfg_block": 0,
    }
    if kind == "allocation":
        fact["allocation_api"] = "malloc"
        fact["pointer_id"] = "p"
    elif kind == "release":
        fact["release_api"] = "free"
        fact["pointer_id"] = "p"
        fact["related_fact_ids"] = list(related or ())
    elif kind == "dereference":
        fact["pointer_id"] = "p"
    elif kind == "rebind":
        fact["pointer_id"] = "p"
        fact["source_pointer_id"] = "n"
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
        _wire_fact("rebind", REBIND, 25, related=(ALLOC,)),
    ]


def _unit_entry(facts, *, cfg_complete=True):
    return {
        "translation_unit": UNIT,
        "extraction": "completed",
        "build_context": {
            "status": "resolved",
            "source_kind": "repository-compdb",
            "context_hash": CONTEXT,
            "diagnostics": [],
        },
        "coverage": {
            "ast_complete": True,
            "cfg_complete": cfg_complete,
            "semantic_gaps": [],
        },
        "facts": list(facts),
    }


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
    """Offline ``analyze_uaf_facts`` stand-in serving one canned bundle."""

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
        raise AssertionError("the platform must not call the LLM here")


class DeadTransport:
    """Provider transport that always fails."""

    def __init__(self):
        self.calls = 0

    def __call__(self, *args, **kwargs):
        self.calls += 1
        raise LLMTransportError("provider unreachable")


def scout_target_transport(requests):
    """Escalate every reviewed lead as a scout target."""

    def transport(provider, base_url, api_key, payload, timeout,
                  extra_headers=None, max_bytes=None):
        requests.append(payload)
        user = payload["messages"][1]["content"]
        lead_id = next(
            line.split(": ", 1)[1]
            for line in user.splitlines()
            if line.startswith("- lead_id: ")
        )
        return json.dumps([{
            "lead_id": lead_id,
            "verdict": "target",
            "reason": "release precedes use on the same pointer",
            "confidence": "high",
        }])

    return transport


class ScriptedPlatformTransport:
    """Role-aware Specialist/Critic transport with scripted replies.

    Queues are selected by the role anchor in the system message; items are
    reply text or exception instances raised verbatim.
    """

    def __init__(self, specialist=(), critic=()):
        self.specialist = list(specialist)
        self.critic = list(critic)
        self.calls = []
        self.timeouts = []

    @property
    def specialist_calls(self):
        return len([
            payload for payload in self.calls
            if SPECIALIST_ROLE in payload["messages"][0]["content"]
        ])

    @property
    def critic_calls(self):
        return len([
            payload for payload in self.calls
            if CRITIC_ROLE in payload["messages"][0]["content"]
        ])

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append(payload)
        self.timeouts.append(timeout)
        system = payload["messages"][0]["content"]
        if SPECIALIST_ROLE in system:
            queue = self.specialist
        elif CRITIC_ROLE in system:
            queue = self.critic
        else:
            raise AssertionError("platform transport saw an unknown role")
        item = queue.pop(0)
        if isinstance(item, Exception):
            raise item
        # Re-bind scripted replies to the in-context target id, the same
        # authority rule the orchestrator enforces on real replies.
        target_id = ""
        for line in payload["messages"][1]["content"].splitlines():
            if line.startswith("- target_id: "):
                target_id = line.split(": ", 1)[1]
        if target_id and target_id != LEAD.lead_id:
            item = item.replace(f'"{LEAD.lead_id}"', f'"{target_id}"')
        return item


def hypothesis_json(
    target_id=LEAD.lead_id,
    cwe="CWE-416",
    driver="int main() { return 0; }",
    hypothesis="the pointer p is used after free(p) at line 30",
    trigger=("free(p)", "return p->value"),
    design="compile src/a.cpp with the driver and run under ASan",
    assumptions=(),
):
    return json.dumps({
        "target_id": target_id,
        "hypothesis": hypothesis,
        "trigger_path": list(trigger),
        "cwe": cwe,
        "driver_code": driver,
        "experiment_design": design,
        "unresolved_assumptions": list(assumptions),
    })


def critic_json(
    target_id=LEAD.lead_id,
    assessment="supports-hypothesis",
    rationale="no guard, rebind or lifetime restart survives the evidence",
    revised_driver="",
):
    return json.dumps({
        "target_id": target_id,
        "assessment": assessment,
        "rationale": rationale,
        "revised_driver_code": revised_driver,
    })


# ------------------------------------------------------------- experiments
#
# Every fixture below travels the real ReproResponse ->
# ExperimentObservation conversion: the Sidecar contract makes ``ok=False``
# the only possible state for a parsed ASan report, and the faulting
# frame's file carries the identity the hit judgment binds to.


def clean_run():
    return observation_from(
        repro_response(ok=True, exit_code=0, asan_report=None, diagnostics=())
    )


def compile_failure():
    return observation_from(
        repro_response(
            stage="compile",
            asan_report=None,
            diagnostics=("error: unknown type name 'x'",),
        )
    )


def uaf_hit(faulting_line=30):
    report = _asan_report_with_faulting_file(UNIT)
    report["faulting_frame"]["line"] = faulting_line
    report["freed_by_frame"] = {
        "function": "leak", "file": UNIT, "line": 20, "column": 5,
    }
    report["allocated_by_frame"] = {
        "function": "leak", "file": UNIT, "line": 10, "column": 26,
    }
    return observation_from(repro_response(asan_report=report))


def overflow_hit():
    report = _asan_report_with_faulting_file(UNIT)
    report["error_type"] = "heap-buffer-overflow"
    report["access"] = "WRITE"
    report["faulting_frame"]["line"] = 30
    report["allocated_by_frame"] = {
        "function": "leak", "file": UNIT, "line": 10, "column": 26,
    }
    return observation_from(repro_response(asan_report=report))


# ---------------------------------------------- real-chain repro fixtures

_DEFAULT_DRIVER = "int main() { return 0; }"


def _asan_report_with_faulting_file(file):
    """A wire-shaped ASan report whose faulting frame sits in ``file``."""

    return {
        "error_type": "heap-use-after-free",
        "access": "READ",
        "access_size": 4,
        "faulting_frame": {
            "function": "leak", "file": file, "line": 30, "column": 21,
        },
        "freed_by_frame": None,
        "allocated_by_frame": None,
        "raw_report_sha256": "f" * 64,
    }


def repro_response(**changes) -> ReproResponse:
    """A contract-shaped ``/v1/repro`` response over the real wire dict."""

    fields = {
        "request_id": "00000000-0000-0000-0000-0000000000f1",
        "snapshot_sha256": SNAPSHOT,
        "stage": "run",
        "ok": False,
        "exit_code": 1,
        "asan_report": {
            "error_type": "heap-use-after-free",
            "access": "READ",
            "access_size": 4,
            "faulting_frame": {
                "function": "leak", "file": UNIT, "line": 30, "column": 21,
            },
            "freed_by_frame": {
                "function": "leak", "file": UNIT, "line": 20, "column": 5,
            },
            "allocated_by_frame": {
                "function": "leak", "file": UNIT, "line": 10, "column": 26,
            },
            "raw_report_sha256": "f" * 64,
        },
        "diagnostics": (
            "ERROR: AddressSanitizer: heap-use-after-free on 0x602 ...",
        ),
        "driver_sha256": "1" * 64,
        "binary_sha256": "2" * 64,
        "elapsed_seconds": 0.125,
    }
    fields.update(changes)
    return ReproResponse(**fields)


def observation_from(response: ReproResponse) -> ExperimentObservation:
    """The real ``ReproResponse -> ExperimentObservation`` conversion."""

    return _observation_from_response(response)


def driver_self_crash(driver=_DEFAULT_DRIVER):
    """The PoC driver's own UAF: the target file itself stays safe."""

    return observation_from(
        repro_response(
            asan_report=_asan_report_with_faulting_file(
                _repro_driver_relative_path(driver),
            ),
        )
    )


def unknown_file_crash():
    """A crash in a file that is neither the target nor the driver."""

    return observation_from(
        repro_response(
            asan_report=_asan_report_with_faulting_file("src/other.c"),
        )
    )


class FakeWorkbench:
    """Scripted ``run_experiment`` double recording every driver."""

    def __init__(self, observations):
        self.observations = list(observations)
        self.calls = []

    def run_experiment(
        self, repository_key, snapshot_hash, source_files, driver_code,
    ):
        self.calls.append((
            repository_key, snapshot_hash, tuple(source_files), driver_code,
        ))
        return self.observations.pop(0)


class DeadlineWorkbench:
    """``run_experiment`` double recording the deadline-bounded timeout.

    The orchestrator only passes the ``timeout`` keyword when a deadline is
    active, mirroring the real workbench's optional orchestration ceiling.
    """

    def __init__(self, observations):
        self.observations = list(observations)
        self.timeouts = []

    def run_experiment(
        self, repository_key, snapshot_hash, source_files, driver_code,
        timeout=None,
    ):
        self.timeouts.append(timeout)
        return self.observations.pop(0)


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


def _rmtree(root):
    import shutil

    shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------------------ run helper


def _run(
    *,
    mode="auto",
    llm_config=None,
    llm_transport=None,
    workbench=None,
    analyzer=None,
    leads=(LEAD,),
    snapshot=SNAPSHOT,
    dialogue_rounds=1,
    source_mode="repository",
    budget=None,
    units=(UNIT,),
    timeout=60,
    deadline_seconds=None,
):
    """Run one offline platform review over a temp workspace."""

    root = tempfile.mkdtemp(suffix="-agent-orchestrator")
    workspace = _write_cxx_repo(root)
    scout_requests = []
    run_budget = budget if budget is not None else CxxAgentBudget(
        max_calls=64, max_output_bytes=1_048_576,
    )

    def _review():
        return run_platform_review(
            analyzer,
            workspace,
            repository_key=REPO_KEY,
            snapshot_hash=snapshot,
            translation_units=units,
            mode=mode,
            budget=run_budget,
            llm_config=dict(
                RESOLVED_LLM if llm_config is None else llm_config
            ),
            repro_workbench=workbench,
            leads=leads,
            dialogue_rounds=dialogue_rounds,
            source_mode=source_mode,
            timeout=timeout,
            deadline_seconds=deadline_seconds,
        )

    try:
        with patch(
            "lima.agent_scout.post_chat_completion_text",
            scout_target_transport(scout_requests),
        ):
            if llm_transport is not None:
                with patch(
                    "lima.uaf_llm_branch.post_chat_completion_text",
                    llm_transport,
                ):
                    outcome = _review()
            else:
                outcome = _review()
    finally:
        _rmtree(root)
    return outcome


# ================================================================= tests


class HypothesisExperimentRevisionLoopTests(unittest.TestCase):
    """The core loop: hypothesis -> experiment -> revise -> confirm."""

    def test_hypothesis_experiment_revision_loop_converges(self):
        workbench = FakeWorkbench([clean_run(), uaf_hit()])
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json(driver="int first() { return 0; }")],
            critic=[critic_json(
                assessment="revise-experiment",
                revised_driver="int revised() { FREE_THEN_USE; }",
            )],
        )
        outcome = _run(llm_transport=transport, workbench=workbench)
        self.assertIsNotNone(run_platform_review)
        self.assertEqual(1, len(outcome.targets))
        target = outcome.targets[0]
        self.assertEqual("runtime-confirmed", target.state)
        self.assertIn("runtime-confirmed", UAF_FINDING_STATES)
        self.assertEqual(1, len(outcome.findings))
        self.assertIs(target, outcome.findings[0])
        # Experiment ledger: two rounds, first missed, second hit.
        self.assertEqual(2, len(target.experiment_log))
        self.assertFalse(target.experiment_log[0]["hit"])
        self.assertTrue(target.experiment_log[1]["hit"])
        self.assertEqual(2, len(workbench.calls))
        self.assertNotEqual(
            workbench.calls[0][3], workbench.calls[1][3],
            "the revision must run a different driver",
        )
        self.assertEqual(
            "int revised() { FREE_THEN_USE; }", target.poc_driver_code,
        )
        self.assertEqual("CWE-416", target.cwe)
        self.assertEqual("the pointer p is used after free(p) at line 30",
                         target.hypothesis_reason)
        self.assertIsNone(target.identity)
        # Runtime evidence is bound as an ASan record.
        self.assertTrue(target.evidence_records)
        self.assertTrue(
            any(record.source == "asan" for record in target.evidence_records)
        )
        self.assertEqual(1, transport.specialist_calls)
        self.assertEqual(1, transport.critic_calls)
        self.assertEqual(1, outcome.stats.specialist_calls)
        self.assertEqual(1, outcome.stats.critic_calls)
        self.assertEqual(1, outcome.stats.scout_calls)


class RuntimeEvidenceDisciplineTests(unittest.TestCase):
    """runtime-confirmed is reachable only through executed ASan evidence."""

    def test_runtime_confirmed_requires_executed_asan_evidence(self):
        scripts = [hypothesis_json()]
        critics = [critic_json()]
        # (a) experiment executed clean (no ASan report): no confirmation.
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(scripts, critics),
            workbench=FakeWorkbench([clean_run()]),
        )
        self.assertEqual("semantic-supported", outcome.targets[0].state)
        self.assertEqual("semantic-supported", outcome.findings[0].state)
        # (b) experiment transport failed: no confirmation either.
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(scripts, critics),
            workbench=FakeWorkbench([ExperimentObservation(
                ok=False, stage="transport-failed", exit_code=None,
                error_type=None, faulting_line=None, freed_line=None,
                allocated_line=None,
                diagnostics=("transport-failed: provider down",),
                raw_tail="",
            )]),
        )
        self.assertEqual("semantic-supported", outcome.targets[0].state)
        # (c) executed but hit a different bug class than hypothesized:
        # the ASan evidence does not confirm this hypothesis.
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(scripts, critics),
            workbench=FakeWorkbench([overflow_hit()]),
        )
        self.assertNotEqual("runtime-confirmed", outcome.targets[0].state)
        self.assertEqual("semantic-supported", outcome.targets[0].state)
        for outcome_item in (outcome.targets[0],):
            self.assertFalse(
                any(
                    record.kind == "runtime" and record.source == "asan"
                    for record in outcome_item.evidence_records
                ),
                "no runtime evidence without an executed matching ASan hit",
            )


class RealChainHitContractTests(unittest.TestCase):
    """Hits are judged only on protocol-possible observations (P1 fixes).

    The Sidecar contract defines ``ok`` as "the tested binary exited
    cleanly", so a parsed ASan report forces ``ok=False``; execution is
    proven by the ``run`` stage plus the report itself.  Identity binding:
    the faulting frame must land in the Scout target file -- a crash inside
    the model-generated driver, or in a file that is neither target nor
    driver, must never confirm the target.
    """

    def _hit(self, observation, cwe="CWE-416", target_path=UNIT):
        return _experiment_hit(
            observation, cwe,
            target_path=target_path,
            driver_paths=(_repro_driver_relative_path(_DEFAULT_DRIVER),),
        )

    def test_real_asan_report_hits_target(self):
        observation = observation_from(repro_response())
        # The protocol shape: a parsed ASan report forces ok=False.
        self.assertIs(False, observation.ok)
        self.assertEqual("run", observation.stage)
        self.assertEqual("'heap-use-after-free'", observation.error_type)
        self.assertEqual(f"'{UNIT}'", observation.faulting_file)
        self.assertEqual("'leak'", observation.faulting_function)
        self.assertTrue(self._hit(observation))
        # ASan may spell the frame file absolutely or bare: the binding is
        # a normalized suffix match ("session.c" binds "src/session.c").
        for file in (f"/srv/snapshot/{UNIT}", UNIT.rsplit("/", 1)[-1]):
            with self.subTest(faulting_file=file):
                self.assertTrue(self._hit(
                    observation_from(
                        repro_response(
                            asan_report=_asan_report_with_faulting_file(file),
                        )
                    )
                ))

    def test_clean_run_does_not_hit(self):
        observation = observation_from(
            repro_response(ok=True, exit_code=0, asan_report=None, diagnostics=())
        )
        self.assertIs(True, observation.ok)
        self.assertIsNone(observation.error_type)
        self.assertIsNone(observation.faulting_file)
        self.assertFalse(self._hit(observation))

    def test_compile_failure_does_not_hit(self):
        observation = observation_from(
            repro_response(
                stage="compile",
                asan_report=None,
                diagnostics=("driver.cpp:1:1: error: unknown type name 'x'",),
            )
        )
        self.assertEqual("compile", observation.stage)
        self.assertIs(False, observation.ok)
        self.assertFalse(self._hit(observation))

    def test_driver_self_crash_does_not_hit(self):
        staged = _repro_driver_relative_path(_DEFAULT_DRIVER)
        observation = driver_self_crash()
        self.assertEqual(f"'{staged}'", observation.faulting_file)
        self.assertFalse(
            self._hit(observation),
            "a crash inside the PoC driver must not confirm the target",
        )

    def test_unknown_file_crash_does_not_hit(self):
        observation = unknown_file_crash()
        self.assertEqual("'src/other.c'", observation.faulting_file)
        self.assertFalse(
            self._hit(observation),
            "a crash in a file that is neither target nor driver must be "
            "refused, not guessed at",
        )

    def test_unbound_caller_never_hits(self):
        # Without a target to bind to, no hit may be judged.
        self.assertFalse(
            _experiment_hit(observation_from(repro_response()), "CWE-416")
        )

    def test_frame_without_file_never_hits(self):
        report = _asan_report_with_faulting_file(UNIT)
        report["faulting_frame"] = None  # no symbolized frame at all
        observation = observation_from(repro_response(asan_report=report))
        self.assertIsNone(observation.faulting_file)
        self.assertFalse(self._hit(observation))

    def test_driver_self_crash_never_confirms_end_to_end(self):
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([driver_self_crash()]),
        )
        target = outcome.targets[0]
        self.assertFalse(target.experiment_log[0]["hit"])
        self.assertEqual("semantic-supported", target.state)
        self.assertFalse(any(
            record.kind == "runtime" and record.source == "asan"
            for record in target.evidence_records
        ))

    def test_unknown_file_crash_never_confirms_end_to_end(self):
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([unknown_file_crash()]),
        )
        target = outcome.targets[0]
        self.assertFalse(target.experiment_log[0]["hit"])
        self.assertNotEqual("runtime-confirmed", target.state)
        self.assertFalse(any(
            record.kind == "runtime" and record.source == "asan"
            for record in target.evidence_records
        ))


class NoProofGateTests(unittest.TestCase):
    """Specialists run without the retired v2 proof gate."""

    def test_specialists_run_without_proof_gate(self):
        # No analyzer facts at all (analyzer_client=None): the Specialist
        # still runs, no proof artifact exists anywhere in the journey.
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[critic_json()],
        )
        outcome = _run(
            analyzer=None,
            llm_transport=transport,
            workbench=FakeWorkbench([uaf_hit()]),
        )
        self.assertEqual(1, transport.specialist_calls)
        self.assertEqual(1, outcome.stats.specialist_calls)
        target = outcome.targets[0]
        self.assertEqual("", target.proof_verdict)
        self.assertIsNone(target.identity)
        # The experiment hit alone arbitrates: no proof was required first.
        self.assertEqual("runtime-confirmed", target.state)
        self.assertFalse(
            any(item.startswith("proof-") for item in outcome.diagnostics),
            outcome.diagnostics,
        )


class InstrumentConsultTests(unittest.TestCase):
    """The proof engine is a consultable instrument, never a gate."""

    def test_proof_engine_consultable_as_instrument(self):
        # PASS consult + clean experiment + semantic consensus:
        # the deterministic PASS is D2 evidence -> fact-verified.
        analyzer = FakeUafAnalyzer(_payload(_unit_entry(_straight_facts())))
        outcome = _run(
            analyzer=analyzer,
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([clean_run()]),
        )
        target = outcome.targets[0]
        self.assertEqual("fact-verified", target.state)
        self.assertEqual("PASS", target.proof_verdict)
        self.assertIsInstance(target.identity, CandidateIdentity)
        self.assertEqual(SNAPSHOT, target.identity.snapshot_hash)
        self.assertTrue(target.identity.candidate_id)
        self.assertEqual(1, len(outcome.findings))

        # REFUTED consult (rebind counterexample): the candidate is rejected
        # with the refuted obligation in its audit reason, never a finding.
        refuting = FakeUafAnalyzer(
            _payload(_unit_entry(_rebind_facts())),
        )
        outcome = _run(
            analyzer=refuting,
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([clean_run()]),
        )
        target = outcome.targets[0]
        self.assertEqual("rejected", target.state)
        self.assertNotIn(target.state, UAF_FINDING_STATES)
        self.assertEqual((), outcome.findings)
        self.assertEqual("REFUTED", target.proof_verdict)
        self.assertIn("P6", target.rejected_reason)

        # REFUTED consult + a real ASan hit: conflicting strong evidence
        # forces needs-human-review (frozen arbiter rule 1).
        outcome = _run(
            analyzer=refuting,
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([uaf_hit()]),
        )
        self.assertEqual("needs-human-review", outcome.targets[0].state)
        self.assertEqual(1, len(outcome.findings))


class RevisionBoundTests(unittest.TestCase):
    """Revisions are bounded by dialogue_rounds and the agent budget."""

    def test_revision_rounds_bounded_by_dialogue_rounds_and_budget(self):
        revising = critic_json(assessment="revise-experiment",
                               revised_driver="int r() { return 1; }")
        # dialogue_rounds=1: one initial experiment + at most one revision.
        workbench = FakeWorkbench([clean_run(), clean_run()])
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[revising, revising],
        )
        outcome = _run(
            llm_transport=transport, workbench=workbench, dialogue_rounds=1,
        )
        self.assertEqual(2, len(workbench.calls))
        self.assertEqual(1, outcome.stats.critic_calls)
        self.assertEqual(2, len(target_experiments(outcome)))
        # Unrefuted but unproven after the rounds: semantic cap.
        self.assertEqual("semantic-supported", outcome.targets[0].state)

        # dialogue_rounds=2: three experiments, two critic calls.
        workbench = FakeWorkbench([clean_run(), clean_run(), clean_run()])
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[revising, revising],
        )
        outcome = _run(
            llm_transport=transport, workbench=workbench, dialogue_rounds=2,
        )
        self.assertEqual(3, len(workbench.calls))
        self.assertEqual(2, outcome.stats.critic_calls)

        # Budget exhaustion mid-loop (auto): honest abstain, no extra wire
        # calls after the budget died.
        budget = CxxAgentBudget(max_calls=2, max_output_bytes=1_048_576)
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()], critic=[],
        )
        outcome = _run(
            llm_transport=transport,
            workbench=FakeWorkbench([clean_run()]),
            budget=budget,
        )
        self.assertEqual(1, outcome.stats.scout_calls)
        self.assertEqual(1, outcome.stats.specialist_calls)
        # The critic round was charged as attempted but never reached the
        # wire: the budget died before the send.
        self.assertEqual(1, outcome.stats.critic_calls)
        self.assertEqual(0, transport.critic_calls)
        self.assertEqual("abstain", outcome.targets[0].state)
        self.assertEqual((), outcome.findings)
        self.assertTrue(
            any("budget" in item for item in outcome.diagnostics),
            outcome.diagnostics,
        )

        # dialogue_rounds must be a positive integer.
        with self.assertRaises(ValueError):
            _run(
                llm_transport=ScriptedPlatformTransport([], []),
                workbench=FakeWorkbench([]),
                dialogue_rounds=0,
            )


class DeadlineBoundsTests(unittest.TestCase):
    """P2-3.3: the deadline bounds every step, not just the start gates."""

    def test_deadline_bounds_step_timeouts(self):
        # Base timeout far above the deadline: every Specialist/Critic
        # round and every sandbox experiment must receive a timeout no
        # larger than the seconds remaining at that step boundary.
        workbench = DeadlineWorkbench([clean_run(), clean_run()])
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json(driver="int first() { return 0; }")],
            critic=[critic_json(
                assessment="revise-experiment",
                revised_driver="int revised() { FREE_THEN_USE; }",
            )],
        )
        deadline_seconds = 5.0
        outcome = _run(
            llm_transport=transport,
            workbench=workbench,
            timeout=600,
            deadline_seconds=deadline_seconds,
        )
        # The full hypothesis -> experiment -> critic -> experiment chain
        # actually ran, so the assertion below covers both step kinds.
        self.assertEqual(1, outcome.stats.specialist_calls)
        self.assertEqual(1, outcome.stats.critic_calls)
        self.assertEqual(2, outcome.stats.experiment_count)
        self.assertTrue(transport.timeouts)
        for step_timeout in transport.timeouts:
            self.assertGreaterEqual(step_timeout, 1)
            self.assertLessEqual(step_timeout, deadline_seconds)
        self.assertEqual(2, len(workbench.timeouts))
        for step_timeout in workbench.timeouts:
            self.assertIsNotNone(step_timeout)
            self.assertGreaterEqual(step_timeout, 1)
            self.assertLessEqual(step_timeout, deadline_seconds)

        # No deadline: the caller's timeout travels unchanged and no
        # experiment timeout keyword is forced onto the workbench.
        workbench = DeadlineWorkbench([clean_run()])
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()], critic=[critic_json()],
        )
        _run(llm_transport=transport, workbench=workbench, timeout=77)
        self.assertEqual({77}, set(transport.timeouts))
        self.assertEqual([None], workbench.timeouts)


class HardDeadlineAbstainTests(unittest.TestCase):
    """Round 3: a passed deadline forbids the next send, never shrinks it.

    The ``or 1`` idiom turned the helpers' ``None`` ("must not send") into
    a fresh 1-second call; these tests pin the corrected contract.
    """

    def test_no_format_repair_after_deadline(self):
        # The reviewer probe: the first reply is malformed and the deadline
        # has already passed -- the repair request must never leave.
        calls = []

        def transport(provider, base_url, api_key, payload, timeout,
                      extra_headers=None, max_bytes=None):
            calls.append(timeout)
            return "not a platform reply"

        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text", transport,
        ):
            with self.assertRaises(PlatformFormatError) as raised:
                _platform_round(
                    RESOLVED_LLM, "system-prompt", "user-context", 5,
                    CxxAgentBudget(max_calls=4, max_output_bytes=65536),
                    [0], parse_hypothesis_reply, frozenset({LEAD.lead_id}),
                    time.monotonic() - 0.5,
                )
        self.assertEqual([5], calls)
        self.assertIn("deadline", str(raised.exception))

    def test_repair_still_sent_without_deadline(self):
        # Control: no aggregate deadline -> the one allowed repair goes
        # out with the caller's timeout and the round completes.
        calls = []

        def transport(provider, base_url, api_key, payload, timeout,
                      extra_headers=None, max_bytes=None):
            calls.append(timeout)
            if len(calls) == 1:
                return "not a platform reply"
            return hypothesis_json()

        with patch(
            "lima.uaf_llm_branch.post_chat_completion_text", transport,
        ):
            hypothesis = _platform_round(
                RESOLVED_LLM, "system-prompt", "user-context", 5,
                CxxAgentBudget(max_calls=4, max_output_bytes=65536),
                [0], parse_hypothesis_reply, frozenset({LEAD.lead_id}),
            )
        self.assertEqual([5, 5], calls)
        self.assertEqual(LEAD.lead_id, hypothesis.target_id)

    def test_scout_entry_abstains_once_deadline_passes(self):
        # Entry gate passes; by the Scout call the deadline has expired.
        # The Scout must never be invoked and the run degrades to an empty
        # outcome instead of sending a 1-second request.
        fake_time = MagicMock()
        fake_time.monotonic.side_effect = [1000.0, 1000.0, 1010.0]
        root = tempfile.mkdtemp(suffix="-agent-orchestrator")
        try:
            workspace = _write_cxx_repo(root)
            with patch("lima.agent_orchestrator.time", fake_time), patch(
                "lima.agent_scout.post_chat_completion_text", GuardTransport(),
            ):
                outcome = run_platform_review(
                    None,
                    workspace,
                    repository_key=REPO_KEY,
                    snapshot_hash=SNAPSHOT,
                    translation_units=(UNIT,),
                    mode="auto",
                    budget=CxxAgentBudget(max_calls=4, max_output_bytes=65536),
                    llm_config=dict(RESOLVED_LLM),
                    repro_workbench=FakeWorkbench([]),
                    leads=(LEAD,),
                    timeout=60,
                    deadline_seconds=5.0,
                )
        finally:
            _rmtree(root)
        self.assertEqual((), outcome.targets)
        self.assertEqual((), outcome.findings)
        self.assertTrue(
            any(
                "deadline-exceeded before the scout review" in item
                for item in outcome.diagnostics
            ),
            outcome.diagnostics,
        )


class FpDisciplineTests(unittest.TestCase):
    """Without executed evidence the state caps at semantic-supported."""

    def test_fp_discipline_low_confidence_states_without_evidence(self):
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([clean_run()]),
        )
        target = outcome.targets[0]
        self.assertEqual("semantic-supported", target.state)
        self.assertEqual(0.6, UAF_STATE_CONFIDENCE["semantic-supported"])
        self.assertFalse(any(
            record.source == "asan" for record in target.evidence_records
        ))

        # A critic refutation vetoes the hypothesis entirely: abstain,
        # and nothing is projected as a finding.
        outcome = _run(
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()],
                [critic_json(assessment="hypothesis-wrong",
                             rationale="p is reassigned before the use")],
            ),
            workbench=FakeWorkbench([clean_run()]),
        )
        self.assertEqual("abstain", outcome.targets[0].state)
        self.assertEqual((), outcome.findings)


class ModeMatrixTests(unittest.TestCase):
    """off/auto/required semantics for the platform review."""

    def test_mode_matrix(self):
        # off: a no-op with zero wire calls and zero experiments.
        scout = GuardTransport()
        llm = GuardTransport()
        workbench = FakeWorkbench([uaf_hit()])
        root = tempfile.mkdtemp(suffix="-agent-off")
        try:
            workspace = _write_cxx_repo(root)
            with patch(
                "lima.agent_scout.post_chat_completion_text", scout,
            ):
                with patch(
                    "lima.uaf_llm_branch.post_chat_completion_text", llm,
                ):
                    outcome = run_platform_review(
                        None,
                        workspace,
                        repository_key=REPO_KEY,
                        snapshot_hash=SNAPSHOT,
                        translation_units=(UNIT,),
                        mode="off",
                        budget=CxxAgentBudget(),
                        llm_config=dict(RESOLVED_LLM),
                        repro_workbench=workbench,
                        leads=(LEAD,),
                    )
        finally:
            _rmtree(root)
        self.assertEqual((), outcome.findings)
        self.assertEqual((), outcome.targets)
        self.assertEqual([], scout.calls)
        self.assertEqual([], llm.calls)
        self.assertEqual([], workbench.calls)

        # auto + dead provider: honest degradation, abstaining target.
        dead = DeadTransport()
        outcome = _run(llm_transport=dead, workbench=FakeWorkbench([]))
        self.assertEqual("abstain", outcome.targets[0].state)
        self.assertEqual((), outcome.findings)
        self.assertEqual(1, dead.calls)
        self.assertTrue(
            any("llm-unavailable" in item for item in outcome.diagnostics),
            outcome.diagnostics,
        )

        # required + dead provider: the task fails instead of silently
        # skipping the required LLM work.
        with self.assertRaises(RuntimeError):
            _run(
                mode="required",
                llm_transport=DeadTransport(),
                workbench=FakeWorkbench([]),
            )

        # required + failing experiments: experiments are information, not
        # task failures -- the loop completes on the semantic track.
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[critic_json()],
        )
        outcome = _run(
            mode="required",
            llm_transport=transport,
            workbench=FakeWorkbench([compile_failure()]),
        )
        self.assertEqual("semantic-supported", outcome.targets[0].state)
        self.assertEqual("compile", target_experiments(outcome)[0]["stage"])

        # required + unconfigured provider: task failure before any call.
        with self.assertRaises(RuntimeError):
            _run(mode="required", llm_config={}, workbench=FakeWorkbench([]))


class DiffOnlyTests(unittest.TestCase):
    """Diff-only mode never runs experiments and never confirms."""

    def test_diff_only_never_confirmed(self):
        transport = ScriptedPlatformTransport(
            [hypothesis_json()], [critic_json()],
        )
        workbench = FakeWorkbench([uaf_hit()])
        outcome = _run(
            source_mode="diff-only",
            llm_transport=transport,
            workbench=workbench,
        )
        self.assertEqual([], workbench.calls)
        self.assertEqual([], target_experiments(outcome))
        self.assertEqual("semantic-supported", outcome.targets[0].state)

        # Even a PASSing proof instrument cannot promote a diff-only claim.
        analyzer = FakeUafAnalyzer(_payload(_unit_entry(_straight_facts())))
        outcome = _run(
            source_mode="diff-only",
            analyzer=analyzer,
            llm_transport=ScriptedPlatformTransport(
                [hypothesis_json()], [critic_json()],
            ),
            workbench=FakeWorkbench([uaf_hit()]),
        )
        self.assertEqual([], workbench.calls)
        self.assertEqual("semantic-supported", outcome.targets[0].state)
        self.assertEqual("semantic-supported", outcome.findings[0].state)


class ScannerSingleChainTests(unittest.TestCase):
    """The scanner runs exactly one agent chain: the platform branch."""

    def test_scanner_runs_single_agent_chain(self):
        import lima.repository_scanner as scanner_module

        source = inspect.getsource(scanner_module)
        # The v2 proof-first wiring is gone from the scanner module.
        self.assertNotIn("review_uaf", source)
        self.assertNotIn("uaf_v2", source)
        self.assertNotIn("_run_uaf_v2_branch", source)
        # The platform branch is the single agent chain.
        self.assertIn("run_platform_review", source)
        self.assertNotIn("_run_uaf_v2_branch", scanner_module.__dict__)
        scanner = RepositoryScanner(sast_mode="off", dataflow_enabled=False)
        self.assertFalse(hasattr(scanner, "_run_uaf_v2_branch"))
        self.assertTrue(hasattr(scanner, "_run_platform_branch"))

    def test_uaf_proof_first_entrypoint_retired(self):
        # The semantic branch is directly usable: proof is optional and the
        # UNKNOWN-only gate (SemanticBranchOutcome.skipped) is gone.
        signature = inspect.signature(run_semantic_branch)
        self.assertIsNone(signature.parameters["proof"].default)
        self.assertFalse(hasattr(SemanticBranchOutcome, "skipped"))
        # The production scan path no longer references the v2 orchestrator.
        import lima.repository_scanner as scanner_module

        source = inspect.getsource(scanner_module)
        self.assertNotIn("review_uaf", source)
        self.assertNotIn("uaf_v2", source)
        # The retained instruments stay importable for agent consultation.
        from lima.uaf_orchestrator import (  # noqa: F401
            arbiter_state,
            instrument_broker,
            instrument_facts,
            instrument_proof,
        )


class ScannerPlatformBranchTests(unittest.TestCase):
    """Scanner-level platform branch wiring (facts-derived leads)."""

    def test_scanner_platform_branch_projects_findings(self):
        root = tempfile.mkdtemp(suffix="-agent-scanner")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root)
        analyzer = FakeUafAnalyzer(_payload(_unit_entry(_straight_facts())))
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="auto",
            cxx_memory_adapter=analyzer,
            cxx_agent_mode="auto",
            cxx_uaf_llm_factory=lambda: dict(RESOLVED_LLM),
        )
        scout_requests = []
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[critic_json()],
        )
        with patch(
            "lima.agent_scout.post_chat_completion_text",
            scout_target_transport(scout_requests),
        ):
            with patch(
                "lima.uaf_llm_branch.post_chat_completion_text", transport,
            ):
                result = scanner.scan(
                    RepositoryWorkspace(Path(root)),
                    repository_key=REPO_KEY,
                )
        # No workbench is configured (the fake sidecar exposes no
        # repro_compile_run), but the proof instrument consulted the
        # resolved facts bundle: PASS grades the pursued target
        # fact-verified (frozen arbiter rule 3) -- never a runtime claim.
        findings = [
            item for item in result.report.to_dict()["findings"]
            if item["cwe"] == "CWE-416"
        ]
        self.assertEqual(1, len(findings))
        finding = findings[0]
        self.assertEqual("cxx-agent-platform", finding["source"])
        self.assertEqual("fact-verified", finding["verification_state"])
        self.assertEqual("proof", finding["evidence_kind"])
        self.assertEqual(UNIT, finding["path"])
        self.assertEqual(30, finding["line"])
        self.assertFalse(finding["automatic_repair"])
        self.assertAlmostEqual(0.97, finding["confidence"])
        self.assertTrue(finding["explanation"].strip())

        payload = result.report.collaboration["platform"]
        self.assertEqual("auto", payload["mode"])
        self.assertEqual("completed", payload["status"])
        self.assertEqual({"fact-verified": 1}, payload["states"])
        self.assertEqual({}, payload["broker"])
        self.assertEqual(1, payload["stats"]["targets"])
        self.assertEqual(1, payload["stats"]["findings"])
        self.assertEqual(1, payload["stats"]["scout_calls"])
        self.assertGreaterEqual(payload["stats"]["specialist_calls"], 1)
        self.assertEqual(["src/a.cpp"], payload["translation_units"])

        # The retired v2 payload/source names are gone from new reports.
        self.assertNotIn("uaf_v2", result.report.collaboration)
        self.assertEqual(
            [], [item for item in result.report.to_dict()["findings"]
                 if item["source"] == "cxx-uaf-v2"],
        )

    def test_scanner_platform_branch_without_llm_degrades(self):
        root = tempfile.mkdtemp(suffix="-agent-scanner-bare")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root)
        analyzer = FakeUafAnalyzer(_payload(_unit_entry(_straight_facts())))
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="auto",
            cxx_memory_adapter=analyzer,
            cxx_agent_mode="auto",
        )
        result = scanner.scan(RepositoryWorkspace(Path(root)))
        payload = result.report.collaboration["platform"]
        self.assertEqual("llm-not-configured", payload["status"])
        self.assertEqual(
            [], [item for item in result.report.to_dict()["findings"]
                 if item["cwe"] == "CWE-416"],
        )


class LegacyCwe416IsolationTests(unittest.TestCase):
    """After the v2 retirement the legacy isolation still holds."""

    def test_legacy_cwe416_isolation_unchanged(self):
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
        from lima.cxx_agent_models import LEGACY_AGENT_CWES, SUPPORTED_CWES

        self.assertEqual(
            frozenset({"CWE-787", "CWE-125", "CWE-415"}), LEGACY_AGENT_CWES
        )
        self.assertIn("CWE-416", SUPPORTED_CWES)

        # Layer 2 (projection): a legacy run whose scripted specialist
        # returns a CWE-416 candidate built past the contract still emits
        # no CWE-416 Finding, while the legacy pipeline itself completes.
        from lima.cxx_agents import ROLE_MEMORY_LIFETIME, ROLE_PLANNER
        from lima.cxx_llm import AgentStep

        vuln_c = """#include <stdlib.h>

static char *g_buf = 0;

void leak(void) {
    char *buf = malloc(64);
    free(buf);
    buf[0] = 'a';
}
"""

        def agent_final(candidate):
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

        def direct_cwe_416_candidate():
            return CxxAgentCandidate(
                candidate_id="sha256-" + "4" * 64,
                cwe="CWE-416",
                path="vuln.c",
                line=8,
                symbol="leak",
                title="buf is used after free",
                mechanism="free(buf) releases the buffer before buf[0]",
                trigger_path=("leak", "free", "buf[0]"),
                confidence=0.9,
            )

        root = tempfile.mkdtemp(suffix="-agent-legacy-isolation")
        self.addCleanup(lambda: _rmtree(root))
        workspace = _write_cxx_repo(root, name="vuln.c", content=vuln_c)

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

        unavailable = {
            "translation_unit": "vuln.c",
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
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="auto",
            cxx_memory_adapter=FakeUafAnalyzer(
                payload=_payload(unavailable),
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


def target_experiments(outcome):
    """All experiment log entries across the audited targets."""

    entries = []
    for target in outcome.targets:
        entries.extend(target.experiment_log)
    return entries


if __name__ == "__main__":
    unittest.main()
