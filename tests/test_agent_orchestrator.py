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

try:  # public hit truth shared with pilot replay (RED until Task 1 lands)
    from lima.agent_orchestrator import (
        experiment_matches_target,
        repro_driver_relative_path,
    )
except ImportError:  # pragma: no cover - RED phase
    experiment_matches_target = None

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

    def __init__(self, specialist=(), critic=(), discovery=()):
        self.specialist = list(specialist)
        self.critic = list(critic)
        self.discovery = list(discovery)
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

    @property
    def discovery_calls(self):
        return len([
            payload for payload in self.calls
            if "Discovery agent" in payload["messages"][0]["content"]
        ])

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append(payload)
        self.timeouts.append(timeout)
        system = payload["messages"][0]["content"]
        if "Discovery agent" in system:
            queue = self.discovery
        elif SPECIALIST_ROLE in system:
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


def discovery_json(leads):
    """One scripted Discovery reply: dicts with path/line/summary/function."""

    return json.dumps({"leads": list(leads)})


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


class PublicHitTruthContractTests(unittest.TestCase):
    """The public hit truth the platform loop and pilot replay share."""

    def _match(self, observation, cwe="CWE-416", target_path=UNIT):
        return experiment_matches_target(
            observation, cwe,
            target_path=target_path,
            driver_paths=(repro_driver_relative_path(_DEFAULT_DRIVER),),
        )

    def test_real_uaf_report_matches_target(self):
        observation = observation_from(repro_response())
        # The protocol shape: a parsed ASan report forces ok=False, and the
        # match must survive that.
        self.assertIs(False, observation.ok)
        self.assertEqual("run", observation.stage)
        self.assertTrue(self._match(observation))

    def test_driver_self_crash_never_matches(self):
        self.assertFalse(
            self._match(driver_self_crash()),
            "a crash inside the PoC driver must not match the target",
        )

    def test_unknown_file_never_matches(self):
        self.assertFalse(self._match(unknown_file_crash()))

    def test_cwe_mismatch_never_matches(self):
        observation = observation_from(repro_response())
        self.assertFalse(self._match(observation, cwe="CWE-120"))

    def test_compile_stage_never_matches(self):
        observation = observation_from(
            repro_response(
                stage="compile",
                asan_report=None,
                diagnostics=("driver.cpp:1:1: error: unknown type name 'x'",),
            )
        )
        self.assertEqual("compile", observation.stage)
        self.assertFalse(self._match(observation))

    def test_repro_driver_relative_path_is_public(self):
        self.assertEqual(
            repro_driver_relative_path(_DEFAULT_DRIVER),
            _repro_driver_relative_path(_DEFAULT_DRIVER),
        )
        self.assertTrue(
            repro_driver_relative_path(_DEFAULT_DRIVER).startswith(
                "build/repro_driver_"
            )
        )


class DiscoveryFallbackTests(unittest.TestCase):
    """Facts-instrument abstention hands discovery to the Discovery agent.

    The agent receives exactly the audited translation units (never the
    sought answer), its leads flow through the ordinary Scout review, and
    the lead source is recorded in the outcome diagnostics.
    """

    def test_discovery_lead_runs_the_full_chain(self):
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[critic_json()],
            discovery=[discovery_json([{
                "path": UNIT,
                "line": 0,
                "function": "leak",
                "summary": "shared object freed on a child error path",
            }])],
        )
        outcome = _run(
            llm_transport=transport,
            analyzer=None,
            leads=(),
            workbench=FakeWorkbench([uaf_hit()]),
        )
        self.assertEqual(1, len(outcome.findings))
        self.assertEqual("runtime-confirmed", outcome.targets[0].state)
        self.assertEqual(UNIT, outcome.targets[0].path)
        # The function name resolved mechanically to the definition line.
        self.assertEqual(7, outcome.targets[0].line)
        self.assertTrue(
            any(
                "leads-from-llm-discovery: 1 leads" in note
                for note in outcome.diagnostics
            ),
            outcome.diagnostics,
        )
        self.assertEqual(1, transport.discovery_calls)

    def test_discovery_snippet_lines_cover_the_function(self):
        from lima.agent_orchestrator import _discovery_snippet_lines

        # leak() spans lines 7..31 in UAF_SOURCE; the evidence (free at 20,
        # use at 30) is far past the default +-10 snippet window.
        self.assertEqual(26, _discovery_snippet_lines(UAF_SOURCE, 7, "leak"))
        self.assertEqual(0, _discovery_snippet_lines(UAF_SOURCE, 7, ""))
        # No column-0 closing brace within the bound degrades to a wide
        # fallback rather than a cramped default window.
        self.assertEqual(
            120, _discovery_snippet_lines("int f(void) {\n", 1, "f")
        )

    def test_discovery_abstain_keeps_no_leads_outcome(self):
        transport = ScriptedPlatformTransport(
            discovery=[discovery_json([])],
        )
        outcome = _run(
            llm_transport=transport,
            analyzer=None,
            leads=(),
            workbench=FakeWorkbench([uaf_hit()]),
        )
        self.assertEqual((), outcome.targets)
        self.assertEqual((), outcome.findings)
        self.assertIn("no-leads-available", outcome.diagnostics)
        # The attempt itself is recorded: discovery ran and found nothing.
        self.assertTrue(
            any(
                "leads-from-llm-discovery: 0 leads" in note
                for note in outcome.diagnostics
            ),
            outcome.diagnostics,
        )

    def test_mode_off_never_uses_discovery(self):
        outcome = _run(
            mode="off",
            llm_transport=GuardTransport(),
            analyzer=None,
            leads=(),
        )
        self.assertEqual((), outcome.targets)
        self.assertEqual(("mode-off",), outcome.diagnostics)

    def test_discovery_reply_repair_recovers_a_bad_path(self):
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()],
            critic=[critic_json()],
            discovery=[
                # First reply points outside the audited units: contract
                # failure, repaired once.
                discovery_json([{
                    "path": "src/other.c", "line": 1, "summary": "outside",
                }]),
                discovery_json([{
                    "path": UNIT, "line": 30, "summary": "repaired",
                }]),
            ],
        )
        outcome = _run(
            llm_transport=transport,
            analyzer=None,
            leads=(),
            workbench=FakeWorkbench([uaf_hit()]),
        )
        self.assertEqual("runtime-confirmed", outcome.targets[0].state)
        self.assertEqual(2, transport.discovery_calls)

    def test_split_windows_respect_line_boundaries(self):
        from lima.agent_orchestrator import (
            _DISCOVERY_WINDOW_BYTES,
            _split_windows,
        )

        single = "int f(void) { return 0; }\n" * 5
        self.assertEqual(((single, 1),), _split_windows(single))
        line = "x" * 60 + "\n"  # 61 bytes per line
        big = line * 2000
        windows = _split_windows(big)
        # 49152 // 61 = 805 lines per window boundary.
        self.assertEqual([1, 806, 1611], [start for _, start in windows])
        for text, start in windows:
            self.assertLessEqual(len(text.encode("utf-8")), _DISCOVERY_WINDOW_BYTES)
        self.assertEqual(big, "\n".join(text for text, _ in windows))

    def test_parse_discovery_reply_contract(self):
        from lima.agent_orchestrator import (
            PlatformFormatError,
            _parse_discovery_reply,
            _resolve_discovery_line,
        )

        known = frozenset({UNIT})
        good = _parse_discovery_reply(
            json.dumps({"leads": [
                {"path": UNIT, "line": 0, "summary": "s",
                 "function": "dtdCopy"},
            ]}),
            known,
        )
        self.assertEqual(((UNIT, 0, "s", "dtdCopy"),), good)
        self.assertEqual((), _parse_discovery_reply('{"leads": []}', known))
        bad_replies = (
            "not json",
            "[]",
            json.dumps({"leads": [], "extra": 1}),
            json.dumps({"leads": [{"path": "src/other.c", "line": 5,
                                   "summary": "s"}]}),
            json.dumps({"leads": [{"path": UNIT, "line": -1,
                                   "summary": "s"}]}),
            json.dumps({"leads": [{"path": UNIT, "line": 5}]}),
            json.dumps({"leads": [{"path": UNIT, "summary": "no location"}]}),
            json.dumps({"leads": [
                {"path": UNIT, "line": i + 1, "summary": "s"}
                for i in range(9)
            ]}),
        )
        for reply in bad_replies:
            with self.subTest(reply=reply[:60]):
                with self.assertRaises(PlatformFormatError):
                    _parse_discovery_reply(reply, known)

        # Function names resolve mechanically to the *definition* line;
        # prototypes are skipped and hallucinated approximate lines never
        # win over the function.
        source = (
            "static int poolGrow(STRING_POOL *pool);\n"
            "\n"
            "static int dtdCopy(XML_Parser old, DTD *n, const DTD *o) {\n"
            "  return 1;\n"
            "}\n"
            "\n"
            "static int poolGrow(STRING_POOL *pool) {\n"
            "  return 1;\n"
            "}\n"
        )
        self.assertEqual(
            3, _resolve_discovery_line(source, "dtdCopy", 9999)
        )
        self.assertEqual(
            7, _resolve_discovery_line(source, "poolGrow", 9999)
        )
        # Unknown function falls back to the approximate line, and to
        # None without one.
        self.assertEqual(
            42, _resolve_discovery_line(source, "missing", 42)
        )
        self.assertIsNone(_resolve_discovery_line(source, "missing", 0))
        self.assertIsNone(_resolve_discovery_line(source, "", 0))


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


def target_experiments(outcome):
    """All experiment log entries across the audited targets."""

    entries = []
    for target in outcome.targets:
        entries.extend(target.experiment_log)
    return entries


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

    def test_scanner_has_no_legacy_branch_residue(self):
        """Retirement Task 1: the seven-role chain is gone from the scanner.

        The legacy repository branch, its collaboration payload and its
        finding projection must not exist anywhere on the scanner.
        """
        import lima.repository_scanner as scanner_module

        source = inspect.getsource(scanner_module)
        for residue in (
            "_run_cxx_agent_branch",
            "_cxx_agent_collaboration",
            "_agent_finding",
            "_legacy_all_roles_failed_error",
            "retrieve_repository",
            "LEGACY_AGENT_CWES",
        ):
            self.assertNotIn(residue, source, residue)
        scanner = RepositoryScanner(sast_mode="off", dataflow_enabled=False)
        for residue in (
            "_run_cxx_agent_branch",
            "_cxx_agent_collaboration",
            "_agent_finding",
            "_legacy_all_roles_failed_error",
        ):
            self.assertFalse(hasattr(scanner, residue), residue)

    def test_required_platform_never_succeeds_without_analyzer(self):
        """Review #225: required mode must fail loudly when no sidecar.

        The platform chain consults the sidecar analyzer for facts; with
        the adapter missing (memory=off), a required-mode scan must raise
        instead of returning a successful task with zero agent findings.
        """
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_agent_mode="required",
            cxx_uaf_llm_factory=lambda: {"provider": "openai", "model": "fake"},
        )
        root = tempfile.mkdtemp(suffix="-agent-scanner")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root)
        with self.assertRaisesRegex(RuntimeError, "sidecar adapter"):
            scanner.scan(RepositoryWorkspace(Path(root)))

    def test_auto_platform_without_analyzer_is_honest_skip(self):
        """auto + memory=off: the platform chain records its unavailability."""
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_agent_mode="auto",
            cxx_uaf_llm_factory=lambda: {"provider": "openai", "model": "fake"},
        )
        root = tempfile.mkdtemp(suffix="-agent-scanner")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root)
        result = scanner.scan(RepositoryWorkspace(Path(root)))
        platform = result.report.collaboration.get("platform", {})
        self.assertEqual("auto", platform.get("mode"))
        self.assertEqual("analyzer-not-configured", platform.get("status"))

    def test_platform_collaboration_has_no_cxx_agent_key(self):
        """The scan report drops the legacy collaboration key entirely."""
        from lima.agent_orchestrator import (
            PlatformFinding,
            PlatformReviewOutcome,
            PlatformReviewStats,
        )

        finding = PlatformFinding(
            target_id="lead-0001",
            path="src/example.c",
            line=42,
            symbol="parse_input",
            cwe="CWE-787",
            state="abstain",
            hypothesis_reason="",
            poc_driver_code="",
            experiment_log=(),
            identity=None,
            evidence_records=(),
        )
        outcome = PlatformReviewOutcome(
            findings=(),
            targets=(finding,),
            stats=PlatformReviewStats(1, 1, 0, 0, 0, 0, 1),
            diagnostics=("deadline-exceeded before the platform review started",),
            leads_considered=1,
            translation_units=("src/example.c",),
        )
        scanner = RepositoryScanner(sast_mode="off", dataflow_enabled=False)
        payload = scanner._platform_collaboration(
            "auto", "completed", outcome
        )
        self.assertNotIn("cxx_agent", payload)
        # The legacy collaboration key disappears even on the disabled path.
        disabled = scanner._platform_collaboration(
            "off", "disabled",
            PlatformReviewOutcome(
                findings=(), targets=(), diagnostics=(),
                stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 0),
                leads_considered=0, translation_units=(),
            ),
        )
        self.assertNotIn("cxx_agent", disabled)

    # --- #244（方案 §3.4）：目标审计详情投影 -------------------------------

    @staticmethod
    def _detail_finding(
        target_id="lead-0001", state="runtime-confirmed", hypothesis="释放后再次使用对象",
        poc="int main() { int *p = new int(1); delete p; return *p; }",
        log=({
            "round": 1, "stage": "run", "exit_code": 1,
            "error_type": "heap-use-after-free", "faulting_line": 42,
            "hit": True, "raw_object": {"untrusted": True},
        },),
        **overrides,
    ):
        from lima.agent_orchestrator import PlatformFinding

        fields = {
            "target_id": target_id, "path": "src/a.c", "line": 42,
            "symbol": "parse_input", "cwe": "CWE-416", "state": state,
            "hypothesis_reason": hypothesis, "poc_driver_code": poc,
            "experiment_log": log, "identity": None, "evidence_records": (),
        }
        fields.update(overrides)
        return PlatformFinding(**fields)

    def _detail_collaboration(self, findings, targets):
        from lima.agent_orchestrator import PlatformReviewOutcome, PlatformReviewStats

        outcome = PlatformReviewOutcome(
            findings=findings, targets=targets,
            stats=PlatformReviewStats(
                len(targets), len(targets), len(findings), 0, 0, 0, 0,
            ),
            diagnostics=(), leads_considered=len(targets),
            translation_units=("src/a.c",),
        )
        scanner = RepositoryScanner(sast_mode="off", dataflow_enabled=False)
        return scanner._platform_collaboration("auto", "completed", outcome)

    def test_platform_collaboration_projects_bounded_target_details(self):
        from lima.platform_contracts import privacy_text

        # 10 轮日志 → 只保留最后 8 轮并记录省略；自由文本先脱敏再入报告
        # （含 secret 形态的整体遮盖）；日志仅投影白名单字段。
        log = tuple(
            {"round": round, "stage": "run", "exit_code": 1,
             "error_type": "heap-use-after-free", "faulting_line": 42,
             "hit": True, "raw_object": {"untrusted": True}}
            for round in range(1, 11)
        ) + ({
            # 金丝雀轮：error_type 携带 secret 形态，必须整体遮盖后入报告。
            "round": 11, "stage": "run", "exit_code": 1,
            "error_type": "password = synthetic-secret-canary",
            "faulting_line": 42, "hit": False,
        },)
        raw_hypothesis = "api_key=AKIAIOSFODNN7EXAMPLE 释放后再次读取句柄"
        positive = self._detail_finding(hypothesis=raw_hypothesis, log=log)
        rejected = self._detail_finding(
            target_id="lead-0002", state="rejected", hypothesis="", poc="",
            log=(), rejected_reason="实验未命中",
        )
        payload = self._detail_collaboration(
            (positive,), (positive, rejected),
        )
        first, second = payload["targets"]
        # 摘要顺序与关键字段保持原序原样。
        self.assertEqual("lead-0001", first["target_id"])
        self.assertEqual(11, first["experiments"])
        self.assertEqual("实验未命中", second["rejected_reason"])
        # 假设先过 #94 mask：输出必须等于脱敏结果，secret 原文不得出现。
        self.assertIn("hypothesis_reason", first)
        self.assertEqual(
            privacy_text(raw_hypothesis), first["hypothesis_reason"],
        )
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", first["hypothesis_reason"])
        # PoC 是脱敏后的展示副本。
        self.assertIn("delete p", first["poc_driver_code"])
        # 日志：最后 8 轮、白名单字段；金丝雀轮的 error_type 被遮盖。
        entries = first["experiment_log"]
        self.assertEqual(
            [4, 5, 6, 7, 8, 9, 10, 11], [item["round"] for item in entries],
        )
        self.assertEqual(
            {"round", "stage", "exit_code", "error_type",
             "faulting_line", "hit"},
            set(entries[0]),
        )
        self.assertNotIn(
            "synthetic-secret-canary", json.dumps(payload, ensure_ascii=False),
        )
        self.assertEqual(
            ["experiment_log:older-rounds-omitted"], first["detail_omissions"],
        )
        # 无详情目标也输出空省略数组：缺失≠未发生。
        self.assertEqual([], second["detail_omissions"])

    def test_platform_details_omit_oversized_items_whole(self):
        # 单项超限：整项省略（不截断成不可运行的 PoC），原因可读。
        # 两条都是 #94 放行的自然文本，脱敏后仍超限。
        hypothesis = "释放后再次读取该指针指向的对象，需要人工确认调用链。" * 120
        poc = "The object is released and then read again in the same function. " * 520
        finding = self._detail_finding(hypothesis=hypothesis, poc=poc)
        payload = self._detail_collaboration((finding,), (finding,))
        target = payload["targets"][0]
        self.assertNotIn("hypothesis_reason", target)
        self.assertNotIn("poc_driver_code", target)
        self.assertEqual(
            ["hypothesis_reason:too-large", "poc_driver_code:too-large"],
            target["detail_omissions"],
        )

    def test_platform_details_allocate_positive_findings_first(self):
        # 8 × 32 KiB PoC 恰好耗尽 256 KiB；分配与摘要顺序无关：正向
        # finding 优先、再按 target_id——非正向（即使排最前）与超额的
        # 后续正向目标都整项省略并记录 budget-exhausted。
        base = "The object is released and then read again in the same function. "
        # 9 份 ~30 KiB 的 PoC：含键名/容器的完整编码让 8 份接近预算上限，
        # 第 9 份与非正向目标（即使排最前）都整项省略。
        poc = (base * 600)[:30000]
        positive = tuple(
            self._detail_finding(
                target_id=f"lead-{index:04d}", poc=poc,
                hypothesis="", log=(),
            )
            for index in range(1, 10)  # lead-0001..0009
        )
        rejected = self._detail_finding(
            target_id="lead-0000", state="rejected", poc=poc,
            hypothesis="", log=(),
        )
        payload = self._detail_collaboration(
            positive, (rejected,) + positive,
        )
        targets = {item["target_id"]: item for item in payload["targets"]}
        for index in range(1, 9):
            self.assertIn("poc_driver_code", targets[f"lead-{index:04d}"])
        self.assertNotIn("poc_driver_code", targets["lead-0009"])
        self.assertNotIn("poc_driver_code", targets["lead-0000"])
        self.assertIn(
            "poc_driver_code:budget-exhausted",
            targets["lead-0009"]["detail_omissions"],
        )
        self.assertIn(
            "poc_driver_code:budget-exhausted",
            targets["lead-0000"]["detail_omissions"],
        )

    def test_platform_details_budget_counts_json_escaping(self):
        # 复审问题复现：JSON 转义（\n → \\n、引号、反斜杠）会膨胀实际
        # 报告字节。9 份多行 C 源码——按原始 UTF-8 计量时 9 份全收、
        # 序列化 ~295KiB 无省略提示；按 JSON 编码计量后第 9 份省略。
        # 断言口径是完整 entry 序列化（字段名 + 容器 + 省略说明全部
        # 计入）：详情总计不超 256 KiB 是对物理载荷的事实。
        poc = "int x = 0;\n" * 2500
        positive = tuple(
            self._detail_finding(
                target_id=f"lead-{index:04d}", poc=poc,
                hypothesis="", log=(),
            )
            for index in range(1, 10)
        )
        payload = self._detail_collaboration(positive, positive)
        targets = {item["target_id"]: item for item in payload["targets"]}
        accepted = [
            item for item in payload["targets"] if "poc_driver_code" in item
        ]
        self.assertEqual(8, len(accepted))
        self.assertIn(
            "poc_driver_code:budget-exhausted",
            targets["lead-0009"]["detail_omissions"],
        )
        detail_bytes = sum(
            len(json.dumps(
                {
                    field: item[field]
                    for field in (
                        "hypothesis_reason", "poc_driver_code",
                        "experiment_log", "detail_omissions",
                    )
                    if field in item
                },
                ensure_ascii=False,
            ).encode("utf-8"))
            for item in payload["targets"]
        )
        self.assertLessEqual(detail_bytes, 256 * 1024)

    def test_platform_details_budget_covers_all_omission_overhead(self):
        # 审计复现（P3 续）：前 8 个目标恰好耗尽字段预算后，后 24 个
        # 仍会追加容器与 budget-exhausted 省略说明——这些字节必须由
        # 全量预留兜底，完整详情序列化不得超 256 KiB。
        base = "The object is released and then read again in the same function. "
        poc = (base * 600)[:30000]
        positive = tuple(
            self._detail_finding(
                target_id=f"lead-{index:04d}", poc=poc,
                hypothesis="", log=(),
            )
            for index in range(1, 33)  # 32 个目标（摘要截断上限）
        )
        payload = self._detail_collaboration(positive, positive)
        accepted = [
            item for item in payload["targets"] if "poc_driver_code" in item
        ]
        self.assertEqual(8, len(accepted))
        exhausted = [
            item for item in payload["targets"]
            if "poc_driver_code:budget-exhausted" in item["detail_omissions"]
        ]
        self.assertEqual(24, len(exhausted))
        detail_bytes = sum(
            len(json.dumps(
                {
                    field: item[field]
                    for field in (
                        "hypothesis_reason", "poc_driver_code",
                        "experiment_log", "detail_omissions",
                    )
                    if field in item
                },
                ensure_ascii=False,
            ).encode("utf-8"))
            for item in payload["targets"]
        )
        self.assertLessEqual(detail_bytes, 256 * 1024)

    def test_platform_details_single_item_cap_counts_json_escaping(self):
        # 单项上限同样按编码后字节：原始 22,000B 的密集换行 PoC 编码后
        # 33,002B > 32 KiB，必须整项省略，不得按原始字节放行。
        finding = self._detail_finding(
            poc="a\n" * 11000, hypothesis="", log=(),
        )
        payload = self._detail_collaboration((finding,), (finding,))
        target = payload["targets"][0]
        self.assertNotIn("poc_driver_code", target)
        self.assertEqual(
            ["poc_driver_code:too-large"], target["detail_omissions"],
        )

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

    def test_default_scanner_makes_no_sidecar_calls(self):
        """Review round 3: C/C++ memory analysis is explicit opt-in.

        Scanning a C/C++ repository without an explicit ``cxx_memory_mode``
        must complete with zero sidecar calls -- the adapter raises on any
        use -- and report the chain as disabled (complete rollback).
        """

        root = tempfile.mkdtemp(suffix="-agent-scanner")
        self.addCleanup(lambda: _rmtree(root))
        _write_cxx_repo(root)

        class ExplodingAdapter:
            def analyze(self, *args, **kwargs):  # pragma: no cover - guard
                raise AssertionError("sidecar adapter used with mode off")

        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_adapter=ExplodingAdapter(),
        )
        result = scanner.scan(RepositoryWorkspace(Path(root)))
        cxx_summary = result.report.collaboration.get("cxx_memory", {})
        self.assertEqual("off", cxx_summary.get("mode"))
        self.assertEqual("disabled", cxx_summary.get("status"))

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
