"""Patch suggestion and PoC regression tests (plan Task 8, design section 7).

Zero-network: the shared chat transport is replaced by canned callables
patched over ``lima.agent_patch.post_chat_completion_text`` (the name this
module imports, mirroring ``tests.test_agent_scout`` style) and the sandbox
is replaced by a content-keyed fake pair (``FakePreparer`` stages the
isolated repository copy, ``FakeReproClient`` maps staged-content markers to
scripted ``ReproExecution`` outcomes).  Red lines pinned here:

- a patch is "verified" only when the isolated patched copy compiles AND the
  PoC driver no longer triggers (clean exit, no ASan report) -- never from
  the model's rationale text;
- a PoC that still triggers the same defect, a different defect, a patch
  that does not compile, a noop patch and sanitizer instrument noise are
  distinct honest failures;
- the patch application always happens on an isolated temporary copy; the
  caller's snapshot/repo is never written;
- strict LLM contract: fenced JSON unwrapping, closed two-field shape,
  exactly one format repair, budget charged (call before the wire round
  trip, completion bytes on arrival);
- the flow retries with the rejection diagnostics fed back and converges,
  with ``rounds`` bounding the loop.

``PatchFlowContainerTests`` runs the real chain (real ``prepare_snapshot``
plus real ``run_repro`` with clang-14/ASan) inside the analyzer container;
on host it skips with the same guards as the existing container classes.
"""

import json
import shutil
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from cxx_analyzer.repro import ReproExecution
from lima.agent_patch import (
    GENERATION_FAILED,
    INCONCLUSIVE,
    INSTRUMENT_NOISE,
    PATCH_DOES_NOT_COMPILE,
    PATCH_IS_NOOP,
    POC_DIFFERENT_DEFECT,
    POC_STILL_TRIGGERS,
    PatchFlowOutcome,
    PatchGenerationError,
    PatchProposal,
    generate_patch,
    suggest_patch_flow,
    verify_patch,
)
from lima.cxx_agent_tools import AgentBudgetExceeded, CxxAgentBudget

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "patch_flow"
TARGET_PATH = "vuln_lib.cpp"
VULN_SOURCE = (FIXTURES / "vuln_lib.cpp").read_text(encoding="utf-8")
FIXED_SOURCE = (FIXTURES / "vuln_lib_fixed.cpp").read_text(encoding="utf-8")
DRIVER_SOURCE = (FIXTURES / "driver_uaf.cpp").read_text(encoding="utf-8")
# Different bytes, same defect: must not be mistaken for a noop patch.
UNFIXED_SOURCE = VULN_SOURCE.replace(
    "(vulnerable variant)", "(vulnerable variant, reformatted)"
)
assert UNFIXED_SOURCE != VULN_SOURCE

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

FINDING_SUMMARY = "heap-use-after-free: p is freed at line 8 and read at line 9"
DRIVER_SUMMARY = (
    "the PoC driver calls use_after_free_read() under AddressSanitizer and "
    "currently aborts with heap-use-after-free"
)

_VULN_MARKER = "vulnerable variant"
_FIXED_MARKER = "fixed variant"


def _patch_reply(patched_content, rationale="moved the read before the release"):
    return json.dumps(
        {"patched_content": patched_content, "rationale": rationale},
        sort_keys=True,
    )


def _fenced(reply):
    return "```json\n" + reply + "\n```"


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


class FakeSnapshot:
    """Snapshot stand-in recording the cleanup contract of PreparedSnapshot."""

    def __init__(self, files):
        self.files = tuple(files)
        self.cleaned = False

    def cleanup(self):
        self.cleaned = True


class FakePreparer:
    """Stands in for prepare_snapshot: captures the staged isolated copy."""

    def __init__(self):
        self.staged = []

    def __call__(self, import_root, repository_key, work_root):
        target = Path(import_root) / repository_key / TARGET_PATH
        self.staged.append(target.read_text(encoding="utf-8"))
        return FakeSnapshot((TARGET_PATH,))


def _artifacts():
    return {
        "driver_path": "build/repro_driver_x.cpp",
        "binary_path": "build/repro_bin_x",
        "driver_sha256": "a" * 64,
        "binary_sha256": "",
    }


def _asan_report(error_type):
    return {
        "error_type": error_type,
        "access": "READ",
        "access_size": 4,
        "faulting_frame": {
            "function": "use_after_free_read",
            "file": TARGET_PATH,
            "line": 9,
            "column": 12,
        },
        "freed_by_frame": None,
        "allocated_by_frame": None,
        "raw_report_sha256": "0" * 64,
    }


CLEAN_RUN = ReproExecution(
    stage="run", ok=True, exit_code=0, asan_report=None,
    diagnostics=(), artifacts=_artifacts(), elapsed_seconds=0.0,
)
UAF_RUN = ReproExecution(
    stage="run", ok=False, exit_code=1,
    asan_report=_asan_report("heap-use-after-free"),
    diagnostics=(), artifacts=_artifacts(), elapsed_seconds=0.0,
)
OOB_RUN = ReproExecution(
    stage="run", ok=False, exit_code=1,
    asan_report=_asan_report("heap-buffer-overflow"),
    diagnostics=(), artifacts=_artifacts(), elapsed_seconds=0.0,
)
COMPILE_FAIL = ReproExecution(
    stage="compile", ok=False, exit_code=1, asan_report=None,
    diagnostics=("vuln_lib.cpp:3:5: error: expected ';'",),
    artifacts=_artifacts(), elapsed_seconds=0.0,
)
SEGV_NOISE = ReproExecution(
    stage="run", ok=False, exit_code=-11, asan_report=None,
    diagnostics=("asan-runtime-segv-retried",),
    artifacts=_artifacts(), elapsed_seconds=0.0,
)
TIMEOUT_RUN = ReproExecution(
    stage="run", ok=False, exit_code=None, asan_report=None,
    diagnostics=("repro-step-timed-out",),
    artifacts=_artifacts(), elapsed_seconds=0.0,
)

DEFAULT_RULES = (
    (_FIXED_MARKER, CLEAN_RUN),
    (_VULN_MARKER, UAF_RUN),
)


class FakeReproClient:
    """Content-keyed sandbox stand-in: staged marker -> scripted outcome."""

    def __init__(self, preparer, rules=DEFAULT_RULES):
        self.preparer = preparer
        self.rules = tuple(rules)
        self.calls = []

    def run_repro(self, snapshot, source_files, driver_code, *,
                  timeout_seconds=60):
        self.calls.append({
            "snapshot": snapshot,
            "source_files": tuple(source_files),
            "driver_code": driver_code,
            "timeout_seconds": timeout_seconds,
        })
        content = self.preparer.staged[-1]
        for marker, execution in self.rules:
            if marker in content:
                return execution
        raise AssertionError("no scripted outcome for the staged content")


class GeneratePatchTests(unittest.TestCase):
    """Strict patch-generation contract over canned transports."""

    def _generate(self, transport, budget, source_path=TARGET_PATH,
                  source_code=VULN_SOURCE, revision_notes=""):
        with patch("lima.agent_patch.post_chat_completion_text", transport):
            return generate_patch(
                RESOLVED,
                FINDING_SUMMARY,
                source_path,
                source_code,
                DRIVER_SUMMARY,
                budget,
                60,
                revision_notes=revision_notes,
            )

    def test_generate_patch_parses_llm_reply(self):
        transport = FakeTransport(_fenced(_patch_reply(FIXED_SOURCE)))
        budget = CxxAgentBudget(max_calls=4)
        proposal = self._generate(transport, budget)

        self.assertIsInstance(proposal, PatchProposal)
        self.assertEqual(TARGET_PATH, proposal.target_path)
        self.assertEqual(FIXED_SOURCE, proposal.patched_content)
        self.assertEqual("moved the read before the release", proposal.rationale)

        self.assertEqual(1, len(transport.calls))
        call = transport.calls[0]
        self.assertEqual(PROVIDER, call["provider"])
        self.assertEqual(BASE_URL, call["base_url"])
        self.assertEqual(API_KEY, call["api_key"])
        self.assertEqual(60, call["timeout"])
        self.assertEqual(1_048_576, call["max_bytes"])
        payload = call["payload"]
        self.assertEqual(MODEL, payload["model"])
        self.assertEqual(0, payload["temperature"])
        self.assertEqual({"type": "json_object"}, payload["response_format"])
        system, user = payload["messages"]
        self.assertEqual("system", system["role"])
        self.assertIn("patch engineer", system["content"])
        self.assertIn("patched_content", system["content"])
        self.assertEqual("user", user["role"])
        self.assertIn(FINDING_SUMMARY, user["content"])
        self.assertIn(DRIVER_SUMMARY, user["content"])
        self.assertIn(TARGET_PATH, user["content"])
        self.assertIn(VULN_SOURCE, user["content"])

        remaining = budget.remaining()
        self.assertEqual(3, remaining.calls)
        self.assertEqual(
            len(_fenced(_patch_reply(FIXED_SOURCE)).encode("utf-8")),
            1_048_576 - remaining.bytes_remaining,
        )

    def test_generate_patch_invalid_json_repairs_once_then_fails(self):
        transport = FakeTransport("utter nonsense", "still not json")
        with self.assertRaises(PatchGenerationError) as raised:
            self._generate(transport, CxxAgentBudget(max_calls=8))
        self.assertIn("format repair", str(raised.exception))
        self.assertEqual(2, len(transport.calls))
        repair_messages = transport.calls[1]["payload"]["messages"]
        self.assertEqual(4, len(repair_messages))
        self.assertEqual(
            {"role": "assistant", "content": "utter nonsense"},
            repair_messages[2],
        )
        self.assertEqual("user", repair_messages[3]["role"])
        self.assertIn("not a valid patch", repair_messages[3]["content"])

        # A single repair succeeds when the second reply is compliant.
        transport = FakeTransport("utter nonsense", _patch_reply(FIXED_SOURCE))
        proposal = self._generate(transport, CxxAgentBudget(max_calls=8))
        self.assertEqual(FIXED_SOURCE, proposal.patched_content)
        self.assertEqual(2, len(transport.calls))

    def test_generate_patch_feeds_revision_notes_into_context(self):
        transport = FakeTransport(_patch_reply(FIXED_SOURCE))
        self._generate(
            transport,
            CxxAgentBudget(max_calls=8),
            revision_notes="- poc-still-triggers",
        )
        user = transport.calls[0]["payload"]["messages"][1]
        self.assertIn("poc-still-triggers", user["content"])
        self.assertIn("rejected by the PoC regression", user["content"])

    def test_generate_patch_rejects_bad_arguments_without_wire_call(self):
        transport = FakeTransport()
        with self.assertRaises(ValueError):
            self._generate(transport, CxxAgentBudget(), source_path="../esc.cpp")
        with self.assertRaises(ValueError):
            self._generate(transport, CxxAgentBudget(), source_code="")
        self.assertEqual([], transport.calls)


class VerifyPatchTests(unittest.TestCase):
    """The honest failure states plus the single pass state."""

    def _verify(self, patched_content, *, rules=DEFAULT_RULES,
                expected_asan_type="heap-use-after-free", original=VULN_SOURCE):
        preparer = FakePreparer()
        client = FakeReproClient(preparer, rules)
        verification = verify_patch(
            client,
            PatchProposal(TARGET_PATH, patched_content, "rationale"),
            original,
            DRIVER_SOURCE,
            prepare_snapshot_fn=preparer,
            budget=CxxAgentBudget(),
            expected_asan_type=expected_asan_type,
            timeout=30,
        )
        return verification, preparer, client

    def test_verify_patch_fixed_version_passes(self):
        verification, preparer, client = self._verify(FIXED_SOURCE)

        self.assertIs(True, verification.verified)
        self.assertIs(True, verification.compiles)
        self.assertIs(False, verification.poc_still_triggers)
        self.assertIsNone(verification.asan_type_after)
        self.assertEqual((), verification.diagnostics)
        # The isolated copy received exactly the patched bytes.
        self.assertEqual([FIXED_SOURCE], preparer.staged)
        self.assertEqual(1, len(client.calls))
        self.assertEqual((TARGET_PATH,), client.calls[0]["source_files"])
        self.assertEqual(DRIVER_SOURCE, client.calls[0]["driver_code"])
        self.assertEqual(30, client.calls[0]["timeout_seconds"])
        # The staged snapshot was cleaned up afterwards.
        self.assertIs(True, client.calls[0]["snapshot"].cleaned)

    def test_verify_patch_unfixed_version_fails(self):
        verification, _, _ = self._verify(UNFIXED_SOURCE)

        self.assertIs(False, verification.verified)
        self.assertIs(True, verification.compiles)
        self.assertIs(True, verification.poc_still_triggers)
        self.assertEqual("heap-use-after-free", verification.asan_type_after)
        self.assertEqual((POC_STILL_TRIGGERS,), verification.diagnostics[:1])

    def test_verify_patch_noop_detected(self):
        verification, preparer, client = self._verify(VULN_SOURCE)

        self.assertIs(False, verification.verified)
        self.assertEqual((PATCH_IS_NOOP,), verification.diagnostics)
        self.assertIsNone(verification.compiles)
        self.assertIsNone(verification.poc_still_triggers)
        # A noop never reaches the sandbox: no staging, no experiment.
        self.assertEqual([], preparer.staged)
        self.assertEqual([], client.calls)

    def test_verify_patch_compile_failure_reported(self):
        broken = "// compile-broken\n" + UNFIXED_SOURCE
        verification, _, _ = self._verify(
            broken,
            rules=(("compile-broken", COMPILE_FAIL),) + DEFAULT_RULES,
        )

        self.assertIs(False, verification.verified)
        self.assertIs(False, verification.compiles)
        self.assertIsNone(verification.poc_still_triggers)
        self.assertIsNone(verification.asan_type_after)
        self.assertEqual(
            (PATCH_DOES_NOT_COMPILE, COMPILE_FAIL.diagnostics[0]),
            verification.diagnostics,
        )

    def test_verify_patch_different_defect_reported(self):
        oob = "// oob-variant\n" + UNFIXED_SOURCE
        rules = (("oob-variant", OOB_RUN),) + DEFAULT_RULES
        verification, _, _ = self._verify(
            oob, rules=rules, expected_asan_type="heap-use-after-free"
        )

        self.assertIs(False, verification.verified)
        self.assertIs(True, verification.compiles)
        self.assertIs(True, verification.poc_still_triggers)
        self.assertEqual("heap-buffer-overflow", verification.asan_type_after)
        self.assertEqual((POC_DIFFERENT_DEFECT,), verification.diagnostics[:1])

        # Without a pinned expected type any post-patch report is honestly
        # judged "still triggers" (conservative default).
        conservative, _, _ = self._verify(
            oob, rules=rules, expected_asan_type=None
        )
        self.assertEqual((POC_STILL_TRIGGERS,), conservative.diagnostics[:1])

    def test_verify_patch_instrument_noise_reported(self):
        noisy = "// segv-noise\n" + UNFIXED_SOURCE
        verification, _, _ = self._verify(
            noisy, rules=(("segv-noise", SEGV_NOISE),) + DEFAULT_RULES
        )

        self.assertIs(False, verification.verified)
        self.assertIs(True, verification.compiles)
        self.assertIsNone(verification.poc_still_triggers)
        self.assertEqual(
            (INSTRUMENT_NOISE, "asan-runtime-segv-retried"),
            verification.diagnostics,
        )

    def test_verify_patch_inconclusive_run_reported(self):
        hanging = "// hangs-after-patch\n" + UNFIXED_SOURCE
        verification, _, _ = self._verify(
            hanging,
            rules=(("hangs-after-patch", TIMEOUT_RUN),) + DEFAULT_RULES,
        )

        self.assertIs(False, verification.verified)
        self.assertIs(True, verification.compiles)
        self.assertIsNone(verification.poc_still_triggers)
        self.assertEqual(
            (INCONCLUSIVE, "repro-step-timed-out"), verification.diagnostics
        )

    def test_verify_patch_rejects_bad_arguments(self):
        preparer = FakePreparer()
        client = FakeReproClient(preparer)
        with self.assertRaises(ValueError):
            verify_patch(
                client,
                PatchProposal("../escape.cpp", FIXED_SOURCE, "rationale"),
                VULN_SOURCE,
                DRIVER_SOURCE,
                prepare_snapshot_fn=preparer,
                budget=CxxAgentBudget(),
            )
        with self.assertRaises(ValueError):
            verify_patch(
                client,
                PatchProposal(TARGET_PATH, FIXED_SOURCE, "rationale"),
                VULN_SOURCE,
                "int\x00main() {}\n",
                prepare_snapshot_fn=preparer,
                budget=CxxAgentBudget(),
            )
        # Nothing was staged and no experiment ran for rejected arguments.
        self.assertEqual([], preparer.staged)
        self.assertEqual([], client.calls)


class PatchFlowTests(unittest.TestCase):
    """End-to-end generate -> verify loop over fakes."""

    def _flow(self, transport, *, rounds=2, budget=None,
              expected_asan_type="heap-use-after-free"):
        # The client and the flow's preparer must share the staged copies.
        preparer = FakePreparer()
        client = FakeReproClient(preparer)
        with patch("lima.agent_patch.post_chat_completion_text", transport):
            outcome = suggest_patch_flow(
                RESOLVED,
                client,
                FINDING_SUMMARY,
                TARGET_PATH,
                VULN_SOURCE,
                DRIVER_SOURCE,
                prepare_snapshot_fn=preparer,
                budget=budget or CxxAgentBudget(max_calls=16),
                rounds=rounds,
                timeout=60,
                expected_asan_type=expected_asan_type,
            )
        return outcome, client, preparer

    def test_flow_retries_with_diagnostics_and_converges(self):
        transport = FakeTransport(
            _patch_reply(VULN_SOURCE, "noop reply"),  # round 1: noop patch
            _patch_reply(FIXED_SOURCE),               # round 2: real fix
        )
        outcome, client, preparer = self._flow(transport, rounds=2)

        self.assertIsInstance(outcome, PatchFlowOutcome)
        self.assertIs(True, outcome.verified)
        self.assertEqual(2, outcome.rounds_used)
        self.assertEqual((), outcome.diagnostics)
        self.assertEqual(FIXED_SOURCE, outcome.proposal.patched_content)
        self.assertIs(True, outcome.verification.verified)
        self.assertIs(False, outcome.verification.poc_still_triggers)
        # The rejection diagnostics of round 1 were fed back into round 2.
        self.assertEqual(2, len(transport.calls))
        round_two_user = transport.calls[1]["payload"]["messages"][1]
        self.assertIn(PATCH_IS_NOOP, round_two_user["content"])
        self.assertIn("rejected by the PoC regression", round_two_user["content"])
        # Round 1 was a local noop (no experiment); round 2 ran once.
        self.assertEqual(1, len(client.calls))
        self.assertEqual([FIXED_SOURCE], preparer.staged)

    def test_flow_rounds_bounded(self):
        transport = FakeTransport(_patch_reply(VULN_SOURCE, "noop reply"))
        outcome, _, _ = self._flow(transport, rounds=1)

        self.assertIs(False, outcome.verified)
        self.assertEqual(1, outcome.rounds_used)
        self.assertIsNotNone(outcome.proposal)
        self.assertIsNotNone(outcome.verification)
        self.assertEqual((PATCH_IS_NOOP,), outcome.diagnostics)
        self.assertEqual((PATCH_IS_NOOP,), outcome.verification.diagnostics)
        # Exactly one wire round: the bounded flow did not retry.
        self.assertEqual(1, len(transport.calls))

    def test_flow_generation_failure_reported(self):
        transport = FakeTransport("utter nonsense", "still not json")
        outcome, _, _ = self._flow(transport, rounds=2)

        self.assertIs(False, outcome.verified)
        self.assertIsNone(outcome.proposal)
        self.assertIsNone(outcome.verification)
        self.assertEqual((GENERATION_FAILED,), outcome.diagnostics)
        # Round 1 spent its one repair; the flow did not start a second round.
        self.assertEqual(2, len(transport.calls))

    def test_flow_reports_poc_still_triggers(self):
        transport = FakeTransport(_patch_reply(UNFIXED_SOURCE))
        outcome, _, _ = self._flow(transport, rounds=1)

        self.assertIs(False, outcome.verified)
        self.assertEqual((POC_STILL_TRIGGERS,), outcome.diagnostics[:1])
        self.assertIs(True, outcome.verification.compiles)


class BudgetTests(unittest.TestCase):
    """Budget honesty for generation and the bounded flow."""

    def test_budget_charged_for_generation(self):
        transport = FakeTransport(_patch_reply(FIXED_SOURCE))
        budget = CxxAgentBudget(max_calls=1)
        with patch("lima.agent_patch.post_chat_completion_text", transport):
            generate_patch(
                RESOLVED, FINDING_SUMMARY, TARGET_PATH, VULN_SOURCE,
                DRIVER_SUMMARY, budget, 60,
            )
            self.assertEqual(1, len(transport.calls))
            with self.assertRaises(AgentBudgetExceeded):
                generate_patch(
                    RESOLVED, FINDING_SUMMARY, TARGET_PATH, VULN_SOURCE,
                    DRIVER_SUMMARY, budget, 60,
                )
        # The second call was refused before another wire round trip.
        self.assertEqual(1, len(transport.calls))

        # Completion bytes are charged on arrival; an oversized reply is
        # dropped unparsed.
        transport = FakeTransport(_patch_reply(FIXED_SOURCE))
        tiny = CxxAgentBudget(max_calls=8, max_output_bytes=16)
        with patch("lima.agent_patch.post_chat_completion_text", transport):
            with self.assertRaises(AgentBudgetExceeded):
                generate_patch(
                    RESOLVED, FINDING_SUMMARY, TARGET_PATH, VULN_SOURCE,
                    DRIVER_SUMMARY, tiny, 60,
                )
        self.assertEqual(1, len(transport.calls))

    def test_flow_budget_exhaustion_propagates(self):
        transport = FakeTransport(_patch_reply(VULN_SOURCE))
        budget = CxxAgentBudget(max_calls=1)
        with patch("lima.agent_patch.post_chat_completion_text", transport):
            with self.assertRaises(AgentBudgetExceeded):
                suggest_patch_flow(
                    RESOLVED,
                    FakeReproClient(FakePreparer()),
                    FINDING_SUMMARY,
                    TARGET_PATH,
                    VULN_SOURCE,
                    DRIVER_SOURCE,
                    prepare_snapshot_fn=FakePreparer(),
                    budget=budget,
                    rounds=2,
                    timeout=60,
                )
        self.assertEqual(1, len(transport.calls))


class PatchFlowContainerTests(unittest.TestCase):
    """Real clang-14 + ASan verification of the patch flow in the container."""

    def _verify(self, patched_content):
        if sys.platform != "linux":
            self.skipTest("patch-flow container regression requires Linux")
        if shutil.which("clang-14") is None or shutil.which("clang++-14") is None:
            self.skipTest("clang-14 and clang++-14 are required for patch-flow fixtures")
        try:
            Path("/work/tmp").mkdir(parents=True, exist_ok=True)
        except OSError:
            self.skipTest("requires a writable container work root")

        from cxx_analyzer.deadline import AnalysisDeadline
        from cxx_analyzer.repro import run_repro
        from cxx_analyzer.snapshot import prepare_snapshot
        from lima.workspace import RepositoryWorkspace

        def prepare(import_root, repository_key, work_root):
            repository = Path(import_root) / repository_key
            fingerprint = RepositoryWorkspace(repository).inventory().fingerprint()
            return prepare_snapshot(import_root, repository_key, fingerprint, work_root)

        class SandboxReproClient:
            """In-process production stand-in over the Task 1 workbench."""

            def run_repro(self, snapshot, source_files, driver_code, *,
                          timeout_seconds=60):
                return run_repro(
                    snapshot,
                    list(source_files),
                    driver_code,
                    deadline=AnalysisDeadline.start(timeout_seconds * 4),
                    timeout_seconds=timeout_seconds,
                )

        return verify_patch(
            SandboxReproClient(),
            PatchProposal(TARGET_PATH, patched_content, "container fixture patch"),
            VULN_SOURCE,
            DRIVER_SOURCE,
            prepare_snapshot_fn=prepare,
            budget=CxxAgentBudget(),
            staging_root='/work/tmp',
            expected_asan_type="heap-use-after-free",
            timeout=60,
        )

    def test_container_fixed_patch_passes_regression(self):
        result = self._verify(FIXED_SOURCE)
        if not result.verified and INSTRUMENT_NOISE in result.diagnostics:
            # run_repro's internal retry budget was exhausted by renderer
            # noise (SIGSEGV, empty stream): one fresh verification
            # re-judges the fixed patch instead of failing on the noise.
            result = self._verify(FIXED_SOURCE)

        self.assertIs(True, result.verified)
        self.assertIs(True, result.compiles)
        self.assertIs(False, result.poc_still_triggers)
        self.assertIsNone(result.asan_type_after)

    def test_container_noop_patch_fails(self):
        result = self._verify(VULN_SOURCE)

        self.assertIs(False, result.verified)
        self.assertEqual((PATCH_IS_NOOP,), result.diagnostics)


if __name__ == "__main__":
    unittest.main()
