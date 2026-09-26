"""Scout agent tests (plan Task 3, design section 6).

Zero-network: the shared chat transport is replaced by canned callables
patched over ``lima.agent_scout.post_chat_completion_text`` (the name this
module imports, mirroring ``tests.test_uaf_llm_branch`` style). Red lines
pinned here:

- ``mode == "off"`` resolves every lead as unresolved with zero calls;
- batching is five leads per round and ``max_rounds`` bounds wire rounds;
- target/discard reasons are recorded verbatim, targets carry the closed
  high/medium/low confidence vocabulary;
- the coverage law: targets + discards + unresolved must account for every
  input lead id exactly once (constructor-enforced, extra or missing id
  raises ``ValueError``);
- a forged lead_id rejects the whole batch without repair (auto degrades to
  ``contract-violation``, required raises);
- budget exhaustion honestly marks the remaining leads unresolved; transport
  failure degrades per batch under ``auto``;
- rounds exhausted leaves leftovers unresolved with ``rounds-exhausted``;
- budget timing: calls plus context bytes charged before send, response
  bytes charged on arrival;
- the assembled context carries code snippets and never label vocabulary
  (CVE/expected/ground truth have no path in);
- fenced JSON replies are unwrapped and exactly one format repair happens.
"""

import json
import re
import time
import unittest
from unittest.mock import MagicMock, patch

from lima.agent_scout import (
    SCOUT_BATCH_SIZE,
    ScoutDiscard,
    ScoutLead,
    ScoutReport,
    ScoutTarget,
    review_leads,
)
from lima.cxx_agent_tools import AgentBudgetExceeded, CxxAgentBudget
from lima.reviewer import LLMTransportError

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

A_CPP = (
    "void handler(Context *ctx) {\n"
    "    Widget *widget = ctx->widget;\n"
    "    free(widget);\n"
    "    widget->render(ctx);\n"
    "}\n"
)

LEAD_ID_PATTERN = re.compile(r"^- lead_id: (.+)$", re.MULTILINE)


def _lead(number, path="src/a.cpp", line=3, summary=None, seed="uaf-free-then-use"):
    return ScoutLead(
        lead_id=f"lead-{number:02d}",
        path=path,
        line=line,
        summary=summary if summary is not None else f"suspicious call site {number}",
        seed=seed,
        score=number,
    )


class FakeReader:
    """Read-only snapshot stand-in; missing paths raise KeyError."""

    def __init__(self, files):
        self.files = dict(files)
        self.reads = []

    def read_text(self, path):
        self.reads.append(path)
        return self.files[path]


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
        raise AssertionError("the scout must not call the LLM")


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


def _ids_in_context(user_message):
    return LEAD_ID_PATTERN.findall(user_message)


def _target_entry(lead_id, reason="escalate for deep analysis", confidence="high"):
    return {
        "lead_id": lead_id, "verdict": "target", "reason": reason,
        "confidence": confidence,
    }


def _discard_entry(lead_id, reason="benign under the given snippet"):
    return {
        "lead_id": lead_id, "verdict": "discard", "reason": reason,
        "confidence": "low",
    }


class AnsweringTransport:
    """Answers every lead in the context: odd ids target, even ids discard."""

    def __init__(self):
        self.calls = []
        self.batch_sizes = []

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append(payload)
        ids = _ids_in_context(payload["messages"][1]["content"])
        self.batch_sizes.append(len(ids))
        entries = []
        for lead_id in ids:
            number = int(lead_id.split("-")[1])
            if number % 2 == 1:
                entries.append(_target_entry(
                    lead_id, f"escalating {lead_id}",
                    ("high", "medium", "low")[number % 3],
                ))
            else:
                entries.append(_discard_entry(lead_id, f"benign {lead_id}"))
        return json.dumps(entries)


class FirstLeadOnlyTransport:
    """Answers only the first lead of every batch; leftovers stay pending."""

    def __init__(self):
        self.calls = []

    def __call__(self, provider, base_url, api_key, payload, timeout,
                 extra_headers=None, max_bytes=None):
        self.calls.append(payload)
        ids = _ids_in_context(payload["messages"][1]["content"])
        return json.dumps([_target_entry(ids[0], f"escalating {ids[0]}", "high")])


def run_review(
    leads, transport, mode="auto", budget=None, rounds=3, reader=None,
    config=None, timeout=60,
):
    budget = budget if budget is not None else CxxAgentBudget(
        max_calls=12, max_output_bytes=1_000_000,
    )
    reader = reader if reader is not None else FakeReader({"src/a.cpp": A_CPP})
    with patch("lima.agent_scout.post_chat_completion_text", transport):
        report = review_leads(
            leads, llm_config=dict(config or RESOLVED), workspace_reader=reader,
            budget=budget, mode=mode, max_rounds=rounds, timeout=timeout,
        )
    return report, budget, reader


def _outcome_ids(report):
    return (
        [target.lead_id for target in report.targets]
        + [discard.lead_id for discard in report.discards]
        + [lead.lead_id for lead in report.unresolved_leads]
    )


class ModeOffTests(unittest.TestCase):
    """mode="off" abstains without a single wire call."""

    def test_mode_off_returns_all_unresolved_zero_calls(self):
        leads = [_lead(3), _lead(1), _lead(2)]  # deliberately out of id order
        transport = GuardTransport()
        budget = CxxAgentBudget(max_calls=4, max_output_bytes=100_000)
        report, budget, _ = run_review(
            leads, transport, mode="off", budget=budget,
        )
        self.assertEqual("mode-off", report.degradation)
        self.assertEqual(0, report.calls_used)
        self.assertEqual((), report.targets)
        self.assertEqual((), report.discards)
        self.assertEqual(
            ("lead-01", "lead-02", "lead-03"),
            tuple(lead.lead_id for lead in report.unresolved_leads),
        )
        self.assertEqual(0, len(transport.calls))
        self.assertEqual(4, budget.remaining().calls)


class BatchingTests(unittest.TestCase):
    """Five leads per wire round; rounds bound the loop."""

    def test_batching_five_leads_per_round(self):
        leads = [_lead(number) for number in range(1, 12)]  # 11 leads
        transport = AnsweringTransport()
        report, budget, _ = run_review(leads, transport, rounds=5)
        self.assertEqual([5, 5, 1], transport.batch_sizes)
        self.assertEqual(SCOUT_BATCH_SIZE, 5)
        self.assertEqual(3, report.calls_used)
        self.assertEqual(12 - 3, budget.remaining().calls)
        self.assertEqual(11, len(report.targets) + len(report.discards))
        self.assertEqual((), report.unresolved_leads)
        self.assertEqual("", report.degradation)
        target_ids = sorted(target.lead_id for target in report.targets)
        self.assertEqual(
            [f"lead-{number:02d}" for number in (1, 3, 5, 7, 9, 11)], target_ids,
        )
        self.assertEqual(3, len(transport.calls))


class ReasonRecordingTests(unittest.TestCase):
    """Target and discard verdicts keep the model's reason and confidence."""

    def test_target_and_discard_reasons_recorded(self):
        reply = json.dumps([
            _target_entry("lead-01", "the freed pointer is used without a rebind", "high"),
            _discard_entry("lead-02", "the early return guards the second free"),
        ])
        leads = [_lead(1, line=3), _lead(2, line=4, summary="guarded free path")]
        report, _, _ = run_review(leads, FakeTransport(reply))
        self.assertEqual(
            (
                ScoutTarget(
                    "lead-01", "src/a.cpp", 3,
                    "the freed pointer is used without a rebind", "high",
                ),
            ),
            report.targets,
        )
        self.assertEqual(
            (ScoutDiscard("lead-02", "the early return guards the second free"),),
            report.discards,
        )
        self.assertEqual("", report.degradation)
        self.assertEqual(1, report.calls_used)

    def test_targets_sort_by_confidence_then_path_then_line(self):
        low = ScoutTarget("lead-03", "src/b.cpp", 9, "weak signal", "low")
        high_line9 = ScoutTarget("lead-01", "src/a.cpp", 9, "strong", "high")
        high_line4 = ScoutTarget("lead-02", "src/a.cpp", 4, "strong", "high")
        report = ScoutReport(
            targets=(low, high_line9, high_line4),
            discards=(),
            unresolved_leads=(),
            calls_used=1,
            degradation="",
            lead_ids=frozenset({"lead-01", "lead-02", "lead-03"}),
        )
        self.assertEqual((high_line4, high_line9, low), report.targets)


class CoverageLawTests(unittest.TestCase):
    """Every input lead needs exactly one outcome; enforced at construction."""

    def test_coverage_law_every_lead_accounted(self):
        lead_one = _lead(1)
        lead_two = _lead(2)
        valid_target = ScoutTarget("lead-01", "src/a.cpp", 3, "reason", "high")
        valid_discard = ScoutDiscard("lead-02", "reason")
        lead_ids = frozenset({"lead-01", "lead-02"})

        ScoutReport(
            targets=(valid_target,), discards=(valid_discard,),
            unresolved_leads=(), calls_used=1, degradation="", lead_ids=lead_ids,
        )

        with self.assertRaises(ValueError):  # extra: unknown id accounted
            ScoutReport(
                targets=(ScoutTarget("lead-99", "src/a.cpp", 3, "r", "high"),),
                discards=(valid_discard,), unresolved_leads=(),
                calls_used=1, degradation="", lead_ids=lead_ids,
            )
        with self.assertRaises(ValueError):  # missing: lead-02 has no outcome
            ScoutReport(
                targets=(valid_target,), discards=(), unresolved_leads=(),
                calls_used=1, degradation="", lead_ids=lead_ids,
            )
        with self.assertRaises(ValueError):  # one id with two outcomes
            ScoutReport(
                targets=(valid_target,), discards=(valid_discard,),
                unresolved_leads=(lead_two,),
                calls_used=1, degradation="",
                lead_ids=frozenset({lead_one.lead_id, lead_two.lead_id}),
            )


class ContractViolationTests(unittest.TestCase):
    """A forged lead_id rejects the whole batch; never repaired."""

    def test_forged_lead_id_rejects_batch_auto_degrades(self):
        reply = json.dumps([
            _target_entry("lead-01"),
            _discard_entry("ghost-lead", "invented id"),
        ])
        report, _, _ = run_review(
            [_lead(1), _lead(2)], FakeTransport(reply), mode="auto",
        )
        self.assertEqual("contract-violation", report.degradation)
        self.assertEqual({"lead-01", "lead-02"}, set(_outcome_ids(report)))
        self.assertEqual(
            ("lead-01", "lead-02"),
            tuple(lead.lead_id for lead in report.unresolved_leads),
        )
        self.assertEqual((), report.targets)
        self.assertEqual((), report.discards)
        self.assertEqual(1, report.calls_used)  # rejected without repair

    def test_forged_lead_id_rejects_batch_required_raises(self):
        reply = json.dumps([_discard_entry("ghost-lead", "invented id")])
        with self.assertRaises(RuntimeError):
            run_review(
                [_lead(1)], FakeTransport(reply), mode="required",
            )


class BudgetTests(unittest.TestCase):
    """Budget exhaustion degrades honestly; timing is before-send/on-arrival."""

    def test_budget_exhaustion_marks_remaining_unresolved(self):
        transport = AnsweringTransport()
        budget = CxxAgentBudget(max_calls=1, max_output_bytes=1_000_000)
        report, budget, _ = run_review(
            [_lead(number) for number in range(1, 12)],
            transport, budget=budget,
        )
        self.assertEqual("budget-exhausted", report.degradation)
        self.assertEqual(1, report.calls_used)
        self.assertEqual(0, budget.remaining().calls)
        answered = {f"lead-{number:02d}" for number in (1, 3, 5)}
        self.assertEqual(
            answered, {target.lead_id for target in report.targets},
        )
        leftover = {lead.lead_id for lead in report.unresolved_leads}
        self.assertTrue(
            leftover.issuperset({f"lead-{number:02d}" for number in range(6, 12)}),
        )
        self.assertEqual(11, len(_outcome_ids(report)))

    def test_budget_charged_before_send_and_after_response(self):
        budget = CxxAgentBudget(max_calls=1, max_output_bytes=200_000)
        reply = json.dumps([_target_entry("lead-01")])
        transport = ProbingTransport(budget, reply)
        report, budget, _ = run_review([_lead(1)], transport, budget=budget)
        self.assertEqual("", report.degradation)
        user_content = transport.calls[0]["messages"][1]["content"]
        context_bytes = len(user_content.encode("utf-8"))
        # The call and the context bytes are charged before the wire send.
        self.assertEqual(0, transport.snapshots[0].calls)
        self.assertEqual(
            200_000 - context_bytes, transport.snapshots[0].bytes_remaining,
        )
        # The response bytes were charged on arrival.
        self.assertEqual(
            200_000 - context_bytes - len(reply.encode("utf-8")),
            budget.remaining().bytes_remaining,
        )
        self.assertEqual(0, budget.remaining().calls)
        self.assertEqual(1, report.calls_used)


class TransportFailureTests(unittest.TestCase):
    """Transport failures degrade per batch under auto, raise under required."""

    def test_transport_failure_auto_degrades_per_batch(self):
        transport = FakeTransport(LLMTransportError("provider down"), None)
        transport.contents[1] = json.dumps([_target_entry("lead-06", "real", "high")])
        report, _, _ = run_review(
            [_lead(number) for number in range(1, 7)], transport, mode="auto",
        )
        self.assertEqual("llm-unavailable", report.degradation)
        self.assertEqual(2, report.calls_used)
        self.assertEqual(
            (ScoutTarget("lead-06", "src/a.cpp", 3, "real", "high"),),
            report.targets,
        )
        self.assertEqual(6, len(_outcome_ids(report)))
        self.assertEqual(
            {f"lead-{number:02d}" for number in range(1, 6)},
            {lead.lead_id for lead in report.unresolved_leads},
        )

    def test_transport_failure_required_raises(self):
        with self.assertRaises(RuntimeError):
            run_review(
                [_lead(1)], FakeTransport(LLMTransportError("provider down")),
                mode="required",
            )


class RoundsTests(unittest.TestCase):
    """Rounds exhausted leaves leftovers unresolved, not guessed."""

    def test_rounds_exhausted_degradation(self):
        transport = FirstLeadOnlyTransport()
        report, _, _ = run_review(
            [_lead(1), _lead(2)], transport, mode="auto", rounds=1,
        )
        self.assertEqual(1, report.calls_used)
        self.assertEqual("rounds-exhausted", report.degradation)
        self.assertEqual(
            (ScoutTarget("lead-01", "src/a.cpp", 3, "escalating lead-01", "high"),),
            report.targets,
        )
        self.assertEqual(
            ("lead-02",),
            tuple(lead.lead_id for lead in report.unresolved_leads),
        )
        self.assertEqual(2, len(_outcome_ids(report)))


class ContextTests(unittest.TestCase):
    """The assembled context carries code, never label vocabulary."""

    def test_context_contains_code_snippet_and_no_label_leak(self):
        reply = json.dumps([_target_entry("lead-01")])
        transport = FakeTransport(reply)
        reader = FakeReader({"src/a.cpp": A_CPP})
        report, _, reader = run_review(
            [_lead(1, line=3, summary="call to free helper", seed="uaf-seed")],
            transport, reader=reader,
        )
        self.assertEqual("", report.degradation)
        self.assertEqual(["src/a.cpp"], reader.reads)
        user_content = transport.calls[0]["payload"]["messages"][1]["content"]
        self.assertIn("lead_id: lead-01", user_content)
        self.assertIn("src/a.cpp:3", user_content)
        self.assertIn("free(widget);", user_content)
        self.assertIn("widget->render(ctx);", user_content)
        self.assertIn("call to free helper", user_content)
        lowered = user_content.lower()
        for forbidden in ("cve", "expected", "vulnerable", "label", "ground truth"):
            self.assertNotIn(forbidden, lowered)
        system = transport.calls[0]["payload"]["messages"][0]["content"]
        self.assertIn("untrusted data", system)
        self.assertIn("JSON", system)

    def test_missing_snippet_file_degrades_context_not_crash(self):
        reply = json.dumps([_discard_entry("lead-01", "nothing to see")])
        transport = FakeTransport(reply)
        reader = FakeReader({})  # lead path not present in the snapshot
        report, _, _ = run_review([_lead(1)], transport, reader=reader)
        self.assertEqual(
            (ScoutDiscard("lead-01", "nothing to see"),), report.discards,
        )


class StrictJsonTests(unittest.TestCase):
    """Fenced replies unwrap; exactly one repair happens; then honest failure."""

    def test_strict_json_with_fence_unwrap_and_one_repair(self):
        plain = json.dumps([_target_entry("lead-01", "kept", "medium")])
        fenced = "```json\n" + plain + "\n```"
        with self.subTest("fenced reply unwraps in one call"):
            transport = FakeTransport(fenced)
            report, _, _ = run_review([_lead(1)], transport)
            self.assertEqual(
                (ScoutTarget("lead-01", "src/a.cpp", 3, "kept", "medium"),),
                report.targets,
            )
            self.assertEqual(1, report.calls_used)
        with self.subTest("one repair rescues a malformed first reply"):
            transport = FakeTransport("this is not json", plain)
            report, _, _ = run_review([_lead(1)], transport)
            self.assertEqual(2, report.calls_used)
            self.assertEqual("lead-01", report.targets[0].lead_id)
            self.assertEqual("", report.degradation)
            messages = transport.calls[1]["payload"]["messages"]
            self.assertEqual(
                ["system", "user", "assistant", "user"],
                [message["role"] for message in messages],
            )
            self.assertIn("not a valid scout review", messages[3]["content"])
            self.assertIn("Reply again", messages[3]["content"])

    def test_invalid_reply_after_repair_degrades_auto_and_raises_required(self):
        with self.subTest("auto: invalid reply degrades the batch"):
            transport = FakeTransport("{}", "not json again")
            report, _, _ = run_review([_lead(1)], transport, mode="auto")
            self.assertEqual("invalid-reply", report.degradation)
            self.assertEqual(2, report.calls_used)
            self.assertEqual(
                ("lead-01",),
                tuple(lead.lead_id for lead in report.unresolved_leads),
            )
            self.assertEqual((), report.targets)
        with self.subTest("required: invalid reply fails the task"):
            with self.assertRaises(RuntimeError):
                run_review(
                    [_lead(1)],
                    FakeTransport("{", "still not json"),
                    mode="required",
                )


class InputContractTests(unittest.TestCase):
    """Argument validation is free: nothing is charged on rejection."""

    def test_empty_leads_return_empty_report(self):
        transport = GuardTransport()
        report, budget, _ = run_review([], transport, mode="auto")
        self.assertEqual((), report.targets)
        self.assertEqual((), report.discards)
        self.assertEqual((), report.unresolved_leads)
        self.assertEqual(0, report.calls_used)
        self.assertEqual("", report.degradation)
        self.assertEqual(0, len(transport.calls))
        self.assertEqual(budget.max_calls, budget.remaining().calls)

    def test_bad_arguments_rejected_without_calls(self):
        cases = [
            ("bad mode", dict(mode="bogus")),
            ("zero rounds", dict(rounds=0)),
            ("zero timeout", dict(timeout=0)),
        ]
        for name, kwargs in cases:
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    run_review([_lead(1)], GuardTransport(), **kwargs)

    def test_reader_must_provide_read_text(self):
        with self.assertRaises(ValueError):
            run_review([_lead(1)], GuardTransport(), reader=object())

    def test_duplicate_lead_ids_rejected(self):
        with self.assertRaises(ValueError):
            run_review([_lead(1), _lead(1)], GuardTransport())

    def test_lead_validation(self):
        with self.subTest("empty lead id"):
            with self.assertRaises(ValueError):
                ScoutLead("", "src/a.cpp", 3, "summary", "seed")
        with self.subTest("escaping path"):
            with self.assertRaises(ValueError):
                ScoutLead("lead-01", "../etc/passwd", 3, "summary", "seed")
        with self.subTest("backslash path"):
            with self.assertRaises(ValueError):
                ScoutLead("lead-01", "src\\a.cpp", 3, "summary", "seed")
        with self.subTest("zero line"):
            with self.assertRaises(ValueError):
                ScoutLead("lead-01", "src/a.cpp", 0, "summary", "seed")
        with self.subTest("empty summary"):
            with self.assertRaises(ValueError):
                ScoutLead("lead-01", "src/a.cpp", 3, "", "seed")
        with self.subTest("empty seed"):
            with self.assertRaises(ValueError):
                ScoutLead("lead-01", "src/a.cpp", 3, "summary", "")

    def test_report_field_validation(self):
        lead = _lead(1)
        with self.subTest("degradation vocabulary"):
            with self.assertRaises(ValueError):
                ScoutReport(
                    targets=(), discards=(), unresolved_leads=(lead,),
                    calls_used=0, degradation="made-up", lead_ids=frozenset({"lead-01"}),
                )
        with self.subTest("negative calls"):
            with self.assertRaises(ValueError):
                ScoutReport(
                    targets=(), discards=(), unresolved_leads=(lead,),
                    calls_used=-1, degradation="", lead_ids=frozenset({"lead-01"}),
                )
        with self.subTest("bad confidence"):
            with self.assertRaises(ValueError):
                ScoutTarget("lead-01", "src/a.cpp", 3, "reason", "certain")
        with self.subTest("AgentBudgetExceeded is a budget signal"):
            self.assertTrue(issubclass(AgentBudgetExceeded, RuntimeError))


class DeadlineTests(unittest.TestCase):
    """The absolute deadline bounds every send, batch and format repair.

    Round-3 acceptance contract: the deadline is not converted into a
    smaller timeout once it has passed -- it forbids the next send, and the
    unjudged leads stay unresolved with ``deadline-exceeded``.
    """

    def _deadline_review(self, leads, transport, clock_values, deadline,
                         timeout=60):
        clock = MagicMock()
        clock.monotonic.side_effect = clock_values
        with patch(
            "lima.agent_scout.post_chat_completion_text", transport,
        ), patch("lima.agent_scout.time", clock):
            return review_leads(
                leads,
                llm_config=dict(RESOLVED),
                workspace_reader=FakeReader({"src/a.cpp": A_CPP}),
                budget=CxxAgentBudget(max_calls=12, max_output_bytes=1_000_000),
                timeout=timeout,
                deadline=deadline,
            )

    def test_expired_deadline_sends_nothing(self):
        transport = GuardTransport()
        report = self._deadline_review(
            [_lead(number) for number in range(1, 4)],
            transport,
            [time.monotonic()],
            time.monotonic() - 1,
        )
        self.assertEqual(0, len(transport.calls))
        self.assertEqual(0, report.calls_used)
        self.assertEqual("deadline-exceeded", report.degradation)
        self.assertEqual((), report.targets)
        self.assertEqual((), report.discards)
        self.assertEqual(
            ("lead-01", "lead-02", "lead-03"),
            tuple(lead.lead_id for lead in report.unresolved_leads),
        )

    def test_deadline_stops_between_batches(self):
        # Batch 1 (leads 1-5) sends within the deadline; before batch 2 the
        # remaining budget is re-derived, found expired, and nothing more
        # is sent -- leads 6-8 stay unresolved.
        reply = json.dumps([
            _target_entry(f"lead-0{number}", "release precedes use", "high")
            for number in range(1, 6)
        ])
        transport = FakeTransport(reply)
        report = self._deadline_review(
            [_lead(number) for number in range(1, 9)],
            transport,
            [1000.0, 1000.1, 1010.0],
            deadline=1005.0,
        )
        self.assertEqual(1, len(transport.calls))
        # The one send that did happen was bounded by the deadline remainder.
        self.assertEqual(4, transport.calls[0]["timeout"])
        self.assertEqual(1, report.calls_used)
        self.assertEqual(5, len(report.targets))
        self.assertEqual("deadline-exceeded", report.degradation)
        self.assertEqual(
            ("lead-06", "lead-07", "lead-08"),
            tuple(lead.lead_id for lead in report.unresolved_leads),
        )

    def test_deadline_forbids_format_repair(self):
        # The first reply is malformed; by the time the repair would be
        # sent the deadline has passed, so the repair never goes out and
        # the batch stays unresolved.
        transport = FakeTransport("not json")
        report = self._deadline_review(
            [_lead(number) for number in range(1, 6)],
            transport,
            [1000.0, 1000.1, 1010.0],
            deadline=1005.0,
        )
        self.assertEqual(1, len(transport.calls))
        self.assertEqual(1, report.calls_used)
        self.assertEqual("deadline-exceeded", report.degradation)
        self.assertEqual((), report.targets)
        self.assertEqual(
            tuple(f"lead-0{number}" for number in range(1, 6)),
            tuple(lead.lead_id for lead in report.unresolved_leads),
        )

    def test_no_deadline_keeps_caller_timeout(self):
        # Control: without a deadline the wire timeout travels unchanged
        # for the normal send and the repair alike.
        transport = FakeTransport("not json", json.dumps([_target_entry("lead-01")]))
        with patch("lima.agent_scout.post_chat_completion_text", transport):
            report = review_leads(
                [_lead(1)],
                llm_config=dict(RESOLVED),
                workspace_reader=FakeReader({"src/a.cpp": A_CPP}),
                budget=CxxAgentBudget(max_calls=12, max_output_bytes=1_000_000),
                timeout=77,
            )
        self.assertEqual(2, len(transport.calls))
        self.assertEqual({77}, {call["timeout"] for call in transport.calls})
        self.assertEqual(("lead-01",), tuple(
            target.lead_id for target in report.targets
        ))

    def test_deadline_argument_validation(self):
        with patch(
            "lima.agent_scout.post_chat_completion_text", GuardTransport(),
        ):
            with self.subTest("bool is not a deadline"):
                with self.assertRaises(ValueError):
                    review_leads(
                        [_lead(1)], llm_config=dict(RESOLVED),
                        workspace_reader=FakeReader({"src/a.cpp": A_CPP}),
                        budget=CxxAgentBudget(), deadline=True,
                    )
            with self.subTest("text is not a deadline"):
                with self.assertRaises(ValueError):
                    review_leads(
                        [_lead(1)], llm_config=dict(RESOLVED),
                        workspace_reader=FakeReader({"src/a.cpp": A_CPP}),
                        budget=CxxAgentBudget(), deadline="soon",
                    )


if __name__ == "__main__":
    unittest.main()
