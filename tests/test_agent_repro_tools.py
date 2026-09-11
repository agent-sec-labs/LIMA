"""Contract tests for the agent reproduction workbench (platform plan Task 2).

The versioned ``/v1/repro`` Sidecar endpoint (Task 1) is wrapped for agents:

* ``lima.repro_templates`` ships one self-contained PoC driver skeleton per
  memory-safety class with a closed ``{{...}}`` placeholder vocabulary.
* ``lima.agent_repro_tools.ReproWorkbench`` pre-validates the experiment
  request against the Task 1 rules, charges ``CxxAgentBudget`` in the
  cxx_llm order (call plus exact request bytes before the wire, response
  text bytes on arrival, nothing refunded after a failed transport) and
  distills the strictly validated ``ReproResponse`` into an escaped,
  bounded :class:`ExperimentObservation`.  Protocol and transport failures
  degrade to a ``transport-failed`` observation instead of raising through
  the agent loop.

Every test injects a fake analyzer client: the workbench itself performs
no network access, and no compiler or sandbox is needed on the host.
"""

from __future__ import annotations

import re
import unittest

from lima.agent_repro_tools import (
    MAX_DIAGNOSTIC_CHARS,
    MAX_RAW_TAIL_CHARS,
    ExperimentObservation,
    ReproWorkbench,
    as_agent_tool,
    observation_payload_bytes,
)
from lima.cxx_agent_tools import AgentBudgetExceeded, CxxAgentBudget
from lima.cxx_memory import (
    MAX_REPRO_DRIVER_BYTES,
    CxxAnalyzerProtocolError,
    CxxAnalyzerUnavailable,
    ReproResponse,
)
from lima.repro_templates import (
    DRIVER_TEMPLATES,
    PLACEHOLDER_NAMES,
    TEMPLATE_NAMES,
    list_templates,
    render_driver,
)
from lima.runtime import AgentLoopProtocolError, ToolRegistry

REQUEST_ID = "00000000-0000-0000-0000-000000000003"
REPOSITORY_KEY = "team/project"
SNAPSHOT = "c" * 64
SOURCE_FILES = ("src/vuln.cpp",)
DRIVER_CODE = "#include <cstdio>\nint main() { return 0; }\n"


def asan_report_payload(**overrides):
    report = {
        "error_type": "heap-use-after-free",
        "access": "READ",
        "access_size": 4,
        "faulting_frame": {
            "function": "main",
            "file": "build/repro_driver_ab12cd34.cpp",
            "line": 6,
            "column": 30,
        },
        "freed_by_frame": {
            "function": "main",
            "file": "build/repro_driver_ab12cd34.cpp",
            "line": 5,
            "column": 5,
        },
        "allocated_by_frame": None,
        "raw_report_sha256": "b" * 64,
    }
    report.update(overrides)
    return report


def canned_repro_response(**changes) -> ReproResponse:
    fields = {
        "request_id": REQUEST_ID,
        "snapshot_sha256": SNAPSHOT,
        "stage": "run",
        "ok": False,
        "exit_code": 1,
        "asan_report": asan_report_payload(),
        "diagnostics": (),
        "driver_sha256": "d" * 64,
        "binary_sha256": "e" * 64,
        "elapsed_seconds": 0.25,
    }
    fields.update(changes)
    return ReproResponse(**fields)


class FakeAnalyzerClient:
    """Injected Task 1 client: records calls, never touches the network."""

    def __init__(self, response=None, *, error=None, budget=None):
        self.response = response
        self.error = error
        self.budget = budget
        self.calls = []
        self.remaining_calls_seen_at_call = None

    def repro_compile_run(self, repository_key, snapshot_sha256, source_files, driver_code):
        self.calls.append(
            (repository_key, snapshot_sha256, tuple(source_files), driver_code)
        )
        if self.budget is not None:
            self.remaining_calls_seen_at_call = self.budget.remaining().calls
        if self.error is not None:
            raise self.error
        return self.response


def workbench_with(client, budget=None) -> ReproWorkbench:
    return ReproWorkbench(client, budget or CxxAgentBudget())


class TemplateContractTests(unittest.TestCase):
    def test_expected_template_catalog(self):
        self.assertEqual(
            {"heap-uaf", "double-free", "heap-overflow", "null-deref", "generic-call"},
            set(DRIVER_TEMPLATES),
        )
        self.assertEqual(frozenset(DRIVER_TEMPLATES), TEMPLATE_NAMES)
        self.assertEqual(sorted(DRIVER_TEMPLATES), list_templates())

    def test_render_driver_all_placeholders_filled(self):
        placeholders = {
            "HEADER_DECL": "struct Widget { int v; };\nvoid touch(Widget *w);",
            "TARGET_FUNC": "touch",
            "TARGET_ARGS": "static_cast<Widget *>(poc_object)",
        }
        for name in TEMPLATE_NAMES:
            with self.subTest(template=name):
                rendered = render_driver(name, **placeholders)
                self.assertNotIn("{{", rendered)
                self.assertNotIn("}}", rendered)
                self.assertIn("touch(", rendered)
                self.assertIn("int main()", rendered)

    def test_render_driver_rejects_missing_or_unknown_placeholders(self):
        with self.assertRaises(ValueError):
            render_driver("heap-uaf")
        with self.assertRaises(ValueError):
            render_driver("heap-uaf", HEADER_DECL="", TARGET_FUNC="touch")
        with self.assertRaises(ValueError):
            render_driver(
                "heap-uaf",
                HEADER_DECL="",
                TARGET_FUNC="touch",
                TARGET_ARGS="poc_object",
                BOGUS="x",
            )
        # Empty-string values are legal: the skeleton must stay compilable.
        rendered = render_driver(
            "generic-call", HEADER_DECL="", TARGET_FUNC="touch", TARGET_ARGS=""
        )
        self.assertIn("touch();", rendered)

    def test_unknown_template_rejected(self):
        with self.assertRaises(ValueError):
            render_driver(
                "no-such-template",
                HEADER_DECL="",
                TARGET_FUNC="touch",
                TARGET_ARGS="",
            )
        self.assertNotIn("no-such-template", TEMPLATE_NAMES)

    def test_templates_are_self_contained(self):
        for name, template in DRIVER_TEMPLATES.items():
            with self.subTest(template=name):
                self.assertIn("#include <", template)
                self.assertIn("int main()", template)
                found = set(re.findall(r"\{\{([A-Z_]+)\}\}", template))
                self.assertTrue(found)
                self.assertLessEqual(found, PLACEHOLDER_NAMES)
                # Every {{ sequence is a well-formed known placeholder: no
                # other placeholder style (or stray brace soup) is allowed.
                self.assertEqual(
                    len(re.findall(r"\{\{", template)),
                    len(re.findall(r"\{\{[A-Z_]+\}\}", template)),
                )
                self.assertNotIn("${", template)
                self.assertNotIn("%s", template)
                self.assertNotIn("%(", template)


class ReproWorkbenchTests(unittest.TestCase):
    def test_run_experiment_happy_path_maps_fields(self):
        response = canned_repro_response(
            diagnostics=("repro-run-recorded",),
        )
        client = FakeAnalyzerClient(response)
        observation = workbench_with(client).run_experiment(
            REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
        )

        self.assertEqual(1, len(client.calls))
        self.assertEqual(
            (REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE), client.calls[0]
        )
        self.assertIsInstance(observation, ExperimentObservation)
        self.assertIs(False, observation.ok)
        self.assertEqual("run", observation.stage)
        self.assertEqual(1, observation.exit_code)
        # error_type is wire-derived text: it arrives repr-escaped.
        self.assertEqual("'heap-use-after-free'", observation.error_type)
        self.assertEqual(6, observation.faulting_line)
        self.assertEqual(5, observation.freed_line)
        self.assertIsNone(observation.allocated_line)
        self.assertEqual(("'repro-run-recorded'",), observation.diagnostics)
        self.assertIn("repro-run-recorded", observation.raw_tail)

        # The allocated-by line maps when the report carries the frame.
        report = asan_report_payload(
            allocated_by_frame={
                "function": "main",
                "file": "build/repro_driver_ab12cd34.cpp",
                "line": 4,
                "column": 3,
            }
        )
        allocated = workbench_with(
            FakeAnalyzerClient(canned_repro_response(asan_report=report))
        ).run_experiment(REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE)
        self.assertEqual(4, allocated.allocated_line)

    def test_compile_failure_maps_stage_without_report(self):
        response = canned_repro_response(
            stage="compile",
            ok=False,
            exit_code=1,
            asan_report=None,
            diagnostics=("driver.cpp:2:5: error: use of undeclared identifier",),
        )
        observation = workbench_with(FakeAnalyzerClient(response)).run_experiment(
            REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
        )

        self.assertIs(False, observation.ok)
        self.assertEqual("compile", observation.stage)
        self.assertEqual(1, observation.exit_code)
        self.assertIsNone(observation.error_type)
        self.assertIsNone(observation.faulting_line)
        self.assertEqual(
            (
                "'driver.cpp:2:5: error: use of undeclared identifier'",
            ),
            observation.diagnostics,
        )

    def test_budget_calls_before_send(self):
        budget = CxxAgentBudget()
        client = FakeAnalyzerClient(
            error=CxxAnalyzerUnavailable("C/C++ analyzer is unavailable"),
            budget=budget,
        )
        observation = workbench_with(client, budget).run_experiment(
            REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
        )

        # The call charge was already visible to the wire layer: deduction
        # happens before the request is sent, and a failed transport never
        # refunds it (cxx_llm semantics).
        expected_remaining_calls = budget.max_calls - 1
        self.assertEqual(
            [expected_remaining_calls], [client.remaining_calls_seen_at_call]
        )
        self.assertEqual(expected_remaining_calls, budget.remaining().calls)
        self.assertEqual(
            len(DRIVER_CODE.encode("utf-8")),
            budget.max_output_bytes - budget.remaining().bytes_remaining,
        )
        self.assertIs(False, observation.ok)
        self.assertEqual("transport-failed", observation.stage)
        self.assertTrue(
            observation.diagnostics[0].startswith("transport-failed: "),
            observation.diagnostics,
        )

    def test_budget_bytes_after_response(self):
        budget = CxxAgentBudget(max_output_bytes=1_000_000)
        response = canned_repro_response(diagnostics=("x" * 5000,))
        client = FakeAnalyzerClient(response)
        observation = workbench_with(client, budget).run_experiment(
            REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
        )

        charged = 1_000_000 - budget.remaining().bytes_remaining
        self.assertEqual(
            len(DRIVER_CODE.encode("utf-8")) + observation_payload_bytes(observation),
            charged,
        )
        self.assertEqual(1, budget.max_calls - budget.remaining().calls)

    def test_transport_error_degrades_not_raises(self):
        for error in (
            CxxAnalyzerUnavailable("C/C++ analyzer is unavailable"),
            CxxAnalyzerProtocolError("invalid C/C++ analyzer response fields"),
        ):
            with self.subTest(error=type(error).__name__):
                client = FakeAnalyzerClient(error=error)
                observation = workbench_with(client).run_experiment(
                    REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
                )
                self.assertIs(False, observation.ok)
                self.assertEqual("transport-failed", observation.stage)
                self.assertIsNone(observation.exit_code)
                self.assertIsNone(observation.error_type)
                self.assertEqual(1, len(observation.diagnostics))
                self.assertLessEqual(
                    len(observation.diagnostics[0]),
                    len("transport-failed: ") + 500,
                )

    def test_driver_size_capped_locally(self):
        budget = CxxAgentBudget()
        client = FakeAnalyzerClient(canned_repro_response())
        bench = workbench_with(client, budget)

        oversized = "x" * (MAX_REPRO_DRIVER_BYTES + 1)
        with self.assertRaises(ValueError):
            bench.run_experiment(REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, oversized)
        for driver in ("", "int main() { return 0; }\x00"):
            with self.assertRaises(ValueError):
                bench.run_experiment(REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, driver)

        # Local rejection never reaches the client and never charges budget.
        self.assertEqual([], client.calls)
        self.assertEqual(budget.max_calls, budget.remaining().calls)
        self.assertEqual(0, budget.max_output_bytes - budget.remaining().bytes_remaining)

    def test_source_files_capped(self):
        budget = CxxAgentBudget()
        client = FakeAnalyzerClient(canned_repro_response())
        bench = workbench_with(client, budget)

        too_many = tuple(f"src/file_{index}.cpp" for index in range(17))
        cases = (
            too_many,
            (),
            ("src/a.cpp", "src/a.cpp"),
            ("src\\evil.cpp",),
            ("../escape.cpp",),
            ("/etc/passwd.cpp",),
            ("src/./traversal.cpp",),
            ("src/ok.cpp", 42),
        )
        for source_files in cases:
            with self.subTest(source_files=str(source_files)[:60]):
                with self.assertRaises(ValueError):
                    bench.run_experiment(
                        REPOSITORY_KEY, SNAPSHOT, source_files, DRIVER_CODE
                    )
        self.assertEqual([], client.calls)
        self.assertEqual(budget.max_calls, budget.remaining().calls)

    def test_observation_text_is_escaped_and_bounded(self):
        hostile = "segv\x07 on\x1b[31m address\nsecond line caf\u202e"
        response = canned_repro_response(diagnostics=(hostile, "x" * 5000))
        observation = workbench_with(FakeAnalyzerClient(response)).run_experiment(
            REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
        )

        texts = (*observation.diagnostics, observation.raw_tail)
        for text in texts:
            self.assertFalse(any(ord(character) < 32 or ord(character) == 127
                                 for character in text))
        for item in observation.diagnostics:
            self.assertLessEqual(len(item), MAX_DIAGNOSTIC_CHARS)
        self.assertLessEqual(len(observation.raw_tail), MAX_RAW_TAIL_CHARS)
        # repr-style escapes survive: newline, control and bidi characters
        # are all visible literals, never raw bytes in the model context.
        self.assertIn("\\x07", observation.raw_tail)
        self.assertIn("\\n", observation.raw_tail)
        self.assertIn("\\u202e", observation.raw_tail)

    def test_budget_exhausted_response_is_dropped(self):
        # Enough headroom for the pre-send call + driver charge but not for
        # the observation: the request is sent, the response arrives and is
        # dropped unreturned (cxx_llm over-budget semantics).
        driver_bytes = len(DRIVER_CODE.encode("utf-8"))
        budget = CxxAgentBudget(max_calls=1, max_output_bytes=driver_bytes + 10)
        client = FakeAnalyzerClient(canned_repro_response())
        with self.assertRaises(AgentBudgetExceeded):
            workbench_with(client, budget).run_experiment(
                REPOSITORY_KEY, SNAPSHOT, SOURCE_FILES, DRIVER_CODE
            )
        self.assertEqual(1, len(client.calls))


class AgentToolFactoryTests(unittest.TestCase):
    def test_as_agent_tool_schema_exact(self):
        client = FakeAnalyzerClient(canned_repro_response())
        tool = as_agent_tool(workbench_with(client))

        self.assertEqual("compile_and_run_asan", tool.name)
        schema = tool.parameters
        self.assertEqual("object", schema["type"])
        self.assertIs(False, schema["additionalProperties"])
        expected = {"repository_key", "snapshot_hash", "source_files", "driver_code"}
        self.assertEqual(expected, set(schema["properties"]))
        self.assertEqual(expected, set(schema["required"]))
        self.assertEqual("string", schema["properties"]["repository_key"]["type"])
        self.assertEqual("string", schema["properties"]["snapshot_hash"]["type"])
        self.assertEqual(
            {"type": "array", "items": {"type": "string"}},
            schema["properties"]["source_files"],
        )
        self.assertEqual("string", schema["properties"]["driver_code"]["type"])

        # The handler is wired through the registry validator end to end.
        registry = ToolRegistry([tool])
        observation = registry.invoke(
            "compile_and_run_asan",
            {
                "repository_key": REPOSITORY_KEY,
                "snapshot_hash": SNAPSHOT,
                "source_files": list(SOURCE_FILES),
                "driver_code": DRIVER_CODE,
            },
        )
        self.assertIsInstance(observation, ExperimentObservation)
        self.assertEqual(1, len(client.calls))
        with self.assertRaises(AgentLoopProtocolError):
            registry.invoke(
                "compile_and_run_asan",
                {
                    "repository_key": REPOSITORY_KEY,
                    "snapshot_hash": SNAPSHOT,
                    "source_files": list(SOURCE_FILES),
                    "driver_code": DRIVER_CODE,
                    "extra": True,
                },
            )


if __name__ == "__main__":
    unittest.main()
