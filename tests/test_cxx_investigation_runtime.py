"""Regression coverage for bounded investigation runtime extensions."""

from dataclasses import dataclass
import unittest
from unittest.mock import patch

from lima.cxx_agent_tools import CxxAgentBudget
from lima.runtime import AgentLoop, RuntimeBudgetExceeded, RuntimeCancelled


class _FatalToolError(RuntimeError):
    pass


class AgentLoopCancellationTests(unittest.TestCase):
    def test_cancellation_after_stepper_prevents_tool_side_effect(self):
        checks = iter((False, True))
        calls = []

        with self.assertRaises(RuntimeCancelled):
            AgentLoop().run(
                lambda _state: {"action": "tool", "tool": "write", "arguments": {}},
                {"write": lambda: calls.append("called")}, {},
                cancel_check=lambda: next(checks),
            )
        self.assertEqual([], calls)

    def test_enabled_cancellation_propagates_tool_cancellation(self):
        with self.assertRaises(RuntimeCancelled):
            AgentLoop().run(
                lambda _state: {"action": "tool", "tool": "stop", "arguments": {}},
                {"stop": lambda: (_ for _ in ()).throw(RuntimeCancelled("stop"))}, {},
                cancel_check=lambda: False,
            )

    def test_deadline_expiring_during_stepper_prevents_tool_side_effect(self):
        calls = []
        with patch("lima.runtime.time.monotonic", side_effect=(0.0, 0.0, 2.0)):
            with self.assertRaises(RuntimeBudgetExceeded):
                AgentLoop(timeout_seconds=1).run(
                    lambda _state: {
                        "action": "tool", "tool": "write", "arguments": {},
                    },
                    {"write": lambda: calls.append("called")}, {},
                )
        self.assertEqual([], calls)

    def test_fatal_tool_exception_is_opt_in_and_legacy_stays_observation(self):
        tool = {"bad": lambda: (_ for _ in ()).throw(_FatalToolError("fatal"))}
        legacy_actions = iter((
            {"action": "tool", "tool": "bad", "arguments": {}},
            {"action": "final", "output": "done"},
        ))
        legacy = AgentLoop(max_steps=2).run(lambda _state: next(legacy_actions), tool, {})
        self.assertFalse(legacy.observations[0]["ok"])
        with self.assertRaises(_FatalToolError):
            AgentLoop().run(
                lambda _state: {"action": "tool", "tool": "bad", "arguments": {}},
                tool, {}, fatal_exceptions=(_FatalToolError,),
            )

    def test_projected_observation_is_bounded_and_raw_result_is_retained(self):
        @dataclass
        class Payload:
            identifier: str
            content: str

        payload = Payload("one", "x" * 500)
        actions = iter((
            {"action": "tool", "tool": "read", "arguments": {}},
            {"action": "final", "output": "done"},
        ))
        result = AgentLoop(max_steps=2, max_observation_chars=256).run(
            lambda _state: next(actions), {"read": lambda: payload}, {},
            result_projector=lambda value: {
                "identifier": value.identifier, "content": value.content,
            },
        )
        self.assertIs(payload, result.tool_results[0])
        self.assertTrue(result.observations[0]["truncated"])
        self.assertEqual(256, len(result.observations[0]["result"]))


class CxxAgentBudgetRestoreTests(unittest.TestCase):
    def test_usage_snapshot_restores_deduplication_and_remaining_budget(self):
        budget = CxxAgentBudget(max_calls=4, max_context_files=3,
                                max_context_lines=10, max_output_bytes=20)
        budget.consume(calls=1, files=1, lines=2, bytes=3, file_path="src/a.cc")
        caps = {
            "max_calls": budget.max_calls,
            "max_context_files": budget.max_context_files,
            "max_context_lines": budget.max_context_lines,
            "max_output_bytes": budget.max_output_bytes,
        }
        restored = CxxAgentBudget.from_usage(caps, budget.usage_snapshot())
        self.assertEqual(budget.remaining(), restored.remaining())
        restored.consume(files=1, file_path="src/a.cc")
        self.assertEqual(2, restored.remaining().files)

    def test_usage_restore_rejects_over_cap_and_duplicated_paths(self):
        caps = {
            "max_calls": 1, "max_context_files": 1,
            "max_context_lines": 1, "max_output_bytes": 1,
        }
        over_cap = {
            "version": 1, "used_calls": 2, "used_files": 0,
            "used_lines": 0, "used_bytes": 0, "files_read": [],
        }
        duplicated = {
            "version": 1, "used_calls": 0, "used_files": 1,
            "used_lines": 0, "used_bytes": 0, "files_read": ["a", "a"],
        }
        for usage in (over_cap, duplicated):
            with self.subTest(usage=usage):
                with self.assertRaises(ValueError):
                    CxxAgentBudget.from_usage(caps, usage)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
