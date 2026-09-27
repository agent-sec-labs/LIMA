"""Shared budget accounting tests (retirement Task 2 trim).

Only ``CxxAgentBudget`` and friends remain in the module; the registry,
symbol, snippet and evidence tool test classes rode the retired
seven-role chain.
"""

from __future__ import annotations

import dataclasses
import threading
import unittest

from lima.cxx_agent_tools import (
    AgentBudgetExceeded,
    CxxAgentBudget,
    RemainingBudget,
)


class CxxAgentBudgetTests(unittest.TestCase):
    def test_defaults_match_task_config_limits(self):
        budget = CxxAgentBudget()
        self.assertEqual(40, budget.max_calls)
        self.assertEqual(12, budget.max_context_files)
        self.assertEqual(1200, budget.max_context_lines)
        self.assertEqual(1_048_576, budget.max_output_bytes)

    def test_budget_rejects_invalid_limits(self):
        for field in (
            "max_calls",
            "max_context_files",
            "max_context_lines",
            "max_output_bytes",
        ):
            for value in (0, -1, True, 2.5, "40"):
                with self.subTest(field=field, value=value):
                    with self.assertRaises(ValueError):
                        CxxAgentBudget(**{field: value})

    def test_consume_is_atomic_all_or_nothing(self):
        budget = CxxAgentBudget(max_calls=1, max_context_lines=10)
        with self.assertRaises(AgentBudgetExceeded):
            budget.consume(calls=1, lines=100)
        self.assertEqual((1, 10), (budget.remaining().calls, budget.remaining().lines))
        budget.consume(calls=1, lines=10)
        self.assertEqual((0, 0), (budget.remaining().calls, budget.remaining().lines))

    def test_error_message_names_dimension_and_remaining(self):
        budget = CxxAgentBudget(max_calls=1, max_context_lines=5)
        with self.assertRaises(AgentBudgetExceeded) as caught:
            budget.consume(calls=1, lines=6)
        message = str(caught.exception)
        self.assertIn("lines", message)
        self.assertIn("5", message)
        self.assertEqual(1, budget.remaining().calls)

    def test_concurrent_consume_calls_never_exceed_budget(self):
        budget = CxxAgentBudget(max_calls=8)
        barrier = threading.Barrier(24)
        successes = []

        def worker():
            barrier.wait()
            try:
                budget.consume_call()
                successes.append(1)
            except AgentBudgetExceeded:
                pass

        threads = [threading.Thread(target=worker) for _ in range(24)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(8, len(successes))
        self.assertEqual(0, budget.remaining().calls)

    def test_concurrent_combined_consume_stays_consistent(self):
        budget = CxxAgentBudget(max_calls=10, max_context_lines=30)
        barrier = threading.Barrier(28)
        successes = []

        def worker():
            barrier.wait()
            try:
                budget.consume(calls=1, lines=4)
                successes.append(1)
            except AgentBudgetExceeded:
                pass

        threads = [threading.Thread(target=worker) for _ in range(28)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(5)
        self.assertEqual(7, len(successes))
        self.assertEqual(3, budget.remaining().calls)
        self.assertEqual(2, budget.remaining().lines)

    def test_thin_wrappers_charge_the_shared_pool(self):
        budget = CxxAgentBudget()
        budget.consume_call()
        budget.consume_files(2)
        budget.consume_lines(3)
        budget.consume_bytes(7)
        remaining = budget.remaining()
        self.assertEqual(39, remaining.calls)
        self.assertEqual(10, remaining.files)
        self.assertEqual(1197, remaining.lines)
        self.assertEqual(1_048_576 - 7, remaining.bytes_remaining)

    def test_consume_rejects_negative_or_boolean_amounts(self):
        budget = CxxAgentBudget()
        for kwargs in (
            {"calls": -1},
            {"files": -2},
            {"lines": True},
            {"bytes": False},
            {"calls": 1.5},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ValueError):
                    budget.consume(**kwargs)
        self.assertEqual(40, budget.remaining().calls)

    def test_remaining_is_a_frozen_non_mutating_snapshot(self):
        budget = CxxAgentBudget()
        first = budget.remaining()
        self.assertIsInstance(first, RemainingBudget)
        self.assertEqual(first, budget.remaining())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            first.calls = 5
        budget.consume_call()
        self.assertEqual(39, budget.remaining().calls)
        self.assertEqual(40, first.calls)

    def test_file_charge_is_idempotent_per_path(self):
        budget = CxxAgentBudget(max_context_files=1)
        budget.consume(calls=1, files=1, lines=2, bytes=3, file_path="src/a.c")
        budget.consume(calls=1, files=1, lines=2, bytes=3, file_path="src/a.c")
        self.assertEqual(0, budget.remaining().files)
        with self.assertRaises(AgentBudgetExceeded):
            budget.consume(calls=1, files=1, lines=1, bytes=1, file_path="src/b.c")


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
