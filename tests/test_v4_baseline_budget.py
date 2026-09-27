"""Frozen acceptance tests for IP-0031: budget gate and real-run lock (Issue #221).

Contract under test (frozen by Coordinator Assignment CA-IP-0031-v1.0 of
2026-09-27; see docs/LIMA_Implementation_Packet_IP-0031_Offline_Budget_Gate.md):

- The Implementation deliverable is ``benchmarks/v4/baseline/budget.py``: the
  closed seven-code ``BudgetGateError`` family with verbatim stable messages,
  the two-level seven-dimension ``BudgetLimits``/``BudgetSpec`` value objects
  (int-only, zero budget constructible), ``CallEstimate``/``CallUsage``/
  ``Pricing`` carriers (None never means zero), the ``BudgetLedger`` with the
  frozen reserve/record_usage/record_failure check order and three-state
  accounting (reservations released on failure, consumed usage retained, call
  counts never recycled, missing usage a violation with the reservation kept),
  ``LedgerSnapshot`` as the single assertion surface, the injectable
  ``now_ns`` monotonic clock, and the locked real-run gate
  (``REAL_RUN_GATE_UNLOCKED is False``; ``require_real_run_unlock()`` raises
  unconditionally with ``REAL_RUN_LOCKED``).
- The worst-case cost formula is frozen as
  ``ceil(price_p * prompt_tokens / 1_000_000) + ceil(price_c * completion_tokens
  / 1_000_000)``; unknown pricing or missing token bounds is
  ``COST_NOT_PRE_BOUNDED``, never free. The at-cap semantics is frozen:
  ``reserved + consumed + estimate == cap`` passes and the next call is
  refused.
- Offline hygiene scans cover both new modules (``budget.py`` and
  ``benchmarks/v4/baseline/offline_flow.py``): no network imports, no
  environment reads, and exactly one ``REAL_RUN_GATE_UNLOCKED`` assignment
  whose value is the constant ``False`` (no unlock setter). Every scanner is
  validated in-test against a deliberately violating positive control string
  and against this file's own source (token concatenation, PC1).

Expected RED before implementation: every behavior test fails on the missing
deliverable -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.budget'``
(lazy per-test import), and the hygiene tests that read
``benchmarks/v4/baseline/offline_flow.py`` fail with "required product source
is missing" while that second deliverable is absent. The suite is offline and
secretless: stdlib only, no network, no environment reads, no paid calls.
"""

import ast
import math
import pathlib
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_BUDGET_MODULE_RELATIVE_PATH = "benchmarks/v4/baseline/budget.py"
_OFFLINE_FLOW_MODULE_RELATIVE_PATH = "benchmarks/v4/baseline/offline_flow.py"

_FROZEN_DIMENSIONS = (
    "cost_micro_usd",
    "calls",
    "prompt_tokens",
    "completion_tokens",
    "wall_ms",
    "download_bytes",
    "storage_bytes",
)

_BUDGET_ALL = (
    "BudgetGateError",
    "BudgetGateErrorCode",
    "BudgetLimits",
    "BudgetSpec",
    "BUDGET_DIMENSIONS",
    "CallEstimate",
    "CallUsage",
    "Pricing",
    "BudgetLedger",
    "LedgerSnapshot",
    "REAL_RUN_GATE_UNLOCKED",
    "require_real_run_unlock",
)

_ERROR_MESSAGES = {
    "BUDGET_SPEC_INVALID": "The budget specification is invalid for this schema version.",
    "RUN_BUDGET_EXCEEDED": "The per-run budget cap would be exceeded by this call.",
    "BATCH_BUDGET_EXCEEDED": "The batch budget cap would be exceeded by this call.",
    "COST_NOT_PRE_BOUNDED": (
        "The cost of this call cannot be pre-bounded because pricing is unknown or incomplete."
    ),
    "USAGE_MISSING": (
        "Usage was not reported for a completed call; missing usage is a violation, not zero."
    ),
    "BUDGET_USAGE_INVALID": "Reported usage values are invalid for this schema version.",
    "REAL_RUN_LOCKED": (
        "Real-run execution is locked; a future Maintainer authorization with a numeric budget"
        " is required."
    ),
}

_BOOK_KEYS = {"reserved", "consumed", "released", "calls"}
_GATE_CONSTANT_NAME = "REAL_RUN_GATE_UNLOCKED"


def _forbidden_network_roots():
    """First-level import roots that must never be imported by the new modules."""
    return {"sock" + "et", "url" + "lib", "requ" + "ests", "http"}


def _network_import_roots(source):
    """First-level import roots of a python source string (AST parse, no exec)."""
    tree = ast.parse(source)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def _environ_token():
    """The forbidden environment-read token, built by concatenation (PC1)."""
    return "os." + "environ"


def _gate_unlock_assignments(source):
    """AST values of every assignment targeting the frozen gate constant."""
    tree = ast.parse(source)
    values = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            targets = node.targets
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
        else:
            continue
        for target in targets:
            if isinstance(target, ast.Name) and target.id == _GATE_CONSTANT_NAME:
                values.append(node.value)
    return values


class _SteppingClock:
    """Injectable monotonic clock: returns the current value and steps after."""

    def __init__(self):
        self.now_ns_value = 1_000_000_000
        self.step_ns = 0

    def __call__(self):
        value = self.now_ns_value
        self.now_ns_value += self.step_ns
        return value


class _BudgetTestCase(unittest.TestCase):
    """Shared arrange helpers (no collected test methods)."""

    def budget(self):
        import benchmarks.v4.baseline.budget as budget_module

        return budget_module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def limits(self, **overrides):
        values = {
            "cost_micro_usd": 10_000,
            "calls": 10,
            "prompt_tokens": 10_000,
            "completion_tokens": 10_000,
            "wall_ms": 10_000_000,
            "download_bytes": 10_000,
            "storage_bytes": 10_000,
        }
        values.update(overrides)
        return self.budget().BudgetLimits(**values)

    def zero_limits(self):
        return self.limits(
            cost_micro_usd=0,
            calls=0,
            prompt_tokens=0,
            completion_tokens=0,
            wall_ms=0,
            download_bytes=0,
            storage_bytes=0,
        )

    def spec(self, per_run=None, batch=None):
        module = self.budget()
        return module.BudgetSpec(
            per_run=self.limits() if per_run is None else per_run,
            batch=self.limits() if batch is None else batch,
        )

    def prices(self, prompt=1_000_000, completion=1_000_000):
        return self.budget().Pricing(
            prompt_token_price_micro_usd_per_million=prompt,
            completion_token_price_micro_usd_per_million=completion,
        )

    def ledger(self, spec=None, pricing=None, now_ns=None):
        module = self.budget()
        kwargs = {}
        if now_ns is not None:
            kwargs["now_ns"] = now_ns
        return module.BudgetLedger(
            spec if spec is not None else self.spec(),
            pricing if pricing is not None else self.prices(),
            **kwargs,
        )

    def estimate(self, **overrides):
        values = {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "wall_ms": 10,
            "download_bytes": 5,
            "storage_bytes": 3,
        }
        values.update(overrides)
        return self.budget().CallEstimate(**values)

    def usage(self, **overrides):
        values = {
            "prompt_tokens": 90,
            "completion_tokens": 40,
            "cost_micro_usd": 12,
            "wall_ms": 8,
            "download_bytes": 5,
            "storage_bytes": 0,
        }
        values.update(overrides)
        return self.budget().CallUsage(**values)

    def oracle_cost(self, prompt_tokens, completion_tokens):
        """Independent re-evaluation of the frozen worst-case cost formula."""
        price = 1_000_000
        return math.ceil(price * prompt_tokens / 1_000_000) + math.ceil(
            price * completion_tokens / 1_000_000
        )

    def assert_budget_error(self, action, code, field_path):
        module = self.budget()
        with self.assertRaises(module.BudgetGateError) as caught:
            action()
        self.assertIs(caught.exception.code, module.BudgetGateErrorCode[code])
        self.assertEqual(caught.exception.field_path, field_path)
        self.assertEqual(str(caught.exception), _ERROR_MESSAGES[code])


class TestBudgetSpecValidation(_BudgetTestCase):
    """FR-03: value objects, zero budget, snapshot surface."""

    def test_limits_reject_non_int_dimension_values(self):
        for dimension in _FROZEN_DIMENSIONS:
            for bad in (True, 1.5, "10"):
                with self.subTest(dimension=dimension, bad=bad):
                    self.assert_budget_error(
                        lambda bad=bad, dimension=dimension: self.limits(**{dimension: bad}),
                        "BUDGET_SPEC_INVALID",
                        f"$.budget_limits.{dimension}",
                    )

    def test_limits_reject_negative_dimension_values(self):
        for dimension in _FROZEN_DIMENSIONS:
            with self.subTest(dimension=dimension):
                self.assert_budget_error(
                    lambda dimension=dimension: self.limits(**{dimension: -1}),
                    "BUDGET_SPEC_INVALID",
                    f"$.budget_limits.{dimension}",
                )

    def test_spec_rejects_batch_below_per_run_component(self):
        cases = {
            "cost_micro_usd": (100, 99),
            "calls": (2, 1),
        }
        for dimension, (per_run_value, batch_value) in cases.items():
            with self.subTest(dimension=dimension):
                module = self.budget()
                per_run = self.limits(**{dimension: per_run_value})
                batch = self.limits(**{dimension: batch_value})
                with self.assertRaises(module.BudgetGateError) as caught:
                    module.BudgetSpec(per_run=per_run, batch=batch)
                self.assertIs(
                    caught.exception.code, module.BudgetGateErrorCode.BUDGET_SPEC_INVALID
                )
                self.assertEqual(caught.exception.field_path, f"$.budget.batch.{dimension}")

    def test_zero_budget_is_constructible(self):
        module = self.budget()
        zero = self.zero_limits()
        spec = module.BudgetSpec(per_run=zero, batch=zero)
        ledger = module.BudgetLedger(spec, self.prices())
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.batch["calls"], 0)
        self.assertEqual(set(snapshot.per_run), set())
        self.assertEqual(snapshot.violations, 0)

    def test_public_surface_and_snapshot_field_set(self):
        module = self.budget()
        self.assertEqual(tuple(module.__all__), _BUDGET_ALL)
        self.assertEqual(module.BUDGET_DIMENSIONS, _FROZEN_DIMENSIONS)
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        snapshot = ledger.snapshot()
        six = tuple(d for d in module.BUDGET_DIMENSIONS if d != "calls")
        self.assertEqual(set(snapshot.per_run), {"run-1"})
        books = snapshot.per_run["run-1"]
        self.assertEqual(set(books), _BOOK_KEYS)
        self.assertEqual(set(snapshot.batch), _BOOK_KEYS)
        for holder in (books, snapshot.batch):
            for book in ("reserved", "consumed", "released"):
                self.assertEqual(set(holder[book]), set(six))
        self.assertIs(type(snapshot.violations), int)


class TestReserveAndConsume(_BudgetTestCase):
    """FR-03 positive paths: reservation, usage accounting, call counting, at-cap."""

    def test_reserve_books_estimate_and_call_count(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        snapshot = ledger.snapshot()
        books = snapshot.per_run["run-1"]
        expected_reserved = {
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "cost_micro_usd": self.oracle_cost(100, 50),
            "wall_ms": 10,
            "download_bytes": 5,
            "storage_bytes": 3,
        }
        self.assertEqual(books["reserved"], expected_reserved)
        self.assertEqual(books["calls"], 1)
        self.assertEqual(snapshot.batch["reserved"], expected_reserved)
        self.assertEqual(snapshot.batch["calls"], 1)

    def test_usage_moves_consumed_and_releases_difference(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        ledger.record_usage("run-1", self.usage())
        books = ledger.snapshot().per_run["run-1"]
        self.assertEqual(
            books["consumed"],
            {
                "prompt_tokens": 90,
                "completion_tokens": 40,
                "cost_micro_usd": 12,
                "wall_ms": 8,
                "download_bytes": 5,
                "storage_bytes": 0,
            },
        )
        self.assertEqual(
            books["released"],
            {
                "prompt_tokens": 10,
                "completion_tokens": 10,
                "cost_micro_usd": self.oracle_cost(100, 50) - 12,
                "wall_ms": 2,
                "download_bytes": 0,
                "storage_bytes": 3,
            },
        )
        self.assertEqual(set(books["reserved"].values()), {0})

    def test_call_counts_accumulate_per_run_and_batch(self):
        ledger = self.ledger()
        ledger.reserve("run-a", self.estimate())
        ledger.reserve("run-a", self.estimate())
        ledger.reserve("run-b", self.estimate())
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.per_run["run-a"]["calls"], 2)
        self.assertEqual(snapshot.per_run["run-b"]["calls"], 1)
        self.assertEqual(snapshot.batch["calls"], 3)

    def test_exactly_at_cap_passes_for_calls_and_cost(self):
        spec = self.spec(per_run=self.limits(calls=2))
        ledger = self.ledger(spec=spec)
        ledger.reserve("run-1", self.estimate())
        ledger.reserve("run-1", self.estimate())
        self.assertEqual(ledger.snapshot().per_run["run-1"]["calls"], 2)
        cost_cap = self.oracle_cost(100, 50)
        cost_spec = self.spec(per_run=self.limits(cost_micro_usd=cost_cap))
        cost_ledger = self.ledger(spec=cost_spec)
        cost_ledger.reserve("run-1", self.estimate())
        self.assertEqual(cost_ledger.snapshot().batch["calls"], 1)


class TestFailClosedNegatives(_BudgetTestCase):
    """FR-06 / AC-2: the frozen negative matrix, every refusal fail closed."""

    def test_zero_budget_first_reserve_refused_with_zero_bookings(self):
        module = self.budget()
        spec = module.BudgetSpec(per_run=self.zero_limits(), batch=self.zero_limits())
        ledger = self.ledger(spec=spec)
        self.assert_budget_error(
            lambda: ledger.reserve("run-1", self.estimate()),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.calls",
        )
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.batch["calls"], 0)
        self.assertEqual(set(snapshot.per_run), set())
        for book in ("reserved", "consumed", "released"):
            self.assertEqual(set(snapshot.batch[book].values()), {0})

    def test_call_after_reaching_cap_is_refused(self):
        spec = self.spec(per_run=self.limits(calls=2))
        ledger = self.ledger(spec=spec)
        ledger.reserve("run-1", self.estimate())
        ledger.reserve("run-1", self.estimate())
        self.assert_budget_error(
            lambda: ledger.reserve("run-1", self.estimate()),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.calls",
        )
        self.assertEqual(ledger.snapshot().per_run["run-1"]["calls"], 2)

    def test_per_run_cost_cap_refused(self):
        cap = self.oracle_cost(100, 50) - 1
        ledger = self.ledger(spec=self.spec(per_run=self.limits(cost_micro_usd=cap)))
        self.assert_budget_error(
            lambda: ledger.reserve("run-1", self.estimate()),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.cost_micro_usd",
        )

    def test_per_run_token_and_resource_dimensions_refused(self):
        cases = {
            "prompt_tokens": "$.budget.per_run.prompt_tokens",
            "completion_tokens": "$.budget.per_run.completion_tokens",
            "download_bytes": "$.budget.per_run.download_bytes",
            "storage_bytes": "$.budget.per_run.storage_bytes",
        }
        for dimension, field_path in cases.items():
            with self.subTest(dimension=dimension):
                ledger = self.ledger(spec=self.spec(per_run=self.limits(**{dimension: 0})))
                self.assert_budget_error(
                    lambda ledger=ledger: ledger.reserve("run-1", self.estimate()),
                    "RUN_BUDGET_EXCEEDED",
                    field_path,
                )

    def test_wall_clock_gate_refused_with_injected_clock(self):
        clock = _SteppingClock()
        spec = self.spec(per_run=self.limits(wall_ms=1_000))
        ledger = self.ledger(spec=spec, now_ns=clock)
        clock.now_ns_value += 1_001 * 1_000_000
        self.assert_budget_error(
            lambda: ledger.reserve("run-1", self.estimate()),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.wall_ms",
        )
        estimate_ledger = self.ledger(spec=self.spec(per_run=self.limits(wall_ms=1_000)))
        self.assert_budget_error(
            lambda: estimate_ledger.reserve("run-1", self.estimate(wall_ms=2_000)),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.wall_ms",
        )

    def test_batch_cost_accumulation_refused(self):
        first = self.oracle_cost(100, 50)
        second = self.oracle_cost(80, 40)
        spec = self.spec(batch=self.limits(cost_micro_usd=first + second - 1))
        ledger = self.ledger(spec=spec)
        ledger.reserve("run-a", self.estimate())
        ledger.reserve("run-b", self.estimate(prompt_tokens=80, completion_tokens=40))
        self.assert_budget_error(
            lambda: ledger.reserve(
                "run-c", self.estimate(prompt_tokens=10, completion_tokens=10)
            ),
            "BATCH_BUDGET_EXCEEDED",
            "$.budget.batch.cost_micro_usd",
        )

    def test_missing_usage_field_is_violation_with_reservation_kept(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        self.assert_budget_error(
            lambda: ledger.record_usage("run-1", self.usage(prompt_tokens=None)),
            "USAGE_MISSING",
            "$.usage.prompt_tokens",
        )
        snapshot = ledger.snapshot()
        books = snapshot.per_run["run-1"]
        self.assertEqual(books["reserved"]["prompt_tokens"], 100)
        self.assertEqual(books["consumed"]["prompt_tokens"], 0)
        self.assertEqual(set(books["released"].values()), {0})
        self.assertEqual(snapshot.violations, 1)

    def test_none_usage_is_violation_not_zero(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        self.assert_budget_error(
            lambda: ledger.record_usage("run-1", None),
            "USAGE_MISSING",
            "$.usage",
        )
        snapshot = ledger.snapshot()
        books = snapshot.per_run["run-1"]
        self.assertEqual(set(books["consumed"].values()), {0})
        self.assertEqual(books["reserved"]["prompt_tokens"], 100)
        self.assertEqual(snapshot.violations, 1)

    def test_unknown_pricing_is_not_free(self):
        cases = (
            (
                self.prices(prompt=None),
                "$.pricing.prompt_token_price_micro_usd_per_million",
            ),
            (
                self.prices(completion=None),
                "$.pricing.completion_token_price_micro_usd_per_million",
            ),
        )
        for pricing, field_path in cases:
            with self.subTest(field_path=field_path):
                ledger = self.ledger(pricing=pricing)
                self.assert_budget_error(
                    lambda ledger=ledger: ledger.reserve("run-1", self.estimate()),
                    "COST_NOT_PRE_BOUNDED",
                    field_path,
                )
        unbounded = self.ledger()
        self.assert_budget_error(
            lambda: unbounded.reserve("run-1", self.estimate(prompt_tokens=None)),
            "COST_NOT_PRE_BOUNDED",
            "$.estimate.prompt_tokens",
        )
        self.assert_budget_error(
            lambda: unbounded.reserve("run-2", self.estimate(completion_tokens=None)),
            "COST_NOT_PRE_BOUNDED",
            "$.estimate.completion_tokens",
        )

    def test_require_real_run_unlock_always_raises_locked(self):
        module = self.budget()
        self.assertIs(module.REAL_RUN_GATE_UNLOCKED, False)
        self.assertIs(type(module.REAL_RUN_GATE_UNLOCKED), bool)
        with self.assertRaises(module.BudgetGateError) as caught:
            module.require_real_run_unlock()
        self.assertIs(caught.exception.code, module.BudgetGateErrorCode.REAL_RUN_LOCKED)
        self.assertEqual(caught.exception.field_path, "$.real_run_gate")
        self.assertEqual(str(caught.exception), _ERROR_MESSAGES["REAL_RUN_LOCKED"])

    def test_invalid_usage_values_refused(self):
        cases = (("prompt_tokens", -5), ("cost_micro_usd", True), ("wall_ms", 1.5))
        for field, bad in cases:
            with self.subTest(field=field, bad=bad):
                ledger = self.ledger()
                ledger.reserve("run-1", self.estimate())
                self.assert_budget_error(
                    lambda bad=bad, field=field, ledger=ledger: ledger.record_usage(
                        "run-1", self.usage(**{field: bad})
                    ),
                    "BUDGET_USAGE_INVALID",
                    f"$.usage.{field}",
                )
                self.assertEqual(ledger.snapshot().violations, 0)


class TestFailureCancelAccounting(_BudgetTestCase):
    """FR-06: failure and cancellation accounting semantics."""

    def test_record_failure_releases_reservation(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        ledger.record_failure("run-1")
        books = ledger.snapshot().per_run["run-1"]
        self.assertEqual(set(books["reserved"].values()), {0})
        self.assertEqual(
            books["released"],
            {
                "prompt_tokens": 100,
                "completion_tokens": 50,
                "cost_micro_usd": self.oracle_cost(100, 50),
                "wall_ms": 10,
                "download_bytes": 5,
                "storage_bytes": 3,
            },
        )
        self.assertEqual(set(books["consumed"].values()), {0})

    def test_failure_with_partial_usage_retains_consumed_part(self):
        module = self.budget()
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        ledger.record_failure("run-1", module.CallUsage(prompt_tokens=60))
        books = ledger.snapshot().per_run["run-1"]
        self.assertEqual(books["consumed"]["prompt_tokens"], 60)
        self.assertEqual(books["consumed"]["completion_tokens"], 0)
        self.assertEqual(books["released"]["prompt_tokens"], 40)
        self.assertEqual(books["released"]["completion_tokens"], 50)
        self.assertEqual(set(books["reserved"].values()), {0})

    def test_call_counts_are_never_recycled(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        ledger.record_failure("run-1")
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.per_run["run-1"]["calls"], 1)
        self.assertEqual(snapshot.batch["calls"], 1)

    def test_reserve_after_failure_still_checked_against_caps(self):
        spec = self.spec(per_run=self.limits(calls=2))
        ledger = self.ledger(spec=spec)
        ledger.reserve("run-1", self.estimate())
        ledger.record_failure("run-1")
        ledger.reserve("run-1", self.estimate())
        self.assertEqual(ledger.snapshot().per_run["run-1"]["calls"], 2)
        self.assert_budget_error(
            lambda: ledger.reserve("run-1", self.estimate()),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.calls",
        )


class TestGateHygiene(_BudgetTestCase):
    """AC-2 locked state: source-level guarantees for both new modules."""

    def test_real_run_gate_constant_is_false(self):
        module = self.budget()
        self.assertIs(module.REAL_RUN_GATE_UNLOCKED, False)
        self.assertIs(type(module.REAL_RUN_GATE_UNLOCKED), bool)

    def test_new_modules_have_no_network_imports(self):
        forbidden = _forbidden_network_roots()
        violating_source = "import " + "sock" + "et\n"
        self.assertTrue(_network_import_roots(violating_source) & forbidden)
        own_roots = _network_import_roots(pathlib.Path(__file__).read_text(encoding="utf-8"))
        self.assertFalse(own_roots & forbidden)
        for relative in (_BUDGET_MODULE_RELATIVE_PATH, _OFFLINE_FLOW_MODULE_RELATIVE_PATH):
            with self.subTest(module=relative):
                roots = _network_import_roots(self.product_source(relative))
                self.assertFalse(roots & forbidden)

    def test_no_environment_reads_and_single_false_gate_assignment(self):
        token = _environ_token()
        self.assertIn(token, "value = " + token + "['X']\n")
        own_source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertNotIn(token, own_source)
        budget_source = self.product_source(_BUDGET_MODULE_RELATIVE_PATH)
        flow_source = self.product_source(_OFFLINE_FLOW_MODULE_RELATIVE_PATH)
        self.assertNotIn(token, budget_source)
        self.assertNotIn(token, flow_source)
        self.assertEqual(_gate_unlock_assignments(own_source), [])
        assignments = _gate_unlock_assignments(budget_source)
        self.assertEqual(len(assignments), 1)
        self.assertIsInstance(assignments[0], ast.Constant)
        self.assertIs(assignments[0].value, False)
        violating = _gate_unlock_assignments(_GATE_CONSTANT_NAME + " = True\n")
        self.assertEqual(len(violating), 1)
        self.assertIs(violating[0].value, True)


class TestLedgerInvariants(_BudgetTestCase):
    """FR-03 invariants: accounting identity, injected clock, snapshot freshness."""

    def test_reserved_consumed_released_identity_holds(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        ledger.record_usage("run-1", self.usage())
        ledger.reserve(
            "run-2",
            self.estimate(
                prompt_tokens=80, completion_tokens=40, wall_ms=20, download_bytes=4,
                storage_bytes=2,
            ),
        )
        ledger.record_failure("run-2")
        snapshot = ledger.snapshot()
        for run_id in ("run-1", "run-2"):
            self.assertEqual(set(snapshot.per_run[run_id]["reserved"].values()), {0})
        run_one = snapshot.per_run["run-1"]
        self.assertEqual(run_one["consumed"]["prompt_tokens"], 90)
        self.assertEqual(run_one["consumed"]["cost_micro_usd"], 12)
        self.assertEqual(run_one["released"]["prompt_tokens"], 10)
        run_two = snapshot.per_run["run-2"]
        self.assertEqual(set(run_two["consumed"].values()), {0})
        self.assertEqual(
            run_two["released"],
            {
                "prompt_tokens": 80,
                "completion_tokens": 40,
                "cost_micro_usd": self.oracle_cost(80, 40),
                "wall_ms": 20,
                "download_bytes": 4,
                "storage_bytes": 2,
            },
        )
        batch = snapshot.batch
        self.assertEqual(batch["calls"], 2)
        self.assertEqual(batch["consumed"]["prompt_tokens"], 90)
        self.assertEqual(batch["consumed"]["cost_micro_usd"], 12)
        self.assertEqual(batch["released"]["prompt_tokens"], 10 + 80)
        self.assertEqual(snapshot.violations, 0)

    def test_injected_clock_drives_wall_gate(self):
        clock = _SteppingClock()
        spec = self.spec(per_run=self.limits(wall_ms=5_000))
        ledger = self.ledger(spec=spec, now_ns=clock)
        ledger.reserve("run-1", self.estimate())
        self.assertEqual(ledger.snapshot().batch["calls"], 1)
        clock.now_ns_value += 5_000 * 1_000_000
        self.assert_budget_error(
            lambda: ledger.reserve("run-1", self.estimate()),
            "RUN_BUDGET_EXCEEDED",
            "$.budget.per_run.wall_ms",
        )

    def test_snapshot_is_fresh_copy_of_operation_state(self):
        ledger = self.ledger()
        ledger.reserve("run-1", self.estimate())
        snapshot = ledger.snapshot()
        snapshot.per_run["run-1"]["reserved"]["prompt_tokens"] = 999_999
        fresh = ledger.snapshot()
        self.assertEqual(fresh.per_run["run-1"]["reserved"]["prompt_tokens"], 100)
        self.assertEqual(fresh.batch["reserved"]["prompt_tokens"], 100)
        self.assertEqual(fresh.batch["calls"], 1)
        self.assertEqual(fresh.violations, 0)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
