"""Budget gate and real-run lock for LIMA v4 offline baselines (IP-0031).

This module owns the closed seven-code :class:`BudgetGateError` family with
verbatim stable messages, the two-level seven-dimension
``BudgetLimits``/``BudgetSpec`` value objects (int-only, zero budget
constructible), the ``CallEstimate``/``CallUsage``/``Pricing`` carriers in
which ``None`` never means zero (an absent price or token bound is unknown,
not free), the three-state :class:`BudgetLedger` with the frozen
reserve/record_usage/record_failure check order (reservations released on
failure, consumed usage retained, call counts never recycled, missing usage
a violation with the reservation kept), the :class:`LedgerSnapshot`
assertion surface with an injectable ``now_ns`` monotonic clock, and the
locked real-run gate.

The real-run gate is a module-level frozen constant
(:data:`REAL_RUN_GATE_UNLOCKED` is ``False``) and
:func:`require_real_run_unlock` raises unconditionally: there is no unlock
parameter, no configuration switch, and no unlock code path in this slice.
Unlocking requires a future Maintainer authorization with a numeric budget
plus a code change (the three prerequisites are recorded in the decision
pack ``docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md``).

The module is stdlib-only and offline: deterministic, no network, no
environment reads, no secrets, and no real-run state of any kind.
"""

import dataclasses
import enum
import math
import time
import typing

__all__ = [
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
]

#: The frozen seven-dimension order: cost, call count, tokens (prompt and
#: completion as two dimensions), wall time, and the controllable resources
#: (download and storage as two dimensions).  Spec validation, the reserve
#: check order, and the snapshot dimension key order all follow this tuple.
BUDGET_DIMENSIONS: typing.Final[tuple[str, ...]] = (
    "cost_micro_usd",
    "calls",
    "prompt_tokens",
    "completion_tokens",
    "wall_ms",
    "download_bytes",
    "storage_bytes",
)

#: The six accounted dimensions: ``BUDGET_DIMENSIONS`` without ``calls``
#: (calls are counted separately and never recycled).
_BOOK_DIMENSIONS: typing.Final[tuple[str, ...]] = tuple(
    dimension for dimension in BUDGET_DIMENSIONS if dimension != "calls"
)

#: The five estimate-carrier fields in their frozen validation order.
_ESTIMATE_FIELDS: typing.Final[tuple[str, ...]] = (
    "prompt_tokens",
    "completion_tokens",
    "wall_ms",
    "download_bytes",
    "storage_bytes",
)

#: The six usage-carrier fields in their frozen record_usage scan order
#: (the three required reporters first, then the three optional ones).
_USAGE_FIELDS: typing.Final[tuple[str, ...]] = (
    "prompt_tokens",
    "completion_tokens",
    "cost_micro_usd",
    "wall_ms",
    "download_bytes",
    "storage_bytes",
)

_REQUIRED_USAGE_FIELDS: typing.Final[frozenset[str]] = frozenset(
    ("prompt_tokens", "completion_tokens", "cost_micro_usd")
)

_PRICING_FIELDS: typing.Final[tuple[str, ...]] = (
    "prompt_token_price_micro_usd_per_million",
    "completion_token_price_micro_usd_per_million",
)

_NS_PER_MS: typing.Final[int] = 1_000_000
_TOKENS_PER_MILLION: typing.Final[int] = 1_000_000


class BudgetGateErrorCode(str, enum.Enum):  # noqa: UP042 -- frozen by IP-0031 Packet 7.1
    """Frozen wire values for every deterministic budget-gate failure."""

    BUDGET_SPEC_INVALID = "BUDGET_SPEC_INVALID"
    RUN_BUDGET_EXCEEDED = "RUN_BUDGET_EXCEEDED"
    BATCH_BUDGET_EXCEEDED = "BATCH_BUDGET_EXCEEDED"
    COST_NOT_PRE_BOUNDED = "COST_NOT_PRE_BOUNDED"
    USAGE_MISSING = "USAGE_MISSING"
    BUDGET_USAGE_INVALID = "BUDGET_USAGE_INVALID"
    REAL_RUN_LOCKED = "REAL_RUN_LOCKED"


_STABLE_MESSAGES: dict[BudgetGateErrorCode, str] = {
    BudgetGateErrorCode.BUDGET_SPEC_INVALID: (
        "The budget specification is invalid for this schema version."
    ),
    BudgetGateErrorCode.RUN_BUDGET_EXCEEDED: (
        "The per-run budget cap would be exceeded by this call."
    ),
    BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED: (
        "The batch budget cap would be exceeded by this call."
    ),
    BudgetGateErrorCode.COST_NOT_PRE_BOUNDED: (
        "The cost of this call cannot be pre-bounded because pricing is unknown"
        " or incomplete."
    ),
    BudgetGateErrorCode.USAGE_MISSING: (
        "Usage was not reported for a completed call; missing usage is a"
        " violation, not zero."
    ),
    BudgetGateErrorCode.BUDGET_USAGE_INVALID: (
        "Reported usage values are invalid for this schema version."
    ),
    BudgetGateErrorCode.REAL_RUN_LOCKED: (
        "Real-run execution is locked; a future Maintainer authorization with a"
        " numeric budget is required."
    ),
}


class BudgetGateError(ValueError):
    """Deterministic budget-gate violation with a stable code and message.

    The shape aligns with the frozen collection/spec/result/orchestration
    error precedents while remaining an independent class that neither
    subclasses nor reuses them.  The rendered message is exactly the catalog
    entry above; raw payloads, secrets, and numeric values are never
    embedded.  Use ``field_path`` for structure-only position reporting such
    as ``$.budget.per_run.calls``.
    """

    code: BudgetGateErrorCode
    field_path: str

    def __init__(self, code: BudgetGateErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BudgetGateErrorCode):
            raise TypeError("code must be a BudgetGateErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


@dataclasses.dataclass(frozen=True, slots=True)
class BudgetLimits:
    """Per-level caps across the frozen seven dimensions (int-only, >= 0).

    A zero budget is constructible (every dimension ``0``); the first
    ``reserve`` against it fails closed.  ``bool``, ``float``, ``str``, and
    negative values are rejected at construction with
    ``BUDGET_SPEC_INVALID`` under ``$.budget_limits.<dimension>``.  Caps are
    explicit ints: there is no ``None`` cap, because a dimension without a
    cap is not a representable state of this schema.
    """

    cost_micro_usd: int
    calls: int
    prompt_tokens: int
    completion_tokens: int
    wall_ms: int
    download_bytes: int
    storage_bytes: int

    def __post_init__(self) -> None:
        for name in BUDGET_DIMENSIONS:
            value = getattr(self, name)
            if type(value) is not int or value < 0:
                raise BudgetGateError(
                    BudgetGateErrorCode.BUDGET_SPEC_INVALID, f"$.budget_limits.{name}"
                )


@dataclasses.dataclass(frozen=True, slots=True)
class BudgetSpec:
    """Two-level budget specification: per-run caps plus batch caps.

    Construction fails fast with ``BUDGET_SPEC_INVALID`` under
    ``$.budget.batch.<dimension>`` for any batch dimension below the
    corresponding per-run dimension (a contradictory configuration must
    never reach the ledger).  Non-:class:`BudgetLimits` members raise
    ``TypeError`` (structural misuse).
    """

    per_run: BudgetLimits
    batch: BudgetLimits

    def __post_init__(self) -> None:
        if not isinstance(self.per_run, BudgetLimits) or not isinstance(
            self.batch, BudgetLimits
        ):
            raise TypeError("per_run and batch must be BudgetLimits instances")
        for name in BUDGET_DIMENSIONS:
            if getattr(self.batch, name) < getattr(self.per_run, name):
                raise BudgetGateError(
                    BudgetGateErrorCode.BUDGET_SPEC_INVALID, f"$.budget.batch.{name}"
                )


@dataclasses.dataclass(frozen=True, slots=True)
class CallEstimate:
    """Pre-call upper-bound carrier for one call; pure value object.

    All validation happens in :meth:`BudgetLedger.reserve`: a non-``None``
    value must be an exact non-negative ``int`` (``bool``/``float``/``str``
    rejected) with ``BUDGET_SPEC_INVALID`` under ``$.estimate.<field>``.
    ``None`` declares that this call reports no bound for the dimension; a
    missing token bound makes the cost not pre-bounded (never free).
    """

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    wall_ms: int | None = None
    download_bytes: int | None = None
    storage_bytes: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class CallUsage:
    """Post-call usage carrier for one call; pure value object.

    All judgment happens in :meth:`BudgetLedger.record_usage` and
    :meth:`BudgetLedger.record_failure`: missingness is judged on the three
    required reporters (prompt tokens, completion tokens, cost); ``None`` is
    legal absence only for wall/download/storage (booked as the ledger value
    zero without changing the missing-usage-is-a-violation judgment).
    """

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    cost_micro_usd: int | None = None
    wall_ms: int | None = None
    download_bytes: int | None = None
    storage_bytes: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class Pricing:
    """Token prices in micro-USD per million tokens; ``None`` means unknown.

    A ``None`` price dimension (or an all-``None`` table) is unknown
    pricing, never a zero price: any cost pre-bound on unknown pricing fails
    closed with ``COST_NOT_PRE_BOUNDED``.  Non-``None`` values must be exact
    non-negative ints (``bool``/``float``/negatives rejected at construction
    with ``BUDGET_SPEC_INVALID`` under ``$.pricing.<field>``).
    """

    prompt_token_price_micro_usd_per_million: int | None = None
    completion_token_price_micro_usd_per_million: int | None = None

    def __post_init__(self) -> None:
        for name in _PRICING_FIELDS:
            value = getattr(self, name)
            if value is None:
                continue
            if type(value) is not int or value < 0:
                raise BudgetGateError(
                    BudgetGateErrorCode.BUDGET_SPEC_INVALID, f"$.pricing.{name}"
                )


#: The real-run gate constant.  ``False`` is the only legal value in this
#: slice: there is no setter, no configuration switch, and no unlock path.
#: Unlocking requires a future Maintainer authorization with a numeric
#: budget plus a code change (three prerequisites, decision pack section 11).
REAL_RUN_GATE_UNLOCKED: bool = False


def require_real_run_unlock() -> None:
    """The single real-run entry-point behavior of this slice: always locked.

    Raises :class:`BudgetGateError` with ``REAL_RUN_LOCKED`` unconditionally.
    The function reads no state, accepts no arguments, and has no pass
    path; the gate constant above is the only related state and it is fixed
    to ``False``.
    """
    raise BudgetGateError(BudgetGateErrorCode.REAL_RUN_LOCKED, "$.real_run_gate")


def _require_run_id(run_id: object) -> None:
    """Enforce the run-id rule: a non-empty ``str`` (else ``TypeError``)."""
    if not isinstance(run_id, str) or not run_id:
        raise TypeError("run_id must be a non-empty str")


def _estimate_value(estimate: CallEstimate, name: str) -> int:
    """Resolve one estimate dimension to its booking value (``None`` -> 0)."""
    value = getattr(estimate, name)
    return 0 if value is None else value


@dataclasses.dataclass(frozen=True, slots=True)
class LedgerSnapshot:
    """Deep-copied per-run and batch books plus the violation count.

    Every per-run value and the batch value share one book shape:
    ``{"reserved": {...}, "consumed": {...}, "released": {...}, "calls": n}``
    with the six accounted dimensions as keys.  Mutating a returned
    snapshot can never pollute the ledger's internal state.
    """

    per_run: dict[str, dict[str, object]]
    batch: dict[str, object]
    violations: int


class _Book:
    """Internal mutable ledger book for one run or for the batch level."""

    __slots__ = ("calls", "consumed", "pending", "released", "reserved")

    def __init__(self) -> None:
        self.reserved: dict[str, int] = dict.fromkeys(_BOOK_DIMENSIONS, 0)
        self.consumed: dict[str, int] = dict.fromkeys(_BOOK_DIMENSIONS, 0)
        self.released: dict[str, int] = dict.fromkeys(_BOOK_DIMENSIONS, 0)
        self.pending: list[dict[str, int]] = []
        self.calls: int = 0

    def snapshot_book(self) -> dict[str, object]:
        return {
            "reserved": dict(self.reserved),
            "consumed": dict(self.consumed),
            "released": dict(self.released),
            "calls": self.calls,
        }


class BudgetLedger:
    """Three-state budget accounting: reserve, consume, release.

    The check order of :meth:`reserve` is frozen: structural gates, the
    per-run non-cost dimension gates (calls first, wall time with the
    already-elapsed pre-gate), the batch non-cost gates, the
    cost-not-pre-bounded gate, the two cost caps, and only then the
    booking (reservations entered, the call counted immediately and never
    recycled).  ``record_usage`` never re-checks caps: honest over-draw is
    booked and the next reserve is refused.  Missing usage is a violation
    (never booked as zero) and keeps the reservation occupied.
    """

    def __init__(
        self,
        spec: BudgetSpec,
        pricing: Pricing,
        *,
        now_ns: typing.Callable[[], int] = time.monotonic_ns,
    ) -> None:
        if not isinstance(spec, BudgetSpec):
            raise TypeError("spec must be a BudgetSpec instance")
        if not isinstance(pricing, Pricing):
            raise TypeError("pricing must be a Pricing instance")
        self._spec = spec
        self._pricing = pricing
        self._now_ns = now_ns
        self._start_ns = now_ns()
        self._runs: dict[str, _Book] = {}
        self._batch = _Book()
        self._violations = 0

    def reserve(self, run_id: str, estimate: CallEstimate) -> None:
        """Pre-call check and reservation entry (see the frozen gate order).

        Any refusal leaves zero bookings behind and the call count
        unchanged; the at-cap semantics is inclusive
        (``reserved + consumed + estimate == cap`` passes; the next call is
        refused).
        """
        _require_run_id(run_id)
        if not isinstance(estimate, CallEstimate):
            raise TypeError("estimate must be a CallEstimate instance")
        for name in _ESTIMATE_FIELDS:
            value = getattr(estimate, name)
            if value is not None and (type(value) is not int or value < 0):
                raise BudgetGateError(
                    BudgetGateErrorCode.BUDGET_SPEC_INVALID, f"$.estimate.{name}"
                )
        run = self._runs.get(run_id)
        gate_run = run if run is not None else _Book()
        per_run = self._spec.per_run
        batch = self._spec.batch
        elapsed_ms: int | None = None

        # Per-run non-cost gates in the frozen dimension order.
        if gate_run.calls + 1 > per_run.calls:
            raise BudgetGateError(
                BudgetGateErrorCode.RUN_BUDGET_EXCEEDED, "$.budget.per_run.calls"
            )
        for name in _BOOK_DIMENSIONS:
            if name == "cost_micro_usd":
                continue
            if name == "wall_ms":
                elapsed_ms = (self._now_ns() - self._start_ns) // _NS_PER_MS
                if elapsed_ms >= per_run.wall_ms:
                    raise BudgetGateError(
                        BudgetGateErrorCode.RUN_BUDGET_EXCEEDED, "$.budget.per_run.wall_ms"
                    )
            if gate_run.reserved[name] + gate_run.consumed[name] + _estimate_value(
                estimate, name
            ) > getattr(per_run, name):
                raise BudgetGateError(
                    BudgetGateErrorCode.RUN_BUDGET_EXCEEDED, f"$.budget.per_run.{name}"
                )

        # Batch non-cost gates in the same order against the batch book.
        if self._batch.calls + 1 > batch.calls:
            raise BudgetGateError(
                BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED, "$.budget.batch.calls"
            )
        for name in _BOOK_DIMENSIONS:
            if name == "cost_micro_usd":
                continue
            if name == "wall_ms":
                if elapsed_ms is None:
                    elapsed_ms = (self._now_ns() - self._start_ns) // _NS_PER_MS
                if elapsed_ms >= batch.wall_ms:
                    raise BudgetGateError(
                        BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED, "$.budget.batch.wall_ms"
                    )
            if self._batch.reserved[name] + self._batch.consumed[name] + _estimate_value(
                estimate, name
            ) > getattr(batch, name):
                raise BudgetGateError(
                    BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED, f"$.budget.batch.{name}"
                )

        # Cost-not-pre-bounded gate: unknown pricing or a missing token bound
        # is never treated as free (the closed four-way judgment, in order).
        if self._pricing.prompt_token_price_micro_usd_per_million is None:
            raise BudgetGateError(
                BudgetGateErrorCode.COST_NOT_PRE_BOUNDED,
                "$.pricing.prompt_token_price_micro_usd_per_million",
            )
        if self._pricing.completion_token_price_micro_usd_per_million is None:
            raise BudgetGateError(
                BudgetGateErrorCode.COST_NOT_PRE_BOUNDED,
                "$.pricing.completion_token_price_micro_usd_per_million",
            )
        if estimate.prompt_tokens is None:
            raise BudgetGateError(
                BudgetGateErrorCode.COST_NOT_PRE_BOUNDED, "$.estimate.prompt_tokens"
            )
        if estimate.completion_tokens is None:
            raise BudgetGateError(
                BudgetGateErrorCode.COST_NOT_PRE_BOUNDED, "$.estimate.completion_tokens"
            )

        # Cost caps with the frozen worst-case formula, per-run then batch.
        worst_case_cost = self._worst_case_cost(estimate)
        if (
            gate_run.reserved["cost_micro_usd"]
            + gate_run.consumed["cost_micro_usd"]
            + worst_case_cost
            > per_run.cost_micro_usd
        ):
            raise BudgetGateError(
                BudgetGateErrorCode.RUN_BUDGET_EXCEEDED, "$.budget.per_run.cost_micro_usd"
            )
        if (
            self._batch.reserved["cost_micro_usd"]
            + self._batch.consumed["cost_micro_usd"]
            + worst_case_cost
            > batch.cost_micro_usd
        ):
            raise BudgetGateError(
                BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED, "$.budget.batch.cost_micro_usd"
            )

        # Booking: enter the reservation on both levels and count the call
        # immediately (call counts are never recycled).
        entry = {name: _estimate_value(estimate, name) for name in _ESTIMATE_FIELDS}
        entry["cost_micro_usd"] = worst_case_cost
        if run is None:
            run = _Book()
            self._runs[run_id] = run
        for name in _BOOK_DIMENSIONS:
            run.reserved[name] += entry[name]
            self._batch.reserved[name] += entry[name]
        run.pending.append(entry)
        run.calls += 1
        self._batch.calls += 1

    def record_usage(self, run_id: str, usage: CallUsage | None) -> None:
        """Post-call reconciliation: missing usage is a violation, not zero.

        A ``None`` usage or a missing required field raises
        ``USAGE_MISSING`` (the violation count increments, nothing is booked
        as zero, and the reservation stays occupied).  Invalid values raise
        ``BUDGET_USAGE_INVALID``.  On success the oldest pending reservation
        settles: consumed grows by the reported usage on both levels, the
        unconsumed difference is released, and the reservation leaves the
        in-flight balance.  Usage without a pending reservation is still
        booked into consumed (honest accounting); caps are never re-checked
        here.
        """
        _require_run_id(run_id)
        if usage is None:
            self._violations += 1
            raise BudgetGateError(BudgetGateErrorCode.USAGE_MISSING, "$.usage")
        if not isinstance(usage, CallUsage):
            raise BudgetGateError(BudgetGateErrorCode.BUDGET_USAGE_INVALID, "$.usage")
        values = {name: 0 for name in _BOOK_DIMENSIONS}
        for name in _USAGE_FIELDS:
            value = getattr(usage, name)
            if value is None:
                if name in _REQUIRED_USAGE_FIELDS:
                    self._violations += 1
                    raise BudgetGateError(
                        BudgetGateErrorCode.USAGE_MISSING, f"$.usage.{name}"
                    )
                continue
            if type(value) is not int or value < 0:
                raise BudgetGateError(
                    BudgetGateErrorCode.BUDGET_USAGE_INVALID, f"$.usage.{name}"
                )
            values[name] = value
        self._settle(run_id, values)

    def record_failure(self, run_id: str, usage: CallUsage | None = None) -> None:
        """Failure or cancellation: release the reservation, keep the spent.

        The oldest pending reservation is released (its unconsumed part
        counts as released, its reserved amount leaves the in-flight
        balance) while any partially reported usage is retained in consumed.
        The call count is not recycled: a granted call is a granted call.
        Subsequent reserves for the same run are still checked against the
        caps normally.
        """
        _require_run_id(run_id)
        if usage is not None and not isinstance(usage, CallUsage):
            raise TypeError("usage must be a CallUsage instance or None")
        values = {name: 0 for name in _BOOK_DIMENSIONS}
        if usage is not None:
            for name in _USAGE_FIELDS:
                value = getattr(usage, name)
                if value is None:
                    continue
                if type(value) is not int or value < 0:
                    raise BudgetGateError(
                        BudgetGateErrorCode.BUDGET_USAGE_INVALID, f"$.usage.{name}"
                    )
                values[name] = value
        self._settle(run_id, values)

    def snapshot(self) -> LedgerSnapshot:
        """Return a fresh deep copy of the per-run and batch books."""
        per_run = {
            run_id: book.snapshot_book() for run_id, book in self._runs.items()
        }
        return LedgerSnapshot(
            per_run=per_run,
            batch=self._batch.snapshot_book(),
            violations=self._violations,
        )

    def _worst_case_cost(self, estimate: CallEstimate) -> int:
        """The frozen worst-case cost formula (ceil on both token terms)."""
        price_p = self._pricing.prompt_token_price_micro_usd_per_million
        price_c = self._pricing.completion_token_price_micro_usd_per_million
        return math.ceil(price_p * estimate.prompt_tokens / _TOKENS_PER_MILLION) + math.ceil(
            price_c * estimate.completion_tokens / _TOKENS_PER_MILLION
        )

    def _settle(self, run_id: str, values: dict[str, int]) -> None:
        """Settle the oldest pending reservation against reported values."""
        run = self._runs.get(run_id)
        if run is None:
            run = _Book()
            self._runs[run_id] = run
        entry = run.pending.pop(0) if run.pending else None
        for name in _BOOK_DIMENSIONS:
            actual = values[name]
            run.consumed[name] += actual
            self._batch.consumed[name] += actual
            if entry is None:
                continue
            difference = entry[name] - actual
            if difference > 0:
                run.released[name] += difference
                self._batch.released[name] += difference
            run.reserved[name] -= entry[name]
            self._batch.reserved[name] -= entry[name]
