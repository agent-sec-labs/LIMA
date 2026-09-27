"""Offline suite composition for LIMA v4 baselines (IP-0031).

This module composes the frozen upstream faces read-only into one offline
typed data flow: :func:`run_offline_baseline_suite` validates the IP-0030
fixture registry, materializes the default synthetic fixture into an
internal temporary workspace (never the output directory), guards the
injected evaluator behind the IP-0031 budget ledger (reserve before
invoke, usage recording after, failure accounting with the reservation
released), drives 5 cold + 5 warm attempts through
``orchestrate.run_repeats`` (default ``repeat=5``, covering the 3/5
minimal-sufficient gate), writes the canonical synthetic marker sidecar
after ``run_repeats`` returns, projects and persists the IP-0029 report,
and returns :class:`OfflineSuiteResult` with ``synthetic=True``.

Everything produced here is synthetic offline validation output: it is not
a real measurement, must not be counted toward the real cold/warm
evidence, AC-03, the V5 acceptance, or the immutable before baseline of
the parent issue, and the real-run entry point stays locked
(``budget.REAL_RUN_GATE_UNLOCKED`` is ``False``; unlocking requires a
future Maintainer authorization with a numeric budget plus a code change).

The module is offline and secretless: stdlib plus the frozen upstream
modules only, an injected evaluator and platform sources, tempdir
isolation, no network, no environment reads, and no paid calls.
"""

import dataclasses
import json
import pathlib
import tempfile
import typing

from benchmarks.v4.baseline.budget import (
    BudgetLedger,
    BudgetSpec,
    CallEstimate,
    CallUsage,
    LedgerSnapshot,
    Pricing,
)
from benchmarks.v4.baseline.fixtures import load_registry, materialize_fixture
from benchmarks.v4.baseline.orchestrate import (
    BaselineOrchestrationError,
    BaselineOrchestrationErrorCode,
    run_repeats,
)
from benchmarks.v4.baseline.report import build_baseline_report, write_report_file
from lima.contracts.codec import canonical_encode, compute_content_digest

__all__ = [
    "EvaluatorOutcome",
    "FakeEvaluator",
    "OfflineSuiteResult",
    "make_fake_evaluator",
    "run_offline_baseline_suite",
    "synthetic_call_usage",
    "synthetic_e2e_payload",
    "write_synthetic_marker",
]

_DEFAULT_MANIFEST_PATH = (
    pathlib.Path(__file__).resolve().parents[3]
    / "evaluation_data"
    / "v4"
    / "baseline_manifest.json"
)

_SYNTHETIC_PAYLOAD_NAME = "lima-offline-synthetic-e2e"

_MARKER_DECLARATIONS: typing.Final[tuple[str, ...]] = (
    "excluded-from-v5-and-immutable-baseline",
    "not-real-acceptance-evidence",
    "offline-fake-evaluator",
    "synthetic-usage",
)


@dataclasses.dataclass(frozen=True, slots=True)
class EvaluatorOutcome:
    """One evaluator result: the payload object plus its reported usage."""

    payload: object
    usage: CallUsage


def synthetic_e2e_payload() -> dict:
    """Return a freshly constructed synthetic e2e payload (frozen literal).

    The e2e shape is the one minimal synthetic face the frozen report
    recognizer accepts (``schema_version == 1`` plus the five e2e keys with
    non-negative integer metrics); the e2e projection reads only
    ``metrics.tp``/``metrics.fp``.
    """
    return {
        "schema_version": 1,
        "name": _SYNTHETIC_PAYLOAD_NAME,
        "metrics": {"tp": 3, "fp": 1, "fn": 2},
        "by_split": {
            "validation": {"tp": 3, "fp": 1, "fn": 2},
            "holdout": {"tp": 3, "fp": 1, "fn": 2},
        },
        "case_results": [],
        "dataset": {
            "name": "lima-offline-synthetic-e2e-dataset",
            "source_kinds": ["synthetic"],
        },
    }


def synthetic_call_usage(call_index: int) -> CallUsage:
    """Deterministic pure function of the 0-based attempt index (frozen).

    ``prompt_tokens = 1000 + 10 * i``, ``completion_tokens = 500 + 5 * i``,
    ``cost_micro_usd = 10 + i``, ``wall_ms = 50 + i``, and zero download and
    storage bytes.  Ten calls (``i = 0..9``) therefore sum to
    ``prompt = 10045``, ``completion = 5225``, ``cost = 145``, and
    ``wall = 545``.
    """
    return CallUsage(
        prompt_tokens=1000 + 10 * call_index,
        completion_tokens=500 + 5 * call_index,
        cost_micro_usd=10 + call_index,
        wall_ms=50 + call_index,
        download_bytes=0,
        storage_bytes=0,
    )


class FakeEvaluator:
    """Synthetic evaluator with a call counter and optional failure injection.

    The ``calls`` attribute is the injected call counter used to prove that
    a refused call performs zero evaluator invocations.  ``failures`` maps a
    0-based call ordinal to an exception instance raised on that call (the
    counter increments before raising, so the failure ordinal is stable);
    the exception propagates unchanged so the frozen attempt runner can
    classify it into the retained failure taxonomy.
    """

    __slots__ = ("calls", "_failures")

    def __init__(self, *, failures: dict[int, BaseException] | None = None) -> None:
        self.calls = 0
        self._failures: dict[int, BaseException] = dict(failures) if failures else {}

    def __call__(self) -> EvaluatorOutcome:
        self.calls += 1
        index = self.calls - 1
        failure = self._failures.get(index)
        if failure is not None:
            raise failure
        return EvaluatorOutcome(
            payload=synthetic_e2e_payload(), usage=synthetic_call_usage(index)
        )

    def peek_estimate(self) -> CallEstimate:
        """The tight upper bound for the next call (same deterministic formula)."""
        upcoming = synthetic_call_usage(self.calls)
        return CallEstimate(
            prompt_tokens=upcoming.prompt_tokens,
            completion_tokens=upcoming.completion_tokens,
            wall_ms=upcoming.wall_ms,
            download_bytes=upcoming.download_bytes,
            storage_bytes=upcoming.storage_bytes,
        )


def make_fake_evaluator(
    *, failures: dict[int, BaseException] | None = None
) -> FakeEvaluator:
    """Build the standard synthetic evaluator (optionally failure-injecting)."""
    return FakeEvaluator(failures=failures)


class _GuardedEvaluator:
    """Gate-before-invoke wrapper: budget checks run before the evaluator.

    The wrapper is the execution body handed to ``run_repeats``.  A reserve
    refusal propagates before the wrapped callable is ever invoked (zero
    evaluator calls); an evaluator failure is recorded as a failure (its
    reservation released) and re-raised unchanged so the frozen attempt
    runner retains the taxonomy sample; a successful call records its usage
    and remembers the first successful payload for the report.
    """

    __slots__ = ("_evaluator", "_ledger", "_invocations", "first_payload")

    def __init__(self, evaluator: typing.Any, ledger: BudgetLedger) -> None:
        self._evaluator = evaluator
        self._ledger = ledger
        self._invocations = 0
        self.first_payload: object = None

    def __call__(self) -> object:
        run_id = f"attempt-{self._invocations}"
        self._invocations += 1
        self._ledger.reserve(run_id, self._evaluator.peek_estimate())
        try:
            outcome = self._evaluator()
        except BaseException:
            self._ledger.record_failure(run_id)
            raise
        self._ledger.record_usage(run_id, outcome.usage)
        if self.first_payload is None:
            self.first_payload = outcome.payload
        return outcome.payload


def _guard_with_budget(evaluator: typing.Any, ledger: BudgetLedger) -> _GuardedEvaluator:
    """Wrap one FakeEvaluator-protocol callable behind the budget ledger."""
    return _GuardedEvaluator(evaluator, ledger)


def write_synthetic_marker(
    document: dict, output_dir: str | pathlib.Path
) -> pathlib.Path:
    """Persist one canonical synthetic marker sidecar under its digest prefix.

    The file name is ``{run_spec_digest[:16]}-synthetic-{n}.json`` (zero
    collision with the ``-run-``/``-report-``/``.expert-timing`` families)
    and the payload is exactly ``canonical_encode(document)``.  The slot
    rule is frozen: the smallest positive ``n`` whose slot is free is
    written exclusively; a slot already holding byte-identical bytes is
    returned idempotently (no overwrite, no error, no append); a slot
    holding different bytes defers to the next slot.
    """
    directory = pathlib.Path(output_dir)
    payload = canonical_encode(document)
    prefix = document["run_spec_digest"][:16]
    sequence = 1
    while True:
        path = directory / f"{prefix}-synthetic-{sequence}.json"
        if not path.exists():
            with open(path, "xb") as handle:
                handle.write(payload)
            return path
        if path.read_bytes() == payload:
            return path
        sequence += 1


def _load_suite_manifest(manifest_path: str | pathlib.Path | None) -> object:
    """Parse the baseline manifest (frozen default when ``None``), fail closed.

    An unreadable file, a non-UTF-8 byte stream, or invalid JSON raises the
    frozen orchestration error ``MANIFEST_UNREADABLE`` under
    ``$.manifest_path``.
    """
    path = _DEFAULT_MANIFEST_PATH if manifest_path is None else pathlib.Path(manifest_path)
    try:
        payload = path.read_bytes()
        parsed = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise BaselineOrchestrationError(
            BaselineOrchestrationErrorCode.MANIFEST_UNREADABLE, "$.manifest_path"
        ) from exc
    return parsed


@dataclasses.dataclass(frozen=True, slots=True)
class OfflineSuiteResult:
    """Paths, digests, and ledger state of one offline synthetic suite run.

    An independent frozen type: not a ``BaselineRunResult`` or
    ``BaselineRunSummary`` subclass, so downstream code cannot mistake a
    synthetic suite for a real run.  ``synthetic`` is the constant
    ``True``.
    """

    run_spec_digest: str
    attempt_count: int
    status: str
    result_paths: tuple[pathlib.Path, ...]
    aggregate_path: pathlib.Path
    aggregate_sha256: str
    report_path: pathlib.Path
    report_sha256: str
    marker_path: pathlib.Path
    marker_sha256: str
    ledger_snapshot: LedgerSnapshot
    evaluator_calls: int
    fixture_key: str
    fixture_file_count: int
    fixture_fingerprint: str
    synthetic: bool


def run_offline_baseline_suite(
    spec_mapping: object,
    *,
    output_dir: str | pathlib.Path,
    evaluator: typing.Any,
    budget_spec: BudgetSpec,
    pricing: Pricing,
    repeat: int = 5,
    sources: object = None,
    manifest_path: str | pathlib.Path | None = None,
    fixture_key: str = "archetype/minimal-python-repository",
) -> OfflineSuiteResult:
    """Run one fully offline synthetic baseline suite (frozen order 1-7).

    Order: registry validation; fixture materialization into an internal
    temporary workspace (never ``output_dir``); guarded-evaluator and
    ledger construction (default monotonic clock); ``run_repeats`` with the
    frozen default manifest; the synthetic marker sidecar written strictly
    after ``run_repeats`` returns; report projection and persistence; the
    :class:`OfflineSuiteResult`.  ``budget_spec`` and ``pricing`` are
    required keyword arguments: no scenario may implicitly receive an
    unlimited or free budget.

    Budget-gate refusals propagate out of the guarded evaluator into the
    frozen attempt runner and are retained as ``EXECUTION_ERROR`` taxonomy
    samples (the suite does not abort); the evaluator call counter is the
    proof that a refused scenario performed zero evaluator calls.
    """
    if (
        not callable(evaluator)
        or not callable(getattr(evaluator, "peek_estimate", None))
        or type(getattr(evaluator, "calls", None)) is not int
    ):
        raise TypeError(
            "evaluator must be callable with peek_estimate() and a calls counter"
        )
    load_registry()
    with tempfile.TemporaryDirectory() as workspace:
        materialization = materialize_fixture(
            fixture_key, pathlib.Path(workspace) / "fixture"
        )
        ledger = BudgetLedger(budget_spec, pricing)
        guarded = _guard_with_budget(evaluator, ledger)
        summary = run_repeats(
            spec_mapping,
            _load_suite_manifest(manifest_path),
            guarded,
            output_dir,
            repeat=repeat,
            sources=sources,
        )
    snapshot = ledger.snapshot()
    marker_document = {
        "marker_version": 1,
        "marker_type": "synthetic-offline-run",
        "run_spec_digest": summary.aggregate.run_spec_digest,
        "aggregate_sha256": summary.aggregate_sha256,
        "attempt_count": len(summary.attempts),
        "budget_ledger_digest": compute_content_digest(
            {
                "per_run": snapshot.per_run,
                "batch": snapshot.batch,
                "violations": snapshot.violations,
            }
        ),
        "declarations": list(_MARKER_DECLARATIONS),
    }
    marker_path = write_synthetic_marker(marker_document, output_dir)
    payload = guarded.first_payload
    if payload is None:
        payload = synthetic_e2e_payload()
    report = build_baseline_report(summary, payload)
    artifacts = write_report_file(report, output_dir)
    return OfflineSuiteResult(
        run_spec_digest=summary.aggregate.run_spec_digest,
        attempt_count=len(summary.attempts),
        status=summary.status,
        result_paths=summary.result_paths,
        aggregate_path=summary.aggregate_path,
        aggregate_sha256=summary.aggregate_sha256,
        report_path=artifacts.report_path,
        report_sha256=artifacts.report_sha256,
        marker_path=marker_path,
        marker_sha256=compute_content_digest(marker_path.read_bytes()),
        ledger_snapshot=snapshot,
        evaluator_calls=evaluator.calls,
        fixture_key=materialization.key,
        fixture_file_count=materialization.file_count,
        fixture_fingerprint=materialization.fingerprint,
        synthetic=True,
    )
