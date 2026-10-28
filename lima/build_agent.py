"""Bounded repository build agent (build agent slice 3).

The agent drives the seven controlled tools (slice 2) through the shared
:class:`~lima.runtime.AgentLoop` with an injected model adapter.  The model
only ever proposes tool calls; every discipline that matters is code:

- the shared attempt budget is enforced by the tools, the model-call budget
  and the wall clock by the loop, both set from the request's frozen
  :class:`~lima.build_contracts.BuildBudget`;
- a retry of the same failing configuration without a new accepted plan is
  refused before the executor is touched (failure-fingerprint discipline);
- cancellation is checked between tool calls, and the final terminal state
  is decided by re-validating the package through the tool chain, never by
  trusting the model's own ``final`` announcement.

Progress callbacks receive the frozen phases
(``INSPECTING/PLANNING/PREPARING/EXECUTING/VALIDATING``, ``REPLANNING``
after a first execution) with the current attempt and plan digest; every
result carries attempt evidence as artifacts-root-relative references.
"""

from __future__ import annotations

import dataclasses
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any, Final

from lima.build_contracts import (
    BuildPolicy,
    BuildRequest,
)
from lima.build_executor import BuildExecutor
from lima.build_tools import register_build_tools
from lima.runtime import (
    AgentLoop,
    RuntimeBudgetExceeded,
    RuntimeCancelled,
    ToolRegistry,
)

__all__ = [
    "CANCELLED",
    "FAILED",
    "NEEDS_ATTENTION",
    "PARTIAL",
    "SUCCEEDED",
    "TIMED_OUT",
    "BuildAgent",
    "BuildProgress",
    "BuildResult",
]

SUCCEEDED: Final = "SUCCEEDED"
PARTIAL: Final = "PARTIAL"
FAILED: Final = "FAILED"
NEEDS_ATTENTION: Final = "NEEDS_ATTENTION"
CANCELLED: Final = "CANCELLED"
TIMED_OUT: Final = "TIMED_OUT"

_TOOL_PHASES: Final = {
    "inspect_build_files": "INSPECTING",
    "propose_build_plan": "PLANNING",
    "prepare_dependencies": "PREPARING",
    "execute_configure": "EXECUTING",
    "inspect_build_failure": "EXECUTING",
    "export_context_package": "VALIDATING",
    "validate_context": "VALIDATING",
}


@dataclasses.dataclass(frozen=True, slots=True)
class BuildProgress:
    """One phase transition observed while the agent runs."""

    phase: str
    attempt: int
    plan_digest: str | None
    evidence_refs: tuple[str, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class BuildResult:
    """Terminal outcome of one build-agent run.

    ``package_ref``/``evidence_refs`` are artifacts-root-relative; the
    per-file ``artifact_digest`` lands with slice 4A's verifier and
    ``coverage`` with the downstream TU consumers, so both stay ``None``
    in this slice rather than being approximated.
    """

    run_id: str
    status: str
    snapshot_hash: str
    plan_digest: str | None
    image_digest: str | None
    dependency_digest: str | None
    package_ref: str | None
    artifact_digest: str | None
    attempts: int
    coverage: dict[str, Any] | None
    failure_code: str | None
    evidence_refs: tuple[str, ...]


class _GuardedTools:
    """Tool-invocation guard: phases, fingerprint discipline, cancellation.

    The AgentLoop converts tool exceptions into failure observations, so the
    guard's disciplines are delivered as data: a refused identical retry
    returns an error observation and sets ``fingerprint_stop``, and
    cancellation surfaces through the agent's final publication gate.  The
    AgentLoop calls ``get(name)(**arguments)``; this wrapper forwards to the
    real registry while enforcing the code-side rules the model cannot waive
    and reporting progress.
    """

    def __init__(
        self,
        inner: ToolRegistry,
        *,
        cancel: Callable[[], bool],
        progress: Callable[[BuildProgress], None],
    ) -> None:
        self._inner = inner
        self._cancel = cancel
        self._progress = progress
        self.last_plan_digest: str | None = None
        self.failed_plan_digest: str | None = None
        self.last_failure_code: str | None = None
        self.fingerprint_stop: str | None = None
        self.prepared_ref: str | None = None
        self.last_image_digest: str | None = None
        self.attempts: int = 0
        self.executed_once = False
        self.evidence: list[str] = []
        self.package_ref: str | None = None

    def get(self, name: str) -> Callable[..., Any]:
        def invoke(**arguments: Any) -> Any:
            return self.invoke(name, arguments)

        return invoke

    def names(self) -> list[str]:
        return self._inner.names()

    def invoke(self, name: str, arguments: dict[str, Any]) -> Any:
        phase = _TOOL_PHASES.get(name)
        if phase == "PLANNING" and self.executed_once:
            phase = "REPLANNING"
        if (
            name == "execute_configure"
            and self.failed_plan_digest is not None
            and self.failed_plan_digest == self.last_plan_digest
        ):
            # Identical failing plan, no effective change: refuse the retry
            # before the executor is touched and flag the stop condition.
            self.fingerprint_stop = (
                f"failure-fingerprint-unchanged:{self.last_failure_code or 'unknown'}"
            )
            return {
                "ok": False,
                "error": self.fingerprint_stop,
                "attempt": self.attempts,
                "steps": [],
            }
        result = self._inner.invoke(name, arguments)
        self._record(name, result)
        if phase is not None:
            self._progress(
                BuildProgress(
                    phase=phase,
                    attempt=self.attempts,
                    plan_digest=self.last_plan_digest,
                    evidence_refs=tuple(self.evidence),
                )
            )
        return result

    def _record(self, name: str, result: Any) -> None:
        if not isinstance(result, dict):
            return
        if name == "propose_build_plan" and result.get("ok"):
            self.last_plan_digest = result.get("plan_digest")
        elif name == "prepare_dependencies" and result.get("ok"):
            self.prepared_ref = result.get("dependency_set_ref")
        elif name == "execute_configure":
            self.executed_once = True
            self.attempts = max(self.attempts, int(result.get("attempt") or 0))
            self.last_image_digest = result.get("image_digest")
            for step in result.get("steps") or []:
                ref = step.get("stderr_ref")
                if ref:
                    self.evidence.append(ref)
            if result.get("ok"):
                self.failed_plan_digest = None
                self.last_failure_code = None
                self.fingerprint_stop = None
            else:
                self.failed_plan_digest = self.last_plan_digest
                self.last_failure_code = (
                    result.get("failure_code") or result.get("error") or "failed"
                )
        elif name == "export_context_package" and result.get("ok"):
            self.package_ref = result.get("package_ref")
            if self.package_ref:
                self.evidence.append(self.package_ref)


class BuildAgent:
    """Runs one bounded build task per :meth:`run` call."""

    def __init__(
        self,
        *,
        model: Callable[[dict[str, Any]], dict[str, Any]],
        executor: BuildExecutor,
        policy: BuildPolicy,
        snapshot_dir: Path,
        artifacts_root: Path,
    ) -> None:
        self._model = model
        self._executor = executor
        self._policy = policy
        self._snapshot_dir = Path(snapshot_dir)
        self._artifacts_root = Path(artifacts_root)

    def run(
        self,
        request: BuildRequest,
        *,
        cancel: Callable[[], bool] = lambda: False,
        progress: Callable[[BuildProgress], None] = lambda update: None,
    ) -> BuildResult:
        run_id = "build-" + uuid.uuid4().hex[:16]
        registry = ToolRegistry()
        register_build_tools(
            registry,
            self._executor,
            self._policy,
            request=request,
            snapshot_dir=self._snapshot_dir,
            artifacts_root=self._artifacts_root,
            cancel=cancel,
        )
        guarded = _GuardedTools(registry, cancel=cancel, progress=progress)
        budget = request.budget
        loop = AgentLoop(
            max_steps=budget.max_model_calls,
            timeout_seconds=max(1, int(budget.total_seconds)),
        )

        status: str | None = None
        failure_code: str | None = None
        final_output: Any = None
        if cancel():
            status, failure_code = CANCELLED, "cancelled"
        else:
            try:
                loop_result = loop.run(
                    self._model, guarded, {"run_id": run_id}
                )
                final_output = loop_result.output
            except RuntimeBudgetExceeded as exc:
                if "time" in str(exc):
                    status, failure_code = TIMED_OUT, "timed-out"
                else:
                    failure_code = "budget-exhausted"
            except RuntimeCancelled:
                status, failure_code = CANCELLED, "cancelled"

        verdict: dict[str, Any] | None = None
        if status is None and failure_code is None:
            # Publication gate: cancellation and an unanswered fingerprint
            # stop outrank everything the loop concluded (the AgentLoop turns
            # tool exceptions into observations, so both are re-checked here
            # rather than trusted to propagate).
            if cancel():
                status, failure_code = CANCELLED, "cancelled"
            elif guarded.fingerprint_stop:
                status = FAILED
                failure_code = guarded.fingerprint_stop
            else:
                announcement = (
                    final_output if isinstance(final_output, dict) else {}
                )
                if (
                    str(announcement.get("status", "")).lower()
                    == "needs-attention"
                ):
                    status = NEEDS_ATTENTION
                    failure_code = str(
                        announcement.get("reason") or "needs-attention"
                    )
                else:
                    # The terminal verdict is the tool chain's own
                    # validation, never the model's success announcement.
                    verdict = registry.invoke("validate_context", {})
                    if verdict.get("ok"):
                        status = SUCCEEDED
                    else:
                        status = FAILED
                        failure_code = "no-validated-package"
        if status is None:
            status = FAILED

        dependency_digest: str | None = None
        if guarded.prepared_ref:
            approved = self._policy.dependency_sets.get(guarded.prepared_ref)
            dependency_digest = (
                approved.image_digest if approved is not None else None
            )
        package_ref = (
            guarded.package_ref if status == SUCCEEDED else None
        )
        evidence = tuple(
            ref for ref in guarded.evidence
            if package_ref is None or ref != package_ref or status == SUCCEEDED
        )
        return BuildResult(
            run_id=run_id,
            status=status,
            snapshot_hash=request.snapshot_hash,
            plan_digest=guarded.last_plan_digest,
            image_digest=guarded.last_image_digest,
            dependency_digest=dependency_digest,
            package_ref=package_ref,
            artifact_digest=None,
            attempts=guarded.attempts,
            coverage=None,
            failure_code=failure_code,
            evidence_refs=evidence,
        )
