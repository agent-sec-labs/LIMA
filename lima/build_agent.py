"""Bounded repository build agent (build agent slice 3).

The agent drives the seven controlled tools (slice 2) through the shared
:class:`~lima.runtime.AgentLoop` with an injected model adapter.  The model
only ever proposes tool calls; every discipline that matters is code:

- the shared attempt budget is enforced by the tools, the model-call budget
  by the loop, and one wall-clock deadline set at :meth:`BuildAgent.run`
  entry bounds the loop, every container side effect (the executor receives
  the remaining time, never a fresh budget) and the final publication;
- a retry whose execution identity - configure argv, dependency set, image -
- matches the last failure is refused before the executor is touched, and
  once that stop condition fires it is locked: later tool results and model
  output cannot clear it;
- cancellation is checked between model calls and tool calls, and the
  publication gate lets cancellation and the deadline override every
  candidate terminal state (the AgentLoop turns tool exceptions into
  observations, so nothing is trusted to propagate);
- the final terminal verdict comes from the tool chain's own
  ``validate_context`` - package reference, plan digest and context hash are
  read from that same objective verdict, never from model announcements or
  parallel caches.

The model receives a serializable projection of the request, the policy and
the tool catalog in its initial state, so an adapter can plan from the
actual run context alone (no host paths, no secrets).
"""

from __future__ import annotations

import dataclasses
import time
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

    ``package_ref``/``evidence_refs`` are artifacts-root-relative and, on
    success, come from the same objective ``validate_context`` verdict as
    the plan digest; the per-file ``artifact_digest`` lands with slice 4A's
    verifier and ``coverage`` with the downstream TU consumers, so both
    stay ``None`` in this slice rather than being approximated.
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
    """Tool-invocation guard: phases, fingerprint lock, cancellation.

    The AgentLoop converts tool exceptions into failure observations, so the
    guard's disciplines are delivered as data and re-checked at the agent's
    publication gate: a refused identical retry returns an error observation
    and locks ``fingerprint_stop`` (which no later success clears), and a
    pending cancellation makes every tool call fail-fast while the agent's
    stepper wrapper stops the model loop itself.
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
        self.last_execution_digest: str | None = None
        self.failed_execution_digest: str | None = None
        self.last_failure_code: str | None = None
        self.fingerprint_stop: str | None = None
        self.cancelled: bool = False
        self.prepared_ref: str | None = None
        self.last_image_digest: str | None = None
        self.attempts: int = 0
        self.executed_once = False
        self.evidence: list[str] = []

    def get(self, name: str) -> Callable[..., Any]:
        def invoke(**arguments: Any) -> Any:
            return self.invoke(name, arguments)

        return invoke

    def names(self) -> list[str]:
        return self._inner.names()

    def invoke(self, name: str, arguments: dict[str, Any]) -> Any:
        if self._cancel():
            self.cancelled = True
            return {
                "ok": False,
                "error": "cancelled",
                "cancelled": True,
                "attempt": self.attempts,
                "steps": [],
            }
        phase = _TOOL_PHASES.get(name)
        if phase == "PLANNING" and self.executed_once:
            phase = "REPLANNING"
        if name == "execute_configure":
            refusal = self._fingerprint_refusal()
            if refusal is not None:
                return refusal
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

    def _fingerprint_refusal(self) -> dict[str, Any] | None:
        """Refuse retries that would repeat the last failing execution.

        The identity is what an attempt actually executes (configure argv,
        dependency set, image) - not the whole plan digest, so editing
        export-only metadata such as generated-header globs cannot reset the
        discipline.  Once fired, the stop is locked: later plans and tool
        results cannot clear it.
        """

        if self.fingerprint_stop is not None:
            return {
                "ok": False,
                "error": self.fingerprint_stop,
                "attempt": self.attempts,
                "steps": [],
            }
        if (
            self.failed_execution_digest is not None
            and self.failed_execution_digest == self.last_execution_digest
        ):
            self.fingerprint_stop = (
                "failure-fingerprint-unchanged:"
                f"{self.last_failure_code or 'unknown'}"
            )
            return {
                "ok": False,
                "error": self.fingerprint_stop,
                "attempt": self.attempts,
                "steps": [],
            }
        return None

    def _record(self, name: str, result: Any) -> None:
        if not isinstance(result, dict):
            return
        if name == "propose_build_plan" and result.get("ok"):
            self.last_plan_digest = result.get("plan_digest")
            self.last_execution_digest = result.get("execution_digest")
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
                # A success opens a new failure cycle; the locked stop is
                # deliberately not cleared here.
                self.failed_execution_digest = None
                self.last_failure_code = None
            else:
                self.failed_execution_digest = (
                    result.get("execution_digest") or self.last_execution_digest
                )
                self.last_failure_code = (
                    result.get("failure_code") or result.get("error") or "failed"
                )
        elif name == "export_context_package" and result.get("ok"):
            ref = result.get("package_ref")
            if ref and ref not in self.evidence:
                self.evidence.append(ref)


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

    def _initial_state(
        self, run_id: str, request: BuildRequest, registry: ToolRegistry
    ) -> dict[str, Any]:
        """A serializable, host-path-free projection for the model."""

        budget = request.budget
        return {
            "run_id": run_id,
            "request": {
                "repository_ref": request.repository_ref,
                "snapshot_hash": request.snapshot_hash,
                "goal": request.goal,
                "component_scope": list(request.component_scope),
                "target_units": list(request.target_units),
                "budget": {
                    "max_attempts": budget.max_attempts,
                    "max_model_calls": budget.max_model_calls,
                    "total_seconds": budget.total_seconds,
                    "step_seconds": budget.step_seconds,
                    "max_output_bytes": budget.max_output_bytes,
                },
            },
            "policy": {
                "adapters": sorted(self._policy.adapters),
                "allowed_executables": sorted(self._policy.allowed_executables),
                "dependency_sets": {
                    ref: {
                        "image": dep.image,
                        "image_digest": dep.image_digest,
                    }
                    for ref, dep in self._policy.dependency_sets.items()
                },
                "allow_repository_root_configure": (
                    self._policy.allow_repository_root_configure
                ),
            },
            "tools": registry.catalog(),
        }

    def run(
        self,
        request: BuildRequest,
        *,
        cancel: Callable[[], bool] = lambda: False,
        progress: Callable[[BuildProgress], None] = lambda update: None,
    ) -> BuildResult:
        run_id = "build-" + uuid.uuid4().hex[:16]
        budget = request.budget
        # One wall clock for the whole run: loop, tool side effects, export
        # validation and the final publication all share this deadline.
        deadline = time.monotonic() + budget.total_seconds
        registry = ToolRegistry()
        register_build_tools(
            registry,
            self._executor,
            self._policy,
            request=request,
            snapshot_dir=self._snapshot_dir,
            artifacts_root=self._artifacts_root,
            cancel=cancel,
            deadline=deadline,
        )
        guarded = _GuardedTools(registry, cancel=cancel, progress=progress)
        loop = AgentLoop(
            max_steps=budget.max_model_calls,
            timeout_seconds=max(1, int(budget.total_seconds)),
        )

        def stepper(state: dict[str, Any]) -> dict[str, Any]:
            # The model call itself honors cancellation between rounds; the
            # AgentLoop runs stepper calls outside its observation trap, so
            # this exception escapes the loop instead of becoming an
            # observation.
            if cancel():
                raise RuntimeCancelled("build agent cancelled")
            return self._model(state)

        status: str | None = None
        failure_code: str | None = None
        final_output: Any = None
        if cancel():
            status, failure_code = CANCELLED, "cancelled"
        else:
            try:
                loop_result = loop.run(
                    stepper, guarded, self._initial_state(run_id, request, registry)
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
            if guarded.fingerprint_stop:
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
                    # validation, never the model's success announcement;
                    # package identity is read from this same verdict.
                    verdict = registry.invoke("validate_context", {})
                    if verdict.get("ok") and verdict.get("package_ref"):
                        status = SUCCEEDED
                    else:
                        status = FAILED
                        failure_code = "no-validated-package"

        # Publication gate: cancellation and the shared deadline override
        # every candidate terminal state, including a just-earned success.
        if status != CANCELLED and cancel():
            status, failure_code = CANCELLED, "cancelled"
        if (
            status not in {CANCELLED, TIMED_OUT}
            and time.monotonic() >= deadline
        ):
            status, failure_code = TIMED_OUT, "timed-out"
        if status is None:
            status = FAILED

        dependency_digest: str | None = None
        if guarded.prepared_ref:
            approved = self._policy.dependency_sets.get(guarded.prepared_ref)
            dependency_digest = (
                approved.image_digest if approved is not None else None
            )
        package_ref = (
            verdict.get("package_ref") if status == SUCCEEDED and verdict else None
        )
        evidence = list(guarded.evidence)
        if package_ref and package_ref not in evidence:
            evidence.append(package_ref)
        return BuildResult(
            run_id=run_id,
            status=status,
            snapshot_hash=request.snapshot_hash,
            plan_digest=(
                verdict.get("plan_digest")
                if verdict and verdict.get("ok")
                else guarded.last_plan_digest
            ),
            image_digest=guarded.last_image_digest,
            dependency_digest=dependency_digest,
            package_ref=package_ref,
            artifact_digest=None,
            attempts=guarded.attempts,
            coverage=None,
            failure_code=failure_code,
            evidence_refs=tuple(evidence),
        )
