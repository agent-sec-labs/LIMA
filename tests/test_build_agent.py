"""Bounded repository build agent tests (build agent slice 3).

The agent drives the seven controlled tools through a scripted model and the
shared AgentLoop.  These tests freeze the state-machine discipline the plan
names: the happy identify-to-validate chain, one bounded revision after an
approved-dependency failure, an immediate stop when the same failure repeats
without an effective plan change, and the terminal mapping for exhausted
budgets, unapproved dependencies and cancellation -- all with a fake model
and a fake executor, never Docker or a real model key.
"""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.build_agent import (
    NEEDS_ATTENTION,
    SUCCEEDED,
    BuildAgent,
    BuildProgress,
)
from lima.build_contracts import (
    ApprovedDependencySet,
    BuildBudget,
    BuildPolicy,
    BuildRequest,
)
from lima.build_executor import BuildExecutionResult
from lima.build_tools import BUILD_TOOL_NAMES
from lima.context_package import build_manifest, write_package

SNAPSHOT = "a" * 64


def make_policy() -> BuildPolicy:
    return BuildPolicy(
        dependency_sets={
            "clang16-cmake": ApprovedDependencySet(
                image="lima-builder-clang16:2026-10"
            )
        },
        allow_repository_root_configure=True,
    )


def make_request() -> BuildRequest:
    return BuildRequest(
        repository_ref="Fixtures/AgentRepo",
        snapshot_hash=SNAPSHOT,
        component_scope=("app",),
        target_units=("app/main.cpp",),
        toolchain_profile="clang16",
        policy_ref="default",
        budget=BuildBudget(),
    )


def plan_action(*, feature: str = "ON") -> dict:
    return {
        "action": "tool",
        "tool": "propose_build_plan",
        "arguments": {
            "plan": {
                "snapshot_hash": SNAPSHOT,
                "adapter": "cmake-linux",
                "component_scope": ["app"],
                "configure_argv": [
                    [
                        "cmake",
                        "-S",
                        ".",
                        "-B",
                        "build",
                        f"-DFEATURE={feature}",
                    ]
                ],
                "expected_compdb": "build/compile_commands.json",
                "generated_headers": ["build/*.h"],
                "include_roots": [
                    {
                        "container": "/usr/include/fixture",
                        "package": "headers/fixture",
                    }
                ],
                "dependency_set_ref": "clang16-cmake",
            }
        },
    }


def tool(name: str, **arguments) -> dict:
    return {
        "action": "tool",
        "tool": name,
        "arguments": arguments,
    }


def final(status: str = "done", reason: str = "") -> dict:
    # AgentLoop only forwards the ``output`` field of a final action.
    return {
        "action": "final",
        "output": {"status": status, "reason": reason},
    }


class ScriptedModel:
    """A stepper that replays scripted actions; hooks run before each step."""

    def __init__(self, actions, before_step=None):
        self.actions = list(actions)
        self.before_step = before_step
        self.states_seen: list[dict] = []

    def __call__(self, state: dict) -> dict:
        self.states_seen.append(
            {
                "loop_step": state.get("loop_step"),
                "observations": len(state.get("observations") or []),
            }
        )
        if self.before_step is not None:
            self.before_step(self)
        if not self.actions:
            raise AssertionError("scripted model ran out of actions")
        return self.actions.pop(0)


class FakeExecutor:
    """Succeeds on chosen attempts; writes a real minimal package."""

    def __init__(
        self,
        *,
        fail_first_attempts: int = 0,
        failure_code: str = "configure-step-failed",
    ) -> None:
        self.fail_first_attempts = fail_first_attempts
        self.failure_code = failure_code
        self.calls = 0

    def execute(self, recipe, snapshot_dir, output_dir, *, limits, cancel,
                revision="unknown"):
        self.calls += 1
        ok = self.calls > self.fail_first_attempts
        if ok:
            self._write_package(Path(output_dir) / "package", revision)
        return BuildExecutionResult(
            ok=ok,
            steps=(),
            image=recipe.image,
            image_digest=None,
            package_path=str(Path(output_dir) / "package") if ok else None,
            failure_code=None if ok else self.failure_code,
        )

    @staticmethod
    def _write_package(pkg_dir: Path, revision: str) -> None:
        compdb = [
            {
                "directory": "app",
                "arguments": ["/usr/bin/c++", "-c", "app/main.cpp"],
                "file": "app/main.cpp",
            }
        ]
        manifest = build_manifest(
            repository="Fixtures/AgentRepo",
            revision=revision,
            compdb=compdb,
            generated=[],
            header_roots=[],
            rewrites={},
            created_by="agent-test",
        )
        write_package(
            pkg_dir, manifest, json.dumps(compdb).encode("utf8"), {}, {}
        )


class BuildAgentTest(unittest.TestCase):
    def run_agent(self, model, *, executor=None, cancel=lambda: False,
                  progress=None, request=None, policy=None, tmp=None):
        tmp = tmp or tempfile.mkdtemp()
        snapshot = Path(tmp) / "snapshot"
        snapshot.mkdir(parents=True, exist_ok=True)
        (snapshot / "app").mkdir(exist_ok=True)
        (snapshot / "app" / "main.cpp").write_text("int main(void){return 0;}\n")
        agent = BuildAgent(
            model=model,
            executor=executor or FakeExecutor(),
            policy=policy or make_policy(),
            snapshot_dir=snapshot,
            artifacts_root=Path(tmp) / "artifacts",
        )
        return agent.run(
            request or make_request(),
            cancel=cancel,
            progress=progress or (lambda update: None),
        )

    def test_identify_plan_configure_validate_chain_succeeds(self) -> None:
        model = ScriptedModel(
            [
                tool("inspect_build_files"),
                plan_action(),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                tool("export_context_package"),
                tool("validate_context"),
                final(),
            ]
        )
        progress_log: list[BuildProgress] = []
        result = self.run_agent(model, progress=progress_log.append)

        self.assertEqual(result.status, SUCCEEDED)
        self.assertIsNone(result.failure_code)
        self.assertEqual(result.attempts, 1)
        self.assertTrue(result.package_ref)
        self.assertEqual(result.snapshot_hash, SNAPSHOT)
        self.assertTrue(result.plan_digest)
        self.assertTrue(result.evidence_refs)
        # The progress feed walks the frozen phases and carries the plan.
        phases = [update.phase for update in progress_log]
        self.assertIn("INSPECTING", phases)
        self.assertIn("PLANNING", phases)
        self.assertIn("PREPARING", phases)
        self.assertIn("EXECUTING", phases)
        self.assertIn("VALIDATING", phases)
        planning = next(u for u in progress_log if u.phase == "PLANNING")
        self.assertTrue(planning.plan_digest)
        executing = next(u for u in progress_log if u.phase == "EXECUTING")
        self.assertEqual(executing.attempt, 1)

    def test_revision_after_failure_succeeds_on_second_attempt(self) -> None:
        model = ScriptedModel(
            [
                plan_action(feature="ON"),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                tool("inspect_build_failure",
                     step_ref="attempt-1/logs/step-000.stderr.log"),
                plan_action(feature="OFF"),
                tool("execute_configure"),
                tool("export_context_package"),
                tool("validate_context"),
                final(),
            ]
        )
        executor = FakeExecutor(fail_first_attempts=1)
        progress_log: list[BuildProgress] = []
        # The revision script is nine model calls; give both the request
        # and the deployment ceiling headroom over the pilot default of
        # eight (the ceiling gate from slice 2 rejects the request alone).
        ceiling = BuildBudget(max_model_calls=12)
        request = BuildRequest(
            repository_ref="Fixtures/AgentRepo",
            snapshot_hash=SNAPSHOT,
            component_scope=("app",),
            target_units=("app/main.cpp",),
            toolchain_profile="clang16",
            policy_ref="default",
            budget=ceiling,
        )
        policy = BuildPolicy(
            dependency_sets=make_policy().dependency_sets,
            allow_repository_root_configure=True,
            budget_ceiling=ceiling,
        )
        result = self.run_agent(model, executor=executor, request=request,
                                policy=policy, progress=progress_log.append)

        self.assertEqual(result.status, SUCCEEDED)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(executor.calls, 2)
        phases = [update.phase for update in progress_log]
        self.assertIn("REPLANNING", phases)
        replanning = next(u for u in progress_log if u.phase == "REPLANNING")
        self.assertEqual(replanning.attempt, 1)

    def test_same_fingerprint_without_change_stops_immediately(self) -> None:
        model = ScriptedModel(
            [
                plan_action(feature="ON"),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                # No new plan: retrying the identical failing configuration
                # must be refused before the executor is touched again.
                tool("execute_configure"),
                final(),
            ]
        )
        executor = FakeExecutor(fail_first_attempts=99)
        result = self.run_agent(model, executor=executor)

        self.assertNotEqual(result.status, SUCCEEDED)
        self.assertIn("fingerprint", result.failure_code or "")
        self.assertEqual(executor.calls, 1)

    def test_exhausted_model_budget_maps_to_failed(self) -> None:
        model = ScriptedModel(
            [
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                final(),
            ]
        )
        request = BuildRequest(
            repository_ref="Fixtures/AgentRepo",
            snapshot_hash=SNAPSHOT,
            component_scope=("app",),
            target_units=("app/main.cpp",),
            toolchain_profile="clang16",
            policy_ref="default",
            budget=BuildBudget(max_model_calls=3),
        )
        result = self.run_agent(model, request=request)

        self.assertEqual(result.status, "FAILED")
        self.assertEqual(result.failure_code, "budget-exhausted")

    def test_unapproved_dependency_maps_to_needs_attention(self) -> None:
        model = ScriptedModel(
            [
                tool("prepare_dependencies", dependency_set_ref="vendor-sdk"),
                final(status="needs-attention",
                      reason="dependency-set-not-approved:vendor-sdk"),
            ]
        )
        result = self.run_agent(model)

        self.assertEqual(result.status, NEEDS_ATTENTION)
        self.assertIn("dependency-set-not-approved", result.failure_code or "")

    def test_cancellation_maps_to_cancelled(self) -> None:
        flags = {"cancel": False}

        def cancel() -> bool:
            return flags["cancel"]

        model = ScriptedModel(
            [
                plan_action(),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                final(),
            ],
            before_step=lambda m: flags.__setitem__("cancel", True)
            if m.states_seen and len(m.states_seen) >= 3 else None,
        )
        executor = FakeExecutor()
        result = self.run_agent(model, executor=executor, cancel=cancel)

        self.assertEqual(result.status, "CANCELLED")
        self.assertEqual(result.failure_code, "cancelled")


class ContextReadingModel:
    """Plans from the run state itself instead of replaying fixed data."""

    def __init__(self):
        self.seen_states: list[dict] = []

    def __call__(self, state: dict) -> dict:
        self.seen_states.append(state)
        step = len(self.seen_states)
        if step == 1:
            return tool("inspect_build_files")
        if step == 2:
            request, policy = state["request"], state["policy"]
            ref = sorted(policy["dependency_sets"])[0]
            return {
                "action": "tool",
                "tool": "propose_build_plan",
                "arguments": {
                    "plan": {
                        "snapshot_hash": request["snapshot_hash"],
                        "adapter": sorted(policy["adapters"])[0],
                        "component_scope": list(request["component_scope"]),
                        "configure_argv": [["cmake", "-S", ".", "-B", "build"]],
                        "expected_compdb": "build/compile_commands.json",
                        "generated_headers": ["build/*.h"],
                        "include_roots": [
                            {
                                "container": "/usr/include/fixture",
                                "package": "headers/fixture",
                            }
                        ],
                        "dependency_set_ref": ref,
                    }
                },
            }
        if step == 3:
            ref = sorted(state["policy"]["dependency_sets"])[0]
            return tool("prepare_dependencies", dependency_set_ref=ref)
        if step == 4:
            return tool("execute_configure")
        if step == 5:
            return tool("validate_context")
        return final()


class Round1ReviewTests(unittest.TestCase):
    """Targeted regressions for the PR #345 review findings."""

    def run_agent(self, model, *, executor=None, cancel=lambda: False,
                  request=None, policy=None, tmp=None):
        tmp = tmp or tempfile.mkdtemp()
        snapshot = Path(tmp) / "snapshot"
        snapshot.mkdir(parents=True, exist_ok=True)
        (snapshot / "app").mkdir(exist_ok=True)
        (snapshot / "app" / "main.cpp").write_text("int main(void){return 0;}\n")
        agent = BuildAgent(
            model=model,
            executor=executor or FakeExecutor(),
            policy=policy or make_policy(),
            snapshot_dir=snapshot,
            artifacts_root=Path(tmp) / "artifacts",
        )
        return agent.run(
            request or make_request(),
            cancel=cancel,
            progress=lambda update: None,
        )

    def test_final_without_export_binds_current_package(self) -> None:
        # The package identity must come from the objective validate
        # verdict, so a run that never calls export after a newer plan
        # still reports the current attempt's package (review F1).
        model = ScriptedModel(
            [
                plan_action(feature="ON"),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                tool("export_context_package"),
                plan_action(feature="OFF"),
                tool("execute_configure"),
                final(),
            ]
        )
        ceiling = BuildBudget(max_model_calls=12)
        request = BuildRequest(
            repository_ref="Fixtures/AgentRepo",
            snapshot_hash=SNAPSHOT,
            component_scope=("app",),
            target_units=("app/main.cpp",),
            toolchain_profile="clang16",
            policy_ref="default",
            budget=ceiling,
        )
        policy = BuildPolicy(
            dependency_sets=make_policy().dependency_sets,
            allow_repository_root_configure=True,
            budget_ceiling=ceiling,
        )
        result = self.run_agent(model, request=request, policy=policy)

        self.assertEqual(result.status, SUCCEEDED)
        self.assertEqual(result.attempts, 2)
        self.assertEqual(result.package_ref, "attempt-2/package")
        ScriptedModel([plan_action(feature="OFF")])
        from lima.build_contracts import BuildPlan, plan_digest, validate_build_plan

        plan_b = BuildPlan.from_mapping(plan_action(feature="OFF")["arguments"]["plan"])
        validated = validate_build_plan(request, plan_b, policy)
        self.assertEqual(result.plan_digest, plan_digest(validated.plan))

    def test_wall_clock_gate_blocks_stale_success(self) -> None:
        # A final landing after the total budget must not publish success
        # (review F2).
        clock = {"now": 100.0}
        budget = BuildBudget(total_seconds=10.0)
        request = BuildRequest(
            repository_ref="Fixtures/AgentRepo",
            snapshot_hash=SNAPSHOT,
            component_scope=("app",),
            target_units=("app/main.cpp",),
            toolchain_profile="clang16",
            policy_ref="default",
            budget=budget,
        )
        policy = BuildPolicy(
            dependency_sets=make_policy().dependency_sets,
            allow_repository_root_configure=True,
            budget_ceiling=budget,
        )
        model = ScriptedModel(
            [
                plan_action(),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                tool("validate_context"),
                final(),
            ],
            before_step=lambda m: clock.__setitem__(
                "now", 111.0
            )
            if len(m.states_seen) >= 4
            else None,
        )
        with mock.patch(
            "lima.build_agent.time.monotonic", lambda: clock["now"]
        ), mock.patch(
            "lima.build_tools.time.monotonic", lambda: clock["now"]
        ):
            result = self.run_agent(model, request=request, policy=policy)
        self.assertEqual(result.status, "TIMED_OUT")
        self.assertEqual(result.failure_code, "timed-out")

    def test_executor_receives_remaining_budget(self) -> None:
        # Time spent planning shrinks what the executor is authorized to
        # spend (review F2).
        clock = {"now": 100.0}
        budget = BuildBudget(total_seconds=10.0)
        request = BuildRequest(
            repository_ref="Fixtures/AgentRepo",
            snapshot_hash=SNAPSHOT,
            component_scope=("app",),
            target_units=("app/main.cpp",),
            toolchain_profile="clang16",
            policy_ref="default",
            budget=budget,
        )
        policy = BuildPolicy(
            dependency_sets=make_policy().dependency_sets,
            allow_repository_root_configure=True,
            budget_ceiling=budget,
        )
        FakeExecutor()
        model = ScriptedModel(
            [
                plan_action(),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                final(),
            ],
            before_step=lambda m: clock.__setitem__(
                "now", 109.0
            )
            if len(m.states_seen) >= 3
            else None,
        )
        captured = {}

        class RecordingExecutor(FakeExecutor):
            def execute(self, recipe, snapshot_dir, output_dir, *, limits,
                        cancel, revision="unknown"):
                captured["limits"] = limits
                return super().execute(
                    recipe, snapshot_dir, output_dir,
                    limits=limits, cancel=cancel, revision=revision,
                )

        with mock.patch(
            "lima.build_agent.time.monotonic", lambda: clock["now"]
        ), mock.patch(
            "lima.build_tools.time.monotonic", lambda: clock["now"]
        ):
            result = self.run_agent(
                model, executor=RecordingExecutor(), request=request, policy=policy
            )
        self.assertEqual(result.status, SUCCEEDED)
        self.assertAlmostEqual(
            captured["limits"].total_seconds, 1.0, delta=0.5
        )

    def test_cancellation_between_rounds_beats_budget_exhaustion(self) -> None:
        # A cancellation during the run outranks a later step-budget
        # exhaustion, and stops calling the model at all (review F3).
        flags = {"cancel": False}
        model = ScriptedModel(
            [
                plan_action(),
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                tool("inspect_build_files"),
                final(),
            ],
            before_step=lambda m: flags.__setitem__("cancel", True)
            if m.states_seen
            else None,
        )
        result = self.run_agent(model, cancel=lambda: flags["cancel"])
        self.assertEqual(result.status, "CANCELLED")
        self.assertEqual(result.failure_code, "cancelled")
        self.assertEqual(len(model.states_seen), 1)

    def test_irrelevant_change_cannot_reset_fingerprint(self) -> None:
        # Editing export-only metadata keeps the execution identity, so the
        # identical failing configure is not retried (review F4).
        first = plan_action(feature="ON")

        def only_glob_changed() -> dict:
            edited = json.loads(json.dumps(first["arguments"]["plan"]))
            edited["generated_headers"] = ["build/config.h"]
            return {
                "action": "tool",
                "tool": "propose_build_plan",
                "arguments": {"plan": edited},
            }

        model = ScriptedModel(
            [
                first,
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                only_glob_changed(),
                tool("execute_configure"),
                final(),
            ]
        )
        executor = FakeExecutor(fail_first_attempts=99)
        result = self.run_agent(model, executor=executor)

        self.assertEqual(result.status, "FAILED")
        self.assertIn("fingerprint", result.failure_code or "")
        self.assertEqual(executor.calls, 1)

    def test_fingerprint_stop_locks_terminal(self) -> None:
        # Once the stop fires, even a genuinely new plan cannot continue:
        # the terminal is locked against later model output (review F4).
        model = ScriptedModel(
            [
                plan_action(feature="ON"),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                tool("execute_configure"),
                plan_action(feature="OFF"),
                tool("execute_configure"),
                final(),
            ]
        )
        executor = FakeExecutor(fail_first_attempts=99)
        result = self.run_agent(model, executor=executor)

        self.assertEqual(result.status, "FAILED")
        self.assertIn("fingerprint", result.failure_code or "")
        self.assertEqual(executor.calls, 1)

    def test_precondition_error_allows_first_real_attempt(self) -> None:
        # A dependencies-not-prepared refusal never started the executor,
        # so completing the precondition and executing for real is a first
        # attempt, not a fingerprint repeat (review round 2).
        model = ScriptedModel(
            [
                plan_action(),
                tool("execute_configure"),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                final(),
            ]
        )
        executor = FakeExecutor()
        result = self.run_agent(model, executor=executor)

        self.assertEqual(result.status, SUCCEEDED)
        self.assertEqual(executor.calls, 1)
        self.assertEqual(result.attempts, 1)

    def test_export_failure_allows_export_field_revision(self) -> None:
        # An export-stage failure fingerprints on the whole plan digest:
        # fixing expected_compdb (with the configure argv untouched) is the
        # effective change and must reach the executor (review round 2).
        def plan_with_compdb(compdb: str) -> dict:
            mapping = json.loads(
                json.dumps(plan_action(feature="ON")["arguments"]["plan"])
            )
            mapping["expected_compdb"] = compdb
            return {
                "action": "tool",
                "tool": "propose_build_plan",
                "arguments": {"plan": mapping},
            }

        model = ScriptedModel(
            [
                plan_with_compdb("build/wrong-compdb.json"),
                tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                tool("execute_configure"),
                plan_with_compdb("build/compile_commands.json"),
                tool("execute_configure"),
                final(),
            ]
        )
        executor = FakeExecutor(
            fail_first_attempts=1, failure_code="export-failed"
        )
        result = self.run_agent(model, executor=executor)

        self.assertEqual(result.status, SUCCEEDED)
        self.assertEqual(executor.calls, 2)
        self.assertEqual(result.attempts, 2)

    def test_model_receives_request_and_tool_catalog(self) -> None:
        # A generic adapter must be able to plan from the run state alone;
        # two different snapshots both succeed with the same model class
        # (review F5).
        for snapshot_hash in (SNAPSHOT, "c" * 64):
            with self.subTest(snapshot_hash[:8]):
                tmp = tempfile.mkdtemp()
                model = ContextReadingModel()
                request = BuildRequest(
                    repository_ref="Fixtures/AgentRepo",
                    snapshot_hash=snapshot_hash,
                    component_scope=("app",),
                    target_units=("app/main.cpp",),
                    toolchain_profile="clang16",
                    policy_ref="default",
                    budget=BuildBudget(),
                )
                result = self.run_agent(model, request=request, tmp=tmp)
                self.assertEqual(result.status, SUCCEEDED)
                first_state = model.seen_states[0]
                self.assertEqual(
                    first_state["request"]["snapshot_hash"], snapshot_hash
                )
                self.assertEqual(
                    sorted(t["name"] for t in first_state["tools"]),
                    sorted(BUILD_TOOL_NAMES),
                )
                # No host paths leak into the model-facing projection.
                self.assertNotIn(str(tmp), json.dumps(first_state))


if __name__ == "__main__":
    unittest.main()
