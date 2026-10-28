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

    def __init__(self, *, fail_first_attempts: int = 0) -> None:
        self.fail_first_attempts = fail_first_attempts
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
            failure_code=None if ok else "configure-step-failed",
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


if __name__ == "__main__":
    unittest.main()
