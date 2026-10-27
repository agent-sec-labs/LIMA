"""Controlled build tool tests (build agent slice 2).

The tool set is the only surface the model gets: seven structured tools over
one trusted, code-built context.  These tests freeze the negative gates the
plan names -- unapproved dependencies and network reach, budgets the model
cannot raise -- plus the happy path down to a package reference the agent
(S3) will hand to its result contract.
"""

import json
import tempfile
import unittest
from pathlib import Path

from lima.build_contracts import (
    ApprovedDependencySet,
    BuildBudget,
    BuildPolicy,
    BuildRequest,
)
from lima.build_executor import BuildExecutionResult, BuildLimits
from lima.build_tools import register_build_tools
from lima.context_package import build_manifest, write_package
from lima.runtime import ToolRegistry

SNAPSHOT = "a" * 64
TOOL_NAMES = {
    "inspect_build_files",
    "propose_build_plan",
    "prepare_dependencies",
    "execute_configure",
    "inspect_build_failure",
    "export_context_package",
    "validate_context",
}


def make_policy() -> BuildPolicy:
    return BuildPolicy(
        dependency_sets={
            "clang16-cmake": ApprovedDependencySet(
                image="lima-builder-clang16:2026-10"
            )
        }
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


def make_plan_mapping() -> dict:
    return {
        "snapshot_hash": SNAPSHOT,
        "adapter": "cmake-linux",
        "component_scope": ["app"],
        "configure_argv": [["cmake", "-S", ".", "-B", "build"]],
        "expected_compdb": "build/compile_commands.json",
        "generated_headers": ["build/*.h"],
        "include_roots": [
            {"container": "/usr/include/fixture", "package": "headers/fixture"}
        ],
        "dependency_set_ref": "clang16-cmake",
    }


def write_minimal_package(pkg_dir: Path, revision: str) -> None:
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
        created_by="tools-test",
    )
    write_package(
        pkg_dir,
        manifest,
        json.dumps(compdb, indent=2).encode("utf8"),
        {},
        {},
    )


class FakeExecutor:
    """Records execute() calls; a successful call writes a real package."""

    def __init__(self, *, ok: bool = True, forced_revision: str | None = None) -> None:
        self.ok = ok
        self.forced_revision = forced_revision
        self.calls: list[dict] = []

    def execute(self, recipe, snapshot_dir, output_dir, *, limits, cancel,
                revision="unknown"):
        self.calls.append(
            {
                "recipe": recipe,
                "snapshot_dir": Path(snapshot_dir),
                "output_dir": Path(output_dir),
                "limits": limits,
                "revision": revision,
            }
        )
        if self.ok:
            write_minimal_package(
                Path(output_dir) / "package", self.forced_revision or revision
            )
        return BuildExecutionResult(
            ok=self.ok,
            steps=(),
            image=recipe.image,
            image_digest=None,
            package_path=str(Path(output_dir) / "package") if self.ok else None,
            failure_code=None if self.ok else "configure-step-failed",
        )


class BuildToolsTest(unittest.TestCase):
    def make_registry(self, executor, *, request=None, policy=None,
                      root=None) -> ToolRegistry:
        registry = ToolRegistry()
        register_build_tools(
            registry,
            executor,
            policy or make_policy(),
            request=request or make_request(),
            snapshot_dir=root / "snapshot",
            artifacts_root=root / "artifacts",
            cancel=lambda: False,
        )
        return registry

    def test_tool_rejects_unapproved_dependency_and_network(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "snapshot" / "app").mkdir(parents=True)
            executor = FakeExecutor()
            registry = self.make_registry(executor, root=root)

            # Exactly the seven controlled tools; nothing network-shaped.
            self.assertEqual(set(registry.names()), TOOL_NAMES)

            result = registry.invoke(
                "prepare_dependencies", {"dependency_set_ref": "evil-download"}
            )
            self.assertFalse(result["ok"])
            self.assertIn("dependency-set-not-approved", result["error"])
            self.assertEqual(executor.calls, [])

    def test_budget_cannot_be_raised_by_model(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "snapshot" / "app").mkdir(parents=True)
            executor = FakeExecutor()
            registry = self.make_registry(executor, root=root)

            smuggled = make_plan_mapping()
            smuggled["budget"] = {"max_attempts": 99, "total_seconds": 99999}
            result = registry.invoke("propose_build_plan", {"plan": smuggled})
            self.assertFalse(result["ok"])
            self.assertIn("plan-field-unknown:budget", result["error"])
            self.assertEqual(executor.calls, [])

            registry.invoke(
                "propose_build_plan", {"plan": make_plan_mapping()}
            )
            registry.invoke(
                "prepare_dependencies",
                {"dependency_set_ref": "clang16-cmake"},
            )
            for _ in range(4):
                outcome = registry.invoke("execute_configure", {})
            self.assertFalse(outcome["ok"])
            self.assertIn("budget-exhausted-attempts", outcome["error"])
            # Three attempts ran; the fourth was refused before the executor.
            self.assertEqual(len(executor.calls), 3)

    def test_execute_configure_requires_validated_plan_and_prepared_deps(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "snapshot" / "app").mkdir(parents=True)
            executor = FakeExecutor()
            registry = self.make_registry(executor, root=root)

            result = registry.invoke("execute_configure", {})
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "no-validated-plan")

            registry.invoke(
                "propose_build_plan", {"plan": make_plan_mapping()}
            )
            result = registry.invoke("execute_configure", {})
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "dependencies-not-prepared")
            self.assertEqual(executor.calls, [])

    def test_execute_configure_happy_path_binds_request(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "snapshot" / "app").mkdir(parents=True)
            executor = FakeExecutor()
            registry = self.make_registry(executor, root=root)

            registry.invoke(
                "propose_build_plan", {"plan": make_plan_mapping()}
            )
            registry.invoke(
                "prepare_dependencies",
                {"dependency_set_ref": "clang16-cmake"},
            )
            result = registry.invoke("execute_configure", {})
            self.assertTrue(result["ok"])
            self.assertEqual(executor.calls[0]["recipe"].image,
                             "lima-builder-clang16:2026-10")
            self.assertEqual(executor.calls[0]["revision"], SNAPSHOT)
            self.assertIsInstance(executor.calls[0]["limits"], BuildLimits)
            self.assertEqual(
                executor.calls[0]["limits"].total_seconds,
                make_request().budget.total_seconds,
            )
            # Only attempt-relative references are returned to the model.
            self.assertEqual(result["package_ref"], "attempt-1/package")
            self.assertNotIn(str(root), json.dumps(result))

            second = registry.invoke("execute_configure", {})
            self.assertEqual(second["attempt"], 2)

    def test_inspect_build_failure_bounded_and_jailed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            logs = root / "artifacts" / "attempt-1" / "logs"
            logs.mkdir(parents=True)
            (logs / "step-000.stderr.log").write_bytes(b"E" * 200_000)

            executor = FakeExecutor(ok=False)
            registry = self.make_registry(executor, root=root)
            result = registry.invoke(
                "inspect_build_failure",
                {"step_ref": "attempt-1/logs/step-000.stderr.log"},
            )
            self.assertTrue(result["ok"])
            self.assertLessEqual(len(result["tail"].encode("utf8")), 32_768)
            self.assertIn("truncated", result["tail"])

            for bad in ("../secrets.txt", "/etc/passwd", "attempt-1/../../x"):
                with self.subTest(bad):
                    denied = registry.invoke(
                        "inspect_build_failure", {"step_ref": bad}
                    )
                    self.assertFalse(denied["ok"])
                    self.assertEqual(denied["error"], "step-ref-invalid")

    def test_validate_context_binds_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "snapshot" / "app").mkdir(parents=True)
            executor = FakeExecutor()
            registry = self.make_registry(executor, root=root)
            registry.invoke(
                "propose_build_plan", {"plan": make_plan_mapping()}
            )
            registry.invoke(
                "prepare_dependencies",
                {"dependency_set_ref": "clang16-cmake"},
            )
            registry.invoke("execute_configure", {})
            registry.invoke("export_context_package", {})
            result = registry.invoke("validate_context", {})
            self.assertTrue(result["ok"])
            self.assertEqual(result["snapshot_hash"], SNAPSHOT)

            # A package bound to another snapshot must not validate.
            other_root = Path(tempfile.mkdtemp(dir=tmp))
            (other_root / "snapshot" / "app").mkdir(parents=True)
            # The package is exported under a foreign revision, simulating a
            # package that does not belong to the requesting snapshot.
            wrong = FakeExecutor(forced_revision="d" * 64)
            wrong_registry = self.make_registry(
                wrong,
                request=BuildRequest(
                    repository_ref="Fixtures/AgentRepo",
                    snapshot_hash="c" * 64,
                    component_scope=("app",),
                    target_units=("app/main.cpp",),
                    toolchain_profile="clang16",
                    policy_ref="default",
                    budget=BuildBudget(),
                ),
                root=other_root,
            )
            wrong_plan = make_plan_mapping()
            wrong_plan["snapshot_hash"] = "c" * 64
            wrong_registry.invoke(
                "propose_build_plan", {"plan": wrong_plan}
            )
            wrong_registry.invoke(
                "prepare_dependencies",
                {"dependency_set_ref": "clang16-cmake"},
            )
            wrong_registry.invoke("execute_configure", {})
            wrong_registry.invoke("export_context_package", {})
            result = wrong_registry.invoke("validate_context", {})
            self.assertFalse(result["ok"])
            self.assertEqual(result["error"], "snapshot-mismatch")


if __name__ == "__main__":
    unittest.main()
