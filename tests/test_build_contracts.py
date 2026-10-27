"""Build request, plan and policy contract tests (build agent slice 2).

The contracts freeze the boundary between the model and the executor: a
candidate ``BuildPlan`` is data the model proposes, never something it may
execute; ``validate_build_plan`` is the trusted gate that binds a plan to one
request snapshot and one deployment-approved policy before any container can
start.  Every rejection carries a stable reason string and never reaches the
executor.
"""

import unittest

from lima.build_contracts import (
    ApprovedDependencySet,
    BuildBudget,
    BuildPlan,
    BuildPlanError,
    BuildPolicy,
    BuildRequest,
    validate_build_plan,
)

SNAPSHOT = "a" * 64
OTHER_SNAPSHOT = "b" * 64


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


class BuildRequestTest(unittest.TestCase):
    def test_request_contract(self) -> None:
        request = make_request()
        self.assertEqual(request.goal, "analysis-context")
        with self.assertRaises(BuildPlanError) as caught:
            BuildRequest(
                repository_ref="x",
                snapshot_hash="nothex",
                component_scope=("app",),
                target_units=("app/main.cpp",),
                toolchain_profile="clang16",
                policy_ref="default",
                budget=BuildBudget(),
            )
        self.assertIn("snapshot-hash-invalid", caught.exception.reason)
        with self.assertRaises(BuildPlanError) as caught_goal:
            BuildRequest(
                repository_ref="x",
                snapshot_hash=SNAPSHOT,
                goal="compile-target",
                component_scope=("app",),
                target_units=("app/main.cpp",),
                toolchain_profile="clang16",
                policy_ref="default",
                budget=BuildBudget(),
            )
        self.assertIn("goal-unsupported", caught_goal.exception.reason)

    def test_budget_must_be_positive(self) -> None:
        with self.assertRaises(BuildPlanError):
            BuildBudget(max_attempts=0)
        with self.assertRaises(BuildPlanError):
            BuildBudget(total_seconds=-1)


class BuildPlanTest(unittest.TestCase):
    def test_plan_parses_from_model_mapping(self) -> None:
        plan = BuildPlan.from_mapping(make_plan_mapping())
        self.assertEqual(plan.adapter, "cmake-linux")
        self.assertEqual(
            plan.configure_argv, (("cmake", "-S", ".", "-B", "build"),)
        )

    def test_plan_rejects_unknown_fields(self) -> None:
        mapping = make_plan_mapping()
        mapping["budget"] = {"max_attempts": 99}
        with self.assertRaises(BuildPlanError) as caught:
            BuildPlan.from_mapping(mapping)
        self.assertIn("plan-field-unknown:budget", caught.exception.reason)

    def test_plan_rejects_shell_or_host_path(self) -> None:
        cases = {
            "configure-as-string": {
                "configure_argv": ["cmake -S . -B build"]
            },
            "argv-item-not-string": {"configure_argv": [["cmake", 7]]},
            "empty-argv": {"configure_argv": [[]]},
            "windows-drive": {"configure_argv": [["cmake", "-S", "C:\\repo"]]},
            "backslash-path": {"configure_argv": [["cmake", "-S", "a\\b"]]},
            "shell-chaining": {"configure_argv": [["cmake", "-S", "a && b"]]},
            "shell-substitution": {
                "configure_argv": [["cmake", "-S", "$(whoami)"]]
            },
        }
        for label, patch in cases.items():
            with self.subTest(label):
                mapping = make_plan_mapping()
                mapping.update(patch)
                with self.assertRaises(BuildPlanError) as caught:
                    BuildPlan.from_mapping(mapping)
                self.assertIn(
                    "configure", caught.exception.reason
                )

    def test_plan_rejects_bad_relative_paths(self) -> None:
        cases = {
            "compdb-absolute": {"expected_compdb": "/build/compdb.json"},
            "compdb-escape": {"expected_compdb": "../escape.json"},
            "generated-absolute": {"generated_headers": ["/build/*.h"]},
            "include-root-relative": {
                "include_roots": [
                    {"container": "usr/include/x", "package": "headers/x"}
                ]
            },
            "include-root-package-escape": {
                "include_roots": [
                    {"container": "/usr/include/x", "package": "../evil"}
                ]
            },
        }
        for label, patch in cases.items():
            with self.subTest(label):
                mapping = make_plan_mapping()
                mapping.update(patch)
                with self.assertRaises(BuildPlanError):
                    BuildPlan.from_mapping(mapping)


class ValidateBuildPlanTest(unittest.TestCase):
    def test_valid_plan_binds_request_and_policy(self) -> None:
        validated = validate_build_plan(
            make_request(), BuildPlan.from_mapping(make_plan_mapping()),
            make_policy(),
        )
        self.assertEqual(
            validated.dependency_set.image, "lima-builder-clang16:2026-10"
        )
        self.assertEqual(validated.budget, make_request().budget)

    def test_plan_rejects_snapshot_scope_mismatch(self) -> None:
        for label, patch in {
            "snapshot": {"snapshot_hash": OTHER_SNAPSHOT},
            "scope": {"component_scope": ["other"]},
        }.items():
            with self.subTest(label):
                mapping = make_plan_mapping()
                mapping.update(patch)
                with self.assertRaises(BuildPlanError) as caught:
                    validate_build_plan(
                        make_request(),
                        BuildPlan.from_mapping(mapping),
                        make_policy(),
                    )
                self.assertIn(f"{label}-mismatch", caught.exception.reason)

    def test_plan_rejects_unapproved_adapter_and_dependency(self) -> None:
        for label, patch in {
            "adapter-unsupported": {"adapter": "gn-openharmony"},
            "dependency-set-not-approved": {
                "dependency_set_ref": "evil-download"
            },
        }.items():
            with self.subTest(label):
                mapping = make_plan_mapping()
                mapping.update(patch)
                with self.assertRaises(BuildPlanError) as caught:
                    validate_build_plan(
                        make_request(),
                        BuildPlan.from_mapping(mapping),
                        make_policy(),
                    )
                self.assertIn(label, caught.exception.reason)

    def test_request_budget_cannot_exceed_policy_ceiling(self) -> None:
        request = BuildRequest(
            repository_ref="Fixtures/AgentRepo",
            snapshot_hash=SNAPSHOT,
            component_scope=("app",),
            target_units=("app/main.cpp",),
            toolchain_profile="clang16",
            policy_ref="default",
            budget=BuildBudget(max_attempts=99),
        )
        with self.assertRaises(BuildPlanError) as caught:
            validate_build_plan(
                request, BuildPlan.from_mapping(make_plan_mapping()),
                make_policy(),
            )
        self.assertIn("budget-exceeds-policy", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
