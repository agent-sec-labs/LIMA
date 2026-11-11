"""Regression tests for the requested build-target coverage contract."""

from __future__ import annotations

import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from lima.build_agent import FAILED, BuildAgent
from lima.build_context_view import snapshot_fingerprint
from tests.test_build_agent import (
    FakeExecutor,
    ScriptedModel,
    final,
    make_policy,
    make_request,
    plan_action,
    tool,
)


class BuildTargetContractTest(unittest.TestCase):
    def test_missing_requested_translation_unit_cannot_succeed(self) -> None:
        """A valid package is insufficient when it omits a requested TU."""

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot = root / "snapshot"
            (snapshot / "app").mkdir(parents=True)
            (snapshot / "app" / "main.cpp").write_text("int main(){return 0;}\n")
            (snapshot / "app" / "required.cpp").write_text("int required(){return 1;}\n")
            fingerprint = snapshot_fingerprint(snapshot)
            request = replace(
                make_request(),
                snapshot_hash=fingerprint,
                target_units=("app/required.cpp",),
            )
            plan = plan_action()
            plan["arguments"]["plan"]["snapshot_hash"] = fingerprint
            model = ScriptedModel(
                [
                    plan,
                    tool("prepare_dependencies", dependency_set_ref="clang16-cmake"),
                    tool("execute_configure"),
                    tool("validate_context"),
                    final(),
                ]
            )
            result = BuildAgent(
                model=model,
                executor=FakeExecutor(),  # exports only app/main.cpp
                policy=make_policy(),
                snapshot_dir=snapshot,
                artifacts_root=root / "artifacts",
            ).run(request)

        self.assertEqual(result.status, FAILED)
        self.assertEqual(result.failure_code, "target-units-missing")
        self.assertIsNone(result.package_ref)

