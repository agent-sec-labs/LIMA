from __future__ import annotations

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ContinuousIntegrationContractTests(unittest.TestCase):
    def test_pull_requests_have_one_stable_fail_closed_merge_gate(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("pull_request:", workflow)
        self.assertNotIn("pull_request_target", workflow)
        self.assertIn("name: merge-gate", workflow)
        self.assertIn("if: always()", workflow)
        for dependency in (
            "quality-contracts", "unit-tests", "repair-constraints",
            "container-tests", "security-baseline",
        ):
            self.assertIn("${{ needs.%s.result }}" % dependency, workflow)

    def test_workflow_is_secretless_and_pins_every_action(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertNotIn("secrets.", workflow)
        self.assertNotIn("API_KEY", workflow)
        references = re.findall(r"^\s*-?\s*uses:\s*([^\s#]+)", workflow, re.MULTILINE)
        self.assertTrue(references)
        for reference in references:
            self.assertRegex(
                reference,
                r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[0-9a-f]{40}$",
            )

    def test_cross_platform_frontend_experiment_and_evidence_gates_are_present(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for required in (
            "ubuntu-latest", "windows-latest", "'3.11'", "'3.12'",
            "node --check web/app.js", "tests.test_experiments",
            "scripts/run_ci_tests.py", "actions/upload-artifact@",
            "docker run --rm --read-only", "--min-constraint-accuracy 1.0",
        ):
            self.assertIn(required, workflow)
        self.assertTrue((ROOT / "scripts" / "run_ci_tests.py").is_file())

    def test_contributor_commands_match_the_actual_test_runner(self):
        contributing = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
        template = (ROOT / ".github" / "pull_request_template.md").read_text(
            encoding="utf-8"
        )
        self.assertIn("python -m unittest discover -s tests -v", contributing)
        self.assertIn("python -m unittest discover -s tests -v", template)
        self.assertNotIn("python -m pytest", contributing)
        self.assertNotIn("python -m pytest", template)


if __name__ == "__main__":
    unittest.main()
