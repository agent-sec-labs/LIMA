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
            "tests.test_experiments",
            "scripts/run_ci_tests.py", "actions/upload-artifact@",
            "docker run --rm --read-only", "--min-constraint-accuracy 1.0",
        ):
            self.assertIn(required, workflow)
        # T10：legacy 前端语法检查随 web/ 一并退役（React 有 typecheck + Vitest）。
        self.assertNotIn("node --check", workflow)
        self.assertTrue((ROOT / "scripts" / "run_ci_tests.py").is_file())

    def test_frontend_quality_and_linux_only_e2e_gates_are_present(self):
        workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
            encoding="utf-8"
        )
        for required in (
            "name: frontend-tests", "name: frontend-e2e",
            "vitest run --coverage", "npm run build", "npx playwright test",
        ):
            self.assertIn(required, workflow)
        # merge-gate 聚合前端质量与 E2E 门禁（T9）。
        for dependency in ("frontend-tests", "frontend-e2e"):
            self.assertIn("${{ needs.%s.result }}" % dependency, workflow)
        # 冻结决策 4：E2E 仅 Linux CI，绝不进入 windows 矩阵。
        e2e_block = workflow.split("name: frontend-e2e", 1)[1]
        self.assertIn("runs-on: ubuntu-latest", e2e_block.split("name: merge-gate", 1)[0])
        self.assertNotIn("windows-latest", e2e_block.split("name: merge-gate", 1)[0])
        vitest_config = (
            ROOT / "frontend" / "vitest.config.ts"
        ).read_text(encoding="utf-8")
        self.assertIn("thresholds: { lines: 60 }", vitest_config)
        self.assertEqual(
            vitest_config.count("thresholds"), 1,
            "覆盖率阈值只允许行覆盖率一个维度",
        )

    def test_e2e_spec_documents_linux_only_freeze_and_reports_stay_in_frontend(self):
        spec = (
            ROOT / "frontend" / "e2e" / "audit-lifecycle.spec.ts"
        ).read_text(encoding="utf-8")
        header = spec[:800]
        self.assertIn("冻结决策 4", header)
        self.assertIn("Linux CI", header)
        playwright_config = (
            ROOT / "frontend" / "playwright.config.ts"
        ).read_text(encoding="utf-8")
        # 报告与产物固定在 frontend/test-results 之下（不落在仓库 tests/）。
        self.assertIn('outputFolder: "test-results/html"', playwright_config)
        self.assertIn('outputDir: "test-results/output"', playwright_config)
        gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
        for entry in ("frontend/coverage/", "frontend/test-results/"):
            self.assertIn(entry, gitignore)

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
