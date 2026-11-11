"""Platform TU-budget omissions remain visible in reports and sealed AEPs."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lima.cxx_memory import UafFactsResponse, uaf_facts_bundle_sha256
from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace


class _FactsAdapter:
    def analyze_uaf_facts(
        self, repository_key, snapshot_hash, translation_units, build_context_mode,
        *, artifact_digest=None,
    ):
        units = [
            {
                "translation_unit": unit,
                "extraction": "completed",
                "build_context": {
                    "status": "resolved",
                    "source_kind": "repository-compdb",
                    "context_hash": "c" * 64,
                    "diagnostics": [],
                },
                "coverage": {
                    "ast_complete": True,
                    "cfg_complete": True,
                    "semantic_gaps": [],
                },
                "facts": [],
            }
            for unit in translation_units
        ]
        return UafFactsResponse(
            request_id="scope-budget",
            repository_key=repository_key,
            snapshot_sha256=snapshot_hash,
            tool_runs=(
                {"run_id": "scope-budget", "tool": "uaf-facts", "status": "completed"},
            ),
            translation_units=tuple(units),
            bundle_sha256=uaf_facts_bundle_sha256(units),
            diagnostics=(),
        )


class PlatformScopeBudgetTests(unittest.TestCase):
    def _summary(self, unit_count):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        for index in range(unit_count):
            source = root / "src" / f"unit{index:03d}.cpp"
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text("int value() { return 0; }\n", encoding="utf8")
        workspace = RepositoryWorkspace(root)
        inventory = workspace.inventory()
        scanner = RepositoryScanner(
            cxx_memory_mode="auto",
            cxx_memory_adapter=_FactsAdapter(),
            cxx_agent_mode="auto",
            cxx_uaf_llm_factory=lambda: {
                "provider": "custom", "base_url": "http://unit.invalid",
                "api_key": "test", "model": "test", "headers": {},
            },
        )
        with mock.patch(
            "lima.agent_orchestrator.send_semantic_request",
            return_value=json.dumps({"leads": []}),
        ), mock.patch(
            "lima.agent_orchestrator._discover_leads",
            return_value=((), (), ()),
        ):
            return scanner._run_platform_branch(
                workspace, inventory, [], None, {}, "team/project", None,
            )

    @staticmethod
    def _aep(summary):
        v4 = summary["v4"]
        aep_id = v4["aep"]["artifact_id"]
        return v4["payloads"][aep_id]

    def test_seventeenth_requested_translation_unit_is_reported_unreviewed(self):
        summary = self._summary(17)
        self.assertEqual("review-incomplete", summary["status"])
        self.assertEqual(16, len(summary["translation_units"]))
        self.assertEqual(["src/unit016.cpp"], summary["unreviewed_units"])
        aep = self._aep(summary)
        self.assertEqual("incomplete", aep["audit_outcome"])
        self.assertEqual(17, aep["coverage"]["in_scope_file_count"])
        self.assertIn(
            {"gap_code": "COVERAGE_GAP", "detail": "unreviewed-unit: src/unit016.cpp"},
            aep["coverage_gaps"],
        )

    def test_large_omitted_scope_keeps_full_summary_and_bounded_aep_sample(self):
        summary = self._summary(300)
        self.assertEqual("review-incomplete", summary["status"])
        self.assertEqual(284, len(summary["unreviewed_units"]))
        self.assertEqual("src/unit016.cpp", summary["unreviewed_units"][0])
        self.assertEqual("src/unit299.cpp", summary["unreviewed_units"][-1])
        aep = self._aep(summary)
        self.assertEqual("incomplete", aep["audit_outcome"])
        self.assertEqual(300, aep["coverage"]["in_scope_file_count"])
        self.assertLessEqual(len(aep["coverage_gaps"]), 256)
        self.assertTrue(any(
            gap["detail"].startswith("unreviewed-unit-count: 284;")
            for gap in aep["coverage_gaps"]
        ))


if __name__ == "__main__":
    unittest.main()
