"""Task-scoped gates for C/C++ analyzer layers."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from lima.cxx_memory import REQUESTED_LAYERS, CxxAnalysisResult
from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace


class RecordingAdapter:
    def __init__(self) -> None:
        self.calls: list[tuple[str, ...]] = []

    def analyze(self, _repository, _snapshot, layers, *, inventory):
        self.calls.append(layers)
        return CxxAnalysisResult(
            status="completed",
            tool_runs=[{"tool": "semgrep", "status": "completed"}],
            findings=[],
            coverage={"source_files": len(inventory.files)},
            diagnostics=[],
        )


def _workspace(root: Path) -> RepositoryWorkspace:
    root.joinpath("main.cpp").write_text("int main(){ return 0; }\n", encoding="utf-8")
    return RepositoryWorkspace(root)


class ScanContextLayerGateTests(unittest.TestCase):
    def test_build_context_gate_requests_only_source_layer_without_mutating_scanner(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adapter = RecordingAdapter()
            scanner = RepositoryScanner(
                sast_mode="off",
                dataflow_enabled=False,
                cxx_memory_mode="auto",
                cxx_memory_adapter=adapter,
            )
            gated = scanner.scan(
                _workspace(Path(temporary)),
                repository_key="team/project",
                cxx_allowed_layers=("source-only",),
            )
            summary = gated.report.collaboration["cxx_memory"]
            self.assertEqual(adapter.calls, [("source-only",)])
            self.assertEqual(summary["requested_layers"], list(REQUESTED_LAYERS))
            self.assertEqual(summary["effective_layers"], ["source-only"])
            self.assertEqual(
                summary["blocked_layers"], ["build-backed", "sanitizer-confirmed"]
            )
            self.assertEqual(summary["status"], "partial")

            # The override is per task: the next scan keeps the scanner default.
            second_root = Path(temporary) / "second"
            second_root.mkdir()
            scanner.scan(_workspace(second_root), repository_key="team/project")
            self.assertEqual(adapter.calls[-1], REQUESTED_LAYERS)

    def test_all_cxx_layers_blocked_does_not_call_adapter(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            adapter = RecordingAdapter()
            result = RepositoryScanner(
                sast_mode="off",
                dataflow_enabled=False,
                cxx_memory_mode="required",
                cxx_memory_adapter=adapter,
            ).scan(
                _workspace(Path(temporary)),
                repository_key="team/project",
                cxx_allowed_layers=(),
            )
            summary = result.report.collaboration["cxx_memory"]
            self.assertEqual(adapter.calls, [])
            self.assertEqual(summary["status"], "blocked")
            self.assertEqual(summary["effective_layers"], [])
            self.assertEqual(summary["blocked_layers"], list(REQUESTED_LAYERS))
