"""Verified-package build-context consumption tests (build agent slice 4B).

The verified-package mode is the first-class source above the existing
snapshot-compdb and heuristic tiers: an injected read-only
:class:`~lima.build_context_view.AnalysisContextView` (already verified and
sealed by slice 4A) provides the same per-TU argument projection to the
facts endpoint, the repro resolver and the Specialist driver contract.
Dangerous flags are rejected by the same fail-closed validator, every
declared target unit is resolved individually with its own TU-level
context hash, and the existing tiers keep their frozen semantics for
units outside the view.
"""

import json
import tempfile
import unittest
from pathlib import Path

from cxx_analyzer.build_context import (
    WIRE_SOURCE_KINDS,
    resolve_build_context_execution,
    resolve_build_context_wire,
)
from cxx_analyzer.config import AnalyzerSettings
from lima.agent_orchestrator import _driver_contract
from lima.build_context_view import (
    compute_artifact_digest,
    create_analysis_view,
    snapshot_fingerprint,
    verify_build_artifact,
)
from lima.context_package import build_manifest, write_package
from lima.cxx_memory import UAF_FACTS_BUILD_CONTEXT_MODES
from lima.uaf_models import RESOLUTION_SOURCE_KINDS
from lima.workspace import RepositoryWorkspace


def make_settings() -> AnalyzerSettings:
    return AnalyzerSettings(
        auto_cmake=True,
        build_steps=(),
        test_steps=(),
        max_memory_mb=1024,
        max_processes=32,
        max_output_bytes=8192,
        step_timeout_seconds=17,
        total_timeout_seconds=90,
        repository_scan_max_files=100,
        repository_scan_max_file_bytes=4096,
        repository_scan_max_total_bytes=16384,
        trusted_build_context_generation=False,
    )


def write_two_unit_package(pkg_dir: Path, revision: str, arguments) -> None:
    compdb = []
    for unit in ("app/main.cpp", "app/util.cpp"):
        entry_arguments = list(arguments) + [unit.rsplit("/", 1)[-1]]
        compdb.append(
            {
                "directory": "app",
                "arguments": entry_arguments,
                "file": unit,
            }
        )
    manifest = build_manifest(
        repository="Fixtures/AgentRepo",
        revision=revision,
        compdb=compdb,
        generated=[],
        header_roots=["headers/fixture"],
        rewrites={"/usr/include/fixture": "headers/fixture"},
        created_by="s4b-test",
    )
    write_package(
        pkg_dir,
        manifest,
        json.dumps(compdb).encode("utf8"),
        {},
        {"headers/fixture/lib.h": b"// lib\n"},
    )


def make_view(
    tmp: str,
    *,
    arguments: tuple[str, ...] = (
        "/usr/bin/c++",
        "-DVERIFIED=1",
        "-Iheaders/fixture",
        "-c",
    ),
):
    root = Path(tmp)
    snapshot = root / "snapshot"
    (snapshot / "app").mkdir(parents=True)
    (snapshot / "app" / "main.cpp").write_text("int main(void){return 0;}\n")
    (snapshot / "app" / "util.cpp").write_text("int util(void){return 1;}\n")
    fingerprint = snapshot_fingerprint(snapshot)
    pkg = root / "package"
    write_two_unit_package(pkg, fingerprint, arguments)
    artifact = verify_build_artifact(
        pkg, fingerprint, compute_artifact_digest(pkg)
    )
    view = create_analysis_view(
        snapshot, artifact, ("app/main.cpp", "app/util.cpp")
    )
    return snapshot, view


class VerifiedPackageResolutionTest(unittest.TestCase):
    def test_all_target_tus_checked(self) -> None:
        # Every declared target unit resolves individually, each with its
        # own TU-level context hash - never one sample for all.
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            hashes = set()
            for unit in ("app/main.cpp", "app/util.cpp"):
                context = resolve_build_context_execution(
                    snapshot, unit, make_settings(), verified_view=view
                )
                self.assertEqual(context.status, "resolved")
                self.assertEqual(context.source_kind, "verified-package")
                self.assertEqual(len(context.context_hash), 64)
                hashes.add(context.context_hash)
                self.assertIn("-DVERIFIED=1", context.arguments)
                self.assertEqual(context.relative_directory, "app")
            self.assertEqual(len(hashes), 2)

    def test_view_takes_priority_over_snapshot_compdb(self) -> None:
        # A registered verified package outranks a snapshot-local compdb.
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            (snapshot / "compile_commands.json").write_text(
                json.dumps(
                    [
                        {
                            "directory": str(snapshot),
                            "arguments": ["clang++-14", "-DLOCAL=1", "-c", "app/main.cpp"],
                            "file": "app/main.cpp",
                        }
                    ]
                ),
                encoding="utf8",
            )
            context = resolve_build_context_execution(
                snapshot, "app/main.cpp", make_settings(), verified_view=view
            )
            self.assertEqual(context.source_kind, "verified-package")
            self.assertIn("-DVERIFIED=1", context.arguments)
            self.assertNotIn("-DLOCAL=1", context.arguments)

    def test_unlisted_unit_falls_back_to_existing_sources(self) -> None:
        # Units outside the view keep the frozen existing semantics.
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _view = make_view(tmp)
            context = resolve_build_context_execution(
                snapshot,
                "app/other.cpp",
                make_settings(),
            )
            self.assertEqual(context.status, "incomplete")
            self.assertEqual(context.source_kind, "heuristic")
            self.assertIn("heuristic-context", context.diagnostics)

    def test_heuristic_never_reports_resolved(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _view = make_view(tmp)
            context = resolve_build_context_execution(
                snapshot, "app/other.cpp", make_settings()
            )
            self.assertNotEqual(context.status, "resolved")

    def test_response_file_and_plugin_flag_rejected(self) -> None:
        for dangerous in (
            ("-fplugin=evil.so",),
            ("-mllvm=evil",),
            ("-load=evil.so",),
        ):
            with self.subTest(dangerous[0]):
                with tempfile.TemporaryDirectory() as tmp:
                    full_argv = ("/usr/bin/c++", *dangerous, "-c")
                    snapshot, view = make_view(tmp, arguments=full_argv)
                    context = resolve_build_context_execution(
                        snapshot,
                        "app/main.cpp",
                        make_settings(),
                        verified_view=view,
                    )
                    self.assertEqual(context.status, "incomplete")
                    self.assertEqual(context.source_kind, "verified-package")
                    self.assertTrue(context.diagnostics)
                    self.assertNotIn("resolved", context.status)

    def test_mode_vocabularies_accept_verified_package(self) -> None:
        self.assertIn("verified-package", UAF_FACTS_BUILD_CONTEXT_MODES)
        self.assertIn("verified-package", WIRE_SOURCE_KINDS)
        self.assertIn("verified-package", RESOLUTION_SOURCE_KINDS)


class SharedProjectionTest(unittest.TestCase):
    def test_facts_repro_specialist_share_sanitized_flags(self) -> None:
        # The facts wire dict, the repro resolver entry and the
        # Specialist driver contract all consume the same view projection.
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            settings = make_settings()
            wire = resolve_build_context_wire(
                snapshot, "app/main.cpp", settings, verified_view=view
            )
            execution = resolve_build_context_execution(
                snapshot, "app/main.cpp", settings, verified_view=view
            )
            self.assertEqual(wire["status"], "resolved")
            self.assertEqual(wire["source_kind"], "verified-package")
            self.assertEqual(wire["context_hash"], execution.context_hash)

            workspace = RepositoryWorkspace(str(snapshot))
            contract = _driver_contract(
                workspace, "app/main.cpp", verified_view=view
            )
            self.assertIn("-DVERIFIED=1", contract)
            legacy = _driver_contract(workspace, "app/main.cpp")
            self.assertNotIn("-DVERIFIED=1", legacy)


if __name__ == "__main__":
    unittest.main()
