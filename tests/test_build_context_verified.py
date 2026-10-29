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
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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


def write_two_unit_package(
    pkg_dir: Path, revision: str, arguments, util_arguments=None
) -> None:
    compdb = []
    for unit in ("app/main.cpp", "app/util.cpp"):
        unit_arguments = (
            arguments if unit.endswith("main.cpp") or util_arguments is None
            else util_arguments
        )
        entry_arguments = list(unit_arguments) + [unit.rsplit("/", 1)[-1]]
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
    util_arguments: tuple[str, ...] | None = None,
):
    root = Path(tmp)
    snapshot = root / "snapshot"
    (snapshot / "app").mkdir(parents=True)
    (snapshot / "app" / "main.cpp").write_text("int main(void){return 0;}\n")
    (snapshot / "app" / "util.cpp").write_text("int util(void){return 1;}\n")
    fingerprint = snapshot_fingerprint(snapshot)
    pkg = root / "package"
    write_two_unit_package(
        pkg, fingerprint, arguments, util_arguments
    )
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
                # One repository-root working directory for every path.
                self.assertEqual(context.relative_directory, ".")
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


class Round1ReviewTests(unittest.TestCase):
    """Targeted regressions for the PR #347 review findings."""

    def test_repro_entry_consumes_the_view(self) -> None:
        # The real repro parameter path (_context_flags, called by
        # run_repro) consumes the verified view (review F1).
        from cxx_analyzer.repro import _context_flags

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            prepared = SimpleNamespace(root=snapshot, sha256="a" * 64)
            from cxx_analyzer.repro import _verified_context_outcome

            outcome = _verified_context_outcome(
                prepared, ("app/main.cpp",), make_settings(), view
            )
            self.assertIsInstance(outcome, tuple)
            self.assertIn("-DVERIFIED=1", outcome)
            legacy = _context_flags(prepared, ("app/main.cpp",), make_settings())
            self.assertNotIn("-DVERIFIED=1", legacy)

    def test_specialist_entry_consumes_the_view(self) -> None:
        # _process_target (the real Specialist loop entry called by
        # run_platform_review) threads the view into the driver contract
        # (review F1): patch the contract recorder and run one mocked
        # target.

        import lima.agent_orchestrator as orchestrator
        from lima.agent_scout import ScoutTarget
        from lima.cxx_agent_tools import CxxAgentBudget

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            workspace = RepositoryWorkspace(str(snapshot))
            captured: dict[str, object] = {}

            def recording_contract(workspace, unit_path, verified_view=None):
                captured["verified_view"] = verified_view
                return "contract"

            target = ScoutTarget(
                lead_id="L1",
                path="app/main.cpp",
                line=1,
                reason="test",
                confidence="medium",
            )
            with mock.patch.object(
                orchestrator, "_driver_contract", recording_contract
            ), mock.patch.object(
                orchestrator,
                "_platform_round",
                side_effect=RuntimeError("stop-after-contract"),
            ):
                with self.assertRaises(RuntimeError):
                    orchestrator._process_target(
                        target,
                        workspace=workspace,
                        repository_key="Fixtures/AgentRepo",
                        snapshot_hash="a" * 64,
                        bundle=None,
                        candidate=None,
                        resolved_llm={},
                        budget=CxxAgentBudget(),
                        mode="auto",
                        dialogue_rounds=1,
                        timeout=1,
                        deadline=None,
                        source_mode="repository",
                        repro_workbench=None,
                        tool_analysis=None,
                        verified_view=view,
                        diagnostics=[],
                        specialist_calls=[0],
                        critic_calls=[0],
                    )
            self.assertIs(captured["verified_view"], view)

    def test_specialist_projection_keeps_standards(self) -> None:
        # The verified Specialist projection is the full flags projection
        # - a -std flag survives instead of being filtered away (F4).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(
                tmp,
                arguments=(
                    "/usr/bin/c++",
                    "-std=c++20",
                    "-DVERIFIED=1",
                    "-Iheaders/fixture",
                    "-c",
                ),
            )
            workspace = RepositoryWorkspace(str(snapshot))
            contract = _driver_contract(
                workspace, "app/main.cpp", verified_view=view
            )
            self.assertIn("-std=c++20", contract)
            self.assertIn("-DVERIFIED=1", contract)

    def test_mode_gating_and_missing_view(self) -> None:
        # Only mode=verified-package consults the registry; a missing view
        # is an explicit incomplete, and legacy modes ignore whatever is
        # registered (review F3).
        from cxx_analyzer import server as analyzer_server
        from cxx_analyzer.deadline import AnalysisDeadline

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            prepared = SimpleNamespace(root=snapshot, sha256="b" * 64)
            deadline = AnalysisDeadline(expires_at=time.time() + 60)
            analyzer_server.clear_verified_build_views()

            missing = analyzer_server._extract_uaf_unit(
                prepared,
                "app/main.cpp",
                make_settings(),
                deadline,
                build_context_mode="verified-package",
            )
            self.assertEqual(missing["extraction"], "unavailable")
            self.assertIn(
                "verified-view-not-registered",
                missing["coverage"]["semantic_gaps"],
            )

            analyzer_server.register_verified_build_view("b" * 64, view)
            legacy = analyzer_server._extract_uaf_unit(
                prepared,
                "app/main.cpp",
                make_settings(),
                deadline,
                build_context_mode="snapshot-compdb",
            )
            self.assertEqual(
                legacy["build_context"]["source_kind"], "heuristic"
            )
            analyzer_server.clear_verified_build_views()

    def test_view_digest_slots_select_identity(self) -> None:
        from cxx_analyzer import server as analyzer_server

        analyzer_server.clear_verified_build_views()
        try:
            analyzer_server.register_verified_build_view("c" * 64, "view-a")
            analyzer_server.register_verified_build_view(
                "c" * 64, "view-b", artifact_digest="d" * 64
            )
            self.assertIs(
                analyzer_server.lookup_verified_build_view("c" * 64, None),
                "view-a",
            )
            self.assertIs(
                analyzer_server.lookup_verified_build_view(
                    "c" * 64, "d" * 64
                ),
                "view-b",
            )
            self.assertIsNone(
                analyzer_server.lookup_verified_build_view(
                    "c" * 64, "e" * 64
                )
            )
        finally:
            analyzer_server.clear_verified_build_views()

    def test_members_are_laid_out_and_argv_executes(self) -> None:
        # Sealed members become readable files and the emitted argv/cwd
        # actually resolves on disk (review F2); real Clang when present.

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "snapshot"
            (snapshot / "app").mkdir(parents=True)
            (snapshot / "app" / "main.cpp").write_text(
                '#include "lib.h"\n#include "config.h"\n'
                "int main(void) { return FIXTURE_VALUE; }\n",
                encoding="utf8",
            )
            (snapshot / "build").mkdir(exist_ok=True)
            frozen_root = sys.platform != "win32"
            if frozen_root:
                snapshot.chmod(0o555)
            try:
                self._layout_and_compile(snapshot, frozen_root)
            finally:
                # Restore permissions while the directory still exists;
                # a cleanup callback would run after TemporaryDirectory
                # has already removed it.
                if frozen_root:
                    snapshot.chmod(0o755)

    def _layout_and_compile(self, snapshot: Path, frozen_root: bool) -> None:
        import shutil
        import subprocess

        if True:
            root = snapshot.parent
            fingerprint = snapshot_fingerprint(snapshot)
            compdb = [
                {
                    "directory": "app",
                    "arguments": [
                        "/usr/bin/c++",
                        "-Iheaders/fixture",
                        "-Ibuild",
                        "-c",
                        "main.cpp",
                    ],
                    "file": "app/main.cpp",
                }
            ]
            manifest = build_manifest(
                repository="Fixtures/AgentRepo",
                revision=fingerprint,
                compdb=compdb,
                generated=["build/config.h"],
                header_roots=["headers/fixture"],
                rewrites={"/usr/include/fixture": "headers/fixture"},
                created_by="s4b-test",
            )
            pkg = root / "package"
            write_package(
                pkg,
                manifest,
                json.dumps(compdb).encode("utf8"),
                {"build/config.h": b"#define FIXTURE_VALUE 0\n"},
                {"headers/fixture/lib.h": b"#define LIB_H\n"},
            )
            artifact = verify_build_artifact(
                pkg, fingerprint, compute_artifact_digest(pkg)
            )
            view = create_analysis_view(snapshot, artifact, ("app/main.cpp",))

            context = resolve_build_context_execution(
                snapshot, "app/main.cpp", make_settings(), verified_view=view
            )
            self.assertEqual(context.status, "resolved")
            # Vendored roots land in the writable layout directory, never
            # next to the frozen sources; generated files return to their
            # build location.
            self.assertTrue(
                (
                    snapshot
                    / "build"
                    / "lima-verified"
                    / "headers"
                    / "fixture"
                    / "lib.h"
                ).is_file()
            )
            self.assertTrue((snapshot / "build" / "config.h").is_file())
            self.assertIn(
                "-Ibuild/lima-verified/headers/fixture", context.arguments
            )

            compiler = shutil.which("clang++-14") or shutil.which("clang++")
            if compiler is None:
                self.skipTest("a clang++ compiler is required for this fixture")
            argv = [compiler, *context.arguments[1:]]
            completed = subprocess.run(  # noqa: S603 - fixed clang fixture argv
                argv,
                cwd=snapshot,
                capture_output=True,
                check=False,
                timeout=90,
            )
            self.assertEqual(
                completed.returncode,
                0,
                completed.stderr.decode("utf8", errors="replace")[-2000:],
            )
            # Without the laid-out context the same unit must not compile.
            broken = subprocess.run(  # noqa: S603 - fixed clang fixture argv
                [compiler, "-fsyntax-only", "app/main.cpp"],
                cwd=snapshot,
                capture_output=True,
                check=False,
                timeout=90,
            )
            self.assertNotEqual(broken.returncode, 0)


class Round2ReviewTests(unittest.TestCase):
    """Targeted regressions for the PR #347 round-2 review."""

    def test_repro_keeps_language_standard(self) -> None:
        # The verified repro path intersects the validated per-unit
        # projections verbatim: a shared -std survives instead of being
        # dropped by the legacy language-neutral subset (review round 2
        # F3).

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(
                tmp,
                arguments=(
                    "/usr/bin/c++",
                    "-std=c++20",
                    "-DVERIFIED=1",
                    "-Iheaders/fixture",
                    "-c",
                ),
            )
            prepared = SimpleNamespace(root=snapshot, sha256="a" * 64)
            from cxx_analyzer.repro import _verified_context_outcome

            outcome = _verified_context_outcome(
                prepared, ("app/main.cpp", "app/util.cpp"), make_settings(), view
            )
            self.assertIsInstance(outcome, tuple)
            self.assertIn("-std=c++20", outcome)
            self.assertIn("-DVERIFIED=1", outcome)

    def test_specialist_rejects_unsafe_view(self) -> None:
        # A view whose projection fails the shared fail-closed validation
        # never produces a usable Specialist compile contract (review
        # round 2 F4).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(
                tmp,
                arguments=("/usr/bin/c++", "-fplugin=evil.so", "-c"),
            )
            workspace = RepositoryWorkspace(str(snapshot))
            contract = _driver_contract(
                workspace, "app/main.cpp", verified_view=view
            )
            self.assertIn("verified context rejected", contract)
            self.assertNotIn("fplugin", contract)

    def test_repro_request_wire_accepts_view_identity(self) -> None:
        # The repro wire contract carries the verified view identity and
        # the handler threads it into run_repro (review round 2 F1).
        from cxx_analyzer import server as analyzer_server

        payload = {
            "schema_version": analyzer_server.SCHEMA_VERSION,
            "request_id": "123e4567-e89b-42d3-a456-426614174000",
            "repository_key": "acme/widgets",
            "snapshot_sha256": "a" * 64,
            "source_files": ["app/main.cpp"],
            "driver_code": "int main(void){return 0;}",
            "verified_artifact_digest": "d" * 64,
        }
        request = analyzer_server._validate_repro_payload(payload)
        self.assertEqual(request["verified_artifact_digest"], "d" * 64)

    def test_repro_entry_threads_registered_view(self) -> None:
        # The default-slot view registered for the snapshot reaches
        # run_repro when the request names its artifact digest.
        from cxx_analyzer import server as analyzer_server

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(tmp)
            analyzer_server.clear_verified_build_views()
            analyzer_server.register_verified_build_view(
                "f" * 64, view, artifact_digest="d" * 64
            )
            self.addCleanup(analyzer_server.clear_verified_build_views)
            resolved = analyzer_server.lookup_verified_build_view(
                "f" * 64, "d" * 64
            )
            self.assertIs(resolved, view)
            self.assertIsNone(analyzer_server.lookup_verified_build_view("e" * 64, None))


class Round3ReviewTests(unittest.TestCase):
    """Targeted regressions for the PR #347 round-3 review."""

    def test_std_reaches_the_command_builder(self) -> None:
        # The verified -std survives the real command constructor, not
        # just the flag helper (review round 3 F1).
        from cxx_analyzer.repro import build_compile_argv

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(
                tmp,
                arguments=(
                    "/usr/bin/c++",
                    "-std=c++20",
                    "-DVERIFIED=1",
                    "-Iheaders/fixture",
                    "-c",
                ),
            )
            prepared = SimpleNamespace(root=snapshot, sha256="a" * 64)
            from cxx_analyzer.repro import _verified_context_outcome

            outcome = _verified_context_outcome(
                prepared, ("app/main.cpp",), make_settings(), view
            )
            self.assertIsInstance(outcome, tuple)
            flags = outcome
            argv = build_compile_argv(
                ["app/main.cpp"],
                "build/repro_driver_x.cpp",
                "build/repro_x",
                context_flags=flags,
                allowed_std=True,
            )
            self.assertIn("-std=c++20", argv)
            # The legacy channel still refuses a standard.
            with self.assertRaises(ValueError):
                build_compile_argv(
                    ["app/main.cpp"],
                    "build/repro_driver_x.cpp",
                    "build/repro_x",
                    context_flags=flags,
                )

    def test_divergent_unit_macros_fall_back_to_bare_argv(self) -> None:
        # Units carrying different macros cannot ride one argv; the
        # verified path returns the bare environment instead of an
        # intersection that leaves a value-less option behind (review
        # round 3 F2).

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(
                tmp,
                arguments=("/usr/bin/c++", "-D", "ONE=1", "-Iheaders/fixture", "-c"),
                util_arguments=("/usr/bin/c++", "-D", "TWO=1", "-Iheaders/fixture", "-c"),
            )
            prepared = SimpleNamespace(root=snapshot, sha256="a" * 64)
            from cxx_analyzer.repro import _verified_context_outcome

            outcome = _verified_context_outcome(
                prepared, ("app/main.cpp", "app/util.cpp"), make_settings(), view
            )
            self.assertEqual(outcome, "verified-context-inconsistent")

    def test_c_target_with_standard_falls_back(self) -> None:
        # A -std riding a command that also hosts the C++ driver is only
        # safe when every unit is C++; a C target falls back to the bare
        # environment.

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = root / "snapshot"
            (snapshot / "app").mkdir(parents=True)
            (snapshot / "app" / "legacy.c").write_text(
                "int legacy(void){return 0;}\n", encoding="utf8"
            )
            fingerprint = snapshot_fingerprint(snapshot)
            compdb = [
                {
                    "directory": "app",
                    "arguments": [
                        "/usr/bin/clang",
                        "-std=c99",
                        "-c",
                        "legacy.c",
                    ],
                    "file": "app/legacy.c",
                }
            ]
            manifest = build_manifest(
                repository="Fixtures/AgentRepo",
                revision=fingerprint,
                compdb=compdb,
                generated=[],
                header_roots=[],
                rewrites={},
                created_by="s4b-test",
            )
            pkg = root / "package"
            write_package(
                pkg,
                manifest,
                json.dumps(compdb).encode("utf8"),
                {},
                {},
            )
            artifact = verify_build_artifact(
                pkg, fingerprint, compute_artifact_digest(pkg)
            )
            view = create_analysis_view(snapshot, artifact, ("app/legacy.c",))
            prepared = SimpleNamespace(root=snapshot, sha256="a" * 64)
            from cxx_analyzer.repro import _verified_context_outcome

            outcome = _verified_context_outcome(
                prepared, ("app/legacy.c",), make_settings(), view
            )
            self.assertEqual(outcome, "verified-std-language-mismatch")


class Round4ReviewTests(unittest.TestCase):
    """The verified context gap must surface as an explicit failed result."""

    def test_run_repro_reports_context_gap(self) -> None:
        # Divergent verified units never silently compile under the bare
        # argv: run_repro returns a stage="context" failure carrying the
        # gap diagnostic (PR #347 round 4).
        from cxx_analyzer.deadline import AnalysisDeadline
        from cxx_analyzer.repro import run_repro

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, view = make_view(
                tmp,
                arguments=("/usr/bin/c++", "-D", "ONE=1", "-Iheaders/fixture", "-c"),
                util_arguments=("/usr/bin/c++", "-D", "TWO=1", "-Iheaders/fixture", "-c"),
            )
            (snapshot / "build").mkdir(exist_ok=True)
            prepared = SimpleNamespace(
                root=snapshot,
                build_root=snapshot / "build",
                sha256="a" * 64,
                files=("app/main.cpp", "app/util.cpp"),
            )
            execution = run_repro(
                prepared,
                ["app/main.cpp", "app/util.cpp"],
                "int main(void){return 0;}",
                deadline=AnalysisDeadline(expires_at=time.time() + 30),
                timeout_seconds=5,
                settings=make_settings(),
                verified_view=view,
            )
            self.assertEqual(execution.stage, "context")
            self.assertFalse(execution.ok)
            self.assertIsNone(execution.exit_code)
            self.assertIn(
                "verified-context-inconsistent", execution.diagnostics
            )

    def test_repro_stage_vocabulary_accepts_context(self) -> None:
        from lima.cxx_memory import REPRO_STAGES

        self.assertIn("context", REPRO_STAGES)


if __name__ == "__main__":
    unittest.main()
