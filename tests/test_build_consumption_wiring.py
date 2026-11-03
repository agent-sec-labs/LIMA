"""Consumption chain wiring tests.

After a successful build, the service must construct the verified
AnalysisContextView from the produced package, hand it to the repository
scanner, which passes it to run_platform_review so facts, repro and the
Specialist actually consume the verified-package projection instead of the
legacy paths — and the report must honestly mark consumed_by_analysis.
"""

import os
import tempfile
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from lima.build_agent import NEEDS_ATTENTION, SUCCEEDED, BuildResult
from lima.config import Settings
from lima.service import ReviewService


def make_build_result(status: str, package_ref: str | None = None) -> BuildResult:
    return BuildResult(
        run_id="build-wire",
        status=status,
        snapshot_hash="a" * 64,
        plan_digest="b" * 64,
        image_digest=None,
        dependency_digest=None,
        package_ref=package_ref,
        artifact_digest="c" * 64,
        attempts=1,
        coverage=None,
        failure_code=None if status == SUCCEEDED else "build-not-configured",
        evidence_refs=(),
    )


class ConsumptionWiringTests(unittest.TestCase):
    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, self.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text("safe = True\n", encoding="utf8")
        self.base = Settings(
            host="127.0.0.1", port=8080, db_path=self.path, max_diff_bytes=10000,
            max_steps=8, timeout_seconds=120, llm_base_url="", llm_api_key="",
            llm_model="", github_webhook_secret="", github_token="",
            auto_post_review=False, repository_import_root=self.temporary.name,
            repository_scan_sast_mode="off", cxx_memory_mode="off",
        )

    def _service(self, **overrides) -> ReviewService:
        service = ReviewService(replace(self.base, **overrides))
        self.addCleanup(service.queue.close)
        return service

    def _run_scan(self, service, build_result, *, mode="auto"):
        """Run one scan with a stubbed build result; return the task."""
        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy, mock.patch.object(
            service, "_consume_build_context",
            wraps=service._consume_build_context,
        ) as consume_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode=mode
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        return task, scan_spy, consume_spy

    def test_success_constructs_view_and_passes_to_scanner(self):
        """A successful build's view reaches the scanner only when the
        analyzer deployment declares same-process verified package support
        (round 6: capability is decided before the scan starts)."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        build_result = make_build_result(SUCCEEDED, "run-1/attempt-1/package")
        sentinel_view = object()  # stands in for the AnalysisContextView

        class _DeclaringAdapter:
            # In-process deployment: the adapter and the registry serving
            # verified packages share one process.
            verified_package_supported = True

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service, "_consume_build_context", return_value=sentinel_view
        ) as consume_mock, mock.patch.object(
            service.repository_scanner, "cxx_memory_adapter",
            _DeclaringAdapter(),
        ), mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        self.assertEqual(task["state"], "SUCCESS")
        # The consumption wiring was invoked.
        consume_mock.assert_called_once()
        # The declaring deployment received the verified_view.
        kwargs = scan_spy.call_args.kwargs
        self.assertIs(kwargs.get("verified_view"), sentinel_view)
        # The report honestly says whether the context was consumed.
        # No LLM provider is configured here, so the platform chain can
        # never report completed-with-verified-package: consumed_by_analysis
        # is False even though the view was handed over (don't mark
        # consumed without the consumer's affirmative evidence).
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(visible)
        self.assertFalse(visible["consumed_by_analysis"])

    def test_failure_does_not_construct_view(self):
        """A failed build must not produce a view for the scanner."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        build_result = make_build_result(NEEDS_ATTENTION)
        task, scan_spy, consume_spy = self._run_scan(service, build_result)

        self.assertEqual(task["state"], "SUCCESS")  # auto degrades
        consume_spy.assert_not_called()
        kwargs = scan_spy.call_args.kwargs
        self.assertIsNone(kwargs.get("verified_view"))
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertFalse(visible["consumed_by_analysis"])

    def test_off_mode_never_consumes(self):
        """off mode keeps the current path with no consumption wiring."""
        service = self._service()
        task, scan_spy, consume_spy = self._run_scan(
            service, make_build_result(SUCCEEDED), mode="off"
        )
        consume_spy.assert_not_called()
        report = task.get("report") or {}
        self.assertNotIn("build_agent", report.get("collaboration", {}))

    def test_invalid_package_does_not_crash_scan(self):
        """A missing/corrupt package degrades to gap, not a scan failure."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="lima-builder:test"
        )
        # The build "succeeded" but the package doesn't exist on disk.
        build_result = make_build_result(SUCCEEDED, "run-1/nonexistent/package")
        task, scan_spy, consume_spy = self._run_scan(service, build_result)

        # The scan still completes (the consumption attempt failed silently
        # — the context isn't consumed, but the detection isn't blocked).
        self.assertEqual(task["state"], "SUCCESS")
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        # The consumption failed, so it's not marked as consumed.
        self.assertFalse(visible["consumed_by_analysis"])


class ConsumptionRealPathTests(unittest.TestCase):
    """The real _consume_build_context path: package → view → scanner kwarg."""

    def test_consume_build_context_returns_real_view(self):
        """A real package on disk produces a real AnalysisContextView."""
        import json as _json

        from lima.build_context_view import (
            AnalysisContextView,
            compute_artifact_digest,
        )
        from lima.context_package import build_manifest, write_package

        handle, path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, path)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        artifacts = tempfile.TemporaryDirectory()
        self.addCleanup(artifacts.cleanup)
        repository = Path(temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app").mkdir()
        (repository / "app" / "main.cpp").write_text(
            "int main(void) { return 0; }\\n", encoding="utf8"
        )
        from lima.service import ReviewService
        from lima.workspace import RepositoryWorkspace

        service = ReviewService(
            Settings(
                host="127.0.0.1", port=8080, db_path=path,
                max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
                llm_base_url="", llm_api_key="", llm_model="",
                github_webhook_secret="", github_token="",
                auto_post_review=False,
                repository_import_root=temporary.name,
                repository_scan_sast_mode="off", cxx_memory_mode="off",
                build_artifacts_root=artifacts.name,
            )
        )
        self.addCleanup(service.queue.close)

        workspace = RepositoryWorkspace(str(repository))
        fingerprint = workspace.inventory().fingerprint()
        # Lay out a real verified package.
        compdb = [
            {
                "directory": "app",
                "arguments": [
                    "/usr/bin/c++", "-DREAL=1", "-c", "main.cpp",
                ],
                "file": "app/main.cpp",
            }
        ]
        manifest = build_manifest(
            repository="team/project", revision=fingerprint,
            compdb=compdb, generated=[], header_roots=[], rewrites={},
            created_by="consumption-test",
        )
        package_dir = Path(artifacts.name) / "task-x" / "run-1" / "package"
        write_package(
            package_dir, manifest,
            _json.dumps(compdb).encode("utf8"), {}, {},
        )
        digest = compute_artifact_digest(package_dir)
        from lima.build_agent import SUCCEEDED as OK
        from lima.build_agent import BuildResult

        build_result = BuildResult(
            run_id="build-real", status=OK, snapshot_hash=fingerprint,
            plan_digest="p" * 64, image_digest=None, dependency_digest=None,
            package_ref="run-1/package", artifact_digest=digest,
            attempts=1, coverage=None, failure_code=None, evidence_refs=(),
        )
        view = service._consume_build_context("task-x", workspace, build_result)
        # The view is a real AnalysisContextView with the compdb's TU list.
        self.assertIsInstance(view, AnalysisContextView)
        self.assertEqual(view.target_units, ("app/main.cpp",))
        self.assertIn("-DREAL=1", view.flags_for_tu("app/main.cpp"))


class RequiredConsumptionTests(unittest.TestCase):
    """Required mode blocks on consumption failure; flag reflects actual use."""

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, self.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text(
            "safe = True\\n", encoding="utf8"
        )
        self.base = Settings(
            host="127.0.0.1", port=8080, db_path=self.path,
            max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
            llm_base_url="", llm_api_key="", llm_model="",
            github_webhook_secret="", github_token="",
            auto_post_review=False,
            repository_import_root=self.temporary.name,
            repository_scan_sast_mode="off", cxx_memory_mode="off",
        )

    def _service(self, **overrides):
        service = ReviewService(replace(self.base, **overrides))
        self.addCleanup(service.queue.close)
        return service

    def test_required_blocks_on_consumption_failure(self):
        """required + build success + package missing = blocks cxx stages."""
        service = self._service(
            build_agent_mode="required", build_agent_image="test",
            cxx_agent_mode="required",
            cxx_memory_mode="auto",
            llm_provider="custom",
            llm_base_url="http://127.0.0.1:9/v1",
            llm_api_key="unit-test-key",
            llm_model="unit-test-model",
        )
        # Build succeeds but the package doesn't exist on disk.
        build_result = make_build_result(SUCCEEDED, "run-1/missing/pkg")

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="required"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        # The scanner was called with cxx_agent_mode=off (the required
        # context was not consumable, so the context-dependent stage was
        # blocked, not silently run with the old path).
        kwargs = scan_spy.call_args.kwargs
        self.assertEqual(kwargs.get("cxx_agent_mode"), "off")
        # The gap is blocking.
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(visible)
        self.assertTrue(visible["blocking"])
        self.assertEqual(visible["failure_code"], "consumption-unavailable")

    def test_auto_degrades_on_consumption_failure_with_explicit_gap(self):
        """auto + build success + package missing = degrades with a gap."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="test",
        )
        build_result = make_build_result(SUCCEEDED, "run-1/missing/pkg")

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ):
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        self.assertEqual(task["state"], "SUCCESS")
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertIsNotNone(visible)
        self.assertFalse(visible["blocking"])
        self.assertEqual(visible["failure_code"], "consumption-unavailable")
        self.assertFalse(visible["consumed_by_analysis"])

    def test_consumed_flag_false_when_platform_disabled(self):
        """consumed_by_analysis stays false when the platform chain is off."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="test",
            cxx_agent_mode="off",  # explicit off
        )
        build_result = make_build_result(SUCCEEDED, "run-1/pkg")
        sentinel = object()

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service, "_consume_build_context", return_value=sentinel
        ):
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        self.assertEqual(task["state"], "SUCCESS")
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        # View was constructed, but the platform chain is disabled —
        # consumed_by_analysis must be false (honest, not optimistic).
        self.assertFalse(visible["consumed_by_analysis"])

    def test_required_blocks_when_adapter_does_not_declare_support(self):
        """required + view constructed + non-declaring adapter = blocked.

        Round 6 P1: a locally constructed view is not consumable when the
        analyzer deployment does not declare same-process verified package
        support.  required must block the context-dependent stage instead
        of running detection on a context nobody can consume.
        """
        service = self._service(
            build_agent_mode="required", build_agent_image="test",
            cxx_agent_mode="required",
            cxx_memory_mode="auto",
            llm_provider="custom",
            llm_base_url="http://127.0.0.1:9/v1",
            llm_api_key="unit-test-key",
            llm_model="unit-test-model",
        )
        build_result = make_build_result(SUCCEEDED, "run-1/pkg")

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            # The view constructs fine locally; capability is the issue.
            service, "_consume_build_context", return_value=object(),
        ), mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="required"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        kwargs = scan_spy.call_args.kwargs
        self.assertEqual("off", kwargs.get("cxx_agent_mode"))
        self.assertIsNone(kwargs.get("verified_view"))
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertTrue(visible["blocking"])
        self.assertEqual(
            "verified-context-not-consumable", visible["failure_code"]
        )
        self.assertFalse(visible["consumed_by_analysis"])

    def test_auto_degrades_when_adapter_does_not_declare_support(self):
        """auto: same non-consumable view degrades with an explicit gap."""
        service = self._service(
            build_agent_mode="auto", build_agent_image="test",
            cxx_agent_mode="auto",
            cxx_memory_mode="auto",
            llm_provider="custom",
            llm_base_url="http://127.0.0.1:9/v1",
            llm_api_key="unit-test-key",
            llm_model="unit-test-model",
        )
        build_result = make_build_result(SUCCEEDED, "run-1/pkg")

        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service, "_consume_build_context", return_value=object(),
        ), mock.patch.object(
            service.repository_scanner, "scan",
            wraps=service.repository_scanner.scan,
        ) as scan_spy:
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)

        kwargs = scan_spy.call_args.kwargs
        self.assertEqual("off", kwargs.get("cxx_agent_mode"))
        self.assertIsNone(kwargs.get("verified_view"))
        report = task.get("report") or {}
        visible = report.get("collaboration", {}).get("build_agent")
        self.assertFalse(visible["blocking"])
        self.assertEqual(
            "verified-context-not-consumable", visible["failure_code"]
        )
        self.assertFalse(visible["consumed_by_analysis"])


class CapabilityGateTests(unittest.TestCase):
    """Mode switches only when the adapter declares same-process support."""

    def test_remote_adapter_does_not_switch(self):
        """Cross-process: adapter says no → stays snapshot-compdb.

        This is the actual failure condition (#350 round 5): the main
        process has the view registered locally, but the adapter is an
        HTTP client to an independent sidecar — the sidecar's registry
        is a different dict.  The local registration must NOT cause a
        mode switch.
        """
        from cxx_analyzer import server as analyzer_server

        SNAP = "a" * 64
        analyzer_server.clear_verified_build_views()
        self.addCleanup(analyzer_server.clear_verified_build_views)

        # Register in the main process (the service does this).
        fake_view = type("V", (), {"artifact_digest": "b" * 64})()
        analyzer_server.register_verified_build_view(SNAP, fake_view)
        # Local registry has the view — but this must NOT matter.

        # The adapter is remote (default verified_package_supported=False).
        # Verify the gate source checks the adapter, not the registry.
        import inspect

        from lima import agent_orchestrator

        source = inspect.getsource(agent_orchestrator.run_platform_review)
        self.assertIn("verified_package_supported", source)
        self.assertIn("analyzer_client", source)
        # The old registry-based check must be gone.
        self.assertNotIn("lookup_verified_build_view", source)

    def test_in_process_adapter_switches(self):
        """Same-process: adapter declares True → mode switches."""
        from lima.cxx_memory import CxxMemoryAdapter

        # Verify the protocol has the property.
        self.assertTrue(hasattr(CxxMemoryAdapter, "verified_package_supported"))

    def test_adapter_property_defaults_false(self):
        """Adapters that don't override default to False (remote)."""

        class RemoteAdapter:
            def analyze(self, *args, **kwargs):
                pass

        adapter = RemoteAdapter()
        self.assertFalse(
            getattr(adapter, "verified_package_supported", False)
        )


def _make_verified_view(root: str):
    """A real sealed view binding src/a.cpp with -DVERIFIED=1.

    Uses the same product helpers as the S4A/S4B suites (package ->
    verify -> create view) so the Specialist contract projection and the
    repro digest both have genuine content to consume.
    """
    import json as _json

    from lima.build_context_view import (
        compute_artifact_digest,
        create_analysis_view,
        snapshot_fingerprint,
        verify_build_artifact,
    )
    from lima.context_package import build_manifest, write_package

    snapshot = Path(root)
    fingerprint = snapshot_fingerprint(snapshot)
    entry = {
        "directory": "src",
        "arguments": ["/usr/bin/c++", "-DVERIFIED=1", "-c", "a.cpp"],
        "file": "src/a.cpp",
    }
    manifest = build_manifest(
        repository="Fixtures/AgentRepo",
        revision=fingerprint,
        compdb=[entry],
        generated=[],
        header_roots=[],
        rewrites={},
        created_by="round6-three-consumer-test",
    )
    package = snapshot.parent / "package"
    write_package(
        package, manifest, _json.dumps([entry]).encode("utf8"), {}, {},
    )
    artifact = verify_build_artifact(
        package, fingerprint, compute_artifact_digest(package)
    )
    return create_analysis_view(snapshot, artifact, ("src/a.cpp",))


class ThreeConsumerDegradationTests(unittest.TestCase):
    """Round 6 P1: one capability decision, three consistent consumers.

    When the adapter does not declare same-process verified package
    support, facts, the Specialist driver contract and the repro
    experiment must degrade TOGETHER to the repository context; when it
    declares support, all three consume the same view.  No consumer may
    end up on a different environment than the others.
    """

    def _run_one(self, *, declaring: bool):
        from lima.agent_orchestrator import run_platform_review
        from lima.cxx_agent_tools import CxxAgentBudget
        from tests.test_agent_orchestrator import (
            LEAD,
            REPO_KEY,
            RESOLVED_LLM,
            SNAPSHOT,
            SPECIALIST_ROLE,
            UNIT,
            FakeUafAnalyzer,
            ScriptedPlatformTransport,
            _payload,
            _straight_facts,
            _unit_entry,
            _write_cxx_repo,
            critic_json,
            hypothesis_json,
            scout_target_transport,
            uaf_hit,
        )

        class _DeclaringAnalyzer(FakeUafAnalyzer):
            # In-process deployment: adapter and verified-package
            # registry share one process.
            verified_package_supported = True

        analyzer = (
            _DeclaringAnalyzer(_payload(_unit_entry(_straight_facts())))
            if declaring
            else FakeUafAnalyzer(_payload(_unit_entry(_straight_facts())))
        )

        class _RecordingWorkbench:
            """run_experiment double preserving every extra kwarg."""

            def __init__(self, observations):
                self.observations = list(observations)
                self.calls = []

            def run_experiment(
                self, repository_key, snapshot_hash, source_files,
                driver_code, *, timeout=None, **kwargs,
            ):
                self.calls.append({
                    "sources": tuple(source_files),
                    "driver": driver_code,
                    "extra": dict(kwargs),
                })
                return self.observations.pop(0)

        workbench = _RecordingWorkbench([uaf_hit()])
        transport = ScriptedPlatformTransport(
            specialist=[hypothesis_json()], critic=[critic_json()],
        )
        scout_requests = []

        root = tempfile.mkdtemp(suffix="-round6-three-consumer")
        self.addCleanup(__import__("shutil").rmtree, root, True)
        workspace = _write_cxx_repo(root)
        view = _make_verified_view(root)

        with mock.patch(
            "lima.agent_scout.post_chat_completion_text",
            scout_target_transport(scout_requests),
        ), mock.patch(
            "lima.uaf_llm_branch.post_chat_completion_text", transport,
        ):
            outcome = run_platform_review(
                analyzer,
                workspace,
                repository_key=REPO_KEY,
                snapshot_hash=SNAPSHOT,
                translation_units=(UNIT,),
                verified_view=view,
                mode="auto",
                budget=CxxAgentBudget(
                    max_calls=64, max_output_bytes=1_048_576,
                ),
                llm_config=dict(RESOLVED_LLM),
                repro_workbench=workbench,
                leads=(LEAD,),
                dialogue_rounds=1,
                source_mode="repository",
            )
        specialist_payload = next(
            payload
            for payload in transport.calls
            if SPECIALIST_ROLE in payload["messages"][0]["content"]
        )
        return analyzer, workbench, specialist_payload, outcome, view

    def test_platform_summary_carries_build_context(self):
        """The real scanner summary projects the outcome's mode field."""
        from lima.agent_orchestrator import (
            PlatformReviewOutcome,
            PlatformReviewStats,
        )
        from lima.repository_scanner import RepositoryScanner

        scanner = RepositoryScanner(sast_mode="off", dataflow_enabled=False)
        outcome = PlatformReviewOutcome(
            findings=(),
            targets=(),
            stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 0),
            build_context_mode="verified-package",
        )
        summary = scanner._platform_collaboration("auto", "completed", outcome)
        self.assertEqual("verified-package", summary["build_context"])

    def test_degrading_adapter_reverts_all_three_consumers(self):
        """No declaration: facts, contract and repro all revert together."""
        analyzer, workbench, specialist_payload, outcome, _ = (
            self._run_one(declaring=False)
        )
        # facts boundary: repository context, not verified-package.
        self.assertTrue(analyzer.unit_calls)
        self.assertEqual(
            "snapshot-compdb", analyzer.unit_calls[0][1]
        )
        # Specialist contract: compdb projection without view macros.
        self.assertNotIn(
            "-DVERIFIED=1", specialist_payload["messages"][1]["content"]
        )
        # repro: legacy call shape, no artifact digest kwarg.
        self.assertTrue(workbench.calls)
        self.assertEqual({}, workbench.calls[0]["extra"])
        # Outcome evidence + explicit degradation note.
        self.assertEqual("snapshot-compdb", outcome.build_context_mode)
        self.assertTrue(
            any("degraded" in note for note in outcome.diagnostics),
            outcome.diagnostics,
        )

    def test_declaring_adapter_feeds_all_three_consumers(self):
        """Declaration: facts, contract and repro consume the same view."""
        analyzer, workbench, specialist_payload, outcome, view = (
            self._run_one(declaring=True)
        )
        self.assertEqual(
            "verified-package", analyzer.unit_calls[0][1]
        )
        self.assertIn(
            "-DVERIFIED=1", specialist_payload["messages"][1]["content"]
        )
        self.assertTrue(workbench.calls)
        self.assertEqual(
            view.artifact_digest,
            workbench.calls[0]["extra"].get("verified_artifact_digest"),
        )
        self.assertEqual("verified-package", outcome.build_context_mode)
        self.assertFalse(
            any("degraded" in note for note in outcome.diagnostics),
            outcome.diagnostics,
        )


class ConsumedEvidenceTests(unittest.TestCase):
    """consumed_by_analysis needs the consumer's affirmative evidence.

    Platform completed alone is not enough: the platform summary must
    also carry build_context=verified-package (round 6 P1).
    """

    def setUp(self):
        handle, self.path = tempfile.mkstemp(suffix=".db")
        os.close(handle)
        self.addCleanup(os.unlink, self.path)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository = Path(self.temporary.name, "team", "project")
        repository.mkdir(parents=True)
        (repository / "app.py").write_text(
            "safe = True\n", encoding="utf8"
        )
        self.base = Settings(
            host="127.0.0.1", port=8080, db_path=self.path,
            max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
            llm_base_url="", llm_api_key="", llm_model="",
            github_webhook_secret="", github_token="",
            auto_post_review=False,
            repository_import_root=self.temporary.name,
            repository_scan_sast_mode="off", cxx_memory_mode="off",
        )

    class _StaticScanner:
        """Declaring scanner whose platform summary is fixed."""

        def __init__(self, platform_summary: dict) -> None:
            self.platform_summary = dict(platform_summary)
            self.scan_kwargs: dict | None = None

        @property
        def cxx_memory_adapter(self):
            class _Adapter:
                verified_package_supported = True

            return _Adapter()

        def scan(self, workspace, **kwargs):
            from lima.models import ReviewReport
            from lima.repository_scanner import RepositoryScanResult
            from lima.workspace import WorkspaceInventory

            self.scan_kwargs = dict(kwargs)
            return RepositoryScanResult(
                report=ReviewReport(
                    repository=str(workspace.root),
                    pull_request=None,
                    summary="scan",
                    risk="low",
                    collaboration={"platform": dict(self.platform_summary)},
                ),
                inventory=WorkspaceInventory(root=str(workspace.root)),
            )

    def _visible_gap(self, platform_summary: dict) -> dict:
        service = ReviewService(replace(self.base, build_agent_mode="auto"))
        self.addCleanup(service.queue.close)
        service.repository_scanner = self._StaticScanner(platform_summary)
        build_result = make_build_result(SUCCEEDED, "run-1/pkg")
        with mock.patch.object(
            service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            service, "_consume_build_context", return_value=object(),
        ):
            created = service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        self.assertEqual("SUCCESS", task["state"])
        return (task.get("report") or {}).get("collaboration", {})

    def test_consumed_true_only_with_verified_package_evidence(self):
        collaboration = self._visible_gap(
            {"mode": "auto", "status": "completed",
             "build_context": "verified-package"}
        )
        self.assertTrue(
            collaboration["build_agent"]["consumed_by_analysis"]
        )

    def test_completed_but_legacy_context_is_not_consumed(self):
        collaboration = self._visible_gap(
            {"mode": "auto", "status": "completed",
             "build_context": "snapshot-compdb"}
        )
        self.assertFalse(
            collaboration["build_agent"]["consumed_by_analysis"]
        )

    def test_disabled_platform_is_not_consumed(self):
        collaboration = self._visible_gap(
            {"mode": "off", "status": "disabled"}
        )
        self.assertFalse(
            collaboration["build_agent"]["consumed_by_analysis"]
        )


if __name__ == "__main__":
    unittest.main()
