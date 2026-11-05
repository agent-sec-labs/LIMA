"""lima-side wiring for cross-process verified-view registration (#351 B).

The sidecar endpoint landed in PR #352 (part A).  This file pins the
lima half: the analyzer client's register/confirm/unregister verbs, the
service's delivery gate (an ack -- not a local construction -- is the
capability evidence), the task-end cleanup, the scanner's explicit
verified-package hand-off, and a real subprocess sidecar proving facts
AND repro consume the wire-registered view cross-process.
"""

import json
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from dataclasses import replace
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from lima.config import Settings
from lima.cxx_memory import CxxMemoryAnalyzerClient
from lima.service import ReviewService
from tests.test_verified_view_registry_wire import (
    build_repository_and_view,
    envelope_from_view,
    make_settings,
)


def _free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


class _SidecarThread:
    """The real analyzer request handler on a loopback thread."""

    def __init__(self):
        from cxx_analyzer.server import AnalyzerRequestHandler

        class Configured(AnalyzerRequestHandler):
            analyzer_settings = make_settings()

        self.server = ThreadingHTTPServer(
            ("127.0.0.1", 0), Configured
        )
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True
        )

    def __enter__(self):
        from cxx_analyzer import server as analyzer_server

        analyzer_server.clear_verified_build_views()
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        from cxx_analyzer import server as analyzer_server

        analyzer_server.clear_verified_build_views()


def _client(port: int) -> CxxMemoryAnalyzerClient:
    return CxxMemoryAnalyzerClient(
        f"http://127.0.0.1:{port}", 30, 4 * 1024 * 1024
    )


class ClientRegistrationTests(unittest.TestCase):
    """The client verbs against the real handler (in-process thread)."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        repository, view, snapshot_hash, digest = (
            build_repository_and_view(Path(self.temporary.name))
        )
        self.view = view
        self.snapshot_hash = snapshot_hash
        self.digest = digest

    def test_register_confirm_unregister_roundtrip(self):
        with _SidecarThread() as sidecar:
            client = _client(sidecar.port)
            self.assertFalse(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )
            self.assertTrue(
                client.register_verified_view(self.snapshot_hash, self.view)
            )
            self.assertTrue(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )
            self.assertTrue(
                client.unregister_verified_view(
                    self.snapshot_hash, self.digest
                )
            )
            self.assertFalse(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )

    def test_semantic_refusal_returns_false(self):
        # The same sealed package re-labeled onto another snapshot: the
        # sidecar's revision binding refuses it, and the client reports
        # the refusal as False rather than raising.
        with _SidecarThread() as sidecar:
            client = _client(sidecar.port)
            self.assertFalse(
                client.register_verified_view("1" * 64, self.view)
            )
            self.assertFalse(
                client.confirmed_verified_view("1" * 64, self.digest)
            )

    def test_envelope_is_the_slim_wire_shape(self):
        from lima.cxx_memory import verified_view_envelope

        envelope = verified_view_envelope(self.snapshot_hash, self.view)
        self.assertEqual(
            {
                "schema_version", "snapshot_sha256", "artifact_digest",
                "target_units", "members",
            },
            set(envelope),
        )
        # The envelope the sidecar accepts and the one this builder
        # produces are interchangeable (PR #352's slim shape).
        self.assertEqual(
            envelope,
            envelope_from_view(self.view, self.snapshot_hash),
        )


class ServiceDeliveryTests(unittest.TestCase):
    """The service capability gate is the delivery ack (#351 B)."""

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

    def _run(self, service, mode):
        from lima.build_agent import SUCCEEDED
        from tests.test_build_consumption_wiring import make_build_result

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
                "team/project", build_agent_mode=mode
            )
            task = {}
            for _ in range(300):
                task = service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        return task, scan_spy

    def test_http_delivery_passes_view_and_cleans_up(self):
        service = ReviewService(
            replace(self.base, build_agent_mode="auto")
        )
        self.addCleanup(service.queue.close)
        deliveries: list[tuple[str, object]] = []
        cleanups: list[tuple[str, str]] = []

        class _HttpAdapter:
            def register_verified_view(self, snapshot, view):
                deliveries.append((snapshot, view))
                return True

            def unregister_verified_view(self, snapshot, digest):
                cleanups.append((snapshot, digest))
                return True

        service.repository_scanner.cxx_memory_adapter = _HttpAdapter()
        task, scan_spy = self._run(service, "auto")
        self.assertEqual("SUCCESS", task["state"])
        self.assertEqual(1, len(deliveries))
        self.assertEqual("a" * 64, deliveries[0][0])
        kwargs = scan_spy.call_args.kwargs
        self.assertIsNotNone(kwargs.get("verified_view"))
        # Task-end cleanup ran with the build's identity pair.
        self.assertEqual([("a" * 64, "c" * 64)], cleanups)
        visible = (
            (task.get("report") or {}).get("collaboration", {})
        ).get("build_agent")
        self.assertIsNotNone(visible)
        self.assertNotEqual(
            "verified-context-not-consumable", visible["failure_code"]
        )

    def test_http_delivery_failure_blocks_required(self):
        service = ReviewService(
            replace(
                self.base, build_agent_mode="required",
                cxx_agent_mode="required", cxx_memory_mode="auto",
                llm_provider="custom",
                llm_base_url="http://127.0.0.1:9/v1",
                llm_api_key="unit-test-key", llm_model="unit-test-model",
            )
        )
        self.addCleanup(service.queue.close)

        class _RefusingAdapter:
            def register_verified_view(self, snapshot, view):
                return False

        service.repository_scanner.cxx_memory_adapter = _RefusingAdapter()
        task, scan_spy = self._run(service, "required")
        kwargs = scan_spy.call_args.kwargs
        self.assertEqual("off", kwargs.get("cxx_agent_mode"))
        self.assertIsNone(kwargs.get("verified_view"))
        visible = (
            (task.get("report") or {}).get("collaboration", {})
        ).get("build_agent")
        self.assertTrue(visible["blocking"])
        self.assertEqual(
            "verified-context-not-consumable", visible["failure_code"]
        )
        self.assertFalse(visible["consumed_by_analysis"])

    def test_http_delivery_transport_error_degrades_auto(self):
        service = ReviewService(
            replace(self.base, build_agent_mode="auto")
        )
        self.addCleanup(service.queue.close)

        class _BrokenAdapter:
            def register_verified_view(self, snapshot, view):
                raise OSError("sidecar gone")

        service.repository_scanner.cxx_memory_adapter = _BrokenAdapter()
        task, scan_spy = self._run(service, "auto")
        kwargs = scan_spy.call_args.kwargs
        self.assertIsNone(kwargs.get("verified_view"))
        visible = (
            (task.get("report") or {}).get("collaboration", {})
        ).get("build_agent")
        self.assertFalse(visible["blocking"])
        self.assertEqual(
            "verified-context-not-consumable", visible["failure_code"]
        )


class ScannerExplicitModeTests(unittest.TestCase):
    """The platform branch hands the orchestrator the delivered mode."""

    def test_view_present_requests_verified_package(self):
        import lima.repository_scanner as scanner_module
        from tests.test_agent_orchestrator import FakeUafAnalyzer

        captured: dict[str, object] = {}

        def _capture(adapter, workspace, **kwargs):
            captured.update(kwargs)
            from lima.agent_orchestrator import (
                PlatformReviewOutcome,
                PlatformReviewStats,
            )

            return PlatformReviewOutcome(
                findings=(),
                targets=(),
                stats=PlatformReviewStats(0, 0, 0, 0, 0, 0, 0),
            )

        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary, "team", "project", "src")
            repository.mkdir(parents=True)
            (repository / "a.cpp").write_text(
                "int leak(void) { return 0; }\n", encoding="utf8"
            )
            from lima.workspace import RepositoryWorkspace

            workspace = RepositoryWorkspace(
                Path(temporary, "team", "project")
            )
            scanner = scanner_module.RepositoryScanner(
                sast_mode="off",
                dataflow_enabled=False,
                cxx_memory_adapter=FakeUafAnalyzer(),
                cxx_agent_mode="auto",
                cxx_uaf_llm_factory=lambda: {
                    "provider": "custom", "model": "fake",
                },
            )
            sentinel = object()
            with mock.patch.object(
                scanner_module, "run_platform_review", _capture
            ):
                scanner.scan(
                    workspace,
                    repository_key="team/project",
                    verified_view=sentinel,
                )
            self.assertEqual("verified-package", captured["build_context_mode"])
            self.assertIs(sentinel, captured["verified_view"])

            captured.clear()
            with mock.patch.object(
                scanner_module, "run_platform_review", _capture
            ):
                scanner.scan(
                    workspace,
                    repository_key="team/project",
                    verified_view=None,
                )
            self.assertEqual(
                "snapshot-compdb", captured["build_context_mode"]
            )


class SubprocessCrossProcessTests(unittest.TestCase):
    """The real client against a real sidecar process (#351 B).

    The failure condition the whole chain exists for: this process owns
    the sealed view, the sidecar owns its own registry.  facts AND repro
    must consume the wire-registered view across the process boundary.
    """

    def setUp(self):
        from cxx_analyzer import server as analyzer_server

        analyzer_server.clear_verified_build_views()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.import_root = root / "imports"
        self.work_root = root / "work"
        self.work_root.mkdir()
        repository, view, snapshot_hash, digest = (
            build_repository_and_view(root / "imports")
        )
        self.repository = repository
        self.view = view
        self.snapshot_hash = snapshot_hash
        self.digest = digest
        self.port = _free_port()
        environment = dict(os.environ)
        environment.update({
            "LIMA_CXX_PORT": str(self.port),
            "LIMA_CXX_HOST": "127.0.0.1",
            "LIMA_CXX_IMPORT_ROOT": str(self.import_root),
            "LIMA_CXX_WORK_ROOT": str(self.work_root),
        })
        self.process = subprocess.Popen(  # noqa: S603 - fixed interpreter, repo module
            [sys.executable, "-m", "cxx_analyzer.server"],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self._stop_sidecar)
        self._wait_healthy()
        self.client = _client(self.port)

    def _stop_sidecar(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=10)

    def _wait_healthy(self, timeout: float = 30.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(  # noqa: S310 - loopback, fixed port
                    f"http://127.0.0.1:{self.port}/health", timeout=2
                ) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        self.fail("sidecar did not become healthy in time")

    def _raw(self, method: str, path: str, body: dict | None = None):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_client_register_serves_facts_and_repro_cross_process(self):
        import uuid as _uuid

        self.assertFalse(
            self.client.confirmed_verified_view(
                self.snapshot_hash, self.digest
            )
        )
        # Before registration a verified-package facts request reports
        # the explicit gap and repro refuses with invalid_request.
        status, payload = self._raw(
            "POST",
            "/v1/uaf-facts",
            {
                "schema_version": 1,
                "request_id": str(_uuid.uuid4()),
                "repository_key": "team/project",
                "snapshot_sha256": self.snapshot_hash,
                "translation_units": ["src/a.cpp"],
                "build_context": {"mode": "verified-package"},
            },
        )
        gaps = payload["translation_units"][0]["coverage"]["semantic_gaps"]
        self.assertIn("verified-view-not-registered", gaps)
        repro_body = {
            "schema_version": 1,
            "request_id": str(_uuid.uuid4()),
            "repository_key": "team/project",
            "snapshot_sha256": self.snapshot_hash,
            "source_files": ["src/a.cpp"],
            "driver_code": "int main() { return 0; }\n",
            "verified_artifact_digest": self.digest,
        }
        status, payload = self._raw("POST", "/v1/repro", repro_body)
        self.assertEqual(400, status)
        self.assertEqual("invalid_request", payload["error"])

        # The real client registers the sealed view cross-process.
        self.assertTrue(
            self.client.register_verified_view(
                self.snapshot_hash, self.view
            )
        )
        self.assertTrue(
            self.client.confirmed_verified_view(
                self.snapshot_hash, self.digest
            )
        )

        # facts: the wire-registered view resolves verified-package
        # inside the independent process.
        status, payload = self._raw(
            "POST",
            "/v1/uaf-facts",
            {
                "schema_version": 1,
                "request_id": str(_uuid.uuid4()),
                "repository_key": "team/project",
                "snapshot_sha256": self.snapshot_hash,
                "translation_units": ["src/a.cpp"],
                "build_context": {
                    "mode": "verified-package",
                    "artifact_digest": self.digest,
                },
            },
        )
        self.assertEqual(200, status)
        unit = payload["translation_units"][0]
        self.assertEqual(
            "verified-package", unit["build_context"]["source_kind"]
        )
        self.assertNotIn(
            "verified-view-not-registered",
            unit["coverage"]["semantic_gaps"],
        )

        # repro: the digest slot now HITS (the request proceeds past the
        # registry lookup; on hosts without the sandbox that surfaces as
        # an explicit experiment failure, never invalid_request again).
        repro_body["request_id"] = str(_uuid.uuid4())
        status, payload = self._raw("POST", "/v1/repro", repro_body)
        self.assertEqual(200, status)
        self.assertIn("stage", payload)

        # Task-end cleanup: the client unregister empties the registry.
        self.assertTrue(
            self.client.unregister_verified_view(
                self.snapshot_hash, self.digest
            )
        )
        self.assertFalse(
            self.client.confirmed_verified_view(
                self.snapshot_hash, self.digest
            )
        )
        repro_body["request_id"] = str(_uuid.uuid4())
        status, payload = self._raw("POST", "/v1/repro", repro_body)
        self.assertEqual(400, status)
        self.assertEqual("invalid_request", payload["error"])


if __name__ == "__main__":
    unittest.main()
