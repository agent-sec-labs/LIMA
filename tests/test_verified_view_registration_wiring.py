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
            task.setdefault("task_id", created["task_id"])
        return task, scan_spy

    def test_http_delivery_passes_view_and_cleans_up(self):
        service = ReviewService(
            replace(self.base, build_agent_mode="auto")
        )
        self.addCleanup(service.queue.close)
        deliveries: list[tuple[str, object, object]] = []
        cleanups: list[tuple[str, str, object]] = []

        class _HttpAdapter:
            def register_verified_view(
                self, snapshot, view, *, holder=None
            ):
                deliveries.append((snapshot, view, holder))
                return True

            def unregister_verified_view(
                self, snapshot, digest, *, holder=None
            ):
                cleanups.append((snapshot, digest, holder))
                return True

        service.repository_scanner.cxx_memory_adapter = _HttpAdapter()
        task, scan_spy = self._run(service, "auto")
        self.assertEqual("SUCCESS", task["state"])
        self.assertEqual(1, len(deliveries))
        self.assertEqual("a" * 64, deliveries[0][0])
        kwargs = scan_spy.call_args.kwargs
        self.assertIsNotNone(kwargs.get("verified_view"))
        # Task-end cleanup released THIS task's hold: identity pair plus
        # the holder token (#354 round 2).
        task_id = task["task_id"]
        self.assertEqual(task_id, deliveries[0][2])
        self.assertEqual(1, len(cleanups))
        self.assertEqual(("a" * 64, "c" * 64, task_id), cleanups[0])
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
            def register_verified_view(self, snapshot, view, *, holder=None):
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
            def register_verified_view(self, snapshot, view, *, holder=None):
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
            with urllib.request.urlopen(  # noqa: S310 - loopback, fixed port
                request, timeout=120
            ) as response:
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


class FactsDigestBindingTests(unittest.TestCase):
    """Round-1 P1: a verified-package facts request is bound to THIS
    task's delivered artifact, not the snapshot's mutable default slot.

    The reviewer's repro: two legal builds of the SAME snapshot, both
    registered, and a digest-less facts request silently served the
    sibling's context.  The real client now pins the digest.
    """

    def test_sibling_builds_of_one_snapshot_stay_disambiguated(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            # Same variant (same snapshot), different compdb macros:
            # two sealed artifacts of ONE snapshot identity.
            repository_a, view_a, snapshot_hash, digest_a = (
                build_repository_and_view(root / "case-a")
            )
            repository_b, view_b, snapshot_hash_b, digest_b = (
                build_repository_and_view(root / "case-b", macro="2")
            )
            self.assertEqual(snapshot_hash, snapshot_hash_b)
            self.assertNotEqual(digest_a, digest_b)
            self.assertNotEqual(view_a.context_hash, view_b.context_hash)

            with _SidecarThread() as sidecar:
                client = _client(sidecar.port)
                self.assertTrue(
                    client.register_verified_view(snapshot_hash, view_a)
                )
                self.assertTrue(
                    client.register_verified_view(snapshot_hash, view_b)
                )
                with mock.patch.object(
                    __import__(
                        "cxx_analyzer.server", fromlist=["server"]
                    ),
                    "IMPORT_ROOT",
                    root / "case-a",
                ), mock.patch.object(
                    __import__("cxx_analyzer.server", fromlist=["server"]),
                    "WORK_ROOT",
                    Path(temporary) / "work-a",
                ):
                    (Path(temporary) / "work-a").mkdir(exist_ok=True)

                    def _tu_context_hash(artifact_digest=None):
                        response = client.analyze_uaf_facts(
                            "team/project", snapshot_hash, ("src/a.cpp",),
                            "verified-package",
                            **(
                                {} if artifact_digest is None
                                else {"artifact_digest": artifact_digest}
                            ),
                        )
                        return response.translation_units[0]["build_context"][
                            "context_hash"
                        ]

                    # The reviewer's repro, inverted: the digest-bound
                    # requests are pinned to their own package's TU
                    # context, the digest-less default serves whatever
                    # registered last (the sibling's build).
                    hash_a = _tu_context_hash(digest_a)
                    hash_b = _tu_context_hash(digest_b)
                    hash_default = _tu_context_hash()
                    self.assertNotEqual(hash_a, hash_b)
                    self.assertEqual(hash_b, hash_default)
                    self.assertEqual(hash_a, _tu_context_hash(digest_a))

    def test_client_rejects_malformed_digest_binding(self):
        with tempfile.TemporaryDirectory() as temporary:
            _repository, view, _snapshot, _digest = (
                build_repository_and_view(Path(temporary))
            )
            with _SidecarThread() as sidecar:
                client = _client(sidecar.port)
                from lima.cxx_memory import CxxAnalyzerProtocolError

                with self.assertRaises(CxxAnalyzerProtocolError):
                    client.analyze_uaf_facts(
                        "team/project", "a" * 64, ("src/a.cpp",),
                        "verified-package", artifact_digest="z" * 64,
                    )
                with self.assertRaises(CxxAnalyzerProtocolError):
                    # The digest binding is only valid in verified-package
                    # mode.
                    client.analyze_uaf_facts(
                        "team/project", "a" * 64, ("src/a.cpp",),
                        "snapshot-compdb", artifact_digest="b" * 64,
                    )


class HolderLifecycleTests(unittest.TestCase):
    """Round-1 P1: cleanup releases this task's hold, not the shared
    registration; release also covers scan exceptions and cancellation."""

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
        from lima.build_agent import SUCCEEDED
        from lima.service import (
            _VERIFIED_VIEW_HOLDERS,
            _VERIFIED_VIEW_HOLDERS_LOCK,
        )
        from tests.test_build_consumption_wiring import make_build_result

        self.holders = _VERIFIED_VIEW_HOLDERS
        self.holders_lock = _VERIFIED_VIEW_HOLDERS_LOCK
        self.build_result = make_build_result(SUCCEEDED, "run-1/pkg")

        class _RecordingAdapter:
            def __init__(self):
                self.registers = []
                self.unregisters = []

            def register_verified_view(
                self, snapshot, view, *, holder=None
            ):
                self.registers.append((snapshot, holder))
                return True

            def unregister_verified_view(
                self, snapshot, digest, *, holder=None
            ):
                self.unregisters.append((snapshot, digest, holder))
                return True

        self.adapter = _RecordingAdapter()
        self.service = ReviewService(
            replace(self.base, build_agent_mode="auto")
        )
        self.addCleanup(self.service.queue.close)
        self.service.repository_scanner.cxx_memory_adapter = self.adapter
        self.holders.clear()
        self.addCleanup(self.holders.clear)

    def test_last_holder_releases_the_shared_registration(self):
        # The declaration branch keeps the holder count locally, with
        # the registration refresh, the count and the last-holder
        # removal inside one critical section.
        from cxx_analyzer import server as analyzer_server

        class _DeclaringAdapter:
            verified_package_supported = True

        adapter = _DeclaringAdapter()
        analyzer_server.clear_verified_build_views()
        self.addCleanup(analyzer_server.clear_verified_build_views)
        self.assertTrue(
            self.service._deliver_verified_context(
                adapter, self.build_result, object(), "task-1"
            )
        )
        self.assertTrue(
            self.service._deliver_verified_context(
                adapter, self.build_result, object(), "task-2"
            )
        )
        # Both deliveries refreshed the local registration.
        self.assertIsNotNone(
            analyzer_server.lookup_verified_build_view("a" * 64, "c" * 64)
        )
        # The first task finishing must NOT delete the registration the
        # second task is still consuming.
        self.service._release_verified_context(
            adapter, self.build_result, "task-1"
        )
        self.assertIsNotNone(
            analyzer_server.lookup_verified_build_view("a" * 64, "c" * 64)
        )
        # Replay/idempotency: releasing a released task again is a no-op.
        self.service._release_verified_context(
            adapter, self.build_result, "task-1"
        )
        self.assertIsNotNone(
            analyzer_server.lookup_verified_build_view("a" * 64, "c" * 64)
        )
        # The last holder frees the shared registration.
        self.service._release_verified_context(
            adapter, self.build_result, "task-2"
        )
        self.assertIsNone(
            analyzer_server.lookup_verified_build_view("a" * 64, "c" * 64)
        )
        with self.holders_lock:
            self.assertEqual({}, self.holders)

    def test_release_covers_scan_exceptions(self):
        from lima.build_agent import SUCCEEDED
        from tests.test_build_consumption_wiring import make_build_result

        build_result = make_build_result(SUCCEEDED, "run-1/pkg")
        with mock.patch.object(
            self.service, "_run_build_agent", return_value=build_result
        ), mock.patch.object(
            self.service, "_consume_build_context", return_value=object(),
        ), mock.patch.object(
            self.service.repository_scanner, "scan",
            side_effect=RuntimeError("scan exploded"),
        ):
            created = self.service.enqueue_repository_scan(
                "team/project", build_agent_mode="auto"
            )
            task = {}
            for _ in range(300):
                task = self.service.store.get(created["task_id"]) or {}
                if task.get("state") in {"SUCCESS", "FAILED"}:
                    break
                time.sleep(0.02)
        # The scan kept failing and the task failed after its retries,
        # yet every delivery attempt released from the finally -- one
        # holder-scoped unregister per retry's delivery, all for the
        # identity pair and THIS task's token.
        self.assertEqual("FAILED", task["state"])
        self.assertTrue(self.adapter.registers)
        self.assertEqual(
            len(self.adapter.registers), len(self.adapter.unregisters)
        )
        self.assertEqual(
            {("a" * 64, "c" * 64, created["task_id"])},
            set(self.adapter.unregisters),
        )
        with self.holders_lock:
            self.assertEqual({}, self.holders)


class ServerTokenLifecycleTests(unittest.TestCase):
    """Round-2 P1: delivery holds are server-side tokens.

    The reviewer's interleave -- a release's DELETE landing AFTER a
    sibling delivery's POST -- is now order-independent by
    construction: the hold count lives with the registration under the
    sidecar's registry lock.
    """

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        _repository, view, snapshot_hash, digest = (
            build_repository_and_view(Path(self.temporary.name))
        )
        self.view = view
        self.snapshot_hash = snapshot_hash
        self.digest = digest

    def test_holder_tokens_count_and_release_one_hold_each(self):
        with _SidecarThread() as sidecar:
            client = _client(sidecar.port)
            self.assertTrue(
                client.register_verified_view(
                    self.snapshot_hash, self.view, holder="task-a"
                )
            )
            self.assertTrue(
                client.register_verified_view(
                    self.snapshot_hash, self.view, holder="task-b"
                )
            )
            # Retry of the same holder adds no unreleaseable reference.
            self.assertTrue(
                client.register_verified_view(
                    self.snapshot_hash, self.view, holder="task-a"
                )
            )
            self.assertTrue(
                client.unregister_verified_view(
                    self.snapshot_hash, self.digest, holder="task-a"
                )
            )
            # task-b's delivery survives task-a's release.
            self.assertTrue(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )
            # An untracked holder releases nothing it does not own.
            self.assertTrue(
                client.unregister_verified_view(
                    self.snapshot_hash, self.digest, holder="task-z"
                )
            )
            self.assertTrue(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )
            # The last tracked holder frees the registration.
            self.assertTrue(
                client.unregister_verified_view(
                    self.snapshot_hash, self.digest, holder="task-b"
                )
            )
            self.assertFalse(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )

    def test_legacy_holderless_shapes_still_work(self):
        with _SidecarThread() as sidecar:
            client = _client(sidecar.port)
            self.assertTrue(
                client.register_verified_view(self.snapshot_hash, self.view)
            )
            self.assertTrue(
                client.unregister_verified_view(
                    self.snapshot_hash, self.digest
                )
            )
            self.assertFalse(
                client.confirmed_verified_view(self.snapshot_hash, self.digest)
            )

    def test_interleaved_release_cannot_delete_a_fresh_delivery(self):
        # The reviewer's exact sequence, against the REAL service
        # methods and a REAL sidecar: A delivers; A's release has its
        # DELETE held back by a barrier; B delivers (real POST + ack);
        # A's DELETE lands; B must still be registered.
        with _SidecarThread() as sidecar:
            base_client = _client(sidecar.port)
            delete_gate = threading.Event()

            class _GatedAdapter:
                """The real client with a barrier on A's DELETE only."""

                def register_verified_view(self, snapshot, view, *, holder=None):
                    return base_client.register_verified_view(
                        snapshot, view, holder=holder
                    )

                def unregister_verified_view(
                    self, snapshot, digest, *, holder=None
                ):
                    delete_gate.wait(timeout=30)
                    return base_client.unregister_verified_view(
                        snapshot, digest, holder=holder
                    )

            gated = _GatedAdapter()
            handle, database = tempfile.mkstemp(suffix=".db")
            os.close(handle)
            self.addCleanup(os.unlink, database)
            holder_service = ReviewService(
                Settings(
                    host="127.0.0.1", port=0, db_path=database,
                    max_diff_bytes=10000, max_steps=1, timeout_seconds=30,
                    llm_base_url="", llm_api_key="", llm_model="",
                    github_webhook_secret="", github_token="",
                    auto_post_review=False,
                )
            )
            self.addCleanup(holder_service.queue.close)

            class _Build:
                snapshot_hash = self.snapshot_hash
                artifact_digest = self.digest

            self.assertTrue(
                holder_service._deliver_verified_context(
                    gated, _Build(), self.view, "task-a"
                )
            )
            releaser = threading.Thread(
                target=holder_service._release_verified_context,
                args=(gated, _Build(), "task-a"),
                daemon=True,
            )
            releaser.start()
            # While A's DELETE is held back, B delivers for real.
            self.assertTrue(
                holder_service._deliver_verified_context(
                    gated, _Build(), self.view, "task-b"
                )
            )
            delete_gate.set()
            releaser.join(timeout=30)
            # B's registration survived A's late DELETE.
            self.assertTrue(
                base_client.confirmed_verified_view(
                    self.snapshot_hash, self.digest
                )
            )
            # And B can still release it as the last holder.
            self.assertTrue(
                base_client.unregister_verified_view(
                    self.snapshot_hash, self.digest, holder="task-b"
                )
            )
            self.assertFalse(
                base_client.confirmed_verified_view(
                    self.snapshot_hash, self.digest
                )
            )

    def test_two_app_instances_share_one_sidecar(self):
        # Two independent client objects stand in for two service
        # processes: overlapping deliveries of the same identity, and
        # neither instance's release deletes the other's registration.
        with _SidecarThread() as sidecar:
            client_one = _client(sidecar.port)
            client_two = _client(sidecar.port)
            self.assertTrue(
                client_one.register_verified_view(
                    self.snapshot_hash, self.view, holder="inst-1:task-1"
                )
            )
            self.assertTrue(
                client_two.register_verified_view(
                    self.snapshot_hash, self.view, holder="inst-2:task-2"
                )
            )
            self.assertTrue(
                client_one.unregister_verified_view(
                    self.snapshot_hash, self.digest, holder="inst-1:task-1"
                )
            )
            self.assertTrue(
                client_two.confirmed_verified_view(
                    self.snapshot_hash, self.digest
                )
            )
            self.assertTrue(
                client_two.unregister_verified_view(
                    self.snapshot_hash, self.digest, holder="inst-2:task-2"
                )
            )
            self.assertFalse(
                client_two.confirmed_verified_view(
                    self.snapshot_hash, self.digest
                )
            )


class WideCompdbTests(unittest.TestCase):
    """Round-1 P2: a whole-package view registers past the 16-TU
    per-REQUEST batch cap; only facts requests stay batched."""

    def _wide_repository_and_view(self, root: Path, unit_count: int):
        import json as _json

        from lima.build_context_view import (
            compute_artifact_digest,
            create_analysis_view,
            snapshot_fingerprint,
            verify_build_artifact,
        )
        from lima.context_package import build_manifest, write_package

        repository = root / "team" / "project"
        (repository / "src").mkdir(parents=True, exist_ok=True)
        entries = []
        for index in range(unit_count):
            unit = f"src/unit{index:02d}.cpp"
            (repository / unit).write_text(
                f"int u{index}(void) {{ return {index}; }}\n",
                encoding="utf8",
            )
            entries.append({
                "directory": "src",
                "arguments": [
                    "/usr/bin/c++", "-DVERIFIED=1", "-c",
                    unit.rsplit("/", 1)[-1],
                ],
                "file": unit,
            })
        snapshot_hash = snapshot_fingerprint(repository)
        manifest = build_manifest(
            repository="Fixtures/WideRepo",
            revision=snapshot_hash,
            compdb=entries,
            generated=[],
            header_roots=["headers/fixture"],
            rewrites={},
            created_by="wide-compdb-test",
        )
        package = root / "package"
        write_package(
            package, manifest, _json.dumps(entries).encode("utf8"),
            {}, {"headers/fixture/lib.h": b"// lib\n"},
        )
        artifact = verify_build_artifact(
            package, snapshot_hash, compute_artifact_digest(package)
        )
        target_units = tuple(
            sorted(entry["file"] for entry in entries)
        )
        view = create_analysis_view(repository, artifact, target_units)
        return repository, view, snapshot_hash

    def test_seventeen_tu_package_registers_whole_view(self):
        with tempfile.TemporaryDirectory() as temporary:
            _repository, view, snapshot_hash = (
                self._wide_repository_and_view(Path(temporary), 17)
            )
            self.assertEqual(17, len(view.target_units))
            with _SidecarThread() as sidecar:
                client = _client(sidecar.port)
                self.assertTrue(
                    client.register_verified_view(snapshot_hash, view)
                )
                self.assertTrue(
                    client.confirmed_verified_view(
                        snapshot_hash, view.artifact_digest
                    )
                )
                # A per-request batch within the 16-TU request cap still
                # resolves through the wide view.
                with mock.patch.object(
                    __import__(
                        "cxx_analyzer.server", fromlist=["server"]
                    ),
                    "IMPORT_ROOT",
                    Path(temporary),
                ), mock.patch.object(
                    __import__("cxx_analyzer.server", fromlist=["server"]),
                    "WORK_ROOT",
                    Path(temporary) / "work",
                ):
                    (Path(temporary) / "work").mkdir(exist_ok=True)
                    response = client.analyze_uaf_facts(
                        "team/project", snapshot_hash,
                        ("src/unit00.cpp", "src/unit16.cpp"),
                        "verified-package",
                        artifact_digest=view.artifact_digest,
                    )
                    for unit in response.translation_units:
                        self.assertEqual(
                            "verified-package",
                            unit["build_context"]["source_kind"],
                        )


if __name__ == "__main__":
    unittest.main()
