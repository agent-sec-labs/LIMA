"""Execution-scoped ownership and input rejection for verified-view delivery."""

import json
import tempfile
import threading
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path
from unittest import mock

from cxx_analyzer import server
from lima.build_agent import SUCCEEDED
from lima.config import Settings
from lima.cxx_memory import verified_view_envelope
from lima.models import ReviewReport
from lima.repository_scanner import RepositoryScanResult
from lima.service import ReviewService
from tests import test_verified_view_registration_wiring as wiring
from tests.test_build_consumption_wiring import make_build_result
from tests.test_verified_view_registry_wire import build_repository_and_view, make_settings


class ExecutionHolderTests(unittest.TestCase):
    def _service_with_sidecar(self):
        sidecar = wiring.SubprocessCrossProcessTests()
        self.addCleanup(sidecar.doCleanups)
        sidecar.setUp()
        settings = Settings(
            host="127.0.0.1", port=0,
            db_path=str(Path(sidecar.temporary.name) / "tasks.db"),
            max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
            llm_base_url="", llm_api_key="", llm_model="",
            github_webhook_secret="", github_token="", auto_post_review=False,
            repository_import_root=str(sidecar.import_root),
            repository_scan_sast_mode="off", cxx_memory_mode="off",
        )
        service = ReviewService(settings)
        self.addCleanup(service.queue.close)
        service.repository_scanner.cxx_memory_adapter = sidecar.client
        return service, sidecar

    def test_overlapping_executions_of_one_task_keep_independent_holds(self):
        # A reclaimed Redis delivery has the same task_id as the handler
        # still running on the old worker. Exercise the actual scan entry
        # point twice, with real delivery/release against a child sidecar.
        service, sidecar = self._service_with_sidecar()
        registered = []
        released = []

        class RecordingAdapter:
            def register_verified_view(self, snapshot, view, *, holder=None):
                # A retry within ONE delivery must reuse the same holder.
                for _ in range(2):
                    registered.append(holder)
                    if not sidecar.client.register_verified_view(snapshot, view, holder=holder):
                        return False
                return True

            def unregister_verified_view(self, snapshot, digest, *, holder=None):
                released.append(holder)
                return sidecar.client.unregister_verified_view(snapshot, digest, holder=holder)

        service.repository_scanner.cxx_memory_adapter = RecordingAdapter()
        with mock.patch.object(service.queue, "submit"):
            created = service.enqueue_repository_scan("team/project", build_agent_mode="auto")
        task_id = created["task_id"]
        build = replace(
            make_build_result(SUCCEEDED, "run-1/pkg"),
            snapshot_hash=sidecar.snapshot_hash, artifact_digest=sidecar.digest,
        )
        entered = [threading.Event(), threading.Event()]
        finish = [threading.Event(), threading.Event()]
        scan_lock = threading.Lock()
        scan_indices = []
        errors = []

        def scan(workspace, **kwargs):
            with scan_lock:
                index = len(scan_indices)
                scan_indices.append(index)
            entered[index].set()
            if not finish[index].wait(20):
                raise RuntimeError("test scan was not released")
            return RepositoryScanResult(
                report=ReviewReport(
                    repository="team/project", pull_request=None,
                    summary="scan", risk="low",
                    collaboration={"platform": {"mode": "off", "status": "disabled"}},
                ),
                inventory=workspace.inventory(),
            )

        def execute():
            try:
                service._execute_repository_scan(
                    task_id, sidecar.repository, "default", "team/project", {},
                    cxx_agent_mode="off", build_agent_mode="auto",
                )
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=execute) for _ in range(2)]
        with mock.patch.object(service, "_run_build_agent", return_value=build), \
                mock.patch.object(service, "_consume_build_context", return_value=sidecar.view), \
                mock.patch.object(service.repository_scanner, "scan", side_effect=scan):
            try:
                threads[0].start()
                self.assertTrue(entered[0].wait(10))
                threads[1].start()
                self.assertTrue(entered[1].wait(10))
                finish[0].set()
                threads[0].join(10)
                self.assertFalse(threads[0].is_alive())
                self.assertTrue(sidecar.client.confirmed_verified_view(
                    sidecar.snapshot_hash, sidecar.digest
                ))
                self.assertEqual(2, len(set(registered)))
                self.assertEqual([2, 2], sorted(Counter(registered).values()))
                self.assertNotIn(task_id, registered)
            finally:
                for event in finish:
                    event.set()
                for thread in threads:
                    if thread.ident is not None:
                        thread.join(10)
        self.assertFalse(any(thread.is_alive() for thread in threads))
        self.assertEqual([], errors)
        self.assertEqual(set(registered), set(released))
        self.assertFalse(sidecar.client.confirmed_verified_view(
            sidecar.snapshot_hash, sidecar.digest
        ))

    def test_execution_transition_failure_releases_acknowledged_hold(self):
        service, sidecar = self._service_with_sidecar()
        with mock.patch.object(service.queue, "submit"):
            created = service.enqueue_repository_scan("team/project", build_agent_mode="auto")
        build = replace(
            make_build_result(SUCCEEDED, "run-1/pkg"),
            snapshot_hash=sidecar.snapshot_hash, artifact_digest=sidecar.digest,
        )
        with (
            mock.patch.object(service, "_run_build_agent", return_value=build),
            mock.patch.object(service, "_consume_build_context", return_value=sidecar.view),
            mock.patch.object(
                service.store, "transition", side_effect=RuntimeError("store failed"),
            ),
            mock.patch.object(service.repository_scanner, "scan") as scan,
            mock.patch.object(
                sidecar.client, "register_verified_view",
                wraps=sidecar.client.register_verified_view,
            ) as register,
            mock.patch.object(
                sidecar.client, "unregister_verified_view",
                wraps=sidecar.client.unregister_verified_view,
            ) as unregister,
        ):
            with self.assertRaisesRegex(RuntimeError, "store failed"):
                service._execute_repository_scan(
                    created["task_id"], sidecar.repository, "default", "team/project", {},
                    cxx_agent_mode="off", build_agent_mode="auto",
                )
        register.assert_called_once()
        unregister.assert_called_once_with(
            sidecar.snapshot_hash, sidecar.digest, holder=register.call_args.kwargs["holder"]
        )
        scan.assert_not_called()
        self.assertFalse(sidecar.client.confirmed_verified_view(
            sidecar.snapshot_hash, sidecar.digest
        ))


class HolderInputTests(unittest.TestCase):
    def test_surrogate_holder_is_a_400_and_preserves_registered_holds(self):
        server.clear_verified_build_views()
        self.addCleanup(server.clear_verified_build_views)
        with tempfile.TemporaryDirectory() as temporary:
            _, view, snapshot, digest = build_repository_and_view(Path(temporary))
            server.register_view_request(
                verified_view_envelope(snapshot, view, holder="existing"), make_settings()
            )
            existing = server.lookup_verified_build_view(snapshot, digest)
            for holder in ("bad\ud800", "\udfff", "x\ud800y"):
                for method in ("POST", "DELETE"):
                    with self.subTest(holder=repr(holder), method=method):
                        body = (
                            verified_view_envelope(snapshot, view, holder=holder)
                            if method == "POST" else
                            {"snapshot_sha256": snapshot, "artifact_digest": digest,
                             "holder": holder}
                        )
                        status, payload = server.dispatch_request(
                            method, "/v1/verified-build-views", "application/json",
                            json.dumps(body).encode("utf8"), make_settings(),
                        )
                        self.assertEqual(400, status)
                        self.assertEqual("invalid_request", payload["error"])
                        self.assertIs(existing, server.lookup_verified_build_view(snapshot, digest))
                        self.assertEqual({"existing"}, server._VIEW_HOLDERS[(snapshot, digest)])


if __name__ == "__main__":
    unittest.main()
