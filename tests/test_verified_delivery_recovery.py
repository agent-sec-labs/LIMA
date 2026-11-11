"""Ambiguous registration and failed cleanup do not silently leak a hold."""

import tempfile
import unittest
import urllib.error
from pathlib import Path

from cxx_analyzer import server
from lima.cxx_memory import CxxMemoryAnalyzerClient
from lima.service import ReviewService
from tests.test_verified_view_registry_wire import build_repository_and_view, make_settings


class DeliveryRecoveryTests(unittest.TestCase):
    def setUp(self):
        server.clear_verified_build_views()
        self.addCleanup(server.clear_verified_build_views)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        _, self.view, snapshot, digest = build_repository_and_view(Path(temporary.name))
        self.build = type("Build", (), {"snapshot_hash": snapshot, "artifact_digest": digest})()
        self.service = object.__new__(ReviewService)

    def test_post_committed_then_ack_lost_releases_its_hold(self):
        def exchange(request, timeout):
            if request.method == "POST":
                status, _ = server.dispatch_request(
                    "POST", "/v1/verified-build-views", "application/json",
                    request.data, make_settings(),
                )
                self.assertEqual(status, 200)
                raise urllib.error.URLError("ack lost")
            # Exercise real client parsing with a tiny context-manager response.
            status, payload = server.dispatch_request(
                request.method, "/v1/verified-build-views", "application/json",
                request.data, make_settings(),
            )
            import io
            import json
            response = io.BytesIO(json.dumps(payload).encode())
            response.status = status
            response.headers = {"Content-Type": "application/json"}
            return response

        client = CxxMemoryAnalyzerClient("http://sidecar", 5, 1024 * 1024, opener=exchange)
        self.assertFalse(self.service._deliver_verified_context(
            client, self.build, self.view, "scan-ack-lost",
        ))
        self.assertIsNone(server.lookup_verified_build_view(
            self.build.snapshot_hash, self.build.artifact_digest,
        ))

    def test_false_delete_is_retried_until_real_hold_is_released(self):
        from lima.cxx_memory import verified_view_envelope

        server.register_view_request(verified_view_envelope(
            self.build.snapshot_hash, self.view, "scan-release",
        ), make_settings())

        class Adapter:
            calls = 0

            def unregister_verified_view(inner, snapshot, digest, *, holder=None):
                inner.calls += 1
                if inner.calls == 1:
                    return False
                status, _ = server.unregister_view_request({
                    "snapshot_sha256": snapshot, "artifact_digest": digest, "holder": holder,
                })
                return status == 200

        self.service._release_verified_context(Adapter(), self.build, "scan-release")
        self.assertIsNone(server.lookup_verified_build_view(
            self.build.snapshot_hash, self.build.artifact_digest,
        ))
