"""Lease and capacity invariants for holder-backed verified views."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cxx_analyzer import server
from tests.test_verified_view_registry_wire import (
    build_repository_and_view,
    envelope_from_view,
    make_settings,
)


class VerifiedViewLeaseTests(unittest.TestCase):
    def setUp(self):
        server.clear_verified_build_views()
        self.addCleanup(server.clear_verified_build_views)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.settings = make_settings()

    def _envelope(self, name, *, holder):
        _repository, view, snapshot, digest = build_repository_and_view(
            self.root / name, variant=1 if name == "a" else 2
        )
        envelope = envelope_from_view(view, snapshot)
        envelope["holder"] = holder
        return envelope, snapshot, digest

    def test_capacity_never_evicts_an_active_holder(self):
        first, first_snapshot, first_digest = self._envelope("a", holder="first")
        second, second_snapshot, _ = self._envelope("b", holder="second")
        with patch.object(server, "_MAX_REGISTRY_SNAPSHOTS", 1):
            server.register_view_request(first, self.settings)
            with self.assertRaises(server.RequestError) as raised:
                server.register_view_request(second, self.settings)
        self.assertEqual(503, raised.exception.status)
        self.assertEqual("registry_capacity_exhausted", raised.exception.code)
        self.assertIsNotNone(server.lookup_verified_build_view(first_snapshot, first_digest))
        self.assertIsNone(server.lookup_verified_build_view(second_snapshot, None))
        self.assertEqual({"first"}, server._VIEW_HOLDERS[(first_snapshot, first_digest)])

    def test_expired_holder_releases_capacity_for_a_new_registration(self):
        first, first_snapshot, first_digest = self._envelope("a", holder="first")
        second, second_snapshot, second_digest = self._envelope("b", holder="second")
        with patch.object(server, "_MAX_REGISTRY_SNAPSHOTS", 1), \
                patch.object(
                    server.time, "monotonic",
                    side_effect=(100.0, 100.0, 100.0, *(401.0 for _ in range(10))),
                ):
            server.register_view_request(first, self.settings)
            server.register_view_request(second, self.settings)
            self.assertIsNone(server.lookup_verified_build_view(first_snapshot, first_digest))
            self.assertIsNotNone(server.lookup_verified_build_view(second_snapshot, second_digest))

    def test_same_holder_renewal_extends_lease_without_consuming_capacity(self):
        envelope, snapshot, digest = self._envelope("a", holder="holder")
        with patch.object(
            server.time, "monotonic",
            side_effect=(100.0, 100.0, 100.0, 250.0, 250.0, *(401.0 for _ in range(10))),
        ):
            server.register_view_request(envelope, self.settings)
            result = server.renew_view_request({
                "snapshot_sha256": snapshot,
                "artifact_digest": digest,
                "holder": "holder",
            })
            self.assertEqual("renewed", result["status"])
            self.assertIsNotNone(server.lookup_verified_build_view(snapshot, digest))

    def test_holder_budget_rejects_new_holder_without_mutating_view(self):
        envelope, snapshot, digest = self._envelope("a", holder="one")
        with patch.object(server, "_MAX_HOLDERS_PER_VIEW", 1):
            server.register_view_request(envelope, self.settings)
            envelope["holder"] = "two"
            with self.assertRaises(server.RequestError) as raised:
                server.register_view_request(envelope, self.settings)
        self.assertEqual(503, raised.exception.status)
        self.assertEqual("registry_holder_capacity_exhausted", raised.exception.code)
        self.assertEqual({"one"}, server._VIEW_HOLDERS[(snapshot, digest)])

    def test_patch_renewal_uses_a_bounded_json_holder_request(self):
        envelope, snapshot, digest = self._envelope("a", holder="holder")
        server.register_view_request(envelope, self.settings)
        status, payload = server.dispatch_request(
            "PATCH", "/v1/verified-build-views", "application/json",
            json.dumps({
                "snapshot_sha256": snapshot,
                "artifact_digest": digest,
                "holder": "holder",
            }).encode("utf8"), self.settings,
        )
        self.assertEqual(200, status)
        self.assertEqual("renewed", payload["status"])

    def test_in_process_holder_protects_view_from_capacity_eviction(self):
        _repo_a, view_a, snapshot_a, digest_a = build_repository_and_view(
            self.root / "in-process-a", variant=1
        )
        _repo_b, view_b, snapshot_b, _digest_b = build_repository_and_view(
            self.root / "in-process-b", variant=2
        )
        with patch.object(server, "_MAX_REGISTRY_SNAPSHOTS", 1):
            server.register_verified_build_view(
                snapshot_a, view_a, digest_a, set_default=True, holder="first"
            )
            with self.assertRaises(server.RequestError) as raised:
                server.register_verified_build_view(
                    snapshot_b, view_b, _digest_b, set_default=True, holder="second"
                )
        self.assertEqual("registry_capacity_exhausted", raised.exception.code)
        self.assertIs(view_a, server.lookup_verified_build_view(snapshot_a, digest_a))
        self.assertIsNone(server.lookup_verified_build_view(snapshot_b, None))

    def test_in_process_holder_budget_rejects_before_replacing_a_view(self):
        _repo, original, snapshot, digest = build_repository_and_view(
            self.root / "in-process", variant=1
        )
        _repo, replacement, _same_snapshot, _same_digest = build_repository_and_view(
            self.root / "in-process-replacement", variant=1
        )
        self.assertEqual(snapshot, _same_snapshot)
        with patch.object(server, "_MAX_HOLDERS_PER_VIEW", 1):
            server.register_verified_build_view(
                snapshot, original, digest, set_default=True, holder="first"
            )
            with self.assertRaises(server.RequestError) as raised:
                server.register_verified_build_view(
                    snapshot, replacement, digest, set_default=True, holder="second"
                )
        self.assertEqual("registry_holder_capacity_exhausted", raised.exception.code)
        self.assertIs(original, server.lookup_verified_build_view(snapshot, digest))
        self.assertEqual({"first"}, server._VIEW_HOLDERS[(snapshot, digest)])

    def test_in_process_holder_can_renew_and_release_through_existing_api(self):
        _repo, view, snapshot, digest = build_repository_and_view(
            self.root / "in-process", variant=1
        )
        server.register_verified_build_view(
            snapshot, view, digest, set_default=True, holder="holder"
        )
        self.assertEqual("renewed", server.renew_view_request({
            "snapshot_sha256": snapshot,
            "artifact_digest": digest,
            "holder": "holder",
        })["status"])
        server.unregister_verified_build_view(snapshot, digest, holder="holder")
        self.assertIsNone(server.lookup_verified_build_view(snapshot, digest))


if __name__ == "__main__":
    unittest.main()
