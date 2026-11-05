"""Registry capacity follows retained views, not the largest build per snapshot."""

import base64
import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from cxx_analyzer import server, wire_view
from tests.test_verified_view_registry_wire import (
    build_repository_and_view,
    envelope_from_view,
    make_settings,
)


class RegistryAccountingTests(unittest.TestCase):
    def setUp(self):
        server.clear_verified_build_views()
        self.addCleanup(server.clear_verified_build_views)
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.settings = make_settings()

    def _envelope(self, snapshot_variant=0, build_variant=0, header_size=4000):
        root = self.root / f"snapshot-{snapshot_variant}-build-{build_variant}"
        _, view, snapshot, _ = build_repository_and_view(root, variant=snapshot_variant)
        envelope = copy.deepcopy(envelope_from_view(view, snapshot))
        members = {path: base64.b64decode(data) for path, data in envelope["members"].items()}
        members["headers/fixture/lib.h"] = bytes([65 + build_variant]) * header_size
        manifest = json.loads(members["context_manifest.json"])
        manifest["totals"]["total_bytes"] = len(members["compile_commands.json"]) + header_size
        members["context_manifest.json"] = json.dumps(manifest).encode("utf8")
        envelope["members"] = {
            path: base64.b64encode(data).decode("ascii") for path, data in members.items()
        }
        envelope["artifact_digest"] = server.artifact_digest_from_members(members)
        return envelope, sum(len(data) for data in members.values())

    def _register(self, envelope):
        return server.register_view_request(envelope, self.settings)

    def _unregister(self, envelope):
        server.unregister_view_request({
            key: envelope[key] for key in ("snapshot_sha256", "artifact_digest")
        })

    def test_distinct_builds_add_bytes_but_default_alias_does_not(self):
        first, first_size = self._envelope(build_variant=0)
        second, second_size = self._envelope(build_variant=1, header_size=6000)
        self._register(first)
        self._register(second)
        self.assertEqual(first_size + second_size, server._registry_total_bytes())
        # A new wire object for the same artifact replaces both references.
        with patch.object(
            server, "_MAX_REGISTRY_TOTAL_MEMBER_BYTES", first_size + second_size
        ):
            self._register(second)
        self.assertEqual(first_size + second_size, server._registry_total_bytes())
        self.assertEqual(3, len(server._VERIFIED_BUILD_VIEWS[first["snapshot_sha256"]]))

    def test_delete_older_build_subtracts_only_its_bytes(self):
        older, _ = self._envelope(build_variant=0, header_size=6000)
        current, current_size = self._envelope(build_variant=1)
        self._register(older)
        self._register(current)
        self._unregister(older)
        self.assertEqual(current_size, server._registry_total_bytes())
        self.assertEqual(
            current["artifact_digest"],
            server.lookup_verified_build_view(current["snapshot_sha256"], None).artifact_digest,
        )
        self._unregister(current)
        self.assertEqual(0, server._registry_total_bytes())

    def test_delete_current_build_keeps_older_digest_accounted(self):
        older, older_size = self._envelope(build_variant=0)
        current, _ = self._envelope(build_variant=1, header_size=6000)
        self._register(older)
        self._register(current)
        self._unregister(current)
        self.assertEqual(older_size, server._registry_total_bytes())
        self.assertIsNone(server.lookup_verified_build_view(older["snapshot_sha256"], None))
        self.assertIsNotNone(server.lookup_verified_build_view(
            older["snapshot_sha256"], older["artifact_digest"]
        ))

    def test_same_snapshot_over_capacity_is_rejected_without_mutation(self):
        first, size = self._envelope(build_variant=0)
        second, _ = self._envelope(build_variant=1)
        self._register(first)
        registered = server.lookup_verified_build_view(first["snapshot_sha256"], None)
        with patch.object(server, "_MAX_REGISTRY_TOTAL_MEMBER_BYTES", size + 1):
            with self.assertRaises(server.RequestError) as raised:
                self._register(second)
        self.assertEqual(413, raised.exception.status)
        self.assertIs(registered, server.lookup_verified_build_view(first["snapshot_sha256"], None))
        self.assertEqual(size, server._registry_total_bytes())
        self.assertIsNone(server.lookup_verified_build_view(
            second["snapshot_sha256"], second["artifact_digest"]
        ))

    def test_legacy_default_only_replacement_releases_old_bytes(self):
        first, _ = self._envelope(build_variant=0, header_size=6000)
        second, second_size = self._envelope(build_variant=1)
        for envelope in (first, second):
            members = {
                path: base64.b64decode(data) for path, data in envelope["members"].items()
            }
            view = wire_view.derive_wire_view(
                envelope["snapshot_sha256"], envelope["artifact_digest"],
                envelope["target_units"], members,
            )
            server.register_verified_build_view(envelope["snapshot_sha256"], view)
        self.assertEqual(second_size, server._registry_total_bytes())
        self.assertEqual(1, len(server._VERIFIED_BUILD_VIEWS[second["snapshot_sha256"]]))

    def test_multi_build_bytes_trigger_oldest_snapshot_eviction(self):
        first, first_size = self._envelope(snapshot_variant=0, build_variant=0)
        second, second_size = self._envelope(snapshot_variant=0, build_variant=1)
        newest, newest_size = self._envelope(snapshot_variant=1, build_variant=0)
        with patch.object(
            server, "_MAX_REGISTRY_TOTAL_MEMBER_BYTES", first_size + second_size + 1
        ):
            self._register(first)
            self._register(second)
            self._register(newest)
        self.assertNotIn(first["snapshot_sha256"], server._VERIFIED_BUILD_VIEWS)
        self.assertEqual(newest_size, server._registry_total_bytes())
        self.assertEqual({newest["snapshot_sha256"]}, set(server._REGISTRY_SNAPSHOT_BYTES))


if __name__ == "__main__":
    unittest.main()
