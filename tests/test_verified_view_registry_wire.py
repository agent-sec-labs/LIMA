"""Cross-process verified-view registration wire tests (issue #351, PR A).

The verified-package consumption chain works only when the analyzer
process can actually see the sealed view.  In-process deployments share
the module registry; a production deployment runs the analyzer as an
independent sidecar process, so the view must travel over the wire.
These tests pin that wire end to end: the envelope validation, the
digest parity with lima's :func:`compute_artifact_digest`, real
extraction served from a wire-registered view, and a subprocess sidecar
proving the process boundary itself.
"""

import base64
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from cxx_analyzer import server as analyzer_server
from cxx_analyzer.config import AnalyzerSettings
from lima.build_context_view import (
    compute_artifact_digest,
    create_analysis_view,
    snapshot_fingerprint,
    verify_build_artifact,
)
from lima.context_package import build_manifest, write_package


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


def build_repository_and_view(root: Path):
    """One directory serving as snapshot, import-root repo and package source.

    Returns ``(repository, view, snapshot_hash, artifact_digest)``.  The
    package binds ``src/a.cpp`` with ``-DVERIFIED=1`` plus one vendored
    header member, mirroring the S4B fixtures.
    """
    repository = root / "team" / "project"
    (repository / "src").mkdir(parents=True)
    (repository / "src" / "a.cpp").write_text(
        "int leak(void) { return 0; }\n", encoding="utf8"
    )
    snapshot_hash = snapshot_fingerprint(repository)
    entry = {
        "directory": "src",
        "arguments": ["/usr/bin/c++", "-DVERIFIED=1", "-c", "a.cpp"],
        "file": "src/a.cpp",
    }
    manifest = build_manifest(
        repository="Fixtures/AgentRepo",
        revision=snapshot_hash,
        compdb=[entry],
        generated=[],
        header_roots=["headers/fixture"],
        rewrites={},
        created_by="registry-wire-test",
    )
    package = root / "package"
    write_package(
        package,
        manifest,
        json.dumps([entry]).encode("utf8"),
        {},
        {"headers/fixture/lib.h": b"// lib\n"},
    )
    artifact_digest = compute_artifact_digest(package)
    artifact = verify_build_artifact(package, snapshot_hash, artifact_digest)
    view = create_analysis_view(repository, artifact, ("src/a.cpp",))
    return repository, view, snapshot_hash, artifact_digest


def envelope_from_view(view, snapshot_hash: str) -> dict:
    """The wire envelope for one sealed view (the PR-B sender shape)."""
    members = {
        path: base64.b64encode(bytes(view.read_member(path))).decode("ascii")
        for path in view.member_paths
    }
    return {
        "schema_version": 1,
        "snapshot_sha256": snapshot_hash,
        "artifact_digest": view.artifact_digest,
        "context_hash": view.context_hash,
        "target_units": list(view.target_units),
        "tu_flags": {
            unit: list(view.flags_for_tu(unit))
            for unit in view.target_units
        },
        "tu_directories": {
            unit: view.working_directory_for_tu(unit)
            for unit in view.target_units
        },
        "members": members,
    }


class RegistryIsolation(unittest.TestCase):
    def setUp(self):
        analyzer_server.clear_verified_build_views()
        self.addCleanup(analyzer_server.clear_verified_build_views)


class WireValidationTests(RegistryIsolation):
    """register_view_request validates a closed, digest-anchored envelope."""

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.repository, self.view, self.snapshot_hash, self.digest = (
            build_repository_and_view(root)
        )
        self.envelope = envelope_from_view(self.view, self.snapshot_hash)

    def _register(self, envelope):
        return analyzer_server.register_view_request(
            envelope, make_settings()
        )

    def test_valid_envelope_registers_both_slots(self):
        result = self._register(self.envelope)
        self.assertEqual("registered", result["status"])
        self.assertEqual(self.snapshot_hash, result["snapshot_sha256"])
        self.assertEqual(self.digest, result["artifact_digest"])
        # Both the digest slot and the default slot serve the view, so a
        # repro request without an explicit digest still finds it (the
        # lima-side service registers both slots too).
        by_digest = analyzer_server.lookup_verified_build_view(
            self.snapshot_hash, self.digest
        )
        by_default = analyzer_server.lookup_verified_build_view(
            self.snapshot_hash, None
        )
        self.assertIsNotNone(by_digest)
        self.assertIsNotNone(by_default)
        self.assertEqual(self.digest, by_digest.artifact_digest)
        # The reconstructed view keeps the duck-typed surface the
        # extraction path consumes.
        self.assertEqual(("src/a.cpp",), by_digest.target_units)
        self.assertIn("-DVERIFIED=1", by_digest.flags_for_tu("src/a.cpp"))
        self.assertEqual(
            b"// lib\n", by_digest.read_member("headers/fixture/lib.h")
        )

    def test_tampered_member_bytes_rejected_and_registry_clean(self):
        envelope = json.loads(json.dumps(self.envelope))
        envelope["members"]["headers/fixture/lib.h"] = base64.b64encode(
            b"// tampered\n"
        ).decode("ascii")
        # The tampering must not merely change the claimed digest: the
        # recomputed member digest disagrees with the envelope identity.
        with self.assertRaises(analyzer_server.RequestError):
            self._register(envelope)
        self.assertIsNone(
            analyzer_server.lookup_verified_build_view(
                self.snapshot_hash, self.digest
            )
        )
        self.assertIsNone(
            analyzer_server.lookup_verified_build_view(
                self.snapshot_hash, None
            )
        )

    def test_extra_and_missing_fields_rejected(self):
        extra = json.loads(json.dumps(self.envelope))
        extra["surprise"] = True
        with self.assertRaises(analyzer_server.RequestError):
            self._register(extra)
        missing = json.loads(json.dumps(self.envelope))
        del missing["context_hash"]
        with self.assertRaises(analyzer_server.RequestError):
            self._register(missing)

    def test_control_character_and_drive_letter_paths_rejected(self):
        # Null bytes reach the materializer's write path, whose guard
        # catches OSError only -- an embedded null would surface as a
        # per-request 500, so registration must refuse it up front (same
        # for other control characters and Windows drive prefixes; a
        # contained single segment like "c:x" stays legal).
        for unsafe in (
            "a\x00b.h", "a\nb.h", "a\rb.h", "a\x7fb.h", "C:/x.h", "C:",
        ):
            bad = json.loads(json.dumps(self.envelope))
            bad["members"][unsafe] = base64.b64encode(b"x").decode("ascii")
            # Keep the digest self-consistent: this test pins the path
            # gate, not the digest gate.
            members = {
                path: base64.b64decode(value)
                for path, value in bad["members"].items()
            }
            bad["artifact_digest"] = (
                analyzer_server.artifact_digest_from_members(members)
            )
            with self.assertRaises(analyzer_server.RequestError):
                self._register(bad)

    def test_snapshot_slot_bound_fails_loud_on_digest_flood(self):
        # Seven distinct digests plus the default slot fill the retry
        # window; an eighth distinct digest is refused while
        # re-registering an existing digest keeps overwriting in place.
        limit = analyzer_server._MAX_VIEWS_PER_SNAPSHOT
        last_variant = None
        for index in range(limit - 1):
            variant = json.loads(json.dumps(self.envelope))
            variant["members"]["headers/fixture/lib.h"] = base64.b64encode(
                f"// lib v{index}\n".encode()
            ).decode("ascii")
            members = {
                path: base64.b64decode(value)
                for path, value in variant["members"].items()
            }
            variant["artifact_digest"] = (
                analyzer_server.artifact_digest_from_members(members)
            )
            self._register(variant)
            last_variant = variant
        views = analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot_hash]
        self.assertEqual(limit, len(views))
        # A new digest beyond the window is a leak signal: refused, and
        # the registry is untouched by the refusal.
        overflow = json.loads(json.dumps(self.envelope))
        overflow["members"]["headers/fixture/lib.h"] = base64.b64encode(
            b"// lib overflow\n"
        ).decode("ascii")
        members = {
            path: base64.b64decode(value)
            for path, value in overflow["members"].items()
        }
        overflow["artifact_digest"] = (
            analyzer_server.artifact_digest_from_members(members)
        )
        with self.assertRaises(analyzer_server.RequestError):
            self._register(overflow)
        self.assertEqual(
            limit, len(analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot_hash])
        )
        # An existing digest still refreshes in place without growth.
        self._register(last_variant)
        self.assertEqual(
            limit, len(analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot_hash])
        )

    def test_identity_fields_must_be_hex64(self):
        for field in ("snapshot_sha256", "artifact_digest", "context_hash"):
            bad = json.loads(json.dumps(self.envelope))
            bad[field] = "z" * 64
            with self.assertRaises(analyzer_server.RequestError):
                self._register(bad)

    def test_unsafe_member_paths_rejected(self):
        for unsafe in ("../escape.h", "/absolute.h", "back\\slash.h", ""):
            bad = json.loads(json.dumps(self.envelope))
            bad["members"][unsafe] = base64.b64encode(b"x").decode("ascii")
            with self.assertRaises(analyzer_server.RequestError):
                self._register(bad)

    def test_tu_maps_must_cover_targets_exactly(self):
        bad = json.loads(json.dumps(self.envelope))
        bad["tu_flags"]["src/other.cpp"] = ["-DX=1"]
        with self.assertRaises(analyzer_server.RequestError):
            self._register(bad)
        bad = json.loads(json.dumps(self.envelope))
        del bad["tu_directories"]["src/a.cpp"]
        with self.assertRaises(analyzer_server.RequestError):
            self._register(bad)

    def test_member_budget_enforced(self):
        big = json.loads(json.dumps(self.envelope))
        big["members"] = {
            f"headers/fixture/f{index}.h": base64.b64encode(b"x").decode(
                "ascii"
            )
            for index in range(1200)
        }
        with self.assertRaises(analyzer_server.RequestError):
            self._register(big)

    def test_unregister_clears_both_slots_idempotently(self):
        self._register(self.envelope)
        analyzer_server.unregister_view_request({
            "snapshot_sha256": self.snapshot_hash,
            "artifact_digest": self.digest,
        })
        self.assertIsNone(
            analyzer_server.lookup_verified_build_view(
                self.snapshot_hash, self.digest
            )
        )
        self.assertIsNone(
            analyzer_server.lookup_verified_build_view(
                self.snapshot_hash, None
            )
        )
        # Idempotent: a second cleanup must not raise (service restart
        # recovery may replay it).
        analyzer_server.unregister_view_request({
            "snapshot_sha256": self.snapshot_hash,
            "artifact_digest": self.digest,
        })


class DigestParityTests(unittest.TestCase):
    """The wire digest equals lima's artifact digest over the same bytes."""

    def test_wire_digest_matches_lima_compute(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository, view, snapshot_hash, digest = (
                build_repository_and_view(Path(tmp))
            )
            members = {
                path: bytes(view.read_member(path))
                for path in view.member_paths
            }
            self.assertEqual(
                digest, analyzer_server.artifact_digest_from_members(members)
            )


class RoutingTests(RegistryIsolation):
    """handle_request routing for the three verbs on the new endpoint."""

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.repository, self.view, self.snapshot_hash, self.digest = (
            build_repository_and_view(root)
        )
        self.envelope = envelope_from_view(self.view, self.snapshot_hash)
        analyzer_server.register_view_request(
            self.envelope, make_settings()
        )

    def _request(self, method, path, body=None):
        return analyzer_server.dispatch_request(
            method,
            path,
            "application/json" if body is not None else "",
            json.dumps(body).encode("utf8") if body is not None else b"",
            make_settings(),
        )

    def test_confirm_query_hits_and_misses(self):
        status, payload = self._request(
            "GET",
            "/v1/verified-build-views"
            f"?snapshot_sha256={self.snapshot_hash}"
            f"&artifact_digest={self.digest}",
        )
        self.assertEqual(200, status)
        self.assertEqual("registered", payload["status"])
        # Without a digest the confirmation reads the default slot
        # (the shape a capability probe without an identity uses).
        status, payload = self._request(
            "GET",
            f"/v1/verified-build-views?snapshot_sha256={self.snapshot_hash}",
        )
        self.assertEqual(200, status)
        self.assertEqual("registered", payload["status"])
        status, payload = self._request(
            "GET",
            "/v1/verified-build-views"
            f"?snapshot_sha256={'b' * 64}&artifact_digest={self.digest}",
        )
        self.assertEqual(404, status)
        self.assertEqual("not-registered", payload["status"])

    def test_register_via_routing_and_oversize_body(self):
        with tempfile.TemporaryDirectory() as tmp:
            repository, view, snapshot_hash, digest = (
                build_repository_and_view(Path(tmp))
            )
            envelope = envelope_from_view(view, snapshot_hash)
            status, payload = self._request(
                "POST", "/v1/verified-build-views", envelope
            )
            self.assertEqual(200, status)
            self.assertEqual("registered", payload["status"])
        # Oversized bodies are refused before any parsing.
        status, payload = analyzer_server.dispatch_request(
            "POST",
            "/v1/verified-build-views",
            "application/json",
            b"x" * (analyzer_server.REGISTER_VIEW_MAX_REQUEST_BYTES + 1),
            make_settings(),
        )
        self.assertEqual(413, status)

    def test_unregistered_view_confirm_after_delete(self):
        status, _ = self._request(
            "DELETE",
            "/v1/verified-build-views",
            {
                "snapshot_sha256": self.snapshot_hash,
                "artifact_digest": self.digest,
            },
        )
        self.assertEqual(200, status)
        status, payload = self._request(
            "GET",
            "/v1/verified-build-views"
            f"?snapshot_sha256={self.snapshot_hash}"
            f"&artifact_digest={self.digest}",
        )
        self.assertEqual(404, status)

    def test_legacy_paths_keep_exact_matching(self):
        # Unknown paths still 404; the legacy endpoints never gained
        # query tolerance.
        status, _ = self._request("GET", "/v1/nope")
        self.assertEqual(404, status)


class ExtractionIntegrationTests(RegistryIsolation):
    """A wire-registered view serves real verified-package extraction."""

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.import_root = root / "imports"
        self.work_root = root / "work"
        self.work_root.mkdir()
        # The repository doubles as the import-root checkout the sidecar
        # prepares: build it under imports/team/project.
        repository, view, snapshot_hash, digest = (
            build_repository_and_view(root / "imports")
        )
        self.repository = repository
        self.view = view
        self.snapshot_hash = snapshot_hash
        self.digest = digest

    def _facts_request(self, mode: str, artifact_digest=None):
        build_context = {"mode": mode}
        if artifact_digest is not None:
            build_context["artifact_digest"] = artifact_digest
        payload = {
            "schema_version": 1,
            "request_id": str(__import__("uuid").uuid4()),
            "repository_key": "team/project",
            "snapshot_sha256": self.snapshot_hash,
            "translation_units": ["src/a.cpp"],
            "build_context": build_context,
        }
        with mock.patch.object(
            analyzer_server, "IMPORT_ROOT", self.import_root
        ), mock.patch.object(
            analyzer_server, "WORK_ROOT", self.work_root
        ):
            return analyzer_server.uaf_facts_request(
                payload, make_settings()
            )

    def test_wire_registered_view_resolves_verified_package(self):
        envelope = envelope_from_view(self.view, self.snapshot_hash)
        analyzer_server.register_view_request(envelope, make_settings())
        result = self._facts_request("verified-package", self.digest)
        unit = result["translation_units"][0]
        self.assertEqual(
            "verified-package",
            unit["build_context"]["source_kind"],
        )
        gaps = unit["coverage"]["semantic_gaps"]
        self.assertNotIn("verified-view-not-registered", gaps)

    def test_unregistered_view_keeps_explicit_gap(self):
        result = self._facts_request("verified-package", "b" * 64)
        unit = result["translation_units"][0]
        gaps = unit["coverage"]["semantic_gaps"]
        self.assertIn("verified-view-not-registered", gaps)


class SubprocessSidecarTests(unittest.TestCase):
    """The process boundary: register, confirm, extract, unregister over HTTP.

    This is the failure condition the whole endpoint exists for: the
    main process holds the sealed view, the sidecar holds its own
    module registry.  Everything runs against a real
    ``python -m cxx_analyzer.server`` subprocess on a free port.
    """

    @staticmethod
    def _free_port() -> int:
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            return probe.getsockname()[1]

    def setUp(self):
        analyzer_server.clear_verified_build_views()
        self.addCleanup(analyzer_server.clear_verified_build_views)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.import_root = root / "imports"
        self.work_root = root / "work"
        self.work_root.mkdir()
        repository, view, snapshot_hash, digest = (
            build_repository_and_view(root / "imports")
        )
        self.view = view
        self.snapshot_hash = snapshot_hash
        self.digest = digest
        self.port = self._free_port()
        environment = dict(os.environ)
        environment.update({
            "LIMA_CXX_PORT": str(self.port),
            "LIMA_CXX_HOST": "127.0.0.1",
            "LIMA_CXX_IMPORT_ROOT": str(self.import_root),
            "LIMA_CXX_WORK_ROOT": str(self.work_root),
        })
        self.process = subprocess.Popen(  # noqa: S603 - fixed interpreter, repo module, synthetic input
            [sys.executable, "-m", "cxx_analyzer.server"],
            cwd=str(Path(__file__).resolve().parents[1]),
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        self.addCleanup(self._stop_sidecar)
        self._wait_healthy()

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
                with urllib.request.urlopen(  # noqa: S310 - loopback http, fixed port
                    f"http://127.0.0.1:{self.port}/health", timeout=2
                ) as response:
                    if response.status == 200:
                        return
            except (OSError, urllib.error.URLError):
                time.sleep(0.1)
        self.fail("sidecar did not become healthy in time")

    def _request(self, method: str, path: str, body: dict | None = None):
        data = (
            json.dumps(body).encode("utf8") if body is not None else None
        )
        request = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=data,
            method=method,
            headers={"Content-Type": "application/json"} if data else {},
        )
        try:
            with urllib.request.urlopen(  # noqa: S310 - loopback http, fixed port
                request, timeout=60
            ) as response:
                return response.status, json.loads(response.read())
        except urllib.error.HTTPError as error:
            return error.code, json.loads(error.read())

    def test_cross_process_register_confirm_extract_unregister(self):
        envelope = envelope_from_view(self.view, self.snapshot_hash)

        # Before registration the confirmation query says not-registered
        # and a verified-package request reports the explicit gap.
        status, payload = self._request(
            "GET",
            "/v1/verified-build-views"
            f"?snapshot_sha256={self.snapshot_hash}"
            f"&artifact_digest={self.digest}",
        )
        self.assertEqual(404, status)
        self.assertEqual("not-registered", payload["status"])

        status, payload = self._request(
            "POST", "/v1/verified-build-views", envelope
        )
        self.assertEqual(200, status)
        self.assertEqual("registered", payload["status"])

        status, payload = self._request(
            "GET",
            "/v1/verified-build-views"
            f"?snapshot_sha256={self.snapshot_hash}"
            f"&artifact_digest={self.digest}",
        )
        self.assertEqual(200, status)

        # The extraction consumes the wire-registered view inside the
        # independent process.
        status, payload = self._request(
            "POST",
            "/v1/uaf-facts",
            {
                "schema_version": 1,
                "request_id": str(__import__("uuid").uuid4()),
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
            "verified-package",
            unit["build_context"]["source_kind"],
        )
        self.assertNotIn(
            "verified-view-not-registered",
            unit["coverage"]["semantic_gaps"],
        )

        status, _ = self._request(
            "DELETE",
            "/v1/verified-build-views",
            {
                "snapshot_sha256": self.snapshot_hash,
                "artifact_digest": self.digest,
            },
        )
        self.assertEqual(200, status)
        status, _ = self._request(
            "GET",
            "/v1/verified-build-views"
            f"?snapshot_sha256={self.snapshot_hash}"
            f"&artifact_digest={self.digest}",
        )
        self.assertEqual(404, status)


if __name__ == "__main__":
    unittest.main()
