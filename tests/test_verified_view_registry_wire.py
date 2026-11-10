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


def build_repository_and_view(root: Path, variant: int = 0, macro: str = "1"):
    """One directory serving as snapshot, import-root repo and package source.

    Returns ``(repository, view, snapshot_hash, artifact_digest)``.  The
    package binds ``src/a.cpp`` with ``-DVERIFIED=<macro>`` plus one
    vendored header member, mirroring the S4B fixtures.  ``variant``
    varies the source content so distinct calls yield DISTINCT snapshot
    fingerprints (capacity tests register many snapshots); ``macro``
    varies only the compdb flag, so two calls with the same ``variant``
    share ONE snapshot while producing two different sealed artifacts
    (#354 review round 1, P1: sibling builds of the same snapshot).
    """
    repository = root / "team" / "project"
    (repository / "src").mkdir(parents=True, exist_ok=True)
    (repository / "src" / "a.cpp").write_text(
        f"int leak(void) {{ return {variant}; }}\n", encoding="utf8"
    )
    snapshot_hash = snapshot_fingerprint(repository)
    entry = {
        "directory": "src",
        "arguments": ["/usr/bin/c++", f"-DVERIFIED={macro}", "-c", "a.cpp"],
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
    package = root / f"package-{macro}"
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
    """The wire envelope for one sealed view (the PR-B sender shape).

    Identity plus the sealed members only: TU flags, directories and
    the context hash are DERIVED on the sidecar from the sealed
    manifest/compdb members (#352 review round 1) -- they cannot be
    asserted independently over the wire.
    """
    members = {
        path: base64.b64encode(bytes(view.read_member(path))).decode("ascii")
        for path in view.member_paths
    }
    return {
        "schema_version": 1,
        "snapshot_sha256": snapshot_hash,
        "artifact_digest": view.artifact_digest,
        "target_units": list(view.target_units),
        "members": members,
    }


def replace_fixture_header(envelope: dict, content: bytes) -> None:
    """Keep capacity-test package totals valid while varying artifact bytes."""

    members = {
        path: base64.b64decode(data) for path, data in envelope["members"].items()
    }
    members["headers/fixture/lib.h"] = content
    manifest = json.loads(members["context_manifest.json"])
    manifest["totals"]["total_bytes"] = len(members["compile_commands.json"]) + len(content)
    members["context_manifest.json"] = json.dumps(manifest).encode("utf8")
    envelope["members"] = {
        path: base64.b64encode(data).decode("ascii") for path, data in members.items()
    }
    envelope["artifact_digest"] = analyzer_server.artifact_digest_from_members(members)


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
        del missing["target_units"]
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
            replace_fixture_header(variant, f"// lib v{index}\n".encode())
            self._register(variant)
            last_variant = variant
        views = analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot_hash]
        self.assertEqual(limit, len(views))
        # A new digest beyond the window is a leak signal: refused, and
        # the registry is untouched by the refusal.
        overflow = json.loads(json.dumps(self.envelope))
        replace_fixture_header(overflow, b"// lib overflow\n")
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
        for field in ("snapshot_sha256", "artifact_digest"):
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

    def _reseat(self, mutate) -> dict:
        """Rebuild one envelope whose members were mutated, re-hashing.

        The artifact digest is recomputed over the mutated members, so
        these cases exercise the SEALED-PACKAGE derivation (manifest,
        compdb, revision binding), not the digest anchor.
        """

        envelope = json.loads(json.dumps(self.envelope))
        members = {
            path: base64.b64decode(value)
            for path, value in envelope["members"].items()
        }
        mutate(members)
        envelope["members"] = {
            path: base64.b64encode(data).decode("ascii")
            for path, data in members.items()
        }
        envelope["artifact_digest"] = (
            analyzer_server.artifact_digest_from_members(members)
        )
        return envelope

    def test_sealed_semantics_cannot_be_reasserted_independently(self):
        """Round-1 P1: every consumed semantic derives from sealed bytes.

        A digest-consistent package whose manifest lies (wrong context
        hash), whose revision re-labels it onto another snapshot, whose
        compdb is malformed, whose target TU is not declared, or that
        lacks a core member must all be refused -- and a refusal must
        never overwrite an existing registration.
        """
        # Baseline good registration to prove refusals do not clobber.
        self._register(self.envelope)

        def tamper_context_hash(members):
            manifest = json.loads(members["context_manifest.json"])
            manifest["context_hash"] = "e" * 64
            members["context_manifest.json"] = json.dumps(
                manifest
            ).encode("utf8")

        def relabel_revision(members):
            manifest = json.loads(members["context_manifest.json"])
            manifest["revision"] = "f" * 64
            members["context_manifest.json"] = json.dumps(
                manifest
            ).encode("utf8")

        def mangle_compdb(members):
            members["compile_commands.json"] = b"not json at all"

        def drop_manifest(members):
            del members["context_manifest.json"]

        def drop_compdb(members):
            del members["compile_commands.json"]

        for mutate in (
            tamper_context_hash,
            relabel_revision,
            mangle_compdb,
            drop_manifest,
            drop_compdb,
        ):
            with self.assertRaises(analyzer_server.RequestError):
                self._register(self._reseat(mutate))
        # Re-labeling via the envelope identity alone is refused the
        # same way (the sealed revision no longer matches the claim).
        relabeled = json.loads(json.dumps(self.envelope))
        relabeled["snapshot_sha256"] = "1" * 64
        with self.assertRaises(analyzer_server.RequestError):
            self._register(relabeled)
        # A target TU outside the declared compilation database.
        undeclared = json.loads(json.dumps(self.envelope))
        undeclared["target_units"] = ["src/other.cpp"]
        with self.assertRaises(analyzer_server.RequestError):
            self._register(undeclared)
        # The good registration survives every refusal untouched.
        self.assertIsNotNone(
            analyzer_server.lookup_verified_build_view(
                self.snapshot_hash, self.digest
            )
        )

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


class DerivationParityTests(RegistryIsolation):
    """The derived wire view equals the lima view on every consumed field.

    The sidecar derives TU flags, working directories and the context
    hash from the sealed manifest/compdb via mirrored algorithms; this
    pins byte-level parity with what the in-process path would serve,
    so facts/repro see identical semantics either way.
    """

    def test_derived_view_matches_lima_view(self):
        from cxx_analyzer import wire_view

        with tempfile.TemporaryDirectory() as tmp:
            repository, view, snapshot_hash, digest = (
                build_repository_and_view(Path(tmp))
            )
            members = {
                path: bytes(view.read_member(path))
                for path in view.member_paths
            }
            derived = wire_view.derive_wire_view(
                snapshot_hash, digest, list(view.target_units), members
            )
            self.assertEqual(view.target_units, derived.target_units)
            self.assertEqual(view.context_hash, derived.context_hash)
            self.assertEqual(view.artifact_digest, derived.artifact_digest)
            self.assertEqual(view.member_paths, derived.member_paths)
            for unit in view.target_units:
                self.assertEqual(
                    view.flags_for_tu(unit), derived.flags_for_tu(unit)
                )
                self.assertEqual(
                    view.working_directory_for_tu(unit),
                    derived.working_directory_for_tu(unit),
                )
                self.assertEqual(
                    view.read_member("headers/fixture/lib.h"),
                    derived.read_member("headers/fixture/lib.h"),
                )


class RegistryConcurrencyTests(RegistryIsolation):
    """Round-1 P2: registration and cleanup are atomic under threads."""

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.repository, self.view, self.snapshot_hash, self.digest = (
            build_repository_and_view(root)
        )
        self.envelope = envelope_from_view(self.view, self.snapshot_hash)
        self.settings = make_settings()

    def test_interleaved_register_delete_never_tears_state(self):
        """A concurrent DELETE lands fully before or after the POST.

        The reviewer's scenario: a barrier-synchronized DELETE between
        the two slot writes produced a registered-default-but-missing-
        digest mix.  With the registry lock the observable end state of
        every round is either both slots present or both absent.
        """
        import threading as _threading

        rounds = 24
        barrier = _threading.Barrier(2, timeout=10)
        torn: list[str] = []

        def register_worker():
            for _ in range(rounds):
                barrier.wait()
                try:
                    analyzer_server.register_view_request(
                        self.envelope, self.settings
                    )
                except analyzer_server.RequestError:
                    torn.append("register-refused")

        def delete_worker():
            for _ in range(rounds):
                barrier.wait()
                analyzer_server.unregister_view_request({
                    "snapshot_sha256": self.snapshot_hash,
                    "artifact_digest": self.digest,
                })

        workers = [
            _threading.Thread(target=register_worker),
            _threading.Thread(target=delete_worker),
        ]
        for worker in workers:
            worker.start()
        for worker in workers:
            worker.join(timeout=30)
        # The final state must be a coherent registration or removal --
        # never one slot without the other.
        views = analyzer_server._VERIFIED_BUILD_VIEWS.get(
            self.snapshot_hash, {}
        )
        has_digest = self.digest in views
        has_default = "" in views
        self.assertEqual(
            has_digest, has_default, f"torn registry: {sorted(views)}"
        )
        self.assertEqual([], torn)
        # Accounting invariant: tracked bytes exist exactly for the
        # snapshots present (register tracks, unregister/evict untracks).
        self.assertEqual(
            set(analyzer_server._VERIFIED_BUILD_VIEWS),
            set(analyzer_server._REGISTRY_SNAPSHOT_BYTES),
        )

    def test_slot_bound_race_never_exceeds_cap(self):
        """Parallel distinct-digest registrations respect the cap."""
        import threading as _threading

        cap = analyzer_server._MAX_VIEWS_PER_SNAPSHOT
        variants = []
        for index in range(cap + 6):
            envelope = json.loads(json.dumps(self.envelope))
            replace_fixture_header(envelope, f"// lib race {index}\n".encode())
            variants.append(envelope)
        refused: list[int] = []
        start = _threading.Barrier(len(variants), timeout=15)

        def worker(index: int):
            start.wait()
            try:
                analyzer_server.register_view_request(
                    variants[index], self.settings
                )
            except analyzer_server.RequestError:
                refused.append(index)

        threads = [
            _threading.Thread(target=worker, args=(index,))
            for index in range(len(variants))
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=30)
        views = analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot_hash]
        self.assertLessEqual(len(views), cap)
        # The default slot occupies one of the cap slots, so at most
        # cap-1 distinct digests survive; every further variant refused.
        self.assertEqual(len(variants) - (cap - 1), len(refused))


class RegistryCapacityTests(RegistryIsolation):
    """Round-1 P2: process-level capacity with oldest-first eviction."""

    def setUp(self):
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.settings = make_settings()

    def _envelope_for(self, index: int):
        repository, view, snapshot_hash, digest = (
            build_repository_and_view(self.root / f"case{index}", variant=index)
        )
        return envelope_from_view(view, snapshot_hash), snapshot_hash, digest

    def test_snapshot_count_evicts_oldest_first(self):
        cap = analyzer_server._MAX_REGISTRY_SNAPSHOTS
        first = None
        newest = None
        for index in range(cap + 3):
            envelope, snapshot_hash, _ = self._envelope_for(index)
            if index == 0:
                first = snapshot_hash
            newest = snapshot_hash
            analyzer_server.register_view_request(envelope, self.settings)
        # The oldest registration (a crashed host's leak) is gone; the
        # newest survive; the registry never exceeds the cap.
        self.assertLessEqual(
            len(analyzer_server._VERIFIED_BUILD_VIEWS), cap
        )
        self.assertNotIn(first, analyzer_server._VERIFIED_BUILD_VIEWS)
        self.assertIn(newest, analyzer_server._VERIFIED_BUILD_VIEWS)

    def test_total_bytes_evicts_oldest_and_rejects_oversize(self):
        with mock.patch.object(
            analyzer_server, "_MAX_REGISTRY_TOTAL_MEMBER_BYTES", 1
        ):
            # Any single registration already exceeds the byte cap and
            # is refused without evicting everything else.
            envelope, snapshot_hash, digest = self._envelope_for(0)
            with self.assertRaises(analyzer_server.RequestError):
                analyzer_server.register_view_request(envelope, self.settings)
            self.assertEqual({}, analyzer_server._VERIFIED_BUILD_VIEWS)
        with mock.patch.object(
            analyzer_server, "_MAX_REGISTRY_SNAPSHOTS", 2
        ):
            for index in (1, 2, 3):
                envelope, _, _ = self._envelope_for(index)
                analyzer_server.register_view_request(envelope, self.settings)
            self.assertLessEqual(
                len(analyzer_server._VERIFIED_BUILD_VIEWS), 2
            )
        # Accounting follows unregistration: the removed snapshot's
        # bytes are untracked while survivors stay tracked.
        envelope, snapshot_hash, digest = self._envelope_for(4)
        analyzer_server.register_view_request(envelope, self.settings)
        analyzer_server.unregister_view_request({
            "snapshot_sha256": snapshot_hash, "artifact_digest": digest,
        })
        self.assertNotIn(
            snapshot_hash, analyzer_server._REGISTRY_SNAPSHOT_BYTES
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
