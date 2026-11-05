"""Parity checks for wire registration and the context-package reader."""

import base64
import json
import tempfile
import unittest
from pathlib import Path

from cxx_analyzer import server as analyzer_server
from cxx_analyzer.config import AnalyzerSettings
from lima.build_context_view import snapshot_fingerprint
from lima.context_package import ContextPackageError, build_manifest, read_package, write_package


def _settings() -> AnalyzerSettings:
    return AnalyzerSettings(
        auto_cmake=True, build_steps=(), test_steps=(), max_memory_mb=1024,
        max_processes=32, max_output_bytes=8192, step_timeout_seconds=17,
        total_timeout_seconds=90, repository_scan_max_files=100,
        repository_scan_max_file_bytes=4096, repository_scan_max_total_bytes=16384,
        trusted_build_context_generation=False,
    )


class WirePackageValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        analyzer_server.clear_verified_build_views()
        self.addCleanup(analyzer_server.clear_verified_build_views)
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        repository = root / "repository"
        (repository / "src").mkdir(parents=True)
        (repository / "src" / "a.cpp").write_text("int main() {}\n", encoding="utf8")
        self.snapshot = snapshot_fingerprint(repository)
        self.entry = {
            "directory": "src",
            "arguments": ["c++", "-include", "build/unlisted.h", "-c", "a.cpp"],
            "file": "src/a.cpp",
        }
        self.package = root / "package"
        manifest = build_manifest(
            repository="fixtures/wire", revision=self.snapshot, compdb=[self.entry],
            generated=[], header_roots=["headers/vendor"], rewrites={}, created_by="test",
        )
        write_package(
            self.package, manifest, json.dumps([self.entry]).encode("utf8"), {},
            {"headers/vendor/lib.h": b"// header\n"},
        )

    def _members(self) -> dict[str, bytes]:
        return {
            path.relative_to(self.package).as_posix(): path.read_bytes()
            for path in self.package.rglob("*") if path.is_file()
        }

    def _envelope(self, members: dict[str, bytes]) -> dict[str, object]:
        return {
            "schema_version": 1,
            "snapshot_sha256": self.snapshot,
            "artifact_digest": analyzer_server.artifact_digest_from_members(members),
            "target_units": ["src/a.cpp"],
            "members": {
                path: base64.b64encode(data).decode("ascii")
                for path, data in members.items()
            },
        }

    def _assert_reader_and_wire_reject(self, mutate) -> None:
        members = self._members()
        mutate(members)
        # Materialize the exact member shape to exercise the authoritative reader.
        broken = Path(tempfile.mkdtemp(dir=self.temporary.name))
        for path, data in members.items():
            target = broken / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        with self.assertRaises(ContextPackageError):
            read_package(broken)

        valid_members = self._members()
        valid_envelope = self._envelope(valid_members)
        analyzer_server.register_view_request(valid_envelope, _settings())
        before = dict(analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])
        with self.assertRaises(analyzer_server.RequestError):
            analyzer_server.register_view_request(self._envelope(members), _settings())
        self.assertEqual(before, analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])

    def test_valid_real_package_is_readable_and_registerable(self) -> None:
        read_package(self.package)
        result = analyzer_server.register_view_request(
            self._envelope(self._members()), _settings()
        )
        self.assertEqual("registered", result["status"])

    def test_undeclared_generated_member_is_rejected_like_reader(self) -> None:
        self._assert_reader_and_wire_reject(
            lambda members: members.__setitem__("generated/build/unlisted.h", b"// hidden\n")
        )

    def test_missing_declared_generated_member_is_rejected_like_reader(self) -> None:
        generated_package = Path(self.temporary.name) / "generated-package"
        manifest = build_manifest(
            repository="fixtures/wire", revision=self.snapshot, compdb=[self.entry],
            generated=["build/declared.h"], header_roots=["headers/vendor"],
            rewrites={}, created_by="test",
        )
        write_package(
            generated_package, manifest, json.dumps([self.entry]).encode("utf8"),
            {"build/declared.h": b"// generated\n"},
            {"headers/vendor/lib.h": b"// header\n"},
        )
        read_package(generated_package)
        good_members = {
            path.relative_to(generated_package).as_posix(): path.read_bytes()
            for path in generated_package.rglob("*") if path.is_file()
        }
        missing_members = dict(good_members)
        missing_members.pop("generated/build/declared.h")
        broken = Path(self.temporary.name) / "missing-generated"
        for path, data in missing_members.items():
            target = broken / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        with self.assertRaises(ContextPackageError):
            read_package(broken)
        analyzer_server.register_view_request(self._envelope(good_members), _settings())
        before = dict(analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])
        with self.assertRaises(analyzer_server.RequestError):
            analyzer_server.register_view_request(self._envelope(missing_members), _settings())
        self.assertEqual(before, analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])

    def test_unlisted_top_level_member_missing_root_and_bad_totals_reject(self) -> None:
        for mutate in (
            lambda members: members.__setitem__("unexpected/file.h", b"x"),
            lambda members: members.pop("headers/vendor/lib.h"),
            lambda members: members.__setitem__("headers/vendor/extra.h", b"x"),
        ):
            with self.subTest(mutate=mutate):
                self._assert_reader_and_wire_reject(mutate)

    def test_closed_manifest_schema_types_paths_and_totals_reject(self) -> None:
        def edit_manifest(edit):
            def mutate(members: dict[str, bytes]) -> None:
                manifest = json.loads(members["context_manifest.json"])
                edit(manifest)
                members["context_manifest.json"] = json.dumps(manifest).encode("utf8")
            return mutate

        cases = (
            ("unknown-field", edit_manifest(lambda manifest: manifest.__setitem__("extra", True))),
            (
                "bad-schema",
                edit_manifest(lambda manifest: manifest.__setitem__("schema_version", 2)),
            ),
            ("boolean-total", edit_manifest(
                lambda manifest: manifest["totals"].__setitem__("total_bytes", True)
            )),
            ("wrong-total", edit_manifest(
                lambda manifest: manifest["totals"].__setitem__(
                    "total_bytes", manifest["totals"]["total_bytes"] + 1
                )
            )),
            ("reserved-root", edit_manifest(
                lambda manifest: manifest.__setitem__("header_roots", ["generated"])
            )),
            ("nested-roots", edit_manifest(
                lambda manifest: manifest.__setitem__(
                    "header_roots", ["headers", "headers/vendor"]
                )
            )),
        )
        for name, mutate in cases:
            with self.subTest(name=name):
                self._assert_reader_and_wire_reject(mutate)

    def test_valid_generated_command_multitu_and_rewrites_register(self) -> None:
        entries = [
            {
                "directory": "src",
                "command": "c++ -Ithird/vendor -include generated/config.h -c a.cpp",
                "file": "src/a.cpp",
            },
            {
                "directory": "src",
                "arguments": ["c++", "-Ithird/vendor", "-c", "b.cpp"],
                "file": "src/b.cpp",
            },
        ]
        package = Path(self.temporary.name) / "multitu-package"
        manifest = build_manifest(
            repository="fixtures/wire", revision=self.snapshot, compdb=entries,
            generated=["config.h"], header_roots=["third/vendor"],
            rewrites={"/upstream/vendor": "third/vendor"}, created_by="test",
        )
        write_package(
            package, manifest, json.dumps(entries).encode("utf8"),
            {"config.h": b"#define CONFIG 1\n"},
            {"third/vendor/lib.h": b"// vendor\n"},
        )
        read_package(package)
        members = {
            path.relative_to(package).as_posix(): path.read_bytes()
            for path in package.rglob("*") if path.is_file()
        }
        envelope = self._envelope(members)
        envelope["target_units"] = ["src/a.cpp", "src/b.cpp"]
        result = analyzer_server.register_view_request(envelope, _settings())
        self.assertEqual("registered", result["status"])

    def test_bad_non_target_command_rejects_like_local_view_creation(self) -> None:
        entries = [
            dict(self.entry),
            {
                "directory": "src",
                "arguments": ["c++", "not-a-source-or-option"],
                "file": "src/b.cpp",
            },
        ]
        package = Path(self.temporary.name) / "bad-nontarget-package"
        manifest = build_manifest(
            repository="fixtures/wire", revision=self.snapshot, compdb=entries,
            generated=[], header_roots=["headers/vendor"], rewrites={}, created_by="test",
        )
        write_package(
            package, manifest, json.dumps(entries).encode("utf8"), {},
            {"headers/vendor/lib.h": b"// header\n"},
        )
        # S4A's package reader accepts this structural package; its local
        # view constructor then projects every compdb command and rejects it.
        read_package(package)
        members = {
            path.relative_to(package).as_posix(): path.read_bytes()
            for path in package.rglob("*") if path.is_file()
        }
        with self.assertRaises(analyzer_server.RequestError):
            analyzer_server.register_view_request(self._envelope(members), _settings())

    def test_decoder_recursion_and_surrogate_fail_as_request_errors(self) -> None:
        good_members = self._members()
        analyzer_server.register_view_request(self._envelope(good_members), _settings())
        before = dict(analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])
        for malformed_manifest in (b'"\\ud800"', b"[" * 2000 + b"]" * 2000):
            with self.subTest(malformed_manifest=malformed_manifest[:12]):
                members = dict(good_members)
                members["context_manifest.json"] = malformed_manifest
                with self.assertRaises(analyzer_server.RequestError):
                    analyzer_server.register_view_request(self._envelope(members), _settings())
                self.assertEqual(before, analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])

    def test_surrogate_compdb_key_is_rejected_before_hashing(self) -> None:
        def mutate(members):
            compdb = json.loads(members["compile_commands.json"])
            compdb[0]["\ud800"] = "invalid unicode key"
            members["compile_commands.json"] = json.dumps(compdb).encode("utf8")
            manifest = json.loads(members["context_manifest.json"])
            manifest["totals"]["total_bytes"] = (
                len(members["compile_commands.json"]) + len(members["headers/vendor/lib.h"])
            )
            members["context_manifest.json"] = json.dumps(manifest).encode("utf8")
        self._assert_reader_and_wire_reject(mutate)

    def test_surrogate_member_path_returns_400_without_changing_registry(self) -> None:
        good = self._envelope(self._members())
        analyzer_server.register_view_request(good, _settings())
        before = dict(analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])
        malformed = self._envelope(self._members())
        malformed["members"]["bad\ud800.h"] = base64.b64encode(b"x").decode("ascii")
        status, payload = analyzer_server.dispatch_request(
            "POST", "/v1/verified-build-views", "application/json",
            json.dumps(malformed).encode("utf8"), _settings(),
        )
        self.assertEqual(400, status)
        self.assertEqual("invalid_request", payload["error"])
        self.assertEqual(before, analyzer_server._VERIFIED_BUILD_VIEWS[self.snapshot])


if __name__ == "__main__":
    unittest.main()
