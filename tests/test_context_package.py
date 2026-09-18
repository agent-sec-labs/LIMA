"""Analysis context package format freeze and codec tests (workstream A, task A1).

A package is a directory holding ``context_manifest.json``,
``compile_commands.json``, ``generated/`` and third-party header roots.  These
tests freeze the manifest contract, the deterministic ``context_hash``, the
fail-closed package reader, the size caps and the compdb path rewriter.
"""

import json
import unittest
from pathlib import Path

from lima.context_package import (
    MAX_COMPDB_BYTES,
    MAX_MEMBER_FILE_BYTES,
    MAX_PACKAGE_TOTAL_BYTES,
    ContextManifest,
    ContextPackageError,
    build_manifest,
    read_package,
    rewrite_compdb_paths,
    write_package,
)
from lima.contracts.errors import ContractError, ContractErrorCode


def make_compdb() -> list[dict]:
    """Two entries: the ``arguments`` array form and the ``command`` string form."""

    return [
        {
            "directory": "ApplicationLibCode/FileInterface",
            "arguments": [
                "/usr/bin/clang++",
                "-std=c++17",
                "-I/usr/include/qt5",
                "-I",
                "/usr/include/hdf5",
                "-c",
                "ApplicationLibCode/FileInterface/RifActiveCellsReader.cpp",
            ],
            "file": "ApplicationLibCode/FileInterface/RifActiveCellsReader.cpp",
        },
        {
            "directory": "ApplicationLibCode",
            "command": (
                "/usr/bin/clang++ -std=c++17 -I/usr/include/qt5 "
                "-c ApplicationLibCode/RiaMain.cpp"
            ),
            "file": "ApplicationLibCode/RiaMain.cpp",
        },
    ]


def make_rewrites() -> dict[str, str]:
    return {
        "/usr/include/qt5": "headers/qt5",
        "/usr/include/hdf5": "headers/hdf5",
    }


def make_manifest() -> ContextManifest:
    return build_manifest(
        repository="OPM/ResInsight",
        revision="0123456789abcdef0123456789abcdef01234567",
        compdb=make_compdb(),
        generated=["config.h", "version.h"],
        header_roots=["headers/qt5", "headers/hdf5"],
        rewrites=make_rewrites(),
        created_by="resinsight-v1",
    )


def make_generated_files() -> dict[str, bytes]:
    return {"config.h": b"#define RI_VERSION_MAJOR 2023\n", "version.h": b"#define RI_DEBUG 0\n"}


def make_header_files() -> dict[str, bytes]:
    return {
        "headers/qt5/QtCore/qstring.h": b"// qt5 qstring shim\n",
        "headers/hdf5/hdf5.h": b"// hdf5 shim\n",
    }


def write_sample_package(pkg_dir: Path) -> ContextManifest:
    manifest = make_manifest()
    compdb_bytes = json.dumps(make_compdb()).encode("utf-8")
    return write_package(
        pkg_dir, manifest, compdb_bytes, make_generated_files(), make_header_files()
    )


class ManifestContractTest(unittest.TestCase):
    def test_manifest_roundtrip_via_json(self) -> None:
        manifest = make_manifest()
        wire = manifest.to_dict()

        self.assertEqual(wire["schema_version"], 1)
        self.assertEqual(wire["repository"], "OPM/ResInsight")
        self.assertEqual(wire["compdb"]["entry_count"], 2)
        self.assertEqual(
            wire["compdb"]["tu_list"],
            sorted(wire["compdb"]["tu_list"]),
        )
        self.assertEqual(wire["compdb"]["path_prefix_rewrite"], make_rewrites())
        self.assertEqual(wire["generated_headers"], ["config.h", "version.h"])
        self.assertEqual(wire["header_roots"], ["headers/hdf5", "headers/qt5"])
        self.assertEqual(wire["totals"]["compdb_entries"], 2)
        self.assertEqual(wire["totals"]["generated_header_count"], 2)

        decoded = ContextManifest.from_dict(json.loads(json.dumps(wire)))
        self.assertEqual(decoded, manifest)
        self.assertEqual(decoded.to_dict(), wire)

    def test_context_hash_deterministic(self) -> None:
        first = make_manifest()
        second = make_manifest()
        self.assertEqual(first.context_hash, second.context_hash)
        self.assertEqual(len(first.context_hash), 64)
        self.assertTrue(all(c in "0123456789abcdef" for c in first.context_hash))

        mutated = make_compdb()
        mutated[0]["arguments"][4] = "/opt/hdf5"
        changed = build_manifest(
            repository="OPM/ResInsight",
            revision="0123456789abcdef0123456789abcdef01234567",
            compdb=mutated,
            generated=["config.h", "version.h"],
            header_roots=["headers/qt5", "headers/hdf5"],
            rewrites=make_rewrites(),
            created_by="resinsight-v1",
        )
        self.assertNotEqual(changed.context_hash, first.context_hash)

    def test_manifest_rejects_bad_sha(self) -> None:
        manifest = make_manifest()
        bad = manifest.to_dict()
        bad["context_hash"] = "zz" + "0" * 62

        with self.assertRaises(ContractError) as caught:
            ContextManifest.from_dict(bad)
        self.assertEqual(caught.exception.code, ContractErrorCode.INVALID_FIELD_VALUE)


class PackageWriteReadTest(unittest.TestCase):
    def test_write_read_package_roundtrip(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp) / "pkg"
            final_manifest = write_sample_package(pkg_dir)

            self.assertTrue((pkg_dir / "context_manifest.json").is_file())
            self.assertTrue((pkg_dir / "compile_commands.json").is_file())
            self.assertTrue((pkg_dir / "generated" / "config.h").is_file())
            self.assertTrue((pkg_dir / "headers" / "qt5" / "QtCore" / "qstring.h").is_file())

            package = read_package(pkg_dir)
            self.assertEqual(package.manifest, final_manifest)
            self.assertEqual(package.manifest.context_hash, make_manifest().context_hash)
            self.assertEqual(package.manifest.totals.compdb_entries, 2)
            self.assertEqual(package.manifest.totals.generated_header_count, 2)
            self.assertEqual(package.manifest.totals.header_file_count, 2)
            self.assertEqual(
                package.manifest.totals.total_bytes,
                len(json.dumps(make_compdb()).encode("utf-8"))
                + sum(len(data) for data in make_generated_files().values())
                + sum(len(data) for data in make_header_files().values()),
            )
            self.assertEqual(list(package.compdb), make_compdb())
            self.assertEqual(dict(package.generated_files), make_generated_files())
            self.assertEqual(
                package.header_roots,
                (
                    pkg_dir / "headers" / "hdf5",
                    pkg_dir / "headers" / "qt5",
                ),
            )

            # Overwriting the same directory stays atomic and consistent.
            rewritten = write_sample_package(pkg_dir)
            self.assertEqual(read_package(pkg_dir).manifest, rewritten)

    def test_read_rejects_hash_mismatch(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp) / "pkg"
            write_sample_package(pkg_dir)
            compdb_path = pkg_dir / "compile_commands.json"
            text = compdb_path.read_text(encoding="utf-8")
            tampered = text.replace("-std=c++17", "-std=c++20")
            self.assertNotEqual(tampered, text)
            compdb_path.write_text(tampered, encoding="utf-8")

            with self.assertRaises(ContextPackageError):
                read_package(pkg_dir)

    def test_read_rejects_missing_file(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp) / "pkg"
            write_sample_package(pkg_dir)
            (pkg_dir / "generated" / "version.h").unlink()

            with self.assertRaises(ContextPackageError):
                read_package(pkg_dir)

    def test_read_rejects_totals_mismatch(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp) / "pkg"
            write_sample_package(pkg_dir)
            manifest_path = pkg_dir / "context_manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["totals"]["total_bytes"] += 1
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaises(ContextPackageError):
                read_package(pkg_dir)

    def test_size_caps_enforced(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            pkg_dir = Path(tmp) / "pkg"
            compdb_bytes = json.dumps(make_compdb()).encode("utf-8")

            oversized_compdb = b"[" + b" " * MAX_COMPDB_BYTES + b"]"
            with self.assertRaises(ValueError):
                write_package(
                    pkg_dir, make_manifest(), oversized_compdb, {}, {}
                )

            blob = b"x" * (MAX_MEMBER_FILE_BYTES + 1)
            with self.assertRaises(ValueError):
                write_package(
                    pkg_dir,
                    build_manifest(
                        repository="OPM/ResInsight",
                        revision="0123456789abcdef0123456789abcdef01234567",
                        compdb=make_compdb(),
                        generated=["big.h"],
                        header_roots=["headers/qt5"],
                        rewrites=make_rewrites(),
                        created_by="resinsight-v1",
                    ),
                    compdb_bytes,
                    {"big.h": blob},
                    {},
                )

            per_file = b"x" * MAX_MEMBER_FILE_BYTES
            count = MAX_PACKAGE_TOTAL_BYTES // MAX_MEMBER_FILE_BYTES + 1
            headers = {f"headers/qt5/h{i}.h": per_file for i in range(count)}
            manifest = build_manifest(
                repository="OPM/ResInsight",
                revision="0123456789abcdef0123456789abcdef01234567",
                compdb=make_compdb(),
                generated=[],
                header_roots=["headers/qt5"],
                rewrites=make_rewrites(),
                created_by="resinsight-v1",
            )
            with self.assertRaises(ValueError):
                write_package(pkg_dir, manifest, compdb_bytes, {}, headers)


class RewriteCompdbPathsTest(unittest.TestCase):
    def test_rewrite_compdb_arguments_and_command_forms(self) -> None:
        compdb_text = json.dumps(make_compdb())
        rewritten_text = rewrite_compdb_paths(compdb_text, make_rewrites())
        rewritten = json.loads(rewritten_text)

        arguments = rewritten[0]["arguments"]
        self.assertEqual(arguments[2], "-Iheaders/qt5")  # joined form keeps the option head
        self.assertEqual(arguments[3], "-I")
        self.assertEqual(arguments[4], "headers/hdf5")
        self.assertEqual(arguments[6], "ApplicationLibCode/FileInterface/RifActiveCellsReader.cpp")

        argv = rewritten[1]["command"].split()
        self.assertIn("-Iheaders/qt5", argv)
        self.assertIn("ApplicationLibCode/RiaMain.cpp", argv)
        self.assertNotIn("/usr/include/qt5", rewritten[1]["command"])

        # Untouched positional structure stays intact.
        self.assertEqual(rewritten[0]["file"], make_compdb()[0]["file"])
        self.assertEqual(rewritten[0]["directory"], make_compdb()[0]["directory"])

    def test_rewrite_idempotent(self) -> None:
        compdb_text = json.dumps(make_compdb())
        once = rewrite_compdb_paths(compdb_text, make_rewrites())
        twice = rewrite_compdb_paths(once, make_rewrites())
        self.assertEqual(once, twice)


if __name__ == "__main__":
    unittest.main()
