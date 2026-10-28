"""Verified build artifact and read-only analysis view tests (slice 4A).

The view is the downstream trust boundary for build-agent packages:
``verify_build_artifact`` re-checks the package with a per-file byte digest
(a same-length header swap changes it even though the structural context
hash does not), binds it to the requesting snapshot, and only then does
``create_analysis_view`` lay the package over the fixed snapshot as a
read-only projection.  Every failure refuses to create a view at all.
"""

import json
import tempfile
import unittest
from pathlib import Path

from lima.build_context_view import (
    AnalysisContextView,
    BuildContextViewError,
    compute_artifact_digest,
    create_analysis_view,
    verify_build_artifact,
)
from lima.context_package import build_manifest, read_package, write_package

SNAPSHOT = "a" * 64
OTHER_SNAPSHOT = "b" * 64


def write_package_fixture(
    pkg_dir: Path,
    *,
    revision: str = SNAPSHOT,
    header_content: bytes = b"// lib\n",
) -> None:
    compdb = [
        {
            "directory": "app",
            "arguments": [
                "/usr/bin/c++",
                "-std=c++17",
                "-Iheaders/fixture",
                "-c",
                "app/main.cpp",
                "-o",
                "build/main.o",
            ],
            "file": "app/main.cpp",
        }
    ]
    manifest = build_manifest(
        repository="Fixtures/AgentRepo",
        revision=revision,
        compdb=compdb,
        generated=["build/config.h"],
        header_roots=["headers/fixture"],
        rewrites={"/usr/include/fixture": "headers/fixture"},
        created_by="view-test",
    )
    write_package(
        pkg_dir,
        manifest,
        json.dumps(compdb, indent=2).encode("utf8"),
        {"build/config.h": b"#define FIXTURE 1\n"},
        {"headers/fixture/lib.h": header_content},
    )


def write_snapshot(root: Path, *, with_generated=False) -> Path:
    snapshot = root / "snapshot"
    (snapshot / "app").mkdir(parents=True, exist_ok=True)
    (snapshot / "app" / "main.cpp").write_text(
        "int main(void) { return 0; }\n", encoding="utf8"
    )
    if with_generated:
        (snapshot / "build").mkdir(exist_ok=True)
        (snapshot / "build" / "config.h").write_text(
            "stale snapshot copy\n", encoding="utf8"
        )
    return snapshot


def tree_digest(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class VerifyBuildArtifactTest(unittest.TestCase):
    def test_verify_accepts_valid_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "package"
            write_package_fixture(pkg)
            artifact = verify_build_artifact(
                pkg, SNAPSHOT, compute_artifact_digest(pkg)
            )
            self.assertEqual(artifact.snapshot_hash, SNAPSHOT)
            self.assertTrue(artifact.artifact_digest)
            self.assertTrue(artifact.context_hash)

    def test_same_length_header_tamper_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            pkg = Path(tmp) / "package"
            write_package_fixture(pkg, header_content=b"// lib\n")
            declared = compute_artifact_digest(pkg)
            # Same length, different bytes: the structural reader still
            # accepts it, only the per-file digest catches the swap.
            (pkg / "headers" / "fixture" / "lib.h").write_bytes(b"// evl\n")
            read_package(pkg)
            with self.assertRaises(BuildContextViewError) as caught:
                verify_build_artifact(pkg, SNAPSHOT, declared)
            self.assertIn("artifact-digest-mismatch", caught.exception.reason)

    def test_wrong_snapshot_and_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            wrong = Path(tmp) / "wrong-snapshot"
            write_package_fixture(wrong, revision=OTHER_SNAPSHOT)
            with self.assertRaises(BuildContextViewError) as caught:
                verify_build_artifact(
                    wrong, SNAPSHOT, compute_artifact_digest(wrong)
                )
            self.assertIn("snapshot-mismatch", caught.exception.reason)

            smuggled = Path(tmp) / "smuggled"
            write_package_fixture(smuggled)
            (smuggled / "escape.sh").write_text("curl evil\n", encoding="utf8")
            with self.assertRaises(BuildContextViewError) as caught_extra:
                verify_build_artifact(
                    smuggled, SNAPSHOT, compute_artifact_digest(smuggled)
                )
            self.assertTrue(caught_extra.exception.reason)

    def test_verify_rejects_missing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BuildContextViewError):
                verify_build_artifact(
                    Path(tmp) / "missing", SNAPSHOT, "0" * 64
                )


class CreateAnalysisViewTest(unittest.TestCase):
    def test_view_projects_flags_per_tu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package"
            write_package_fixture(pkg)
            snapshot = write_snapshot(root)
            before = tree_digest(snapshot)
            artifact = verify_build_artifact(
                pkg, SNAPSHOT, compute_artifact_digest(pkg)
            )

            view = create_analysis_view(
                snapshot, artifact, ("app/main.cpp",)
            )

            self.assertIsInstance(view, AnalysisContextView)
            self.assertEqual(view.target_units, ("app/main.cpp",))
            self.assertEqual(view.context_hash, artifact.context_hash)
            self.assertEqual(view.artifact_digest, artifact.artifact_digest)
            self.assertEqual(
                view.flags_for_tu("app/main.cpp"),
                ("-std=c++17", "-Iheaders/fixture"),
            )
            with self.assertRaises(BuildContextViewError) as caught:
                view.flags_for_tu("other/unit.cpp")
            self.assertIn("tu-not-declared", caught.exception.reason)
            # The snapshot is never written through the view.
            self.assertEqual(tree_digest(snapshot), before)

    def test_view_rejects_file_overlay_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package"
            write_package_fixture(pkg)
            snapshot = write_snapshot(root, with_generated=True)
            artifact = verify_build_artifact(
                pkg, SNAPSHOT, compute_artifact_digest(pkg)
            )

            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn("overlay-conflict", caught.exception.reason)

    def test_view_rejects_unlisted_target_tu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package"
            write_package_fixture(pkg)
            snapshot = write_snapshot(root)
            artifact = verify_build_artifact(
                pkg, SNAPSHOT, compute_artifact_digest(pkg)
            )

            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(
                    snapshot, artifact, ("app/main.cpp", "other/unit.cpp")
                )
            self.assertIn("target-tu-missing", caught.exception.reason)

    def test_view_rejects_missing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            pkg = root / "package"
            write_package_fixture(pkg)
            artifact = verify_build_artifact(
                pkg, SNAPSHOT, compute_artifact_digest(pkg)
            )
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(
                    root / "missing", artifact, ("app/main.cpp",)
                )
            self.assertIn("snapshot-directory-missing", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
