"""Verified build artifact and read-only analysis view tests (slice 4A).

The view is the downstream trust boundary for build-agent packages:
``verify_build_artifact`` re-checks the package with a per-file byte digest
(a same-length header swap changes it even though the structural context
hash does not) and binds it to the requesting snapshot fingerprint;
``create_analysis_view`` re-verifies every identity at construction time
(the package directory and the snapshot directory are both mutable),
refuses overlay conflicts, undeclared or snapshot-missing target units and
unparseable compile commands, and never writes the snapshot.  The package
revision is the real snapshot fingerprint, so the fixtures exercise the
same binding rule the control plane uses.
"""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from lima.build_context_view import (
    AnalysisContextView,
    BuildContextViewError,
    compute_artifact_digest,
    create_analysis_view,
    snapshot_fingerprint,
    verify_build_artifact,
)
from lima.context_package import build_manifest, read_package, write_package

DEFAULT_ARGUMENTS = [
    "/usr/bin/c++",
    "-std=c++17",
    "-Iheaders/fixture",
    "-c",
    "app/main.cpp",
    "-o",
    "build/main.o",
]


def write_package_fixture(
    pkg_dir: Path,
    *,
    revision: str,
    header_content: bytes = b"// lib\n",
    entry: dict | None = None,
) -> None:
    compdb_entry = entry or {
        "directory": "app",
        "arguments": DEFAULT_ARGUMENTS,
        "file": "app/main.cpp",
    }
    compdb = [compdb_entry]
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
    (snapshot / "app" / "main.cpp").write_bytes(
        b"int main(void) { return 0; }\n"
    )
    if with_generated:
        (snapshot / "build").mkdir(exist_ok=True)
        (snapshot / "build" / "config.h").write_text(
            "stale snapshot copy\n", encoding="utf8"
        )
    return snapshot


def make_verified(
    tmp: str,
    *,
    header_content: bytes = b"// lib\n",
    entry: dict | None = None,
):
    """Build a snapshot, a package bound to its fingerprint, and verify."""

    root = Path(tmp)
    snapshot = write_snapshot(root)
    fingerprint = snapshot_fingerprint(snapshot)
    pkg = root / "package"
    write_package_fixture(
        pkg, revision=fingerprint, header_content=header_content, entry=entry
    )
    artifact = verify_build_artifact(
        pkg, fingerprint, compute_artifact_digest(pkg)
    )
    return snapshot, pkg, artifact, fingerprint


def tree_digest(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


class VerifyBuildArtifactTest(unittest.TestCase):
    def test_verify_accepts_valid_artifact(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            _snapshot, _pkg, artifact, fingerprint = make_verified(tmp)
            self.assertEqual(artifact.snapshot_hash, fingerprint)
            self.assertTrue(artifact.artifact_digest)
            self.assertTrue(artifact.context_hash)

    def test_same_length_header_tamper_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = write_snapshot(root)
            fingerprint = snapshot_fingerprint(snapshot)
            pkg = root / "package"
            write_package_fixture(pkg, revision=fingerprint)
            declared = compute_artifact_digest(pkg)
            # Same length, different bytes: the structural reader still
            # accepts it, only the per-file digest catches the swap.
            (pkg / "headers" / "fixture" / "lib.h").write_bytes(b"// evl\n")
            read_package(pkg)
            with self.assertRaises(BuildContextViewError) as caught:
                verify_build_artifact(pkg, fingerprint, declared)
            self.assertIn("artifact-digest-mismatch", caught.exception.reason)

    def test_wrong_snapshot_and_path_escape_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = write_snapshot(root)
            fingerprint = snapshot_fingerprint(snapshot)
            wrong = root / "wrong-snapshot"
            write_package_fixture(wrong, revision="b" * 64)
            with self.assertRaises(BuildContextViewError) as caught:
                verify_build_artifact(
                    wrong, fingerprint, compute_artifact_digest(wrong)
                )
            self.assertIn("snapshot-mismatch", caught.exception.reason)

            smuggled = root / "smuggled"
            write_package_fixture(smuggled, revision=fingerprint)
            (smuggled / "escape.sh").write_text("curl evil\n", encoding="utf8")
            with self.assertRaises(BuildContextViewError):
                verify_build_artifact(
                    smuggled, fingerprint, compute_artifact_digest(smuggled)
                )

    def test_verify_rejects_missing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(BuildContextViewError):
                verify_build_artifact(
                    Path(tmp) / "missing", "a" * 64, "0" * 64
                )


class CreateAnalysisViewTest(unittest.TestCase):
    def test_view_projects_flags_per_tu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _pkg, artifact, _fingerprint = make_verified(tmp)
            before = tree_digest(snapshot)

            view = create_analysis_view(snapshot, artifact, ("app/main.cpp",))

            self.assertIsInstance(view, AnalysisContextView)
            self.assertEqual(view.target_units, ("app/main.cpp",))
            self.assertEqual(view.context_hash, artifact.context_hash)
            self.assertEqual(view.artifact_digest, artifact.artifact_digest)
            self.assertEqual(
                view.flags_for_tu("app/main.cpp"),
                ("-std=c++17", "-Iheaders/fixture"),
            )
            self.assertEqual(
                view.working_directory_for_tu("app/main.cpp"), "app"
            )
            with self.assertRaises(BuildContextViewError) as caught:
                view.flags_for_tu("other/unit.cpp")
            self.assertIn("tu-not-declared", caught.exception.reason)
            # The snapshot is never written through the view.
            self.assertEqual(tree_digest(snapshot), before)

    def test_view_rechecks_identity_between_verify_and_create(self) -> None:
        # The package directory is mutable between the two calls; the view
        # re-verifies bytes and identities (review F1).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, pkg, artifact, _ = make_verified(tmp)
            (pkg / "headers" / "fixture" / "lib.h").write_bytes(b"// evl\n")
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn("artifact-digest-mismatch", caught.exception.reason)

        with tempfile.TemporaryDirectory() as tmp:
            snapshot, pkg, artifact, _ = make_verified(tmp)
            # Swap in a structurally valid package bound to another
            # snapshot, under the same directory path.
            replacement = Path(tmp) / "replacement"
            write_package_fixture(replacement, revision="b" * 64)
            for member in list(pkg.iterdir()):
                if member.is_dir():
                    shutil.rmtree(member)
                else:
                    member.unlink()
            for member in replacement.iterdir():
                target = pkg / member.name
                if member.is_dir():
                    shutil.copytree(member, target)
                else:
                    shutil.copy2(member, target)
            with self.assertRaises(BuildContextViewError) as caught_swap:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn("snapshot-mismatch", caught_swap.exception.reason)

    def test_view_binds_actual_snapshot_directory(self) -> None:
        # A different content directory with a different fingerprint is
        # refused even though the package itself stays valid (review F2).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _pkg, artifact, _ = make_verified(tmp)
            other = Path(tmp) / "other-snapshot"
            (other / "app").mkdir(parents=True)
            (other / "app" / "main.cpp").write_bytes(
                b"int main(void) { return 1; }\n"
            )
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(other, artifact, ("app/main.cpp",))
            self.assertIn(
                "snapshot-directory-mismatch", caught.exception.reason
            )

    def test_view_requires_tu_source_in_snapshot(self) -> None:
        # A TU declared in compdb but absent from the bound snapshot must
        # not produce a view (review F2): build the package against a
        # snapshot variant, then point the view at the pruned directory.
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = write_snapshot(root)
            fingerprint = snapshot_fingerprint(snapshot)
            pkg = root / "package"
            write_package_fixture(pkg, revision=fingerprint)
            artifact = verify_build_artifact(
                pkg, fingerprint, compute_artifact_digest(pkg)
            )
            (snapshot / "app" / "main.cpp").unlink()
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertTrue(caught.exception.reason)

    def test_view_rejects_file_overlay_conflict(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = write_snapshot(root, with_generated=True)
            fingerprint = snapshot_fingerprint(snapshot)
            pkg = root / "package"
            write_package_fixture(pkg, revision=fingerprint)
            artifact = verify_build_artifact(
                pkg, fingerprint, compute_artifact_digest(pkg)
            )

            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn("overlay-conflict", caught.exception.reason)

    def test_view_rejects_unlisted_target_tu(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, _pkg, artifact, _ = make_verified(tmp)
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(
                    snapshot, artifact, ("app/main.cpp", "other/unit.cpp")
                )
            self.assertIn("target-tu-missing", caught.exception.reason)

    def test_view_rejects_missing_snapshot(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _snapshot, _pkg, artifact, _ = make_verified(tmp)
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(
                    root / "missing", artifact, ("app/main.cpp",)
                )
            self.assertIn(
                "snapshot-directory-missing", caught.exception.reason
            )

    def test_projection_preserves_directory_semantics(self) -> None:
        # Slice-1 producers relativize source-tree paths to repository
        # roots, so include values stay repository-relative (normalized,
        # never re-prefixed with the working directory); joined -o and the
        # working-directory spelling of the source file are stripped
        # (review round 1 F3 + round 2 F4).
        with tempfile.TemporaryDirectory() as tmp:
            entry = {
                "directory": "app",
                "arguments": [
                    "c++",
                    "-Iinclude",
                    "-isystem",
                    "third_party",
                    "-oapp_obj.o",
                    "-c",
                    "main.cpp",
                ],
                "file": "app/main.cpp",
            }
            snapshot, _pkg, artifact, _ = make_verified(tmp, entry=entry)
            view = create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertEqual(
                view.flags_for_tu("app/main.cpp"),
                ("-Iinclude", "-isystem", "third_party"),
            )
            self.assertEqual(view.working_directory_for_tu("app/main.cpp"), "app")

    def test_separated_option_values_are_preserved(self) -> None:
        # -x, -D, -target and friends take a separate operand; dropping it
        # as a "bare positional" would corrupt the command (round 2 F3).
        with tempfile.TemporaryDirectory() as tmp:
            entry = {
                "directory": "app",
                "arguments": [
                    "c++",
                    "-x",
                    "c++",
                    "-D",
                    "FEATURE=1",
                    "-target",
                    "x86_64-linux-gnu",
                    "-c",
                    "main.cpp",
                ],
                "file": "app/main.cpp",
            }
            snapshot, _pkg, artifact, _ = make_verified(tmp, entry=entry)
            view = create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertEqual(
                view.flags_for_tu("app/main.cpp"),
                (
                    "-x",
                    "c++",
                    "-D",
                    "FEATURE=1",
                    "-target",
                    "x86_64-linux-gnu",
                ),
            )

    def test_unknown_bare_positional_refuses_view(self) -> None:
        # A bare token that is neither a known operand nor the source file
        # must refuse the view, not vanish silently (round 2 F3).
        with tempfile.TemporaryDirectory() as tmp:
            entry = {
                "directory": "app",
                "arguments": ["c++", "-c", "main.cpp", "surprise.o"],
                "file": "app/main.cpp",
            }
            snapshot, _pkg, artifact, _ = make_verified(tmp, entry=entry)
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn(
                "compdb-unexpected-positional", caught.exception.reason
            )

    def test_slice1_relativized_paths_are_not_re_prefixed(self) -> None:
        # End-to-end with the real slice-1 relativizer: a container-
        # absolute compdb becomes repository-relative in the package, and
        # the view must keep those values instead of re-joining the
        # working directory (round 2 F4).
        from lima.build_recipe import _relativize_source_paths
        from lima.context_package import rewrite_compdb_paths

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = write_snapshot(root)
            fingerprint = snapshot_fingerprint(snapshot)
            compdb = [
                {
                    "directory": "/src/build",
                    "arguments": [
                        "/usr/bin/c++",
                        "-I/src/app/include",
                        "-c",
                        "/src/app/main.cpp",
                        "-o",
                        "main.o",
                    ],
                    "file": "/src/app/main.cpp",
                }
            ]
            relativized = json.loads(
                _relativize_source_paths(json.dumps(compdb), "/src")
            )
            rewritten = rewrite_compdb_paths(
                json.dumps(relativized), {"/usr/include/fixture": "headers/fixture"}
            )
            entry = json.loads(rewritten)[0]
            pkg = root / "package"
            write_package_fixture(pkg, revision=fingerprint, entry=entry)
            artifact = verify_build_artifact(
                pkg, fingerprint, compute_artifact_digest(pkg)
            )
            view = create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertEqual(
                view.flags_for_tu("app/main.cpp"), ("-Iapp/include",)
            )
            self.assertEqual(view.working_directory_for_tu("app/main.cpp"), "build")

    def test_view_seals_members_against_later_mutation(self) -> None:
        # Package bytes are consumed through the sealed copy; mutating the
        # original directory after creation changes nothing the view
        # serves (round 2 F1).
        with tempfile.TemporaryDirectory() as tmp:
            snapshot, pkg, artifact, _ = make_verified(tmp)
            view = create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn("headers/fixture/lib.h", view.member_paths)
            self.assertEqual(view.read_member("headers/fixture/lib.h"), b"// lib\n")
            with self.assertRaises(BuildContextViewError):
                view.read_member("headers/fixture/absent.h")

            (pkg / "headers" / "fixture" / "lib.h").write_bytes(b"// evl\n")
            self.assertEqual(view.read_member("headers/fixture/lib.h"), b"// lib\n")
            self.assertTrue(view.flags_for_tu("app/main.cpp"))

    def test_target_outside_inventory_coverage_is_refused(self) -> None:
        # The fingerprint covers only the deterministic inventory; a TU
        # under an ignored directory could change without changing the
        # bound identity, so it is refused (round 2 F2).
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            snapshot = write_snapshot(root)
            (snapshot / "vendor").mkdir()
            (snapshot / "vendor" / "unit.cpp").write_text(
                "int unit(void) { return 9; }\n", encoding="utf8"
            )
            fingerprint = snapshot_fingerprint(snapshot)
            entry = {
                "directory": "vendor",
                "arguments": ["c++", "-c", "unit.cpp"],
                "file": "vendor/unit.cpp",
            }
            pkg = root / "package"
            write_package_fixture(pkg, revision=fingerprint, entry=entry)
            artifact = verify_build_artifact(
                pkg, fingerprint, compute_artifact_digest(pkg)
            )
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("vendor/unit.cpp",))
            self.assertIn("target-tu-not-covered", caught.exception.reason)

    def test_unparseable_command_refuses_view(self) -> None:
        # An unparseable compile command refuses the view instead of
        # degrading to empty flags (review F4).
        with tempfile.TemporaryDirectory() as tmp:
            entry = {
                "directory": "app",
                "command": 'c++ -I"unterminated -c main.cpp',
                "file": "app/main.cpp",
            }
            snapshot, _pkg, artifact, _ = make_verified(tmp, entry=entry)
            with self.assertRaises(BuildContextViewError) as caught:
                create_analysis_view(snapshot, artifact, ("app/main.cpp",))
            self.assertIn("compdb-command", caught.exception.reason)


if __name__ == "__main__":
    unittest.main()
