"""Version changes must affect baseline identity without rewriting old evidence."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmarks.v4.baseline import analyzer_identity, b1_source, lf_baseline
from lima.contracts.codec import compute_content_digest
from tests.test_v4_baseline_b1_source import _NOMINAL_MACHINE_PROFILE
from tests.test_v4_baseline_lf_baseline import _LFBaselineTestCase


class AnalyzerIdentityTests(unittest.TestCase):
    def source_bundle(self, root, newline="\n"):
        for name in (
            "repository_scanner",
            "reviewer",
            "python_analyzer",
            "python_dataflow",
            "workspace",
            "models",
        ):
            (root / (name + ".py")).write_bytes((name + newline).encode())

    def test_changed_rule_and_added_helper_change_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_bundle(root)
            before = compute_content_digest(analyzer_identity._source_manifest(root))
            (root / "python_analyzer.py").write_text("fixed_rule\n", encoding="utf-8")
            changed = compute_content_digest(analyzer_identity._source_manifest(root))
            self.assertNotEqual(before, changed)
            (root / "new_rule.py").write_text("rule\n", encoding="utf-8")
            self.assertNotEqual(
                changed, compute_content_digest(analyzer_identity._source_manifest(root))
            )

    def test_checkout_location_newlines_and_cache_do_not_change_identity(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            left, right = Path(first), Path(second)
            self.source_bundle(left, "\n")
            self.source_bundle(right, "\r\n")
            (right / "__pycache__").mkdir()
            (right / "__pycache__/rule.pyc").write_bytes(b"cache")
            self.assertEqual(
                analyzer_identity._source_manifest(left), analyzer_identity._source_manifest(right)
            )

    def test_incomplete_bundle_fails_instead_of_using_config_only(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ValueError, "incomplete"):
                analyzer_identity._source_manifest(Path(directory))

    def test_linked_helper_directory_cannot_be_omitted_from_the_manifest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.source_bundle(root)
            (root / "linked_helpers").mkdir()
            with patch.object(Path, "is_symlink", lambda path: path.name == "linked_helpers"):
                with self.assertRaisesRegex(ValueError, "symbolic links"):
                    analyzer_identity._source_manifest(root)

    def test_manifest_matches_independent_source_digest_and_subprocess(self):
        import lima

        manifest = analyzer_identity.scanner_implementation_manifest()
        path = Path(lima.__file__).parent / "python_analyzer.py"
        self.assertEqual(
            manifest["sources"]["lima/python_analyzer.py"],
            hashlib.sha256(path.read_text(encoding="utf-8").encode()).hexdigest(),
        )
        code = (
            "import json; from benchmarks.v4.baseline.analyzer_identity import "
            "scanner_implementation_manifest; print(json.dumps(scanner_implementation_manifest()))"
        )
        output = subprocess.check_output([sys.executable, "-c", code], text=True)  # noqa: S603
        self.assertEqual(json.loads(output), manifest)

    def test_b1_versions_change_run_identity_and_old_evidence_stays_readable(self):
        stamps = [
            {"scheme": "test-version", "sources": {"lima/python_analyzer.py": c * 64}}
            for c in ("a", "b")
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            results = []
            for index, stamp in enumerate(stamps):
                with patch.object(b1_source, "scanner_implementation_manifest", return_value=stamp):
                    result = b1_source.run_b1_source_baseline_suite(
                        output_dir=root / str(index),
                        machine_profile=dict(_NOMINAL_MACHINE_PROFILE),
                        cold_count=1,
                        warm_count=1,
                    )
                results.append(result)
            self.assertNotEqual(results[0].run_spec_digest, results[1].run_spec_digest)
            manifests = [
                json.loads((root / str(index) / "b1-manifest.json").read_text(encoding="utf-8"))
                for index in range(2)
            ]
            self.assertNotEqual(
                manifests[0]["analyzer_fingerprint"], manifests[1]["analyzer_fingerprint"]
            )
            # Verification consumes recorded evidence, not the current source stamp.
            with patch.object(
                b1_source,
                "scanner_implementation_manifest",
                side_effect=AssertionError("must not replace historical identity"),
            ):
                for index in range(2):
                    b1_source.verify_b1_evidence(root / str(index))
            path = root / "0/b1-manifest.json"
            document = json.loads(path.read_text(encoding="utf-8"))
            document["scanner_config"]["implementation"]["sources"]["lima/python_analyzer.py"] = (
                "c" * 64
            )
            path.write_text(json.dumps(document), encoding="utf-8")
            with self.assertRaises(b1_source.B1SourceError) as caught:
                b1_source.verify_b1_evidence(root / "0")
            self.assertIn("scanner_config_sha256", caught.exception.field_path)

    def test_lf_versions_change_run_identity(self):
        fixture = _LFBaselineTestCase()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            archive, binding = fixture.synthetic_run_inputs(root)
            results = []
            for index, version in enumerate(("a", "b")):
                stamp = {
                    "scheme": "test-version",
                    "sources": {"lima/python_analyzer.py": version * 64},
                }
                with patch.object(
                    lf_baseline, "scanner_implementation_manifest", return_value=stamp
                ):
                    results.append(
                        fixture.run_suite(
                            root / str(index), archive, binding, cold_count=1, warm_count=1
                        )
                    )
            self.assertNotEqual(results[0].run_spec_digest, results[1].run_spec_digest)
            self.assertNotEqual(results[0].analyzer_fingerprint, results[1].analyzer_fingerprint)


if __name__ == "__main__":
    unittest.main()
