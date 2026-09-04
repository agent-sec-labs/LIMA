import io
import json
import tempfile
import unittest
import urllib.error
import zipfile
from pathlib import Path
from unittest.mock import patch

import lima.real_world_evaluation as evaluation_module
from lima.real_world_evaluation import (
    ANALYZER_COMPONENTS,
    LLMSecurityTriageClient,
    RealWorldSecurityEvaluator,
    SnapshotStore,
    _symbol_matches,
    adjudicate_evidence,
    analyzer_fingerprint,
    load_real_world_dataset,
)
from lima.semantic_retrieval import SecurityInvariant, SemanticCandidate


ROOT = Path(__file__).resolve().parents[1]
DATASET = ROOT / "evaluation_data" / "real_world_security_cases.json"
CALIBRATION_DATASET = ROOT / "evaluation_data" / "popular_calibration_v1.json"
CALIBRATION_DATASET_V2 = ROOT / "evaluation_data" / "popular_external_calibration_v2.json"
EXTERNAL_HOLDOUT_V2 = ROOT / "evaluation_data" / "popular_external_holdout_v2.json"


def archive(commit, files):
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        for path, content in files.items():
            bundle.writestr("repository-%s/%s" % (commit, path), content)
    return output.getvalue()


class Response:
    def __init__(self, value):
        self.value = value
        self.offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        if size < 0:
            size = len(self.value) - self.offset
        result = self.value[self.offset:self.offset + size]
        self.offset += len(result)
        return result


class RealWorldEvaluationTests(unittest.TestCase):
    def test_parent_symbol_identity_matches_nested_security_boundary(self):
        self.assertTrue(_symbol_matches("WindowsViewer.show_file", {"WindowsViewer"}))
        self.assertTrue(_symbol_matches(
            "ModelFileManager.add_routes.get_model_preview",
            {"ModelFileManager.add_routes"},
        ))
        self.assertFalse(_symbol_matches("OtherViewer.show_file", {"WindowsViewer"}))

    def test_hybrid_adjudication_never_auto_clears_evidence_conflicts(self):
        candidates = [
            SemanticCandidate(
                path="app.py", qualname="risky", start_line=1, end_line=2,
                category="command", score=80, signals=("dynamic-shell-sink",),
                code="def risky(command): ...\n",
                invariants=(SecurityInvariant(
                    identifier="command-boundary", category="command", status="risk",
                    summary="untrusted data reaches a shell",
                ),),
            ),
            SemanticCandidate(
                path="app.py", qualname="fixed", start_line=3, end_line=4,
                category="command", score=70, signals=("dynamic-shell-sink",),
                code="def fixed(command): ...\n",
                invariants=(SecurityInvariant(
                    identifier="command-boundary", category="command", status="mitigation",
                    summary="shell operators are rejected",
                ),),
            ),
        ]
        response = {
            "status": "completed", "contract_valid": True,
            "verdicts": [
                {"path": "app.py", "symbol": "risky", "is_vulnerable": False, "cwe": "NONE"},
                {"path": "app.py", "symbol": "fixed", "is_vulnerable": False, "cwe": "NONE"},
            ],
        }

        result = adjudicate_evidence(response, candidates)

        self.assertEqual("needs_review", result["decisions"][0]["disposition"])
        self.assertEqual("risk-invariant-conflicts-with-llm", result["decisions"][0]["reason"])
        self.assertEqual("clear", result["decisions"][1]["disposition"])
        self.assertFalse(result["auto_clear"])

    @staticmethod
    def _external_manifest():
        cwes = ("CWE-22", "CWE-78", "CWE-89", "CWE-22", "CWE-78", "CWE-89")
        cases = []
        for index, cwe in enumerate(cwes):
            repository = "popular/project-%d" % index
            cases.append({
                "id": "external-%d" % index,
                "cve": "CVE-TEST-%d" % index,
                "cwe": cwe,
                "repository": repository,
                "vulnerable_commit": "a" * 40,
                "fixed_commit": "b" * 40,
                "vulnerable_archive_sha256": "c" * 64,
                "fixed_archive_sha256": "d" * 64,
                "ground_truth_paths": ["src/security.py"],
                "ground_truth_symbols": ["security_boundary"],
                "expected_repair_policy": "abstain",
                "split": "external-holdout",
                "popularity_snapshot": {
                    "captured_at": "2026-08-24",
                    "stars": 1000 + index,
                    "watchers": 20,
                    "source": "https://github.com/%s" % repository,
                },
                "sources": ["https://github.com/advisories/GHSA-test-%d" % index],
            })
        return {
            "schema_version": 2,
            "name": "external-test",
            "evaluation_role": "external-holdout",
            "frozen_analyzer_sha256": analyzer_fingerprint(),
            "selection_policy": {
                "minimum_stars": 1000,
                "minimum_watchers": 100,
                "threshold_operator": "or",
                "case_count_range": [5, 10],
                "excluded_repositories": ["development/project"],
            },
            "cases": cases,
        }

    @staticmethod
    def _write_manifest(root, manifest):
        target = Path(root, "manifest.json")
        target.write_text(json.dumps(manifest), encoding="utf-8")
        return target

    def test_manifest_pins_balanced_real_cases(self):
        dataset = load_real_world_dataset(DATASET)
        self.assertEqual(3, len(dataset["cases"]))
        self.assertEqual(
            {"CWE-22", "CWE-78", "CWE-89"},
            {item["cwe"] for item in dataset["cases"]},
        )
        self.assertTrue(all(len(item["fixed_commit"]) == 40 for item in dataset["cases"]))

    def test_v2_external_holdout_is_frozen_popular_and_repository_disjoint(self):
        dataset = json.loads(EXTERNAL_HOLDOUT_V2.read_text(encoding="utf-8"))
        development = json.loads(DATASET.read_text(encoding="utf-8"))
        calibration = json.loads(CALIBRATION_DATASET.read_text(encoding="utf-8"))
        known_repositories = {
            item["repository"]
            for manifest in (development, calibration)
            for item in manifest["cases"]
        }
        repositories = {item["repository"] for item in dataset["cases"]}
        excluded = set(dataset["selection_policy"]["excluded_repositories"])

        self.assertEqual(5, len(dataset["cases"]))
        self.assertEqual({"CWE-22", "CWE-78", "CWE-89"}, {
            item["cwe"] for item in dataset["cases"]
        })
        self.assertTrue(repositories.isdisjoint(known_repositories))
        self.assertTrue(known_repositories.issubset(excluded))
        self.assertTrue(all(
            len(item["vulnerable_archive_sha256"]) == 64
            and len(item["fixed_archive_sha256"]) == 64
            for item in dataset["cases"]
        ))
        self.assertEqual(
            ["mlflow/mlflow"],
            [item["repository"] for item in dataset["resource_exclusions"]],
        )
        self.assertEqual("external-holdout", dataset["evaluation_role"])
        self.assertEqual(
            "bf81ba2cf0719bd62b7b9b2bf3b621571a6a38fe5b6e79374c3cdc2e36f1e5f1",
            dataset["frozen_analyzer_sha256"],
        )

    def test_v2_calibration_records_the_completed_holdout_without_relabeling_it(self):
        holdout = json.loads(EXTERNAL_HOLDOUT_V2.read_text(encoding="utf-8"))
        calibration = load_real_world_dataset(CALIBRATION_DATASET_V2)
        self.assertEqual("calibration", calibration["evaluation_role"])
        self.assertEqual(
            "3a45b1138a5863ea4db6bb13b804f7eef4c3122fbcd5bc6bf176a0828ae181f4",
            calibration["source_holdout_manifest_sha256"],
        )
        self.assertEqual(
            holdout["frozen_analyzer_sha256"],
            calibration["baseline_analyzer_sha256"],
        )
        self.assertEqual(
            analyzer_fingerprint(),
            calibration["calibration_analyzer_sha256"],
        )
        self.assertEqual(
            [item["id"] for item in holdout["cases"]],
            [item["id"] for item in calibration["cases"]],
        )
        self.assertTrue(all(item["split"] == "calibration" for item in calibration["cases"]))

    def test_analyzer_fingerprint_is_portable_across_lf_and_crlf_checkouts(self):
        with tempfile.TemporaryDirectory() as root:
            package = Path(root)
            for name in ANALYZER_COMPONENTS:
                (package / name).write_bytes(b"first line\nsecond line\n")
            with patch.object(
                evaluation_module, "__file__", str(package / "real_world_evaluation.py")
            ):
                lf_fingerprint = analyzer_fingerprint()
                for name in ANALYZER_COMPONENTS:
                    (package / name).write_bytes(b"first line\r\nsecond line\r\n")
                crlf_fingerprint = analyzer_fingerprint()
        self.assertEqual(lf_fingerprint, crlf_fingerprint)

    def test_snapshot_store_extracts_pinned_archive_and_uses_cache(self):
        commit = "a" * 40
        payload = archive(commit, {"app.py": "print('safe')\n"})
        calls = []

        def opener(request, timeout):
            calls.append((request.full_url, timeout))
            return Response(payload)

        with tempfile.TemporaryDirectory() as root:
            store = SnapshotStore(root, opener=opener)
            first = store.acquire("owner/project", commit)
            second = store.acquire("owner/project", commit)
            self.assertFalse(first["cache_hit"])
            self.assertTrue(second["cache_hit"])
            self.assertEqual(1, len(calls))
            self.assertEqual("print('safe')\n", Path(first["path"], "app.py").read_text())

    def test_snapshot_store_refetches_a_tampered_cache_tree(self):
        commit = "f" * 40
        payload = archive(commit, {"app.py": "safe = True\n"})
        calls = []

        def opener(_request, timeout):
            self.assertEqual(90, timeout)
            calls.append(True)
            return Response(payload)

        with tempfile.TemporaryDirectory() as root:
            store = SnapshotStore(root, opener=opener)
            first = store.acquire("owner/project", commit)
            Path(first["path"], "app.py").write_text("tampered = True\n", encoding="utf-8")
            second = store.acquire("owner/project", commit, first["archive_sha256"])
            self.assertFalse(second["cache_hit"])
            self.assertEqual(2, len(calls))
            self.assertEqual(
                "safe = True\n", Path(second["path"], "app.py").read_text(encoding="utf-8")
            )

    def test_external_holdout_manifest_accepts_popular_repository_pairs(self):
        with tempfile.TemporaryDirectory() as root:
            target = self._write_manifest(root, self._external_manifest())
            loaded = load_real_world_dataset(target)
        self.assertEqual("external-holdout", loaded["evaluation_role"])
        self.assertEqual(6, len(loaded["cases"]))

    def test_external_holdout_manifest_rejects_unpopular_or_duplicate_repositories(self):
        manifest = self._external_manifest()
        manifest["cases"][0]["popularity_snapshot"].update({"stars": 999, "watchers": 99})
        with tempfile.TemporaryDirectory() as root:
            target = self._write_manifest(root, manifest)
            with self.assertRaisesRegex(ValueError, "popularity policy"):
                load_real_world_dataset(target)
        manifest = self._external_manifest()
        manifest["cases"][1]["repository"] = manifest["cases"][0]["repository"]
        manifest["cases"][1]["popularity_snapshot"]["source"] = (
            manifest["cases"][0]["popularity_snapshot"]["source"]
        )
        with tempfile.TemporaryDirectory() as root:
            target = self._write_manifest(root, manifest)
            with self.assertRaisesRegex(ValueError, "repositories must be unique"):
                load_real_world_dataset(target)

    def test_external_holdout_requires_archive_pins_except_in_fetch_mode(self):
        manifest = self._external_manifest()
        manifest["cases"][0]["vulnerable_archive_sha256"] = ""
        with tempfile.TemporaryDirectory() as root:
            target = self._write_manifest(root, manifest)
            with self.assertRaisesRegex(ValueError, "archive digests must be pinned"):
                load_real_world_dataset(target)
            loaded = load_real_world_dataset(target, allow_unpinned_archives=True)
        self.assertEqual("", loaded["cases"][0]["vulnerable_archive_sha256"])

    def test_external_holdout_rejects_analyzer_drift(self):
        manifest = self._external_manifest()
        manifest["frozen_analyzer_sha256"] = "0" * 64
        with tempfile.TemporaryDirectory() as root:
            target = self._write_manifest(root, manifest)
            with self.assertRaisesRegex(ValueError, "fingerprint does not match"):
                load_real_world_dataset(target)

    def test_calibration_manifest_records_holdout_origin_without_claiming_frozen_status(self):
        manifest = self._external_manifest()
        baseline = manifest.pop("frozen_analyzer_sha256")
        manifest.update({
            "name": "popular-calibration-v1",
            "evaluation_role": "calibration",
            "source_holdout_manifest_sha256": "e" * 64,
            "baseline_analyzer_sha256": baseline,
        })
        for case in manifest["cases"]:
            case["split"] = "calibration"
        with tempfile.TemporaryDirectory() as root:
            loaded = load_real_world_dataset(self._write_manifest(root, manifest))
        self.assertEqual("calibration", loaded["evaluation_role"])
        self.assertNotIn("frozen_analyzer_sha256", loaded)

    def test_snapshot_store_rejects_traversal(self):
        output = io.BytesIO()
        with zipfile.ZipFile(output, "w") as bundle:
            bundle.writestr("../escape.py", "bad")
        with tempfile.TemporaryDirectory() as root:
            store = SnapshotStore(root, opener=lambda *_args, **_kwargs: Response(output.getvalue()))
            with self.assertRaisesRegex(ValueError, "unsafe path"):
                store.acquire("owner/project", "b" * 40)

    def test_snapshot_store_omits_symbolic_links(self):
        output = io.BytesIO()
        info = zipfile.ZipInfo("repository-c/link.py")
        info.create_system = 3
        info.external_attr = 0o120777 << 16
        with zipfile.ZipFile(output, "w") as bundle:
            bundle.writestr("repository-c/app.py", "safe = True\n")
            bundle.writestr(info, "../../outside.py")
        with tempfile.TemporaryDirectory() as root:
            store = SnapshotStore(
                root, opener=lambda *_args, **_kwargs: Response(output.getvalue())
            )
            result = store.acquire("owner/project", "c" * 40)
            self.assertTrue(Path(result["path"], "app.py").is_file())
            self.assertFalse(Path(result["path"], "link.py").exists())

    def test_llm_triage_validates_and_records_usage_without_secret(self):
        response_body = {
            "choices": [{"message": {"content": json.dumps({
                "is_vulnerable": True, "cwe": "CWE-78", "path": "app.py",
                "root_cause": "Untrusted text reaches a shell.", "confidence": 0.9,
                "locally_template_repairable": False,
            })}}],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
        }
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text("import os\nos.system(value)\n", encoding="utf-8")
            client = LLMSecurityTriageClient(
                base_url="https://llm.invalid/v1", api_key="do-not-leak",
                model="test-model", provider="test",
            )
            with patch(
                "lima.real_world_evaluation.urllib.request.urlopen",
                return_value=Response(json.dumps(response_body).encode()),
            ):
                result = client.triage(root, ["app.py"])
        self.assertTrue(result["is_vulnerable"])
        self.assertEqual(15, result["usage"]["total_tokens"])
        self.assertNotIn("do-not-leak", json.dumps(result))
        self.assertEqual(64, len(result["prompt_sha256"]))

    def test_llm_http_errors_redact_api_key(self):
        with tempfile.TemporaryDirectory() as root:
            Path(root, "app.py").write_text("safe = True\n", encoding="utf-8")
            client = LLMSecurityTriageClient(
                base_url="https://llm.invalid/v1", api_key="sensitive-token",
                model="test-model", provider="test",
            )
            error = urllib.error.HTTPError(
                "https://llm.invalid/v1/chat/completions", 401, "Unauthorized", {},
                io.BytesIO(b"invalid sensitive-token"),
            )
            with patch(
                "lima.real_world_evaluation.urllib.request.urlopen",
                side_effect=error,
            ):
                with self.assertRaises(RuntimeError) as raised:
                    client.triage(root, ["app.py"])
        self.assertIn("[REDACTED]", str(raised.exception))
        self.assertNotIn("sensitive-token", str(raised.exception))

    def test_llm_candidate_contract_carries_invariants_symbol_and_token_cap(self):
        response_body = {
            "choices": [{"message": {"content": json.dumps({
                "is_vulnerable": True,
                "cwe": "CWE-78",
                "path": "git/cmd.py",
                "symbol": "Git.check_unsafe_options",
                "root_cause": "Validation and execution canonicalize option names differently.",
                "confidence": 0.95,
                "locally_template_repairable": False,
            })}}],
            "usage": {"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
        }
        candidate = SemanticCandidate(
            path="git/cmd.py",
            qualname="Git.check_unsafe_options",
            start_line=10,
            end_line=20,
            category="command",
            score=100,
            signals=("unsafe_option",),
            code="def check_unsafe_options(options):\n    return options\n",
            relations=("Git.transform_kwargs",),
            invariants=(SecurityInvariant(
                identifier="command-option-canonicalization",
                category="command",
                status="risk",
                summary="Validation and execution use different canonical forms.",
            ),),
        )
        captured = {}

        def opener(request, timeout):
            captured.update(json.loads(request.data.decode("utf-8")))
            self.assertEqual(90, timeout)
            return Response(json.dumps(response_body).encode())

        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1",
            api_key="do-not-leak",
            model="test-model",
            provider="deepseek",
            max_completion_tokens=777,
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen",
            side_effect=opener,
        ):
            result = client.triage_candidates([candidate])

        self.assertTrue(result["contract_valid"])
        self.assertEqual("Git.check_unsafe_options", result["symbol"])
        self.assertEqual(777, captured["max_tokens"])
        self.assertEqual({"type": "disabled"}, captured["thinking"])
        prompt = captured["messages"][1]["content"]
        self.assertIn("DETERMINISTIC HYPOTHESES", prompt)
        self.assertIn("Git.transform_kwargs", prompt)
        self.assertIn("Distinguish an explicitly selected executable", prompt)
        self.assertIn("trust_boundary", prompt)
        self.assertIn("AI-tool argument", prompt)
        self.assertIn("absence of an HTTP call site is not by itself", prompt)
        self.assertIn("default metadata value as validation", prompt)
        self.assertIn("do not demand an unrelated root-containment", prompt)
        self.assertIn("Do not infer that a returned command string is executed", prompt)

    def test_llm_candidate_contract_rejects_unprovided_symbol(self):
        response_body = {
            "choices": [{"message": {"content": json.dumps({
                "is_vulnerable": True,
                "cwe": "CWE-78",
                "path": "app.py",
                "symbol": "invented.symbol",
                "root_cause": "claim",
                "confidence": 0.8,
                "locally_template_repairable": False,
            })}}],
        }
        candidate = SemanticCandidate(
            path="app.py", qualname="Runner.execute", start_line=1, end_line=2,
            category="command", score=10, signals=("command",),
            code="def execute(value):\n    return value\n",
        )
        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1", api_key="secret",
            model="test-model", provider="test",
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen",
            return_value=Response(json.dumps(response_body).encode()),
        ):
            result = client.triage_candidates([candidate])
        self.assertFalse(result["contract_valid"])
        self.assertIn("vulnerability-invalid-symbol-identity", result["contract_errors"])

    def test_llm_candidate_batch_requires_one_verdict_per_exact_identity(self):
        candidates = [
            SemanticCandidate(
                path="paths.py", qualname="contains", start_line=1, end_line=3,
                category="path", score=100, signals=("lexical-commonprefix",),
                code="def contains(root, target):\n    return commonprefix([root, target])\n",
            ),
            SemanticCandidate(
                path="commands.py", qualname="run", start_line=1, end_line=3,
                category="command", score=90, signals=("dynamic-shell-sink",),
                code="def run(command):\n    return subprocess.run(command, shell=True)\n",
            ),
        ]
        response_body = {
            "choices": [{"message": {"content": json.dumps({"verdicts": [
                {
                    "is_vulnerable": True, "cwe": "CWE-22", "path": "paths.py",
                    "symbol": "contains", "root_cause": "lexical prefix", "confidence": 0.9,
                    "locally_template_repairable": True,
                },
                {
                    "is_vulnerable": False, "cwe": "NONE", "path": "commands.py",
                    "symbol": "run", "root_cause": "missing untrusted source", "confidence": 0.7,
                    "locally_template_repairable": False,
                },
            ]})}}],
            "usage": {"prompt_tokens": 80, "completion_tokens": 40, "total_tokens": 120},
        }
        captured = {}

        def opener(request, timeout=None):
            self.assertEqual(90, timeout)
            captured.update(json.loads(request.data.decode("utf-8")))
            return Response(json.dumps(response_body).encode())

        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1", api_key="secret",
            model="test-model", provider="test",
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen", side_effect=opener
        ):
            result = client.triage_candidate_batch(candidates)

        self.assertTrue(result["contract_valid"])
        self.assertEqual(2, len(result["verdicts"]))
        self.assertEqual(120, result["usage"]["total_tokens"])
        self.assertIn("exactly one verdict for every FILE/SYMBOL", captured["messages"][1]["content"])

    def test_llm_candidate_batch_describes_typed_file_provenance_flow(self):
        candidates = [
            SemanticCandidate(
                path="models.py", qualname="FileData", start_line=1, end_line=3,
                category="path", score=160,
                signals=("file-model-provenance-boundary",),
                code="class FileData:\n    path: str\n",
                invariants=(SecurityInvariant(
                    identifier="path-file-object-provenance", category="path",
                    status="risk", summary="default marker is not provenance",
                ),),
            ),
            SemanticCandidate(
                path="blocks.py", qualname="Blocks.preprocess_data", start_line=1,
                end_line=3, category="path", score=120,
                signals=("file-cache-boundary", "check_in_upload_folder"),
                code="def preprocess_data(value):\n    return move_files_to_cache(value)\n",
                calls=("async_move_files_to_cache",),
                invariants=(SecurityInvariant(
                    identifier="path-file-object-provenance", category="path",
                    status="risk", summary="missing contextual marker validation",
                ),),
            ),
            SemanticCandidate(
                path="blocks.py", qualname="Blocks.postprocess_data", start_line=5,
                end_line=7, category="path", score=80,
                signals=("file-cache-boundary",),
                code="def postprocess_data(value):\n    return move_files_to_cache(value)\n",
            ),
            SemanticCandidate(
                path="processing.py", qualname="async_move_files_to_cache", start_line=1,
                end_line=3, category="path", score=110,
                signals=("is_file_obj_with_meta",),
                code="def async_move_files_to_cache(value):\n"
                "    return traverse(value, is_file_obj_with_meta)\n",
            ),
            SemanticCandidate(
                path="file.py", qualname="File._process_single_file", start_line=1,
                end_line=3, category="path", score=170,
                signals=("component-file-read-sink", "path-read-sink"),
                code="def _process_single_file(value):\n"
                "    return open(value.path, 'rb').read()\n",
            ),
        ]
        response_body = {
            "choices": [{"message": {"content": json.dumps({"verdicts": [
                {
                    "is_vulnerable": False, "cwe": "NONE", "path": item.path,
                    "symbol": item.qualname, "root_cause": "guard shown",
                    "confidence": 0.8, "locally_template_repairable": False,
                }
                for item in candidates
            ]})}}],
        }
        captured = {}

        def opener(request, timeout=None):
            captured.update(json.loads(request.data.decode("utf-8")))
            return Response(json.dumps(response_body).encode())

        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1", api_key="secret",
            model="test-model", provider="test",
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen", side_effect=opener
        ):
            result = client.triage_candidate_batch(candidates)

        self.assertTrue(result["contract_valid"])
        prompt = captured["messages"][1]["content"]
        self.assertIn("file-provenance-input-flow", prompt)
        self.assertIn("FileData", prompt)
        self.assertIn("Blocks.preprocess_data", prompt)
        self.assertIn("scope boundary", prompt)
        self.assertIn("Blocks.postprocess_data", prompt)
        self.assertIn("marker-bypass hypothesis", prompt)
        self.assertIn("async_move_files_to_cache", prompt)
        self.assertIn("downstream file-use sink", prompt)
        self.assertIn("File._process_single_file", prompt)

    def test_llm_candidate_batch_fails_contract_when_identity_is_omitted(self):
        candidate = SemanticCandidate(
            path="app.py", qualname="run", start_line=1, end_line=2,
            category="command", score=10, signals=("dynamic-shell-sink",),
            code="def run(command):\n    return command\n",
        )
        response_body = {
            "choices": [{"message": {"content": json.dumps({"verdicts": []})}}],
        }
        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1", api_key="secret",
            model="test-model", provider="test",
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen",
            return_value=Response(json.dumps(response_body).encode()),
        ):
            result = client.triage_candidate_batch([candidate])
        self.assertFalse(result["contract_valid"])
        self.assertIn("batch-missing-identities", result["contract_errors"])

    def test_llm_candidate_batch_canonicalizes_unique_short_symbol(self):
        candidate = SemanticCandidate(
            path="commands.py", qualname="Runner.run", start_line=1, end_line=2,
            category="command", score=50, signals=("dynamic-shell-sink",),
            code="class Runner:\n    def run(self, command): ...\n",
        )
        response_body = {
            "choices": [{"message": {"content": json.dumps({"verdicts": [{
                "is_vulnerable": True, "cwe": "CWE-78", "path": "commands.py",
                "symbol": "run", "root_cause": "dynamic shell data", "confidence": 0.8,
                "locally_template_repairable": True,
            }]})}}],
        }
        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1", api_key="secret",
            model="test-model", provider="test",
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen",
            return_value=Response(json.dumps(response_body).encode()),
        ):
            result = client.triage_candidate_batch([candidate])

        self.assertTrue(result["contract_valid"])
        self.assertEqual("Runner.run", result["verdicts"][0]["symbol"])
        self.assertEqual([{
            "path": "commands.py", "reported_symbol": "run",
            "canonical_symbol": "Runner.run",
        }], result["identity_normalizations"])

    def test_llm_candidate_batch_rejects_ambiguous_short_symbol(self):
        candidates = [
            SemanticCandidate(
                path="commands.py", qualname=f"{owner}.run", start_line=1, end_line=2,
                category="command", score=50, signals=("dynamic-shell-sink",),
                code=f"class {owner}:\n    def run(self, command): ...\n",
            )
            for owner in ("First", "Second")
        ]
        response_body = {
            "choices": [{"message": {"content": json.dumps({"verdicts": [{
                "is_vulnerable": True, "cwe": "CWE-78", "path": "commands.py",
                "symbol": "run", "root_cause": "dynamic shell data", "confidence": 0.8,
                "locally_template_repairable": True,
            }]})}}],
        }
        client = LLMSecurityTriageClient(
            base_url="https://llm.invalid/v1", api_key="secret",
            model="test-model", provider="test",
        )
        with patch(
            "lima.real_world_evaluation.urllib.request.urlopen",
            return_value=Response(json.dumps(response_body).encode()),
        ):
            result = client.triage_candidate_batch(candidates)

        self.assertFalse(result["contract_valid"])
        self.assertIn("verdict-0-invalid-identity", result["contract_errors"])
        self.assertIn("batch-missing-identities", result["contract_errors"])

    def test_oracle_matrix_scores_only_configured_cases(self):
        vulnerable = "d" * 40
        fixed = "e" * 40
        files = {"app.py": "safe = True\n"}
        payloads = {
            vulnerable: archive(vulnerable, files),
            fixed: archive(fixed, files),
        }

        def opener(request, timeout):
            self.assertEqual(90, timeout)
            commit = request.full_url.rsplit("/", 1)[-1]
            return Response(payloads[commit])

        class Oracle:
            def run(self, _kind, root):
                return {
                    "status": "completed",
                    "secure": str(root).endswith(fixed),
                    "diagnostic": "",
                    "duration_ms": 1.0,
                }

        dataset = {
            "name": "test",
            "cases": [{
                "id": "paired", "cve": "CVE-test", "cwe": "CWE-78",
                "repository": "owner/project", "vulnerable_commit": vulnerable,
                "fixed_commit": fixed, "sources": ["https://example.invalid"],
                "oracle": {"kind": "test", "automated": True},
            }],
        }
        with tempfile.TemporaryDirectory() as root:
            evaluator = RealWorldSecurityEvaluator(
                SnapshotStore(root, opener=opener), oracle_runner=Oracle()
            )
            result = evaluator.run_oracle_matrix(dataset)
        self.assertEqual(1.0, result["metrics"]["paired_oracle_pass_rate"])
        self.assertTrue(result["cases"][0]["paired_pass"])


if __name__ == "__main__":
    unittest.main()
