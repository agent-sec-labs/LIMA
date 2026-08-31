import hashlib
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import yaml

ROOT = Path(__file__).parents[1]
SCRIPT_PATH = ROOT / "scripts" / "run_cxx_memory_evaluation.py"
CASES_PATH = ROOT / "evaluation_data" / "cxx_memory_cases.json"
PREPARE_CASE_PATH = ROOT / "scripts" / "prepare_cxx_memory_evaluation_case.py"


def load_evaluation_module():
    spec = importlib.util.spec_from_file_location("cxx_memory_evaluation", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("evaluation module could not be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def valid_case(case_id="owner-project-cve-2026-0001", cwe="CWE-787"):
    return {
        "id": case_id,
        "project": "owner/project",
        "cwe": cwe,
        "vulnerable_commit": "1" * 40,
        "fixed_commit": "2" * 40,
        "archives": {
            "vulnerable": {
                "url": "https://codeload.github.com/owner/project/tar.gz/" + "1" * 40,
                "sha256": "3" * 64,
            },
            "fixed": {
                "url": "https://codeload.github.com/owner/project/tar.gz/" + "2" * 40,
                "sha256": "4" * 64,
            },
        },
        "advisory_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-0001",
        "upstream_fix_url": "https://github.com/owner/project/commit/" + "2" * 40,
        "affected": {"path": "src/memory.c", "symbol": "copy_data"},
        "build_steps": [["cmake", "-S", ".", "-B", "build"], ["cmake", "--build", "build"]],
        "test_steps": [["ctest", "--test-dir", "build", "--output-on-failure"]],
        "selection_rationale": (
            "CVE-2026-0001 names the affected function and the exact upstream fix has one parent."
        ),
        "license": {
            "spdx": "MIT",
            "url": "https://raw.githubusercontent.com/owner/project/" + "2" * 40 + "/LICENSE",
        },
    }


def valid_document(target):
    cases = [target]
    companions = (
        ("owner-project-cve-2026-0002", "CWE-125", "CVE-2026-0002"),
        ("owner-project-cve-2026-0003", "CWE-415", "CVE-2026-0003"),
        ("owner-project-cve-2026-0004", "CWE-416", "CVE-2026-0004"),
    )
    for case_id, cwe, advisory_id in companions:
        if cwe == target["cwe"]:
            continue
        case = valid_case(case_id, cwe)
        case["advisory_url"] = f"https://nvd.nist.gov/vuln/detail/{advisory_id}"
        case["selection_rationale"] = (
            f"{advisory_id} names the affected function and the exact upstream fix has one parent."
        )
        cases.append(case)
    return {"schema_version": 1, "cases": cases}


def tool_run(tool="semgrep", status="completed"):
    return {
        "tool": tool,
        "status": status,
        "returncode": 0 if status == "completed" else None,
        "output_sha256": "a" * 64,
        "output_truncated": False,
        "digests_complete": True,
    }


def analysis(
    findings=(),
    *,
    source_lines=100,
    status="completed",
    elapsed=1.0,
    tool_runs=None,
):
    return {
        "findings": list(findings),
        "tool_runs": list(tool_runs) if tool_runs is not None else [tool_run(status=status)],
        "coverage": {"source_files": 1, "snapshot_files": 1},
        "diagnostics": [],
        "elapsed_seconds": elapsed,
        "timed_out": status == "timed-out",
        "source_lines": source_lines,
        "snapshot_sha256": "b" * 64,
    }


class PublicCaseSchemaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_committed_manifest_has_one_fully_pinned_pair_per_supported_cwe(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        self.module.validate_case_document(document)
        self.assertEqual(1, document["schema_version"])
        self.assertEqual(
            {"CWE-125", "CWE-415", "CWE-416", "CWE-787"},
            {case["cwe"] for case in document["cases"]},
        )
        self.assertEqual(4, len(document["cases"]))

    def test_committed_cwe416_pair_keeps_compile_verification_out_of_runtime_steps(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        case = next(item for item in document["cases"] if item["cwe"] == "CWE-416")

        self.assertEqual("podofo-podofo-cve-2025-9394", case["id"])
        self.assertEqual("podofo/podofo", case["project"])
        self.assertEqual("e002106677a83b85dd8d4717b1be7fac88f9756e", case["vulnerable_commit"])
        self.assertEqual("22d16cb142f293bf956f66a4d399cdd65576d36c", case["fixed_commit"])
        self.assertEqual(
            "2f40ff086b3510f8818eaf503c880c0a68146559a2563ea81e1048d26cada6ba",
            case["archives"]["vulnerable"]["sha256"],
        )
        self.assertEqual(
            "98839065de6c3bfb6fc331e39cf094d0cb407dc86bad17dfc3f050cc9dadee3f",
            case["archives"]["fixed"]["sha256"],
        )
        self.assertEqual(
            {
                "path": "src/podofo/main/PdfTokenizer.cpp",
                "symbol": "PdfTokenizer::DetermineDataType",
            },
            case["affected"],
        )
        object_target = "src/podofo/CMakeFiles/podofo_static.dir/main/PdfTokenizer.cpp.o"
        self.assertEqual("make", case["build_steps"][1][0])
        self.assertIn("-B", case["build_steps"][1])
        self.assertIn(object_target, case["build_steps"][1])
        self.assertEqual([], case["test_steps"])
        self.assertIn("build-verification", case["selection_rationale"])
        self.assertIn("test-resources submodule", case["selection_rationale"])

    def test_schema_accepts_empty_runtime_steps_but_rejects_malformed_values(self):
        case = valid_case()
        case["test_steps"] = []
        self.module.validate_case_document(valid_document(case))

        malformed_values = (
            None,
            "ctest --test-dir build",
            ["ctest", "--test-dir", "build"],
            [[]],
            [["ctest", ""]],
            [["sh", "-c", "ctest --test-dir build"]],
        )
        for value in malformed_values:
            with self.subTest(value=value):
                invalid = valid_case()
                invalid["test_steps"] = value
                with self.assertRaises(ValueError):
                    self.module.validate_case_document(valid_document(invalid))

    def test_schema_rejects_unpinned_non_https_and_shell_shaped_values(self):
        mutations = {
            "short vulnerable commit": lambda item: item.update(vulnerable_commit="abc123"),
            "floating archive": lambda item: item["archives"]["fixed"].update(
                url="https://github.com/owner/project/archive/refs/heads/main.tar.gz"
            ),
            "missing digest": lambda item: item["archives"]["fixed"].update(sha256=""),
            "non-https advisory": lambda item: item.update(
                advisory_url="http://example.test/CVE-1"
            ),
            "shell build step": lambda item: item.update(build_steps=["cmake -S . -B build"]),
            "shell test step": lambda item: item.update(test_steps=[["sh", "-c", "make test"]]),
            "indirect shell wrapper": lambda item: item.update(
                test_steps=[["env", "sh", "-c", "make test"]]
            ),
            "request environment": lambda item: item.update(request_environment={"CC": "clang"}),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = valid_case()
                mutate(case)
                with self.assertRaises(ValueError):
                    self.module.validate_case_document(valid_document(case))

    def test_schema_rejects_placeholder_and_cross_project_provenance(self):
        mutations = {
            "placeholder advisory": lambda item: item.update(
                advisory_url="https://example.test/CVE-2026-0001"
            ),
            "malformed NVD path": lambda item: item.update(
                advisory_url="https://nvd.nist.gov/vuln/detail/not-a-cve"
            ),
            "wrong fix host": lambda item: item.update(
                upstream_fix_url="https://example.test/owner/project/commit/" + "2" * 40
            ),
            "wrong fix project": lambda item: item.update(
                upstream_fix_url="https://github.com/other/project/commit/" + "2" * 40
            ),
            "wrong license host": lambda item: item["license"].update(
                url="https://example.test/owner/project/" + "2" * 40 + "/LICENSE"
            ),
            "wrong license project": lambda item: item["license"].update(
                url="https://raw.githubusercontent.com/other/project/" + "2" * 40 + "/LICENSE"
            ),
            "wrong license commit": lambda item: item["license"].update(
                url="https://raw.githubusercontent.com/owner/project/" + "1" * 40 + "/LICENSE"
            ),
            "case id mismatch": lambda item: item.update(id="owner-project-cve-2026-9999"),
            "rationale mismatch": lambda item: item.update(
                selection_rationale=(
                    "CVE-2026-9999 names the affected function and the fix has one parent."
                )
            ),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                case = valid_case()
                mutate(case)
                with self.assertRaises(ValueError):
                    self.module.validate_case_document(valid_document(case))

    def test_archive_commit_in_each_url_matches_the_corresponding_exact_commit(self):
        case = valid_case()
        case["archives"]["fixed"]["url"] = (
            "https://codeload.github.com/owner/project/tar.gz/" + "1" * 40
        )
        with self.assertRaisesRegex(ValueError, "archive URL.*commit"):
            self.module.validate_case_document({"schema_version": 1, "cases": [case]})

    def test_schema_version_rejects_json_boolean_even_though_bool_equals_one(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        document["schema_version"] = True
        with self.assertRaises(ValueError):
            self.module.validate_case_document(document)


class MetricTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_metrics_count_tp_fp_fn_tn_pairs_layers_kloc_timeouts_and_elapsed(self):
        first = valid_case("first", "CWE-787")
        second = valid_case("second", "CWE-125")
        first_hit = {
            "cwe": "CWE-787",
            "path": "src/memory.c",
            "symbol": "copy_data",
            "analysis_mode": "source-only",
        }
        results = {
            ("first", "vulnerable"): analysis([first_hit], source_lines=120, elapsed=1.0),
            ("first", "fixed"): analysis([first_hit], source_lines=100, elapsed=2.0),
            ("second", "vulnerable"): analysis(source_lines=220, status="timed-out", elapsed=3.0),
            ("second", "fixed"): analysis(source_lines=300, elapsed=4.0),
        }

        report = self.module.run_evaluation(
            [first, second], lambda case, revision: results[(case["id"], revision)]
        )

        self.assertEqual({"tp": 1, "fp": 1, "fn": 1, "tn": 1}, report["confusion_matrix"])
        self.assertEqual(0.5, report["precision"])
        self.assertEqual(0.5, report["recall"])
        self.assertEqual(0.5, report["f1"])
        self.assertEqual(0.0, report["pair_accuracy"])
        self.assertEqual(2.5, report["false_positives_per_kloc"])
        self.assertEqual(2, report["layer_counts"]["source-only"])
        self.assertEqual(0.75, report["layer_coverage"]["source-only"])
        self.assertEqual(0.25, report["timeout_rate"])
        self.assertEqual(10.0, report["elapsed_seconds"]["total"])
        self.assertEqual(2.5, report["elapsed_seconds"]["mean"])
        self.assertIsNone(report["build_success_rate"])
        self.assertIn("build_success_rate denominator is zero", report["diagnostics"])

    def test_zero_denominators_are_null_with_diagnostics_not_perfect_scores(self):
        report = self.module.run_evaluation([], lambda case, revision: None)
        for key in (
            "precision",
            "recall",
            "f1",
            "pair_accuracy",
            "false_positives_per_kloc",
            "build_success_rate",
            "timeout_rate",
        ):
            self.assertIsNone(report[key])
        self.assertGreaterEqual(len(report["diagnostics"]), 7)

    def test_mixed_required_runs_do_not_count_as_completed_layers_or_builds(self):
        case = valid_case("mixed", "CWE-787")
        mixed_runs = [
            tool_run("semgrep", "completed"),
            tool_run("semgrep", "failed"),
            tool_run("build-step", "completed"),
            tool_run("build-step", "build_failed"),
            tool_run("clang", "completed"),
            tool_run("asan-test", "completed"),
            tool_run("asan-test", "timed-out"),
        ]
        result = analysis(tool_runs=mixed_runs)
        result["timed_out"] = True

        report = self.module.run_evaluation([case], lambda _case, _revision: result)

        self.assertEqual(
            {
                "source-only": 0.0,
                "build-backed": 0.0,
                "sanitizer-confirmed": 0.0,
            },
            report["layer_coverage"],
        )
        self.assertEqual(0.0, report["build_success_rate"])
        self.assertEqual(1.0, report["timeout_rate"])

    def test_unconfigured_runtime_sanitizer_does_not_count_as_completed_coverage(self):
        case = valid_case("podofo-podofo-cve-2025-9394", "CWE-416")
        completed_compile_only_result = analysis(
            tool_runs=[
                tool_run("semgrep", "completed"),
                tool_run("build-step", "completed"),
                tool_run("clang", "completed"),
            ]
        )
        completed_compile_only_result["diagnostics"] = ["sanitizer-not-configured"]

        report = self.module.run_evaluation(
            [case], lambda _case, _revision: completed_compile_only_result
        )
        vulnerable = report["cases"][0]["revisions"]["vulnerable"]

        self.assertEqual(0.0, report["layer_coverage"]["sanitizer-confirmed"])
        self.assertFalse(vulnerable["layer_completed"]["sanitizer-confirmed"])
        self.assertNotIn("asan-test", {run["tool"] for run in vulnerable["tool_runs"]})

    def test_revision_records_recompute_every_aggregate_metric(self):
        case = valid_case("audit", "CWE-787")
        hit = {
            "cwe": "CWE-787",
            "path": "src/memory.c",
            "symbol": "copy_data",
            "analysis_mode": "source-only",
        }
        results = {
            "vulnerable": analysis(
                [hit],
                source_lines=80,
                elapsed=1.25,
                tool_runs=[tool_run("semgrep"), tool_run("build-step"), tool_run("clang")],
            ),
            "fixed": analysis(
                [hit],
                source_lines=200,
                elapsed=2.75,
                tool_runs=[tool_run("semgrep"), tool_run("build-step"), tool_run("clang")],
            ),
        }

        report = self.module.run_evaluation([case], lambda _case, revision: results[revision])
        revisions = report["cases"][0]["revisions"]
        records = list(revisions.values())
        confusion = {"tp": 0, "fp": 0, "fn": 0, "tn": 0}
        for record in records:
            expected = record["expected_vulnerable"]
            predicted = record["predicted_vulnerable"]
            confusion[
                "tp"
                if expected and predicted
                else "fn"
                if expected
                else "fp"
                if predicted
                else "tn"
            ] += 1
        self.assertEqual(report["confusion_matrix"], confusion)
        self.assertEqual(
            report["false_positives_per_kloc"],
            sum(
                record["target_finding_count"] * 1000
                for record in records
                if not record["expected_vulnerable"]
            )
            / sum(
                record["source_lines"] for record in records if not record["expected_vulnerable"]
            ),
        )
        for mode in self.module.ANALYSIS_MODES:
            self.assertEqual(
                report["layer_counts"][mode],
                sum(record["layer_finding_counts"][mode] for record in records),
            )
            self.assertEqual(
                report["layer_coverage"][mode],
                sum(record["layer_completed"][mode] for record in records) / len(records),
            )
        attempted = [record for record in records if record["build_attempted"]]
        self.assertEqual(
            report["build_success_rate"],
            sum(record["build_completed"] for record in attempted) / len(attempted),
        )
        self.assertEqual(
            report["timeout_rate"],
            sum(record["timed_out"] for record in records) / len(records),
        )
        self.assertEqual(
            report["elapsed_seconds"]["total"],
            sum(record["elapsed_seconds"] for record in records),
        )
        for record in records:
            self.assertEqual(
                {
                    "expected_vulnerable",
                    "predicted_vulnerable",
                    "target_identity",
                    "target_finding_count",
                    "snapshot_sha256",
                    "source_lines",
                    "layer_finding_counts",
                    "layer_completed",
                    "build_attempted",
                    "build_completed",
                    "timed_out",
                    "elapsed_seconds",
                    "tool_runs",
                    "coverage",
                    "diagnostics",
                },
                set(record),
            )

    def test_analysis_result_rejects_extra_or_unbounded_audit_fields(self):
        case = valid_case("strict-result", "CWE-787")
        mutations = {
            "extra field": lambda item: item.update(raw_log="secret"),
            "object diagnostic": lambda item: item.update(diagnostics=[{"path": "/private/x"}]),
            "missing snapshot": lambda item: item.pop("snapshot_sha256"),
        }
        for label, mutate in mutations.items():
            with self.subTest(label=label):
                result = analysis()
                mutate(result)
                with self.assertRaises(ValueError):
                    self.module.run_evaluation(
                        [case], lambda _case, _revision, result=result: result
                    )

    def test_sidecar_result_carries_the_analyzed_snapshot_fingerprint(self):
        class Inventory:
            def fingerprint(self):
                return "c" * 64

        class Workspace:
            def __init__(self, source_root):
                self.source_root = source_root

            def inventory(self):
                return Inventory()

        class Result:
            findings = []
            tool_runs = [tool_run()]
            coverage = {"source_files": 1, "snapshot_files": 1}
            diagnostics = []

        class Client:
            def __init__(self, *args, **kwargs):
                pass

            def analyze(
                self, repository_key, snapshot_sha256, requested_layers, *, inventory
            ):
                self.request = (
                    repository_key,
                    snapshot_sha256,
                    requested_layers,
                    inventory,
                )
                return Result()

        with (
            mock.patch.object(self.module, "RepositoryWorkspace", Workspace),
            mock.patch.object(self.module, "CxxMemoryAnalyzerClient", Client),
            mock.patch.object(self.module, "_source_line_count", return_value=12),
        ):
            result = self.module._sidecar_result(
                "http://sidecar:8090", "repository", Path("repository")
            )

        self.assertEqual("c" * 64, result["snapshot_sha256"])


class ArchiveSafetyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    @staticmethod
    def archive_with(member):
        stream = io.BytesIO()
        with tarfile.open(fileobj=stream, mode="w:gz") as archive:
            if member.isfile():
                payload = b"int main(void) { return 0; }\n"
                member.size = len(payload)
                archive.addfile(member, io.BytesIO(payload))
            else:
                archive.addfile(member)
        return stream.getvalue()

    def test_verified_regular_archive_extracts_under_one_project_root(self):
        member = tarfile.TarInfo("project-commit/src/main.c")
        raw = self.archive_with(member)
        digest = hashlib.sha256(raw).hexdigest()
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "case.tar.gz"
            destination = Path(temporary) / "out"
            archive.write_bytes(raw)
            project_root = self.module.extract_verified_archive(archive, digest, destination)
            self.assertEqual(destination / "project-commit", project_root)
            self.assertTrue((project_root / "src" / "main.c").is_file())

    def test_extraction_rejects_traversal_absolute_links_and_special_files(self):
        members = []
        for name in ("../escape.c", "/absolute.c", "C:/windows.c", "root\\escape.c"):
            members.append(tarfile.TarInfo(name))
        symbolic = tarfile.TarInfo("root/link")
        symbolic.type = tarfile.SYMTYPE
        symbolic.linkname = "../outside"
        members.append(symbolic)
        hard = tarfile.TarInfo("root/hard")
        hard.type = tarfile.LNKTYPE
        hard.linkname = "root/file"
        members.append(hard)
        special = tarfile.TarInfo("root/device")
        special.type = tarfile.CHRTYPE
        members.append(special)

        for member in members:
            with self.subTest(name=member.name, type=member.type):
                raw = self.archive_with(member)
                with tempfile.TemporaryDirectory() as temporary:
                    archive = Path(temporary) / "case.tar.gz"
                    archive.write_bytes(raw)
                    with self.assertRaises(ValueError):
                        self.module.extract_verified_archive(
                            archive, hashlib.sha256(raw).hexdigest(), Path(temporary) / "out"
                        )

    def test_hash_mismatch_is_rejected_before_destination_is_created(self):
        member = tarfile.TarInfo("root/main.c")
        raw = self.archive_with(member)
        with tempfile.TemporaryDirectory() as temporary:
            archive = Path(temporary) / "case.tar.gz"
            destination = Path(temporary) / "out"
            archive.write_bytes(raw)
            with self.assertRaisesRegex(ValueError, "SHA-256"):
                self.module.extract_verified_archive(archive, "0" * 64, destination)
            self.assertFalse(destination.exists())

    def test_download_rejects_an_https_url_that_redirects_to_plain_http(self):
        class RedirectedResponse(io.BytesIO):
            def geturl(self):
                return "http://mirror.example.test/archive.tar.gz"

        class StaticOpener:
            def open(self, request, timeout):
                return RedirectedResponse(raw)

        raw = b"archive bytes"
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "archive.tar.gz"
            with mock.patch.object(
                self.module.urllib.request,
                "build_opener",
                return_value=StaticOpener(),
            ):
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    self.module.download_verified_archive(
                        "https://example.test/archive.tar.gz",
                        hashlib.sha256(raw).hexdigest(),
                        destination,
                    )
            self.assertFalse(destination.exists())

    def test_redirect_handler_rejects_an_intermediate_http_hop(self):
        class FinalHttpsResponse(io.BytesIO):
            def geturl(self):
                return "https://example.test/final.tar.gz"

        raw = b"archive bytes"

        def build_opener(handler):
            request = self.module.urllib.request.Request("https://example.test/archive.tar.gz")
            handler.redirect_request(
                request,
                None,
                302,
                "Found",
                {},
                "http://mirror.example.test/intermediate.tar.gz",
            )
            self.fail("the insecure intermediate redirect was followed")

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "archive.tar.gz"
            with (
                mock.patch.object(
                    self.module.urllib.request,
                    "build_opener",
                    side_effect=build_opener,
                ),
                mock.patch.object(
                    self.module.urllib.request,
                    "urlopen",
                    return_value=FinalHttpsResponse(raw),
                ),
            ):
                with self.assertRaisesRegex(ValueError, "HTTPS"):
                    self.module.download_verified_archive(
                        "https://example.test/archive.tar.gz",
                        hashlib.sha256(raw).hexdigest(),
                        destination,
                    )
            self.assertFalse(destination.exists())

    def test_download_enforces_total_wall_clock_deadline_and_cleans_partial(self):
        class Socket:
            def settimeout(self, value):
                self.value = value

        class Raw:
            def __init__(self):
                self._sock = Socket()

        class Fp:
            def __init__(self):
                self.raw = Raw()

        class SlowResponse(io.BytesIO):
            def __init__(self, raw):
                super().__init__(raw)
                self.fp = Fp()

            def geturl(self):
                return "https://example.test/archive.tar.gz"

        class StaticOpener:
            def __init__(self, response):
                self.response = response

            def open(self, request, timeout):
                return self.response

        raw = b"archive bytes"
        response = SlowResponse(raw)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "archive.tar.gz"
            with (
                mock.patch.object(
                    self.module.urllib.request,
                    "build_opener",
                    return_value=StaticOpener(response),
                ),
                mock.patch.object(
                    self.module.urllib.request,
                    "urlopen",
                    return_value=response,
                ),
                mock.patch.object(
                    self.module.time,
                    "monotonic",
                    side_effect=(10.0, 10.0, 10.0, 16.0),
                ),
                mock.patch.object(self.module, "_DOWNLOAD_DEADLINE_SECONDS", 5.0),
            ):
                with self.assertRaisesRegex(TimeoutError, "deadline"):
                    self.module.download_verified_archive(
                        "https://example.test/archive.tar.gz",
                        hashlib.sha256(raw).hexdigest(),
                        destination,
                    )
            self.assertFalse(destination.exists())
            self.assertFalse(destination.with_suffix(".gz.part").exists())


class CliAndCiContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.module = load_evaluation_module()

    def test_cli_exposes_only_the_six_fixed_parameters(self):
        parser = self.module.build_parser()
        options = {
            option
            for action in parser._actions
            for option in action.option_strings
            if option not in {"-h", "--help"}
        }
        self.assertEqual(
            {
                "--cases",
                "--cache-dir",
                "--output",
                "--analyzer-url",
                "--analyzer-image-digest",
                "--fail-under-precision",
            },
            options,
        )

    def test_report_metadata_records_digest_hash_and_required_validity_boundary(self):
        raw = b'{"schema_version":1,"cases":[]}'
        digest = "sha256:" + "a" * 64
        report = self.module.add_report_metadata(
            {"precision": None}, raw, analyzer_image_digest=digest
        )
        self.assertEqual(hashlib.sha256(raw).hexdigest(), report["case_data_sha256"])
        self.assertEqual(digest, report["analyzer_image_digest"])
        with self.assertRaises(ValueError):
            self.module.add_report_metadata(
                {"precision": None}, raw, analyzer_image_digest=None
            )
        self.assertIn(
            "合成和固定样本结果不代表真实项目完整检测能力",
            report["validity_boundaries"],
        )

    def test_trusted_case_preparer_emits_exact_argv_json_without_shell_evaluation(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        selected = document["cases"][0]
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "github-output"
            completed = subprocess.run(  # noqa: S603 - argv is fixed test input.
                [
                    sys.executable,
                    str(PREPARE_CASE_PATH),
                    "--cases",
                    str(CASES_PATH),
                    "--case-id",
                    selected["id"],
                    "--github-output",
                    str(output),
                ],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(0, completed.returncode, completed.stderr)
            values = dict(
                line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines()
            )
        self.assertEqual(selected["id"], values["case_id"])
        self.assertEqual(selected["build_steps"], json.loads(values["build_steps_json"]))
        self.assertEqual(selected["test_steps"], json.loads(values["test_steps_json"]))

    def test_case_selection_requires_an_exact_committed_identifier(self):
        document = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        selected = self.module.select_evaluation_cases(document, document["cases"][0]["id"])
        self.assertEqual([document["cases"][0]], selected)
        with self.assertRaisesRegex(ValueError, "case id"):
            self.module.select_evaluation_cases(document, "missing-case")

    def test_ci_keeps_cross_platform_matrix_and_adds_isolated_sidecar_gates(self):
        workflow = yaml.safe_load(
            (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
        )
        events = workflow[True]
        self.assertIn("pull_request", events)
        self.assertIn("workflow_dispatch", events)
        self.assertIn("schedule", events)
        matrix = workflow["jobs"]["unit-tests"]["strategy"]["matrix"]
        self.assertEqual({"ubuntu-latest", "windows-latest"}, set(matrix["os"]))
        self.assertEqual({"3.11", "3.12"}, set(matrix["python-version"]))

        sidecar = workflow["jobs"]["cxx-sidecar-integration"]
        commands = "\n".join(
            step.get("run", "") for step in sidecar["steps"] if isinstance(step, dict)
        )
        self.assertIn("docker network create --internal", commands)
        self.assertIn("SourceScanContainerTests", commands)
        self.assertIn("BuildScanContainerTests", commands)
        self.assertIn("SanitizerContainerTests", commands)
        self.assertIn("--network none", commands)
        self.assertIn("--read-only", commands)
        self.assertIn("--cap-drop ALL", commands)
        self.assertNotIn("/var/run/docker.sock", commands)
        self.assertNotRegex(commands, r"(?:^|\s)-p\s|--publish")

        public = workflow["jobs"]["public-cxx-memory-evaluation"]
        manifest = json.loads(CASES_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            {case["id"] for case in manifest["cases"]},
            set(public["strategy"]["matrix"]["case-id"]),
        )
        public_commands = "\n".join(
            step.get("run", "") for step in public["steps"] if isinstance(step, dict)
        )
        self.assertIn("prepare_cxx_memory_evaluation_case.py", public_commands)
        self.assertIn("--env LIMA_CXX_BUILD_STEPS_JSON", public_commands)
        self.assertIn("--env LIMA_CXX_TEST_STEPS_JSON", public_commands)
        self.assertIn("--env LIMA_CXX_EVALUATION_CASE_ID", public_commands)
        self.assertNotIn("steps.case.outputs.build_steps_json", public_commands)


if __name__ == "__main__":
    unittest.main()
