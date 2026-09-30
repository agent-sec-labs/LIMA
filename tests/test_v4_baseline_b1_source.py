"""Frozen acceptance tests for IP-0040: B1 machine source wiring (Issue #249).

Contract under test (frozen by Coordinator Assignment CA-IP-0040-v1.0 of
2026-09-30; see docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md
sections 7-10):

- The Implementation deliverable is ``benchmarks/v4/baseline/b1_source.py``:
  the formal B1 entry ``run_b1_source_baseline_suite`` (all keyword-only:
  output_dir / machine_profile / fixture_key / seed / cold_count / warm_count /
  workload / transport / manifest_path / sources) that materializes a frozen
  synthetic fixture into an internal temporary workspace, scans it with the
  real local ``RepositoryScanner`` under the explicit offline configuration
  (SAST / C++ memory / platform-agent / LLM factories all disabled, never
  environment defaults), drives 3 cold + 5 warm attempts through the frozen
  ``run_baseline_attempt``/``result_from_mapping``/``write_result_file``
  primitives, projects the report through the frozen
  ``build_baseline_report(kind="scanner")`` path (no bundle, no domain block),
  and writes per-attempt ``source_receipt`` documents plus a closed-key
  ``b1-manifest.json`` aggregated by ``source_receipts_digest``; the read-back
  entry ``verify_b1_evidence`` cross-checks the receipt/manifest/report
  bindings and fails closed with typed ``B1SourceError`` codes
  (B1_OUTPUT_NOT_EMPTY / SOURCE_RECEIPT_INVALID / SOURCE_BINDING_MISMATCH /
  SCANNER_DIGEST_MISMATCH).
- The per-field source contract (Packet 7.2): raw_candidates is the scanner
  output findings count at the merged/deduplicated level, the deterministic
  ladder partitions along the frozen five-state closed vocabulary, scanned
  files / coverage gap are measured, signals / security issues stay
  legacy_projection (one Signal + one SecurityIssue per legacy Finding),
  hypotheses / vep / rvr / stage_outcome / resources stay null +
  unavailable, and the scanner source digest is the frozen fingerprint of
  ``{**report.to_dict(), "workspace": inventory.to_dict()}``.
- Boundary discipline (Packet 7.7): docs-content / test-heavy / signal-storm
  samples, findings above the twelve-file request-construction cap are never
  truncated in the report counts, malicious-layout is scanned statically
  (zero repository-code execution, no out-of-bounds writes), and
  dependency-blocked keeps its honest inventory faces; a real complete
  zero-finding scan stays distinguishable from parse-failure / truncation
  faces.
- Old-path anchors (Packet 7.8): the frozen ``run_real_baseline_suite``
  signature, the eleven-key artifact family, the locked real-run gate, the
  frozen candidate cap, and this packet's repository/container copy line.

Everything here is offline and deterministic: fixtures materialize into temp
directories, the scanner runs with the explicit offline configuration, the
model layer is only ever an injected fake transport (zero real POST), and no
test ever touches a network socket, reads the environment, or sleeps.

Expected RED before implementation: sixteen methods fail on the missing
deliverable -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.b1_source'``
(lazy per-test import); the frozen-face groups inside the three-state and
zero-finding methods (built directly on the frozen report/scanner modules)
pass by design and are recorded in the RED evidence, as do the three
old-path anchor methods and the packet-document probe; the PC1 method's
self-scan group passes while its product-source group fails on the absent
file (split attribution).  The pre-freeze baseline runs of the frozen files
(112 / 47 / 322 green, discover 2728 OK with 24 skips) are archived
alongside the RED log.
"""

import ast
import hashlib
import inspect
import json
import pathlib
import re
import tempfile
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_B1_RELATIVE_PATH = "benchmarks/v4/baseline/b1_source.py"
_PACKET_RELATIVE_PATH = "docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md"
_DOCKERFILE_RELATIVE_PATH = "Dockerfile"
_PACKET_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0040_B1_Source_"
    "Wiring.md ./docs/"
)

#: The B1 workload label (Packet 7.4 / R4): it enters the run identity face.
_WORKLOAD = "b1-offline-scanner-v1"
#: The frozen request-construction parameter (value pinned, never changed).
_CANDIDATE_FILE_CAP = 12

#: Transcribed verbatim from lima.repository_scanner.COVERAGE_AFFECTING_SKIPS
#: (read-only consumption mirror, PC3 dual-source against the product value).
_COVERAGE_AFFECTING_SKIPS = frozenset(
    {
        "symlink",
        "unreadable",
        "file-size-limit",
        "file-limit",
        "total-size-limit",
        "binary",
        "non-utf8",
    }
)

#: Transcribed verbatim from benchmarks/v4/baseline/report.py
#: ``_VERIFICATION_STATES`` (the frozen five-state closed vocabulary; the
#: scanner's nine-state rank ladder is the wider production set, and any
#: off-vocabulary state reaching the report fails closed).
_REPORT_VERIFICATION_STATES = frozenset(
    {"candidate", "syntax-verified", "corroborated", "dataflow-verified", "confirmed"}
)
_DETERMINISTIC_STATES = frozenset(
    {"corroborated", "dataflow-verified", "confirmed"}
)
_INCONCLUSIVE_STATES = frozenset({"candidate", "syntax-verified"})
#: One state inside the scanner ladder but outside the frozen report
#: vocabulary (the off-vocabulary fail-closed arrange).
_OFF_VOCABULARY_STATE = "runtime-confirmed"

#: The frozen source_receipt key set (Packet 7.6.3; sixteen keys, the R4
#: floor merged with the dispatch list, semantics never shrunk).
_RECEIPT_KEYS = frozenset(
    {
        "snapshot_tree_sha256",
        "fixture_key",
        "fixture_manifest_sha256",
        "analyzer_name",
        "analyzer_fingerprint",
        "scanner_config_sha256",
        "seed",
        "workload",
        "run_spec_digest",
        "attempt_index",
        "mode",
        "scanner_payload_sha256",
        "scanner_reexecuted",
        "scanner_result_reused",
        "snapshot_reused",
        "request_body_rebuilt",
    }
)

#: The frozen b1-manifest key set (Packet 7.6.3; closed).
_B1_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "workload",
        "run_spec_digest",
        "attempt_count",
        "cold_count",
        "warm_count",
        "fixture_key",
        "fixture_manifest_sha256",
        "snapshot_tree_sha256",
        "analyzer_name",
        "analyzer_fingerprint",
        "scanner_config",
        "scanner_config_sha256",
        "seed",
        "scanner_payload_sha256",
        "source_receipts",
        "source_receipts_digest",
        "failures",
        "transport_calls",
        "model_calls",
        "declarations",
    }
)

#: The frozen four-code typed error family (Packet 7.6.3 / DR-IP-0040-PV-9).
_B1_ERROR_CODES = frozenset(
    {
        "B1_OUTPUT_NOT_EMPTY",
        "SOURCE_RECEIPT_INVALID",
        "SOURCE_BINDING_MISMATCH",
        "SCANNER_DIGEST_MISMATCH",
    }
)

_NOMINAL_MACHINE_PROFILE = {
    "profile_id": "lima-baseline-profile-001",
    "cpu_arch": "x86_64",
    "cpu_model": "declared-baseline-cpu",
    "cores": 8,
    "ram_gb": 32,
    "os_family": "linux",
    "python_version": "3.12.4",
    "gpu_summary": "none",
}

#: Old-path static anchors (transcribed from the frozen v9' test file; the
#: B1 leaf must not move any of these surfaces).
_ENTRY_PARAM_ORDER = (
    "approval_path",
    "api_key",
    "output_root",
    "spec_mapping",
    "transport",
    "timeout_seconds",
    "manifest_path",
    "sources",
    "artifact_key",
)
_ENTRY_KEYWORD_ONLY = frozenset(
    {
        "output_root",
        "spec_mapping",
        "transport",
        "timeout_seconds",
        "manifest_path",
        "sources",
        "artifact_key",
    }
)
_DEFAULT_ARTIFACT_KEY = "external/llamafactory-replay"
_REAL_RUN_ALL = (
    "APPROVAL_COMPLETION_PRICE_MICRO_USD_PER_MILLION",
    "APPROVAL_PROMPT_PRICE_MICRO_USD_PER_MILLION",
    "RealRunError",
    "RealRunErrorCode",
    "RealSuiteResult",
    "run_real_baseline_suite",
)
_ARTIFACT_FAMILY_KEYS = frozenset(
    {
        "archetype/application",
        "archetype/library",
        "archetype/cli",
        "archetype/docs-content",
        "archetype/test-heavy",
        "archetype/monorepo",
        "archetype/large-repo",
        "archetype/malicious-layout",
        "archetype/dependency-blocked",
        "external/llamafactory-replay",
        "real-pilot/large-repo",
    }
)
_OFFLINE_FLOW_ALL = (
    "EvaluatorOutcome",
    "FakeEvaluator",
    "OfflineSuiteResult",
    "make_fake_evaluator",
    "run_offline_baseline_suite",
    "synthetic_call_usage",
    "synthetic_e2e_payload",
    "write_synthetic_marker",
)

_SECRET_KEY_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{16,}")
_HEX64_SHAPE = re.compile(r"^[0-9a-f]{64}$")
_REPORT_DECLARATIONS = ("baseline_mode_legacy_report_parameters_inert",)

_INERT_HEADER = (
    "# SYNTHETIC INERT BASELINE FIXTURE -- NOT A REAL VULNERABILITY\n"
)


def _forbidden_network_roots():
    """First-level import roots these offline tests must never use."""
    return {"sock" + "et", "url" + "lib", "requ" + "ests", "http"}


def _import_roots(source):
    """First-level import roots of a python source string (AST parse, no exec)."""
    tree = ast.parse(source)
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


class _CountingTransport:
    """The injected fake transport: records requests, never touches a network."""

    def __init__(self):
        self.calls = 0
        self.requests = []

    def __call__(self, request):
        self.calls += 1
        self.requests.append(request)
        return {"synthetic": True}


class _B1SourceTestCase(unittest.TestCase):
    """Shared arrange helpers (all product imports are lazy per test)."""

    def b1(self):
        import benchmarks.v4.baseline.b1_source as module

        return module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def machine_profile(self):
        return dict(_NOMINAL_MACHINE_PROFILE)

    def run_suite(self, output_dir, **overrides):
        module = self.b1()
        options = {"output_dir": output_dir, "machine_profile": self.machine_profile()}
        options.update(overrides)
        return module.run_b1_source_baseline_suite(**options)

    def materialize(self, key, parent):
        from benchmarks.v4.baseline.fixtures import materialize_fixture

        return materialize_fixture(key, pathlib.Path(parent) / "fixture")

    def registry_fingerprint(self, key):
        from benchmarks.v4.baseline.fixtures import load_registry

        for entry in load_registry()["fixtures"]:
            if entry["key"] == key:
                return entry["fingerprint"]
        raise AssertionError(f"fixture key absent from registry: {key}")

    def direct_scan(self, root):
        """The real local scanner under the frozen explicit offline config."""
        from lima.repository_scanner import RepositoryScanner
        from lima.workspace import RepositoryWorkspace

        scanner = RepositoryScanner(
            sast_mode="off",
            sast_adapters=[],
            cxx_memory_mode="off",
            cxx_memory_adapter=None,
            cxx_agent_mode="off",
            cxx_agent_budget_factory=None,
            cxx_uaf_llm_factory=None,
            dataflow_enabled=True,
        )
        workspace = RepositoryWorkspace(
            root,
            max_files=5000,
            max_file_bytes=512 * 1024,
            max_total_bytes=20 * 1024 * 1024,
        )
        return scanner.scan(workspace)

    def scanner_wire_digest(self, scan_result, fixture_key):
        """Independent mirror of the frozen scanner fingerprint rule (PC3).

        The wire is canonicalized exactly like the product's
        ``_canonical_payload`` rule (NFR-01/AC-2 path independence): the
        materialization-path dependent ``repository`` and ``workspace.root``
        labels are replaced by the fixture key before hashing, so the
        mirrored fingerprint is a pure function of snapshot content and
        analyzer configuration, not of the tempdir.
        """
        wire = {
            **scan_result.report.to_dict(),
            "workspace": scan_result.inventory.to_dict(),
        }
        wire["repository"] = fixture_key
        wire["workspace"] = {**wire["workspace"], "root": fixture_key}
        encoded = json.dumps(
            wire,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def expected_faces(self, scan_result, fixture_key):
        """Direct-scanner-output recomputation of every reported count (PC3)."""
        findings = scan_result.report.findings
        states = [finding.verification_state for finding in findings]
        skipped = scan_result.report.collaboration["skipped"]
        reasons = {
            reason: count
            for reason, count in sorted(skipped.items())
            if reason in _COVERAGE_AFFECTING_SKIPS and count > 0
        }
        return {
            "raw_candidates": len(findings),
            "deterministic_alerts": sum(
                1 for state in states if state in _DETERMINISTIC_STATES
            ),
            "confirmed": sum(1 for state in states if state == "confirmed"),
            "inconclusive": sum(
                1 for state in states if state in _INCONCLUSIVE_STATES
            ),
            "scanned_files": scan_result.report.collaboration["scanned_files"],
            "coverage_gap": sum(reasons.values()),
            "coverage_gap_reasons": reasons,
            "signals": len(findings),
            "security_issues": len(findings),
            "scanner_digest": self.scanner_wire_digest(scan_result, fixture_key),
        }

    def read_json(self, path):
        return json.loads(pathlib.Path(path).read_bytes().decode("utf-8"))

    def report_of(self, result):
        return self.read_json(result.report_path)

    def manifest_of(self, output_dir):
        return self.read_json(pathlib.Path(output_dir) / "b1-manifest.json")

    def receipts_of(self, output_dir):
        directory = pathlib.Path(output_dir) / "b1-attempts"
        paths = sorted(directory.glob("attempt-*.json"))
        self.assertTrue(paths, "no b1 attempt documents were written")
        return [self.read_json(path)["source_receipt"] for path in paths]

    def content_digest(self, value):
        from lima.contracts.codec import compute_content_digest

        return compute_content_digest(value)


class TestB1EntryFullChain(_B1SourceTestCase):
    """Cluster 1 (Packet 9.1 M1/M2): the formal B1 entry full chain."""

    def test_b1_entry_full_chain_from_empty_directory(self):
        self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output)
            # RunResult artifacts: eight per-attempt files plus the aggregate.
            self.assertEqual(result.attempt_count, 8)
            self.assertEqual(len(result.result_paths), 8)
            for path in result.result_paths:
                self.assertTrue(path.is_file())
            self.assertTrue(result.aggregate_path.is_file())
            self.assertTrue(pathlib.Path(result.report_path).is_file())
            # Report: exactly one scanner source, digest reproducible from an
            # independently materialized and scanned fixture (PC3).
            report = self.report_of(result)
            self.assertEqual(report["run_spec_digest"], result.run_spec_digest)
            self.assertEqual(
                [source["kind"] for source in report["sources"]], ["scanner"]
            )
            materialization = self.materialize(
                "archetype/minimal-python-repository",
                pathlib.Path(temporary) / "direct",
            )
            scan = self.direct_scan(materialization.root)
            self.assertEqual(
                report["sources"][0]["payload_sha256"],
                self.scanner_wire_digest(
                    scan, "archetype/minimal-python-repository"
                ),
            )
            # Receipts: one per attempt, all carrying the suite digest.
            receipts = self.receipts_of(output)
            self.assertEqual(len(receipts), 8)
            for receipt in receipts:
                self.assertEqual(receipt["run_spec_digest"], result.run_spec_digest)
            # Manifest: the explicit offline configuration, digest-bound.
            manifest = self.manifest_of(output)
            config = manifest["scanner_config"]
            frozen_scanner = config["scanner"]
            self.assertEqual(frozen_scanner["sast_mode"], "off")
            self.assertEqual(frozen_scanner["sast_adapters"], [])
            self.assertEqual(frozen_scanner["cxx_memory_mode"], "off")
            self.assertIsNone(frozen_scanner["cxx_memory_adapter"])
            self.assertEqual(frozen_scanner["cxx_agent_mode"], "off")
            self.assertIsNone(frozen_scanner["cxx_agent_budget_factory"])
            self.assertIsNone(frozen_scanner["cxx_uaf_llm_factory"])
            self.assertTrue(frozen_scanner["dataflow_enabled"])
            self.assertEqual(
                manifest["scanner_config_sha256"],
                self.content_digest(config),
            )
            self.assertEqual(manifest["workload"], _WORKLOAD)
            self.assertEqual(manifest["model_calls"], 0)
            self.assertEqual(manifest["failures"], [])
            # Result faces: the offline marker constants and identity faces.
            self.assertTrue(result.b1)
            self.assertEqual(result.model_calls, 0)
            self.assertEqual(result.workload, _WORKLOAD)
            self.assertEqual(result.fixture_key, "archetype/minimal-python-repository")
            self.assertEqual(
                result.snapshot_tree_sha256,
                self.registry_fingerprint("archetype/minimal-python-repository"),
            )
            self.assertTrue(_HEX64_SHAPE.match(result.scanner_payload_sha256))
            self.assertTrue(_HEX64_SHAPE.match(result.source_receipts_digest))

    def test_b1_counts_match_direct_scanner_output(self):
        self.b1()
        key = "archetype/signal-storm"
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key=key)
            materialization = self.materialize(key, pathlib.Path(temporary) / "direct")
            scan = self.direct_scan(materialization.root)
            faces = self.expected_faces(scan, key)
            self.assertGreater(faces["raw_candidates"], _CANDIDATE_FILE_CAP)
            report = self.report_of(result)
            chain = report["compression_chain"]
            self.assertEqual(chain["raw_candidates"], faces["raw_candidates"])
            self.assertEqual(
                chain["deterministic_alerts"], faces["deterministic_alerts"]
            )
            self.assertEqual(chain["confirmed"], faces["confirmed"])
            self.assertEqual(chain["inconclusive"], faces["inconclusive"])
            self.assertEqual(
                chain["raw_candidates"],
                chain["deterministic_alerts"] + chain["inconclusive"],
            )
            # Ratio links: floor basis points, zero denominator keeps counts
            # and yields a null ratio (never zero).
            self.assertEqual(
                chain["candidates_to_deterministic"],
                {
                    "numerator": faces["deterministic_alerts"],
                    "denominator": faces["raw_candidates"],
                    "ratio_basis_points": (
                        faces["deterministic_alerts"] * 10000 // faces["raw_candidates"]
                    ),
                },
            )
            self.assertEqual(
                chain["deterministic_to_confirmed"],
                {
                    "numerator": faces["confirmed"],
                    "denominator": faces["deterministic_alerts"],
                    "ratio_basis_points": (
                        faces["confirmed"] * 10000 // faces["deterministic_alerts"]
                        if faces["deterministic_alerts"] > 0
                        else None
                    ),
                },
            )
            counts = report["counts"]
            self.assertEqual(
                counts["scanned_files"],
                {"value": faces["scanned_files"], "projection": "measured"},
            )
            self.assertEqual(
                counts["coverage_gap"],
                {"value": faces["coverage_gap"], "projection": "measured"},
            )
            self.assertEqual(report["coverage_gap_reasons"], faces["coverage_gap_reasons"])
            self.assertEqual(
                counts["signals"],
                {"value": faces["signals"], "projection": "legacy_projection"},
            )
            self.assertEqual(
                counts["security_issues"],
                {"value": faces["security_issues"], "projection": "legacy_projection"},
            )
            self.assertEqual(
                report["sources"][0]["payload_sha256"], faces["scanner_digest"]
            )


class TestB1IdentityAndDigests(_B1SourceTestCase):
    """Cluster 2 (Packet 9.1 M3/M4): identity stability and sensitivity."""

    def test_b1_identity_bytes_stable_same_inputs(self):
        self.b1()
        digests = []
        for index in range(2):
            with tempfile.TemporaryDirectory() as temporary:
                output = pathlib.Path(temporary) / f"out-{index}"
                output.mkdir()
                result = self.run_suite(output)
                report = self.report_of(result)
                digests.append(
                    (
                        result.run_spec_digest,
                        result.scanner_payload_sha256,
                        result.snapshot_tree_sha256,
                        report["sources"][0]["payload_sha256"],
                        self.manifest_of(output)["scanner_config_sha256"],
                    )
                )
        self.assertEqual(digests[0], digests[1])
        # The canonical source bytes are path-independent: the same fixture
        # scanned directly in yet another directory yields the same digest.
        with tempfile.TemporaryDirectory() as temporary:
            materialization = self.materialize(
                "archetype/minimal-python-repository",
                pathlib.Path(temporary) / "direct",
            )
            scan = self.direct_scan(materialization.root)
            self.assertEqual(
                digests[0][1],
                self.scanner_wire_digest(
                    scan, "archetype/minimal-python-repository"
                ),
            )

    def test_b1_identity_changes_on_snapshot_config_workload_seed(self):
        self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            baseline = self.run_suite(pathlib.Path(temporary) / "base")
            variations = {
                "snapshot": {"fixture_key": "archetype/application"},
                "analyzer-config": {"cold_count": 2},
                "workload": {"workload": "b1-offline-scanner-probe"},
                "seed": {"seed": 7},
            }
            baseline_manifest = self.manifest_of(pathlib.Path(temporary) / "base")
            for name, overrides in variations.items():
                with self.subTest(face=name):
                    output = pathlib.Path(temporary) / name
                    output.mkdir()
                    result = self.run_suite(output, **overrides)
                    self.assertNotEqual(
                        result.run_spec_digest, baseline.run_spec_digest
                    )
                    manifest = self.manifest_of(output)
                    self.assertNotEqual(
                        manifest["scanner_config_sha256"],
                        baseline_manifest["scanner_config_sha256"],
                    )
                    for receipt in self.receipts_of(output):
                        self.assertEqual(
                            receipt["run_spec_digest"], result.run_spec_digest
                        )


class TestB1TamperFailClosed(_B1SourceTestCase):
    """Cluster 3 (Packet 9.1 M5): tampered evidence fails closed."""

    def _tamper_attempt_receipt(self, output, mutate):
        directory = pathlib.Path(output) / "b1-attempts"
        path = sorted(directory.glob("attempt-*.json"))[0]
        document = self.read_json(path)
        mutate(document["source_receipt"])
        path.write_bytes(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )

    def test_b1_tampered_evidence_fail_closed(self):
        module = self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            # Face 1: a receipt value tampered in the attempt document.
            output = pathlib.Path(temporary) / "receipt"
            output.mkdir()
            self.run_suite(output)
            self._tamper_attempt_receipt(
                output, lambda receipt: receipt.__setitem__("seed", 424242)
            )
            with self.assertRaises(module.B1SourceError) as caught:
                module.verify_b1_evidence(output)
            self.assertIn(str(caught.exception.code), _B1_ERROR_CODES)

            # Face 2: the manifest aggregate digest tampered.
            output = pathlib.Path(temporary) / "manifest"
            output.mkdir()
            self.run_suite(output)
            manifest_path = output / "b1-manifest.json"
            manifest = self.read_json(manifest_path)
            manifest["source_receipts_digest"] = "f" * 64
            manifest_path.write_bytes(
                json.dumps(
                    manifest, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            with self.assertRaises(module.B1SourceError) as caught:
                module.verify_b1_evidence(output)
            self.assertEqual(
                str(caught.exception.code), "SOURCE_BINDING_MISMATCH"
            )

            # Face 3: the scanner payload binding tampered consistently in
            # the attempt document and the manifest list (aggregate digest
            # recomputed), so only the report cross-check can catch it.
            output = pathlib.Path(temporary) / "payload"
            output.mkdir()
            self.run_suite(output)
            self._tamper_attempt_receipt(
                output,
                lambda receipt: receipt.__setitem__(
                    "scanner_payload_sha256", "e" * 64
                ),
            )
            manifest_path = output / "b1-manifest.json"
            manifest = self.read_json(manifest_path)
            manifest["source_receipts"][0]["scanner_payload_sha256"] = "e" * 64
            manifest["source_receipts_digest"] = self.content_digest(
                manifest["source_receipts"]
            )
            manifest_path.write_bytes(
                json.dumps(
                    manifest, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
            )
            with self.assertRaises(module.B1SourceError) as caught:
                module.verify_b1_evidence(output)
            self.assertEqual(
                str(caught.exception.code), "SCANNER_DIGEST_MISMATCH"
            )
            # The untampered baseline of the same run still verifies.
            output = pathlib.Path(temporary) / "intact"
            output.mkdir()
            intact = self.run_suite(output)
            verified = module.verify_b1_evidence(output)
            self.assertEqual(verified["run_spec_digest"], intact.run_spec_digest)
            self.assertEqual(
                verified["scanner_payload_sha256"], intact.scanner_payload_sha256
            )
            self.assertEqual(
                verified["source_receipts_digest"], intact.source_receipts_digest
            )


class TestB1SourceThreeStates(_B1SourceTestCase):
    """Cluster 4 (Packet 9.1 M6): scanner source valid / absent / invalid."""

    def _summary(self):
        from benchmarks.v4.baseline.orchestrate import BaselineRunSummary
        from lima.baseline_run_result import from_mapping

        samples = []
        for index in range(8):
            samples.append(
                {
                    "attempt_index": index,
                    "mode": "cold" if index < 3 else "warm",
                    "outcome": "success",
                    "wall_time_ms": 10 + index,
                    "queue_time_ms": None,
                    "cpu_time_ms": 2,
                    "expert_time_ms": None,
                    "memory_rss_peak_bytes": 1,
                    "io_read_bytes": 1,
                    "io_write_bytes": 1,
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "cost_micro_usd": None,
                    "failure_code": None,
                }
            )
        aggregate = from_mapping(
            {
                "schema_version": 1,
                "run_spec_digest": "a" * 64,
                "samples": samples,
            }
        )
        return BaselineRunSummary(
            attempts=(aggregate,),
            result_paths=(),
            aggregate=aggregate,
            aggregate_path=pathlib.Path("unused"),
            aggregate_sha256=aggregate.content_digest(),
            status=aggregate.status,
        )

    def _scanner_payload(self, state):
        from lima.models import Finding, ReviewReport, Severity
        from lima.repository_scanner import RepositoryScanResult
        from lima.workspace import WorkspaceInventory

        finding = Finding(
            rule_id="rule-a",
            severity=Severity.HIGH,
            title="title",
            explanation="explanation",
            path="pkg/module.py",
            line=10,
            evidence="evidence",
            fix="fix",
            test="test",
            verification_state=state,
        )
        review = ReviewReport(
            repository="fixture-repo",
            pull_request=None,
            summary="summary",
            risk="high",
            findings=[finding],
            files_reviewed=["pkg/module.py"],
            reviewer="local-rules",
            collaboration={"scanned_files": 1, "skipped": {}},
            adjudication={},
        )
        inventory = WorkspaceInventory(root="fixture-repo", skipped={})
        return RepositoryScanResult(report=review, inventory=inventory)

    def test_b1_source_states_valid_absent_invalid(self):
        # Group A -- source absent (frozen report face, passes by design): a
        # real-world v2 payload carries no scanner source, so the
        # scanner-exclusive faces stay honestly unavailable.
        from benchmarks.v4.baseline.report import build_baseline_report

        real_world_payload = {
            "schema_version": 2,
            "mode": "deterministic",
            "scanner_profile": "fast-ast",
            "metrics": {"cases": 1},
            "results": [
                {
                    "deterministic": {
                        "total_findings": {"vulnerable": 2},
                        "workspace": {
                            "rev": {"files": 3, "scanned": 3, "skipped": {}}
                        },
                    }
                }
            ],
        }
        document = build_baseline_report(self._summary(), real_world_payload)
        absent = document.to_canonical_value()
        self.assertEqual(
            absent["counts"]["confirmed"],
            {"value": None, "projection": "unavailable"},
        )
        self.assertEqual(
            absent["counts"]["inconclusive"],
            {"value": None, "projection": "unavailable"},
        )
        self.assertIsNone(absent["compression_chain"]["deterministic_alerts"])

        # Group B -- source invalid (frozen report face, passes by design): a
        # scanner payload carrying a state inside the scanner ladder but
        # outside the frozen report vocabulary fails closed; it is never
        # swallowed into an unavailable projection.
        from benchmarks.v4.baseline.report import (
            BaselineReportError,
            BaselineReportErrorCode,
        )

        self.assertNotIn(_OFF_VOCABULARY_STATE, _REPORT_VERIFICATION_STATES)
        with self.assertRaises(BaselineReportError) as caught:
            build_baseline_report(self._summary(), self._scanner_payload(_OFF_VOCABULARY_STATE))
        self.assertEqual(
            caught.exception.code, BaselineReportErrorCode.EVALUATOR_PAYLOAD_INVALID
        )

        # Group C -- source valid (the B1 deliverable, RED at the freeze):
        # the formal entry projects the measured / legacy_projection faces.
        self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key="archetype/signal-storm")
            report = self.report_of(result)
            counts = report["counts"]
            self.assertEqual(counts["scanned_files"]["projection"], "measured")
            self.assertEqual(counts["coverage_gap"]["projection"], "measured")
            self.assertEqual(
                counts["signals"]["projection"], "legacy_projection"
            )
            self.assertEqual(
                counts["security_issues"]["projection"], "legacy_projection"
            )
            self.assertEqual(report["compression_chain"]["raw_candidates"], 24)


class TestB1ProjectionHonesty(_B1SourceTestCase):
    """Cluster 5 (Packet 9.1 M7/M8): honest projection and zero-finding."""

    def test_b1_projection_honesty_faces(self):
        self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key="archetype/signal-storm")
            report = self.report_of(result)
            counts = report["counts"]
            self.assertEqual(
                counts["signals"],
                {"value": 24, "projection": "legacy_projection"},
            )
            self.assertEqual(
                counts["security_issues"],
                {"value": 24, "projection": "legacy_projection"},
            )
            self.assertEqual(
                counts["hypotheses"], {"value": None, "projection": "unavailable"}
            )
            self.assertEqual(
                counts["confirmed"],
                {"value": 0, "projection": "legacy_projection"},
            )
            self.assertEqual(
                counts["inconclusive"],
                {"value": 24, "projection": "legacy_projection"},
            )
            # No Mining/Repair execution: the stage faces stay null and
            # unavailable -- never a zero-valued measured stand-in.
            self.assertEqual(
                report["vep"], {"value": None, "projection": "unavailable"}
            )
            self.assertEqual(
                report["rvr"], {"value": None, "projection": "unavailable"}
            )
            for stage in ("audit", "mining", "repair"):
                self.assertEqual(
                    report["stage_outcome"][stage],
                    {"value": None, "projection": "unavailable"},
                )
            self.assertEqual(
                report["resources"],
                {
                    "prompt_tokens": None,
                    "completion_tokens": None,
                    "cost_micro_usd": None,
                },
            )
            self.assertEqual(
                report["expert"],
                {"active_time_ms_total": None, "sessions": 0, "reviewer_digests": []},
            )
            self.assertEqual(report["evidence_domain"], "legacy")
            self.assertTrue(report["legacy_projection"])
            self.assertEqual(tuple(report["declarations"]), _REPORT_DECLARATIONS)

    def test_b1_zero_finding_measured_zero_vs_failure_distinguishable(self):
        self.b1()
        # Contrast faces on the frozen scanner modules (pass by design): a
        # parse-failure tree and a truncated inventory are each observable
        # and never confusable with a complete zero-finding scan.
        with tempfile.TemporaryDirectory() as temporary:
            broken = pathlib.Path(temporary) / "broken"
            broken.mkdir()
            (broken / "broken.py").write_text(
                "def broken(:\n    pass\n", encoding="utf-8"
            )
            parse_failed = self.direct_scan(broken)
            self.assertEqual(
                parse_failed.report.collaboration["python_parse_errors"], 1
            )
            self.assertEqual(len(parse_failed.report.findings), 0)

            from benchmarks.v4.baseline.fixtures import materialize_fixture

            storm = materialize_fixture(
                "archetype/signal-storm", pathlib.Path(temporary) / "storm"
            )
            from lima.repository_scanner import RepositoryScanner
            from lima.workspace import RepositoryWorkspace

            truncated_scan = RepositoryScanner(
                sast_mode="off",
                sast_adapters=[],
                cxx_memory_mode="off",
                cxx_memory_adapter=None,
                cxx_agent_mode="off",
                cxx_agent_budget_factory=None,
                cxx_uaf_llm_factory=None,
                dataflow_enabled=True,
            ).scan(
                RepositoryWorkspace(
                    storm.root,
                    max_files=1,
                    max_file_bytes=512 * 1024,
                    max_total_bytes=20 * 1024 * 1024,
                )
            )
            self.assertTrue(truncated_scan.inventory.truncated)
            self.assertEqual(truncated_scan.inventory.skipped["file-limit"], 23)

            # The B1 deliverable (RED at the freeze): a real complete
            # zero-finding scan reports measured zero with a non-empty scan.
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key="archetype/minimal-python-repository")
            report = self.report_of(result)
            self.assertEqual(report["compression_chain"]["raw_candidates"], 0)
            self.assertEqual(
                report["counts"]["scanned_files"],
                {"value": 3, "projection": "measured"},
            )
            self.assertEqual(
                report["counts"]["coverage_gap"],
                {"value": 0, "projection": "measured"},
            )
            self.assertEqual(report["coverage_gap_reasons"], {})
            self.assertEqual(self.manifest_of(output)["failures"], [])


class TestB1BoundarySamples(_B1SourceTestCase):
    """Cluster 6 (Packet 9.1 M9-M12): boundary archetypes and no truncation."""

    def test_b1_boundary_samples_three_archetypes(self):
        self.b1()
        for key in (
            "archetype/docs-content",
            "archetype/test-heavy",
            "archetype/signal-storm",
        ):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as temporary:
                    output = pathlib.Path(temporary) / "out"
                    output.mkdir()
                    result = self.run_suite(output, fixture_key=key)
                    materialization = self.materialize(
                        key, pathlib.Path(temporary) / "direct"
                    )
                    faces = self.expected_faces(
                        self.direct_scan(materialization.root), key
                    )
                    report = self.report_of(result)
                    self.assertEqual(
                        report["compression_chain"]["raw_candidates"],
                        faces["raw_candidates"],
                    )
                    self.assertEqual(
                        report["counts"]["scanned_files"]["value"],
                        faces["scanned_files"],
                    )
                    self.assertEqual(
                        report["counts"]["coverage_gap"]["value"],
                        faces["coverage_gap"],
                    )
                    self.assertEqual(
                        report["sources"][0]["payload_sha256"],
                        faces["scanner_digest"],
                    )
                    self.assertEqual(len(self.receipts_of(output)), 8)

    def test_b1_signal_storm_not_truncated_by_request_cap(self):
        self.b1()
        key = "archetype/signal-storm"
        transport = _CountingTransport()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key=key, transport=transport)
            materialization = self.materialize(key, pathlib.Path(temporary) / "direct")
            findings = self.direct_scan(materialization.root).report.findings
            self.assertGreater(len(findings), _CANDIDATE_FILE_CAP)
            # The report keeps every finding: the cap is a request-construction
            # parameter only, and the two scopes are registered separately.
            report = self.report_of(result)
            self.assertEqual(
                report["compression_chain"]["raw_candidates"], len(findings)
            )
            # Every constructed request carries the workload, the snapshot
            # binding, and a bounded candidate selection.
            self.assertEqual(transport.calls, 8)
            selections = set()
            for request in transport.requests:
                self.assertEqual(request["workload"], _WORKLOAD)
                self.assertEqual(
                    request["snapshot_tree_sha256"], result.snapshot_tree_sha256
                )
                selection = request["candidates"]
                self.assertGreaterEqual(len(selection), 1)
                self.assertLessEqual(len(selection), _CANDIDATE_FILE_CAP)
                selections.add(tuple(selection))
            self.assertEqual(len(selections), 1)
            # Identity independence: the snapshot fingerprint is content
            # derived, so a differently located materialization is identical.
            from benchmarks.v4.baseline.fixtures import compute_tree_fingerprint

            self.assertEqual(
                compute_tree_fingerprint(materialization.root),
                result.snapshot_tree_sha256,
            )

    def test_b1_malicious_layout_static_only_no_escape(self):
        self.b1()
        key = "archetype/malicious-layout"
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key=key)
            materialization = self.materialize(key, pathlib.Path(temporary) / "direct")
            faces = self.expected_faces(self.direct_scan(materialization.root), key)
            report = self.report_of(result)
            self.assertEqual(
                report["compression_chain"]["raw_candidates"], faces["raw_candidates"]
            )
            self.assertEqual(
                report["sources"][0]["payload_sha256"], faces["scanner_digest"]
            )
            # The wiring module itself stays offline and static: no network
            # roots, no environment reads, no code-execution tokens.
            source = self.product_source(_B1_RELATIVE_PATH)
            self.assertEqual(_import_roots(source) & _forbidden_network_roots(), set())
            self.assertNotIn("environ", source)
            self.assertNotIn("getenv", source)
            self.assertNotIn("subprocess", source)
            self.assertNotIn("exec(", source)
            self.assertNotIn("eval(", source)
            # Only the evidence families are written into the output root.
            names = sorted(path.name for path in output.iterdir())
            for name in names:
                self.assertTrue(
                    re.match(r"^[0-9a-f]{16}-run-\d+\.json$", name)
                    or re.match(r"^[0-9a-f]{16}-report-\d+\.json$", name)
                    or name in ("b1-attempts", "b1-manifest.json"),
                    f"unexpected output entry: {name}",
                )

    def test_b1_dependency_blocked_gap_reported_honestly(self):
        self.b1()
        key = "archetype/dependency-blocked"
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key=key)
            materialization = self.materialize(key, pathlib.Path(temporary) / "direct")
            scan = self.direct_scan(materialization.root)
            faces = self.expected_faces(scan, key)
            report = self.report_of(result)
            self.assertEqual(report["compression_chain"]["raw_candidates"], 0)
            self.assertEqual(
                report["counts"]["scanned_files"]["value"], faces["scanned_files"]
            )
            self.assertEqual(
                report["counts"]["coverage_gap"]["value"], faces["coverage_gap"]
            )
            self.assertEqual(report["coverage_gap_reasons"], faces["coverage_gap_reasons"])
            # The honest inventory faces (the unsupported-extension skips)
            # ride inside the scanner payload the digest points back to.
            self.assertEqual(
                report["sources"][0]["payload_sha256"], faces["scanner_digest"]
            )
            self.assertEqual(
                scan.inventory.skipped.get("unsupported-extension", 0),
                2,
            )


class TestB1ColdWarmAndReceipts(_B1SourceTestCase):
    """Cluster 7 (Packet 9.1 M13/M14/M19/M20): cold/warm, receipts, binding."""

    def test_b1_cold_warm_fake_transport_three_plus_five(self):
        self.b1()
        transport = _CountingTransport()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, transport=transport)
            self.assertEqual(result.attempt_count, 8)
            self.assertEqual(result.status, "sufficient_sample")
            # Fake counts are never real calls.
            self.assertEqual(transport.calls, 8)
            self.assertEqual(result.transport_calls, 8)
            self.assertEqual(result.model_calls, 0)
            manifest = self.manifest_of(output)
            self.assertEqual(manifest["transport_calls"], 8)
            self.assertEqual(manifest["model_calls"], 0)
            self.assertEqual(manifest["cold_count"], 3)
            self.assertEqual(manifest["warm_count"], 5)
            receipts = self.receipts_of(output)
            self.assertEqual(
                [receipt["mode"] for receipt in receipts],
                ["cold"] * 3 + ["warm"] * 5,
            )
            self.assertEqual(
                [receipt["attempt_index"] for receipt in receipts], list(range(8))
            )

    def test_b1_scanner_reexecution_vs_reuse_semantics(self):
        self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output)
            receipts = self.receipts_of(output)
            for receipt in receipts[:3]:
                self.assertTrue(receipt["scanner_reexecuted"])
                self.assertFalse(receipt["scanner_result_reused"])
                self.assertFalse(receipt["snapshot_reused"])
                self.assertTrue(receipt["request_body_rebuilt"])
            for receipt in receipts[3:]:
                self.assertFalse(receipt["scanner_reexecuted"])
                self.assertTrue(receipt["scanner_result_reused"])
                self.assertTrue(receipt["snapshot_reused"])
                self.assertFalse(receipt["request_body_rebuilt"])
            # Same snapshot and config: one stable payload digest for every
            # attempt, equal to the report's scanner source digest.
            digests = {receipt["scanner_payload_sha256"] for receipt in receipts}
            self.assertEqual(len(digests), 1)
            report = self.report_of(result)
            self.assertEqual(
                digests.pop(), report["sources"][0]["payload_sha256"]
            )
            self.assertEqual(result.scanner_executions, 3)

    def test_b1_sample_aggregation_no_summation(self):
        self.b1()
        key = "archetype/signal-storm"
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output, fixture_key=key)
            materialization = self.materialize(key, pathlib.Path(temporary) / "direct")
            single = len(self.direct_scan(materialization.root).report.findings)
            self.assertEqual(single, 24)
            report = self.report_of(result)
            # Eight samples over one snapshot: counts stay per-snapshot.
            self.assertEqual(report["compression_chain"]["raw_candidates"], single)
            self.assertEqual(report["counts"]["signals"]["value"], single)
            self.assertEqual(report["attempt_count"], 8)
            self.assertEqual(self.manifest_of(output)["attempt_count"], 8)

    def test_b1_receipt_key_set_and_manifest_digest(self):
        self.b1()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "out"
            output.mkdir()
            result = self.run_suite(output)
            manifest = self.manifest_of(output)
            self.assertEqual(set(manifest), _B1_MANIFEST_KEYS)
            receipts = self.receipts_of(output)
            self.assertEqual(manifest["source_receipts"], receipts)
            self.assertEqual(
                manifest["source_receipts_digest"],
                self.content_digest(receipts),
            )
            for receipt in receipts:
                self.assertEqual(set(receipt), _RECEIPT_KEYS)
                self.assertEqual(receipt["fixture_key"], result.fixture_key)
                self.assertEqual(
                    receipt["fixture_manifest_sha256"],
                    self.registry_fingerprint(result.fixture_key),
                )
                self.assertEqual(receipt["snapshot_tree_sha256"], result.snapshot_tree_sha256)
                self.assertEqual(receipt["workload"], _WORKLOAD)
                self.assertEqual(
                    receipt["analyzer_fingerprint"], manifest["analyzer_fingerprint"]
                )
                self.assertEqual(
                    receipt["scanner_config_sha256"],
                    manifest["scanner_config_sha256"],
                )
                self.assertEqual(receipt["seed"], 0)
                self.assertTrue(_HEX64_SHAPE.match(receipt["analyzer_fingerprint"]))
                self.assertTrue(_HEX64_SHAPE.match(receipt["scanner_config_sha256"]))
            verified = self.b1().verify_b1_evidence(output)
            self.assertEqual(verified["run_spec_digest"], result.run_spec_digest)
            self.assertEqual(
                verified["scanner_payload_sha256"], result.scanner_payload_sha256
            )
            self.assertEqual(
                verified["source_receipts_digest"], result.source_receipts_digest
            )


class TestB1OldPathAnchors(_B1SourceTestCase):
    """Cluster 8 (Packet 9.1 M15-M18): frozen old-path anchors (by design)."""

    def test_b1_old_entry_signature_unchanged(self):
        import benchmarks.v4.baseline.real_run as real_run

        parameters = inspect.signature(real_run.run_real_baseline_suite).parameters
        self.assertEqual(tuple(parameters), _ENTRY_PARAM_ORDER)
        self.assertEqual(
            {name for name, item in parameters.items() if item.kind is item.KEYWORD_ONLY},
            _ENTRY_KEYWORD_ONLY,
        )
        self.assertIsNone(parameters["transport"].default)
        self.assertEqual(parameters["timeout_seconds"].default, 120)
        self.assertIsNone(parameters["manifest_path"].default)
        self.assertIsNone(parameters["sources"].default)
        self.assertEqual(parameters["artifact_key"].default, _DEFAULT_ARTIFACT_KEY)
        self.assertEqual(tuple(real_run.__all__), _REAL_RUN_ALL)

    def test_b1_old_static_surfaces_frozen(self):
        import benchmarks.v4.baseline.budget as budget
        import benchmarks.v4.baseline.offline_flow as offline_flow
        import benchmarks.v4.baseline.real_run as real_run

        self.assertEqual(
            set(real_run.REAL_RUN_ARTIFACT_FAMILY), _ARTIFACT_FAMILY_KEYS
        )
        # The locked IP-0031 gate face lives in the frozen budget module.
        self.assertFalse(budget.REAL_RUN_GATE_UNLOCKED)
        self.assertEqual(real_run.CANDIDATE_FILE_CAP, _CANDIDATE_FILE_CAP)
        self.assertEqual(tuple(offline_flow.__all__), _OFFLINE_FLOW_ALL)

    def test_b1_packet_doc_in_repo_with_container_copy_line(self):
        packet = _REPO_ROOT / _PACKET_RELATIVE_PATH
        self.assertTrue(packet.is_file())
        dockerfile = (_REPO_ROOT / _DOCKERFILE_RELATIVE_PATH).read_text(
            encoding="utf-8"
        )
        self.assertEqual(dockerfile.count(_PACKET_COPY_LINE), 1)

    def test_b1_test_sources_offline_and_secretless(self):
        # PC1 self-scan (passes by design): this file stays offline and
        # secretless.
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))
        # Product group (RED at the freeze on the absent module): the wiring
        # module source gets the same offline/secretless discipline.
        path = _REPO_ROOT / _B1_RELATIVE_PATH
        if not path.is_file():
            self.fail(
                "b1_source.py product source is missing (expected before C3)"
            )
        source = path.read_text(encoding="utf-8")
        self.assertEqual(_import_roots(source) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(source))


if __name__ == "__main__":
    unittest.main()
