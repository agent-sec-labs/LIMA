"""Frozen acceptance tests for IP-0027: baseline collection foundation (Issue #212).

Contract under test (frozen by Coordinator Assignment CA-IP-0027-v1.0 of
2026-09-25; see docs/LIMA_Implementation_Packet_IP-0027_Baseline_Collection_Foundation.md):

- The Implementation deliverables are the six files of the new
  ``benchmarks/v4/baseline/`` package (three package markers plus the three
  logic modules ``collect``, ``expert_timing`` and ``run``); this slice ships
  zero ``lima/`` product code, zero ``scripts/`` changes and zero
  ``evaluation_data/`` changes.
- ``collect`` owns the package-wide typed error family
  (``BaselineCollectionError`` with a closed 10-member
  ``BaselineCollectionErrorCode``), the monotonic clock guard, the bounded
  failure taxonomy (EXECUTION_ERROR / EXECUTION_TIMEOUT / EXECUTION_CANCELLED),
  injectable platform metric sources (stdlib-only, int-or-None, float is
  forbidden) and the honest None semantics for unavailable platform metrics.
- ``expert_timing`` owns the expert timing protocol (start/pause/resume/finish
  event sequence, reviewer ID stored only as its SHA-256 digest, active time
  with paused intervals excluded) and the sidecar canonical serialization via
  ``lima.contracts.codec``.
- ``run`` owns the frozen dataset-role registry (third-party truth verbatim
  from ``evaluation_data/v4/baseline_manifest.json``), the SF-01
  dataset->role binding gate (spec side plus manifest side, defense-in-depth
  fingerprint double pinning, independent of the frozen
  ``validate_baseline_manifest`` which never compares roles), the collection
  runner (spec layer -> frozen manifest cross-check -> role gate -> only then
  the execute callable) and the independent result writer (deterministic
  digest-prefixed names, monotonic numbering, exclusive creation, history
  never overwritten, failed runs retained).
- The whole suite is offline and secretless: deterministic, no network, no
  environment reads, no paid model calls.  Module-level imports are stdlib
  plus the frozen ``lima`` contracts plus the new product package; the frozen
  manifest artifact is loaded inside test methods.

Expected RED before implementation (product package absent): the test module
is discovered, but the module-level ``from benchmarks.v4.baseline import ...``
fails with ``ModuleNotFoundError`` (naming the first absent ancestor
``benchmarks``), so every test fails closed, attributable solely to the
missing product package.
"""

import ast
import copy
import hashlib
import json
import pathlib
import re
import tempfile
import unittest
from asyncio import CancelledError

from benchmarks.v4.baseline import (  # isort: skip -- first-party only once the package exists
    collect,
    expert_timing,
    run,
)

from lima.baseline_run_result import BaselineRunResult, BaselineRunResultError
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.baseline_run_spec import (
    BaselineRunSpecError,
    BaselineRunSpecErrorCode,
    validate_baseline_manifest,
)
from lima.baseline_run_spec import from_mapping as spec_from_mapping
from lima.contracts.codec import canonical_encode

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MANIFEST_RELATIVE_PATH = "evaluation_data/v4/baseline_manifest.json"

_COLLECTION_ERROR_CODES = (
    "INVALID_FIELD_TYPE",
    "UNKNOWN_FROZEN_DATASET",
    "ROLE_BINDING_MISMATCH",
    "FROZEN_FINGERPRINT_MISMATCH",
    "CLOCK_NOT_MONOTONIC",
    "INVALID_METRIC_TYPE",
    "INVALID_REVIEWER_ID",
    "EVENT_SEQUENCE_INVALID",
    "OUTPUT_DIRECTORY_UNAVAILABLE",
    "OUTPUT_PATH_ALREADY_EXISTS",
)

_FAILURE_CODE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]{0,63}")
_RESULT_FILENAME_PATTERN = re.compile(r"[0-9a-f]{16}-run-[1-9][0-9]*\.json")

_ROLE_SWAP = {"calibration": "external-holdout", "external-holdout": "calibration"}

_NOMINAL_ANALYZER_FINGERPRINT = "a" * 64
_NOMINAL_CONFIG_DIGEST = "b" * 64
_NOMINAL_SEED = 20260925
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

_PRODUCT_MODULE_NAMES = ("collect", "expert_timing", "run")
_ALLOWED_STDLIB_IMPORT_ROOTS = frozenset(
    {
        "dataclasses",
        "enum",
        "hashlib",
        "json",
        "pathlib",
        "re",
        "resource",
        "time",
        "types",
        "typing",
    }
)
_ALLOWED_PRODUCT_IMPORTS = frozenset(
    {
        "lima.contracts.codec",
        "lima.baseline_run_spec",
        "lima.baseline_run_result",
        "benchmarks.v4.baseline.collect",
        "benchmarks.v4.baseline.expert_timing",
    }
)


def _forbidden_source_tokens():
    """Tokens that must never appear in this test file or the product modules."""
    return [
        "os." + "environ",
        "get" + "env",
        "sock" + "et",
        "url" + "lib",
        "requ" + "ests",
    ]


class _CountingExecute:
    """Execution body double that only records how often it was invoked."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return None


def _fake_sources(
    wall_values=(1_000_000_000, 1_002_000_000),
    cpu_values=(500_000_000, 600_000_000),
    rss=4096,
    io_read=512,
    io_write=256,
):
    """Deterministic injectable sources: wall diff 2 ms, cpu diff 100 ms."""
    wall = iter(wall_values)
    cpu = iter(cpu_values)
    return collect.PlatformSources(
        wall_ns=lambda: next(wall),
        cpu_ns=lambda: next(cpu),
        peak_rss_bytes=lambda: rss,
        io_read_bytes=lambda: io_read,
        io_write_bytes=lambda: io_write,
    )


def _success_result(digest):
    sample = {
        "attempt_index": 0,
        "mode": "cold",
        "outcome": "success",
        "wall_time_ms": 1000,
        "queue_time_ms": None,
        "cpu_time_ms": None,
        "expert_time_ms": None,
        "memory_rss_peak_bytes": None,
        "io_read_bytes": None,
        "io_write_bytes": None,
        "prompt_tokens": None,
        "completion_tokens": None,
        "cost_micro_usd": None,
        "failure_code": None,
    }
    return result_from_mapping(
        {"schema_version": 1, "run_spec_digest": digest, "samples": [sample]}
    )


class _IP0027CollectionTestCase(unittest.TestCase):
    """Shared arrange helpers (no collected tests)."""

    def load_manifest(self):
        path = _REPO_ROOT / _MANIFEST_RELATIVE_PATH
        if not path.is_file():
            self.fail(f"required frozen manifest artifact is missing: {_MANIFEST_RELATIVE_PATH}")
        with path.open("rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    def spec_mapping_from_manifest(self, manifest):
        """Build a nominal spec mapping from manifest values (frozen roles)."""
        repositories = [
            {"identity": entry["repository"], "commit_sha": entry["commit_sha"]}
            for dataset in manifest["datasets"]
            for entry in dataset["entries"]
        ]
        datasets = [
            {
                "name": dataset["name"],
                "fingerprint": dataset["fingerprint"],
                "role": dataset["role"],
            }
            for dataset in manifest["datasets"]
        ]
        return {
            "schema_version": 1,
            "repositories": repositories,
            "datasets": datasets,
            "analyzer_fingerprint": _NOMINAL_ANALYZER_FINGERPRINT,
            "config_digest": _NOMINAL_CONFIG_DIGEST,
            "seed": _NOMINAL_SEED,
            "machine_profile": dict(_NOMINAL_MACHINE_PROFILE),
        }

    def product_source(self, module_name):
        relative = f"benchmarks/v4/baseline/{module_name}.py"
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product module is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def assert_role_gate_rejected(self, spec, manifest, code, fragment=None):
        with self.assertRaises(collect.BaselineCollectionError) as caught:
            run.validate_role_bindings(spec, manifest)
        self.assertEqual(caught.exception.code, code)
        if fragment is not None:
            self.assertIn(fragment, caught.exception.field_path)


class TestPublicSurfaceAndHygiene(_IP0027CollectionTestCase):
    """AC-3 static face: closed error family, taxonomy, registry, offline hygiene."""

    def test_collection_error_family_shape_and_closed_code_set(self):
        error_class = collect.BaselineCollectionError
        self.assertTrue(issubclass(error_class, ValueError))
        self.assertFalse(issubclass(error_class, BaselineRunSpecError))
        self.assertFalse(issubclass(error_class, BaselineRunResultError))
        members = {member.name for member in collect.BaselineCollectionErrorCode}
        self.assertEqual(members, set(_COLLECTION_ERROR_CODES))
        for name in _COLLECTION_ERROR_CODES:
            with self.subTest(code=name):
                member = collect.BaselineCollectionErrorCode(name)
                self.assertEqual(member.value, name)
        clock = collect.BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC
        first = collect.BaselineCollectionError(clock, "$.samples[0].wall_time_ms")
        second = collect.BaselineCollectionError(clock, "$.events[2].time_ns")
        self.assertEqual(str(first), str(second))
        self.assertEqual(first.code, clock)
        self.assertIsInstance(first.field_path, str)

    def test_failure_taxonomy_codes_and_classification(self):
        self.assertEqual(
            set(collect.FAILURE_TAXONOMY_CODES),
            {"EXECUTION_ERROR", "EXECUTION_TIMEOUT", "EXECUTION_CANCELLED"},
        )
        for code in collect.FAILURE_TAXONOMY_CODES:
            with self.subTest(code=code):
                self.assertIsNotNone(_FAILURE_CODE_PATTERN.fullmatch(code))
        expectations = (
            (ValueError("boom"), "EXECUTION_ERROR"),
            (RuntimeError(), "EXECUTION_ERROR"),
            (TimeoutError("slow"), "EXECUTION_TIMEOUT"),
            (KeyboardInterrupt(), "EXECUTION_CANCELLED"),
            (CancelledError(), "EXECUTION_CANCELLED"),
        )
        for exception, expected in expectations:
            with self.subTest(exception=type(exception).__name__):
                self.assertEqual(collect.classify_failure(exception), expected)

    def test_frozen_role_registry_equals_on_disk_manifest(self):
        manifest = self.load_manifest()
        bindings = run.FROZEN_DATASET_BINDINGS
        self.assertEqual(len(bindings), 3)
        self.assertEqual(
            set(bindings), {dataset["name"] for dataset in manifest["datasets"]}
        )
        for dataset in manifest["datasets"]:
            with self.subTest(dataset=dataset["name"]):
                self.assertEqual(
                    bindings[dataset["name"]],
                    (dataset["role"], dataset["fingerprint"]),
                )

    def test_product_modules_import_whitelist(self):
        for module_name in _PRODUCT_MODULE_NAMES:
            tree = ast.parse(self.product_source(module_name))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        self._assert_import_allowed(alias.name)
                elif isinstance(node, ast.ImportFrom):
                    self.assertEqual(node.level, 0, "relative imports are not allowed")
                    self._assert_import_allowed(node.module or "")

    def _assert_import_allowed(self, module_name):
        root = module_name.split(".")[0]
        if root in ("lima", "benchmarks"):
            allowed = any(
                module_name == candidate or module_name.startswith(candidate + ".")
                for candidate in _ALLOWED_PRODUCT_IMPORTS
            )
        else:
            allowed = root in _ALLOWED_STDLIB_IMPORT_ROOTS
        self.assertTrue(
            allowed, f"import {module_name!r} is outside the frozen whitelist"
        )

    def test_offline_hygiene_source_scan(self):
        sources = [pathlib.Path(__file__).read_text(encoding="utf-8")]
        sources.extend(self.product_source(name) for name in _PRODUCT_MODULE_NAMES)
        for token in _forbidden_source_tokens():
            with self.subTest(token=token):
                for source in sources:
                    self.assertNotIn(token, source)


class TestRoleBindingGate(_IP0027CollectionTestCase):
    """FR-04 / SF-01: the dataset->role binding gate with registry truth."""

    def test_pristine_manifest_and_spec_pass_role_gate(self):
        manifest = self.load_manifest()
        spec = spec_from_mapping(self.spec_mapping_from_manifest(manifest))
        self.assertIsNone(run.validate_role_bindings(spec, manifest))

    def test_self_consistent_role_swap_rejected_despite_frozen_contract_pass(self):
        manifest = self.load_manifest()
        swapped = copy.deepcopy(manifest)
        for dataset in swapped["datasets"]:
            dataset["role"] = _ROLE_SWAP.get(dataset["role"], dataset["role"])
        spec = spec_from_mapping(self.spec_mapping_from_manifest(swapped))
        # The frozen cross-check has no spec-vs-manifest role comparison
        # (SF-IP-0026-20260925-01 blind spot): the self-consistent swap passes.
        validate_baseline_manifest(swapped, spec)
        # The new binding gate rejects it against the frozen registry.
        self.assert_role_gate_rejected(
            spec,
            swapped,
            collect.BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH,
            fragment="role",
        )

    def test_spec_only_role_swap_rejected(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        index = next(
            i for i, dataset in enumerate(mapping["datasets"])
            if dataset["role"] == "calibration"
        )
        mapping["datasets"][index]["role"] = "external-holdout"
        spec = spec_from_mapping(mapping)
        self.assert_role_gate_rejected(
            spec,
            manifest,
            collect.BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH,
            fragment="role",
        )

    def test_manifest_only_role_swap_rejected(self):
        manifest = self.load_manifest()
        swapped = copy.deepcopy(manifest)
        for dataset in swapped["datasets"]:
            dataset["role"] = _ROLE_SWAP.get(dataset["role"], dataset["role"])
        spec = spec_from_mapping(self.spec_mapping_from_manifest(manifest))
        self.assert_role_gate_rejected(
            spec,
            swapped,
            collect.BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH,
        )

    def test_unknown_dataset_name_rejected_on_spec_and_manifest_sides(self):
        manifest = self.load_manifest()

        renamed = copy.deepcopy(manifest)
        renamed["datasets"][0]["name"] += "-renamed"
        spec = spec_from_mapping(self.spec_mapping_from_manifest(renamed))
        with self.subTest(side="spec"):
            self.assert_role_gate_rejected(
                spec,
                renamed,
                collect.BaselineCollectionErrorCode.UNKNOWN_FROZEN_DATASET,
                fragment="name",
            )

        extended = copy.deepcopy(manifest)
        extended["datasets"].append(
            {
                "name": "lima-unknown-dataset-v9",
                "fingerprint": "e" * 64,
                "role": "development",
                "entries": [],
            }
        )
        pristine_spec = spec_from_mapping(self.spec_mapping_from_manifest(manifest))
        with self.subTest(side="manifest"):
            self.assert_role_gate_rejected(
                pristine_spec,
                extended,
                collect.BaselineCollectionErrorCode.UNKNOWN_FROZEN_DATASET,
                fragment="name",
            )

    def test_self_consistent_fingerprint_recomputation_rejected(self):
        manifest = self.load_manifest()
        drifted = copy.deepcopy(manifest)
        drifted["datasets"][0]["fingerprint"] = "9" * 64
        spec = spec_from_mapping(self.spec_mapping_from_manifest(drifted))
        # Spec and manifest agree, so the frozen fingerprint cross-check passes.
        validate_baseline_manifest(drifted, spec)
        # The registry double pin catches the self-consistent recomputation.
        self.assert_role_gate_rejected(
            spec,
            drifted,
            collect.BaselineCollectionErrorCode.FROZEN_FINGERPRINT_MISMATCH,
            fragment="fingerprint",
        )


class TestRunnerIdentityGates(_IP0027CollectionTestCase):
    """FR-05 / FR-04 runner path: frozen passthrough, zero execution, no files."""

    def test_identity_gate_failures_pass_through_with_zero_execution_and_no_files(self):
        manifest = self.load_manifest()
        base_mapping = self.spec_mapping_from_manifest(manifest)

        def swap_roles(mapping, mutated_manifest):
            for dataset in mutated_manifest["datasets"]:
                dataset["role"] = _ROLE_SWAP.get(dataset["role"], dataset["role"])
            for dataset in mapping["datasets"]:
                if dataset["role"] == "calibration":
                    dataset["role"] = "external-holdout"
                elif dataset["role"] == "external-holdout":
                    dataset["role"] = "calibration"

        gate_code = collect.BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH
        cases = (
            (
                "moving-ref",
                lambda mapping, _manifest: mapping["repositories"][0].update(
                    commit_sha="main"
                ),
                BaselineRunSpecError,
                BaselineRunSpecErrorCode.MOVING_REF_REJECTED,
            ),
            (
                "abbreviated-sha",
                lambda mapping, _manifest: mapping["repositories"][0].update(
                    commit_sha="1" * 12
                ),
                BaselineRunSpecError,
                BaselineRunSpecErrorCode.ABBREVIATED_COMMIT_SHA_REJECTED,
            ),
            (
                "dataset-fingerprint-drift",
                lambda mapping, _manifest: mapping["datasets"][0].update(
                    fingerprint="9" * 64
                ),
                BaselineRunSpecError,
                BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH,
            ),
            (
                "self-consistent-role-swap",
                swap_roles,
                collect.BaselineCollectionError,
                gate_code,
            ),
        )
        for label, mutator, error_type, code in cases:
            with self.subTest(case=label):
                mapping = copy.deepcopy(base_mapping)
                mutated_manifest = copy.deepcopy(manifest)
                mutator(mapping, mutated_manifest)
                recorder = _CountingExecute()
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(error_type) as caught:
                        run.run_baseline_attempt(
                            mapping, mutated_manifest, recorder, directory
                        )
                    self.assertEqual(caught.exception.code, code)
                    self.assertEqual(recorder.calls, 0)
                    self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_runner_rejects_invalid_metric_params_before_execution(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        cases = (
            ("float-cost", {"cost_micro_usd": 1.5}),
            ("bool-prompt-tokens", {"prompt_tokens": True}),
            ("string-completion-tokens", {"completion_tokens": "80"}),
        )
        for label, kwargs in cases:
            with self.subTest(case=label):
                recorder = _CountingExecute()
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(collect.BaselineCollectionError) as caught:
                        run.run_baseline_attempt(
                            mapping,
                            manifest,
                            recorder,
                            directory,
                            sources=_fake_sources(),
                            **kwargs,
                        )
                    self.assertEqual(
                        caught.exception.code,
                        collect.BaselineCollectionErrorCode.INVALID_METRIC_TYPE,
                    )
                    self.assertEqual(recorder.calls, 0)
                    self.assertEqual(list(pathlib.Path(directory).iterdir()), [])
        with self.subTest(case="unavailable-output-directory"):
            recorder = _CountingExecute()
            with tempfile.TemporaryDirectory() as directory:
                missing = pathlib.Path(directory) / "missing" / "sub"
                with self.assertRaises(collect.BaselineCollectionError) as caught:
                    run.run_baseline_attempt(mapping, manifest, recorder, missing)
                self.assertEqual(
                    caught.exception.code,
                    collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
                )
                self.assertEqual(recorder.calls, 0)


class TestClockGuardAndSources(_IP0027CollectionTestCase):
    """FR-01: monotonic clock guard and honest int-or-None metric semantics."""

    def test_elapsed_ms_rejects_non_monotonic_reads(self):
        self.assertEqual(collect.elapsed_ms(1_000_000_000, 1_002_000_000), 2)
        self.assertEqual(collect.elapsed_ms(500, 500), 0)
        with self.assertRaises(collect.BaselineCollectionError) as caught:
            collect.elapsed_ms(1_000, 999)
        self.assertEqual(
            caught.exception.code, collect.BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC
        )
        for bad_start in (1.5, True, "10"):
            with self.subTest(bad=repr(bad_start)):
                with self.assertRaises(collect.BaselineCollectionError) as caught:
                    collect.elapsed_ms(bad_start, 10)
                self.assertEqual(
                    caught.exception.code,
                    collect.BaselineCollectionErrorCode.INVALID_METRIC_TYPE,
                )

    def test_runner_rejects_non_monotonic_injected_wall_clock(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        recorder = _CountingExecute()
        sources = _fake_sources(wall_values=(1_000_000_000, 999_999_999))
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.run_baseline_attempt(
                    mapping, manifest, recorder, directory, sources=sources
                )
            self.assertEqual(
                caught.exception.code, collect.BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC
            )
            self.assertEqual(recorder.calls, 1)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_null_semantics_keep_missing_metrics_none(self):
        rss = collect.read_peak_rss_bytes()
        self.assertTrue(rss is None or (type(rss) is int and rss >= 0))
        io_read, io_write = collect.read_io_bytes()
        for value in (io_read, io_write):
            with self.subTest(platform_value=repr(value)):
                self.assertTrue(value is None or (type(value) is int and value >= 0))

        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        recorder = _CountingExecute()
        none_sources = collect.PlatformSources(
            wall_ns=lambda: 1_000_000_000,
            cpu_ns=lambda: 1_000_000_000,
            peak_rss_bytes=lambda: None,
            io_read_bytes=lambda: None,
            io_write_bytes=lambda: None,
        )
        with tempfile.TemporaryDirectory() as directory:
            result = run.run_baseline_attempt(
                mapping, manifest, recorder, directory, sources=none_sources
            )
            sample = result.to_canonical_value()["samples"][0]
            self.assertEqual(sample["outcome"], "success")
            self.assertTrue(type(sample["wall_time_ms"]) is int)
            # A constant fake clock yields a measured zero diff, never None.
            self.assertTrue(type(sample["cpu_time_ms"]) is int)
            for field in (
                "queue_time_ms",
                "expert_time_ms",
                "memory_rss_peak_bytes",
                "io_read_bytes",
                "io_write_bytes",
                "prompt_tokens",
                "completion_tokens",
                "cost_micro_usd",
            ):
                with self.subTest(field=field):
                    self.assertIsNone(sample[field])

        float_sources = _fake_sources(rss=12.5)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.run_baseline_attempt(
                    mapping, manifest, _CountingExecute(), directory, sources=float_sources
                )
            self.assertEqual(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.INVALID_METRIC_TYPE,
            )
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])


class TestRunRecording(_IP0027CollectionTestCase):
    """FR-02 / AC-1: canonical result files, failure taxonomy, history kept."""

    def test_success_run_records_canonical_result_with_metrics(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        recorder = _CountingExecute()
        with tempfile.TemporaryDirectory() as directory:
            result = run.run_baseline_attempt(
                mapping,
                manifest,
                recorder,
                directory,
                attempt_index=0,
                mode="cold",
                enqueued_ns=999_000_000,
                sources=_fake_sources(),
                prompt_tokens=120,
                completion_tokens=80,
                cost_micro_usd=250,
            )
            self.assertEqual(recorder.calls, 1)
            self.assertIsInstance(result, BaselineRunResult)
            self.assertEqual(result.run_spec_digest, spec_from_mapping(mapping).content_digest())
            self.assertEqual(result.status, "insufficient_sample")
            sample = result.to_canonical_value()["samples"][0]
            self.assertEqual(sample["attempt_index"], 0)
            self.assertEqual(sample["mode"], "cold")
            self.assertEqual(sample["outcome"], "success")
            self.assertEqual(sample["failure_code"], None)
            expected_metrics = {
                "wall_time_ms": 2,
                "queue_time_ms": 1,
                "cpu_time_ms": 100,
                "expert_time_ms": None,
                "memory_rss_peak_bytes": 4096,
                "io_read_bytes": 512,
                "io_write_bytes": 256,
                "prompt_tokens": 120,
                "completion_tokens": 80,
                "cost_micro_usd": 250,
            }
            for field, expected in expected_metrics.items():
                with self.subTest(field=field):
                    self.assertTrue(type(sample[field]) is type(expected), field)
                    self.assertEqual(sample[field], expected)

            prefix = result.run_spec_digest[:16]
            files = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(files, [f"{prefix}-run-1.json"])
            raw = (pathlib.Path(directory) / files[0]).read_bytes()
            self.assertEqual(raw, result.canonical_bytes())
            self.assertEqual(
                hashlib.sha256(raw).hexdigest(), result.content_digest()
            )
            self.assertNotIn(b"\r", raw)
            self.assertNotIn(b"\n", raw)
            self.assertEqual(json.loads(raw.decode("utf-8")), result.to_canonical_value())

    def test_failed_runs_recorded_with_taxonomy_and_retained(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        cases = (
            (ValueError("boom"), "failure", "EXECUTION_ERROR"),
            (TimeoutError("slow"), "timeout", "EXECUTION_TIMEOUT"),
        )
        for exception, outcome, code in cases:
            with self.subTest(exception=type(exception).__name__):
                def failing_body(error=exception):
                    raise error

                with tempfile.TemporaryDirectory() as directory:
                    result = run.run_baseline_attempt(
                        mapping, manifest, failing_body, directory, sources=_fake_sources()
                    )
                    sample = result.to_canonical_value()["samples"][0]
                    self.assertEqual(sample["outcome"], outcome)
                    self.assertEqual(sample["failure_code"], code)
                    files = list(pathlib.Path(directory).iterdir())
                    self.assertEqual(len(files), 1)
                    decoded = json.loads(files[0].read_bytes().decode("utf-8"))
                    self.assertEqual(decoded["samples"][0]["failure_code"], code)
                    self.assertEqual(decoded["samples"][0]["outcome"], outcome)

        with self.subTest(exception="CancelledError"):
            def cancelled_body():
                raise CancelledError

            with tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(CancelledError):
                    run.run_baseline_attempt(
                        mapping, manifest, cancelled_body, directory, sources=_fake_sources()
                    )
                files = list(pathlib.Path(directory).iterdir())
                self.assertEqual(len(files), 1)
                decoded = json.loads(files[0].read_bytes().decode("utf-8"))
                self.assertEqual(decoded["samples"][0]["outcome"], "cancelled")
                self.assertEqual(
                    decoded["samples"][0]["failure_code"], "EXECUTION_CANCELLED"
                )

    def test_second_execution_writes_new_file_preserving_history(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        recorder = _CountingExecute()
        with tempfile.TemporaryDirectory() as directory:
            first = run.run_baseline_attempt(
                mapping,
                manifest,
                recorder,
                directory,
                sources=_fake_sources(),
                prompt_tokens=10,
                cost_micro_usd=1,
            )
            prefix = first.run_spec_digest[:16]
            first_path = pathlib.Path(directory) / f"{prefix}-run-1.json"
            first_bytes = first_path.read_bytes()
            second = run.run_baseline_attempt(
                mapping,
                manifest,
                recorder,
                directory,
                sources=_fake_sources(cpu_values=(500_000_000, 700_000_000)),
                prompt_tokens=20,
                cost_micro_usd=2,
            )
            files = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(files, [f"{prefix}-run-1.json", f"{prefix}-run-2.json"])
            self.assertEqual(first_path.read_bytes(), first_bytes)
            second_path = pathlib.Path(directory) / f"{prefix}-run-2.json"
            self.assertEqual(second_path.read_bytes(), second.canonical_bytes())
            self.assertNotEqual(first.content_digest(), second.content_digest())


class TestWriter(_IP0027CollectionTestCase):
    """FR-02 / R3: exclusive creation, deterministic naming, no overwrites."""

    def test_write_exclusive_refuses_existing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            sentinel = pathlib.Path(directory) / "sentinel.json"
            sentinel.write_bytes(b'{"sentinel":true}')
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.write_exclusive(sentinel, b"replacement")
            self.assertEqual(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_PATH_ALREADY_EXISTS,
            )
            self.assertEqual(sentinel.read_bytes(), b'{"sentinel":true}')
            fresh = pathlib.Path(directory) / "fresh.bin"
            run.write_exclusive(fresh, b"payload")
            self.assertEqual(fresh.read_bytes(), b"payload")

    def test_result_filenames_are_digest_prefixed_monotonic_without_timestamps(self):
        digest = "c" * 64
        result = _success_result(digest)
        with tempfile.TemporaryDirectory() as directory:
            first = run.write_result_file(result, directory)
            second = run.write_result_file(result, directory)
            prefix = digest[:16]
            self.assertEqual(first.result_path.name, f"{prefix}-run-1.json")
            self.assertEqual(second.result_path.name, f"{prefix}-run-2.json")
            files = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(files, [f"{prefix}-run-1.json", f"{prefix}-run-2.json"])
            for name in files:
                with self.subTest(filename=name):
                    self.assertIsNotNone(_RESULT_FILENAME_PATTERN.fullmatch(name))
            self.assertIsNone(first.sidecar_path)
            self.assertEqual(
                first.result_path.read_bytes(), result.canonical_bytes()
            )
            self.assertEqual(
                hashlib.sha256(first.result_path.read_bytes()).hexdigest(),
                first.result_sha256,
            )
            self.assertIsNone(first.sidecar_sha256)
        with tempfile.TemporaryDirectory() as directory:
            missing = pathlib.Path(directory) / "missing"
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.write_result_file(result, missing)
            self.assertEqual(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
            )


class TestExpertTimingProtocol(_IP0027CollectionTestCase):
    """FR-01 / R4: expert timing protocol and sidecar canonical serialization."""

    def test_reviewer_id_stored_only_as_sha256_digest(self):
        reviewer = "reviewer-alice@example.com"
        session = expert_timing.ExpertTimingSession(reviewer)
        expected = hashlib.sha256(reviewer.encode("utf-8")).hexdigest()
        self.assertEqual(session.reviewer_digest, expected)
        session.start(1_000_000)
        session.finish(2_000_000)
        document = session.to_sidecar_document("d" * 64)
        self.assertEqual(document["reviewer_digest"], expected)
        rendered = json.dumps(document, sort_keys=True)
        self.assertNotIn(reviewer, rendered)
        payload = session.sidecar_bytes("d" * 64)
        self.assertNotIn(reviewer, payload.decode("utf-8"))
        for bad in ("", 5, None, b"reviewer"):
            with self.subTest(bad=repr(bad)):
                with self.assertRaises(collect.BaselineCollectionError) as caught:
                    expert_timing.ExpertTimingSession(bad)
                self.assertEqual(
                    caught.exception.code,
                    collect.BaselineCollectionErrorCode.INVALID_REVIEWER_ID,
                )

    def test_active_time_excludes_paused_intervals(self):
        session = expert_timing.ExpertTimingSession("reviewer-bob")
        session.start(0)
        session.pause(1_000_000_000)
        self.assertEqual(session.active_time_ms(), 1000)
        session.resume(5_000_000_000)
        self.assertEqual(session.active_time_ms(), 1000)
        session.finish(6_000_000_000)
        self.assertEqual(session.active_time_ms(), 2000)
        events = session.events()
        self.assertEqual(
            [event["event"] for event in events],
            ["start", "pause", "resume", "finish"],
        )
        self.assertEqual(
            [event["time_ns"] for event in events],
            [0, 1_000_000_000, 5_000_000_000, 6_000_000_000],
        )
        document = session.to_sidecar_document("e" * 64)
        self.assertEqual(document["active_time_ms"], 2000)
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["run_spec_digest"], "e" * 64)
        self.assertEqual(document["events"], [dict(event) for event in events])

    def test_invalid_event_sequences_and_non_monotonic_events_rejected(self):
        def fresh_session():
            return expert_timing.ExpertTimingSession("reviewer-carol")

        def assert_event_invalid(session, method, time_ns):
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                getattr(session, method)(time_ns)
            self.assertEqual(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.EVENT_SEQUENCE_INVALID,
            )

        assert_event_invalid(fresh_session(), "pause", 1)
        assert_event_invalid(fresh_session(), "resume", 1)
        assert_event_invalid(fresh_session(), "finish", 1)
        double_start = fresh_session()
        double_start.start(1)
        assert_event_invalid(double_start, "start", 2)
        double_pause = fresh_session()
        double_pause.start(1)
        double_pause.pause(2)
        assert_event_invalid(double_pause, "pause", 3)
        resume_while_active = fresh_session()
        resume_while_active.start(1)
        assert_event_invalid(resume_while_active, "resume", 2)
        finished = fresh_session()
        finished.start(1)
        finished.finish(2)
        for method in ("start", "pause", "resume", "finish"):
            with self.subTest(after_finish=method):
                assert_event_invalid(finished, method, 3)

        non_monotonic = fresh_session()
        non_monotonic.start(100)
        with self.assertRaises(collect.BaselineCollectionError) as caught:
            non_monotonic.pause(50)
        self.assertEqual(
            caught.exception.code, collect.BaselineCollectionErrorCode.CLOCK_NOT_MONOTONIC
        )

    def test_sidecar_canonical_bytes_stable_and_digest_recomputable(self):
        def build_session():
            session = expert_timing.ExpertTimingSession("same-reviewer")
            session.start(1_000_000)
            session.pause(2_000_000)
            session.resume(3_000_000)
            session.finish(4_000_000)
            return session

        first = build_session()
        second = build_session()
        digest_value = "f" * 64
        first_bytes = first.sidecar_bytes(digest_value)
        second_bytes = second.sidecar_bytes(digest_value)
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(
            first_bytes, canonical_encode(first.to_sidecar_document(digest_value))
        )
        digest = first.sidecar_digest(digest_value)
        self.assertRegex(digest, "^[0-9a-f]{64}$")
        self.assertEqual(digest, hashlib.sha256(first_bytes).hexdigest())
        self.assertNotIn(b"\xef\xbb\xbf", first_bytes[:3])
        self.assertNotIn(b"\r", first_bytes)
        self.assertNotIn(b"\n", first_bytes)
        decoded = json.loads(first_bytes.decode("utf-8"))
        self.assertEqual(decoded, first.to_sidecar_document(digest_value))


class TestSidecarIntegration(_IP0027CollectionTestCase):
    """R3/R4: the runner persists the expert timing sidecar next to the result."""

    def test_runner_writes_sidecar_alongside_result(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        recorder = _CountingExecute()
        with tempfile.TemporaryDirectory() as directory:
            session = expert_timing.ExpertTimingSession("integration-reviewer")
            session.start(1_000_000)
            session.finish(2_000_000)
            result = run.run_baseline_attempt(
                mapping,
                manifest,
                recorder,
                directory,
                sources=_fake_sources(),
                expert_session=session,
            )
            prefix = result.run_spec_digest[:16]
            files = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(
                files,
                [f"{prefix}-run-1.expert-timing.json", f"{prefix}-run-1.json"],
            )
            sidecar_path = pathlib.Path(directory) / f"{prefix}-run-1.expert-timing.json"
            payload = sidecar_path.read_bytes()
            self.assertEqual(payload, session.sidecar_bytes(result.run_spec_digest))
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(),
                session.sidecar_digest(result.run_spec_digest),
            )
            sample = result.to_canonical_value()["samples"][0]
            self.assertEqual(sample["expert_time_ms"], 1)

        with tempfile.TemporaryDirectory() as directory:
            result = run.run_baseline_attempt(
                mapping, manifest, recorder, directory, sources=_fake_sources()
            )
            files = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(files, [f"{result.run_spec_digest[:16]}-run-1.json"])
            self.assertFalse(
                any(name.endswith(".expert-timing.json") for name in files)
            )


if __name__ == "__main__":
    unittest.main()
