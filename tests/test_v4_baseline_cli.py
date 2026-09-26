"""Frozen acceptance tests for IP-0028: CLI wiring and repeat orchestration (Issue #214).

Contract under test (frozen by Coordinator Assignment CA-IP-0028-v1.0 of
2026-09-26; see docs/LIMA_Implementation_Packet_IP-0028_Baseline_CLI_Repeat_Orchestration.md):

- The Implementation deliverables are the new shared orchestration module
  ``benchmarks/v4/baseline/orchestrate.py`` (baseline argument surface, the
  ``run_baseline_from_args`` CLI adapter with a one-shot pre-execution gate
  stack, the ``run_repeats`` N cold + N warm orchestration with a multi-sample
  aggregate assembled only through the frozen
  ``lima.baseline_run_result.from_mapping`` and persisted through the existing
  ``write_result_file``) plus the three-script wiring (one
  ``add_baseline_arguments`` call and one ``if args.run_spec is not None:``
  early-exit branch per script, lazy imports, byte-identical legacy behavior)
  plus the two IP-0027 interface errata in ``benchmarks/v4/baseline/run.py``
  (sequence allocation probing both the result and sidecar names; three
  structure-only field_path literals ``$.output_path`` / ``$.output_dir``).
- ``--repeat N`` executes N cold attempts (attempt_index 0..N-1) then N warm
  attempts (attempt_index N..2N-1); each attempt result file is written by the
  frozen ``run_baseline_attempt``; the aggregate carries all 2N samples
  (failures included, sorted by attempt_index) and the all-or-nothing
  sufficient/insufficient status of the frozen contract.
- The CLI adapter fails closed before any execution for argument-combination,
  repeat-count, spec, manifest, role-gate, and output-directory violations;
  the SF-IP-0026-20260925-01 four negative classes hold at the orchestration
  entry with zero execute calls and zero files.
- Everything is offline and secretless: deterministic, no network, no
  environment reads, no paid model calls.  Platform sources are injected; the
  legacy equivalence expectations below were derived programmatically from the
  unmodified baseline-state scripts.

Expected RED before implementation (product submodule absent): the test module
is discovered, but the module-level ``import benchmarks.v4.baseline.orchestrate``
fails with ``ModuleNotFoundError: No module named
'benchmarks.v4.baseline.orchestrate'`` (the package exists, the submodule does
not), so every test fails closed, attributable solely to the missing product
module.
"""

import argparse
import ast
import copy
import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import pathlib
import tempfile
import types
import unittest
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock

from benchmarks.v4.baseline import (  # isort: skip -- first-party only once the module exists
    collect,
    expert_timing,
    run,
)
import benchmarks.v4.baseline.orchestrate as orchestrate  # isort: skip -- RED anchor

from lima.baseline_run_result import BaselineRunResult
from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.baseline_run_spec import BaselineRunSpecError, BaselineRunSpecErrorCode
from lima.baseline_run_spec import from_mapping as spec_from_mapping

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MANIFEST_RELATIVE_PATH = "evaluation_data/v4/baseline_manifest.json"

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

_SCRIPT_NAMES = ("run_e2e_evaluation", "run_real_world_evaluation", "run_repair_evaluation")

_ORCHESTRATE_ALLOWED_STDLIB_IMPORTS = frozenset(
    {"argparse", "dataclasses", "enum", "json", "pathlib", "typing"}
)
_ORCHESTRATE_ALLOWED_PRODUCT_IMPORTS = frozenset(
    {
        "lima.baseline_run_spec",
        "lima.baseline_run_result",
        "benchmarks.v4.baseline.collect",
        "benchmarks.v4.baseline.run",
    }
)

_BASELINE_ERROR_CODES = (
    "BASELINE_OUTPUT_REQUIRED",
    "INVALID_REPEAT_COUNT",
    "MANIFEST_UNREADABLE",
)

_BASELINE_ERROR_MESSAGES = {
    "BASELINE_OUTPUT_REQUIRED": "A baseline run requires the --baseline-output directory.",
    "INVALID_REPEAT_COUNT": "The baseline repeat count must be a positive integer.",
    "MANIFEST_UNREADABLE": "The baseline manifest file could not be read.",
}

_OUTPUT_DIR_MESSAGE = "The requested output directory is unavailable."
_OUTPUT_PATH_MESSAGE = "The requested output path already exists and is never overwritten."

_SUMMARY_FIELDS = (
    "attempts",
    "result_paths",
    "aggregate",
    "aggregate_path",
    "aggregate_sha256",
    "status",
)

# Legacy-equivalence expectations (AC-1).  These literals were derived on
# 2026-09-26 by running the unmodified baseline-state scripts (98b8a35) under
# evaluator-boundary stubs; see Packet section 10 for the derivation record.
_E2E_BASE_METRICS = {
    "precision": 0.5,
    "recall": 0.5,
    "f1": 0.5,
    "severity_accuracy": 0.5,
    "high_risk_recall": 0.5,
    "clean_accuracy": 0.5,
    "execution_success_rate": 1.0,
    "safe_fix_rate": 0.0,
    "e2e_security_fix_rate": 0.0,
    "tp": 1,
    "fp": 1,
    "fn": 1,
}
_E2E_CANDIDATE_METRICS = {
    "precision": 0.75,
    "recall": 0.75,
    "f1": 0.75,
    "severity_accuracy": 0.75,
    "high_risk_recall": 0.75,
    "clean_accuracy": 0.75,
    "execution_success_rate": 1.0,
    "safe_fix_rate": 0.5,
    "e2e_security_fix_rate": 0.25,
    "tp": 2,
    "fp": 0,
    "fn": 0,
    "repair_attempted": 1,
    "repair_passed": 1,
    "risk_cases": 1,
    "e2e_successes": 1,
}
_E2E_BASE_SPLIT = {
    "cases": 1,
    "risk_cases": 1,
    "clean_cases": 0,
    "f1": 0.5,
    "high_risk_recall": 0.5,
    "clean_accuracy": 0.5,
}
_E2E_CANDIDATE_SPLIT = {
    "cases": 1,
    "risk_cases": 1,
    "clean_cases": 0,
    "f1": 0.75,
    "high_risk_recall": 0.75,
    "clean_accuracy": 0.75,
}
_E2E_SENTINELS = {
    "single-agent-baseline": {
        "name": "single-agent-baseline",
        "metrics": dict(_E2E_BASE_METRICS),
        "dataset": {
            "cases": 2,
            "risk_cases": 1,
            "clean_cases": 1,
            "repositories": 1,
            "source_kinds": ["synthetic"],
            "sha256": "0" * 64,
        },
        "by_split": {"validation": dict(_E2E_BASE_SPLIT), "holdout": dict(_E2E_BASE_SPLIT)},
    },
    "multi-agent-candidate": {
        "name": "multi-agent-candidate",
        "metrics": dict(_E2E_CANDIDATE_METRICS),
        "dataset": {
            "cases": 2,
            "risk_cases": 1,
            "clean_cases": 1,
            "repositories": 1,
            "source_kinds": ["synthetic"],
            "sha256": "0" * 64,
        },
        "by_split": {
            "validation": dict(_E2E_CANDIDATE_SPLIT),
            "holdout": dict(_E2E_CANDIDATE_SPLIT),
        },
        "repair_attempted": 1,
        "repair_passed": 1,
        "e2e_successes": 1,
    },
}
_REAL_WORLD_SENTINEL_RESULT = {"metrics": {"cases": 1}, "marker": "real-world-sentinel"}
_REAL_WORLD_EXPECTED_STDOUT = (
    '{\n  "metrics": {\n    "cases": 1\n  },\n  "marker": "real-world-sentinel"\n}\n'
)
_REPAIR_SENTINEL_RESULT = {
    "metrics": {"constraint_accuracy": 1.0, "cases": 0},
    "marker": "repair-sentinel",
}
_REPAIR_EXPECTED_STDOUT = (
    '{\n  "metrics": {\n    "constraint_accuracy": 1.0,\n    "cases": 0\n  },\n'
    '  "marker": "repair-sentinel"\n}\n'
)
_E2E_EXPECTED_TAIL = (
    "baseline F1=50.0% candidate F1=75.0% high-risk recall=75.0% clean accuracy=75.0%\n"
    "safe fix=50.0% e2e fix=25.0%\n"
)

_SCRIPT_MODULE_CACHE: dict[str, types.ModuleType] = {}


def _forbidden_source_tokens():
    """Tokens that must never appear in this test file or the product sources."""
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


class _FailOnNthCall:
    """Execution body double that raises on the n-th invocation and counts calls."""

    def __init__(self, failure, n):
        self.failure = failure
        self.n = n
        self.calls = 0

    def __call__(self):
        self.calls += 1
        if self.calls == self.n:
            raise self.failure
        return None


def _repeat_sources(cold_ms, warm_ms):
    """Injectable sources whose wall durations per attempt are given in ms."""
    durations = [value * 1_000_000 for value in (*cold_ms, *warm_ms)]
    wall_reads = []
    wall_base = 1_000_000_000
    for span in durations:
        wall_reads.extend((wall_base, wall_base + span))
        wall_base += span + 1_000_000
    cpu_reads = []
    cpu_base = 500_000_000
    for _ in durations:
        cpu_reads.extend((cpu_base, cpu_base + 100_000_000))
        cpu_base += 200_000_000
    wall = iter(wall_reads)
    cpu = iter(cpu_reads)
    return collect.PlatformSources(
        wall_ns=lambda: next(wall),
        cpu_ns=lambda: next(cpu),
        peak_rss_bytes=lambda: 4096,
        io_read_bytes=lambda: 512,
        io_write_bytes=lambda: 256,
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


def _load_script(name):
    """Load scripts/run_<name>.py by path (scripts/ has no package marker)."""
    if name not in _SCRIPT_MODULE_CACHE:
        path = _REPO_ROOT / "scripts" / f"{name}.py"
        if not path.is_file():
            raise FileNotFoundError(path)
        spec = importlib.util.spec_from_file_location(name, path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _SCRIPT_MODULE_CACHE[name] = module
    return _SCRIPT_MODULE_CACHE[name]


class _StubEndToEndHarness:
    """Evaluator-boundary stub returning frozen sentinel results by run name."""

    def __init__(self, repairer=None):
        pass

    def run(self, reviewer, cases, name=""):
        return json.loads(json.dumps(_E2E_SENTINELS[name]))


class _StubRealWorldEvaluator:
    """Evaluator-boundary stub returning the frozen real-world sentinel."""

    def __init__(self, store, scanner=None, oracle_runner=None, llm_client=None):
        pass

    def run(self, dataset, mode="deterministic", run_oracles=False):
        return json.loads(json.dumps(_REAL_WORLD_SENTINEL_RESULT))


class _StubRepairEvaluator:
    """Evaluator-boundary stub returning the frozen repair sentinel."""

    def __init__(self, fixer=None):
        pass

    def run(self, dataset):
        return json.loads(json.dumps(_REPAIR_SENTINEL_RESULT))


class _LegacyEntryBomb:
    """Sentinel failing the test if the legacy path is entered in baseline mode."""

    def __init__(self, name="legacy-entry"):
        raise AssertionError(f"legacy path must not be entered in baseline mode: {name}")


def _recording_real_world_evaluator():
    state = {"instantiations": 0, "run_calls": 0}

    class _Evaluator:
        def __init__(self, store, scanner=None, oracle_runner=None, llm_client=None):
            state["instantiations"] += 1

        def run(self, dataset, mode="deterministic", run_oracles=False):
            state["run_calls"] += 1
            return {}

    return _Evaluator, state


def _recording_repair_evaluator():
    state = {"instantiations": 0, "run_calls": 0}

    class _Evaluator:
        def __init__(self, fixer=None):
            state["instantiations"] += 1

        def run(self, dataset):
            state["run_calls"] += 1
            return {}

    return _Evaluator, state


def _fake_summary():
    return types.SimpleNamespace(
        status="insufficient_sample",
        attempts=(0, 1, 2, 3),
        aggregate_path=pathlib.Path("baseline-out") / "digest-run-5.json",
        aggregate_sha256="a" * 64,
    )


class _IP0028CLITestCase(unittest.TestCase):
    """Shared arrange helpers (no collected tests)."""

    def load_manifest(self):
        path = _REPO_ROOT / _MANIFEST_RELATIVE_PATH
        if not path.is_file():
            self.fail(f"required frozen manifest artifact is missing: {_MANIFEST_RELATIVE_PATH}")
        with path.open("rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    def spec_mapping_from_manifest(self, manifest):
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

    def write_json_file(self, directory, name, payload):
        path = pathlib.Path(directory) / name
        path.write_text(json.dumps(payload), encoding="utf-8")
        return path

    def baseline_args(self, spec_path, output_dir, repeat=None):
        parser = argparse.ArgumentParser()
        orchestrate.add_baseline_arguments(parser)
        argv = ["--run-spec", str(spec_path), "--baseline-output", str(output_dir)]
        if repeat is not None:
            argv.extend(["--repeat", str(repeat)])
        return parser.parse_args(argv)

    def run_repeats_with_sources(self, directory, repeat, cold_ms, warm_ms, execute=None):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        if execute is None:
            execute = _CountingExecute()
        summary = orchestrate.run_repeats(
            mapping,
            manifest,
            execute,
            directory,
            repeat=repeat,
            sources=_repeat_sources(cold_ms, warm_ms),
        )
        return summary, execute

    def orchestrate_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def assert_summary_matches_directory(self, summary, directory, expected_files):
        names = sorted(path.name for path in pathlib.Path(directory).iterdir())
        self.assertEqual(names, expected_files)
        self.assertEqual(
            [path.name for path in summary.result_paths],
            [name for name in expected_files if name != summary.aggregate_path.name],
        )
        self.assertEqual(summary.status, summary.aggregate.status)


class TestBaselineArgumentSurface(_IP0028CLITestCase):
    """FR-01 parameter face: defaults, guards, fail-closed combination."""

    def test_baseline_argument_defaults_and_types(self):
        parser = argparse.ArgumentParser()
        orchestrate.add_baseline_arguments(parser)
        args = parser.parse_args([])
        self.assertIsNone(args.run_spec)
        self.assertIsNone(args.baseline_output)
        self.assertTrue(type(args.repeat) is int)
        self.assertEqual(args.repeat, 5)
        positive = parser.parse_args(["--repeat", "3"])
        self.assertEqual(positive.repeat, 3)

    def test_repeat_guard_rejects_non_positive_and_non_integer(self):
        parser = argparse.ArgumentParser()
        orchestrate.add_baseline_arguments(parser)
        for bad in ("0", "-1", "abc", "2.5"):
            with self.subTest(value=bad):
                with self.assertRaises(SystemExit) as caught:
                    with redirect_stderr(io.StringIO()):
                        parser.parse_args(["--repeat", bad])
                self.assertEqual(caught.exception.code, 2)
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        recorder = _CountingExecute()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(orchestrate.BaselineOrchestrationError) as caught:
                orchestrate.run_repeats(mapping, manifest, recorder, directory, repeat=0)
            self.assertIs(
                caught.exception.code,
                orchestrate.BaselineOrchestrationErrorCode.INVALID_REPEAT_COUNT,
            )
            self.assertEqual(caught.exception.field_path, "$.repeat")
            self.assertEqual(recorder.calls, 0)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

    def test_run_spec_without_baseline_output_fails_closed(self):
        parser = argparse.ArgumentParser()
        orchestrate.add_baseline_arguments(parser)
        args = parser.parse_args(["--run-spec", "unused-spec.json"])
        recorder = _CountingExecute()
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(orchestrate.BaselineOrchestrationError) as caught:
                orchestrate.run_baseline_from_args(
                    args, execute=recorder, manifest_path=str(pathlib.Path(directory) / "m.json")
                )
            self.assertIs(
                caught.exception.code,
                orchestrate.BaselineOrchestrationErrorCode.BASELINE_OUTPUT_REQUIRED,
            )
            self.assertEqual(caught.exception.field_path, "$.baseline_output")
            self.assertEqual(
                str(caught.exception), _BASELINE_ERROR_MESSAGES["BASELINE_OUTPUT_REQUIRED"]
            )
            self.assertEqual(recorder.calls, 0)
            self.assertEqual(list(pathlib.Path(directory).iterdir()), [])

        manifest = self.load_manifest()
        with tempfile.TemporaryDirectory() as directory:
            spec_path = self.write_json_file(
                directory, "spec.json", self.spec_mapping_from_manifest(manifest)
            )
            out_dir = pathlib.Path(directory) / "out"
            out_dir.mkdir()
            for label, manifest_path in (
                ("absent", str(pathlib.Path(directory) / "absent.json")),
                ("malformed", None),
            ):
                with self.subTest(manifest=label):
                    if label == "malformed":
                        manifest_path = pathlib.Path(directory) / "malformed.json"
                        manifest_path.write_bytes(b"not-json{")
                    recorder = _CountingExecute()
                    args = self.baseline_args(spec_path, out_dir)
                    with self.assertRaises(orchestrate.BaselineOrchestrationError) as caught:
                        orchestrate.run_baseline_from_args(
                            args, execute=recorder, manifest_path=str(manifest_path)
                        )
                    self.assertIs(
                        caught.exception.code,
                        orchestrate.BaselineOrchestrationErrorCode.MANIFEST_UNREADABLE,
                    )
                    self.assertEqual(caught.exception.field_path, "$.manifest_path")
                    self.assertEqual(
                        str(caught.exception), _BASELINE_ERROR_MESSAGES["MANIFEST_UNREADABLE"]
                    )
                    self.assertEqual(recorder.calls, 0)
                    self.assertEqual(list(out_dir.iterdir()), [])


class TestScriptWiring(_IP0028CLITestCase):
    """FR-01 wiring: baseline branch delegates, legacy path untouched."""

    _MANIFEST_PATH = str(pathlib.Path(__file__).resolve().parent.parent / _MANIFEST_RELATIVE_PATH)

    def test_e2e_script_wires_baseline_mode(self):
        module = _load_script("run_e2e_evaluation")
        generated = mock.Mock(return_value=[])
        summary = _fake_summary()
        with tempfile.TemporaryDirectory() as directory:
            out_dir = pathlib.Path(directory) / "baseline-out"
            out_dir.mkdir()
            argv = [
                "prog",
                "--run-spec",
                str(pathlib.Path(directory) / "spec.json"),
                "--baseline-output",
                str(out_dir),
                "--dataset",
                str(pathlib.Path(directory) / "cases.jsonl"),
            ]
            buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args",
                return_value=summary,
            ) as entry, mock.patch.object(
                module, "generate_controlled_pr_cases", generated
            ), mock.patch.object(
                module, "EndToEndEvaluationHarness", _LegacyEntryBomb
            ), mock.patch(
                "sys.argv", argv
            ), redirect_stdout(buffer):
                result = module.main()
            self.assertIsNone(result)
            entry.assert_called_once()
            positional, kwargs = entry.call_args
            self.assertEqual(positional[0].run_spec, argv[2])
            self.assertEqual(positional[0].baseline_output, str(out_dir))
            self.assertEqual(positional[0].repeat, 5)
            self.assertEqual(kwargs["manifest_path"], self._MANIFEST_PATH)
            self.assertTrue(callable(kwargs["execute"]))
            generated.assert_called_once()
            expected = (
                f"baseline: status={summary.status} attempts={len(summary.attempts)}"
                f" aggregate={summary.aggregate_path} sha256={summary.aggregate_sha256}\n"
            )
            self.assertEqual(buffer.getvalue(), expected)

    def test_real_world_script_wires_baseline_mode(self):
        module = _load_script("run_real_world_evaluation")
        loader = mock.Mock(return_value={"marker": "dataset"})
        evaluator_class, state = _recording_real_world_evaluator()
        summary = _fake_summary()
        with tempfile.TemporaryDirectory() as directory:
            out_dir = pathlib.Path(directory) / "baseline-out"
            out_dir.mkdir()
            argv = [
                "--run-spec",
                str(pathlib.Path(directory) / "spec.json"),
                "--baseline-output",
                str(out_dir),
                "--repeat",
                "3",
                "--dataset",
                str(pathlib.Path(directory) / "cases.json"),
                "--cache",
                str(pathlib.Path(directory) / "cache"),
            ]
            buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args",
                return_value=summary,
            ) as entry, mock.patch.object(
                module, "load_real_world_dataset", loader
            ), mock.patch.object(
                module, "RealWorldSecurityEvaluator", evaluator_class
            ), redirect_stdout(buffer):
                code = module.main(argv)
            self.assertEqual(code, 0)
            entry.assert_called_once()
            positional, kwargs = entry.call_args
            self.assertEqual(positional[0].run_spec, argv[1])
            self.assertEqual(positional[0].baseline_output, str(out_dir))
            self.assertEqual(positional[0].repeat, 3)
            self.assertEqual(kwargs["manifest_path"], self._MANIFEST_PATH)
            self.assertTrue(callable(kwargs["execute"]))
            loader.assert_called_once()
            self.assertEqual(state["instantiations"], 1)
            self.assertEqual(state["run_calls"], 0)
            expected = (
                f"baseline: status={summary.status} attempts={len(summary.attempts)}"
                f" aggregate={summary.aggregate_path} sha256={summary.aggregate_sha256}\n"
            )
            self.assertEqual(buffer.getvalue(), expected)

    def test_repair_script_wires_baseline_mode(self):
        module = _load_script("run_repair_evaluation")
        loader = mock.Mock(return_value={"cases": []})
        evaluator_class, state = _recording_repair_evaluator()
        summary = _fake_summary()
        with tempfile.TemporaryDirectory() as directory:
            out_dir = pathlib.Path(directory) / "baseline-out"
            out_dir.mkdir()
            argv = [
                "--run-spec",
                str(pathlib.Path(directory) / "spec.json"),
                "--baseline-output",
                str(out_dir),
                "--dataset",
                str(pathlib.Path(directory) / "cases.json"),
            ]
            buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args",
                return_value=summary,
            ) as entry, mock.patch.object(
                module, "load_repair_dataset", loader
            ), mock.patch.object(
                module, "RepairConstraintEvaluator", evaluator_class
            ), redirect_stdout(buffer):
                code = module.main(argv)
            self.assertEqual(code, 0)
            entry.assert_called_once()
            positional, kwargs = entry.call_args
            self.assertEqual(positional[0].run_spec, argv[1])
            self.assertEqual(positional[0].baseline_output, str(out_dir))
            self.assertEqual(positional[0].repeat, 5)
            self.assertEqual(kwargs["manifest_path"], self._MANIFEST_PATH)
            self.assertTrue(callable(kwargs["execute"]))
            loader.assert_called_once()
            self.assertEqual(state["instantiations"], 1)
            self.assertEqual(state["run_calls"], 0)
            self.assertEqual(
                buffer.getvalue(),
                f"baseline: status={summary.status} attempts={len(summary.attempts)}"
                f" aggregate={summary.aggregate_path} sha256={summary.aggregate_sha256}\n",
            )

    def test_script_baseline_error_rendering(self):
        module = _load_script("run_real_world_evaluation")
        loader = mock.Mock(return_value={"marker": "dataset"})
        evaluator_class, state = _recording_real_world_evaluator()
        failure = collect.BaselineCollectionError(
            collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
            "$.output_dir",
        )
        with tempfile.TemporaryDirectory() as directory:
            out_dir = pathlib.Path(directory) / "baseline-out"
            out_dir.mkdir()
            argv = [
                "--run-spec",
                str(pathlib.Path(directory) / "spec.json"),
                "--baseline-output",
                str(out_dir),
                "--dataset",
                str(pathlib.Path(directory) / "cases.json"),
            ]
            stdout_buffer = io.StringIO()
            stderr_buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args",
                side_effect=failure,
            ), mock.patch.object(
                module, "load_real_world_dataset", loader
            ), mock.patch.object(
                module, "RealWorldSecurityEvaluator", evaluator_class
            ), redirect_stdout(stdout_buffer), redirect_stderr(stderr_buffer):
                code = module.main(argv)
            self.assertEqual(code, 2)
            self.assertEqual(
                stderr_buffer.getvalue(),
                "baseline error: OUTPUT_DIRECTORY_UNAVAILABLE $.output_dir\n",
            )
            self.assertEqual(stdout_buffer.getvalue(), "")
            self.assertEqual(state["run_calls"], 0)


class TestLegacyEquivalence(_IP0028CLITestCase):
    """AC-1 behavior layer: legacy argv stdout bytes and exit codes unchanged."""

    def test_e2e_legacy_stdout_and_exit_unchanged(self):
        module = _load_script("run_e2e_evaluation")
        entry = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            dataset = str(pathlib.Path(directory) / "cases.jsonl")
            output_dir = str(pathlib.Path(directory) / "out")
            argv = ["prog", "--dataset", dataset, "--output-dir", output_dir]
            buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args", entry
            ), mock.patch.object(
                module, "EndToEndEvaluationHarness", _StubEndToEndHarness
            ), mock.patch.object(
                module, "generate_controlled_pr_cases", lambda: []
            ), mock.patch(
                "sys.argv", argv
            ), redirect_stdout(buffer):
                result = module.main()
            self.assertIsNone(result)
            entry.assert_not_called()
            report_path = os.path.join(output_dir, "evaluation-report.json")
            expected = f"dataset: {dataset}\nreport: {report_path}\n"
            expected += _E2E_EXPECTED_TAIL
            self.assertEqual(buffer.getvalue(), expected)

    def test_real_world_legacy_stdout_and_exit_unchanged(self):
        module = _load_script("run_real_world_evaluation")
        entry = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            argv = [
                "--dataset",
                str(pathlib.Path(directory) / "cases.json"),
                "--cache",
                str(pathlib.Path(directory) / "cache"),
            ]
            buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args", entry
            ), mock.patch.object(
                module, "load_real_world_dataset", lambda *a, **k: {"marker": "dataset"}
            ), mock.patch.object(
                module, "RealWorldSecurityEvaluator", _StubRealWorldEvaluator
            ), redirect_stdout(buffer):
                code = module.main(argv)
            self.assertEqual(code, 0)
            entry.assert_not_called()
            self.assertEqual(buffer.getvalue(), _REAL_WORLD_EXPECTED_STDOUT)

    def test_repair_legacy_stdout_and_exit_unchanged(self):
        module = _load_script("run_repair_evaluation")
        entry = mock.Mock()
        with tempfile.TemporaryDirectory() as directory:
            argv = ["--dataset", str(pathlib.Path(directory) / "cases.json")]
            buffer = io.StringIO()
            with mock.patch(
                "benchmarks.v4.baseline.orchestrate.run_baseline_from_args", entry
            ), mock.patch.object(
                module, "load_repair_dataset", lambda *a, **k: {"cases": []}
            ), mock.patch.object(
                module, "RepairConstraintEvaluator", _StubRepairEvaluator
            ), redirect_stdout(buffer):
                code = module.main(argv)
            self.assertEqual(code, 0)
            entry.assert_not_called()
            self.assertEqual(buffer.getvalue(), _REPAIR_EXPECTED_STDOUT)


class TestOrchestrationSemantics(_IP0028CLITestCase):
    """FR-02/FR-03: N cold + N warm, aggregation, history, taxonomy."""

    def test_two_repeats_execute_four_attempts_and_aggregate_naming(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, execute = self.run_repeats_with_sources(directory, 2, [10, 11], [20, 21])
            self.assertEqual(execute.calls, 4)
            self.assertEqual(len(summary.attempts), 4)
            aggregate = summary.aggregate
            self.assertIsInstance(aggregate, BaselineRunResult)
            prefix = aggregate.run_spec_digest[:16]
            self.assert_summary_matches_directory(
                summary, directory, [f"{prefix}-run-{n}.json" for n in range(1, 6)]
            )
            self.assertEqual(summary.aggregate_path.name, f"{prefix}-run-5.json")
            self.assertEqual(aggregate.status, "insufficient_sample")
            samples = aggregate.to_canonical_value()["samples"]
            self.assertEqual([sample["attempt_index"] for sample in samples], [0, 1, 2, 3])
            self.assertEqual(
                [sample["mode"] for sample in samples], ["cold", "cold", "warm", "warm"]
            )
            decoded = json.loads(summary.aggregate_path.read_bytes().decode("utf-8"))
            self.assertEqual([s["attempt_index"] for s in decoded["samples"]], [0, 1, 2, 3])

    def test_three_repeats_yield_insufficient_with_null_percentiles(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, execute = self.run_repeats_with_sources(
                directory, 3, [10, 11, 12], [20, 21, 22]
            )
            self.assertEqual(execute.calls, 6)
            prefix = summary.aggregate.run_spec_digest[:16]
            self.assert_summary_matches_directory(
                summary, directory, [f"{prefix}-run-{n}.json" for n in range(1, 8)]
            )
            self.assertEqual(summary.aggregate.status, "insufficient_sample")
            for field in (
                "cold_p50_wall_time_ms",
                "cold_p95_wall_time_ms",
                "warm_p50_wall_time_ms",
                "warm_p95_wall_time_ms",
            ):
                with self.subTest(percentile=field):
                    self.assertIsNone(getattr(summary.aggregate, field))

    def test_five_repeats_yield_sufficient_with_nearest_rank_percentiles(self):
        cold = [10, 20, 30, 40, 50]
        warm = [100, 200, 300, 400, 500]
        with tempfile.TemporaryDirectory() as directory:
            summary, execute = self.run_repeats_with_sources(directory, 5, cold, warm)
            self.assertEqual(execute.calls, 10)
            aggregate = summary.aggregate
            self.assertEqual(aggregate.status, "sufficient_sample")
            # Nearest-rank hand check: n=5, p50 rank=(50*5+99)//100=3, p95 rank=(95*5+99)//100=5.
            expected = {
                "cold_p50_wall_time_ms": 30,
                "cold_p95_wall_time_ms": 50,
                "warm_p50_wall_time_ms": 300,
                "warm_p95_wall_time_ms": 500,
            }
            for field, value in expected.items():
                with self.subTest(percentile=field):
                    self.assertEqual(getattr(aggregate, field), value)
                    self.assertTrue(type(getattr(aggregate, field)) is int)
            payload = summary.aggregate_path.read_bytes()
            self.assertEqual(payload, aggregate.canonical_bytes())
            self.assertEqual(
                hashlib.sha256(payload).hexdigest(), summary.aggregate_sha256
            )
            self.assertEqual(summary.aggregate_sha256, aggregate.content_digest())

    def test_single_repeat_runs_two_attempts_without_error(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, execute = self.run_repeats_with_sources(directory, 1, [10], [20])
            self.assertEqual(execute.calls, 2)
            prefix = summary.aggregate.run_spec_digest[:16]
            self.assert_summary_matches_directory(
                summary, directory, [f"{prefix}-run-{n}.json" for n in range(1, 4)]
            )
            samples = summary.aggregate.to_canonical_value()["samples"]
            self.assertEqual(
                [(sample["attempt_index"], sample["mode"]) for sample in samples],
                [(0, "cold"), (1, "warm")],
            )
            self.assertEqual(summary.aggregate.status, "insufficient_sample")

    def test_rerun_same_spec_adds_files_preserving_history(self):
        def by_sequence(names):
            return sorted(
                names, key=lambda name: int(pathlib.Path(name).stem.rsplit("-", 1)[1])
            )

        with tempfile.TemporaryDirectory() as directory:
            first, _ = self.run_repeats_with_sources(directory, 2, [10, 11], [20, 21])
            before = {path.name: path.read_bytes() for path in pathlib.Path(directory).iterdir()}
            second, _ = self.run_repeats_with_sources(directory, 2, [12, 13], [22, 23])
            after = {path.name: path.read_bytes() for path in pathlib.Path(directory).iterdir()}
            prefix = second.aggregate.run_spec_digest[:16]
            self.assertEqual(
                by_sequence(after), [f"{prefix}-run-{n}.json" for n in range(1, 11)]
            )
            for name, payload in before.items():
                with self.subTest(history=name):
                    self.assertEqual(after[name], payload)
            self.assertEqual(second.aggregate_path.name, f"{prefix}-run-10.json")
            self.assertNotEqual(first.aggregate.content_digest(), second.aggregate.content_digest())

    def test_failed_attempt_keeps_taxonomy_and_orchestration_continues(self):
        execute = _FailOnNthCall(ValueError("boom"), 3)
        cold = [10, 20, 30, 40, 50]
        warm = [100, 200, 300, 400, 500]
        with tempfile.TemporaryDirectory() as directory:
            summary, execute = self.run_repeats_with_sources(
                directory, 5, cold, warm, execute=execute
            )
            self.assertEqual(execute.calls, 10)
            samples = summary.aggregate.to_canonical_value()["samples"]
            self.assertEqual(len(samples), 10)
            failures = [sample for sample in samples if sample["outcome"] != "success"]
            self.assertEqual(len(failures), 1)
            self.assertEqual(failures[0]["attempt_index"], 2)
            self.assertEqual(failures[0]["failure_code"], "EXECUTION_ERROR")
            # 4 cold + 5 warm successes still satisfy the all-or-nothing minimums;
            # percentiles use successful walls only: cold p50 rank=(50*4+99)//100=2 -> 20.
            self.assertEqual(summary.aggregate.status, "sufficient_sample")
            self.assertEqual(summary.aggregate.cold_p50_wall_time_ms, 20)
            self.assertEqual(summary.aggregate.cold_p95_wall_time_ms, 50)
            self.assertEqual(summary.aggregate.warm_p50_wall_time_ms, 300)
            self.assertEqual(summary.aggregate.warm_p95_wall_time_ms, 500)
            decoded = json.loads(summary.aggregate_path.read_bytes().decode("utf-8"))
            self.assertEqual(
                [s["failure_code"] for s in decoded["samples"]].count("EXECUTION_ERROR"), 1
            )

    def test_base_exception_persists_attempt_then_propagates_without_aggregate(self):
        execute = _FailOnNthCall(KeyboardInterrupt(), 3)
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(KeyboardInterrupt):
                self.run_repeats_with_sources(directory, 2, [10, 11], [20, 21], execute=execute)
            self.assertEqual(execute.calls, 3)
            names = sorted(path.name for path in pathlib.Path(directory).iterdir())
            prefix = json.loads(
                (pathlib.Path(directory) / names[0]).read_bytes().decode("utf-8")
            )["run_spec_digest"][:16]
            self.assertEqual(names, [f"{prefix}-run-{n}.json" for n in (1, 2, 3)])
            third = json.loads(
                (pathlib.Path(directory) / f"{prefix}-run-3.json").read_bytes().decode("utf-8")
            )
            self.assertEqual(third["samples"][0]["outcome"], "cancelled")
            self.assertEqual(third["samples"][0]["failure_code"], "EXECUTION_CANCELLED")
            for name in names:
                with self.subTest(file=name):
                    decoded = json.loads(
                        (pathlib.Path(directory) / name).read_bytes().decode("utf-8")
                    )
                    self.assertEqual(len(decoded["samples"]), 1)

    def test_missing_output_directory_fails_closed_before_execution(self):
        manifest = self.load_manifest()
        with tempfile.TemporaryDirectory() as directory:
            spec_path = self.write_json_file(
                directory, "spec.json", self.spec_mapping_from_manifest(manifest)
            )
            missing = pathlib.Path(directory) / "missing" / "baseline-out"
            args = self.baseline_args(spec_path, missing)
            recorder = _CountingExecute()
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                orchestrate.run_baseline_from_args(args, execute=recorder)
            self.assertIs(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
            )
            self.assertEqual(caught.exception.field_path, "$.output_dir")
            self.assertEqual(str(caught.exception), _OUTPUT_DIR_MESSAGE)
            self.assertEqual(recorder.calls, 0)
            self.assertFalse(missing.exists())


class TestGateStackNegatives(_IP0028CLITestCase):
    """FR-04 / SF-01: four negative classes fail closed at the CLI entry."""

    def test_sf01_four_negatives_fail_closed_with_zero_execution_zero_files(self):
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

        cases = (
            (
                "moving-ref",
                lambda mapping, _manifest: mapping["repositories"][0].update(commit_sha="main"),
                "pristine",
                BaselineRunSpecError,
                BaselineRunSpecErrorCode.MOVING_REF_REJECTED,
            ),
            (
                "abbreviated-sha",
                lambda mapping, _manifest: mapping["repositories"][0].update(commit_sha="1" * 12),
                "pristine",
                BaselineRunSpecError,
                BaselineRunSpecErrorCode.ABBREVIATED_COMMIT_SHA_REJECTED,
            ),
            (
                "dataset-fingerprint-drift",
                lambda mapping, _manifest: mapping["datasets"][0].update(fingerprint="9" * 64),
                "pristine",
                BaselineRunSpecError,
                BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH,
            ),
            (
                "self-consistent-role-swap",
                swap_roles,
                "swapped",
                collect.BaselineCollectionError,
                collect.BaselineCollectionErrorCode.ROLE_BINDING_MISMATCH,
            ),
        )
        for label, mutator, manifest_kind, error_type, code in cases:
            with self.subTest(case=label):
                mapping = copy.deepcopy(base_mapping)
                mutated_manifest = copy.deepcopy(manifest)
                mutator(mapping, mutated_manifest)
                with tempfile.TemporaryDirectory() as directory:
                    spec_path = self.write_json_file(directory, "spec.json", mapping)
                    manifest_path = self.write_json_file(
                        directory,
                        "manifest.json",
                        mutated_manifest if manifest_kind == "swapped" else manifest,
                    )
                    out_dir = pathlib.Path(directory) / "out"
                    out_dir.mkdir()
                    args = self.baseline_args(spec_path, out_dir)
                    recorder = _CountingExecute()
                    with self.assertRaises(error_type) as caught:
                        orchestrate.run_baseline_from_args(
                            args, execute=recorder, manifest_path=str(manifest_path)
                        )
                    self.assertIs(caught.exception.code, code)
                    self.assertEqual(recorder.calls, 0)
                    self.assertEqual(list(out_dir.iterdir()), [])


class TestWriterErratum(_IP0028CLITestCase):
    """FR-05: IP-0027 interface errata (sidecar collision; structure-only paths)."""

    def test_sidecar_only_collision_with_session_writes_next_sequence(self):
        digest = "c" * 64
        result = _success_result(digest)
        with tempfile.TemporaryDirectory() as directory:
            prefix = digest[:16]
            preset = pathlib.Path(directory) / f"{prefix}-run-1.expert-timing.json"
            preset.write_bytes(b'{"preset":true}')
            session = expert_timing.ExpertTimingSession("reviewer-r8")
            session.start(1_000_000)
            session.finish(2_000_000)
            artifacts = run.write_result_file(result, directory, expert_session=session)
            self.assertEqual(artifacts.result_path.name, f"{prefix}-run-2.json")
            self.assertEqual(
                artifacts.sidecar_path.name, f"{prefix}-run-2.expert-timing.json"
            )
            names = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(
                names,
                [
                    preset.name,
                    f"{prefix}-run-2.expert-timing.json",
                    f"{prefix}-run-2.json",
                ],
            )
            self.assertEqual(preset.read_bytes(), b'{"preset":true}')
            self.assertEqual(
                artifacts.result_path.read_bytes(), result.canonical_bytes()
            )
            self.assertEqual(
                artifacts.sidecar_path.read_bytes(),
                session.sidecar_bytes(result.run_spec_digest),
            )

    def test_sidecar_only_collision_without_session_writes_next_sequence(self):
        digest = "d" * 64
        result = _success_result(digest)
        with tempfile.TemporaryDirectory() as directory:
            prefix = digest[:16]
            preset = pathlib.Path(directory) / f"{prefix}-run-1.expert-timing.json"
            preset.write_bytes(b'{"preset":true}')
            artifacts = run.write_result_file(result, directory)
            self.assertEqual(artifacts.result_path.name, f"{prefix}-run-2.json")
            self.assertIsNone(artifacts.sidecar_path)
            names = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(names, [preset.name, f"{prefix}-run-2.json"])
            self.assertEqual(preset.read_bytes(), b'{"preset":true}')

    def test_attempt_with_session_in_occupied_directory_writes_run_two(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        session = expert_timing.ExpertTimingSession("reviewer-r8-attempt")
        session.start(1_000_000)
        session.finish(2_000_000)
        with tempfile.TemporaryDirectory() as directory:
            prefix = spec_from_mapping(mapping).content_digest()[:16]
            preset = pathlib.Path(directory) / f"{prefix}-run-1.expert-timing.json"
            preset.write_bytes(b'{"preset":true}')
            recorder = _CountingExecute()
            result = run.run_baseline_attempt(
                mapping,
                manifest,
                recorder,
                directory,
                sources=_repeat_sources([7], [9]),
                expert_session=session,
            )
            self.assertEqual(recorder.calls, 1)
            names = sorted(path.name for path in pathlib.Path(directory).iterdir())
            self.assertEqual(
                names,
                [
                    preset.name,
                    f"{prefix}-run-2.expert-timing.json",
                    f"{prefix}-run-2.json",
                ],
            )
            self.assertEqual(preset.read_bytes(), b'{"preset":true}')
            decoded = json.loads(
                (pathlib.Path(directory) / f"{prefix}-run-2.json").read_bytes().decode("utf-8")
            )
            self.assertEqual(decoded["samples"][0]["outcome"], "success")
            self.assertEqual(
                decoded["run_spec_digest"], result.run_spec_digest
            )

    def test_output_error_field_paths_are_structure_only_without_path_leak(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        with tempfile.TemporaryDirectory() as directory:
            sentinel = pathlib.Path(directory) / "sentinel.json"
            sentinel.write_bytes(b"x")
            supplied = str(sentinel)
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.write_exclusive(sentinel, b"replacement")
            self.assertIs(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_PATH_ALREADY_EXISTS,
            )
            self.assertEqual(caught.exception.field_path, "$.output_path")
            rendered = str(caught.exception)
            self.assertEqual(rendered, _OUTPUT_PATH_MESSAGE)
            self.assertNotIn(supplied, rendered)
            self.assertNotIn("\\", rendered)
            self.assertNotIn("/", rendered)

            missing = pathlib.Path(directory) / "missing"
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.write_result_file(_success_result("e" * 64), missing)
            self.assertIs(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
            )
            self.assertEqual(caught.exception.field_path, "$.output_dir")
            rendered = str(caught.exception)
            self.assertEqual(rendered, _OUTPUT_DIR_MESSAGE)
            self.assertNotIn(str(missing), rendered)

            recorder = _CountingExecute()
            with self.assertRaises(collect.BaselineCollectionError) as caught:
                run.run_baseline_attempt(
                    mapping, manifest, recorder, missing, sources=_repeat_sources([7], [9])
                )
            self.assertIs(
                caught.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
            )
            self.assertEqual(caught.exception.field_path, "$.output_dir")
            self.assertEqual(str(caught.exception), _OUTPUT_DIR_MESSAGE)
            self.assertNotIn(str(missing), str(caught.exception))
            self.assertEqual(recorder.calls, 0)


class TestPublicSurfaceAndHygiene(_IP0028CLITestCase):
    """FR-06 + frozen surface: imports, offline hygiene, summary face, default path."""

    def test_orchestrate_import_whitelist(self):
        tree = ast.parse(self.orchestrate_source("benchmarks/v4/baseline/orchestrate.py"))
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
                for candidate in _ORCHESTRATE_ALLOWED_PRODUCT_IMPORTS
            )
        else:
            allowed = root in _ORCHESTRATE_ALLOWED_STDLIB_IMPORTS
        self.assertTrue(
            allowed, f"import {module_name!r} is outside the frozen whitelist"
        )

    def test_offline_hygiene_source_scan(self):
        sources = [pathlib.Path(__file__).read_text(encoding="utf-8")]
        sources.append(self.orchestrate_source("benchmarks/v4/baseline/orchestrate.py"))
        for name in _SCRIPT_NAMES:
            sources.append(self.orchestrate_source(f"scripts/{name}.py"))
        for token in _forbidden_source_tokens():
            with self.subTest(token=token):
                for source in sources:
                    self.assertNotIn(token, source)

    def test_baseline_run_summary_surface(self):
        members = {member.name for member in orchestrate.BaselineOrchestrationErrorCode}
        self.assertEqual(members, set(_BASELINE_ERROR_CODES))
        for name in _BASELINE_ERROR_CODES:
            with self.subTest(code=name):
                member = orchestrate.BaselineOrchestrationErrorCode(name)
                self.assertEqual(member.value, name)
                error = orchestrate.BaselineOrchestrationError(member, "$.x")
                self.assertEqual(str(error), _BASELINE_ERROR_MESSAGES[name])
        self.assertTrue(issubclass(orchestrate.BaselineOrchestrationError, ValueError))
        summary_class = orchestrate.BaselineRunSummary
        self.assertTrue(dataclasses.is_dataclass(summary_class))
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(summary_class)), _SUMMARY_FIELDS
        )
        instance = summary_class(
            attempts=(),
            result_paths=(),
            aggregate=None,
            aggregate_path=pathlib.Path("aggregate.json"),
            aggregate_sha256="a" * 64,
            status="insufficient_sample",
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            instance.status = "sufficient_sample"
        self.assertFalse(hasattr(instance, "__dict__"))
        self.assertEqual(
            set(orchestrate.__all__),
            {
                "add_baseline_arguments",
                "BaselineOrchestrationError",
                "BaselineOrchestrationErrorCode",
                "BaselineRunSummary",
                "run_baseline_from_args",
                "run_repeats",
            },
        )

    def test_adapter_end_to_end_with_default_manifest_path(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping_from_manifest(manifest)
        with tempfile.TemporaryDirectory() as directory:
            spec_path = self.write_json_file(directory, "spec.json", mapping)
            out_dir = pathlib.Path(directory) / "baseline-out"
            out_dir.mkdir()
            args = self.baseline_args(spec_path, out_dir, repeat=1)
            recorder = _CountingExecute()
            summary = orchestrate.run_baseline_from_args(
                args, execute=recorder, sources=_repeat_sources([7], [9])
            )
            self.assertEqual(recorder.calls, 2)
            self.assertEqual(len(summary.attempts), 2)
            prefix = summary.aggregate.run_spec_digest[:16]
            self.assertEqual(
                summary.aggregate.run_spec_digest, spec_from_mapping(mapping).content_digest()
            )
            self.assert_summary_matches_directory(
                summary, out_dir, [f"{prefix}-run-{n}.json" for n in range(1, 4)]
            )
            samples = summary.aggregate.to_canonical_value()["samples"]
            self.assertEqual(
                [(sample["attempt_index"], sample["mode"]) for sample in samples],
                [(0, "cold"), (1, "warm")],
            )
            self.assertEqual(summary.status, "insufficient_sample")


if __name__ == "__main__":
    unittest.main()
