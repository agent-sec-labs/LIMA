"""Frozen acceptance tests for IP-0025: BaselineRunResult (Source Issue #206).

Contract under test (frozen by Coordinator Assignment v1.0, 2026-09-25; see
docs/LIMA_Implementation_Packet_IP-0025_BaselineRunResult.md):

- ``lima/baseline_run_result.py`` must expose exactly four public symbols:
  BaselineRunResultErrorCode (str-Enum, 9 codes), BaselineRunResultError
  (independent ``ValueError`` with ``code`` + ``field_path``), the frozen
  BaselineRunResult dataclass (8 fields) and ``from_mapping``.
- Strict schema-v1 reads (top-level 3 keys, closed 14-key samples), typed
  cross-field rules (SUCCESS_WALL_TIME_REQUIRED before FAILURE_CODE_CONFLICT),
  nearest-rank cold/warm p50/p95 aggregation over success wall times only, and
  the insufficient/sufficient sample policy (all-null versus all-int).
- Canonical JSON is delegated to ``lima.contracts.codec``; identical semantic
  input yields byte-identical bytes and digest, samples are emitted in
  ascending attempt_index order with no sample dropped, and constructed
  results are deeply immutable (MF-IP-0024-01/02 lessons applied up front).
- The whole suite is offline and secretless: deterministic, no network, no
  environment reads, no paid model calls.

Expected RED before implementation (product module absent):

    ModuleNotFoundError: No module named 'lima.baseline_run_result'
"""

import ast
import contextlib
import dataclasses
import enum
import hashlib
import json
import pathlib
import unittest

from lima.baseline_run_result import (
    BaselineRunResult,
    BaselineRunResultError,
    BaselineRunResultErrorCode,
    from_mapping,
)
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError

_DIGEST_A = "a" * 64

_METRIC_FIELDS = (
    "wall_time_ms",
    "queue_time_ms",
    "cpu_time_ms",
    "expert_time_ms",
    "memory_rss_peak_bytes",
    "io_read_bytes",
    "io_write_bytes",
    "prompt_tokens",
    "completion_tokens",
    "cost_micro_usd",
)

_SAMPLE_FIELDS = ("attempt_index", "mode", "outcome") + _METRIC_FIELDS + ("failure_code",)

_REQUIRED_TOP_LEVEL_FIELDS = ("schema_version", "run_spec_digest", "samples")

_RESULT_FIELDS = (
    "schema_version",
    "run_spec_digest",
    "samples",
    "status",
    "cold_p50_wall_time_ms",
    "cold_p95_wall_time_ms",
    "warm_p50_wall_time_ms",
    "warm_p95_wall_time_ms",
)

_PERCENTILE_FIELDS = (
    "cold_p50_wall_time_ms",
    "cold_p95_wall_time_ms",
    "warm_p50_wall_time_ms",
    "warm_p95_wall_time_ms",
)

_FROZEN_ERROR_CODES = (
    "SCHEMA_VERSION_INVALID",
    "REQUIRED_FIELD_MISSING",
    "UNKNOWN_FIELD",
    "INVALID_FIELD_TYPE",
    "INVALID_FIELD_VALUE",
    "INVALID_DIGEST",
    "DUPLICATE_ATTEMPT_INDEX",
    "FAILURE_CODE_CONFLICT",
    "SUCCESS_WALL_TIME_REQUIRED",
)

_KNOWN_OUTCOMES = (
    "success",
    "failure",
    "cancelled",
    "timeout",
    "oom",
    "rate_limited",
)

_ALLOWED_STDLIB_IMPORT_ROOTS = frozenset({"dataclasses", "enum", "math", "re", "typing"})
_ALLOWED_LIMA_IMPORTS = ("lima.contracts.codec",)


def _forbidden_source_tokens():
    """Tokens that must never appear in the product module or in this file."""
    return [
        "os." + "environ",
        "get" + "env",
        "sock" + "et",
        "url" + "lib",
        "requ" + "ests",
    ]


def _sample(attempt_index, **overrides):
    sample = {
        "attempt_index": attempt_index,
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
    sample.update(overrides)
    return sample


def _failure_sample(attempt_index, outcome="timeout", failure_code="MODEL_TIMEOUT", **overrides):
    sample = _sample(attempt_index, outcome=outcome, failure_code=failure_code)
    sample["wall_time_ms"] = None
    sample.update(overrides)
    return sample


def _warm_samples(walls):
    return [
        _sample(100 + index, mode="warm", wall_time_ms=wall)
        for index, wall in enumerate(walls)
    ]


def _sufficient_samples():
    """3 cold + 5 warm successes: p50/p95 = (200, 300) cold and (30, 50) warm."""
    cold = [
        _sample(0, mode="cold", wall_time_ms=100),
        _sample(1, mode="cold", wall_time_ms=200),
        _sample(2, mode="cold", wall_time_ms=300),
    ]
    return cold + _warm_samples((10, 20, 30, 40, 50))


def _result_mapping(samples=None, **overrides):
    mapping = {
        "schema_version": 1,
        "run_spec_digest": _DIGEST_A,
        "samples": _sufficient_samples() if samples is None else samples,
    }
    mapping.update(overrides)
    return mapping


def _product_module_source():
    path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "lima"
        / "baseline_run_result.py"
    )
    return path.read_text(encoding="utf-8")


class _FrozenResultTestCase(unittest.TestCase):
    """Shared assertion helpers for the frozen contract (no collected tests)."""

    def assert_from_mapping_rejected(self, mapping, code, fragment=None):
        with self.assertRaises(BaselineRunResultError) as caught:
            from_mapping(mapping)
        self.assertEqual(caught.exception.code, code)
        if fragment is not None:
            self.assertIn(fragment, caught.exception.field_path)

    def assert_percentiles(self, result, cold_p50, cold_p95, warm_p50, warm_p95):
        self.assertEqual(result.cold_p50_wall_time_ms, cold_p50)
        self.assertEqual(result.cold_p95_wall_time_ms, cold_p95)
        self.assertEqual(result.warm_p50_wall_time_ms, warm_p50)
        self.assertEqual(result.warm_p95_wall_time_ms, warm_p95)


class TestPublicContractSurface(_FrozenResultTestCase):
    """AC-4 / S-14: symbol surface, error shape, static offline guarantees."""

    def test_error_code_enum_is_str_enum_with_exact_nine_members(self):
        self.assertTrue(issubclass(BaselineRunResultErrorCode, enum.Enum))
        self.assertTrue(issubclass(BaselineRunResultErrorCode, str))
        self.assertEqual(
            {member.name for member in BaselineRunResultErrorCode},
            set(_FROZEN_ERROR_CODES),
        )
        for name in _FROZEN_ERROR_CODES:
            with self.subTest(code=name):
                member = BaselineRunResultErrorCode(name)
                self.assertEqual(member.value, name)

    def test_error_class_shape_and_stable_messages(self):
        self.assertTrue(issubclass(BaselineRunResultError, ValueError))
        self.assertFalse(issubclass(BaselineRunResultError, ContractError))
        with self.assertRaises(BaselineRunResultError) as caught:
            from_mapping(_result_mapping(run_spec_digest="Z" * 64))
        exception = caught.exception
        self.assertEqual(exception.code, BaselineRunResultErrorCode.INVALID_DIGEST)
        self.assertIsInstance(exception.field_path, str)
        # Stable catalog message: the same code from a different raw input
        # renders identically and never embeds the offending raw value.
        with self.assertRaises(BaselineRunResultError) as second:
            from_mapping(_result_mapping(run_spec_digest="not-hex-at-all"))
        self.assertEqual(str(second.exception), str(exception))
        self.assertNotIn("Z" * 8, str(exception))
        self.assertNotIn("not-hex-at-all", str(exception))

    def test_result_is_frozen_dataclass_with_exact_eight_fields(self):
        result = from_mapping(_result_mapping())
        self.assertIsInstance(result, BaselineRunResult)
        self.assertTrue(dataclasses.is_dataclass(result))
        self.assertEqual(
            {field.name for field in dataclasses.fields(result)},
            set(_RESULT_FIELDS),
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.status = "insufficient_sample"

    def test_module_public_symbols_are_exactly_four(self):
        import lima.baseline_run_result as product

        self.assertEqual(
            set(product.__all__),
            {
                "BaselineRunResult",
                "BaselineRunResultError",
                "BaselineRunResultErrorCode",
                "from_mapping",
            },
        )
        self.assertIs(product.BaselineRunResult, BaselineRunResult)
        self.assertIs(product.BaselineRunResultError, BaselineRunResultError)
        self.assertIs(product.BaselineRunResultErrorCode, BaselineRunResultErrorCode)
        self.assertIs(product.from_mapping, from_mapping)

    def test_module_import_whitelist(self):
        tree = ast.parse(_product_module_source())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._assert_module_allowed(alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "relative imports are not allowed")
                self._assert_module_allowed(node.module or "")

    def _assert_module_allowed(self, module_name):
        root = module_name.split(".")[0]
        if root == "lima":
            allowed = any(
                module_name == candidate or module_name.startswith(candidate + ".")
                for candidate in _ALLOWED_LIMA_IMPORTS
            )
        else:
            allowed = root in _ALLOWED_STDLIB_IMPORT_ROOTS
        self.assertTrue(
            allowed,
            f"import {module_name!r} is outside the frozen whitelist",
        )

    def test_module_source_has_no_network_or_environment_access(self):
        source = _product_module_source()
        for token in _forbidden_source_tokens():
            with self.subTest(token=token):
                self.assertNotIn(token, source)

    def test_suite_source_is_offline_and_secretless(self):
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        for token in _forbidden_source_tokens():
            with self.subTest(token=token):
                self.assertNotIn(token, source)


class TestCanonicalDeterminism(_FrozenResultTestCase):
    """S3 / S9 / S13: byte-stable canonical JSON, order invariance, no caching."""

    def test_same_input_produces_identical_bytes_and_digest(self):
        first = from_mapping(_result_mapping())
        second = from_mapping(_result_mapping())
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.content_digest(), second.content_digest())

    def test_digest_is_lowercase_hex_sha256_of_canonical_bytes(self):
        result = from_mapping(_result_mapping())
        digest = result.content_digest()
        self.assertIsInstance(digest, str)
        self.assertRegex(digest, "^[0-9a-f]{64}$")
        self.assertEqual(digest, hashlib.sha256(result.canonical_bytes()).hexdigest())
        self.assertEqual(digest, compute_content_digest(result.canonical_bytes()))

    def test_canonical_bytes_are_sorted_compact_utf8_json(self):
        result = from_mapping(_result_mapping())
        raw = result.canonical_bytes()
        self.assertIsInstance(raw, bytes)
        text = raw.decode("utf-8")
        loaded = json.loads(text)
        self.assertEqual(loaded, result.to_canonical_value())
        self.assertEqual(
            raw,
            json.dumps(
                loaded, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8"),
        )
        self.assertNotIn(b"\r", raw)
        self.assertNotIn(b"\n", raw)

    def test_canonical_value_covers_exact_top_level_fields(self):
        value = from_mapping(_result_mapping()).to_canonical_value()
        self.assertIsInstance(value, dict)
        self.assertEqual(set(value), set(_RESULT_FIELDS))
        self.assertEqual(value["schema_version"], 1)
        self.assertIn(value["status"], ("sufficient_sample", "insufficient_sample"))
        self.assertNotIn("created_at", value)
        self.assertNotIn("digest", value)
        self.assertNotIn("canonical_bytes", value)

    def test_samples_sorted_by_attempt_index_and_permutation_invariant(self):
        samples = _sufficient_samples()
        straight = from_mapping(_result_mapping(samples=list(samples)))
        shuffled = from_mapping(_result_mapping(samples=list(reversed(samples))))
        self.assertEqual(straight.canonical_bytes(), shuffled.canonical_bytes())
        self.assertEqual(straight.content_digest(), shuffled.content_digest())
        indices = [
            sample["attempt_index"] for sample in straight.to_canonical_value()["samples"]
        ]
        self.assertEqual(indices, sorted(indices))
        self.assertEqual(set(indices), {sample["attempt_index"] for sample in samples})
        # Key insertion order inside each sample is irrelevant (codec sorts keys).
        remapped = _result_mapping()
        remapped["samples"] = [
            dict(reversed(list(sample.items()))) for sample in samples
        ]
        self.assertEqual(from_mapping(remapped).canonical_bytes(), straight.canonical_bytes())

    def test_all_samples_preserved_verbatim_in_canonical_output(self):
        failure = _failure_sample(
            8, outcome="timeout", queue_time_ms=7, prompt_tokens=128
        )
        oom = _failure_sample(9, outcome="oom", failure_code="WORKER_OOM", wall_time_ms=12)
        samples = _sufficient_samples() + [failure, oom]
        result = from_mapping(_result_mapping(samples=samples))
        canonical_samples = result.to_canonical_value()["samples"]
        self.assertEqual(len(canonical_samples), 10)
        expected = sorted(samples, key=lambda sample: sample["attempt_index"])
        self.assertEqual(canonical_samples, expected)


class TestStrictFieldValidation(_FrozenResultTestCase):
    """S1 / S2 / S6: strict top-level and sample structural validation."""

    def test_top_level_shape_and_schema_version_rules(self):
        for bad_input in ([], "nope", 7, None):
            with self.subTest(bad=type(bad_input).__name__):
                self.assert_from_mapping_rejected(
                    bad_input, BaselineRunResultErrorCode.INVALID_FIELD_TYPE
                )
        for field in _REQUIRED_TOP_LEVEL_FIELDS:
            with self.subTest(field=field):
                mapping = _result_mapping()
                del mapping[field]
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.REQUIRED_FIELD_MISSING,
                    fragment=field,
                )
        # status and percentiles are computed by the module, never carried in.
        for extra in ("status", "cold_p50_wall_time_ms", "created_at"):
            with self.subTest(extra=extra):
                mapping = _result_mapping()
                mapping[extra] = "value"
                self.assert_from_mapping_rejected(
                    mapping, BaselineRunResultErrorCode.UNKNOWN_FIELD
                )
        for bad_value in (0, 2, -1):
            with self.subTest(value=bad_value):
                self.assert_from_mapping_rejected(
                    _result_mapping(schema_version=bad_value),
                    BaselineRunResultErrorCode.SCHEMA_VERSION_INVALID,
                )
        for bad_value in ("1", True, 1.0, None):
            with self.subTest(value=repr(bad_value)):
                self.assert_from_mapping_rejected(
                    _result_mapping(schema_version=bad_value),
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                )
        for bad_samples in ("nope", {}, (), 7):
            with self.subTest(samples=type(bad_samples).__name__):
                self.assert_from_mapping_rejected(
                    _result_mapping(samples=bad_samples),
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                )
        # An empty sample list is a legal input (yields insufficient_sample).
        from_mapping(_result_mapping(samples=[]))

    def test_run_spec_digest_rules(self):
        for bad_type in (123, None, ["a" * 64]):
            with self.subTest(bad=type(bad_type).__name__):
                self.assert_from_mapping_rejected(
                    _result_mapping(run_spec_digest=bad_type),
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                    fragment="run_spec_digest",
                )
        for bad_value in ("z" * 64, "a" * 63, "a" * 65, "A" * 64, "aB" + "a" * 62, "a b"):
            with self.subTest(bad=bad_value[:6] + "..."):
                self.assert_from_mapping_rejected(
                    _result_mapping(run_spec_digest=bad_value),
                    BaselineRunResultErrorCode.INVALID_DIGEST,
                    fragment="run_spec_digest",
                )
        for good in ("0" * 64, "9" * 64, "a" * 64, "f" * 64, "0123456789abcdef" * 4):
            with self.subTest(good=good[:6] + "..."):
                from_mapping(_result_mapping(run_spec_digest=good))

    def test_sample_structure_rules(self):
        for bad in ("x", 5, None, [_sample(0)]):
            with self.subTest(bad=type(bad).__name__):
                self.assert_from_mapping_rejected(
                    _result_mapping(samples=[bad]),
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                    fragment="samples",
                )
        for field in _SAMPLE_FIELDS:
            with self.subTest(field=field):
                mapping = _result_mapping()
                del mapping["samples"][0][field]
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.REQUIRED_FIELD_MISSING,
                    fragment=field,
                )
        for extra in ("notes", "retry_of"):
            with self.subTest(extra=extra):
                mapping = _result_mapping()
                mapping["samples"][0][extra] = 1
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.UNKNOWN_FIELD,
                    fragment=extra,
                )


class TestSampleContract(_FrozenResultTestCase):
    """S3 / S4 / S5 / S8: attempt identity, mode, outcome, failure codes."""

    def test_attempt_index_type_range_and_uniqueness(self):
        for bad_type in (True, 1.0, "0", None):
            with self.subTest(bad=repr(bad_type)):
                mapping = _result_mapping()
                mapping["samples"][0]["attempt_index"] = bad_type
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                    fragment="attempt_index",
                )
        for bad_range in (-1, 2**63):
            with self.subTest(bad=bad_range):
                mapping = _result_mapping()
                mapping["samples"][0]["attempt_index"] = bad_range
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.INVALID_FIELD_VALUE,
                    fragment="attempt_index",
                )
        # Boundaries 0 and 2**63 - 1 are accepted.
        mapping = _result_mapping()
        mapping["samples"][0]["attempt_index"] = 2**63 - 1
        from_mapping(mapping)
        duplicate = _result_mapping()
        duplicate["samples"][1]["attempt_index"] = duplicate["samples"][0]["attempt_index"]
        self.assert_from_mapping_rejected(
            duplicate,
            BaselineRunResultErrorCode.DUPLICATE_ATTEMPT_INDEX,
            fragment="attempt_index",
        )

    def test_mode_domain(self):
        for accepted in ("cold", "warm"):
            with self.subTest(mode=accepted):
                mapping = _result_mapping()
                mapping["samples"][0]["mode"] = accepted
                from_mapping(mapping)
        for rejected in ("hot", "COLD", "cold ", ""):
            with self.subTest(mode=repr(rejected)):
                mapping = _result_mapping()
                mapping["samples"][0]["mode"] = rejected
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.INVALID_FIELD_VALUE,
                    fragment="mode",
                )
        for bad_type in (1, None, ["cold"], 1.5):
            with self.subTest(bad=type(bad_type).__name__):
                mapping = _result_mapping()
                mapping["samples"][0]["mode"] = bad_type
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                    fragment="mode",
                )

    def test_outcome_domain_is_open_with_shape_rules(self):
        for outcome in _KNOWN_OUTCOMES + ("agent_aborted", "z"):
            with self.subTest(outcome=outcome):
                if outcome == "success":
                    replacement = _sample(0, wall_time_ms=100)
                else:
                    replacement = _failure_sample(
                        0, outcome=outcome, failure_code="OUTCOME_PROBE"
                    )
                samples = [replacement] + _sufficient_samples()[1:]
                from_mapping(_result_mapping(samples=samples))
        for malformed in ("Success", "1start", "success!", "x" * 65, ""):
            with self.subTest(outcome=repr(malformed[:10])):
                mapping = _result_mapping()
                mapping["samples"][0]["outcome"] = malformed
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.INVALID_FIELD_VALUE,
                    fragment="outcome",
                )
        for bad_type in (5, None, 1.5, ["success"]):
            with self.subTest(bad=type(bad_type).__name__):
                mapping = _result_mapping()
                mapping["samples"][0]["outcome"] = bad_type
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                    fragment="outcome",
                )

    def test_failure_code_shape_and_content_bounds(self):
        def mapping_with_code(code):
            cold = [_failure_sample(0, failure_code=code)] + _sufficient_samples()[1:]
            return _result_mapping(samples=cold)

        for accepted in ("MODEL_TIMEOUT", "A", "A_1", "A" * 64):
            with self.subTest(code=accepted[:12] + "..."):
                from_mapping(mapping_with_code(accepted))
        for rejected in ("timeout", "1X", "MODEL TIMEOUT", "A" * 65, "A-1"):
            with self.subTest(code=repr(rejected[:12])):
                self.assert_from_mapping_rejected(
                    mapping_with_code(rejected),
                    BaselineRunResultErrorCode.INVALID_FIELD_VALUE,
                    fragment="failure_code",
                )
        # S8: the bounded stable-code charset keeps raw exception text, paths,
        # secrets, prompts and source snippets out of stored failure codes.
        for forbidden_content in (
            "Traceback (most recent call last): RuntimeError: boom",
            "/etc/passwd",
            "sk-1234567890abcdef",
            "SELECT * FROM users",
        ):
            with self.subTest(forbidden=forbidden_content[:12] + "..."):
                self.assert_from_mapping_rejected(
                    mapping_with_code(forbidden_content),
                    BaselineRunResultErrorCode.INVALID_FIELD_VALUE,
                    fragment="failure_code",
                )
        for bad_type in (5, True, [], 1.5):
            with self.subTest(bad=type(bad_type).__name__):
                self.assert_from_mapping_rejected(
                    mapping_with_code(bad_type),
                    BaselineRunResultErrorCode.INVALID_FIELD_TYPE,
                    fragment="failure_code",
                )


class TestNullMetricSemantics(_FrozenResultTestCase):
    """S6 / S7 + supplement B: null versus zero, typed cross-field rejection."""

    def test_metric_field_type_and_range_rules(self):
        for field in _METRIC_FIELDS:
            for bad_type in (True, 1.5, "5", [3]):
                with self.subTest(field=field, bad=repr(bad_type)):
                    mapping = _result_mapping()
                    mapping["samples"][0][field] = bad_type
                    self.assert_from_mapping_rejected(
                        mapping, BaselineRunResultErrorCode.INVALID_FIELD_TYPE
                    )
            for bad_range in (-1, 2**63):
                with self.subTest(field=field, bad=bad_range):
                    mapping = _result_mapping()
                    mapping["samples"][0][field] = bad_range
                    self.assert_from_mapping_rejected(
                        mapping, BaselineRunResultErrorCode.INVALID_FIELD_VALUE
                    )
        # int64 ceiling and explicit zero are legitimate observed values.
        ceiling = _result_mapping()
        for sample in ceiling["samples"]:
            for field in _METRIC_FIELDS:
                sample[field] = 2**63 - 1
        from_mapping(ceiling)
        zeros = _result_mapping()
        for sample in zeros["samples"]:
            for field in _METRIC_FIELDS:
                sample[field] = 0
        from_mapping(zeros)

    def test_null_metrics_preserved_as_null_and_distinct_from_zero(self):
        result = from_mapping(_result_mapping())
        for sample in result.to_canonical_value()["samples"]:
            for field in _METRIC_FIELDS:
                if field == "wall_time_ms":
                    continue
                self.assertIsNone(sample[field], f"{field} must stay null, not default to 0")
        zeroed = _result_mapping()
        for sample in zeroed["samples"]:
            sample["cost_micro_usd"] = 0
        zero_result = from_mapping(zeroed)
        self.assertEqual(
            zero_result.to_canonical_value()["samples"][0]["cost_micro_usd"], 0
        )
        self.assertNotEqual(zero_result.content_digest(), result.content_digest())

    def test_success_wall_time_required_checked_before_conflict(self):
        missing_wall = _result_mapping()
        missing_wall["samples"][0]["wall_time_ms"] = None
        self.assert_from_mapping_rejected(
            missing_wall,
            BaselineRunResultErrorCode.SUCCESS_WALL_TIME_REQUIRED,
            fragment="wall_time_ms",
        )
        # The wall-time rule takes precedence even when the failure-code rule
        # would also fire on the same success sample.
        both_broken = _result_mapping()
        both_broken["samples"][0]["wall_time_ms"] = None
        both_broken["samples"][0]["failure_code"] = "STALE_CODE"
        self.assert_from_mapping_rejected(
            both_broken, BaselineRunResultErrorCode.SUCCESS_WALL_TIME_REQUIRED
        )

    def test_failure_code_conflict_matrix(self):
        success_with_code = _result_mapping()
        success_with_code["samples"][0]["failure_code"] = "ANY_CODE"
        self.assert_from_mapping_rejected(
            success_with_code,
            BaselineRunResultErrorCode.FAILURE_CODE_CONFLICT,
            fragment="failure_code",
        )
        failure_without_code = _result_mapping()
        failure_without_code["samples"][0] = _failure_sample(0, failure_code=None)
        self.assert_from_mapping_rejected(
            failure_without_code, BaselineRunResultErrorCode.FAILURE_CODE_CONFLICT
        )
        failure_with_wall_but_no_code = _result_mapping()
        failure_with_wall_but_no_code["samples"][0] = _failure_sample(
            0, failure_code=None, wall_time_ms=123
        )
        self.assert_from_mapping_rejected(
            failure_with_wall_but_no_code,
            BaselineRunResultErrorCode.FAILURE_CODE_CONFLICT,
        )


class TestPercentileAggregation(_FrozenResultTestCase):
    """S10 / S11 + supplement A: nearest-rank aggregation and status policy."""

    def test_nearest_rank_percentile_exact_values(self):
        result = from_mapping(_result_mapping())
        self.assert_percentiles(result, 200, 300, 30, 50)
        cold20 = [
            _sample(10 + index, mode="cold", wall_time_ms=index + 1)
            for index in range(20)
        ]
        warm5 = _warm_samples((5, 10, 15, 20, 25))
        result20 = from_mapping(_result_mapping(samples=cold20 + warm5))
        self.assert_percentiles(result20, 10, 19, 15, 25)
        cold3 = [
            _sample(200 + index, mode="cold", wall_time_ms=wall)
            for index, wall in enumerate((100, 200, 300))
        ]
        warm40 = [
            _sample(300 + index, mode="warm", wall_time_ms=index + 1)
            for index in range(40)
        ]
        result40 = from_mapping(_result_mapping(samples=cold3 + warm40))
        self.assert_percentiles(result40, 200, 300, 20, 38)
        # Duplicated wall values and unsorted input still land on the exact
        # nearest-rank rank positions.
        duplicates = _warm_samples((7, 7, 7, 7, 7))
        result_dup = from_mapping(_result_mapping(samples=list(reversed(cold3 + duplicates))))
        self.assertEqual(result_dup.warm_p50_wall_time_ms, 7)
        self.assertEqual(result_dup.warm_p95_wall_time_ms, 7)

    def test_status_thresholds_and_null_policy(self):
        sufficient = from_mapping(_result_mapping())
        self.assertEqual(sufficient.status, "sufficient_sample")
        for field in _PERCENTILE_FIELDS:
            value = getattr(sufficient, field)
            self.assertIsInstance(value, int, field)
            self.assertNotIsInstance(value, bool, field)

        cold2 = [
            _sample(0, mode="cold", wall_time_ms=1),
            _sample(1, mode="cold", wall_time_ms=2),
        ]
        warm5 = _warm_samples((10, 20, 30, 40, 50))
        cases = {
            "cold_n_2": cold2 + warm5,
            "warm_n_4": _sufficient_samples()[:3] + _warm_samples((1, 2, 3, 4)),
            "empty_samples": [],
            "cold_only": [
                _sample(0, mode="cold", wall_time_ms=1),
                _sample(1, mode="cold", wall_time_ms=2),
                _sample(2, mode="cold", wall_time_ms=3),
            ],
            "cold_success_mixed_outcome": [
                _sample(0, mode="cold", wall_time_ms=1),
                _sample(1, mode="cold", wall_time_ms=2),
                _failure_sample(2),
            ] + warm5,
        }
        for label, samples in cases.items():
            with self.subTest(case=label):
                result = from_mapping(_result_mapping(samples=samples))
                self.assertEqual(result.status, "insufficient_sample")
                for field in _PERCENTILE_FIELDS:
                    self.assertIsNone(getattr(result, field), field)

    def test_percentiles_use_only_success_wall_times_per_mode(self):
        outlier_failure = _failure_sample(
            90, outcome="timeout", failure_code="MODEL_TIMEOUT", wall_time_ms=999999
        )
        cold = [
            _sample(0, mode="cold", wall_time_ms=100),
            _sample(1, mode="cold", wall_time_ms=200),
            _sample(2, mode="cold", wall_time_ms=300),
            outlier_failure,
        ]
        result = from_mapping(
            _result_mapping(samples=cold + _warm_samples((10, 20, 30, 40, 50)))
        )
        self.assert_percentiles(result, 200, 300, 30, 50)
        # Warm values never leak into cold percentiles and vice versa.
        warm_shifted = from_mapping(
            _result_mapping(samples=cold + _warm_samples((11, 22, 33, 44, 55)))
        )
        self.assertEqual(warm_shifted.cold_p50_wall_time_ms, result.cold_p50_wall_time_ms)
        self.assertEqual(warm_shifted.cold_p95_wall_time_ms, result.cold_p95_wall_time_ms)
        self.assert_percentiles(warm_shifted, 200, 300, 33, 55)


class TestDeepImmutability(_FrozenResultTestCase):
    """S12 + MF-IP-0024-01/02 lessons: constructed results are deeply immutable.

    Behavior-only invariants (internal container types are not pinned): any
    mutation attempt against the result, its samples collection, or any sample
    entry must either raise or leave the result with no observable change;
    after every failed attempt ``canonical_bytes()`` and ``content_digest()``
    must be unchanged. The mapping passed to ``from_mapping`` and the mutable
    plain JSON copy returned by ``to_canonical_value()`` may be mutated freely
    without affecting the result.
    """

    def _assert_result_stable(self, result, attempts):
        before_bytes = result.canonical_bytes()
        before_digest = result.content_digest()
        for index, attempt in enumerate(attempts):
            with self.subTest(attempt=index):
                # A raised error is an acceptable fail-closed outcome; a
                # silent observable change is the defect under test.
                with contextlib.suppress(Exception):
                    attempt()
                self.assertEqual(result.canonical_bytes(), before_bytes)
                self.assertEqual(result.content_digest(), before_digest)

    def test_result_samples_collection_and_entries_deeply_immutable(self):
        result = from_mapping(_result_mapping())
        samples = result.samples
        first = samples[0]
        extra = _sample(99)
        self._assert_result_stable(
            result,
            [
                lambda: samples.append(extra),
                lambda: samples.insert(0, dict(extra)),
                lambda: samples.extend([dict(extra)]),
                lambda: samples.pop(),
                lambda: samples.clear(),
                lambda: samples.__delitem__(0),
                lambda: samples.__setitem__(0, dict(extra)),
                lambda: first.__setitem__("wall_time_ms", 424242),
                lambda: first.__setitem__("failure_code", "INJECTED"),
                lambda: first.__setitem__("unfrozen_extra", "value"),
                lambda: first.__delitem__("attempt_index"),
                lambda: first.update({"mode": "warm"}),
                lambda: first.pop("outcome", None),
                lambda: setattr(first, "mode", "warm"),
            ],
        )

    def test_scalar_assignment_and_combined_barrage_leave_bytes_stable(self):
        result = from_mapping(_result_mapping())
        for field, value in (
            ("status", "insufficient_sample"),
            ("cold_p50_wall_time_ms", 0),
            ("warm_p95_wall_time_ms", None),
            ("run_spec_digest", "0" * 64),
            ("schema_version", 2),
            ("samples", []),
        ):
            with self.subTest(field=field):
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    setattr(result, field, value)
        self._assert_result_stable(
            result,
            [
                lambda: result.samples.append(_sample(98)),
                lambda: result.samples[1].__setitem__("wall_time_ms", 1),
                lambda: setattr(result, "status", "insufficient_sample"),
            ],
        )

    def test_standard_attribute_paths_expose_no_mutable_builtin_containers(self):
        """No mutable builtin container may be reachable via attribute access.

        Walks the result and the objects reachable from its frozen fields (the
        samples collection and its entries) and, for every dict/list/set/
        bytearray found through a standard (non-dunder) attribute, attempts
        representative mutations. Implementation names and container types are
        not pinned: the invariant is that any such attempt either raises or
        leaves ``canonical_bytes()`` and ``content_digest()`` unchanged.
        Dunder attributes such as ``__dict__`` and interpreter-level tampering
        (``object.__setattr__``, ctypes) are explicitly out of scope.
        """
        result = from_mapping(_result_mapping())
        before_bytes = result.canonical_bytes()
        before_digest = result.content_digest()
        targets = [result, result.samples]
        targets.extend(result.samples)
        for target in targets:
            for name in dir(target):
                if name.startswith("__"):
                    continue
                try:
                    value = getattr(target, name)
                except Exception:  # noqa: S112 -- probing; inaccessible attrs are skipped
                    continue
                if not isinstance(value, (dict, list, set, bytearray)):
                    continue
                with self.subTest(target=type(target).__name__, attribute=name):
                    with contextlib.suppress(Exception):
                        self._mutate_builtin_container(value)
                    self.assertEqual(result.canonical_bytes(), before_bytes)
                    self.assertEqual(result.content_digest(), before_digest)

    @staticmethod
    def _mutate_builtin_container(container):
        if isinstance(container, dict):
            container["__immutability_probe__"] = "probe"
            for key in list(container)[:1]:
                container[key] = "probe-replacement"
        elif isinstance(container, list):
            container.append("probe")
            if container:
                container[0] = "probe-replacement"
        elif isinstance(container, set):
            container.add("__immutability_probe__")
        elif isinstance(container, bytearray):
            container.extend(b"probe")

    def test_input_mapping_mutation_after_construction_does_not_affect_result(self):
        mapping = _result_mapping()
        result = from_mapping(mapping)
        before_bytes = result.canonical_bytes()
        before_digest = result.content_digest()
        mapping["samples"].append(_sample(99))
        mapping["samples"][0]["wall_time_ms"] = 424242
        mapping["samples"][0]["failure_code"] = "LATE_CODE"
        mapping["run_spec_digest"] = "0" * 64
        mapping["schema_version"] = 2
        self.assertEqual(result.canonical_bytes(), before_bytes)
        self.assertEqual(result.content_digest(), before_digest)

    def test_to_canonical_value_returns_mutable_json_copy_isolated_from_result(self):
        result = from_mapping(_result_mapping())
        before_bytes = result.canonical_bytes()
        before_digest = result.content_digest()
        value = result.to_canonical_value()
        second = result.to_canonical_value()
        self.assertIsInstance(value, dict)
        self.assertIsInstance(value["samples"], list)
        for sample in value["samples"]:
            self.assertIsInstance(sample, dict)
        # The copy must remain a plain, serializable, mutable JSON subset and
        # must be rebuilt fresh on every call (no cached canonical state).
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        self.assertIsNot(value, second)
        self.assertIsNot(value["samples"], second["samples"])
        value["status"] = "tampered"
        value["samples"].append(_sample(99))
        value["samples"][0]["wall_time_ms"] = 424242
        self.assertEqual(result.canonical_bytes(), before_bytes)
        self.assertEqual(result.content_digest(), before_digest)

    def test_instance_has_no_writable_attribute_dict(self):
        """MF-IP-0025-01 regression: no writable per-instance ``__dict__``.

        A frozen dataclass without slots still exposes a writable
        ``__dict__``: assigning ``result.__dict__["status"]`` rewrites frozen
        state and drifts ``canonical_bytes()``/``content_digest()`` without
        any exception. The invariant is that no ``__dict__`` exists at all,
        so the write path is naturally unreachable (``__dict__`` attribute
        access raises). Interpreter-level tampering (``object.__setattr__``,
        ctypes, pickle) remains out of scope.
        """
        result = from_mapping(_result_mapping())
        before_bytes = result.canonical_bytes()
        before_digest = result.content_digest()
        with self.subTest(probe="instance_has_no_attribute_dict"):
            self.assertFalse(hasattr(result, "__dict__"))
        with self.subTest(probe="vars_rejects_instance"):
            with self.assertRaises(TypeError):
                vars(result)
        with self.subTest(probe="attribute_dict_access_unreachable"):
            with self.assertRaises(AttributeError):
                result.__dict__  # noqa: B018 -- probing; raising is the assertion
        with self.subTest(probe="digest_stable_after_dict_write_attempt"):
            with contextlib.suppress(AttributeError):
                result.__dict__["status"] = "tampered"
            self.assertEqual(result.canonical_bytes(), before_bytes)
            self.assertEqual(result.content_digest(), before_digest)


if __name__ == "__main__":
    unittest.main()
