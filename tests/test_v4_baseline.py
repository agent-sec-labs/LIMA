"""Frozen acceptance tests for IP-0024: versioned BaselineRunSpec (Source Issue #204).

Contract under test (frozen by Coordinator Assignment v1.0, 2026-09-24; see
docs/LIMA_Implementation_Packet_IP-0024_BaselineRunSpec.md):

- ``lima/baseline_run_spec.py`` must expose BaselineRunSpecErrorCode (str-Enum),
  BaselineRunSpecError (independent Exception with ``code`` + ``field_path``),
  the frozen BaselineRunSpec dataclass, ``from_mapping``, the canonical-value /
  canonical-bytes / content-digest methods, ``load_baseline_run_spec`` and
  ``validate_baseline_manifest``.
- Strict from_mapping reads, canonical JSON via ``lima.contracts.codec``, the
  frozen typed-error matrix, revision triage, duplicate detection and the
  fail-closed manifest validation rules.
- D-1 machine-profile field semantics live only in ``TestAssumptionD1*`` classes
  and D-2 role-conflict predicate semantics only in ``TestAssumptionD2*``
  classes; decision-independent tests must not depend on anything defined
  inside those partitions (their fixtures are class-scoped).
- The whole suite is offline and secretless: deterministic, no network, no
  environment reads, no paid model calls.

Expected RED before implementation (product module absent):

    ModuleNotFoundError: No module named 'lima.baseline_run_spec'
"""

import ast
import contextlib
import copy
import dataclasses
import enum
import hashlib
import json
import pathlib
import sys
import tempfile
import unittest

from lima.baseline_run_spec import (
    BaselineRunSpec,
    BaselineRunSpecError,
    BaselineRunSpecErrorCode,
    from_mapping,
    load_baseline_run_spec,
    validate_baseline_manifest,
)
from lima.contracts.errors import ContractError

_COMMIT_SHA_A = "1" * 40
_COMMIT_SHA_B = "2" * 40
_FINGERPRINT_A = "a" * 64
_FINGERPRINT_B = "b" * 64
_FINGERPRINT_C = "c" * 64

_REQUIRED_TOP_LEVEL_FIELDS = (
    "schema_version",
    "repositories",
    "datasets",
    "analyzer_fingerprint",
    "config_digest",
    "seed",
    "machine_profile",
)

_FROZEN_ERROR_CODES = (
    "SCHEMA_VERSION_INVALID",
    "REQUIRED_FIELD_MISSING",
    "UNKNOWN_FIELD",
    "INVALID_FIELD_TYPE",
    "INVALID_FIELD_VALUE",
    "ABBREVIATED_COMMIT_SHA_REJECTED",
    "MOVING_REF_REJECTED",
    "INVALID_COMMIT_SHA",
    "DUPLICATE_REPOSITORY",
    "DATASET_FINGERPRINT_MISMATCH",
    "DATASET_ROLE_CONFLICT",
    "INVALID_FINGERPRINT",
    "MANIFEST_IDENTITY_CONFLICT",
)

_ALLOWED_STDLIB_IMPORT_ROOTS = frozenset(
    {"dataclasses", "enum", "hashlib", "json", "re", "typing"}
)
_ALLOWED_LIMA_IMPORTS = ("lima.contracts.codec", "lima.contracts.errors")


def _forbidden_source_tokens():
    """Tokens that must never appear in the product module or in this file."""
    return [
        "os." + "environ",
        "get" + "env",
        "sock" + "et",
        "url" + "lib",
        "requ" + "ests",
    ]


def _machine_profile():
    return {
        "profile_id": "lima-baseline-profile-001",
        "cpu_arch": "x86_64",
        "cpu_model": "declared-baseline-cpu",
        "cores": 8,
        "ram_gb": 32,
        "os_family": "linux",
        "python_version": "3.12.4",
        "gpu_summary": "none",
    }


def _spec_mapping(**overrides):
    mapping = {
        "schema_version": 1,
        "repositories": [
            {"identity": "agent-sec-labs/lima-fixture", "commit_sha": _COMMIT_SHA_A},
            {"identity": "mirror-team/reference-set", "commit_sha": _COMMIT_SHA_B},
        ],
        "datasets": [
            {
                "name": "popular-external-holdout-v2",
                "fingerprint": _FINGERPRINT_A,
                "role": "external-holdout",
            }
        ],
        "analyzer_fingerprint": _FINGERPRINT_B,
        "config_digest": _FINGERPRINT_C,
        "seed": 20260924,
        "machine_profile": _machine_profile(),
    }
    mapping.update(overrides)
    return mapping


def _manifest_mapping():
    return {
        "schema_version": 1,
        "datasets": [
            {
                "name": "popular-external-holdout-v2",
                "fingerprint": _FINGERPRINT_A,
                "role": "external-holdout",
                "license": "public",
                "source": "frozen-public-snapshot",
                "entries": [
                    {
                        "repository": "agent-sec-labs/lima-fixture",
                        "commit_sha": _COMMIT_SHA_A,
                    },
                    {
                        "repository": "mirror-team/reference-set",
                        "commit_sha": _COMMIT_SHA_B,
                    },
                ],
            }
        ],
    }


def _product_module_source():
    path = (
        pathlib.Path(__file__).resolve().parent.parent
        / "lima"
        / "baseline_run_spec.py"
    )
    return path.read_text(encoding="utf-8")


class _FrozenSpecTestCase(unittest.TestCase):
    """Shared assertion helpers for the frozen contract (no collected tests)."""

    def assert_from_mapping_rejected(self, mapping, code, fragment=None):
        with self.assertRaises(BaselineRunSpecError) as caught:
            from_mapping(mapping)
        self.assertEqual(caught.exception.code, code)
        if fragment is not None:
            self.assertIn(fragment, caught.exception.field_path)

    def assert_manifest_rejected(self, manifest, spec, code):
        with self.assertRaises(BaselineRunSpecError) as caught:
            validate_baseline_manifest(manifest, spec)
        self.assertEqual(caught.exception.code, code)


class TestPublicContractSurface(_FrozenSpecTestCase):
    """AC-5 / FR-01: symbol surface, error shape, static offline guarantees."""

    def test_error_code_enum_is_str_enum(self):
        self.assertTrue(issubclass(BaselineRunSpecErrorCode, enum.Enum))
        self.assertTrue(issubclass(BaselineRunSpecErrorCode, str))

    def test_error_codes_define_frozen_members(self):
        for name in _FROZEN_ERROR_CODES:
            with self.subTest(code=name):
                member = BaselineRunSpecErrorCode(name)
                self.assertEqual(member.value, name)

    def test_error_class_is_independent_exception(self):
        self.assertTrue(issubclass(BaselineRunSpecError, Exception))
        self.assertFalse(issubclass(BaselineRunSpecError, ContractError))
        with self.assertRaises(BaselineRunSpecError) as caught:
            from_mapping(_spec_mapping(schema_version=20260924))
        self.assertEqual(
            caught.exception.code, BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID
        )
        self.assertIsInstance(caught.exception.field_path, str)
        # ContractError-aligned shape: the rendered message embeds no raw value.
        self.assertNotIn("20260924", str(caught.exception))

    def test_spec_is_frozen_dataclass(self):
        spec = from_mapping(_spec_mapping())
        self.assertIsInstance(spec, BaselineRunSpec)
        self.assertTrue(dataclasses.is_dataclass(spec))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            spec.seed = 0

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

    def test_assumption_partitions_are_class_scoped(self):
        module_namespace = vars(sys.modules[__name__])
        partition_names = sorted(
            name
            for name in module_namespace
            if name.startswith(("TestAssumptionD1", "TestAssumptionD2"))
        )
        self.assertEqual(
            partition_names,
            [
                "TestAssumptionD1MachineProfileFields",
                "TestAssumptionD2DatasetRoleConflict",
            ],
        )


class TestCanonicalEncodingDeterminism(_FrozenSpecTestCase):
    """AC-1 / FR-02 / FR-06: byte-stable canonical JSON and SHA-256 digest."""

    def test_same_input_produces_identical_bytes_and_digest(self):
        first = from_mapping(_spec_mapping())
        second = from_mapping(_spec_mapping())
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.content_digest(), second.content_digest())
        self.assertEqual(first, second)

    def test_digest_is_lowercase_hex_sha256_of_canonical_bytes(self):
        spec = from_mapping(_spec_mapping())
        digest = spec.content_digest()
        self.assertIsInstance(digest, str)
        self.assertRegex(digest, "^[0-9a-f]{64}$")
        self.assertEqual(digest, hashlib.sha256(spec.canonical_bytes()).hexdigest())

    def test_canonical_bytes_are_sorted_compact_utf8_json(self):
        spec = from_mapping(_spec_mapping())
        raw = spec.canonical_bytes()
        self.assertIsInstance(raw, bytes)
        text = raw.decode("utf-8")
        loaded = json.loads(text)
        self.assertEqual(loaded, spec.to_canonical_value())
        self.assertEqual(
            raw,
            json.dumps(
                loaded, ensure_ascii=False, sort_keys=True, separators=(",", ":")
            ).encode("utf-8"),
        )
        self.assertNotIn(b"\r", raw)
        self.assertNotIn(b"\n", raw)

    def test_key_insertion_order_does_not_change_bytes(self):
        mapping = _spec_mapping()
        reordered = dict(reversed(list(mapping.items())))
        reordered["machine_profile"] = dict(
            reversed(list(mapping["machine_profile"].items()))
        )
        self.assertEqual(
            from_mapping(reordered).canonical_bytes(),
            from_mapping(mapping).canonical_bytes(),
        )

    def test_nfc_normalization_applies_to_string_fields(self):
        decomposed = _spec_mapping()
        decomposed["datasets"][0]["name"] = "cafe\u0301-holdout-set"
        composed = _spec_mapping()
        composed["datasets"][0]["name"] = "caf\u00e9-holdout-set"
        first = from_mapping(decomposed)
        second = from_mapping(composed)
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        self.assertEqual(first.content_digest(), second.content_digest())


class TestIdentityFieldSensitivity(_FrozenSpecTestCase):
    """AC-2 / FR-05 / FR-07: any identity field change changes the digest."""

    def test_each_identity_field_change_changes_digest(self):
        base = from_mapping(_spec_mapping()).content_digest()
        mutations = {
            "repository_identity": lambda m: m["repositories"][0].update(
                {"identity": "alternate-org/alternate-repo"}
            ),
            "repository_commit_sha": lambda m: m["repositories"][0].update(
                {"commit_sha": "3" * 40}
            ),
            "dataset_name": lambda m: m["datasets"][0].update(
                {"name": "renamed-holdout-set"}
            ),
            "dataset_fingerprint": lambda m: m["datasets"][0].update(
                {"fingerprint": "d" * 64}
            ),
            "dataset_role": lambda m: m["datasets"][0].update(
                {"role": "development"}
            ),
            "analyzer_fingerprint": lambda m: m.update(
                {"analyzer_fingerprint": "e" * 64}
            ),
            "config_digest": lambda m: m.update({"config_digest": "f" * 64}),
            "seed": lambda m: m.update({"seed": 999999}),
        }
        for label, mutate in mutations.items():
            with self.subTest(field=label):
                mutated = copy.deepcopy(_spec_mapping())
                mutate(mutated)
                self.assertNotEqual(from_mapping(mutated).content_digest(), base)

    def test_canonical_value_covers_exact_top_level_fields(self):
        value = from_mapping(_spec_mapping()).to_canonical_value()
        self.assertIsInstance(value, dict)
        self.assertEqual(set(value), set(_REQUIRED_TOP_LEVEL_FIELDS))
        self.assertEqual(value["schema_version"], 1)
        self.assertNotIn("created_at", value)
        self.assertNotIn("generated_at", value)
        self.assertNotIn("hostname", value)


class TestStrictFieldValidation(_FrozenSpecTestCase):
    """FR-01 / FR-02 / FR-05: strict from_mapping field validation."""

    def test_non_mapping_input_rejected(self):
        for bad_input in ([], "nope", 7, None):
            with self.subTest(bad=type(bad_input).__name__):
                self.assert_from_mapping_rejected(
                    bad_input, BaselineRunSpecErrorCode.INVALID_FIELD_TYPE
                )

    def test_missing_required_fields_rejected(self):
        for field in _REQUIRED_TOP_LEVEL_FIELDS:
            with self.subTest(field=field):
                mapping = _spec_mapping()
                del mapping[field]
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING,
                    fragment=field,
                )

    def test_unknown_top_level_field_rejected(self):
        mapping = _spec_mapping()
        mapping["created_at"] = "2026-09-24T00:00:00Z"
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.UNKNOWN_FIELD
        )

    def test_unknown_repository_field_rejected(self):
        mapping = _spec_mapping()
        mapping["repositories"][0]["requested_ref"] = "main"
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.UNKNOWN_FIELD
        )

    def test_unknown_dataset_field_rejected(self):
        mapping = _spec_mapping()
        mapping["datasets"][0]["split"] = "holdout"
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.UNKNOWN_FIELD
        )

    def test_schema_version_value_and_type_rules(self):
        for bad_value in (0, 2, -1):
            with self.subTest(value=bad_value):
                self.assert_from_mapping_rejected(
                    _spec_mapping(schema_version=bad_value),
                    BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID,
                )
        for bad_value in ("1", True, 1.0, None):
            with self.subTest(value=repr(bad_value)):
                self.assert_from_mapping_rejected(
                    _spec_mapping(schema_version=bad_value),
                    BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
                )

    def test_repositories_container_rules(self):
        self.assert_from_mapping_rejected(
            _spec_mapping(repositories="nope"),
            BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
        )
        self.assert_from_mapping_rejected(
            _spec_mapping(repositories=[]),
            BaselineRunSpecErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_from_mapping_rejected(
            _spec_mapping(repositories=["nope"]),
            BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
        )

    def test_datasets_container_rules(self):
        self.assert_from_mapping_rejected(
            _spec_mapping(datasets="nope"),
            BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
        )
        self.assert_from_mapping_rejected(
            _spec_mapping(datasets=[]),
            BaselineRunSpecErrorCode.INVALID_FIELD_VALUE,
        )
        self.assert_from_mapping_rejected(
            _spec_mapping(datasets=[{"name": "x"}]),
            BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING,
        )

    def test_seed_type_and_int64_bounds(self):
        for bad_seed in ("7", True, 7.0, None, [7]):
            with self.subTest(seed=repr(bad_seed)):
                self.assert_from_mapping_rejected(
                    _spec_mapping(seed=bad_seed),
                    BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
                )
        for out_of_range in (2**63, -(2**63) - 1):
            with self.subTest(seed=out_of_range):
                self.assert_from_mapping_rejected(
                    _spec_mapping(seed=out_of_range),
                    BaselineRunSpecErrorCode.INVALID_FIELD_VALUE,
                )
        for boundary_seed in (2**63 - 1, -(2**63)):
            with self.subTest(seed=boundary_seed):
                from_mapping(_spec_mapping(seed=boundary_seed))

    def test_fingerprint_fields_must_be_canonical_64_hex(self):
        for bad in ("z" * 64, "a" * 63, "a" * 65, "A" * 64, "a b" + "c" * 61):
            with self.subTest(bad=bad[:12] + "..."):
                self.assert_from_mapping_rejected(
                    _spec_mapping(analyzer_fingerprint=bad),
                    BaselineRunSpecErrorCode.INVALID_FINGERPRINT,
                )
        self.assert_from_mapping_rejected(
            _spec_mapping(analyzer_fingerprint=123),
            BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
        )
        self.assert_from_mapping_rejected(
            _spec_mapping(config_digest="g" * 64),
            BaselineRunSpecErrorCode.INVALID_FINGERPRINT,
        )
        mapping = _spec_mapping()
        mapping["datasets"][0]["fingerprint"] = "A" * 64
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.INVALID_FINGERPRINT
        )

    def test_repository_identity_invalid_shapes_rejected(self):
        for bad_identity in ("", "   ", "owner/repo x", "owner\\repo"):
            with self.subTest(identity=repr(bad_identity)):
                mapping = _spec_mapping()
                mapping["repositories"][0]["identity"] = bad_identity
                self.assert_from_mapping_rejected(
                    mapping, BaselineRunSpecErrorCode.INVALID_FIELD_VALUE
                )


class TestRevisionTriage(_FrozenSpecTestCase):
    """AC-3 / FR-03 / FR-04: frozen revision triage for commit_sha."""

    def _mapping_with_commit(self, commit_sha):
        mapping = _spec_mapping()
        mapping["repositories"][0]["commit_sha"] = commit_sha
        return mapping

    def test_full_length_lowercase_hex_sha_accepted(self):
        for good in ("1" * 40, "0123456789abcdef" + "0" * 24):
            with self.subTest(sha=good[:8] + "..."):
                from_mapping(self._mapping_with_commit(good))

    def test_abbreviated_sha_rejected(self):
        for short in ("1" * 7, "1" * 39, "abcdef1"):
            with self.subTest(sha=short):
                self.assert_from_mapping_rejected(
                    self._mapping_with_commit(short),
                    BaselineRunSpecErrorCode.ABBREVIATED_COMMIT_SHA_REJECTED,
                    fragment="commit_sha",
                )

    def test_moving_refs_rejected(self):
        moving_refs = (
            "main",
            "v1.2.3",
            "refs/heads/main",
            "feature/auth-flow",
            "release/1.0",
            "123abc",
            "A" * 40,
            "1" * 41,
        )
        for moving in moving_refs:
            with self.subTest(ref=moving):
                self.assert_from_mapping_rejected(
                    self._mapping_with_commit(moving),
                    BaselineRunSpecErrorCode.MOVING_REF_REJECTED,
                    fragment="commit_sha",
                )

    def test_non_hex_40_char_rejected(self):
        for bad in ("g" * 40, "z" * 40, "1" * 39 + "g", "0" * 39 + "Z"):
            with self.subTest(sha=bad[:8] + "..."):
                self.assert_from_mapping_rejected(
                    self._mapping_with_commit(bad),
                    BaselineRunSpecErrorCode.INVALID_COMMIT_SHA,
                    fragment="commit_sha",
                )

    def test_commit_sha_type_rules(self):
        for bad in (123, None, ["1" * 40]):
            with self.subTest(bad=type(bad).__name__):
                self.assert_from_mapping_rejected(
                    self._mapping_with_commit(bad),
                    BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
                )


class TestDuplicateRepositoryDetection(_FrozenSpecTestCase):
    """AC-4 / FR-08: duplicate repositories by normalized identity."""

    def test_distinct_identities_accepted(self):
        mapping = _spec_mapping()
        mapping["repositories"].append(
            {"identity": "third-team/third-repo", "commit_sha": "4" * 40}
        )
        from_mapping(mapping)

    def test_duplicate_identity_case_fold(self):
        mapping = _spec_mapping()
        mapping["repositories"][1]["identity"] = "Agent-Sec-Labs/LIMA-Fixture"
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )

    def test_duplicate_identity_git_suffix(self):
        mapping = _spec_mapping()
        mapping["repositories"][1]["identity"] = "agent-sec-labs/lima-fixture.git"
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )

    def test_duplicate_identity_url_form(self):
        mapping = _spec_mapping()
        mapping["repositories"][1]["identity"] = (
            "https://github.com/agent-sec-labs/lima-fixture"
        )
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )


class TestLoadBaselineRunSpec(_FrozenSpecTestCase):
    """AC-1 / FR-02: file loading is formatting-independent and fail-closed."""

    def test_roundtrip_from_canonical_file(self):
        spec = from_mapping(_spec_mapping())
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "baseline-run-spec.json"
            path.write_bytes(spec.canonical_bytes())
            loaded = load_baseline_run_spec(str(path))
        self.assertEqual(loaded, spec)
        self.assertEqual(loaded.content_digest(), spec.content_digest())
        self.assertEqual(loaded.canonical_bytes(), spec.canonical_bytes())

    def test_formatting_independent_load(self):
        spec = from_mapping(_spec_mapping())
        formatted = json.dumps(_spec_mapping(), indent=3)
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "formatted.json"
            path.write_text(formatted, encoding="utf-8")
            loaded = load_baseline_run_spec(str(path))
        self.assertEqual(loaded.content_digest(), spec.content_digest())

    def test_malformed_json_fails_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "broken.json"
            path.write_bytes(b'{"schema_version": 1, "repositories": [')
            with self.assertRaises(BaselineRunSpecError):
                load_baseline_run_spec(str(path))

    def test_invalid_contract_in_file_reports_typed_error(self):
        mapping = _spec_mapping()
        del mapping["seed"]
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "missing-seed.json"
            path.write_text(json.dumps(mapping), encoding="utf-8")
            with self.assertRaises(BaselineRunSpecError) as caught:
                load_baseline_run_spec(str(path))
        self.assertEqual(
            caught.exception.code, BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING
        )


class TestValidateBaselineManifest(_FrozenSpecTestCase):
    """AC-4 / FR-08: fail-closed spec-versus-manifest validation."""

    def test_valid_manifest_passes(self):
        spec = from_mapping(_spec_mapping())
        validate_baseline_manifest(_manifest_mapping(), spec)

    def test_dataset_fingerprint_mismatch_rejected(self):
        manifest = _manifest_mapping()
        manifest["datasets"][0]["fingerprint"] = "9" * 64
        spec = from_mapping(_spec_mapping())
        self.assert_manifest_rejected(
            manifest, spec, BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH
        )

    def test_manifest_identity_commit_conflict_rejected(self):
        manifest = _manifest_mapping()
        manifest["datasets"][0]["entries"][0]["commit_sha"] = "5" * 40
        spec = from_mapping(_spec_mapping())
        self.assert_manifest_rejected(
            manifest, spec, BaselineRunSpecErrorCode.MANIFEST_IDENTITY_CONFLICT
        )

    def test_spec_repository_missing_from_manifest_rejected(self):
        mapping = _spec_mapping()
        mapping["repositories"].append(
            {"identity": "third-team/third-repo", "commit_sha": "6" * 40}
        )
        spec = from_mapping(mapping)
        self.assert_manifest_rejected(
            _manifest_mapping(), spec, BaselineRunSpecErrorCode.MANIFEST_IDENTITY_CONFLICT
        )

    def test_manifest_identity_matches_despite_case_difference(self):
        mapping = _spec_mapping()
        mapping["repositories"][0]["identity"] = (
            "https://github.com/Agent-Sec-Labs/LIMA-Fixture"
        )
        spec = from_mapping(mapping)
        validate_baseline_manifest(_manifest_mapping(), spec)

    def test_within_dataset_duplicate_repository_rejected(self):
        manifest = _manifest_mapping()
        manifest["datasets"][0]["entries"].append(
            {
                "repository": "Agent-Sec-Labs/LIMA-Fixture",
                "commit_sha": _COMMIT_SHA_A,
            }
        )
        spec = from_mapping(_spec_mapping())
        self.assert_manifest_rejected(
            manifest, spec, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )

    def test_manifest_structural_rules(self):
        def without_dataset_field(field):
            manifest = _manifest_mapping()
            del manifest["datasets"][0][field]
            return manifest

        def without_entry_field(field):
            manifest = _manifest_mapping()
            del manifest["datasets"][0]["entries"][0][field]
            return manifest

        def with_overrides(**overrides):
            manifest = _manifest_mapping()
            manifest.update(overrides)
            return manifest

        broken_manifests = (
            (with_overrides(schema_version=2), BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID),
            (with_overrides(datasets="nope"), BaselineRunSpecErrorCode.INVALID_FIELD_TYPE),
            (with_overrides(datasets=[]), BaselineRunSpecErrorCode.INVALID_FIELD_VALUE),
            (without_dataset_field("fingerprint"), BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING),
            (without_dataset_field("entries"), BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING),
            (without_entry_field("repository"), BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING),
            (without_entry_field("commit_sha"), BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING),
        )
        spec = from_mapping(_spec_mapping())
        for manifest, code in broken_manifests:
            with self.subTest(code=code.value):
                self.assert_manifest_rejected(manifest, spec, code)

    def test_manifest_entry_extra_fields_tolerated(self):
        manifest = _manifest_mapping()
        manifest["datasets"][0]["entries"][0]["archive_sha256"] = "7" * 64
        manifest["datasets"][0]["risk_notes"] = "forward-compatible extra field"
        spec = from_mapping(_spec_mapping())
        validate_baseline_manifest(manifest, spec)

    def test_spec_dataset_absent_from_manifest_fails_closed(self):
        manifest = _manifest_mapping()
        manifest["datasets"][0]["name"] = "renamed-dataset"
        spec = from_mapping(_spec_mapping())
        with self.assertRaises(BaselineRunSpecError):
            validate_baseline_manifest(manifest, spec)


class TestAssumptionD1MachineProfileFields(_FrozenSpecTestCase):
    """D-1 partition: declarative machine profile semantics.

    Fixtures for this partition are class-scoped; decision-independent tests
    must not depend on anything defined here.
    """

    @staticmethod
    def _profile(**overrides):
        profile = {
            "profile_id": "d1-declared-profile-001",
            "cpu_arch": "x86_64",
            "cpu_model": "declared-baseline-cpu",
            "cores": 4,
            "ram_gb": 16,
            "os_family": "linux",
            "python_version": "3.11.9",
            "gpu_summary": "declared-gpu-summary",
        }
        profile.update(overrides)
        return profile

    def test_canonical_value_contains_exactly_declared_profile_fields(self):
        spec = from_mapping(_spec_mapping(machine_profile=self._profile()))
        profile = spec.to_canonical_value()["machine_profile"]
        self.assertIsInstance(profile, dict)
        self.assertEqual(
            set(profile),
            {
                "profile_id",
                "cpu_arch",
                "cpu_model",
                "cores",
                "ram_gb",
                "os_family",
                "python_version",
                "gpu_summary",
            },
        )
        self.assertNotIn("hostname", profile)
        self.assertNotIn("detected_at", profile)

    def test_cpu_arch_whitelist(self):
        for accepted in ("x86_64", "aarch64"):
            with self.subTest(cpu_arch=accepted):
                from_mapping(_spec_mapping(machine_profile=self._profile(cpu_arch=accepted)))
        for rejected_arch in ("arm64", "x86-64", "X86_64", "riscv"):
            with self.subTest(cpu_arch=rejected_arch):
                self.assert_from_mapping_rejected(
                    _spec_mapping(machine_profile=self._profile(cpu_arch=rejected_arch)),
                    BaselineRunSpecErrorCode.INVALID_FIELD_VALUE,
                    fragment="cpu_arch",
                )

    def test_os_family_whitelist(self):
        for accepted in ("linux", "windows", "darwin"):
            with self.subTest(os_family=accepted):
                from_mapping(_spec_mapping(machine_profile=self._profile(os_family=accepted)))
        for rejected_os in ("macos", "Linux", "osx", "WINDOWS"):
            with self.subTest(os_family=rejected_os):
                self.assert_from_mapping_rejected(
                    _spec_mapping(machine_profile=self._profile(os_family=rejected_os)),
                    BaselineRunSpecErrorCode.INVALID_FIELD_VALUE,
                    fragment="os_family",
                )

    def test_float_and_bool_rejected_for_integer_fields(self):
        for field in ("cores", "ram_gb"):
            for bad in (4.5, 16.0, True):
                with self.subTest(field=field, bad=repr(bad)):
                    self.assert_from_mapping_rejected(
                        _spec_mapping(machine_profile=self._profile(**{field: bad})),
                        BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
                    )

    def test_string_profile_field_type_rules(self):
        for field in ("profile_id", "cpu_model", "python_version", "gpu_summary"):
            for bad in (8, None, True, ["declared"]):
                with self.subTest(field=field, bad=repr(bad)):
                    self.assert_from_mapping_rejected(
                        _spec_mapping(machine_profile=self._profile(**{field: bad})),
                        BaselineRunSpecErrorCode.INVALID_FIELD_TYPE,
                    )

    def test_missing_profile_field_rejected(self):
        for field in (
            "profile_id",
            "cpu_arch",
            "cpu_model",
            "cores",
            "ram_gb",
            "os_family",
            "python_version",
            "gpu_summary",
        ):
            with self.subTest(field=field):
                profile = self._profile()
                del profile[field]
                self.assert_from_mapping_rejected(
                    _spec_mapping(machine_profile=profile),
                    BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING,
                    fragment=field,
                )

    def test_unknown_profile_field_rejected(self):
        profile = self._profile()
        profile["detected_hostname"] = "worker-01"
        self.assert_from_mapping_rejected(
            _spec_mapping(machine_profile=profile),
            BaselineRunSpecErrorCode.UNKNOWN_FIELD,
        )

    def test_machine_profile_change_changes_digest(self):
        first = from_mapping(_spec_mapping(machine_profile=self._profile(cores=4)))
        second = from_mapping(_spec_mapping(machine_profile=self._profile(cores=8)))
        self.assertNotEqual(first.content_digest(), second.content_digest())


class TestAssumptionD2DatasetRoleConflict(_FrozenSpecTestCase):
    """D-2 partition: frozen role set and the holdout/calibration crossing.

    Fixtures for this partition are class-scoped; decision-independent tests
    must not depend on anything defined here.
    """

    _FROZEN_ROLES = ("external-holdout", "calibration", "development")
    _SHARED_REPO = "crossing-team/shared-repo"

    def test_spec_accepts_exactly_frozen_roles(self):
        for role in self._FROZEN_ROLES:
            with self.subTest(role=role):
                mapping = _spec_mapping()
                mapping["datasets"] = [
                    {"name": "role-probe-set", "fingerprint": _FINGERPRINT_A, "role": role}
                ]
                from_mapping(mapping)

    def test_unknown_spec_role_rejected(self):
        for role in ("staging", "holdout", "external-holdout ", "HOLDOUT"):
            with self.subTest(role=repr(role)):
                mapping = _spec_mapping()
                mapping["datasets"][0]["role"] = role
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunSpecErrorCode.INVALID_FIELD_VALUE,
                    fragment="role",
                )

    def test_unknown_manifest_role_rejected(self):
        manifest = _manifest_mapping()
        manifest["datasets"][0]["role"] = "evaluation"
        spec = from_mapping(_spec_mapping())
        self.assert_manifest_rejected(
            manifest, spec, BaselineRunSpecErrorCode.INVALID_FIELD_VALUE
        )

    def test_holdout_calibration_cross_rejected_as_role_conflict(self):
        spec = from_mapping(self._crossing_spec())
        self.assert_manifest_rejected(
            self._crossing_manifest(),
            spec,
            BaselineRunSpecErrorCode.DATASET_ROLE_CONFLICT,
        )

    def test_same_role_cross_dataset_duplicate_reports_duplicate_repository(self):
        manifest, spec = self._development_duplicate_setup()
        self.assert_manifest_rejected(
            manifest, spec, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )

    def _crossing_spec(self):
        return {
            "schema_version": 1,
            "repositories": [
                {"identity": self._SHARED_REPO, "commit_sha": _COMMIT_SHA_A},
            ],
            "datasets": [
                {
                    "name": "holdout-set",
                    "fingerprint": _FINGERPRINT_A,
                    "role": "external-holdout",
                },
                {
                    "name": "calibration-set",
                    "fingerprint": _FINGERPRINT_B,
                    "role": "calibration",
                },
            ],
            "analyzer_fingerprint": _FINGERPRINT_B,
            "config_digest": _FINGERPRINT_C,
            "seed": 11,
            "machine_profile": _machine_profile(),
        }

    def _crossing_manifest(self):
        return {
            "schema_version": 1,
            "datasets": [
                {
                    "name": "holdout-set",
                    "fingerprint": _FINGERPRINT_A,
                    "role": "external-holdout",
                    "license": "public",
                    "source": "frozen-public-snapshot",
                    "entries": [
                        {
                            "repository": self._SHARED_REPO,
                            "commit_sha": _COMMIT_SHA_A,
                        }
                    ],
                },
                {
                    "name": "calibration-set",
                    "fingerprint": _FINGERPRINT_B,
                    "role": "calibration",
                    "license": "public",
                    "source": "frozen-public-snapshot",
                    "entries": [
                        {
                            "repository": self._SHARED_REPO,
                            "commit_sha": _COMMIT_SHA_A,
                        }
                    ],
                },
            ],
        }

    def _development_duplicate_setup(self):
        mapping = _spec_mapping()
        mapping["repositories"] = [
            {"identity": self._SHARED_REPO, "commit_sha": _COMMIT_SHA_A},
        ]
        mapping["datasets"] = [
            {
                "name": "dev-set-1",
                "fingerprint": _FINGERPRINT_A,
                "role": "development",
            },
            {
                "name": "dev-set-2",
                "fingerprint": _FINGERPRINT_B,
                "role": "development",
            },
        ]
        manifest = {
            "schema_version": 1,
            "datasets": [
                {
                    "name": "dev-set-1",
                    "fingerprint": _FINGERPRINT_A,
                    "role": "development",
                    "license": "public",
                    "source": "frozen-public-snapshot",
                    "entries": [
                        {
                            "repository": self._SHARED_REPO,
                            "commit_sha": _COMMIT_SHA_A,
                        }
                    ],
                },
                {
                    "name": "dev-set-2",
                    "fingerprint": _FINGERPRINT_B,
                    "role": "development",
                    "license": "public",
                    "source": "frozen-public-snapshot",
                    "entries": [
                        {
                            "repository": self._SHARED_REPO,
                            "commit_sha": _COMMIT_SHA_A,
                        }
                    ],
                },
            ],
        }
        return manifest, from_mapping(mapping)


class TestDeepImmutability(_FrozenSpecTestCase):
    """MF-IP-0024-01 regression: constructed specs must be deeply immutable.

    Behavior-only invariants (internal container types are not pinned): any
    mutation attempt against the repositories collection or its entries, the
    datasets collection or its entries, or any machine_profile field must
    either raise or leave the spec with no observable change; after every
    failed attempt ``canonical_bytes()`` and ``content_digest()`` must be
    unchanged. The mapping passed to ``from_mapping`` and the mutable plain
    JSON copy returned by ``to_canonical_value()`` may be mutated freely
    without affecting the spec, and specs returned by
    ``load_baseline_run_spec`` obey the same deep immutability.
    """

    _REPLACEMENT_COMMIT = "9" * 40
    _REPLACEMENT_FINGERPRINT = "9" * 64

    def _assert_spec_stable(self, spec, attempts):
        before_bytes = spec.canonical_bytes()
        before_digest = spec.content_digest()
        for index, attempt in enumerate(attempts):
            with self.subTest(attempt=index):
                # A raised error is an acceptable fail-closed outcome; a
                # silent observable change is the defect under test.
                with contextlib.suppress(Exception):
                    attempt()
                self.assertEqual(spec.canonical_bytes(), before_bytes)
                self.assertEqual(spec.content_digest(), before_digest)

    def test_spec_repositories_collection_and_entries_are_deeply_immutable(self):
        spec = from_mapping(_spec_mapping())
        repositories = spec.repositories
        first = repositories[0]
        extra = {"identity": "extra-team/extra-repo", "commit_sha": "8" * 40}
        self._assert_spec_stable(
            spec,
            [
                lambda: repositories.append(extra),
                lambda: repositories.insert(0, dict(extra)),
                lambda: repositories.extend([dict(extra)]),
                lambda: repositories.pop(),
                lambda: repositories.clear(),
                lambda: repositories.__delitem__(0),
                lambda: repositories.__setitem__(0, dict(extra)),
                lambda: first.__setitem__("identity", "mutated-owner/mutated-repo"),
                lambda: first.__setitem__("commit_sha", self._REPLACEMENT_COMMIT),
                lambda: first.__setitem__("unfrozen_extra", "value"),
                lambda: first.__delitem__("identity"),
                lambda: first.update(
                    {"identity": "u-owner/u-repo", "commit_sha": "7" * 40}
                ),
                lambda: first.pop("commit_sha", None),
                lambda: setattr(first, "identity", "attr-owner/attr-repo"),
            ],
        )

    def test_spec_datasets_collection_and_entries_are_deeply_immutable(self):
        spec = from_mapping(_spec_mapping())
        datasets = spec.datasets
        first = datasets[0]
        extra = {
            "name": "extra-set",
            "fingerprint": "8" * 64,
            "role": "development",
        }
        self._assert_spec_stable(
            spec,
            [
                lambda: datasets.append(extra),
                lambda: datasets.insert(0, dict(extra)),
                lambda: datasets.extend([dict(extra)]),
                lambda: datasets.pop(),
                lambda: datasets.clear(),
                lambda: datasets.__delitem__(0),
                lambda: datasets.__setitem__(0, dict(extra)),
                lambda: first.__setitem__("name", "mutated-set"),
                lambda: first.__setitem__("fingerprint", self._REPLACEMENT_FINGERPRINT),
                lambda: first.__setitem__("role", "development"),
                lambda: first.__setitem__("unfrozen_extra", "value"),
                lambda: first.__delitem__("fingerprint"),
                lambda: first.update({"name": "u-set", "fingerprint": "7" * 64}),
                lambda: setattr(first, "name", "attr-set"),
            ],
        )

    def test_spec_machine_profile_fields_are_deeply_immutable(self):
        spec = from_mapping(_spec_mapping())
        profile = spec.machine_profile
        self._assert_spec_stable(
            spec,
            [
                lambda: profile.__setitem__("cores", 999999),
                lambda: profile.__setitem__("ram_gb", 0),
                lambda: profile.__setitem__("cpu_arch", "aarch64"),
                lambda: profile.__setitem__("cpu_model", "mutated-cpu"),
                lambda: profile.__setitem__("profile_id", "mutated-profile"),
                lambda: profile.__setitem__("unfrozen_extra", "value"),
                lambda: profile.__delitem__("cores"),
                lambda: profile.pop("ram_gb", None),
                lambda: profile.update({"cores": 1, "os_family": "windows"}),
                lambda: profile.clear(),
                lambda: setattr(profile, "cores", 42),
                lambda: setattr(spec, "machine_profile", {}),
            ],
        )

    def test_canonical_bytes_and_digest_unchanged_after_combined_mutation_barrage(self):
        spec = from_mapping(_spec_mapping())
        before_bytes = spec.canonical_bytes()
        before_digest = spec.content_digest()
        attempts = (
            lambda: spec.repositories.append(
                {"identity": "barrage-team/barrage-repo", "commit_sha": "6" * 40}
            ),
            lambda: spec.repositories[0].__setitem__("commit_sha", "5" * 40),
            lambda: spec.datasets[0].__setitem__("fingerprint", "4" * 64),
            lambda: spec.machine_profile.__setitem__("cores", 64),
            lambda: setattr(spec, "seed", 0),
        )
        for attempt in attempts:
            # A raised error is acceptable; a silent change is the defect.
            with contextlib.suppress(Exception):
                attempt()
        self.assertEqual(spec.canonical_bytes(), before_bytes)
        self.assertEqual(spec.content_digest(), before_digest)

    def test_input_mapping_mutation_after_construction_does_not_affect_spec(self):
        mapping = _spec_mapping()
        spec = from_mapping(mapping)
        before_bytes = spec.canonical_bytes()
        before_digest = spec.content_digest()
        mapping["repositories"].append(
            {"identity": "late-owner/late-repo", "commit_sha": "3" * 40}
        )
        mapping["repositories"][0]["commit_sha"] = self._REPLACEMENT_COMMIT
        mapping["repositories"][0]["identity"] = "late-mutation/late-mutation"
        mapping["datasets"].append(
            {"name": "late-set", "fingerprint": "2" * 64, "role": "development"}
        )
        mapping["datasets"][0]["fingerprint"] = self._REPLACEMENT_FINGERPRINT
        mapping["machine_profile"]["cores"] = 999999
        mapping["seed"] = 0
        self.assertEqual(spec.canonical_bytes(), before_bytes)
        self.assertEqual(spec.content_digest(), before_digest)

    def test_to_canonical_value_returns_mutable_json_copy_isolated_from_spec(self):
        spec = from_mapping(_spec_mapping())
        before_bytes = spec.canonical_bytes()
        before_digest = spec.content_digest()
        value = spec.to_canonical_value()
        self.assertIsInstance(value, dict)
        self.assertIsInstance(value["repositories"], list)
        self.assertIsInstance(value["machine_profile"], dict)
        # The copy must remain a plain, serializable, mutable JSON subset.
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        value["seed"] = 0
        value["repositories"].append(
            {"identity": "copy-team/copy-repo", "commit_sha": "1" * 40}
        )
        value["repositories"][0]["commit_sha"] = self._REPLACEMENT_COMMIT
        value["datasets"][0]["role"] = "development"
        value["machine_profile"]["cores"] = 12345
        # Mutating the returned copy must not observably change the spec.
        self.assertEqual(spec.canonical_bytes(), before_bytes)
        self.assertEqual(spec.content_digest(), before_digest)

    def test_loaded_spec_is_deeply_immutable(self):
        original = from_mapping(_spec_mapping())
        with tempfile.TemporaryDirectory() as directory:
            path = pathlib.Path(directory) / "loaded-spec.json"
            path.write_bytes(original.canonical_bytes())
            loaded = load_baseline_run_spec(str(path))
        extra = {"identity": "load-team/load-repo", "commit_sha": "0" * 40}
        self._assert_spec_stable(
            loaded,
            [
                lambda: loaded.repositories.append(extra),
                lambda: loaded.repositories[0].__setitem__(
                    "commit_sha", self._REPLACEMENT_COMMIT
                ),
                lambda: loaded.repositories[0].__setitem__(
                    "identity", "load-owner/load-repo"
                ),
                lambda: loaded.datasets[0].__setitem__(
                    "fingerprint", self._REPLACEMENT_FINGERPRINT
                ),
                lambda: loaded.datasets.append(
                    {"name": "load-set", "fingerprint": "9" * 64, "role": "calibration"}
                ),
                lambda: loaded.machine_profile.__setitem__("cores", 32),
                lambda: loaded.machine_profile.__setitem__("cpu_arch", "aarch64"),
                lambda: loaded.machine_profile.__delitem__("profile_id"),
            ],
        )


    def test_standard_attribute_paths_expose_no_mutable_builtin_containers(self):
        """No mutable builtin container may be reachable via attribute access.

        Walks the spec and the objects reachable from its frozen fields
        (field containers and repository/dataset entries) and, for every
        dict/list/set/bytearray found through a standard (non-dunder)
        attribute, attempts representative mutations. Implementation
        names and container types are not pinned: the invariant is that
        any such attempt either raises or leaves ``canonical_bytes()`` and
        ``content_digest()`` unchanged. Dunder attributes such as
        ``__dict__`` and interpreter-level tampering (``object.__setattr__``,
        ctypes) are explicitly out of scope.
        """
        spec = from_mapping(_spec_mapping())
        before_bytes = spec.canonical_bytes()
        before_digest = spec.content_digest()
        targets = [spec, spec.repositories, spec.datasets, spec.machine_profile]
        targets.extend(spec.repositories)
        targets.extend(spec.datasets)
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
                    self.assertEqual(spec.canonical_bytes(), before_bytes)
                    self.assertEqual(spec.content_digest(), before_digest)

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

    def test_instance_has_no_writable_attribute_dict(self):
        """MF-IP-0024-02 regression: no writable per-instance ``__dict__``.

        A frozen dataclass without slots still exposes a writable
        ``__dict__``: assigning ``spec.__dict__["seed"]`` rewrites frozen
        state and drifts ``canonical_bytes()``/``content_digest()`` without
        any exception. The invariant is that no ``__dict__`` exists at all,
        so the write path is naturally unreachable (``__dict__`` attribute
        access raises). Interpreter-level tampering (``object.__setattr__``,
        ctypes, pickle) remains out of scope.
        """
        spec = from_mapping(_spec_mapping())
        before_bytes = spec.canonical_bytes()
        before_digest = spec.content_digest()
        with self.subTest(probe="instance_has_no_attribute_dict"):
            self.assertFalse(hasattr(spec, "__dict__"))
        with self.subTest(probe="vars_rejects_instance"):
            with self.assertRaises(TypeError):
                vars(spec)
        with self.subTest(probe="attribute_dict_access_unreachable"):
            with self.assertRaises(AttributeError):
                spec.__dict__  # noqa: B018 -- probing; raising is the assertion
        with self.subTest(probe="digest_stable_after_dict_write_attempt"):
            with contextlib.suppress(AttributeError):
                spec.__dict__["seed"] = 0
            self.assertEqual(spec.canonical_bytes(), before_bytes)
            self.assertEqual(spec.content_digest(), before_digest)


if __name__ == "__main__":
    unittest.main()
