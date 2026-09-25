"""Frozen acceptance tests for IP-0026: baseline static foundation (Issue #210).

Contract under test (frozen by Coordinator Assignment CA-IP-0026-v1.0 of
2026-09-25; see docs/LIMA_Implementation_Packet_IP-0026_Baseline_Static_Foundation.md):

- The Implementation deliverables are two JSON data artifacts (this slice ships
  zero ``lima/`` product code): ``evaluation_data/v4/baseline_manifest.json``
  and ``evaluation_data/v4/python_mvp_support_matrix.json``.  They are
  Implementation products, not P&V fixtures.
- The manifest must register exactly the three frozen datasets bound by ruling
  R3 (names, roles, fingerprints equal to the SHA-256 of each frozen file's
  bytes, entries transcribed verbatim from each case's ``repository`` and
  ``vulnerable_commit``) and must pass
  ``lima.baseline_run_spec.validate_baseline_manifest`` against a spec built
  from its own values plus a nominal declarative machine profile (ruling R6:
  no persistent spec artifact is delivered in this slice).
- The support matrix must be an honest three-level matrix (ruling R2): every
  capability entry carries a stable unique key, a level, a reason, a boundary
  and evidence pointers; ``supported`` entries must cite at least one
  repository path that resolves; evidence-free archetypes are registered as
  coverage gaps; each excluded frozen file has a registration note; the
  LlamaFactory identity ``7fcf5b3b130e5713b52415bb7404c476fada9c8c`` is a
  coverage-gap entry that must never appear in the manifest (ruling R4).
- Fail-closed negatives reuse the frozen IP-0024 semantics (typed error codes)
  against deep-copy mutations of the on-disk manifest; calibration data must
  never reappear as external-holdout (M12).
- The whole suite is offline and secretless: deterministic, no network, no
  environment reads, no paid model calls.  Module-level imports are stdlib
  plus the frozen ``lima.baseline_run_spec`` only; deliverable loading happens
  inside test methods, so collection always succeeds.

Expected RED before implementation (deliverable artifacts absent): every test
fails closed with ``required deliverable artifact is missing:
evaluation_data/v4/<artifact>.json``.
"""

import copy
import hashlib
import json
import pathlib
import re
import tempfile
import unittest

from lima.baseline_run_spec import (
    BaselineRunSpecError,
    BaselineRunSpecErrorCode,
    from_mapping,
    validate_baseline_manifest,
)

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MANIFEST_RELATIVE_PATH = "evaluation_data/v4/baseline_manifest.json"
_MATRIX_RELATIVE_PATH = "evaluation_data/v4/python_mvp_support_matrix.json"

_DATASET_ROLE_BY_FILE = {
    "popular_calibration_v1.json": "calibration",
    "popular_external_holdout_v2.json": "external-holdout",
    "real_world_security_cases.json": "development",
}
_DATASET_NAME_BY_FILE = {
    "popular_calibration_v1.json": "lima-popular-python-calibration-v1",
    "popular_external_holdout_v2.json": "lima-popular-python-external-holdout-v2",
    "real_world_security_cases.json": "lima-real-world-pilot-v1",
}
_FILE_BY_DATASET_NAME = {
    name: filename for filename, name in _DATASET_NAME_BY_FILE.items()
}
_REGISTERED_FROZEN_FILES = tuple(
    "evaluation_data/" + filename for filename in _DATASET_ROLE_BY_FILE
)
_EXCLUDED_FROZEN_FILES = (
    "evaluation_data/popular_external_holdout.json",
    "evaluation_data/popular_external_calibration_v2.json",
    "evaluation_data/security_repair_cases.json",
    "evaluation_data/pr_diff_100.jsonl",
)
_REQUIRED_GAP_CAPABILITY_KEYS = (
    "archetype/empty-repository",
    "archetype/minimal-python-repository",
    "archetype/llamafactory-replay",
)
_LLAMAFACTORY_COMMIT_SHA = "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
_CAPABILITY_LEVELS = ("supported", "conditionally-supported", "unsupported")
_FULL_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
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


def _forbidden_source_tokens():
    """Tokens that must never appear in this test file."""
    return [
        "os." + "environ",
        "get" + "env",
        "sock" + "et",
        "url" + "lib",
        "requ" + "ests",
    ]


def _normalize_repository_identity(repository):
    """Best-effort mirror of the frozen github identity normalization."""
    candidate = repository.strip()
    if candidate.lower().startswith("https://github.com/"):
        candidate = candidate[len("https://github.com/") :]
    if candidate.lower().endswith(".git"):
        candidate = candidate[: -len(".git")]
    return candidate.lower()


class _IP0026ArtifactTestCase(unittest.TestCase):
    """Shared arrange helpers for the two deliverables (no collected tests)."""

    def load_deliverable_json(self, relative_path):
        path = _REPO_ROOT / relative_path
        if not path.is_file():
            self.fail(f"required deliverable artifact is missing: {relative_path}")
        with path.open("rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    def load_frozen_json(self, relative_path):
        path = _REPO_ROOT / relative_path
        if not path.is_file():
            self.fail(f"required frozen data file is missing: {relative_path}")
        with path.open("rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    def load_manifest(self):
        return self.load_deliverable_json(_MANIFEST_RELATIVE_PATH)

    def load_matrix(self):
        return self.load_deliverable_json(_MATRIX_RELATIVE_PATH)

    def spec_mapping_from_manifest(self, manifest):
        """Build a nominal spec mapping from the on-disk manifest values (R6)."""

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

    def manifest_spec(self, manifest):
        return from_mapping(self.spec_mapping_from_manifest(manifest))

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


class TestBaselineManifestArtifact(_IP0026ArtifactTestCase):
    """AC-2 positive face: the on-disk manifest consumes the frozen contract."""

    def test_manifest_artifact_parses_with_schema_v1_datasets(self):
        manifest = self.load_manifest()
        self.assertIsInstance(manifest, dict)
        self.assertEqual(manifest["schema_version"], 1)
        self.assertIsInstance(manifest["datasets"], list)
        self.assertTrue(manifest["datasets"])

    def test_registers_exactly_the_three_frozen_datasets_with_bound_roles(self):
        manifest = self.load_manifest()
        expected_roles = {
            _DATASET_NAME_BY_FILE[filename]: _DATASET_ROLE_BY_FILE[filename]
            for filename in _DATASET_ROLE_BY_FILE
        }
        observed_roles = {
            dataset["name"]: dataset["role"] for dataset in manifest["datasets"]
        }
        self.assertEqual(observed_roles, expected_roles)
        self.assertEqual(len(manifest["datasets"]), len(expected_roles))

    def test_dataset_fixed_identity_fields_and_pinned_files(self):
        manifest = self.load_manifest()
        for dataset in manifest["datasets"]:
            expected_path = (
                _REPO_ROOT / "evaluation_data" / _FILE_BY_DATASET_NAME[dataset["name"]]
            )
            for field in ("source", "license", "pinned_file"):
                with self.subTest(dataset=dataset["name"], field=field):
                    self.assertIsInstance(dataset.get(field), str)
                    self.assertTrue(dataset[field].strip())
            with self.subTest(dataset=dataset["name"], probe="pinned-file-resolves"):
                pinned = _REPO_ROOT / dataset["pinned_file"]
                self.assertTrue(pinned.is_file())
                self.assertEqual(pinned.resolve(), expected_path.resolve())
            with self.subTest(dataset=dataset["name"], probe="source-matches-pinned"):
                source = _REPO_ROOT / dataset["source"]
                self.assertTrue(source.is_file())
                self.assertEqual(source.resolve(), pinned.resolve())

    def test_fingerprints_recompute_from_frozen_file_bytes(self):
        manifest = self.load_manifest()
        for dataset in manifest["datasets"]:
            with self.subTest(dataset=dataset["name"]):
                self.assertIsNotNone(
                    _FINGERPRINT_PATTERN.fullmatch(dataset["fingerprint"])
                )
                pinned = _REPO_ROOT / dataset["pinned_file"]
                with pinned.open("rb") as handle:
                    digest = hashlib.sha256(handle.read()).hexdigest()
                self.assertEqual(dataset["fingerprint"], digest)

    def test_entries_transcribed_verbatim_from_frozen_files(self):
        manifest = self.load_manifest()
        for dataset in manifest["datasets"]:
            frozen = self.load_frozen_json(dataset["pinned_file"])
            expected = {
                case["repository"]: case["vulnerable_commit"]
                for case in frozen["cases"]
            }
            observed = {
                entry["repository"]: entry["commit_sha"]
                for entry in dataset["entries"]
            }
            with self.subTest(dataset=dataset["name"]):
                self.assertEqual(observed, expected)
                self.assertEqual(len(dataset["entries"]), len(frozen["cases"]))

    def test_all_entry_commit_shas_are_full_lowercase_hex(self):
        manifest = self.load_manifest()
        for dataset in manifest["datasets"]:
            for entry in dataset["entries"]:
                with self.subTest(
                    dataset=dataset["name"], repository=entry["repository"]
                ):
                    self.assertIsInstance(entry["repository"], str)
                    self.assertTrue(entry["repository"].strip())
                    self.assertIsNotNone(
                        _FULL_COMMIT_SHA_PATTERN.fullmatch(entry["commit_sha"])
                    )

    def test_manifest_passes_frozen_contract_with_extra_fields_tolerated(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        validate_baseline_manifest(manifest, spec)
        tolerated = copy.deepcopy(manifest)
        tolerated["datasets"][0]["risk_notes"] = "forward-compatible extra field"
        tolerated["datasets"][0]["entries"][0]["archive_sha256"] = "7" * 64
        validate_baseline_manifest(tolerated, spec)


class TestSpecLayerFailClosed(_IP0026ArtifactTestCase):
    """AC-2 negative face at the frozen from_mapping gate (IP-0024 semantics)."""

    def test_abbreviated_commit_sha_rejected(self):
        base = self.spec_mapping_from_manifest(self.load_manifest())
        for abbreviated in ("1" * 12, "abcdef1", "1" * 39):
            with self.subTest(sha=abbreviated):
                mapping = copy.deepcopy(base)
                mapping["repositories"][0]["commit_sha"] = abbreviated
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunSpecErrorCode.ABBREVIATED_COMMIT_SHA_REJECTED,
                    fragment="commit_sha",
                )

    def test_moving_and_nonhex_refs_rejected(self):
        base = self.spec_mapping_from_manifest(self.load_manifest())
        for moving_ref in ("main", "v1.2.3", "refs/heads/main", "A" * 40):
            with self.subTest(ref=moving_ref):
                mapping = copy.deepcopy(base)
                mapping["repositories"][0]["commit_sha"] = moving_ref
                self.assert_from_mapping_rejected(
                    mapping,
                    BaselineRunSpecErrorCode.MOVING_REF_REJECTED,
                    fragment="commit_sha",
                )
        mapping = copy.deepcopy(base)
        mapping["repositories"][0]["commit_sha"] = "g" * 40
        self.assert_from_mapping_rejected(
            mapping, BaselineRunSpecErrorCode.INVALID_COMMIT_SHA, fragment="commit_sha"
        )

    def test_duplicate_identity_variants_rejected(self):
        base = self.spec_mapping_from_manifest(self.load_manifest())
        first_identity = base["repositories"][0]["identity"]
        folded = (
            first_identity.upper()
            if first_identity != first_identity.upper()
            else first_identity.lower()
        )
        variants = (folded, first_identity + ".git", "https://github.com/" + first_identity)
        for variant in variants:
            with self.subTest(identity=variant):
                mapping = copy.deepcopy(base)
                mapping["repositories"][1]["identity"] = variant
                self.assert_from_mapping_rejected(
                    mapping, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
                )

    def test_invalid_fingerprints_rejected(self):
        base = self.spec_mapping_from_manifest(self.load_manifest())
        dataset_mutations = {
            "datasets[0].fingerprint": lambda m: m["datasets"][0].update(
                {"fingerprint": "A" * 64}
            ),
            "analyzer_fingerprint": lambda m: m.update(
                {"analyzer_fingerprint": "z" * 64}
            ),
            "config_digest": lambda m: m.update({"config_digest": "a" * 63}),
        }
        for label, mutate in dataset_mutations.items():
            with self.subTest(field=label):
                mapping = copy.deepcopy(base)
                mutate(mapping)
                self.assert_from_mapping_rejected(
                    mapping, BaselineRunSpecErrorCode.INVALID_FINGERPRINT
                )


class TestManifestValidationFailClosed(_IP0026ArtifactTestCase):
    """AC-2 negative face at the frozen manifest cross-check gate."""

    def test_schema_version_and_datasets_container_rules(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        broken = []
        mutated = copy.deepcopy(manifest)
        mutated["schema_version"] = 2
        broken.append((mutated, BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID))
        mutated = copy.deepcopy(manifest)
        mutated["datasets"] = []
        broken.append((mutated, BaselineRunSpecErrorCode.INVALID_FIELD_VALUE))
        mutated = copy.deepcopy(manifest)
        mutated["datasets"] = "nope"
        broken.append((mutated, BaselineRunSpecErrorCode.INVALID_FIELD_TYPE))
        for broken_manifest, code in broken:
            with self.subTest(code=code.value):
                self.assert_manifest_rejected(broken_manifest, spec, code)

    def test_missing_required_fields_rejected(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        for field in ("name", "fingerprint", "role", "entries"):
            mutated = copy.deepcopy(manifest)
            del mutated["datasets"][0][field]
            with self.subTest(dataset_field=field):
                self.assert_manifest_rejected(
                    mutated, spec, BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING
                )
        for field in ("repository", "commit_sha"):
            mutated = copy.deepcopy(manifest)
            del mutated["datasets"][0]["entries"][0][field]
            with self.subTest(entry_field=field):
                self.assert_manifest_rejected(
                    mutated, spec, BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING
                )

    def test_dataset_fingerprint_mismatch_rejected(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        drifted = copy.deepcopy(manifest)
        drifted["datasets"][0]["fingerprint"] = "9" * 64
        self.assert_manifest_rejected(
            drifted, spec, BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH
        )
        frozen = self.load_frozen_json(manifest["datasets"][0]["pinned_file"])
        with tempfile.TemporaryDirectory() as directory:
            tampered = copy.deepcopy(frozen)
            tampered["name"] = tampered["name"] + "-tampered"
            tampered_path = pathlib.Path(directory) / "tampered-frozen-copy.json"
            tampered_path.write_text(json.dumps(tampered), encoding="utf-8")
            with tampered_path.open("rb") as handle:
                tampered_digest = hashlib.sha256(handle.read()).hexdigest()
        self.assertNotEqual(tampered_digest, manifest["datasets"][0]["fingerprint"])
        drifted_spec_mapping = self.spec_mapping_from_manifest(manifest)
        drifted_spec_mapping["datasets"][0]["fingerprint"] = tampered_digest
        self.assert_manifest_rejected(
            manifest,
            from_mapping(drifted_spec_mapping),
            BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH,
        )
        renamed_spec_mapping = self.spec_mapping_from_manifest(manifest)
        renamed_spec_mapping["datasets"][0]["name"] += "-renamed"
        with self.assertRaises(BaselineRunSpecError):
            validate_baseline_manifest(
                manifest, from_mapping(renamed_spec_mapping)
            )

    def test_role_crossing_rejected_as_role_conflict(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        crossed = copy.deepcopy(manifest)
        datasets_by_role = {
            dataset["role"]: dataset for dataset in crossed["datasets"]
        }
        holdout_entries = datasets_by_role["external-holdout"]["entries"]
        calibration_entry = datasets_by_role["calibration"]["entries"][0]
        holdout_entries.append(copy.deepcopy(calibration_entry))
        self.assert_manifest_rejected(
            crossed, spec, BaselineRunSpecErrorCode.DATASET_ROLE_CONFLICT
        )

    def test_duplicate_repository_rejected(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        duplicated = copy.deepcopy(manifest)
        dataset = duplicated["datasets"][0]
        dataset["entries"].append(copy.deepcopy(dataset["entries"][0]))
        self.assert_manifest_rejected(
            duplicated, spec, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )
        case_variant = copy.deepcopy(manifest)
        entry = case_variant["datasets"][0]["entries"][0]
        clone = copy.deepcopy(entry)
        clone["repository"] = entry["repository"].upper()
        clone["commit_sha"] = "5" * 40
        case_variant["datasets"][0]["entries"].append(clone)
        self.assert_manifest_rejected(
            case_variant, spec, BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY
        )

    def test_identity_conflicts_rejected(self):
        manifest = self.load_manifest()
        spec = self.manifest_spec(manifest)
        mutated = copy.deepcopy(manifest)
        mutated["datasets"][0]["entries"][0]["commit_sha"] = "5" * 40
        self.assert_manifest_rejected(
            mutated, spec, BaselineRunSpecErrorCode.MANIFEST_IDENTITY_CONFLICT
        )
        extra_repository = self.spec_mapping_from_manifest(manifest)
        extra_repository["repositories"].append(
            {"identity": "ghost-team/ghost-repo", "commit_sha": "6" * 40}
        )
        self.assert_manifest_rejected(
            manifest,
            from_mapping(extra_repository),
            BaselineRunSpecErrorCode.MANIFEST_IDENTITY_CONFLICT,
        )


class TestSupportMatrixArtifact(_IP0026ArtifactTestCase):
    """AC-1: the on-disk support matrix is structured and honest (ruling R2)."""

    def test_matrix_artifact_top_level_shape(self):
        matrix = self.load_matrix()
        self.assertIsInstance(matrix, dict)
        self.assertEqual(matrix["schema_version"], 1)
        for field in ("matrix_id", "matrix_version"):
            with self.subTest(field=field):
                self.assertIsInstance(matrix[field], str)
                self.assertTrue(matrix[field].strip())
        for field in ("capabilities", "coverage_gaps", "registration_notes"):
            with self.subTest(field=field):
                self.assertIsInstance(matrix[field], list)
        self.assertTrue(matrix["capabilities"])

    def test_capability_entries_structure_levels_and_unique_keys(self):
        matrix = self.load_matrix()
        capability_keys = []
        for capability in matrix["capabilities"]:
            key = capability["capability_key"]
            with self.subTest(capability=key):
                self.assertIsInstance(capability, dict)
                self.assertIsInstance(key, str)
                self.assertTrue(key.strip())
                self.assertIn(capability["level"], _CAPABILITY_LEVELS)
                for field in ("reason", "boundary"):
                    self.assertIsInstance(capability[field], str)
                    self.assertTrue(capability[field].strip())
                evidence = capability["evidence"]
                self.assertIsInstance(evidence, list)
                self.assertTrue(evidence)
                for pointer in evidence:
                    self.assertIsInstance(pointer, str)
                    self.assertTrue(pointer.strip())
            capability_keys.append(key)
        self.assertEqual(len(capability_keys), len(set(capability_keys)))

    def test_supported_entries_cite_resolvable_repository_evidence(self):
        matrix = self.load_matrix()
        for capability in matrix["capabilities"]:
            if capability["level"] != "supported":
                continue
            resolvable = [
                pointer
                for pointer in capability["evidence"]
                if not pointer.startswith(("http://", "https://"))
                and " " not in pointer
                and "#" not in pointer
                and (_REPO_ROOT / pointer).is_file()
            ]
            with self.subTest(capability=capability["capability_key"]):
                self.assertTrue(
                    resolvable,
                    "supported entries must cite at least one resolvable repo path",
                )

    def test_required_coverage_gaps_registered_with_referential_integrity(self):
        matrix = self.load_matrix()
        capability_keys = {
            capability["capability_key"] for capability in matrix["capabilities"]
        }
        gap_keys = []
        for gap in matrix["coverage_gaps"]:
            key = gap["capability_key"]
            with self.subTest(gap=key):
                self.assertIsInstance(gap, dict)
                self.assertIsInstance(key, str)
                self.assertTrue(key.strip())
                self.assertIsInstance(gap["reason"], str)
                self.assertTrue(gap["reason"].strip())
                self.assertIn(key, capability_keys)
            gap_keys.append(key)
        for required in _REQUIRED_GAP_CAPABILITY_KEYS:
            with self.subTest(required_gap=required):
                self.assertIn(required, gap_keys)

    def test_llamafactory_gap_entry_is_unsupported_with_full_sha(self):
        matrix = self.load_matrix()
        capabilities = {
            capability["capability_key"]: capability
            for capability in matrix["capabilities"]
        }
        entry = capabilities["archetype/llamafactory-replay"]
        self.assertEqual(entry["level"], "unsupported")
        self.assertIn(_LLAMAFACTORY_COMMIT_SHA, json.dumps(entry))
        self.assertTrue(any("#57" in pointer for pointer in entry["evidence"]))

    def test_registration_notes_cover_exactly_the_excluded_frozen_files(self):
        matrix = self.load_matrix()
        noted_files = set()
        for note in matrix["registration_notes"]:
            with self.subTest(note=note.get("file")):
                self.assertIsInstance(note, dict)
                self.assertIsInstance(note["file"], str)
                self.assertTrue(note["file"].strip())
                self.assertIsInstance(note["reason"], str)
                self.assertTrue(note["reason"].strip())
                self.assertTrue((_REPO_ROOT / note["file"]).is_file())
            noted_files.add(note["file"])
        self.assertEqual(noted_files, set(_EXCLUDED_FROZEN_FILES))

    def test_registered_dataset_archetypes_covered_by_matrix_evidence(self):
        matrix = self.load_matrix()
        for frozen_path in _REGISTERED_FROZEN_FILES:
            with self.subTest(registered=frozen_path):
                covered = any(
                    frozen_path in capability["evidence"]
                    for capability in matrix["capabilities"]
                )
                self.assertTrue(
                    covered,
                    "every registered dataset must be covered by matrix evidence",
                )


class TestCrossArtifactConsistencyAndHygiene(_IP0026ArtifactTestCase):
    """M12 / R4 cross-artifact consistency and offline hygiene."""

    def test_v1_holdout_identities_never_reappear_as_holdout(self):
        manifest = self.load_manifest()
        v1_holdout = self.load_frozen_json(
            "evaluation_data/popular_external_holdout.json"
        )
        v1_repositories = {case["repository"] for case in v1_holdout["cases"]}
        for dataset in manifest["datasets"]:
            for entry in dataset["entries"]:
                if entry["repository"] not in v1_repositories:
                    continue
                with self.subTest(
                    repository=entry["repository"], dataset=dataset["name"]
                ):
                    self.assertEqual(dataset["role"], "calibration")
        registered = {
            entry["repository"]
            for dataset in manifest["datasets"]
            for entry in dataset["entries"]
        }
        self.assertTrue(v1_repositories.issubset(registered))
        for filename in (
            "popular_calibration_v1.json",
            "popular_external_holdout_v2.json",
        ):
            frozen = self.load_frozen_json("evaluation_data/" + filename)
            dataset = next(
                candidate
                for candidate in manifest["datasets"]
                if candidate["name"] == frozen["name"]
            )
            with self.subTest(role_agreement=filename):
                self.assertEqual(dataset["role"], frozen["evaluation_role"])

    def test_manifest_identities_pairwise_disjoint(self):
        manifest = self.load_manifest()
        expected_count = 0
        for filename in _DATASET_NAME_BY_FILE:
            frozen = self.load_frozen_json("evaluation_data/" + filename)
            expected_count += len(frozen["cases"])
        entries = [
            entry
            for dataset in manifest["datasets"]
            for entry in dataset["entries"]
        ]
        self.assertEqual(len(entries), expected_count)
        normalized_identities = {
            _normalize_repository_identity(entry["repository"]) for entry in entries
        }
        self.assertEqual(len(normalized_identities), expected_count)

    def test_llamafactory_identity_absent_from_manifest_present_in_matrix(self):
        manifest = self.load_manifest()
        matrix = self.load_matrix()
        for dataset in manifest["datasets"]:
            for entry in dataset["entries"]:
                with self.subTest(repository=entry["repository"]):
                    self.assertNotIn("llama", entry["repository"].lower())
                    self.assertNotEqual(
                        entry["commit_sha"], _LLAMAFACTORY_COMMIT_SHA
                    )
        self.assertIn(_LLAMAFACTORY_COMMIT_SHA, json.dumps(matrix))

    def test_offline_hygiene_source_scan(self):
        self.load_manifest()
        self.load_matrix()
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        for token in _forbidden_source_tokens():
            with self.subTest(token=token):
                self.assertNotIn(token, source)


if __name__ == "__main__":
    unittest.main()
