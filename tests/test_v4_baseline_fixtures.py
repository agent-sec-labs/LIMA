"""Frozen acceptance tests for IP-0030: baseline fixture family (Issue #219).

Contract under test (frozen by Coordinator Assignment CA-IP-0030-v1.0 of
2026-09-26; see docs/LIMA_Implementation_Packet_IP-0030_Baseline_Fixture_Family.md):

- The Implementation deliverables are ``benchmarks/v4/baseline/fixtures.py``
  (deterministic generator for eleven synthetic repository shapes plus the
  closed error family and public symbol surface of Packet section 7) and
  ``evaluation_data/v4/fixture_registry.json`` (a twelve-entry data-identity
  registry written by ``write_registry`` in canonical JSON).  The materialized
  fixture trees are never committed; every test materializes into a tempdir.
- ``archetype/empty-repository`` materializes zero files (no .git metadata,
  no README placeholder) and its fingerprint is the sha256(b"") sentinel.
- Fingerprints follow the frozen algorithm: sha256 over the sorted-POSIX-path
  concatenation of utf-8(path) + b"\\x00" + content + b"\\x00" per file; the
  registry fingerprints, the recomputed tree digests and two materializations
  must agree byte for byte.
- The registry holds exactly the twelve frozen keys, the eleven synthetic
  entries carry the frozen field set with origin "synthetic-lima-authored",
  and the single external-identity entry registers the dual LlamaFactory
  identity (requested hiyouga/LLaMA-Factory, canonical hiyouga/LlamaFactory,
  commit 7fcf5b3b130e5713b52415bb7404c476fada9c8c) with fingerprint null and
  materialization deferred to PR3-d; it must never be materializable here.
- Fail-closed negatives cover the six frozen error codes with verbatim stable
  messages; offline hygiene scans assert no network tokens, no random or
  clock imports, exactly one registry URL (the external fetch URL) and no
  real-world identities inside synthetic content.
- The two IP-0026 frozen JSON artifacts are never consumed by the module.

Expected RED before implementation: every test fails on the missing
deliverables -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.fixtures'``
(lazy per-test import), and registry-artifact readers fail with
``required deliverable artifact is missing: evaluation_data/v4/fixture_registry.json``.
The suite is offline and secretless: stdlib plus the frozen
``lima.contracts.codec`` only, tempdir isolation, no network, no environment
reads, no paid model calls.
"""

import ast
import copy
import hashlib
import json
import pathlib
import re
import tempfile
import unittest

from lima.contracts.codec import canonical_encode

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_REGISTRY_RELATIVE_PATH = "evaluation_data/v4/fixture_registry.json"
_MODULE_RELATIVE_PATH = "benchmarks/v4/baseline/fixtures.py"

_EMPTY_TREE_SENTINEL = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
_LLAMAFACTORY_COMMIT_SHA = "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
_LLAMAFACTORY_FETCH_URL = (
    "https://codeload.github.com/hiyouga/LLaMA-Factory/tar.gz/" + _LLAMAFACTORY_COMMIT_SHA
)
_LARGE_REPO_FILE_COUNT = 305
_LARGE_REPO_MAX_BYTES = 256 * 1024

_SYNTHETIC_FIELD_SET = {
    "key",
    "kind",
    "purpose",
    "origin",
    "license",
    "generation",
    "fingerprint",
    "file_count",
    "declared_size_bytes",
    "notes",
}
_EXTERNAL_FIELD_SET = {
    "key",
    "kind",
    "identity",
    "fetch",
    "precheck",
    "license",
    "fingerprint",
    "fingerprint_note",
    "materialization",
    "notes",
}

_EXPECTED_FILE_COUNTS = {
    "archetype/empty-repository": 0,
    "archetype/minimal-python-repository": 3,
    "archetype/application": 6,
    "archetype/library": 5,
    "archetype/cli": 4,
    "archetype/docs-content": 6,
    "archetype/test-heavy": 14,
    "archetype/monorepo": 11,
    "archetype/large-repo": _LARGE_REPO_FILE_COUNT,
    "archetype/malicious-layout": 6,
    "archetype/dependency-blocked": 4,
}

_FINGERPRINT_HEX_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_FULL_COMMIT_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")

_MESSAGE_UNKNOWN_FIXTURE_KEY = (
    "The requested fixture key is not part of the frozen baseline fixture family."
)
_MESSAGE_EXTERNAL_IDENTITY = (
    "An external-identity registry entry has no materializable synthetic tree in this repository."
)
_MESSAGE_TARGET_NOT_EMPTY = "The materialization target directory is not empty."
_MESSAGE_TARGET_UNAVAILABLE = "The materialization target directory cannot be created or used."
_MESSAGE_FINGERPRINT_MISMATCH = (
    "The materialized tree does not match the frozen fixture fingerprint."
)
_MESSAGE_INVALID_REGISTRY = "The fixture registry document violates the frozen registry schema."
_LLAMAFACTORY_FINGERPRINT_NOTE = (
    "no content bytes exist in this repository; digest deferred to PR3-d materialization"
)

_MODULE_STDLIB_IMPORT_WHITELIST = {
    "dataclasses",
    "enum",
    "hashlib",
    "json",
    "pathlib",
    "re",
    "typing",
}
_MODULE_PRODUCT_IMPORT_WHITELIST = {"lima.contracts.codec"}
_MODULE_FORBIDDEN_IMPORTS = {
    "random",
    "time",
    "datetime",
    "os",
    "secrets",
    # concatenated spellings keep the hygiene self-scan from matching this file
    # (ALLOWED_ONCE fix A, DR-IP0030-IMPL-1; runtime set values unchanged)
    "sock" + "et",
    "url" + "lib",
    "requ" + "ests",
}

_ARCHETYPE_FILE_TOKENS = {
    "archetype/application": {
        "requirements.txt": ("synth-web==1.0.0", "synth-validation==0.4.0"),
        "pyproject.toml": ('name = "synth-app"',),
        "app.py": ('if __name__ == "__main__":',),
        "synth_app/api.py": ('@app.get("/health")',),
        "synth_app/__init__.py": (),
        "synth_app/config.py": ("os.getenv(", "SYNTH_APP_CONFIG"),
    },
    "archetype/library": {
        "setup.cfg": ("[metadata]", "name = synth-lib"),
        "synth_lib/__init__.py": (),
        "synth_lib/core.py": ("def compute",),
        "synth_lib/loader.py": ("import pickle", "pickle.loads("),
        "README.md": ("# synth-lib",),
    },
    "archetype/cli": {
        "synth_cli/__main__.py": ('if __name__ == "__main__":', "argparse"),
        "synth_cli/main.py": ("def build_parser", "synth-cli"),
        "synth_cli/commands.py": ("def ",),
        "pyproject.toml": ("[project.scripts]",),
    },
    "archetype/docs-content": {
        "README.md": ("# synth-docs",),
        "mkdocs.yml": ("site_name: synth-docs",),
        "docs/index.md": ("# ",),
        "docs/guide.md": ("# ",),
        "docs/reference.md": ("# ",),
        "tools/build_docs.py": ("def build",),
    },
    "archetype/malicious-layout": {
        "setup.py": ("download_url", "exec("),
        "synth_risk/paths.py": ("../",),
        "synth_risk/eval_sample.py": ("eval(",),
        "synth_risk/shell.py": ("subprocess", "shell=True"),
        "synth_risk/deser.py": ("pickle.loads(",),
        "NOTICE.md": ("SYNTHETIC",),
    },
    "archetype/dependency-blocked": {
        "requirements.txt": ("synth-internal-core==9.9.9",),
        "pyproject.toml": ("git+https://git.internal.invalid/synth/pkg.git",),
        "constraints.txt": ("synth-internal-core==9.9.9",),
        "src/synth_blocked/__init__.py": (),
    },
}

_MONOREPO_SUBPROJECTS = {
    "packages/alpha": ("alpha_pkg", "synth-alpha"),
    "packages/beta": ("beta_pkg", "synth-beta"),
    "services/gateway": ("gateway_pkg", "synth-gateway"),
}

_MALICIOUS_FORBIDDEN_TOKENS = (
    "CVE-",
    "github.com",
    "gitlab.com",
    "pypi.org",
    "hiyouga",
    "AKIA",
    "ghp_",
    "BEGIN PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
)
_REAL_IDENTITY_TOKENS = (
    "github.com",
    "gitlab.com",
    "pypi.org",
    "hiyouga",
    "LLaMA-Factory",
    "LlamaFactory",
)


def _forbidden_network_tokens():
    """Network tokens that must never appear in module, test or registry sources."""
    return [
        "sock" + "et",
        "url" + "lib",
        "requ" + "ests",
        "http." + "client",
        "os." + "environ",
    ]


def _relative_files(root):
    """Return {POSIX-relative-path: content-bytes} for every regular file under root."""
    root = pathlib.Path(root)
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _oracle_fingerprint(root):
    """Independent re-implementation of the frozen tree fingerprint algorithm."""
    root = pathlib.Path(root)
    relative_paths = sorted(
        path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()
    )
    digest = hashlib.sha256()
    for relative in relative_paths:
        digest.update(relative.encode("utf-8"))
        digest.update(b"\x00")
        digest.update((root / relative).read_bytes())
        digest.update(b"\x00")
    return digest.hexdigest()


class _FixtureContractTestCase(unittest.TestCase):
    """Shared arrange helpers (no collected test methods)."""

    def fixtures(self):
        import benchmarks.v4.baseline.fixtures as fixtures_module

        return fixtures_module

    def read_registry_artifact(self):
        path = _REPO_ROOT / _REGISTRY_RELATIVE_PATH
        if not path.is_file():
            self.fail(f"required deliverable artifact is missing: {_REGISTRY_RELATIVE_PATH}")
        return path.read_bytes()

    def read_module_source(self):
        path = _REPO_ROOT / _MODULE_RELATIVE_PATH
        if not path.is_file():
            self.fail(f"required deliverable module is missing: {_MODULE_RELATIVE_PATH}")
        return path.read_text(encoding="utf-8")

    def read_module_source_after_import(self):
        self.fixtures()
        return self.read_module_source()

    def _materialize(self, key):
        fixtures = self.fixtures()
        directory = tempfile.TemporaryDirectory(prefix="lima-ip0030-")
        self.addCleanup(directory.cleanup)
        root = pathlib.Path(directory.name)
        return fixtures.materialize_fixture(key, root), root

    def _assert_fixture_error(self, callable_, args, code_name, message):
        fixtures = self.fixtures()
        with self.assertRaises(fixtures.BaselineFixtureError) as caught:
            callable_(*args)
        self.assertEqual(caught.exception.code.value, code_name)
        self.assertEqual(str(caught.exception), message)

    def _registry_entries_by_key(self):
        registry = self.fixtures().load_registry()
        return {entry["key"]: entry for entry in registry["fixtures"]}

    def _external_entry(self):
        entries = [
            entry
            for entry in self.fixtures().load_registry()["fixtures"]
            if entry["key"] == "external/llamafactory-replay"
        ]
        self.assertEqual(len(entries), 1)
        return entries[0]


class TestFixtureMaterialization(_FixtureContractTestCase):
    """AC-1 / FR-01..FR-03: eleven synthetic fixtures materialize to frozen shapes."""

    def test_materializes_all_eleven_synthetic_fixtures_with_declared_counts(self):
        fixtures = self.fixtures()
        self.assertEqual(len(fixtures.SYNTHETIC_FIXTURE_KEYS), 11)
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            with self.subTest(key=key):
                result, root = self._materialize(key)
                self.assertEqual(result.key, key)
                self.assertEqual(result.root, root.resolve())
                self.assertEqual(result.file_count, _EXPECTED_FILE_COUNTS[key])
                materialized = _relative_files(root)
                self.assertEqual(len(materialized), _EXPECTED_FILE_COUNTS[key])
                self.assertEqual(
                    result.size_bytes, sum(len(payload) for payload in materialized.values())
                )
                self.assertRegex(result.fingerprint, _FINGERPRINT_HEX_PATTERN)

    def test_empty_repository_materializes_zero_files_with_sentinel(self):
        result, root = self._materialize("archetype/empty-repository")
        self.assertTrue(root.is_dir())
        self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(result.file_count, 0)
        self.assertEqual(result.size_bytes, 0)
        self.assertEqual(result.fingerprint, _EMPTY_TREE_SENTINEL)
        self.assertEqual(_EMPTY_TREE_SENTINEL, hashlib.sha256(b"").hexdigest())

    def test_minimal_python_repository_structure_is_exact(self):
        result, root = self._materialize("archetype/minimal-python-repository")
        materialized = _relative_files(root)
        self.assertEqual(result.file_count, 3)
        self.assertEqual(
            set(materialized),
            {
                "pyproject.toml",
                "src/minimal_pkg/__init__.py",
                "src/minimal_pkg/core.py",
            },
        )
        self.assertIn(
            'name = "synth-minimal-pkg"',
            materialized["pyproject.toml"].decode("utf-8"),
        )
        self.assertIn(
            "def evaluate", materialized["src/minimal_pkg/core.py"].decode("utf-8")
        )

    def test_archetype_key_files_and_content_tokens(self):
        for key, file_tokens in _ARCHETYPE_FILE_TOKENS.items():
            with self.subTest(key=key):
                _, root = self._materialize(key)
                materialized = _relative_files(root)
                self.assertEqual(set(materialized), set(file_tokens))
                self.assertEqual(len(materialized), _EXPECTED_FILE_COUNTS[key])
                for relative, tokens in file_tokens.items():
                    text = materialized[relative].decode("utf-8")
                    for token in tokens:
                        self.assertIn(token, text)

    def test_test_heavy_fixture_is_test_dominant(self):
        _, root = self._materialize("archetype/test-heavy")
        materialized = _relative_files(root)
        self.assertEqual(len(materialized), 14)
        tests = [rel for rel in materialized if rel.startswith("tests/")]
        sources = [rel for rel in materialized if rel.startswith("src/synth_core/")]
        self.assertEqual(len(tests), 10)
        self.assertEqual(len(sources), 3)
        self.assertTrue(all(rel.split("/")[-1].startswith("test_") for rel in tests))
        self.assertTrue(all(rel.endswith(".py") for rel in tests))
        self.assertIn("pytest.ini", materialized)
        self.assertGreaterEqual(len(tests) * 3, len(sources) * 10)

    def test_monorepo_fixture_has_three_subprojects(self):
        _, root = self._materialize("archetype/monorepo")
        materialized = _relative_files(root)
        self.assertEqual(len(materialized), 11)
        for project, (package, name) in _MONOREPO_SUBPROJECTS.items():
            with self.subTest(project=project):
                for relative in (
                    f"{project}/pyproject.toml",
                    f"{project}/{package}/__init__.py",
                    f"{project}/{package}/module.py",
                ):
                    self.assertIn(relative, materialized)
                self.assertIn(name, materialized[f"{project}/pyproject.toml"].decode("utf-8"))
        self.assertIn("workspace", materialized["pyproject.toml"].decode("utf-8"))
        self.assertIn("# synth-monorepo", materialized["README.md"].decode("utf-8"))

    def test_large_repo_fixture_respects_frozen_bounds(self):
        result, root = self._materialize("archetype/large-repo")
        materialized = _relative_files(root)
        self.assertEqual(result.file_count, _LARGE_REPO_FILE_COUNT)
        self.assertEqual(len(materialized), _LARGE_REPO_FILE_COUNT)
        self.assertLessEqual(result.size_bytes, _LARGE_REPO_MAX_BYTES)
        self.assertLessEqual(
            sum(len(payload) for payload in materialized.values()), _LARGE_REPO_MAX_BYTES
        )
        self.assertEqual(
            {rel for rel in materialized if "/" not in rel},
            {"README.md", "pyproject.toml", ".gitignore", "LICENSE.txt", "Makefile"},
        )
        bulk = {rel for rel in materialized if rel.startswith("synth_bulk/")}
        self.assertEqual(len(bulk), 300)
        for index in (0, 1, 298, 299):
            relative = f"synth_bulk/module_{index:03d}.py"
            with self.subTest(module=relative):
                self.assertIn(relative, materialized)
                self.assertIn(
                    f"MODULE_INDEX = {index}", materialized[relative].decode("utf-8")
                )
        self.assertIn("SYNTHETIC", materialized["LICENSE.txt"].decode("utf-8"))

    def test_materialized_files_are_ascii_and_lf_only(self):
        fixtures = self.fixtures()
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            with self.subTest(key=key):
                _, root = self._materialize(key)
                for relative, payload in _relative_files(root).items():
                    with self.subTest(path=relative):
                        self.assertNotIn(b"\r", payload)
                        self.assertTrue(
                            all(byte < 0x80 for byte in payload),
                            f"non-ascii byte in {relative}",
                        )
                        payload.decode("ascii")


class TestDeterminism(_FixtureContractTestCase):
    """AC-1: byte-identical regeneration and recomputable fingerprints."""

    def test_two_materializations_are_byte_identical(self):
        fixtures = self.fixtures()
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            with self.subTest(key=key):
                first_result, first_root = self._materialize(key)
                second_result, second_root = self._materialize(key)
                first = {
                    relative: hashlib.sha256(payload).hexdigest()
                    for relative, payload in _relative_files(first_root).items()
                }
                second = {
                    relative: hashlib.sha256(payload).hexdigest()
                    for relative, payload in _relative_files(second_root).items()
                }
                self.assertEqual(first, second)
                self.assertEqual(first_result.fingerprint, second_result.fingerprint)

    def test_registry_fingerprints_match_recomputed_tree_digests(self):
        fixtures = self.fixtures()
        entries = self._registry_entries_by_key()
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            with self.subTest(key=key):
                result, root = self._materialize(key)
                self.assertEqual(result.fingerprint, entries[key]["fingerprint"])
                self.assertEqual(
                    fixtures.compute_tree_fingerprint(root), entries[key]["fingerprint"]
                )

    def test_fingerprint_matches_independent_algorithm_oracle(self):
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory(prefix="lima-ip0030-empty-") as temporary:
            empty_root = pathlib.Path(temporary)
            self.assertEqual(fixtures.compute_tree_fingerprint(empty_root), _EMPTY_TREE_SENTINEL)
            self.assertEqual(_oracle_fingerprint(empty_root), _EMPTY_TREE_SENTINEL)
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            with self.subTest(key=key):
                result, root = self._materialize(key)
                self.assertEqual(_oracle_fingerprint(root), result.fingerprint)

    def test_fingerprints_distinct_across_keys_and_stable_across_runs(self):
        fixtures = self.fixtures()
        fingerprints = {}
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            result, _ = self._materialize(key)
            fingerprints[key] = result.fingerprint
        self.assertEqual(len(set(fingerprints.values())), 11)
        repeat, _ = self._materialize("archetype/application")
        self.assertEqual(repeat.fingerprint, fingerprints["archetype/application"])

    def test_write_registry_bytes_stable_and_match_committed_artifact(self):
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory(prefix="lima-ip0030-reg1-") as first, (
            tempfile.TemporaryDirectory(prefix="lima-ip0030-reg2-")
        ) as second:
            first_bytes = fixtures.write_registry(pathlib.Path(first) / "registry.json")
            second_bytes = fixtures.write_registry(pathlib.Path(second) / "registry.json")
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, self.read_registry_artifact())


class TestRegistryContract(_FixtureContractTestCase):
    """AC-2 / FR-04..FR-05: registry schema, closed key set, zero manifest consumption."""

    def test_registry_top_level_schema_fields(self):
        registry = self.fixtures().load_registry()
        self.assertEqual(
            set(registry),
            {
                "schema_version",
                "registry_id",
                "relationship_to_support_matrix",
                "offline_note",
                "fixtures",
            },
        )
        self.assertEqual(registry["schema_version"], 1)
        self.assertEqual(registry["registry_id"], "lima-baseline-fixture-registry")
        relationship = registry["relationship_to_support_matrix"]
        self.assertIsInstance(relationship, str)
        self.assertTrue(relationship.strip())
        for token in (
            "baseline_manifest.json",
            "python_mvp_support_matrix.json",
            "unsupported",
            "PR3-e",
        ):
            with self.subTest(relationship_token=token):
                self.assertIn(token, relationship)
        offline_note = registry["offline_note"]
        self.assertIsInstance(offline_note, str)
        self.assertTrue(offline_note.strip())
        self.assertIn("offline", offline_note)
        self.assertIsInstance(registry["fixtures"], list)
        self.assertEqual(len(registry["fixtures"]), 12)

    def test_registry_keys_form_closed_set_matching_fixture_keys(self):
        fixtures = self.fixtures()
        registry = fixtures.load_registry()
        keys = [entry["key"] for entry in registry["fixtures"]]
        self.assertEqual(len(keys), 12)
        self.assertEqual(len(set(keys)), 12)
        self.assertEqual(set(keys), set(fixtures.FIXTURE_KEYS))
        self.assertEqual(
            set(fixtures.SYNTHETIC_FIXTURE_KEYS) | set(fixtures.EXTERNAL_IDENTITY_KEYS),
            set(fixtures.FIXTURE_KEYS),
        )
        self.assertEqual(len(fixtures.SYNTHETIC_FIXTURE_KEYS), 11)
        self.assertEqual(fixtures.EXTERNAL_IDENTITY_KEYS, ("external/llamafactory-replay",))
        self.assertEqual(fixtures.registry_relative_path, _REGISTRY_RELATIVE_PATH)

    def test_synthetic_entries_carry_frozen_field_set_and_values(self):
        entries = self._registry_entries_by_key()
        self.assertEqual(set(entries), set(_EXPECTED_FILE_COUNTS))
        for key, expected_count in _EXPECTED_FILE_COUNTS.items():
            with self.subTest(key=key):
                entry = entries[key]
                self.assertEqual(set(entry), _SYNTHETIC_FIELD_SET)
                self.assertEqual(entry["kind"], "synthetic-fixture")
                self.assertEqual(entry["origin"], "synthetic-lima-authored")
                self.assertEqual(
                    entry["license"], "Apache-2.0 (LIMA-authored synthetic content)"
                )
                self.assertTrue(entry["purpose"].startswith("baseline archetype: "))
                self.assertRegex(entry["fingerprint"], _FINGERPRINT_HEX_PATTERN)
                self.assertIs(type(entry["file_count"]), int)
                self.assertEqual(entry["file_count"], expected_count)
                self.assertIs(type(entry["declared_size_bytes"]), int)
                self.assertGreaterEqual(entry["declared_size_bytes"], 0)
                self.assertEqual(
                    entry["generation"],
                    {
                        "mode": "deterministic-script",
                        "entrypoint": "benchmarks.v4.baseline.fixtures.materialize_fixture",
                    },
                )
                self.assertIsInstance(entry["notes"], str)
                self.assertTrue(entry["notes"].strip())
                result, _ = self._materialize(key)
                self.assertEqual(entry["declared_size_bytes"], result.size_bytes)
        self.assertIn("no .git metadata", entries["archetype/empty-repository"]["notes"])

    def test_external_entry_carries_frozen_r8_field_set(self):
        entry = self._external_entry()
        self.assertEqual(set(entry), _EXTERNAL_FIELD_SET)
        self.assertEqual(entry["kind"], "external-identity")
        self.assertEqual(
            set(entry["identity"]),
            {"repository_requested", "canonical_repository", "commit_sha"},
        )
        self.assertEqual(set(entry["fetch"]), {"method", "url"})
        self.assertEqual(set(entry["precheck"]), {"date", "commit_api", "tarball_head"})
        self.assertEqual(entry["materialization"], "deferred-to-PR3-d")
        self.assertEqual(entry["fingerprint_note"], _LLAMAFACTORY_FINGERPRINT_NOTE)

    def test_registry_artifact_is_canonical_bytes(self):
        self.fixtures()
        raw = self.read_registry_artifact()
        document = json.loads(raw.decode("utf-8"))
        self.assertEqual(raw, canonical_encode(document))
        self.assertNotIn(b"\r", raw)
        self.assertFalse(raw.endswith(b"\n"))

    def test_module_consumes_no_manifest_or_matrix(self):
        source = self.read_module_source_after_import()
        for token in ("baseline_manifest", "python_mvp_support_matrix"):
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        product_imports = set()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                if node.module.startswith("lima"):
                    product_imports.add(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("lima"):
                        product_imports.add(alias.name)
        self.assertEqual(product_imports, _MODULE_PRODUCT_IMPORT_WHITELIST)


class TestFailClosedNegatives(_FixtureContractTestCase):
    """AC-3: every frozen error code rejects its trigger with the verbatim message."""

    def test_unknown_fixture_key_rejected_with_stable_message(self):
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory(prefix="lima-ip0030-neg-") as temporary:
            target = pathlib.Path(temporary) / "workspace"
            self._assert_fixture_error(
                fixtures.materialize_fixture,
                ("archetype/does-not-exist", target),
                "UNKNOWN_FIXTURE_KEY",
                _MESSAGE_UNKNOWN_FIXTURE_KEY,
            )
            self._assert_fixture_error(
                fixtures.verify_fixture,
                ("archetype/does-not-exist", target),
                "UNKNOWN_FIXTURE_KEY",
                _MESSAGE_UNKNOWN_FIXTURE_KEY,
            )

    def test_external_identity_key_not_materializable(self):
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory(prefix="lima-ip0030-ext-") as temporary:
            target = pathlib.Path(temporary) / "workspace"
            self._assert_fixture_error(
                fixtures.materialize_fixture,
                ("external/llamafactory-replay", target),
                "EXTERNAL_IDENTITY_NOT_MATERIALIZABLE",
                _MESSAGE_EXTERNAL_IDENTITY,
            )
            self._assert_fixture_error(
                fixtures.verify_fixture,
                ("external/llamafactory-replay", target),
                "EXTERNAL_IDENTITY_NOT_MATERIALIZABLE",
                _MESSAGE_EXTERNAL_IDENTITY,
            )
            self.assertFalse(target.exists())

    def test_non_empty_or_unavailable_target_rejected(self):
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory(prefix="lima-ip0030-tgt-") as temporary:
            base = pathlib.Path(temporary)
            non_empty = base / "not-empty"
            non_empty.mkdir()
            (non_empty / "stray.txt").write_bytes(b"stray\n")
            occupied = base / "occupied.txt"
            occupied.write_bytes(b"a regular file\n")
            with self.subTest(case="non-empty-target"):
                self._assert_fixture_error(
                    fixtures.materialize_fixture,
                    ("archetype/library", non_empty),
                    "MATERIALIZE_TARGET_NOT_EMPTY",
                    _MESSAGE_TARGET_NOT_EMPTY,
                )
            with self.subTest(case="target-is-regular-file"):
                self._assert_fixture_error(
                    fixtures.materialize_fixture,
                    ("archetype/library", occupied),
                    "MATERIALIZE_TARGET_UNAVAILABLE",
                    _MESSAGE_TARGET_UNAVAILABLE,
                )
            with self.subTest(case="verify-missing-root"):
                self._assert_fixture_error(
                    fixtures.verify_fixture,
                    ("archetype/empty-repository", base / "missing-root"),
                    "MATERIALIZE_TARGET_UNAVAILABLE",
                    _MESSAGE_TARGET_UNAVAILABLE,
                )

    def test_verify_rejects_fingerprint_drift(self):
        fixtures = self.fixtures()
        _, root = self._materialize("archetype/application")
        drifted = root / "synth_app" / "config.py"
        drifted.write_bytes(drifted.read_bytes() + b"# fingerprint drift\n")
        self._assert_fixture_error(
            fixtures.verify_fixture,
            ("archetype/application", root),
            "FIXTURE_FINGERPRINT_MISMATCH",
            _MESSAGE_FINGERPRINT_MISMATCH,
        )

    def test_verify_rejects_missing_or_extra_files(self):
        fixtures = self.fixtures()
        with self.subTest(case="missing-file"):
            _, root = self._materialize("archetype/library")
            # the frozen library shape keeps README.md at the repository root
            # (ALLOWED_ONCE fix B, DR-IP0030-IMPL-1; Packet section 7.4)
            (root / "README.md").unlink()
            self._assert_fixture_error(
                fixtures.verify_fixture,
                ("archetype/library", root),
                "FIXTURE_FINGERPRINT_MISMATCH",
                _MESSAGE_FINGERPRINT_MISMATCH,
            )
        with self.subTest(case="extra-file"):
            _, root = self._materialize("archetype/library")
            (root / "extra-note.txt").write_bytes(b"extra file\n")
            self._assert_fixture_error(
                fixtures.verify_fixture,
                ("archetype/library", root),
                "FIXTURE_FINGERPRINT_MISMATCH",
                _MESSAGE_FINGERPRINT_MISMATCH,
            )

    def test_invalid_registry_rejected_by_load(self):
        fixtures = self.fixtures()
        base_document = fixtures.load_registry()

        def load_from(document=None, raw_text=None):
            with tempfile.TemporaryDirectory(prefix="lima-ip0030-reg-") as temporary:
                path = pathlib.Path(temporary) / "registry.json"
                if raw_text is not None:
                    path.write_bytes(raw_text)
                else:
                    path.write_bytes(json.dumps(document).encode("utf-8"))
                return fixtures.load_registry(path)

        with self.subTest(case="valid-roundtrip-control"):
            self.assertEqual(load_from(document=copy.deepcopy(base_document)), base_document)
        with self.subTest(case="unknown-extra-key"):
            mutated = copy.deepcopy(base_document)
            mutated["fixtures"].append({"key": "archetype/ghost", "kind": "synthetic-fixture"})
            self._assert_fixture_error(
                load_from, (mutated,), "INVALID_REGISTRY", _MESSAGE_INVALID_REGISTRY
            )
        with self.subTest(case="missing-key"):
            mutated = copy.deepcopy(base_document)
            mutated["fixtures"] = [
                entry for entry in mutated["fixtures"] if entry["key"] != "archetype/cli"
            ]
            self._assert_fixture_error(
                load_from, (mutated,), "INVALID_REGISTRY", _MESSAGE_INVALID_REGISTRY
            )
        with self.subTest(case="duplicate-json-key"):
            self._assert_fixture_error(
                load_from,
                (None, b'{"schema_version": 1, "schema_version": 1}'),
                "INVALID_REGISTRY",
                _MESSAGE_INVALID_REGISTRY,
            )
        with self.subTest(case="bad-synthetic-fingerprint-hex"):
            mutated = copy.deepcopy(base_document)
            library_entry = [
                entry
                for entry in mutated["fixtures"]
                if entry["key"] == "archetype/library"
            ][0]
            library_entry["fingerprint"] = "deadbeef"
            self._assert_fixture_error(
                load_from, (mutated,), "INVALID_REGISTRY", _MESSAGE_INVALID_REGISTRY
            )
        with self.subTest(case="external-fingerprint-not-null"):
            mutated = copy.deepcopy(base_document)
            external = [
                entry
                for entry in mutated["fixtures"]
                if entry["key"] == "external/llamafactory-replay"
            ][0]
            external["fingerprint"] = "a" * 64
            self._assert_fixture_error(
                load_from, (mutated,), "INVALID_REGISTRY", _MESSAGE_INVALID_REGISTRY
            )

    def test_empty_entry_declares_exact_zero_and_sentinel(self):
        self.fixtures()
        entry = self._registry_entries_by_key()["archetype/empty-repository"]
        self.assertIs(type(entry["file_count"]), int)
        self.assertEqual(entry["file_count"], 0)
        self.assertIs(type(entry["declared_size_bytes"]), int)
        self.assertEqual(entry["declared_size_bytes"], 0)
        self.assertEqual(entry["fingerprint"], _EMPTY_TREE_SENTINEL)
        self.assertEqual(_EMPTY_TREE_SENTINEL, hashlib.sha256(b"").hexdigest())
        result, root = self._materialize("archetype/empty-repository")
        self.assertEqual(list(root.iterdir()), [])
        self.assertEqual(result.file_count, 0)


class TestOfflineHygiene(_FixtureContractTestCase):
    """AC-3: offline, secretless, deterministic sources with no real identities."""

    def test_no_network_tokens_in_module_test_or_registry(self):
        self.fixtures()
        module_source = self.read_module_source()
        test_source = pathlib.Path(__file__).read_text(encoding="utf-8")
        registry_text = self.read_registry_artifact().decode("utf-8")
        for token in _forbidden_network_tokens():
            with self.subTest(token=token):
                self.assertNotIn(token, module_source)
                self.assertNotIn(token, test_source)
                self.assertNotIn(token, registry_text)

    def test_registry_contains_exactly_one_url(self):
        self.fixtures()
        registry_text = self.read_registry_artifact().decode("utf-8")
        self.assertEqual(registry_text.count("https://"), 1)
        registry = json.loads(registry_text)
        for entry in registry["fixtures"]:
            with self.subTest(key=entry["key"]):
                if entry["key"] == "external/llamafactory-replay":
                    continue
                self.assertNotIn("http", json.dumps(entry))
        external = self._external_entry()
        self.assertEqual(external["fetch"]["url"], _LLAMAFACTORY_FETCH_URL)
        self.assertEqual(
            _LLAMAFACTORY_FETCH_URL,
            "https://codeload.github.com/hiyouga/LLaMA-Factory/tar.gz/"
            + _LLAMAFACTORY_COMMIT_SHA,
        )

    def test_malicious_fixture_contains_no_real_world_artifacts(self):
        _, root = self._materialize("archetype/malicious-layout")
        materialized = _relative_files(root)
        combined = b"\n".join(materialized.values())
        for token in _MALICIOUS_FORBIDDEN_TOKENS:
            with self.subTest(token=token):
                self.assertNotIn(token.encode("ascii"), combined)
        for relative, payload in materialized.items():
            with self.subTest(path=relative):
                self.assertTrue(
                    payload.decode("utf-8").startswith("# SYNTHETIC INERT BASELINE FIXTURE"),
                    f"missing inert header in {relative}",
                )

    def test_module_imports_within_frozen_whitelist(self):
        source = self.read_module_source_after_import()
        stdlib_imports = set()
        product_imports = set()
        relative_imports = []
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.ImportFrom):
                if node.level > 0:
                    relative_imports.append(node)
                elif node.module:
                    if node.module.startswith("lima"):
                        product_imports.add(node.module)
                    else:
                        stdlib_imports.add(node.module.split(".")[0])
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("lima"):
                        product_imports.add(alias.name)
                    else:
                        stdlib_imports.add(alias.name.split(".")[0])
        self.assertEqual(relative_imports, [])
        self.assertTrue(
            stdlib_imports.issubset(_MODULE_STDLIB_IMPORT_WHITELIST),
            f"non-whitelisted stdlib imports: {sorted(stdlib_imports)}",
        )
        self.assertTrue(
            product_imports.issubset(_MODULE_PRODUCT_IMPORT_WHITELIST),
            f"non-whitelisted product imports: {sorted(product_imports)}",
        )
        self.assertEqual(stdlib_imports & _MODULE_FORBIDDEN_IMPORTS, set())

    def test_synthetic_fixture_bytes_contain_no_real_identities(self):
        fixtures = self.fixtures()
        for key in fixtures.SYNTHETIC_FIXTURE_KEYS:
            with self.subTest(key=key):
                _, root = self._materialize(key)
                combined = b"\n".join(_relative_files(root).values())
                for token in _REAL_IDENTITY_TOKENS:
                    with self.subTest(token=token):
                        self.assertNotIn(token.encode("ascii"), combined)


class TestLlamaFactoryIdentityRegistration(_FixtureContractTestCase):
    """AC-2 / FR-05: external identity registered with dual names, no content."""

    def test_identity_dual_registration_fields(self):
        entry = self._external_entry()
        self.assertEqual(
            entry["identity"],
            {
                "repository_requested": "hiyouga/LLaMA-Factory",
                "canonical_repository": "hiyouga/LlamaFactory",
                "commit_sha": _LLAMAFACTORY_COMMIT_SHA,
            },
        )
        self.assertRegex(entry["identity"]["commit_sha"], _FULL_COMMIT_SHA_PATTERN)
        self.assertNotEqual(
            entry["identity"]["repository_requested"],
            entry["identity"]["canonical_repository"],
        )

    def test_fetch_and_precheck_registration(self):
        entry = self._external_entry()
        self.assertEqual(
            entry["fetch"], {"method": "codeload-tarball", "url": _LLAMAFACTORY_FETCH_URL}
        )
        self.assertEqual(
            entry["precheck"],
            {
                "date": "2026-09-26",
                "commit_api": "301-redirect-then-200 to hiyouga/LlamaFactory",
                "tarball_head": "200",
            },
        )
        self.assertEqual(
            entry["license"],
            "Apache-2.0 (upstream SPDX; hiyouga/LlamaFactory repository license)",
        )

    def test_fingerprint_null_and_materialization_deferred(self):
        entry = self._external_entry()
        self.assertIsNone(entry["fingerprint"])
        self.assertEqual(entry["fingerprint_note"], _LLAMAFACTORY_FINGERPRINT_NOTE)
        self.assertEqual(entry["materialization"], "deferred-to-PR3-d")
        notes = entry["notes"]
        self.assertIsInstance(notes, str)
        for token in ("needs-decision", "latest main", "Maintainer decision"):
            with self.subTest(notes_token=token):
                self.assertIn(token, notes)
        self.assertNotIn("https://", notes)


if __name__ == "__main__":
    unittest.main()
