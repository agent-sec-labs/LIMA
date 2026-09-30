"""Frozen acceptance tests for IP-0036: V5 negative probes (Issue #237).

Contract under test (frozen by Coordinator Assignment CA-IP-0036-v1.0 of
2026-09-28; see docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md
sections 7.6, 8 and 9.4):

- Probe one (hidden fixed caps do not exist, two-sided): the production
  scanner face keeps every finding above any fixed cap (an inline 14-file
  inert command-injection tree, plus the materialized signal-storm +
  docs-content + test-heavy fixture trees), and the runner triage face
  proves ``CANDIDATE_FILE_CAP == 12`` is a request-construction parameter:
  ``_walk_python_files`` returns every file while ``_select_candidate_texts``
  takes exactly twelve.
- Probe two (holdout identity independence, three forms): renaming the
  dataset and case ids, changing the dataset file path and snapshot cache
  path, and appending non-semantic metadata keys never change the per-case
  deterministic verdicts or the aggregate metrics, while the identity faces
  (dataset name, ``dataset_sha256``, ``manifest_sha256``) differ honestly.
- Discipline probes (IP-0036 R6.5): the three C1 documents are in the
  repository with their three container copy lines; the zero-budget artifact
  naming discipline holds mechanically on the frozen artifact family; the
  artifact family catalog matches the fixture registry through the frozen
  commit-sha derivation; and this test file's own sources stay offline and
  secretless (PC1).

Everything here is offline and deterministic: the scanner runs with
``sast_mode="off"``, the snapshot store is injected with an in-memory zip
opener (zero real hosts), fixture trees materialize into temp directories,
and no test ever touches a network socket or sleeps.

Expected RED at the C2 freeze (unmodified product of the 1046501d baseline):
the guard probes pass by design -- the inline-tree scanner face, the runner
face, both holdout probes and the self-scan assert current behavior that is
already the target behavior (R7: "A4=混合态...现行为按设计通过"); the
document probe passes because the C1 documents landed first; the
signal-storm materialization probe fails on the missing C3 deliverable
(``UNKNOWN_FIXTURE_KEY``), and the two artifact-family probes fail on the
missing C5 deliverable (``REAL_RUN_ARTIFACT_FAMILY`` absent).
"""

import ast
import copy
import hashlib
import io
import json
import pathlib
import re
import tempfile
import unittest
import zipfile

from lima.real_world_evaluation import (
    RealWorldSecurityEvaluator,
    SnapshotStore,
    load_real_world_dataset,
)
from lima.repository_scanner import RepositoryScanner
from lima.workspace import RepositoryWorkspace

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PACKET_RELATIVE_PATH = "docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md"
_MATRIX_RELATIVE_PATH = "docs/LIMA_PR3e_Requirement_Matrix_v2.md"
_EXPERT_PACKAGE_RELATIVE_PATH = "docs/LIMA_PR3e_Expert_Review_Package.md"
_DOCKERFILE_RELATIVE_PATH = "Dockerfile"

_PACKET_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_"
    "Integration.md ./docs/"
)
_MATRIX_COPY_LINE = "COPY --chown=lima:lima docs/LIMA_PR3e_Requirement_Matrix_v2.md ./docs/"
_EXPERT_PACKAGE_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_PR3e_Expert_Review_Package.md ./docs/"
)

#: The zero-budget offline-proof family discriminator (Packet 7.4.4): the
#: new family values never carry the frozen approval wording.
_ZERO_BUDGET_FAMILY_VALUE = "PR3E-OFFLINE-PROOF-ZERO-BUDGET"
#: The frozen request-construction parameter (value pinned, never changed).
_CANDIDATE_FILE_CAP = 12

_INERT_HEADER = (
    "# SYNTHETIC INERT BASELINE FIXTURE -- NOT A REAL VULNERABILITY\n"
)

#: Holdout probe identity (all synthetic, RFC 2606-respecting hosts only).
_PROBE_REPOSITORY = "lima-synth/holdout-fixture"
_PROBE_VULNERABLE_COMMIT = "a" * 40
_PROBE_FIXED_COMMIT = "b" * 40
_PROBE_CWE = "CWE-78"
_PROBE_SOURCE = "https://example.invalid/synthetic-holdout-case"

_VULNERABLE_FILES = {
    "app.py": (
        _INERT_HEADER
        + "# Inert command-injection pattern shape; never executed.\n"
        "\n"
        "import os\n"
        "\n"
        "\n"
        "def run_user_command() -> int:\n"
        '    return os.system("synthetic-inert-command")\n'
    ),
}
_FIXED_FILES = {
    "app.py": (
        _INERT_HEADER
        + "# Inert repaired shape: argument-array subprocess, no shell.\n"
        "\n"
        "import subprocess\n"
        "\n"
        "\n"
        "def run_user_command() -> int:\n"
        '    return subprocess.run(["echo", "synthetic"]).returncode\n'
    ),
}

_SECRET_KEY_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{16,}")
_COMMIT_SHA_SHAPE = re.compile(r"^[0-9a-f]{40}$")


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


def _write_probe_module(root, relative, index):
    """One inert CWE-78 pattern file: a constant-argument os.system call."""
    path = pathlib.Path(root) / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        _INERT_HEADER
        + "# Inert command-injection pattern shape; never executed.\n"
        "\n"
        "import os\n"
        "\n"
        "\n"
        f"def trigger_{index}() -> int:\n"
        f'    return os.system("synthetic-inert-{index}")\n',
        encoding="utf-8",
    )


def _scan_findings(root):
    """Deterministic production scan face: local reviewers only, SAST off."""
    scanner = RepositoryScanner(sast_mode="off")
    result = scanner.scan(RepositoryWorkspace(pathlib.Path(root)))
    return result.report.findings


def _zip_archive(commit, files):
    """One in-memory GitHub-shaped zip archive of the given file mapping."""
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as bundle:
        for path, content in files.items():
            bundle.writestr(f"repository-{commit}/{path}", content)
    return output.getvalue()


def _codeload_url(commit):
    return f"https://codeload.github.com/{_PROBE_REPOSITORY}/zip/{commit}"


class _InMemoryZipResponse:
    """Context-managed byte reader over one in-memory archive payload."""

    def __init__(self, payload):
        self._payload = payload
        self._offset = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, size=-1):
        if size < 0:
            size = len(self._payload) - self._offset
        result = self._payload[self._offset : self._offset + size]
        self._offset += len(result)
        return result


class _InMemoryZipOpener:
    """Injected opener: serves in-memory zips only, records every request."""

    def __init__(self, payloads):
        self._payloads = dict(payloads)
        self.calls = []

    def __call__(self, request, timeout=90):
        self.calls.append(request.full_url)
        return _InMemoryZipResponse(self._payloads[request.full_url])


def _probe_dataset(name, case_id, extra_top=None, extra_case=None):
    """One minimal schema-v1 holdout dataset with optional non-semantic keys."""
    case = {
        "id": case_id,
        "cwe": _PROBE_CWE,
        "repository": _PROBE_REPOSITORY,
        "vulnerable_commit": _PROBE_VULNERABLE_COMMIT,
        "fixed_commit": _PROBE_FIXED_COMMIT,
        "ground_truth_paths": ["app.py"],
        "ground_truth_symbols": ["run_user_command"],
        "expected_repair_policy": "abstain",
        "sources": [_PROBE_SOURCE],
    }
    if extra_case is not None:
        case.update(extra_case)
    document = {"schema_version": 1, "name": name, "cases": [case]}
    if extra_top is not None:
        document.update(extra_top)
    return document


def _verdict_tuple(document):
    """The per-case deterministic judgment face (identity-free by design)."""
    deterministic = document["cases"][0]["deterministic"]
    return (
        deterministic["vulnerable_hit"],
        deterministic["fixed_clean"],
        deterministic["paired_discrimination"],
        deterministic["verified_evidence"],
    )


def _stable_metrics(document):
    """Aggregate metrics minus the wall-clock timing keys."""
    return {
        key: value
        for key, value in document["metrics"].items()
        if "latency" not in key and key != "total_duration_seconds"
    }


class _V5NegativesTestCase(unittest.TestCase):
    """Shared arrange helpers (no collected test methods)."""

    def real_run(self):
        import benchmarks.v4.baseline.real_run as real_run_module

        return real_run_module

    def fixtures(self):
        import benchmarks.v4.baseline.fixtures as fixtures_module

        return fixtures_module

    def read_repo_file(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required deliverable document is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def run_holdout(self, dataset, cache_root):
        opener = _InMemoryZipOpener(
            {
                _codeload_url(_PROBE_VULNERABLE_COMMIT): _zip_archive(
                    _PROBE_VULNERABLE_COMMIT, _VULNERABLE_FILES
                ),
                _codeload_url(_PROBE_FIXED_COMMIT): _zip_archive(
                    _PROBE_FIXED_COMMIT, _FIXED_FILES
                ),
            }
        )
        evaluator = RealWorldSecurityEvaluator(SnapshotStore(cache_root, opener=opener))
        document = evaluator.run(dataset, mode="deterministic")
        return document, opener


class TestHiddenCapProbes(_V5NegativesTestCase):
    """AC-2 / FR-03 (Packet 8.1): no hidden fixed review or processing cap."""

    def test_scanner_face_inline_tree_no_fixed_finding_cap(self):
        # Guard probe (zero fixture dependency; passes by design at RED):
        # an inline 14-file inert pattern tree must yield all 14 findings.
        count = 14
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-cap-") as temporary:
            root = pathlib.Path(temporary)
            expected_paths = set()
            for index in range(count):
                relative = f"synth_probe/module_{index:02d}.py"
                _write_probe_module(root, relative, index)
                expected_paths.add(relative)
            findings = _scan_findings(root)
            self.assertGreater(count, 6)
            self.assertGreater(count, 12)
            self.assertEqual(len(findings), count)
            self.assertEqual({finding.path for finding in findings}, expected_paths)
            matched = [
                finding for finding in findings if finding.cwe == _PROBE_CWE
            ]
            self.assertEqual(len(matched), count)

    def test_scanner_face_signal_storm_materialization_not_truncated(self):
        # Fixture probe (needs the C3 deliverable): the materialized
        # signal-storm tree (plus docs-content and test-heavy) must keep
        # every finding above any fixed cap; the expected count is derived
        # from the materialized tree itself (PC3), never hardcoded.
        fixtures = self.fixtures()
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-storm-") as temporary:
            root = pathlib.Path(temporary)
            storm = root / "signal-storm"
            fixtures.materialize_fixture("archetype/signal-storm", storm)
            docs = root / "docs-content"
            fixtures.materialize_fixture("archetype/docs-content", docs)
            heavy = root / "test-heavy"
            fixtures.materialize_fixture("archetype/test-heavy", heavy)
            pattern_files = sorted(storm.rglob("*.py"))
            expected_count = len(pattern_files)
            self.assertGreater(expected_count, 12)
            expected_paths = {
                "signal-storm/" + path.relative_to(storm).as_posix()
                for path in pattern_files
            }
            for relative, payload in (
                (path.relative_to(storm).as_posix(), path.read_bytes())
                for path in pattern_files
            ):
                with self.subTest(pattern_file=relative):
                    self.assertTrue(
                        payload.decode("utf-8").startswith(
                            "# SYNTHETIC INERT BASELINE FIXTURE"
                        ),
                        f"missing inert header in {relative}",
                    )
                    self.assertIn(b"os.system(", payload)
            findings = _scan_findings(root)
            self.assertEqual(len(findings), expected_count)
            self.assertEqual({finding.path for finding in findings}, expected_paths)
            self.assertEqual(
                len([f for f in findings if f.cwe == _PROBE_CWE]), expected_count
            )

    def test_runner_face_cap_is_request_construction_parameter(self):
        # Runner triage face (guard; passes by design at RED): the walk
        # returns every file while the selection takes exactly the frozen
        # cap -- 12 is a request-construction parameter, not a processing
        # limit, and its value stays pinned.
        module = self.real_run()
        count = 15
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-walk-") as temporary:
            root = pathlib.Path(temporary) / "tree"
            root.mkdir()
            for index in range(count):
                (root / f"module_{index:02d}.py").write_text(
                    f"VALUE = {index}\n", encoding="utf-8"
                )
            walked = module._walk_python_files(root)
            self.assertEqual(len(walked), count)
            self.assertGreater(count, module.CANDIDATE_FILE_CAP)
            selected = module._select_candidate_texts(root)
            self.assertEqual(len(selected), module.CANDIDATE_FILE_CAP)
            self.assertEqual(module.CANDIDATE_FILE_CAP, _CANDIDATE_FILE_CAP)


class TestHoldoutIdentityProbes(_V5NegativesTestCase):
    """AC-2 / FR-04 (Packet 8.2): identity variants never change verdicts."""

    def test_holdout_identity_variants_keep_verdicts_and_metrics(self):
        baseline = _probe_dataset("holdout-fixture-baseline", "case-1")
        variants = {
            "rename": _probe_dataset("holdout-fixture-renamed", "case-1-renamed"),
            "repath": copy.deepcopy(baseline),
            "metadata-top": _probe_dataset(
                "holdout-fixture-baseline",
                "case-1",
                extra_top={
                    "annotation_note": "non-semantic re-run variant",
                    "collection_tag": "variant-b",
                },
            ),
            "metadata-case": _probe_dataset(
                "holdout-fixture-baseline",
                "case-1",
                extra_case={"collector_note": "same semantics"},
            ),
        }
        # Validation face: every variant loads through the frozen validator.
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-hold-") as temporary:
            root = pathlib.Path(temporary)
            for label, dataset in (("baseline", baseline), *variants.items()):
                path = root / f"dataset-{label}.json"
                path.write_text(json.dumps(dataset), encoding="utf-8")
                loaded = load_real_world_dataset(path)
                self.assertEqual(loaded, dataset, label)
            # The repath variant is also loaded back from a different file
            # path than the baseline document (identity-free file location).
            repath_path = root / "nested" / "elsewhere" / "dataset-copy.json"
            repath_path.parent.mkdir(parents=True)
            repath_path.write_text(json.dumps(variants["repath"]), encoding="utf-8")
            self.assertEqual(load_real_world_dataset(repath_path), baseline)
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-run0-") as cache:
            baseline_document, baseline_opener = self.run_holdout(baseline, cache)
            self.assertEqual(
                baseline_opener.calls,
                [
                    _codeload_url(_PROBE_VULNERABLE_COMMIT),
                    _codeload_url(_PROBE_FIXED_COMMIT),
                ],
            )
        baseline_verdict = _verdict_tuple(baseline_document)
        # The probe measures a decidable judgment, not a vacuous pass: the
        # vulnerable revision alerts on the known file and the fixed pair
        # stays clean (paired discrimination follows from both).
        self.assertIs(baseline_verdict[0], True)
        self.assertIs(baseline_verdict[1], True)
        self.assertIs(baseline_verdict[2], True)
        baseline_metrics = _stable_metrics(baseline_document)
        for label, dataset in variants.items():
            with self.subTest(variant=label):
                with tempfile.TemporaryDirectory(prefix="lima-ip0036-run-") as cache:
                    document, opener = self.run_holdout(dataset, cache)
                    self.assertEqual(len(opener.calls), 2)
                    self.assertEqual(_verdict_tuple(document), baseline_verdict)
                    self.assertEqual(_stable_metrics(document), baseline_metrics)
        # The same cache root serves the second acquire from cache (zero
        # additional opener calls): the acquisition key is content-pinned.
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-cache-") as cache:
            first, opener = self.run_holdout(baseline, cache)
            second, _ = self.run_holdout(baseline, cache)
            self.assertEqual(len(opener.calls), 2)
            self.assertEqual(_verdict_tuple(second), _verdict_tuple(first))
            self.assertEqual(_stable_metrics(second), baseline_metrics)

    def test_holdout_identity_faces_differ_honestly(self):
        baseline = _probe_dataset("holdout-fixture-baseline", "case-1")
        rename = _probe_dataset("holdout-fixture-renamed", "case-1-renamed")
        metadata_top = _probe_dataset(
            "holdout-fixture-baseline",
            "case-1",
            extra_top={"annotation_note": "non-semantic re-run variant"},
        )
        metadata_case = _probe_dataset(
            "holdout-fixture-baseline",
            "case-1",
            extra_case={"collector_note": "same semantics"},
        )
        documents = {}
        for label, dataset in (
            ("baseline", baseline),
            ("rename", rename),
            ("metadata-top", metadata_top),
            ("metadata-case", metadata_case),
        ):
            with tempfile.TemporaryDirectory(prefix="lima-ip0036-id-") as cache:
                document, _ = self.run_holdout(dataset, cache)
                documents[label] = document

        def identity(document):
            return (
                document["dataset"],
                document["dataset_sha256"],
                document["manifest_sha256"],
            )

        baseline_identity = identity(documents["baseline"])
        self.assertEqual(baseline_identity[0], "holdout-fixture-baseline")
        # Rename changes every identity face honestly.
        self.assertNotEqual(identity(documents["rename"]), baseline_identity)
        self.assertNotEqual(
            identity(documents["rename"])[1], baseline_identity[1]
        )
        self.assertNotEqual(
            identity(documents["rename"])[2], baseline_identity[2]
        )
        # Top-level non-semantic metadata leaves the case digest identical
        # (dataset_sha256 covers only the cases) while the manifest digest
        # of the whole document differs.
        self.assertEqual(
            identity(documents["metadata-top"])[1], baseline_identity[1]
        )
        self.assertNotEqual(
            identity(documents["metadata-top"])[2], baseline_identity[2]
        )
        self.assertEqual(
            identity(documents["metadata-top"])[0], baseline_identity[0]
        )
        # Case-level non-semantic metadata changes the case digest too --
        # and still never changes the judgment face.
        self.assertNotEqual(
            identity(documents["metadata-case"])[1], baseline_identity[1]
        )
        self.assertNotEqual(
            identity(documents["metadata-case"])[2], baseline_identity[2]
        )
        for label, document in documents.items():
            with self.subTest(variant=label):
                self.assertIs(_verdict_tuple(document)[0], True)
                self.assertIs(_verdict_tuple(document)[1], True)
                self.assertEqual(
                    _verdict_tuple(document), _verdict_tuple(documents["baseline"])
                )
                self.assertEqual(
                    _stable_metrics(document),
                    _stable_metrics(documents["baseline"]),
                )


class TestDisciplineProbes(_V5NegativesTestCase):
    """FR-01 / FR-08 / AC-4 / AC-5 (Packet 8.3): mechanical discipline faces."""

    def test_pr3e_docs_in_repo_with_container_copy_lines(self):
        packet = self.read_repo_file(_PACKET_RELATIVE_PATH)
        matrix = self.read_repo_file(_MATRIX_RELATIVE_PATH)
        package = self.read_repo_file(_EXPERT_PACKAGE_RELATIVE_PATH)
        dockerfile = self.read_repo_file(_DOCKERFILE_RELATIVE_PATH)
        for copy_line in (
            _PACKET_COPY_LINE,
            _MATRIX_COPY_LINE,
            _EXPERT_PACKAGE_COPY_LINE,
        ):
            self.assertIn(copy_line, dockerfile)
        # The Packet carries the R1-R12 range authority transcription and the
        # census table (spot-check tokens, a1-style).
        for token in (
            "R1（文件拓扑终形",
            "R12（升级条款",
            "固定上限普查表",
            "signal-storm",
            "REAL_RUN_ARTIFACT_FAMILY",
        ):
            self.assertIn(token, packet)
        # The matrix carries the frozen six columns and the anchor rows.
        for token in (
            "完成门禁（可机械检查判据）",
            "未闭环缺口与真实运行/人工依赖",
            "LlamaFactory 固定 SHA",
            "repository-disjoint",
            "signal-storm",
            "CANDIDATE_FILE_CAP=12",
        ):
            self.assertIn(token, matrix)
        # The expert package carries the verified example sidecar digests.
        for token in (
            "5803dc30a7af3cb0d271be1ec7e3a8f1caba267879696e588f6d827163889c0e",
            "36ed63756dcabce7a73ffa296186294a5f30d41c1e8ba6bdd6e6ae98850c2603",
        ):
            self.assertIn(token, package)

    def test_zero_budget_artifact_naming_discipline_scan(self):
        # R9.4 (1)/(2) as mechanical criteria over the frozen catalog: the
        # nine synthetic descriptors carry the offline-proof family
        # discriminator and offline-proof run names, and neither value ever
        # carries the frozen approval wording.  IP-0039 CA v1.1 erratum: the
        # real-pilot key joins the llamafactory key in the same exclusion
        # pattern, so the discipline keeps holding on its original domain
        # (the nine offline-proof synthetic descriptors).
        module = self.real_run()
        catalog = getattr(module, "REAL_RUN_ARTIFACT_FAMILY", None)
        self.assertIsNotNone(
            catalog, "REAL_RUN_ARTIFACT_FAMILY is missing (C5 deliverable)"
        )
        synthetic_keys = sorted(
            key
            for key in catalog
            if key not in ("external/llamafactory-replay", "real-pilot/large-repo")
        )
        self.assertEqual(len(synthetic_keys), 9)
        for key in synthetic_keys:
            with self.subTest(key=key):
                descriptor = catalog[key]
                self.assertEqual(
                    descriptor["approval_type"], _ZERO_BUDGET_FAMILY_VALUE
                )
                self.assertNotIn("approval", str(descriptor["approval_type"]).lower())
                self.assertIn("offline-proof", str(descriptor["run_name"]).lower())
                self.assertNotIn("approval", str(descriptor["run_name"]).lower())

    def test_artifact_family_matches_fixture_registry(self):
        # Catalog <-> registry consistency: every synthetic artifact key is
        # a registry key, and its commit_sha equals the frozen derivation
        # recomputed from the registry fingerprint (PC3, Packet 7.4.1).
        # IP-0039 CA v1.1 erratum: the real-pilot key joins the llamafactory
        # key in the same exclusion pattern (its provenance is the
        # archetype/large-repo derivation, not a registry key of its own),
        # so the match keeps holding on its original domain.
        module = self.real_run()
        fixtures = self.fixtures()
        catalog = getattr(module, "REAL_RUN_ARTIFACT_FAMILY", None)
        self.assertIsNotNone(
            catalog, "REAL_RUN_ARTIFACT_FAMILY is missing (C5 deliverable)"
        )
        registry = fixtures.load_registry()
        entries = {entry["key"]: entry for entry in registry["fixtures"]}
        for key, descriptor in sorted(catalog.items()):
            if key in ("external/llamafactory-replay", "real-pilot/large-repo"):
                continue
            with self.subTest(key=key):
                self.assertIn(key, entries)
                fingerprint = entries[key]["fingerprint"]
                expected_sha = hashlib.sha256(
                    ("lima-synth-artifact:" + key + ":" + fingerprint).encode("utf-8")
                ).hexdigest()[:40]
                self.assertEqual(descriptor["commit_sha"], expected_sha)
                self.assertIsNotNone(_COMMIT_SHA_SHAPE.match(descriptor["commit_sha"]))

    def test_new_test_sources_offline_and_secretless(self):
        # PC1 self-scan: this file's own sources never import a network
        # root and never carry a secret shape; the positive controls prove
        # the patterns themselves match (split spellings keep the scanned
        # literals from matching this file's own assertions).
        source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(source) & _forbidden_network_roots(), set())
        self.assertIsNotNone(_SECRET_KEY_SHAPE.search("sk-" + "abcdefghij123456"))
        self.assertIsNone(_SECRET_KEY_SHAPE.search(source))
        access_key_marker = "AK" + "IA"
        self.assertIn(access_key_marker, access_key_marker + "SOMETOKEN")
        self.assertNotIn(access_key_marker, source)
        self.assertNotIn("Bear" + "er ", source)
        # The only URLs this file ever references belong to the synthetic
        # probe repository served from memory (never a real host request).
        self.assertIn("lima-synth/holdout-fixture", source)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
