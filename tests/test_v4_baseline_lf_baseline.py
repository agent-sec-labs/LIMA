"""Frozen acceptance tests for IP-0043: fixed-SHA LlamaFactory local baseline (AC-1).

Contract under test (frozen by Coordinator Assignment CA-IP-0043-v1.0 of
2026-10-01, R1/R2/R7 and C1 Done 4 AC-1; the tenth-round ruling
``.pv_tmp/ZCODE_LONG_TASK_LLAMAFACTORY_REPORT_CLOSURE_AND_HUMAN_REVIEW_2026-10-01.md``
section 3 is carried in intent):

- The Implementation deliverables are ``benchmarks/v4/baseline/lf_baseline.py``
  with the formal entry ``run_lf_local_baseline_suite(*, output_dir,
  machine_profile, source_root, binding, cold_count=3, warm_count=5, seed=0,
  sources=None)`` (positive-integer cold/warm validation, defaults 3/5), plus
  the thin CLI ``scripts/run_lf_baseline.py``.  The entry does NOT route
  through ``run_baseline_attempt``/``run_repeats`` (the SF-01 frozen dataset
  registry would reject the run-specific LF dataset name); it reuses the
  frozen identity/aggregation/persistence primitives instead:
  ``spec_from_mapping`` + ``validate_baseline_manifest``,
  ``result_from_mapping``, ``write_result_file``/``write_exclusive``,
  ``PlatformSources``/``elapsed_ms``/``classify_failure``.
- Identity is fail-closed (R2): the sealed tarball is reused read-only; the
  run-specific source binding declares archive hash/bytes, the materialized
  snapshot tree fingerprint, the repository identity and the pinned commit
  SHA ``7fcf5b3b130e5713b52415bb7404c476fada9c8c``.  A missing archive, an
  archive hash mismatch, a snapshot tree mismatch, a wrong commit SHA, an
  invalid binding shape or a non-empty output directory each terminate with
  its own typed ``LFSourceError`` code (needs-decision, this scan only) and
  zero output bytes.
- Execution is honestly counted (R1): 3 cold attempts each re-materialize a
  fresh working copy from the archive and truly re-scan it; 5 warm attempts
  reuse the last cold snapshot and scanner result, recorded truthfully in the
  per-attempt receipts (``scanner_reexecuted`` / ``materializations`` /
  ``snapshot_reused`` / ``scanner_result_reused``); aggregation goes through
  the frozen ``result_from_mapping`` (nearest-rank p50/p95, sufficient-sample
  status); failure samples are retained under the frozen taxonomy.
- Zero-model workload (R1/R3): every sample carries integer-zero
  prompt/completion/cost faces and the suite reports ``model_calls == 0``.
- Canonical projection (R1/DR-C2 Option A): the scanner wire digest is taken
  over the canonical payload whose ``repository`` and ``workspace.root``
  labels are replaced by the frozen stable external identity
  ``external/llamafactory-replay@7fcf5b3b``, so the same layout yields equal
  wire digests across directories and the new artifact family cannot collide
  with the existing frozen families.

Everything here is offline and deterministic: the "sealed" archive is a
synthetic inert tarball built in a temp directory (zero real downloads; the
real sealed snapshot stays untouched), the scanner runs under the frozen
explicit offline configuration, platform sources are injected fakes (Windows
null RSS/IO faces included honestly), and no test ever touches a network
socket, reads the environment, or sleeps.

Expected RED before implementation (product modules absent): ten methods fail
on the missing deliverables -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.lf_baseline'``
(lazy per-test import) plus the missing CLI script; no method fails on an
import accident of a frozen module.  The five old frozen test files stay
untouched and green.
"""

import ast
import hashlib
import importlib.util
import inspect
import io
import json
import pathlib
import re
import tarfile
import tempfile
import unittest

from benchmarks.v4.baseline.collect import FAILURE_TAXONOMY_CODES, PlatformSources
from lima.baseline_run_spec import BaselineRunSpecError, validate_baseline_manifest
from lima.baseline_run_spec import from_mapping as spec_from_mapping

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_LF_RELATIVE_PATH = "benchmarks/v4/baseline/lf_baseline.py"
_LF_CLI_RELATIVE_PATH = "scripts/run_lf_baseline.py"

#: The frozen target identity (CA-IP-0043-v1.0 R2; pinned, never replaced).
_LF_COMMIT_SHA = "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
_LF_REPOSITORY_IDENTITY = "hiyouga/LlamaFactory"
_LF_DATASET_NAME = "lima-external-llamafactory-holdout-v1"
_LF_DATASET_ROLE = "external-holdout"
#: The canonical projection label (R1: the Packet pins this exact literal).
_LF_CANONICAL_LABEL = "external/llamafactory-replay@7fcf5b3b"
#: The LF workload label; it enters the run identity face.
_LF_WORKLOAD = "lf-local-scanner-v1"
#: The archive top-level directory (mirrors the sealed 2026-09-28 layout,
#: single top-level directory stripped at materialization time).
_ARCHIVE_TOP = f"LlamaFactory-{_LF_COMMIT_SHA}"

#: The frozen typed error family of the new module (R2 floor, Packet final).
_LF_ERROR_CODES = frozenset(
    {
        "LF_SOURCE_MISSING",
        "LF_SOURCE_HASH_MISMATCH",
        "LF_SNAPSHOT_TREE_MISMATCH",
        "LF_IDENTITY_CONFLICT",
        "LF_OUTPUT_NOT_EMPTY",
        "LF_BINDING_INVALID",
        "LF_PARAM_INVALID",
    }
)
_IDENTITY_ERROR_CODES = frozenset(
    {
        "LF_SOURCE_MISSING",
        "LF_SOURCE_HASH_MISMATCH",
        "LF_SNAPSHOT_TREE_MISMATCH",
        "LF_IDENTITY_CONFLICT",
    }
)

#: The frozen per-attempt receipt key set (the b1_source sixteen-key
#: precedent re-cut for the LF source binding; closed).
_LF_RECEIPT_KEYS = frozenset(
    {
        "attempt_index",
        "mode",
        "run_spec_digest",
        "workload",
        "commit_sha",
        "snapshot_tree_sha256",
        "archive_sha256",
        "materializations",
        "scanner_reexecuted",
        "scanner_result_reused",
        "snapshot_reused",
        "scanner_payload_sha256",
    }
)

#: The frozen lf-binding manifest key set (closed).
_LF_BINDING_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "workload",
        "run_spec_digest",
        "attempt_count",
        "cold_count",
        "warm_count",
        "repository_identity",
        "commit_sha",
        "dataset_name",
        "dataset_role",
        "archive_sha256",
        "archive_bytes",
        "snapshot_tree_sha256",
        "analyzer_name",
        "analyzer_fingerprint",
        "config_digest",
        "scanner_config",
        "scanner_config_sha256",
        "seed",
        "scanner_payload_sha256",
        "lf_receipts",
        "lf_receipts_digest",
        "failures",
        "model_calls",
        "declarations",
    }
)

#: The frozen entry signature (R1 skeleton plus the run-specific source
#: binding; every parameter keyword-only, cold/warm defaulting to 3/5).
_LF_ENTRY_ORDER = (
    "output_dir",
    "machine_profile",
    "source_root",
    "binding",
    "cold_count",
    "warm_count",
    "seed",
    "sources",
)

_MACHINE_PROFILE = {
    "profile_id": "lima-lf-local-profile-001",
    "cpu_arch": "x86_64",
    "cpu_model": "declared-lf-baseline-cpu",
    "cores": 8,
    "ram_gb": 32,
    "os_family": "windows",
    "python_version": "3.12.4",
    "gpu_summary": "none",
}

_SECRET_KEY_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{16,}")
_HEX64_SHAPE = re.compile(r"^[0-9a-f]{64}$")
_RUN_NAME_SHAPE = re.compile(r"^[0-9a-f]{16}-run-\d+\.json$")
_REPORT_NAME_SHAPE = re.compile(r"^[0-9a-f]{16}-report-\d+\.json$")

_INERT_HEADER = (
    "# SYNTHETIC INERT LF BASELINE FIXTURE -- NOT A REAL VULNERABILITY\n"
)

#: The synthetic sealed snapshot (inert, offline, temp-local): a small
#: LlamaFactory-shaped tree with one inert pattern file, one sensitive-config
#: placeholder (a non-coverage-affecting skip face) and plain metadata files.
_SYNTHETIC_TREE = {
    "README.md": (
        "# SYNTHETIC INERT LF BASELINE FIXTURE\n"
        "# Not the real LlamaFactory repository; offline test tree only.\n"
    ),
    "setup.py": 'from setuptools import setup\n\nsetup(name="synthetic-lf")\n',
    "pyproject.toml": '[project]\nname = "synthetic-lf"\nversion = "0.0.0"\n',
    ".env.local": "# SYNTHETIC inert local config placeholder\n",
    "src/llamafactory/__init__.py": '"""Synthetic inert package."""\n',
    "src/llamafactory/extras.py": (
        _INERT_HEADER
        + "# Inert command-injection pattern shape; never executed.\n"
        "\n"
        "import os\n"
        "\n"
        "\n"
        "def run_user_command() -> int:\n"
        '    return os.system("synthetic-inert-lf-command")\n'
    ),
}


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


def _write_tree(root, tree):
    """Materialize a flat {relative: text} mapping under root."""
    base = pathlib.Path(root)
    for relative, payload in tree.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
    return base


def _tree_sha256(root):
    """Independent transcription of the frozen snapshot tree fingerprint rule.

    Mirrors ``SnapshotStore._tree_identity`` (the algorithm backing the
    authoritative 596-file sealed inventory): sorted relative POSIX paths,
    ``len(path):path:size:\\0`` framing then the raw bytes, excluding the
    snapshot metadata marker.  Dual-source discipline (PC3): the module must
    independently arrive at exactly this value.
    """
    base = pathlib.Path(root)
    digest = hashlib.sha256()
    files = sorted(
        (
            item
            for item in base.rglob("*")
            if item.name != ".lima-snapshot.json" and item.is_file()
        ),
        key=lambda item: item.relative_to(base).as_posix(),
    )
    for item in files:
        relative = item.relative_to(base).as_posix().encode("utf-8")
        size = item.stat().st_size
        digest.update(str(len(relative)).encode("ascii"))
        digest.update(b":")
        digest.update(relative)
        digest.update(b":")
        digest.update(str(size).encode("ascii"))
        digest.update(b"\0")
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _build_archive(directory, tree, top=_ARCHIVE_TOP):
    """One deterministic synthetic sealed tarball of the given tree."""
    archive = pathlib.Path(directory) / "lf-source.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for relative in sorted(tree):
            payload = tree[relative].encode("utf-8")
            info = tarfile.TarInfo(f"{top}/{relative}")
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            bundle.addfile(info, io.BytesIO(payload))
    return archive


def _archive_faces(archive_path):
    """(sha256, byte length) of one archive file, freshly computed."""
    payload = pathlib.Path(archive_path).read_bytes()
    return hashlib.sha256(payload).hexdigest(), len(payload)


class _FakePlatformSources:
    """Deterministic injected sources: monotonic fake clocks, Windows nulls."""

    def sources(self):
        state = {"wall_ns": 1_000_000_000, "cpu_ns": 500_000_000}

        def wall_ns():
            state["wall_ns"] += 2_500_000
            return state["wall_ns"]

        def cpu_ns():
            state["cpu_ns"] += 1_000_000
            return state["cpu_ns"]

        return PlatformSources(
            wall_ns=wall_ns,
            cpu_ns=cpu_ns,
            peak_rss_bytes=lambda: None,
            io_read_bytes=lambda: None,
            io_write_bytes=lambda: None,
        )


class _LFBaselineTestCase(unittest.TestCase):
    """Shared arrange helpers (all new-module imports are lazy per test)."""

    def lf(self):
        import benchmarks.v4.baseline.lf_baseline as module

        return module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def machine_profile(self):
        return dict(_MACHINE_PROFILE)

    def synthetic_run_inputs(self, parent, tree=None):
        """(archive path, binding) for the synthetic sealed snapshot."""
        tree = dict(_SYNTHETIC_TREE if tree is None else tree)
        materialized = _write_tree(pathlib.Path(parent) / "authority", tree)
        archive = _build_archive(pathlib.Path(parent) / "authority", tree)
        return archive, self.binding_for(archive, materialized)

    def binding_for(self, archive, materialized_tree, **overrides):
        """The run-specific schema-v1 source-binding manifest document."""
        archive_sha256, archive_bytes = _archive_faces(archive)
        dataset = {
            "name": _LF_DATASET_NAME,
            "fingerprint": _tree_sha256(materialized_tree),
            "role": _LF_DATASET_ROLE,
            "entries": [
                {
                    "repository": _LF_REPOSITORY_IDENTITY,
                    "commit_sha": _LF_COMMIT_SHA,
                }
            ],
            "license": "Apache-2.0 (upstream SPDX)",
            "source": "sealed-tarball-reuse-2026-09-28",
            "layout": "single-top-level-directory",
            "archive_sha256": archive_sha256,
            "archive_bytes": archive_bytes,
        }
        dataset.update(overrides)
        return {"schema_version": 1, "datasets": [dataset]}

    def run_suite(self, output_dir, archive, binding, **overrides):
        module = self.lf()
        options = {
            "output_dir": output_dir,
            "machine_profile": self.machine_profile(),
            "source_root": archive,
            "binding": binding,
            "sources": _FakePlatformSources().sources(),
        }
        options.update(overrides)
        return module.run_lf_local_baseline_suite(**options)

    def read_json(self, path):
        return json.loads(pathlib.Path(path).read_bytes().decode("utf-8"))

    def receipts_of(self, output_dir):
        directory = pathlib.Path(output_dir) / "lf-attempts"
        paths = sorted(directory.glob("attempt-*.json"))
        self.assertTrue(paths, "no lf attempt documents were written")
        return [self.read_json(path)["source_receipt"] for path in paths]

    def result_documents(self, output_dir):
        """Every result file, ordered by run sequence number."""
        directory = pathlib.Path(output_dir)
        paths = sorted(
            directory.glob("*-run-*.json"),
            key=lambda path: int(path.stem.rsplit("-", 1)[1]),
        )
        self.assertTrue(paths, "no lf result files were written")
        return [(path, self.read_json(path)) for path in paths]

    def content_digest(self, value):
        from lima.contracts.codec import compute_content_digest

        return compute_content_digest(value)

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

    def scanner_wire_digest(self, scan_result, label):
        """Independent mirror of the frozen scanner fingerprint rule (PC3)."""
        wire = {
            **scan_result.report.to_dict(),
            "workspace": scan_result.inventory.to_dict(),
        }
        wire["repository"] = label
        wire["workspace"] = {**wire["workspace"], "root": label}
        encoded = json.dumps(
            wire,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
        return hashlib.sha256(encoded).hexdigest()

    def assert_zero_output(self, output_dir):
        names = sorted(item.name for item in pathlib.Path(output_dir).iterdir())
        self.assertEqual(names, [], "fail-closed termination must write nothing")


class TestLFEntrySurface(_LFBaselineTestCase):
    """The module surface, the pinned identity constants and the CLI entry."""

    def test_lf_module_surface_signature_and_source_hygiene(self):
        module = self.lf()
        # Frozen constants: the pinned external identity and the labels.
        self.assertEqual(module.LF_TARGET_COMMIT_SHA, _LF_COMMIT_SHA)
        self.assertEqual(module.LF_REPOSITORY_IDENTITY, _LF_REPOSITORY_IDENTITY)
        self.assertEqual(module.LF_DATASET_NAME, _LF_DATASET_NAME)
        self.assertEqual(module.LF_DATASET_ROLE, _LF_DATASET_ROLE)
        self.assertEqual(module.LF_WORKLOAD, _LF_WORKLOAD)
        self.assertEqual(module.LF_CANONICAL_LABEL, _LF_CANONICAL_LABEL)
        # Frozen entry signature: keyword-only, defaults 3/5/0.
        parameters = inspect.signature(
            module.run_lf_local_baseline_suite
        ).parameters
        self.assertEqual(tuple(parameters), _LF_ENTRY_ORDER)
        for parameter in parameters.values():
            self.assertTrue(
                parameter.kind is parameter.KEYWORD_ONLY, parameter.name
            )
        self.assertEqual(parameters["cold_count"].default, 3)
        self.assertEqual(parameters["warm_count"].default, 5)
        self.assertEqual(parameters["seed"].default, 0)
        self.assertIsNone(parameters["sources"].default)
        # Frozen typed error family: closed code set; each member renders its
        # bare frozen wire value through ``__str__`` (the B1SourceErrorCode
        # precedent), never the ``Class.MEMBER`` enum spelling.
        self.assertEqual(
            {str(code) for code in module.LFSourceErrorCode}, _LF_ERROR_CODES
        )
        self.assertTrue(issubclass(module.LFSourceError, ValueError))
        # The thin CLI entry exists and parses the frozen flag surface.
        cli_path = _REPO_ROOT / _LF_CLI_RELATIVE_PATH
        if not cli_path.is_file():
            self.fail(f"required CLI script is missing: {_LF_CLI_RELATIVE_PATH}")
        cli_source = cli_path.read_text(encoding="utf-8")
        self.assertIn("run_lf_local_baseline_suite", cli_source)
        spec = importlib.util.spec_from_file_location("run_lf_baseline_cli", cli_path)
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as temporary:
            parsed = cli.build_parser().parse_args(
                [
                    "--output-dir", str(pathlib.Path(temporary) / "out"),
                    "--source-root", str(pathlib.Path(temporary) / "source.tar.gz"),
                    "--binding", str(pathlib.Path(temporary) / "binding.json"),
                    "--cold-count", "3",
                    "--warm-count", "5",
                    "--seed", "0",
                ]
            )
            self.assertEqual(parsed.cold_count, 3)
            self.assertEqual(parsed.warm_count, 5)
            self.assertEqual(parsed.seed, 0)
        # Source hygiene (AC-5): the new module stays offline and secretless,
        # with no transport parameter and no budget constant.
        source = self.product_source(_LF_RELATIVE_PATH)
        self.assertEqual(_import_roots(source) & _forbidden_network_roots(), set())
        self.assertNotIn("environ", source)
        self.assertNotIn("getenv", source)
        self.assertNotIn("subprocess", source)
        self.assertNotIn("exec(", source)
        self.assertNotIn("eval(", source)
        self.assertIsNone(_SECRET_KEY_SHAPE.search(source))
        self.assertNotIn("transport", source)
        self.assertNotIn("BUDGET", source)
        # PC1 self-scan (passes by design): this file stays offline too.
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))


class TestLFIdentityFailClosed(_LFBaselineTestCase):
    """AC-1: identity is fail-closed, typed, needs-decision, zero output."""

    def test_lf_missing_archive_fails_closed_with_zero_output(self):
        module = self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            archive.unlink()
            output = parent / "out"
            output.mkdir()
            with self.assertRaises(module.LFSourceError) as caught:
                self.run_suite(output, archive, binding)
            self.assertEqual(str(caught.exception.code), "LF_SOURCE_MISSING")
            self.assertIs(True, caught.exception.needs_decision)
            self.assert_zero_output(output)

    def test_lf_identity_mismatch_faces_each_typed_code(self):
        module = self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            materialized = parent / "authority"
            archive_sha256, archive_bytes = _archive_faces(archive)
            tree_sha = _tree_sha256(materialized)
            hash_mismatch = self.binding_for(archive, materialized)
            hash_mismatch["datasets"][0]["archive_sha256"] = "f" * 64
            tree_mismatch = self.binding_for(archive, materialized)
            tree_mismatch["datasets"][0]["fingerprint"] = "e" * 64
            identity_conflict = self.binding_for(archive, materialized)
            identity_conflict["datasets"][0]["entries"][0]["commit_sha"] = "c" * 40
            binding_invalid = self.binding_for(archive, materialized)
            binding_invalid["datasets"][0]["role"] = "not-a-role"
            faces = {
                "LF_SOURCE_HASH_MISMATCH": hash_mismatch,
                "LF_SNAPSHOT_TREE_MISMATCH": tree_mismatch,
                "LF_IDENTITY_CONFLICT": identity_conflict,
                "LF_BINDING_INVALID": binding_invalid,
            }
            for code, face_binding in sorted(faces.items()):
                with self.subTest(code=code):
                    output = parent / f"out-{code}"
                    output.mkdir()
                    with self.assertRaises(module.LFSourceError) as caught:
                        self.run_suite(output, archive, face_binding)
                    self.assertEqual(str(caught.exception.code), code)
                    if code in _IDENTITY_ERROR_CODES:
                        self.assertIs(True, caught.exception.needs_decision)
                    self.assert_zero_output(output)
            # The non-empty output directory is its own typed face: nothing
            # pre-existing is touched or overwritten.
            output = parent / "out-nonempty"
            output.mkdir()
            marker = output / "pre-existing-marker.json"
            marker.write_text("{}", encoding="utf-8")
            with self.assertRaises(module.LFSourceError) as caught:
                self.run_suite(output, archive, binding)
            self.assertEqual(str(caught.exception.code), "LF_OUTPUT_NOT_EMPTY")
            self.assertEqual(marker.read_text(encoding="utf-8"), "{}")
            self.assertEqual(
                sorted(item.name for item in output.iterdir()),
                ["pre-existing-marker.json"],
            )
            # The invalid role face is also rejected by the frozen spec-layer
            # validator itself (three-way agreement, dual source).
            rebuilt_spec = spec_from_mapping(
                {
                    "schema_version": 1,
                    "repositories": [
                        {
                            "identity": _LF_REPOSITORY_IDENTITY,
                            "commit_sha": _LF_COMMIT_SHA,
                        }
                    ],
                    "datasets": [
                        {
                            "name": _LF_DATASET_NAME,
                            "fingerprint": tree_sha,
                            "role": _LF_DATASET_ROLE,
                        }
                    ],
                    "analyzer_fingerprint": "a" * 64,
                    "config_digest": "b" * 64,
                    "seed": 0,
                    "machine_profile": self.machine_profile(),
                }
            )
            with self.assertRaises(BaselineRunSpecError):
                validate_baseline_manifest(binding_invalid, rebuilt_spec)
            # The honest binding passes the frozen validators unchanged.
            self.assertIsNone(validate_baseline_manifest(binding, rebuilt_spec))

    def test_lf_cold_warm_positive_integer_validation(self):
        module = self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            for label, overrides in (
                ("cold-zero", {"cold_count": 0}),
                ("cold-negative", {"cold_count": -1}),
                ("cold-bool", {"cold_count": True}),
                ("cold-float", {"cold_count": 1.5}),
                ("warm-zero", {"warm_count": 0}),
                ("warm-float", {"warm_count": 2.5}),
            ):
                with self.subTest(face=label):
                    output = parent / f"out-{label}"
                    output.mkdir()
                    with self.assertRaises(module.LFSourceError) as caught:
                        self.run_suite(output, archive, binding, **overrides)
                    self.assertEqual(str(caught.exception.code), "LF_PARAM_INVALID")
                    self.assert_zero_output(output)
            # Positive integers are honored: defaults give 3+5, 1+1 gives 2.
            default_output = parent / "out-default"
            default_output.mkdir()
            default = self.run_suite(default_output, archive, binding)
            self.assertEqual(default.attempt_count, 8)
            custom_output = parent / "out-custom"
            custom_output.mkdir()
            custom = self.run_suite(
                custom_output, archive, binding, cold_count=1, warm_count=1
            )
            self.assertEqual(custom.attempt_count, 2)


class TestLFFullChain(_LFBaselineTestCase):
    """AC-1: 3 cold + 5 warm execution with honest receipts and binding."""

    def test_lf_three_cold_five_warm_receipt_semantics(self):
        self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            output = parent / "out"
            output.mkdir()
            result = self.run_suite(output, archive, binding)
            self.assertEqual(result.attempt_count, 8)
            self.assertEqual(result.status, "sufficient_sample")
            self.assertEqual(result.model_calls, 0)
            self.assertEqual(result.workload, _LF_WORKLOAD)
            self.assertEqual(result.scanner_executions, 3)
            self.assertEqual(result.materializations, 3)
            self.assertTrue(_HEX64_SHAPE.match(result.run_spec_digest))
            self.assertTrue(_HEX64_SHAPE.match(result.aggregate_sha256))
            self.assertEqual(
                result.snapshot_tree_sha256, _tree_sha256(parent / "authority")
            )
            self.assertEqual(result.archive_sha256, _archive_faces(archive)[0])
            receipts = self.receipts_of(output)
            self.assertEqual(len(receipts), 8)
            self.assertEqual(
                [receipt["mode"] for receipt in receipts],
                ["cold"] * 3 + ["warm"] * 5,
            )
            self.assertEqual(
                [receipt["attempt_index"] for receipt in receipts], list(range(8))
            )
            for receipt in receipts:
                self.assertEqual(set(receipt), _LF_RECEIPT_KEYS)
                self.assertEqual(receipt["run_spec_digest"], result.run_spec_digest)
                self.assertEqual(receipt["workload"], _LF_WORKLOAD)
                self.assertEqual(receipt["commit_sha"], _LF_COMMIT_SHA)
                self.assertEqual(
                    receipt["snapshot_tree_sha256"], result.snapshot_tree_sha256
                )
                self.assertEqual(receipt["archive_sha256"], result.archive_sha256)
            for index, receipt in enumerate(receipts[:3]):
                self.assertTrue(receipt["scanner_reexecuted"])
                self.assertFalse(receipt["scanner_result_reused"])
                self.assertFalse(receipt["snapshot_reused"])
                self.assertEqual(receipt["materializations"], index + 1)
            for receipt in receipts[3:]:
                self.assertFalse(receipt["scanner_reexecuted"])
                self.assertTrue(receipt["scanner_result_reused"])
                self.assertTrue(receipt["snapshot_reused"])
                self.assertEqual(receipt["materializations"], 3)
            # One stable scanner payload digest across every attempt.
            self.assertEqual(
                {receipt["scanner_payload_sha256"] for receipt in receipts},
                {result.scanner_payload_sha256},
            )

    def test_lf_binding_manifest_closed_keys_and_identity_sensitivity(self):
        self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            output = parent / "base"
            output.mkdir()
            result = self.run_suite(output, archive, binding)
            manifest = self.read_json(output / "lf-binding.json")
            self.assertEqual(set(manifest), _LF_BINDING_MANIFEST_KEYS)
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["workload"], _LF_WORKLOAD)
            self.assertEqual(manifest["run_spec_digest"], result.run_spec_digest)
            self.assertEqual(manifest["attempt_count"], 8)
            self.assertEqual(manifest["cold_count"], 3)
            self.assertEqual(manifest["warm_count"], 5)
            self.assertEqual(manifest["repository_identity"], _LF_REPOSITORY_IDENTITY)
            self.assertEqual(manifest["commit_sha"], _LF_COMMIT_SHA)
            self.assertEqual(manifest["dataset_name"], _LF_DATASET_NAME)
            self.assertEqual(manifest["dataset_role"], _LF_DATASET_ROLE)
            self.assertEqual(manifest["archive_sha256"], result.archive_sha256)
            self.assertEqual(manifest["archive_bytes"], archive.stat().st_size)
            self.assertEqual(
                manifest["snapshot_tree_sha256"], result.snapshot_tree_sha256
            )
            self.assertEqual(manifest["seed"], 0)
            self.assertEqual(manifest["model_calls"], 0)
            self.assertEqual(manifest["failures"], [])
            self.assertTrue(manifest["declarations"])
            receipts = self.receipts_of(output)
            self.assertEqual(manifest["lf_receipts"], receipts)
            self.assertEqual(
                manifest["lf_receipts_digest"], self.content_digest(receipts)
            )
            # The explicit offline scanner configuration, digest-bound.
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
                config["workspace"],
                {
                    "max_files": 5000,
                    "max_file_bytes": 512 * 1024,
                    "max_total_bytes": 20 * 1024 * 1024,
                },
            )
            self.assertEqual(
                manifest["scanner_config_sha256"], self.content_digest(config)
            )
            # The three-way agreement holds on the frozen validators too:
            # the accepted binding and the rebuilt spec cross-validate.
            spec_mapping = {
                "schema_version": 1,
                "repositories": [
                    {
                        "identity": _LF_REPOSITORY_IDENTITY,
                        "commit_sha": _LF_COMMIT_SHA,
                    }
                ],
                "datasets": [
                    {
                        "name": _LF_DATASET_NAME,
                        "fingerprint": result.snapshot_tree_sha256,
                        "role": _LF_DATASET_ROLE,
                    }
                ],
                "analyzer_fingerprint": manifest["analyzer_fingerprint"],
                "config_digest": manifest["config_digest"],
                "seed": 0,
                "machine_profile": self.machine_profile(),
            }
            self.assertIsNone(
                validate_baseline_manifest(binding, spec_from_mapping(spec_mapping))
            )
            # Identity sensitivity (NFR-01): snapshot content, seed and the
            # cold/warm configuration each change the run identity face.
            varied_tree = dict(_SYNTHETIC_TREE)
            varied_tree["src/llamafactory/extra_module.py"] = (
                _INERT_HEADER + "VALUE = 1\n"
            )
            varied_archive, varied_binding = self.synthetic_run_inputs(
                parent / "varied", varied_tree
            )
            variations = {
                "snapshot": (varied_archive, varied_binding, {}),
                "seed": (archive, binding, {"seed": 7}),
                "cold-count": (archive, binding, {"cold_count": 2}),
            }
            for label, (face_archive, face_binding, overrides) in variations.items():
                with self.subTest(face=label):
                    face_output = parent / f"var-{label}"
                    face_output.mkdir()
                    face_result = self.run_suite(
                        face_output, face_archive, face_binding, **overrides
                    )
                    self.assertNotEqual(
                        face_result.run_spec_digest, result.run_spec_digest
                    )
                    for receipt in self.receipts_of(face_output):
                        self.assertEqual(
                            receipt["run_spec_digest"], face_result.run_spec_digest
                        )

    def test_lf_aggregation_through_frozen_contract_and_taxonomy_retention(self):
        self.lf()
        from lima.baseline_run_result import from_mapping

        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            output = parent / "out"
            output.mkdir()
            result = self.run_suite(output, archive, binding)
            documents = self.result_documents(output)
            per_attempt = documents[:-1]
            aggregate_path, aggregate_document = documents[-1]
            self.assertEqual(aggregate_path, pathlib.Path(result.aggregate_path))
            self.assertEqual(len(per_attempt), 8)
            samples = []
            for _, document in per_attempt:
                self.assertEqual(len(document["samples"]), 1)
                samples.append(document["samples"][0])
            ordered = sorted(samples, key=lambda sample: sample["attempt_index"])
            # The written aggregate is exactly the frozen recomputation over
            # the per-attempt samples (nearest-rank + status, never hand-made).
            recomputed = from_mapping(
                {
                    "schema_version": 1,
                    "run_spec_digest": result.run_spec_digest,
                    "samples": ordered,
                }
            )
            self.assertEqual(aggregate_document["samples"], recomputed.samples)
            self.assertEqual(aggregate_document["status"], recomputed.status)
            self.assertEqual(aggregate_document["status"], "sufficient_sample")
            self.assertEqual(
                aggregate_document["cold_p50_wall_time_ms"],
                recomputed.cold_p50_wall_time_ms,
            )
            self.assertEqual(
                aggregate_document["warm_p95_wall_time_ms"],
                recomputed.warm_p95_wall_time_ms,
            )
            self.assertEqual(
                pathlib.Path(aggregate_path).read_bytes(),
                recomputed.canonical_bytes(),
            )
            # Taxonomy retention (the frozen contract semantics the entry
            # must consume): failure samples stay in the denominator and flip
            # the status honestly instead of being dropped.
            retained = [dict(sample) for sample in ordered]
            retained[0]["outcome"] = "failure"
            retained[0]["failure_code"] = "EXECUTION_ERROR"
            retained[0]["wall_time_ms"] = None
            failure_aggregate = from_mapping(
                {
                    "schema_version": 1,
                    "run_spec_digest": result.run_spec_digest,
                    "samples": retained,
                }
            )
            self.assertEqual(failure_aggregate.status, "insufficient_sample")
            self.assertEqual(len(failure_aggregate.samples), 8)
            self.assertIsNone(failure_aggregate.cold_p50_wall_time_ms)
            # A corrupt-but-hash-consistent archive (the declared binding pins
            # the corrupt bytes) fails every attempt body without raising:
            # eight failure samples are retained under the frozen taxonomy.
            corrupt = parent / "corrupt"
            corrupt.mkdir()
            corrupt_archive = corrupt / "lf-source.tar.gz"
            corrupt_archive.write_bytes(b"synthetic corrupt archive payload" * 16)
            corrupt_binding = self.binding_for(corrupt_archive, parent / "authority")
            corrupt_output = corrupt / "out"
            corrupt_output.mkdir()
            corrupt_result = self.run_suite(
                corrupt_output, corrupt_archive, corrupt_binding
            )
            self.assertEqual(corrupt_result.attempt_count, 8)
            corrupt_documents = self.result_documents(corrupt_output)
            corrupt_aggregate = corrupt_documents[-1][1]
            self.assertEqual(len(corrupt_aggregate["samples"]), 8)
            self.assertEqual(corrupt_aggregate["status"], "insufficient_sample")
            for _, document in corrupt_documents[:-1]:
                sample = document["samples"][0]
                self.assertNotEqual(sample["outcome"], "success")
                self.assertIn(sample["failure_code"], FAILURE_TAXONOMY_CODES)
            corrupt_manifest = self.read_json(corrupt_output / "lf-binding.json")
            self.assertEqual(set(corrupt_manifest["failures"]), {"EXECUTION_ERROR"})

    def test_lf_samples_zero_model_faces_everywhere(self):
        self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            output = parent / "out"
            output.mkdir()
            result = self.run_suite(output, archive, binding)
            self.assertEqual(result.model_calls, 0)
            manifest = self.read_json(output / "lf-binding.json")
            self.assertEqual(manifest["model_calls"], 0)
            for path, document in self.result_documents(output):
                for sample in document["samples"]:
                    with self.subTest(result_file=path.name):
                        self.assertIs(type(sample["prompt_tokens"]), int)
                        self.assertEqual(sample["prompt_tokens"], 0)
                        self.assertIs(type(sample["completion_tokens"]), int)
                        self.assertEqual(sample["completion_tokens"], 0)
                        self.assertIs(type(sample["cost_micro_usd"]), int)
                        self.assertEqual(sample["cost_micro_usd"], 0)

    def test_lf_output_family_naming_and_no_prefix_collision(self):
        self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            output = parent / "out"
            output.mkdir()
            result = self.run_suite(output, archive, binding)
            for entry in sorted(output.iterdir()):
                self.assertTrue(
                    _RUN_NAME_SHAPE.match(entry.name)
                    or _REPORT_NAME_SHAPE.match(entry.name)
                    or entry.name in ("lf-attempts", "lf-binding.json"),
                    f"unexpected output entry: {entry.name}",
                )
            result_names = sorted(
                path.name for path, _ in self.result_documents(output)
            )
            self.assertEqual(len(result_names), 9)  # 8 attempts + aggregate
            prefix = result.run_spec_digest[:16]
            self.assertTrue(all(name.startswith(prefix) for name in result_names))
            report_path = pathlib.Path(result.report_path)
            self.assertTrue(report_path.is_file())
            self.assertTrue(_REPORT_NAME_SHAPE.match(report_path.name))
            # Zero collision with the frozen B1 family (structural face): a
            # completely different source binding yields a different full
            # run-spec digest and a different 16-char file prefix.
            import benchmarks.v4.baseline.b1_source as b1_source

            b1_output = parent / "b1-out"
            b1_output.mkdir()
            b1_result = b1_source.run_b1_source_baseline_suite(
                output_dir=b1_output, machine_profile=self.machine_profile()
            )
            self.assertNotEqual(result.run_spec_digest, b1_result.run_spec_digest)
            self.assertNotEqual(prefix, b1_result.run_spec_digest[:16])
            b1_names = {path.name for path in b1_output.iterdir() if path.is_file()}
            self.assertEqual(set(result_names) & b1_names, set())

    def test_lf_canonical_projection_stable_external_identity(self):
        module = self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            archive, binding = self.synthetic_run_inputs(parent)
            output = parent / "out"
            output.mkdir()
            result = self.run_suite(output, archive, binding)
            # DR-C2 Option A: two independently materialized copies of the
            # same layout in different directories project to one wire
            # digest under the frozen stable external identity label.
            digests = set()
            for index in range(2):
                root = _write_tree(parent / f"direct-{index}", _SYNTHETIC_TREE)
                digests.add(
                    self.scanner_wire_digest(
                        self.direct_scan(root), module.LF_CANONICAL_LABEL
                    )
                )
            self.assertEqual(len(digests), 1)
            expected_digest = digests.pop()
            self.assertEqual(result.scanner_payload_sha256, expected_digest)
            receipts = self.receipts_of(output)
            self.assertEqual(
                {receipt["scanner_payload_sha256"] for receipt in receipts},
                {expected_digest},
            )
            report = self.read_json(result.report_path)
            self.assertEqual(
                [source["kind"] for source in report["sources"]], ["scanner"]
            )
            self.assertEqual(report["sources"][0]["payload_sha256"], expected_digest)
            self.assertEqual(report["run_spec_digest"], result.run_spec_digest)


class TestLFLinkMemberSkip(_LFBaselineTestCase):
    """DR-IP-0043-CFINAL Option A: link members skip, everything else not.

    The sealed archive carries a symbolic link member, so the amended
    materialization rule (2026-10-01 ruling) deterministically skips link
    members (symbolic and hard links): they never enter the materialized
    tree or its fingerprint, mirroring the ``real_world_evaluation`` omit
    precedent and the authoritative 09-28 sealed inventory.  Every other
    abnormal member type keeps the whole-archive rejection, and the skip
    must not disturb the canonical projection, the aggregation or the
    per-attempt receipt faces of a minimal chain.
    """

    def test_lf_link_members_skipped_deterministically(self):
        module = self.lf()
        tree = dict(_SYNTHETIC_TREE)
        tree[".ai/CLAUDE.md"] = "# SYNTHETIC inert agent notes\n"
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            authority = _write_tree(parent / "authority", tree)
            expected = _tree_sha256(authority)

            def member(name, **attributes):
                info = tarfile.TarInfo(f"{_ARCHIVE_TOP}/{name}")
                info.mtime = 0
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                for field, value in attributes.items():
                    setattr(info, field, value)
                return info

            def link_archive(directory):
                archive = pathlib.Path(directory) / "lf-source.tar.gz"
                archive.parent.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive, "w:gz") as bundle:
                    for name in (".ai", "src", "src/llamafactory"):
                        bundle.addfile(
                            member(name, type=tarfile.DIRTYPE, mode=0o755)
                        )
                    for name in sorted(tree):
                        payload = tree[name].encode("utf-8")
                        bundle.addfile(
                            member(name, size=len(payload), mode=0o644),
                            io.BytesIO(payload),
                        )
                    bundle.addfile(
                        member(
                            "CLAUDE.md",
                            type=tarfile.SYMTYPE,
                            mode=0o644,
                            linkname=".ai/CLAUDE.md",
                        )
                    )
                    bundle.addfile(
                        member(
                            "NOTES.md",
                            type=tarfile.LNKTYPE,
                            mode=0o644,
                            linkname=f"{_ARCHIVE_TOP}/README.md",
                        )
                    )
                return archive

            archive = link_archive(parent / "with-links")
            # Arrange guard: the synthetic sealed archive truly carries one
            # symbolic and one hard link member (the DR-IP-0043-CFINAL
            # failure faces), so a skip cannot pass vacuously.
            with tarfile.open(archive, "r:gz") as bundle:
                members = {item.name: item for item in bundle}
            self.assertTrue(members[f"{_ARCHIVE_TOP}/CLAUDE.md"].issym())
            self.assertTrue(members[f"{_ARCHIVE_TOP}/NOTES.md"].islnk())
            # Two fresh materializations deterministically skip both link
            # members: the link names never enter the tree under any shape.
            fingerprints = []
            for index in range(2):
                target = parent / f"materialized-{index}"
                self.assertIs(
                    module._materialize_snapshot(archive, target), target
                )
                self.assertFalse((target / "CLAUDE.md").exists())
                self.assertFalse((target / "NOTES.md").exists())
                self.assertFalse(
                    any(item.is_symlink() for item in target.rglob("*"))
                )
                self.assertEqual(
                    {
                        item.relative_to(target).as_posix()
                        for item in target.rglob("*")
                        if item.is_file()
                    },
                    set(tree),
                )
                fingerprints.append(_tree_sha256(target))
            self.assertEqual(fingerprints[0], fingerprints[1])
            # ... so the tree is exactly the one from the same-content
            # archive sealed without any link or directory member.
            (parent / "plain").mkdir()
            plain = _build_archive(parent / "plain", tree)
            plain_target = parent / "plain-materialized"
            module._materialize_snapshot(plain, plain_target)
            self.assertEqual(fingerprints[0], _tree_sha256(plain_target))
            self.assertEqual(fingerprints[0], expected)

    def test_lf_other_abnormal_member_types_still_rejected(self):
        module = self.lf()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            for label, member_type in sorted(
                {
                    "fifo": tarfile.FIFOTYPE,
                    "character-device": tarfile.CHRTYPE,
                    "block-device": tarfile.BLKTYPE,
                }.items()
            ):
                with self.subTest(face=label):
                    archive = parent / f"abnormal-{label}" / "lf-source.tar.gz"
                    archive.parent.mkdir(parents=True, exist_ok=True)
                    with tarfile.open(archive, "w:gz") as bundle:
                        for name in sorted(_SYNTHETIC_TREE):
                            payload = _SYNTHETIC_TREE[name].encode("utf-8")
                            info = tarfile.TarInfo(f"{_ARCHIVE_TOP}/{name}")
                            info.size = len(payload)
                            info.mtime = 0
                            info.mode = 0o644
                            info.uid = 0
                            info.gid = 0
                            info.uname = ""
                            info.gname = ""
                            bundle.addfile(info, io.BytesIO(payload))
                        oddity = tarfile.TarInfo(f"{_ARCHIVE_TOP}/dev-{label}")
                        oddity.type = member_type
                        oddity.size = 0
                        oddity.mtime = 0
                        oddity.mode = 0o600
                        oddity.uid = 0
                        oddity.gid = 0
                        oddity.uname = ""
                        oddity.gname = ""
                        if member_type in (tarfile.CHRTYPE, tarfile.BLKTYPE):
                            oddity.devmajor = 1
                            oddity.devminor = 3
                        bundle.addfile(oddity)
                    # Arrange guard: the abnormal member is really in the
                    # archive and is really of the abnormal type.
                    with tarfile.open(archive, "r:gz") as bundle:
                        members = {item.name: item for item in bundle}
                    odd_member = members[f"{_ARCHIVE_TOP}/dev-{label}"]
                    self.assertFalse(odd_member.isfile())
                    self.assertFalse(odd_member.isdir())
                    self.assertFalse(odd_member.issym())
                    self.assertFalse(odd_member.islnk())
                    # Option A boundary: only link members are skipped; any
                    # other abnormal type still rejects the whole archive.
                    target = parent / f"materialized-{label}"
                    with self.assertRaises(ValueError) as caught:
                        module._materialize_snapshot(archive, target)
                    self.assertIn(
                        "neither a regular file nor a directory",
                        str(caught.exception),
                    )

    def test_lf_link_skip_preserves_aggregation_and_canonical_faces(self):
        module = self.lf()
        tree = dict(_SYNTHETIC_TREE)
        tree[".ai/CLAUDE.md"] = "# SYNTHETIC inert agent notes\n"
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            authority = _write_tree(parent / "authority", tree)

            def link_archive(directory):
                archive = pathlib.Path(directory) / "lf-source.tar.gz"
                archive.parent.mkdir(parents=True, exist_ok=True)
                with tarfile.open(archive, "w:gz") as bundle:
                    for name in sorted(tree):
                        payload = tree[name].encode("utf-8")
                        info = tarfile.TarInfo(f"{_ARCHIVE_TOP}/{name}")
                        info.size = len(payload)
                        info.mtime = 0
                        info.mode = 0o644
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        bundle.addfile(info, io.BytesIO(payload))
                    for name, link_type, linkname in (
                        ("CLAUDE.md", tarfile.SYMTYPE, ".ai/CLAUDE.md"),
                        (
                            "NOTES.md",
                            tarfile.LNKTYPE,
                            f"{_ARCHIVE_TOP}/README.md",
                        ),
                    ):
                        info = tarfile.TarInfo(f"{_ARCHIVE_TOP}/{name}")
                        info.type = link_type
                        info.linkname = linkname
                        info.mtime = 0
                        info.mode = 0o644
                        info.uid = 0
                        info.gid = 0
                        info.uname = ""
                        info.gname = ""
                        bundle.addfile(info)
                return archive

            faces = {}
            (parent / "without-links").mkdir()
            for label, archive in (
                ("with-links", link_archive(parent / "with-links")),
                ("without-links", _build_archive(parent / "without-links", tree)),
            ):
                output = parent / f"out-{label}"
                output.mkdir()
                faces[label] = (
                    self.run_suite(
                        output,
                        archive,
                        self.binding_for(archive, authority),
                        cold_count=1,
                        warm_count=1,
                    ),
                    output,
                )
            linked, linked_output = faces["with-links"]
            plain, plain_output = faces["without-links"]
            # The skip never disturbs the tree or the canonical projection:
            # both stay pure functions of the no-link tree content, and the
            # dual-source direct scan agrees with the suite's digest.
            expected_digest = self.scanner_wire_digest(
                self.direct_scan(authority), module.LF_CANONICAL_LABEL
            )
            self.assertEqual(
                linked.snapshot_tree_sha256, plain.snapshot_tree_sha256
            )
            self.assertEqual(linked.snapshot_tree_sha256, _tree_sha256(authority))
            self.assertEqual(
                linked.scanner_payload_sha256, plain.scanner_payload_sha256
            )
            self.assertEqual(linked.scanner_payload_sha256, expected_digest)
            # Aggregation: identical samples, status and percentile faces
            # (1 cold + 1 warm honestly stays below the 3/5 floors).
            self.assertEqual(linked.attempt_count, plain.attempt_count)
            self.assertEqual(linked.attempt_count, 2)
            self.assertEqual(linked.model_calls, plain.model_calls)
            self.assertEqual(linked.status, plain.status)
            self.assertEqual(linked.status, "insufficient_sample")
            linked_aggregate = self.result_documents(linked_output)[-1][1]
            plain_aggregate = self.result_documents(plain_output)[-1][1]
            self.assertNotEqual(
                linked_aggregate["run_spec_digest"],
                plain_aggregate["run_spec_digest"],
            )
            for document in (linked_aggregate, plain_aggregate):
                document.pop("run_spec_digest")
            self.assertEqual(linked_aggregate, plain_aggregate)
            # Receipts: every face except the two archive-byte identity
            # faces is identical, and the cold/warm reuse semantics hold.
            linked_receipts = self.receipts_of(linked_output)
            plain_receipts = self.receipts_of(plain_output)
            self.assertEqual(len(linked_receipts), len(plain_receipts))
            for index in range(len(linked_receipts)):
                linked_receipt = dict(linked_receipts[index])
                plain_receipt = dict(plain_receipts[index])
                self.assertEqual(set(linked_receipt), _LF_RECEIPT_KEYS)
                for key in ("run_spec_digest", "archive_sha256"):
                    self.assertNotEqual(
                        linked_receipt.pop(key), plain_receipt.pop(key)
                    )
                self.assertEqual(linked_receipt, plain_receipt)
            self.assertTrue(linked_receipts[0]["scanner_reexecuted"])
            self.assertFalse(linked_receipts[0]["snapshot_reused"])
            self.assertEqual(linked_receipts[0]["materializations"], 1)
            self.assertFalse(linked_receipts[1]["scanner_reexecuted"])
            self.assertTrue(linked_receipts[1]["scanner_result_reused"])
            self.assertTrue(linked_receipts[1]["snapshot_reused"])
            self.assertEqual(linked_receipts[1]["materializations"], 1)
            # The identity faces carrying the archive bytes are the only
            # differing faces; both reports project the same scanner payload
            # digest under the stable external label.
            self.assertNotEqual(linked.run_spec_digest, plain.run_spec_digest)
            self.assertNotEqual(linked.archive_sha256, plain.archive_sha256)
            for label, result in (
                ("with-links", linked),
                ("without-links", plain),
            ):
                with self.subTest(face=label):
                    report = self.read_json(result.report_path)
                    self.assertEqual(
                        [source["kind"] for source in report["sources"]],
                        ["scanner"],
                    )
                    self.assertEqual(
                        report["sources"][0]["payload_sha256"],
                        linked.scanner_payload_sha256,
                    )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
