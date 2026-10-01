"""Frozen acceptance tests for IP-0043: LF resource observation companion (AC-2).

Contract under test (frozen by Coordinator Assignment CA-IP-0043-v1.0 of
2026-10-01 R3 and C1 Done 4 AC-2; the tenth-round ruling section 3 "reported
observation source authorization" is carried in intent):

- The Implementation deliverable is ``benchmarks/v4/baseline/lf_observation.py``
  (the companion scheme; ``report.py`` stays at zero hunks).  It produces the
  independently versioned document ``lf-local-observation-v1.json`` in the
  same directory as the run artifacts, carrying the five mandatory back
  references -- ``run_spec_digest``, ``aggregate_sha256``, the scanner wire
  digest (``report.py`` L1340-1344 rule), ``snapshot_tree_sha256`` and
  ``archive_sha256`` -- plus per-attempt resource faces that point back to
  each result file's original bytes (SHA-256).
- Measurement semantics are mandatory fields (ruling: no fake values, no
  guesses, no zero substitutes): ``memory_rss_peak_bytes`` is the
  process-lifetime cumulative peak (ru_maxrss scope, not a per-attempt
  delta), ``io_read_bytes``/``io_write_bytes`` are process-lifetime
  cumulative counters at read time, ``wall_time_ms``/``cpu_time_ms`` are
  per-attempt deltas, and platforms without the sources (Windows: no
  ``resource`` module, no ``/proc/self/io``) report null with the platform
  reason -- never a fabricated value.
- The scoped zero-call model face is explicit: prompt/completion/cost are
  integer zero with the source ``zero-model-calls-by-construction`` and the
  note that local compute and human time are not therefore free.
- Typed fail-closed negatives (own error family): a missing
  version/profile, a source mismatch (artifacts swapped from another run),
  any back-reference digest mismatch (tampering) and missing run artifacts
  each terminate with their own code; no fallback guess algorithm.
- The old v2 default is unchanged: ``build_baseline_report`` keeps the
  three-key null resources face for scanner payloads (report.py L1407-1433),
  with or without a companion document present in the directory.

Everything here is offline and deterministic: the run artifacts come from the
synthetic LF suite (temp-local inert tarball), platform sources are injected
fakes with honest Windows nulls, and no test ever touches a network socket,
reads the environment, or sleeps.

Expected RED before implementation (product modules absent): six methods fail
on the missing deliverables -- the module-absence anchors are
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.lf_observation'``
and ``... lf_baseline`` (lazy per-test imports); the frozen-face groups inside
method five (the old v2 default negative on ``build_baseline_report``) pass by
design and are recorded in the RED evidence.  The five old frozen test files
stay untouched and green.
"""

import ast
import hashlib
import io
import json
import pathlib
import re
import shutil
import tarfile
import tempfile
import unittest

from benchmarks.v4.baseline.collect import PlatformSources

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_OBSERVATION_RELATIVE_PATH = "benchmarks/v4/baseline/lf_observation.py"
_LF_BASELINE_RELATIVE_PATH = "benchmarks/v4/baseline/lf_baseline.py"

#: The frozen external identity pins (mirrored from the LF baseline packet).
_LF_COMMIT_SHA = "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
_LF_REPOSITORY_IDENTITY = "hiyouga/LlamaFactory"
_LF_DATASET_NAME = "lima-external-llamafactory-holdout-v1"
_LF_DATASET_ROLE = "external-holdout"
_ARCHIVE_TOP = f"LlamaFactory-{_LF_COMMIT_SHA}"

#: The companion document name and profile (independently versioned family).
_OBSERVATION_DOCUMENT_NAME = "lf-local-observation-v1.json"
_OBSERVATION_PROFILE = "lf-local-observation-v1"

#: The frozen companion top-level key set (closed).
_OBSERVATION_KEYS = frozenset(
    {
        "schema_version",
        "profile",
        "run_spec_digest",
        "aggregate_sha256",
        "scanner_payload_sha256",
        "snapshot_tree_sha256",
        "archive_sha256",
        "attempts",
        "measurement_semantics",
        "model_usage",
    }
)

#: The frozen per-attempt observation key set (closed).
_OBSERVATION_ATTEMPT_KEYS = frozenset(
    {
        "attempt_index",
        "mode",
        "result_sha256",
        "wall_time_ms",
        "cpu_time_ms",
        "memory_rss_peak_bytes",
        "io_read_bytes",
        "io_write_bytes",
    }
)

#: The mandatory measurement-semantics notes (exact frozen strings).
_MEASUREMENT_SEMANTICS = {
    "memory_rss_peak_bytes": (
        "process-lifetime cumulative peak (ru_maxrss scope); not a per-attempt delta"
    ),
    "io_read_bytes": (
        "process-lifetime cumulative counter at read time; not a per-attempt delta"
    ),
    "io_write_bytes": (
        "process-lifetime cumulative counter at read time; not a per-attempt delta"
    ),
    "wall_time_ms": "per-attempt delta between two monotonic reads",
    "cpu_time_ms": "per-attempt delta between two monotonic reads",
    "platform": (
        "windows: no resource module and no /proc/self/io; unavailable platform "
        "metrics are null, never zero-filled or guessed"
    ),
}

#: The scoped zero-call model face (exact frozen strings and zeros).
_MODEL_USAGE = {
    "prompt_tokens": 0,
    "completion_tokens": 0,
    "cost_micro_usd": 0,
    "source": "zero-model-calls-by-construction",
    "cost_note": "zero model usage does not make local compute or human time free",
}

#: The frozen typed error family of the companion module.
_OBSERVATION_ERROR_CODES = frozenset(
    {
        "OBSERVATION_VERSION_MISSING",
        "OBSERVATION_SOURCE_MISMATCH",
        "OBSERVATION_DIGEST_MISMATCH",
        "OBSERVATION_ARTIFACT_INVALID",
    }
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

_INERT_HEADER = (
    "# SYNTHETIC INERT LF BASELINE FIXTURE -- NOT A REAL VULNERABILITY\n"
)

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
    base = pathlib.Path(root)
    for relative, payload in tree.items():
        target = base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(payload, encoding="utf-8")
    return base


def _tree_sha256(root):
    """Independent transcription of the frozen snapshot tree fingerprint rule."""
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
        digest.update(str(len(relative)).encode("ascii"))
        digest.update(b":")
        digest.update(relative)
        digest.update(b":")
        digest.update(str(item.stat().st_size).encode("ascii"))
        digest.update(b"\0")
        with item.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    return digest.hexdigest()


def _build_archive(directory, tree):
    archive = pathlib.Path(directory) / "lf-source.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        for relative in sorted(tree):
            payload = tree[relative].encode("utf-8")
            info = tarfile.TarInfo(f"{_ARCHIVE_TOP}/{relative}")
            info.size = len(payload)
            info.mtime = 0
            info.mode = 0o644
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            bundle.addfile(info, io.BytesIO(payload))
    return archive


class _LFObservationTestCase(unittest.TestCase):
    """Shared arrange helpers (all new-module imports are lazy per test)."""

    def observation(self):
        import benchmarks.v4.baseline.lf_observation as module

        return module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def run_inputs(self, parent):
        """(archive, binding, tree digest) for the synthetic sealed snapshot."""
        tree = dict(_SYNTHETIC_TREE)
        materialized = _write_tree(pathlib.Path(parent) / "authority", tree)
        archive = _build_archive(pathlib.Path(parent) / "authority", tree)
        payload = archive.read_bytes()
        dataset = {
            "name": _LF_DATASET_NAME,
            "fingerprint": _tree_sha256(materialized),
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
            "archive_sha256": hashlib.sha256(payload).hexdigest(),
            "archive_bytes": len(payload),
        }
        return archive, {"schema_version": 1, "datasets": [dataset]}

    def fake_sources(self):
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

    def run_lf_suite(self, parent, output_name, **overrides):
        import benchmarks.v4.baseline.lf_baseline as lf_module

        archive, binding = self.run_inputs(parent)
        output = pathlib.Path(parent) / output_name
        output.mkdir()
        options = {
            "output_dir": output,
            "machine_profile": dict(_MACHINE_PROFILE),
            "source_root": archive,
            "binding": binding,
            "sources": self.fake_sources(),
        }
        options.update(overrides)
        return lf_module.run_lf_local_baseline_suite(**options), archive

    def build_observation(self, output_dir):
        module = self.observation()
        path = module.build_lf_observation(output_dir=output_dir)
        document = json.loads(pathlib.Path(path).read_bytes().decode("utf-8"))
        return module, pathlib.Path(path), document

    def read_json(self, path):
        return json.loads(pathlib.Path(path).read_bytes().decode("utf-8"))

    def result_documents(self, output_dir):
        directory = pathlib.Path(output_dir)
        paths = sorted(
            directory.glob("*-run-*.json"),
            key=lambda path: int(path.stem.rsplit("-", 1)[1]),
        )
        self.assertTrue(paths, "no lf result files were written")
        return [(path, self.read_json(path)) for path in paths]

    def rewrite_json(self, path, document):
        from lima.contracts.codec import canonical_encode

        pathlib.Path(path).write_bytes(canonical_encode(document))

    def summary_fixture(self):
        """One frozen-recipe summary over eight synthetic samples."""
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
            {"schema_version": 1, "run_spec_digest": "a" * 64, "samples": samples}
        )
        return BaselineRunSummary(
            attempts=(aggregate,),
            result_paths=(),
            aggregate=aggregate,
            aggregate_path=pathlib.Path("unused"),
            aggregate_sha256=aggregate.content_digest(),
            status=aggregate.status,
        )

    def scanner_payload_fixture(self):
        """One frozen-recipe scanner payload (offline, synthetic, inert)."""
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
            verification_state="syntax-verified",
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


class TestLFObservationCompanion(_LFObservationTestCase):
    """AC-2: the versioned companion with its five back references."""

    def test_observation_companion_version_and_five_back_references(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            result, archive = self.run_lf_suite(parent, "out")
            module, path, document = self.build_observation(parent / "out")
            self.assertEqual(path.name, _OBSERVATION_DOCUMENT_NAME)
            self.assertEqual(path.parent, pathlib.Path(result.aggregate_path).parent)
            self.assertEqual(set(document), _OBSERVATION_KEYS)
            self.assertEqual(document["schema_version"], 1)
            self.assertEqual(document["profile"], _OBSERVATION_PROFILE)
            # The five mandatory back references, recomputed independently
            # from the run artifacts and the synthetic sealed archive.
            aggregate_bytes = pathlib.Path(result.aggregate_path).read_bytes()
            self.assertEqual(document["run_spec_digest"], result.run_spec_digest)
            self.assertTrue(_HEX64_SHAPE.match(document["run_spec_digest"]))
            self.assertEqual(
                document["aggregate_sha256"],
                hashlib.sha256(aggregate_bytes).hexdigest(),
            )
            self.assertEqual(
                document["scanner_payload_sha256"], result.scanner_payload_sha256
            )
            self.assertEqual(
                document["snapshot_tree_sha256"],
                _tree_sha256(parent / "authority"),
            )
            self.assertEqual(
                document["archive_sha256"],
                hashlib.sha256(archive.read_bytes()).hexdigest(),
            )
            report = self.read_json(result.report_path)
            self.assertEqual(
                document["scanner_payload_sha256"],
                report["sources"][0]["payload_sha256"],
            )
            for _, run_document in self.result_documents(parent / "out"):
                self.assertEqual(
                    run_document["run_spec_digest"], document["run_spec_digest"]
                )
            # Per-attempt faces: one entry per attempt, each pointing back to
            # its result file's original bytes and carrying the sample values.
            attempts = document["attempts"]
            self.assertEqual(len(attempts), result.attempt_count)
            per_attempt = self.result_documents(parent / "out")[:-1]
            self.assertEqual(len(per_attempt), len(attempts))
            for (path_obj, run_document), entry in zip(
                per_attempt, attempts, strict=True
            ):
                self.assertEqual(set(entry), _OBSERVATION_ATTEMPT_KEYS)
                sample = run_document["samples"][0]
                self.assertEqual(entry["attempt_index"], sample["attempt_index"])
                self.assertEqual(entry["mode"], sample["mode"])
                self.assertEqual(
                    entry["result_sha256"],
                    hashlib.sha256(path_obj.read_bytes()).hexdigest(),
                )
                self.assertEqual(entry["wall_time_ms"], sample["wall_time_ms"])
                self.assertEqual(entry["cpu_time_ms"], sample["cpu_time_ms"])
                self.assertEqual(
                    entry["memory_rss_peak_bytes"],
                    sample["memory_rss_peak_bytes"],
                )
                self.assertEqual(entry["io_read_bytes"], sample["io_read_bytes"])
                self.assertEqual(entry["io_write_bytes"], sample["io_write_bytes"])
            # The verified companion verifies clean.
            self.assertEqual(
                module.verify_lf_observation(path)["run_spec_digest"],
                result.run_spec_digest,
            )

    def test_observation_windows_null_with_reason_and_cumulative_scope_notes(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            result, _ = self.run_lf_suite(parent, "out")
            _, _, document = self.build_observation(parent / "out")
            # The mandatory scope notes are the exact frozen strings.
            self.assertEqual(document["measurement_semantics"], _MEASUREMENT_SEMANTICS)
            # The honest Windows faces: unavailable platform metrics are null
            # (never zero-filled), wall/cpu remain per-attempt int deltas.
            for entry in document["attempts"]:
                with self.subTest(attempt=entry["attempt_index"]):
                    self.assertIsNone(entry["memory_rss_peak_bytes"])
                    self.assertIsNone(entry["io_read_bytes"])
                    self.assertIsNone(entry["io_write_bytes"])
                    self.assertIs(type(entry["wall_time_ms"]), int)
                    self.assertIs(type(entry["cpu_time_ms"]), int)
                    self.assertGreaterEqual(entry["wall_time_ms"], 0)
                    self.assertGreaterEqual(entry["cpu_time_ms"], 0)

    def test_observation_zero_model_usage_faces_and_source(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            result, _ = self.run_lf_suite(parent, "out")
            _, _, document = self.build_observation(parent / "out")
            usage = document["model_usage"]
            self.assertEqual(usage, _MODEL_USAGE)
            self.assertIs(type(usage["prompt_tokens"]), int)
            self.assertIs(type(usage["completion_tokens"]), int)
            self.assertIs(type(usage["cost_micro_usd"]), int)
            # Cross-check against the run samples: the scoped zero-call face
            # is the same zero the result contract records.
            for _, run_document in self.result_documents(parent / "out"):
                for sample in run_document["samples"]:
                    self.assertEqual(sample["prompt_tokens"], usage["prompt_tokens"])
                    self.assertEqual(
                        sample["completion_tokens"], usage["completion_tokens"]
                    )
                    self.assertEqual(sample["cost_micro_usd"], usage["cost_micro_usd"])
            self.assertEqual(result.model_calls, 0)

    def test_observation_fail_closed_version_source_and_tamper(self):
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            result, _ = self.run_lf_suite(parent, "out", cold_count=1, warm_count=1)
            other, _ = self.run_lf_suite(parent, "other", seed=7)
            module, path, document = self.build_observation(parent / "out")
            self.assertNotEqual(
                result.run_spec_digest, other.run_spec_digest
            )  # arrange sanity: two distinct runs
            faces = {}

            # Face 1: the version (schema/profile) is missing.
            versionless = dict(document)
            del versionless["schema_version"]
            faces["OBSERVATION_VERSION_MISSING"] = ("out", versionless, None, None)

            # Face 2: the artifacts belong to another run (source mismatch).
            faces["OBSERVATION_SOURCE_MISMATCH"] = (
                "out",
                document,
                pathlib.Path(result.aggregate_path).name,
                pathlib.Path(other.aggregate_path).read_bytes(),
            )

            # Face 3: a back-reference digest tampered in the companion.
            tampered = dict(document)
            tampered["aggregate_sha256"] = "e" * 64
            faces["OBSERVATION_DIGEST_MISMATCH"] = ("out", tampered, None, None)
            tampered_wire = dict(document)
            tampered_wire["scanner_payload_sha256"] = "d" * 64
            faces["OBSERVATION_DIGEST_MISMATCH-wire"] = (
                "out",
                tampered_wire,
                None,
                None,
            )

            # Face 4: the run artifacts are gone entirely.
            faces["OBSERVATION_ARTIFACT_INVALID"] = ("empty", document, None, None)

            for label, (source_dir, face_document, swap_name, swap_bytes) in sorted(
                faces.items()
            ):
                with self.subTest(face=label):
                    face_dir = parent / f"face-{label}"
                    if source_dir == "empty":
                        face_dir.mkdir()
                    else:
                        shutil.copytree(parent / source_dir, face_dir)
                    if swap_name is not None:
                        (face_dir / swap_name).write_bytes(swap_bytes)
                    face_path = face_dir / _OBSERVATION_DOCUMENT_NAME
                    self.rewrite_json(face_path, face_document)
                    expected_code = label.replace("-wire", "")
                    with self.assertRaises(module.LFObservationError) as caught:
                        module.verify_lf_observation(face_path)
                    self.assertEqual(str(caught.exception.code), expected_code)
                    self.assertIn(
                        str(caught.exception.code), _OBSERVATION_ERROR_CODES
                    )
            # The frozen error family is closed and independent; each member
            # renders its bare frozen wire value through ``__str__``
            # (the B1SourceErrorCode precedent).
            self.assertEqual(
                {str(code) for code in module.LFObservationErrorCode},
                _OBSERVATION_ERROR_CODES,
            )
            self.assertTrue(
                issubclass(module.LFObservationError, ValueError)
            )

    def test_observation_old_v2_default_resources_unchanged_negative(self):
        from benchmarks.v4.baseline.report import build_baseline_report

        summary = self.summary_fixture()
        payload = self.scanner_payload_fixture()
        # Frozen-face group (passes by design): the old v2 default keeps the
        # three-key null resources face for a scanner payload.
        baseline_report = build_baseline_report(summary, payload).to_canonical_value()
        self.assertEqual(
            baseline_report["resources"],
            {"prompt_tokens": None, "completion_tokens": None, "cost_micro_usd": None},
        )
        # New-deliverable group (RED until C2): a companion document present
        # in the run directory never leaks into that frozen v2 face.
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            self.run_lf_suite(parent, "out", cold_count=1, warm_count=1)
            _, companion_path, _ = self.build_observation(parent / "out")
            self.assertTrue(companion_path.is_file())
            after_report = build_baseline_report(
                summary, payload
            ).to_canonical_value()
            self.assertEqual(
                after_report["resources"],
                {"prompt_tokens": None, "completion_tokens": None, "cost_micro_usd": None},
            )
            self.assertEqual(after_report["resources"], baseline_report["resources"])

    def test_observation_sources_offline_and_secretless(self):
        # Product group (RED at the freeze on the absent module): both new
        # modules stay offline and secretless (AC-5 discipline).
        for relative in (_OBSERVATION_RELATIVE_PATH, _LF_BASELINE_RELATIVE_PATH):
            with self.subTest(source=relative):
                source = self.product_source(relative)
                self.assertEqual(
                    _import_roots(source) & _forbidden_network_roots(), set()
                )
                self.assertNotIn("environ", source)
                self.assertNotIn("getenv", source)
                self.assertNotIn("subprocess", source)
                self.assertIsNone(_SECRET_KEY_SHAPE.search(source))
        # PC1 self-scan (passes by design): this file stays offline and
        # secretless too.
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
