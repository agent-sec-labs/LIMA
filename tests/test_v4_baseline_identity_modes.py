"""Frozen acceptance tests for IP-0043: K5 per-mode identity injection and
the V5-AC-02 coverage account (AC-4).

Contract under test (frozen by Coordinator Assignment CA-IP-0043-v1.0 of
2026-10-01 R5/R7 and C1 Done 4 AC-4; the tenth-round ruling section 5 is
carried in intent):

- K5 (four modes): ``RealWorldSecurityEvaluator.run`` is exercised in every
  mode of the frozen closed set (deterministic / retrieval / llm /
  llm-retrieval) across identity variants of the same semantic content --
  a renamed dataset/case id, a repathed snapshot cache root, and appended
  non-semantic metadata keys -- against a semantic positive/negative pair
  (the vulnerable revision alerts, the fixed pair stays clean).  The fake
  ``llm_client`` CAPTURES THE ACTUAL INPUTS (``triage(path, paths)`` and
  ``triage_candidate_batch(evidence)``) and answers from the semantic
  content it read, never from a fixed single return; the fake retriever is
  deterministic and content-keyed.  The judgment faces (captured contexts,
  candidate sets, adjudication decisions, matching, stable aggregate
  metrics) stay identical across the identity variants while the identity
  faces (dataset name, ``dataset_sha256``, ``manifest_sha256``) differ
  honestly.  llm and llm-retrieval are asserted separately: llm-retrieval
  responses must carry the consumed ``adjudication`` (anchored at
  real_world_evaluation.py L1293-1318, recomputed independently here through
  the frozen ``adjudicate_evidence``); plain llm responses never do.
- V5-AC-02 (same file, independent TestCases): the ``CANDIDATE_FILE_CAP=12``
  two-sided proof stays (the walk returns every file while the selection
  takes exactly twelve -- a request-construction parameter, not a processing
  limit), unselected objects keep their destination (every finding above the
  cap is retained by the scanner face), the zero-call workload records model
  processing 0 with the zero-call source, the production root-cause producer
  dependency is registered in the coverage account instead of being claimed
  proven, and the account carries the R7 counting-scope declaration
  (scanner-face 447 vs real-world-payload-face 596 are different counting
  faces and are not directly comparable).
- The coverage-account deliverable is
  ``docs/LIMA_IP0043_Coverage_Account_and_Dependency_Correction.md`` (C2);
  the per-mode and account probes below are its frozen acceptance face.

Everything here is offline and deterministic: the snapshot store is injected
with an in-memory zip opener (zero real hosts, zero credentials), the llm
client and retriever are injected fakes, fixture trees materialize into temp
directories, and no test ever touches a network socket or sleeps.

Expected RED before implementation: the four K5 behavior groups and the
frozen cap/retention groups pass by design on the frozen product modules
(they are recorded as guard probes in the RED evidence), while every method
also carries a missing-deliverable group -- the coverage-account document
and the ``lf_baseline``/``lf_observation`` modules -- so all six methods
fail with failures attributable to the missing C2 deliverables, never to an
import accident.  The five old frozen test files stay untouched and green.
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
    adjudicate_evidence,
)
from lima.repository_scanner import RepositoryScanner
from lima.semantic_retrieval import (
    RetrievalRun,
    SecurityInvariant,
    SemanticCandidate,
)
from lima.workspace import RepositoryWorkspace

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_COVERAGE_ACCOUNT_RELATIVE_PATH = (
    "docs/LIMA_IP0043_Coverage_Account_and_Dependency_Correction.md"
)

#: The frozen request-construction parameter (value pinned, never changed).
_CANDIDATE_FILE_CAP = 12

_PROBE_REPOSITORY = "lima-synth/holdout-fixture"
_PROBE_VULNERABLE_COMMIT = "a" * 40
_PROBE_FIXED_COMMIT = "b" * 40
_PROBE_CWE = "CWE-78"
_PROBE_SOURCE = "https://example.invalid/synthetic-holdout-case"

_INERT_HEADER = (
    "# SYNTHETIC INERT BASELINE FIXTURE -- NOT A REAL VULNERABILITY\n"
)

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

#: The K5 identity-variant vocabulary (the frozen four faces).
_K5_VARIANT_LABELS = ("baseline", "rename", "repath", "metadata")


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


def _stable(value):
    """Drop every timing face (latency/duration keys) recursively."""

    if isinstance(value, dict):
        return {
            key: _stable(item)
            for key, item in value.items()
            if "latency" not in key and key != "total_duration_seconds"
        }
    if isinstance(value, list):
        return [_stable(item) for item in value]
    return value


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


def _app_content(root):
    """The semantic content face of one materialized snapshot (label-free)."""
    matches = sorted(pathlib.Path(root).rglob("app.py"))
    if not matches:
        raise AssertionError("app.py is absent from the snapshot")
    return matches[0].read_text(encoding="utf-8")


def _content_digest(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _TriageCaptureClient:
    """Fake llm client (llm mode): captures inputs, answers from content."""

    def __init__(self):
        self.calls = []

    def triage(self, root, paths):
        content = _app_content(root)
        self.calls.append((tuple(paths), _content_digest(content)))
        if "os.system(" in content:
            return {
                "status": "completed",
                "contract_valid": True,
                "is_vulnerable": True,
                "cwe": _PROBE_CWE,
                "path": "app.py",
                "symbol": "run_user_command",
                "confidence": 0.9,
                "latency_ms": 3,
            }
        return {
            "status": "completed",
            "contract_valid": True,
            "is_vulnerable": False,
            "cwe": "NONE",
            "path": "",
            "symbol": "",
            "confidence": 0.9,
            "latency_ms": 3,
        }


class _BatchCaptureClient:
    """Fake llm client (llm-retrieval): captures candidates, answers content."""

    def __init__(self):
        self.calls = []
        self.evidence = []

    def triage_candidate_batch(self, candidates):
        candidates = list(candidates)
        self.evidence.append(list(candidates))
        self.calls.append(
            tuple(
                (
                    candidate.path,
                    candidate.qualname,
                    _content_digest(candidate.code),
                    tuple(
                        sorted(
                            invariant.status for invariant in candidate.invariants
                        )
                    ),
                )
                for candidate in candidates
            )
        )
        verdicts = []
        for candidate in candidates:
            vulnerable = "os.system(" in candidate.code
            verdicts.append(
                {
                    "path": candidate.path,
                    "symbol": candidate.qualname,
                    "is_vulnerable": vulnerable,
                    "cwe": _PROBE_CWE if vulnerable else "NONE",
                    "confidence": 0.9,
                    "root_cause": "synthetic inert pattern" if vulnerable else "",
                }
            )
        return {
            "status": "completed",
            "contract_valid": True,
            "verdicts": verdicts,
            "usage": {},
            "latency_ms": 3,
        }


class _FakeRetriever:
    """Injected deterministic retriever: content-keyed semantic candidates."""

    def __init__(self):
        self.calls = []

    def _candidate(self, root):
        content = _app_content(root)
        vulnerable = "os.system(" in content
        invariant = SecurityInvariant(
            identifier="synthetic-invariant-001",
            category="command",
            status="risk" if vulnerable else "mitigation",
            summary="synthetic inert command-injection invariant",
        )
        return SemanticCandidate(
            path="app.py",
            qualname="run_user_command",
            start_line=5,
            end_line=8,
            category="command",
            score=12,
            signals=("os.system",),
            code=content,
            invariants=(invariant,),
        )

    def retrieve_run(self, path):
        self.calls.append(_content_digest(_app_content(path)))
        return RetrievalRun(
            candidates=(self._candidate(path),),
            inventory_paths=frozenset({"app.py"}),
            diagnostics={},
        )

    def evidence_packet(self, candidates):
        return list(candidates)


class _IdentityModesTestCase(unittest.TestCase):
    """Shared arrange helpers (the K5 groups run on frozen modules only)."""

    def read_coverage_account(self):
        path = _REPO_ROOT / _COVERAGE_ACCOUNT_RELATIVE_PATH
        if not path.is_file():
            self.fail(
                "required coverage-account document is missing: "
                f"{_COVERAGE_ACCOUNT_RELATIVE_PATH}"
            )
        return path.read_text(encoding="utf-8")

    def variants(self):
        """The four K5 identity variants of one semantic holdout case."""
        baseline = _probe_dataset("holdout-fixture-baseline", "case-1")
        return {
            "baseline": baseline,
            "rename": _probe_dataset("holdout-fixture-renamed", "case-1-renamed"),
            "repath": copy.deepcopy(baseline),
            "metadata": _probe_dataset(
                "holdout-fixture-baseline",
                "case-1",
                extra_top={"annotation_note": "non-semantic re-run variant"},
                extra_case={"collector_note": "same semantics"},
            ),
        }

    def run_mode(self, dataset, cache_root, mode, *, client=None, retriever=None):
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
        evaluator = RealWorldSecurityEvaluator(
            SnapshotStore(cache_root, opener=opener),
            llm_client=client,
            retriever=retriever,
        )
        return evaluator.run(dataset, mode=mode), opener

    def verdict_tuple(self, document):
        deterministic = document["cases"][0]["deterministic"]
        return (
            deterministic["vulnerable_hit"],
            deterministic["fixed_clean"],
            deterministic["paired_discrimination"],
            deterministic["verified_evidence"],
        )

    def metrics_of(self, document):
        return _stable(document["metrics"])

    def identity_of(self, document):
        return (
            document["dataset"],
            document["dataset_sha256"],
            document["manifest_sha256"],
        )

    def assert_baseline_judgment_pair(self, document):
        """The semantic positive/negative pair is actually discriminative."""
        vulnerable_hit, fixed_clean, paired, _ = self.verdict_tuple(document)
        self.assertIs(vulnerable_hit, True)  # semantic positive example
        self.assertIs(fixed_clean, True)  # semantic negative example
        self.assertIs(paired, True)

    def assert_honest_identity_faces(self, documents):
        baseline_identity = self.identity_of(documents["baseline"])
        self.assertEqual(baseline_identity[0], "holdout-fixture-baseline")
        self.assertNotEqual(
            self.identity_of(documents["rename"]), baseline_identity
        )
        self.assertNotEqual(
            self.identity_of(documents["metadata"]), baseline_identity
        )
        # The repath variant is byte-identical content at a different cache
        # root: every identity face stays equal (path is not identity).
        self.assertEqual(
            self.identity_of(documents["repath"]), baseline_identity
        )

    def run_all_variants(self, mode, *, client_factory=None, retriever=None):
        """(documents, per-variant clients) for the four identity variants."""
        documents = {}
        clients = {}
        for label in _K5_VARIANT_LABELS:
            dataset = self.variants()[label]
            client = client_factory() if client_factory is not None else None
            with tempfile.TemporaryDirectory(
                prefix=f"lima-ip0043-k5-{label}-"
            ) as cache:
                document, opener = self.run_mode(
                    dataset, cache, mode, client=client, retriever=retriever
                )
                self.assertEqual(len(opener.calls), 2)
            documents[label] = document
            clients[label] = client
        return documents, clients

    def require_coverage_tokens(self, *tokens):
        document = self.read_coverage_account()
        for token in tokens:
            self.assertIn(token, document)


class TestK5DeterministicMode(_IdentityModesTestCase):
    """K5 deterministic: identity variants never change the judgment."""

    def test_deterministic_mode_identity_invariance(self):
        documents, _ = self.run_all_variants("deterministic")
        baseline_verdict = self.verdict_tuple(documents["baseline"])
        baseline_metrics = self.metrics_of(documents["baseline"])
        for label in _K5_VARIANT_LABELS:
            with self.subTest(variant=label):
                self.assert_baseline_judgment_pair(documents[label])
                self.assertEqual(
                    self.verdict_tuple(documents[label]), baseline_verdict
                )
                self.assertEqual(
                    self.metrics_of(documents[label]), baseline_metrics
                )
        self.assert_honest_identity_faces(documents)
        # The coverage account registers this mode's coverage honestly.
        self.require_coverage_tokens("K5", "deterministic", "V5-AC-02")


class TestK5RetrievalMode(_IdentityModesTestCase):
    """K5 retrieval: injected retriever, content-keyed candidate faces."""

    def test_retrieval_mode_identity_invariance_with_injected_retriever(self):
        retriever = _FakeRetriever()
        documents, _ = self.run_all_variants(
            "retrieval", retriever=retriever
        )
        baseline_verdict = self.verdict_tuple(documents["baseline"])
        baseline_metrics = self.metrics_of(documents["baseline"])
        baseline_faces = _stable(documents["baseline"]["cases"][0]["retrieval"])
        for label in _K5_VARIANT_LABELS:
            with self.subTest(variant=label):
                self.assert_baseline_judgment_pair(documents[label])
                self.assertEqual(
                    self.verdict_tuple(documents[label]), baseline_verdict
                )
                self.assertEqual(
                    _stable(documents[label]["cases"][0]["retrieval"]),
                    baseline_faces,
                )
                self.assertEqual(
                    self.metrics_of(documents[label]), baseline_metrics
                )
        # The candidate face is content-keyed: the vulnerable and the fixed
        # revision each yield their own semantic candidate, identically for
        # every identity variant (eight runs, two content digests).
        self.assertEqual(len(retriever.calls), 8)
        self.assertEqual(
            set(retriever.calls),
            {_content_digest(_VULNERABLE_FILES["app.py"]),
             _content_digest(_FIXED_FILES["app.py"])},
        )
        # The retrieval faces actually discriminate (semantic positive and
        # negative), not a vacuous pass.
        self.assertIs(baseline_faces["vulnerable"]["path_hit"], True)
        self.assertIs(baseline_faces["vulnerable"]["symbol_hit"], True)
        self.assertEqual(baseline_faces["vulnerable"]["candidate_count"], 1)
        self.assertIs(baseline_faces["fixed"]["path_hit"], True)
        self.assert_honest_identity_faces(documents)
        self.require_coverage_tokens("K5", "retrieval", "V5-AC-02")


class TestK5LLMMode(_IdentityModesTestCase):
    """K5 llm: the fake client captures the real triage inputs."""

    def test_llm_mode_captures_actual_triage_context(self):
        documents, clients = self.run_all_variants(
            "llm", client_factory=_TriageCaptureClient
        )
        baseline_verdict = self.verdict_tuple(documents["baseline"])
        baseline_metrics = self.metrics_of(documents["baseline"])
        baseline_llm = _stable(documents["baseline"]["cases"][0]["llm"])
        # Plain llm responses never carry an adjudication face (that path is
        # llm-retrieval only; anchored at real_world_evaluation L1293-1318).
        for label in _K5_VARIANT_LABELS:
            with self.subTest(variant=label):
                self.assert_baseline_judgment_pair(documents[label])
                self.assertEqual(
                    self.verdict_tuple(documents[label]), baseline_verdict
                )
                self.assertEqual(
                    _stable(documents[label]["cases"][0]["llm"]), baseline_llm
                )
                self.assertEqual(
                    self.metrics_of(documents[label]), baseline_metrics
                )
                response = documents[label]["cases"][0]["llm"]["vulnerable"]
                self.assertNotIn("adjudication", response)
        # The captured judgment context is identical across the identity
        # variants: the ground-truth paths plus the CONTENT digest of the
        # file the client actually read (never the host path).
        captured = {
            label: tuple(sorted(clients[label].calls))
            for label in _K5_VARIANT_LABELS
        }
        self.assertEqual(
            len({tuple(value) for value in captured.values()}), 1
        )
        face = captured["baseline"]
        self.assertEqual(face, ((("app.py",), _content_digest(
            _VULNERABLE_FILES["app.py"]
        )), (("app.py",), _content_digest(_FIXED_FILES["app.py"]))))
        # The semantic positive/negative pair is answered from content.
        self.assertIs(baseline_llm["vulnerable_correct"], True)
        self.assertIs(baseline_llm["fixed_correct"], True)
        self.assertIs(baseline_llm["paired_correct"], True)
        self.assert_honest_identity_faces(documents)
        self.require_coverage_tokens("K5", "llm", "V5-AC-02")


class TestK5LLMRetrievalMode(_IdentityModesTestCase):
    """K5 llm-retrieval: candidate sets captured, adjudication consumed."""

    def test_llm_retrieval_mode_consumes_adjudication(self):
        retriever = _FakeRetriever()
        documents, clients = self.run_all_variants(
            "llm-retrieval", client_factory=_BatchCaptureClient,
            retriever=retriever,
        )
        baseline_verdict = self.verdict_tuple(documents["baseline"])
        baseline_metrics = self.metrics_of(documents["baseline"])
        # The captured candidate sets are identical across the variants
        # (path/qualname/content digest/invariant statuses, never host data).
        captured = {
            label: tuple(clients[label].calls) for label in _K5_VARIANT_LABELS
        }
        self.assertEqual(len(set(captured.values())), 1)
        candidate_face = captured["baseline"][0]
        self.assertEqual(candidate_face[0][0], "app.py")
        self.assertEqual(candidate_face[0][1], "run_user_command")
        self.assertIn(
            _content_digest(_VULNERABLE_FILES["app.py"]),
            {item[2] for item in candidate_face},
        )
        for label in _K5_VARIANT_LABELS:
            with self.subTest(variant=label):
                self.assert_baseline_judgment_pair(documents[label])
                self.assertEqual(
                    self.verdict_tuple(documents[label]), baseline_verdict
                )
                self.assertEqual(
                    self.metrics_of(documents[label]), baseline_metrics
                )
                llm = documents[label]["cases"][0]["llm"]
                # The adjudication is consumed: dispositions follow the
                # content-keyed pair (alert on the vulnerable revision, clear
                # on the fixed pair) and the hybrid faces derive from them.
                vulnerable = llm["vulnerable"]["adjudication"]["decisions"][0]
                fixed = llm["fixed"]["adjudication"]["decisions"][0]
                self.assertEqual(vulnerable["disposition"], "alert")
                self.assertEqual(
                    vulnerable["reason"], "risk-invariant-and-llm-agree"
                )
                self.assertEqual(fixed["disposition"], "clear")
                self.assertEqual(
                    fixed["reason"], "mitigation-invariant-and-llm-agree"
                )
                self.assertIs(llm["vulnerable_correct"], True)
                self.assertIs(llm["fixed_correct"], True)
                self.assertIs(llm["hybrid"]["paired_safe"], True)
                # Independent recomputation through the frozen adjudicator
                # reproduces the consumed adjudication exactly.
                stripped = {
                    key: copy.deepcopy(value)
                    for key, value in llm["vulnerable"].items()
                    if key != "adjudication"
                }
                self.assertEqual(
                    adjudicate_evidence(
                        stripped, clients[label].evidence[0]
                    ),
                    llm["vulnerable"]["adjudication"],
                )
        self.assert_honest_identity_faces(documents)
        self.require_coverage_tokens("K5", "llm-retrieval", "V5-AC-02")


class TestV5AC02CoverageAccount(_IdentityModesTestCase):
    """V5-AC-02: candidate cap two-sided, retention, dependencies, scope."""

    def _inline_tree(self, root, count):
        expected = set()
        for index in range(count):
            relative = f"synth_probe/module_{index:02d}.py"
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
            expected.add(relative)
        return expected

    def test_candidate_cap_two_sided_and_unselected_destination(self):
        # Frozen two-sided proof (guard, passes by design): the walk returns
        # every file while the selection takes exactly the frozen cap.
        import benchmarks.v4.baseline.real_run as real_run

        count = 15
        with tempfile.TemporaryDirectory(prefix="lima-ip0043-cap-") as temporary:
            root = pathlib.Path(temporary) / "tree"
            root.mkdir()
            for index in range(count):
                (root / f"module_{index:02d}.py").write_text(
                    f"VALUE = {index}\n", encoding="utf-8"
                )
            walked = real_run._walk_python_files(root)
            self.assertEqual(len(walked), count)
            self.assertGreater(count, real_run.CANDIDATE_FILE_CAP)
            selected = real_run._select_candidate_texts(root)
            self.assertEqual(len(selected), real_run.CANDIDATE_FILE_CAP)
            self.assertEqual(real_run.CANDIDATE_FILE_CAP, _CANDIDATE_FILE_CAP)
            # Unselected-destination face (guard, passes by design): every
            # finding above the cap is retained by the scanner face -- the
            # full-scope findings are never truncated to the request cap.
            findings_root = pathlib.Path(temporary) / "findings"
            findings_root.mkdir()
            expected_paths = self._inline_tree(findings_root, count)
            scanner = RepositoryScanner(sast_mode="off")
            findings = scanner.scan(
                RepositoryWorkspace(findings_root)
            ).report.findings
            self.assertEqual(len(findings), count)
            self.assertEqual({finding.path for finding in findings}, expected_paths)
        # The coverage account carries the cap proof, the unselected-object
        # destination, the root-cause producer dependency and the R7
        # counting-scope declaration (447 scanner face vs 596 payload face).
        account = self.read_coverage_account()
        for token in (
            "CANDIDATE_FILE_CAP=12",
            "V5-AC-02",
            "K5",
            "unselected",
            "root-cause",
            "owner",
            "producer",
            "Mining",
            "Repair",
            "447",
            "596",
            "compar",
        ):
            with self.subTest(token=token):
                self.assertIn(token, account)

    def test_zero_call_model_processing_and_dependency_registration(self):
        # The zero-call workload face is backed by the real artifacts: the
        # LF suite records integer-zero model usage with the zero-call
        # source, and the observation companion carries the same face.
        with tempfile.TemporaryDirectory(prefix="lima-ip0043-zerocall-") as temporary:
            parent = pathlib.Path(temporary)
            import benchmarks.v4.baseline.lf_baseline as lf_module

            archive = parent / "lf-source.tar.gz"
            import tarfile

            tree = {
                "README.md": "# SYNTHETIC INERT LF BASELINE FIXTURE\n",
                "src/llamafactory/__init__.py": '"""Synthetic inert package."""\n',
            }
            with tarfile.open(archive, "w:gz") as bundle:
                for relative in sorted(tree):
                    payload = tree[relative].encode("utf-8")
                    info = tarfile.TarInfo(
                        f"LlamaFactory-7fcf5b3b130e5713b52415bb7404c476fada9c8c/"
                        f"{relative}"
                    )
                    info.size = len(payload)
                    info.mtime = 0
                    bundle.addfile(info, io.BytesIO(payload))
            materialized = parent / "authority"
            for relative, payload in tree.items():
                target = materialized / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(payload, encoding="utf-8")

            def _tree_sha256(root):
                digest = hashlib.sha256()
                files = sorted(
                    (item for item in pathlib.Path(root).rglob("*") if item.is_file()),
                    key=lambda item: item.relative_to(root).as_posix(),
                )
                for item in files:
                    relative = item.relative_to(root).as_posix().encode("utf-8")
                    digest.update(str(len(relative)).encode("ascii"))
                    digest.update(b":")
                    digest.update(relative)
                    digest.update(b":")
                    digest.update(str(item.stat().st_size).encode("ascii"))
                    digest.update(b"\0")
                    digest.update(item.read_bytes())
                return digest.hexdigest()

            payload_bytes = archive.read_bytes()
            binding = {
                "schema_version": 1,
                "datasets": [
                    {
                        "name": "lima-external-llamafactory-holdout-v1",
                        "fingerprint": _tree_sha256(materialized),
                        "role": "external-holdout",
                        "entries": [
                            {
                                "repository": "hiyouga/LlamaFactory",
                                "commit_sha": (
                                    "7fcf5b3b130e5713b52415bb7404c476fada9c8c"
                                ),
                            }
                        ],
                        "license": "Apache-2.0 (upstream SPDX)",
                        "source": "sealed-tarball-reuse-2026-09-28",
                        "layout": "single-top-level-directory",
                        "archive_sha256": hashlib.sha256(payload_bytes).hexdigest(),
                        "archive_bytes": len(payload_bytes),
                    }
                ],
            }
            output = parent / "out"
            output.mkdir()
            from benchmarks.v4.baseline.collect import PlatformSources

            result = lf_module.run_lf_local_baseline_suite(
                output_dir=output,
                machine_profile={
                    "profile_id": "lima-lf-local-profile-001",
                    "cpu_arch": "x86_64",
                    "cpu_model": "declared-lf-baseline-cpu",
                    "cores": 8,
                    "ram_gb": 32,
                    "os_family": "windows",
                    "python_version": "3.12.4",
                    "gpu_summary": "none",
                },
                source_root=archive,
                binding=binding,
                cold_count=1,
                warm_count=1,
                seed=0,
                sources=PlatformSources(
                    peak_rss_bytes=lambda: None,
                    io_read_bytes=lambda: None,
                    io_write_bytes=lambda: None,
                ),
            )
            self.assertEqual(result.model_calls, 0)
            for path in sorted(output.glob("*-run-*.json")):
                document = json.loads(path.read_bytes().decode("utf-8"))
                for sample in document["samples"]:
                    self.assertEqual(sample["prompt_tokens"], 0)
                    self.assertEqual(sample["completion_tokens"], 0)
                    self.assertEqual(sample["cost_micro_usd"], 0)
            import benchmarks.v4.baseline.lf_observation as observation_module

            companion_path = observation_module.build_lf_observation(
                output_dir=output
            )
            companion = json.loads(
                pathlib.Path(companion_path).read_bytes().decode("utf-8")
            )
            self.assertEqual(
                companion["model_usage"]["source"],
                "zero-model-calls-by-construction",
            )
            self.assertEqual(companion["model_usage"]["prompt_tokens"], 0)
        # The production root-cause producer dependency is registered as a
        # dependency (owner/inputs/producer), never claimed proven, and the
        # "A1 DR pending" catch-all is not used to absorb the gap.
        account = self.read_coverage_account()
        for token in ("root-cause", "owner", "producer", "V5-AC-02"):
            self.assertIn(token, account)
        self.assertNotIn("A1 DR 待定", account)
        # PC1 self-scan (passes by design): this file stays offline and
        # secretless.
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
