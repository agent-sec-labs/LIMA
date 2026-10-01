"""Frozen acceptance tests for IP-0041: B1 real entry (Issue #251), v11.

Contract under test (frozen by Coordinator Assignment CA-IP-0041-v1.0 of
2026-10-01 and docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md
sections 7-11; the eighth-round ruling of 2026-10-01 is the upstream
authorization):

- The Implementation deliverables are ``benchmarks/v4/baseline/b1_real.py``
  (the public entry ``run_b1_real_baseline_suite`` and the read-back entry
  ``verify_b1_real_evidence``, exactly five ``__all__`` symbols) plus the
  five Packet-named additive hooks E0-E4 in ``real_run.py`` (the twelfth
  catalog entry ``real-pilot/signal-storm`` with its sixteen-field closed
  set, the descriptor-driven ``b1_source_binding`` tail default, the
  evaluator binding attributes, the scanner-execution hook inside the cold
  attempt-0 guarded window, and the gated scanner report payload).
- The B1 real entry drives the frozen order 1-9 real chain through
  ``run_real_baseline_suite(artifact_key="real-pilot/signal-storm")`` with
  the one-time pilot shape {1 cold + 4 warm, max_attempts 5}: approval /
  budget-gate / identity / request-body / transport / canary / first-failure
  / deadline / settlement / cancellation primitives are all reused, never
  re-implemented, and the whole suite honestly records the actual POST
  count (``real_post_count`` -- never a model_calls=0 stand-in).
- The B1 source binding: the scanner runs exactly once inside the cold
  attempt-0 reserve/deadline window over the same materialized snapshot the
  request body was built from, the four warm attempts reuse the snapshot /
  scan result / request body, and the independent companion artifacts
  (``b1-real-attempts/b1-real-attempt-{i:02d}.json`` with the closed
  twenty-three-key receipt set plus ``b1-real-manifest.json``) bind approval
  / request-body / RunResult / attempt-document / ledger / suite faces by
  canonical SHA-256 digests, cross-verified fail-closed with the typed
  ``B1RealError`` family of exactly five codes.
- The seven-dimension budget (per_run/batch: 100000/198000 micro-USD,
  1/5 calls, 150000/500000 prompt, 8000/40000 completion, 1200000/6000000
  wall, 250M/250M download, 500M/500M storage) is loaded from the twin
  approval artifact -- the entry itself carries no numeric budget
  constants; 198000 = 5 x 39600 is the frozen internal worst-case formula.
- The authorization sync points S1-S7 (Packet 7.7, exactly seven) admit the
  twelfth key into the three frozen old test files' catalog mirrors; every
  other old assertion is untouched.

Everything here is offline and deterministic: the model layer is only ever
an injected fake transport (zero real POST, zero network socket), fixtures
materialize locally (the synthetic fixture_key branch keeps signal-storm
off the download path), and no test reads the environment or sleeps.

Expected RED before implementation (Packet 8.3): nineteen methods fail on
the module-absence anchor ``ModuleNotFoundError: No module named
'benchmarks.v4.baseline.b1_real'`` (lazy per-test import as the first
statement) and the two descriptor methods fail on the eleven-key catalog
(the twelfth key absent -- behavior-missing, not arrange failure); the
twelve-key mirror group inside M22 fails the same way after its by-design
group passes; four methods pass by design (M20/M21/M23 old-path anchors,
M24 the packet-document probe) and M25's self-scan group passes while its
product-source group fails on the absent file (split attribution).
"""

import ast
import copy
import hashlib
import inspect
import json
import pathlib
import re
import tempfile
import unittest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_B1_REAL_RELATIVE_PATH = "benchmarks/v4/baseline/b1_real.py"
_REAL_RUN_RELATIVE_PATH = "benchmarks/v4/baseline/real_run.py"
_PACKET_RELATIVE_PATH = "docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md"
_DOCKERFILE_RELATIVE_PATH = "Dockerfile"
_PACKET_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0041_B1_Real_"
    "Entry.md ./docs/"
)
_APPROVAL_RELATIVE_PATH = "docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md"
_FAKE_KEY = "test-key-do-not-use"

# ---------------------------------------------------------------------------
# The twelfth-key descriptor pins (Packet 7.3; literal mirrors, PC3 -- the
# catalog assertions below compare the product values against these
# independently transcribed pins and the frozen derivation formulas).
# ---------------------------------------------------------------------------
_B1_REAL_KEY = "real-pilot/signal-storm"
_B1_REAL_FIXTURE_KEY = "archetype/signal-storm"
_B1_REAL_APPROVAL_TYPE = "PR3D-B1-REAL-ENTRY-ONE-SHOT"
_B1_REAL_RUN_NAME = "pr3d-b1-real-signal-storm-2026-10-01"
_B1_REAL_DATE_PIN = "2026-10-01"
_B1_REAL_RETRIEVAL_DATE_PIN = "2026-10-01"
_B1_REAL_WORKLOAD = "b1-real-signal-storm-v1"
_B1_REAL_SCANNER_CONFIG_REF = "b1-source-offline-scan-v1"
_B1_REAL_SOURCE_CONTRACT = "b1-real-source-binding"
_B1_REAL_SOURCE_CONTRACT_VERSION = 1
_B1_REAL_COLD = 1
_B1_REAL_WARM = 4
_B1_REAL_ATTEMPTS = _B1_REAL_COLD + _B1_REAL_WARM

# The frozen seven-field descriptor set (the ten old keys' closed face) and
# the IP-0039 four-field addition (the eleventh key's closed face).
_DESCRIPTOR_FIELDS = frozenset(
    {
        "repository",
        "requested_name",
        "commit_sha",
        "tarball_url",
        "tarball_filename",
        "approval_type",
        "run_name",
    }
)
_REAL_PILOT_KEY = "real-pilot/large-repo"
_REAL_PILOT_FIXTURE_KEY = "archetype/large-repo"
_REAL_PILOT_EXTRA_FIELDS = frozenset(
    {"fixture_key", "date_pin", "retrieval_date_pin", "stop_on_first_failure"}
)
# Packet 7.3: the five B1-real binding fields -- the twelfth key's closed
# set is the seven base fields plus the four R2 fields plus these five.
_B1_REAL_EXTRA_FIELDS = frozenset(
    {
        "workload",
        "scanner_config_ref",
        "scanner_config_sha256",
        "source_contract",
        "source_contract_version",
    }
)
_TWELFTH_FIELD_SET = (
    _DESCRIPTOR_FIELDS | _REAL_PILOT_EXTRA_FIELDS | _B1_REAL_EXTRA_FIELDS
)

# The twelve-key catalog mirror (the new file's independent mirror of the
# S1/S7 authorization-sync constants; the closed set after the twelfth key).
_NINE_SYNTHETIC_KEYS = (
    "archetype/application",
    "archetype/library",
    "archetype/cli",
    "archetype/docs-content",
    "archetype/test-heavy",
    "archetype/monorepo",
    "archetype/large-repo",
    "archetype/malicious-layout",
    "archetype/dependency-blocked",
)
_ARTIFACT_FAMILY_KEYS = frozenset(
    {
        *_NINE_SYNTHETIC_KEYS,
        "external/llamafactory-replay",
        _REAL_PILOT_KEY,
        _B1_REAL_KEY,
    }
)

# The frozen real_run static faces (mirrors of the frozen module values,
# asserted as anchors in M21/M22).
_REAL_RUN_ALL = (
    "APPROVAL_COMPLETION_PRICE_MICRO_USD_PER_MILLION",
    "APPROVAL_PROMPT_PRICE_MICRO_USD_PER_MILLION",
    "RealRunError",
    "RealRunErrorCode",
    "RealSuiteResult",
    "run_real_baseline_suite",
)
_ENTRY_PARAM_ORDER = (
    "approval_path",
    "api_key",
    "output_root",
    "spec_mapping",
    "transport",
    "timeout_seconds",
    "manifest_path",
    "sources",
    "artifact_key",
)
_ENTRY_KEYWORD_ONLY = {
    "output_root",
    "spec_mapping",
    "transport",
    "timeout_seconds",
    "manifest_path",
    "sources",
    "artifact_key",
}
_FROZEN_ERROR_CODES = frozenset(
    {
        "APPROVAL_ARTIFACT_INVALID",
        "REAL_RUN_OUTPUT_NOT_EMPTY",
        "REAL_RUN_DOWNLOAD_EXCEEDED",
        "REAL_RUN_ARCHIVE_UNSAFE",
        "REAL_RUN_REQUEST_TOO_LARGE",
        "REAL_RUN_TRANSPORT_FAILED",
        "REAL_RUN_USAGE_MISSING",
        "REAL_RUN_RESPONSE_INVALID",
        "REAL_RUN_IDENTITY_CHANGED",
        "REAL_RUN_CANARY_FAILED",
        "REAL_RUN_BATCH_STOPPED",
    }
)
_B1_SOURCE_ALL = (
    "B1SourceError",
    "B1SourceErrorCode",
    "B1SuiteResult",
    "B1_WORKLOAD",
    "CANDIDATE_FILE_CAP",
    "run_b1_source_baseline_suite",
    "verify_b1_evidence",
)
_B1_SOURCE_PARAM_ORDER = (
    "output_dir",
    "machine_profile",
    "fixture_key",
    "seed",
    "cold_count",
    "warm_count",
    "workload",
    "transport",
    "manifest_path",
    "sources",
)
_CANDIDATE_FILE_CAP = 12
_REQUEST_MODEL = "deepseek-v4-flash"
_UNKNOWN_MODEL_FORM = "deepseek-ghost-form"
_PRICES = (300_000, 1_200_000)

# The seven-dimension authorization table (Packet 7.6.1 / ruling section 3,
# verbatim): the sole numeric source is the twin approval artifact, and the
# entry source must carry none of these literals (M3).
_B1_REAL_PER_RUN = {
    "cost_micro_usd": 100_000,
    "calls": 1,
    "prompt_tokens": 150_000,
    "completion_tokens": 8_000,
    "wall_ms": 1_200_000,
    "download_bytes": 250_000_000,
    "storage_bytes": 500_000_000,
}
_B1_REAL_BATCH = {
    "cost_micro_usd": 198_000,
    "calls": 5,
    "prompt_tokens": 500_000,
    "completion_tokens": 40_000,
    "wall_ms": 6_000_000,
    "download_bytes": 250_000_000,
    "storage_bytes": 500_000_000,
}
_FORBIDDEN_BUDGET_LITERALS = (
    "100000",
    "100_000",
    "198000",
    "198_000",
    "150000",
    "150_000",
    "500000",
    "500_000",
    "8000",
    "8_000",
    "1200000",
    "1_200_000",
    "6000000",
    "6_000_000",
    "250000000",
    "250_000_000",
    "500000000",
    "500_000_000",
)

# The B1-real receipt key set (Packet 7.5.3: the sixteen b1_source keys with
# their semantics preserved plus the seven real-binding keys).
_B1_REAL_RECEIPT_KEYS = frozenset(
    {
        # -- the b1_source sixteen (semantics preserved) --
        "snapshot_tree_sha256",
        "fixture_key",
        "fixture_manifest_sha256",
        "analyzer_name",
        "analyzer_fingerprint",
        "scanner_config_sha256",
        "seed",
        "workload",
        "run_spec_digest",
        "attempt_index",
        "mode",
        "scanner_payload_sha256",
        "scanner_reexecuted",
        "scanner_result_reused",
        "snapshot_reused",
        "request_body_rebuilt",
        # -- the seven real-binding additions (R3.3) --
        "approval_sha256",
        "request_body_sha256",
        "run_result_name",
        "run_result_sha256",
        "attempt_document_name",
        "suite_run_name",
        "ledger_sha256",
    }
)
_B1_REAL_MANIFEST_KEYS = frozenset(
    {
        "schema_version",
        "workload",
        "run_name",
        "artifact_key",
        "approval_sha256",
        "run_spec_digest",
        "attempt_count",
        "cold_count",
        "warm_count",
        "fixture_key",
        "fixture_manifest_sha256",
        "snapshot_tree_sha256",
        "analyzer_name",
        "analyzer_fingerprint",
        "scanner_config",
        "scanner_config_sha256",
        "seed",
        "source_contract",
        "source_contract_version",
        "scanner_payload_sha256",
        "scanner_executions",
        "scanner_phase",
        "source_receipts",
        "source_receipts_digest",
        "failures",
        "real_post_count",
        "ledger_calls",
        "companion_bytes_total",
        "transport_face",
        "declarations",
    }
)
_SCANNER_PHASE_FACE = {
    "executions": 1,
    "reuses": 4,
    "window": "attempt-0-guarded",
    "wall_registration": "inside-attempt0-wall-reservation",
}
_B1_REAL_DECLARATIONS = frozenset(
    {
        "b1-real-suite-actual-post-count-recorded",
        "signal-storm-local-materialization-zero-download",
        "one-time-pilot-shape-one-cold-four-warm",
        "not-nine-category-sample",
        "scanner-component-zero-model-calls",
    }
)

# The scanner offline configuration mirrors (b1_source Packet 7.5 constants,
# transcribed for the independent config-document digest recomputation).
_SAST_MODE = "off"
_CXX_MEMORY_MODE = "off"
_CXX_AGENT_MODE = "off"
_DATAFLOW_ENABLED = True
_WORKSPACE_MAX_FILES = 5000
_WORKSPACE_MAX_FILE_BYTES = 512 * 1024
_WORKSPACE_MAX_TOTAL_BYTES = 20 * 1024 * 1024

_COVERAGE_AFFECTING_SKIPS = frozenset(
    {
        "symlink",
        "unreadable",
        "file-size-limit",
        "file-limit",
        "total-size-limit",
        "binary",
        "non-utf8",
    }
)
_DETERMINISTIC_STATES = frozenset({"corroborated", "dataflow-verified", "confirmed"})
_INCONCLUSIVE_STATES = frozenset({"candidate", "syntax-verified"})

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
_SECRET_KEY_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{16,}")
_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def _import_roots(source):
    """The set of top-level import roots in one python source (PC1)."""
    roots = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.split(".")[0])
    return roots


def _forbidden_network_roots():
    return {"socket", "urllib", "http", "requests", "ftplib", "telnetlib"}


def _chat_response(
    *,
    model=_REQUEST_MODEL,
    fingerprint="fp-stable-001",
    prompt_tokens=1_000,
    completion_tokens=500,
    with_usage=True,
):
    """One scripted chat-completion response body (the frozen contract)."""
    content = json.dumps(
        {"is_vulnerable": False, "cwe": None, "path": None, "reason": "clean-tree"}
    )
    body = {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": content},
                "finish_reason": "stop",
            }
        ],
        "system_fingerprint": fingerprint,
    }
    if with_usage:
        body["usage"] = {
            "prompt_tokens": prompt_tokens,
            "completion_tokens": completion_tokens,
            "total_tokens": prompt_tokens + completion_tokens,
        }
    return body


class _SteppingClock:
    """A monotonic seam whose every read advances by a huge step.

    The first read anchors the batch; every later read sits far beyond the
    per-attempt wall reservation, so the frozen deadline discipline refuses
    the attempt before any POST (M19b).
    """

    def __init__(self):
        self.reads = 0

    def __call__(self):
        value = 1_000.0 + 2_000_000.0 * self.reads
        self.reads += 1
        return value


class _FakeTransport:
    """Injected transport double: POST-only chat calls, GET never expected.

    The synthetic fixture_key branch materializes locally, so a well-formed
    B1 real twin never performs a GET; ``download_calls`` doubles as the
    zero-connectivity-request assertion face (M2/M14).
    """

    def __init__(self, responses=None):
        self.chat_calls = 0
        self.download_calls = 0
        self.chat_payloads = []
        if responses is None:
            responses = [_chat_response()]
        self._responses = list(responses)

    def __call__(self, url, payload, headers, timeout):
        if payload is None:
            self.download_calls += 1
            raise AssertionError("the B1 real twin must never perform a GET")
        self.chat_calls += 1
        self.chat_payloads.append(bytes(payload))
        scheduled = self._responses[min(self.chat_calls - 1, len(self._responses) - 1)]
        if isinstance(scheduled, BaseException):
            raise scheduled
        return json.dumps(scheduled).encode("utf-8")


class _B1RealTestCase(unittest.TestCase):
    """Shared arrange helpers (offline, deterministic, PC2/PC3)."""

    def b1_real(self):
        import benchmarks.v4.baseline.b1_real as module

        return module

    def real_run(self):
        import benchmarks.v4.baseline.real_run as module

        return module

    def b1_source(self):
        import benchmarks.v4.baseline.b1_source as module

        return module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def load_repo_approval(self):
        path = _REPO_ROOT / _APPROVAL_RELATIVE_PATH
        if not path.is_file():
            self.fail(f"required approval artifact is missing: {_APPROVAL_RELATIVE_PATH}")
        text = path.read_text(encoding="utf-8")
        match = re.search(r"```json\n(.*?)\n```", text, re.DOTALL)
        if match is None:
            self.fail("approval artifact carries no machine-readable json block")
        return json.loads(match.group(1))

    def registry_fingerprint(self, key):
        from benchmarks.v4.baseline.fixtures import load_registry

        for entry in load_registry()["fixtures"]:
            if entry["key"] == key:
                return entry["fingerprint"]
        raise AssertionError(f"fixture key absent from registry: {key}")

    def expected_commit_sha(self, key, fingerprint):
        """The frozen synthetic commit-sha derivation (PC3 recompute)."""
        return hashlib.sha256(
            ("lima-synth-artifact:" + key + ":" + fingerprint).encode("utf-8")
        ).hexdigest()[:40]

    def apply_synthetic_upstream(self, document, key):
        """Pin one synthetic descriptor's upstream faces onto a document."""
        fingerprint = self.registry_fingerprint(key)
        commit_sha = self.expected_commit_sha(key, fingerprint)
        archetype = key.removeprefix("archetype/")
        document["upstream"]["repository"] = f"lima-synth/{archetype}"
        document["upstream"]["requested_name"] = f"lima-synth/{archetype}"
        document["upstream"]["commit_sha"] = commit_sha
        document["upstream"]["tarball_url"] = (
            f"https://lima-synth.invalid/{archetype}/tar.gz/{commit_sha}"
        )

    def expected_scanner_config_document(self):
        """The B1-real scanner config document (Packet 7.3; PC3 mirror)."""
        return {
            "workload": _B1_REAL_WORKLOAD,
            "fixture_key": _B1_REAL_FIXTURE_KEY,
            "snapshot_tree_sha256": self.registry_fingerprint(_B1_REAL_FIXTURE_KEY),
            "seed": 0,
            "cold_count": _B1_REAL_COLD,
            "warm_count": _B1_REAL_WARM,
            "scanner": {
                "sast_mode": _SAST_MODE,
                "sast_adapters": [],
                "cxx_memory_mode": _CXX_MEMORY_MODE,
                "cxx_memory_adapter": None,
                "cxx_agent_mode": _CXX_AGENT_MODE,
                "cxx_agent_budget_factory": None,
                "cxx_uaf_llm_factory": None,
                "dataflow_enabled": _DATAFLOW_ENABLED,
                "reviewers": "security-rule-reviewer",
                "should_cancel": None,
            },
            "workspace": {
                "max_files": _WORKSPACE_MAX_FILES,
                "max_file_bytes": _WORKSPACE_MAX_FILE_BYTES,
                "max_total_bytes": _WORKSPACE_MAX_TOTAL_BYTES,
            },
        }

    def content_digest(self, value):
        from lima.contracts.codec import compute_content_digest

        return compute_content_digest(value)

    def write_b1_real_artifact(self, directory, mutate=None):
        """One twelfth-key twin approval artifact inside the run root.

        The base document is the frozen repo approval (loaded through the
        same markdown json block the frozen loader reads, PC2); the mutation
        applies the twelfth-key pins: the five provenance fields follow the
        frozen synthetic derivation of archetype/signal-storm, the approval
        identity carries the new pins, the date pins are the 2026-10-01
        authorization, the attempt policy is the one-time {1,4,5} shape, and
        the budget block carries the seven-dimension authorization table.
        """
        document = copy.deepcopy(self.load_repo_approval())
        self.apply_synthetic_upstream(document, _B1_REAL_FIXTURE_KEY)
        document["approval_type"] = _B1_REAL_APPROVAL_TYPE
        document["run_name"] = _B1_REAL_RUN_NAME
        document["date"] = _B1_REAL_DATE_PIN
        document["pricing"]["retrieval_date"] = _B1_REAL_RETRIEVAL_DATE_PIN
        policy = document["attempt_policy"]
        policy["cold"] = _B1_REAL_COLD
        policy["warm"] = _B1_REAL_WARM
        policy["max_attempts"] = _B1_REAL_ATTEMPTS
        policy["canary_required"] = True
        policy["canary_first_attempt"] = 0
        for level, table in (("per_run", _B1_REAL_PER_RUN), ("batch", _B1_REAL_BATCH)):
            for dimension, value in table.items():
                document["budget"][level][dimension] = value
        if mutate is not None:
            mutate(document)
        body = json.dumps(document, ensure_ascii=False, indent=2)
        path = pathlib.Path(directory) / "approval.md"
        path.write_text(
            "# arrange approval\n\n```json\n" + body + "\n```\n", encoding="utf-8"
        )
        return path

    def load_manifest(self):
        path = _REPO_ROOT / "evaluation_data" / "v4" / "baseline_manifest.json"
        if not path.is_file():
            self.fail(f"required frozen manifest artifact is missing: {path}")
        return json.loads(path.read_bytes().decode("utf-8"))

    def spec_mapping(self):
        manifest = self.load_manifest()
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
            "analyzer_fingerprint": "a" * 64,
            "config_digest": "b" * 64,
            "seed": 20260927,
            "machine_profile": dict(_NOMINAL_MACHINE_PROFILE),
        }

    def fixed_sources(self):
        from benchmarks.v4.baseline import collect

        durations = [value * 1_000_000 for value in [100] + [80] * 4]
        wall_reads = []
        base = 1_000_000_000
        for span in durations:
            wall_reads.extend((base, base + span))
            base += span + 1_000_000
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

    def run_twin(self, output, *, transport=None, mutate=None, timeout_seconds=120):
        """Drive the B1 real entry on one fresh empty twin root."""
        module = self.b1_real()
        artifact = self.write_b1_real_artifact(output, mutate)
        return module.run_b1_real_baseline_suite(
            artifact,
            _FAKE_KEY,
            output_root=pathlib.Path(output),
            spec_mapping=self.spec_mapping(),
            transport=transport if transport is not None else _FakeTransport(),
            timeout_seconds=timeout_seconds,
            sources=self.fixed_sources(),
        )

    def read_json(self, path):
        return json.loads(pathlib.Path(path).read_bytes().decode("utf-8"))

    def read_attempt(self, root, index):
        return self.read_json(
            pathlib.Path(root) / "attempts" / f"attempt-{index:02d}.json"
        )

    def report_of(self, result):
        return self.read_json(result.report_path)

    def companion_manifest(self, root):
        return self.read_json(pathlib.Path(root) / "b1-real-manifest.json")

    def companion_receipts(self, root):
        directory = pathlib.Path(root) / "b1-real-attempts"
        paths = sorted(directory.glob("b1-real-attempt-*.json"))
        self.assertTrue(paths, "no companion receipts were written")
        return [self.read_json(path) for path in paths]

    def direct_scan(self, root):
        """The real local scanner under the frozen explicit offline config."""
        from lima.repository_scanner import RepositoryScanner
        from lima.reviewer import SecurityRuleReviewer
        from lima.workspace import RepositoryWorkspace

        scanner = RepositoryScanner(
            [SecurityRuleReviewer()],
            sast_mode=_SAST_MODE,
            sast_adapters=[],
            cxx_memory_mode=_CXX_MEMORY_MODE,
            cxx_memory_adapter=None,
            cxx_agent_mode=_CXX_AGENT_MODE,
            cxx_agent_budget_factory=None,
            cxx_uaf_llm_factory=None,
            dataflow_enabled=_DATAFLOW_ENABLED,
            should_cancel=None,
        )
        workspace = RepositoryWorkspace(
            pathlib.Path(root),
            max_files=_WORKSPACE_MAX_FILES,
            max_file_bytes=_WORKSPACE_MAX_FILE_BYTES,
            max_total_bytes=_WORKSPACE_MAX_TOTAL_BYTES,
        )
        return scanner.scan(workspace)

    def expected_faces(self, scan_result):
        """Direct-scanner-output recomputation of every reported count (PC3)."""
        findings = scan_result.report.findings
        states = [finding.verification_state for finding in findings]
        skipped = scan_result.report.collaboration["skipped"]
        reasons = {
            reason: count
            for reason, count in sorted(skipped.items())
            if reason in _COVERAGE_AFFECTING_SKIPS and count > 0
        }
        return {
            "raw_candidates": len(findings),
            "deterministic_alerts": sum(
                1 for state in states if state in _DETERMINISTIC_STATES
            ),
            "confirmed": sum(1 for state in states if state == "confirmed"),
            "inconclusive": sum(1 for state in states if state in _INCONCLUSIVE_STATES),
            "scanned_files": scan_result.report.collaboration["scanned_files"],
            "coverage_gap": sum(reasons.values()),
            "coverage_gap_reasons": reasons,
        }

    def reuse_face(self, receipt):
        return {
            key: receipt[key]
            for key in (
                "scanner_reexecuted",
                "scanner_result_reused",
                "snapshot_reused",
                "request_body_rebuilt",
            )
        }


class TestB1RealEntryTwin(_B1RealTestCase):
    """Cluster 1: the entry's full offline twin and the honest POST face."""

    def test_b1_real_entry_full_chain_offline_twin(self):
        self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            transport = _FakeTransport()
            result = self.run_twin(output, transport=transport)
            # Exactly five fake POSTs, zero GETs (local materialization).
            self.assertEqual(transport.chat_calls, 5)
            self.assertEqual(transport.download_calls, 0)
            # The {1,4} shape: one cold attempt-0 and four warm reuses.
            self.assertEqual(result.attempt_count, 5)
            modes = [self.read_attempt(output, index)["mode"] for index in range(5)]
            self.assertEqual(modes, ["cold", "warm", "warm", "warm", "warm"])
            # The honest aggregate of an undersized shape.
            self.assertEqual(result.status, "insufficient_sample")
            # The five-file frozen evidence set is complete.
            for name in (
                "approval.json",
                "ledger.json",
                "manifest.json",
                "machine_profile.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            self.assertTrue((output / "attempts").is_dir())
            self.assertEqual(len(list((output / "attempts").glob("attempt-*.json"))), 5)
            # The report exists and goes through the scanner type path.
            report = self.report_of(result)
            self.assertEqual(
                [source["kind"] for source in report["sources"]], ["scanner"]
            )
            # The companion family is written next to the frozen evidence.
            self.assertTrue((output / "b1-real-manifest.json").is_file())
            self.assertEqual(
                len(list((output / "b1-real-attempts").glob("b1-real-attempt-*.json"))),
                5,
            )
            # The result faces: the B1-real discriminant and binding pins.
            self.assertIs(result.b1_real, True)
            self.assertIs(result.real_run, True)
            self.assertEqual(result.real_post_count, 5)
            self.assertEqual(result.artifact_key, _B1_REAL_KEY)
            self.assertEqual(result.fixture_key, _B1_REAL_FIXTURE_KEY)
            self.assertEqual(result.workload, _B1_REAL_WORKLOAD)
            self.assertEqual(result.run_name, _B1_REAL_RUN_NAME)
            self.assertEqual(result.scanner_executions, 1)
            self.assertEqual(
                result.report_sha256,
                hashlib.sha256(result.report_path.read_bytes()).hexdigest(),
            )

    def test_b1_real_post_count_honesty_face(self):
        self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            transport = _FakeTransport()
            result = self.run_twin(output, transport=transport)
            # The independent counter (the injected transport itself), the
            # ledger calls face, and the entry's recorded count all agree.
            self.assertEqual(result.real_post_count, transport.chat_calls)
            self.assertEqual(result.ledger_snapshot.batch["calls"], 5)
            manifest = self.companion_manifest(output)
            self.assertEqual(manifest["real_post_count"], 5)
            self.assertEqual(manifest["ledger_calls"], 5)
            # The honesty face: no model_calls key, no offline-proof marker.
            self.assertNotIn("model_calls", manifest)
            for declaration in manifest["declarations"]:
                self.assertNotIn("offline-proof", declaration)
            self.assertEqual(set(manifest["declarations"]), _B1_REAL_DECLARATIONS)
            self.assertEqual(manifest["transport_face"], "injected")
            # No extra connectivity requests: zero GETs alongside the POSTs.
            self.assertEqual(transport.download_calls, 0)


class TestB1RealBudget(_B1RealTestCase):
    """Cluster 2: the seven-dimension table, its internal reconciliation,
    and the at-cap / shape enforcement."""

    def test_b1_real_seven_dimensions_per_value_from_approval(self):
        self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            result = self.run_twin(output)
            # The approval-side table is the sole numeric source: the twin
            # artifact carries the authorization values verbatim and the
            # frozen loader enforced them (the five reserves passed under
            # the caps; the sixth is refused -- the boundary face is M5).
            self.assertEqual(
                set(_B1_REAL_PER_RUN),
                set(_B1_REAL_BATCH),
            )
            # The ledger booked exactly the authorized call count and the
            # reported usage (5 x {1000 prompt, 500 completion} tokens).
            snapshot = result.ledger_snapshot
            self.assertEqual(snapshot.batch["calls"], 5)
            self.assertEqual(snapshot.batch["consumed"]["prompt_tokens"], 5_000)
            self.assertEqual(snapshot.batch["consumed"]["completion_tokens"], 2_500)
            self.assertLessEqual(
                snapshot.batch["consumed"]["cost_micro_usd"],
                _B1_REAL_BATCH["cost_micro_usd"],
            )
            # NFR: the entry source carries no numeric budget constant.
            source = self.product_source(_B1_REAL_RELATIVE_PATH)
            for literal in _FORBIDDEN_BUDGET_LITERALS:
                self.assertNotIn(literal, source, literal)

    def test_b1_real_internal_reconciliation_and_estimate_registration(self):
        self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            self.run_twin(output)
            # The frozen internal formula, recomputed independently (PC3):
            # the attempt-0 worst case admits the frozen byte-derived prompt
            # bound (100000) and the max-tokens completion bound (8000) at
            # the frozen prices -- 39600 micro-USD per attempt, and the
            # batch ceiling is exactly five attempts.
            worst_call = (
                100_000 * _PRICES[0] // 1_000_000
                + 8_000 * _PRICES[1] // 1_000_000
            )
            self.assertEqual(worst_call, 39_600)
            self.assertEqual(worst_call * 5, _B1_REAL_BATCH["cost_micro_usd"])
            self.assertGreaterEqual(
                _B1_REAL_PER_RUN["prompt_tokens"], 100_000
            )
            self.assertEqual(_B1_REAL_PER_RUN["completion_tokens"], 8_000)
            self.assertEqual(
                _B1_REAL_PER_RUN["wall_ms"] * 5, _B1_REAL_BATCH["wall_ms"]
            )
            self.assertEqual(
                _B1_REAL_PER_RUN["completion_tokens"] * 5,
                _B1_REAL_BATCH["completion_tokens"],
            )
            self.assertEqual(100_000 * 5, _B1_REAL_BATCH["prompt_tokens"])
            # The estimate-registration face (Packet 7.6.3): the companion
            # manifest registers the scanner phase inside the attempt-0
            # wall reservation and the companion bytes under the frozen
            # storage reservation, without a scanner-specific wall number.
            manifest = self.companion_manifest(output)
            self.assertEqual(manifest["scanner_phase"], _SCANNER_PHASE_FACE)
            self.assertGreaterEqual(manifest["companion_bytes_total"], 0)
            self.assertLess(
                manifest["companion_bytes_total"],
                _B1_REAL_PER_RUN["storage_bytes"],
            )
            # The attempt-0 wall observation exists (the scan ran inside it).
            attempt0 = self.read_attempt(output, 0)
            self.assertIn("attempt_wall_ms", attempt0["timings"])

    def test_b1_real_at_cap_and_shape_enforcement(self):
        module = self.b1_real()
        from benchmarks.v4.baseline import budget

        # (a) The frozen at-cap semantics on the ledger face (the {1,4,5}
        # authorization: five reserves pass, the sixth is refused at the
        # batch call ceiling -- the test_ten_reserves precedent's shape).
        per_run = budget.BudgetLimits(**_B1_REAL_PER_RUN)
        batch = budget.BudgetLimits(**_B1_REAL_BATCH)
        ledger = budget.BudgetLedger(
            budget.BudgetSpec(per_run=per_run, batch=batch),
            budget.Pricing(
                prompt_token_price_micro_usd_per_million=_PRICES[0],
                completion_token_price_micro_usd_per_million=_PRICES[1],
            ),
        )
        canary_estimate = budget.CallEstimate(
            prompt_tokens=100_000,
            completion_tokens=_B1_REAL_PER_RUN["completion_tokens"],
            wall_ms=_B1_REAL_PER_RUN["wall_ms"],
            download_bytes=_B1_REAL_PER_RUN["download_bytes"],
            storage_bytes=_B1_REAL_PER_RUN["storage_bytes"],
        )
        follow_on = budget.CallEstimate(
            prompt_tokens=100_000,
            completion_tokens=_B1_REAL_PER_RUN["completion_tokens"],
            wall_ms=_B1_REAL_PER_RUN["wall_ms"],
        )
        ledger.reserve("attempt-0", canary_estimate)
        for index in range(1, 5):
            ledger.reserve(f"attempt-{index}", follow_on)
        with self.assertRaises(budget.BudgetGateError) as caught:
            ledger.reserve("attempt-extra", follow_on)
        self.assertEqual(
            caught.exception.code, budget.BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED
        )
        self.assertEqual(caught.exception.field_path, "$.budget.batch.calls")
        self.assertEqual(ledger.snapshot().batch["calls"], 5)
        # (b) The entry's shape enforcement: only the authorized {1,4,5}
        # policy is accepted; {2,4} and {5,5} twin artifacts are rejected
        # with the entry's typed input code and zero POSTs.
        for cold, warm in ((2, 4), (5, 5)):
            with self.subTest(cold=cold, warm=warm):
                with tempfile.TemporaryDirectory() as temporary:
                    output = pathlib.Path(temporary) / "run"
                    output.mkdir()

                    def drift_shape(document, cold=cold, warm=warm):
                        policy = document["attempt_policy"]
                        policy["cold"] = cold
                        policy["warm"] = warm
                        policy["max_attempts"] = cold + warm

                    transport = _FakeTransport()
                    with self.assertRaises(module.B1RealError) as rejection:
                        self.run_twin(output, transport=transport, mutate=drift_shape)
                    self.assertEqual(
                        rejection.exception.code,
                        module.B1RealErrorCode.B1_REAL_INPUT_INVALID,
                    )
                    self.assertEqual(transport.chat_calls, 0)


class TestB1RealDescriptor(_B1RealTestCase):
    """Cluster 3: the twelfth catalog key and its deterministic pins."""

    def test_b1_real_twelfth_descriptor_field_set_and_pins(self):
        catalog = self.real_run().REAL_RUN_ARTIFACT_FAMILY
        self.assertEqual(set(catalog), _ARTIFACT_FAMILY_KEYS)
        descriptor = catalog[_B1_REAL_KEY]
        self.assertEqual(set(descriptor), _TWELFTH_FIELD_SET)
        # The five provenance fields are the signal-storm synthetic
        # derivation verbatim (independently recomputed, PC3).
        fingerprint = self.registry_fingerprint(_B1_REAL_FIXTURE_KEY)
        commit_sha = self.expected_commit_sha(_B1_REAL_FIXTURE_KEY, fingerprint)
        self.assertEqual(descriptor["repository"], "lima-synth/signal-storm")
        self.assertEqual(descriptor["requested_name"], "lima-synth/signal-storm")
        self.assertEqual(descriptor["commit_sha"], commit_sha)
        self.assertEqual(
            descriptor["tarball_url"],
            f"https://lima-synth.invalid/signal-storm/tar.gz/{commit_sha}",
        )
        self.assertEqual(
            descriptor["tarball_filename"],
            "lima-synth-signal-storm-{commit_sha}.tar.gz",
        )
        # The approval identity and the four R2 fields carry the pins.
        self.assertEqual(descriptor["approval_type"], _B1_REAL_APPROVAL_TYPE)
        self.assertEqual(descriptor["run_name"], _B1_REAL_RUN_NAME)
        self.assertEqual(descriptor["fixture_key"], _B1_REAL_FIXTURE_KEY)
        self.assertEqual(descriptor["date_pin"], _B1_REAL_DATE_PIN)
        self.assertEqual(descriptor["retrieval_date_pin"], _B1_REAL_RETRIEVAL_DATE_PIN)
        self.assertIs(descriptor["stop_on_first_failure"], True)
        # The five B1 binding fields carry the frozen values.
        self.assertEqual(descriptor["workload"], _B1_REAL_WORKLOAD)
        self.assertEqual(descriptor["scanner_config_ref"], _B1_REAL_SCANNER_CONFIG_REF)
        self.assertRegex(descriptor["scanner_config_sha256"], _HEX64_PATTERN)
        self.assertEqual(descriptor["source_contract"], _B1_REAL_SOURCE_CONTRACT)
        self.assertEqual(
            descriptor["source_contract_version"], _B1_REAL_SOURCE_CONTRACT_VERSION
        )
        # Every old key keeps its exact closed field set.
        for key, expected in [
            *((key, _DESCRIPTOR_FIELDS) for key in _NINE_SYNTHETIC_KEYS),
            ("external/llamafactory-replay", _DESCRIPTOR_FIELDS),
            (_REAL_PILOT_KEY, _DESCRIPTOR_FIELDS | _REAL_PILOT_EXTRA_FIELDS),
        ]:
            with self.subTest(key=key):
                self.assertEqual(set(catalog[key]), expected)

    def test_b1_real_descriptor_derivation_deterministic(self):
        catalog = self.real_run().REAL_RUN_ARTIFACT_FAMILY
        self.assertEqual(set(catalog), _ARTIFACT_FAMILY_KEYS)
        descriptor = catalog[_B1_REAL_KEY]
        # The config-document digest is recomputable from the registry and
        # the frozen document shape (Packet 7.3; PC3).
        expected_digest = self.content_digest(self.expected_scanner_config_document())
        self.assertEqual(descriptor["scanner_config_sha256"], expected_digest)
        self.assertEqual(
            descriptor["commit_sha"],
            self.expected_commit_sha(
                _B1_REAL_FIXTURE_KEY, self.registry_fingerprint(_B1_REAL_FIXTURE_KEY)
            ),
        )
        # The new pins are unique across the whole catalog.
        run_names = {entry["run_name"] for entry in catalog.values()}
        approval_types = {entry["approval_type"] for entry in catalog.values()}
        self.assertEqual(len(run_names), len(catalog))
        self.assertEqual(len(approval_types), len(catalog))
        self.assertIn(_B1_REAL_RUN_NAME, run_names)
        self.assertIn(_B1_REAL_APPROVAL_TYPE, approval_types)


class TestB1RealSourceBinding(_B1RealTestCase):
    """Cluster 4: the scanner-once-in-window binding and the companion set."""

    def test_b1_real_scanner_once_cold_attempt0_warm_reuse(self):
        self.b1_real()
        from benchmarks.v4.baseline.fixtures import compute_tree_fingerprint

        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            result = self.run_twin(output)
            self.assertEqual(result.scanner_executions, 1)
            # The cold attempt-0 initial materialization observation.
            attempt0 = self.read_attempt(output, 0)
            self.assertIn("cold_reset", attempt0)
            self.assertIs(attempt0["cold_reset"]["performed"], False)
            self.assertEqual(attempt0["cold_reset"]["materialization_count"], 1)
            # The warm reuses carry the frozen state_reuse face and no
            # cold_reset key at all.
            for index in range(1, 5):
                attempt = self.read_attempt(output, index)
                self.assertNotIn("cold_reset", attempt)
                self.assertIs(attempt["state_reuse"]["snapshot_reused"], True)
            # The companion receipts carry the frozen reuse vocabulary.
            receipts = self.companion_receipts(output)
            self.assertEqual(len(receipts), 5)
            cold_face = self.reuse_face(receipts[0])
            self.assertEqual(
                cold_face,
                {
                    "scanner_reexecuted": True,
                    "scanner_result_reused": False,
                    "snapshot_reused": False,
                    "request_body_rebuilt": True,
                },
            )
            warm_face = {
                "scanner_reexecuted": False,
                "scanner_result_reused": True,
                "snapshot_reused": True,
                "request_body_rebuilt": False,
            }
            for receipt in receipts[1:]:
                self.assertEqual(self.reuse_face(receipt), warm_face)
            # The three-way snapshot identity: receipt == cold_reset
            # observation == the recomputed digest of the persisted tree.
            persisted = compute_tree_fingerprint(output / "_materialized" / "snapshot")
            self.assertEqual(attempt0["cold_reset"]["snapshot_tree_sha256"], persisted)
            for receipt in receipts:
                self.assertEqual(receipt["snapshot_tree_sha256"], persisted)

    def test_b1_real_report_matches_independent_direct_scan(self):
        self.b1_real()
        from benchmarks.v4.baseline.fixtures import materialize_fixture

        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            result = self.run_twin(output)
            # The independent direct scan of a fresh materialization is the
            # final truth (never the transcribed 24).
            materialization = materialize_fixture(
                _B1_REAL_FIXTURE_KEY, pathlib.Path(temporary) / "direct"
            )
            faces = self.expected_faces(self.direct_scan(materialization.root))
            self.assertEqual(faces["raw_candidates"], 24)
            self.assertEqual(faces["confirmed"], 0)
            self.assertGreater(faces["raw_candidates"], _CANDIDATE_FILE_CAP)
            report = self.report_of(result)
            chain = report["compression_chain"]
            self.assertEqual(chain["raw_candidates"], faces["raw_candidates"])
            self.assertEqual(chain["deterministic_alerts"], faces["deterministic_alerts"])
            self.assertEqual(chain["confirmed"], faces["confirmed"])
            self.assertEqual(chain["inconclusive"], faces["inconclusive"])
            self.assertEqual(
                chain["raw_candidates"],
                chain["deterministic_alerts"] + chain["inconclusive"],
            )
            counts = report["counts"]
            self.assertEqual(
                counts["scanned_files"],
                {"value": faces["scanned_files"], "projection": "measured"},
            )
            self.assertEqual(
                counts["coverage_gap"],
                {"value": faces["coverage_gap"], "projection": "measured"},
            )
            self.assertEqual(
                counts["signals"],
                {"value": faces["raw_candidates"], "projection": "legacy_projection"},
            )
            self.assertEqual(
                counts["security_issues"],
                {"value": faces["raw_candidates"], "projection": "legacy_projection"},
            )
            self.assertEqual(
                report["coverage_gap_reasons"], faces["coverage_gap_reasons"]
            )
            # The no-summation rule: five samples, one scan's counts.
            self.assertEqual(result.attempt_count, 5)
            self.assertNotEqual(chain["raw_candidates"], 5 * faces["raw_candidates"])
            # The frozen unavailable discipline on the real scanner report.
            self.assertEqual(
                report["counts"]["hypotheses"],
                {"value": None, "projection": "unavailable"},
            )
            self.assertEqual(report["vep"], {"value": None, "projection": "unavailable"})
            self.assertEqual(report["rvr"], {"value": None, "projection": "unavailable"})
            self.assertEqual(report["evidence_domain"], "legacy")
            self.assertTrue(report["legacy_projection"])

    def test_b1_real_receipt_key_set_and_companion_layout(self):
        self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            result = self.run_twin(output)
            receipts = self.companion_receipts(output)
            for index, receipt in enumerate(receipts):
                with self.subTest(attempt=index):
                    self.assertEqual(set(receipt), _B1_REAL_RECEIPT_KEYS)
                    self.assertEqual(receipt["attempt_index"], index)
            manifest = self.companion_manifest(output)
            self.assertEqual(set(manifest), _B1_REAL_MANIFEST_KEYS)
            self.assertEqual(manifest["schema_version"], 1)
            self.assertEqual(manifest["source_contract"], _B1_REAL_SOURCE_CONTRACT)
            self.assertEqual(
                manifest["source_contract_version"], _B1_REAL_SOURCE_CONTRACT_VERSION
            )
            # The companion family is exactly the five receipts plus the
            # manifest, never colliding with any frozen family.
            names = {path.name for path in output.iterdir()}
            self.assertEqual(
                {path.name for path in (output / "b1-real-attempts").iterdir()},
                {f"b1-real-attempt-{index:02d}.json" for index in range(5)},
            )
            self.assertIn("b1-real-manifest.json", names)
            self.assertIn("b1-real-attempts", names)
            self.assertNotIn("b1-attempts", names)
            self.assertNotIn("b1-manifest.json", names)
            digest16 = result.run_spec_digest[:16]
            run_family = {
                name
                for name in names
                if re.match(r"^[0-9a-f]{16}-(run|report)-[0-9]+\.json$", name)
            }
            self.assertTrue(run_family)
            for name in run_family:
                self.assertTrue(name.startswith(digest16))


class TestB1RealDigestCross(_B1RealTestCase):
    """Cluster 5: the digest cross-chain and the companion verifier."""

    def test_b1_real_digest_cross_chain(self):
        self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            result = self.run_twin(output)
            # The independent re-scan of the persisted snapshot recomputes
            # the frozen scanner wire fingerprint (the same rule the report
            # projection applies -- PC3 through the frozen module).
            persisted_scan = self.direct_scan(output / "_materialized" / "snapshot")
            scanner_digest = self.b1_source()._wire_fingerprint(persisted_scan)
            report = self.report_of(result)
            self.assertEqual(report["sources"][0]["payload_sha256"], scanner_digest)
            receipts = self.companion_receipts(output)
            for receipt in receipts:
                self.assertEqual(receipt["scanner_payload_sha256"], scanner_digest)
                # The actual model request-body digest equals the frozen
                # cold_reset observation of the initial materialization.
                self.assertEqual(
                    receipt["request_body_sha256"],
                    self.read_attempt(output, 0)["cold_reset"]["request_body_sha256"],
                )
                # The RunResult pointer is valid and digest-bound.
                run_result = output / receipt["run_result_name"]
                self.assertTrue(run_result.is_file(), receipt["run_result_name"])
                self.assertEqual(
                    receipt["run_result_sha256"],
                    hashlib.sha256(run_result.read_bytes()).hexdigest(),
                )
                # The attempt-document pointer and suite association.
                attempt_document = output / receipt["attempt_document_name"]
                self.assertTrue(attempt_document.is_file())
                self.assertEqual(receipt["suite_run_name"], _B1_REAL_RUN_NAME)
                # The analyzer identity derivation (the b1_source formula).
                self.assertEqual(
                    receipt["analyzer_fingerprint"],
                    self.content_digest(
                        {
                            "analyzer_name": receipt["analyzer_name"],
                            "scanner_config_sha256": receipt["scanner_config_sha256"],
                        }
                    ),
                )
                self.assertEqual(receipt["run_spec_digest"], result.run_spec_digest)
            # The approval and ledger digests bind the file bytes.
            approval_digest = hashlib.sha256(
                (output / "approval.json").read_bytes()
            ).hexdigest()
            self.assertEqual(result.approval_digest, approval_digest)
            self.assertEqual(receipts[0]["approval_sha256"], approval_digest)
            ledger_digest = hashlib.sha256(
                (output / "ledger.json").read_bytes()
            ).hexdigest()
            for receipt in receipts:
                self.assertEqual(receipt["ledger_sha256"], ledger_digest)

    def test_b1_real_companion_verifier_pass_and_tamper_fail_closed(self):
        module = self.b1_real()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            result = self.run_twin(output)
            # The pass state: the read-back verifier recomputes everything.
            verified = module.verify_b1_real_evidence(output)
            self.assertEqual(verified["run_spec_digest"], result.run_spec_digest)
            # The tamper faces: every mutation is rejected fail-closed with
            # the typed family (never a downgrade), then restored.
            manifest_path = output / "b1-real-manifest.json"
            receipt_path = output / "b1-real-attempts" / "b1-real-attempt-00.json"
            receipts = self.companion_receipts(output)
            run_result_path = output / receipts[0]["run_result_name"]
            other_result_path = output / receipts[4]["run_result_name"]
            original = {
                path: path.read_bytes()
                for path in (manifest_path, receipt_path, run_result_path)
            }
            receipt = json.loads(original[receipt_path].decode("utf-8"))
            manifest = json.loads(original[manifest_path].decode("utf-8"))

            def write_json(path, document):
                path.write_text(
                    json.dumps(document, ensure_ascii=False), encoding="utf-8"
                )

            def expect_tamper_refusal(code):
                with self.assertRaises(module.B1RealError) as caught:
                    module.verify_b1_real_evidence(output)
                self.assertEqual(caught.exception.code, code)

            try:
                # (a) A dropped receipt key: the closed set is violated.
                dropped = dict(receipt)
                dropped.pop("seed")
                write_json(receipt_path, dropped)
                expect_tamper_refusal(module.B1RealErrorCode.B1_REAL_RECEIPT_INVALID)
                receipt_path.write_bytes(original[receipt_path])
                # (b) A receipt value tamper: the aggregate digest breaks.
                drifted = dict(receipt)
                drifted["suite_run_name"] = "some-other-run"
                write_json(receipt_path, drifted)
                expect_tamper_refusal(module.B1RealErrorCode.B1_REAL_BINDING_MISMATCH)
                receipt_path.write_bytes(original[receipt_path])
                # (c) A scanner digest tamper: the digest chain breaks.
                wrong_digest = dict(receipt)
                wrong_digest["scanner_payload_sha256"] = "f" * 64
                write_json(receipt_path, wrong_digest)
                expect_tamper_refusal(
                    module.B1RealErrorCode.B1_REAL_SCANNER_DIGEST_MISMATCH
                )
                receipt_path.write_bytes(original[receipt_path])
                # (d) A RunResult backfill: the pointer's digest breaks.
                run_result_path.write_bytes(other_result_path.read_bytes())
                expect_tamper_refusal(module.B1RealErrorCode.B1_REAL_BINDING_MISMATCH)
                run_result_path.write_bytes(original[run_result_path])
                # (e) A manifest aggregate tamper: the recomputed receipts
                # digest no longer matches the manifest claim.
                broken = dict(manifest)
                broken["source_receipts_digest"] = "0" * 64
                write_json(manifest_path, broken)
                expect_tamper_refusal(module.B1RealErrorCode.B1_REAL_BINDING_MISMATCH)
                manifest_path.write_bytes(original[manifest_path])
            finally:
                for path, payload in original.items():
                    path.write_bytes(payload)
            # The restored directory verifies again (fail-closed is pure).
            module.verify_b1_real_evidence(output)


class TestB1RealNegatives(_B1RealTestCase):
    """Cluster 6: the negative matrix (ruling section 6, Packet 8.1)."""

    def test_b1_real_rejects_old_or_unknown_descriptor_misuse(self):
        module = self.b1_real()
        real_run = self.real_run()
        pilot = real_run.REAL_RUN_ARTIFACT_FAMILY[_REAL_PILOT_KEY]

        def pilot_bound(document):
            self.apply_synthetic_upstream(document, _REAL_PILOT_FIXTURE_KEY)
            document["approval_type"] = pilot["approval_type"]
            document["run_name"] = pilot["run_name"]
            document["date"] = pilot["date_pin"]
            document["pricing"]["retrieval_date"] = pilot["retrieval_date_pin"]

        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            # (a) An old-descriptor approval (the eleventh key's pins) is
            # refused by the B1 entry as not twelfth-bound, zero POSTs.
            transport = _FakeTransport()
            with self.assertRaises(module.B1RealError) as caught:
                self.run_twin(output, transport=transport, mutate=pilot_bound)
            self.assertEqual(
                caught.exception.code,
                module.B1RealErrorCode.B1_REAL_INPUT_INVALID,
            )
            self.assertEqual(transport.chat_calls, 0)
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()

            # (b) A drifted approval identity is refused the same way.
            def drifted_identity(document):
                document["approval_type"] = "PR3D-SOME-OTHER-ENTRY"

            transport = _FakeTransport()
            with self.assertRaises(module.B1RealError) as caught:
                self.run_twin(output, transport=transport, mutate=drifted_identity)
            self.assertEqual(
                caught.exception.code,
                module.B1RealErrorCode.B1_REAL_INPUT_INVALID,
            )
            self.assertEqual(transport.chat_calls, 0)

    def test_b1_real_rejects_fixture_workload_config_date_drift(self):
        self.b1_real()
        real_run = self.real_run()
        # (a) The date pins drift: the frozen descriptor-driven pin check
        # refuses the artifact before any POST.
        for face, mutation in (
            (
                "date",
                lambda document: document.__setitem__("date", "2026-10-02"),
            ),
            (
                "retrieval_date",
                lambda document: document["pricing"].__setitem__(
                    "retrieval_date", "2026-10-02"
                ),
            ),
        ):
            with self.subTest(face=face):
                with tempfile.TemporaryDirectory() as temporary:
                    output = pathlib.Path(temporary) / "run"
                    output.mkdir()
                    transport = _FakeTransport()
                    with self.assertRaises(real_run.RealRunError) as caught:
                        self.run_twin(output, transport=transport, mutate=mutation)
                    self.assertEqual(
                        caught.exception.code,
                        real_run.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(transport.chat_calls, 0)
        # (b) The fixture drift face: a large-repo-derived upstream under the
        # B1 entry is refused (the loader pins the whole upstream against
        # the twelfth descriptor -- the frozen pin family).
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()

            def fixture_drift(document):
                self.apply_synthetic_upstream(document, _REAL_PILOT_FIXTURE_KEY)

            transport = _FakeTransport()
            with self.assertRaises(real_run.RealRunError) as caught:
                self.run_twin(output, transport=transport, mutate=fixture_drift)
            self.assertEqual(
                caught.exception.code,
                real_run.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
            )
            self.assertEqual(transport.chat_calls, 0)
        # (c) The no-download mechanism proof: the twelfth fixture_key is in
        # the descriptor, so the synthetic local materialization branch runs
        # -- zero GETs and zero download bytes on the happy twin.
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            transport = _FakeTransport()
            result = self.run_twin(output, transport=transport)
            self.assertEqual(transport.download_calls, 0)
            self.assertEqual(result.attempt_count, 5)
            attempt0 = self.read_attempt(output, 0)
            self.assertEqual(attempt0["resources"]["download_bytes"], 0)

    def test_b1_real_nonempty_output_and_source_missing_tampered(self):
        module = self.b1_real()
        real_run = self.real_run()
        # (a) A non-empty output root is refused by the frozen gate.
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            (output / "stray.txt").write_text("stale", encoding="utf-8")
            transport = _FakeTransport()
            with self.assertRaises(real_run.RealRunError) as caught:
                self.run_twin(output, transport=transport)
            self.assertEqual(
                caught.exception.code,
                real_run.RealRunErrorCode.REAL_RUN_OUTPUT_NOT_EMPTY,
            )
            self.assertEqual(transport.chat_calls, 0)
        # (b) The source-missing / tampered faces on one twin: the persisted
        # snapshot tree no longer matches the receipts' binding after any
        # content change, and the verifier refuses fail-closed.
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            self.run_twin(output)
            module.verify_b1_real_evidence(output)
            snapshot_dir = output / "_materialized" / "snapshot"
            first_python = next(snapshot_dir.rglob("*.py"))
            first_python.unlink()
            with self.assertRaises(module.B1RealError) as caught:
                module.verify_b1_real_evidence(output)
            self.assertEqual(
                caught.exception.code,
                module.B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
            )
            # The backfilled placeholder keeps the tree digest mismatched
            # (a foreign snapshot is the same typed refusal).
            first_python.write_text("# backfilled\n", encoding="utf-8")
            with self.assertRaises(module.B1RealError) as caught:
                module.verify_b1_real_evidence(output)
            self.assertEqual(
                caught.exception.code,
                module.B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
            )

    def test_b1_real_scanner_failure_zero_post(self):
        module = self.b1_real()
        b1_source = self.b1_source()
        original_scan = b1_source._scan_snapshot
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()

            def scanner_down(root):
                raise RuntimeError("scanner-down")

            b1_source._scan_snapshot = scanner_down
            try:
                transport = _FakeTransport()
                with self.assertRaises(module.B1RealError) as caught:
                    self.run_twin(output, transport=transport)
                self.assertEqual(
                    caught.exception.code,
                    module.B1RealErrorCode.B1_REAL_BINDING_MISMATCH,
                )
            finally:
                b1_source._scan_snapshot = original_scan
            # Zero POSTs: the scanner failure precedes the first POST.
            self.assertEqual(transport.chat_calls, 0)
            # The first cause is kept and the stop gate refused the rest.
            attempt0 = self.read_attempt(output, 0)
            self.assertEqual(attempt0["outcome"], "failure")
            for index in range(1, 5):
                self.assertEqual(
                    self.read_attempt(output, index)["error_code"],
                    "REAL_RUN_BATCH_STOPPED",
                )
            # No companion artifacts for an unbound suite.
            self.assertFalse((output / "b1-real-manifest.json").is_file())

    def test_b1_real_cold_side_failure_first_cause_kept(self):
        self.b1_real()
        scenarios = (
            ("transport_failed", OSError("boom"), "REAL_RUN_TRANSPORT_FAILED"),
            ("usage_missing", _chat_response(with_usage=False), "REAL_RUN_USAGE_MISSING"),
        )
        for name, failure, expected in scenarios:
            with self.subTest(face=name):
                with tempfile.TemporaryDirectory() as temporary:
                    output = pathlib.Path(temporary) / "run"
                    output.mkdir()
                    transport = _FakeTransport(responses=[failure])
                    result = self.run_twin(output, transport=transport)
                    self.assertEqual(transport.chat_calls, 1)
                    self.assertEqual(
                        self.read_attempt(output, 0)["error_code"], expected
                    )
                    for index in range(1, 5):
                        self.assertEqual(
                            self.read_attempt(output, index)["error_code"],
                            "REAL_RUN_BATCH_STOPPED",
                        )
                    # The companion carries the honest failure list.
                    manifest = self.companion_manifest(output)
                    self.assertTrue(manifest["failures"])
                    self.assertEqual(result.attempt_count, 5)

    def test_b1_real_warm_side_canary_and_response_failures(self):
        self.b1_real()
        # (a) The index-1 canary face: an unknown served form at attempt-0
        # fails the checklist's identity item and latches the batch.
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            transport = _FakeTransport(
                responses=[_chat_response(model=_UNKNOWN_MODEL_FORM)]
            )
            result = self.run_twin(output, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            self.assertEqual(
                self.read_attempt(output, 0)["error_code"],
                "REAL_RUN_RESPONSE_INVALID",
            )
            for index in range(1, 5):
                self.assertEqual(
                    self.read_attempt(output, index)["error_code"],
                    "REAL_RUN_CANARY_FAILED",
                )
        # (b) A warm response-contract failure after a passing canary: the
        # first failure keeps its code, the stop gate refuses the rest.
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            broken = _chat_response()
            broken["choices"][0]["message"]["content"] = json.dumps(
                {"unexpected": True}
            )
            transport = _FakeTransport(responses=[_chat_response(), broken])
            result = self.run_twin(output, transport=transport)
            self.assertEqual(transport.chat_calls, 2)
            self.assertEqual(result.canary_status, "passed")
            self.assertEqual(
                self.read_attempt(output, 1)["error_code"],
                "REAL_RUN_RESPONSE_INVALID",
            )
            for index in range(2, 5):
                self.assertEqual(
                    self.read_attempt(output, index)["error_code"],
                    "REAL_RUN_BATCH_STOPPED",
                )

    def test_b1_real_budget_deadline_refusal_and_cancellation(self):
        module = self.b1_real()
        # (a) The zero-budget twin: the first reserve refuses with the
        # frozen budget taxonomy, zero POSTs, and the entry's typed
        # terminal state (no scan, no companion).
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()

            def zero_budget(document):
                for level in ("per_run", "batch"):
                    for dimension in _B1_REAL_PER_RUN:
                        document["budget"][level][dimension] = 0

            transport = _FakeTransport()
            with self.assertRaises(module.B1RealError):
                self.run_twin(output, transport=transport, mutate=zero_budget)
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(
                self.read_attempt(output, 0)["error_code"], "RUN_BUDGET_EXCEEDED"
            )
            self.assertEqual(
                self.read_attempt(output, 0)["error_field_path"],
                "$.budget.per_run.calls",
            )
            self.assertFalse((output / "b1-real-manifest.json").is_file())
        # (b) The deadline refusal: an exhausted attempt window refuses
        # before the POST under the frozen timeout taxonomy (the stepping
        # clock puts every read past the per-attempt wall reservation).
        real_run = self.real_run()
        original_monotonic = real_run._monotonic
        real_run._monotonic = _SteppingClock()
        try:
            with tempfile.TemporaryDirectory() as temporary:
                output = pathlib.Path(temporary) / "run"
                output.mkdir()
                transport = _FakeTransport()
                with self.assertRaises(module.B1RealError):
                    self.run_twin(output, transport=transport)
                self.assertEqual(transport.chat_calls, 0)
                attempt0 = self.read_attempt(output, 0)
                self.assertEqual(attempt0["error_code"], "REAL_RUN_TRANSPORT_FAILED")
                self.assertEqual(attempt0["failure_code"], "EXECUTION_TIMEOUT")
        finally:
            real_run._monotonic = original_monotonic
        # (c) The cancellation face: a control-flow exception unwinds through
        # the frozen partial-evidence path and the entry never swallows it.
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            transport = _FakeTransport(responses=[KeyboardInterrupt("cancel")])
            with self.assertRaises(KeyboardInterrupt):
                self.run_twin(output, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            for name in (
                "approval.json",
                "ledger.json",
                "manifest.json",
                "machine_profile.json",
            ):
                self.assertTrue((output / name).is_file(), name)
            self.assertFalse((output / "b1-real-manifest.json").is_file())

    def test_b1_real_old_paths_never_enable_new_hooks(self):
        # The default-off proof on the frozen entry: an old key (the
        # eleventh) keeps the real-world payload report, writes no
        # companion artifacts, and its descriptor carries no binding field.
        real_run = self.real_run()
        catalog = real_run.REAL_RUN_ARTIFACT_FAMILY
        for key, descriptor in catalog.items():
            if key == _B1_REAL_KEY:
                continue
            with self.subTest(key=key):
                self.assertNotIn("workload", descriptor)
                self.assertNotIn("source_contract", descriptor)
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "run"
            output.mkdir()
            pilot = catalog[_REAL_PILOT_KEY]

            def pilot_bound(document):
                self.apply_synthetic_upstream(document, _REAL_PILOT_FIXTURE_KEY)
                document["approval_type"] = pilot["approval_type"]
                document["run_name"] = pilot["run_name"]
                document["date"] = pilot["date_pin"]
                document["pricing"]["retrieval_date"] = pilot["retrieval_date_pin"]

            artifact = self.write_b1_real_artifact(output, mutate=pilot_bound)
            transport = _FakeTransport()
            result = real_run.run_real_baseline_suite(
                artifact,
                _FAKE_KEY,
                output_root=output,
                spec_mapping=self.spec_mapping(),
                transport=transport,
                sources=self.fixed_sources(),
                artifact_key=_REAL_PILOT_KEY,
            )
            report = self.report_of(result)
            self.assertEqual(
                [source["kind"] for source in report["sources"]], ["real-world"]
            )
            self.assertEqual(transport.chat_calls, 5)
            self.assertFalse((output / "b1-real-manifest.json").is_file())
            self.assertFalse((output / "b1-real-attempts").exists())
            self.assertFalse((output / "b1-attempts").exists())


class TestB1RealOldPathAnchors(_B1RealTestCase):
    """Cluster 7: the frozen old-path anchors and the twelve-key mirrors."""

    def test_b1_real_old_entry_signature_and_all_frozen(self):
        module = self.real_run()
        parameters = inspect.signature(module.run_real_baseline_suite).parameters
        self.assertEqual(tuple(parameters), _ENTRY_PARAM_ORDER)
        self.assertEqual(
            {
                name
                for name, item in parameters.items()
                if item.kind is item.KEYWORD_ONLY
            },
            _ENTRY_KEYWORD_ONLY,
        )
        self.assertIsNone(parameters["transport"].default)
        self.assertEqual(parameters["timeout_seconds"].default, 120)
        self.assertIsNone(parameters["manifest_path"].default)
        self.assertIsNone(parameters["sources"].default)
        self.assertEqual(
            parameters["artifact_key"].default, "external/llamafactory-replay"
        )
        self.assertEqual(tuple(module.__all__), _REAL_RUN_ALL)

    def test_b1_real_static_surfaces_twelve_key_and_offline_contract(self):
        module = self.real_run()
        b1_source = self.b1_source()
        from benchmarks.v4.baseline import budget

        # The by-design group first (passes in the RED state too): the
        # locked gate (the frozen budget-module face), the frozen cap, the
        # closed error family, and the b1_source offline contract faces.
        self.assertIs(budget.REAL_RUN_GATE_UNLOCKED, False)
        self.assertEqual(module.CANDIDATE_FILE_CAP, _CANDIDATE_FILE_CAP)
        self.assertEqual(
            {code.value for code in module.RealRunErrorCode}, _FROZEN_ERROR_CODES
        )
        self.assertEqual(tuple(b1_source.__all__), _B1_SOURCE_ALL)
        # The twelve-key mirror group: RED before C3 adds the twelfth key
        # (the eleven-key catalog cannot satisfy the closed set).
        self.assertEqual(set(module.REAL_RUN_ARTIFACT_FAMILY), _ARTIFACT_FAMILY_KEYS)

    def test_b1_real_b1_source_offline_entry_unchanged(self):
        module = self.b1_source()
        parameters = inspect.signature(module.run_b1_source_baseline_suite).parameters
        self.assertEqual(tuple(parameters), _B1_SOURCE_PARAM_ORDER)
        self.assertTrue(
            all(item.kind is item.KEYWORD_ONLY for item in parameters.values())
        )
        self.assertTrue(callable(module.verify_b1_evidence))
        self.assertEqual(module.B1_WORKLOAD, "b1-offline-scanner-v1")
        self.assertEqual(module.CANDIDATE_FILE_CAP, _CANDIDATE_FILE_CAP)


class TestB1RealDiscipline(_B1RealTestCase):
    """Cluster 8: the packet-document probe and the PC1 source scan."""

    def test_b1_real_packet_doc_and_dockerfile_copy_line(self):
        packet = _REPO_ROOT / _PACKET_RELATIVE_PATH
        if not packet.is_file():
            self.fail(
                f"required deliverable document is missing: {_PACKET_RELATIVE_PATH}"
            )
        dockerfile = self.product_source(_DOCKERFILE_RELATIVE_PATH)
        self.assertIn(_PACKET_COPY_LINE, dockerfile)
        self.assertEqual(
            dockerfile.count("LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md"),
            1,
            "exactly one copy line references the IP-0041 packet",
        )

    def test_b1_real_sources_offline_and_secretless(self):
        # PC1 self-scan (passes by design): this file stays offline and
        # secretless.  The environment-read face is asserted through split
        # spellings so the scanned literals never match this source itself.
        env_read_face = "os." + "environ"
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))
        self.assertNotIn(env_read_face, own)
        # Product group (RED at the freeze on the absent module): the B1
        # real entry source gets the same offline/secretless discipline.
        path = _REPO_ROOT / _B1_REAL_RELATIVE_PATH
        if not path.is_file():
            self.fail("b1_real.py product source is missing (expected before C3)")
        source = path.read_text(encoding="utf-8")
        self.assertEqual(_import_roots(source) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(source))
        self.assertNotIn(env_read_face, source)


if __name__ == "__main__":
    unittest.main()
