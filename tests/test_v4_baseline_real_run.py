"""Frozen acceptance tests for IP-0032: gated real-run entry (limited, one-time).

Contract under test (frozen by Coordinator Assignment CA-IP-0032-v1.0 of
2026-09-27; see docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md):

- The Implementation deliverable is ``benchmarks/v4/baseline/real_run.py``: the
  minimal reviewed real-run entry ``run_real_baseline_suite`` that consumes the
  2026-09-27 Maintainer approval artifact (docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md,
  machine-readable json block), enforces every pre-call cap before the first real
  request (serialized request bytes <= 100,000 measured before send, max_tokens
  8000 explicit, exactly one model call per attempt, transport timeout, streaming
  download byte cap with partial-file deletion, two-phase safe extraction, usage
  and served-identity fail-closed), runs the fixed execution order (download the
  canonical fixed-commit tarball, cold canary, closed mechanical checklist, then
  at most nine follow-on attempts, 5 cold + 5 warm in total) through the frozen
  ``orchestrate.run_repeats`` behind the IP-0031 ``BudgetLedger`` with a
  process-in latch, and writes the real evidence set (approval byte copy, ledger,
  per-attempt summaries without raw content, manifest, machine profile) strictly
  after ``run_repeats`` returns into a one-time directory outside the repository.
- The approval artifact itself is a C1 deliverable: its field set is closed, its
  numbers are verbatim transcriptions of the Maintainer authorization constants
  (guarded here with derived assertions, PC3), it contains no secret, and its
  machine profile matches the frozen eight-field schema.
- The IP-0031 locked-gate face is untouched: ``REAL_RUN_GATE_UNLOCKED`` stays
  False and ``require_real_run_unlock`` keeps raising ``REAL_RUN_LOCKED``; no
  default path imports the real-run module; the module reads no environment.

Everything here is offline: the transport is always an injected fake (streaming
in-memory tarball for the GET, scripted chat responses for the POST), tarballs
are constructed inside the tests, artifacts are written into temp directories,
platform sources are injected, and no test ever touches a network socket.

Expected RED before implementation: the behavior tests fail on the missing
deliverable -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.real_run'``
(lazy per-test import). The tests whose deliverables already exist at C2 pass by
design and are recorded in the RED evidence: the four approval-artifact static
checks (a1-a4, C1 document), the locked-gate guard (h2, IP-0031 module), the
default-path import scan (h3, frozen sources), and the two budget-ledger probes
(g3 at-cap self-consistency, g4 injected-clock wall gate; the frozen IP-0031
ledger is the validator being probed, mirroring the IP-0031 n5 precedent).
"""

import ast
import copy
import dataclasses
import hashlib
import inspect
import io
import json
import math
import pathlib
import re
import tarfile
import tempfile
import unittest

from benchmarks.v4.baseline import budget as budget_module
from benchmarks.v4.baseline import collect, orchestrate, report
from benchmarks.v4.baseline import fixtures as fixtures_module
from benchmarks.v4.baseline.budget import (
    BudgetGateError,
    BudgetGateErrorCode,
    BudgetLedger,
    BudgetLimits,
    BudgetSpec,
    CallEstimate,
    Pricing,
)
from benchmarks.v4.baseline.offline_flow import OfflineSuiteResult
from benchmarks.v4.baseline.run import FROZEN_DATASET_BINDINGS, validate_role_bindings
from lima.baseline_run_result import BaselineRunResult
from lima.baseline_run_spec import (
    _MACHINE_PROFILE_ENUM_FIELDS,
    _MACHINE_PROFILE_FIELDS,
    _MACHINE_PROFILE_INT_FIELDS,
    validate_baseline_manifest,
)
from lima.baseline_run_spec import from_mapping as spec_from_mapping
from lima.contracts.codec import canonical_encode, compute_content_digest

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PACKET_RELATIVE_PATH = "docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md"
_APPROVAL_RELATIVE_PATH = "docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md"
_DOCKERFILE_RELATIVE_PATH = "Dockerfile"
_MODULE_RELATIVE_PATH = "benchmarks/v4/baseline/real_run.py"
_MANIFEST_RELATIVE_PATH = "evaluation_data/v4/baseline_manifest.json"

_FAKE_KEY = "test-key-do-not-use"
_BEARER_PREFIX = "Bear" + "er "
_RAW_CONTENT_MARKER = "raw-content-marker-7f3a"

# Frozen authorization constants (Maintainer 2026-09-27; transcription guard).
_AUTH_PER_RUN = {
    "cost_micro_usd": 100_000,
    "calls": 1,
    "prompt_tokens": 150_000,
    "completion_tokens": 8_000,
    "wall_ms": 1_200_000,
    "download_bytes": 250_000_000,
    "storage_bytes": 500_000_000,
}
_AUTH_BATCH_MULTIPLIERS = {
    "cost_micro_usd": 10,
    "calls": 10,
    "prompt_tokens": 10,
    "completion_tokens": 10,
    "wall_ms": 10,
    "download_bytes": 2,
    "storage_bytes": 4,
}
_AUTH_PRICES = (300_000, 1_200_000)
_COLD_COUNT = 5
_WARM_COUNT = 5
_ATTEMPT_TOTAL = _COLD_COUNT + _WARM_COUNT
_BASELINE_SHA = "888793f1a46db6924009e7ec33f9ff1b633f01fa"
_RUN_NAME = "pr3d-real-2026-09-27"
_AUTHORIZATION_DATE = "2026-09-27"
_REQUEST_MODEL = "deepseek-v4-flash"
_SERVED_MODEL = "DeepSeek-V4.1-Flash"
_BASE_URL = "https://api.deepseek.com"
_CANONICAL_REPOSITORY = "hiyouga/LlamaFactory"

# Frozen module caps (Packet 7.5/7.6).
_REQUEST_BYTE_CAP = 100_000
_MAX_CONTEXT_CHARS = 36_000
_CANDIDATE_CHAR_CAP = 6_000
_DOWNLOAD_CHUNK_BYTES = 1_048_576
_MEMBER_COUNT_CAP = 30_000
_MEMBER_BYTE_CAP = 50_000_000

# Frozen public surface of the real-run module (Packet 7.2/7.4/7.10).
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
)
_ENTRY_KEYWORD_ONLY = {
    "output_root",
    "spec_mapping",
    "transport",
    "timeout_seconds",
    "manifest_path",
    "sources",
}
_RESULT_FIELDS = (
    "run_name",
    "approval_digest",
    "run_spec_digest",
    "attempt_count",
    "status",
    "result_paths",
    "aggregate_path",
    "aggregate_sha256",
    "report_path",
    "report_sha256",
    "ledger_snapshot",
    "model",
    "system_fingerprint_baseline",
    "canary_status",
    "evidence_paths",
    "real_run",
)
_EVIDENCE_KEYS = {"approval", "ledger", "manifest", "machine_profile", "attempts"}
_CANARY_CHECK_KEYS = {
    "usage_within_reservation",
    "identity_matches",
    "attempt0_digest_verified",
    "batch_margin_positive",
    "canary_sample_success",
}
_APPROVAL_FIELDS = frozenset(
    {
        "schema_version",
        "approval_type",
        "run_name",
        "date",
        "authorized_by",
        "baseline_sha",
        "upstream",
        "model",
        "pricing",
        "budget",
        "machine_profile",
        "attempt_policy",
    }
)

_HEX64_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_RUN_NAME_PATTERN = re.compile(r"^[0-9a-f]{16}-run-[0-9]+\.json$")

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

_HAPPY_TOP = "LlamaFactory-7fcf5b3b130e5713b52415bb7404c476fada9c8c"

_V2_PAYLOAD_LITERAL = {
    "schema_version": 2,
    "mode": "llm-bounded-triage",
    "scanner_profile": "a" * 64,
    "metrics": {"cases": 1},
    "results": [
        {
            "deterministic": {
                "total_findings": {"bounded-candidate-files": 3},
                "workspace": {
                    "llamafactory-7fcf5b3": {
                        "files": 4,
                        "scanned": 3,
                        "skipped": {"unselected": 1},
                    }
                },
            }
        }
    ],
}

_TARBALL_CACHE: dict[str, bytes] = {}


def _chat_response(
    *,
    model=_REQUEST_MODEL,
    fingerprint="fp-stable-001",
    prompt_tokens=1_000,
    completion_tokens=500,
    with_usage=True,
    verdict_reason=_RAW_CONTENT_MARKER,
):
    """One scripted chat-completion response body (frozen response contract)."""
    content = json.dumps(
        {"is_vulnerable": False, "cwe": None, "path": None, "reason": verdict_reason}
    )
    body = {
        "id": "chatcmpl-fake",
        "object": "chat.completion",
        "created": 0,
        "model": model,
        "choices": [
            {"index": 0, "message": {"role": "assistant", "content": content},
             "finish_reason": "stop"}
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


def _happy_files():
    """Clean-tree arrange: 3 python candidates plus a README under one top dir."""
    return {
        f"{_HAPPY_TOP}/README.md": "# synthetic upstream readme\n",
        f"{_HAPPY_TOP}/src/alpha.py": "def alpha():\n    return 1\n",
        f"{_HAPPY_TOP}/src/beta.py": "def beta():\n    return 2\n",
        f"{_HAPPY_TOP}/src/gamma.py": "def gamma():\n    return 3\n",
    }


def _cjk_files():
    """Truncation-failure arrange: python files whose chars are mostly 3-byte."""
    files = {}
    for index in range(6):
        files[f"{_HAPPY_TOP}/src/cjk{index}.py"] = "# " + "注" * _CANDIDATE_CHAR_CAP + "\n"
    return files


def _build_tarball(files, symlinks=()):
    """Deterministic gz tarball from {member name: text content} plus symlinks."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", compresslevel=1) as archive:
        for name, content in sorted(files.items()):
            payload = content.encode("utf-8")
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
        for name, target in symlinks:
            info = tarfile.TarInfo(name)
            info.type = tarfile.SYMTYPE
            info.linkname = target
            archive.addfile(info)
    return buffer.getvalue()


def _happy_tarball():
    if "happy" not in _TARBALL_CACHE:
        _TARBALL_CACHE["happy"] = _build_tarball(_happy_files())
    return _TARBALL_CACHE["happy"]


def _cjk_tarball():
    if "cjk" not in _TARBALL_CACHE:
        _TARBALL_CACHE["cjk"] = _build_tarball(_cjk_files())
    return _TARBALL_CACHE["cjk"]


class _ZerosReader:
    """Endless zero-byte reader backing members with large declared sizes."""

    def read(self, size):
        return b"\x00" * size


def _big_declared_tarball(kind):
    """Heavy-header tarballs for the extraction cap faces (built once, cached)."""
    if kind in _TARBALL_CACHE:
        return _TARBALL_CACHE[kind]
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz", compresslevel=1) as archive:
        if kind == "member":
            info = tarfile.TarInfo("LlamaFactory-x/single.bin")
            info.size = _MEMBER_BYTE_CAP + 1
            archive.addfile(info, _ZerosReader())
        elif kind == "total":
            for index in range(11):
                info = tarfile.TarInfo(f"LlamaFactory-x/total{index:02d}.bin")
                info.size = _MEMBER_BYTE_CAP
                archive.addfile(info, _ZerosReader())
        elif kind == "count":
            payload = b"x"
            for index in range(_MEMBER_COUNT_CAP + 1):
                info = tarfile.TarInfo(f"LlamaFactory-x/tree/m{index:06d}.py")
                info.size = len(payload)
                archive.addfile(info, io.BytesIO(payload))
        else:  # pragma: no cover - arrange integrity
            raise AssertionError(f"unknown tarball kind: {kind}")
    _TARBALL_CACHE[kind] = buffer.getvalue()
    return _TARBALL_CACHE[kind]


class _UnboundedDownload:
    """GET stream that never ends; records how many bytes were pulled out."""

    def __init__(self):
        self.served = 0

    def read(self, size):
        self.served += size
        return b"\x00" * size


class _FakeTransport:
    """Injected transport double: streaming GET plus scripted chat POSTs."""

    def __init__(self, *, tarball=b"", responses=None, download_factory=None,
                 output_root=None):
        self.chat_calls = 0
        self.download_calls = 0
        self.chat_urls = []
        self.chat_payloads = []
        self.chat_headers = []
        self.chat_timeouts = []
        self.download_urls = []
        self.midwindow_top_names = []
        self._tarball = tarball
        self._responses = list(responses) if responses is not None else [_chat_response()]
        self._download_factory = download_factory
        self._output_root = output_root

    def __call__(self, url, payload, headers, timeout):
        if payload is None:
            self.download_calls += 1
            self.download_urls.append(url)
            if self._download_factory is not None:
                return self._download_factory()
            return io.BytesIO(self._tarball)
        self.chat_calls += 1
        self.chat_urls.append(url)
        self.chat_payloads.append(bytes(payload))
        self.chat_headers.append(dict(headers))
        self.chat_timeouts.append(timeout)
        if self._output_root is not None:
            self.midwindow_top_names.append(
                sorted(path.name for path in self._output_root.iterdir())
            )
        scheduled = self._responses[min(self.chat_calls - 1, len(self._responses) - 1)]
        if isinstance(scheduled, BaseException):
            raise scheduled
        return json.dumps(scheduled).encode("utf-8")


def _fixed_sources(durations_ms):
    """Injectable platform sources with fixed per-attempt wall/cpu durations."""
    durations = [value * 1_000_000 for value in durations_ms]
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


class _CountingExecute:
    """Execution body double that only records how often it was invoked."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return None


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


def _forbidden_network_roots():
    """First-level import roots these offline tests must never use themselves."""
    return {"sock" + "et", "url" + "lib", "requ" + "ests", "http"}


def _real_run_dotted_name():
    """The real-run module dotted name, assembled by concatenation (PC1)."""
    return "benchmarks.v4.baseline.real_" + "run"


def _imports_real_run(source):
    """True when the source imports the real-run module (AST, no exec)."""
    tree = ast.parse(source)
    target = _real_run_dotted_name()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == target:
                    return True
        elif isinstance(node, ast.ImportFrom) and node.module == target:
            return True
    return False


class _RealRunTestCase(unittest.TestCase):
    """Shared arrange helpers (no collected test methods)."""

    def real_run(self):
        import benchmarks.v4.baseline.real_run as real_run_module

        return real_run_module

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

    def canonical_tarball_url(self):
        registry = fixtures_module.load_registry()
        entry = next(
            item
            for item in registry["fixtures"]
            if item["key"] == "external/llamafactory-replay"
        )
        commit = entry["identity"]["commit_sha"]
        return f"https://codeload.github.com/{_CANONICAL_REPOSITORY}/tar.gz/{commit}"

    def write_artifact(self, directory, mutate=None):
        document = copy.deepcopy(self.load_repo_approval())
        if mutate is not None:
            mutate(document)
        body = json.dumps(document, ensure_ascii=False, indent=2)
        path = pathlib.Path(directory) / "approval.md"
        path.write_text(
            "# arrange approval\n\n```json\n" + body + "\n```\n", encoding="utf-8"
        )
        return path

    def load_manifest(self):
        path = _REPO_ROOT / _MANIFEST_RELATIVE_PATH
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
        return _fixed_sources([100] * _COLD_COUNT + [80] * _WARM_COUNT)

    def happy_transport(self, *, responses=None, output_root=None, tarball=None):
        return _FakeTransport(
            tarball=_happy_tarball() if tarball is None else tarball,
            responses=responses,
            output_root=output_root,
        )

    def run_entry(self, output_root, *, transport, artifact_path=None,
                  timeout_seconds=120):
        module = self.real_run()
        return module.run_real_baseline_suite(
            artifact_path or (_REPO_ROOT / _APPROVAL_RELATIVE_PATH),
            _FAKE_KEY,
            output_root=pathlib.Path(output_root),
            spec_mapping=self.spec_mapping(),
            transport=transport,
            timeout_seconds=timeout_seconds,
            sources=self.fixed_sources(),
        )

    def read_attempt(self, root, index):
        path = pathlib.Path(root) / "attempts" / f"attempt-{index:02d}.json"
        return json.loads(path.read_bytes().decode("utf-8"))

    def read_manifest(self, root):
        return json.loads(
            (pathlib.Path(root) / "manifest.json").read_bytes().decode("utf-8")
        )

    def error_code_sequence(self, root):
        return [self.read_attempt(root, index)["error_code"] for index in range(10)]


class TestApprovalArtifact(_RealRunTestCase):
    """FR-05 / AC-4: the C1 approval artifact exists, closed, transcribed, secretless."""

    def test_artifact_in_repo_with_closed_field_set_and_container_copy_line(self):
        packet = _REPO_ROOT / _PACKET_RELATIVE_PATH
        if not packet.is_file():
            self.fail(f"required deliverable document is missing: {_PACKET_RELATIVE_PATH}")
        document = self.load_repo_approval()
        self.assertEqual(set(document), _APPROVAL_FIELDS)
        dockerfile = self.product_source(_DOCKERFILE_RELATIVE_PATH)
        copy_line = (
            "COPY --chown=lima:lima docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md"
            " ./docs/"
        )
        self.assertIn(copy_line, dockerfile)

    def test_authorized_numbers_match_maintainer_constants(self):
        document = self.load_repo_approval()
        per_run = document["budget"]["per_run"]
        batch = document["budget"]["batch"]
        self.assertEqual(set(per_run), set(_AUTH_PER_RUN))
        for dimension, value in _AUTH_PER_RUN.items():
            self.assertEqual(per_run[dimension], value)
            self.assertEqual(
                batch[dimension], value * _AUTH_BATCH_MULTIPLIERS[dimension]
            )
        self.assertEqual(
            document["pricing"]["prompt_token_price_micro_usd_per_million"],
            _AUTH_PRICES[0],
        )
        self.assertEqual(
            document["pricing"]["completion_token_price_micro_usd_per_million"],
            _AUTH_PRICES[1],
        )
        self.assertEqual(document["schema_version"], 1)
        self.assertEqual(document["approval_type"], "PR3D-REAL-RUN-LIMITED")
        self.assertEqual(document["run_name"], _RUN_NAME)
        self.assertEqual(document["date"], _AUTHORIZATION_DATE)
        self.assertEqual(document["authorized_by"], "Maintainer")
        self.assertEqual(document["baseline_sha"], _BASELINE_SHA)
        self.assertEqual(document["upstream"]["repository"], _CANONICAL_REPOSITORY)
        self.assertEqual(
            document["upstream"]["commit_sha"],
            self.canonical_tarball_url().rsplit("/", 1)[1],
        )
        self.assertEqual(document["upstream"]["tarball_url"], self.canonical_tarball_url())
        self.assertEqual(document["model"]["request_name"], _REQUEST_MODEL)
        self.assertEqual(document["model"]["served_as"], _SERVED_MODEL)
        self.assertEqual(document["model"]["base_url"], _BASE_URL)
        policy = document["attempt_policy"]
        self.assertEqual(policy["cold"], _COLD_COUNT)
        self.assertEqual(policy["warm"], _WARM_COUNT)
        self.assertEqual(policy["max_attempts"], _ATTEMPT_TOTAL)
        self.assertIs(policy["canary_required"], True)
        self.assertEqual(policy["canary_first_attempt"], 0)
        # F11 self-consistency, derived (PC3): the caps admit exactly ten worst-case
        # calls, with the completion and wall batch caps reached exactly at-cap.
        worst_call = (
            math.ceil(_AUTH_PRICES[0] * _REQUEST_BYTE_CAP / 1_000_000)
            + math.ceil(_AUTH_PRICES[1] * per_run["completion_tokens"] / 1_000_000)
        )
        self.assertLessEqual(worst_call, per_run["cost_micro_usd"])
        self.assertLessEqual(worst_call * _ATTEMPT_TOTAL, batch["cost_micro_usd"])
        self.assertEqual(
            per_run["completion_tokens"] * _ATTEMPT_TOTAL, batch["completion_tokens"]
        )
        self.assertEqual(per_run["wall_ms"] * _ATTEMPT_TOTAL, batch["wall_ms"])

    def test_approval_artifact_contains_no_secrets(self):
        key_shape = re.compile(r"\bsk-[A-Za-z0-9]{16,}")
        env_name = "LIMA_" + "DEEPSEEK_" + "API" + "_KEY"
        api_word = "API_" + "KEY"
        bearer_word = "Bear" + "er "
        self.assertIsNotNone(key_shape.search("sk-" + "abcdefghij123456"))
        self.assertIn(env_name, "export " + env_name + "=...")
        self.assertIn(api_word, "the " + api_word + " value")
        self.assertIn(bearer_word, "header " + bearer_word + "xyz")
        own_source = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertIsNone(key_shape.search(own_source))
        self.assertNotIn(env_name, own_source)
        self.assertNotIn(api_word, own_source)
        self.assertNotIn(bearer_word, own_source)
        text = (_REPO_ROOT / _APPROVAL_RELATIVE_PATH).read_text(encoding="utf-8")
        self.assertIsNone(key_shape.search(text))
        self.assertNotIn(env_name, text)
        self.assertNotIn(api_word, text)
        self.assertNotIn(bearer_word, text)

    def test_machine_profile_has_frozen_fields_and_enums(self):
        profile = self.load_repo_approval()["machine_profile"]
        self.assertEqual(set(profile), set(_MACHINE_PROFILE_FIELDS))
        self.assertEqual(
            profile["cpu_arch"] in _MACHINE_PROFILE_ENUM_FIELDS["cpu_arch"], True
        )
        self.assertEqual(
            profile["os_family"] in _MACHINE_PROFILE_ENUM_FIELDS["os_family"], True
        )
        for field in _MACHINE_PROFILE_INT_FIELDS:
            self.assertIsInstance(profile[field], int)
        for field in ("profile_id", "cpu_model", "python_version", "gpu_summary"):
            self.assertIsInstance(profile[field], str)
            self.assertTrue(profile[field])


class TestRealRunEntryValidation(_RealRunTestCase):
    """FR-01 / AC-2: fail-closed entry validation of the approval and output root."""

    def test_missing_unreadable_or_malformed_artifact_rejected(self):
        module = self.real_run()
        with tempfile.TemporaryDirectory() as directory:
            bad_json = pathlib.Path(directory) / "broken.md"
            bad_json.write_text("# x\n\n```json\n{not json\n```\n", encoding="utf-8")
            bad_bytes = pathlib.Path(directory) / "binary.md"
            bad_bytes.write_bytes(b"\xff\xfe\x00bad")
            cases = [
                pathlib.Path(directory) / "absent.md",
                bad_json,
                bad_bytes,
            ]
            for approval in cases:
                with self.subTest(approval=approval.name):
                    with self.assertRaises(module.RealRunError) as caught:
                        module.run_real_baseline_suite(
                            approval,
                            _FAKE_KEY,
                            output_root=pathlib.Path(directory) / "out",
                            spec_mapping=self.spec_mapping(),
                            transport=self.happy_transport(),
                        )
                    self.assertEqual(
                        caught.exception.code,
                        module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(caught.exception.field_path, "$.approval_artifact")

    def test_field_missing_type_or_identity_drift_rejected(self):
        module = self.real_run()

        def drop_date(document):
            document.pop("date")

        def drift_schema_version(document):
            document["schema_version"] = 2

        def wrong_budget_type(document):
            document["budget"] = "not-a-mapping"

        def unknown_field(document):
            document["extra"] = 1

        def drift_attempt_policy(document):
            document["attempt_policy"]["max_attempts"] = _ATTEMPT_TOTAL - 1

        def drift_baseline(document):
            document["baseline_sha"] = "0" * 40

        cases = [
            (drop_date, "$.date"),
            (drift_schema_version, "$.schema_version"),
            (wrong_budget_type, "$.budget"),
            (unknown_field, "$"),
            (drift_attempt_policy, "$.attempt_policy.max_attempts"),
            (drift_baseline, "$.baseline_sha"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for mutate, field_path in cases:
                with self.subTest(field_path=field_path):
                    approval = self.write_artifact(directory, mutate)
                    with self.assertRaises(module.RealRunError) as caught:
                        self.run_entry(
                            pathlib.Path(directory) / "out",
                            transport=self.happy_transport(),
                            artifact_path=approval,
                        )
                    self.assertEqual(
                        caught.exception.code,
                        module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(caught.exception.field_path, field_path)

    def test_inconsistent_budget_passes_budget_spec_error_through(self):
        module = self.real_run()

        def shrink_batch_completion(document):
            document["budget"]["batch"]["completion_tokens"] = (
                document["budget"]["per_run"]["completion_tokens"] - 1
            )

        with tempfile.TemporaryDirectory() as directory:
            approval = self.write_artifact(directory, shrink_batch_completion)
            with self.assertRaises(BudgetGateError) as caught:
                self.run_entry(
                    pathlib.Path(directory) / "out",
                    transport=self.happy_transport(),
                    artifact_path=approval,
                )
            self.assertEqual(caught.exception.code, BudgetGateErrorCode.BUDGET_SPEC_INVALID)
            self.assertEqual(
                caught.exception.field_path, "$.budget.batch.completion_tokens"
            )
            self.assertNotIsInstance(caught.exception, module.RealRunError)

    def test_pricing_zero_none_or_drift_rejected(self):
        module = self.real_run()

        def zero_prompt(document):
            document["pricing"]["prompt_token_price_micro_usd_per_million"] = 0

        def null_completion(document):
            document["pricing"]["completion_token_price_micro_usd_per_million"] = None

        def drift_prompt(document):
            document["pricing"]["prompt_token_price_micro_usd_per_million"] = (
                _AUTH_PRICES[0] + 100_000
            )

        cases = [
            (zero_prompt, "$.pricing.prompt_token_price_micro_usd_per_million"),
            (null_completion, "$.pricing.completion_token_price_micro_usd_per_million"),
            (drift_prompt, "$.pricing.prompt_token_price_micro_usd_per_million"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            for mutate, field_path in cases:
                with self.subTest(field_path=field_path):
                    approval = self.write_artifact(directory, mutate)
                    with self.assertRaises(module.RealRunError) as caught:
                        self.run_entry(
                            pathlib.Path(directory) / "out",
                            transport=self.happy_transport(),
                            artifact_path=approval,
                        )
                    self.assertEqual(
                        caught.exception.code,
                        module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(caught.exception.field_path, field_path)

    def test_non_empty_output_root_rejected_and_empty_root_allowed(self):
        module = self.real_run()
        with tempfile.TemporaryDirectory() as directory:
            stale = pathlib.Path(directory) / "used"
            stale.mkdir()
            (stale / "stale.txt").write_text("leftover\n", encoding="utf-8")
            with self.assertRaises(module.RealRunError) as caught:
                self.run_entry(stale, transport=self.happy_transport())
            self.assertEqual(
                caught.exception.code, module.RealRunErrorCode.REAL_RUN_OUTPUT_NOT_EMPTY
            )
            self.assertEqual(caught.exception.field_path, "$.output_root")

            empty = pathlib.Path(directory) / "fresh"
            empty.mkdir()
            result = self.run_entry(empty, transport=self.happy_transport())
            self.assertEqual(result.attempt_count, _ATTEMPT_TOTAL)


class TestRequestBoundaries(_RealRunTestCase):
    """FR-02 / AC-2: the request-side caps are enforced before any send."""

    def test_oversized_context_rejected_before_any_model_call(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(tarball=_cjk_tarball())
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(result.status, "insufficient_sample")
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[0], "REAL_RUN_REQUEST_TOO_LARGE")
            self.assertEqual(set(codes[1:]), {"REAL_RUN_CANARY_FAILED"})
            for index in range(_ATTEMPT_TOTAL):
                self.assertEqual(
                    self.read_attempt(directory, index)["failure_code"],
                    "EXECUTION_ERROR",
                )

    def test_request_body_shape_and_byte_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(
                transport.chat_urls, [f"{_BASE_URL}/chat/completions"] * _ATTEMPT_TOTAL
            )
            self.assertEqual(
                transport.download_urls, [self.canonical_tarball_url()]
            )
            for headers, timeout in zip(
                transport.chat_headers, transport.chat_timeouts, strict=True
            ):
                self.assertEqual(set(headers), {"Authorization", "Content-Type"})
                self.assertEqual(headers["Authorization"], _BEARER_PREFIX + _FAKE_KEY)
                self.assertEqual(timeout, 120)
            first = json.loads(transport.chat_payloads[0])
            self.assertEqual(len(first["messages"]), 2)
            self.assertEqual([item["role"] for item in first["messages"]],
                             ["system", "user"])
            self.assertEqual(first["model"], _REQUEST_MODEL)
            self.assertEqual(first["temperature"], 0)
            self.assertEqual(
                first["max_tokens"], _AUTH_PER_RUN["completion_tokens"]
            )
            self.assertEqual(first["response_format"], {"type": "json_object"})
            self.assertEqual(first["thinking"], {"type": "disabled"})
            for payload in transport.chat_payloads:
                self.assertLessEqual(len(payload), _REQUEST_BYTE_CAP)
            self.assertEqual(len(set(transport.chat_payloads)), 1)

    def test_exactly_one_call_per_attempt_and_timeout_taxonomy(self):
        with tempfile.TemporaryDirectory() as directory:
            responses = [
                _chat_response(),
                _chat_response(),
                TimeoutError("synthetic-transport-timeout"),
                _chat_response(),
            ]
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            attempt2 = self.read_attempt(directory, 2)
            self.assertEqual(attempt2["failure_code"], "EXECUTION_TIMEOUT")
            self.assertEqual(attempt2["error_code"], "REAL_RUN_TRANSPORT_FAILED")
            outcomes = [
                self.read_attempt(directory, index)["outcome"]
                for index in range(_ATTEMPT_TOTAL)
            ]
            self.assertEqual(outcomes.count("timeout"), 1)
            self.assertEqual(outcomes.count("success"), _ATTEMPT_TOTAL - 1)


class TestDownloadAndExtraction(_RealRunTestCase):
    """FR-02 / AC-2: streaming download cap and two-phase safe extraction."""

    def test_streaming_download_over_cap_aborts_and_deletes_partial(self):
        stream = _UnboundedDownload()
        with tempfile.TemporaryDirectory() as directory:
            transport = _FakeTransport(
                download_factory=lambda: stream, responses=[_chat_response()]
            )
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(transport.chat_calls, 0)
            self.assertLessEqual(
                stream.served, _AUTH_PER_RUN["download_bytes"] + 2 * _DOWNLOAD_CHUNK_BYTES
            )
            leftovers = list((pathlib.Path(directory) / "_materialized").rglob("*.gz"))
            self.assertEqual(leftovers, [])
            self.assertEqual(result.status, "insufficient_sample")
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[0], "REAL_RUN_DOWNLOAD_EXCEEDED")
            self.assertEqual(set(codes[1:]), {"REAL_RUN_CANARY_FAILED"})

    def test_absolute_path_member_rejected(self):
        members = {
            "/etc/lima-evil.txt": "evil\n",
            f"{_HAPPY_TOP}/src/ok.py": "def ok():\n    return 1\n",
        }
        self._assert_archive_unsafe(_build_tarball(members))

    def test_parent_escape_member_rejected(self):
        members = {
            "pkg/../../evil.txt": "evil\n",
            f"{_HAPPY_TOP}/src/ok.py": "def ok():\n    return 1\n",
        }
        self._assert_archive_unsafe(_build_tarball(members))

    def test_symlink_member_skipped_not_materialized(self):
        top = _HAPPY_TOP
        tarball = _build_tarball(
            {
                f"{top}/README.md": "# readme\n",
                f"{top}/src/real.py": "def real():\n    return 1\n",
            },
            symlinks=[(f"{top}/src/link.py", "/etc/lima-evil-target")],
        )
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(tarball=tarball)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            links = list((pathlib.Path(directory) / "_materialized").rglob("link.py"))
            self.assertEqual(links, [])
            self.assertFalse(pathlib.Path("/etc/lima-evil-target").exists())

    def test_member_count_byte_caps_and_top_level_uniqueness(self):
        two_top_dirs = _build_tarball(
            {"dirA/x.py": "x\n", "dirB/y.py": "y\n"}
        )
        cases = {
            "member-count": _big_declared_tarball("count"),
            "member-bytes": _big_declared_tarball("member"),
            "total-bytes": _big_declared_tarball("total"),
            "two-top-dirs": two_top_dirs,
        }
        for label, tarball in cases.items():
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as directory:
                    transport = self.happy_transport(tarball=tarball)
                    result = self.run_entry(directory, transport=transport)
                    self.assertEqual(transport.download_calls, 1)
                    self.assertEqual(transport.chat_calls, 0)
                    self.assertEqual(
                        self.read_attempt(directory, 0)["error_code"],
                        "REAL_RUN_ARCHIVE_UNSAFE",
                    )
                    self.assertEqual(result.status, "insufficient_sample")
                    self.assertEqual(
                        set(self.error_code_sequence(directory)[1:]),
                        {"REAL_RUN_CANARY_FAILED"},
                    )

    def _assert_archive_unsafe(self, tarball):
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(tarball=tarball)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(
                self.read_attempt(directory, 0)["error_code"], "REAL_RUN_ARCHIVE_UNSAFE"
            )
            self.assertEqual(result.status, "insufficient_sample")
            self.assertEqual(
                set(self.error_code_sequence(directory)[1:]), {"REAL_RUN_CANARY_FAILED"}
            )


class TestUsageAndIdentity(_RealRunTestCase):
    """FR-02 / AC-2: usage reconciliation and served-identity fail-closed."""

    def test_missing_usage_is_violation_with_reservation_released(self):
        # DR-1 fixture correction (re-freeze v2): only the second call may lack
        # usage; the remaining eight responses stay healthy (Packet 9 u1 row),
        # because the fake repeats its last scheduled entry once the list is
        # exhausted.
        responses = [_chat_response()]
        responses.append(_chat_response(with_usage=False))
        responses.extend(_chat_response() for _ in range(8))
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            self.assertEqual(result.ledger_snapshot.violations, 1)
            for book in ("reserved",):
                self.assertEqual(
                    set(result.ledger_snapshot.batch[book].values()), {0}
                )
            attempt1 = self.read_attempt(directory, 1)
            self.assertEqual(attempt1["failure_code"], "EXECUTION_ERROR")
            self.assertEqual(attempt1["error_code"], "REAL_RUN_USAGE_MISSING")

    def test_identity_change_latches_with_zero_follow_on_calls(self):
        responses = [
            _chat_response(fingerprint="fp-alpha"),
            _chat_response(fingerprint="fp-beta"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 2)
            self.assertEqual(result.canary_status, "passed")
            self.assertEqual(result.status, "insufficient_sample")
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[1], "REAL_RUN_IDENTITY_CHANGED")
            self.assertEqual(set(codes[2:]), {"REAL_RUN_CANARY_FAILED"})

    def test_canary_model_mismatch_rejected(self):
        responses = [_chat_response(model="deepseek-v9-ultra")]
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            self.assertEqual(
                self.read_attempt(directory, 0)["error_code"],
                "REAL_RUN_RESPONSE_INVALID",
            )
            manifest = self.read_manifest(directory)
            self.assertIs(manifest["canary"]["checks"]["identity_matches"], False)
            self.assertEqual(
                set(self.error_code_sequence(directory)[1:]), {"REAL_RUN_CANARY_FAILED"}
            )

    def test_usage_consumed_matches_fake_response_values(self):
        prompts = [1_000 + 7 * index for index in range(_ATTEMPT_TOTAL)]
        completions = [500 + 3 * index for index in range(_ATTEMPT_TOTAL)]
        responses = [
            _chat_response(prompt_tokens=p, completion_tokens=c)
            for p, c in zip(prompts, completions, strict=True)
        ]
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            consumed = result.ledger_snapshot.batch["consumed"]
            self.assertEqual(consumed["prompt_tokens"], sum(prompts))
            self.assertEqual(consumed["completion_tokens"], sum(completions))
            expected_cost = sum(
                math.ceil(_AUTH_PRICES[0] * p / 1_000_000)
                + math.ceil(_AUTH_PRICES[1] * c / 1_000_000)
                for p, c in zip(prompts, completions, strict=True)
            )
            self.assertEqual(consumed["cost_micro_usd"], expected_cost)
            self.assertEqual(consumed["download_bytes"], len(_happy_tarball()))
            expected_storage = sum(
                len(content.encode("utf-8")) for content in _happy_files().values()
            )
            self.assertEqual(consumed["storage_bytes"], expected_storage)
            self.assertEqual(result.ledger_snapshot.batch["calls"], _ATTEMPT_TOTAL)
            self.assertEqual(result.ledger_snapshot.violations, 0)


class TestCanaryProtocol(_RealRunTestCase):
    """FR-03 / AC-3: checklist pass continues, any failure latches the batch."""

    def test_canary_pass_continues_to_ten_attempts(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(output_root=pathlib.Path(directory))
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.attempt_count, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            self.assertEqual(result.canary_status, "passed")
            self.assertEqual(result.ledger_snapshot.batch["calls"], _ATTEMPT_TOTAL)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["canary"]["status"], "passed")
            self.assertEqual(set(manifest["canary"]["checks"]), _CANARY_CHECK_KEYS)
            self.assertEqual(set(manifest["canary"]["checks"].values()), {True})
            self.assertEqual(manifest["cold_count"], _COLD_COUNT)
            self.assertEqual(manifest["warm_count"], _WARM_COUNT)

    def test_canary_usage_over_reservation_latches_with_nine_errors(self):
        responses = [_chat_response(prompt_tokens=_REQUEST_BYTE_CAP * 2)]
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.status, "insufficient_sample")
            self.assertEqual(result.canary_status, "failed")
            canary = self.read_attempt(directory, 0)
            self.assertEqual(canary["outcome"], "success")
            self.assertIsNone(canary["failure_code"])
            manifest = self.read_manifest(directory)
            self.assertIs(manifest["canary"]["checks"]["usage_within_reservation"], False)
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[1:], ["REAL_RUN_CANARY_FAILED"] * 9)
            self.assertEqual(
                result.ledger_snapshot.batch["consumed"]["prompt_tokens"],
                _REQUEST_BYTE_CAP * 2,
            )

    def test_canary_batch_margin_check_trips_latch(self):
        def tighten_prompt(document):
            document["budget"]["per_run"]["prompt_tokens"] = _REQUEST_BYTE_CAP
            document["budget"]["batch"]["prompt_tokens"] = _REQUEST_BYTE_CAP

        responses = [_chat_response(prompt_tokens=_REQUEST_BYTE_CAP)]
        with tempfile.TemporaryDirectory() as directory:
            approval = self.write_artifact(directory, tighten_prompt)
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(
                directory, transport=transport, artifact_path=approval
            )
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            manifest = self.read_manifest(directory)
            checks = manifest["canary"]["checks"]
            self.assertIs(checks["batch_margin_positive"], False)
            self.assertIs(checks["usage_within_reservation"], True)
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[1:], ["REAL_RUN_CANARY_FAILED"] * 9)


class TestBudgetIntegration(_RealRunTestCase):
    """FR-02 / AC-2: the seven-dimension caps gate every guarded call."""

    def test_zero_budget_refuses_before_invoke_and_arrange_validators(self):
        manifest = self.load_manifest()
        mapping = self.spec_mapping()
        spec_object = spec_from_mapping(mapping)
        validate_baseline_manifest(manifest, spec_object)
        validate_role_bindings(spec_object, manifest)
        self.assertEqual(len(manifest["datasets"]), len(FROZEN_DATASET_BINDINGS))
        with tempfile.TemporaryDirectory() as probe:
            execute = _CountingExecute()
            summary = orchestrate.run_repeats(
                mapping,
                manifest,
                execute,
                probe,
                repeat=_COLD_COUNT,
                sources=self.fixed_sources(),
            )
            self.assertEqual(execute.calls, _ATTEMPT_TOTAL)
            built = report.build_baseline_report(summary, _V2_PAYLOAD_LITERAL)
            document = built.to_canonical_value()
            self.assertEqual(
                document["compression_chain"]["raw_candidates"],
                sum(
                    _V2_PAYLOAD_LITERAL["results"][0]["deterministic"][
                        "total_findings"
                    ].values()
                ),
            )
            self.assertEqual(
                document["counts"]["scanned_files"]["value"],
                _V2_PAYLOAD_LITERAL["results"][0]["deterministic"]["workspace"][
                    "llamafactory-7fcf5b3"
                ]["files"],
            )

        def zero_budget(document):
            for level in ("per_run", "batch"):
                for dimension in _AUTH_PER_RUN:
                    document["budget"][level][dimension] = 0

        with tempfile.TemporaryDirectory() as directory:
            approval = self.write_artifact(directory, zero_budget)
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport, artifact_path=approval)
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(transport.download_calls, 0)
            self.assertEqual(result.status, "insufficient_sample")
            canary = self.read_attempt(directory, 0)
            self.assertEqual(canary["failure_code"], "EXECUTION_ERROR")
            self.assertEqual(canary["error_code"], "RUN_BUDGET_EXCEEDED")
            self.assertEqual(
                canary["error_field_path"], "$.budget.per_run.calls"
            )
            self.assertEqual(
                set(self.error_code_sequence(directory)[1:]), {"REAL_RUN_CANARY_FAILED"}
            )
            self.assertEqual(result.ledger_snapshot.batch["calls"], 0)

    def test_per_dimension_overlimit_refused_before_invoke(self):
        worst_call = (
            math.ceil(_AUTH_PRICES[0] * _REQUEST_BYTE_CAP / 1_000_000)
            + math.ceil(_AUTH_PRICES[1] * _AUTH_PER_RUN["completion_tokens"] / 1_000_000)
        )
        cases = {}

        def shrink_cost(document):
            document["budget"]["per_run"]["cost_micro_usd"] = worst_call - 1

        cases["cost_micro_usd"] = (
            shrink_cost,
            "$.budget.per_run.cost_micro_usd",
        )

        def zero_calls(document):
            document["budget"]["per_run"]["calls"] = 0

        cases["calls"] = (zero_calls, "$.budget.per_run.calls")

        def shrink_download(document):
            document["budget"]["per_run"]["download_bytes"] = (
                _AUTH_PER_RUN["download_bytes"] - 1
            )

        cases["download_bytes"] = (
            shrink_download,
            "$.budget.per_run.download_bytes",
        )
        for dimension, (mutate, field_path) in cases.items():
            with self.subTest(dimension=dimension):
                with tempfile.TemporaryDirectory() as directory:
                    approval = self.write_artifact(directory, mutate)
                    transport = self.happy_transport()
                    result = self.run_entry(
                        directory, transport=transport, artifact_path=approval
                    )
                    self.assertEqual(transport.chat_calls, 0)
                    self.assertEqual(transport.download_calls, 0)
                    self.assertEqual(result.status, "insufficient_sample")
                    canary = self.read_attempt(directory, 0)
                    self.assertEqual(canary["error_code"], "RUN_BUDGET_EXCEEDED")
                    self.assertEqual(canary["error_field_path"], field_path)

    def test_ten_reserves_pass_and_eleventh_refused_at_cap(self):
        per_run = BudgetLimits(**_AUTH_PER_RUN)
        batch = BudgetLimits(
            **{
                dimension: value * _AUTH_BATCH_MULTIPLIERS[dimension]
                for dimension, value in _AUTH_PER_RUN.items()
            }
        )
        ledger = BudgetLedger(
            BudgetSpec(per_run=per_run, batch=batch),
            Pricing(
                prompt_token_price_micro_usd_per_million=_AUTH_PRICES[0],
                completion_token_price_micro_usd_per_million=_AUTH_PRICES[1],
            ),
        )
        canary_estimate = CallEstimate(
            prompt_tokens=_REQUEST_BYTE_CAP,
            completion_tokens=_AUTH_PER_RUN["completion_tokens"],
            wall_ms=_AUTH_PER_RUN["wall_ms"],
            download_bytes=_AUTH_PER_RUN["download_bytes"],
            storage_bytes=_AUTH_PER_RUN["storage_bytes"],
        )
        follow_on_estimate = CallEstimate(
            prompt_tokens=_REQUEST_BYTE_CAP,
            completion_tokens=_AUTH_PER_RUN["completion_tokens"],
            wall_ms=_AUTH_PER_RUN["wall_ms"],
        )
        ledger.reserve("attempt-0", canary_estimate)
        for index in range(1, _ATTEMPT_TOTAL):
            ledger.reserve(f"attempt-{index}", follow_on_estimate)
        with self.assertRaises(BudgetGateError) as caught:
            ledger.reserve("attempt-extra", follow_on_estimate)
        self.assertEqual(caught.exception.code, BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED)
        self.assertEqual(caught.exception.field_path, "$.budget.batch.calls")
        snapshot = ledger.snapshot()
        self.assertEqual(snapshot.batch["calls"], _ATTEMPT_TOTAL)
        self.assertEqual(
            snapshot.batch["reserved"]["completion_tokens"],
            _AUTH_PER_RUN["completion_tokens"] * _ATTEMPT_TOTAL,
        )

    def test_injected_clock_wall_gate_refuses(self):
        per_run = BudgetLimits(**_AUTH_PER_RUN)
        batch = BudgetLimits(
            **{
                dimension: value * _AUTH_BATCH_MULTIPLIERS[dimension]
                for dimension, value in _AUTH_PER_RUN.items()
            }
        )
        start_ns = 1_000_000_000_000
        clock = iter(
            [start_ns, start_ns + _AUTH_PER_RUN["wall_ms"] * 1_000_000]
        )
        ledger = BudgetLedger(
            BudgetSpec(per_run=per_run, batch=batch),
            Pricing(
                prompt_token_price_micro_usd_per_million=_AUTH_PRICES[0],
                completion_token_price_micro_usd_per_million=_AUTH_PRICES[1],
            ),
            now_ns=lambda: next(clock),
        )
        estimate = CallEstimate(
            prompt_tokens=_REQUEST_BYTE_CAP,
            completion_tokens=_AUTH_PER_RUN["completion_tokens"],
        )
        with self.assertRaises(BudgetGateError) as caught:
            ledger.reserve("attempt-0", estimate)
        self.assertEqual(caught.exception.code, BudgetGateErrorCode.RUN_BUDGET_EXCEEDED)
        self.assertEqual(caught.exception.field_path, "$.budget.per_run.wall_ms")


class TestRealSuiteResultAndEvidence(_RealRunTestCase):
    """FR-04 / AC-3 / AC-4: evidence timing, secretlessness, and digests."""

    def test_evidence_written_after_run_repeats_window(self):
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            transport = self.happy_transport(output_root=root)
            result = self.run_entry(directory, transport=transport)
            self.assertTrue(transport.midwindow_top_names)
            for names in transport.midwindow_top_names:
                for name in names:
                    self.assertTrue(
                        name == "_materialized" or _RUN_NAME_PATTERN.match(name),
                        f"unexpected in-window top-level name: {name}",
                    )
            digest16 = result.run_spec_digest[:16]
            names_after = sorted(path.name for path in root.iterdir())
            expected_after = sorted(
                ["_materialized", "attempts", "approval.json", "ledger.json",
                 "manifest.json", "machine_profile.json", f"{digest16}-report-1.json"]
                + [f"{digest16}-run-{n}.json" for n in range(1, _ATTEMPT_TOTAL + 2)]
            )
            self.assertEqual(names_after, expected_after)
            attempt_files = sorted(
                path.name for path in (root / "attempts").glob("attempt-*.json")
            )
            self.assertEqual(
                attempt_files,
                [f"attempt-{index:02d}.json" for index in range(_ATTEMPT_TOTAL)],
            )
            self.assertEqual(
                [path.name for path in result.result_paths],
                [f"{digest16}-run-{n}.json" for n in range(1, _ATTEMPT_TOTAL + 1)],
            )
            self.assertEqual(
                result.aggregate_path.name, f"{digest16}-run-{_ATTEMPT_TOTAL + 1}.json"
            )

    def test_evidence_chain_free_of_key_and_raw_content(self):
        self.assertIn(_RAW_CONTENT_MARKER, json.dumps(_chat_response()))
        self.assertIn(_BEARER_PREFIX, _BEARER_PREFIX + _FAKE_KEY)
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            self.run_entry(directory, transport=transport)
            self.assertIn(_FAKE_KEY, transport.chat_headers[0]["Authorization"])
            offenders = []
            for path in sorted(pathlib.Path(directory).rglob("*")):
                if not path.is_file():
                    continue
                data = path.read_bytes()
                if _FAKE_KEY.encode("utf-8") in data:
                    offenders.append((path.name, "api-key"))
                if _RAW_CONTENT_MARKER.encode("utf-8") in data:
                    offenders.append((path.name, "raw-content"))
            self.assertEqual(offenders, [])

    def test_ledger_evidence_matches_snapshot(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport)
            raw = (pathlib.Path(directory) / "ledger.json").read_bytes()
            document = json.loads(raw.decode("utf-8"))
            snapshot = result.ledger_snapshot
            self.assertEqual(document["per_run"], snapshot.per_run)
            self.assertEqual(document["batch"], snapshot.batch)
            self.assertEqual(document["violations"], snapshot.violations)
            triple = {
                "per_run": snapshot.per_run,
                "batch": snapshot.batch,
                "violations": snapshot.violations,
            }
            self.assertEqual(
                document["budget_ledger_digest"], compute_content_digest(triple)
            )
            self.assertEqual(raw, canonical_encode(document))
            self.assertTrue(_HEX64_PATTERN.match(document["budget_ledger_digest"]))

    def test_real_suite_result_fields_and_digests(self):
        module = self.real_run()
        self.assertEqual(tuple(module.__all__), _REAL_RUN_ALL)
        parameters = inspect.signature(module.run_real_baseline_suite).parameters
        self.assertEqual(tuple(parameters), _ENTRY_PARAM_ORDER)
        self.assertEqual(
            {name for name, item in parameters.items() if item.kind is item.KEYWORD_ONLY},
            _ENTRY_KEYWORD_ONLY,
        )
        self.assertIsNone(parameters["transport"].default)
        self.assertEqual(parameters["timeout_seconds"].default, 120)
        self.assertIsNone(parameters["manifest_path"].default)
        self.assertIsNone(parameters["sources"].default)
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(
                [field.name for field in dataclasses.fields(result)],
                list(_RESULT_FIELDS),
            )
            self.assertIs(result.real_run, True)
            self.assertNotIsInstance(result, OfflineSuiteResult)
            self.assertNotIsInstance(result, BaselineRunResult)
            self.assertEqual(result.run_name, _RUN_NAME)
            self.assertTrue(_HEX64_PATTERN.match(result.approval_digest))
            self.assertEqual(
                result.approval_digest,
                hashlib.sha256(
                    (_REPO_ROOT / _APPROVAL_RELATIVE_PATH).read_bytes()
                ).hexdigest(),
            )
            self.assertEqual(
                set(result.evidence_paths), _EVIDENCE_KEYS
            )
            spec_digest = spec_from_mapping(self.spec_mapping()).content_digest()
            aggregate = json.loads(result.aggregate_path.read_bytes().decode("utf-8"))
            report_doc = json.loads(result.report_path.read_bytes().decode("utf-8"))
            self.assertEqual(result.run_spec_digest, spec_digest)
            self.assertEqual(aggregate["run_spec_digest"], spec_digest)
            self.assertEqual(report_doc["run_spec_digest"], spec_digest)
            self.assertEqual(report_doc["aggregate_sha256"], result.aggregate_sha256)
            approval_copy = pathlib.Path(directory) / "approval.json"
            self.assertEqual(
                approval_copy.read_bytes(),
                (_REPO_ROOT / _APPROVAL_RELATIVE_PATH).read_bytes(),
            )
            report_counts = report_doc["counts"]
            happy_candidates = len(
                [name for name in _happy_files() if name.endswith(".py")]
            )
            # DR-2 assertion-container correction (re-freeze v2): the frozen
            # report schema exposes raw_candidates only under
            # compression_chain (report.py), so the assertion must not read it
            # from counts.
            self.assertEqual(
                report_doc["compression_chain"]["raw_candidates"], happy_candidates
            )
            self.assertEqual(
                report_counts["scanned_files"]["value"],
                len(_happy_files()),
            )


class TestRealRunHygiene(_RealRunTestCase):
    """FR-01 / AC-1 / AC-4: module hygiene and the untouched locked gate."""

    def test_real_run_module_has_no_environment_or_config_reads(self):
        source = self.product_source(_MODULE_RELATIVE_PATH)
        environ_token = "os." + "environ"
        env_get_token = "get" + "env"
        dotenv_token = "load_" + "dotenv"
        config_token = "lima." + "config"
        for token in (environ_token, env_get_token, dotenv_token, config_token):
            self.assertIn(token, "value = " + token + "['X']")
            self.assertNotIn(token, pathlib.Path(__file__).read_text(encoding="utf-8"))
            self.assertNotIn(token, source)
        roots = _import_roots(source)
        self.assertFalse(roots & {"rand" + "om", "secre" + "ts"})
        for node in ast.walk(ast.parse(source)):
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and node.module.split(".")[0] == "lima"
            ):
                self.assertEqual(node.module, "lima.contracts.codec")

    def test_real_run_gate_constants_unchanged(self):
        self.assertIs(budget_module.REAL_RUN_GATE_UNLOCKED, False)
        with self.assertRaises(BudgetGateError) as caught:
            budget_module.require_real_run_unlock()
        self.assertEqual(caught.exception.code, BudgetGateErrorCode.REAL_RUN_LOCKED)
        self.assertEqual(caught.exception.field_path, "$.real_run_gate")

    def test_default_paths_never_import_real_run(self):
        module_sources = [
            "benchmarks/v4/baseline/orchestrate.py",
            "benchmarks/v4/baseline/run.py",
            "benchmarks/v4/baseline/offline_flow.py",
            "benchmarks/v4/baseline/budget.py",
            "benchmarks/v4/baseline/collect.py",
            "benchmarks/v4/baseline/report.py",
            "benchmarks/v4/baseline/expert_timing.py",
            "benchmarks/v4/baseline/fixtures.py",
        ]
        scanned = [
            _REPO_ROOT / relative for relative in module_sources
        ] + sorted((_REPO_ROOT / "scripts").rglob("*.py"))
        self.assertGreater(len(scanned), len(module_sources))
        positive = "import " + _real_run_dotted_name() + " as real_run\n"
        self.assertTrue(_imports_real_run(positive))
        negative = "from benchmarks.v4.baseline import orchestrate\n"
        self.assertFalse(_imports_real_run(negative))
        for path in scanned:
            self.assertFalse(
                _imports_real_run(path.read_text(encoding="utf-8")), path.name
            )
        forbidden = _forbidden_network_roots()
        self.assertTrue(
            _import_roots("import " + "url" + "lib.request\n") & forbidden
        )
        own_roots = _import_roots(pathlib.Path(__file__).read_text(encoding="utf-8"))
        self.assertFalse(own_roots & forbidden)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
