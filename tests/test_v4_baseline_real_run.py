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

IP-0033 evolution to frozen version v3 (CA-IP-0033-v1.0 of 2026-09-28; the
formal one-time frozen-surface evolution authorization is recorded in
docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md section 10):
all 35 v2 methods are retained without weakening -- three gain additive
assertions only (a1 the IP-0033 packet document and its container copy line,
u3 the response_identity checkpoint, e2 the diagnostic-face leak audit) --
and twelve new methods in three new classes pin the checkpoint diagnostics
matrix (FR-01), the usage-decoupled settlement (FR-03), and the failure
resource observation (FR-04).  The product module already exists at the v3
freeze, so the RED anchor is capability absence: the new and evolved
assertions fail on the unmodified real_run.py of the 45a7ec7 baseline
(missing diagnostic/resources evidence keys, the v2 all-usage-discarded
settlement), never through import or arrange errors; the pre-freeze baseline
run of the v2 file (35/35 green) is archived alongside the RED log.

IP-0034 evolution to frozen version v4 (CA-IP-0034-v1.0 of 2026-09-28; the
formal one-time frozen-surface evolution authorization and its six conditions
are recorded in docs/LIMA_Implementation_Packet_IP-0034_Identity_SF01.md
section 10): all 47 v3 methods are retained without weakening -- the fixture
base moves to the 2026-09-28 approval artifact (the closed served_model_forms
list replaces served_as), the identity-failure anchors move from the
now-approved deepseek-flash form to an unknown form, three verbatim-value
expectations become the SF-01 digest-token form derived by formula, and the
value-domain audits admit exactly the expected fingerprint token -- and seven
new methods in two new classes pin the three-form identity expansion (FR-01)
and the SF-01 bounded-transform channels (FR-02), including the
legacy-artifact run_name rejection (FR-03) and the v3-shape compatibility
criterion (FR-06).  The RED anchor is capability absence: on the unmodified
real_run.py of the 6d69078 baseline the 2026-09-28 artifact is refused at
$.run_name by the current loader pins, so every entry-driven arrange fails
there and the token expectations fail against verbatim recording; the
pre-freeze baseline run of the v3 file (47/47 green, nine frozen files
298/298, discover 2631 OK with 24 skips) is archived alongside the RED log.
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
_APPROVAL_RELATIVE_PATH = "docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md"
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
_RUN_NAME = "pr3d-real-2026-09-28"
_AUTHORIZATION_DATE = "2026-09-28"
# IP-0034 v4 (R8): the loader-pin triplet that migrates with the 2026-09-28
# approval artifact (run name, authorization date, pricing retrieval date).
_PRICING_RETRIEVAL_DATE = "2026-09-28"
_REQUEST_MODEL = "deepseek-v4-flash"
# IP-0034 v4 (R2): the closed, order-sensitive served-form list of the
# 2026-09-28 artifact model block (served_model_forms replaces served_as).
_SERVED_MODEL_FORMS = ("DeepSeek-V4.1-Flash", "deepseek-flash")
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

# IP-0033 v3 frozen surfaces (Packet 7.2/7.3/7.4/7.6 and section 8).
_PACKET_IP0033_RELATIVE_PATH = (
    "docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md"
)
_IP0033_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0033_Real_Run_"
    "Diagnostics.md ./docs/"
)
# IP-0034 v4 static deliverables (Packet section 8): the identity/SF-01
# packet document, the 2026-09-28 approval artifact, and their two container
# copy lines; the legacy 2026-09-27 artifact stays in the repository as
# historical evidence and must fail closed at $.run_name after the pin
# migration (R8).
_PACKET_IP0034_RELATIVE_PATH = (
    "docs/LIMA_Implementation_Packet_IP-0034_Identity_SF01.md"
)
_IP0034_PACKET_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0034_Identity_"
    "SF01.md ./docs/"
)
_IP0034_APPROVAL_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md"
    " ./docs/"
)
_APPROVAL_2026_09_27_RELATIVE_PATH = (
    "docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md"
)
# The served form the last real canary actually returned (2026-09-27 attempt-0
# evidence, ERR-D issuecomment-5856555608).  IP-0034 v4 (R2) flips its
# meaning: deepseek-flash is now an APPROVED form -- pinned in the
# 2026-09-28 artifact served_model_forms list and recorded verbatim in the
# persisted evidence -- so the identity-FAILURE anchor duty (rd1/rd2/u3/ie2)
# moves to the unknown form below.
_LAST_ROUND_SERVED_FORM = "deepseek-flash"
_UNKNOWN_MODEL_FORM = "deepseek-v9-ultra"
_RESPONSE_CHECKPOINTS = (
    "response_json",
    "response_dict",
    "response_model",
    "response_identity",
    "choices_list",
    "choice0_dict",
    "message_dict",
    "content_str",
    "content_json",
    "verdict_shape",
    "verdict_types",
)
_CHECKPOINT_FIELD_PATHS = {
    "response_json": "$.response",
    "response_dict": "$.response",
    "response_model": "$.response.model",
    "response_identity": "$.response.model",
    "choices_list": "$.response.choices",
    "choice0_dict": "$.response.choices[0]",
    "message_dict": "$.response.choices[0].message",
    "content_str": "$.response.choices[0].message.content",
    "content_json": "$.response.choices[0].message.content",
    "verdict_shape": "$.response.verdict",
    "verdict_types": "$.response.verdict",
}
_RESPONSE_META_KEYS = frozenset(
    {
        "top_level_keys",
        "choices_count",
        "message_keys",
        "content_len",
        "content_sha256",
        "finish_reason",
        "usage_present",
        "model",
        "system_fingerprint",
    }
)
_ATTEMPT_DOC_KEYS = frozenset(
    {
        "attempt_index",
        "mode",
        "outcome",
        "request",
        "response",
        "usage",
        "latency_ms",
        "failure_code",
        "error_code",
        "error_field_path",
        "diagnostic",
        "resources",
    }
)
_RESOURCES_KEYS = frozenset({"download_bytes", "storage_bytes"})
_EMPTY_CONTENT_SHA256 = (
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)
# IP-0034 v4 SF-01 frozen faces (Packet 7.4/7.5): the controlled key and
# finish-reason enumerations (the frozen minimal supersets), the fingerprint
# format predicate, and the irreversible digest-token grammar.  Expected
# tokens are always DERIVED through _sf01_token (PC3), never hardcoded.
_EXPECTED_RESPONSE_KEYS = frozenset(
    {
        "id",
        "object",
        "created",
        "model",
        "choices",
        "usage",
        "system_fingerprint",
        "service_tier",
        "role",
        "content",
        "reasoning_content",
        "tool_calls",
        "refusal",
    }
)
_EXPECTED_FINISH_REASONS = frozenset(
    {
        "stop",
        "length",
        "content_filter",
        "tool_calls",
        "function_call",
        "insufficient_system_resource",
    }
)
_FINGERPRINT_PATTERN = re.compile(r"^fp_[A-Za-z0-9]{1,63}$")
_SF01_TOKEN_PATTERN = re.compile(r"^~d:[0-9]+:[0-9a-f]{64}$")

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


class _RawBodyTransport(_FakeTransport):
    """Chat double that can return scripted raw bytes (IP-0033 matrix).

    The GET (download) side is inherited unchanged; the POST side returns the
    scheduled entry verbatim when it is ``bytes`` -- invalid UTF-8 or non-JSON
    bodies cannot be produced through ``json.dumps`` -- so the eleven
    checkpoint forms can all be driven offline (Packet 9.1 rd1).
    """

    def __call__(self, url, payload, headers, timeout):
        if payload is None:
            return super().__call__(url, payload, headers, timeout)
        self.chat_calls += 1
        scheduled = self._responses[min(self.chat_calls - 1, len(self._responses) - 1)]
        if isinstance(scheduled, BaseException):
            raise scheduled
        if isinstance(scheduled, bytes):
            return scheduled
        return json.dumps(scheduled).encode("utf-8")


def _verdict_shape_failure_body(
    *, prompt_tokens=1_000, completion_tokens=500, with_usage=True,
    content_payload=None,
):
    """One response body whose content is JSON with the wrong verdict key set.

    Shared arrange for the decoupled-settlement and resource-observation
    faces (Packet 9.1): the response contract fails at verdict_shape while
    the usage block stays scriptable.
    """
    body = _chat_response(
        prompt_tokens=prompt_tokens,
        completion_tokens=completion_tokens,
        with_usage=with_usage,
    )
    body["choices"][0]["message"]["content"] = json.dumps(
        content_payload if content_payload is not None else {"unexpected": True}
    )
    return body


def _string_values(value):
    """Every string leaf of a nested json-shaped value (diagnostic audit)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [leaf for item in value.values() for leaf in _string_values(item)]
    if isinstance(value, list):
        return [leaf for item in value for leaf in _string_values(item)]
    return []


def _sf01_token(value):
    """The frozen SF-01 irreversible digest token of one controlled string.

    Grammar (IP-0034 Packet 7.4): ``~d:<len>:<sha256-hex64>`` where ``len`` is
    the Python character count of the value and the digest covers the full
    UTF-8 bytes.  Derived here by formula so every expectation in this file
    is recomputed, never hardcoded (PC3).
    """
    return "~d:" + f"{len(value)}:" + hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()


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
        # IP-0033 v3 (Packet section 8): the diagnostics packet document and
        # its container copy line are static C1 deliverables.
        packet_ip0033 = _REPO_ROOT / _PACKET_IP0033_RELATIVE_PATH
        if not packet_ip0033.is_file():
            self.fail(
                f"required deliverable document is missing:"
                f" {_PACKET_IP0033_RELATIVE_PATH}"
            )
        self.assertIn(_IP0033_COPY_LINE, dockerfile)
        # IP-0034 v4 (Packet section 8): the identity/SF-01 packet document
        # and the 2026-09-28 approval artifact are static C1 deliverables,
        # each with its own container copy line.
        packet_ip0034 = _REPO_ROOT / _PACKET_IP0034_RELATIVE_PATH
        if not packet_ip0034.is_file():
            self.fail(
                f"required deliverable document is missing:"
                f" {_PACKET_IP0034_RELATIVE_PATH}"
            )
        self.assertIn(_IP0034_PACKET_COPY_LINE, dockerfile)
        self.assertIn(_IP0034_APPROVAL_COPY_LINE, dockerfile)

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
        # IP-0034 v4 (FR-01/AC-1, R2): the closed served-form list replaces
        # served_as and must equal the frozen pin tuple exactly (two-source
        # agreement between the artifact and this file's authorization
        # constants); the model block stays a five-key closed set.
        self.assertEqual(
            set(document["model"]),
            {
                "provider",
                "request_name",
                "served_model_forms",
                "base_url",
                "system_fingerprint_policy",
            },
        )
        self.assertEqual(
            tuple(document["model"]["served_model_forms"]), _SERVED_MODEL_FORMS
        )
        self.assertEqual(
            document["pricing"]["retrieval_date"], _PRICING_RETRIEVAL_DATE
        )
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
        responses = [_chat_response(model=_UNKNOWN_MODEL_FORM)]
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
            # IP-0033 v3 (FR-01/AC-1): the served-form rejection carries the
            # first-class identity checkpoint and the sanitized model meta.
            # IP-0034 v4 (FR-02/R4): the persisted model value of an
            # unapproved form is the digest token derived by formula (PC3).
            diagnostic = self.read_attempt(directory, 0)["diagnostic"]
            self.assertEqual(diagnostic["checkpoint"], "response_identity")
            self.assertEqual(
                diagnostic["response_meta"]["model"],
                _sf01_token(_UNKNOWN_MODEL_FORM),
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
            # IP-0033 v3 (FR-02/AC-2): the leak probe extends to the diagnostic
            # face -- sanitized metadata must never carry content values or any
            # string outside the scripted response structure.
            happy_body = _chat_response()
            allowlist = (
                set(happy_body)
                | set(happy_body["choices"][0]["message"])
                | set(_RESPONSE_CHECKPOINTS)
                | {
                    _REQUEST_MODEL,
                    happy_body["system_fingerprint"],
                    happy_body["choices"][0]["finish_reason"],
                }
            )
            # IP-0034 v4 (FR-02/AC-2, R4): the value-domain audit admits the
            # digest-token form ONLY as the expected token of the fixture's
            # non-format-compliant fingerprint -- an arbitrary token value is
            # still a leak.
            expected_tokens = {_sf01_token(happy_body["system_fingerprint"])}
            for index in range(_ATTEMPT_TOTAL):
                document = self.read_attempt(directory, index)
                self.assertIn("diagnostic", document)
                for value in _string_values(document["diagnostic"]):
                    if _HEX64_PATTERN.match(value):
                        continue
                    if _SF01_TOKEN_PATTERN.match(value):
                        self.assertIn(
                            value,
                            expected_tokens,
                            f"attempt {index} unexpected token {value!r}",
                        )
                        continue
                    self.assertIn(
                        value, allowlist, f"attempt {index} leaked {value!r}"
                    )

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


class TestResponseDiagnostics(_RealRunTestCase):
    """FR-01 / FR-02 / AC-1 / AC-2: checkpoint diagnostics and sanitized meta."""

    def test_eleven_checkpoints_produce_distinct_diagnostics(self):
        module = self.real_run()
        checkpoint_enum = getattr(module, "RealRunResponseCheckpoint", None)
        self.assertIsNotNone(
            checkpoint_enum, "RealRunResponseCheckpoint enum is missing"
        )
        self.assertTrue(issubclass(checkpoint_enum, str))
        members = list(checkpoint_enum)
        self.assertEqual(len(members), len(_RESPONSE_CHECKPOINTS))
        self.assertEqual(
            {member.value for member in members}, set(_RESPONSE_CHECKPOINTS)
        )
        for member in members:
            self.assertEqual(member, member.value)
        self.assertNotIn("RealRunResponseCheckpoint", module.__all__)
        shape_bad = _chat_response()
        shape_bad["choices"][0]["message"]["content"] = json.dumps({"unexpected": True})
        types_bad = _chat_response()
        types_bad["choices"][0]["message"]["content"] = json.dumps(
            {"is_vulnerable": "yes", "cwe": None, "path": None, "reason": "ok"}
        )
        model_not_str = _chat_response()
        model_not_str["model"] = 1234
        # ERR-D anchor (issuecomment-5856555608), evolved by IP-0034 v4
        # (FR-01/R2): the last-round served form deepseek-flash is now an
        # approved form, so the identity-failure reproduction uses an unknown
        # form whose normalization stays outside the three-form allowed set
        # (AC-1); the eleven distinct (checkpoint, field_path) pairs must
        # survive the SF-01 transformation unchanged.
        identity_drift = _chat_response(model=_UNKNOWN_MODEL_FORM)
        choices_missing = _chat_response()
        del choices_missing["choices"]
        choice0_not_dict = _chat_response()
        choice0_not_dict["choices"] = [42]
        message_missing = _chat_response()
        message_missing["choices"] = [{"index": 0, "finish_reason": "stop"}]
        content_null = _chat_response()
        content_null["choices"][0]["message"] = {"role": "assistant", "content": None}
        content_empty = _chat_response()
        content_empty["choices"][0]["message"]["content"] = ""
        matrix = (
            ("response_json", b"\xff\xfe\x00\xfa not-utf8"),
            ("response_dict", b"[1, 2, 3]"),
            ("response_model", model_not_str),
            ("response_identity", identity_drift),
            ("choices_list", choices_missing),
            ("choice0_dict", choice0_not_dict),
            ("message_dict", message_missing),
            ("content_str", content_null),
            ("content_json", content_empty),
            ("verdict_shape", shape_bad),
            ("verdict_types", types_bad),
        )
        observed = {}
        for checkpoint, body in matrix:
            with self.subTest(checkpoint=checkpoint):
                with tempfile.TemporaryDirectory() as directory:
                    transport = _RawBodyTransport(
                        tarball=_happy_tarball(), responses=[body]
                    )
                    self.run_entry(directory, transport=transport)
                    attempt = self.read_attempt(directory, 0)
                    self.assertEqual(set(attempt), _ATTEMPT_DOC_KEYS)
                    self.assertEqual(attempt["error_code"], "REAL_RUN_RESPONSE_INVALID")
                    self.assertEqual(
                        attempt["error_field_path"],
                        _CHECKPOINT_FIELD_PATHS[checkpoint],
                    )
                    self.assertEqual(attempt["diagnostic"]["checkpoint"], checkpoint)
                observed[checkpoint] = _CHECKPOINT_FIELD_PATHS[checkpoint]
        self.assertEqual(len(observed), len(_RESPONSE_CHECKPOINTS))
        self.assertEqual(
            sorted(observed.items()), sorted(_CHECKPOINT_FIELD_PATHS.items())
        )

    def test_response_meta_nine_keys_sorting_and_none_discipline(self):
        # IP-0034 v4 (FR-02/R4): the identity failure uses an unknown form;
        # every fixture response key sits inside the controlled enumeration,
        # so the sorted key lists stay verbatim (the sort-then-transform order
        # keeps normal responses byte-identical to v3), while the model value
        # and the non-format-compliant fingerprint value become the derived
        # digest tokens.
        identity_form = _chat_response(model=_UNKNOWN_MODEL_FORM)
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[identity_form])
            self.run_entry(directory, transport=transport)
            diagnostic = self.read_attempt(directory, 0)["diagnostic"]
            self.assertEqual(diagnostic["checkpoint"], "response_identity")
            meta = diagnostic["response_meta"]
            self.assertEqual(set(meta), _RESPONSE_META_KEYS)
            self.assertEqual(meta["top_level_keys"], sorted(identity_form))
            self.assertEqual(meta["choices_count"], 1)
            self.assertEqual(meta["message_keys"], ["content", "role"])
            content = identity_form["choices"][0]["message"]["content"]
            self.assertEqual(meta["content_len"], len(content))
            self.assertEqual(
                meta["content_sha256"],
                hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
            self.assertEqual(meta["finish_reason"], "stop")
            self.assertIs(meta["usage_present"], True)
            self.assertEqual(meta["model"], _sf01_token(_UNKNOWN_MODEL_FORM))
            self.assertEqual(
                meta["system_fingerprint"], _sf01_token("fp-stable-001")
            )
        # None discipline (ERR-C): an unparseable body read nothing, so every
        # meta field is null -- never an empty collection or zero.
        with tempfile.TemporaryDirectory() as directory:
            transport = _RawBodyTransport(
                tarball=_happy_tarball(), responses=[b"\xff\xfe unparseable"]
            )
            self.run_entry(directory, transport=transport)
            meta = self.read_attempt(directory, 0)["diagnostic"]["response_meta"]
            self.assertEqual(set(meta), _RESPONSE_META_KEYS)
            for key in sorted(_RESPONSE_META_KEYS):
                self.assertIsNone(meta[key], key)
        # Early checkpoint: structure fields are read, everything downstream
        # of the failure stays null.
        with tempfile.TemporaryDirectory() as directory:
            missing = _chat_response()
            del missing["choices"]
            transport = self.happy_transport(responses=[missing])
            self.run_entry(directory, transport=transport)
            meta = self.read_attempt(directory, 0)["diagnostic"]["response_meta"]
            self.assertEqual(meta["top_level_keys"], sorted(missing))
            self.assertIsNone(meta["choices_count"])
            self.assertIsNone(meta["message_keys"])
            self.assertIsNone(meta["content_len"])
            self.assertIsNone(meta["content_sha256"])
            self.assertIsNone(meta["finish_reason"])

    def test_success_attempts_carry_null_checkpoint_full_meta(self):
        # IP-0034 v4 (FR-01/R2): the success-path fixture returns the
        # first-round observed served form deepseek-flash -- now an approved
        # form recorded verbatim across the full chain (all ten attempts).
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(
                responses=[_chat_response(model=_LAST_ROUND_SERVED_FORM)]
            )
            self.run_entry(directory, transport=transport)
            content = _chat_response()["choices"][0]["message"]["content"]
            for index in range(_ATTEMPT_TOTAL):
                with self.subTest(index=index):
                    document = self.read_attempt(directory, index)
                    diagnostic = document["diagnostic"]
                    self.assertEqual(
                        set(diagnostic), {"checkpoint", "response_meta"}
                    )
                    self.assertIsNone(diagnostic["checkpoint"])
                    meta = diagnostic["response_meta"]
                    self.assertEqual(set(meta), _RESPONSE_META_KEYS)
                    self.assertEqual(meta["model"], _LAST_ROUND_SERVED_FORM)
                    self.assertIs(meta["usage_present"], True)
                    self.assertEqual(meta["choices_count"], 1)
                    self.assertEqual(meta["content_len"], len(content))
                    self.assertEqual(
                        meta["content_sha256"],
                        hashlib.sha256(content.encode("utf-8")).hexdigest(),
                    )

    def test_content_digest_recorded_even_when_verdict_fails(self):
        empty = _chat_response()
        empty["choices"][0]["message"]["content"] = ""
        unparseable = _chat_response()
        unparseable["choices"][0]["message"]["content"] = "not-json"
        for body in (empty, unparseable):
            text = body["choices"][0]["message"]["content"]
            with self.subTest(content_len=len(text)):
                with tempfile.TemporaryDirectory() as directory:
                    transport = self.happy_transport(responses=[body])
                    self.run_entry(directory, transport=transport)
                    attempt = self.read_attempt(directory, 0)
                    self.assertEqual(attempt["error_code"], "REAL_RUN_RESPONSE_INVALID")
                    self.assertEqual(
                        attempt["diagnostic"]["checkpoint"], "content_json"
                    )
                    meta = attempt["diagnostic"]["response_meta"]
                    self.assertEqual(meta["content_len"], len(text))
                    self.assertEqual(
                        meta["content_sha256"],
                        hashlib.sha256(text.encode("utf-8")).hexdigest(),
                    )
        # H2 decidable offline: the empty-string digest is the known constant.
        self.assertEqual(hashlib.sha256(b"").hexdigest(), _EMPTY_CONTENT_SHA256)
        self.assertEqual(
            hashlib.sha256(b"").hexdigest(),
            hashlib.sha256(empty["choices"][0]["message"]["content"].encode()).hexdigest(),
        )

    def test_diagnostics_face_leak_free_and_value_domain_audit(self):
        bait = _verdict_shape_failure_body(content_payload={"bait": _RAW_CONTENT_MARKER})
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[bait])
            self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
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
            allowlist = (
                set(bait)
                | set(bait["choices"][0]["message"])
                | set(_RESPONSE_CHECKPOINTS)
                | {
                    _REQUEST_MODEL,
                    bait["system_fingerprint"],
                    bait["choices"][0]["finish_reason"],
                }
            )
            # IP-0034 v4 (FR-02/AC-2, R4): same tight token admission as e2 --
            # only the expected digest token of the fixture fingerprint.
            expected_tokens = {_sf01_token(bait["system_fingerprint"])}
            for index in range(_ATTEMPT_TOTAL):
                document = self.read_attempt(directory, index)
                self.assertIn("diagnostic", document)
                for value in _string_values(document["diagnostic"]):
                    if _HEX64_PATTERN.match(value):
                        continue
                    if _SF01_TOKEN_PATTERN.match(value):
                        self.assertIn(
                            value,
                            expected_tokens,
                            f"attempt {index} unexpected token {value!r}",
                        )
                        continue
                    self.assertIn(value, allowlist, f"attempt {index} leak {value!r}")

    def test_transport_failure_keeps_null_diagnostic_and_latency(self):
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(
                responses=[TimeoutError("synthetic-diagnostics-timeout")]
            )
            self.run_entry(directory, transport=transport)
            attempt = self.read_attempt(directory, 0)
            self.assertEqual(attempt["error_code"], "REAL_RUN_TRANSPORT_FAILED")
            self.assertIn("diagnostic", attempt)
            self.assertIsNone(attempt["diagnostic"])
            self.assertIsInstance(attempt["latency_ms"], int)
            self.assertIsNotNone(attempt["latency_ms"])


class TestUsageDecoupling(_RealRunTestCase):
    """FR-03 / AC-3: verdict failure never discards compliant usage (D1-D4)."""

    def test_verdict_failure_with_usage_settles_and_retains_failure(self):
        body = _verdict_shape_failure_body()
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.status, "insufficient_sample")
            attempt = self.read_attempt(directory, 0)
            self.assertEqual(attempt["outcome"], "failure")
            self.assertEqual(attempt["failure_code"], "EXECUTION_ERROR")
            self.assertEqual(attempt["error_code"], "REAL_RUN_RESPONSE_INVALID")
            self.assertEqual(attempt["error_field_path"], "$.response.verdict")
            self.assertEqual(attempt["diagnostic"]["checkpoint"], "verdict_shape")
            self.assertEqual(result.ledger_snapshot.violations, 0)
            book = result.ledger_snapshot.batch
            self.assertEqual(set(book["reserved"].values()), {0})
            consumed = book["consumed"]
            self.assertEqual(consumed["prompt_tokens"], 1_000)
            self.assertEqual(consumed["completion_tokens"], 500)
            expected_cost = (
                math.ceil(_AUTH_PRICES[0] * 1_000 / 1_000_000)
                + math.ceil(_AUTH_PRICES[1] * 500 / 1_000_000)
            )
            self.assertEqual(consumed["cost_micro_usd"], expected_cost)
            self.assertEqual(consumed["download_bytes"], len(_happy_tarball()))
            expected_storage = sum(
                len(text.encode("utf-8")) for text in _happy_files().values()
            )
            self.assertEqual(consumed["storage_bytes"], expected_storage)
            released = book["released"]
            self.assertEqual(released["prompt_tokens"], _REQUEST_BYTE_CAP - 1_000)
            self.assertEqual(
                released["completion_tokens"],
                _AUTH_PER_RUN["completion_tokens"] - 500,
            )

    def test_verdict_failure_without_usage_counts_violation_and_keeps_observation(
        self,
    ):
        body = _verdict_shape_failure_body(with_usage=False)
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.ledger_snapshot.violations, 1)
            book = result.ledger_snapshot.batch
            self.assertEqual(set(book["reserved"].values()), {0})
            consumed = book["consumed"]
            self.assertEqual(consumed["prompt_tokens"], 0)
            self.assertEqual(consumed["completion_tokens"], 0)
            self.assertEqual(consumed["cost_micro_usd"], 0)
            self.assertEqual(consumed["download_bytes"], len(_happy_tarball()))
            expected_storage = sum(
                len(text.encode("utf-8")) for text in _happy_files().values()
            )
            self.assertEqual(consumed["storage_bytes"], expected_storage)
            self.assertEqual(
                consumed["wall_ms"], self.read_attempt(directory, 0)["latency_ms"]
            )

    def test_identity_change_records_usage_then_latches(self):
        first = _chat_response(fingerprint="fp-alpha")
        second = _chat_response(
            fingerprint="fp-beta", prompt_tokens=1_234, completion_tokens=567
        )
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[first, second])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 2)
            self.assertEqual(result.canary_status, "passed")
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[1], "REAL_RUN_IDENTITY_CHANGED")
            self.assertEqual(set(codes[2:]), {"REAL_RUN_CANARY_FAILED"})
            self.assertEqual(result.ledger_snapshot.violations, 0)
            book = result.ledger_snapshot.batch
            self.assertEqual(set(book["reserved"].values()), {0})
            consumed = book["consumed"]
            self.assertEqual(consumed["prompt_tokens"], 1_000 + 1_234)
            self.assertEqual(consumed["completion_tokens"], 500 + 567)
            expected_cost = sum(
                math.ceil(_AUTH_PRICES[0] * p / 1_000_000)
                + math.ceil(_AUTH_PRICES[1] * c / 1_000_000)
                for p, c in ((1_000, 500), (1_234, 567))
            )
            self.assertEqual(consumed["cost_micro_usd"], expected_cost)

    def test_canary_first_item_true_when_usage_settled_but_canary_still_latches(
        self,
    ):
        body = _verdict_shape_failure_body(prompt_tokens=900, completion_tokens=450)
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            self.assertEqual(result.ledger_snapshot.violations, 0)
            manifest = self.read_manifest(directory)
            checks = manifest["canary"]["checks"]
            self.assertIs(checks["usage_within_reservation"], True)
            self.assertIs(checks["identity_matches"], False)
            self.assertIs(checks["canary_sample_success"], False)
            self.assertEqual(
                self.error_code_sequence(directory)[1:],
                ["REAL_RUN_CANARY_FAILED"] * 9,
            )


class TestResourceObservation(_RealRunTestCase):
    """FR-04: failure attempts keep observed bytes/wall without ledger drift."""

    def test_attempt0_failure_keeps_resources_and_request_observation(self):
        body = _verdict_shape_failure_body()
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            self.run_entry(directory, transport=transport)
            attempt = self.read_attempt(directory, 0)
            self.assertIn("resources", attempt)
            self.assertEqual(set(attempt["resources"]), _RESOURCES_KEYS)
            self.assertEqual(
                attempt["resources"]["download_bytes"], len(_happy_tarball())
            )
            expected_storage = sum(
                len(text.encode("utf-8")) for text in _happy_files().values()
            )
            self.assertEqual(attempt["resources"]["storage_bytes"], expected_storage)
            request = attempt["request"]
            self.assertIsInstance(request["body_bytes"], int)
            self.assertGreater(request["body_bytes"], 0)
            self.assertIsInstance(attempt["latency_ms"], int)
            self.assertGreaterEqual(attempt["latency_ms"], 0)

    def test_follow_on_failure_observation_and_release_reconciliation(self):
        responses = [
            _chat_response(),
            TimeoutError("synthetic-observation-timeout"),
            _chat_response(),
        ]
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=responses)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            documents = [
                self.read_attempt(directory, index) for index in range(_ATTEMPT_TOTAL)
            ]
            failed = documents[1]
            self.assertEqual(failed["error_code"], "REAL_RUN_TRANSPORT_FAILED")
            self.assertIn("resources", failed)
            self.assertIsNone(failed["resources"])
            self.assertEqual(
                failed["request"]["body_bytes"], documents[0]["request"]["body_bytes"]
            )
            self.assertIsInstance(failed["latency_ms"], int)
            latencies = [document["latency_ms"] for document in documents]
            body_bytes = documents[0]["request"]["body_bytes"]
            expected_storage = sum(
                len(text.encode("utf-8")) for text in _happy_files().values()
            )
            wall_entry = _AUTH_PER_RUN["wall_ms"]
            completion_entry = _AUTH_PER_RUN["completion_tokens"]
            entry0_cost = (
                math.ceil(_AUTH_PRICES[0] * _REQUEST_BYTE_CAP / 1_000_000)
                + math.ceil(_AUTH_PRICES[1] * completion_entry / 1_000_000)
            )
            follow_on_entry_cost = (
                math.ceil(_AUTH_PRICES[0] * body_bytes / 1_000_000)
                + math.ceil(_AUTH_PRICES[1] * completion_entry / 1_000_000)
            )
            settled_cost = (
                math.ceil(_AUTH_PRICES[0] * 1_000 / 1_000_000)
                + math.ceil(_AUTH_PRICES[1] * 500 / 1_000_000)
            )
            # Reconciliation (Packet 9.1 ro2): released == sum(entry - actual)
            # per dimension, with the attempt-0 worst-case entry, the body-
            # derived follow-on entries, and actuals read from the evidence.
            expected_released = {
                "prompt_tokens": (
                    (_REQUEST_BYTE_CAP - 1_000)
                    + body_bytes
                    + 8 * max(0, body_bytes - 1_000)
                ),
                "completion_tokens": (
                    (completion_entry - 500) + completion_entry
                    + 8 * (completion_entry - 500)
                ),
                "wall_ms": (
                    (wall_entry - latencies[0])
                    + wall_entry
                    + sum(wall_entry - value for value in latencies[2:])
                ),
                "download_bytes": (
                    _AUTH_PER_RUN["download_bytes"] - len(_happy_tarball())
                ),
                "storage_bytes": _AUTH_PER_RUN["storage_bytes"] - expected_storage,
                "cost_micro_usd": (
                    (entry0_cost - settled_cost)
                    + follow_on_entry_cost
                    + 8 * (follow_on_entry_cost - settled_cost)
                ),
            }
            released = result.ledger_snapshot.batch["released"]
            for dimension, expected in expected_released.items():
                self.assertEqual(released[dimension], expected, dimension)
            # D5 unchanged: the transport-failure attempt books no usage wall.
            self.assertEqual(
                result.ledger_snapshot.batch["consumed"]["wall_ms"],
                latencies[0] + sum(latencies[2:]),
            )
            self.assertEqual(result.ledger_snapshot.batch["calls"], _ATTEMPT_TOTAL)
            self.assertEqual(result.ledger_snapshot.violations, 0)


class TestIdentityExpansion(_RealRunTestCase):
    """FR-01 / AC-1: the three approved forms pass; anything else fails."""

    def test_three_approved_forms_pass_identity_gate_full_chain(self):
        forms = (_REQUEST_MODEL, _SERVED_MODEL_FORMS[0], _SERVED_MODEL_FORMS[1])
        for form in forms:
            with self.subTest(form=form):
                with tempfile.TemporaryDirectory() as directory:
                    transport = self.happy_transport(
                        responses=[_chat_response(model=form)]
                    )
                    result = self.run_entry(directory, transport=transport)
                    self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
                    self.assertEqual(result.status, "sufficient_sample")
                    self.assertEqual(result.canary_status, "passed")
                    attempt0 = self.read_attempt(directory, 0)
                    self.assertIsNone(attempt0["error_code"])
                    self.assertIsNone(attempt0["diagnostic"]["checkpoint"])
                    # An approved canonical identity is recorded verbatim on
                    # every persisted face (R4 verbatim predicate), including
                    # the deepseek-flash full chain of ten successes.
                    self.assertEqual(
                        attempt0["diagnostic"]["response_meta"]["model"], form
                    )
                    self.assertEqual(attempt0["response"]["model"], form)
                    self.assertEqual(self.read_manifest(directory)["model"], form)

    def test_vision_exp_and_unknown_forms_rejected_with_tokenized_evidence(self):
        for form in ("deepseek-v4-flash-vision-exp", _UNKNOWN_MODEL_FORM):
            with self.subTest(form=form):
                with tempfile.TemporaryDirectory() as directory:
                    transport = self.happy_transport(
                        responses=[_chat_response(model=form)]
                    )
                    result = self.run_entry(directory, transport=transport)
                    self.assertEqual(transport.chat_calls, 1)
                    self.assertEqual(result.canary_status, "failed")
                    attempt0 = self.read_attempt(directory, 0)
                    self.assertEqual(
                        attempt0["error_code"], "REAL_RUN_RESPONSE_INVALID"
                    )
                    self.assertEqual(
                        attempt0["diagnostic"]["checkpoint"], "response_identity"
                    )
                    expected = _sf01_token(form)
                    self.assertEqual(
                        attempt0["diagnostic"]["response_meta"]["model"], expected
                    )
                    self.assertEqual(attempt0["response"]["model"], expected)
                    # None discipline: an unapproved form never becomes the
                    # batch baseline, so the manifest model face stays null
                    # instead of carrying an unbounded hostile string.
                    self.assertIsNone(self.read_manifest(directory)["model"])

    def test_artifact_served_model_forms_negative_matrix(self):
        module = self.real_run()

        def non_list(document):
            document["model"]["served_model_forms"] = _SERVED_MODEL_FORMS[0]

        def non_str_element(document):
            document["model"]["served_model_forms"] = [
                _SERVED_MODEL_FORMS[0],
                42,
            ]

        def unpinned_form(document):
            document["model"]["served_model_forms"] = [
                _SERVED_MODEL_FORMS[0],
                "deepseek-v4-flash-vision-exp",
            ]

        def order_drift(document):
            document["model"]["served_model_forms"] = [
                _SERVED_MODEL_FORMS[1],
                _SERVED_MODEL_FORMS[0],
            ]

        def length_mismatch(document):
            document["model"]["served_model_forms"] = [_SERVED_MODEL_FORMS[0]]

        cases = (
            ("non-list", non_list),
            ("non-str-element", non_str_element),
            ("unpinned-form", unpinned_form),
            ("order-drift", order_drift),
            ("length-mismatch", length_mismatch),
        )
        for label, mutate in cases:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as directory:
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
                    self.assertEqual(
                        caught.exception.field_path, "$.model.served_model_forms"
                    )


class TestSF01Sanitization(_RealRunTestCase):
    """FR-02 / AC-2: server-controlled strings stay bounded on every face."""

    def test_hostile_key_names_tokenized_counts_preserved(self):
        marker_key = f"evil-top-{_RAW_CONTENT_MARKER}"
        unicode_key = "evil\u2045unicode\u2046key"
        long_key = "k" * 4096
        credential_key = "leak-sk-" + "a" * 24
        message_key = f"evil-msg-{_RAW_CONTENT_MARKER}"
        body = _chat_response()
        for key in (marker_key, unicode_key, long_key, credential_key):
            body[key] = 1
        message = body["choices"][0]["message"]
        message[message_key] = 1
        hostile_keys = (
            marker_key,
            unicode_key,
            long_key,
            credential_key,
            message_key,
        )
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            self.run_entry(directory, transport=transport)
            meta = self.read_attempt(directory, 0)["diagnostic"]["response_meta"]
            # Sort by original key names, then transform item by item: an
            # enumerated key stays verbatim, anything else becomes the
            # derived token (Packet 7.4 ordering; expectations derived, PC3).
            self.assertEqual(
                meta["top_level_keys"],
                [
                    key if key in _EXPECTED_RESPONSE_KEYS else _sf01_token(key)
                    for key in sorted(body)
                ],
            )
            self.assertEqual(
                meta["message_keys"],
                [
                    key if key in _EXPECTED_RESPONSE_KEYS else _sf01_token(key)
                    for key in sorted(message)
                ],
            )
            # Counts and digests are untouched by the transformation.
            self.assertEqual(meta["choices_count"], 1)
            content = message["content"]
            self.assertEqual(meta["content_len"], len(content))
            self.assertEqual(
                meta["content_sha256"],
                hashlib.sha256(content.encode("utf-8")).hexdigest(),
            )
            offenders = []
            for path in sorted(pathlib.Path(directory).rglob("*")):
                if not path.is_file():
                    continue
                data = path.read_bytes()
                for key in hostile_keys:
                    if key.encode("utf-8") in data:
                        offenders.append((path.name, key[:24]))
                if _RAW_CONTENT_MARKER.encode("utf-8") in data:
                    offenders.append((path.name, "marker"))
            self.assertEqual(offenders, [])

    def test_identity_string_channels_tokenized_across_three_faces(self):
        long_model = "m" * 200 + _RAW_CONTENT_MARKER + "x" * 7
        self.assertEqual(len(long_model), 230)
        hostile_fingerprint = "fingerprint-" + _RAW_CONTENT_MARKER + "-nope"
        hostile_finish = "finish-" + _RAW_CONTENT_MARKER
        compliant_fingerprint = "fp_" + "a" * 32
        self.assertIsNotNone(_FINGERPRINT_PATTERN.match(compliant_fingerprint))
        self.assertIsNone(_FINGERPRINT_PATTERN.match(hostile_fingerprint))
        self.assertNotIn(hostile_finish, _EXPECTED_FINISH_REASONS)
        # Hostile model string: rejected at the identity checkpoint; both
        # response faces carry the derived token and the manifest face stays
        # null (an unapproved form never latches as the batch baseline).
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(
                responses=[_chat_response(model=long_model)]
            )
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            attempt0 = self.read_attempt(directory, 0)
            self.assertEqual(
                attempt0["diagnostic"]["checkpoint"], "response_identity"
            )
            model_token = _sf01_token(long_model)
            self.assertEqual(
                attempt0["diagnostic"]["response_meta"]["model"], model_token
            )
            self.assertEqual(attempt0["response"]["model"], model_token)
            self.assertIsNone(self.read_manifest(directory)["model"])
            self.assertEqual(self._marker_hits(directory), [])
        # Hostile fingerprint plus out-of-enum finish reason on a successful
        # run: every persisted face of each channel carries the token.
        with tempfile.TemporaryDirectory() as directory:
            body = _chat_response(fingerprint=hostile_fingerprint)
            body["choices"][0]["finish_reason"] = hostile_finish
            transport = self.happy_transport(responses=[body])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.status, "sufficient_sample")
            fingerprint_token = _sf01_token(hostile_fingerprint)
            finish_token = _sf01_token(hostile_finish)
            for index in range(_ATTEMPT_TOTAL):
                with self.subTest(index=index):
                    document = self.read_attempt(directory, index)
                    meta = document["diagnostic"]["response_meta"]
                    self.assertEqual(
                        meta["system_fingerprint"], fingerprint_token
                    )
                    self.assertEqual(meta["finish_reason"], finish_token)
                    self.assertEqual(
                        document["response"]["system_fingerprint"],
                        fingerprint_token,
                    )
                    self.assertEqual(
                        document["response"]["finish_reason"], finish_token
                    )
            manifest = self.read_manifest(directory)
            self.assertEqual(
                manifest["system_fingerprint_baseline"], fingerprint_token
            )
            self.assertEqual(self._marker_hits(directory), [])
        # Positive controls: the approved form, a format-compliant
        # fingerprint, and the enumerated finish reason stay verbatim on all
        # of their persisted faces.
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(
                responses=[
                    _chat_response(
                        model=_LAST_ROUND_SERVED_FORM,
                        fingerprint=compliant_fingerprint,
                    )
                ]
            )
            self.run_entry(directory, transport=transport)
            attempt0 = self.read_attempt(directory, 0)
            meta = attempt0["diagnostic"]["response_meta"]
            self.assertEqual(meta["model"], _LAST_ROUND_SERVED_FORM)
            self.assertEqual(meta["system_fingerprint"], compliant_fingerprint)
            self.assertEqual(meta["finish_reason"], "stop")
            self.assertEqual(
                attempt0["response"]["system_fingerprint"], compliant_fingerprint
            )
            self.assertEqual(attempt0["response"]["finish_reason"], "stop")
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["model"], _LAST_ROUND_SERVED_FORM)
            self.assertEqual(
                manifest["system_fingerprint_baseline"], compliant_fingerprint
            )

    def test_legacy_2026_09_27_artifact_rejected_at_run_name(self):
        module = self.real_run()
        legacy = _REPO_ROOT / _APPROVAL_2026_09_27_RELATIVE_PATH
        if not legacy.is_file():
            self.fail(
                "required legacy approval artifact is missing:"
                f" {_APPROVAL_2026_09_27_RELATIVE_PATH}"
            )
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(module.RealRunError) as caught:
                self.run_entry(
                    directory,
                    transport=self.happy_transport(),
                    artifact_path=legacy,
                )
            self.assertEqual(
                caught.exception.code,
                module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
            )
            self.assertEqual(caught.exception.field_path, "$.run_name")

    def test_normal_response_evidence_matches_v3_shape(self):
        # Compatibility criterion (Packet 7.8): with the standard key set, an
        # approved model, a format-compliant fingerprint, and the enumerated
        # finish reason, the sanitized evidence is byte-for-byte the v3 shape
        # -- sorted verbatim key lists, verbatim identity channels, and no
        # digest token anywhere in the response metadata.
        compliant_fingerprint = "fp_" + "a" * 32
        body = _chat_response(
            model=_LAST_ROUND_SERVED_FORM, fingerprint=compliant_fingerprint
        )
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.status, "sufficient_sample")
            message = body["choices"][0]["message"]
            for index in range(_ATTEMPT_TOTAL):
                with self.subTest(index=index):
                    document = self.read_attempt(directory, index)
                    meta = document["diagnostic"]["response_meta"]
                    self.assertEqual(set(meta), _RESPONSE_META_KEYS)
                    self.assertEqual(meta["top_level_keys"], sorted(body))
                    self.assertEqual(meta["message_keys"], sorted(message))
                    self.assertEqual(meta["model"], _LAST_ROUND_SERVED_FORM)
                    self.assertEqual(
                        meta["system_fingerprint"], compliant_fingerprint
                    )
                    self.assertEqual(meta["finish_reason"], "stop")
                    self.assertEqual(meta["choices_count"], 1)
                    self.assertEqual(meta["content_len"], len(message["content"]))
                    self.assertEqual(
                        meta["content_sha256"],
                        hashlib.sha256(
                            message["content"].encode("utf-8")
                        ).hexdigest(),
                    )
                    self.assertEqual(
                        document["response"]["model"], _LAST_ROUND_SERVED_FORM
                    )
                    for value in _string_values(meta):
                        self.assertIsNone(_SF01_TOKEN_PATTERN.match(value))
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["model"], _LAST_ROUND_SERVED_FORM)
            self.assertEqual(
                manifest["system_fingerprint_baseline"], compliant_fingerprint
            )

    def _marker_hits(self, directory):
        """Evidence files whose bytes still contain the raw leak marker."""
        hits = []
        for path in sorted(pathlib.Path(directory).rglob("*")):
            if path.is_file() and _RAW_CONTENT_MARKER.encode("utf-8") in (
                path.read_bytes()
            ):
                hits.append(path.name)
        return hits


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
