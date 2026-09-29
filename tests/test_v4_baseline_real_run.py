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

IP-0035 evolution to frozen version v5 (CA-IP-0035-v1.0 of 2026-09-28; the
formal one-time frozen-surface evolution authorization and its six conditions
are recorded in docs/LIMA_Implementation_Packet_IP-0035_Time_Governance.md
section 10): all 54 v4' methods are retained without weakening -- the
attempt-document key set grows by the three additive observation sub-blocks
(state_reuse/provider_cache/timings, R5/R6), the static artifact guard admits
the IP-0035 packet document and its single container copy line, and three
settlement/observation methods gain additive coexistence assertions only --
while twelve new methods in two new classes pin the executable wall deadline
per phase (FR-01: slow-stream download, slow extraction, slow-response
recheck, transport-timeout clamping, batch-margin clamping), the
cancellation evidence path (FR-02: partial five-file evidence set,
EXECUTION_CANCELLED taxonomy, D7/D8 release-and-partial-observation
reconciliation), and the honest cold/warm and separated-timing observation
faces (FR-03/FR-04: state_reuse flags, provider_cache null discipline,
timings separation, manifest batch_wall_ms plus the deadline observation
block, and the frozen ten-code/eleven-checkpoint/canary static anchors).
Every negative is injection-driven through the module monotonic seam
``_monotonic`` (patched with a deterministic clock, never a real sleep), so
the RED anchor is capability absence: on the unmodified real_run.py of the
d59c135 baseline the seam is never read, the deadlines never trip, the
cancelled path writes no evidence, and the observation sub-blocks are
absent; the pre-freeze baseline run of the v4' file (54/54 green, nine
frozen files 298/298, discover 2638 OK with 24 skips) is archived alongside
the RED log.

IP-0036 evolution to frozen version v6 (CA-IP-0036-v1.0 of 2026-09-28; the
formal one-time frozen-surface evolution authorization and its six conditions
are recorded in docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md
section 10): all 66 v5 methods are retained without weakening -- the entry
signature pin gains exactly one trailing keyword-only parameter
(``artifact_key``, default ``external/llamafactory-replay``, R9.2) -- while
ten new methods in one new class pin the frozen artifact family (ten keys:
nine synthetic archetypes plus the verbatim llamafactory descriptor), the
per-descriptor loader pinning with the derived 40-hex commit shas and the
structure-only unknown-key rejection, the zero-budget refusal face for all
nine synthetic keys (calls=0/cost=0, zero transport), the offline full
chain under a synthetic key with the gates unrelaxed, and the cold-reset
program (``reset_cold_state``: re-extract from the cached tarball into a
per-cold snapshot directory, rebuild the request body, zero GET,
state_reuse (T,F,T), download_ms=None discipline, repeat determinism, the
full attempt-sequence assertion, and the unchanged default batch).  The RED
anchor is capability absence: on the unmodified real_run.py of the 1046501d
baseline the parameter, the catalog and the reset entry are absent; the
default-batch compatibility method passes by design.

IP-0037 evolution to frozen version v7 (CA-IP-0037-v1.0 of 2026-09-29; the
formal one-time frozen-surface evolution authorization and its six conditions
are recorded in docs/LIMA_Implementation_Packet_IP-0037_Batch_Protocol.md
section 10): all 76 v6 methods are retained without any modification -- the
existing method bodies gain nothing and lose nothing, so the old ten-attempt
path regression is exactly the unchanged v6 suite -- while fourteen new
methods in one new class pin the artifact-signed batch protocol (FR-01..06 /
AC-1..5): the open-interval attempt-policy generalization with the exact
``$.attempt_policy.*`` tamper field paths and the {2,2} well-formed member,
the {5,5}-only routing to the byte-identical ``run_repeats`` path, the
shaped driver executing exactly cold+warm frozen ``run_baseline_attempt``
calls (pilot {1,4} = five POSTs, formal {3,5} = eight POSTs, aggregate
isomorphism), the cold-reset wiring with the additive ``cold_reset``
four-key observation (performed/materialization_count 1->2->3, digests
identical to the first materialization, ``snapshot-cold-{n}`` directories,
warm reuse (F,T,F) and the 16/15/15 key-presence matrix), the sixth/ninth
guarded-call refusals at ``$.budget.batch.calls`` with zero transmission,
the missing-reset typed failure that is never claimed as a cold success, the
shaped canary latch, the dual-batch ledger isolation with the one-time
directory gate, and the shaped missing-usage violation that is never booked
as zero.  The RED anchor is capability absence: on the unmodified real_run.py
of the ddb8675 baseline the loader still pins cold==5/warm==5/max==10, so
every shaped artifact is refused at ``$.attempt_policy.cold`` before any
shaped behavior exists, the ``_run_shaped_repeats`` driver and the
``cold_reset`` observation key are absent, and the aggregate-status rule
stays the frozen one (three cold plus five warm successes are the
sufficient-sample minimum, so an all-success {1,4} pilot honestly reports
``insufficient_sample`` -- never failure-masquerade).  The tamper matrix and
the {5,5} routing pin pass by design (guard rejections and the old path are
the current behavior); the pre-freeze baseline run of the v6 file (76/76
green, ten frozen files 322/322, discover 2692 OK with 24 skips) is archived
alongside the RED log.

IP-0038 evolution to frozen version v8 (CA-IP-0038-v1.0 of 2026-09-29; the
formal one-time frozen-surface evolution authorization and its six conditions
are recorded in docs/LIMA_Implementation_Packet_IP-0038_Preflight_Calibration.md
section 10): all 90 v7' methods are retained without any modification -- the
existing method bodies gain nothing and lose nothing -- while seven new
methods in one new class pin the pilot preflight calibration (FR-01..06 /
AC-1..5): the manifest planned-shape three states (DR-IP-0037-PV-8: pilot 1/4
and formal 3/5 derived from the carried batch shape; the old {5,5} path
byte-identical through a complete inline expected manifest document under a
constant monotonic clock), the offline rehearsal full chain on the option-b
calibrated artifact (licensed download/storage ceilings of 250,000,000 /
500,000,000 exactly admitting the frozen first-round conservative
reservation; consumed.download=0 with released.download=250,000,000 on the
synthetic large-repo key; exactly five POSTs; one cold_reset observation,
performed False at the initial materialization with zero claimed resets,
DR-IP-0038-PV-2; four warm reuses; zero budget refusals; and every
source-less V5 report field null + unavailable, DR-IP-0037-01), the
one-byte-short download-ceiling refusals (both frozen fail-closed faces with
zero transmission, DR-IP-0038-PV-3), the estimate constants and the
first-round reservation wiring statically pinned, the manifest derivation
discipline (class read-only properties never exported in ``__all__`` and a
builder that reads only the carried state -- no second parse, no hardcoded
repeat count), and the numeric-table dual-source loader check.  The RED
anchor is capability absence: on the unmodified real_run.py of the ae613ce3
baseline the manifest still writes the frozen 5/5 pair and the planned-count
properties are absent, so the three planned-shape methods fail on exactly
those assertions; the old-path byte identity, the ceiling refusals, the
static pins, and the loader check pass by design (the current behavior is
the target behavior); the pre-freeze baseline run of the v7' file (90/90
green, ten frozen files 322/322, discover 2706 OK with 24 skips) is archived
alongside the RED log.
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
    # IP-0036 v6 (R9.2): the single trailing keyword-only artifact key.
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
# IP-0035 v5 static deliverable (Packet section 5.1): the time-governance
# packet document and its single container copy line (exactly one added
# Dockerfile line after the IP-0034 packet line).
_PACKET_IP0035_RELATIVE_PATH = (
    "docs/LIMA_Implementation_Packet_IP-0035_Time_Governance.md"
)
_IP0035_PACKET_COPY_LINE = (
    "COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0035_Time_"
    "Governance.md ./docs/"
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
        # IP-0035 v5 (R5/R6): the three additive observation sub-blocks.
        "state_reuse",
        "provider_cache",
        "timings",
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
# IP-0035 v5 frozen observation faces (Packet 7.5/7.6): the three attempt
# sub-block key sets, the manifest deadline observation block, and the
# frozen ten-code error family that the time-governance evolution must not
# touch (static anchors, ho5).
_STATE_REUSE_KEYS = frozenset(
    {"materialized", "snapshot_reused", "request_body_rebuilt", "process_identity"}
)
_PROVIDER_CACHE_KEYS = frozenset(
    {"prompt_cache_hit_tokens", "prompt_cache_miss_tokens"}
)
_TIMINGS_KEYS = frozenset(
    {"api_latency_ms", "attempt_wall_ms", "download_ms", "extract_ms"}
)
_LEDGER_BOOK_DIMENSIONS = frozenset(_AUTH_PER_RUN) - {"calls"}
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
    }
)

# IP-0036 v6 frozen artifact-family faces (Packet 7.4/7.5): the closed
# ten-key catalog, the nine synthetic keys, the family discriminator, the
# descriptor field set, the synthetic derivation rule, and the cold-reset
# observation document keys and per-cold directory naming.
_ARTIFACT_FAMILY_KEYS = (
    "archetype/application",
    "archetype/library",
    "archetype/cli",
    "archetype/docs-content",
    "archetype/test-heavy",
    "archetype/monorepo",
    "archetype/large-repo",
    "archetype/malicious-layout",
    "archetype/dependency-blocked",
    "external/llamafactory-replay",
)
_SYNTHETIC_ARTIFACT_KEYS = tuple(
    key for key in _ARTIFACT_FAMILY_KEYS if key != "external/llamafactory-replay"
)
_DEFAULT_ARTIFACT_KEY = "external/llamafactory-replay"
_ZERO_BUDGET_FAMILY_VALUE = "PR3E-OFFLINE-PROOF-ZERO-BUDGET"
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
_COLD_RESET_KEYS = frozenset(
    {
        "state_reuse",
        "timings",
        "snapshot_tree_sha256",
        "request_body_sha256",
        "materialization_count",
    }
)
_PER_COLD_DIR_PATTERN = re.compile(r"^snapshot-cold-[0-9]+$")

# IP-0037 v7 (R2/R3/R6): the pinned batch shapes of the artifact-signed
# batch protocol -- pilot 1c+4w (five POSTs), formal batch 3c+5w (eight
# POSTs), and the open-interval well-formed member {2,2} that keeps the
# generalized validator from ever silently regrowing a whitelist.
_PILOT_COLD = 1
_PILOT_WARM = 4
_FORMAL_COLD = 3
_FORMAL_WARM = 5
_TWO_TWO_COLD = 2
_TWO_TWO_WARM = 2
_COLD_RESET_VALUE_KEYS = frozenset(
    {
        "performed",
        "materialization_count",
        "snapshot_tree_sha256",
        "request_body_sha256",
    }
)
# The frozen aggregate-status minimums (lima/baseline_run_result.py,
# read-only): three cold and five warm successes are the lower bound of
# ``sufficient_sample``, so the shaped expectations below derive every
# status honestly from the shape instead of hardcoding it (PC3).
_COLD_MIN_SUCCESSES = 3
_WARM_MIN_SUCCESSES = 5

# IP-0038 v8 (R5, Packet 7.3): the preflight-calibration budget vector -- a
# verbatim replica of the Packet numeric table, the sole source of the
# seven-dimension pilot values (the decision pack v6 quotes it verbatim and
# may not establish a second one).  batch keeps the licensed resource
# ceilings exactly at the frozen first-round reservation constants and
# derives the four free dimensions as five times the per-attempt worst-case
# reservation (DR-IP-0038-PV-1); the first-round reservation itself stays
# untouched (never zeroed).
_PREFLIGHT_PER_RUN = {
    "cost_micro_usd": 100_000,
    "calls": 1,
    "prompt_tokens": 150_000,
    "completion_tokens": 8_000,
    "wall_ms": 1_200_000,
    "download_bytes": 250_000_000,
    "storage_bytes": 500_000_000,
}
_PREFLIGHT_BATCH = {
    "cost_micro_usd": 198_000,
    "calls": 5,
    "prompt_tokens": 500_000,
    "completion_tokens": 40_000,
    "wall_ms": 6_000_000,
    "download_bytes": 250_000_000,
    "storage_bytes": 500_000_000,
}
# The synthetic rehearsal key: local fixture materialization performs zero
# GET calls, which is exactly the honest consumed.download=0 /
# released.download=250,000,000 accounting face of Packet 7.4.
_PREFLIGHT_REHEARSAL_KEY = "archetype/large-repo"
# One byte below the licensed download ceiling (and the frozen first-round
# reservation constant): the fail-closed refusal arrange of Packet 8-3.
_PREFLIGHT_ONE_BYTE_SHORT = 249_999_999
# The frozen canary-checklist construction order (real_run
# _run_canary_checklist insertion order; the manifest embeds it verbatim).
_PREFLIGHT_CANARY_ORDER = (
    "usage_within_reservation",
    "identity_matches",
    "attempt0_digest_verified",
    "batch_margin_positive",
    "canary_sample_success",
)


def _preflight_policy(cold, warm, *, batch=None, per_run=None):
    """Mutate one repo approval document into the calibrated variant.

    Only the attempt-policy shape and the seven budget dimensions change
    (the Packet 7.3 numeric table by default); every other pin stays the
    frozen transcription, so the arrange keeps going through the same
    document the frozen loader validates (PC2).  ``max_attempts`` is always
    derived as cold+warm (PC3).
    """

    def mutate(document):
        policy = document["attempt_policy"]
        policy["cold"] = cold
        policy["warm"] = warm
        policy["max_attempts"] = cold + warm
        for level, table in (
            ("per_run", per_run if per_run is not None else _PREFLIGHT_PER_RUN),
            ("batch", batch if batch is not None else _PREFLIGHT_BATCH),
        ):
            for dimension, value in table.items():
                document["budget"][level][dimension] = value

    return mutate


def _shaped_policy(cold, warm, *, batch_calls=None):
    """Mutate one repo approval document into a shaped artifact variant.

    Only the attempt-policy shape (and optionally the artifact-signed batch
    call ceiling) changes; every other pin stays the frozen transcription,
    so the arrange keeps going through the same document the frozen loader
    validates (PC2).  ``max_attempts`` is always derived as cold+warm (PC3).
    """

    def mutate(document):
        policy = document["attempt_policy"]
        policy["cold"] = cold
        policy["warm"] = warm
        policy["max_attempts"] = cold + warm
        if batch_calls is not None:
            document["budget"]["batch"]["calls"] = batch_calls

    return mutate


def _synthetic_commit_sha(key, fingerprint):
    """The frozen synthetic-descriptor commit-sha derivation (Packet 7.4.1).

    ``sha256("lima-synth-artifact:<key>:<registry-fingerprint>")[:40]`` --
    a deterministic 40-hex identity derived from the fixture tree
    fingerprint, never a git commit.
    """
    return hashlib.sha256(
        ("lima-synth-artifact:" + key + ":" + fingerprint).encode("utf-8")
    ).hexdigest()[:40]

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


class _JumpClock:
    """Monotonic-seam double: constant between explicit test-side jumps.

    Every read returns the current value, so the elapsed window between two
    product reads is exactly the total of the jumps applied in between (a
    fake stream or chat double applies them at deterministic points).  The
    product reads time only through the patched ``_monotonic`` seam (Packet
    7.3.4); no real sleep ever happens.
    """

    def __init__(self, base=1_000.0):
        self._value = base

    def __call__(self):
        return self._value

    def jump_ms(self, milliseconds):
        self._value += milliseconds / 1_000.0


class _SteppedClock:
    """Monotonic-seam double advancing a fixed step on every single read."""

    def __init__(self, step_ms):
        self._value = 0.0
        self._step_seconds = step_ms / 1_000.0

    def __call__(self):
        self._value += self._step_seconds
        return self._value


class _SlowStream:
    """Endless 1 MiB-chunk GET stream that jumps the clock on read ``n``."""

    def __init__(self, clock, jump_on_read, jump_ms):
        self._clock = clock
        self._jump_on_read = jump_on_read
        self._jump_ms = jump_ms
        self._chunk = b"\x00" * _DOWNLOAD_CHUNK_BYTES
        self.reads = 0
        self.served = 0

    def read(self, size):
        self.reads += 1
        if self.reads == self._jump_on_read:
            self._clock.jump_ms(self._jump_ms)
        data = self._chunk[:size]
        self.served += len(data)
        return data


class _JumpingTarballStream:
    """Finite GET stream over a tarball that jumps the clock on read ``n``."""

    def __init__(self, payload, clock, jump_on_read, jump_ms):
        self._payload = payload
        self._clock = clock
        self._jump_on_read = jump_on_read
        self._jump_ms = jump_ms

    def read(self, size):
        if not self._payload:
            return b""
        if self._jump_on_read is not None:
            self._jump_on_read -= 1
            if self._jump_on_read == 0:
                self._clock.jump_ms(self._jump_ms)
        data, self._payload = self._payload[:size], self._payload[size:]
        return data


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


class _ClockJumpChatTransport(_FakeTransport):
    """Chat double that jumps the injected clock before every reply (IP-0035).

    The GET (download) side is inherited unchanged; every POST advances the
    monotonic-seam clock by ``chat_jump_ms`` before returning the scripted
    response, so the product's post-call latency measurement and deadline
    recheck observe exactly that elapsed window (Packet 9.1 tg3/tg6/tg7).
    """

    def __init__(self, *, clock, chat_jump_ms, **kwargs):
        super().__init__(**kwargs)
        self._clock = clock
        self._chat_jump_ms = chat_jump_ms

    def __call__(self, url, payload, headers, timeout):
        if payload is not None:
            self._clock.jump_ms(self._chat_jump_ms)
        return super().__call__(url, payload, headers, timeout)


class _TarballDeletingTransport(_FakeTransport):
    """Chat double that removes the cached tarball right after the first POST.

    IP-0037 v7 (R6 wiring, Packet 9.1): at the moment of the first chat POST
    attempt-0's materialization is complete and the tarball is cached, so
    deleting it there makes every later cold reset's re-extraction fail
    closed while the warm reuse path (in-memory request state) stays
    unaffected -- the injection point for the missing-reset negative.
    """

    def __init__(self, *, tarball_dir, **kwargs):
        super().__init__(**kwargs)
        self._tarball_dir = pathlib.Path(tarball_dir)
        self.deleted = False

    def __call__(self, url, payload, headers, timeout):
        if payload is not None and not self.deleted:
            for path in self._tarball_dir.iterdir():
                if path.is_file():
                    path.unlink()
            self.deleted = True
        return super().__call__(url, payload, headers, timeout)


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

    def patch_monotonic(self, clock):
        """Bind the module monotonic seam to a deterministic clock (IP-0035).

        The frozen seam is the module attribute ``_monotonic`` (Packet
        7.3.4).  Setting it is safe in the RED state too: when the product
        does not read the seam yet, the attribute simply sits unused and the
        failure stays a behavior assertion failure, never an arrange error.
        The sentinel-based cleanup restores or removes the attribute.
        """
        module = self.real_run()
        sentinel = object()
        original = getattr(module, "_monotonic", sentinel)
        module._monotonic = clock

        def restore():
            if original is sentinel:
                try:
                    del module._monotonic
                except AttributeError:  # pragma: no cover - defensive
                    pass
            else:
                module._monotonic = original

        self.addCleanup(restore)
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
                  timeout_seconds=120, artifact_key=None):
        module = self.real_run()
        kwargs = {}
        if artifact_key is not None:
            # IP-0036 v6 (R9.2): the keyword is forwarded only when the
            # caller selects an artifact, so every pre-existing call site
            # keeps exercising the byte-identical default path.
            kwargs["artifact_key"] = artifact_key
        return module.run_real_baseline_suite(
            artifact_path or (_REPO_ROOT / _APPROVAL_RELATIVE_PATH),
            _FAKE_KEY,
            output_root=pathlib.Path(output_root),
            spec_mapping=self.spec_mapping(),
            transport=transport,
            timeout_seconds=timeout_seconds,
            sources=self.fixed_sources(),
            **kwargs,
        )

    def artifact_catalog(self):
        """The frozen artifact family catalog (C5 deliverable), fail-closed."""
        module = self.real_run()
        catalog = getattr(module, "REAL_RUN_ARTIFACT_FAMILY", None)
        self.assertIsNotNone(
            catalog, "REAL_RUN_ARTIFACT_FAMILY is missing (C5 deliverable)"
        )
        return catalog

    def write_synthetic_artifact(self, directory, key, mutate=None):
        """One approval-shaped document carrying the descriptor pins."""
        descriptor = self.artifact_catalog()[key]

        def apply_descriptor(document):
            document["approval_type"] = descriptor["approval_type"]
            document["run_name"] = descriptor["run_name"]
            document["upstream"]["repository"] = descriptor["repository"]
            document["upstream"]["requested_name"] = descriptor["requested_name"]
            document["upstream"]["commit_sha"] = descriptor["commit_sha"]
            document["upstream"]["tarball_url"] = descriptor["tarball_url"]
            if mutate is not None:
                mutate(document)

        return self.write_artifact(directory, apply_descriptor)

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
        # IP-0035 v5 (Packet section 5.1): the time-governance packet
        # document and its single container copy line are static C1
        # deliverables (the Dockerfile grows by exactly one line).
        packet_ip0035 = _REPO_ROOT / _PACKET_IP0035_RELATIVE_PATH
        if not packet_ip0035.is_file():
            self.fail(
                f"required deliverable document is missing:"
                f" {_PACKET_IP0035_RELATIVE_PATH}"
            )
        self.assertIn(_IP0035_PACKET_COPY_LINE, dockerfile)

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
        # IP-0035 v5 (R4.4 evolution registration): the evidence-write
        # timing face now has two honest states -- the full set pinned here
        # after a normal ``run_repeats`` return (assertions unchanged) and
        # the partial five-file set on a control-flow BaseException re-raise
        # (pinned by the cancellation test of TestTimeGovernance, tg4).
        # No assertion on this normal path changed.
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
            # IP-0035 v5 (FR-02/FR-04): the additive observation sub-blocks
            # coexist with the D1 settlement face (D8 must not disturb
            # D1-D6).
            self.assertIn("timings", attempt)
            self.assertIn("state_reuse", attempt)

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
            # IP-0035 v5 (FR-04): the timings/state_reuse sub-blocks coexist
            # with the attempt-0 resources face.
            self.assertIn("timings", attempt)
            self.assertIn("state_reuse", attempt)

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
            # IP-0035 v5 (FR-02/FR-04): the follow-on failure keeps the D5
            # release-only face alongside the new observation sub-block.
            self.assertIn("timings", failed)
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


class TestTimeGovernance(_RealRunTestCase):
    """FR-01 / FR-02 / AC-1 / AC-2: executable deadlines and cancellation.

    Every negative below is injection-driven through the frozen module
    monotonic seam ``_monotonic`` (Packet 7.3.4): a constant-until-jumped
    clock or a fixed-step clock replaces real time, a fake stream or chat
    double applies deterministic jumps, and no test ever sleeps or touches a
    socket.  The typed deadline failures follow the frozen taxonomy of
    Packet 7.2 (EXECUTION_TIMEOUT + REAL_RUN_TRANSPORT_FAILED + the
    phase-specific structure path) and settle through D7/D8.
    """

    def test_slow_stream_download_deadline_aborts_cleans_and_types(self):
        # tg1 (Packet 9.1): the per-chunk deadline check aborts the
        # download mid-stream (the second 1 MiB chunk read jumps the clock
        # 1,500,000 ms past the 1,200,000 ms attempt deadline).
        clock = _JumpClock()
        stream = _SlowStream(clock, jump_on_read=2, jump_ms=1_500_000)
        with tempfile.TemporaryDirectory() as directory:
            transport = _FakeTransport(
                download_factory=lambda: stream, responses=[_chat_response()]
            )
            self.patch_monotonic(clock)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(transport.chat_calls, 0)
            attempt = self.read_attempt(directory, 0)
            self.assertEqual(attempt["failure_code"], "EXECUTION_TIMEOUT")
            self.assertEqual(attempt["error_code"], "REAL_RUN_TRANSPORT_FAILED")
            self.assertEqual(attempt["error_field_path"], "$.download")
            self.assertEqual(attempt["outcome"], "timeout")
            # Partial-file cleanup: the aborted tarball leaves no residue.
            leftovers = list((pathlib.Path(directory) / "_materialized").rglob("*.gz"))
            self.assertEqual(leftovers, [])
            # None discipline: the chat never ran, so the api-latency
            # channel is unread on both faces while the attempt wall keeps
            # its honest partial value.
            self.assertIsNone(attempt["latency_ms"])
            self.assertIn("timings", attempt)
            self.assertIsNone(attempt["timings"]["api_latency_ms"])
            self.assertIsInstance(attempt["timings"]["attempt_wall_ms"], int)
            self.assertGreaterEqual(attempt["timings"]["attempt_wall_ms"], 0)
            self.assertEqual(result.status, "insufficient_sample")
            codes = self.error_code_sequence(directory)
            self.assertEqual(codes[0], "REAL_RUN_TRANSPORT_FAILED")
            self.assertEqual(set(codes[1:]), {"REAL_RUN_CANARY_FAILED"})
            # D7 reconciliation: release-only settlement -- the reservation
            # left the in-flight balance, the granted call was not
            # recycled, and any partial download observation stays bounded
            # by what the slow stream actually served.
            book = result.ledger_snapshot.batch
            self.assertEqual(set(book["reserved"].values()), {0})
            self.assertEqual(book["calls"], 1)
            consumed_download = book["consumed"]["download_bytes"]
            self.assertIsInstance(consumed_download, int)
            self.assertLessEqual(0, consumed_download)
            self.assertLessEqual(consumed_download, stream.served)

    def test_slow_extraction_deadline_types_archive_phase(self):
        # tg2: the stepped clock (200,000 ms per seam read) leaves the
        # one-chunk gz download under the deadline but crosses it inside
        # the 16 MiB member's extraction loop, typing the failure at the
        # archive phase.
        members = {
            f"{_HAPPY_TOP}/README.md": "# readme\n",
            f"{_HAPPY_TOP}/big.bin": "\x00" * (16 * _DOWNLOAD_CHUNK_BYTES),
        }
        clock = _SteppedClock(step_ms=200_000)
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(tarball=_build_tarball(members))
            self.patch_monotonic(clock)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(transport.chat_calls, 0)
            attempt = self.read_attempt(directory, 0)
            self.assertEqual(attempt["failure_code"], "EXECUTION_TIMEOUT")
            self.assertEqual(attempt["error_code"], "REAL_RUN_TRANSPORT_FAILED")
            self.assertEqual(attempt["error_field_path"], "$.archive")
            self.assertEqual(attempt["outcome"], "timeout")
            self.assertEqual(result.status, "insufficient_sample")
            book = result.ledger_snapshot.batch
            self.assertEqual(set(book["reserved"].values()), {0})
            self.assertEqual(book["calls"], 1)
            self.assertEqual(
                set(self.error_code_sequence(directory)[1:]), {"REAL_RUN_CANARY_FAILED"}
            )

    def test_slow_response_deadline_recheck_never_success_settles_d7(self):
        # tg3: the chat reply arrives 2,000,000 ms after the attempt anchor
        # (deadline 1,200,000 ms); the post-chat deadline recheck fails the
        # attempt typed, never records usage, and settles D7 with the
        # attempt-0 partial observation.
        clock = _JumpClock()
        with tempfile.TemporaryDirectory() as directory:
            transport = _ClockJumpChatTransport(
                clock=clock,
                chat_jump_ms=2_000_000,
                tarball=_happy_tarball(),
                responses=[_chat_response()],
            )
            self.patch_monotonic(clock)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            attempt = self.read_attempt(directory, 0)
            self.assertEqual(attempt["outcome"], "timeout")
            self.assertEqual(attempt["failure_code"], "EXECUTION_TIMEOUT")
            self.assertEqual(attempt["error_code"], "REAL_RUN_TRANSPORT_FAILED")
            self.assertEqual(attempt["error_field_path"], "$.transport")
            self.assertIsNone(attempt["usage"])
            self.assertIn("timings", attempt)
            self.assertEqual(attempt["timings"]["api_latency_ms"], attempt["latency_ms"])
            self.assertEqual(attempt["latency_ms"], 2_000_000)
            self.assertGreaterEqual(
                attempt["timings"]["attempt_wall_ms"],
                attempt["timings"]["api_latency_ms"],
            )
            # D7 numeric reconciliation (PC3): release-only with the
            # attempt-0 partial observation retained in consumed.
            book = result.ledger_snapshot.batch
            self.assertEqual(set(book["reserved"].values()), {0})
            consumed = book["consumed"]
            self.assertEqual(consumed["wall_ms"], 2_000_000)
            self.assertEqual(consumed["prompt_tokens"], 0)
            self.assertEqual(consumed["completion_tokens"], 0)
            self.assertEqual(consumed["cost_micro_usd"], 0)
            self.assertEqual(consumed["download_bytes"], len(_happy_tarball()))
            expected_storage = sum(
                len(text.encode("utf-8")) for text in _happy_files().values()
            )
            self.assertEqual(consumed["storage_bytes"], expected_storage)
            entry0_cost = (
                math.ceil(_AUTH_PRICES[0] * _REQUEST_BYTE_CAP / 1_000_000)
                + math.ceil(
                    _AUTH_PRICES[1] * _AUTH_PER_RUN["completion_tokens"] / 1_000_000
                )
            )
            released = book["released"]
            self.assertEqual(released["prompt_tokens"], _REQUEST_BYTE_CAP)
            self.assertEqual(
                released["completion_tokens"], _AUTH_PER_RUN["completion_tokens"]
            )
            self.assertEqual(released["cost_micro_usd"], entry0_cost)
            self.assertEqual(
                released["download_bytes"],
                _AUTH_PER_RUN["download_bytes"] - len(_happy_tarball()),
            )
            self.assertEqual(
                released["storage_bytes"], _AUTH_PER_RUN["storage_bytes"] - expected_storage
            )
            # The measured wall overshot its reservation, so nothing was
            # releasable on the wall dimension.
            self.assertEqual(released["wall_ms"], 0)
            self.assertEqual(book["calls"], 1)
            self.assertEqual(result.status, "insufficient_sample")
            self.assertEqual(
                set(self.error_code_sequence(directory)[1:]), {"REAL_RUN_CANARY_FAILED"}
            )

    def test_cancellation_writes_partial_evidence_set_and_releases(self):
        # tg4: a control-flow BaseException injected at the chat transport
        # re-raises out of the entry after the partial five-file evidence
        # set is written and the trailing unsettled attempt is released.
        interrupt = KeyboardInterrupt("synthetic-operator-cancel")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            transport = self.happy_transport(
                responses=[_chat_response(), _chat_response(), interrupt]
            )
            with self.assertRaises(KeyboardInterrupt):
                self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 3)
            expected_files = [
                "approval.json",
                "ledger.json",
                "machine_profile.json",
                "manifest.json",
            ]
            for name in expected_files:
                self.assertTrue((root / name).is_file(), name)
            attempt_files = sorted(path.name for path in (root / "attempts").glob("*"))
            self.assertEqual(
                attempt_files,
                ["attempt-00.json", "attempt-01.json", "attempt-02.json"],
            )
            cancelled = self.read_attempt(directory, 2)
            self.assertEqual(cancelled["outcome"], "cancelled")
            self.assertEqual(cancelled["failure_code"], "EXECUTION_CANCELLED")
            self.assertIsNone(cancelled["error_code"])
            self.assertIsNone(cancelled["error_field_path"])
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["attempt_count"], 3)
            self.assertEqual(manifest["cold_count"], _COLD_COUNT)
            self.assertEqual(manifest["warm_count"], _WARM_COUNT)
            self.assertEqual(
                manifest["failures"],
                [
                    {
                        "attempt_index": 2,
                        "failure_code": "EXECUTION_CANCELLED",
                        "error_code": None,
                        "error_field_path": None,
                    }
                ],
            )
            self.assertIn("batch_wall_ms", manifest)
            self.assertIsInstance(manifest["batch_wall_ms"], int)
            self.assertGreaterEqual(manifest["batch_wall_ms"], 0)
            self.assertIn("deadline", manifest)
            # D8 reconciliation: the trailing pending reservation is
            # released (reserved zero), the two settled successes keep
            # their usage, and the granted calls are not recycled.
            book = json.loads((root / "ledger.json").read_bytes().decode("utf-8"))
            batch = book["batch"]
            self.assertEqual(set(batch["reserved"].values()), {0})
            self.assertEqual(batch["calls"], 3)
            self.assertEqual(batch["consumed"]["prompt_tokens"], 2_000)
            # The aggregate and report are honestly absent on the
            # cancelled path; the orchestration persisted exactly the
            # three per-attempt run files and nothing after them.
            self.assertEqual(list(root.glob("*-report-*")), [])
            run_sequences = sorted(
                int(path.stem.rsplit("-", 1)[1])
                for path in root.iterdir()
                if _RUN_NAME_PATTERN.match(path.name)
            )
            self.assertEqual(run_sequences, [1, 2, 3])
        # Cancellation on attempt-0 keeps the D8 attempt-0 partial
        # observation (measured download/storage of the completed
        # materialization) while releasing the reservation.
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            transport = self.happy_transport(responses=[interrupt])
            with self.assertRaises(KeyboardInterrupt):
                self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["attempt_count"], 1)
            self.assertEqual(
                manifest["failures"],
                [
                    {
                        "attempt_index": 0,
                        "failure_code": "EXECUTION_CANCELLED",
                        "error_code": None,
                        "error_field_path": None,
                    }
                ],
            )
            cancelled0 = self.read_attempt(directory, 0)
            self.assertEqual(cancelled0["outcome"], "cancelled")
            book = json.loads((root / "ledger.json").read_bytes().decode("utf-8"))
            batch = book["batch"]
            self.assertEqual(set(batch["reserved"].values()), {0})
            self.assertEqual(batch["calls"], 1)
            self.assertEqual(batch["consumed"]["download_bytes"], len(_happy_tarball()))
            expected_storage = sum(
                len(text.encode("utf-8")) for text in _happy_files().values()
            )
            self.assertEqual(batch["consumed"]["storage_bytes"], expected_storage)
            self.assertEqual(
                sorted(path.name for path in (root / "attempts").glob("*")),
                ["attempt-00.json"],
            )
            run_sequences = sorted(
                int(path.stem.rsplit("-", 1)[1])
                for path in root.iterdir()
                if _RUN_NAME_PATTERN.match(path.name)
            )
            self.assertEqual(run_sequences, [1])

    def test_transport_timeout_clamped_to_remaining_deadline(self):
        # tg5: the four-argument transport contract is unchanged; the
        # timeout argument passed to the transport is clamped to the
        # remaining attempt deadline, max(1, min(timeout_seconds,
        # ceil(remaining_seconds))) -- the min branch, the >=1 floor, and
        # the untouched timeout_seconds branch.
        def widen_wall(document):
            document["budget"]["per_run"]["wall_ms"] = 1_500_000

        cases = (
            ("min-branch", 1_400_000, 100),
            ("floor-branch", 1_499_990, 1),
            ("timeout-seconds-branch", 0, 1_500),
        )
        for label, jump_ms, expected_timeout in cases:
            with self.subTest(case=label):
                with tempfile.TemporaryDirectory() as directory:
                    clock = _JumpClock()
                    stream = _JumpingTarballStream(
                        _happy_tarball(), clock, jump_on_read=1, jump_ms=jump_ms
                    )
                    transport = _FakeTransport(
                        download_factory=lambda stream=stream: stream,
                        responses=[_chat_response()],
                    )
                    self.patch_monotonic(clock)
                    approval = self.write_artifact(directory, widen_wall)
                    self.run_entry(
                        directory,
                        transport=transport,
                        artifact_path=approval,
                        timeout_seconds=1_500,
                    )
                    self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
                    self.assertEqual(transport.chat_timeouts[0], expected_timeout)
                    self.assertEqual(transport.chat_timeouts[1:], [1_500] * 9)

    def test_batch_wall_margin_clamps_attempt_deadline(self):
        # tg6: with per_run.wall_ms 2,400,000 and batch.wall_ms 7,200,000,
        # each 1,500,000 ms chat keeps attempts 0-3 under the per-run
        # deadline; from attempt 4 on, the consumed batch wall (6,000,000)
        # leaves a 1,200,000 ms batch margin that clamps the attempt
        # deadline below per-run -- observable in the clamped transport
        # timeout and in the post-chat recheck failures.
        def widen_walls(document):
            document["budget"]["per_run"]["wall_ms"] = 2_400_000
            document["budget"]["batch"]["wall_ms"] = 7_200_000

        clock = _JumpClock()
        with tempfile.TemporaryDirectory() as directory:
            transport = _ClockJumpChatTransport(
                clock=clock,
                chat_jump_ms=1_500_000,
                tarball=_happy_tarball(),
                responses=[_chat_response()],
            )
            self.patch_monotonic(clock)
            approval = self.write_artifact(directory, widen_walls)
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                timeout_seconds=2_000,
            )
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(transport.chat_timeouts, [2_000] * 4 + [1_200] * 6)
            outcomes = [
                self.read_attempt(directory, index)["outcome"]
                for index in range(_ATTEMPT_TOTAL)
            ]
            self.assertEqual(outcomes.count("success"), 4)
            self.assertEqual(outcomes.count("timeout"), 6)
            for index in range(4, _ATTEMPT_TOTAL):
                attempt = self.read_attempt(directory, index)
                self.assertEqual(attempt["failure_code"], "EXECUTION_TIMEOUT")
                self.assertEqual(attempt["error_code"], "REAL_RUN_TRANSPORT_FAILED")
                self.assertEqual(attempt["error_field_path"], "$.transport")
            book = result.ledger_snapshot.batch
            self.assertEqual(book["consumed"]["wall_ms"], 6_000_000)
            self.assertEqual(book["calls"], _ATTEMPT_TOTAL)

    def test_manifest_batch_wall_ms_and_deadline_observation(self):
        # tg7: the manifest carries the additive batch wall (int >= 0) and
        # the evidence-phase deadline observation block -- false on a
        # healthy margin, true once a D7 partial observation pushes the
        # consumed batch wall past the batch cap (the run still completes
        # and writes every remaining evidence file).
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            self.run_entry(directory, transport=transport)
            manifest = self.read_manifest(directory)
            self.assertIn("batch_wall_ms", manifest)
            self.assertIsInstance(manifest["batch_wall_ms"], int)
            self.assertGreaterEqual(manifest["batch_wall_ms"], 0)
            self.assertIn("deadline", manifest)
            self.assertEqual(manifest["deadline"], {"batch_wall_exceeded": False})
        clock = _JumpClock()
        with tempfile.TemporaryDirectory() as directory:
            transport = _ClockJumpChatTransport(
                clock=clock,
                chat_jump_ms=12_500_000,
                tarball=_happy_tarball(),
                responses=[_chat_response()],
            )
            self.patch_monotonic(clock)
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(
                result.ledger_snapshot.batch["consumed"]["wall_ms"], 12_500_000
            )
            manifest = self.read_manifest(directory)
            self.assertIn("deadline", manifest)
            self.assertIs(manifest["deadline"]["batch_wall_exceeded"], True)
            self.assertIn("batch_wall_ms", manifest)
            self.assertIsInstance(manifest["batch_wall_ms"], int)
            self.assertEqual(
                set(self.error_code_sequence(directory)[1:]), {"REAL_RUN_CANARY_FAILED"}
            )


class TestHonestObservation(_RealRunTestCase):
    """FR-03 / FR-04 / AC-3 / AC-4: honest cold-warm and separated metrics."""

    def test_state_reuse_annotation_and_process_identity(self):
        # ho1: the state_reuse sub-block annotates the actual execution
        # face of every attempt (attempt-0 materializes and rebuilds the
        # request body; the follow-ons reuse the snapshot and the cached
        # body), and the process identity is one digest token shared by
        # the whole suite (the frozen _digest_token form; a restart
        # changes it).  The mode labels stay exactly 0-4 cold / 5-9 warm.
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.status, "sufficient_sample")
            identities = set()
            modes = []
            for index in range(_ATTEMPT_TOTAL):
                document = self.read_attempt(directory, index)
                self.assertIn("state_reuse", document)
                reuse = document["state_reuse"]
                self.assertEqual(set(reuse), _STATE_REUSE_KEYS)
                expected_flags = (
                    (True, False, True) if index == 0 else (False, True, False)
                )
                self.assertEqual(
                    (
                        reuse["materialized"],
                        reuse["snapshot_reused"],
                        reuse["request_body_rebuilt"],
                    ),
                    expected_flags,
                )
                identities.add(reuse["process_identity"])
                modes.append(document["mode"])
            self.assertEqual(len(identities), 1)
            identity = identities.pop()
            self.assertIsInstance(identity, str)
            self.assertTrue(identity)
            self.assertIsNotNone(_SF01_TOKEN_PATTERN.match(identity))
            self.assertEqual(modes, ["cold"] * _COLD_COUNT + ["warm"] * _WARM_COUNT)

    def test_provider_cache_observation_keys_and_null_discipline(self):
        # ho2: compliant cache counters land in the observation face;
        # missing or non-compliant values stay null (never a fabricated
        # zero); the counters never reach any ledger face and the frozen
        # six-field usage view is unchanged.
        def cached_response(hit, miss):
            body = _chat_response()
            body["usage"]["prompt_cache_hit_tokens"] = hit
            body["usage"]["prompt_cache_miss_tokens"] = miss
            return body

        usage_view_keys = _LEDGER_BOOK_DIMENSIONS
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[cached_response(64, 936)])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            for index in range(_ATTEMPT_TOTAL):
                document = self.read_attempt(directory, index)
                self.assertIn("provider_cache", document)
                cache = document["provider_cache"]
                self.assertEqual(set(cache), _PROVIDER_CACHE_KEYS)
                self.assertEqual(cache["prompt_cache_hit_tokens"], 64)
                self.assertEqual(cache["prompt_cache_miss_tokens"], 936)
                self.assertEqual(set(document["usage"]), usage_view_keys)
            book = result.ledger_snapshot.batch
            for face in ("consumed", "reserved", "released"):
                self.assertNotIn("prompt_cache_hit_tokens", book[face])
                self.assertNotIn("prompt_cache_miss_tokens", book[face])
            self.assertEqual(set(book["consumed"]), usage_view_keys)
        for label, hit in (("missing", None), ("non-int", "64"), ("negative", -1)):
            with self.subTest(case=label):
                body = _chat_response()
                if hit is not None:
                    body["usage"]["prompt_cache_hit_tokens"] = hit
                with tempfile.TemporaryDirectory() as directory:
                    transport = self.happy_transport(responses=[body])
                    result = self.run_entry(directory, transport=transport)
                    self.assertEqual(result.status, "sufficient_sample")
                    self.assertIn("provider_cache", self.read_attempt(directory, 0))
                    cache = self.read_attempt(directory, 0)["provider_cache"]
                    self.assertIsNone(cache["prompt_cache_hit_tokens"])
                    self.assertIsNone(cache["prompt_cache_miss_tokens"])

    def test_timings_separation_and_none_discipline(self):
        # ho3: api_latency_ms is the same measurement as latency_ms, the
        # attempt wall dominates it, and the download/extract phase
        # channels are attempt-0 only.  On a request-side refusal (after
        # materialization, before the chat) the api-latency channel is
        # unread (null on both faces) while the attempt wall and the
        # attempt-0 phase channels keep honest values.
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport()
            self.run_entry(directory, transport=transport)
            for index in range(_ATTEMPT_TOTAL):
                with self.subTest(index=index):
                    document = self.read_attempt(directory, index)
                    self.assertIn("timings", document)
                    timings = document["timings"]
                    self.assertEqual(set(timings), _TIMINGS_KEYS)
                    self.assertEqual(timings["api_latency_ms"], document["latency_ms"])
                    self.assertIsInstance(timings["api_latency_ms"], int)
                    self.assertGreaterEqual(
                        timings["attempt_wall_ms"], timings["api_latency_ms"]
                    )
                    if index == 0:
                        self.assertIsInstance(timings["download_ms"], int)
                        self.assertGreaterEqual(timings["download_ms"], 0)
                        self.assertIsInstance(timings["extract_ms"], int)
                        self.assertGreaterEqual(timings["extract_ms"], 0)
                    else:
                        self.assertIsNone(timings["download_ms"])
                        self.assertIsNone(timings["extract_ms"])
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(tarball=_cjk_tarball())
            self.run_entry(directory, transport=transport)
            document = self.read_attempt(directory, 0)
            self.assertIn("timings", document)
            timings = document["timings"]
            self.assertIsNone(document["latency_ms"])
            self.assertIsNone(timings["api_latency_ms"])
            self.assertIsInstance(timings["attempt_wall_ms"], int)
            self.assertGreaterEqual(timings["attempt_wall_ms"], 0)
            self.assertIsInstance(timings["download_ms"], int)
            self.assertIsInstance(timings["extract_ms"], int)

    def test_cold_label_with_cache_hit_decidable_and_mode_unchanged(self):
        # ho4: the decidable falsification pair -- a cold mode label and a
        # non-zero provider cache hit coexist on the evidence face, so a
        # cold-start claim made from the mode label alone is falsifiable
        # by the observation keys (Packet 7.5.4 conclusion-limitation
        # rules); the mode sequence itself is untouched.
        body = _chat_response()
        body["usage"]["prompt_cache_hit_tokens"] = 64
        body["usage"]["prompt_cache_miss_tokens"] = 936
        with tempfile.TemporaryDirectory() as directory:
            transport = self.happy_transport(responses=[body])
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.status, "sufficient_sample")
            modes = []
            for index in range(_ATTEMPT_TOTAL):
                document = self.read_attempt(directory, index)
                modes.append(document["mode"])
                self.assertIn("state_reuse", document)
                self.assertIn("provider_cache", document)
            self.assertEqual(modes, ["cold"] * _COLD_COUNT + ["warm"] * _WARM_COUNT)
            first = self.read_attempt(directory, 0)
            self.assertEqual(first["mode"], "cold")
            self.assertEqual(first["provider_cache"]["prompt_cache_hit_tokens"], 64)

    def test_frozen_taxonomy_checkpoints_and_canary_static_anchors(self):
        # ho5: the time-governance evolution must not touch the frozen
        # wire faces -- exactly ten error codes, the closed
        # eleven-checkpoint map, and the five canary keys stay verbatim.
        module = self.real_run()
        self.assertEqual(
            {member.value for member in module.RealRunErrorCode}, _FROZEN_ERROR_CODES
        )
        checkpoint_paths = module._CHECKPOINT_FIELD_PATHS
        self.assertEqual(
            {
                member.value: checkpoint_paths[member]
                for member in module.RealRunResponseCheckpoint
            },
            dict(_CHECKPOINT_FIELD_PATHS),
        )
        self.assertEqual(set(module._CANARY_CHECK_KEYS), _CANARY_CHECK_KEYS)


class TestArtifactFamilyAndColdReset(_RealRunTestCase):
    """IP-0036 FR-07/FR-08/AC-4 (Packet 7.4/7.5): artifact family, entry
    generalization, zero-budget proof, and the cold-reset program."""

    def test_entry_signature_gains_artifact_key_with_frozen_default(self):
        # R9.2: exactly one trailing keyword-only parameter whose default
        # keeps the llamafactory path byte-identical.
        module = self.real_run()
        parameters = inspect.signature(module.run_real_baseline_suite).parameters
        self.assertIn("artifact_key", parameters)
        self.assertIs(parameters["artifact_key"].kind, inspect.Parameter.KEYWORD_ONLY)
        self.assertEqual(parameters["artifact_key"].default, _DEFAULT_ARTIFACT_KEY)
        self.assertEqual(_ENTRY_PARAM_ORDER[-1], "artifact_key")
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.attempt_count, _ATTEMPT_TOTAL)
            self.assertEqual(transport.download_urls, [self.canonical_tarball_url()])
            commit = self.canonical_tarball_url().rsplit("/", 1)[1]
            self.assertTrue(
                (root / "_materialized" / "tarball" / f"llamafactory-{commit}.tar.gz").is_file()
            )

    def test_artifact_family_catalog_frozen_ten_keys(self):
        # R9.1: the closed ten-key catalog with the verbatim llamafactory
        # descriptor (four pins, identity pins, byte-identical filename
        # template).
        catalog = self.artifact_catalog()
        self.assertEqual(set(catalog), set(_ARTIFACT_FAMILY_KEYS))
        self.assertEqual(len(catalog), 10)
        for key in _ARTIFACT_FAMILY_KEYS:
            with self.subTest(key=key):
                self.assertEqual(set(catalog[key]), _DESCRIPTOR_FIELDS)
        descriptor = catalog["external/llamafactory-replay"]
        commit = self.canonical_tarball_url().rsplit("/", 1)[1]
        self.assertEqual(descriptor["repository"], _CANONICAL_REPOSITORY)
        self.assertEqual(descriptor["requested_name"], "hiyouga/LLaMA-Factory")
        self.assertEqual(descriptor["commit_sha"], commit)
        self.assertEqual(descriptor["tarball_url"], self.canonical_tarball_url())
        self.assertEqual(descriptor["tarball_filename"], "llamafactory-{commit_sha}.tar.gz")
        self.assertEqual(descriptor["approval_type"], "PR3D-REAL-RUN-LIMITED")
        self.assertEqual(descriptor["run_name"], _RUN_NAME)

    def test_synthetic_descriptors_derived_deterministically(self):
        # R9.1/DR-IP-0036-PV-4: the nine synthetic descriptors are derived
        # once -- slug form, registry-fingerprint commit sha, .invalid URL,
        # filename template, and the offline-proof identity pins.
        catalog = self.artifact_catalog()
        registry = fixtures_module.load_registry()
        entries = {entry["key"]: entry for entry in registry["fixtures"]}
        for key in _SYNTHETIC_ARTIFACT_KEYS:
            with self.subTest(key=key):
                descriptor = catalog[key]
                archetype = key.removeprefix("archetype/")
                slug = f"lima-synth/{archetype}"
                expected_sha = _synthetic_commit_sha(key, entries[key]["fingerprint"])
                self.assertEqual(descriptor["repository"], slug)
                self.assertEqual(descriptor["requested_name"], slug)
                self.assertEqual(descriptor["commit_sha"], expected_sha)
                self.assertRegex(descriptor["commit_sha"], r"^[0-9a-f]{40}$")
                self.assertEqual(
                    descriptor["tarball_url"],
                    f"https://lima-synth.invalid/{archetype}/tar.gz/{expected_sha}",
                )
                self.assertEqual(
                    descriptor["tarball_filename"],
                    f"lima-synth-{archetype}-{{commit_sha}}.tar.gz",
                )
                self.assertEqual(descriptor["approval_type"], _ZERO_BUDGET_FAMILY_VALUE)
                self.assertEqual(descriptor["run_name"], f"pr3e-offline-proof-{archetype}")

    def test_unknown_artifact_key_rejected_structure_only(self):
        # R9.1: an unknown artifact key is the frozen structure-only
        # rejection under the existing code family (zero new error codes).
        module = self.real_run()
        self.assertIn(
            "artifact_key",
            inspect.signature(module.run_real_baseline_suite).parameters,
        )
        for key in ("external/ghost", "archetype/ghost", "lima-synth/application"):
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    with self.assertRaises(module.RealRunError) as caught:
                        self.run_entry(
                            pathlib.Path(directory) / "out",
                            transport=self.happy_transport(),
                            artifact_key=key,
                        )
                    self.assertEqual(
                        caught.exception.code,
                        module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(caught.exception.field_path, "$")

    def test_synthetic_key_loader_pins_upstream_per_descriptor(self):
        # R9.1 (S1): the loader validates the selected descriptor's pins --
        # a matching document runs, every drift is rejected at its path.
        module = self.real_run()
        key = "archetype/application"
        with tempfile.TemporaryDirectory() as directory:
            approval = self.write_synthetic_artifact(directory, key)
            transport = self.happy_transport()
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                artifact_key=key,
            )
            self.assertEqual(result.attempt_count, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")

            def drift(field, value):
                def mutate(document):
                    document["upstream"][field] = value

                return mutate

            cases = [
                ("repository", drift("repository", "lima-synth/other"),
                 "$.upstream.repository"),
                ("requested_name", drift("requested_name", "lima-synth/other"),
                 "$.upstream.requested_name"),
                ("commit_sha", drift("commit_sha", "0" * 40),
                 "$.upstream.commit_sha"),
                ("tarball_url",
                 drift("tarball_url", "https://lima-synth.invalid/other/tar.gz/x"),
                 "$.upstream.tarball_url"),
            ]

            def drift_approval_type(document):
                document["approval_type"] = "PR3D-REAL-RUN-LIMITED"

            def drift_run_name(document):
                document["run_name"] = "pr3d-real-2026-09-28"

            cases.append(("approval_type", drift_approval_type, "$.approval_type"))
            cases.append(("run_name", drift_run_name, "$.run_name"))
            for label, mutate, field_path in cases:
                with self.subTest(drift=label):
                    drifted = self.write_synthetic_artifact(directory, key, mutate)
                    with self.assertRaises(module.RealRunError) as caught:
                        self.run_entry(
                            pathlib.Path(directory) / "out",
                            transport=self.happy_transport(),
                            artifact_path=drifted,
                            artifact_key=key,
                        )
                    self.assertEqual(
                        caught.exception.code,
                        module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(caught.exception.field_path, field_path)

    def test_zero_budget_synthetic_keys_refuse_before_invoke(self):
        # R9.3(a)/R9.4(3)(4): every synthetic key under a zero-budget
        # document refuses at the first reserve with zero transport calls,
        # a zero ledger, and exactly the frozen five-file evidence set.
        def zero_budget(document):
            for level in ("per_run", "batch"):
                for dimension in _AUTH_PER_RUN:
                    document["budget"][level][dimension] = 0

        for key in _SYNTHETIC_ARTIFACT_KEYS:
            with self.subTest(key=key):
                with tempfile.TemporaryDirectory() as directory:
                    root = pathlib.Path(directory)
                    approval = self.write_synthetic_artifact(directory, key, zero_budget)
                    transport = self.happy_transport()
                    result = self.run_entry(
                        directory,
                        transport=transport,
                        artifact_path=approval,
                        artifact_key=key,
                    )
                    self.assertEqual(transport.chat_calls, 0)
                    self.assertEqual(transport.download_calls, 0)
                    self.assertEqual(result.status, "insufficient_sample")
                    attempt = self.read_attempt(directory, 0)
                    self.assertEqual(attempt["error_code"], "RUN_BUDGET_EXCEEDED")
                    self.assertEqual(
                        attempt["error_field_path"], "$.budget.per_run.calls"
                    )
                    book = result.ledger_snapshot.batch
                    self.assertEqual(book["calls"], 0)
                    for dimension in _LEDGER_BOOK_DIMENSIONS:
                        self.assertEqual(book["consumed"][dimension], 0, dimension)
                    # ALLOWED_ONCE defect 2 (2026-09-28): the frozen
                    # orchestration (run_baseline_attempt per attempt plus the
                    # run_repeats aggregate via write_result_file, then
                    # write_report_file) necessarily persists the
                    # ``{digest16}-run-{1.._ATTEMPT_TOTAL+1}.json`` family and
                    # one ``{digest16}-report-1.json`` next to the frozen
                    # five-file evidence set -- the same root state the v5
                    # test_evidence_written_after_run_repeats_window pins.
                    # The expected set is enumerated from the run digest; the
                    # five-file evidence presence and every substantive
                    # assertion are unchanged.
                    digest16 = result.run_spec_digest[:16]
                    self.assertEqual(
                        {path.name for path in root.iterdir() if path.is_file()},
                        {
                            "approval.md",
                            "approval.json",
                            "ledger.json",
                            "manifest.json",
                            "machine_profile.json",
                        }
                        | {
                            f"{digest16}-run-{sequence}.json"
                            for sequence in range(1, _ATTEMPT_TOTAL + 2)
                        }
                        | {f"{digest16}-report-1.json"},
                    )
                    self.assertEqual(
                        sorted(path.name for path in (root / "attempts").iterdir()),
                        [f"attempt-{index:02d}.json" for index in range(_ATTEMPT_TOTAL)],
                    )

    def test_offline_full_chain_synthetic_key_with_fake_transport(self):
        # R9.3(b)/R9.5: the offline full chain under a synthetic key with
        # the gates unrelaxed -- canary, identity, and the seven-dimension
        # budget all behave exactly as on the llamafactory path.
        module = self.real_run()
        key = "archetype/application"
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            approval = self.write_synthetic_artifact(directory, key)
            transport = self.happy_transport()
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                artifact_key=key,
            )
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.status, "sufficient_sample")
            self.assertEqual(result.canary_status, "passed")
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["canary"]["status"], "passed")
            self.assertEqual(set(manifest["canary"]["checks"]), _CANARY_CHECK_KEYS)
            self.assertEqual(set(manifest["canary"]["checks"].values()), {True})
            self.assertEqual(manifest["cold_count"], _COLD_COUNT)
            self.assertEqual(manifest["warm_count"], _WARM_COUNT)
            descriptor = self.artifact_catalog()[key]
            self.assertTrue(
                (
                    root
                    / "_materialized"
                    / "tarball"
                    / f"lima-synth-application-{descriptor['commit_sha']}.tar.gz"
                ).is_file()
            )
        # Identity gate: an unknown served form is rejected identically.
        with tempfile.TemporaryDirectory() as directory:
            approval = self.write_synthetic_artifact(directory, key)
            transport = self.happy_transport(
                responses=[_chat_response(model=_UNKNOWN_MODEL_FORM)]
            )
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                artifact_key=key,
            )
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            self.assertEqual(
                self.read_attempt(directory, 0)["error_code"],
                "REAL_RUN_RESPONSE_INVALID",
            )
        # Seven-dimension budget gate: a shrunken per-run cost refuses
        # before invoke identically.
        worst_call = (
            math.ceil(_AUTH_PRICES[0] * _REQUEST_BYTE_CAP / 1_000_000)
            + math.ceil(_AUTH_PRICES[1] * _AUTH_PER_RUN["completion_tokens"] / 1_000_000)
        )

        def shrink_cost(document):
            document["budget"]["per_run"]["cost_micro_usd"] = worst_call - 1

        with tempfile.TemporaryDirectory() as directory:
            approval = self.write_synthetic_artifact(directory, key, shrink_cost)
            transport = self.happy_transport()
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                artifact_key=key,
            )
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(transport.download_calls, 0)
            attempt = self.read_attempt(directory, 0)
            self.assertEqual(attempt["error_code"], "RUN_BUDGET_EXCEEDED")
            self.assertEqual(
                attempt["error_field_path"], "$.budget.per_run.cost_micro_usd"
            )
            self.assertEqual(
                {member.value for member in module.RealRunErrorCode},
                _FROZEN_ERROR_CODES,
            )

    def _build_guarded_evaluator(self, directory):
        """Direct evaluator construction (g3/g4 precedent); no attempt yet."""
        module = self.real_run()
        root = pathlib.Path(directory)
        approval_path = self.write_artifact(root)
        contract = module._load_and_validate_approval(approval_path)
        ledger = BudgetLedger(contract.budget_spec, contract.pricing)
        (root / "_materialized" / "tarball").mkdir(parents=True, exist_ok=True)
        (root / "_materialized" / "snapshot").mkdir(parents=True, exist_ok=True)
        transport = self.happy_transport()
        guarded = module._GuardedRealEvaluator(
            ledger=ledger,
            transport=transport,
            api_key=_FAKE_KEY,
            timeout_seconds=120,
            approval=contract,
            output_root=root,
        )
        return guarded, transport, root

    def test_cold_reset_entry_reextracts_rebuilds_and_observes(self):
        # R8.1-R8.3: the reset re-extracts the cached tarball into a fresh
        # per-cold snapshot directory, rebuilds the request body, performs
        # zero GET calls, and returns the frozen observation document.
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-reset-") as directory:
            guarded, transport, root = self._build_guarded_evaluator(directory)
            reset = getattr(guarded, "reset_cold_state", None)
            self.assertIsNotNone(reset, "reset_cold_state is missing (C5 deliverable)")
            guarded()  # attempt-0: materialize, chat, settle
            first_tree = fixtures_module.compute_tree_fingerprint(
                root / "_materialized" / "snapshot"
            )
            first_body_sha = hashlib.sha256(transport.chat_payloads[0]).hexdigest()
            self.assertEqual(transport.download_calls, 1)
            observation = reset()
            self.assertEqual(set(observation), _COLD_RESET_KEYS)
            state_reuse = observation["state_reuse"]
            self.assertEqual(set(state_reuse), _STATE_REUSE_KEYS)
            self.assertIs(state_reuse["materialized"], True)
            self.assertIs(state_reuse["snapshot_reused"], False)
            self.assertIs(state_reuse["request_body_rebuilt"], True)
            self.assertIsNotNone(
                _SF01_TOKEN_PATTERN.match(state_reuse["process_identity"])
            )
            timings = observation["timings"]
            self.assertEqual(
                set(timings), {"extract_ms", "download_ms", "attempt_wall_ms"}
            )
            self.assertIsInstance(timings["extract_ms"], int)
            self.assertGreaterEqual(timings["extract_ms"], 0)
            self.assertIsNone(timings["download_ms"])
            self.assertIsInstance(timings["attempt_wall_ms"], int)
            self.assertGreaterEqual(timings["attempt_wall_ms"], 0)
            self.assertEqual(observation["snapshot_tree_sha256"], first_tree)
            self.assertEqual(observation["request_body_sha256"], first_body_sha)
            self.assertEqual(observation["materialization_count"], 2)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(
                sorted(
                    path.name
                    for path in (root / "_materialized").iterdir()
                    if _PER_COLD_DIR_PATTERN.match(path.name)
                ),
                ["snapshot-cold-2"],
            )
            self.assertTrue((root / "_materialized" / "snapshot-cold-2").is_dir())
            self.assertEqual(len(guarded.records), 1)

    def test_cold_reset_repeat_deterministic_and_full_state_sequence(self):
        # R8.3: two resets are deterministic (identical digests, distinct
        # per-cold directories, incrementing materialization count) and the
        # full default batch sequence stays (T,F,T) + (F,T,F)x9 with the
        # reset observations carrying (T,F,T).
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-seq-") as directory:
            guarded, transport, root = self._build_guarded_evaluator(directory)
            self.assertTrue(
                callable(getattr(guarded, "reset_cold_state", None)),
                "reset_cold_state is missing (C5 deliverable)",
            )
            summary = orchestrate.run_repeats(
                self.spec_mapping(),
                self.load_manifest(),
                guarded,
                root,
                repeat=_COLD_COUNT,
                sources=self.fixed_sources(),
            )
            self.assertEqual(len(summary.attempts), _ATTEMPT_TOTAL)
            first_tree = fixtures_module.compute_tree_fingerprint(
                root / "_materialized" / "snapshot"
            )
            first_body_sha = hashlib.sha256(transport.chat_payloads[0]).hexdigest()
            sequence = [
                (
                    record.state_reuse["materialized"],
                    record.state_reuse["snapshot_reused"],
                    record.state_reuse["request_body_rebuilt"],
                )
                for record in guarded.records
            ]
            self.assertEqual(
                sequence, [(True, False, True)] + [(False, True, False)] * 9
            )
            self.assertEqual(transport.download_calls, 1)
            first_reset = guarded.reset_cold_state()
            second_reset = guarded.reset_cold_state()
            for label, observation in (
                ("first", first_reset),
                ("second", second_reset),
            ):
                with self.subTest(reset=label):
                    self.assertEqual(observation["snapshot_tree_sha256"], first_tree)
                    self.assertEqual(observation["request_body_sha256"], first_body_sha)
                    self.assertIs(observation["state_reuse"]["materialized"], True)
                    self.assertIs(observation["state_reuse"]["snapshot_reused"], False)
                    self.assertIs(
                        observation["state_reuse"]["request_body_rebuilt"], True
                    )
            self.assertEqual(first_reset["materialization_count"], 2)
            self.assertEqual(second_reset["materialization_count"], 3)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(
                sorted(
                    path.name
                    for path in (root / "_materialized").iterdir()
                    if _PER_COLD_DIR_PATTERN.match(path.name)
                ),
                ["snapshot-cold-2", "snapshot-cold-3"],
            )

    def test_default_batch_unchanged_and_no_per_cold_dirs(self):
        # R8.1: the default batch keeps the frozen v5 behavior -- no reset
        # is invoked, no per-cold directory appears, and the state_reuse
        # sequence, mode labels, and manifest counts stay verbatim.
        with tempfile.TemporaryDirectory(prefix="lima-ip0036-def-") as directory:
            root = pathlib.Path(directory)
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(result.status, "sufficient_sample")
            self.assertEqual(
                [
                    path.name
                    for path in (root / "_materialized").iterdir()
                    if _PER_COLD_DIR_PATTERN.match(path.name)
                ],
                [],
            )
            commit = self.canonical_tarball_url().rsplit("/", 1)[1]
            self.assertEqual(
                sorted(path.name for path in (root / "_materialized" / "tarball").iterdir()),
                [f"llamafactory-{commit}.tar.gz"],
            )
            sequence = []
            modes = []
            for index in range(_ATTEMPT_TOTAL):
                document = self.read_attempt(directory, index)
                reuse = document["state_reuse"]
                sequence.append(
                    (
                        reuse["materialized"],
                        reuse["snapshot_reused"],
                        reuse["request_body_rebuilt"],
                    )
                )
                modes.append(document["mode"])
            self.assertEqual(
                sequence, [(True, False, True)] + [(False, True, False)] * 9
            )
            self.assertEqual(modes, ["cold"] * _COLD_COUNT + ["warm"] * _WARM_COUNT)
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["cold_count"], _COLD_COUNT)
            self.assertEqual(manifest["warm_count"], _WARM_COUNT)
            self.assertEqual(manifest["attempt_count"], _ATTEMPT_TOTAL)


class TestBatchShapeProtocol(_RealRunTestCase):
    """IP-0037 FR-01..06 / AC-1..5: the artifact-signed batch protocol.

    Fourteen methods pinning the open-interval attempt-policy
    generalization, the {5,5}-only routing, the shaped driver, the cold-reset
    wiring with the additive ``cold_reset`` observation, the over-budget
    refusals, the missing-reset honesty, the shaped canary latch, the
    dual-batch ledger isolation, and the shaped missing-usage violation
    (Packet sections 7.1-7.6 and 9.1, methods N1-N14).  Everything is
    offline: shaped artifacts are repo-document variants, the transport is
    always an injected fake, and no test ever touches a network socket.
    """

    def _run_shaped_entry(
        self, directory, *, cold, warm, batch_calls, transport=None, responses=None
    ):
        """Entry-driven shaped run through one artifact-signed document."""
        approval = self.write_artifact(
            directory, _shaped_policy(cold, warm, batch_calls=batch_calls)
        )
        if transport is None:
            transport = self.happy_transport(responses=responses)
        result = self.run_entry(
            directory, transport=transport, artifact_path=approval
        )
        return result, transport

    def _build_shaped_evaluator(self, directory, *, cold, warm, batch_calls):
        """Direct shaped evaluator + driver run (g3/g4 construction basis).

        Used by the sixth/ninth-call refusals: the entry path cannot fire an
        extra guarded call on the same ledger (one-time directory gate plus
        one fresh ledger per suite), so the overrun face is driven on a
        directly constructed evaluator whose contract carries the shaped
        artifact's own batch.call ceiling.  The first cold+warm attempts go
        through the frozen private driver (so the canary checklist's
        attempt-0 result-file digest verifies exactly as under the entry);
        only the over-budget call is direct.
        """
        module = self.real_run()
        root = pathlib.Path(directory)
        approval = self.write_artifact(
            root, _shaped_policy(cold, warm, batch_calls=batch_calls)
        )
        contract = module._load_and_validate_approval(approval)
        ledger = BudgetLedger(contract.budget_spec, contract.pricing)
        (root / "_materialized" / "tarball").mkdir(parents=True, exist_ok=True)
        (root / "_materialized" / "snapshot").mkdir(parents=True, exist_ok=True)
        transport = self.happy_transport()
        guarded = module._GuardedRealEvaluator(
            ledger=ledger,
            transport=transport,
            api_key=_FAKE_KEY,
            timeout_seconds=120,
            approval=contract,
            output_root=root,
        )
        summary = module._run_shaped_repeats(
            self.spec_mapping(),
            self.load_manifest(),
            guarded,
            root,
            cold=cold,
            warm=warm,
            sources=self.fixed_sources(),
        )
        return guarded, transport, root, summary

    def test_batch_protocol_static_surface_frozen(self):
        # N-static (FR-01/AC-4/R6, Packet 5.6): the untouched frozen surface
        # plus the one new private driver symbol with its frozen signature.
        module = self.real_run()
        self.assertEqual(module._REPEAT_COUNT, 5)
        self.assertEqual(tuple(module.__all__), _REAL_RUN_ALL)
        self.assertEqual(
            module._ATTEMPT_POLICY_FIELDS,
            ("cold", "warm", "max_attempts", "canary_required", "canary_first_attempt"),
        )
        self.assertEqual(
            {member.value for member in module.RealRunErrorCode}, _FROZEN_ERROR_CODES
        )
        driver = getattr(module, "_run_shaped_repeats", None)
        self.assertIsNotNone(
            driver, "_run_shaped_repeats is missing (C3 deliverable)"
        )
        signature = inspect.signature(driver)
        self.assertEqual(
            list(signature.parameters),
            ["spec_mapping", "manifest", "guarded", "output_dir", "cold", "warm",
             "sources"],
        )
        self.assertEqual(
            {
                name
                for name, parameter in signature.parameters.items()
                if parameter.kind == inspect.Parameter.KEYWORD_ONLY
            },
            {"cold", "warm", "sources"},
        )
        self.assertIsNone(signature.parameters["sources"].default)

    def test_pilot_shape_executes_exactly_five_posts(self):
        # N1 (FR-01/FR-02/AC-1, Packet 7.3/7.4): the pilot artifact
        # {cold:1, warm:4, max:5} with its own batch.calls=5 ceiling executes
        # exactly five successful POSTs -- the count is a success-path
        # count, never failure masquerade (every attempt document succeeds
        # and the canary passes); the aggregate status is the frozen
        # statistical rule applied to 1c+4w, honestly insufficient.
        total = _PILOT_COLD + _PILOT_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-pilot-") as directory:
            result, transport = self._run_shaped_entry(
                directory,
                cold=_PILOT_COLD,
                warm=_PILOT_WARM,
                batch_calls=total,
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(result.attempt_count, total)
            self.assertEqual(result.canary_status, "passed")
            self.assertLess(_PILOT_COLD, _COLD_MIN_SUCCESSES)
            self.assertEqual(result.status, "insufficient_sample")
            documents = [self.read_attempt(directory, index) for index in range(total)]
            self.assertEqual(
                [document["mode"] for document in documents],
                ["cold"] * _PILOT_COLD + ["warm"] * _PILOT_WARM,
            )
            for index, document in enumerate(documents):
                with self.subTest(attempt=index):
                    self.assertEqual(document["outcome"], "success")
                    self.assertIsNone(document["failure_code"])
                    self.assertIsNone(document["error_code"])
            digest16 = result.run_spec_digest[:16]
            self.assertEqual(
                [path.name for path in result.result_paths],
                [f"{digest16}-run-{n}.json" for n in range(1, total + 1)],
            )
            self.assertEqual(
                result.aggregate_path.name, f"{digest16}-run-{total + 1}.json"
            )
            self.assertEqual(result.ledger_snapshot.batch["calls"], total)

    def test_formal_batch_executes_exactly_eight_posts(self):
        # N2 (FR-01/FR-02/AC-1, Packet 7.3/7.4): the formal-batch artifact
        # {3,5,8} with batch.calls=8 executes exactly eight POSTs; 3c+5w
        # exactly meets the frozen sufficient-sample minimums.
        total = _FORMAL_COLD + _FORMAL_WARM
        self.assertEqual((total, _FORMAL_WARM), (8, 5))
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-formal-") as directory:
            result, transport = self._run_shaped_entry(
                directory,
                cold=_FORMAL_COLD,
                warm=_FORMAL_WARM,
                batch_calls=total,
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(transport.download_calls, 1)
            self.assertEqual(result.attempt_count, total)
            self.assertEqual(result.canary_status, "passed")
            self.assertEqual(
                (_FORMAL_COLD, _FORMAL_WARM),
                (_COLD_MIN_SUCCESSES, _WARM_MIN_SUCCESSES),
            )
            self.assertEqual(result.status, "sufficient_sample")
            documents = [self.read_attempt(directory, index) for index in range(total)]
            self.assertEqual(
                [document["mode"] for document in documents],
                ["cold"] * _FORMAL_COLD + ["warm"] * _FORMAL_WARM,
            )
            for index, document in enumerate(documents):
                with self.subTest(attempt=index):
                    self.assertEqual(document["outcome"], "success")
                    self.assertIsNone(document["error_code"])
            self.assertEqual(result.ledger_snapshot.batch["calls"], total)
            digest16 = result.run_spec_digest[:16]
            self.assertEqual(
                result.aggregate_path.name, f"{digest16}-run-{total + 1}.json"
            )

    def test_formal_batch_cold_reset_chain_observability(self):
        # N4 (FR-03/AC-2, Packet 7.5): every cold attempt of the shaped run
        # carries the additive four-key cold_reset observation -- performed
        # False at the initial materialization then True on each verifiable
        # reset, materialization_count monotonically 1->2->3, both digests
        # identical to the first materialization (PC3 recomputation), the
        # per-cold snapshot directories present, resets zero-GET, and the
        # warm attempts reusing with (F,T,F) and no cold_reset key.
        total = _FORMAL_COLD + _FORMAL_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-chain-") as directory:
            root = pathlib.Path(directory)
            result, transport = self._run_shaped_entry(
                directory,
                cold=_FORMAL_COLD,
                warm=_FORMAL_WARM,
                batch_calls=total,
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(transport.download_calls, 1)  # resets are zero-GET
            first_tree = fixtures_module.compute_tree_fingerprint(
                root / "_materialized" / "snapshot"
            )
            first_body_sha = hashlib.sha256(transport.chat_payloads[0]).hexdigest()
            expected = [(False, 1), (True, 2), (True, 3)]
            for index, (performed, count) in enumerate(expected):
                with self.subTest(cold_attempt=index):
                    document = self.read_attempt(directory, index)
                    cold_reset = document["cold_reset"]
                    self.assertEqual(set(cold_reset), _COLD_RESET_VALUE_KEYS)
                    self.assertIs(cold_reset["performed"], performed)
                    self.assertEqual(cold_reset["materialization_count"], count)
                    self.assertEqual(cold_reset["snapshot_tree_sha256"], first_tree)
                    self.assertEqual(cold_reset["request_body_sha256"], first_body_sha)
                    reuse = document["state_reuse"]
                    self.assertIs(reuse["materialized"], True)
                    self.assertIs(reuse["snapshot_reused"], False)
                    self.assertIs(reuse["request_body_rebuilt"], True)
            counts = [
                self.read_attempt(directory, index)["cold_reset"][
                    "materialization_count"
                ]
                for index in range(_FORMAL_COLD)
            ]
            self.assertEqual(counts, sorted(set(counts)))
            self.assertTrue((root / "_materialized" / "snapshot-cold-2").is_dir())
            self.assertTrue((root / "_materialized" / "snapshot-cold-3").is_dir())
            for index in range(_FORMAL_COLD, total):
                with self.subTest(warm_attempt=index):
                    document = self.read_attempt(directory, index)
                    self.assertNotIn("cold_reset", document)
                    reuse = document["state_reuse"]
                    self.assertIs(reuse["materialized"], False)
                    self.assertIs(reuse["snapshot_reused"], True)
                    self.assertIs(reuse["request_body_rebuilt"], False)
            self.assertEqual(result.status, "sufficient_sample")

    def test_shape_tamper_matrix_rejected(self):
        # N3 (FR-01/AC-3, Packet 7.2): every shape tamper is refused by the
        # loader with the existing code and the exact ``$.attempt_policy.*``
        # field path, zero transport.  Each case is one where the pinned
        # v6 validator and the generalized v7 validator reject at the same
        # position, so the whole matrix passes by design in the RED state.
        module = self.real_run()
        cases = [
            ("cold_zero", {"cold": 0}, "$.attempt_policy.cold"),
            ("warm_zero", {"warm": 0}, "$.attempt_policy.warm"),
            ("cold_negative", {"cold": -3}, "$.attempt_policy.cold"),
            ("warm_string", {"warm": "4"}, "$.attempt_policy.warm"),
            ("cold_bool", {"cold": True}, "$.attempt_policy.cold"),
            ("max_mismatch", {"max_attempts": 9}, "$.attempt_policy.max_attempts"),
            (
                "canary_required_false",
                {"canary_required": False},
                "$.attempt_policy.canary_required",
            ),
            (
                "canary_first_attempt_one",
                {"canary_first_attempt": 1},
                "$.attempt_policy.canary_first_attempt",
            ),
        ]
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-tamper-") as directory:
            for label, overrides, field_path in cases:
                with self.subTest(case=label):
                    def mutate(document, overrides=overrides):
                        document["attempt_policy"].update(overrides)

                    approval = self.write_artifact(directory, mutate)
                    transport = self.happy_transport()
                    with self.assertRaises(module.RealRunError) as caught:
                        self.run_entry(
                            pathlib.Path(directory) / f"out-{label}",
                            transport=transport,
                            artifact_path=approval,
                        )
                    self.assertEqual(
                        caught.exception.code,
                        module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
                    )
                    self.assertEqual(caught.exception.field_path, field_path)
                    self.assertEqual(transport.chat_calls, 0)
                    self.assertEqual(transport.download_calls, 0)

    def test_open_interval_shape_two_two_executes(self):
        # N6 (FR-01/AC-1, Packet 7.1/7.2): the open interval admits the
        # well-formed member {2,2,4} (loading and executing exactly four
        # POSTs -- the pin that keeps a shape whitelist from ever silently
        # returning), while max_attempts != cold+warm ({2,3,6}) is refused
        # at the max_attempts position under the generalized semantics.
        module = self.real_run()
        total = _TWO_TWO_COLD + _TWO_TWO_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-twotwo-") as directory:
            result, transport = self._run_shaped_entry(
                directory,
                cold=_TWO_TWO_COLD,
                warm=_TWO_TWO_WARM,
                batch_calls=total,
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(result.attempt_count, total)
            self.assertEqual(
                [self.read_attempt(directory, index)["mode"] for index in range(total)],
                ["cold"] * _TWO_TWO_COLD + ["warm"] * _TWO_TWO_WARM,
            )
            self.assertEqual(result.status, "insufficient_sample")
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-twotwo-bad-") as directory:
            # ALLOWED_ONCE 2026-09-29 (re-freeze v7'): the shared helper
            # always derives max_attempts == cold+warm (PC3), so the {2,3}
            # control face overwrites it to 6 here; only then is
            # max_attempts != cold+warm the rejection cause the method
            # asserts.
            def mutate(document):
                _shaped_policy(2, 3)(document)
                document["attempt_policy"]["max_attempts"] = 6

            approval = self.write_artifact(directory, mutate)
            transport = self.happy_transport()
            with self.assertRaises(module.RealRunError) as caught:
                self.run_entry(
                    pathlib.Path(directory) / "out",
                    transport=transport,
                    artifact_path=approval,
                )
            self.assertEqual(
                caught.exception.code,
                module.RealRunErrorCode.APPROVAL_ARTIFACT_INVALID,
            )
            self.assertEqual(
                caught.exception.field_path, "$.attempt_policy.max_attempts"
            )
            self.assertEqual(transport.chat_calls, 0)

    def test_pilot_sixth_guarded_call_refused_zero_transport(self):
        # N5 (FR-04/AC-3, Packet 8-2): after five successful pilot attempts
        # the sixth guarded call is refused at the artifact-signed batch
        # ceiling with zero transmission.
        total = _PILOT_COLD + _PILOT_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-sixth-") as directory:
            guarded, transport, _root, summary = self._build_shaped_evaluator(
                directory, cold=_PILOT_COLD, warm=_PILOT_WARM, batch_calls=total
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(len(summary.attempts), total)
            self.assertEqual(transport.download_calls, 1)
            with self.assertRaises(BudgetGateError) as caught:
                guarded()
            self.assertEqual(
                caught.exception.code, BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED
            )
            self.assertEqual(caught.exception.field_path, "$.budget.batch.calls")
            self.assertEqual(transport.chat_calls, total)  # zero transmission
            self.assertEqual(len(guarded.records), total + 1)
            refused = guarded.records[total]
            self.assertEqual(refused.outcome, "failure")
            self.assertEqual(refused.error_code, "BATCH_BUDGET_EXCEEDED")

    def test_formal_batch_ninth_guarded_call_refused_zero_transport(self):
        # N6-overrun (FR-04/AC-3, Packet 8-3): the same refusal face one
        # call past the formal batch's eight.
        total = _FORMAL_COLD + _FORMAL_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-ninth-") as directory:
            guarded, transport, _root, summary = self._build_shaped_evaluator(
                directory, cold=_FORMAL_COLD, warm=_FORMAL_WARM, batch_calls=total
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(len(summary.attempts), total)
            with self.assertRaises(BudgetGateError) as caught:
                guarded()
            self.assertEqual(
                caught.exception.code, BudgetGateErrorCode.BATCH_BUDGET_EXCEEDED
            )
            self.assertEqual(caught.exception.field_path, "$.budget.batch.calls")
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(transport.download_calls, 1)

    def test_cold_reset_failure_not_claimed_as_cold_success(self):
        # N7 (FR-03/AC-2, Packet 7.4.3): with the cached tarball deleted
        # after the first POST, the later cold resets fail typed and are
        # never claimed as cold successes (outcome failure, performed never
        # true, materialized honestly not True) while the suite continues
        # fail-closed and the warm reuse path stays unaffected.
        total = _FORMAL_COLD + _FORMAL_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-noreset-") as directory:
            root = pathlib.Path(directory)
            approval = self.write_artifact(
                directory,
                _shaped_policy(_FORMAL_COLD, _FORMAL_WARM, batch_calls=total),
            )
            transport = _TarballDeletingTransport(
                tarball_dir=root / "_materialized" / "tarball",
                tarball=_happy_tarball(),
            )
            result = self.run_entry(
                directory, transport=transport, artifact_path=approval
            )
            self.assertTrue(transport.deleted)
            self.assertEqual(transport.chat_calls, 1 + _FORMAL_WARM)
            self.assertEqual(result.attempt_count, total)
            self.assertEqual(result.status, "insufficient_sample")
            cold0 = self.read_attempt(directory, 0)
            self.assertEqual(cold0["outcome"], "success")
            self.assertIs(cold0["cold_reset"]["performed"], False)
            for index in range(1, _FORMAL_COLD):
                with self.subTest(cold_attempt=index):
                    document = self.read_attempt(directory, index)
                    self.assertEqual(document["outcome"], "failure")
                    self.assertEqual(document["failure_code"], "EXECUTION_ERROR")
                    self.assertIn(document["error_code"], _FROZEN_ERROR_CODES)
                    self.assertIsNot(document["state_reuse"]["materialized"], True)
                    cold_reset = document.get("cold_reset")
                    if cold_reset is not None:
                        self.assertIsNot(cold_reset["performed"], True)
            for index in range(_FORMAL_COLD, total):
                with self.subTest(warm_attempt=index):
                    self.assertEqual(
                        self.read_attempt(directory, index)["outcome"], "success"
                    )

    def test_shaped_canary_failure_latches_zero_follow_on_posts(self):
        # N8 (FR-04/AC-3, Packet 8-5): on the shaped path the canary
        # checklist still runs at index 1 and its failure latches the batch
        # -- zero POSTs after the first, every remaining attempt typed
        # REAL_RUN_CANARY_FAILED.
        total = _PILOT_COLD + _PILOT_WARM
        responses = [_chat_response(prompt_tokens=_REQUEST_BYTE_CAP * 2)]
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-canary-") as directory:
            result, transport = self._run_shaped_entry(
                directory,
                cold=_PILOT_COLD,
                warm=_PILOT_WARM,
                batch_calls=total,
                responses=responses,
            )
            self.assertEqual(transport.chat_calls, 1)
            self.assertEqual(result.canary_status, "failed")
            manifest = self.read_manifest(directory)
            self.assertIs(manifest["canary"]["checks"]["usage_within_reservation"], False)
            self.assertEqual(result.status, "insufficient_sample")
            for index in range(1, total):
                with self.subTest(attempt=index):
                    self.assertEqual(
                        self.read_attempt(directory, index)["error_code"],
                        "REAL_RUN_CANARY_FAILED",
                    )

    def test_dual_batch_ledger_isolation_and_root_reuse_refused(self):
        # N9 (FR-05/AC-3, Packet 7.6): two batches in one process each run
        # on their own artifact and output root with their own ledger
        # starting from zero (the second batch's five successes prove no
        # inheritance of the first batch's spent calls), and a forged third
        # batch pointing at the sealed first root is refused by the
        # one-time directory gate with zero transmission.
        module = self.real_run()
        total = _PILOT_COLD + _PILOT_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-b1-") as first:
            with tempfile.TemporaryDirectory(prefix="lima-ip0037-b2-") as second:
                approval1 = self.write_artifact(
                    first, _shaped_policy(_PILOT_COLD, _PILOT_WARM, batch_calls=total)
                )
                transport1 = self.happy_transport()
                result1 = self.run_entry(
                    first, transport=transport1, artifact_path=approval1
                )
                self.assertEqual(transport1.chat_calls, total)
                approval2 = self.write_artifact(
                    second, _shaped_policy(_PILOT_COLD, _PILOT_WARM, batch_calls=total)
                )
                transport2 = self.happy_transport()
                result2 = self.run_entry(
                    second, transport=transport2, artifact_path=approval2
                )
                self.assertEqual(transport2.chat_calls, total)
                self.assertEqual(result2.ledger_snapshot.batch["calls"], total)
                self.assertEqual(result2.status, result1.status)
                ledgers = [
                    json.loads(
                        (pathlib.Path(run_root) / "ledger.json").read_bytes()
                    )
                    for run_root in (first, second)
                ]
                self.assertEqual(
                    [book["batch"]["calls"] for book in ledgers], [total, total]
                )
                transport3 = self.happy_transport()
                with self.assertRaises(module.RealRunError) as caught:
                    self.run_entry(
                        first, transport=transport3, artifact_path=approval1
                    )
                self.assertEqual(
                    caught.exception.code,
                    module.RealRunErrorCode.REAL_RUN_OUTPUT_NOT_EMPTY,
                )
                self.assertEqual(caught.exception.field_path, "$.output_root")
                self.assertEqual(transport3.chat_calls, 0)
                self.assertEqual(transport3.download_calls, 0)

    def test_default_shape_routes_to_run_repeats_verbatim(self):
        # N10 (FR-02/AC-4, Packet 7.3): the {5,5,10} artifacts keep walking
        # the byte-identical run_repeats path -- ten POSTs, the baseline
        # aggregate family run-1..run-11, the 5+5 mode labels, fifteen-key
        # attempt documents (no cold_reset), and zero per-cold directories
        # -- for the default llamafactory key and for a synthetic key alike
        # (the route depends on the shape only, never the artifact key).
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-old-") as directory:
            root = pathlib.Path(directory)
            transport = self.happy_transport()
            result = self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.attempt_count, _ATTEMPT_TOTAL)
            digest16 = result.run_spec_digest[:16]
            self.assertEqual(
                [path.name for path in result.result_paths],
                [f"{digest16}-run-{n}.json" for n in range(1, _ATTEMPT_TOTAL + 1)],
            )
            self.assertEqual(
                result.aggregate_path.name, f"{digest16}-run-{_ATTEMPT_TOTAL + 1}.json"
            )
            self.assertEqual(
                [self.read_attempt(directory, index)["mode"] for index in range(_ATTEMPT_TOTAL)],
                ["cold"] * _COLD_COUNT + ["warm"] * _WARM_COUNT,
            )
            for index in range(_ATTEMPT_TOTAL):
                with self.subTest(attempt=index):
                    self.assertEqual(
                        set(self.read_attempt(directory, index)), _ATTEMPT_DOC_KEYS
                    )
            self.assertEqual(
                [
                    path.name
                    for path in (root / "_materialized").iterdir()
                    if _PER_COLD_DIR_PATTERN.match(path.name)
                ],
                [],
            )
        key = "archetype/application"
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-oldsyn-") as directory:
            root = pathlib.Path(directory)
            approval = self.write_synthetic_artifact(directory, key)
            transport = self.happy_transport()
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                artifact_key=key,
            )
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            self.assertEqual(result.attempt_count, _ATTEMPT_TOTAL)
            self.assertEqual(set(self.read_attempt(directory, 0)), _ATTEMPT_DOC_KEYS)
            self.assertEqual(
                [
                    path.name
                    for path in (root / "_materialized").iterdir()
                    if _PER_COLD_DIR_PATTERN.match(path.name)
                ],
                [],
            )

    def test_cold_reset_key_presence_matrix(self):
        # N11 (FR-03/AC-2, Packet 7.5.2): the presence rule as a matrix --
        # shaped cold attempts carry sixteen keys with the closed four-key
        # cold_reset value, shaped warm attempts carry the fifteen-key
        # document with the key absent (not a None value), and every {5,5}
        # old-path attempt stays fifteen-key.
        shaped_total = _PILOT_COLD + _PILOT_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-matrix-") as directory:
            self._run_shaped_entry(
                directory,
                cold=_PILOT_COLD,
                warm=_PILOT_WARM,
                batch_calls=shaped_total,
            )
            cold_doc = self.read_attempt(directory, 0)
            self.assertEqual(set(cold_doc), _ATTEMPT_DOC_KEYS | {"cold_reset"})
            self.assertEqual(set(cold_doc["cold_reset"]), _COLD_RESET_VALUE_KEYS)
            for index in range(_PILOT_COLD, shaped_total):
                with self.subTest(warm_attempt=index):
                    document = self.read_attempt(directory, index)
                    self.assertEqual(set(document), _ATTEMPT_DOC_KEYS)
                    self.assertNotIn("cold_reset", document)
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-matrix-old-") as directory:
            self.run_entry(directory, transport=self.happy_transport())
            for index in range(_ATTEMPT_TOTAL):
                with self.subTest(old_attempt=index):
                    self.assertEqual(
                        set(self.read_attempt(directory, index)), _ATTEMPT_DOC_KEYS
                    )

    def test_shaped_missing_usage_violation_not_zero(self):
        # N12 (FR-04/AC-3, Packet 8-7): on the shaped path a warm attempt
        # whose response reports no usage is a REAL_RUN_USAGE_MISSING
        # violation -- never booked as zero -- while the successful
        # attempts' scripted usage carries the consumption (PC3: the
        # expected consumption is recomputed from the scripted values).
        total = _PILOT_COLD + _PILOT_WARM
        responses = [
            _chat_response(),
            _chat_response(),
            _chat_response(with_usage=False),
            _chat_response(),
            _chat_response(),
        ]
        self.assertEqual(len(responses), total)
        with tempfile.TemporaryDirectory(prefix="lima-ip0037-usage-") as directory:
            result, transport = self._run_shaped_entry(
                directory,
                cold=_PILOT_COLD,
                warm=_PILOT_WARM,
                batch_calls=total,
                responses=responses,
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(result.ledger_snapshot.violations, 1)
            document = self.read_attempt(directory, 2)
            self.assertEqual(document["outcome"], "failure")
            self.assertEqual(document["failure_code"], "EXECUTION_ERROR")
            self.assertEqual(document["error_code"], "REAL_RUN_USAGE_MISSING")
            consumed = result.ledger_snapshot.batch["consumed"]
            self.assertEqual(consumed["prompt_tokens"], (total - 1) * 1_000)
            self.assertEqual(consumed["completion_tokens"], (total - 1) * 500)


class TestPreflightCalibration(_RealRunTestCase):
    """IP-0038 FR-01..06 / AC-1..5: the pilot preflight calibration.

    Seven methods pinning the manifest planned-shape three states
    (DR-IP-0037-PV-8: pilot 1/4 and formal 3/5 derived from the carried
    batch shape, the old {5,5} path byte-identical), the option-b calibrated
    budget vector (licensed ceilings exactly admitting the frozen first-round
    reservation), the offline rehearsal full chain with the honest
    source-less V5 unavailable faces (DR-IP-0037-01), the one-byte-short
    ceiling refusals, the static estimate pins, and the manifest derivation
    discipline (Packet sections 7.1-7.5 and 9.1, methods N1-N7).  Everything
    is offline: calibrated artifacts are repo/synthetic document variants,
    the transport is always an injected fake, and no test ever touches a
    network socket.
    """

    def test_manifest_planned_shape_pilot_and_formal(self):
        # N1 (FR-01/AC-1, Packet 7.1): the manifest cold_count/warm_count
        # pair is the approved planned shape derived from the artifact's
        # attempt policy -- pilot {1,4} with the calibrated numeric table
        # writes 1/4, the formal batch {3,5} writes 3/5 -- while the
        # attempt-level actual evidence stays separated in the attempt
        # documents (one cold_reset observation on the initial
        # materialization, none on the warm reuses).
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-pilot-") as directory:
            approval = self.write_artifact(
                directory, _preflight_policy(_PILOT_COLD, _PILOT_WARM)
            )
            result = self.run_entry(
                directory, transport=self.happy_transport(), artifact_path=approval
            )
            self.assertEqual(result.attempt_count, _PILOT_COLD + _PILOT_WARM)
            manifest = self.read_manifest(directory)
            self.assertEqual(manifest["cold_count"], _PILOT_COLD)
            self.assertEqual(manifest["warm_count"], _PILOT_WARM)
            self.assertEqual(manifest["attempt_count"], _PILOT_COLD + _PILOT_WARM)
            cold_document = self.read_attempt(directory, 0)
            self.assertIn("cold_reset", cold_document)
            self.assertIs(cold_document["cold_reset"]["performed"], False)
            self.assertEqual(cold_document["cold_reset"]["materialization_count"], 1)
            for index in range(_PILOT_COLD, _PILOT_COLD + _PILOT_WARM):
                with self.subTest(warm_attempt=index):
                    self.assertNotIn("cold_reset", self.read_attempt(directory, index))
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-formal-") as directory:
            approval = self.write_artifact(
                directory,
                _shaped_policy(
                    _FORMAL_COLD, _FORMAL_WARM, batch_calls=_FORMAL_COLD + _FORMAL_WARM
                ),
            )
            result = self.run_entry(
                directory, transport=self.happy_transport(), artifact_path=approval
            )
            self.assertEqual(result.attempt_count, _FORMAL_COLD + _FORMAL_WARM)
            manifest = self.read_manifest(directory)
            self.assertEqual(
                (manifest["cold_count"], manifest["warm_count"]),
                (_FORMAL_COLD, _FORMAL_WARM),
            )
            self.assertEqual(manifest["attempt_count"], _FORMAL_COLD + _FORMAL_WARM)

    def test_manifest_old_shape_full_document_byte_identical(self):
        # N1-old (FR-01/AC-4, Packet 7.1.4): the {5,5} default artifact keeps
        # producing the byte-identical manifest under the derived-value
        # construction -- the complete inline expected document (every key,
        # every value, PC3-recomputed: digests, the SF-01 token, the worst-
        # case cost formula, the remaining arithmetic) equals the written
        # document and canonical_encode(expected) equals the manifest.json
        # bytes (the persisted order is the canonical sorted order; the byte
        # equality is the order-total carrier).  Deterministic arrange: the
        # constant monotonic clock (batch_wall_ms 0, zero wall consumption).
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-old-") as directory:
            self.patch_monotonic(_JumpClock())
            transport = self.happy_transport()
            self.run_entry(directory, transport=transport)
            self.assertEqual(transport.chat_calls, _ATTEMPT_TOTAL)
            happy_files = _happy_files()
            candidates = sum(1 for name in happy_files if name.endswith(".py"))
            per_attempt_cost = math.ceil(
                _AUTH_PRICES[0] * 1_000 / 1_000_000
            ) + math.ceil(_AUTH_PRICES[1] * 500 / 1_000_000)
            tarball = _happy_tarball()
            consumed = {
                "cost_micro_usd": _ATTEMPT_TOTAL * per_attempt_cost,
                "prompt_tokens": _ATTEMPT_TOTAL * 1_000,
                "completion_tokens": _ATTEMPT_TOTAL * 500,
                "wall_ms": 0,
                "download_bytes": len(tarball),
                "storage_bytes": sum(
                    len(content.encode("utf-8")) for content in happy_files.values()
                ),
            }
            remaining = {
                dimension: _AUTH_PER_RUN[dimension]
                * _AUTH_BATCH_MULTIPLIERS[dimension]
                - consumed[dimension]
                for dimension in (
                    "cost_micro_usd",
                    "prompt_tokens",
                    "completion_tokens",
                    "wall_ms",
                    "download_bytes",
                    "storage_bytes",
                )
            }
            remaining["calls"] = (
                _AUTH_PER_RUN["calls"] * _AUTH_BATCH_MULTIPLIERS["calls"]
                - _ATTEMPT_TOTAL
            )
            expected = {
                "schema_version": 1,
                "run_name": _RUN_NAME,
                "approval_digest": hashlib.sha256(
                    (_REPO_ROOT / _APPROVAL_RELATIVE_PATH).read_bytes()
                ).hexdigest(),
                "baseline_sha": _BASELINE_SHA,
                "attempt_count": _ATTEMPT_TOTAL,
                "cold_count": _COLD_COUNT,
                "warm_count": _WARM_COUNT,
                "failures": [],
                "coverage_gap": len(happy_files) - candidates,
                "canary": {
                    "status": "passed",
                    "checks": dict.fromkeys(_PREFLIGHT_CANARY_ORDER, True),
                },
                "batch_remaining": remaining,
                "batch_wall_ms": 0,
                "deadline": {"batch_wall_exceeded": False},
                "tarball_sha256": hashlib.sha256(tarball).hexdigest(),
                "model": _REQUEST_MODEL,
                "system_fingerprint_baseline": _sf01_token("fp-stable-001"),
                "execution_commit_sha": "pending-operator-record",
            }
            manifest = self.read_manifest(directory)
            self.assertEqual(list(manifest), sorted(manifest))
            self.assertEqual(manifest, expected)
            raw = (pathlib.Path(directory) / "manifest.json").read_bytes()
            self.assertEqual(canonical_encode(expected), raw)

    def test_pilot_rehearsal_full_chain_offline_report(self):
        # N2 (FR-02/FR-03/FR-04/FR-05/AC-2/AC-3, Packet 7.2/7.4/7.5 and 8-2):
        # the offline rehearsal full chain -- the exact numeric-table pilot
        # artifact under the synthetic large-repo key, the formal entry, a
        # fake transport, and an empty output directory to the report.
        # Exactly five POSTs and five attempt documents, zero budget
        # refusals, the licensed-ceiling vs actual-download distinction in
        # the released bucket, one cold_reset observation on the initial
        # materialization (performed False, count 1; a {1,4} pilot performs
        # zero verifiable resets and claims none -- DR-IP-0038-PV-2), four
        # warm reuses, the planned manifest shape, and every source-less V5
        # report field honestly null + unavailable.
        total = _PILOT_COLD + _PILOT_WARM
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-rehearsal-") as directory:
            root = pathlib.Path(directory)
            approval = self.write_synthetic_artifact(
                directory,
                _PREFLIGHT_REHEARSAL_KEY,
                _preflight_policy(_PILOT_COLD, _PILOT_WARM),
            )
            transport = self.happy_transport()
            result = self.run_entry(
                directory,
                transport=transport,
                artifact_path=approval,
                artifact_key=_PREFLIGHT_REHEARSAL_KEY,
            )
            self.assertEqual(transport.chat_calls, total)
            self.assertEqual(transport.download_calls, 0)
            self.assertEqual(result.attempt_count, total)
            self.assertEqual(result.canary_status, "passed")
            documents = [self.read_attempt(directory, index) for index in range(total)]
            for index, document in enumerate(documents):
                with self.subTest(attempt=index):
                    self.assertEqual(document["outcome"], "success")
                    self.assertIsNone(document["error_code"])
            self.assertLess(_PILOT_COLD, _COLD_MIN_SUCCESSES)
            self.assertEqual(result.status, "insufficient_sample")
            ledger = json.loads((root / "ledger.json").read_bytes())
            self.assertEqual(ledger["violations"], 0)
            book = ledger["batch"]
            self.assertEqual(book["calls"], total)
            self.assertEqual(book["consumed"]["download_bytes"], 0)
            self.assertEqual(
                book["released"]["download_bytes"], _PREFLIGHT_BATCH["download_bytes"]
            )
            self.assertEqual(
                book["released"]["storage_bytes"],
                _PREFLIGHT_BATCH["storage_bytes"]
                - book["consumed"]["storage_bytes"],
            )
            with_reset = [
                index
                for index, document in enumerate(documents)
                if "cold_reset" in document
            ]
            self.assertEqual(with_reset, [0])
            self.assertIs(documents[0]["cold_reset"]["performed"], False)
            self.assertEqual(documents[0]["cold_reset"]["materialization_count"], 1)
            self.assertEqual(
                sum(
                    1
                    for document in documents
                    if document.get("cold_reset", {}).get("performed") is True
                ),
                0,
            )
            for index in range(_PILOT_COLD, total):
                state = documents[index]["state_reuse"]
                with self.subTest(warm_attempt=index):
                    self.assertIs(state["materialized"], False)
                    self.assertIs(state["snapshot_reused"], True)
                    self.assertIs(state["request_body_rebuilt"], False)
            manifest = self.read_manifest(directory)
            self.assertEqual(
                (manifest["cold_count"], manifest["warm_count"]),
                (_PILOT_COLD, _PILOT_WARM),
            )
            self.assertEqual(manifest["failures"], [])
            self.assertEqual(manifest["attempt_count"], total)
            report = json.loads(pathlib.Path(result.report_path).read_bytes())
            for key in (
                "signals",
                "security_issues",
                "hypotheses",
                "confirmed",
                "inconclusive",
            ):
                with self.subTest(counts=key):
                    self.assertEqual(
                        report["counts"][key],
                        {"value": None, "projection": "unavailable"},
                    )
            for face in ("vep", "rvr"):
                self.assertEqual(
                    report[face], {"value": None, "projection": "unavailable"}, face
                )
            for stage in ("audit", "mining", "repair"):
                self.assertEqual(
                    report["stage_outcome"][stage],
                    {"value": None, "projection": "unavailable"},
                    stage,
                )
            self.assertEqual(
                report["resources"],
                {"prompt_tokens": None, "completion_tokens": None, "cost_micro_usd": None},
            )
            self.assertIsNone(report["expert"]["active_time_ms_total"])
            self.assertEqual(report["evidence_domain"], "legacy")
            self.assertEqual(report["attempt_count"], total)

    def test_download_ceiling_one_byte_short_refused_zero_posts(self):
        # N3 (FR-03/AC-2, Packet 8-3): a licensed ceiling one byte below the
        # frozen first-round conservative reservation (250,000,000) never
        # pays for a call.  With per_run at the numeric table the artifact is
        # itself contradictory (batch < per_run) and the frozen BudgetSpec
        # construction refuses it under the batch download field path; with
        # both levels one byte short the first reserve of the very first
        # attempt is refused (the per-run gate precedes the batch gate) and
        # the canary then latches the batch -- in both faces zero POSTs and
        # zero GETs (DR-IP-0038-PV-3, probe-verified frozen mechanics).
        short = _PREFLIGHT_ONE_BYTE_SHORT
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-short-batch-") as directory:
            approval = self.write_artifact(
                directory,
                _preflight_policy(
                    _PILOT_COLD,
                    _PILOT_WARM,
                    batch={**_PREFLIGHT_BATCH, "download_bytes": short},
                ),
            )
            transport = self.happy_transport()
            with self.assertRaises(BudgetGateError) as caught:
                self.run_entry(
                    directory, transport=transport, artifact_path=approval
                )
            self.assertIs(
                caught.exception.code, BudgetGateErrorCode.BUDGET_SPEC_INVALID
            )
            self.assertEqual(
                caught.exception.field_path, "$.budget.batch.download_bytes"
            )
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(transport.download_calls, 0)
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-short-both-") as directory:
            approval = self.write_artifact(
                directory,
                _preflight_policy(
                    _PILOT_COLD,
                    _PILOT_WARM,
                    batch={**_PREFLIGHT_BATCH, "download_bytes": short},
                    per_run={**_PREFLIGHT_PER_RUN, "download_bytes": short},
                ),
            )
            transport = self.happy_transport()
            result = self.run_entry(
                directory, transport=transport, artifact_path=approval
            )
            self.assertEqual(transport.chat_calls, 0)
            self.assertEqual(transport.download_calls, 0)
            self.assertEqual(result.canary_status, "failed")
            refused = self.read_attempt(directory, 0)
            self.assertEqual(refused["outcome"], "failure")
            self.assertEqual(refused["error_code"], "RUN_BUDGET_EXCEEDED")
            self.assertEqual(
                refused["error_field_path"], "$.budget.per_run.download_bytes"
            )
            for index in range(1, _PILOT_COLD + _PILOT_WARM):
                with self.subTest(latched_attempt=index):
                    latched = self.read_attempt(directory, index)
                    self.assertEqual(latched["outcome"], "failure")
                    self.assertEqual(latched["error_code"], "REAL_RUN_CANARY_FAILED")
            book = json.loads(
                (pathlib.Path(directory) / "ledger.json").read_bytes()
            )["batch"]
            self.assertEqual(book["calls"], 0)

    def test_estimate_constants_and_first_round_wiring_pinned(self):
        # N4 (FR-03/AC-2, Packet 8-4): the first-round conservative
        # reservation is never relaxed -- the frozen module constants keep
        # their values and the attempt-0 estimate branch wires exactly the
        # byte cap, the token cap, the per-run wall bound, and both resource
        # constants (AST-level pinning so a hidden relaxation cannot pass
        # silently).
        module = self.real_run()
        self.assertEqual(module._DOWNLOAD_ESTIMATE_BYTES, 250_000_000)
        self.assertEqual(module._STORAGE_ESTIMATE_BYTES, 500_000_000)
        self.assertEqual(module._WALL_ESTIMATE_MS, 1_200_000)
        tree = ast.parse(self.product_source(_MODULE_RELATIVE_PATH))
        estimate_functions = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name == "_estimate_for"
        ]
        self.assertEqual(len(estimate_functions), 1)
        first_round = None
        for node in ast.walk(estimate_functions[0]):
            if isinstance(node, ast.Return) and isinstance(node.value, ast.Call):
                keywords = {keyword.arg: keyword.value for keyword in node.value.keywords}
                if "download_bytes" in keywords:
                    first_round = keywords
        self.assertIsNotNone(first_round)
        self.assertIsInstance(first_round["prompt_tokens"], ast.Name)
        self.assertEqual(first_round["prompt_tokens"].id, "REQUEST_BODY_BYTE_CAP")
        self.assertIsInstance(first_round["completion_tokens"], ast.Name)
        self.assertEqual(first_round["completion_tokens"].id, "MAX_TOKENS")
        self.assertEqual(
            ast.unparse(first_round["wall_ms"]),
            "self._approval.budget_spec.per_run.wall_ms",
        )
        self.assertIsInstance(first_round["download_bytes"], ast.Name)
        self.assertEqual(first_round["download_bytes"].id, "_DOWNLOAD_ESTIMATE_BYTES")
        self.assertIsInstance(first_round["storage_bytes"], ast.Name)
        self.assertEqual(first_round["storage_bytes"].id, "_STORAGE_ESTIMATE_BYTES")

    def test_manifest_derivation_discipline_carried_state_only(self):
        # N6 (FR-01/AC-1, Packet 8-6): the planned counts are class read-only
        # properties (never exported in __all__), they resolve the carried
        # batch shape with the (5,5) default, and the manifest builder reads
        # only the carried state -- the builder source references the
        # properties, never the approval document's attempt_policy (no
        # second parse) and never the hardcoded repeat count.
        module = self.real_run()
        for name in ("planned_cold_count", "planned_warm_count"):
            attribute = getattr(module._GuardedRealEvaluator, name, None)
            self.assertIsInstance(attribute, property, name)
        self.assertEqual(tuple(module.__all__), _REAL_RUN_ALL)
        for name in ("planned_cold_count", "planned_warm_count"):
            self.assertNotIn(name, module.__all__)
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-carried-") as directory:
            root = pathlib.Path(directory)
            approval = self.write_artifact(root)
            contract = module._load_and_validate_approval(approval)
            (root / "_materialized" / "tarball").mkdir(parents=True, exist_ok=True)
            (root / "_materialized" / "snapshot").mkdir(parents=True, exist_ok=True)

            def build(shape):
                return module._GuardedRealEvaluator(
                    ledger=BudgetLedger(contract.budget_spec, contract.pricing),
                    transport=self.happy_transport(),
                    api_key=_FAKE_KEY,
                    timeout_seconds=120,
                    approval=contract,
                    output_root=root,
                    batch_shape=shape,
                )

            default = build(None)
            self.assertEqual(
                (default.planned_cold_count, default.planned_warm_count),
                (_COLD_COUNT, _WARM_COUNT),
            )
            pilot = build((_PILOT_COLD, _PILOT_WARM))
            self.assertEqual(
                (pilot.planned_cold_count, pilot.planned_warm_count),
                (_PILOT_COLD, _PILOT_WARM),
            )
            formal = build((_FORMAL_COLD, _FORMAL_WARM))
            self.assertEqual(
                (formal.planned_cold_count, formal.planned_warm_count),
                (_FORMAL_COLD, _FORMAL_WARM),
            )
        tree = ast.parse(self.product_source(_MODULE_RELATIVE_PATH))
        builders = [
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef)
            and node.name == "_build_manifest_document"
        ]
        self.assertEqual(len(builders), 1)
        builder_source = ast.unparse(builders[0])
        self.assertIn("guarded.planned_cold_count", builder_source)
        self.assertIn("guarded.planned_warm_count", builder_source)
        self.assertNotIn("attempt_policy", builder_source)
        self.assertNotIn("_REPEAT_COUNT", builder_source)

    def test_numeric_table_artifact_loader_dual_source(self):
        # N7 (FR-03/AC-2, Packet 8-7): the artifact built from the test-side
        # replica of the Packet numeric table loads through the frozen
        # validator and the parsed budget spec equals the table on both
        # levels and every dimension (dual-source consistency), and the R5
        # admission constraints hold as recomputed relations (each batch
        # dimension at or above its per-run counterpart and at or above the
        # first-round worst-case reservation; the resource ceilings exactly
        # at the frozen estimate constants).
        module = self.real_run()
        with tempfile.TemporaryDirectory(prefix="lima-ip0038-table-") as directory:
            approval = self.write_artifact(
                directory, _preflight_policy(_PILOT_COLD, _PILOT_WARM)
            )
            contract = module._load_and_validate_approval(approval)
            for level, table in (
                ("per_run", _PREFLIGHT_PER_RUN),
                ("batch", _PREFLIGHT_BATCH),
            ):
                for dimension, value in table.items():
                    with self.subTest(level=level, dimension=dimension):
                        self.assertEqual(
                            getattr(getattr(contract.budget_spec, level), dimension),
                            value,
                        )
            policy = contract.document["attempt_policy"]
            self.assertEqual(
                (policy["cold"], policy["warm"], policy["max_attempts"]),
                (_PILOT_COLD, _PILOT_WARM, _PILOT_COLD + _PILOT_WARM),
            )
            per_run = contract.budget_spec.per_run
            batch = contract.budget_spec.batch
            for dimension in _PREFLIGHT_PER_RUN:
                self.assertGreaterEqual(
                    getattr(batch, dimension), getattr(per_run, dimension), dimension
                )
            first_round_cost = math.ceil(
                _AUTH_PRICES[0] * module.REQUEST_BODY_BYTE_CAP / 1_000_000
            ) + math.ceil(_AUTH_PRICES[1] * module.MAX_TOKENS / 1_000_000)
            self.assertGreaterEqual(batch.prompt_tokens, module.REQUEST_BODY_BYTE_CAP)
            self.assertGreaterEqual(batch.completion_tokens, module.MAX_TOKENS)
            self.assertGreaterEqual(batch.wall_ms, per_run.wall_ms)
            self.assertGreaterEqual(batch.cost_micro_usd, first_round_cost)
            self.assertEqual(batch.download_bytes, module._DOWNLOAD_ESTIMATE_BYTES)
            self.assertEqual(batch.storage_bytes, module._STORAGE_ESTIMATE_BYTES)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
