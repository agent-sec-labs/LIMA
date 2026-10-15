"""IP-0023 / PR #284 targeted-rework delta regression (IR-01..IR-04).

Frozen delta regression for ASSIGN-60-PR284-TARGETED-REWORK_v1: the four
review findings against rejected head 966181bd, each with its own
independently derived expectation.

- IR-01 aggregate token pools are shared across the whole build call
  (Packet v5.1 section 5.4.4 single scheduling rule: per-attempt estimate
  checked against all three pool remainders, pre-deduction, no refund,
  insufficient attempts are not scheduled).
- IR-02 mixed-cap truncation counts dropped unknown-import *records*
  (section 5.3.4), not import sites; the sum over scan summaries equals
  the unknown-import-limit gap count (V7) and the partial payload stays
  consumable.
- IR-03 ResourceMetering equals real read attempts/successful bytes over
  the nine IO stages (section 5.4.4-IO), observed here by watching
  ``Path.read_bytes`` without altering any data or return value.
- IR-04 the public validator rejects structurally illegal payloads even
  when their identity digest has been consistently recomputed (V5 path
  shapes, V6 sort/dedup, V8 budget domains and the frozen cross-field
  invariant).

Independence policy: every expected number below is hand-derived from the
frozen rules plus the fixture bytes written by this file (byte lengths are
recomputed from the very constants declared here); the builder under test,
its private helpers, and any implementer reference module are never used
to back-fill an answer. Per-call token estimates follow the frozen
estimator calibre (``ceil(chars/4)`` prompts, 128 tokens per batched
candidate) and are recomputed inside the offline client double from the
prompts it actually receives. The module under test is imported lazily so
failures stay behavioural rather than import-time.

Fixture/runtime discipline: lazy temp trees (LF pinned), offline clients,
zero network, no execution of fixture sources.

RC-TEST-01 (mechanical correction, 2026-10-15, MR-60-PR284-CI-AND-
INTEGRATION-RECOVERY-20261015/v1): the observation root now follows the
same root semantics as ``RepositoryWorkspace`` (expanduser + resolve) and
``repo_tree`` yields the resolved root, so equivalent spellings of one
physical root observe the identical non-zero ledger; the pre-fix purely
lexical matching silently dropped alias spellings (``pivot/..``, Windows
8.3 short names) — the CI miss. Product semantics, expected values and
assertion strength are unchanged.
"""

from __future__ import annotations

import ctypes
import importlib
import json
import os
import re
import shutil
import sys
import tempfile
import unittest
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from copy import deepcopy
from pathlib import Path
from typing import Any
from unittest.mock import patch

from lima.audit.ram_schema import (
    execution_required_from_gaps,
    ram_facts_digest_from_wire,
    ram_wire_digest,
    semantic_result_digest_from_wire,
    validate_ram_wire_payload,
)
from lima.audit.semantic_prioritizer import SemanticBudgets, SemanticOptions
from lima.contracts.codec import compute_content_digest
from lima.contracts.errors import ContractError
from lima.workspace import RepositoryWorkspace

BUILD_KWARGS: dict[str, str] = {
    "tenant_id": "tenant-pr284-rework",
    "task_id": "task-pr284-rework",
    "workflow_id": "workflow-pr284-rework",
    "stage_attempt_id": "stage-pr284-rework",
    "artifact_id": "artifact-pr284-rework",
    "repository_snapshot_digest": "1" * 64,
}

# ---------------------------------------------------------------------------
# Fixture contents (the byte lengths used in expectations come from these
# exact constants; assertions recompute lengths from them, never from
# builder output).
# ---------------------------------------------------------------------------

REQUIREMENTS_TXT = "flask==3.0\n"  # 11 bytes
MAIN_PY = "def handler(x):\n    return x\n"  # 29 bytes
SECOND_PY = "value = 2\n"  # 10 bytes
A_MAIN_PY = "value = 1\n"  # 10 bytes
PYPROJECT_TOML = '[project]\nname = "demo"\nversion = "1.0"\n'  # 40 bytes
NULMOD_PY = b"v\x00=1\n"  # 5 bytes (read succeeds, then binary-skip)
BAD_REQUIREMENTS = b"flask==3.0\n\xff\xfe"  # 13 bytes (decode fails after read)
POOL_MAIN_PY = (
    "import os\n"
    "from framework import request\n"
    "\n"
    "def handler(request):\n"
    "    os.system(request.args.get('cmd'))\n"
)

#: Assignment-pinned concrete estimator instance for one pool-fixture model
#: call (one candidate per batched call at ``max_llm_calls=1``): the frozen
#: calibre applied to the rendered prompt yields 173 prompt tokens, 128
#: output tokens, 301 total.
POOL_PER_CALL_ESTIMATE = (173, 128, 301)

#: Frozen aggregate-pool defaults (Packet v5.1 section 5.4.4) and the small
#: caller pools of the IR-01 fixture.
POOL_DEFAULTS = (24_000, 4_096, 28_096)
POOL_CALLER = (1_000, 500, 1_500)


def pool_repo(names: str) -> dict[str, str]:
    files: dict[str, str] = {}
    for name in names:
        files[f"{name}/requirements.txt"] = REQUIREMENTS_TXT
        files[f"{name}/main.py"] = POOL_MAIN_PY
    return files


UNKNOWN_AB_REPO = {
    "a/requirements.txt": REQUIREMENTS_TXT,
    "a/main.py": "import missing_alpha\n",
    "b/requirements.txt": REQUIREMENTS_TXT,
    "b/main.py": "import missing_zeta\nimport missing_zeta\n",
}

#: Multi-file same-key shape: component c aggregates two import sites of one
#: name across two files into ONE record (count=2 sites, 1 record).
UNKNOWN_MULTI_FILE_REPO = {
    "a/requirements.txt": REQUIREMENTS_TXT,
    "a/main.py": "import missing_alpha\n",
    "c/requirements.txt": REQUIREMENTS_TXT,
    "c/one.py": "import missing_mu\n",
    "c/two.py": "import missing_mu\n",
}

#: Mixed flow: two resolved edges (b->a, c->a) then unknown records
#: (a/missing_alpha with 2 sites, b/missing_zeta with 2 sites).
MIXED_CAP_REPO = {
    "a/pyproject.toml": '[project]\nname = "edgea"\nversion = "1.0"\n',
    "a/src/shared/__init__.py": "VALUE = 1\n",
    "a/use.py": "import missing_alpha\nimport missing_alpha\n",
    "b/pyproject.toml": '[project]\nname = "edgeb"\nversion = "1.0"\n',
    "b/call.py": "import shared\nimport missing_zeta\nimport missing_zeta\n",
    "c/pyproject.toml": '[project]\nname = "edgec"\nversion = "1.0"\n',
    "c/call.py": "import shared\n",
}

#: IR-04 base: three components, two edges (one with two evidence lines),
#: two unknown records, two unassigned files, one dual-source manifest pair.
VALIDATOR_BASE_REPO = {
    "a/pyproject.toml": '[project]\nname = "edgea"\nversion = "1.0"\n',
    "a/requirements.txt": REQUIREMENTS_TXT,
    "a/src/shared/__init__.py": "VALUE = 1\n",
    "a/use.py": "import missing_alpha\n",
    "b/pyproject.toml": '[project]\nname = "edgeb"\nversion = "1.0"\n',
    "b/call.py": "import shared\nimport shared\nimport missing_zeta\n",
    "c/pyproject.toml": '[project]\nname = "edgec"\nversion = "1.0"\n',
    "c/call.py": "import shared\n",
    "loose.py": "def loose():\n    return 1\n",
    "loose2.py": "def loose2():\n    return 2\n",
}


def load_cg() -> Any:
    """Lazily import the module under test (behavioural RED anchor)."""

    return importlib.import_module("lima.audit.component_graph")


@contextmanager
def repo_tree(
    files: Mapping[str, str | bytes], *, reverse: bool = False
) -> Iterator[Path]:
    """Materialize ``files`` in a fresh temp tree (LF pinned); yield the root.

    ``reverse=True`` writes the same content in reversed order, exercising
    write-order independence (section 5.7 determinism).

    RC-TEST-01: the yielded root is resolved once, so the fixture hands out
    the same canonical spelling the workspace itself would derive (the raw
    mkdtemp spelling may carry alias components on some hosts).
    """

    root = Path(tempfile.mkdtemp(prefix="lima-pr284-rework-")).resolve()
    names = sorted(files)
    if reverse:
        names = names[::-1]
    try:
        for rel in names:
            target = root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            content = files[rel]
            if isinstance(content, bytes):
                target.write_bytes(content)
            else:
                target.write_text(content, encoding="utf-8", newline="\n")
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


@contextmanager
def observing_reads(root: Path) -> Iterator[list[tuple[str, int]]]:
    """Observe real ``Path.read_bytes`` calls under ``root`` (observe-only).

    Records ``(repo-relative path, successful bytes)``; failures record 0
    bytes and re-raise. Reads outside ``root`` pass through unrecorded. The
    observer never alters data or return values.

    RC-TEST-01: the observation root is normalised once with the same root
    semantics as ``RepositoryWorkspace`` (expanduser + resolve), so every
    equivalent spelling of one physical root (lexical ``pivot/..`` aliases,
    Windows 8.3 short names) records the same ledger; a purely lexical
    ``relative_to`` against the caller's spelling silently dropped those
    reads (CI miss) without touching any product path policy.
    """

    observation_root = root.expanduser().resolve(strict=True)
    records: list[tuple[str, int]] = []
    original = Path.read_bytes

    def observer(path: Path) -> bytes:
        try:
            rel = path.relative_to(observation_root).as_posix()
        except ValueError:
            return original(path)
        try:
            data = original(path)
        except OSError:
            records.append((rel, 0))
            raise
        records.append((rel, len(data)))
        return data

    with patch.object(Path, "read_bytes", observer):
        yield records


def windows_short_path_alias(path: Path) -> Path | None:
    """Real Windows 8.3 short spelling of ``path`` when the volume has one.

    Returns None on non-Windows platforms and when the volume provides no
    distinct short name (8.3 generation disabled): nothing is ever faked,
    and the cross-platform alias variants never depend on it.
    """

    if sys.platform != "win32":
        return None
    kernel32 = ctypes.windll.kernel32
    size = kernel32.GetShortPathNameW(str(path), None, 0)
    if size == 0:
        return None
    buffer = ctypes.create_unicode_buffer(size + 1)
    if kernel32.GetShortPathNameW(str(path), buffer, size + 1) == 0:
        return None
    short = buffer.value
    if short.lower() == str(path).lower():
        return None
    return Path(short)


def build_payload(
    root: Path,
    *,
    workspace_limits: Mapping[str, Any] | None = None,
    **options: Any,
) -> tuple[Any, Any, Any]:
    """Build once; return ``(cg, result, payload)``."""

    cg = load_cg()
    result = cg.build_monorepo_profile(
        RepositoryWorkspace(root, **dict(workspace_limits or {})),
        **BUILD_KWARGS,
        **options,
    )
    return cg, result, cg.component_graph_payload(result)


def entry_of(payload: Mapping[str, Any], component_id: str) -> dict[str, Any]:
    for entry in payload["components"]:
        if entry["component_id"] == component_id:
            return entry
    raise AssertionError(f"component {component_id} missing from payload")


def summary_of(payload: Mapping[str, Any], component_id: str) -> dict[str, Any]:
    for summary in payload["scan_summaries"]:
        if summary["component_id"] == component_id:
            return summary
    raise AssertionError(f"scan summary for {component_id} missing")


def find_gap(payload: Mapping[str, Any], reason: str) -> str | None:
    for gap in payload["coverage_gaps"]:
        if f"reason={reason};" in gap["detail"]:
            return gap["detail"]
    return None


def gap_count(detail: str | None) -> int | None:
    if detail is None:
        return None
    match = re.search(r"count=([0-9]+)", detail)
    if match is None:
        raise AssertionError(f"unparseable gap detail: {detail!r}")
    return int(match.group(1))


def consumes_public_artifacts(result: Any, payload: Mapping[str, Any]) -> None:
    """Section 5.4.7 consumption basis over every built component."""

    wires = {b.component.component_id: b for b in result.per_component}
    for entry in payload["components"]:
        if not entry["built"]:
            continue
        built = wires[entry["component_id"]]
        wire = built.ram_wire
        validate_ram_wire_payload(wire)
        assert ram_wire_digest(wire) == wire["identity"]["wire_digest"]
        assert (
            ram_facts_digest_from_wire(wire)
            == entry["digests"]["ram_facts_digest"]
        )
        assert (
            semantic_result_digest_from_wire(wire)
            == entry["digests"]["semantic_result_digest"]
        )
        assert (
            built.profile_result.envelope.content_digest
            == entry["digests"]["profile_content_digest"]
        )
        gap_codes = [
            gap["gap_code"]
            for section in ("ram", "semantic")
            for gap in wire[section]["coverage_gaps"]
        ]
        required, triggers = execution_required_from_gaps(gap_codes)
        assert wire["execution_required"] == {
            "required": required,
            "trigger_gap_codes": list(triggers),
        }


class OfflineEstimatingClient:
    """Offline model double recording frozen-calibre estimates per call.

    Modes: ``normal`` (valid JSON reply), ``malformed`` (non-JSON reply),
    ``timeout`` (TimeoutError). No network, no state beyond the record.
    """

    def __init__(self, mode: str = "malformed") -> None:
        self.mode = mode
        self.calls: list[tuple[int, int, int]] = []

    def complete(self, prompt: str, *, timeout_seconds: int) -> str:
        # Frozen estimator calibre (Packet v5.1 section 5.4.4 (i)):
        # prompt = ceil(chars/4); output = 128 tokens per batched candidate.
        prompt_tokens = max(1, (len(prompt) + 3) // 4)
        output_tokens = 128 * prompt.count('"candidate_id":')
        self.calls.append(
            (prompt_tokens, output_tokens, prompt_tokens + output_tokens)
        )
        if self.mode == "timeout":
            raise TimeoutError("offline timeout")
        if self.mode == "malformed":
            return "offline malformed reply"
        ids = re.findall(r'"candidate_id":"([^"]+)"', prompt)
        return json.dumps(
            [
                {
                    "candidate_id": cid,
                    "category": "command-execution",
                    "rationale": "offline deterministic assessment",
                }
                for cid in ids
            ]
        )


def caller_budgets(prompt: int, output: int, total: int) -> SemanticOptions:
    return SemanticOptions(
        model_id="offline",
        budgets=SemanticBudgets(
            max_llm_calls=1,
            max_prompt_tokens_estimate=prompt,
            max_output_tokens_estimate=output,
            max_total_tokens_estimate=total,
        ),
    )


def funded_calls(pools: tuple[int, int, int], estimate: tuple[int, int, int]) -> int:
    """Section 5.4.4 (i): attempts funded by the shared remaining pools.

    Each attempt needs the prompt/output/total remainders and pre-deducts
    all three without refund; with uniform per-call estimates the funded
    count is the floor-division minimum over the three pools.
    """

    return min(
        pool // value for pool, value in zip(pools, estimate, strict=True)
    )


# ---------------------------------------------------------------------------
# IR-01: whole-build aggregate token pools
# ---------------------------------------------------------------------------


class AggregateTokenPoolTests(unittest.TestCase):
    """IR-01: the min(requested, caller) pools fund the whole build once."""

    def test_shared_pools_bound_the_whole_build(self) -> None:
        cg = load_cg()
        options = caller_budgets(*POOL_CALLER)
        with repo_tree(pool_repo("abcdefgh")) as root:
            client = OfflineEstimatingClient("malformed")
            result = cg.build_monorepo_profile(
                RepositoryWorkspace(root),
                semantic_options=options,
                model_client=client,
                **BUILD_KWARGS,
            )
        payload = cg.component_graph_payload(result)

        self.assertTrue(client.calls, "fixture must attempt model calls")
        self.assertEqual(
            len(set(client.calls)),
            1,
            "identical components must yield uniform per-call estimates",
        )
        first = client.calls[0]
        self.assertEqual(
            first,
            POOL_PER_CALL_ESTIMATE,
            "frozen-calibre estimate for the pool fixture must be (173,128,301)",
        )
        funded = funded_calls(POOL_CALLER, first)
        self.assertEqual(funded, 3)
        self.assertEqual(
            len(client.calls),
            funded,
            "IR-01: the whole-build shared pools must fund exactly the "
            f"shared-ledger count ({funded}); observed {len(client.calls)} "
            "scheduled calls",
        )
        self.assertEqual(tuple(funded * value for value in first), (519, 384, 903))
        # The 4th attempt is unfunded: output remainder 500 - 3*128 = 116 < 128.
        self.assertLess(POOL_CALLER[1] - funded * first[1], first[1])
        detail = find_gap(payload, "aggregate-token-pool-limit")
        self.assertIsNotNone(
            detail, "typed aggregate-token-pool-limit gap must be published"
        )
        self.assertEqual(gap_count(detail), 8 - funded)
        self.assertIsNone(cg.validate_component_graph_payload(payload))
        # Token pools are a non-dependency-evidence state: completeness holds.
        self.assertTrue(payload["dependencies_complete"])
        consumes_public_artifacts(result, payload)

    def test_failure_variants_share_the_same_limit(self) -> None:
        cg = load_cg()
        options = caller_budgets(*POOL_CALLER)
        with repo_tree(pool_repo("abcdefgh")) as root:
            for mode in ("normal", "malformed", "timeout"):
                with self.subTest(mode=mode):
                    client = OfflineEstimatingClient(mode)
                    result = cg.build_monorepo_profile(
                        RepositoryWorkspace(root),
                        semantic_options=options,
                        model_client=client,
                        **BUILD_KWARGS,
                    )
                    payload = cg.component_graph_payload(result)
                    # Failures and successes alike consume the shared pools:
                    # exactly three attempts, never refunded.
                    self.assertEqual(
                        len(client.calls),
                        3,
                        f"{mode} replies must not refund pre-deducted pools",
                    )
                    self.assertEqual(
                        tuple(
                            sum(call[i] for call in client.calls) for i in range(3)
                        ),
                        (519, 384, 903),
                    )
                    self.assertEqual(
                        gap_count(find_gap(payload, "aggregate-token-pool-limit")), 5
                    )
                    self.assertIsNone(cg.validate_component_graph_payload(payload))

    def test_two_component_boundaries_exact_short_exhausted(self) -> None:
        cg = load_cg()
        # (label, caller pools, monorepo pool overrides, expected funded calls)
        cases = [
            ("exact-fit", (346, 256, 602), None, 2),
            ("output-one-short", (346, 255, 601), None, 1),
            ("prompt-one-short", (345, 256, 601), None, 1),
            (
                "pools-exhausted",
                POOL_DEFAULTS,
                {
                    "aggregate_max_prompt_tokens": 172,
                    "aggregate_max_output_tokens": 128,
                    "aggregate_max_total_tokens": 300,
                },
                0,
            ),
        ]
        with repo_tree(pool_repo("ab")) as root:
            for label, caller, overrides, expected in cases:
                with self.subTest(label=label):
                    client = OfflineEstimatingClient()
                    options = caller_budgets(*caller)
                    budgets = (
                        None if overrides is None else cg.MonorepoBudgets(**overrides)
                    )
                    result = cg.build_monorepo_profile(
                        RepositoryWorkspace(root),
                        semantic_options=options,
                        model_client=client,
                        monorepo_budgets=budgets,
                        **BUILD_KWARGS,
                    )
                    payload = cg.component_graph_payload(result)
                    requested = tuple(
                        (overrides or {}).get(name, default)
                        for name, default in (
                            ("aggregate_max_prompt_tokens", 24_000),
                            ("aggregate_max_output_tokens", 4_096),
                            ("aggregate_max_total_tokens", 28_096),
                        )
                    )
                    effective = tuple(
                        min(a, b) for a, b in zip(requested, caller, strict=True)
                    )
                    estimate = (
                        client.calls[0] if client.calls else POOL_PER_CALL_ESTIMATE
                    )
                    ledger = funded_calls(effective, estimate)
                    self.assertEqual(
                        len(client.calls),
                        ledger,
                        f"IR-01 boundary {label}: shared pools must fund "
                        f"{ledger} attempts",
                    )
                    self.assertEqual(len(client.calls), expected)
                    detail = find_gap(payload, "aggregate-token-pool-limit")
                    if expected == len("ab"):
                        self.assertIsNone(
                            detail, "fully funded builds publish no pool gap"
                        )
                    else:
                        self.assertEqual(gap_count(detail), len("ab") - expected)
                    self.assertIsNone(cg.validate_component_graph_payload(payload))

    def test_call_count_pool_shared_and_model_off_default(self) -> None:
        cg = load_cg()
        options = caller_budgets(*POOL_CALLER)
        with repo_tree(pool_repo("abcdefgh")) as root:
            for limit in (1, 2):
                with self.subTest(max_total_model_calls=limit):
                    client = OfflineEstimatingClient()
                    result = cg.build_monorepo_profile(
                        RepositoryWorkspace(root),
                        semantic_options=options,
                        model_client=client,
                        monorepo_budgets=cg.MonorepoBudgets(
                            max_total_model_calls=limit
                        ),
                        **BUILD_KWARGS,
                    )
                    payload = cg.component_graph_payload(result)
                    self.assertEqual(len(client.calls), limit)
                    self.assertEqual(
                        gap_count(find_gap(payload, "aggregate-model-call-limit")),
                        8 - limit,
                    )
            # Default off: no client, zero attempts, no aggregate gaps, and
            # every component still publishes deterministic real digests.
            _cg, off_result, off_payload = build_payload(root)
            self.assertEqual(
                [d for d in off_payload["coverage_gaps"] if "aggregate" in d["detail"]],
                [],
            )
            self.assertTrue(
                all(entry["built"] for entry in off_payload["components"])
            )
            self.assertTrue(
                all(
                    entry["digests"] is not None
                    for entry in off_payload["components"]
                )
            )
            self.assertIsNone(cg.validate_component_graph_payload(off_payload))
            self.assertTrue(off_result.per_component)

    def test_adjacent_builds_do_not_share_pool_state(self) -> None:
        cg = load_cg()
        options = caller_budgets(*POOL_CALLER)
        digests = []
        with repo_tree(pool_repo("abcd")) as root:
            for _build_index in range(2):
                client = OfflineEstimatingClient()
                result = cg.build_monorepo_profile(
                    RepositoryWorkspace(root),
                    semantic_options=options,
                    model_client=client,
                    **BUILD_KWARGS,
                )
                funded = funded_calls(
                    POOL_CALLER,
                    client.calls[0] if client.calls else POOL_PER_CALL_ESTIMATE,
                )
                self.assertEqual(
                    len(client.calls),
                    funded,
                    "pools must reset per build; a leak would under-fund the "
                    "second identical build",
                )
                digests.append(
                    cg.component_graph_payload(result)["identity"][
                        "component_graph_digest"
                    ]
                )
        self.assertEqual(digests[0], digests[1])

    def test_wire_effective_config_and_digests_self_consistent(self) -> None:
        cg = load_cg()
        options = caller_budgets(*POOL_CALLER)
        with repo_tree(pool_repo("abcdefgh")) as root:
            client = OfflineEstimatingClient()
            result = cg.build_monorepo_profile(
                RepositoryWorkspace(root),
                semantic_options=options,
                model_client=client,
                **BUILD_KWARGS,
            )
        payload = cg.component_graph_payload(result)
        # Effective (post-min) pools ride the payload build section; the
        # requested defaults (24000/4096/28096) must not be back-filled.
        budgets = payload["build"]["monorepo_budgets"]
        self.assertEqual(
            (
                budgets["aggregate_max_prompt_tokens"],
                budgets["aggregate_max_output_tokens"],
                budgets["aggregate_max_total_tokens"],
            ),
            POOL_CALLER,
        )
        self.assertEqual(budgets["max_total_model_calls"], 8)
        wires = {b.component.component_id: b for b in result.per_component}
        self.assertEqual(len(wires), 8)
        for component_id, built in wires.items():
            with self.subTest(component_id=component_id):
                wire = built.ram_wire
                validate_ram_wire_payload(wire)
                self.assertEqual(
                    ram_wire_digest(wire), wire["identity"]["wire_digest"]
                )
                semantic = wire["build"]["semantic"]
                self.assertEqual(semantic["model_id"], "offline")
                self.assertEqual(semantic["budgets"]["max_llm_calls"], 1)
                self.assertEqual(
                    (
                        semantic["budgets"]["max_prompt_tokens_estimate"],
                        semantic["budgets"]["max_output_tokens_estimate"],
                        semantic["budgets"]["max_total_tokens_estimate"],
                    ),
                    POOL_CALLER,
                    "wire build section must carry the effective caller "
                    "values, never the layer defaults",
                )
                entry = entry_of(payload, component_id)
                self.assertEqual(
                    ram_facts_digest_from_wire(wire),
                    entry["digests"]["ram_facts_digest"],
                )
                self.assertEqual(
                    semantic_result_digest_from_wire(wire),
                    entry["digests"]["semantic_result_digest"],
                )
                self.assertEqual(
                    built.profile_result.envelope.content_digest,
                    entry["digests"]["profile_content_digest"],
                )
        self.assertIsNone(cg.validate_component_graph_payload(payload))


# ---------------------------------------------------------------------------
# IR-02: unknown truncation counts records, not import sites
# ---------------------------------------------------------------------------


class UnknownTruncationTests(unittest.TestCase):
    """IR-02: dropped unknown records counted per record; V7 balance holds."""

    def test_record_count_not_site_count_primary_fixture(self) -> None:
        cg = load_cg()
        with repo_tree(UNKNOWN_AB_REPO) as root:
            result, payload = build_payload(
                root, monorepo_budgets=cg.MonorepoBudgets(max_edges=1)
            )[1:]
        # b's dropped record carried 2 sites but is ONE record.
        self.assertEqual(
            summary_of(payload, "component:b")["unknown_truncated_count"],
            1,
            "IR-02: unknown_truncated_count must count dropped records, not "
            "import sites (b drops one record with two sites)",
        )
        self.assertEqual(
            summary_of(payload, "component:a")["unknown_truncated_count"], 0
        )
        self.assertEqual(
            payload["unknown_imports"],
            [
                {
                    "source_component_id": "component:a",
                    "imported_name": "missing_alpha",
                    "count": 1,
                }
            ],
        )
        detail = find_gap(payload, "unknown-import-limit")
        self.assertEqual(detail, "reason=unknown-import-limit; count=1")
        total = sum(
            summary["unknown_truncated_count"]
            for summary in payload["scan_summaries"]
        )
        self.assertEqual(total, gap_count(detail), "V7: summaries sum == gap count")
        self.assertFalse(payload["dependencies_complete"], "T3 must trigger")
        # The builder's own partial payload must pass the public validator.
        self.assertIsNone(
            cg.validate_component_graph_payload(payload),
            "IR-02: the legal partial payload must be accepted",
        )
        consumes_public_artifacts(result, payload)

    def test_cap_two_control_no_truncation(self) -> None:
        cg = load_cg()
        with repo_tree(UNKNOWN_AB_REPO) as root:
            _cg, _result, payload = build_payload(
                root, monorepo_budgets=cg.MonorepoBudgets(max_edges=2)
            )
        self.assertIsNone(find_gap(payload, "unknown-import-limit"))
        self.assertEqual(
            payload["unknown_imports"],
            [
                {
                    "source_component_id": "component:a",
                    "imported_name": "missing_alpha",
                    "count": 1,
                },
                {
                    "source_component_id": "component:b",
                    "imported_name": "missing_zeta",
                    "count": 2,
                },
            ],
        )
        self.assertTrue(payload["dependencies_complete"])
        self.assertIsNone(cg.validate_component_graph_payload(payload))

    def test_multi_file_same_key_single_record(self) -> None:
        cg = load_cg()
        with repo_tree(UNKNOWN_MULTI_FILE_REPO) as root:
            _cg, _r1, cap1 = build_payload(
                root, monorepo_budgets=cg.MonorepoBudgets(max_edges=1)
            )
            _cg, _r2, cap2 = build_payload(
                root, monorepo_budgets=cg.MonorepoBudgets(max_edges=2)
            )
        # cap=1 keeps a's record, drops c's single aggregated record.
        self.assertEqual(
            summary_of(cap1, "component:c")["unknown_truncated_count"], 1
        )
        self.assertEqual(gap_count(find_gap(cap1, "unknown-import-limit")), 1)
        self.assertIsNone(cg.validate_component_graph_payload(cap1))
        # cap=2 publishes c's record with its two-site count intact.
        self.assertEqual(
            [
                record
                for record in cap2["unknown_imports"]
                if record["source_component_id"] == "component:c"
            ],
            [
                {
                    "source_component_id": "component:c",
                    "imported_name": "missing_mu",
                    "count": 2,
                }
            ],
        )
        self.assertTrue(cap2["dependencies_complete"])
        self.assertIsNone(cg.validate_component_graph_payload(cap2))

    def test_mixed_flow_edge_priority_and_dual_overflow(self) -> None:
        cg = load_cg()
        # Mixed stream = [edge(b->a), edge(c->a), unknown(a), unknown(b)].
        with repo_tree(MIXED_CAP_REPO) as root:
            for cap, edges, unknowns, edge_gap, unknown_gap in (
                (1, 1, 0, 1, 2),
                (2, 2, 0, None, 2),
                (3, 2, 1, None, 1),
                (4, 2, 2, None, None),
            ):
                with self.subTest(cap=cap):
                    _cg, _result, payload = build_payload(
                        root, monorepo_budgets=cg.MonorepoBudgets(max_edges=cap)
                    )
                    self.assertEqual(len(payload["edges"]), edges)
                    self.assertEqual(len(payload["unknown_imports"]), unknowns)
                    self.assertEqual(
                        gap_count(find_gap(payload, "edge-limit")), edge_gap
                    )
                    self.assertEqual(
                        gap_count(find_gap(payload, "unknown-import-limit")),
                        unknown_gap,
                    )
                    total = sum(
                        s["unknown_truncated_count"] for s in payload["scan_summaries"]
                    )
                    self.assertEqual(total, unknown_gap if unknown_gap else 0)
                    self.assertLessEqual(
                        len(payload["edges"]) + len(payload["unknown_imports"]), cap
                    )
                    self.assertIs(payload["dependencies_complete"], cap == 4)
                    self.assertIsNone(
                        cg.validate_component_graph_payload(payload),
                        "every single-truncation partial must stay consumable",
                    )
        # Explicit both-sides-overflow shape: cap=1 drops one edge and two
        # unknown records; each side carries its own count.
        with repo_tree(MIXED_CAP_REPO) as root:
            _cg, _result, payload = build_payload(
                root, monorepo_budgets=cg.MonorepoBudgets(max_edges=1)
            )
        self.assertEqual(
            find_gap(payload, "edge-limit"), "reason=edge-limit; count=1"
        )
        self.assertEqual(
            find_gap(payload, "unknown-import-limit"),
            "reason=unknown-import-limit; count=2",
        )
        self.assertEqual(
            summary_of(payload, "component:a")["unknown_truncated_count"], 1
        )
        self.assertEqual(
            summary_of(payload, "component:b")["unknown_truncated_count"], 1
        )

    def test_write_order_invariance_and_classification(self) -> None:
        cg = load_cg()
        budgets = cg.MonorepoBudgets(max_edges=1)
        with repo_tree(UNKNOWN_AB_REPO) as root1, repo_tree(
            UNKNOWN_AB_REPO, reverse=True
        ) as root2:
            _cg, _r1, first = build_payload(root1, monorepo_budgets=budgets)
            _cg, _r2, second = build_payload(root2, monorepo_budgets=budgets)
        self.assertEqual(
            first["identity"]["component_graph_digest"],
            second["identity"]["component_graph_digest"],
        )
        self.assertEqual(first["scan_summaries"], second["scan_summaries"])
        # Three-state classification (section 5.2.4 P3): a component with a
        # truncated unknown record is "insufficient evidence" (criterion 6)
        # and can never classify as real-no-dependencies; a published
        # unknown record likewise disqualifies its component (criterion 5).
        self.assertGreater(
            summary_of(first, "component:b")["unknown_truncated_count"], 0
        )
        self.assertTrue(
            any(
                record["source_component_id"] == "component:a"
                for record in first["unknown_imports"]
            )
        )
        self.assertFalse(
            first["dependencies_complete"],
            "with T3 set, real-no-dependencies is unreachable for both "
            "components; the classification inputs stay visible",
        )


# ---------------------------------------------------------------------------
# IR-03: real IO equivalence accounting
# ---------------------------------------------------------------------------


def io_case(
    files: Mapping[str, str | bytes],
    *,
    workspace_limits: Mapping[str, Any] | None = None,
    budget_kwargs: Mapping[str, int] | None = None,
    manifest_policy: str | None = None,
) -> tuple[list[tuple[str, int]], Any, Any, Any]:
    """Build once under read observation; return (records, cg, result, payload)."""

    cg = load_cg()
    options: dict[str, Any] = {}
    if budget_kwargs:
        options["monorepo_budgets"] = cg.MonorepoBudgets(**budget_kwargs)
    if manifest_policy:
        options["manifest_policy"] = manifest_policy
    with repo_tree(files) as root, observing_reads(root) as records:
        result = cg.build_monorepo_profile(
            RepositoryWorkspace(root, **dict(workspace_limits or {})),
            **BUILD_KWARGS,
            **options,
        )
    return records, cg, result, cg.component_graph_payload(result)


def attempts_by_path(records: list[tuple[str, int]]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for rel, _size in records:
        counts[rel] = counts.get(rel, 0) + 1
    return counts


def bytes_by_path(records: list[tuple[str, int]]) -> dict[str, int]:
    totals: dict[str, int] = {}
    for rel, size in records:
        totals[rel] = totals.get(rel, 0) + size
    return totals


class IOMeteringTests(unittest.TestCase):
    """IR-03: six metering fields equal the real nine-stage read ledger."""

    def assert_metering(
        self,
        records: list[tuple[str, int]],
        result: Any,
        *,
        main: int,
        rescan: int,
        ast: int,
        manifest: int | None = None,
        channel: int | None = None,
        manifest_plus_channel: int | None = None,
    ) -> None:
        meter = result.metering
        observed_attempts = len(records)
        observed_bytes = sum(size for _rel, size in records)
        reported_attempts = (
            meter.main_inventory_read_attempts
            + meter.component_rescan_read_attempts
            + meter.profile_manifest_read_attempts
            + meter.ast_read_attempts
            + meter.metadata_channel_read_attempts
        )
        self.assertEqual(
            meter.read_success_bytes,
            observed_bytes,
            "IR-03: read_success_bytes must equal the observed real bytes",
        )
        self.assertEqual(
            reported_attempts,
            observed_attempts,
            "IR-03: the attempt fields must sum to the observed real reads",
        )
        self.assertEqual(meter.main_inventory_read_attempts, main)
        self.assertEqual(meter.component_rescan_read_attempts, rescan)
        self.assertEqual(meter.ast_read_attempts, ast)
        if manifest is not None:
            self.assertEqual(meter.profile_manifest_read_attempts, manifest)
        if channel is not None:
            self.assertEqual(meter.metadata_channel_read_attempts, channel)
        if manifest_plus_channel is not None:
            self.assertEqual(
                meter.profile_manifest_read_attempts
                + meter.metadata_channel_read_attempts,
                manifest_plus_channel,
            )

    def test_four_frozen_equivalence_cases(self) -> None:
        main_len = len(MAIN_PY.encode())
        req_len = len(REQUIREMENTS_TXT.encode())
        a_main_len = len(A_MAIN_PY.encode())

        # (1) Normal: main.py is read once per stage S0,S1,S2,S4,S5,S6,S7
        # (7 reads) and requirements.txt once in S8 plus once in S3.
        records, cg, result, payload = io_case(
            {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY}
        )
        self.assertEqual(
            attempts_by_path(records), {"main.py": 7, "requirements.txt": 2}
        )
        self.assertEqual(
            bytes_by_path(records),
            {"main.py": 7 * main_len, "requirements.txt": 2 * req_len},
        )
        self.assert_metering(
            records, result, main=1, rescan=5, ast=1, manifest=1, channel=1
        )
        self.assertIsNone(cg.validate_component_graph_payload(payload))

        # (2) max_files=1: second.py is discovered but never read; the real
        # S0 ledger stays at one read and must not be reported as 2.
        records, cg, result, _payload = io_case(
            {
                "requirements.txt": REQUIREMENTS_TXT,
                "main.py": MAIN_PY,
                "second.py": SECOND_PY,
            },
            workspace_limits={"max_files": 1},
        )
        self.assertNotIn("second.py", attempts_by_path(records))
        self.assertEqual(
            attempts_by_path(records), {"main.py": 7, "requirements.txt": 2}
        )
        self.assert_metering(
            records, result, main=1, rescan=5, ast=1, manifest=1, channel=1
        )
        self.assertNotEqual(
            result.metering.main_inventory_read_attempts,
            2,
            "discovered-but-unread files must not be reported as S0 attempts",
        )

        # (3) Channel byte cap rejects AFTER the read: the successful read
        # bytes (a/requirements.txt 11 + a/main.py 10 = 21) must survive.
        records, cg, result, payload = io_case(
            {"a/requirements.txt": REQUIREMENTS_TXT, "a/main.py": A_MAIN_PY},
            budget_kwargs={"max_metadata_total_bytes": 1},
        )
        self.assertEqual(len(records), 2)
        self.assertEqual(
            bytes_by_path(records),
            {"a/requirements.txt": req_len, "a/main.py": a_main_len},
        )
        self.assert_metering(
            records, result, main=1, rescan=0, ast=0, manifest=0, channel=1
        )
        self.assertEqual(
            result.metering.read_success_bytes,
            req_len + a_main_len,
            "a read-then-rejected manifest must not zero its bytes",
        )
        self.assertIsNone(cg.validate_component_graph_payload(payload))

        # (4) admitted-only with .txt admitted: requirements.txt joins the
        # component slice (S1/S2/S5 inventories) and the discovery manifest
        # read-back is a real read: 13 attempts / 269 bytes total.
        records, cg, result, payload = io_case(
            {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY},
            workspace_limits={"extensions": [".py", ".txt"]},
            manifest_policy="admitted-only",
        )
        self.assertEqual(
            attempts_by_path(records), {"main.py": 7, "requirements.txt": 6}
        )
        self.assertEqual(len(records), 13)
        self.assert_metering(
            records, result, main=2, rescan=8, ast=1, manifest_plus_channel=2
        )
        self.assertIsNone(cg.validate_component_graph_payload(payload))

    def test_decode_failure_and_binary_skip_count_real_bytes(self) -> None:
        main_len = len(MAIN_PY.encode())
        bad_len = len(BAD_REQUIREMENTS)
        nul_len = len(NULMOD_PY)
        req_len = len(REQUIREMENTS_TXT.encode())

        # Decode failure: both channel (S8) and per-component manifest (S3)
        # reads of the non-utf8 manifest really read bytes before failing.
        records, cg, result, payload = io_case(
            {"a/requirements.txt": BAD_REQUIREMENTS, "a/main.py": MAIN_PY}
        )
        self.assertEqual(
            attempts_by_path(records), {"a/main.py": 7, "a/requirements.txt": 2}
        )
        self.assertEqual(
            bytes_by_path(records),
            {"a/main.py": 7 * main_len, "a/requirements.txt": 2 * bad_len},
        )
        self.assert_metering(
            records, result, main=1, rescan=5, ast=1, manifest=1, channel=1
        )
        self.assertEqual(payload["metadata_channel_skipped"].get("non-utf8"), 1)
        self.assertIsNone(cg.validate_component_graph_payload(payload))

        # Binary read-then-skip: the NUL file is really read at S0 before
        # the binary classification drops it.
        records, cg, result, payload = io_case(
            {
                "a/requirements.txt": REQUIREMENTS_TXT,
                "a/main.py": MAIN_PY,
                "a/nulmod.py": NULMOD_PY,
            }
        )
        self.assertEqual(
            attempts_by_path(records),
            {"a/main.py": 7, "a/requirements.txt": 2, "a/nulmod.py": 1},
        )
        self.assertEqual(
            bytes_by_path(records),
            {
                "a/main.py": 7 * main_len,
                "a/requirements.txt": 2 * req_len,
                "a/nulmod.py": nul_len,
            },
        )
        self.assert_metering(
            records, result, main=2, rescan=5, ast=1, manifest=1, channel=1
        )
        self.assertIsNone(cg.validate_component_graph_payload(payload))

    def test_pre_read_rejections_never_become_read_attempts(self) -> None:
        req_len = len(REQUIREMENTS_TXT.encode())

        # Per-file size cap: main.py is rejected at stat time (pre-read) —
        # no S0 read happens at all; the root component (metadata-channel
        # anchor) still reads its manifest twice (S8 + S3).
        records, cg, result, payload = io_case(
            {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY},
            workspace_limits={"max_file_bytes": 20},
        )
        self.assertEqual(attempts_by_path(records), {"requirements.txt": 2})
        self.assert_metering(
            records, result, main=0, rescan=0, ast=0, manifest=1, channel=1
        )
        self.assertEqual(result.metering.read_success_bytes, 2 * req_len)
        # Root-component shape ("component:.") stays a valid public surface.
        self.assertIn(
            "component:.", [c["component_id"] for c in payload["components"]]
        )
        self.assertIsNone(cg.validate_component_graph_payload(payload))

        # Total-byte cap mid-inventory: second.py is discovered but rejected
        # before reading; the S0 ledger keeps exactly one real read.
        records, cg, result, _payload = io_case(
            {
                "requirements.txt": REQUIREMENTS_TXT,
                "main.py": MAIN_PY,
                "second.py": SECOND_PY,
            },
            workspace_limits={"max_total_bytes": 30},
        )
        self.assertEqual(
            attempts_by_path(records), {"main.py": 7, "requirements.txt": 2}
        )
        self.assert_metering(
            records, result, main=1, rescan=5, ast=1, manifest=1, channel=1
        )
        self.assertNotEqual(
            result.metering.main_inventory_read_attempts,
            2,
            "a pre-read total-size rejection is not a read attempt",
        )

    def test_s1_s2_overlap_counts_the_whole_chain(self) -> None:
        pyproject_len = len(PYPROJECT_TOML.encode())
        main_len = len(MAIN_PY.encode())
        records, cg, result, payload = io_case(
            {"pyproject.toml": PYPROJECT_TOML, "main.py": MAIN_PY}
        )
        # pyproject.toml is admitted (.toml) AND channel-hit: S0 + S8 + S3
        # plus the slice inventories S1/S2/S5 (it rides the component slice).
        self.assertEqual(
            attempts_by_path(records), {"main.py": 7, "pyproject.toml": 6}
        )
        self.assertEqual(len(records), 13)
        self.assert_metering(
            records, result, main=2, rescan=8, ast=1, manifest=1, channel=1
        )
        self.assertEqual(
            result.metering.read_success_bytes, 6 * pyproject_len + 7 * main_len
        )
        entry = payload["components"][0]
        self.assertEqual(entry["manifests"][0]["source"], "source-inventory")
        self.assertEqual(payload["manifests_discovered_count"], 1)
        self.assertEqual(payload["metadata_manifest_count"], 1)
        self.assertIsNone(cg.validate_component_graph_payload(payload))

    def test_conservative_upper_bound_holds_every_case(self) -> None:
        cases: list[
            tuple[
                str,
                Mapping[str, str | bytes],
                int,
                Mapping[str, Any] | None,
                Mapping[str, int] | None,
                str | None,
            ]
        ] = [
            (
                "normal",
                {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY},
                1,
                None,
                None,
                None,
            ),
            (
                "file-cap",
                {
                    "requirements.txt": REQUIREMENTS_TXT,
                    "main.py": MAIN_PY,
                    "second.py": SECOND_PY,
                },
                2,
                {"max_files": 1},
                None,
                None,
            ),
            (
                "byte-cap",
                {"a/requirements.txt": REQUIREMENTS_TXT, "a/main.py": A_MAIN_PY},
                1,
                None,
                {"max_metadata_total_bytes": 1},
                None,
            ),
            (
                "admitted-only",
                {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY},
                2,
                {"extensions": [".py", ".txt"]},
                None,
                "admitted-only",
            ),
            (
                "overlap",
                {"pyproject.toml": PYPROJECT_TOML, "main.py": MAIN_PY},
                2,
                None,
                None,
                None,
            ),
            (
                "decode",
                {"a/requirements.txt": BAD_REQUIREMENTS, "a/main.py": MAIN_PY},
                1,
                None,
                None,
                None,
            ),
            (
                "binary",
                {
                    "a/requirements.txt": REQUIREMENTS_TXT,
                    "a/main.py": MAIN_PY,
                    "a/nulmod.py": NULMOD_PY,
                },
                2,
                None,
                None,
                None,
            ),
            (
                "file-size",
                {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY},
                0,
                {"max_file_bytes": 20},
                None,
                None,
            ),
            (
                "total-size",
                {
                    "requirements.txt": REQUIREMENTS_TXT,
                    "main.py": MAIN_PY,
                    "second.py": SECOND_PY,
                },
                2,
                {"max_total_bytes": 30},
                None,
                None,
            ),
        ]
        for label, files, discovered, limits, budgets, policy in cases:
            with self.subTest(case=label):
                records, _cg, result, payload = io_case(
                    files,
                    workspace_limits=limits,
                    budget_kwargs=budgets,
                    manifest_policy=policy,
                )
                meter = result.metering
                total = (
                    meter.main_inventory_read_attempts
                    + meter.component_rescan_read_attempts
                    + meter.profile_manifest_read_attempts
                    + meter.ast_read_attempts
                    + meter.metadata_channel_read_attempts
                )
                bound = (
                    7 * discovered
                    + 2 * payload["manifests_discovered_count"]
                    + payload["build"]["monorepo_budgets"]["max_metadata_manifests"]
                )
                self.assertLessEqual(
                    total,
                    bound,
                    "section 5.4.4-IO whole-chain bound is an ADDITIONAL check",
                )
                self.assertEqual(
                    meter.read_success_bytes,
                    sum(size for _rel, size in records),
                    "the bound never replaces the equivalence accounting",
                )


# ---------------------------------------------------------------------------
# IR-03 (RC-TEST-01): equivalent root spellings share one observation ledger
# ---------------------------------------------------------------------------


class EquivalentPathRootTests(unittest.TestCase):
    """RC-TEST-01: one physical root records one ledger under any spelling.

    The observation root must follow the same root semantics as
    ``RepositoryWorkspace`` (expanduser + resolve), so equivalent spellings
    of one physical root — canonical, a lexical ``pivot/..`` alias, the
    alias resolved first, and a real Windows 8.3 short name when the volume
    provides one — observe the identical non-zero read ledger for the same
    product behaviour (the pre-fix observer silently recorded nothing for
    alias spellings). Observer-only rules are pinned by direct probes.
    """

    def test_equivalent_root_spellings_share_one_nonzero_ledger(self) -> None:
        cg = load_cg()
        main_len = len(MAIN_PY.encode())
        req_len = len(REQUIREMENTS_TXT.encode())
        files = {"requirements.txt": REQUIREMENTS_TXT, "main.py": MAIN_PY}
        with repo_tree(files) as raw:
            canonical = raw.resolve()
            (canonical / "obs-pivot").mkdir()
            variants: list[tuple[str, Path]] = [
                ("canonical", canonical),
                ("pivot-dotdot", canonical / "obs-pivot" / ".."),
                (
                    "alias-resolved-first",
                    (canonical / "obs-pivot" / "..").resolve(),
                ),
            ]
            short = windows_short_path_alias(canonical)
            if short is not None:
                variants.append(("short-8dot3", short))
            ledgers: list[list[tuple[str, int]]] = []
            for label, observer_root in variants:
                with self.subTest(variant=label):
                    self.assertTrue(
                        os.path.samefile(observer_root, canonical),
                        "every variant must denote the same physical root",
                    )
                    with observing_reads(observer_root) as records:
                        result = cg.build_monorepo_profile(
                            RepositoryWorkspace(observer_root), **BUILD_KWARGS
                        )
                    self.assertEqual(
                        attempts_by_path(records),
                        {"main.py": 7, "requirements.txt": 2},
                        "alias spellings must not drop real reads",
                    )
                    self.assertEqual(
                        bytes_by_path(records),
                        {"main.py": 7 * main_len, "requirements.txt": 2 * req_len},
                    )
                    meter = result.metering
                    self.assertEqual(
                        meter.read_success_bytes,
                        7 * main_len + 2 * req_len,
                    )
                    self.assertEqual(
                        meter.main_inventory_read_attempts
                        + meter.component_rescan_read_attempts
                        + meter.profile_manifest_read_attempts
                        + meter.ast_read_attempts
                        + meter.metadata_channel_read_attempts,
                        len(records),
                        "the product ledger must equal the observed ledger",
                    )
                    ledgers.append(list(records))
            for index in range(1, len(ledgers)):
                with self.subTest(identity=variants[index][0]):
                    self.assertEqual(
                        ledgers[index],
                        ledgers[0],
                        "all spellings of one physical root share one ledger",
                    )

    def test_out_of_domain_read_passes_through_unrecorded(self) -> None:
        outside_root = Path(tempfile.mkdtemp(prefix="lima-pr284-outside-"))
        try:
            (outside_root / "outside.txt").write_bytes(b"outside-bytes\n")
            with repo_tree({"main.py": MAIN_PY}) as root, observing_reads(
                root
            ) as records:
                outside = (outside_root / "outside.txt").read_bytes()
                inside = (root / "main.py").read_bytes()
        finally:
            shutil.rmtree(outside_root, ignore_errors=True)
        self.assertEqual(outside, b"outside-bytes\n")
        self.assertEqual(inside, MAIN_PY.encode())
        self.assertEqual(
            records,
            [("main.py", len(MAIN_PY.encode()))],
            "only in-domain reads are recorded",
        )

    def test_failed_read_records_zero_bytes_and_reraises(self) -> None:
        with repo_tree({"main.py": MAIN_PY}) as root, observing_reads(
            root
        ) as records:
            with self.assertRaises(FileNotFoundError):
                (root / "missing.py").read_bytes()
        self.assertEqual(
            records,
            [("missing.py", 0)],
            "a failed in-domain read records zero successful bytes",
        )

    def test_observer_transparent_and_no_patch_residue(self) -> None:
        with repo_tree({"main.py": MAIN_PY}) as root:
            original = Path.read_bytes
            with observing_reads(root) as records:
                first = (root / "main.py").read_bytes()
            self.assertIs(Path.read_bytes, original, "no patch state residue")
            second = (root / "main.py").read_bytes()
            self.assertEqual(first, MAIN_PY.encode(), "returns never replaced")
            self.assertEqual(second, MAIN_PY.encode())
            self.assertEqual(
                records,
                [("main.py", len(MAIN_PY.encode()))],
                "reads after the observation window are not recorded",
            )


# ---------------------------------------------------------------------------
# IR-04: structurally illegal payloads rejected despite consistent digests
# ---------------------------------------------------------------------------


def independent_canonical(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Project a payload onto the frozen canonical dict (section 5.4.5)."""

    canonical = {
        key: deepcopy(payload[key])
        for key in (
            "edges",
            "unknown_imports",
            "scan_summaries",
            "unbuilt_components",
            "unassigned_files",
            "unassigned_file_count",
            "dependencies_complete",
            "coverage_gaps",
            "manifests_discovered_count",
            "metadata_manifest_count",
            "collaboration_manifest_count",
            "overflow_manifest_count",
        )
    }
    canonical["components"] = [
        {
            "component_id": entry["component_id"],
            "root_dir": entry["root_dir"],
            "manifests": [
                {
                    "path": ref["path"],
                    "kind": ref["manifest_kind"],
                    "source": ref["source"],
                }
                for ref in entry["manifests"]
            ],
            "python_file_count": entry["python_file_count"],
            "is_empty": entry["is_empty"],
            "artifact_digests": deepcopy(entry["digests"]),
        }
        for entry in payload["components"]
    ]
    return canonical


def reidentify(payload: dict[str, Any]) -> None:
    """Recompute the identity digest via the independent projection."""

    payload["identity"]["component_graph_digest"] = compute_content_digest(
        independent_canonical(payload)
    )


class ValidatorStructureTests(unittest.TestCase):
    """IR-04: V5/V6/V8 enforced even when V9 has been recomputed."""

    @classmethod
    def setUpClass(cls) -> None:
        with repo_tree(VALIDATOR_BASE_REPO) as root:
            cls.cg, cls.result, cls.base = build_payload(root)

    def mutated(self, mutator: Any) -> dict[str, Any]:
        altered = deepcopy(self.base)
        mutator(altered)
        reidentify(altered)
        return altered

    def test_base_recomputes_and_stays_accepted(self) -> None:
        # The independent projection must reproduce the builder's identity
        # before any mutation is judged (identity-method parity).
        self.assertEqual(
            compute_content_digest(independent_canonical(self.base)),
            self.base["identity"]["component_graph_digest"],
        )
        self.assertEqual(
            [c["component_id"] for c in self.base["components"]],
            ["component:a", "component:b", "component:c"],
        )
        self.assertEqual(len(self.base["edges"]), 2)
        self.assertEqual(len(self.base["edges"][0]["evidence"]), 2)
        self.assertEqual(
            [ref["source"] for ref in self.base["components"][0]["manifests"]],
            ["source-inventory", "metadata-channel"],
        )
        self.assertTrue(self.base["dependencies_complete"])
        self.assertIsNone(self.cg.validate_component_graph_payload(self.base))
        self.assertIsNone(
            self.cg.validate_component_graph_payload(self.mutated(lambda p: None)),
            "a consistently recomputed identical payload stays accepted",
        )

    def test_path_shapes_rejected_with_consistent_digest(self) -> None:
        def set_unassigned(paths: list[str]) -> Any:
            def _mutate(payload: dict[str, Any]) -> None:
                payload["unassigned_files"] = paths
                payload["unassigned_file_count"] = len(paths)

            return _mutate

        # V5 negatives: repo-relative POSIX only.
        for label, paths in (
            ("drive-absolute", ["C:/outside.py"]),
            ("backslash", ["dir\\main.py"]),
            ("unc-backslash", ["\\\\srv\\share\\main.py"]),
        ):
            with self.subTest(label=label):
                with self.assertRaises(
                    ContractError,
                    msg=f"V5 must reject {label} paths even after reidentify",
                ):
                    self.cg.validate_component_graph_payload(
                        self.mutated(set_unassigned(paths))
                    )
        # Controls already enforced before this rework: keep them rejected.
        for label, paths in (
            ("leading-slash", ["/abs/main.py"]),
            ("traversal", ["../escape.py"]),
            ("nul-byte", ["dir\x00main.py"]),
            ("unc-slashes", ["//srv/share/main.py"]),
            ("secret-shaped", ["secrets.yaml"]),
        ):
            with self.subTest(control=label):
                with self.assertRaises(ContractError):
                    self.cg.validate_component_graph_payload(
                        self.mutated(set_unassigned(paths))
                    )
        # Positives: legal Unicode and ordinary relative paths stay valid.
        for label, paths in (
            ("unicode", ["über/main.py"]),
            ("plain-relative", ["pkg/mod.py"]),
        ):
            with self.subTest(positive=label):
                self.assertIsNone(
                    self.cg.validate_component_graph_payload(
                        self.mutated(set_unassigned(paths))
                    )
                )

    def test_duplicate_and_unsorted_lists_rejected(self) -> None:
        def duplicate_unassigned(payload: dict[str, Any]) -> None:
            payload["unassigned_files"] = ["loose.py", "loose.py"]
            payload["unassigned_file_count"] = 2

        mutations = [
            # IR-04 RED face first, then ordering/dedup controls on every
            # other list family (V6).
            ("duplicate-unassigned", duplicate_unassigned),
            ("reverse-scan-summaries", lambda p: p["scan_summaries"].reverse()),
            ("reverse-components", lambda p: p["components"].reverse()),
            ("reverse-edges", lambda p: p["edges"].reverse()),
            ("reverse-evidence", lambda p: p["edges"][0]["evidence"].reverse()),
            ("reverse-unknowns", lambda p: p["unknown_imports"].reverse()),
            (
                "reverse-manifests",
                lambda p: p["components"][0]["manifests"].reverse(),
            ),
            ("reverse-unassigned", lambda p: p["unassigned_files"].reverse()),
        ]
        for label, mutator in mutations:
            with self.subTest(label=label):
                with self.assertRaises(ContractError, msg=f"V6 must reject: {label}"):
                    self.cg.validate_component_graph_payload(self.mutated(mutator))

        def unbuild_all_and_reverse(payload: dict[str, Any]) -> None:
            for entry in payload["components"]:
                entry["built"] = False
                entry["digests"] = None
                entry["semantic_topn"] = None
            payload["unbuilt_components"] = [
                {"component_id": "component:c", "reason": "cap-divergence"},
                {"component_id": "component:b", "reason": "cap-divergence"},
                {"component_id": "component:a", "reason": "cap-divergence"},
            ]
            payload["dependencies_complete"] = False

        with self.subTest(label="reverse-unbuilt"):
            with self.assertRaises(ContractError):
                self.cg.validate_component_graph_payload(
                    self.mutated(unbuild_all_and_reverse)
                )

    def test_duplicate_evidence_rejected(self) -> None:
        # IR-04 exit 2 completion (CR-60-PR284-SF-20261012/v1): a sorted
        # but non-unique evidence list is the one V6 dedup face the v1
        # mutation table left uncovered; the identity digest is still
        # consistently recomputed, so only the dedup rule can reject it.
        def duplicate_evidence(payload: dict[str, Any]) -> None:
            evidence = payload["edges"][0]["evidence"]
            evidence.insert(0, dict(evidence[0]))

        with self.assertRaises(
            ContractError,
            msg="V6 must reject: duplicate-evidence",
        ):
            self.cg.validate_component_graph_payload(
                self.mutated(duplicate_evidence)
            )

    def test_budget_domains_and_cross_field_invariant(self) -> None:
        def budget(key: str, value: Any) -> Any:
            def _mutate(payload: dict[str, Any]) -> None:
                payload["build"]["monorepo_budgets"][key] = value

            return _mutate

        # V8 domain/cross-field negatives (schema hard caps 64/16384/512/
        # 1024/4096; frozen invariant total >= prompt + output).
        negatives = [
            ("max_components", 65),
            ("max_edges", 16_385),
            ("max_total_model_calls", 513),
            ("max_metadata_manifests", 2_000),
            ("max_edge_evidence", 2_000),
            ("max_unassigned_files", 5_000),
            ("aggregate_max_total_tokens", 1),
        ]
        for key, value in negatives:
            with self.subTest(key=key, value=value):
                with self.assertRaises(
                    ContractError,
                    msg=f"V8 must reject {key}={value} (the build section is "
                    "not digest-bound; the domain check is the only guard)",
                ):
                    self.cg.validate_component_graph_payload(
                        self.mutated(budget(key, value))
                    )
        # Type/low-end controls: exact int domain, >= 1.
        for key, value in (
            ("max_components", 0),
            ("max_components", "16"),
            ("max_components", 16.0),
            ("aggregate_max_prompt_tokens", True),
        ):
            with self.subTest(control=key, value=value):
                with self.assertRaises(ContractError):
                    self.cg.validate_component_graph_payload(
                        self.mutated(budget(key, value))
                    )
        # Defaults are not hard caps: legal above-default values stay valid.
        for label, mutator in (
            ("components-32", budget("max_components", 32)),
            (
                "pools-above-default",
                lambda p: p["build"]["monorepo_budgets"].update(
                    {
                        "aggregate_max_prompt_tokens": 50_000,
                        "aggregate_max_output_tokens": 8_192,
                        "aggregate_max_total_tokens": 58_192,
                    }
                ),
            ),
        ):
            with self.subTest(positive=label):
                self.assertIsNone(
                    self.cg.validate_component_graph_payload(self.mutated(mutator))
                )


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
