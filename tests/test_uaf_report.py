"""UAF v2 report / API / UI audit-view tests (plan Task 11, design section 14).

Zero network: the collaboration ``uaf_v2`` payload is crafted with the exact
shape ``RepositoryScanner._uaf_collaboration`` emits (Task 10), and one
end-to-end test runs the offline scanner with a fake ``analyze_uaf_facts``
sidecar. Red lines pinned here:

- the markdown report renders every section-14 audit field the payload
  carries (mode/status/translation units, stats, state labels, broker
  three-state summary, bounded diagnostics, per-candidate audit rows);
- ``llm_invoked`` is rendered from the actual call counters only: zero
  calls never display an invocation claim, a zero-call PASS/REFUTED
  full-coverage run must show ``deterministic proof; LLM not required``;
- untrusted diagnostics and audit reasons are context-encoded;
- ``fact-verified`` / ``semantic-supported`` badges no longer fall back to
  the unknown-verification-state label;
- UAF findings keep ``automatic_repair=False`` and the rendered report
  shows no repair support;
- reports without the ``uaf_v2`` key render exactly as before;
- the service capabilities object exposes the ``uaf_v2`` bit shape.
"""

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from lima.config import Settings
from lima.cxx_memory import CxxAnalysisResult, UafFactsResponse, uaf_facts_bundle_sha256
from lima.report import to_markdown
from lima.repository_scanner import RepositoryScanner
from lima.service import ReviewService
from lima.uaf_orchestrator import UAF_FINDING_STATES
from lima.workspace import RepositoryWorkspace

SNAPSHOT = "a" * 64
CONTEXT = "c" * 64
RUN_ID = "run-uaf-1"
UNIT = "src/a.cpp"
USR = "C::leak"

INJECTION = "<script>alert(1)</script>"


def _fid(number: int) -> str:
    return format(number, "064x")


CANDIDATE_ID = _fid(7)


# ------------------------------------------------------------ payload helpers


def _wire_fact(kind, fact_id, line, related=()):
    fact = {
        "fact_id": fact_id,
        "kind": kind,
        "translation_unit": UNIT,
        "canonical_path": UNIT,
        "function_usr": USR,
        "source_range": [line, line],
        "cfg_block": 0,
    }
    if kind == "allocation":
        fact["allocation_api"] = "new"
        fact["pointer_id"] = "p"
    elif kind == "release":
        fact["release_api"] = "delete"
        fact["pointer_id"] = "p"
        fact["related_fact_ids"] = list(related)
    elif kind == "dereference":
        fact["pointer_id"] = "p"
    return fact


def _straight_facts():
    return [
        _wire_fact("allocation", _fid(1), 10),
        _wire_fact("release", _fid(2), 20, related=(_fid(1),)),
        _wire_fact("dereference", _fid(3), 30),
    ]


def _unit_entry(facts):
    return {
        "translation_unit": UNIT,
        "extraction": "completed",
        "build_context": {
            "status": "resolved",
            "source_kind": "repository-compdb",
            "context_hash": CONTEXT,
            "diagnostics": [],
        },
        "coverage": {
            "ast_complete": True,
            "cfg_complete": True,
            "semantic_gaps": [],
        },
        "facts": list(facts),
    }


def _payload(facts=None):
    tool_run = {"run_id": RUN_ID, "tool": "uaf-facts", "status": "completed"}
    units = [_unit_entry(_straight_facts() if facts is None else facts)]
    return {
        "schema_version": 1,
        "request_id": "req-1",
        "repository_key": "team/project",
        "snapshot_sha256": SNAPSHOT,
        "tool_runs": [tool_run],
        "translation_units": units,
        "bundle_sha256": uaf_facts_bundle_sha256(units),
        "diagnostics": [],
    }


class FakeUafAnalyzer:
    """Offline ``CxxMemoryAnalyzerClient`` stand-in (facts + tool layers)."""

    def __init__(self, payload):
        self.payload = payload

    def analyze(self, repository_key, snapshot_sha256, requested_layers, inventory=None):
        return CxxAnalysisResult("completed", [], [], {"files": 0}, [])

    def analyze_uaf_facts(
        self, repository_key, snapshot_sha256, translation_units, build_context_mode,
    ):
        return UafFactsResponse(
            request_id=self.payload["request_id"],
            repository_key=repository_key,
            snapshot_sha256=snapshot_sha256,
            tool_runs=tuple(self.payload["tool_runs"]),
            translation_units=tuple(self.payload["translation_units"]),
            bundle_sha256=uaf_facts_bundle_sha256(
                list(self.payload["translation_units"])
            ),
            diagnostics=tuple(self.payload["diagnostics"]),
        )


# -------------------------------------------------- collaboration uaf_v2 shape


def _uaf_payload(**overrides):
    """One completed UAF v2 audit payload, shaped like ``_uaf_collaboration``."""

    payload = {
        "mode": "auto",
        "status": "completed",
        "translation_units": [UNIT],
        "stats": {
            "tu_count": 1,
            "candidate_count": 1,
            "pass": 1,
            "refuted": 0,
            "unknown": 0,
            "llm_invoked": 0,
            "llm_calls": 0,
        },
        "states": {"fact-verified": 1},
        "broker": {"support": 1},
        "diagnostics": [],
        "candidates": [
            {
                "candidate_id": CANDIDATE_ID,
                "path": UNIT,
                "state": "fact-verified",
                "proof": "PASS",
                "rejected_reason": "",
            }
        ],
    }
    payload.update(overrides)
    return payload


def _report(uaf=None, findings=()):
    return {
        "repository": "team/project",
        "pull_request": None,
        "summary": "",
        "risk": "high" if findings else "low",
        "reviewer": "repository-hybrid",
        "findings": list(findings),
        "collaboration": {"uaf_v2": _uaf_payload() if uaf is None else uaf},
        "adjudication": {},
    }


# ------------------------------------------------------------------- tests


class UafSectionRenderTests(unittest.TestCase):
    """Design section 14: every audit field the payload carries is rendered."""

    def test_uaf_section_renders_all_audit_fields(self):
        rendered = to_markdown(_report())
        self.assertIn("## C/C++ UAF v2", rendered)
        # Status / mode / translation units line.
        self.assertIn("- Status: `completed` · mode `auto` · translation units `1`", rendered)
        # Stats line: candidates and the three proof verdicts.
        self.assertIn("- Candidates: `1` · PASS `1` · REFUTED `0` · UNKNOWN `0`", rendered)
        # State labels with the new Chinese badge (no unknown-state fallback).
        self.assertIn("`fact-verified` 事实已验证 × `1`", rendered)
        # Broker three-state summary.
        self.assertIn(
            "- Broker verdicts: support `1` · contradict `0` · no-evidence `0`",
            rendered,
        )
        # Per-candidate audit row with identity and proof verdict.
        self.assertIn(f"- Audit: `{CANDIDATE_ID}` · `{UNIT}` · `fact-verified`", rendered)
        self.assertIn("· proof `PASS`", rendered)
        self.assertIn("- Automatic repair: **false**", rendered)

    def test_partial_payloads_render_without_stats(self):
        for status in ("disabled", "analyzer-not-configured", "no-cxx-sources"):
            rendered = to_markdown(_report(uaf={"mode": "auto", "status": status}))
            self.assertIn("## C/C++ UAF v2", rendered)
            self.assertIn(f"- Status: `{status}` · mode `auto`", rendered)
            self.assertIn("- Automatic repair: **false**", rendered)


class LlmInvocationDisplayTests(unittest.TestCase):
    """``llm_invoked`` is computed from actual call records, never from mode."""

    def test_zero_call_pass_shows_deterministic_proof_note(self):
        rendered = to_markdown(_report())
        # Design wording verbatim plus the Chinese annotation.
        self.assertIn(
            "- deterministic proof; LLM not required（确定性证明 · 未调用 LLM）",
            rendered,
        )
        # Red line: a zero-call run must never claim an invocation.
        self.assertIn("- LLM 真实调用：否", rendered)
        self.assertNotIn("LLM 真实调用：是", rendered)
        self.assertNotIn("LLM 已调用", rendered)

    def test_llm_invoked_count_rendered_from_actual_calls(self):
        rendered = to_markdown(_report(uaf=_uaf_payload(stats={
            "tu_count": 1,
            "candidate_count": 1,
            "pass": 0,
            "refuted": 0,
            "unknown": 1,
            "llm_invoked": 1,
            "llm_calls": 4,
        })))
        self.assertIn("- LLM 真实调用：是（provider 调用 `4` 次）", rendered)
        self.assertNotIn("deterministic proof; LLM not required", rendered)

    def test_zero_calls_without_full_verdict_coverage_stay_honest(self):
        # UNKNOWN present with zero calls (abstained semantic branch): no
        # invocation claim and no deterministic-proof note either.
        rendered = to_markdown(_report(uaf=_uaf_payload(stats={
            "tu_count": 1,
            "candidate_count": 2,
            "pass": 1,
            "refuted": 0,
            "unknown": 1,
            "llm_invoked": 0,
            "llm_calls": 0,
        })))
        self.assertIn("- LLM 真实调用：否", rendered)
        self.assertNotIn("deterministic proof; LLM not required", rendered)


class UntrustedFieldEscapingTests(unittest.TestCase):
    def test_untrusted_diagnostics_escaped(self):
        rendered = to_markdown(_report(uaf=_uaf_payload(
            diagnostics=[f"binding gap {INJECTION} for {CANDIDATE_ID}"],
            candidates=[{
                "candidate_id": CANDIDATE_ID,
                "path": UNIT,
                "state": "rejected",
                "proof": "REFUTED",
                "rejected_reason": f"p6: rebind after release {INJECTION}",
            }],
        )))
        self.assertNotIn(INJECTION, rendered)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", rendered)
        # The bound keeps one diagnostics line per entry.
        self.assertIn("- Diagnostic:", rendered)


class StateLabelTests(unittest.TestCase):
    def test_new_state_labels_no_fallback(self):
        from lima.report import _verification_state_label

        self.assertEqual("事实已验证", _verification_state_label("fact-verified"))
        self.assertEqual(
            "语义支持 · 需复核", _verification_state_label("semantic-supported")
        )
        self.assertNotIn("未知验证状态", _verification_state_label("fact-verified"))
        self.assertNotIn(
            "未知验证状态", _verification_state_label("semantic-supported")
        )
        # Audit-only states in the payload keep honest labels too.
        self.assertNotIn("未知验证状态", _verification_state_label("rejected"))
        self.assertNotIn("未知验证状态", _verification_state_label("abstain"))


class UafFindingProjectionTests(unittest.TestCase):
    """End-to-end offline scan: findings and markdown keep the red lines."""

    def _scan(self):
        root = tempfile.mkdtemp(suffix="-uaf-report")
        self.addCleanup(lambda: _rmtree(root))
        path = Path(root, UNIT)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(
            "\n".join([
                "#include <cstdlib>",
                "int leak(void) {",
                "    int *p = (int *)malloc(sizeof(int));",
                "    free(p);",
                "    return *p;",
                "}",
            ]).encode("utf-8")
        )
        scanner = RepositoryScanner(
            sast_mode="off",
            dataflow_enabled=False,
            cxx_memory_mode="auto",
            cxx_memory_adapter=FakeUafAnalyzer(_payload(_straight_facts())),
            cxx_agent_mode="auto",
        )
        return scanner.scan(RepositoryWorkspace(Path(root)))

    def test_uaf_findings_keep_automatic_repair_false(self):
        result = self._scan()
        payload = result.report.to_dict()["findings"]
        uaf_findings = [item for item in payload if item["source"] == "cxx-uaf-v2"]
        self.assertEqual(1, len(uaf_findings))
        self.assertFalse(uaf_findings[0]["automatic_repair"])
        rendered = to_markdown(result.report.to_dict())
        self.assertIn("## C/C++ UAF v2", rendered)
        # The straight-line proof passes with zero provider calls.
        self.assertIn("deterministic proof; LLM not required", rendered)
        self.assertIn("- LLM 真实调用：否", rendered)
        # The finding detail keeps the no-repair red line.
        self.assertIn("不支持自动修复", rendered)
        self.assertIn("- Candidate: `", rendered)
        self.assertIn("- Trigger path: ", rendered)

    def test_legacy_reports_unchanged_without_uaf_key(self):
        legacy = _report()
        legacy["collaboration"] = {
            "mode": "hybrid-repository-scan",
            "scanned_files": 3,
            "scanned_bytes": 120,
            "workspace_truncated": False,
            "python_parse_errors": 0,
            "dataflow_verified_findings": 0,
            "candidate_findings": 0,
        }
        rendered = to_markdown(legacy)
        self.assertIn("## Workspace coverage", rendered)
        self.assertIn("- Scanned files: `3`; bytes: `120`; truncated: `False`", rendered)
        self.assertNotIn("C/C++ UAF v2", rendered)
        self.assertNotIn("deterministic proof", rendered)


def _rmtree(root):
    import shutil

    shutil.rmtree(root, ignore_errors=True)


# ------------------------------------------------- service capabilities shape


class UafCapabilitiesTests(unittest.TestCase):
    """``repository_scan_capabilities()["uaf_v2"]`` bit shape (additive)."""

    def make_service(self, llm_model=""):
        settings = Settings(
            host="127.0.0.1", port=8080,
            db_path=str(Path(tempfile.mkdtemp(suffix="-uaf-cap"), "state.db")),
            max_diff_bytes=10000, max_steps=8, timeout_seconds=120,
            llm_base_url="http://127.0.0.1:9" if llm_model else "",
            llm_api_key="stub-key" if llm_model else "",
            llm_model=llm_model,
            github_webhook_secret="", github_token="",
            auto_post_review=False,
            repository_scan_sources="local-import",
            repository_scan_sast_mode="off",
            cxx_memory_mode="off",
            cxx_agent_mode="auto",
        )
        service = ReviewService(settings)
        self.addCleanup(service.queue.close)
        return service

    def test_capabilities_expose_uaf_v2_shape(self):
        service = self.make_service()
        uaf = service.repository_scan_capabilities()["uaf_v2"]
        self.assertEqual("auto", uaf["mode"])
        self.assertIsInstance(uaf["analyzer_configured"], bool)
        self.assertFalse(uaf["llm_configured"])
        self.assertEqual(sorted(UAF_FINDING_STATES), uaf["states"])

    def test_capabilities_flags_follow_real_configuration(self):
        service = self.make_service(llm_model="stub-model")
        # No sidecar adapter yet: the facts ability decides, not the URL.
        self.assertFalse(
            service.repository_scan_capabilities()["uaf_v2"]["analyzer_configured"]
        )
        service.repository_scanner.cxx_memory_adapter = SimpleNamespace(
            analyze_uaf_facts=lambda *args, **kwargs: None
        )
        uaf = service.repository_scan_capabilities()["uaf_v2"]
        self.assertTrue(uaf["analyzer_configured"])
        self.assertTrue(uaf["llm_configured"])
        # Additive key: legacy ``cxx_agent`` bits stay untouched.
        agent = service.repository_scan_capabilities()["cxx_agent"]
        self.assertEqual("auto", agent["mode"])
        self.assertFalse(agent["automatic_repair"])


if __name__ == "__main__":
    unittest.main()
