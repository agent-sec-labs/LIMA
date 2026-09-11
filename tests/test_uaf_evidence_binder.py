"""Plan Task 9: deterministic tool-finding to UafCandidate binder.

Freezes the Task 9 binder rules (plan section "binder 规则（冻结）"):

- Semgrep/Clang: exact ``canonical_path`` equality, finding line inside
  ``release_range`` or ``use_range`` (closed intervals, no +/-N tolerance),
  and a symbol that is empty (line-only pass-through) or equals the last
  ``::``-segment of ``function_usr``.  Every other outcome is a named
  ``binding_gap``.
- ASan: phase-1 degraded witness check -- the faulting ``finding.line``
  must hit ``use_range`` and some evidence-record snippet must carry both
  "freed by" and "allocated by" stack segments (existence only; per-frame
  line matching waits for richer evidence structures).
- ``collect_bound_evidence`` keeps only records whose ``tool_run_id``
  resolves to a completed, tool-matching run; everything skipped is
  reported as a gap.  An empty tool result is never safety.
"""

import dataclasses
import unittest

from lima.models import EvidenceRecord, Finding, Severity
from lima.uaf_evidence_binder import (
    ToolFindingBinding,
    bind_finding_to_candidate,
    collect_bound_evidence,
)
from lima.uaf_models import UafCandidate

_A = "a" * 64
_B = "b" * 64
_C = "c" * 64
_D = "d" * 64
_E = "e" * 64

_USR = "c:@F@Session#close#"
_QUALIFIED_USR = "c:@F@ns::Session::close"


def _candidate(**overrides):
    base = {
        "candidate_id": _A,
        "object_id": _B,
        "allocation_fact_id": _C,
        "release_fact_id": _D,
        "use_fact_id": _E,
        "canonical_path": "src/session.cpp",
        "function_usr": _USR,
        "release_range": (10, 12),
        "use_range": (20, 24),
    }
    base.update(overrides)
    return UafCandidate(**base)


def _finding(
    *,
    source="semgrep",
    path="src/session.cpp",
    line=20,
    symbol="",
    run_id="run-1",
    snippet="free(p); later use(p);",
):
    return Finding(
        rule_id=f"cxx.{source}.identity",
        severity=Severity.HIGH,
        title=f"{source} identity hit",
        explanation=f"{source} matched the candidate identity",
        path=path,
        line=line,
        evidence=snippet,
        fix="",
        test="Reproduce under AddressSanitizer",
        confidence=0.9,
        cwe="CWE-416",
        source=source,
        evidence_kind="line",
        verification_state="candidate",
        language="c++",
        symbol=symbol,
        analysis_mode="tool",
        automatic_repair=False,
        evidence_records=[
            EvidenceRecord(
                source=source,
                kind="match",
                path=path,
                line=line,
                snippet=snippet,
                rule_id=f"cxx.{source}.identity",
                cwe="CWE-416",
                confidence=0.9,
                language="c++",
                symbol=symbol,
                analysis_mode="tool",
                tool_run_id=run_id,
            )
        ],
    )


def _run(run_id="run-1", tool="semgrep", status="completed"):
    return {
        "run_id": run_id,
        "tool": tool,
        "status": status,
        "returncode": 0 if status == "completed" else 1,
        "output_sha256": "b" * 64,
        "output_truncated": False,
        "digests_complete": True,
    }


_ASAN_SNIPPET = (
    "==4711==ERROR: AddressSanitizer: heap-use-after-free on address 0x60200000eff4\n"
    "READ of size 4 at 0x60200000eff4 thread T0\n"
    "    #0 0x4f2e05 in Session::use src/session.cpp:22\n"
    "freed by thread T0 here:\n"
    "    #0 0x4f2b3c in Session::release src/session.cpp:11\n"
    "previously allocated by thread T0 here:\n"
    "    #0 0x4f2a9f in Session::alloc src/session.cpp:5\n"
)


class ToolFindingBindingContractTests(unittest.TestCase):
    """The binding result itself is a frozen, self-consistent record."""

    def test_unbound_binding_requires_a_gap(self):
        with self.assertRaises(ValueError):
            ToolFindingBinding(bound=False, binding_gap="")

    def test_bound_binding_forbids_a_gap(self):
        with self.assertRaises(ValueError):
            ToolFindingBinding(bound=True, binding_gap="path-mismatch")

    def test_binding_is_frozen(self):
        binding = ToolFindingBinding(bound=True)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            binding.bound = False  # type: ignore[misc]


class StaticProducerBindingTests(unittest.TestCase):
    """Semgrep/Clang rules: exact path, closed ranges, symbol last segment."""

    def test_exact_path_and_use_range_line_binds(self):
        binding = bind_finding_to_candidate(_finding(line=22), _candidate())
        self.assertEqual(ToolFindingBinding(bound=True), binding)

    def test_release_range_hit_binds(self):
        binding = bind_finding_to_candidate(_finding(line=11), _candidate())
        self.assertTrue(binding.bound)

    def test_release_range_start_endpoint_binds(self):
        binding = bind_finding_to_candidate(_finding(line=10), _candidate())
        self.assertTrue(binding.bound)

    def test_use_range_end_endpoint_binds(self):
        binding = bind_finding_to_candidate(_finding(line=24), _candidate())
        self.assertTrue(binding.bound)

    def test_path_off_by_one_character_rejected(self):
        binding = bind_finding_to_candidate(
            _finding(path="src/sessiom.cpp"), _candidate()
        )
        self.assertFalse(binding.bound)
        self.assertEqual("path-mismatch", binding.binding_gap)

    def test_path_mismatch_takes_precedence(self):
        binding = bind_finding_to_candidate(
            _finding(path="src/other.cpp", line=999, symbol="bogus"), _candidate()
        )
        self.assertEqual("path-mismatch", binding.binding_gap)

    def test_line_one_before_release_start_rejected(self):
        binding = bind_finding_to_candidate(_finding(line=9), _candidate())
        self.assertFalse(binding.bound)
        self.assertEqual("line-outside-ranges", binding.binding_gap)

    def test_line_one_after_use_end_rejected(self):
        binding = bind_finding_to_candidate(_finding(line=25), _candidate())
        self.assertFalse(binding.bound)
        self.assertEqual("line-outside-ranges", binding.binding_gap)

    def test_line_between_ranges_rejected(self):
        binding = bind_finding_to_candidate(_finding(line=15), _candidate())
        self.assertFalse(binding.bound)
        self.assertEqual("line-outside-ranges", binding.binding_gap)

    def test_empty_symbol_passes_on_line_alone(self):
        binding = bind_finding_to_candidate(_finding(symbol=""), _candidate())
        self.assertTrue(binding.bound)
        self.assertEqual("", binding.binding_gap)

    def test_symbol_matching_full_usr_binds(self):
        binding = bind_finding_to_candidate(_finding(symbol=_USR), _candidate())
        self.assertTrue(binding.bound)

    def test_symbol_matching_last_segment_of_qualified_usr_binds(self):
        candidate = _candidate(function_usr=_QUALIFIED_USR)
        binding = bind_finding_to_candidate(_finding(symbol="close"), candidate)
        self.assertTrue(binding.bound)

    def test_symbol_mismatch_rejected(self):
        binding = bind_finding_to_candidate(_finding(symbol="close"), _candidate())
        self.assertFalse(binding.bound)
        self.assertEqual("symbol-mismatch", binding.binding_gap)

    def test_empty_usr_with_nonempty_symbol_rejected(self):
        binding = bind_finding_to_candidate(
            _finding(symbol="close"), _candidate(function_usr="")
        )
        self.assertFalse(binding.bound)
        self.assertEqual("symbol-mismatch", binding.binding_gap)

    def test_clang_source_binds_under_the_same_rules(self):
        binding = bind_finding_to_candidate(
            _finding(source="clang", line=11), _candidate()
        )
        self.assertTrue(binding.bound)
        rejected = bind_finding_to_candidate(
            _finding(source="clang", line=30), _candidate()
        )
        self.assertEqual(("line-outside-ranges", False), (rejected.binding_gap, rejected.bound))

    def test_binding_is_pure_and_repeatable(self):
        first = bind_finding_to_candidate(_finding(line=22), _candidate())
        second = bind_finding_to_candidate(_finding(line=22), _candidate())
        self.assertEqual(first, second)


class AsanBindingTests(unittest.TestCase):
    """Phase-1 degraded ASan witness check with honest stack-segment gaps."""

    def test_witness_in_use_range_with_both_stack_segments_binds(self):
        binding = bind_finding_to_candidate(
            _finding(source="asan", line=22, snippet=_ASAN_SNIPPET),
            _candidate(),
        )
        self.assertTrue(binding.bound)
        self.assertEqual("", binding.binding_gap)

    def test_missing_freed_stack_rejected(self):
        snippet = _ASAN_SNIPPET.replace("freed by thread T0 here:", "freed here:")
        binding = bind_finding_to_candidate(
            _finding(source="asan", line=22, snippet=snippet), _candidate()
        )
        self.assertFalse(binding.bound)
        self.assertEqual("asan-stack-missing", binding.binding_gap)

    def test_missing_allocated_stack_rejected(self):
        snippet = _ASAN_SNIPPET.replace(
            "previously allocated by thread T0 here:", "allocated earlier:"
        )
        binding = bind_finding_to_candidate(
            _finding(source="asan", line=22, snippet=snippet), _candidate()
        )
        self.assertFalse(binding.bound)
        self.assertEqual("asan-stack-missing", binding.binding_gap)

    def test_witness_outside_use_range_rejected_even_with_stacks(self):
        binding = bind_finding_to_candidate(
            _finding(source="asan", line=30, snippet=_ASAN_SNIPPET),
            _candidate(),
        )
        self.assertFalse(binding.bound)
        self.assertEqual("asan-witness-miss", binding.binding_gap)

    def test_witness_in_release_range_only_is_not_a_use_hit(self):
        # The ASan check pins the faulting access to use_range only; a
        # release-side line never counts as a runtime witness.
        binding = bind_finding_to_candidate(
            _finding(source="asan", line=11, snippet=_ASAN_SNIPPET),
            _candidate(),
        )
        self.assertFalse(binding.bound)
        self.assertEqual("asan-witness-miss", binding.binding_gap)

    def test_any_record_carrying_both_stacks_satisfies_the_check(self):
        finding = _finding(source="asan", line=22, snippet="no stacks here")
        finding.evidence_records.append(
            EvidenceRecord(
                source="asan",
                kind="stack",
                path="src/session.cpp",
                line=22,
                snippet=_ASAN_SNIPPET,
                rule_id="cxx.asan.identity",
                cwe="CWE-416",
                confidence=0.9,
                language="c++",
                symbol="",
                analysis_mode="tool",
                tool_run_id="run-1",
            )
        )
        binding = bind_finding_to_candidate(finding, _candidate())
        self.assertTrue(binding.bound)


class UnsupportedProducerTests(unittest.TestCase):
    """Producers outside the three Sidecar tools never bind."""

    def test_local_rule_producer_unsupported(self):
        binding = bind_finding_to_candidate(_finding(source="local-rule"), _candidate())
        self.assertFalse(binding.bound)
        self.assertEqual("unsupported-producer", binding.binding_gap)

    def test_unknown_producer_unsupported(self):
        binding = bind_finding_to_candidate(_finding(source="cppcheck"), _candidate())
        self.assertFalse(binding.bound)
        self.assertEqual("unsupported-producer", binding.binding_gap)


class TypeContractTests(unittest.TestCase):
    """The binder refuses foreign inputs instead of guessing."""

    def test_non_finding_rejected(self):
        with self.assertRaises(ValueError):
            bind_finding_to_candidate("not-a-finding", _candidate())

    def test_non_candidate_rejected(self):
        with self.assertRaises(ValueError):
            bind_finding_to_candidate(_finding(), "not-a-candidate")


class CollectBoundEvidenceTests(unittest.TestCase):
    """collect_bound_evidence: bound findings plus completed-run filtering."""

    def test_collect_returns_resolvable_records_without_gaps(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22)], _candidate(), [_run()]
        )
        self.assertEqual(1, len(records))
        self.assertEqual("run-1", records[0].tool_run_id)
        self.assertEqual((), gaps)

    def test_collect_skips_failed_run_with_provenance_gap(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22)], _candidate(), [_run(status="failed")]
        )
        self.assertEqual((), records)
        self.assertEqual(("provenance-incomplete",), gaps)

    def test_collect_skips_unknown_run_id(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22)], _candidate(), []
        )
        self.assertEqual((), records)
        self.assertEqual(("provenance-incomplete",), gaps)

    def test_collect_skips_tool_mismatched_run(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22)], _candidate(), [_run(tool="clang")]
        )
        self.assertEqual((), records)
        self.assertEqual(("provenance-incomplete",), gaps)

    def test_collect_uses_asan_test_run_name_for_asan_findings(self):
        records, gaps = collect_bound_evidence(
            [_finding(source="asan", line=22, snippet=_ASAN_SNIPPET, run_id="run-asan")],
            _candidate(),
            [_run("run-asan", "asan-test")],
        )
        self.assertEqual(1, len(records))
        self.assertEqual((), gaps)
        records, gaps = collect_bound_evidence(
            [_finding(source="asan", line=22, snippet=_ASAN_SNIPPET, run_id="run-asan")],
            _candidate(),
            [_run("run-asan", "asan")],
        )
        self.assertEqual((), records)
        self.assertEqual(("provenance-incomplete",), gaps)

    def test_collect_reports_binding_gap_for_unbound_finding(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22), _finding(path="src/other.cpp")],
            _candidate(),
            [_run()],
        )
        self.assertEqual(1, len(records))
        self.assertEqual(("path-mismatch",), gaps)

    def test_collect_keeps_only_the_bound_candidates_records(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22), _finding(line=300, run_id="run-1")],
            _candidate(),
            [_run()],
        )
        self.assertEqual(1, len(records))
        self.assertEqual(("line-outside-ranges",), gaps)

    def test_collect_malformed_run_entries_never_resolve(self):
        records, gaps = collect_bound_evidence(
            [_finding(line=22)], _candidate(), [{"tool": "semgrep"}, "junk", None]
        )
        self.assertEqual((), records)
        self.assertEqual(("provenance-incomplete",), gaps)

    def test_collect_empty_findings_is_empty_without_gaps(self):
        records, gaps = collect_bound_evidence([], _candidate(), [_run()])
        self.assertEqual((), records)
        self.assertEqual((), gaps)

    def test_collect_order_is_deterministic(self):
        records, gaps = collect_bound_evidence(
            [
                _finding(line=22, run_id="run-b"),
                _finding(path="src/other.cpp"),
                _finding(source="clang", line=11, run_id="run-a"),
            ],
            _candidate(),
            [_run("run-b"), _run("run-a", "clang")],
        )
        self.assertEqual(("run-b", "run-a"), tuple(item.tool_run_id for item in records))
        self.assertEqual(("path-mismatch",), gaps)


if __name__ == "__main__":
    unittest.main()
