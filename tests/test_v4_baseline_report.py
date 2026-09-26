"""Frozen acceptance tests for IP-0029: baseline report projection (Issue #217).

Contract under test (frozen by Coordinator Assignment CA-IP-0029-v1.0 of
2026-09-26; see docs/LIMA_Implementation_Packet_IP-0029_Baseline_Report_Projection.md):

- The Implementation deliverable is the new report module
  ``benchmarks/v4/baseline/report.py``: the independent ``lima.baseline-report``
  schema v1 document (16 frozen top-level fields, no floats, no free text),
  strict ``from_mapping`` decoding, deterministic projection of the FR-04
  counting face and compression chain from exactly one injected evaluator
  payload (scanner / e2e / real-world, recognized by frozen structural
  predicates), the two-layer legacy projection marking (report-level bool plus
  per-count ``measured``/``legacy_projection``/``unavailable`` with
  null-not-zero absence), the expert active-time / automation timing faces,
  canonical bytes only through ``lima.contracts.codec``, exclusive report
  file writing through the frozen ``write_exclusive``, the closed
  ``declarations`` enum (SF-IP-0028-20260926-2), and the pure
  ``find_run_artifacts`` discovery contract anchored to real
  ``orchestrate.run_repeats`` disk output.
- Every unavailable position is null (never 0); ratios are integer basis
  points with floor semantics; a real-world payload's ``schema_version == 2``
  is never evidence of a v2 evidence domain; a bundle's statically supported
  hypothesis is never promoted to ``confirmed``.
- Everything is offline and secretless: deterministic, no network, no
  environment reads, no paid model calls, no manifest consumption, tempfile
  fixtures only.

Expected RED before implementation (product submodule absent): the test
module is discovered, but the module-level ``import benchmarks.v4.baseline.report``
fails with ``ModuleNotFoundError: No module named
'benchmarks.v4.baseline.report'`` (the package exists, the submodule does
not), so every test fails closed, attributable solely to the missing product
module.
"""

import ast
import dataclasses
import hashlib
import json
import pathlib
import re
import tempfile
import unittest

from benchmarks.v4.baseline import (  # isort: skip -- first-party only once the module exists
    collect,
    expert_timing,
    orchestrate,
    run,
)
import benchmarks.v4.baseline.report as report  # isort: skip -- RED anchor

from lima.baseline_run_result import from_mapping as result_from_mapping
from lima.contracts import compat, evidence
from lima.contracts.codec import canonical_encode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.models import Finding, ReviewReport, Severity
from lima.repository_scanner import COVERAGE_AFFECTING_SKIPS, RepositoryScanResult
from lima.workspace import WorkspaceInventory

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_MANIFEST_RELATIVE_PATH = "evaluation_data/v4/baseline_manifest.json"

_DIGEST_A = "a" * 64
_DIGEST_B = "b" * 64
_DIGEST_C = "c" * 64
_HEX64 = re.compile(r"[0-9a-f]{64}")

_REPORT_FIELDS = (
    "schema_name",
    "schema_version",
    "run_spec_digest",
    "aggregate_sha256",
    "aggregate_status",
    "attempt_count",
    "evidence_domain",
    "legacy_projection",
    "declarations",
    "sources",
    "counts",
    "coverage_gap_reasons",
    "compression_chain",
    "expert",
    "automation",
    "resources",
)

_COUNT_KEYS = (
    "signals",
    "security_issues",
    "hypotheses",
    "confirmed",
    "inconclusive",
    "scanned_files",
    "coverage_gap",
)

_FROZEN_ERROR_MESSAGES = {
    "SCHEMA_NAME_INVALID": "Baseline report schema name is invalid.",
    "SCHEMA_VERSION_INVALID": "Baseline report schema version is invalid.",
    "REQUIRED_FIELD_MISSING": "A required baseline report field is missing.",
    "UNKNOWN_FIELD": "Baseline report contains an unknown field for this schema version.",
    "INVALID_FIELD_TYPE": "Baseline report field has an invalid type.",
    "INVALID_FIELD_VALUE": "Baseline report field has an invalid value.",
    "INVALID_DIGEST": "A digest is not a lowercase 64-character hex digest.",
    "DIGEST_MISMATCH": "A digest does not match the content it summarizes.",
    "EVALUATOR_PAYLOAD_UNRECOGNIZED": (
        "The evaluator payload matches no frozen evaluator output shape."
    ),
    "EVALUATOR_PAYLOAD_INVALID": "The evaluator payload violates its frozen output shape.",
    "SIDECAR_INVALID": "An expert-timing sidecar document is invalid.",
    "ARTIFACT_UNREADABLE": "A baseline run artifact file could not be parsed.",
}

_ALLOWED_STDLIB_IMPORTS = frozenset(
    {"dataclasses", "enum", "hashlib", "json", "pathlib", "re", "typing"}
)
_ALLOWED_PRODUCT_IMPORTS = frozenset(
    {
        "lima.contracts.codec",
        "lima.contracts.evidence",
        "lima.contracts.compat",
        "lima.baseline_run_result",
        "benchmarks.v4.baseline.collect",
        "benchmarks.v4.baseline.run",
        "benchmarks.v4.baseline.orchestrate",
    }
)

# AC-2 structural boundary: every string in a built document is one of these
# frozen enum literals, a 64-hex digest, or a coverage-affecting skip reason.
_ALLOWED_DOC_STRINGS = frozenset(
    {
        "lima.baseline-report",
        "sufficient_sample",
        "insufficient_sample",
        "v2",
        "legacy",
        "measured",
        "legacy_projection",
        "unavailable",
        "e2e",
        "real-world",
        "scanner",
        "evidence-domain",
        "baseline_mode_legacy_report_parameters_inert",
    }
)

_NOMINAL_ANALYZER_FINGERPRINT = "a" * 64
_NOMINAL_CONFIG_DIGEST = "b" * 64
_NOMINAL_SEED = 20260925
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


def _forbidden_source_tokens():
    """Offline tokens that must never appear in the product module or here."""
    return [
        "os." + "environ",
        "get" + "env",
        "sock" + "et",
        "url" + "lib",
        "requ" + "ests",
    ]


class _CountingExecute:
    """Execution body double that only records how often it was invoked."""

    def __init__(self):
        self.calls = 0

    def __call__(self):
        self.calls += 1
        return None


def _stub_sources(cold_ms, warm_ms):
    """Injectable platform sources whose wall durations per attempt are in ms."""
    durations = [value * 1_000_000 for value in (*cold_ms, *warm_ms)]
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


def _sample(attempt_index, mode, wall_time_ms):
    return {
        "attempt_index": attempt_index,
        "mode": mode,
        "outcome": "success",
        "wall_time_ms": wall_time_ms,
        "queue_time_ms": None,
        "cpu_time_ms": 10,
        "expert_time_ms": None,
        "memory_rss_peak_bytes": 1,
        "io_read_bytes": 1,
        "io_write_bytes": 1,
        "prompt_tokens": None,
        "completion_tokens": None,
        "cost_micro_usd": None,
        "failure_code": None,
    }


def _result_mapping(digest, samples):
    return {"schema_version": 1, "run_spec_digest": digest, "samples": samples}


def _finding(state="candidate", rule_id="rule-a", path="pkg/module.py", line=10):
    return Finding(
        rule_id=rule_id,
        severity=Severity.HIGH,
        title="title",
        explanation="explanation",
        path=path,
        line=line,
        evidence="evidence-" + rule_id,
        fix="fix",
        test="test",
        verification_state=state,
    )


def _scan_payload(states=("candidate",), skipped=None, scanned_files=7):
    findings = [
        _finding(state=state, rule_id=f"rule-{index}") for index, state in enumerate(states)
    ]
    skipped = dict(skipped or {})
    review = ReviewReport(
        repository="fixture-repo",
        pull_request=None,
        summary="summary",
        risk="high",
        findings=findings,
        files_reviewed=["pkg/module.py"],
        reviewer="local-rules",
        collaboration={"scanned_files": scanned_files, "skipped": dict(skipped)},
        adjudication={},
    )
    inventory = WorkspaceInventory(root="fixture-repo", skipped=dict(skipped))
    return RepositoryScanResult(report=review, inventory=inventory)


def _e2e_payload(tp=3, fp=4, fn=2, name="e2e-fixture", reviewer="reviewer-fixture"):
    return {
        "schema_version": 1,
        "name": name,
        "reviewer": reviewer,
        "dataset": {
            "cases": 1,
            "repositories": 1,
            "risk_cases": 1,
            "clean_cases": 0,
            "source_kinds": ["fixture"],
            "sha256": _DIGEST_C,
        },
        "metrics": {"tp": tp, "fp": fp, "fn": fn, "precision": 0.5},
        "by_split": {"validation": {"tp": tp, "fp": fp, "fn": fn}},
        "duration_seconds": 1.5,
        "case_results": [],
    }


def _rw_case(files_v=5, files_f=6, total_v=8, total_f=9, skipped_v=None):
    return {
        "id": "case-1",
        "deterministic": {
            "total_findings": {"vulnerable": total_v, "fixed": total_f},
            "workspace": {
                "vulnerable": {"files": files_v, "skipped": dict(skipped_v or {})},
                "fixed": {"files": files_f, "skipped": {}},
            },
        },
    }


def _rw_payload(cases):
    return {
        "schema_version": 2,
        "mode": "deterministic",
        "scanner_profile": "fast-ast",
        "metrics": {"cases": len(cases)},
        "results": list(cases),
    }


def _sidecar(digest=_DIGEST_A, reviewer_digest=_DIGEST_B, active_ms=5):
    return {
        "schema_version": 1,
        "run_spec_digest": digest,
        "reviewer_digest": reviewer_digest,
        "active_time_ms": active_ms,
        "events": [],
    }


def _payload_digest(payload):
    """The frozen input-fingerprint rule for dict and wire-value payloads."""
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _scanner_payload_digest(payload):
    wire = {**payload.report.to_dict(), "workspace": payload.inventory.to_dict()}
    return _payload_digest(wire)


def _synthetic_bundle():
    """One bundle: 1 signal + 1 issue + 1 statically_supported hypothesis."""
    base = compat.finding_to_domain_bundle(_finding(rule_id="rule-b"))
    location = base.signals[0].location
    hypothesis = evidence.VulnerabilityHypothesis(
        hypothesis_id="hyp-0001",
        issue_id=base.security_issues[0].issue_id,
        status=evidence.HypothesisStatus.STATICALLY_SUPPORTED,
        claim="claim",
        security_invariant="invariant",
        required_proof_kind=evidence.RequiredProofKind.RUNTIME_BEHAVIOR,
        capability_requirements=("cap-a",),
        target_location=location,
        source_locations=(location,),
        critical_path=(location,),
        trigger_conditions=("trigger-a",),
        input_constraints=("constraint-a",),
        evidence_ids=("zz-hyp-0000",),
        reason_codes=("R1",),
    )
    record = evidence.EvidenceRecord(
        evidence_id="zz-hyp-0000",
        subject_kind=evidence.EvidenceSubjectKind.VULNERABILITY_HYPOTHESIS,
        subject_id="hyp-0001",
        level=evidence.EvidenceLevel.D2,
        polarity=evidence.EvidencePolarity.SUPPORTS,
        analysis_family="family-a",
        producer="producer-a",
        independence_key="indep-a",
        summary="summary",
        source_artifact_ids=("artifact-a",),
        reason_codes=("R1",),
    )
    return evidence.EvidenceDomainBundle(
        schema_version=SchemaVersion(4, 0),
        signals=base.signals,
        security_issues=base.security_issues,
        vulnerability_hypotheses=(hypothesis,),
        evidence=base.evidence + (record,),
    )


def _walk_strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_strings(item)


def _walk_floats(value):
    if isinstance(value, float):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from _walk_floats(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _walk_floats(item)


def _count(value, projection):
    """The frozen per-count shape: {"value": int | None, "projection": str}."""
    return {"value": value, "projection": projection}


class _IP0029ReportTestCase(unittest.TestCase):
    """Shared fixtures: summary construction, builds, and typed-error asserts."""

    @staticmethod
    def _fixture_summary(digest=_DIGEST_A, sufficient=True):
        if sufficient:
            samples = [_sample(index, "cold", 100 * (index + 1)) for index in range(3)]
            samples += [_sample(3 + index, "warm", 400 + 100 * index) for index in range(5)]
        else:
            samples = [_sample(0, "cold", 100)]
        attempts = tuple(
            result_from_mapping(_result_mapping(digest, [sample])) for sample in samples
        )
        aggregate = result_from_mapping(_result_mapping(digest, samples))
        return orchestrate.BaselineRunSummary(
            attempts=attempts,
            result_paths=(),
            aggregate=aggregate,
            aggregate_path=pathlib.Path(f"{digest[:16]}-run-2.json"),
            aggregate_sha256=aggregate.content_digest(),
            status=aggregate.status,
        )

    def _build(self, payload, *, digest=_DIGEST_A, sufficient=True, sidecars=(), bundle=None):
        return report.build_baseline_report(
            self._fixture_summary(digest=digest, sufficient=sufficient),
            payload,
            expert_sidecars=sidecars,
            bundle=bundle,
        )

    def _doc(self, payload, **kwargs):
        return self._build(payload, **kwargs).to_canonical_value()

    def _assert_typed_error(self, code, field_path, builder):
        with self.assertRaises(report.BaselineReportError) as ctx:
            builder()
        self.assertEqual(ctx.exception.code, report.BaselineReportErrorCode(code))
        self.assertEqual(ctx.exception.field_path, field_path)
        self.assertEqual(str(ctx.exception), _FROZEN_ERROR_MESSAGES[code])


class TestReportSchemaAndCanonical(_IP0029ReportTestCase):
    """AC-2 / FR-04: canonical stability, strict decode, frozen surface."""

    def test_canonical_bytes_stable_and_digest_recomputable(self):
        first = self._build(_scan_payload(states=("candidate", "confirmed")))
        second = self._build(_scan_payload(states=("candidate", "confirmed")))
        self.assertEqual(first.canonical_bytes(), second.canonical_bytes())
        data = first.canonical_bytes()
        self.assertEqual(hashlib.sha256(data).hexdigest(), first.content_digest())
        self.assertEqual(compute_content_digest(data), first.content_digest())
        self.assertEqual(canonical_encode(first.to_canonical_value()), data)
        self.assertNotIn(b"\n", data)
        self.assertTrue(data.decode("utf-8").startswith(b"{".decode()))

    def test_roundtrip_from_mapping_and_unknown_field_rejected(self):
        document = self._build(_scan_payload(states=("corroborated",)))
        value = document.to_canonical_value()
        again = report.from_mapping(json.loads(json.dumps(value)))
        self.assertEqual(again.canonical_bytes(), document.canonical_bytes())
        self.assertEqual(again.to_canonical_value(), value)
        with_unknown = dict(value)
        with_unknown["unexpected"] = 1
        self._assert_typed_error(
            "UNKNOWN_FIELD", "$.unexpected", lambda: report.from_mapping(with_unknown)
        )
        nested_unknown = json.loads(json.dumps(value))
        nested_unknown["counts"]["signals"]["extra"] = 1
        self._assert_typed_error(
            "UNKNOWN_FIELD", "$.counts.signals.extra", lambda: report.from_mapping(nested_unknown)
        )
        missing = dict(value)
        del missing["expert"]
        self._assert_typed_error(
            "REQUIRED_FIELD_MISSING", "$.expert", lambda: report.from_mapping(missing)
        )

    def test_schema_name_and_version_invalid_rejected(self):
        value = self._build(_e2e_payload()).to_canonical_value()
        wrong_name = dict(value)
        wrong_name["schema_name"] = "lima.other-report"
        self._assert_typed_error(
            "SCHEMA_NAME_INVALID", "$.schema_name", lambda: report.from_mapping(wrong_name)
        )
        wrong_version = dict(value)
        wrong_version["schema_version"] = 2
        self._assert_typed_error(
            "SCHEMA_VERSION_INVALID", "$.schema_version", lambda: report.from_mapping(wrong_version)
        )
        bad_digest = dict(value)
        bad_digest["run_spec_digest"] = "not-hex"
        self._assert_typed_error(
            "INVALID_DIGEST", "$.run_spec_digest", lambda: report.from_mapping(bad_digest)
        )

    def test_document_value_types_no_floats_no_free_text(self):
        document = self._build(
            _scan_payload(states=("candidate",), skipped={"symlink": 2})
        )
        value = document.to_canonical_value()
        for leaked in _walk_floats(value):
            self.fail(f"float leaked into report: {leaked!r}")
        for text in _walk_strings(value):
            self.assertTrue(
                text in _ALLOWED_DOC_STRINGS
                or text in COVERAGE_AFFECTING_SKIPS
                or _HEX64.fullmatch(text) is not None,
                f"free-text string leaked into report: {text!r}",
            )
        self.assertEqual(set(value), set(_REPORT_FIELDS))
        self.assertEqual(set(value["counts"]), set(_COUNT_KEYS))
        data = document.canonical_bytes()
        self.assertNotIn(b"/", data)
        self.assertNotIn(b"\\", data)
        self.assertIsNone(re.search(rb"[A-Za-z]:", data))

    def test_report_surface_frozen(self):
        self.assertEqual(
            set(report.__all__),
            {
                "BASELINE_REPORT_SCHEMA_NAME",
                "BASELINE_REPORT_SCHEMA_VERSION",
                "BASELINE_REPORT_DECLARATIONS",
                "BaselineReport",
                "BaselineReportError",
                "BaselineReportErrorCode",
                "ReportFileArtifacts",
                "RunArtifactEntry",
                "build_baseline_report",
                "find_run_artifacts",
                "from_mapping",
                "write_report_file",
            },
        )
        members = {member.name for member in report.BaselineReportErrorCode}
        self.assertEqual(members, set(_FROZEN_ERROR_MESSAGES))
        for name in _FROZEN_ERROR_MESSAGES:
            member = report.BaselineReportErrorCode(name)
            self.assertEqual(member.value, name)
            error = report.BaselineReportError(member, "$.x")
            self.assertEqual(str(error), _FROZEN_ERROR_MESSAGES[name])
        self.assertTrue(issubclass(report.BaselineReportError, ValueError))
        self.assertEqual(report.BASELINE_REPORT_SCHEMA_NAME, "lima.baseline-report")
        self.assertEqual(report.BASELINE_REPORT_SCHEMA_VERSION, 1)
        self.assertEqual(
            report.BASELINE_REPORT_DECLARATIONS,
            ("baseline_mode_legacy_report_parameters_inert",),
        )
        self.assertTrue(dataclasses.is_dataclass(report.BaselineReport))
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(report.BaselineReport)),
            _REPORT_FIELDS,
        )
        document = self._build(_scan_payload())
        with self.assertRaises(dataclasses.FrozenInstanceError):
            document.schema_version = 2
        self.assertFalse(hasattr(document, "__dict__"))
        entry = report.RunArtifactEntry(
            digest16="a" * 16,
            sequence=1,
            result_path=pathlib.Path("result.json"),
            sidecar_path=None,
            sample_count=1,
            is_aggregate=False,
        )
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(report.RunArtifactEntry)),
            ("digest16", "sequence", "result_path", "sidecar_path", "sample_count", "is_aggregate"),
        )
        self.assertFalse(hasattr(entry, "__dict__"))
        artifacts = report.ReportFileArtifacts(
            report_path=pathlib.Path("report.json"), report_sha256="b" * 64
        )
        self.assertEqual(
            tuple(field.name for field in dataclasses.fields(report.ReportFileArtifacts)),
            ("report_path", "report_sha256"),
        )
        self.assertFalse(hasattr(artifacts, "__dict__"))


class TestProjectionScanner(_IP0029ReportTestCase):
    """AC-1 / FR-01: scanner-source projection, ladder, partition invariant."""

    def test_scanner_counts_and_partition_invariant(self):
        states = (
            "candidate",
            "syntax-verified",
            "corroborated",
            "dataflow-verified",
            "confirmed",
            "confirmed",
        )
        document = self._doc(_scan_payload(states=states))
        counts = document["counts"]
        self.assertEqual(counts["signals"], _count(6, "legacy_projection"))
        self.assertEqual(counts["security_issues"], _count(6, "legacy_projection"))
        self.assertEqual(counts["confirmed"], _count(2, "legacy_projection"))
        self.assertEqual(counts["inconclusive"], _count(2, "legacy_projection"))
        chain = document["compression_chain"]
        self.assertEqual(chain["raw_candidates"], 6)
        self.assertEqual(chain["deterministic_alerts"], 4)
        self.assertEqual(chain["confirmed"], 2)
        self.assertEqual(chain["inconclusive"], 2)
        self.assertEqual(
            chain["candidates_to_deterministic"],
            {"numerator": 4, "denominator": 6, "ratio_basis_points": 6666},
        )
        self.assertEqual(
            chain["deterministic_to_confirmed"],
            {"numerator": 2, "denominator": 4, "ratio_basis_points": 5000},
        )
        self.assertEqual(
            chain["raw_candidates"], chain["deterministic_alerts"] + chain["inconclusive"]
        )
        self.assertEqual(document["evidence_domain"], "legacy")
        self.assertTrue(document["legacy_projection"])
        self.assertEqual(document["attempt_count"], 8)
        expected_sources = [
            {
                "kind": "scanner",
                "payload_sha256": _scanner_payload_digest(_scan_payload(states=states)),
            }
        ]
        self.assertEqual(document["sources"], expected_sources)

    def test_scanner_coverage_face_and_reasons(self):
        skipped = {"symlink": 2, "unreadable": 1, "ignored-directory": 9, "binary": 0}
        document = self._doc(_scan_payload(states=("confirmed",), skipped=skipped, scanned_files=7))
        self.assertEqual(document["counts"]["scanned_files"], _count(7, "measured"))
        self.assertEqual(document["counts"]["coverage_gap"], _count(3, "measured"))
        self.assertEqual(document["coverage_gap_reasons"], {"symlink": 2, "unreadable": 1})
        self.assertTrue(set(document["coverage_gap_reasons"]) <= COVERAGE_AFFECTING_SKIPS)

    def test_scanner_projection_marks_and_hypotheses_unavailable(self):
        document = self._doc(_scan_payload(states=("candidate",)))
        self.assertEqual(document["counts"]["hypotheses"], _count(None, "unavailable"))
        empty = self._doc(_scan_payload(states=()))
        self.assertEqual(empty["counts"]["signals"], _count(0, "legacy_projection"))
        chain = empty["compression_chain"]
        self.assertEqual(
            chain["candidates_to_deterministic"],
            {"numerator": 0, "denominator": 0, "ratio_basis_points": None},
        )
        self.assertEqual(
            chain["deterministic_to_confirmed"],
            {"numerator": 0, "denominator": 0, "ratio_basis_points": None},
        )


class TestProjectionE2E(_IP0029ReportTestCase):
    """AC-1 / FR-01: e2e-source projection (raw only) and payload fingerprint."""

    def test_e2e_projection_raw_only_and_fingerprint_recomputable(self):
        payload = _e2e_payload(tp=3, fp=4)
        document = self._doc(payload)
        chain = document["compression_chain"]
        self.assertEqual(chain["raw_candidates"], 7)
        self.assertIsNone(chain["deterministic_alerts"])
        self.assertIsNone(chain["confirmed"])
        self.assertIsNone(chain["inconclusive"])
        self.assertEqual(
            chain["candidates_to_deterministic"],
            {"numerator": None, "denominator": None, "ratio_basis_points": None},
        )
        self.assertEqual(
            chain["deterministic_to_confirmed"],
            {"numerator": None, "denominator": None, "ratio_basis_points": None},
        )
        for key in (
            "signals",
            "security_issues",
            "hypotheses",
            "confirmed",
            "inconclusive",
            "scanned_files",
            "coverage_gap",
        ):
            self.assertEqual(document["counts"][key], _count(None, "unavailable"), key)
        self.assertEqual(document["coverage_gap_reasons"], {})
        self.assertEqual(
            document["sources"],
            [{"kind": "e2e", "payload_sha256": _payload_digest(payload)}],
        )


class TestProjectionRealWorld(_IP0029ReportTestCase):
    """AC-1 / FR-01: real-world projection sums and the I3 anti-confusion."""

    def test_realworld_projection_and_v2_anticonfusion(self):
        cases = [
            _rw_case(files_v=5, files_f=6, total_v=8, total_f=9, skipped_v={"symlink": 2}),
            _rw_case(
                files_v=3,
                files_f=4,
                total_v=1,
                total_f=2,
                skipped_v={"unreadable": 1, "non-utf8": 0},
            ),
        ]
        payload = _rw_payload(cases)
        document = self._doc(payload)
        self.assertEqual(document["counts"]["scanned_files"], _count(18, "measured"))
        self.assertEqual(document["counts"]["coverage_gap"], _count(3, "measured"))
        self.assertEqual(document["coverage_gap_reasons"], {"symlink": 2, "unreadable": 1})
        chain = document["compression_chain"]
        self.assertEqual(chain["raw_candidates"], 20)
        self.assertIsNone(chain["deterministic_alerts"])
        self.assertIsNone(chain["confirmed"])
        self.assertIsNone(chain["inconclusive"])
        for key in ("signals", "security_issues", "hypotheses", "confirmed", "inconclusive"):
            self.assertEqual(document["counts"][key], _count(None, "unavailable"), key)
        # I3 anti-confusion: the payload's own schema_version == 2 is its output
        # schema version, never evidence of a v2 evidence domain.
        self.assertEqual(payload["schema_version"], 2)
        self.assertEqual(document["evidence_domain"], "legacy")
        self.assertTrue(document["legacy_projection"])
        self.assertEqual(
            document["sources"],
            [{"kind": "real-world", "payload_sha256": _payload_digest(payload)}],
        )


class TestLegacyProjectionMarking(_IP0029ReportTestCase):
    """AC-1 / FR-02: two-layer marking, null-not-zero, synthetic bundle."""

    def test_legacy_absent_marks_and_null_not_zero(self):
        document = self._doc(_scan_payload(states=("confirmed",)))
        self.assertTrue(document["legacy_projection"])
        self.assertEqual(document["evidence_domain"], "legacy")
        self.assertEqual(document["declarations"], ["baseline_mode_legacy_report_parameters_inert"])
        self.assertIsNone(document["counts"]["hypotheses"]["value"])
        self.assertNotEqual(document["counts"]["hypotheses"]["value"], 0)
        self.assertEqual(
            document["resources"],
            {"prompt_tokens": None, "completion_tokens": None, "cost_micro_usd": None},
        )
        e2e = self._doc(_e2e_payload())
        self.assertTrue(e2e["legacy_projection"])
        for key in ("signals", "security_issues", "hypotheses"):
            self.assertIsNone(e2e["counts"][key]["value"], key)
            self.assertNotEqual(e2e["counts"][key]["value"], 0)

    def test_synthetic_bundle_measured_and_no_static_promotion(self):
        bundle = _synthetic_bundle()
        payload = _scan_payload(states=("candidate", "corroborated"))
        document = self._doc(payload, bundle=bundle)
        self.assertEqual(document["evidence_domain"], "v2")
        self.assertFalse(document["legacy_projection"])
        self.assertEqual(document["counts"]["signals"], _count(1, "measured"))
        self.assertEqual(document["counts"]["security_issues"], _count(1, "measured"))
        self.assertEqual(document["counts"]["hypotheses"], _count(1, "measured"))
        # Anti-fabrication: the bundle carries one statically_supported
        # hypothesis, which must never be promoted into the runtime ladder.
        self.assertEqual(document["counts"]["confirmed"], _count(0, "legacy_projection"))
        self.assertEqual(document["counts"]["inconclusive"], _count(1, "legacy_projection"))
        self.assertEqual(
            document["sources"],
            [
                {"kind": "evidence-domain", "payload_sha256": _payload_digest(bundle.to_dict())},
                {"kind": "scanner", "payload_sha256": _scanner_payload_digest(payload)},
            ],
        )


class TestCompressionRatios(_IP0029ReportTestCase):
    """AC-1 / FR-01: integer basis-point floor arithmetic, null-not-zero."""

    def test_ratio_basis_points_floor_arithmetic(self):
        states = ("confirmed",) + ("corroborated",) * 2 + ("candidate",) * 4
        chain = self._doc(_scan_payload(states=states))["compression_chain"]
        self.assertEqual(chain["raw_candidates"], 7)
        self.assertEqual(chain["deterministic_alerts"], 3)
        self.assertEqual(chain["confirmed"], 1)
        self.assertEqual(chain["inconclusive"], 4)
        # Hand-computed floor arithmetic: 3 * 10000 // 7 == 4285, 1 * 10000 // 3 == 3333.
        self.assertEqual(
            chain["candidates_to_deterministic"],
            {"numerator": 3, "denominator": 7, "ratio_basis_points": 4285},
        )
        self.assertEqual(
            chain["deterministic_to_confirmed"],
            {"numerator": 1, "denominator": 3, "ratio_basis_points": 3333},
        )

    def test_ratio_null_not_zero_and_subset_invariants(self):
        empty = self._doc(_scan_payload(states=()))["compression_chain"]
        for link in ("candidates_to_deterministic", "deterministic_to_confirmed"):
            self.assertIsNone(empty[link]["ratio_basis_points"], link)
            self.assertNotEqual(empty[link]["ratio_basis_points"], 0)
        e2e = self._doc(_e2e_payload())["compression_chain"]
        for link in ("candidates_to_deterministic", "deterministic_to_confirmed"):
            self.assertIsNone(e2e[link]["ratio_basis_points"], link)
        states = ("confirmed",) + ("corroborated",) * 2 + ("syntax-verified",) * 4
        chain = self._doc(_scan_payload(states=states))["compression_chain"]
        self.assertLessEqual(chain["deterministic_alerts"], chain["raw_candidates"])
        self.assertLessEqual(chain["confirmed"], chain["deterministic_alerts"])
        self.assertLessEqual(chain["inconclusive"], chain["raw_candidates"])
        self.assertEqual(
            chain["raw_candidates"], chain["deterministic_alerts"] + chain["inconclusive"]
        )


class TestExpertAndAutomationFace(_IP0029ReportTestCase):
    """AC-3 / FR-03: expert active time, sessions, digests, automation, resources."""

    def test_expert_face_sum_sessions_digests(self):
        alice = hashlib.sha256(b"alice-fixture").hexdigest()
        bob = hashlib.sha256(b"bob-fixture").hexdigest()
        sidecars = (
            _sidecar(reviewer_digest=bob, active_ms=7),
            _sidecar(reviewer_digest=alice, active_ms=5),
            _sidecar(reviewer_digest=bob, active_ms=9),
        )
        document = self._build(_scan_payload(states=("candidate",)), sidecars=sidecars)
        self.assertEqual(
            document.to_canonical_value()["expert"],
            {"active_time_ms_total": 21, "sessions": 3, "reviewer_digests": [alice, bob]},
        )
        data = document.canonical_bytes()
        self.assertNotIn(b"alice", data)
        self.assertNotIn(b"bob", data)

    def test_zero_sidecar_active_time_null(self):
        document = self._build(_scan_payload(states=("candidate",)))
        self.assertEqual(
            document.to_canonical_value()["expert"],
            {"active_time_ms_total": None, "sessions": 0, "reviewer_digests": []},
        )

    def test_automation_passthrough_and_resources_null(self):
        summary = self._fixture_summary(sufficient=True)
        document = self._build(_scan_payload(), digest=_DIGEST_A, sufficient=True)
        self.assertEqual(document.to_canonical_value()["aggregate_status"], "sufficient_sample")
        self.assertEqual(
            document.to_canonical_value()["automation"],
            {
                "cold_p50_wall_time_ms": summary.aggregate.cold_p50_wall_time_ms,
                "cold_p95_wall_time_ms": summary.aggregate.cold_p95_wall_time_ms,
                "warm_p50_wall_time_ms": summary.aggregate.warm_p50_wall_time_ms,
                "warm_p95_wall_time_ms": summary.aggregate.warm_p95_wall_time_ms,
            },
        )
        self.assertIsNotNone(summary.aggregate.cold_p50_wall_time_ms)
        insufficient = self._build(_scan_payload(), sufficient=False)
        value = insufficient.to_canonical_value()
        self.assertEqual(value["aggregate_status"], "insufficient_sample")
        self.assertEqual(
            value["automation"],
            {
                "cold_p50_wall_time_ms": None,
                "cold_p95_wall_time_ms": None,
                "warm_p50_wall_time_ms": None,
                "warm_p95_wall_time_ms": None,
            },
        )
        self.assertEqual(
            value["resources"],
            {"prompt_tokens": None, "completion_tokens": None, "cost_micro_usd": None},
        )
        self.assertEqual(value["attempt_count"], 1)


class TestContentBoundary(_IP0029ReportTestCase):
    """AC-2 / FR-04: digest-and-hash-only bytes reject paths, code, credentials."""

    def test_report_bytes_exclude_paths_fragments_credentials(self):
        payload = _e2e_payload(name="AKIA-fixture-access-key", reviewer="def f(): pass reviewer")
        payload["case_results"] = [
            {"path": "C:\\Users\\fixture\\secret-module.py", "token": "sk-live-1"}
        ]
        document = self._build(payload)
        data = document.canonical_bytes()
        for fragment in (b"C:", b"Users", b"secret-module", b"AKIA", b"sk-live", b"def f", b"pass"):
            self.assertNotIn(fragment, data, fragment)
        self.assertNotIn(b"\\", data)
        self.assertNotIn(b"/", data)
        self.assertIsNone(re.search(rb"[A-Za-z]:", data))
        scan = _scan_payload(states=("confirmed",))
        scan.report.collaboration["notes"] = "C:\\host\\path AKIA-sk-live-credential"
        scan.report.files_reviewed.append("C:\\Users\\fixture\\leak.py")
        scan_data = self._build(scan).canonical_bytes()
        for fragment in (b"AKIA", b"sk-live", b"host", b"leak"):
            self.assertNotIn(fragment, scan_data, fragment)
        self.assertNotIn(b"\\", scan_data)
        self.assertNotIn(b"/", scan_data)


class TestReportWriter(_IP0029ReportTestCase):
    """FR-04: report artifact naming, exclusive write, resequencing, errors."""

    def test_writer_naming_payload_and_resequence(self):
        document = self._build(_scan_payload(states=("candidate",)))
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            (output / ("a" * 16 + "-run-1.json")).write_bytes(b"{}")
            first = report.write_report_file(document, output)
            self.assertEqual(first.report_path.name, "a" * 16 + "-report-1.json")
            on_disk = first.report_path.read_bytes()
            self.assertEqual(on_disk, document.canonical_bytes())
            self.assertEqual(first.report_sha256, hashlib.sha256(on_disk).hexdigest())
            self.assertEqual(first.report_sha256, document.content_digest())
            second = report.write_report_file(document, output)
            self.assertEqual(second.report_path.name, "a" * 16 + "-report-2.json")
            self.assertEqual(
                sorted(path.name for path in output.iterdir()),
                [
                    "a" * 16 + "-report-1.json",
                    "a" * 16 + "-report-2.json",
                    "a" * 16 + "-run-1.json",
                ],
            )
            self.assertEqual(first.report_path.read_bytes(), on_disk)
            self.assertNotIn(str(first.report_path).encode("utf-8"), document.canonical_bytes())
            self.assertNotIn(str(output).encode("utf-8"), document.canonical_bytes())

    def test_writer_directory_and_collision_errors(self):
        document = self._build(_scan_payload(states=("candidate",)))
        with tempfile.TemporaryDirectory() as directory:
            output = pathlib.Path(directory)
            sentinel = output / ("a" * 16 + "-report-1.json")
            sentinel.write_bytes(b"sentinel")
            with self.assertRaises(collect.BaselineCollectionError) as ctx:
                report.write_report_file(document, output)
            self.assertEqual(
                ctx.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_PATH_ALREADY_EXISTS,
            )
            self.assertEqual(sentinel.read_bytes(), b"sentinel")
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(collect.BaselineCollectionError) as ctx:
                report.write_report_file(document, pathlib.Path(directory) / "missing")
            self.assertEqual(
                ctx.exception.code,
                collect.BaselineCollectionErrorCode.OUTPUT_DIRECTORY_UNAVAILABLE,
            )


class TestFindRunArtifacts(unittest.TestCase):
    """AC-3 / FR-05: discovery contract anchored to real run_repeats output."""

    @staticmethod
    def _load_manifest():
        path = _REPO_ROOT / _MANIFEST_RELATIVE_PATH
        if not path.is_file():
            raise AssertionError(f"required frozen manifest artifact is missing: {path}")
        with path.open("rb") as handle:
            return json.loads(handle.read().decode("utf-8"))

    @staticmethod
    def _spec_mapping(manifest):
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
            "analyzer_fingerprint": _NOMINAL_ANALYZER_FINGERPRINT,
            "config_digest": _NOMINAL_CONFIG_DIGEST,
            "seed": _NOMINAL_SEED,
            "machine_profile": dict(_NOMINAL_MACHINE_PROFILE),
        }

    def _produce(self, directory):
        manifest = self._load_manifest()
        summary = orchestrate.run_repeats(
            self._spec_mapping(manifest),
            manifest,
            _CountingExecute(),
            directory,
            repeat=1,
            sources=_stub_sources([7], [9]),
        )
        return summary, manifest

    def test_discovery_after_real_run_repeats(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, _ = self._produce(directory)
            prefix = summary.aggregate.run_spec_digest[:16]
            entries = report.find_run_artifacts(directory)
            self.assertEqual([entry.sequence for entry in entries], [1, 2, 3])
            self.assertEqual([entry.digest16 for entry in entries], [prefix] * 3)
            self.assertEqual([entry.sample_count for entry in entries], [1, 1, 2])
            self.assertEqual([entry.is_aggregate for entry in entries], [False, False, True])
            self.assertEqual(
                list(entries), sorted(entries, key=lambda entry: (entry.digest16, entry.sequence))
            )
            for entry in entries:
                self.assertIsNone(entry.sidecar_path)
                self.assertTrue(entry.result_path.is_file())
            parsed = json.loads(entries[-1].result_path.read_bytes().decode("utf-8"))
            indices = [sample["attempt_index"] for sample in parsed["samples"]]
            self.assertEqual(indices, [0, 1])
            aggregate_bytes = entries[-1].result_path.read_bytes()
            self.assertEqual(
                hashlib.sha256(aggregate_bytes).hexdigest(), summary.aggregate_sha256
            )

    def test_sidecar_pairing_via_real_attempt(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = self._load_manifest()
            session = expert_timing.ExpertTimingSession("alice-fixture")
            session.start(1_000_000_000)
            session.finish(1_010_000_000)
            run.run_baseline_attempt(
                self._spec_mapping(manifest),
                manifest,
                _CountingExecute(),
                directory,
                attempt_index=0,
                mode="cold",
                sources=_stub_sources([5], []),
                expert_session=session,
            )
            entries = report.find_run_artifacts(directory)
            self.assertEqual(len(entries), 1)
            entry = entries[0]
            self.assertEqual(entry.sample_count, 1)
            self.assertFalse(entry.is_aggregate)
            self.assertIsNotNone(entry.sidecar_path)
            self.assertTrue(entry.sidecar_path.is_file())
            self.assertEqual(
                entry.sidecar_path.name,
                entry.result_path.stem + ".expert-timing.json",
            )

    def test_foreign_ignored_prefix_filter_and_orphan(self):
        with tempfile.TemporaryDirectory() as directory:
            summary, _ = self._produce(directory)
            prefix = summary.aggregate.run_spec_digest[:16]
            foreign = [
                "notes.txt",
                "aaaa-run-1.json",
                prefix + "-run-1.txt",
                "ABCDEF0123456789-run-2.json",
                prefix + "-run-99.expert-timing.json",
            ]
            for name in foreign:
                (pathlib.Path(directory) / name).write_bytes(b"anything")
            entries = report.find_run_artifacts(directory)
            self.assertEqual([entry.sequence for entry in entries], [1, 2, 3])
            self.assertEqual(report.find_run_artifacts(directory, prefix=prefix), entries)
            self.assertEqual(report.find_run_artifacts(directory, prefix="f" * 16), ())

    def test_corrupted_result_and_sidecar_fail_closed(self):
        valid_result = result_from_mapping(_result_mapping(_DIGEST_A, [_sample(0, "cold", 100)]))
        with tempfile.TemporaryDirectory() as directory:
            self._produce(directory)
            (pathlib.Path(directory) / ("c" * 16 + "-run-1.json")).write_bytes(b"not-json")
            with self.assertRaises(report.BaselineReportError) as ctx:
                report.find_run_artifacts(directory)
            self.assertEqual(ctx.exception.code, report.BaselineReportErrorCode.ARTIFACT_UNREADABLE)
            self.assertEqual(ctx.exception.field_path, "$.artifact")
        with tempfile.TemporaryDirectory() as directory:
            self._produce(directory)
            (pathlib.Path(directory) / ("c" * 16 + "-run-1.json")).write_text(
                '{"schema_version": 1}', encoding="utf-8"
            )
            with self.assertRaises(report.BaselineReportError) as ctx:
                report.find_run_artifacts(directory)
            self.assertEqual(ctx.exception.code, report.BaselineReportErrorCode.ARTIFACT_UNREADABLE)
        with tempfile.TemporaryDirectory() as directory:
            self._produce(directory)
            (pathlib.Path(directory) / ("d" * 16 + "-run-1.json")).write_bytes(
                valid_result.canonical_bytes()
            )
            (pathlib.Path(directory) / ("d" * 16 + "-run-1.expert-timing.json")).write_text(
                '{"schema_version": 2}', encoding="utf-8"
            )
            with self.assertRaises(report.BaselineReportError) as ctx:
                report.find_run_artifacts(directory)
            self.assertEqual(ctx.exception.code, report.BaselineReportErrorCode.ARTIFACT_UNREADABLE)
            self.assertEqual(str(ctx.exception), _FROZEN_ERROR_MESSAGES["ARTIFACT_UNREADABLE"])


class TestFailClosedNegatives(_IP0029ReportTestCase):
    """AC-1 / AC-4: malformed-injection matrix with stable typed codes."""

    def test_payload_none_and_unrecognized_shapes(self):
        repair_like = {"schema_version": 1, "name": "repair", "repair_summary": {}}
        wrong_version = {
            "schema_version": 3,
            "mode": "deterministic",
            "scanner_profile": "fast-ast",
            "metrics": {},
            "results": [],
        }
        missing_profile = {
            "schema_version": 2,
            "mode": "deterministic",
            "metrics": {},
            "results": [],
        }
        str_tp = _e2e_payload()
        str_tp["metrics"]["tp"] = "3"
        missing_case_results = _e2e_payload()
        del missing_case_results["case_results"]
        bad_workspace = _rw_payload([_rw_case()])
        bad_workspace["results"][0]["deterministic"]["workspace"]["vulnerable"]["files"] = "5"
        for label, payload in (
            ("none", None),
            ("repair-like", repair_like),
            ("schema-3", wrong_version),
            ("missing-profile", missing_profile),
            ("str-tp", str_tp),
            ("missing-case-results", missing_case_results),
            ("bad-workspace", bad_workspace),
            ("bare-object", object()),
            ("int", 42),
        ):
            with self.subTest(label=label):
                self._assert_typed_error(
                    "EVALUATOR_PAYLOAD_UNRECOGNIZED",
                    "$.evaluator_payload",
                    lambda payload=payload: self._build(payload),
                )

    def test_malformed_payload_matrix(self):
        missing_scanned = _scan_payload(states=("candidate",))
        del missing_scanned.report.collaboration["scanned_files"]
        str_scanned = _scan_payload(states=("candidate",))
        str_scanned.report.collaboration["scanned_files"] = "7"
        str_skip = _scan_payload(states=("candidate",), skipped={"symlink": 2})
        str_skip.report.collaboration["skipped"]["symlink"] = "2"
        alien_finding = _scan_payload(states=("candidate",))
        alien_finding.report.findings.append("not-a-finding")
        null_collaboration = _scan_payload(states=("candidate",))
        null_collaboration.report.collaboration = None
        for label, payload in (
            ("missing-scanned-files", missing_scanned),
            ("str-scanned-files", str_scanned),
            ("str-skip-count", str_skip),
            ("alien-finding", alien_finding),
            ("null-collaboration", null_collaboration),
        ):
            with self.subTest(label=label):
                self._assert_typed_error(
                    "EVALUATOR_PAYLOAD_INVALID",
                    "$.evaluator_payload",
                    lambda payload=payload: self._build(payload),
                )

    def test_sidecar_and_summary_digest_negatives(self):
        extra_key = _sidecar()
        extra_key["extra"] = 1
        missing_events = _sidecar()
        del missing_events["events"]
        str_active = _sidecar()
        str_active["active_time_ms"] = "5"
        for label, sidecar in (
            ("digest-mismatch", _sidecar(digest=_DIGEST_B)),
            ("extra-key", extra_key),
            ("missing-events", missing_events),
            ("str-active-time", str_active),
        ):
            with self.subTest(label=label):
                with self.assertRaises(report.BaselineReportError) as ctx:
                    self._build(_scan_payload(), sidecars=(sidecar,))
                self.assertEqual(ctx.exception.code, report.BaselineReportErrorCode.SIDECAR_INVALID)
                self.assertTrue(ctx.exception.field_path.startswith("$.expert_sidecars[0]"))
                self.assertEqual(str(ctx.exception), _FROZEN_ERROR_MESSAGES["SIDECAR_INVALID"])
        mismatched = dataclasses.replace(self._fixture_summary(), aggregate_sha256=_DIGEST_B)
        self._assert_typed_error(
            "DIGEST_MISMATCH",
            "$.aggregate_sha256",
            lambda: report.build_baseline_report(mismatched, _scan_payload()),
        )
        self._assert_typed_error(
            "INVALID_FIELD_TYPE",
            "$.summary",
            lambda: report.build_baseline_report({"not": "a summary"}, _scan_payload()),
        )
        self._assert_typed_error(
            "INVALID_FIELD_TYPE",
            "$.bundle",
            lambda: self._build(_scan_payload(states=("candidate",)), bundle=object()),
        )


class TestHygieneAndSurface(unittest.TestCase):
    """AC-4 / FR-07 / FR-08: imports, offline tokens, zero manifest, declarations."""

    @staticmethod
    def _report_source():
        path = _REPO_ROOT / "benchmarks" / "v4" / "baseline" / "report.py"
        if not path.is_file():
            raise AssertionError(f"required product source is missing: {path}")
        return path.read_text(encoding="utf-8")

    def _assert_import_allowed(self, module_name):
        root = module_name.split(".")[0]
        if root in ("lima", "benchmarks"):
            allowed = any(
                module_name == candidate or module_name.startswith(candidate + ".")
                for candidate in _ALLOWED_PRODUCT_IMPORTS
            )
        else:
            allowed = root in _ALLOWED_STDLIB_IMPORTS
        self.assertTrue(allowed, f"import {module_name!r} is outside the frozen whitelist")

    def test_import_whitelist_and_offline_tokens(self):
        source = self._report_source()
        for node in ast.walk(ast.parse(source)):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    self._assert_import_allowed(alias.name)
            elif isinstance(node, ast.ImportFrom):
                self.assertEqual(node.level, 0, "relative imports are not allowed")
                self._assert_import_allowed(node.module or "")
        sources = [source, pathlib.Path(__file__).read_text(encoding="utf-8")]
        for token in _forbidden_source_tokens():
            with self.subTest(token=token):
                for candidate in sources:
                    self.assertNotIn(token, candidate)

    def test_zero_manifest_consumption_and_declarations_closed(self):
        source = self._report_source()
        manifest_tokens = (
            "baseline" + "_manifest",
            "validate_" + "baseline_manifest",
            "evaluation" + "_data",
        )
        for token in manifest_tokens:
            with self.subTest(token=token):
                self.assertNotIn(token, source)
        summary = _IP0029ReportTestCase._fixture_summary()
        document = report.build_baseline_report(summary, _scan_payload(states=("candidate",)))
        value = document.to_canonical_value()
        self.assertEqual(value["declarations"], ["baseline_mode_legacy_report_parameters_inert"])
        self.assertEqual(
            report.BASELINE_REPORT_DECLARATIONS,
            ("baseline_mode_legacy_report_parameters_inert",),
        )


if __name__ == "__main__":
    unittest.main()
