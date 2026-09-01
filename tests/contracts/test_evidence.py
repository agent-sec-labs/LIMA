"""Evidence domain contract tests: enums, SourceLocation, domain objects, and bundle."""

import dataclasses
import hashlib
import unittest
from pathlib import Path

from lima.contracts.codec import canonical_decode, canonical_encode, compute_content_digest
from lima.contracts.common import SchemaVersion
from lima.contracts.errors import ContractError, ContractErrorCode
from lima.contracts.evidence import (
    EVIDENCE_DOMAIN_SCHEMA_NAME,
    EvidenceDomainBundle,
    EvidenceLevel,
    EvidencePolarity,
    EvidenceRecord,
    EvidenceSubjectKind,
    HypothesisStatus,
    RequiredProofKind,
    SecurityIssue,
    Signal,
    SourceLocation,
    VulnerabilityHypothesis,
)

VERSION_4_0 = SchemaVersion(4, 0)
VERSION_4_2 = SchemaVersion(4, 2)


def _location_wire(**overrides):
    wire = {
        "path": "src/example.py",
        "start_line": 10,
        "end_line": 10,
        "start_column": 5,
        "end_column": 18,
        "symbol": "run_command",
    }
    wire.update(overrides)
    return wire


def _cli_location_wire(**overrides):
    wire = _location_wire(
        path="src/cli.py",
        start_line=20,
        end_line=20,
        start_column=1,
        end_column=24,
        symbol="main",
    )
    wire.update(overrides)
    return wire


def _signal_wire(**overrides):
    wire = {
        "signal_id": "signal-0001",
        "fingerprint": "1" * 64,
        "rule_id": "B602",
        "analysis_family": "sast",
        "evidence_kind": "tool-observation",
        "location": _location_wire(),
        "evidence_ids": ["evidence-signal-0001"],
        "reason_codes": ["RULE_MATCH_PROCESS_EXECUTION"],
        "cwe_ids": ["CWE-78"],
    }
    wire.update(overrides)
    return wire


def _issue_wire(**overrides):
    wire = {
        "issue_id": "issue-0001",
        "identity_digest": "2" * 64,
        "root_cause_class": "command-injection",
        "sink_identity": "python.subprocess.shell",
        "trust_boundary": "cli-to-process",
        "primary_location": _location_wire(),
        "signal_ids": ["signal-0001"],
        "evidence_ids": ["evidence-issue-0001"],
        "reason_codes": ["ROOT_CAUSE_CLUSTERED_BY_SINK"],
        "cwe_ids": ["CWE-78"],
    }
    wire.update(overrides)
    return wire


def _hypothesis_wire(**overrides):
    wire = {
        "hypothesis_id": "hypothesis-0001",
        "issue_id": "issue-0001",
        "status": "statically_supported",
        "claim": "Untrusted CLI input may reach a process execution sink.",
        "security_invariant": "Process arguments must not be interpreted by a shell.",
        "required_proof_kind": "runtime_behavior",
        "capability_requirements": ["python", "subprocess-observer"],
        "target_location": _location_wire(),
        "source_locations": [_cli_location_wire()],
        "critical_path": [
            _cli_location_wire(),
            _location_wire(),
        ],
        "trigger_conditions": ["attacker controls the CLI argument"],
        "input_constraints": ["argument contains shell metacharacters"],
        "evidence_ids": ["evidence-hypothesis-0001"],
        "reason_codes": ["STATIC_DATAFLOW_REACHES_PROCESS_SINK"],
        "cwe_ids": ["CWE-78"],
    }
    wire.update(overrides)
    return wire


def _evidence_wire(**overrides):
    wire = {
        "evidence_id": "evidence-signal-0001",
        "subject_kind": "signal",
        "subject_id": "signal-0001",
        "level": "D0",
        "polarity": "supports",
        "analysis_family": "sast",
        "producer": "bandit-1.9.4",
        "independence_key": "bandit:B602:src/example.py:10",
        "summary": "Bandit reported process execution with shell semantics.",
        "source_artifact_ids": ["tool-run-0001"],
        "reason_codes": ["RULE_MATCH"],
        "location": _location_wire(),
        "depends_on_evidence_ids": [],
    }
    wire.update(overrides)
    return wire


def _evidence_wire_for(name, **overrides):
    templates = {
        "evidence-hypothesis-0001": {
            "evidence_id": "evidence-hypothesis-0001",
            "subject_kind": "vulnerability_hypothesis",
            "subject_id": "hypothesis-0001",
            "level": "D2",
            "analysis_family": "static-dataflow",
            "producer": "lima-python-dataflow",
            "independence_key": "python-dataflow:cli-to-process",
            "summary": "A deterministic source-to-sink path reaches process execution.",
            "reason_codes": ["SOURCE_TO_SINK_PATH"],
            "depends_on_evidence_ids": ["evidence-issue-0001"],
        },
        "evidence-issue-0001": {
            "evidence_id": "evidence-issue-0001",
            "subject_kind": "security_issue",
            "subject_id": "issue-0001",
            "level": "D1",
            "analysis_family": "contextual-analysis",
            "producer": "lima-audit",
            "independence_key": "cluster:command-injection:cli-to-process",
            "summary": "The matched sink is in a CLI trust boundary.",
            "reason_codes": ["CONTEXT_APPLICABLE"],
            "depends_on_evidence_ids": ["evidence-signal-0001"],
        },
        "evidence-signal-0001": {
            "evidence_id": "evidence-signal-0001",
            "subject_kind": "signal",
            "subject_id": "signal-0001",
            "level": "D0",
            "analysis_family": "sast",
            "producer": "bandit-1.9.4",
            "independence_key": "bandit:B602:src/example.py:10",
            "summary": "Bandit reported process execution with shell semantics.",
            "reason_codes": ["RULE_MATCH"],
            "depends_on_evidence_ids": [],
        },
    }
    wire = _evidence_wire(**templates[name])
    wire.update(overrides)
    return wire


def _bundle_wire(**overrides):
    wire = {
        "signals": [_signal_wire()],
        "security_issues": [_issue_wire()],
        "vulnerability_hypotheses": [_hypothesis_wire()],
        "evidence": [
            _evidence_wire_for("evidence-hypothesis-0001"),
            _evidence_wire_for("evidence-issue-0001"),
            _evidence_wire_for("evidence-signal-0001"),
        ],
    }
    wire.update(overrides)
    return wire


FIXTURE = Path(__file__).resolve().parent / "fixtures" / "evidence_domain_bundle_v4_golden.json"
GOLDEN_PAYLOAD_DIGEST = "1b313f8ce082fd1721805c4eb6d232e104dabaa9e427f9a3f4699659b3796c51"

_FORBIDDEN_KEY_SUBSTRINGS = ("confidence", "severity", "is_vulnerable", "verified", "snippet")
_FORBIDDEN_KEY_EXACT = {"clear"}


def _all_keys(node):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _all_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from _all_keys(item)


class EvidenceEnumTests(unittest.TestCase):
    def test_wire_values_are_exact(self):
        self.assertEqual(EVIDENCE_DOMAIN_SCHEMA_NAME, "lima.evidence-domain")
        self.assertEqual(
            {member.value for member in EvidenceLevel}, {"D0", "D1", "D2", "D3", "D4"}
        )
        self.assertEqual(
            {member.value for member in EvidencePolarity}, {"supports", "refutes"}
        )
        self.assertEqual(
            {member.value for member in EvidenceSubjectKind},
            {"signal", "security_issue", "vulnerability_hypothesis"},
        )
        self.assertEqual(
            {member.value for member in HypothesisStatus},
            {
                "proposed",
                "statically_supported",
                "statically_refuted",
                "conflicting_static_evidence",
                "insufficient_static_evidence",
            },
        )
        self.assertEqual(
            {member.value for member in RequiredProofKind},
            {
                "runtime_behavior",
                "static_property",
                "configuration_state",
                "external_manual_required",
            },
        )


class SourceLocationTests(unittest.TestCase):
    def _from_wire(self, wire, version=VERSION_4_0):
        return SourceLocation.from_dict(wire, schema_version=version)

    def _assert_rejected(self, wire, code, version=VERSION_4_0):
        with self.assertRaises(ContractError) as ctx:
            self._from_wire(wire, version)
        self.assertIs(ctx.exception.code, code)
        return ctx.exception

    def test_valid_location_round_trip(self):
        location = self._from_wire(_location_wire())
        self.assertEqual(location.path, "src/example.py")
        self.assertEqual(location.start_line, 10)
        self.assertEqual(location.end_line, 10)
        self.assertEqual(location.start_column, 5)
        self.assertEqual(location.end_column, 18)
        self.assertEqual(location.symbol, "run_command")
        self.assertEqual(location.to_dict(), _location_wire())

        unknown = _location_wire(start_column=None, end_column=None, symbol=None)
        location = self._from_wire(unknown)
        self.assertIsNone(location.start_column)
        self.assertIsNone(location.end_column)
        self.assertIsNone(location.symbol)
        self.assertEqual(location.to_dict(), unknown)

        direct = SourceLocation(path="src/cli.py", start_line=20, end_line=24)
        self.assertIsNone(direct.start_column)
        self.assertEqual(
            direct.to_dict(),
            {
                "path": "src/cli.py",
                "start_line": 20,
                "end_line": 24,
                "start_column": None,
                "end_column": None,
                "symbol": None,
            },
        )
        self.assertEqual(
            self._from_wire(direct.to_dict()).to_dict(), direct.to_dict()
        )
        self.assertEqual(
            self._from_wire(_location_wire(path="src/文件.py")).path, "src/文件.py"
        )
        self.assertEqual(
            self._from_wire(_location_wire(path="src/my file.py")).path,
            "src/my file.py",
        )

    def test_rejects_absolute_parent_backslash_empty_and_control_paths(self):
        cases = [
            "/abs/path.py",
            "src/../lib/x.py",
            "src/./x.py",
            "..",
            ".",
            "src\\x.py",
            "C:/x.py",
            "c:x.py",
            "//server/share/x.py",
            "src//x.py",
            "src/",
            "",
            "src/x\x01y.py",
            "src/\x00x.py",
            "src/\ty.py",
        ]
        for path in cases:
            with self.subTest(path=repr(path)):
                self._assert_rejected(
                    _location_wire(path=path), ContractErrorCode.INVALID_FIELD_VALUE
                )
        oversize = "a" * 1025
        exception = self._assert_rejected(
            _location_wire(path=oversize), ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED
        )
        self.assertEqual(exception.field_path, "$.path")
        self.assertIn("path", exception.field_path)
        self.assertNotIn(oversize, str(exception))
        self.assertNotIn(oversize, exception.to_dict()["message"])
        self.assertIsNotNone(self._from_wire(_location_wire(path="a" * 1024)))
        self.assertIsNotNone(self._from_wire(_location_wire(path="a.py")))

    def test_rejects_bool_zero_negative_and_reversed_ranges(self):
        type_cases = [True, False, "10", 10.0, None]
        value_cases = [0, -1, 2147483648]
        for value in type_cases:
            with self.subTest(start_line=repr(value)):
                self._assert_rejected(
                    _location_wire(start_line=value), ContractErrorCode.INVALID_FIELD_TYPE
                )
        for value in value_cases:
            with self.subTest(start_line=repr(value)):
                self._assert_rejected(
                    _location_wire(start_line=value), ContractErrorCode.INVALID_FIELD_VALUE
                )
        self._assert_rejected(
            _location_wire(end_line=2147483648), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(end_line=9), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(start_line=11, end_line=10),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertIsNotNone(self._from_wire(_location_wire(start_line=1)))
        self.assertIsNotNone(
            self._from_wire(_location_wire(end_line=2147483647))
        )

    def test_requires_column_pair_and_valid_symbol(self):
        self._assert_rejected(
            _location_wire(end_column=None), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(start_column=None), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(start_column=19), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(start_column=True), ContractErrorCode.INVALID_FIELD_TYPE
        )
        self._assert_rejected(
            _location_wire(end_column=0), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self.assertIsNotNone(
            self._from_wire(_location_wire(start_line=1, end_line=2, start_column=9, end_column=5))
        )
        self._assert_rejected(
            _location_wire(symbol=""), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(symbol=" run_command"), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(symbol="run_command "), ContractErrorCode.INVALID_FIELD_VALUE
        )
        self._assert_rejected(
            _location_wire(symbol="s" * 513), ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED
        )
        self._assert_rejected(
            _location_wire(symbol=7), ContractErrorCode.INVALID_FIELD_TYPE
        )
        self.assertIsNotNone(self._from_wire(_location_wire(symbol="s" * 512)))
        self.assertIsNotNone(self._from_wire(_location_wire(symbol="run command")))

    def test_future_minor_preserves_extensions_and_current_minor_rejects_them(self):
        future_wire = _location_wire(ref_commit="9c4f1a2b")
        location = self._from_wire(future_wire, version=VERSION_4_2)
        self.assertEqual(location.extensions, {"ref_commit": "9c4f1a2b"})
        self.assertEqual(location.to_dict(), future_wire)
        again = SourceLocation.from_dict(location.to_dict(), schema_version=VERSION_4_2)
        self.assertEqual(again, location)
        self.assertEqual(again.extensions, {"ref_commit": "9c4f1a2b"})

        self._assert_rejected(
            _location_wire(ref_commit="9c4f1a2b"), ContractErrorCode.UNKNOWN_FIELD
        )
        composed_key = "ref\u00e9"
        decomposed_key = "refe\u0301"
        with self.assertRaises(ContractError) as ctx:
            SourceLocation.from_dict(
                dict(_location_wire(), **{decomposed_key: 1, composed_key: 2}),
                schema_version=VERSION_4_2,
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.DUPLICATE_SEMANTIC_FIELD)
        with self.assertRaises(ContractError) as ctx:
            SourceLocation.from_dict(
                dict(_location_wire(), **{"\ud800": 1}), schema_version=VERSION_4_2
            )
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_UTF8)


class EvidenceObjectTests(unittest.TestCase):
    def _assert_rejected(self, wire, code, cls, version=VERSION_4_0):
        with self.assertRaises(ContractError) as ctx:
            cls.from_dict(wire, schema_version=version)
        self.assertIs(ctx.exception.code, code)
        return ctx.exception

    def test_signal_round_trip_has_exact_wire_shape(self):
        wire = _signal_wire()
        signal = Signal.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(signal.to_dict(), wire)
        self.assertIsInstance(signal.location, SourceLocation)
        self.assertEqual(
            Signal.from_dict(signal.to_dict(), schema_version=VERSION_4_0), signal
        )
        self.assertEqual(
            Signal.from_dict(signal.to_dict(), schema_version=VERSION_4_0).to_dict(),
            wire,
        )
        empty_cwe = _signal_wire(cwe_ids=[])
        self.assertEqual(
            Signal.from_dict(empty_cwe, schema_version=VERSION_4_0).to_dict(), empty_cwe
        )
        with self.assertRaises(dataclasses.FrozenInstanceError):
            signal.rule_id = "B603"

    def test_security_issue_round_trip_has_exact_wire_shape(self):
        wire = _issue_wire()
        issue = SecurityIssue.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(issue.to_dict(), wire)
        self.assertIsInstance(issue.primary_location, SourceLocation)
        self.assertEqual(
            SecurityIssue.from_dict(issue.to_dict(), schema_version=VERSION_4_0), issue
        )
        self.assertEqual(
            SecurityIssue.from_dict(issue.to_dict(), schema_version=VERSION_4_0).to_dict(),
            wire,
        )

    def test_vulnerability_hypothesis_round_trip_has_exact_wire_shape(self):
        wire = _hypothesis_wire()
        hypothesis = VulnerabilityHypothesis.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(hypothesis.to_dict(), wire)
        self.assertIsInstance(hypothesis.target_location, SourceLocation)
        self.assertIsInstance(hypothesis.source_locations, tuple)
        self.assertIsInstance(hypothesis.critical_path, tuple)
        self.assertEqual(
            len(hypothesis.critical_path), 2, "critical_path must preserve order"
        )
        self.assertEqual(hypothesis.critical_path[0].path, "src/cli.py")
        self.assertEqual(hypothesis.critical_path[1].path, "src/example.py")
        self.assertEqual(
            VulnerabilityHypothesis.from_dict(
                hypothesis.to_dict(), schema_version=VERSION_4_0
            ),
            hypothesis,
        )
        self.assertEqual(
            VulnerabilityHypothesis.from_dict(
                hypothesis.to_dict(), schema_version=VERSION_4_0
            ).to_dict(),
            wire,
        )

    def test_evidence_record_round_trip_has_exact_wire_shape(self):
        wire = _evidence_wire()
        record = EvidenceRecord.from_dict(wire, schema_version=VERSION_4_0)
        self.assertEqual(record.to_dict(), wire)
        self.assertIsInstance(record.location, SourceLocation)
        self.assertIs(record.subject_kind, EvidenceSubjectKind.SIGNAL)
        self.assertIs(record.level, EvidenceLevel.D0)
        self.assertIs(record.polarity, EvidencePolarity.SUPPORTS)
        self.assertEqual(
            EvidenceRecord.from_dict(record.to_dict(), schema_version=VERSION_4_0),
            record,
        )
        null_location = _evidence_wire(location=None)
        record = EvidenceRecord.from_dict(null_location, schema_version=VERSION_4_0)
        self.assertIsNone(record.location)
        self.assertEqual(record.to_dict(), null_location)

    def test_rejects_missing_required_fields(self):
        cases = [
            (_signal_wire(), Signal),
            (_issue_wire(), SecurityIssue),
            (_hypothesis_wire(), VulnerabilityHypothesis),
            (_evidence_wire(), EvidenceRecord),
        ]
        for wire, cls in cases:
            for key in list(wire):
                with self.subTest(object=cls.__name__, missing=key):
                    broken = dict(wire)
                    del broken[key]
                    self._assert_rejected(
                        broken, ContractErrorCode.REQUIRED_FIELD_MISSING, cls
                    )

    def test_rejects_unknown_enum_and_wrong_field_type(self):
        self._assert_rejected(
            _evidence_wire(subject_kind="feature"),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(level="D9"),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(level="d2"),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(polarity="neutral"),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _hypothesis_wire(status="verified"),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(required_proof_kind="llm_opinion"),
            ContractErrorCode.UNKNOWN_ENUM_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _signal_wire(fingerprint=123),
            ContractErrorCode.INVALID_FIELD_TYPE,
            Signal,
        )
        self._assert_rejected(
            _evidence_wire(summary=[]),
            ContractErrorCode.INVALID_FIELD_TYPE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _hypothesis_wire(target_location="src/example.py"),
            ContractErrorCode.INVALID_FIELD_TYPE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _signal_wire(location=None),
            ContractErrorCode.INVALID_FIELD_TYPE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(location=42),
            ContractErrorCode.INVALID_FIELD_TYPE,
            Signal,
        )
        self._assert_rejected(
            _evidence_wire(location=42),
            ContractErrorCode.INVALID_FIELD_TYPE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _signal_wire(evidence_ids="evidence-signal-0001"),
            ContractErrorCode.INVALID_FIELD_TYPE,
            Signal,
        )

    def test_rejects_invalid_digest_identifier_rule_cwe_and_reason_code(self):
        self._assert_rejected(
            _signal_wire(fingerprint="X" * 64),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(fingerprint="1" * 63),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(fingerprint="1" * 65),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _issue_wire(identity_digest="g" * 64),
            ContractErrorCode.INVALID_FIELD_VALUE,
            SecurityIssue,
        )
        self._assert_rejected(
            _signal_wire(signal_id="../escape"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(analysis_family=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _evidence_wire(producer="producer with spaces"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _signal_wire(evidence_kind="kind!"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(rule_id="B 602"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(rule_id=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(rule_id="B" + "6" * 256),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self.assertIsNotNone(
            Signal.from_dict(
                _signal_wire(rule_id="semgrep/rule.v1:x"), schema_version=VERSION_4_0
            )
        )
        for cwe in ("cwe-78", "78", "CWE-0", "CWE-078 ", "", "CWE-", "CWE-0x78"):
            with self.subTest(cwe=repr(cwe)):
                self._assert_rejected(
                    _signal_wire(cwe_ids=[cwe]),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    Signal,
                )
        for reason in ("lower_case", "", "1STARTS_WITH_DIGIT", "A" + "B" * 64):
            with self.subTest(reason=repr(reason)):
                self._assert_rejected(
                    _evidence_wire(reason_codes=[reason]),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                    EvidenceRecord,
                )
        self._assert_rejected(
            _signal_wire(cwe_ids=["CWE-78", "CWE-78"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )

    def test_rejects_control_oversize_and_noncanonical_text(self):
        self._assert_rejected(
            _evidence_wire(summary="danger\x00ahead"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(summary=" leading space"),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(summary="trailing space "),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(summary="x" * 4097),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            EvidenceRecord,
        )
        self.assertIsNotNone(
            EvidenceRecord.from_dict(
                _evidence_wire(summary="x" * 4096), schema_version=VERSION_4_0
            )
        )
        self._assert_rejected(
            _evidence_wire(summary=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(independence_key="k" * 513),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            EvidenceRecord,
        )
        self.assertIsNotNone(
            EvidenceRecord.from_dict(
                _evidence_wire(independence_key="k" * 512), schema_version=VERSION_4_0
            )
        )
        self._assert_rejected(
            _hypothesis_wire(claim=""),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(claim=" "),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(security_invariant="i" * 4097),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(trigger_conditions=["bad\x01condition"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(input_constraints=[" padded "]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(trigger_conditions=["x" * 4097]),
            ContractErrorCode.MAX_STRING_LENGTH_EXCEEDED,
            VulnerabilityHypothesis,
        )
        decomposed = "Bandit reported proce\u0301ss execution."
        record = EvidenceRecord.from_dict(
            _evidence_wire(summary=decomposed), schema_version=VERSION_4_0
        )
        self.assertEqual(record.summary, "Bandit reported procéss execution.")

    def test_rejects_unsorted_duplicate_and_oversize_set_arrays(self):
        self._assert_rejected(
            _signal_wire(evidence_ids=["evidence-b", "evidence-a"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(evidence_ids=["evidence-a", "evidence-a"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(evidence_ids=[]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(
                evidence_ids=["evidence-0000", "evidence-0000"]
                + [f"evidence-{i:04d}" for i in range(1, 1023)]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _signal_wire(evidence_ids=[f"evidence-{i:04d}" for i in range(1025)]),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            Signal,
        )
        self.assertIsNotNone(
            Signal.from_dict(
                _signal_wire(evidence_ids=[f"evidence-{i:04d}" for i in range(1024)]),
                schema_version=VERSION_4_0,
            )
        )
        self._assert_rejected(
            _evidence_wire(source_artifact_ids=[]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(source_artifact_ids=["tool-b", "tool-a"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(source_artifact_ids=[f"tool-{i:02d}" for i in range(33)]),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            EvidenceRecord,
        )
        self.assertIsNotNone(
            EvidenceRecord.from_dict(
                _evidence_wire(source_artifact_ids=[f"tool-{i:02d}" for i in range(32)]),
                schema_version=VERSION_4_0,
            )
        )
        self._assert_rejected(
            _evidence_wire(reason_codes=[]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            EvidenceRecord,
        )
        self._assert_rejected(
            _evidence_wire(reason_codes=[f"CODE_{i:02d}" for i in range(65)]),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            EvidenceRecord,
        )
        self._assert_rejected(
            _signal_wire(cwe_ids=["CWE-78", "CWE-100"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            Signal,
        )
        self._assert_rejected(
            _evidence_wire(depends_on_evidence_ids=[f"evidence-{i:04d}" for i in range(65)]),
            ContractErrorCode.MAX_ARRAY_LENGTH_EXCEEDED,
            EvidenceRecord,
        )
        self.assertIsNotNone(
            EvidenceRecord.from_dict(
                _evidence_wire(depends_on_evidence_ids=[]), schema_version=VERSION_4_0
            )
        )
        self._assert_rejected(
            _hypothesis_wire(capability_requirements=["subprocess-observer", "python"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(capability_requirements=[]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(trigger_conditions=["zz condition", "aa condition"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _hypothesis_wire(input_constraints=["same constraint", "same constraint"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            VulnerabilityHypothesis,
        )
        self._assert_rejected(
            _issue_wire(signal_ids=["signal-b", "signal-a"]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            SecurityIssue,
        )
        self._assert_rejected(
            _issue_wire(signal_ids=[]),
            ContractErrorCode.INVALID_FIELD_VALUE,
            SecurityIssue,
        )
        reversed_path = _hypothesis_wire(
            critical_path=[
                _location_wire(),
                _cli_location_wire(),
            ]
        )
        hypothesis = VulnerabilityHypothesis.from_dict(
            reversed_path, schema_version=VERSION_4_0
        )
        self.assertEqual(hypothesis.critical_path[0].path, "src/example.py")

    def test_defensive_copy_prevents_post_construction_mutation(self):
        location = SourceLocation.from_dict(
            _location_wire(), schema_version=VERSION_4_0
        )
        evidence_ids = ["evidence-signal-0001"]
        cwe_ids = ["CWE-78"]
        extensions = {"meta": {"items": [1, 2]}}
        signal = Signal(
            signal_id="signal-0001",
            fingerprint="1" * 64,
            rule_id="B602",
            analysis_family="sast",
            evidence_kind="tool-observation",
            location=location,
            evidence_ids=evidence_ids,
            reason_codes=["RULE_MATCH_PROCESS_EXECUTION"],
            cwe_ids=cwe_ids,
            extensions=extensions,
        )
        before = signal.to_dict()
        location.extensions["hack"] = 1
        evidence_ids.append("evidence-other")
        cwe_ids.append("CWE-100")
        extensions["meta"]["items"].append(3)
        self.assertEqual(signal.to_dict(), before)
        self.assertEqual(signal.location.extensions, {})
        self.assertEqual(signal.evidence_ids, ("evidence-signal-0001",))
        rendered = signal.to_dict()
        rendered["evidence_ids"].append("evidence-x")
        rendered["location"]["path"] = "hacked.py"
        rendered["cwe_ids"].append("CWE-100")
        self.assertEqual(signal.to_dict(), before)

        record_location = SourceLocation.from_dict(
            _location_wire(), schema_version=VERSION_4_0
        )
        depends = []
        record_extensions = {"k": {"deep": [1]}}
        record = EvidenceRecord(
            evidence_id="evidence-signal-0001",
            subject_kind=EvidenceSubjectKind.SIGNAL,
            subject_id="signal-0001",
            level=EvidenceLevel.D0,
            polarity=EvidencePolarity.SUPPORTS,
            analysis_family="sast",
            producer="bandit-1.9.4",
            independence_key="bandit:B602:src/example.py:10",
            summary="Bandit reported process execution with shell semantics.",
            source_artifact_ids=["tool-run-0001"],
            reason_codes=["RULE_MATCH"],
            location=record_location,
            depends_on_evidence_ids=depends,
            extensions=record_extensions,
        )
        record_before = record.to_dict()
        record_location.extensions["hack"] = 1
        depends.append("evidence-x")
        record_extensions["k"]["deep"].append(2)
        self.assertEqual(record.to_dict(), record_before)
        self.assertEqual(record.depends_on_evidence_ids, ())

        source_locations = [
            SourceLocation.from_dict(
                _location_wire(path="src/cli.py"), schema_version=VERSION_4_0
            )
        ]
        hypothesis = VulnerabilityHypothesis(
            hypothesis_id="hypothesis-0001",
            issue_id="issue-0001",
            status=HypothesisStatus.STATICALLY_SUPPORTED,
            claim="Untrusted CLI input may reach a process execution sink.",
            security_invariant="Process arguments must not be interpreted by a shell.",
            required_proof_kind=RequiredProofKind.RUNTIME_BEHAVIOR,
            capability_requirements=["python"],
            target_location=location,
            source_locations=source_locations,
            critical_path=source_locations,
            trigger_conditions=["condition"],
            input_constraints=["constraint"],
            evidence_ids=["evidence-hypothesis-0001"],
            reason_codes=["STATIC_DATAFLOW_REACHES_PROCESS_SINK"],
        )
        hypothesis_before = hypothesis.to_dict()
        source_locations.append(
            SourceLocation.from_dict(
                _location_wire(path="src/other.py"), schema_version=VERSION_4_0
            )
        )
        self.assertEqual(hypothesis.to_dict(), hypothesis_before)
        self.assertEqual(len(hypothesis.source_locations), 1)
        self.assertEqual(len(hypothesis.critical_path), 1)


class EvidenceBundleTests(unittest.TestCase):
    def _decode(self, wire, version=VERSION_4_0):
        return EvidenceDomainBundle.from_dict(wire, schema_version=version)

    def _assert_rejected(self, wire, code, version=VERSION_4_0):
        with self.assertRaises(ContractError) as ctx:
            self._decode(wire, version)
        self.assertIs(ctx.exception.code, code)
        return ctx.exception

    def test_empty_bundle_round_trip_is_valid(self):
        empty = {
            "signals": [],
            "security_issues": [],
            "vulnerability_hypotheses": [],
            "evidence": [],
        }
        bundle = self._decode(empty)
        self.assertEqual(
            bundle.to_dict(),
            {"evidence": [], "security_issues": [], "signals": [], "vulnerability_hypotheses": []},
        )
        self.assertEqual(bundle.signals, ())
        direct = EvidenceDomainBundle(schema_version=VERSION_4_0)
        self.assertEqual(direct.to_dict()["signals"], [])
        for key in ("signals", "security_issues", "vulnerability_hypotheses", "evidence"):
            with self.subTest(missing=key):
                broken = dict(empty)
                del broken[key]
                self._assert_rejected(broken, ContractErrorCode.REQUIRED_FIELD_MISSING)
        self._assert_rejected(empty | {"extra": 1}, ContractErrorCode.UNKNOWN_FIELD)
        self._assert_rejected(
            empty | {"signals": "none"}, ContractErrorCode.INVALID_FIELD_TYPE
        )
        with self.assertRaises(ContractError) as ctx:
            EvidenceDomainBundle.from_dict([], schema_version=VERSION_4_0)
        self.assertIs(ctx.exception.code, ContractErrorCode.INVALID_FIELD_TYPE)

    def test_golden_bundle_round_trip_and_digest(self):
        raw = FIXTURE.read_bytes()
        self.assertEqual(len(raw), 3740)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        self.assertFalse(raw.endswith(b"\n"))
        self.assertEqual(hashlib.sha256(raw).hexdigest(), GOLDEN_PAYLOAD_DIGEST)
        payload = canonical_decode(raw)
        bundle = EvidenceDomainBundle.from_dict(payload, schema_version=VERSION_4_0)
        self.assertEqual(canonical_encode(bundle.to_dict()), raw)
        self.assertEqual(compute_content_digest(payload), GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(compute_content_digest(bundle.to_dict()), GOLDEN_PAYLOAD_DIGEST)
        self.assertEqual(
            EvidenceDomainBundle.from_dict(
                canonical_decode(canonical_encode(bundle.to_dict())),
                schema_version=VERSION_4_0,
            ),
            bundle,
        )
        self.assertEqual(len(bundle.signals), 1)
        self.assertEqual(len(bundle.security_issues), 1)
        self.assertEqual(len(bundle.vulnerability_hypotheses), 1)
        self.assertEqual(len(bundle.evidence), 3)

    def test_rejects_unsorted_top_level_arrays_and_duplicate_ids(self):
        signal_two = _signal_wire(
            signal_id="signal-0002",
            fingerprint="9" * 64,
            evidence_ids=["evidence-signal-0002"],
        )
        evidence_two = _evidence_wire_for(
            "evidence-signal-0001", evidence_id="evidence-signal-0002"
        )
        unsorted_signals = _bundle_wire(
            signals=[signal_two, _signal_wire()],
            evidence=[
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
                evidence_two,
            ],
        )
        self._assert_rejected(
            unsorted_signals, ContractErrorCode.INVALID_FIELD_VALUE
        )
        duplicate_signals = _bundle_wire(
            signals=[_signal_wire(), _signal_wire()],
            evidence=[
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
            ],
        )
        self._assert_rejected(duplicate_signals, ContractErrorCode.INVALID_FIELD_VALUE)
        unsorted_evidence = _bundle_wire(
            evidence=[
                _evidence_wire_for("evidence-signal-0001"),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-hypothesis-0001"),
            ]
        )
        self._assert_rejected(unsorted_evidence, ContractErrorCode.INVALID_FIELD_VALUE)
        self.assertIsNotNone(self._decode(_bundle_wire()))

    def test_rejects_cross_namespace_id_collision(self):
        collided = _bundle_wire(
            security_issues=[
                _issue_wire(evidence_ids=["evidence-issue-0001", "issue-0001"])
            ],
            evidence=[
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
                _evidence_wire_for(
                    "evidence-issue-0001",
                    evidence_id="issue-0001",
                    depends_on_evidence_ids=[],
                ),
            ],
        )
        self._assert_rejected(collided, ContractErrorCode.INVALID_FIELD_VALUE)

    def test_rejects_missing_and_mismatched_subject_binding(self):
        dangling = _bundle_wire(
            evidence=[
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001", subject_id="signal-404"),
            ]
        )
        self._assert_rejected(dangling, ContractErrorCode.INVALID_FIELD_VALUE)
        hidden = _bundle_wire(
            signals=[_signal_wire(evidence_ids=["evidence-issue-0001", "evidence-signal-0001"])]
        )
        self._assert_rejected(hidden, ContractErrorCode.INVALID_FIELD_VALUE)
        missing = _bundle_wire(
            signals=[_signal_wire(evidence_ids=["evidence-signal-0001", "evidence-404"])]
        )
        self._assert_rejected(missing, ContractErrorCode.INVALID_FIELD_VALUE)
        unbound = _bundle_wire(
            evidence=_bundle_wire()["evidence"][:2]
        )
        self._assert_rejected(unbound, ContractErrorCode.INVALID_FIELD_VALUE)

    def test_rejects_unknown_issue_signal_hypothesis_and_evidence_reference(self):
        self._assert_rejected(
            _bundle_wire(
                security_issues=[_issue_wire(signal_ids=["signal-0001", "signal-404"])]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _bundle_wire(
                vulnerability_hypotheses=[_hypothesis_wire(issue_id="issue-404")]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _bundle_wire(
                security_issues=[
                    _issue_wire(
                        signal_ids=["signal-0001"],
                        evidence_ids=["evidence-issue-0001", "evidence-404"],
                    )
                ]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )

    def test_rejects_evidence_self_dependency_cycle_and_higher_level_dependency(self):
        self._assert_rejected(
            _bundle_wire(
                evidence=[
                    _evidence_wire_for("evidence-hypothesis-0001"),
                    _evidence_wire_for("evidence-issue-0001"),
                    _evidence_wire_for(
                        "evidence-signal-0001",
                        depends_on_evidence_ids=["evidence-signal-0001"],
                    ),
                ]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _bundle_wire(
                evidence=[
                    _evidence_wire_for("evidence-hypothesis-0001"),
                    _evidence_wire_for("evidence-issue-0001"),
                    _evidence_wire_for(
                        "evidence-signal-0001",
                        depends_on_evidence_ids=["evidence-issue-0001"],
                    ),
                ]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _bundle_wire(
                evidence=[
                    _evidence_wire_for("evidence-hypothesis-0001"),
                    _evidence_wire_for("evidence-issue-0001"),
                    _evidence_wire_for(
                        "evidence-signal-0001",
                        depends_on_evidence_ids=["evidence-404"],
                    ),
                ]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        two_cycle = _bundle_wire(
            vulnerability_hypotheses=[
                _hypothesis_wire(
                    evidence_ids=["evidence-a", "evidence-b", "evidence-hypothesis-0001"]
                )
            ],
            evidence=[
                _evidence_wire_for(
                    "evidence-hypothesis-0001",
                    evidence_id="evidence-a",
                    reason_codes=["CYCLE_A"],
                    depends_on_evidence_ids=["evidence-b"],
                ),
                _evidence_wire_for(
                    "evidence-hypothesis-0001",
                    evidence_id="evidence-b",
                    reason_codes=["CYCLE_B"],
                    depends_on_evidence_ids=["evidence-a"],
                ),
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
            ],
        )
        self._assert_rejected(two_cycle, ContractErrorCode.INVALID_FIELD_VALUE)

    def test_allows_shared_dependency_and_correlated_independence_key(self):
        correlated = _bundle_wire(
            vulnerability_hypotheses=[
                _hypothesis_wire(
                    evidence_ids=["evidence-hypothesis-0001", "evidence-hypothesis-0002"]
                )
            ],
            evidence=[
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for(
                    "evidence-hypothesis-0001",
                    evidence_id="evidence-hypothesis-0002",
                    reason_codes=["INDEPENDENT_CONFIRMATION"],
                ),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
            ],
        )
        bundle = self._decode(correlated)
        self.assertEqual(len(bundle.evidence), 4)
        self.assertEqual(
            bundle.evidence[0].independence_key,
            bundle.evidence[1].independence_key,
        )
        self.assertEqual(
            bundle.evidence[0].depends_on_evidence_ids,
            bundle.evidence[1].depends_on_evidence_ids,
        )

    def test_rejects_hypothesis_cwe_outside_issue(self):
        self._assert_rejected(
            _bundle_wire(
                vulnerability_hypotheses=[_hypothesis_wire(cwe_ids=["CWE-89"])]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _bundle_wire(
                security_issues=[_issue_wire(cwe_ids=[])],
                vulnerability_hypotheses=[_hypothesis_wire(cwe_ids=["CWE-78"])],
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertIsNotNone(
            self._decode(
                _bundle_wire(
                    security_issues=[_issue_wire(cwe_ids=["CWE-78", "CWE-89"])],
                    vulnerability_hypotheses=[_hypothesis_wire(cwe_ids=["CWE-89"])],
                )
            )
        )

    def test_static_status_requires_matching_d2_polarity(self):
        self._assert_rejected(
            _bundle_wire(
                vulnerability_hypotheses=[
                    _hypothesis_wire(status="statically_refuted")
                ]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self._assert_rejected(
            _bundle_wire(
                vulnerability_hypotheses=[
                    _hypothesis_wire(status="conflicting_static_evidence")
                ]
            ),
            ContractErrorCode.INVALID_FIELD_VALUE,
        )
        self.assertIsNotNone(
            self._decode(
                _bundle_wire(
                    vulnerability_hypotheses=[
                        _hypothesis_wire(status="statically_supported")
                    ]
                )
            )
        )
        refuting = _bundle_wire(
            vulnerability_hypotheses=[_hypothesis_wire(status="statically_refuted")],
            evidence=[
                _evidence_wire_for(
                    "evidence-hypothesis-0001", polarity="refutes"
                ),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
            ],
        )
        self.assertIsNotNone(self._decode(refuting))

    def test_d0_d1_cannot_promote_static_status(self):
        for status in ("statically_supported", "statically_refuted"):
            with self.subTest(status=status):
                self._assert_rejected(
                    _bundle_wire(
                        vulnerability_hypotheses=[_hypothesis_wire(status=status)],
                        evidence=[
                            _evidence_wire_for("evidence-hypothesis-0001", level="D1"),
                            _evidence_wire_for("evidence-issue-0001"),
                            _evidence_wire_for("evidence-signal-0001"),
                        ],
                    ),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                )
        for status in ("proposed", "insufficient_static_evidence"):
            with self.subTest(status=status):
                self.assertIsNotNone(
                    self._decode(
                        _bundle_wire(
                            vulnerability_hypotheses=[_hypothesis_wire(status=status)],
                            evidence=[
                                _evidence_wire_for("evidence-hypothesis-0001", level="D1"),
                                _evidence_wire_for("evidence-issue-0001"),
                                _evidence_wire_for("evidence-signal-0001"),
                            ],
                        )
                    )
                )

    def test_rejects_d3_and_d4_in_audit_evidence_bundle(self):
        for level in ("D3", "D4"):
            with self.subTest(level=level):
                exception = self._assert_rejected(
                    _bundle_wire(
                        vulnerability_hypotheses=[_hypothesis_wire(status="proposed")],
                        evidence=[
                            _evidence_wire_for("evidence-hypothesis-0001", level=level),
                            _evidence_wire_for("evidence-issue-0001"),
                            _evidence_wire_for("evidence-signal-0001"),
                        ],
                    ),
                    ContractErrorCode.INVALID_FIELD_VALUE,
                )
                self.assertEqual(exception.field_path, "$.evidence[0].level")
        self.assertIsNotNone(
            EvidenceRecord.from_dict(
                _evidence_wire_for("evidence-hypothesis-0001", level="D3"),
                schema_version=VERSION_4_0,
            )
        )

    def test_preserves_conflicting_support_and_refutation(self):
        conflicting = _bundle_wire(
            vulnerability_hypotheses=[
                _hypothesis_wire(status="conflicting_static_evidence")
            ],
            evidence=[
                _evidence_wire_for("evidence-hypothesis-0001"),
                _evidence_wire_for(
                    "evidence-hypothesis-0001",
                    evidence_id="evidence-hypothesis-0002",
                    polarity="refutes",
                    reason_codes=["INDEPENDENT_REFUTATION"],
                ),
                _evidence_wire_for("evidence-issue-0001"),
                _evidence_wire_for("evidence-signal-0001"),
            ],
        )
        conflicting["vulnerability_hypotheses"][0]["evidence_ids"] = [
            "evidence-hypothesis-0001",
            "evidence-hypothesis-0002",
        ]
        bundle = self._decode(conflicting)
        self.assertIs(
            bundle.vulnerability_hypotheses[0].status,
            HypothesisStatus.CONFLICTING_STATIC_EVIDENCE,
        )
        self.assertEqual(len(bundle.evidence), 4)

    def test_future_minor_round_trips_unknown_fields_at_every_level(self):
        wire = _bundle_wire(
            analysis_stage="stage-1",
            signals=[
                dict(
                    _signal_wire(),
                    qualifier_rank=3,
                    location=dict(_location_wire(), ref_commit="9c4f1a2b"),
                )
            ],
            security_issues=[
                dict(
                    _issue_wire(),
                    cluster_hint="sink-group-7",
                    primary_location=dict(_location_wire(), ref_commit="9c4f1a2b"),
                )
            ],
            vulnerability_hypotheses=[
                dict(
                    _hypothesis_wire(),
                    priority_band="high",
                    target_location=dict(_location_wire(), ref_commit="9c4f1a2b"),
                )
            ],
            evidence=[
                dict(
                    _evidence_wire_for("evidence-hypothesis-0001"),
                    tool_version="1.9.4",
                    location=dict(_location_wire(), ref_commit="9c4f1a2b"),
                ),
                dict(
                    _evidence_wire_for("evidence-issue-0001"),
                    tool_version="1.9.4",
                    location=dict(_location_wire(), ref_commit="9c4f1a2b"),
                ),
                dict(
                    _evidence_wire_for("evidence-signal-0001"),
                    tool_version="1.9.4",
                    location=dict(_location_wire(), ref_commit="9c4f1a2b"),
                ),
            ],
        )
        bundle = EvidenceDomainBundle.from_dict(wire, schema_version=VERSION_4_2)
        self.assertEqual(bundle.extensions, {"analysis_stage": "stage-1"})
        self.assertEqual(bundle.signals[0].extensions, {"qualifier_rank": 3})
        self.assertEqual(bundle.signals[0].location.extensions, {"ref_commit": "9c4f1a2b"})
        self.assertEqual(bundle.security_issues[0].extensions, {"cluster_hint": "sink-group-7"})
        self.assertEqual(
            bundle.security_issues[0].primary_location.extensions, {"ref_commit": "9c4f1a2b"}
        )
        self.assertEqual(
            bundle.vulnerability_hypotheses[0].extensions, {"priority_band": "high"}
        )
        self.assertEqual(
            bundle.vulnerability_hypotheses[0].target_location.extensions,
            {"ref_commit": "9c4f1a2b"},
        )
        self.assertEqual(bundle.evidence[0].extensions, {"tool_version": "1.9.4"})
        self.assertEqual(
            bundle.evidence[0].location.extensions, {"ref_commit": "9c4f1a2b"}
        )
        self.assertEqual(bundle.to_dict(), wire)
        again = EvidenceDomainBundle.from_dict(bundle.to_dict(), schema_version=VERSION_4_2)
        self.assertEqual(again, bundle)

    def test_current_minor_rejects_unknown_fields_at_every_level(self):
        mutations = {
            "bundle": lambda w: w | {"extra": 1},
            "signal": lambda w: {**w, "signals": [dict(_signal_wire(), extra=1)]},
            "signal.location": lambda w: {
                **w,
                "signals": [dict(_signal_wire(), location=dict(_location_wire(), extra=1))],
            },
            "security_issue": lambda w: {
                **w,
                "security_issues": [dict(_issue_wire(), extra=1)],
            },
            "issue.primary_location": lambda w: {
                **w,
                "security_issues": [
                    dict(_issue_wire(), primary_location=dict(_location_wire(), extra=1))
                ],
            },
            "hypothesis": lambda w: {
                **w,
                "vulnerability_hypotheses": [dict(_hypothesis_wire(), extra=1)],
            },
            "hypothesis.target_location": lambda w: {
                **w,
                "vulnerability_hypotheses": [
                    dict(_hypothesis_wire(), target_location=dict(_location_wire(), extra=1))
                ],
            },
            "evidence": lambda w: {
                **w,
                "evidence": [dict(w["evidence"][0], extra=1)] + w["evidence"][1:],
            },
            "evidence.location": lambda w: {
                **w,
                "evidence": [
                    dict(w["evidence"][0], location=dict(_location_wire(), extra=1))
                ]
                + w["evidence"][1:],
            },
        }
        for name, mutate in mutations.items():
            with self.subTest(level=name):
                self._assert_rejected(
                    mutate(_bundle_wire()), ContractErrorCode.UNKNOWN_FIELD
                )

    def test_payload_has_no_confidence_severity_is_vulnerable_clear_or_verified_fields(self):
        payload = self._decode(_bundle_wire()).to_dict()
        self.assertEqual(
            set(payload), {"signals", "security_issues", "vulnerability_hypotheses", "evidence"}
        )
        golden_payload = canonical_decode(FIXTURE.read_bytes())
        for source in (payload, golden_payload):
            for key in _all_keys(source):
                lowered = key.lower()
                self.assertNotIn(lowered, _FORBIDDEN_KEY_EXACT, key)
                for token in _FORBIDDEN_KEY_SUBSTRINGS:
                    self.assertNotIn(token, lowered, key)


if __name__ == "__main__":
    unittest.main()
