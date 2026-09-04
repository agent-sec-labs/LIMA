"""Strict data contracts for the C/C++ LLM multi-agent detection layer."""

import dataclasses
import unittest

from lima.cxx_agent_models import (
    CXX_AGENT_VERIFICATION_STATES,
    ContextReference,
    CxxAgentCandidate,
    CxxAgentCoverage,
    CxxAgentDecision,
    parse_untrusted_json,
    to_agent_finding_payload,
)


class CxxAgentCandidateContractTests(unittest.TestCase):
    def test_valid_candidate_is_immutable_and_derives_identity(self):
        candidate = CxxAgentCandidate.from_untrusted_json(
            {
                "cwe": "CWE-416",
                "path": "src/session.cpp",
                "line": 128,
                "symbol": "Session::close",
                "title": "对象释放后仍可能被回调访问",
                "mechanism": "callback retains an alias after owner deletion",
                "trigger_path": ["register_callback", "Session::close", "on_event"],
                "confidence": 0.78,
            }
        )
        self.assertEqual("CWE-416", candidate.cwe)
        self.assertEqual("llm-candidate", candidate.verification_state)
        self.assertTrue(candidate.candidate_id.startswith("sha256-"))
        self.assertEqual(64, len(candidate.candidate_id) - len("sha256-"))
        with self.assertRaises(dataclasses.FrozenInstanceError):
            candidate.cwe = "CWE-787"

    def test_candidate_identity_is_stable_across_construction(self):
        payload = {
            "cwe": "CWE-415",
            "path": "src/free.c",
            "line": 12,
            "symbol": "release",
            "title": "t",
            "mechanism": "m",
            "trigger_path": ["a", "b"],
            "confidence": 0.5,
        }
        first = CxxAgentCandidate.from_untrusted_json(payload)
        second = CxxAgentCandidate.from_untrusted_json(payload)
        self.assertEqual(first.candidate_id, second.candidate_id)
        different = CxxAgentCandidate.from_untrusted_json({**payload, "line": 13})
        self.assertNotEqual(first.candidate_id, different.candidate_id)

    def test_candidate_rejects_unknown_fields_and_values(self):
        base = {
            "cwe": "CWE-787",
            "path": "src/buf.c",
            "line": 7,
            "symbol": "write_value",
            "title": "t",
            "mechanism": "m",
            "trigger_path": ["a"],
            "confidence": 0.6,
        }
        for name, mutation in (
            ("unknown CWE", {"cwe": "CWE-79"}),
            ("absolute path", {"path": "/etc/passwd"}),
            ("parent path", {"path": "../escape.c"}),
            ("zero line", {"line": 0}),
            ("negative line", {"line": -3}),
            ("empty symbol", {"symbol": ""}),
            ("empty title", {"title": ""}),
            ("empty mechanism", {"mechanism": ""}),
            ("empty trigger path", {"trigger_path": []}),
            ("oversized trigger path", {"trigger_path": [f"s{i}" for i in range(33)]}),
            ("trigger step with parent", {"trigger_path": ["a", "../x"]}),
            ("confidence below zero", {"confidence": -0.1}),
            ("confidence above one", {"confidence": 1.5}),
            ("unknown field", {"unexpected": True}),
            ("candidate_id injection", {"candidate_id": "sha256-" + "f" * 64}),
            ("verification state injection", {"verification_state": "confirmed"}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    CxxAgentCandidate.from_untrusted_json({**base, **mutation})

    def test_candidate_bounds_text_lengths(self):
        base = {
            "cwe": "CWE-787",
            "path": "src/buf.c",
            "line": 7,
            "symbol": "write_value",
            "title": "t",
            "mechanism": "m",
            "trigger_path": ["a"],
            "confidence": 0.6,
        }
        for name, mutation in (
            ("oversized title", {"title": "x" * 3000}),
            ("oversized mechanism", {"mechanism": "x" * 3000}),
            ("oversized symbol", {"symbol": "x" * 3000}),
            ("oversized path", {"path": "src/" + "x" * 4200 + ".c"}),
            ("non-string trigger step", {"trigger_path": [7]}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    CxxAgentCandidate.from_untrusted_json({**base, **mutation})


class ContextReferenceContractTests(unittest.TestCase):
    def test_reference_binds_verified_snapshot_bytes(self):
        reference = ContextReference.from_untrusted_json(
            {
                "path": "src/session.cpp",
                "start_line": 100,
                "end_line": 140,
                "content_sha256": "a" * 64,
            }
        )
        self.assertEqual("src/session.cpp", reference.path)
        self.assertEqual(100, reference.start_line)
        self.assertEqual(140, reference.end_line)

    def test_reference_rejects_invalid_ranges_and_digests(self):
        base = {
            "path": "src/session.cpp",
            "start_line": 100,
            "end_line": 140,
            "content_sha256": "a" * 64,
        }
        for name, mutation in (
            ("reversed range", {"end_line": 99}),
            ("zero start", {"start_line": 0}),
            ("absolute path", {"path": "/x"}),
            ("short digest", {"content_sha256": "a" * 63}),
            ("non-hex digest", {"content_sha256": "z" * 64}),
            ("unknown field", {"extra": 1}),
            ("oversized range", {"end_line": 100 + 5000}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    ContextReference.from_untrusted_json({**base, **mutation})


class CxxAgentDecisionContractTests(unittest.TestCase):
    def test_accept_decision_lists_verification_state(self):
        decision = CxxAgentDecision.from_untrusted_json(
            {
                "decision": "accept",
                "verification_state": "agent-corroborated",
                "rationale": "two specialists agree on mechanism and trigger path",
                "corroborating_agent_roles": ["memory-lifetime", "bounds"],
            }
        )
        self.assertEqual("accept", decision.decision)
        self.assertEqual("agent-corroborated", decision.verification_state)

    def test_reject_decision_needs_reason(self):
        decision = CxxAgentDecision.from_untrusted_json(
            {
                "decision": "reject",
                "verification_state": "needs-human-review",
                "rationale": "evidence conflicts",
                "corroborating_agent_roles": [],
            }
        )
        self.assertEqual("reject", decision.decision)

    def test_decision_rejects_unknown_values_and_fields(self):
        base = {
            "decision": "accept",
            "verification_state": "agent-corroborated",
            "rationale": "r",
            "corroborating_agent_roles": [],
        }
        for name, mutation in (
            ("unknown decision", {"decision": "maybe"}),
            ("unknown verification state", {"verification_state": "definitely"}),
            ("empty rationale", {"rationale": ""}),
            ("unknown role", {"corroborating_agent_roles": ["intruder"]}),
            ("unknown field", {"nope": 1}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    CxxAgentDecision.from_untrusted_json({**base, **mutation})

    def test_verification_state_domain_is_closed(self):
        self.assertEqual(
            {
                "llm-candidate",
                "agent-corroborated",
                "tool-corroborated",
                "runtime-confirmed",
                "human-confirmed",
                "needs-human-review",
            },
            CXX_AGENT_VERIFICATION_STATES,
        )


class CxxAgentCoverageContractTests(unittest.TestCase):
    def test_coverage_reports_gaps_honestly(self):
        coverage = CxxAgentCoverage.from_untrusted_json(
            {
                "indexed_files": 80,
                "indexed_symbols": 240,
                "candidates_generated": 12,
                "candidates_budget_exhausted": False,
                "context_files_used": 8,
                "context_lines_sent": 950,
                "unparsed_regions": ["src/legacy/macro-heavy.c"],
                "llm_unavailable": False,
            }
        )
        self.assertEqual(80, coverage.indexed_files)
        self.assertEqual(1, len(coverage.unparsed_regions))

    def test_coverage_rejects_negative_and_unknown_fields(self):
        base = {
            "indexed_files": 1,
            "indexed_symbols": 1,
            "candidates_generated": 1,
            "candidates_budget_exhausted": False,
            "context_files_used": 1,
            "context_lines_sent": 1,
            "unparsed_regions": [],
            "llm_unavailable": False,
        }
        for name, mutation in (
            ("negative files", {"indexed_files": -1}),
            ("bool as int", {"indexed_files": True}),
            ("unknown field", {"mystery": 1}),
            ("oversized region", {"unparsed_regions": ["x" * 5000]}),
            ("non-string region", {"unparsed_regions": [5]}),
        ):
            with self.subTest(name=name):
                with self.assertRaises(ValueError):
                    CxxAgentCoverage.from_untrusted_json({**base, **mutation})


class UntrustedJsonBoundaryTests(unittest.TestCase):
    def test_valid_document_parses(self):
        self.assertEqual({"a": [1, 2]}, parse_untrusted_json('{"a": [1, 2]}'))

    def test_duplicate_keys_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_untrusted_json('{"a": 1, "a": 2}')

    def test_non_finite_numbers_are_rejected(self):
        for literal in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(literal=literal), self.assertRaises(ValueError):
                parse_untrusted_json(f'{{"a": {literal}}}')

    def test_non_utf8_bytes_are_rejected(self):
        with self.assertRaises(ValueError):
            parse_untrusted_json(b'{"a": "' + bytes([0xff]) + b'"}')

    def test_non_text_input_is_rejected(self):
        with self.assertRaises(ValueError):
            parse_untrusted_json(123)

    def test_broken_json_is_rejected(self):
        for raw in ("{", "[]]", '"unterminated'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_untrusted_json(raw)

    def test_confidence_overflow_is_a_value_error(self):
        with self.assertRaises(ValueError):
            CxxAgentCandidate.from_untrusted_json(
                {
                    "cwe": "CWE-787",
                    "path": "src/b.c",
                    "line": 1,
                    "symbol": "s",
                    "title": "t",
                    "mechanism": "m",
                    "trigger_path": ["a"],
                    "confidence": 10**400,
                }
            )

    def test_trigger_steps_reject_path_syntax(self):
        bad_steps = ["a" + chr(92) + "b", "a" + chr(10) + "b", "a/b", "../x"]
        for step in bad_steps:
            with self.subTest(step=repr(step)), self.assertRaises(ValueError):
                CxxAgentCandidate.from_untrusted_json(
                    {
                        "cwe": "CWE-787",
                        "path": "src/b.c",
                        "line": 1,
                        "symbol": "s",
                        "title": "t",
                        "mechanism": "m",
                        "trigger_path": [step],
                        "confidence": 0.5,
                    }
                )


class FindingPayloadTests(unittest.TestCase):
    def test_payload_constructs_a_finding_with_agent_fields(self):
        candidate = CxxAgentCandidate.from_untrusted_json(
            {
                "cwe": "CWE-416",
                "path": "src/session.cpp",
                "line": 128,
                "symbol": "Session::close",
                "title": "t",
                "mechanism": "m",
                "trigger_path": ["a", "b"],
                "confidence": 0.7,
            }
        )
        payload = to_agent_finding_payload(candidate)
        from lima.models import Finding

        finding = Finding(**payload)
        rendered = finding.to_dict()
        self.assertEqual("high", rendered["severity"])
        self.assertEqual("llm-agent", rendered["analysis_mode"])
        self.assertIs(False, rendered["automatic_repair"])


if __name__ == "__main__":
    unittest.main()
