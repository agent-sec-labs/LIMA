"""Frozen acceptance tests for IP-0043: human expert review entry (AC-3).

Contract under test (frozen by Coordinator Assignment CA-IP-0043-v1.0 of
2026-10-01 R4 and C1 Done 4 AC-3; the tenth-round ruling section 4 is carried
in intent):

- The Implementation deliverables are the logic module
  ``benchmarks/v4/baseline/expert_review.py`` plus the thin interactive CLI
  ``scripts/run_expert_review.py``.  The module reuses the frozen
  ``ExpertTimingSession`` unchanged: the five-key sidecar protocol
  (schema_version / run_spec_digest / reviewer_digest / active_time_ms /
  events), the digest-only reviewer identity, the event state machine and
  the monotonic clock guard are all the frozen faces; real humans drive
  start/pause/resume/finish with live ``time.perf_counter_ns()`` reads.
- The verdict vocabulary is a frozen closed set (agree / disagree /
  partially-agree / needs-more-evidence) with free-text notes; the verdict,
  the review-set digest, the source-binding triple, the coverage/unreviewed
  declaration, the reviewer digest, the active-time back reference, the
  event digest and the sidecar digest go into an independently versioned
  receipt (schema v1) that is separate from the sidecar.
- Typed fail-closed validation (own error family): an invalid review-set
  document, an illegal / non-monotonic / repeated / unterminated event
  sequence, an off-vocabulary verdict, a verdict whose sidecar is bound to a
  different review set (cross-review-set rejection), a reviewer-id/sidecar
  digest disagreement, a malformed receipt, and a duplicated event set or
  sidecar being bound to a second result (event uniqueness: no copying one
  sidecar onto many results to multiply recorded time) each terminate with
  their own code.
- Reviewer identity never persists raw: only the SHA-256 digest appears in
  any produced byte.  Synthetic (test) events are explicitly marked and
  isolated to temp directories; without human return the summary reports
  sessions=0 and unavailable active time honestly.

Everything here is offline and deterministic: timing events carry explicit
synthetic nanosecond stamps (no sleeping), receipts materialize into temp
directories only, and no test ever touches a network socket, reads the
environment, or records an event on behalf of a human.

Expected RED before implementation (product modules absent): eight methods
fail on the missing deliverables -- the module-absence anchor is
``ModuleNotFoundError: No module named 'benchmarks.v4.baseline.expert_review'``
(lazy per-test import) plus the missing CLI script; the frozen-sidecar guard
groups (built on ``expert_timing``/``collect``/codec) pass by design and are
recorded in the RED evidence.  The five old frozen test files stay untouched
and green.
"""

import ast
import hashlib
import importlib.util
import pathlib
import re
import tempfile
import unittest

from benchmarks.v4.baseline.collect import BaselineCollectionError
from benchmarks.v4.baseline.expert_timing import ExpertTimingSession

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_EXPERT_REVIEW_RELATIVE_PATH = "benchmarks/v4/baseline/expert_review.py"
_EXPERT_REVIEW_CLI_RELATIVE_PATH = "scripts/run_expert_review.py"

#: The frozen verdict vocabulary (R4: four values, closed).
_EXPERT_REVIEW_VERDICTS = frozenset(
    {"agree", "disagree", "partially-agree", "needs-more-evidence"}
)

#: The frozen review-set document key set (closed, schema v1).
_REVIEW_SET_KEYS = frozenset(
    {
        "schema_version",
        "review_set_id",
        "run_spec_digest",
        "aggregate_sha256",
        "findings_digest",
        "findings",
        "coverage",
        "unreviewed",
        "representative_result_sha256",
    }
)

#: The frozen receipt key set (closed, schema v1; separate from the sidecar).
_RECEIPT_KEYS = frozenset(
    {
        "schema_version",
        "synthetic",
        "verdict",
        "notes",
        "review_set_digest",
        "run_spec_digest",
        "aggregate_sha256",
        "findings_digest",
        "coverage",
        "unreviewed",
        "reviewer_digest",
        "active_time_ms",
        "events_digest",
        "sidecar_sha256",
    }
)

#: The frozen typed error family of the new module.
_EXPERT_REVIEW_ERROR_CODES = frozenset(
    {
        "REVIEW_SET_INVALID",
        "TIMING_SEQUENCE_INVALID",
        "VERDICT_VOCABULARY_INVALID",
        "VERDICT_REVIEW_SET_MISMATCH",
        "EVENT_DUPLICATE",
        "RECEIPT_INVALID",
    }
)

#: The frozen receipt file-name family (independently versioned).
_RECEIPT_NAME_SHAPE = re.compile(r"^expert-review-receipt-v1-\d{2}\.json$")

#: The frozen five-key sidecar protocol (expert_timing.py L129-142; guard).
_SIDECAR_KEYS = frozenset(
    {
        "schema_version",
        "run_spec_digest",
        "reviewer_digest",
        "active_time_ms",
        "events",
    }
)

_SECRET_KEY_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{16,}")
_HEX64_SHAPE = re.compile(r"^[0-9a-f]{64}$")

#: One legal synthetic event sequence with deliberately non-round timestamps
#: (integer millisecond division is part of the frozen contract).
_LEGAL_EVENTS = (
    {"event": "start", "time_ns": 100},
    {"event": "pause", "time_ns": 5_000_100},
    {"event": "resume", "time_ns": 9_000_200},
    {"event": "finish", "time_ns": 20_000_300},
)
_LEGAL_ACTIVE_MS = 16  # (5_000_100-100 + 20_000_300-9_000_200) // 1_000_000

#: A second, distinct legal sequence (active time 5 ms).
_ALT_EVENTS = (
    {"event": "start", "time_ns": 1_000},
    {"event": "finish", "time_ns": 5_500_000},
)
_ALT_ACTIVE_MS = 5

_REVIEWER_ID = "lima-synthetic-reviewer-0x5EED-face"


def _forbidden_network_roots():
    """First-level import roots these offline tests must never use."""
    return {"sock" + "et", "url" + "lib", "requ" + "ests", "http"}


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


def _independent_active_ms(events):
    """Recompute closed active intervals in whole ms, independent of any module."""
    total_ns = 0
    active_since = None
    for event in events:
        if event["event"] in ("start", "resume"):
            active_since = event["time_ns"]
        elif active_since is not None:
            total_ns += event["time_ns"] - active_since
            active_since = None
    return total_ns // 1_000_000


class _ExpertReviewTestCase(unittest.TestCase):
    """Shared arrange helpers (all new-module imports are lazy per test)."""

    def expert_review(self):
        import benchmarks.v4.baseline.expert_review as module

        return module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def sidecar_for(self, events, run_spec_digest, reviewer_id=_REVIEWER_ID):
        """(sidecar bytes, sidecar document) via the frozen timing session."""
        session = ExpertTimingSession(reviewer_id)
        for event in events:
            getattr(session, event["event"])(event["time_ns"])
        payload = session.sidecar_bytes(run_spec_digest)
        import json

        document = json.loads(payload.decode("utf-8"))
        return payload, document

    def review_set(self, **overrides):
        document = {
            "schema_version": 1,
            "review_set_id": "lima-lf-review-set-0001",
            "run_spec_digest": "a" * 64,
            "aggregate_sha256": "1" * 64,
            "findings_digest": "2" * 64,
            "findings": [
                {
                    "path": "src/llamafactory/extras.py",
                    "line": 10,
                    "cwe": "CWE-78",
                }
            ],
            "coverage": "representative-sample-predefined",
            "unreviewed": "remaining-findings-out-of-scope-of-this-session",
            "representative_result_sha256": "3" * 64,
        }
        document.update(overrides)
        return document

    def build_receipt(
        self,
        review_set,
        events=_LEGAL_EVENTS,
        verdict="agree",
        reviewer_id=_REVIEWER_ID,
        synthetic=False,
    ):
        module = self.expert_review()
        sidecar_bytes, _ = self.sidecar_for(
            events, review_set["run_spec_digest"], reviewer_id
        )
        return module.build_review_receipt(
            review_set=review_set,
            reviewer_id=reviewer_id,
            sidecar_bytes=sidecar_bytes,
            verdict=verdict,
            notes="synthetic test note",
            synthetic=synthetic,
        )

    def content_digest(self, value):
        from lima.contracts.codec import compute_content_digest

        return compute_content_digest(value)

    def receipt_paths(self, output_dir):
        return sorted(pathlib.Path(output_dir).glob("expert-review-receipt-*.json"))


class TestExpertReviewSurface(_ExpertReviewTestCase):
    """The module surface, the frozen vocabulary and the CLI entry."""

    def test_expert_review_surface_and_cli_entry(self):
        module = self.expert_review()
        # Frozen vocabulary and typed error family; each error member renders
        # its bare frozen wire value through ``__str__`` (the
        # B1SourceErrorCode precedent), never the ``Class.MEMBER`` spelling.
        self.assertEqual(
            set(module.EXPERT_REVIEW_VERDICTS), _EXPERT_REVIEW_VERDICTS
        )
        self.assertEqual(
            {str(code) for code in module.ExpertReviewErrorCode},
            _EXPERT_REVIEW_ERROR_CODES,
        )
        self.assertTrue(issubclass(module.ExpertReviewError, ValueError))
        for name in (
            "load_review_set",
            "validate_timing_events",
            "build_review_receipt",
            "write_review_receipt",
            "summarize_review_receipts",
        ):
            self.assertTrue(callable(getattr(module, name, None)), name)
        # The review-set loader accepts an honest schema-v1 document and
        # rejects each invalid face with its typed code.
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            good = parent / "review-set.json"
            from lima.contracts.codec import canonical_encode

            good.write_bytes(canonical_encode(self.review_set()))
            loaded = module.load_review_set(good)
            self.assertEqual(loaded, self.review_set())
            invalid = {
                "missing-key": self.review_set(),
                "bad-digest": self.review_set(run_spec_digest="not-hex"),
                "bad-version": self.review_set(schema_version=2),
                "bad-findings": self.review_set(findings={"not": "a list"}),
                "bad-coverage": self.review_set(coverage=""),
            }
            del invalid["missing-key"]["coverage"]
            for label, face in invalid.items():
                with self.subTest(face=label):
                    path = parent / f"invalid-{label}.json"
                    path.write_bytes(canonical_encode(face))
                    with self.assertRaises(module.ExpertReviewError) as caught:
                        module.load_review_set(path)
                    self.assertEqual(
                        str(caught.exception.code), "REVIEW_SET_INVALID"
                    )
        # The thin CLI entry exists and parses the frozen flag surface; the
        # verdict choices are wired to the frozen vocabulary.
        cli_path = _REPO_ROOT / _EXPERT_REVIEW_CLI_RELATIVE_PATH
        if not cli_path.is_file():
            self.fail(
                f"required CLI script is missing: {_EXPERT_REVIEW_CLI_RELATIVE_PATH}"
            )
        cli_source = cli_path.read_text(encoding="utf-8")
        for token in (
            "build_review_receipt",
            "ExpertTimingSession",
            "EXPERT_REVIEW_VERDICTS",
        ):
            self.assertIn(token, cli_source)
        spec = importlib.util.spec_from_file_location(
            "run_expert_review_cli", cli_path
        )
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as temporary:
            parsed = cli.build_parser().parse_args(
                [
                    "--review-set", str(pathlib.Path(temporary) / "set.json"),
                    "--reviewer-id", _REVIEWER_ID,
                    "--output-dir", str(pathlib.Path(temporary) / "receipts"),
                    "--verdict", "agree",
                    "--notes", "note",
                    "--synthetic",
                ]
            )
            self.assertEqual(parsed.verdict, "agree")
            self.assertTrue(parsed.synthetic)
        # Source hygiene (AC-5): module and CLI stay offline and secretless.
        for relative in (
            _EXPERT_REVIEW_RELATIVE_PATH,
            _EXPERT_REVIEW_CLI_RELATIVE_PATH,
        ):
            with self.subTest(source=relative):
                source = self.product_source(relative)
                self.assertEqual(
                    _import_roots(source) & _forbidden_network_roots(), set()
                )
                self.assertNotIn("environ", source)
                self.assertNotIn("getenv", source)
                self.assertIsNone(_SECRET_KEY_SHAPE.search(source))
        # PC1 self-scan (passes by design).
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))


class TestTimingSequences(_ExpertReviewTestCase):
    """Legal sequences pass with independent accounting; illegal ones fail."""

    def test_legal_event_sequence_with_independent_active_time(self):
        module = self.expert_review()
        # Guard group (frozen engine, passes by design): the frozen session
        # itself yields the same independent accounting.
        session = ExpertTimingSession(_REVIEWER_ID)
        for event in _LEGAL_EVENTS:
            getattr(session, event["event"])(event["time_ns"])
        self.assertEqual(session.active_time_ms(), _LEGAL_ACTIVE_MS)
        self.assertEqual(_independent_active_ms(_LEGAL_EVENTS), _LEGAL_ACTIVE_MS)
        # New-deliverable face: the validator accepts the legal sequence and
        # returns the independently recomputed whole milliseconds.
        self.assertEqual(
            module.validate_timing_events(list(_LEGAL_EVENTS)), _LEGAL_ACTIVE_MS
        )
        self.assertEqual(
            module.validate_timing_events(list(_ALT_EVENTS)), _ALT_ACTIVE_MS
        )
        # The receipt carries the same active-time back reference.
        receipt = self.build_receipt(self.review_set())
        self.assertIs(type(receipt["active_time_ms"]), int)
        self.assertEqual(receipt["active_time_ms"], _LEGAL_ACTIVE_MS)

    def test_illegal_nonmonotonic_unterminated_sequences_rejected(self):
        module = self.expert_review()
        faces = {
            "pause-from-idle": [{"event": "pause", "time_ns": 0}],
            "resume-from-idle": [{"event": "resume", "time_ns": 0}],
            "finish-from-idle": [{"event": "finish", "time_ns": 0}],
            "repeated-start": [
                {"event": "start", "time_ns": 0},
                {"event": "start", "time_ns": 5},
            ],
            "non-monotonic": [
                {"event": "start", "time_ns": 10},
                {"event": "pause", "time_ns": 5},
            ],
            "after-finish": [
                {"event": "start", "time_ns": 0},
                {"event": "finish", "time_ns": 5},
                {"event": "start", "time_ns": 6},
            ],
            "unterminated": [{"event": "start", "time_ns": 0}],
            "empty": [],
        }
        for label, events in sorted(faces.items()):
            with self.subTest(face=label):
                with self.assertRaises(module.ExpertReviewError) as caught:
                    module.validate_timing_events(list(events))
                self.assertEqual(
                    str(caught.exception.code), "TIMING_SEQUENCE_INVALID"
                )
        # Guard group (passes by design): the same faces are rejected by the
        # frozen engine itself -- the new validator never loosens them.
        for label, events in sorted(faces.items()):
            with self.subTest(face=f"frozen-{label}"):
                session = ExpertTimingSession(_REVIEWER_ID)
                with self.assertRaises(BaselineCollectionError):
                    for event in events:
                        getattr(session, event["event"])(event["time_ns"])


class TestVerdictBinding(_ExpertReviewTestCase):
    """The verdict vocabulary and the cross-review-set rejection."""

    def test_verdict_vocabulary_and_cross_review_set_rejected(self):
        module = self.expert_review()
        # Every frozen verdict value is accepted.
        for verdict in sorted(_EXPERT_REVIEW_VERDICTS):
            with self.subTest(verdict=verdict):
                receipt = self.build_receipt(self.review_set(), verdict=verdict)
                self.assertEqual(receipt["verdict"], verdict)
        # Off-vocabulary verdicts are rejected with the typed code.
        for verdict in ("maybe", "AGREE", "", "needs-more-evidence "):
            with self.subTest(off_vocabulary=verdict):
                with self.assertRaises(module.ExpertReviewError) as caught:
                    self.build_receipt(self.review_set(), verdict=verdict)
                self.assertEqual(
                    str(caught.exception.code), "VERDICT_VOCABULARY_INVALID"
                )
        # Cross-review-set rejection: a sidecar whose run_spec_digest belongs
        # to review set B must never produce a verdict for review set A.
        set_a = self.review_set()
        set_b = self.review_set(
            review_set_id="lima-lf-review-set-0002", run_spec_digest="b" * 64
        )
        sidecar_b, _ = self.sidecar_for(_LEGAL_EVENTS, set_b["run_spec_digest"])
        with self.assertRaises(module.ExpertReviewError) as caught:
            module.build_review_receipt(
                review_set=set_a,
                reviewer_id=_REVIEWER_ID,
                sidecar_bytes=sidecar_b,
                verdict="agree",
                synthetic=True,
            )
        self.assertEqual(
            str(caught.exception.code), "VERDICT_REVIEW_SET_MISMATCH"
        )
        # A reviewer id that disagrees with the sidecar's reviewer digest is
        # an invalid receipt face (identity consistency).
        with self.assertRaises(module.ExpertReviewError) as caught:
            module.build_review_receipt(
                review_set=set_a,
                reviewer_id="another-synthetic-reviewer",
                sidecar_bytes=self.sidecar_for(
                    _LEGAL_EVENTS, set_a["run_spec_digest"], _REVIEWER_ID
                )[0],
                verdict="agree",
                synthetic=True,
            )
        self.assertEqual(str(caught.exception.code), "RECEIPT_INVALID")


class TestEventUniqueness(_ExpertReviewTestCase):
    """One event set / sidecar never binds to a second result."""

    def test_event_uniqueness_dedup_no_time_multiplication(self):
        module = self.expert_review()
        set_a = self.review_set()
        set_b = self.review_set(
            review_set_id="lima-lf-review-set-0002", run_spec_digest="b" * 64
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipts"
            output.mkdir()
            first = self.build_receipt(set_a)
            module.write_review_receipt(first, output)
            # Re-submitting the same event set for the same set, or binding
            # the same events under a second review set, is a duplicate.
            with self.assertRaises(module.ExpertReviewError) as caught:
                module.write_review_receipt(first, output)
            self.assertEqual(str(caught.exception.code), "EVENT_DUPLICATE")
            duplicate_b = self.build_receipt(set_b)
            with self.assertRaises(module.ExpertReviewError) as caught:
                module.write_review_receipt(duplicate_b, output)
            self.assertEqual(str(caught.exception.code), "EVENT_DUPLICATE")
            # Copying one sidecar onto many results cannot multiply the
            # recorded time: seven more attempts all fail, sessions stay 1.
            for _ in range(7):
                with self.assertRaises(module.ExpertReviewError):
                    module.write_review_receipt(first, output)
            summary = module.summarize_review_receipts(output)
            self.assertEqual(summary["sessions"], 1)
            self.assertEqual(summary["active_time_ms_total"], _LEGAL_ACTIVE_MS)
            # A genuinely distinct event set is a second honest session.
            second = self.build_receipt(set_b, events=_ALT_EVENTS)
            module.write_review_receipt(second, output)
            summary = module.summarize_review_receipts(output)
            self.assertEqual(summary["sessions"], 2)
            self.assertEqual(
                summary["active_time_ms_total"],
                _LEGAL_ACTIVE_MS + _ALT_ACTIVE_MS,
            )


class TestReviewerPrivacy(_ExpertReviewTestCase):
    """The raw reviewer identity never persists in any produced byte."""

    def test_reviewer_identity_digest_only_across_all_artifacts(self):
        module = self.expert_review()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipts"
            output.mkdir()
            receipt = self.build_receipt(self.review_set())
            module.write_review_receipt(receipt, output)
            sidecar_bytes, sidecar_document = self.sidecar_for(
                _LEGAL_EVENTS, self.review_set()["run_spec_digest"]
            )
            # The digest is the exact SHA-256 of the raw id.
            expected_digest = hashlib.sha256(
                _REVIEWER_ID.encode("utf-8")
            ).hexdigest()
            self.assertEqual(receipt["reviewer_digest"], expected_digest)
            self.assertEqual(
                sidecar_document["reviewer_digest"], expected_digest
            )
            self.assertTrue(_HEX64_SHAPE.match(expected_digest))
            # The raw id appears in no produced byte.
            for label, payload in (
                ("receipt-canonical", self.content_digest(receipt).encode("utf-8")),
                ("receipt-file", self.receipt_paths(output)[0].read_bytes()),
                ("sidecar", sidecar_bytes),
                ("summary", self.content_digest(
                    module.summarize_review_receipts(output)
                ).encode("utf-8")),
            ):
                with self.subTest(face=label):
                    self.assertNotIn(_REVIEWER_ID.encode("utf-8"), payload)
            summary = module.summarize_review_receipts(output)
            self.assertEqual(summary["reviewer_digests"], [expected_digest])


class TestSidecarAndReceiptSchema(_ExpertReviewTestCase):
    """The sidecar protocol stays five-key; the receipt is separate."""

    def test_sidecar_five_keys_and_receipt_independently_versioned(self):
        module = self.expert_review()
        sidecar_bytes, sidecar_document = self.sidecar_for(
            _LEGAL_EVENTS, self.review_set()["run_spec_digest"]
        )
        # Guard group (frozen engine, passes by design): the sidecar stays
        # exactly the frozen five-key protocol.
        self.assertEqual(set(sidecar_document), _SIDECAR_KEYS)
        self.assertEqual(sidecar_document["schema_version"], 1)
        # The receipt is a separate schema-v1 document with the frozen closed
        # key set, digest-bound to the exact sidecar bytes.
        receipt = self.build_receipt(self.review_set())
        self.assertEqual(set(receipt), _RECEIPT_KEYS)
        self.assertEqual(receipt["schema_version"], 1)
        self.assertNotEqual(set(receipt), _SIDECAR_KEYS)
        self.assertEqual(
            receipt["sidecar_sha256"], self.content_digest(sidecar_bytes)
        )
        self.assertTrue(_HEX64_SHAPE.match(receipt["review_set_digest"]))
        self.assertTrue(_HEX64_SHAPE.match(receipt["events_digest"]))
        self.assertEqual(receipt["coverage"], self.review_set()["coverage"])
        self.assertEqual(
            receipt["unreviewed"], self.review_set()["unreviewed"]
        )
        self.assertEqual(
            receipt["run_spec_digest"], self.review_set()["run_spec_digest"]
        )
        self.assertEqual(
            receipt["aggregate_sha256"], self.review_set()["aggregate_sha256"]
        )
        self.assertEqual(
            receipt["findings_digest"], self.review_set()["findings_digest"]
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "receipts"
            output.mkdir()
            module.write_review_receipt(receipt, output)
            written = self.receipt_paths(output)
            self.assertEqual(len(written), 1)
            self.assertTrue(_RECEIPT_NAME_SHAPE.match(written[0].name))
            # Writing a receipt never writes a sidecar file.
            self.assertEqual(
                sorted(item.name for item in output.iterdir()),
                [written[0].name],
            )
            # A malformed receipt mapping is rejected by the writer.
            malformed = dict(receipt)
            del malformed["sidecar_sha256"]
            with self.assertRaises(module.ExpertReviewError) as caught:
                module.write_review_receipt(malformed, output)
            self.assertEqual(str(caught.exception.code), "RECEIPT_INVALID")
            self.assertEqual(len(self.receipt_paths(output)), 1)


class TestSyntheticIsolation(_ExpertReviewTestCase):
    """Synthetic events are marked; no human return reports sessions=0."""

    def test_synthetic_isolation_and_zero_human_sessions_summary(self):
        module = self.expert_review()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            # Empty directory: no human return means sessions=0 and
            # unavailable active time, reported honestly.
            empty = parent / "empty"
            empty.mkdir()
            summary = module.summarize_review_receipts(empty)
            self.assertEqual(
                summary,
                {
                    "schema_version": 1,
                    "sessions": 0,
                    "synthetic_sessions": 0,
                    "active_time_ms_total": None,
                    "reviewer_digests": [],
                    "verdict_counts": {},
                },
            )
            # Synthetic receipts are explicitly marked and never counted as
            # human sessions; they live in temp directories only.
            synthetic_dir = parent / "synthetic-only"
            synthetic_dir.mkdir()
            synthetic = self.build_receipt(self.review_set(), synthetic=True)
            self.assertIs(synthetic["synthetic"], True)
            module.write_review_receipt(synthetic, synthetic_dir)
            summary = module.summarize_review_receipts(synthetic_dir)
            self.assertEqual(summary["sessions"], 0)
            self.assertEqual(summary["synthetic_sessions"], 1)
            self.assertIsNone(summary["active_time_ms_total"])
            self.assertEqual(summary["verdict_counts"], {})
            # A non-synthetic receipt counts as one session.
            human_dir = parent / "human-shaped"
            human_dir.mkdir()
            honest = self.build_receipt(self.review_set(), synthetic=False)
            self.assertIs(honest["synthetic"], False)
            module.write_review_receipt(honest, human_dir)
            summary = module.summarize_review_receipts(human_dir)
            self.assertEqual(summary["sessions"], 1)
            self.assertEqual(summary["synthetic_sessions"], 0)
            self.assertEqual(summary["active_time_ms_total"], _LEGAL_ACTIVE_MS)
            self.assertEqual(summary["verdict_counts"], {"agree": 1})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
