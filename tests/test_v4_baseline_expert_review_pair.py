"""Evidence-pair acceptance tests for the expert review follow-up (2026-10-02).

Contract under test (the Maintainer-authorized fix scope of
ZCODE_LONG_TASK_REVIEW_PAIR_FIX_AND_BASELINE_HANDOFF_2026-10-02):

- One completed session persists an **evidence pair** through the pairing
  layer: the raw canonical five-key timing sidecar file (content-addressed
  name ``expert-timing-sidecar-v1-{sha256[:16]}.json``) plus the frozen
  verdict receipt, bound by content digests.  Sidecar first, receipt as
  the completion voucher; one member alone is incomplete residue that
  never counts as a session.
- Every deterministic failure gates **before the first key press**: the
  frozen review-set loader, an optional pinned review-set file digest, the
  canonical dry run (the float fail-early precheck), the internal findings
  digest, and the output target (create-as-new-leaf rule plus a real
  write probe).
- Independent verification from the persisted bytes replays the frozen
  event state machine, recomputes active time and every digest, and
  cross-checks reviewer/identity and review-set bindings; any single
  mismatch rejects the pair and the human summary never increases.
- A verdict typed at start-up through ``--verdict`` is never accepted as
  the post-review confirmation; without the confirmed verdict the session
  stays incomplete (sidecar-only residue, no receipt).
- Synthetic pairs verify as pairs but are excluded from every human face
  and from the derived-report input; real human sessions stay 0 across
  this whole test file (every session here is synthetic or explicit
  module-level assembly).
- The derived-report flow rebuilds the sealed inputs read-only through the
  frozen production helpers, requires the rebuilt scanner digest to equal
  the sealed binding, excludes synthetic pairs, writes into a brand-new
  directory and leaves the sealed report byte-identical.

Everything here is offline and deterministic: timing events carry explicit
synthetic nanosecond stamps (no sleeping), all materializations live in
temp directories only, and no test ever touches a network socket, reads
the environment, or records an event on behalf of a human.
"""

import ast
import hashlib
import importlib.util
import json
import pathlib
import re
import sys
import tarfile
import tempfile
import unittest

from benchmarks.v4.baseline.expert_review import (
    build_review_receipt,
    summarize_review_receipts,
)
from benchmarks.v4.baseline.expert_timing import ExpertTimingSession
from lima.contracts.codec import canonical_encode

_REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
_PAIR_MODULE_RELATIVE_PATH = "benchmarks/v4/baseline/expert_review_pair.py"
_REVIEW_CLI_RELATIVE_PATH = "scripts/run_expert_review.py"
_VERIFY_CLI_RELATIVE_PATH = "scripts/verify_expert_review.py"

#: The frozen sidecar file-name family of the pairing layer (v1, closed).
_SIDECAR_NAME_SHAPE = re.compile(r"^expert-timing-sidecar-v1-[0-9a-f]{16}\.json$")

#: The frozen typed error family of the pairing layer.
_PAIR_ERROR_CODES = frozenset(
    {
        "REVIEW_SET_PIN_MISMATCH",
        "REVIEW_SET_ENCODING_INVALID",
        "REVIEW_SET_FINDINGS_MISMATCH",
        "OUTPUT_TARGET_INVALID",
        "PAIR_INCOMPLETE",
        "PAIR_INVALID",
    }
)

_SECRET_KEY_SHAPE = re.compile(r"\bsk-[A-Za-z0-9]{16,}")

#: One legal synthetic event sequence with a deliberate pause window
#: (paused time must never accrue; timestamps deliberately non-round).
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

_REVIEWER_ID = "lima-synthetic-pair-reviewer-0x5EED-face"


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
            roots.add(node.module.split(".")[0]
            )
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


class _PairTestCase(unittest.TestCase):
    """Shared arrange helpers (pairing-module imports are lazy per test)."""

    def pair_module(self):
        import benchmarks.v4.baseline.expert_review_pair as module

        return module

    def product_source(self, relative):
        path = _REPO_ROOT / relative
        if not path.is_file():
            self.fail(f"required product source is missing: {relative}")
        return path.read_text(encoding="utf-8")

    def review_set(self, **overrides):
        document = {
            "schema_version": 1,
            "review_set_id": "lima-lf-review-set-0001",
            "run_spec_digest": "a" * 64,
            "aggregate_sha256": "1" * 64,
            "findings_digest": None,  # filled below from the canonical findings
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
        from lima.contracts.codec import compute_content_digest

        if document["findings_digest"] is None:
            document["findings_digest"] = compute_content_digest(document["findings"])
        return document

    def write_review_set(self, directory, document=None):
        from lima.contracts.codec import canonical_encode

        path = pathlib.Path(directory) / "review-set.json"
        path.write_bytes(canonical_encode(document or self.review_set()))
        return path

    def sidecar_for(self, events, run_spec_digest, reviewer_id=_REVIEWER_ID):
        """(sidecar bytes, sidecar document) via the frozen timing session."""
        session = ExpertTimingSession(reviewer_id)
        for event in events:
            getattr(session, event["event"])(event["time_ns"])
        payload = session.sidecar_bytes(run_spec_digest)
        document = json.loads(payload.decode("utf-8"))
        return payload, document

    def complete_pair(
        self,
        output_dir,
        events=_LEGAL_EVENTS,
        review_set=None,
        verdict="agree",
        reviewer_id=_REVIEWER_ID,
        synthetic=True,
    ):
        """Assemble and persist one full evidence pair (module level)."""
        module = self.pair_module()
        document = review_set or self.review_set()
        sidecar_bytes, _ = self.sidecar_for(
            events, document["run_spec_digest"], reviewer_id
        )
        module.persist_timing_sidecar(sidecar_bytes, output_dir)
        receipt = build_review_receipt(
            review_set=document,
            reviewer_id=reviewer_id,
            sidecar_bytes=sidecar_bytes,
            verdict=verdict,
            notes="synthetic pair note",
            synthetic=synthetic,
        )
        return module.attach_verdict_receipt(receipt, output_dir), receipt

    def load_cli(self, relative):
        cli_path = _REPO_ROOT / relative
        if not cli_path.is_file():
            self.fail(f"required CLI script is missing: {relative}")
        spec = importlib.util.spec_from_file_location(
            pathlib.Path(relative).stem.replace(".", "_"), cli_path
        )
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        return cli

    def feed_stdin(self, answers):
        """Patch ``builtins.input`` with a scripted answer queue."""
        import unittest.mock

        queue = list(answers)

        def fake_input(prompt=""):
            if not queue:
                raise EOFError
            answer = queue.pop(0)
            print(f"{prompt}{answer}")
            return answer

        return unittest.mock.patch("builtins.input", fake_input)


class TestPrepareGate(_PairTestCase):
    """Every deterministic failure lands before the first key press."""

    def test_prepare_creates_new_leaf_directory_and_probes(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = self.write_review_set(parent)
            target = parent / "sessions-new"
            prepared = module.prepare_session(set_path, target)
            self.assertTrue(target.is_dir())
            self.assertEqual(prepared.output_dir, target)
            self.assertEqual(prepared.review_set["review_set_id"], "lima-lf-review-set-0001")
            # The write probe leaves no residue and no session artifact.
            self.assertEqual(sorted(item.name for item in target.iterdir()), [])
            # An existing legal directory stays reusable (idempotent gate).
            again = module.prepare_session(set_path, target)
            self.assertEqual(again.output_dir, target)
            # Deep creation and file targets are refused up front.
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.prepare_session(set_path, parent / "missing" / "deep")
            self.assertEqual(
                str(caught.exception.code), "OUTPUT_TARGET_INVALID"
            )
            occupied = parent / "occupied.txt"
            occupied.write_bytes(b"not a directory")
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.prepare_session(set_path, occupied)
            self.assertEqual(
                str(caught.exception.code), "OUTPUT_TARGET_INVALID"
            )

    def test_prepare_rejects_tampered_pinned_review_set(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = self.write_review_set(parent)
            pinned = hashlib.sha256(set_path.read_bytes()).hexdigest()
            prepared = module.prepare_session(
                set_path, parent / "ok", review_set_sha256=pinned
            )
            self.assertTrue(prepared.output_dir.is_dir())
            # Any byte change to the review-set file is rejected pre-start.
            document = self.review_set()
            document["coverage"] = "tampered-coverage"
            set_path.write_bytes(json.dumps(document).encode("utf-8"))
            with tempfile.TemporaryDirectory() as other:
                with self.assertRaises(module.ExpertReviewPairError) as caught:
                    module.prepare_session(
                        set_path,
                        pathlib.Path(other) / "nope",
                        review_set_sha256=pinned,
                    )
                self.assertEqual(
                    str(caught.exception.code), "REVIEW_SET_PIN_MISMATCH"
                )
            # A non-hex64 pin value is itself refused.
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.prepare_session(
                    set_path, parent / "nope2", review_set_sha256="zz"
                )
            self.assertEqual(
                str(caught.exception.code), "REVIEW_SET_PIN_MISMATCH"
            )

    def test_prepare_fail_early_on_non_canonical_review_set(self):
        # The DR-IP-0043-CFINAL-FLOAT face: a float-bearing review-set passes
        # the frozen loader but could never produce a receipt; it must be
        # refused before any human timing starts.
        module = self.pair_module()
        float_bearing = self.review_set()
        float_bearing["findings"] = [{"path": "x.py", "confidence": 0.98}]
        # keep the (canonical) digest of the default findings; the float
        # face must fail on encoding, before digest consistency.
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = parent / "review-set.json"
            set_path.write_bytes(json.dumps(float_bearing).encode("utf-8"))
            from benchmarks.v4.baseline.expert_review import load_review_set

            loaded = load_review_set(set_path)  # loads fine ...
            self.assertEqual(loaded["review_set_id"], "lima-lf-review-set-0001")
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.prepare_session(set_path, parent / "sessions")
            self.assertEqual(
                str(caught.exception.code), "REVIEW_SET_ENCODING_INVALID"
            )
            # Nothing was created: the gate ran before the session.
            self.assertFalse((parent / "sessions").exists())

    def test_prepare_rejects_findings_digest_mismatch(self):
        module = self.pair_module()
        # A findings list that disagrees with the frozen findings digest:
        # build the consistent document first, then swap the content.
        tampered = self.review_set()
        tampered["findings"] = [{"path": "other.py", "cwe": "CWE-79"}]
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = parent / "review-set.json"
            set_path.write_bytes(json.dumps(tampered).encode("utf-8"))
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.prepare_session(set_path, parent / "sessions")
            self.assertEqual(
                str(caught.exception.code), "REVIEW_SET_FINDINGS_MISMATCH"
            )


class TestPairPersistence(_PairTestCase):
    """The pair lands sidecar-first, complete only with the receipt."""

    def test_complete_pair_from_new_directory_with_independent_recompute(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = self.write_review_set(parent)
            output = parent / "sessions"
            module.prepare_session(set_path, output)
            pair, receipt = self.complete_pair(output, synthetic=True)
            # The explicit naming rule: content-addressed sidecar + frozen
            # receipt family, both discoverable without guessing.
            self.assertTrue(_SIDECAR_NAME_SHAPE.fullmatch(pair.sidecar_path.name))
            self.assertEqual(
                pair.sidecar_path.name,
                f"expert-timing-sidecar-v1-{pair.sidecar_sha256[:16]}.json",
            )
            self.assertTrue(
                re.fullmatch(r"expert-review-receipt-v1-\d{2}\.json", pair.receipt_path.name)
            )
            self.assertEqual(pair.active_time_ms, _LEGAL_ACTIVE_MS)
            # Independent verification from the persisted bytes only.
            persisted = json.loads(pair.sidecar_path.read_bytes().decode("utf-8"))
            self.assertEqual(
                _independent_active_ms(persisted["events"]), _LEGAL_ACTIVE_MS
            )
            self.assertEqual(
                hashlib.sha256(pair.sidecar_path.read_bytes()).hexdigest(),
                receipt["sidecar_sha256"],
            )
            # The raw reviewer id appears in no produced byte.
            for artifact in (pair.sidecar_path, pair.receipt_path):
                with self.subTest(artifact=artifact.name):
                    self.assertNotIn(_REVIEWER_ID.encode("utf-8"), artifact.read_bytes())
            record = module.verify_session_directory(output, review_set_path=set_path)
            self.assertEqual(record["human_sessions"], 0)
            self.assertEqual(record["synthetic_sessions"], 1)
            self.assertEqual(record["human_active_time_ms_total"], None)

    def test_pause_window_excluded_and_duplicate_events_rejected(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            self.complete_pair(output, events=_LEGAL_EVENTS, synthetic=False)
            self.complete_pair(output, events=_ALT_EVENTS, synthetic=True)
            # Paused time is excluded by the independent replay (the pause
            # window 5,000,100..9,000,200 never accrues).
            sidecar_files = sorted(
                item for item in output.iterdir() if _SIDECAR_NAME_SHAPE.fullmatch(item.name)
            )
            active = {
                _independent_active_ms(
                    json.loads(item.read_bytes().decode("utf-8"))["events"]
                )
                for item in sidecar_files
            }
            self.assertEqual(active, {_LEGAL_ACTIVE_MS, _ALT_ACTIVE_MS})
            # Re-submitting the same event set is the frozen duplicate face.
            from benchmarks.v4.baseline.expert_review import ExpertReviewError

            sidecar_bytes, _ = self.sidecar_for(
                _LEGAL_EVENTS, self.review_set()["run_spec_digest"]
            )
            receipt = build_review_receipt(
                review_set=self.review_set(),
                reviewer_id=_REVIEWER_ID,
                sidecar_bytes=sidecar_bytes,
                verdict="agree",
                synthetic=True,
            )
            with self.assertRaises(ExpertReviewError) as caught:
                module.attach_verdict_receipt(receipt, output)
            self.assertEqual(str(caught.exception.code), "EVENT_DUPLICATE")
            # Human minutes never multiply: one human + one synthetic.
            record = module.verify_session_directory(output)
            self.assertEqual(record["human_sessions"], 1)
            self.assertEqual(record["synthetic_sessions"], 1)
            self.assertEqual(record["human_active_time_ms_total"], _LEGAL_ACTIVE_MS)

    def test_interrupted_session_leaves_incomplete_residue(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            sidecar_bytes, _ = self.sidecar_for(
                _LEGAL_EVENTS, self.review_set()["run_spec_digest"]
            )
            sidecar_path = module.persist_timing_sidecar(sidecar_bytes, output)
            # No receipt: explicitly unfinished, never a session.
            record = module.verify_session_directory(output)
            self.assertEqual(record["human_sessions"], 0)
            self.assertEqual(record["synthetic_sessions"], 0)
            self.assertEqual(record["human_active_time_ms_total"], None)
            self.assertEqual(record["incomplete_sidecars"], [sidecar_path.name])
            self.assertEqual(
                module.verified_human_sidecar_documents(output), []
            )
            # The frozen summary stays honest too: no receipt, no session.
            self.assertEqual(summarize_review_receipts(output)["sessions"], 0)

    def test_receipt_without_sidecar_fails_closed(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            pair, receipt = self.complete_pair(output)
            pair.sidecar_path.unlink()
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.verify_session_directory(output)
            self.assertEqual(str(caught.exception.code), "PAIR_INCOMPLETE")
            # And attach refuses to complete a pair whose sidecar is gone.
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.attach_verdict_receipt(receipt, output)
            self.assertEqual(str(caught.exception.code), "PAIR_INCOMPLETE")

    def test_sidecar_output_conflict_never_overwrites(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            sidecar_bytes, _ = self.sidecar_for(
                _LEGAL_EVENTS, self.review_set()["run_spec_digest"]
            )
            first = module.persist_timing_sidecar(sidecar_bytes, output)
            # Same content: byte-identical reuse is safe.
            self.assertEqual(module.persist_timing_sidecar(sidecar_bytes, output), first)
            # Different content hashing to the same 16-hex prefix is out of
            # scope of the name rule; instead, an occupant with different
            # bytes under the same name must fail closed.  Simulate by
            # writing foreign bytes at the deterministic target name.
            from lima.contracts.codec import compute_content_digest

            name = f"expert-timing-sidecar-v1-{compute_content_digest(sidecar_bytes)[:16]}.json"
            target = output / name
            original = target.read_bytes()
            target.write_bytes(b"foreign-bytes")
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.persist_timing_sidecar(sidecar_bytes, output)
            self.assertEqual(str(caught.exception.code), "PAIR_INVALID")
            self.assertEqual(target.read_bytes(), b"foreign-bytes")  # untouched
            target.write_bytes(original)  # restore for hygiene


class TestVerificationNegatives(_PairTestCase):
    """One tampered face rejects the pair; human totals never increase."""

    def _tamper_cases(self, output):
        pair, receipt = self.complete_pair(output)
        base_sidecar = json.loads(pair.sidecar_path.read_bytes().decode("utf-8"))
        base_receipt = json.loads(pair.receipt_path.read_bytes().decode("utf-8"))

        def restore():
            # Round-trip through the canonical codec: parse of canonical
            # bytes plus canonical re-encode is byte-identical, so the
            # restored pair verifies again.
            pair.sidecar_path.write_bytes(canonical_encode(base_sidecar))
            pair.receipt_path.write_bytes(canonical_encode(base_receipt))
            return pair

        # (a) tampered events in the sidecar file (still monotonic, so only
        # the digests and the replayed active time can catch it)
        document = json.loads(json.dumps(base_sidecar))
        document["events"][1]["time_ns"] = 6_000_100
        pair.sidecar_path.write_bytes(json.dumps(document).encode("utf-8"))
        yield "events-tampered"
        restore()
        # (b) tampered declared active time
        document = json.loads(json.dumps(base_sidecar))
        document["active_time_ms"] = 99
        pair.sidecar_path.write_bytes(json.dumps(document).encode("utf-8"))
        yield "active-time-tampered"
        restore()
        # (c) tampered receipt events digest
        document = json.loads(json.dumps(base_receipt))
        document["events_digest"] = "f" * 64
        pair.receipt_path.write_bytes(json.dumps(document).encode("utf-8"))
        yield "events-digest-tampered"
        restore()
        # (d) tampered receipt sidecar digest
        document = json.loads(json.dumps(base_receipt))
        document["sidecar_sha256"] = "e" * 64
        pair.receipt_path.write_bytes(json.dumps(document).encode("utf-8"))
        yield "sidecar-digest-tampered"
        restore()

    def test_tampering_rejected_and_human_summary_not_increased(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            for label in self._tamper_cases(output):
                with self.subTest(face=label):
                    with self.assertRaises(module.ExpertReviewPairError) as caught:
                        module.verify_session_directory(output)
                    self.assertEqual(str(caught.exception.code), "PAIR_INVALID")
                    # No human face is produced from a rejected directory:
                    # the report-input gate fails closed the same way.
                    with self.assertRaises(module.ExpertReviewPairError):
                        module.verified_human_sidecar_documents(output)
            # After full restoration the pair verifies again and the human
            # face counts exactly the one session it always had.
            record = module.verify_session_directory(output)
            self.assertEqual(record["human_sessions"], 0)  # synthetic pair
            self.assertEqual(record["synthetic_sessions"], 1)

    def test_cross_review_set_and_binding_rejected(self):
        module = self.pair_module()
        set_a = self.review_set()
        set_b = self.review_set(
            review_set_id="lima-lf-review-set-0002", run_spec_digest="b" * 64
        )
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            pair, _ = self.complete_pair(output, review_set=set_a)
            # Verifying a set-A pair against set B must never pass.
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.verify_session_directory(output, review_set=set_b)
            self.assertEqual(str(caught.exception.code), "PAIR_INVALID")
            # Against its own review set it verifies.
            record = module.verify_session_directory(output, review_set=set_a)
            self.assertEqual(record["synthetic_sessions"], 1)
            # A receipt whose identity face disagrees with the sidecar is
            # the frozen module's own rejection, surfaced by pairing too.
            sidecar_bytes, _ = self.sidecar_for(
                _LEGAL_EVENTS, set_a["run_spec_digest"], "another-reviewer"
            )
            module.persist_timing_sidecar(sidecar_bytes, output)
            from benchmarks.v4.baseline.expert_review import ExpertReviewError

            with self.assertRaises(ExpertReviewError):
                build_review_receipt(
                    review_set=set_a,
                    reviewer_id=_REVIEWER_ID,
                    sidecar_bytes=sidecar_bytes,
                    verdict="agree",
                    synthetic=True,
                )

    def test_synthetic_pairs_excluded_from_every_human_face(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "sessions"
            output.mkdir()
            self.complete_pair(output, synthetic=True)
            self.complete_pair(output, events=_ALT_EVENTS, synthetic=True)
            record = module.verify_session_directory(output)
            self.assertEqual(record["human_sessions"], 0)
            self.assertEqual(record["synthetic_sessions"], 2)
            self.assertEqual(record["human_active_time_ms_total"], None)
            # The report-input gate returns nothing: bare sidecars never
            # enter, paired synthetic sidecars are filtered by the flag.
            self.assertEqual(module.verified_human_sidecar_documents(output), [])
            self.assertEqual(summarize_review_receipts(output)["sessions"], 0)


class TestCliOrchestration(_PairTestCase):
    """The interactive CLI: gate first, pair last, verdict after review."""

    def test_cli_end_to_end_from_new_directory(self):
        cli = self.load_cli(_REVIEW_CLI_RELATIVE_PATH)
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = self.write_review_set(parent)
            output = parent / "fresh-sessions"
            with self.feed_stdin(
                [
                    "start", "pause", "resume", "finish",  # timing keys
                    "agree",  # post-review verdict confirmation
                    "checked the sample",  # notes line
                ]
            ), tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream:
                sys.stdout = stream
                try:
                    exit_code = cli.main(
                        [
                            "--review-set", str(set_path),
                            "--reviewer-id", _REVIEWER_ID,
                            "--output-dir", str(output),
                            "--synthetic",
                        ]
                    )
                finally:
                    sys.stdout = sys.__stdout__
            self.assertEqual(exit_code, 0)
            receipts = sorted(output.glob("expert-review-receipt-v1-*.json"))
            sidecars = sorted(output.glob("expert-timing-sidecar-v1-*.json"))
            self.assertEqual(len(receipts), 1)
            self.assertEqual(len(sidecars), 1)
            receipt = json.loads(receipts[0].read_bytes().decode("utf-8"))
            sidecar = json.loads(sidecars[0].read_bytes().decode("utf-8"))
            self.assertEqual(receipt["verdict"], "agree")
            self.assertEqual(receipt["notes"], "checked the sample")
            self.assertIs(receipt["synthetic"], True)
            self.assertEqual(
                _independent_active_ms(sidecar["events"]), receipt["active_time_ms"]
            )
            self.assertNotIn(_REVIEWER_ID.encode("utf-8"), sidecars[0].read_bytes())
            self.assertNotIn(_REVIEWER_ID.encode("utf-8"), receipts[0].read_bytes())
            record = module.verify_session_directory(
                output, review_set_path=set_path
            )
            self.assertEqual(record["synthetic_sessions"], 1)
            self.assertEqual(record["human_sessions"], 0)

    def test_cli_prefilled_verdict_requires_post_review_confirmation(self):
        cli = self.load_cli(_REVIEW_CLI_RELATIVE_PATH)
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = self.write_review_set(parent)
            output = parent / "sessions"
            with self.feed_stdin(
                ["start", "finish"]
                # EOF at the verdict confirmation prompt
            ), tempfile.TemporaryFile(mode="w+", encoding="utf-8") as stream:
                sys.stdout = stream
                try:
                    with self.assertRaises(SystemExit):
                        cli.main(
                            [
                                "--review-set", str(set_path),
                                "--reviewer-id", _REVIEWER_ID,
                                "--output-dir", str(output),
                                "--verdict", "agree",
                                "--synthetic",
                            ]
                        )
                finally:
                    sys.stdout = sys.__stdout__
            # The pre-filled verdict never counts as the confirmation: the
            # sidecar survives as incomplete residue, no receipt lands.
            sidecars = sorted(output.glob("expert-timing-sidecar-v1-*.json"))
            receipts = sorted(output.glob("expert-review-receipt-v1-*.json"))
            self.assertEqual(len(sidecars), 1)
            self.assertEqual(receipts, [])
            record = module.verify_session_directory(output)
            self.assertEqual(record["human_sessions"], 0)
            self.assertEqual(record["incomplete_sidecars"], [sidecars[0].name])

    def test_cli_rejects_unusable_target_before_any_timing(self):
        cli = self.load_cli(_REVIEW_CLI_RELATIVE_PATH)
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            set_path = self.write_review_set(parent)
            occupied = parent / "a-file.txt"
            occupied.write_bytes(b"x")
            calls = []
            with self.feed_stdin(calls):  # no key press may ever be consumed
                with self.assertRaises(module.ExpertReviewPairError) as caught:
                    cli.main(
                        [
                            "--review-set", str(set_path),
                            "--reviewer-id", _REVIEWER_ID,
                            "--output-dir", str(occupied),
                            "--synthetic",
                        ]
                    )
            self.assertEqual(str(caught.exception.code), "OUTPUT_TARGET_INVALID")
            # Tampered input is likewise refused pre-start (pinned digest).
            pinned = "0" * 64
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                cli.main(
                    [
                        "--review-set", str(set_path),
                        "--reviewer-id", _REVIEWER_ID,
                        "--output-dir", str(parent / "never"),
                        "--review-set-sha256", pinned,
                        "--synthetic",
                    ]
                )
            self.assertEqual(str(caught.exception.code), "REVIEW_SET_PIN_MISMATCH")
            self.assertFalse((parent / "never").exists())

    def test_cli_surface_and_source_hygiene(self):
        cli = self.load_cli(_REVIEW_CLI_RELATIVE_PATH)
        verify_cli = self.load_cli(_VERIFY_CLI_RELATIVE_PATH)
        parsed = cli.build_parser().parse_args(
            [
                "--review-set", "set.json",
                "--reviewer-id", _REVIEWER_ID,
                "--output-dir", "out",
                "--verdict", "agree",
                "--notes", "note",
                "--synthetic",
                "--review-set-sha256", "0" * 64,
            ]
        )
        self.assertEqual(parsed.verdict, "agree")
        self.assertTrue(parsed.synthetic)
        self.assertEqual(parsed.review_set_sha256, "0" * 64)
        # --verdict stays optional: the post-review confirmation is the
        # authoritative verdict input.
        bare = cli.build_parser().parse_args(
            ["--review-set", "set.json", "--reviewer-id", "r", "--output-dir", "o"]
        )
        self.assertIsNone(bare.verdict)
        verify_parsed = verify_cli.build_parser().parse_args(
            ["--sessions-dir", "dir", "--review-set", "set.json", "--json"]
        )
        self.assertEqual(verify_parsed.sessions_dir, "dir")
        # Source hygiene: both CLIs and the pairing module stay offline,
        # secretless and ambient-free.
        for relative in (
            _PAIR_MODULE_RELATIVE_PATH,
            _REVIEW_CLI_RELATIVE_PATH,
            _VERIFY_CLI_RELATIVE_PATH,
        ):
            with self.subTest(source=relative):
                source = self.product_source(relative)
                self.assertEqual(
                    _import_roots(source) & _forbidden_network_roots(), set()
                )
                self.assertNotIn("environ", source)
                self.assertNotIn("getenv", source)
                self.assertIsNone(_SECRET_KEY_SHAPE.search(source))
        # The typed error family of the pairing layer is closed.
        module = self.pair_module()
        self.assertEqual(
            {str(code) for code in module.ExpertReviewPairErrorCode},
            _PAIR_ERROR_CODES,
        )
        self.assertTrue(issubclass(module.ExpertReviewPairError, ValueError))
        # PC1 self-scan (passes by design).
        own = pathlib.Path(__file__).read_text(encoding="utf-8")
        self.assertEqual(_import_roots(own) & _forbidden_network_roots(), set())
        self.assertIsNone(_SECRET_KEY_SHAPE.search(own))


class TestDerivedReport(_PairTestCase):
    """Verify pairs -> exclude synthetic -> derive report, sealed inputs intact."""

    def _build_sealed_mini_baseline(self, parent):
        """A miniature but structurally faithful LF R2 directory, offline."""
        import benchmarks.v4.baseline.lf_baseline as lf

        run_spec_digest = "a" * 64
        prefix = run_spec_digest[:16]
        source = parent / "sealed"
        source.mkdir()
        # 1. A sealed tarball with one top-level directory and a positive.
        archive = parent / "sample-repo.tar.gz"
        sample_root = parent / "archive-staging" / "sample-repo"
        sample_root.mkdir(parents=True)
        (sample_root / "widget.py").write_text(
            "def run(user_expr):\n    return eval(user_expr)\n",
            encoding="utf-8",
            newline="\n",
        )
        with tarfile.open(archive, "w:gz") as bundle:
            bundle.add(sample_root, arcname="sample-repo")
        # 2. The rebuilt scanner payload and wire digest via the frozen
        #    production helpers (the same chain the derivation must replay).
        materialized = lf._materialize_snapshot(
            archive, parent / "sealed-materialized"
        )
        scan = lf._scan_snapshot(materialized)
        payload = lf._canonical_payload(scan, lf.LF_CANONICAL_LABEL)
        wire_digest = lf._wire_fingerprint(payload)
        # 3. Run files: two attempts plus the aggregate, frozen naming.
        from benchmarks.v4.baseline.orchestrate import BaselineRunSummary
        from benchmarks.v4.baseline.report import (
            build_baseline_report,
            write_report_file,
        )
        from benchmarks.v4.baseline.run import write_exclusive
        from lima.baseline_run_result import from_mapping
        from lima.contracts.codec import canonical_encode, compute_content_digest

        def sample(index, mode):
            return {
                "attempt_index": index,
                "mode": mode,
                "outcome": "success",
                "wall_time_ms": 10 + index,
                "queue_time_ms": None,
                "cpu_time_ms": 5 + index,
                "expert_time_ms": None,
                "memory_rss_peak_bytes": 1000,
                "io_read_bytes": 10,
                "io_write_bytes": 10,
                "prompt_tokens": 0,
                "completion_tokens": 0,
                "cost_micro_usd": 0,
                "failure_code": None,
            }

        attempts = [
            from_mapping(
                {
                    "schema_version": 1,
                    "run_spec_digest": run_spec_digest,
                    "samples": [sample(0, "cold")],
                }
            ),
            from_mapping(
                {
                    "schema_version": 1,
                    "run_spec_digest": run_spec_digest,
                    "samples": [sample(1, "warm")],
                }
            ),
        ]
        aggregate = from_mapping(
            {
                "schema_version": 1,
                "run_spec_digest": run_spec_digest,
                "samples": [sample(0, "cold"), sample(1, "warm")],
            }
        )
        paths = []
        for index, result in enumerate(attempts + [aggregate], start=1):
            path = source / f"{prefix}-run-{index}.json"
            write_exclusive(path, result.canonical_bytes())
            paths.append(path)
        summary = BaselineRunSummary(
            attempts=tuple(attempts),
            result_paths=tuple(paths[:2]),
            aggregate=aggregate,
            aggregate_path=paths[2],
            aggregate_sha256=aggregate.content_digest(),
            status=aggregate.status,
        )
        sealed_report = build_baseline_report(summary, payload)
        write_report_file(sealed_report, source)
        # 4. The binding manifest pins the sealed scanner digest.
        binding = {
            "schema_version": 1,
            "run_spec_digest": run_spec_digest,
            "scanner_payload_sha256": wire_digest,
        }
        (source / "lf-binding.json").write_bytes(canonical_encode(binding))
        # 5. The review set binds the aggregate and simple string findings.
        review_set = {
            "schema_version": 1,
            "review_set_id": "mini-sample-review-set-0001",
            "run_spec_digest": run_spec_digest,
            "aggregate_sha256": aggregate.content_digest(),
            "findings_digest": compute_content_digest(
                [{"path": "widget.py", "rule_id": "SEC-EVAL"}]
            ),
            "findings": [{"path": "widget.py", "rule_id": "SEC-EVAL"}],
            "coverage": "mini-full-scan",
            "unreviewed": "none",
            "representative_result_sha256": compute_content_digest(
                paths[0].read_bytes()
            ),
        }
        set_path = parent / "review-set-mini.json"
        set_path.write_bytes(canonical_encode(review_set))
        return source, archive, set_path, prefix

    def test_derive_report_excludes_synthetic_and_keeps_sealed_intact(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            source, archive, set_path, prefix = self._build_sealed_mini_baseline(
                parent
            )
            sealed_report = source / f"{prefix}-report-1.json"
            sealed_before = hashlib.sha256(sealed_report.read_bytes()).hexdigest()
            sessions = parent / "sessions"
            sessions.mkdir()
            from benchmarks.v4.baseline.expert_review import load_review_set

            mini_set = load_review_set(set_path)
            self.complete_pair(
                sessions, review_set=mini_set, synthetic=True, verdict="agree"
            )
            derived = parent / "derived-out"
            record = module.derive_expert_review_report(
                source_dir=source,
                sessions_dir=sessions,
                review_set_path=set_path,
                archive_path=archive,
                output_dir=derived,
            )
            # The rebuilt scanner digest equals the sealed binding pin.
            self.assertEqual(
                record["rebuilt_scanner_payload_sha256"],
                record["sealed_scanner_payload_sha256"],
            )
            # The synthetic pair verified but never entered the report.
            self.assertEqual(record["sessions"]["synthetic_sessions"], 1)
            self.assertEqual(record["sessions"]["human_sessions"], 0)
            self.assertEqual(record["human_sidecar_count"], 0)
            derived_report = json.loads(
                (derived / record["derived_report_path"]).read_bytes()
            )
            self.assertEqual(derived_report["expert"]["sessions"], 0)
            self.assertIsNone(derived_report["expert"]["active_time_ms_total"])
            # Zero human minutes today: byte-identical to the sealed report.
            self.assertEqual(
                record["derived_report_sha256"], sealed_before
            )
            # The sealed report and every sealed input are untouched.
            self.assertEqual(
                hashlib.sha256(sealed_report.read_bytes()).hexdigest(), sealed_before
            )
            self.assertEqual(
                record["sealed_report_sha256_before"],
                record["sealed_report_sha256_after"],
            )
            # The derivation record itself is persisted in the new directory.
            record_path = derived / "expert-review-derivation-v1.json"
            self.assertTrue(record_path.is_file())
            persisted = json.loads(record_path.read_bytes().decode("utf-8"))
            self.assertEqual(persisted["run_spec_digest"], "a" * 64)

    def test_derive_report_fails_closed_on_binding_and_target(self):
        module = self.pair_module()
        with tempfile.TemporaryDirectory() as temporary:
            parent = pathlib.Path(temporary)
            source, archive, set_path, _ = self._build_sealed_mini_baseline(parent)
            sessions = parent / "sessions"
            sessions.mkdir()
            from benchmarks.v4.baseline.expert_review import load_review_set

            mini_set = load_review_set(set_path)
            self.complete_pair(sessions, review_set=mini_set, synthetic=True)
            # A tampered binding pin (scanner digest) must reject the rebuild.
            binding_path = source / "lf-binding.json"
            document = json.loads(binding_path.read_bytes().decode("utf-8"))
            document["scanner_payload_sha256"] = "c" * 64
            binding_path.write_bytes(json.dumps(document).encode("utf-8"))
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.derive_expert_review_report(
                    source_dir=source,
                    sessions_dir=sessions,
                    review_set_path=set_path,
                    archive_path=archive,
                    output_dir=parent / "derived-bad",
                )
            self.assertEqual(str(caught.exception.code), "PAIR_INVALID")
            # Restore the honest pin through the frozen helpers; an
            # already-existing output target is then refused untouched.
            import benchmarks.v4.baseline.lf_baseline as lf

            materialized = lf._materialize_snapshot(archive, parent / "remat")
            payload = lf._canonical_payload(
                lf._scan_snapshot(materialized), lf.LF_CANONICAL_LABEL
            )
            binding_path.write_bytes(
                json.dumps(
                    {
                        "schema_version": 1,
                        "run_spec_digest": "a" * 64,
                        "scanner_payload_sha256": lf._wire_fingerprint(payload),
                    }
                ).encode("utf-8")
            )
            existing = parent / "already-there"
            existing.mkdir()
            with self.assertRaises(module.ExpertReviewPairError) as caught:
                module.derive_expert_review_report(
                    source_dir=source,
                    sessions_dir=sessions,
                    review_set_path=set_path,
                    archive_path=archive,
                    output_dir=existing,
                )
            self.assertEqual(str(caught.exception.code), "OUTPUT_TARGET_INVALID")
            self.assertEqual(sorted(existing.iterdir()), [])  # nothing written


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
