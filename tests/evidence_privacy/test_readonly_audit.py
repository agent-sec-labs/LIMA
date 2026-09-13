"""Frozen acceptance tests v3 for the IP-0020 read-only audit contract.

Anchors (per Packet IP-0020 v1.2 erratum, DR-IP-0020-4R, 2026-09-13):
FR-N05-06, NFR-N05-04 (audit side), AC/T-N05-06, §8.2/§8.3 as revised by
Packet §17 (D1'/D2'/D3'/B2'/F5'), §9 T2/T3/T4/T5 as revised by §17/§18.
Every revised/new assertion carries a DR-IP-0020-4R anchor comment
(D1'/D2'/D3'/B2'/F5'); mapping table = Packet §18 (revision, not deletion).
Dual-runner safe: unittest.TestCase only, no pytest API (PI-DR6-bis).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile
import unittest

from lima.evidence_privacy.audit import (
    AuditFinding,
    AuditLocation,
    AuditReport,
    audit_report_to_json,
    audit_structured,
    audit_text,
    build_audit_report,
)
from lima.evidence_privacy.content_scan import find_base64_spans, is_bare_base64_secret
from lima.evidence_privacy.errors import PrivacyError, PrivacyErrorCode
from lima.evidence_privacy.models import TenantPolicy

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests" / "evidence_privacy" / "fixtures" / "audit_samples"
SCRIPT_PATH = REPO_ROOT / "scripts" / "audit_sensitive_artifacts.py"

# §8.3.8 v1.1 (F-1) offline tenant id is retained as the fixed *identifier*
# (not a credential); the fixed tenant KEY constant is gone per DR-IP-0020-4R
# D3' (per-run random key, red line 4: no fixed-key reflow).
OFFLINE_TENANT_ID = "offline-audit"
# D3': the report self-labels the per-run random fingerprint domain.
TENANT_CONTEXT_VALUE = "offline-audit/random-per-run"

# §11.2: known sensitive values, restated from the fixture header comments.
KNOWN_SECRET_VALUES = [  # noqa: S105 - synthetic IP-0020 audit fixture values
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMg==",
    "c2VjcmV0LXRva2VuLWZvci1kZWVwLWxldmVsLXRlc3QtMTIzNDU2Nzg5MGFi",
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
    "https://svc-usr:SapphoWren42@db-host.internal.svc/backup",
]
# The token embedded in the Unicode-mixed traceback line of log_excerpt.txt.
UNICODE_MIXED_TOKEN = "w7nDvcOtLXRva2VuLWZvci11bmljb2RlLXRlc3Q"  # noqa: S105 - synthetic fixture token
# D1'.2: value #3 doubles as a *key name* inside secret_keyname.json; value #1
# doubles as a *file name* (the QUJD...==.json fixture). Same plaintext, new
# carrier surfaces that must stay value-free.
KEYNAME_SECRET = KNOWN_SECRET_VALUES[2]  # noqa: S105 - synthetic fixture key name
FILENAME_SECRET_VALUE = KNOWN_SECRET_VALUES[0]  # noqa: S105 - synthetic fixture file name
SECRET_FILENAME = FILENAME_SECRET_VALUE + ".json"
# D1'.2: every scanned fixture file name is a forbidden identifier in all
# report/stderr carrier surfaces (source_path is artifact-indexed a<n>).
SCANNED_FILE_NAMES = [
    SECRET_FILENAME,
    "broken.json",
    "clean_note.txt",
    "log_excerpt.txt",
    "sample.json",
    "secret_keyname.json",
]
# D2': canonical member-index path grammar (Packet §17.D1'.1).
ORDINAL_PATH_RE = re.compile(r"^(?:m\d+|\[\d+\])(?:\.m\d+|\[\d+\])*$")
# D3': fingerprint form = compute_fingerprint frozen output (32 lowercase hex).
FINGERPRINT_RE = re.compile(r"^[0-9a-f]{32}$")

LOG_TEXT = (FIXTURE_DIR / "log_excerpt.txt").read_text(encoding="utf-8")
SAMPLE_STRUCT = json.loads((FIXTURE_DIR / "sample.json").read_text(encoding="utf-8"))
KEYNAME_STRUCT = json.loads((FIXTURE_DIR / "secret_keyname.json").read_text(encoding="utf-8"))
POLICY = TenantPolicy(policy_version="v1")


def make_context(tenant_id: str = "t-a", tenant_key: bytes = b"k-a" * 16):
    """D2': build a TenantAuditContext (sole tenant entry for audit calls)."""
    from lima.evidence_privacy.audit import TenantAuditContext

    return TenantAuditContext(tenant_id=tenant_id, tenant_key=tenant_key)


def forbidden_substrings() -> list[str]:
    """AC/T-N05-06 + D1'.2: every known value plus all its >=4-char substrings."""
    values = KNOWN_SECRET_VALUES + [UNICODE_MIXED_TOKEN]
    substrings: list[str] = []
    for value in values:
        substrings.append(value)
        substrings.extend(value[i : i + 4] for i in range(len(value) - 3))
    return substrings


def assert_zero_secret(testcase: unittest.TestCase, output: str, label: str) -> None:
    # AC/T-N05-06 §8.3.5: outputs must not contain any known value or any
    # >=4-character substring of it.
    for forbidden in forbidden_substrings():
        testcase.assertNotIn(forbidden, output, f"{label} leaked forbidden substring")


def assert_zero_identifier(testcase: unittest.TestCase, output: str, label: str) -> None:
    # D1'.2 (DR-IP-0020-4R): carrier surfaces carry zero plaintext key names
    # and zero file names -- source paths are artifact indices (a<n>) and
    # structured field paths are member indices (m<n>/[n]).
    testcase.assertNotIn(KEYNAME_SECRET, output, f"{label} leaked plaintext key name")
    for name in SCANNED_FILE_NAMES:
        testcase.assertNotIn(name, output, f"{label} leaked file name {name!r}")


def collect_key_values(node: object, key: str) -> list:
    """Recursively collect every value stored under ``key`` in a JSON tree."""
    found: list = []
    if isinstance(node, dict):
        for name, value in node.items():
            if name == key:
                found.append(value)
            found.extend(collect_key_values(value, key))
    elif isinstance(node, list):
        for item in node:
            found.extend(collect_key_values(item, key))
    return found


def fixture_state() -> dict[str, tuple[str, int]]:
    # §9 T3: per-file (sha256, integer mtime) of the fixture directory.
    state: dict[str, tuple[str, int]] = {}
    for path in sorted(FIXTURE_DIR.iterdir()):
        if path.is_file():
            data = path.read_bytes()
            state[path.name] = (
                hashlib.sha256(data).hexdigest(),
                int(path.stat().st_mtime),
            )
    return state


def artifact_ids(directory: pathlib.Path) -> dict[str, str]:
    """D1'.2: expected artifact index a<n> per file name (lexicographic order
    over suffix-matching, non-symlink files -- the frozen numbering rule)."""
    names = sorted(
        path.name
        for path in directory.iterdir()
        if not path.is_symlink() and path.is_file() and path.suffix in {".json", ".txt"}
    )
    return {name: f"a{index}" for index, name in enumerate(names)}


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    # §8.3 CLI form: ``python scripts/audit_sensitive_artifacts.py ...`` from
    # the worktree root; PYTHONPATH pins the repo root so the script's
    # sys.path (script dir) can still resolve ``lima`` under both runners.
    env = dict(os.environ)
    existing = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{REPO_ROOT}{os.pathsep}{existing}" if existing else str(REPO_ROOT)
    return subprocess.run(  # noqa: S603 - frozen repo script, argv pinned by tests
        [sys.executable, str(SCRIPT_PATH), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(REPO_ROOT),
        env=env,
        timeout=120,
    )


class FixtureSelfCheckTests(unittest.TestCase):
    """§11.2 + D1'.2: fixture header values and in-test constants must agree."""

    def test_known_values_present_in_fixtures(self) -> None:
        # §11.2: the restated constants actually occur in the fixtures
        # (self-check that the grep denial list matches fixture content).
        decoded = ""
        for name in (
            "sample.json",
            "log_excerpt.txt",
            "secret_keyname.json",
            SECRET_FILENAME,
        ):
            decoded += (FIXTURE_DIR / name).read_bytes().decode("utf-8")
        for value in KNOWN_SECRET_VALUES + [UNICODE_MIXED_TOKEN]:
            self.assertIn(value, decoded)
        # D1'.2: the key-name sample really carries the secret as a *key*, and
        # the secret file-name fixture really exists on disk.
        self.assertIn(KEYNAME_SECRET, KEYNAME_STRUCT)
        self.assertTrue((FIXTURE_DIR / SECRET_FILENAME).is_file())


class AuditTextTests(unittest.TestCase):
    """FR-N05-06 §8.2.4: text scanning via base64 span predicates (§18 #11)."""

    def test_audit_text_finds_spans_with_locations(self) -> None:
        # FR-N05-06 §8.2.2/§8.2.4: findings carry AuditLocation with
        # source_path, field_path None for text, and half-open spans that
        # point at predicate-satisfying base64 spans. D2' §18 #11: context
        # call form (old keyword-only tenant_id=/tenant_key= removed).
        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        self.assertGreaterEqual(len(findings), 3)
        for finding in findings:
            self.assertIsInstance(finding.location, AuditLocation)
            self.assertEqual(finding.location.source_path, "log_excerpt.txt")
            self.assertIsNone(finding.location.field_path)
            start, end = finding.location.span
            self.assertGreaterEqual(start, 0)
            self.assertLess(start, end)
            self.assertEqual(finding.length, end - start)
            self.assertEqual(finding.value_kind, "string")
            # The span text must itself satisfy the frozen predicate.
            self.assertTrue(is_bare_base64_secret(LOG_TEXT[start:end]))

    def test_audit_text_findings_match_find_base64_spans(self) -> None:
        # §8.2.4: text detection consumes find_base64_spans semantics.
        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        spans = {finding.location.span for finding in findings}
        expected = {
            span
            for span in find_base64_spans(LOG_TEXT)
            if is_bare_base64_secret(LOG_TEXT[span[0] : span[1]])
        }
        self.assertEqual(spans, expected)

    def test_audit_text_old_keyword_signature_rejected(self) -> None:
        # D2' §18 #11: tenant_id=/tenant_key= keyword calls are removed --
        # the context object is the sole tenant entry (signature-level
        # enforcement, no bypass).
        with self.assertRaises(TypeError):
            audit_text(
                "log_excerpt.txt",
                LOG_TEXT,
                POLICY,
                tenant_id="t-a",
                tenant_key=b"k-a" * 16,
            )


class AuditStructuredTests(unittest.TestCase):
    """FR-N05-06 §8.2.4 + NFR-N05-04 + D1': ordinal member-index paths."""

    def test_audit_structured_uses_ordinal_field_paths(self) -> None:
        # D1' §18 #1: field_path is a member-index path (m<n> object members
        # in document order, [n] array elements); deep/whole-value behaviour
        # is preserved (deep multi-segment paths exist; whole-value candidates
        # use span (0, len)). Plaintext key names never appear.
        findings = audit_structured("sample.json", SAMPLE_STRUCT, POLICY, context=make_context())
        paths = {finding.location.field_path for finding in findings}
        deep = [p for p in paths if p is not None and p.count(".") + p.count("[") >= 2]
        self.assertTrue(deep, f"missing deep ordinal field_path in {paths}")
        for path in paths:
            if path is not None:
                self.assertRegex(path, ORDINAL_PATH_RE)
                for name in ("entries", "nested", "deep", "auth", "token"):
                    self.assertNotIn(name, path)
        whole = [f for f in findings if f.location.span == (0, f.length)]
        self.assertTrue(whole)

    def test_audit_structured_key_name_never_carried(self) -> None:
        # D1'/D1'.2 §18 #2: a fixture whose *key* is a known secret still
        # produces findings, but no carrier surface (field_path, repr) ever
        # contains the plaintext key name.
        findings = audit_structured(
            "secret_keyname.json", KEYNAME_STRUCT, POLICY, context=make_context()
        )
        self.assertTrue(findings)
        for finding in findings:
            if finding.location.field_path is not None:
                self.assertRegex(finding.location.field_path, ORDINAL_PATH_RE)
            rendered = repr(finding) + json.dumps(dataclasses.asdict(finding), default=str)
            self.assertNotIn(KEYNAME_SECRET, rendered)
            assert_zero_secret(self, rendered, "finding repr/key-name surface")

    def test_audit_structured_scalar_root_field_path_none(self) -> None:
        # D1' §17.D1'.1: scalar roots (str/int/bool/null) have field_path=None
        # and are located by span alone (text-mode parity).
        findings = audit_structured(
            "scalar.txt", KNOWN_SECRET_VALUES[0], POLICY, context=make_context()
        )
        self.assertTrue(findings)
        self.assertIsNone(findings[0].location.field_path)

    def test_audit_structured_does_not_mutate_input(self) -> None:
        # NFR-N05-04: auditing never rewrites the audited object.
        import copy

        snapshot = copy.deepcopy(SAMPLE_STRUCT)
        audit_structured("sample.json", SAMPLE_STRUCT, POLICY, context=make_context())
        self.assertEqual(SAMPLE_STRUCT, snapshot)


class ValueFreeTests(unittest.TestCase):
    """AC/T-N05-06 §8.2.3 + §9 T2 + D1'.2: value-free carrier surfaces."""

    def test_finding_repr_and_fields_zero_secret(self) -> None:
        # §8.2.3/§9 T2 (§18 #2): no preview attribute; repr carries no values
        # and no key names.
        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        self.assertTrue(findings)
        names = {f.name for f in dataclasses.fields(AuditFinding)}
        # D2' §18 #4: _tenant_tag is the one sanctioned internal field.
        self.assertEqual(names, {"location", "fingerprint", "value_kind", "length", "_tenant_tag"})
        for finding in findings:
            self.assertFalse(hasattr(finding, "preview"))
            rendered = repr(finding)
            assert_zero_secret(self, rendered, "finding repr")
            assert_zero_identifier(self, rendered, "finding repr")

    def test_report_json_zero_secret_and_parseable(self) -> None:
        # §8.2.3/AC/T-N05-06 + D1'.2 §18 #2: canonical JSON output parses and
        # leaks neither values nor key names nor file names.
        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        report = build_audit_report(make_context(), {"log_excerpt.txt": findings}, POLICY)
        payload = audit_report_to_json(report)
        assert_zero_secret(self, payload, "report json")
        assert_zero_identifier(self, payload, "report json")
        json.loads(payload)

    def test_report_field_set_whitelist(self) -> None:
        # §8.2.2/§9 T4 + D2'/F5' §18 #3: AuditReport fields are the frozen
        # whitelist plus status/incomplete_reasons; still zero tenant fields.
        names = {f.name for f in dataclasses.fields(AuditReport)}
        self.assertEqual(
            names,
            {
                "policy_version",
                "policy_digest",
                "findings",
                "artifact_count",
                "recommended_action",
                "status",
                "incomplete_reasons",
            },
        )


class TenantContextTests(unittest.TestCase):
    """D2' §17.D2': TenantAuditContext construction and report binding."""

    def test_context_rejects_empty_or_invalid_tenant_key(self) -> None:
        # D2': fail-closed constructor validation, reusing existing codes.
        for bad_key in (b"", "not-bytes", None):
            with self.subTest(bad_key=bad_key):
                with self.assertRaises(PrivacyError) as ctx:
                    make_context(tenant_key=bad_key)
                self.assertIs(ctx.exception.code, PrivacyErrorCode.MISSING_TENANT_KEY)
                self.assertEqual(ctx.exception.field_path, "tenant_key")

    def test_context_rejects_invalid_tenant_id(self) -> None:
        # D2': tenant_id empty/non-str/over-128-UTF-8-bytes -> INVALID_FIELD_VALUE.
        for bad_id in ("", 123, "x" * 129):
            with self.subTest(bad_id=bad_id):
                with self.assertRaises(PrivacyError) as ctx:
                    make_context(tenant_id=bad_id)
                self.assertIs(ctx.exception.code, PrivacyErrorCode.INVALID_FIELD_VALUE)
                self.assertEqual(ctx.exception.field_path, "tenant_id")

    def test_internal_tenant_tag_never_rendered(self) -> None:
        # D2' §18 #4: _tenant_tag is repr-excluded AND serialization-excluded
        # (double leak prevention); it never appears in repr or report JSON.
        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        self.assertTrue(findings)
        tag = getattr(findings[0], "_tenant_tag", None)
        self.assertIsInstance(tag, str)
        self.assertRegex(tag, r"^[0-9a-f]{64}$")
        rendered = "".join(repr(f) for f in findings)
        self.assertNotIn(tag, rendered)
        report = build_audit_report(make_context(), {"log_excerpt.txt": findings}, POLICY)
        payload = audit_report_to_json(report)
        self.assertNotIn(tag, payload)
        self.assertNotIn("_tenant_tag", payload)
        self.assertNotIn("tenant_tag", payload)

    def test_mixed_tenant_findings_rejected(self) -> None:
        # D2' §18 #4: aggregating findings from two different tenants into one
        # report must fail closed with POLICY_ERROR at report.tenant_mixing.
        context_a = make_context("t-a", b"k-a" * 16)
        context_b = make_context("t-b", b"k-b" * 16)
        findings_a = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=context_a)
        findings_b = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=context_b)
        self.assertTrue(findings_a and findings_b)
        with self.assertRaises(PrivacyError) as ctx:
            build_audit_report(context_a, {"mixed": findings_a + findings_b}, POLICY)
        self.assertIs(ctx.exception.code, PrivacyErrorCode.POLICY_ERROR)
        self.assertEqual(ctx.exception.field_path, "report.tenant_mixing")
        self.assertIn("distinct_tenant_tags", ctx.exception.context)

    def test_zero_finding_batch_still_binds_context(self) -> None:
        # D2' §17.D2': an empty findings mapping still executes context
        # validation (zero-finding batches covered); an invalid context is
        # rejected even with nothing to aggregate.
        report = build_audit_report(make_context(), {}, POLICY)
        self.assertEqual(report.artifact_count, 0)
        with self.assertRaises(PrivacyError) as ctx:
            build_audit_report(make_context(tenant_key=b""), {}, POLICY)
        self.assertIs(ctx.exception.code, PrivacyErrorCode.MISSING_TENANT_KEY)

    def test_build_audit_report_old_signature_rejected(self) -> None:
        # D2' §18 #11: the old positional (findings, policy) form is removed;
        # context is the first parameter.
        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        with self.assertRaises(TypeError):
            build_audit_report({"log_excerpt.txt": findings}, POLICY)


class TenantIsolationTests(unittest.TestCase):
    """§9 T4 (§18 #4): fingerprint tenant isolation and same-tenant stability."""

    def test_different_tenant_key_changes_all_fingerprints(self) -> None:
        # §9 T4: same input, different tenant_key -> every fingerprint
        # changes while positions stay identical.
        first = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, context=make_context("t-a", b"k-a" * 16)
        )
        second = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, context=make_context("t-b", b"k-b" * 16)
        )
        self.assertEqual([f.location for f in first], [f.location for f in second])
        self.assertNotEqual([f.fingerprint for f in first], [f.fingerprint for f in second])

    def test_same_tenant_key_fingerprint_stable(self) -> None:
        # §9 T4: same credentials -> identical fingerprints on repeat calls.
        first = audit_structured(
            "sample.json", SAMPLE_STRUCT, POLICY, context=make_context("t-a", b"k-a" * 16)
        )
        second = audit_structured(
            "sample.json", SAMPLE_STRUCT, POLICY, context=make_context("t-a", b"k-a" * 16)
        )
        self.assertEqual([f.fingerprint for f in first], [f.fingerprint for f in second])


class BudgetLimitTests(unittest.TestCase):
    """F5' §17.F5': library-level typed budget rejection."""

    def test_deeply_nested_value_raises_typed_depth_error(self) -> None:
        # F5' §18 #14: depth > PrivacyLimits().max_depth (32) must raise a
        # typed MAX_DEPTH_EXCEEDED PrivacyError (context carries depth and
        # max_depth), never a bare RecursionError.
        nested: dict = {}
        cursor = nested
        for _ in range(40):
            cursor["child"] = {}
            cursor = cursor["child"]
        cursor["child"] = KNOWN_SECRET_VALUES[0]
        with self.assertRaises(PrivacyError) as ctx:
            audit_structured("deep.json", nested, POLICY, context=make_context())
        self.assertIs(ctx.exception.code, PrivacyErrorCode.MAX_DEPTH_EXCEEDED)
        context = ctx.exception.context
        self.assertEqual(context.get("max_depth"), 32)
        self.assertGreater(context.get("depth", 0), 32)

    def test_too_many_findings_raises_typed_items_error(self) -> None:
        # F5' §17.F5': findings count > max_items (10_000) must raise a typed
        # RESOURCE_LIMIT_EXCEEDED error with field_path "findings".
        payload = [KNOWN_SECRET_VALUES[0]] * 10_001
        with self.assertRaises(PrivacyError) as ctx:
            audit_structured("many.json", payload, POLICY, context=make_context())
        self.assertIs(ctx.exception.code, PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED)
        self.assertEqual(ctx.exception.field_path, "findings")
        self.assertEqual(ctx.exception.context.get("max_items"), 10_000)


class ReportPolicyEvidenceTests(unittest.TestCase):
    """NFR-N05-04 audit side §8.2.5/§8.2.6."""

    def test_report_embeds_policy_evidence_and_constant_action(self) -> None:
        # §8.2.5: policy_version + policy_digest embedded; §8.2.6:
        # recommended_action is the frozen constant string.
        from lima.evidence_privacy.policy import policy_digest

        findings = audit_text("log_excerpt.txt", LOG_TEXT, POLICY, context=make_context())
        report = build_audit_report(make_context(), {"log_excerpt.txt": findings}, POLICY)
        self.assertEqual(report.policy_version, POLICY.policy_version)
        self.assertEqual(report.policy_digest, policy_digest(POLICY))
        self.assertEqual(report.recommended_action, "manual-review-and-approved-migration-issue")
        self.assertEqual(report.artifact_count, 1)


class AuditModuleHygieneTests(unittest.TestCase):
    """§8.2.1 + §9 T5: audit module purity and no vault reference."""

    def test_audit_module_does_not_reference_vault_port(self) -> None:
        # §8.2.1/§9 T5: audit.py must not import or mention the vault port.
        import lima.evidence_privacy.audit as audit_module

        source = pathlib.Path(audit_module.__file__).read_text(encoding="utf-8")
        self.assertNotIn("vault", source.lower())

    def test_audit_module_no_io_or_subprocess_imports(self) -> None:
        # §8.2.1: pure-function discipline -- no IO/network/subprocess.
        import lima.evidence_privacy.audit as audit_module

        source = pathlib.Path(audit_module.__file__).read_text(encoding="utf-8")
        for forbidden in ("subprocess", "socket", "os.remove", "shutil", "open("):
            self.assertNotIn(forbidden, source)


class AuditScriptSubprocessTests(unittest.TestCase):
    """§8.3 + §9 T2/T3/T4/T5 as revised by §17 (D1'.2/D3'/F5'/B2')."""

    def test_script_report_value_and_identifier_free(self) -> None:
        # §8.3.3/§8.3.5 + D1'.2 §18 #2: stdout report and stderr carry zero
        # secret values, zero key names, zero file names.
        result = run_script(str(FIXTURE_DIR))
        report = json.loads(result.stdout)
        self.assertIsInstance(report, dict)
        assert_zero_secret(self, result.stdout, "script stdout")
        assert_zero_secret(self, result.stderr, "script stderr")
        assert_zero_identifier(self, result.stdout, "script stdout")
        assert_zero_identifier(self, result.stderr, "script stderr")
        # D1'.2: every source_path is an artifact index a<n>.
        source_paths = [str(p) for p in collect_key_values(report, "source_path")]
        self.assertTrue(source_paths)
        for path in source_paths:
            self.assertRegex(path, r"^a\d+$")
        # NFR-N05-04: policy evidence keys present at top level.
        self.assertIn("policy_version", report)
        self.assertIn("policy_digest", report)

    def test_script_incomplete_exit_when_skips_occur(self) -> None:
        # F5' §18 #10: the fixture directory contains broken.json (an
        # unparseable-json skip), so the run is INCOMPLETE: exit code 3,
        # status "incomplete", non-empty incomplete_reasons. Exit 3 is the
        # normal completed-with-gaps path, not an error exit.
        result = run_script(str(FIXTURE_DIR))
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report.get("status"), "incomplete")
        self.assertTrue(report.get("incomplete_reasons"))

    def test_script_complete_exit_on_clean_directory(self) -> None:
        # F5' §18 #10: a directory with no skips completes: exit 0,
        # status "complete", empty incomplete_reasons.
        with tempfile.TemporaryDirectory() as tmp:
            clean = pathlib.Path(tmp)
            (clean / "clean.txt").write_text("nothing sensitive here\n", encoding="utf-8")
            result = run_script(str(clean))
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "complete")
            self.assertEqual(report.get("incomplete_reasons"), [])

    def test_script_tenant_context_random_per_run(self) -> None:
        # D3' §18 #5: the report self-labels the per-run random fingerprint
        # domain with the frozen tenant_context value.
        result = run_script(str(FIXTURE_DIR))
        report = json.loads(result.stdout)
        self.assertEqual(report.get("tenant_context"), TENANT_CONTEXT_VALUE)

    def test_script_fingerprints_dedupe_within_run(self) -> None:
        # D3' §18 #6: within one run, equal values produce equal
        # fingerprints (dedupe semantics preserved under per-run keys); the
        # known value QUJD... appears in several fixtures, so some
        # fingerprint repeats; fingerprints keep the frozen 32-hex form.
        result = run_script(str(FIXTURE_DIR))
        report = json.loads(result.stdout)
        fingerprints = [str(fp) for fp in collect_key_values(report, "fingerprint")]
        self.assertTrue(fingerprints)
        for fingerprint in fingerprints:
            self.assertRegex(fingerprint, FINGERPRINT_RE)
        counts: dict[str, int] = {}
        for fingerprint in fingerprints:
            counts[fingerprint] = counts.get(fingerprint, 0) + 1
        self.assertGreaterEqual(max(counts.values()), 2, "same-run dedupe broken")
        self.assertGreater(len(counts), 1)

    def test_script_fingerprints_differ_across_runs(self) -> None:
        # D3' §18 #6 (negative, RED on c5b375e): each run uses an independent
        # random key, so two runs over the same fixture directory must yield
        # different fingerprint sets (cross-run comparison is unsupported).
        first = run_script(str(FIXTURE_DIR))
        second = run_script(str(FIXTURE_DIR))
        fp_first = sorted(
            str(fp) for fp in collect_key_values(json.loads(first.stdout), "fingerprint")
        )
        fp_second = sorted(
            str(fp) for fp in collect_key_values(json.loads(second.stdout), "fingerprint")
        )
        self.assertNotEqual(
            fp_first, fp_second, "cross-run fingerprint stability implies a fixed key"
        )

    def test_script_leaves_fixtures_untouched(self) -> None:
        # §8.3.4/§9 T3 (§18 #9): sha256 and mtime (>=1s precision, §11.5)
        # unchanged.
        before = fixture_state()
        result = run_script(str(FIXTURE_DIR))
        self.assertIn(result.returncode, (0, 3), result.stderr)
        self.assertEqual(fixture_state(), before)

    def test_script_output_to_report_file_outside_dir(self) -> None:
        # §8.3.3: --output to an explicit external path writes the report;
        # fixture directory gains no files; report file leaks nothing.
        before = fixture_state()
        with tempfile.TemporaryDirectory() as tmp:
            report_path = pathlib.Path(tmp) / "report.json"
            result = run_script(str(FIXTURE_DIR), "--output", str(report_path))
            self.assertIn(result.returncode, (0, 3), result.stderr)
            self.assertTrue(report_path.is_file())
            content = report_path.read_text(encoding="utf-8")
            assert_zero_secret(self, content, "report file")
            assert_zero_identifier(self, content, "report file")
            report = json.loads(content)
            self.assertEqual(report.get("tenant_context"), TENANT_CONTEXT_VALUE)
        self.assertEqual(fixture_state(), before)

    def test_script_output_inside_target_dir_rejected(self) -> None:
        # §8.3.3/§9 T3: --output inside <target-dir> is a parameter error;
        # variants must be resolved (§11.5) and all rejected non-zero.
        # §11.5 rev. DR-IP-0020-2: cross-platform real-inside variants are
        # built with os.sep and asserted on every platform; Windows-specific
        # separator and case variants are asserted on Windows only.
        variants = [
            FIXTURE_DIR / "report.json",
            pathlib.Path(str(FIXTURE_DIR) + "/sub/../report.json"),
            pathlib.Path(
                str(FIXTURE_DIR) + os.sep + "nested" + os.sep + ".." + os.sep + "report.json"
            ),
            pathlib.Path(
                str(FIXTURE_DIR)
                + os.sep
                + "sub"
                + os.sep
                + ".."
                + os.sep
                + ".."
                + os.sep
                + "audit_samples"
                + os.sep
                + "report.json"
            ),
        ]
        if sys.platform == "win32" and os.sep == "\\":
            variants += [
                pathlib.Path(str(FIXTURE_DIR) + "\\nested\\..\\report.json"),
                pathlib.Path(str(FIXTURE_DIR).replace("audit_samples", "Audit_Samples"))
                / "report.json",
            ]
        before = fixture_state()
        for variant in variants:
            with self.subTest(variant=str(variant)):
                result = run_script(str(FIXTURE_DIR), "--output", str(variant))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((FIXTURE_DIR / "report.json").exists())
                assert_zero_secret(self, result.stdout + result.stderr, "reject output")
        self.assertEqual(fixture_state(), before)

    def test_script_skips_broken_json_with_artifact_warning(self) -> None:
        # D1'.2/F5' §18 #13: unparseable JSON is skipped with an a<n>-indexed
        # stderr warning; no file name ever appears on stderr; the run exits
        # 3 with status incomplete; the skipped artifact contributes nothing.
        ids = artifact_ids(FIXTURE_DIR)
        result = run_script(str(FIXTURE_DIR))
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn("unparseable-json", result.stderr)
        expected = json.dumps({"artifact": ids["broken.json"], "error": "unparseable-json"})
        self.assertIn(expected, result.stderr)
        assert_zero_identifier(self, result.stderr, "skip warning")
        report = json.loads(result.stdout)
        self.assertEqual(report.get("status"), "incomplete")
        self.assertIn(
            f"{ids['broken.json']}:unparseable-json",
            report.get("incomplete_reasons", []),
        )

    def test_script_missing_target_dir_rejected(self) -> None:
        # §8.3.3: a non-directory target is a parameter error (exit 2).
        result = run_script(str(pathlib.Path(tempfile.gettempdir()) / "no-such-ip0020-dir"))
        self.assertEqual(result.returncode, 2)

    def test_script_dependency_whitelist(self) -> None:
        # §8.3.6/§9 T5: only stdlib + lima.evidence_privacy.{audit,
        # content_scan}; no vault / network / DB references; B2' §18 #8:
        # symlink-safe traversal primitives present; D3' red line 4: no fixed
        # tenant key constant reflow; T3: no destructive calls.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("vault", source.lower())
        for forbidden in (
            "requests",
            "urllib",
            "socket",
            "psycopg",
            "sqlite3",
            "shell=True",
            "eval(",
            "exec(",
            "lima-offline-audit.v1",
            "shutil",
            "os.remove",
            "unlink",
            "rename",
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("lima.evidence_privacy.audit", source)
        # B2': scandir-based traversal, symlink detection, POSIX O_NOFOLLOW.
        self.assertIn("scandir", source)
        self.assertIn("is_symlink", source)
        self.assertIn("O_NOFOLLOW", source)
        # D3': per-run random key from the secrets module.
        self.assertIn("secrets", source)

    def test_script_oversize_file_identifiably_skipped(self) -> None:
        # F5' §17.F5' (negative, RED on c5b375e): a file over
        # max_payload_bytes (1 MiB) is identifiably skipped -- stderr
        # resource-limit warning on its artifact index, status incomplete,
        # exit 3. Never a silent skip or a "clean scan" impression.
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "big.txt").write_text("x" * (1_048_576 + 1), encoding="utf-8")
            ids = artifact_ids(target)
            result = run_script(str(target))
            self.assertEqual(result.returncode, 3, result.stderr)
            expected = json.dumps({"artifact": ids["big.txt"], "error": "resource-limit"})
            self.assertIn(expected, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "incomplete")
            self.assertIn(
                f"{ids['big.txt']}:resource-limit",
                report.get("incomplete_reasons", []),
            )


class SymlinkBoundaryTests(unittest.TestCase):
    """B2' §17.B2': symlink traversal and read boundary."""

    def _make_symlink(self, link: pathlib.Path, target: pathlib.Path) -> None:
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover
            self.skipTest(f"symlink creation unavailable on this platform ({exc})")

    def test_symlinked_file_skipped_and_external_target_unread(self) -> None:
        # B2' (Linux CI authoritative; Windows conditional): a symlink inside
        # the target directory pointing at an outside file is skipped with a
        # symlink-skipped warning; the outside content never reaches any
        # output; the run is incomplete.
        with tempfile.TemporaryDirectory() as scan_tmp, tempfile.TemporaryDirectory() as out_tmp:
            target = pathlib.Path(scan_tmp)
            outside = pathlib.Path(out_tmp) / "outside.txt"
            outside.write_text("external bearer " + KNOWN_SECRET_VALUES[1] + "\n", encoding="utf-8")
            (target / "inside.txt").write_text("plain internal note\n", encoding="utf-8")
            self._make_symlink(target / "link.txt", outside)
            ids = artifact_ids(target)
            result = run_script(str(target))
            self.assertEqual(result.returncode, 3, result.stderr)
            expected = json.dumps({"artifact": ids["link.txt"], "error": "symlink-skipped"})
            self.assertIn(expected, result.stderr)
            assert_zero_secret(self, result.stdout + result.stderr, "symlink scan")
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "incomplete")

    def test_target_dir_symlink_rejected(self) -> None:
        # B2': a target directory that is itself a symlink (or resolves
        # through one) is a parameter error -- exit 2.
        with tempfile.TemporaryDirectory() as scan_tmp, tempfile.TemporaryDirectory() as out_tmp:
            real = pathlib.Path(scan_tmp)
            (real / "inside.txt").write_text("plain internal note\n", encoding="utf-8")
            link_dir = pathlib.Path(out_tmp) / "linkdir"
            self._make_symlink(link_dir, real)
            result = run_script(str(link_dir))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("target-dir must not be a symlink path", result.stderr)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
