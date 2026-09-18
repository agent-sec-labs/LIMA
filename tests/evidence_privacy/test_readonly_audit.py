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
import traceback
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


def run_script(*args: str, timeout: int = 120) -> subprocess.CompletedProcess[str]:
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
        timeout=timeout,
    )


IS_WINDOWS_PLATFORM = sys.platform == "win32"
PLATFORM_UNSUPPORTED_MSG = "platform-unsupported-safe-scan"


def posix_script_or_fail_closed(testcase, result) -> bool:
    """R10 §17.B2'-R10: on Windows the script must refuse to run (exit 2,
    single stderr line, no report output); POSIX continues to behavior."""
    if not IS_WINDOWS_PLATFORM:
        return True
    testcase.assertEqual(result.returncode, 2, result.stderr)
    testcase.assertIn(PLATFORM_UNSUPPORTED_MSG, result.stderr)
    testcase.assertEqual(result.stdout.strip(), "")
    return False


def posix_main_or_fail_closed(testcase, code, err) -> bool:
    """R10 in-process variant of posix_script_or_fail_closed."""
    if not IS_WINDOWS_PLATFORM:
        return True
    testcase.assertEqual(code, 2, err)
    testcase.assertIn(PLATFORM_UNSUPPORTED_MSG, err)
    return False


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
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
        self.assertGreaterEqual(len(findings), 3)
        for finding in findings:
            self.assertIsInstance(finding.location, AuditLocation)
            self.assertEqual(finding.location.source_path, "a0")
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
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
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
        findings = audit_structured("a1", SAMPLE_STRUCT, POLICY, context=make_context())
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
        findings = audit_structured("a2", KEYNAME_STRUCT, POLICY, context=make_context())
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
        findings = audit_structured("a3", KNOWN_SECRET_VALUES[0], POLICY, context=make_context())
        self.assertTrue(findings)
        self.assertIsNone(findings[0].location.field_path)

    def test_audit_structured_does_not_mutate_input(self) -> None:
        # NFR-N05-04: auditing never rewrites the audited object.
        import copy

        snapshot = copy.deepcopy(SAMPLE_STRUCT)
        audit_structured("a1", SAMPLE_STRUCT, POLICY, context=make_context())
        self.assertEqual(SAMPLE_STRUCT, snapshot)


class ValueFreeTests(unittest.TestCase):
    """AC/T-N05-06 §8.2.3 + §9 T2 + D1'.2: value-free carrier surfaces."""

    def test_finding_repr_and_fields_zero_secret(self) -> None:
        # §8.2.3/§9 T2 (§18 #2): no preview attribute; repr carries no values
        # and no key names.
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
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
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
        report = build_audit_report(make_context(), {"a0": findings}, POLICY)
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
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
        self.assertTrue(findings)
        tag = getattr(findings[0], "_tenant_tag", None)
        self.assertIsInstance(tag, str)
        self.assertRegex(tag, r"^[0-9a-f]{64}$")
        rendered = "".join(repr(f) for f in findings)
        self.assertNotIn(tag, rendered)
        report = build_audit_report(make_context(), {"a0": findings}, POLICY)
        payload = audit_report_to_json(report)
        self.assertNotIn(tag, payload)
        self.assertNotIn("_tenant_tag", payload)
        self.assertNotIn("tenant_tag", payload)

    def test_mixed_tenant_findings_rejected(self) -> None:
        # D2' §18 #4: aggregating findings from two different tenants into one
        # report must fail closed with POLICY_ERROR at report.tenant_mixing.
        context_a = make_context("t-a", b"k-a" * 16)
        context_b = make_context("t-b", b"k-b" * 16)
        findings_a = audit_text("a0", LOG_TEXT, POLICY, context=context_a)
        findings_b = audit_text("a0", LOG_TEXT, POLICY, context=context_b)
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
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
        with self.assertRaises(TypeError):
            build_audit_report({"a0": findings}, POLICY)


class TenantIsolationTests(unittest.TestCase):
    """§9 T4 (§18 #4): fingerprint tenant isolation and same-tenant stability."""

    def test_different_tenant_key_changes_all_fingerprints(self) -> None:
        # §9 T4: same input, different tenant_key -> every fingerprint
        # changes while positions stay identical.
        first = audit_text("a0", LOG_TEXT, POLICY, context=make_context("t-a", b"k-a" * 16))
        second = audit_text("a0", LOG_TEXT, POLICY, context=make_context("t-b", b"k-b" * 16))
        self.assertEqual([f.location for f in first], [f.location for f in second])
        self.assertNotEqual([f.fingerprint for f in first], [f.fingerprint for f in second])

    def test_same_tenant_key_fingerprint_stable(self) -> None:
        # §9 T4: same credentials -> identical fingerprints on repeat calls.
        first = audit_structured(
            "a1", SAMPLE_STRUCT, POLICY, context=make_context("t-a", b"k-a" * 16)
        )
        second = audit_structured(
            "a1", SAMPLE_STRUCT, POLICY, context=make_context("t-a", b"k-a" * 16)
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
            audit_structured("a4", nested, POLICY, context=make_context())
        self.assertIs(ctx.exception.code, PrivacyErrorCode.MAX_DEPTH_EXCEEDED)
        context = ctx.exception.context
        self.assertEqual(context.get("max_depth"), 32)
        self.assertGreater(context.get("depth", 0), 32)

    def test_too_many_findings_raises_typed_items_error(self) -> None:
        # F5' §17.F5': findings count > max_items (10_000) must raise a typed
        # RESOURCE_LIMIT_EXCEEDED error with field_path "findings".
        payload = [KNOWN_SECRET_VALUES[0]] * 10_001
        with self.assertRaises(PrivacyError) as ctx:
            audit_structured("a5", payload, POLICY, context=make_context())
        self.assertIs(ctx.exception.code, PrivacyErrorCode.RESOURCE_LIMIT_EXCEEDED)
        self.assertEqual(ctx.exception.field_path, "findings")
        self.assertEqual(ctx.exception.context.get("max_items"), 10_000)


class ReportPolicyEvidenceTests(unittest.TestCase):
    """NFR-N05-04 audit side §8.2.5/§8.2.6."""

    def test_report_embeds_policy_evidence_and_constant_action(self) -> None:
        # §8.2.5: policy_version + policy_digest embedded; §8.2.6:
        # recommended_action is the frozen constant string.
        from lima.evidence_privacy.policy import policy_digest

        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context())
        report = build_audit_report(make_context(), {"a0": findings}, POLICY)
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
        if not posix_script_or_fail_closed(self, result):
            return
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
        if not posix_script_or_fail_closed(self, result):
            return
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
            if not posix_script_or_fail_closed(self, result):
                return

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "complete")
            self.assertEqual(report.get("incomplete_reasons"), [])

    def test_script_tenant_context_random_per_run(self) -> None:
        # D3' §18 #5: the report self-labels the per-run random fingerprint
        # domain with the frozen tenant_context value.
        result = run_script(str(FIXTURE_DIR))
        if not posix_script_or_fail_closed(self, result):
            return
        report = json.loads(result.stdout)
        self.assertEqual(report.get("tenant_context"), TENANT_CONTEXT_VALUE)

    def test_script_fingerprints_dedupe_within_run(self) -> None:
        # D3' §18 #6: within one run, equal values produce equal
        # fingerprints (dedupe semantics preserved under per-run keys); the
        # known value QUJD... appears in several fixtures, so some
        # fingerprint repeats; fingerprints keep the frozen 32-hex form.
        result = run_script(str(FIXTURE_DIR))
        if not posix_script_or_fail_closed(self, result):
            return
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
        if not posix_script_or_fail_closed(self, first):
            return
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
        if not posix_script_or_fail_closed(self, result):
            return
        self.assertIn(result.returncode, (0, 3), result.stderr)
        self.assertEqual(fixture_state(), before)

    def test_script_output_to_report_file_outside_dir(self) -> None:
        # §8.3.3: --output to an explicit external path writes the report;
        # fixture directory gains no files; report file leaks nothing.
        before = fixture_state()
        with tempfile.TemporaryDirectory() as tmp:
            report_path = pathlib.Path(tmp) / "report.json"
            result = run_script(str(FIXTURE_DIR), "--output", str(report_path))
            if not posix_script_or_fail_closed(self, result):
                return

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
        if not posix_script_or_fail_closed(self, result):
            return
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
            if not posix_script_or_fail_closed(self, result):
                return

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
    """B2' §17.B2' + R10: symlink boundary (POSIX) / platform fail-closed (Windows)."""

    def _make_symlink(self, link: pathlib.Path, target: pathlib.Path) -> None:
        try:
            link.symlink_to(target)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover
            self.skipTest(f"symlink creation unavailable on this platform ({exc})")

    def _assert_windows_fail_closed(self, target: pathlib.Path) -> None:
        # R10 §18 #25 (revised from the v1.4 Windows conditional-skip): on
        # Windows the safe-scan capabilities are absent, so the script must
        # refuse to run -- exit 2, single platform-unsupported stderr line,
        # no report output, no report file.
        result = run_script(str(target))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(PLATFORM_UNSUPPORTED_MSG, result.stderr)
        self.assertEqual(result.stdout.strip(), "")

    def test_symlinked_file_skipped_and_external_target_unread(self) -> None:
        # B2' (Linux/POSIX authoritative): a symlink inside the target
        # directory pointing at an outside file is skipped with a
        # symlink-skipped warning; the outside content never reaches any
        # output; the run is incomplete. On Windows the R10 fail-closed
        # branch replaces the v1.4 conditional skip (revision, not deletion).
        if IS_WINDOWS_PLATFORM:
            with tempfile.TemporaryDirectory() as tmp:
                target = pathlib.Path(tmp)
                (target / "inside.txt").write_text("plain\n", encoding="utf-8")
                self._assert_windows_fail_closed(target)
            return
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
        # B2': a target directory that is itself a symlink is a parameter
        # error -- exit 2. On Windows the R10 platform fail-closed branch
        # applies (also exit 2, platform-unsupported message).
        with tempfile.TemporaryDirectory() as scan_tmp, tempfile.TemporaryDirectory() as out_tmp:
            real = pathlib.Path(scan_tmp)
            (real / "inside.txt").write_text("plain internal note\n", encoding="utf-8")
            link_dir = pathlib.Path(out_tmp) / "linkdir"
            self._make_symlink(link_dir, real)
            result = run_script(str(link_dir))
            self.assertEqual(result.returncode, 2, result.stderr)
            if IS_WINDOWS_PLATFORM:
                self.assertIn(PLATFORM_UNSUPPORTED_MSG, result.stderr)
            else:
                self.assertIn("target-dir must not be a symlink path", result.stderr)


class DirFdBindingTests(unittest.TestCase):
    """R10 §17.B2'-R10 / §18 #25: directory-handle binding and race isolation."""

    def test_source_uses_dirfd_binding_and_seam(self) -> None:
        # R10 (RED on 30bdfaa): every per-file open is dir_fd-relative; no
        # by-path opens, no path-prefix joins; the _read_artifacts seam
        # exists; R11 flags present at the single openat site.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("dir_fd=", source)
        self.assertIn("_read_artifacts", source)
        self.assertIn("O_NONBLOCK", source)
        self.assertIn("S_ISREG", source)
        self.assertNotIn("read_bytes", source)
        self.assertNotIn("st_size", source)
        self.assertNotIn("os.path.join", source)
        for forbidden_form in ("os.open(path", "os.open(target", "os.open(str("):
            self.assertNotIn(forbidden_form, source)
        # R16 §18 #30 (R11 seam acceptance condition): the seam is not only
        # defined but actually CALLED by the main flow (call site beyond the
        # def line) -- no test-only bypass path.
        call_sites = re.findall(r"_read_artifacts\s*\(", source)
        self.assertGreaterEqual(
            len(call_sites), 2, "_read_artifacts defined but never called by main flow"
        )

    def test_directory_replacement_race_isolated(self) -> None:
        # R10+R16 §17.F5'-R16 / §18 #25 (revised: FIVE minimum assertions;
        # POSIX/Linux authoritative): after the dir_fd is validated, renaming
        # the target directory and replacing it in place with a symlink to an
        # outside directory must not divert any read.
        # (1) POSITIVE proof of actual reading: BOTH in-directory sentinels
        #     S1/S2 each yield findings -- a zero-read implementation cannot
        #     pass; (2) the outside sentinel X never appears; (3) return
        #     structure intact (artifact_count == 2, non-None, well-formed);
        #     (4)/(5) startup-boundary and intermediate-link scenarios are
        #     carried by OpenatChainTests (R13 §18 #27).
        if IS_WINDOWS_PLATFORM:
            self.skipTest("dir_fd binding is POSIX-only; Windows covered by fail-closed")
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "audit_sensitive_artifacts_under_test", SCRIPT_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        with tempfile.TemporaryDirectory() as scan_tmp, tempfile.TemporaryDirectory() as out_tmp:
            target = pathlib.Path(scan_tmp)
            external = pathlib.Path(out_tmp)
            inside_1 = "one.txt"
            inside_2 = "two.json"
            sentinel_1 = KNOWN_SECRET_VALUES[0]
            sentinel_2 = KNOWN_SECRET_VALUES[1]
            (target / inside_1).write_text(
                "bearer " + sentinel_1 + "\n", encoding="utf-8"
            )
            (target / inside_2).write_text(
                json.dumps({"token": sentinel_2}), encoding="utf-8"
            )
            (external / "outside.txt").write_text(
                "external " + KNOWN_SECRET_VALUES[3] + "\n", encoding="utf-8"
            )
            dir_fd = os.open(target, os.O_RDONLY | os.O_DIRECTORY)
            moved = target.with_name(target.name + "-moved")
            try:
                os.rename(target, moved)
                os.symlink(external, target)
                result = module._read_artifacts(dir_fd, [inside_1, inside_2])
            finally:
                os.close(dir_fd)
            rendered = repr(result) + json.dumps(result, default=str, sort_keys=True)
            # R16 (2): the outside sentinel never reaches any returned value.
            self.assertNotIn(KNOWN_SECRET_VALUES[3], rendered)
            assert_zero_secret(self, rendered, "race-isolated seam result")
            # R16 (3): return structure intact -- non-None, sized container
            # of exactly the two in-scope artifacts. artifact_count == 2 is a
            # §18 #25 minimum assertion: an absent field must NOT silently
            # pass (guards against "crashed into an empty object" passes).
            self.assertIsNotNone(result)
            counts = [c for c in collect_key_values(result, "artifact_count") if isinstance(c, int)]
            self.assertTrue(counts, "seam result must carry artifact_count (R16 #25 item 3)")
            self.assertEqual(counts[0], 2, counts)
            # R16 (1): POSITIVE actual-read proof -- BOTH in-directory
            # sentinels each produce findings (distinct fingerprints). A
            # zero-read implementation returns no findings and FAILS here.
            fingerprints = [f for f in collect_key_values(result, "fingerprint") if isinstance(f, str)]
            self.assertGreaterEqual(
                len(fingerprints), 2, "zero-read or partial-read implementation: no findings for S1/S2"
            )
            self.assertGreaterEqual(
                len(set(fingerprints)), 2, "S1 and S2 must yield distinct fingerprints"
            )

    def test_windows_platform_fail_closed_no_report(self) -> None:
        # R10 §18 #25 (Windows): any legal target -> exit 2, single
        # platform-unsupported stderr line, and NO report file produced.
        if not IS_WINDOWS_PLATFORM:
            self.skipTest("fail-closed branch is Windows-only (POSIX runs the safe scan)")
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "clean.txt").write_text("plain\n", encoding="utf-8")
            report_path = pathlib.Path(tmp).parent / "ip0020-win-report.json"
            result = run_script(str(target), "--output", str(report_path))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(PLATFORM_UNSUPPORTED_MSG, result.stderr)
            self.assertEqual(result.stdout.strip(), "")
            self.assertFalse(report_path.exists())


class SpecialFileTests(unittest.TestCase):
    """R11 §17.F5'-R11 / §18 #26: FIFO/special files never block the scan."""

    def test_source_locks_nonblock_and_isreg(self) -> None:
        # R11 (RED on 30bdfaa): O_NONBLOCK at the single openat site and a
        # stat.S_ISREG type gate after the single fstat.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("O_NONBLOCK", source)
        self.assertIn("S_ISREG", source)

    def test_fifo_does_not_block_and_is_identifiably_skipped(self) -> None:
        # R11 (POSIX conditional; Windows covered by R10 fail-closed): a
        # FIFO must not block the open (O_NONBLOCK); it is skipped with a
        # special-file warning, incomplete status, exit 3; the sibling
        # regular file is still scanned normally.
        if IS_WINDOWS_PLATFORM or not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo is POSIX-only; Windows covered by platform fail-closed")
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "normal.txt").write_text(
                "bearer " + KNOWN_SECRET_VALUES[0] + "\n", encoding="utf-8"
            )
            os.mkfifo(str(target / "pipe.txt"))
            ids = artifact_ids(target)
            try:
                result = run_script(str(target), timeout=45)
            except subprocess.TimeoutExpired:
                self.fail("scan blocked on FIFO open -- O_NONBLOCK missing (R11)")
                return
            self.assertEqual(result.returncode, 3, result.stderr)
            expected = json.dumps({"artifact": ids["pipe.txt"], "error": "special-file"})
            self.assertIn(expected, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "incomplete")
            self.assertIn(f"{ids['pipe.txt']}:special-file", report.get("incomplete_reasons", []))
            fingerprints = collect_key_values(report, "fingerprint")
            self.assertTrue(fingerprints, "regular sibling file must still be scanned")


class TenantContextLeakPreventionTests(unittest.TestCase):
    """R1 §17.D2'-R1 / §18 #17: zero tenant_key leakage across repr/str and
    the full constructor-failure exception chain."""

    SENSITIVE_KEY = bytes.fromhex("fa11ce11ba5eca5e1111deadbeef2222" * 2)  # noqa: S105 - synthetic recognizable key

    def test_context_repr_length_metadata_only(self) -> None:
        # R1: repr=False + custom __repr__ carrying ONLY tenant_id_len /
        # tenant_key_len; str() falls back to __repr__; no tenant_id
        # plaintext, no key bytes (raw or hex) anywhere.
        ctx = make_context("tenant-alpha", self.SENSITIVE_KEY)
        rendered = repr(ctx)
        self.assertEqual(
            rendered,
            "TenantAuditContext(tenant_id_len=11, tenant_key_len=32)",
        )
        self.assertEqual(str(ctx), rendered)
        combined = rendered + str(ctx)
        self.assertNotIn("tenant-alpha", combined)
        self.assertNotIn(self.SENSITIVE_KEY.hex(), combined)

    def test_constructor_failure_zero_key_all_surfaces(self) -> None:
        # R1: every failing construction surfaces (str/repr/context
        # serialization and the full exception chain: __cause__,
        # __context__, traceback text) stay zero-key (raw + hex).
        key_hex = self.SENSITIVE_KEY.hex()
        for kwargs in (
            {"tenant_key": b""},
            {"tenant_key": "not-bytes"},
            {"tenant_id": ""},
            {"tenant_id": "x" * 129},
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(PrivacyError) as ctx:
                    make_context(
                        tenant_id=kwargs.get("tenant_id", "tenant-alpha"),
                        tenant_key=kwargs.get("tenant_key", self.SENSITIVE_KEY),
                    )
                exc = ctx.exception
                surfaces = [
                    str(exc),
                    repr(exc),
                    json.dumps(dict(exc.context), default=str, sort_keys=True),
                    str(exc.__cause__),
                    repr(exc.__cause__),
                    str(exc.__context__),
                    repr(exc.__context__),
                    "".join(traceback.format_exception(type(exc), exc, exc.__traceback__)),
                ]
                for surface in surfaces:
                    self.assertNotIn(key_hex, surface)
                    self.assertNotIn("fa11ce11", surface)


class ScriptReadBudgetTests(unittest.TestCase):
    """R2 §17.F5'-R2 / §18 #18: handle-limited reads and directory budgets."""

    def test_source_has_no_full_read_bytes(self) -> None:
        # R2 (RED on c5b375e scripts/audit_sensitive_artifacts.py:67): the
        # script must read via a handle with a byte limit, never
        # path.read_bytes() followed by a length check.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("read_bytes", source)

    def test_exact_limit_file_is_read(self) -> None:
        # R2 boundary: a file of exactly max_payload_bytes (1 MiB) is within
        # budget -- read normally, complete scan, exit 0.
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "edge.txt").write_text("y" * 1_048_576, encoding="utf-8")
            result = run_script(str(target), timeout=300)
            if not posix_script_or_fail_closed(self, result):
                return

            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "complete")

    def test_file_budget_truncation_bounded_output(self) -> None:
        # R9+R14 §18 #24 (revised from the R8 wording, [v1.4-erratum] via
        # R12; R14 adds the supported-suffix qualification): single-pass
        # enumeration + bounded top-K lexicographic selection over
        # SUPPORTED-SUFFIX (.json/.txt) entries only -- the file-budget
        # trigger condition is "supported-suffix entry count > 10,000".
        # 10_005 .txt files (all supported suffix); the 5 lexicographically
        # LARGEST names carry unique sentinels -> they are evicted from the
        # 10_000 selection set and must contribute zero findings; the
        # truncation summary is EXACTLY ONE fixed-shape entry
        # truncated-at=a9999; stderr single line; no per-file a10000+
        # entries; incomplete + exit 3. Mixed-suffix variant = R14 §18 #28
        # (SuffixPreFilterTests).
        import base64

        evicted_sentinels = [
            base64.b64encode(f"evicted-sentinel-{i:03d}-payload-0123456789abcdef".encode()).decode()
            for i in range(5)
        ]
        for sentinel in evicted_sentinels:
            self.assertTrue(is_bare_base64_secret(sentinel))
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            for index in range(10_000):
                (target / f"f{index:05d}.txt").write_text(f"file {index}\n", encoding="utf-8")
            for index, sentinel in zip(range(10_000, 10_005), evicted_sentinels, strict=True):
                (target / f"f{index:05d}.txt").write_text(sentinel + "\n", encoding="utf-8")
            result = run_script(str(target), timeout=600)
            if not posix_script_or_fail_closed(self, result):
                return
            self.assertEqual(result.returncode, 3, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "incomplete")
            reasons = report.get("incomplete_reasons", [])
            summaries = [r for r in reasons if r.startswith("scan:file-budget")]
            self.assertEqual(len(summaries), 1, reasons)
            self.assertEqual(summaries[0], "scan:file-budget:truncated-at=a9999")
            self.assertEqual([r for r in reasons if ":resource-limit" in r], [])
            budget_lines = [line for line in result.stderr.splitlines() if "file-budget" in line]
            self.assertEqual(len(budget_lines), 1, result.stderr)
            self.assertLessEqual(len(result.stderr.strip().splitlines()), 2)
            # R9: evicted files contribute nothing -- zero findings (the
            # kept 10_000 files are clean) and zero sentinel leakage.
            self.assertEqual(report.get("findings", []), [])
            self.assertEqual(collect_key_values(report, "fingerprint"), [])
            for sentinel in evicted_sentinels:
                self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_byte_budget_exceeded_report_still_written(self) -> None:
        # R2 (RED on c5b375e): cumulative handle-read bytes past
        # 104_857_600 -> later files skipped, scan:byte-budget recorded,
        # exit 3, and the --output report file is still written and parseable.
        per_file = 1_048_575  # just under the per-file limit
        count = 101  # 101 * 1_048_575 = 105_906_075 > 104_857_600
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            payload = "z" * per_file
            for index in range(count):
                (target / f"b{index:03d}.txt").write_text(payload, encoding="utf-8")
            report_path = pathlib.Path(tmp) / "report.json"
            result = run_script(str(target), "--output", str(report_path), timeout=600)
            if not posix_script_or_fail_closed(self, result):
                return
            self.assertEqual(result.returncode, 3, result.stderr)
            self.assertTrue(report_path.is_file())
            report = json.loads(report_path.read_text(encoding="utf-8"))
            self.assertEqual(report.get("status"), "incomplete")
            # R8 §18 #23: byte budget overage records EXACTLY ONE bounded
            # truncated-at summary (never per-file entries), report written.
            reasons = report.get("incomplete_reasons", [])
            summaries = [r for r in reasons if r.startswith("scan:byte-budget")]
            self.assertEqual(len(summaries), 1, reasons)
            self.assertRegex(summaries[0], r"^scan:byte-budget:truncated-at=a(0|[1-9][0-9]{0,3})$")
            # R9 §18 #24: the byte budget trips mid-selection-set, so the
            # truncation index is strictly below a9999 (no file-budget trip).
            match = re.search(r"truncated-at=a(\d+)$", summaries[0])
            self.assertIsNotNone(match)
            self.assertLess(int(match.group(1)), 9_999)
            self.assertNotIn("scan:file-budget", reasons, "no file-budget trip in this scenario")


class SecureReadVerificationTests(unittest.TestCase):
    """R3 §17.B2'-R3 / §18 #19: open-then-verify read path, fail-closed."""

    def _load_script_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "audit_sensitive_artifacts_under_test", SCRIPT_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def _run_main(self, module, target: pathlib.Path):
        import contextlib
        import io as _io

        out, err = _io.StringIO(), _io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = module.main([str(target)])
        return code, out.getvalue(), err.getvalue()

    def test_source_uses_open_verify_mechanism(self) -> None:
        # R3 (RED on c5b375e): the script must use os.open + os.fstat and
        # compare (st_dev, st_ino) identity -- no TOCTOU-tolerant fallback.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("os.open", source)
        self.assertIn("os.fstat", source)
        self.assertIn("st_ino", source)

    def test_identity_mismatch_fails_closed(self) -> None:
        # R3 (RED on c5b375e): a mismatch between fstat(fd) and the
        # DirEntry stat identity must fail closed -- symlink-risk warning,
        # status incomplete, exit 3, and the file content never reaches any
        # output.
        module = self._load_script_module()
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            secret = KNOWN_SECRET_VALUES[1]
            (target / "raced.txt").write_text("raced bearer " + secret + "\n", encoding="utf-8")
            real = os.stat(target / "raced.txt")
            # st_dev/st_ino fields are indices 2/1 of the stat_result tuple.
            forged = os.stat_result(
                (
                    real.st_mode,
                    real.st_ino + 1,
                    real.st_dev,
                    real.st_nlink,
                    real.st_uid,
                    real.st_gid,
                    real.st_size,
                    real.st_atime,
                    real.st_mtime,
                    real.st_ctime,
                )
            )
            original_fstat = os.fstat
            try:
                os.fstat = lambda fd: forged
                code, out, err = self._run_main(module, target)
            finally:
                os.fstat = original_fstat
            if not posix_main_or_fail_closed(self, code, err):
                return
            self.assertEqual(code, 3, err)
            self.assertIn("symlink-risk", err)
            combined = out + err
            assert_zero_secret(self, combined, "identity-mismatch scan")
            report = json.loads(out)
            self.assertNotEqual(report.get("status"), "complete")

    def test_zero_stino_fails_closed(self) -> None:
        # R3: st_ino == 0 means identity verification is not feasible on
        # this filesystem -- "not verifiable" is treated exactly like
        # "verification failed": no read, incomplete, never complete.
        module = self._load_script_module()
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "noid.txt").write_text("plain note\n", encoding="utf-8")
            real = os.stat(target / "noid.txt")
            forged = os.stat_result(
                (
                    real.st_mode,
                    0,
                    real.st_dev,
                    real.st_nlink,
                    real.st_uid,
                    real.st_gid,
                    real.st_size,
                    real.st_atime,
                    real.st_mtime,
                    real.st_ctime,
                )
            )
            original_fstat = os.fstat
            try:
                os.fstat = lambda fd: forged
                code, out, err = self._run_main(module, target)
            finally:
                os.fstat = original_fstat
            if not posix_main_or_fail_closed(self, code, err):
                return
            self.assertEqual(code, 3, err)
            self.assertIn("symlink-risk", err)
            report = json.loads(out)
            self.assertNotEqual(report.get("status"), "complete")


class SourcePathWhitelistTests(unittest.TestCase):
    """R4 §17.D1'.3 / §18 #20: library-side artifact-id whitelist."""

    def test_valid_source_paths_accepted(self) -> None:
        # R6 §18 #20 (revised): the ONLY legal form is ^a(0|[1-9][0-9]{0,3})$
        # (a0..a9999). The v1.3 "artifact.main-2 / sample.json legal"
        # assertions are remapped below into the illegal list (not deleted).
        for good in ("a0", "a123", "a9999"):
            with self.subTest(good=good):
                findings = audit_text(good, LOG_TEXT, POLICY, context=make_context())
                self.assertTrue(findings)

    def test_invalid_source_paths_rejected_without_echo(self) -> None:
        # R4 (RED on c5b375e: no entry validation exists): paths, drive
        # letters, traversal, over-length, empty, whitespace and non-ASCII
        # values raise INVALID_FIELD_VALUE at field_path "source_path" with
        # value-free context; str(exc) never echoes the raw value.
        bad_values = [
            "sk_live_ABC123xyztoken",
            "artifact.main-2",
            "sample.json",
            "log_excerpt.txt",
            "a10000",
            "a01",
            "/etc/passwd",
            "C:\\secrets\\token.json",
            "../x",
            "..",
            "",
            "x" * 65,
            "has space.txt",
            "sample 文件.json",
        ]
        for bad in bad_values:
            with self.subTest(bad=bad):
                with self.assertRaises(PrivacyError) as ctx:
                    audit_text(bad, LOG_TEXT, POLICY, context=make_context())
                exc = ctx.exception
                self.assertIs(exc.code, PrivacyErrorCode.INVALID_FIELD_VALUE)
                self.assertEqual(exc.field_path, "source_path")
                self.assertEqual(exc.context.get("reason"), "artifact-id")
                self.assertIn("len", exc.context)
                if bad:
                    self.assertNotIn(bad, str(exc))

    def test_invalid_source_path_rejected_structured_and_report(self) -> None:
        # R4: the same whitelist governs audit_structured inputs and the
        # artifact keys accepted by build_audit_report.
        with self.assertRaises(PrivacyError) as ctx:
            audit_structured("../escape.json", SAMPLE_STRUCT, POLICY, context=make_context())
        self.assertEqual(ctx.exception.field_path, "source_path")


class TenantTagFormulaTests(unittest.TestCase):
    """R5 §17.D2'-R5 / §18 #21: frozen derived_key / _tenant_tag formulas."""

    def test_tenant_tag_matches_frozen_formula(self) -> None:
        # R5: _tenant_tag must equal HMAC-SHA256(derived_key,
        # b"audit.tenant-tag.v1" + tenant_id.utf8).hexdigest() where
        # derived_key = HMAC-SHA256(tenant_key, b"lima.evidence_privacy."
        # "tenant-key.v1\x00" + tenant_id.utf8) -- the same derivation as
        # fingerprint.py's in-tree constant (import-reuse consistency).
        import hashlib
        import hmac as hmac_mod

        from lima.evidence_privacy.fingerprint import _derive_tenant_key

        tenant_id, tenant_key = "t-a", b"k-a" * 16
        findings = audit_text("a0", LOG_TEXT, POLICY, context=make_context(tenant_id, tenant_key))
        self.assertTrue(findings)
        derived = _derive_tenant_key(tenant_key, tenant_id)
        expected = hmac_mod.new(
            derived, b"audit.tenant-tag.v1" + tenant_id.encode("utf-8"), hashlib.sha256
        ).hexdigest()
        for finding in findings:
            self.assertEqual(getattr(finding, "_tenant_tag", None), expected)

    def test_packet_doc_pv_tmp_references_non_authoritative_only(self) -> None:
        # R5.4 docs hygiene: any residual .pv_tmp reference inside the
        # IP-0020 Packet must be marked as process evidence / non-authority.
        packet = REPO_ROOT / "docs" / "LIMA_Implementation_Packet_IP-0020_Vault_Audit.md"
        if not packet.is_file():  # packet not yet merged in this baseline
            self.fail("IP-0020 packet document not found in worktree")
        for line in packet.read_text(encoding="utf-8").splitlines():
            if ".pv_tmp" in line:
                self.assertTrue(
                    "过程性证据" in line or "非权威" in line,
                    f"unmarked .pv_tmp authority reference: {line[:80]}",
                )


class SameHandleReadTests(unittest.TestCase):
    """R7 §17.F5'-R2.1' / §18 #22: one open per file, no re-open, no builtins."""

    def _load_script_module(self):
        import importlib.util

        spec = importlib.util.spec_from_file_location(
            "audit_sensitive_artifacts_under_test", SCRIPT_PATH
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_source_open_forms_whitelisted(self) -> None:
        # R7 (RED on c5b375e): every reading-related open( in the script
        # must be an os.open( or os.fdopen( form -- no builtins
        # open(path, "rb"), no re-open after verification, no read_bytes(),
        # no st_size precheck.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertNotIn("read_bytes", source)
        self.assertNotIn("st_size", source)
        self.assertIn("os.fdopen", source)
        for match in re.finditer(r"open\(", source):
            prefix = source[max(0, match.start() - 3) : match.start()]
            self.assertIn(prefix, ("os.", "fd."), f"non-whitelisted open at {match.start()}")

    def test_single_os_open_per_file_zero_builtin_open(self) -> None:
        # R7 (RED on c5b375e): wrapping builtins.open and os.open with
        # counters over one scan (clean file + over-limit file) shows at
        # most one os.open per artifact and zero builtins.open calls --
        # including the resource-limit skip path.
        import contextlib
        import io as _io

        module = self._load_script_module()
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            (target / "clean.txt").write_text("plain note\n", encoding="utf-8")
            (target / "big.txt").write_text("x" * (1_048_576 + 1), encoding="utf-8")
            counters = {"os_open": 0, "builtin_open": 0}
            real_os_open, real_builtin_open = os.open, open

            def counting_os_open(*args, **kwargs):
                counters["os_open"] += 1
                return real_os_open(*args, **kwargs)

            def counting_builtin_open(*args, **kwargs):
                counters["builtin_open"] += 1
                return real_builtin_open(*args, **kwargs)

            out, err = _io.StringIO(), _io.StringIO()
            try:
                import builtins as _builtins

                os.open = counting_os_open
                _builtins.open = counting_builtin_open
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = module.main([str(target)])
            finally:
                os.open = real_os_open
                import builtins as _builtins

                _builtins.open = real_builtin_open
            if not posix_main_or_fail_closed(self, code, err.getvalue()):
                return
            self.assertEqual(code, 3, err.getvalue())
            self.assertEqual(counters["builtin_open"], 0, "builtins.open used for reading")
            # Two artifacts, each opened exactly once via os.open.
            self.assertEqual(counters["os_open"], 2, counters)


class OpenatChainTests(unittest.TestCase):
    """R13 §17.F5'-R13 / §18 #27: per-component openat chain for the target
    directory handle (intermediate-directory symlink closure)."""

    def test_source_locks_component_openat_chain(self) -> None:
        # R13 (RED on dfa0f85 -- main opens the target by path, single-shot):
        # the target directory handle must be obtained via a per-component
        # openat chain -- O_DIRECTORY|O_NOFOLLOW on every component open,
        # dir_fd= chaining, and zero single-shot by-path opens of the target.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("O_NOFOLLOW", source)
        self.assertIn("O_DIRECTORY", source)
        self.assertIn("dir_fd=", source)
        for forbidden_form in ("os.open(target", "os.open(str(target", "os.open(path"):
            self.assertNotIn(forbidden_form, source)

    def test_intermediate_directory_symlink_rejected(self) -> None:
        # R13 §18 #27.1 (POSIX authoritative; Windows covered by the R10
        # platform fail-closed branch -- the probe fires before the chain):
        # target = t/a/b where t/a is a symlink to t_real/a -- the component
        # chain must reject the intermediate symlink with exit 2 and stderr
        # target-invalid:symlink-component; zero report output and zero
        # reads inside b (sentinel absent).
        if IS_WINDOWS_PLATFORM:
            with tempfile.TemporaryDirectory() as tmp:
                target = pathlib.Path(tmp)
                (target / "s.txt").write_text("plain\n", encoding="utf-8")
                result = run_script(str(target))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(PLATFORM_UNSUPPORTED_MSG, result.stderr)
                self.assertEqual(result.stdout.strip(), "")
            return
        with tempfile.TemporaryDirectory() as tmp:
            base = pathlib.Path(tmp)
            real = base / "t_real"
            (real / "a" / "b").mkdir(parents=True)
            sentinel = KNOWN_SECRET_VALUES[0]
            (real / "a" / "b" / "inside.txt").write_text(
                "bearer " + sentinel + "\n", encoding="utf-8"
            )
            link_root = base / "t"
            link_root.mkdir()
            os.symlink(real / "a", link_root / "a")
            target = link_root / "a" / "b"
            result = run_script(str(target))
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn("target-invalid:symlink-component", result.stderr)
            self.assertEqual(result.stdout.strip(), "", result.stdout)
            self.assertNotIn(sentinel, result.stdout + result.stderr)

    def test_anchor_and_error_category_variants(self) -> None:
        # R13 §18 #27.2 (POSIX): (a) relative anchor forms "./" and "." run
        # from cwd=target produce findings equivalent to the absolute form;
        # (b) final-component symlink -> target-invalid:symlink-component;
        # (c) plain-file target -> target-invalid:not-a-directory.
        if IS_WINDOWS_PLATFORM:
            # R10 platform probe fires first on Windows: exit 2 with the
            # platform-unsupported line for any legal target.
            with tempfile.TemporaryDirectory() as tmp:
                target = pathlib.Path(tmp)
                (target / "s.txt").write_text("plain\n", encoding="utf-8")
                result = run_script(str(target))
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(PLATFORM_UNSUPPORTED_MSG, result.stderr)
            return
        import subprocess as _sp

        env = dict(os.environ)
        env["PYTHONPATH"] = str(REPO_ROOT)
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as ext:
            target = pathlib.Path(tmp)
            external = pathlib.Path(ext)
            sentinel = KNOWN_SECRET_VALUES[1]
            (target / "s1.txt").write_text(
                "bearer " + KNOWN_SECRET_VALUES[0] + "\n", encoding="utf-8"
            )
            (target / "s2.txt").write_text(
                "bearer " + sentinel + "\n", encoding="utf-8"
            )
            (external / "decoy.txt").write_text(
                "external " + KNOWN_SECRET_VALUES[3] + "\n", encoding="utf-8"
            )

            def run_cwd(cli_target: str) -> _sp.CompletedProcess:
                return _sp.run(  # noqa: S603 - frozen repo script, argv pinned
                    [sys.executable, str(SCRIPT_PATH), cli_target],
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    cwd=str(target),
                    env=env,
                    timeout=120,
                )

            # (a) relative anchor forms: "./" and "." produce findings
            # equivalent to the absolute-path form.
            absolute = run_script(str(target))
            self.assertEqual(absolute.returncode, 0, absolute.stderr)
            abs_report = json.loads(absolute.stdout)
            for relative_form in ("./", "."):
                relative = run_cwd(relative_form)
                self.assertEqual(relative.returncode, 0, relative.stderr)
                rel_report = json.loads(relative.stdout)
                self.assertEqual(rel_report.get("status"), "complete")
                self.assertEqual(
                    sorted(f for f in collect_key_values(rel_report, "fingerprint")),
                    sorted(f for f in collect_key_values(abs_report, "fingerprint")),
                )
            # (b) final-component symlink -> symlink-component rejection.
            link_path = target.parent / (target.name + "-link")
            os.symlink(target, link_path)
            final_link = run_script(str(link_path))
            self.assertEqual(final_link.returncode, 2, final_link.stderr)
            self.assertIn("target-invalid:symlink-component", final_link.stderr)
            # (c) plain-file target -> not-a-directory rejection.
            file_target = target / "s1.txt"
            plain = run_script(str(file_target))
            self.assertEqual(plain.returncode, 2, plain.stderr)
            self.assertIn("target-invalid:not-a-directory", plain.stderr)


class SuffixPreFilterTests(unittest.TestCase):
    """R14 §17.F5'-R14 / §18 #28: supported-suffix pre-filter on the
    selection set (out-of-scope suffixes cannot consume the file budget)."""

    def test_unsupported_suffixes_do_not_consume_quota(self) -> None:
        # R14 (RED on dfa0f85 -- main counts every directory entry toward
        # selection): 10_000 .bin entries (all lexicographically BELOW the
        # single sentinel .txt, so an unfiltered top-K would evict it) + 1
        # sentinel z-sentinel.txt -> the sentinel MUST be audited; no
        # file-budget truncation; complete + exit 0; artifact_count == 1 and
        # the single index a0; .bin entries contribute zero warnings.
        # R14 grep lock (§18 #28 ".bin ... zero open/warning/index +
        # grep lock"): the supported-suffix set stays a script-layer
        # constant (_ARTIFACT_SUFFIXES, name anchored on main) so the
        # selection gate cannot silently widen to other suffixes.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("_ARTIFACT_SUFFIXES", source)
        sentinel = KNOWN_SECRET_VALUES[2]
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            for index in range(10_000):
                (target / f"b{index:05d}.bin").write_bytes(b"\x00\x01binary-payload")
            (target / "z-sentinel.txt").write_text(
                "bearer " + sentinel + "\n", encoding="utf-8"
            )
            result = run_script(str(target), timeout=600)
            if not posix_script_or_fail_closed(self, result):
                return
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "complete")
            self.assertEqual(report.get("incomplete_reasons", []), [])
            self.assertEqual(report.get("artifact_count", None), 1)
            source_paths = [str(p) for p in collect_key_values(report, "source_path")]
            self.assertEqual(source_paths, ["a0"], source_paths)
            fingerprints = collect_key_values(report, "fingerprint")
            self.assertTrue(fingerprints, "sentinel .txt must be audited (R14)")
            combined = result.stdout + result.stderr
            self.assertNotIn(".bin", combined)
            self.assertEqual(
                [line for line in result.stderr.splitlines() if line.strip()],
                [],
                "unsupported-suffix entries must be silently ignored (R14)",
            )


class FindingsBudgetTests(unittest.TestCase):
    """R15 §17.F5'-R15 / §18 #29: report-level findings total cap
    max_report_findings = 10_000 (script-layer aggregation point)."""

    def test_findings_capped_at_report_budget(self) -> None:
        # R15 (RED on dfa0f85 -- build_audit_report appends unboundedly):
        # 3 .json fixtures x 4_000 bare-base64 members (12_000 > 10_000),
        # processed in a<n> ascending order -> report findings length is
        # EXACTLY 10_000; incomplete_reasons carries EXACTLY ONE
        # scan:findings-budget:truncated-at=a<n> (a0/a1 full + a2 partial:
        # truncated-at=a1 under the ascending-order processing rule); stderr
        # exactly one findings-budget summary line and zero per-file entries;
        # exit 3 + status incomplete; report JSON still produced and bounded.
        import base64

        # R15 grep lock: the cap is a script-layer constant named per
        # §17.F5'-R15.1 (same family as max_files_per_scan); RED on dfa0f85
        # where no such constant exists.
        source = SCRIPT_PATH.read_text(encoding="utf-8")
        self.assertIn("max_report_findings", source)

        def member_payload(index: int) -> str:
            return base64.b64encode(
                f"findings-budget-member-{index:05d}-0123456789abcdef".encode()
            ).decode()

        members = {f"m{index:05d}": member_payload(index) for index in range(4_000)}
        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp)
            for name in ("f0.json", "f1.json", "f2.json"):
                (target / name).write_text(
                    json.dumps(members), encoding="utf-8"
                )
            result = run_script(str(target), timeout=600)
            if not posix_script_or_fail_closed(self, result):
                return
            self.assertEqual(result.returncode, 3, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report.get("status"), "incomplete")
            findings = report.get("findings", [])
            self.assertEqual(len(findings), 10_000, len(findings))
            reasons = report.get("incomplete_reasons", [])
            summaries = [r for r in reasons if r.startswith("scan:findings-budget")]
            self.assertEqual(len(summaries), 1, reasons)
            # §18 #29 exact value under the frozen ascending-a<n> processing
            # order: a0/a1 contribute 4,000 each, the cap hits 10,000 while
            # processing a2 -> the last fully processed artifact is a1.
            self.assertEqual(summaries[0], "scan:findings-budget:truncated-at=a1")
            budget_lines = [
                line for line in result.stderr.splitlines() if "findings-budget" in line
            ]
            self.assertEqual(len(budget_lines), 1, result.stderr)
            self.assertLessEqual(len(result.stderr.strip().splitlines()), 2)
            # Report boundedness proxy: findings count == the cap.
            self.assertLessEqual(len(json.dumps(report)), 6_000_000)


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
