"""Frozen acceptance tests for the IP-0020 read-only audit contract.

Anchors (per Packet IP-0020 v1.1): FR-N05-06, NFR-N05-04 (audit side),
AC/T-N05-06, §8.2, §8.3 (incl. §8.3.8 offline tenant context), §9 T2/T3/T4/T5.
Dual-runner safe: unittest.TestCase only, no pytest API (PI-DR6-bis).
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import pathlib
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
from lima.evidence_privacy.models import TenantPolicy

REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
FIXTURE_DIR = REPO_ROOT / "tests" / "evidence_privacy" / "fixtures" / "audit_samples"
SCRIPT_PATH = REPO_ROOT / "scripts" / "audit_sensitive_artifacts.py"

# §8.3.8 (F-1): documented fixed offline tenant context of the audit script.
OFFLINE_TENANT_ID = "offline-audit"
OFFLINE_TENANT_KEY = b"lima-offline-audit.v1"

# §11.2: known sensitive values, restated from the fixture header comments
# (sample.json "_known_values_header", log_excerpt.txt "#" header line).
KNOWN_SECRET_VALUES = [  # noqa: S105 - synthetic IP-0020 audit fixture values
    "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5ejAxMg==",
    "c2VjcmV0LXRva2VuLWZvci1kZWVwLWxldmVsLXRlc3QtMTIzNDU2Nzg5MGFi",
    "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v",
    "https://svc-usr:SapphoWren42@db-host.internal.svc/backup",
]
# The token embedded in the Unicode-mixed traceback line of log_excerpt.txt.
UNICODE_MIXED_TOKEN = "w7nDvcOtLXRva2VuLWZvci11bmljb2RlLXRlc3Q"  # noqa: S105 - synthetic fixture token

LOG_TEXT = (FIXTURE_DIR / "log_excerpt.txt").read_text(encoding="utf-8")
SAMPLE_STRUCT = json.loads((FIXTURE_DIR / "sample.json").read_text(encoding="utf-8"))
POLICY = TenantPolicy(policy_version="v1")


def forbidden_substrings() -> list[str]:
    """AC/T-N05-06: every known value plus all its >=4-char substrings."""
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


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    # §8.3 CLI form: ``python scripts/audit_sensitive_artifacts.py ...`` from
    # the worktree root; PYTHONPATH pins the repo root so the script's
    # sys.path (script dir) can still resolve ``lima`` under both runners.
    import os

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
    """§11.2: fixture header values and in-test constants must agree."""

    def test_known_values_present_in_fixtures(self) -> None:
        # §11.2: the restated constants actually occur in the fixtures
        # (self-check that the grep denial list matches fixture content).
        raw = (FIXTURE_DIR / "sample.json").read_bytes()
        raw += (FIXTURE_DIR / "log_excerpt.txt").read_bytes()
        decoded = raw.decode("utf-8")
        for value in KNOWN_SECRET_VALUES + [UNICODE_MIXED_TOKEN]:
            self.assertIn(value, decoded)


class AuditTextTests(unittest.TestCase):
    """FR-N05-06 §8.2.4: text scanning via base64 span predicates."""

    def test_audit_text_finds_spans_with_locations(self) -> None:
        # FR-N05-06 §8.2.2/§8.2.4: findings carry AuditLocation with
        # source_path, field_path None for text, and half-open spans that
        # point at predicate-satisfying base64 spans.
        findings = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
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
        findings = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        spans = {finding.location.span for finding in findings}
        expected = {
            span
            for span in find_base64_spans(LOG_TEXT)
            if is_bare_base64_secret(LOG_TEXT[span[0] : span[1]])
        }
        self.assertEqual(spans, expected)


class AuditStructuredTests(unittest.TestCase):
    """FR-N05-06 §8.2.4 + NFR-N05-04: structured deep traversal."""

    def test_audit_structured_deep_field_paths(self) -> None:
        # §8.2.2: dotted field_path reaches deep values; whole-value
        # candidates use span (0, len(value)).
        findings = audit_structured(
            "sample.json", SAMPLE_STRUCT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        paths = {finding.location.field_path for finding in findings}
        deep = [p for p in paths if p is not None and "deep" in p]
        self.assertTrue(deep, f"missing deep field_path in {paths}")
        whole = [f for f in findings if f.location.span == (0, f.length)]
        self.assertTrue(whole)

    def test_audit_structured_does_not_mutate_input(self) -> None:
        # NFR-N05-04: auditing never rewrites the audited object.
        import copy

        snapshot = copy.deepcopy(SAMPLE_STRUCT)
        audit_structured(
            "sample.json", SAMPLE_STRUCT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        self.assertEqual(SAMPLE_STRUCT, snapshot)


class ValueFreeTests(unittest.TestCase):
    """AC/T-N05-06 §8.2.3 + §9 T2: value-free findings and report JSON."""

    def test_finding_repr_and_fields_zero_secret(self) -> None:
        # §8.2.3/§9 T2: no preview attribute; repr carries no values.
        findings = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        self.assertTrue(findings)
        names = {f.name for f in dataclasses.fields(AuditFinding)}
        self.assertEqual(names, {"location", "fingerprint", "value_kind", "length"})
        for finding in findings:
            self.assertFalse(hasattr(finding, "preview"))
            assert_zero_secret(self, repr(finding), "finding repr")

    def test_report_json_zero_secret_and_parseable(self) -> None:
        # §8.2.3/AC/T-N05-06: canonical JSON output parses and leaks nothing.
        findings = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        report = build_audit_report({"log_excerpt.txt": findings}, POLICY)
        payload = audit_report_to_json(report)
        assert_zero_secret(self, payload, "report json")
        json.loads(payload)

    def test_report_field_set_whitelist(self) -> None:
        # §8.2.2/§9 T4: AuditReport fields are exactly the frozen whitelist;
        # no tenant_id / tenant_key / preview (this dataclass-level assertion
        # is deliberately separate from the script-level tenant_context
        # serialization assertion, §8.3.8 note).
        names = {f.name for f in dataclasses.fields(AuditReport)}
        self.assertEqual(
            names,
            {"policy_version", "policy_digest", "findings", "artifact_count", "recommended_action"},
        )


class TenantIsolationTests(unittest.TestCase):
    """§9 T4: fingerprint tenant isolation and same-tenant stability."""

    def test_different_tenant_key_changes_all_fingerprints(self) -> None:
        # §9 T4: same input, different tenant_key -> every fingerprint
        # changes while positions stay identical.
        first = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        second = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-b", tenant_key=b"k-b" * 16
        )
        self.assertEqual(
            [f.location for f in first], [f.location for f in second]
        )
        self.assertNotEqual(
            [f.fingerprint for f in first], [f.fingerprint for f in second]
        )

    def test_same_tenant_key_fingerprint_stable(self) -> None:
        # §9 T4: same credentials -> identical fingerprints on repeat calls.
        first = audit_structured(
            "sample.json", SAMPLE_STRUCT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        second = audit_structured(
            "sample.json", SAMPLE_STRUCT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        self.assertEqual(
            [f.fingerprint for f in first], [f.fingerprint for f in second]
        )


class ReportPolicyEvidenceTests(unittest.TestCase):
    """NFR-N05-04 audit side §8.2.5/§8.2.6."""

    def test_report_embeds_policy_evidence_and_constant_action(self) -> None:
        # §8.2.5: policy_version + policy_digest embedded; §8.2.6:
        # recommended_action is the frozen constant string.
        from lima.evidence_privacy.policy import policy_digest

        findings = audit_text(
            "log_excerpt.txt", LOG_TEXT, POLICY, tenant_id="t-a", tenant_key=b"k-a" * 16
        )
        report = build_audit_report({"log_excerpt.txt": findings}, POLICY)
        self.assertEqual(report.policy_version, POLICY.policy_version)
        self.assertEqual(report.policy_digest, policy_digest(POLICY))
        self.assertEqual(
            report.recommended_action, "manual-review-and-approved-migration-issue"
        )
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
    """§8.3 + §9 T2/T3/T5: offline script behaviour end to end."""

    def test_script_exit0_stdout_report_zero_secret(self) -> None:
        # §8.3.3: exit 0 with a JSON report on stdout; §8.3.5: zero values;
        # §8.3.8: top-level tenant_context identifies the offline domain.
        result = run_script(str(FIXTURE_DIR))
        self.assertEqual(result.returncode, 0, result.stderr)
        assert_zero_secret(self, result.stdout, "script stdout")
        assert_zero_secret(self, result.stderr, "script stderr")
        report = json.loads(result.stdout)
        self.assertIsInstance(report, dict)
        self.assertEqual(report.get("tenant_context"), OFFLINE_TENANT_ID)
        # NFR-N05-04: policy evidence keys present at top level.
        self.assertIn("policy_version", report)
        self.assertIn("policy_digest", report)
        fingerprints = collect_key_values(report, "fingerprint")
        self.assertTrue(fingerprints, "report carries no fingerprints")

    def test_script_leaves_fixtures_untouched(self) -> None:
        # §8.3.4/§9 T3: sha256 and mtime (>=1s precision, §11.5) unchanged.
        before = fixture_state()
        result = run_script(str(FIXTURE_DIR))
        self.assertEqual(result.returncode, 0, result.stderr)
        after = fixture_state()
        self.assertEqual(before, after)

    def test_script_output_to_report_file_outside_dir(self) -> None:
        # §8.3.3: --output to an explicit external path writes the report;
        # fixture directory gains no files; report file leaks nothing.
        before = fixture_state()
        with tempfile.TemporaryDirectory() as tmp:
            report_path = pathlib.Path(tmp) / "report.json"
            result = run_script(str(FIXTURE_DIR), "--output", str(report_path))
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertTrue(report_path.is_file())
            content = report_path.read_text(encoding="utf-8")
            assert_zero_secret(self, content, "report file")
            report = json.loads(content)
            self.assertEqual(report.get("tenant_context"), OFFLINE_TENANT_ID)
        self.assertEqual(fixture_state(), before)

    def test_script_output_inside_target_dir_rejected(self) -> None:
        # §8.3.3/§9 T3: --output inside <target-dir> is a parameter error;
        # variants must be resolved (§11.5) and all rejected non-zero.
        # §11.5 rev. DR-IP-0020-2: cross-platform real-inside variants are
        # built with os.sep and asserted on every platform; Windows-specific
        # separator and case variants are asserted on Windows only (on POSIX
        # the same literals resolve outside the target and are legal).
        variants = [
            FIXTURE_DIR / "report.json",
            pathlib.Path(str(FIXTURE_DIR) + "/sub/../report.json"),
            pathlib.Path(
                str(FIXTURE_DIR)
                + os.sep
                + "nested"
                + os.sep
                + ".."
                + os.sep
                + "report.json"
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
                pathlib.Path(
                    str(FIXTURE_DIR).replace("audit_samples", "Audit_Samples")
                )
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

    def test_script_skips_broken_json_with_warning(self) -> None:
        # §8.3.2: unparseable JSON is skipped (no finding, no abort) with a
        # one-line stderr warning naming the file and error category only.
        result = run_script(str(FIXTURE_DIR))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("unparseable-json", result.stderr)
        self.assertIn("broken.json", result.stderr)
        assert_zero_secret(self, result.stderr, "skip warning")
        report = json.loads(result.stdout)
        source_paths = [str(p) for p in collect_key_values(report, "source_path")]
        self.assertTrue(source_paths)
        self.assertFalse(
            any("broken.json" in p for p in source_paths),
            "skipped file must not contribute findings",
        )

    def test_script_dependency_whitelist(self) -> None:
        # §8.3.6/§9 T5: only stdlib + lima.evidence_privacy.{audit,
        # content_scan}; no vault / network / DB references.
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
        ):
            self.assertNotIn(forbidden, source)
        self.assertIn("lima.evidence_privacy.audit", source)

    def test_script_offline_fingerprint_consistency(self) -> None:
        # §8.3.8/§9 T4 (F-1): script fingerprints equal the library values
        # computed with the fixed offline tenant credentials and differ from
        # any other tenant's values.
        result = run_script(str(FIXTURE_DIR))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        script_fingerprints = sorted(
            str(fp) for fp in collect_key_values(report, "fingerprint")
        )
        expected: list[str] = []
        expected.extend(
            finding.fingerprint
            for finding in audit_text(
                "log_excerpt.txt",
                LOG_TEXT,
                POLICY,
                tenant_id=OFFLINE_TENANT_ID,
                tenant_key=OFFLINE_TENANT_KEY,
            )
        )
        expected.extend(
            finding.fingerprint
            for finding in audit_structured(
                "sample.json",
                SAMPLE_STRUCT,
                POLICY,
                tenant_id=OFFLINE_TENANT_ID,
                tenant_key=OFFLINE_TENANT_KEY,
            )
        )
        self.assertEqual(script_fingerprints, sorted(expected))
        other_tenant = set(
            finding.fingerprint
            for finding in audit_text(
                "log_excerpt.txt",
                LOG_TEXT,
                POLICY,
                tenant_id="some-online-tenant",
                tenant_key=b"online-tenant-key-0001",
            )
        )
        self.assertFalse(other_tenant & set(script_fingerprints))


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
