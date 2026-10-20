"""Synthetic contract and reproducible CLI demos for Issue #314.

Run tests with unittest; run this file with --demo NEW_DIRECTORY for two reports.
The synthetic PoC is deliberately invalid executable content and is never run.
"""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lima import competition_report_materials as materials


FIELDS = (
    "source_excerpt", "description_and_cwe", "trigger_and_path", "poc_source",
    "reproduction_instructions", "impact_modules_and_versions", "remediation",
    "maintainer_review",
)
SENTINEL = "SYNTHETIC_PRIVATE_CONTENT_314"
REPOSITORY = Path(__file__).resolve().parents[1]


def windows_streams(path):
    """Enumerate native NTFS data streams; default-stream hashes miss ADS writes."""
    import ctypes
    from ctypes import wintypes

    class StreamData(ctypes.Structure):
        _fields_ = [("size", ctypes.c_longlong), ("name", wintypes.WCHAR * 296)]

    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    first = kernel.FindFirstStreamW
    first.argtypes = (wintypes.LPCWSTR, ctypes.c_int, ctypes.POINTER(StreamData), wintypes.DWORD)
    first.restype = wintypes.HANDLE
    following = kernel.FindNextStreamW
    following.argtypes = (wintypes.HANDLE, ctypes.POINTER(StreamData))
    following.restype = wintypes.BOOL
    close = kernel.FindClose
    close.argtypes = (wintypes.HANDLE,)
    close.restype = wintypes.BOOL
    data = StreamData()
    handle = first(str(path), 0, ctypes.byref(data), 0)
    if handle == wintypes.HANDLE(-1).value:
        raise ctypes.WinError(ctypes.get_last_error())
    streams = {}
    try:
        while True:
            streams[data.name] = data.size
            if not following(handle, ctypes.byref(data)):
                error = ctypes.get_last_error()
                if error != 38:  # ERROR_HANDLE_EOF
                    raise ctypes.WinError(error)
                break
    finally:
        close(handle)
    return streams


def cli_command():
    script = REPOSITORY / "scripts" / "check_competition_report_materials.py"
    if script.exists():
        return [sys.executable, str(script)]
    # CI images copy modules without installing them or copying this script.
    # Bootstrap the known package root explicitly, preserving the caller's cwd.
    return [sys.executable, "-c",
            "import runpy,sys; sys.path.insert(0,sys.argv.pop(1)); "
            "runpy.run_module('lima.competition_report_materials',run_name='__main__')",
            str(REPOSITORY)]


def synthetic_case(directory):
    root = directory / "materials"
    root.mkdir()
    (root / "body.txt").write_text(SENTINEL, encoding="utf-8")
    (root / "poc.txt").write_text("NOT EXECUTABLE: " + SENTINEL, encoding="utf-8")
    finding = {
        "finding_id": "synthetic-001",
        "field_refs": dict.fromkeys(FIELDS, "body.txt"),
        "cve_status": "not-assessed",
    }
    finding["field_refs"]["poc_source"] = "poc.txt"
    document = {"schema_version": 1, "scope": "report-materials-check",
                "case_label": "synthetic-314", "findings": [finding]}
    return root, document


class ReportMaterialsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root, self.index = synthetic_case(self.base)
        self.index_path = self.base / "index.json"
        self.output = self.base / "check.json"
        self.console = ""

    @property
    def finding(self):
        return self.index["findings"][0]

    def run_check(self, raw=None, argv=None):
        if argv is None:
            self.index_path.write_text(
                json.dumps(self.index) if raw is None else raw, encoding="utf-8")
        stdout, stderr = io.StringIO(), io.StringIO()
        args = ["--index", str(self.index_path), "--root", str(self.root),
                "--output", str(self.output)] if argv is None else argv
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = materials.main(args)
        self.console = stdout.getvalue() + stderr.getvalue()
        return code

    def report(self):
        return json.loads(self.output.read_text(encoding="utf-8"))

    def reset_output(self):
        self.output.unlink(missing_ok=True)

    def assert_boundaries(self):
        report = self.report()
        self.assertEqual(report["semantic_verification"], "not-performed")
        self.assertEqual(report["disclosure_approval"], "not-checked")
        encoded = json.dumps(report) + self.console
        self.assertNotIn(SENTINEL, encoded)
        self.assertNotIn(str(self.base), encoded)
        self.assertNotIn("Traceback", encoded)

    def test_complete_core_fields_do_not_assert_vulnerability(self):
        self.assertEqual(self.run_check(), 0)
        report = self.report()
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["scope"], "report-materials-check")
        self.assertEqual(report["case_label"], "synthetic-314")
        self.assertIs(report["fields_complete"], True)
        self.assertEqual(report["input_errors"], [])
        self.assertEqual(report["per_finding_missing"][0]["missing"], [])
        self.assertEqual(report["per_finding_missing"][0]["cve_status"], "not-assessed")
        self.assertIn("severity_pending", str(report["diagnostics"]))
        self.assertIn("execution_record_pending", str(report["diagnostics"]))
        self.assert_boundaries()

    def test_each_required_field_missing(self):
        for field in FIELDS:
            with self.subTest(field=field):
                original = self.finding["field_refs"].pop(field)
                self.assertEqual(self.run_check(), 2)
                self.assertIn(field, [x["field"] for x in
                                     self.report()["per_finding_missing"][0]["missing"]])
                self.assertIs(self.report()["fields_complete"], False)
                self.finding["field_refs"][field] = original
                self.reset_output()

    def test_missing_poc_is_reported_without_modifying_input(self):
        (self.root / "poc.txt").unlink()
        self.assertEqual(self.run_check(), 2)
        self.assertIn({"field": "poc_source", "reason": "missing_file"},
                      self.report()["per_finding_missing"][0]["missing"])
        self.assertEqual((self.root / "body.txt").read_text(), SENTINEL)
        self.assert_boundaries()

    def test_empty_attachment(self):
        (self.root / "poc.txt").write_bytes(b"")
        self.assertEqual(self.run_check(), 2)
        self.assertIn("empty_file", str(self.report()))

    def test_all_cve_states_preserved(self):
        for status in ("known", "no-match-recorded", "not-assessed"):
            with self.subTest(status=status):
                self.finding["cve_status"] = status
                if status == "known":
                    self.finding.update(cve_ids=["CVE-2026-12345"], evidence_ref="body.txt")
                else:
                    self.finding.pop("cve_ids", None)
                    self.finding.pop("evidence_ref", None)
                self.assertEqual(self.run_check(), 0)
                self.assertEqual(self.report()["per_finding_missing"][0]["cve_status"], status)
                self.reset_output()

    def test_known_requires_ids_and_evidence(self):
        self.finding["cve_status"] = "known"
        self.assertEqual(self.run_check(), 2)
        missing = self.report()["per_finding_missing"][0]["missing"]
        self.assertIn("cve_ids", [x["field"] for x in missing])
        self.assertIn("evidence_ref", [x["field"] for x in missing])

    def test_known_invalid_ids(self):
        self.finding.update(cve_status="known", evidence_ref="body.txt")
        for ids in ([], "CVE-2026-12345", ["CVE-26-1234"], ["CVE-2026-123"],
                    ["CVE-2026-1234\n"], [True], ["CVE-2026-1234"] * 2):
            with self.subTest(ids=ids):
                self.finding["cve_ids"] = ids
                self.assertEqual(self.run_check(), 2)
                self.reset_output()

    def test_known_missing_evidence_attachment(self):
        self.finding.update(cve_status="known", cve_ids=["CVE-2026-12345"],
                            evidence_ref="missing.txt")
        self.assertEqual(self.run_check(), 2)
        self.assertIn({"field": "evidence_ref", "reason": "missing_file"},
                      self.report()["per_finding_missing"][0]["missing"])

    def test_no_match_or_unassessed_cannot_claim_ids(self):
        for status in ("no-match-recorded", "not-assessed"):
            self.finding.update(cve_status=status, cve_ids=["CVE-2026-12345"])
            self.assertEqual(self.run_check(), 2)
            self.reset_output()

    def test_cve_status_required_and_closed_enum(self):
        for value in (None, True, "new", "passed", ""):
            self.finding["cve_status"] = value
            self.assertEqual(self.run_check(), 2)
            self.reset_output()

    def test_duplicate_finding_id(self):
        self.index["findings"].append(dict(self.finding))
        self.assertEqual(self.run_check(), 2)
        self.assertIn("duplicate_finding_id", str(self.report()["input_errors"]))

    def test_duplicate_json_keys_at_all_levels(self):
        raw = json.dumps(self.index)
        for duplicate in (raw.replace('"schema_version": 1', '"schema_version": 1, "schema_version": 1'),
                          raw.replace('"finding_id":', '"finding_id": "first", "finding_id":'),
                          raw.replace('"poc_source":', '"poc_source": "first", "poc_source":')):
            self.assertEqual(self.run_check(raw=duplicate), 2)
            self.assertIn("duplicate_json_key", str(self.report()["input_errors"]))
            self.assert_boundaries()
            self.reset_output()

    def test_invalid_top_level_and_required_schema(self):
        for document in ([], None, {}, {**self.index, "schema_version": True},
                         {**self.index, "schema_version": 1.0},
                         {**self.index, "scope": "other"}, {**self.index, "findings": []},
                         {**self.index, "findings": [None]},
                         {**self.index, "case_label": "../private"}):
            self.assertEqual(self.run_check(raw=json.dumps(document)), 2)
            self.assertIs(self.report()["fields_complete"], False)
            self.reset_output()

    def test_unknown_fields_and_wrong_containers(self):
        for change in (lambda: self.index.update(unexpected=SENTINEL),
                       lambda: self.finding.update(unexpected=SENTINEL),
                       lambda: self.finding.update(field_refs=[]),
                       lambda: self.finding["field_refs"].update(unknown="body.txt")):
            before = json.loads(json.dumps(self.index))
            change()
            self.assertEqual(self.run_check(), 2)
            self.assert_boundaries()
            self.index = before
            self.reset_output()

    def test_invalid_json_and_nonfinite_numbers(self):
        for raw in ("{", "", '{"secret": NaN}', '{"secret": Infinity}',
                    '{"secret": -Infinity}', '[' * 1500):
            self.assertEqual(self.run_check(raw=raw), 2)
            self.assert_boundaries()
            self.reset_output()

    def test_invalid_utf8(self):
        self.index_path.write_bytes(b"\xff")
        self.assertEqual(self.run_check(argv=["--index", str(self.index_path), "--root",
                                             str(self.root), "--output", str(self.output)]), 2)
        self.assert_boundaries()

    def test_canonical_relative_paths_only(self):
        for value in ("../outside", "/etc/passwd", "C:/private", "C:private", "a\\b",
                      "//host/share", "./body.txt", "a/../body.txt", "a//b", "a/",
                      "a/./b", "file:stream", "a\x00b", "a\nb", "body.txt ",
                      "CON", "aux.txt", "a\ud800b", "a\u0085b", "", None, True, []):
            with self.subTest(value=value):
                self.finding["field_refs"]["poc_source"] = value
                self.assertEqual(self.run_check(), 2)
                self.assert_boundaries()
                self.reset_output()

    def test_attachments_are_not_opened_executed_or_sent_to_network(self):
        self.index_path.write_text(json.dumps(self.index), encoding="utf-8")
        real_open = os.open

        def guarded_open(path, flags, *args, **kwargs):
            self.assertNotIn(Path(path).name, ("body.txt", "poc.txt"))
            return real_open(path, flags, *args, **kwargs)

        with patch.object(materials.os, "open", side_effect=guarded_open), \
                patch.object(subprocess, "Popen", side_effect=AssertionError("execution")), \
                patch.object(socket, "socket", side_effect=AssertionError("network")):
            self.assertEqual(self.run_check(argv=["--index", str(self.index_path), "--root",
                                                 str(self.root), "--output", str(self.output)]), 0)

    @unittest.skipUnless(os.name == "nt", "Windows case-insensitive filesystem")
    def test_output_cannot_bypass_root_with_different_case(self):
        self.output = Path(str(self.root).swapcase()) / "new.json"
        self.assertEqual(self.run_check(), 3)
        self.assertFalse(self.output.exists())

    def test_invalid_severity_and_identifier_types(self):
        for field, values in (("severity", (None, True, [], "", "  ", "a\nb")),
                              ("finding_id", (None, True, [], "../private", SENTINEL + "/x"))):
            original = self.finding.copy()
            for value in values:
                with self.subTest(field=field, value=value):
                    self.finding[field] = value
                    self.assertEqual(self.run_check(), 2)
                    self.assert_boundaries()
                    self.reset_output()
            self.index["findings"][0] = original

    def test_regular_files_only_and_nested_files(self):
        nested = self.root / "nested"
        nested.mkdir()
        (nested / "snippet.txt").write_bytes(b"x")
        self.finding["field_refs"]["poc_source"] = "nested/snippet.txt"
        self.assertEqual(self.run_check(), 0)
        self.reset_output()
        self.finding["field_refs"]["poc_source"] = "nested"
        self.assertEqual(self.run_check(), 2)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "POSIX FIFO")
    def test_fifo_is_rejected_without_open(self):
        os.mkfifo(self.root / "fifo")
        self.finding["field_refs"]["poc_source"] = "fifo"
        self.assertEqual(self.run_check(), 2)
        self.assertIn("not_regular_file", str(self.report()))

    def symlink(self, link, target, directory=False):
        try:
            link.symlink_to(target, target_is_directory=directory)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation unavailable")

    def test_symlink_file_in_root_rejected(self):
        self.symlink(self.root / "alias", self.root / "body.txt")
        self.finding["field_refs"]["poc_source"] = "alias"
        self.assertEqual(self.run_check(), 2)
        self.assertIn("link_or_reparse_point", str(self.report()))

    def test_symlink_directory_escape_rejected(self):
        outside = self.base / "outside"
        outside.mkdir()
        (outside / "secret").write_bytes(SENTINEL.encode())
        self.symlink(self.root / "alias", outside, True)
        self.finding["field_refs"]["poc_source"] = "alias/secret"
        self.assertEqual(self.run_check(), 2)
        self.assert_boundaries()

    def test_broken_symlink_rejected(self):
        self.symlink(self.root / "alias", self.base / "absent")
        self.finding["field_refs"]["poc_source"] = "alias"
        self.assertEqual(self.run_check(), 2)
        self.assertIn("link_or_reparse_point", str(self.report()))

    def test_symlink_root_and_root_ancestor_rejected(self):
        self.symlink(self.base / "alias", self.base, True)
        original = self.root
        for root in (self.base / "alias" / "materials", self.base / "alias"):
            self.root = root
            self.assertEqual(self.run_check(), 2)
            self.reset_output()
        self.root = original

    @unittest.skipUnless(os.name == "nt", "Windows junction")
    def test_windows_junction_rejected(self):
        junction = self.root / "junction"
        result = subprocess.run(["cmd", "/c", "mklink", "/J", str(junction), str(self.base)],
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.addCleanup(lambda: os.rmdir(junction))
        self.finding["field_refs"]["poc_source"] = "junction/index.json"
        self.assertEqual(self.run_check(), 2)
        self.assertIn("link_or_reparse_point", str(self.report()))

    def test_stat_reparse_attribute_rejected(self):
        fake = type("Metadata", (), {"st_mode": 0o100644,
                                    "st_file_attributes": 0x400})()
        self.assertTrue(materials._is_link(fake))

    def test_attachment_budget_without_reading_content(self):
        self.finding["field_refs"]["poc_source"] = "large.bin"
        with (self.root / "large.bin").open("wb") as stream:
            stream.truncate(materials.MAX_ATTACHMENT_BYTES + 1)
        self.assertEqual(self.run_check(), 2)
        self.assertIn("attachment_size_budget", str(self.report()))
        self.assert_boundaries()

    def test_total_size_budget_and_reference_budget(self):
        with patch.object(materials, "MAX_TOTAL_ATTACHMENT_BYTES", 1):
            self.assertEqual(self.run_check(), 2)
            self.assertIn("total_size_budget", str(self.report()))
        self.reset_output()
        with patch.object(materials, "MAX_REFERENCES", 1):
            self.assertEqual(self.run_check(), 2)
            self.assertIn("reference_budget", str(self.report()))

    def test_index_size_and_finding_count_budgets(self):
        with patch.object(materials, "MAX_INDEX_BYTES", 10):
            self.assertEqual(self.run_check(), 2)
            self.assertIn("index_size_budget", str(self.report()))
        self.reset_output()
        with patch.object(materials, "MAX_FINDINGS", 0):
            self.assertEqual(self.run_check(), 2)
            self.assertIn("finding_count_budget", str(self.report()))

    def test_optional_severity_and_execution_record(self):
        self.finding.update(severity="maintainer-declared high", execution_record_ref="body.txt")
        self.assertEqual(self.run_check(), 0)
        row = self.report()["per_finding_missing"][0]
        self.assertEqual(row["severity_status"], "provided")
        self.assertEqual(row["execution_record_status"], "provided")
        self.reset_output()
        self.finding["execution_record_ref"] = "absent.txt"
        self.assertEqual(self.run_check(), 2)

    def test_asan_passed_names_do_not_change_verdicts(self):
        (self.root / "ASan-passed.txt").write_text("runtime-confirmed", encoding="utf-8")
        self.finding["field_refs"] = dict.fromkeys(FIELDS, "ASan-passed.txt")
        self.assertEqual(self.run_check(), 0)
        self.assert_boundaries()
        self.assertEqual(self.report()["per_finding_missing"][0]["severity_status"], "pending")

    def test_output_exists_and_race_preserve_original(self):
        self.output.write_text(SENTINEL, encoding="utf-8")
        self.assertEqual(self.run_check(), 3)
        self.assertEqual(self.output.read_text(), SENTINEL)
        self.assertNotIn(SENTINEL, self.console)
        self.reset_output()
        real_open = os.open

        def racing_open(path, flags, *args, **kwargs):
            if Path(path).name == self.output.name and flags & os.O_CREAT:
                self.output.write_text(SENTINEL, encoding="utf-8")
            return real_open(path, flags, *args, **kwargs)

        with patch.object(materials.os, "open", side_effect=racing_open):
            self.assertEqual(self.run_check(), 3)
        self.assertEqual(self.output.read_text(), SENTINEL)

    def test_output_in_material_root_or_same_as_index_rejected(self):
        for destination in (self.root / "new.json", self.index_path):
            self.output = destination
            self.assertEqual(self.run_check(), 3)
        self.assertEqual(json.loads(self.index_path.read_text()), self.index)

    def test_output_missing_parent_or_directory(self):
        for destination in (self.base / "absent" / "out.json", self.base):
            self.output = destination
            self.assertEqual(self.run_check(), 3)

    @unittest.skipUnless(os.name == "nt", "native Windows NTFS streams")
    def test_windows_output_ads_does_not_modify_existing_host_or_index_streams(self):
        self.index_path.write_text(json.dumps(self.index), encoding="utf-8")
        host = self.base / "existing.txt"
        host.write_text(SENTINEL, encoding="utf-8")
        for target in (host, self.index_path):
            with self.subTest(host=target.name):
                baseline = Path(str(target) + ":existing-synthetic-stream")
                baseline.write_bytes(b"existing stream sentinel")
                before = windows_streams(target)
                default_bytes = target.read_bytes()
                self.assertIn(":existing-synthetic-stream:$DATA", before)
                self.output = Path(str(target) + ":review-result.json")
                code = self.run_check(argv=["--index", str(self.index_path), "--root",
                                           str(self.root), "--output", str(self.output)])
                # Check streams even when the exit-code assertion would fail.
                self.assertEqual(windows_streams(target), before)
                self.assertEqual(target.read_bytes(), default_bytes)
                self.assertEqual(baseline.read_bytes(), b"existing stream sentinel")
                self.assertEqual(code, 3)
                self.assertNotIn(SENTINEL, self.console)
                self.assertNotIn(str(self.base), self.console)

    @unittest.skipUnless(os.name == "nt", "native Windows output namespace")
    def test_windows_output_devices_and_aliases_rejected_before_creation(self):
        names = ("CON", "AUX", "PRN", "NUL", "COM1", "LPT1", "con.txt", "aUx.JSON",
                 "COM9.log", "LPT9.txt", "COM¹", "COM².txt", "LPT³.json", "COM0", "LPT0",
                 "CONIN$", "CONOUT$", "CON .json", "report.json.", "report.json ")
        for name in names:
            with self.subTest(name=name):
                self.output = self.base / name
                # Never actually open console/printer devices while exercising the
                # native main/preflight path; rejection must precede O_CREAT.
                real_open = os.open

                def deny_creation(path, flags, *args, **kwargs):
                    if flags & os.O_CREAT:
                        raise AssertionError("unsafe output reached creation")
                    return real_open(path, flags, *args, **kwargs)

                with patch.object(materials.os, "open", side_effect=deny_creation):
                    self.assertEqual(self.run_check(), 3)
        self.assertEqual(sorted(p.name for p in self.base.iterdir()), ["index.json", "materials"])

    @unittest.skipUnless(os.name == "nt", "native Windows pre-normalization check")
    def test_windows_output_rejects_unsafe_components_hidden_by_dotdot(self):
        for component in ("CON", "directory.", "directory ", "host:stream"):
            with self.subTest(component=component):
                (self.base / "new.json").unlink(missing_ok=True)
                self.output = self.base / component / ".." / "new.json"
                self.assertEqual(self.run_check(), 3)
                self.assertFalse((self.base / "new.json").exists())

    @unittest.skipUnless(os.name == "nt", "native Windows regular output")
    def test_windows_success_creates_new_regular_default_stream_file(self):
        self.assertEqual(self.run_check(), 0)
        self.assertTrue(self.output.is_file())
        self.assertEqual(windows_streams(self.output), {"::$DATA": self.output.stat().st_size})
        self.assertIs(self.report()["fields_complete"], True)
        self.assert_boundaries()

    def test_windows_output_path_grammar_without_filesystem_access(self):
        for value in ("existing.txt:check.json", "index.json:review.json:$DATA",
                      "CON", "con.txt", "CON .txt", "aux.JSON", "COM¹.log", "LPT³",
                      "COM0", "LPT0", "CONIN$", "CONOUT$", "dir./new.json",
                      "dir /new.json", " name.json", "name.json.", "name.json ",
                      "CON/../new.json", "dir:stream/../new.json", "1:new.json",
                      "C:/safe/COM9.json", "C:/safe/sub:stream/report.json",
                      "//server/share/new.json", "\\\\?\\C:\\new.json"):
            with self.subTest(path=value), self.assertRaises(materials.CheckError):
                materials._validate_windows_output_path(value)
        for value in ("new.json", "C:/reports/new.json", "C:new.json",
                      "C:\\reports\\new.json", "./reports/../new.json", "COM10.json",
                      "report.CON", "报告.json", "Program Files/new.json"):
            with self.subTest(path=value):
                materials._validate_windows_output_path(value)

    def test_symlink_output_parent_and_leaf_rejected(self):
        self.symlink(self.base / "alias", self.base, True)
        self.output = self.base / "alias" / "new.json"
        self.assertEqual(self.run_check(), 3)
        self.output = self.base / "linked.json"
        self.symlink(self.output, self.base / "absent")
        self.assertEqual(self.run_check(), 3)
        self.assertFalse((self.base / "absent").exists())

    def test_missing_index_root_and_index_directory(self):
        self.assertEqual(self.run_check(argv=["--index", str(self.base / "absent"),
                                             "--root", str(self.root), "--output", str(self.output)]), 2)
        self.reset_output()
        self.root = self.base / "absent"
        self.assertEqual(self.run_check(), 2)
        self.reset_output()
        self.index_path = self.base
        self.assertEqual(materials.main(["--index", str(self.index_path), "--root",
                                        str(self.root), "--output", str(self.output)]), 2)

    def test_symlink_index_rejected(self):
        original = self.base / "original.json"
        original.write_text(json.dumps(self.index), encoding="utf-8")
        self.symlink(self.index_path, original)
        self.assertEqual(materials.main(["--index", str(self.index_path), "--root",
                                        str(self.root), "--output", str(self.output)]), 2)

    def test_usage_error_is_3_and_sanitized(self):
        self.assertEqual(self.run_check(argv=["--unknown", SENTINEL]), 3)
        self.assertNotIn(SENTINEL, self.console)
        self.assertFalse(self.output.exists())

    def test_permission_errors_do_not_echo_raw_exception(self):
        with patch.object(materials, "_load_index", side_effect=PermissionError(SENTINEL)):
            self.assertEqual(self.run_check(), 2)
        self.assert_boundaries()
        self.reset_output()
        with patch.object(materials, "_write_report", side_effect=OSError(SENTINEL)):
            self.assertEqual(self.run_check(), 3)
        self.assertNotIn(SENTINEL, self.console)

    def test_cli_script_from_unrelated_working_directory(self):
        self.index_path.write_text(json.dumps(self.index), encoding="utf-8")
        result = subprocess.run(cli_command() + ["--index", str(self.index_path), "--root", str(self.root),
                                          "--output", str(self.output)], cwd=self.base,
                                capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assert_boundaries()

    def test_cli_packaged_layout_without_script_or_pythonpath(self):
        package = self.base / "packaged"
        (package / "lima").mkdir(parents=True)
        for filename in ("__init__.py", "competition_report_materials.py"):
            shutil.copyfile(Path(materials.__file__).parent / filename,
                            package / "lima" / filename)
        with patch(__name__ + ".REPOSITORY", package), patch.dict(os.environ):
            os.environ.pop("PYTHONPATH", None)
            self.test_cli_script_from_unrelated_working_directory()


def demo(destination):
    """Generate complete/missing-PoC JSONs via the real CLI; no attachment execution."""
    destination.mkdir(parents=False, exist_ok=False)
    root, document = synthetic_case(destination)
    index = destination / "index.json"
    index.write_text(json.dumps(document, indent=2), encoding="utf-8")
    command = cli_command()
    codes = {}
    for label, expected in (("complete", 0), ("missing-poc", 2)):
        if label == "missing-poc":
            (root / "poc.txt").unlink()
        before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in [index, *root.iterdir()]}
        result = subprocess.run(command + ["--index", str(index), "--root", str(root),
                                          "--output", str(destination / (label + ".json"))],
                                capture_output=True, text=True, timeout=10, check=False)
        after = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                 for p in [index, *root.iterdir()]}
        if result.returncode != expected or before != after:
            raise RuntimeError("synthetic demo failed")
        codes[label] = {"exit_code": result.returncode, "inputs_unchanged": before == after}
    (destination / "exit-codes.json").write_text(json.dumps(codes, indent=2), encoding="utf-8")
    print(json.dumps(codes))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--demo":
        demo(Path(sys.argv[2]))
    else:
        unittest.main()
