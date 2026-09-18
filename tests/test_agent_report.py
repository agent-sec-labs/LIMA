"""Report agent tests (plan Task 6, design section 7).

Zero-network and offline: the CVE index is a local list of dicts (or the
shipped ``evaluation_data/cve_index/`` sample) and the dossier is pure
Markdown rendering over a :class:`~lima.agent_orchestrator.PlatformFinding`.
Red lines pinned here:

- the dossier follows the user's eRST template sections (0 metadata,
  1 profile, 2 target context, 3 technical analysis, 4 reproduction,
  5 impact, 6 remediation & disclosure);
- honesty: only ``runtime-confirmed`` findings backed by a hit ASan
  experiment may carry the "已通过 ASAN 物理验证" wording; evidence-less
  states render as 待复核 with the conservative severity;
- the PoC driver is included verbatim inside a fenced code block next to
  the real workbench compile/run commands; a driver containing backtick
  runs upgrades the fence instead of breaking out;
- CVE matching is the three-key offline match (component prefix, path
  glob, commit-window overlap when commits are provided); no match
  returns an empty tuple and renders as 暂无对应公开 CVE, never a guess;
- ``load_cve_index`` rejects schema violations with ``ValueError``;
- internal ids are deterministic ``LIMA-FIND-YYYY-NNN`` assigned in
  severity-then-path order.
"""

import datetime
import json
import re
import tempfile
import unittest
from pathlib import Path

from lima.agent_orchestrator import PlatformFinding
from lima.agent_report import (
    DossierContext,
    generate_all_dossiers,
    generate_dossier,
    load_cve_index,
    match_cve,
)
from lima.models import EvidenceRecord

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_INDEX_DIR = REPO_ROOT / "evaluation_data" / "cve_index"

DRIVER = (
    "#include <stdio.h>\n"
    "int db_put(int value);\n"
    "int main(void) {\n"
    "    db_put(7);\n"
    "    return 0;\n"
    "}\n"
)

HIT_LOG = (
    {
        "round": 1,
        "driver_sha256": "0123456789abcdef",
        "stage": "run",
        "ok": True,
        "exit_code": 1,
        "error_type": "heap-use-after-free",
        "faulting_line": 42,
        "hit": True,
    },
)

CVE_ENTRY = {
    "cve_id": "CVE-2026-1001",
    "component": "third_party/sample-lib",
    "affected_paths": ["third_party/sample-lib/src/*.cpp"],
    "introduced_commit": "aaaa",
    "fixed_commit": "bbbb",
    "summary": "sample advisory used by the tests",
}


def _finding(**overrides) -> PlatformFinding:
    defaults = dict(
        target_id="lead-01",
        path="third_party/sample-lib/src/db.cpp",
        line=42,
        symbol="db_put",
        cwe="CWE-416",
        state="runtime-confirmed",
        hypothesis_reason="对象在 free 之后仍被解引用读取",
        poc_driver_code=DRIVER,
        experiment_log=HIT_LOG,
        identity=None,
        evidence_records=(
            EvidenceRecord(
                source="asan",
                kind="runtime",
                path="third_party/sample-lib/src/db.cpp",
                line=42,
                snippet="==1==ERROR: AddressSanitizer: heap-use-after-free",
                rule_id="asan.repro",
                cwe="CWE-416",
                symbol="db_put",
            ),
        ),
    )
    defaults.update(overrides)
    return PlatformFinding(**defaults)


def _context(**overrides) -> DossierContext:
    defaults = dict(
        repository="sample/repository",
        component="third_party/sample-lib",
        openharmony_versions=("OpenHarmony 5.0",),
        commit_range="aaaa..bbbb",
        poc_driver_code="",
        experiment_log=(),
        cve_ids=(),
        patch_suggestion="",
        internal_id="LIMA-FIND-2026-001",
    )
    defaults.update(overrides)
    return DossierContext(**defaults)


class CveMatchTests(unittest.TestCase):
    def test_cve_match_three_keys(self):
        index = [CVE_ENTRY]
        path = "third_party/sample-lib/src/db.cpp"
        component = "third_party/sample-lib"
        # All three keys align: component prefix, path glob, commit window.
        self.assertEqual(
            match_cve(component, path, ("aaaa", "cccc"), index),
            ("CVE-2026-1001",),
        )
        # Component key fails.
        self.assertEqual(
            match_cve("other-lib", path, ("aaaa",), index), (),
        )
        # Path key fails.
        self.assertEqual(match_cve(component, "elsewhere/x.cpp", None, index), ())
        # Commit key fails: the window excludes both indexed commits.
        self.assertEqual(
            match_cve(component, path, ("dddd", "eeee"), index), (),
        )
        # No commit window provided: the commit key is skipped, not guessed.
        self.assertEqual(match_cve(component, path, None, index), ("CVE-2026-1001",))

    def test_cve_no_match_returns_empty(self):
        self.assertEqual(
            match_cve(
                "third_party/sample-lib",
                "third_party/sample-lib/src/db.cpp",
                None,
                [],
            ),
            (),
        )
        unrelated = dict(
            CVE_ENTRY,
            cve_id="CVE-2026-1002",
            component="third_party/unrelated",
            affected_paths=["docs/*.md"],
        )
        self.assertEqual(
            match_cve(
                "third_party/sample-lib",
                "third_party/sample-lib/src/db.cpp",
                None,
                [unrelated],
            ),
            (),
        )

    def test_cve_index_schema_validation_rejects(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            bad_entries = [
                ("missing-field.json", [{key: value for key, value in CVE_ENTRY.items()
                                         if key != "summary"}]),
                ("bad-type.json", [dict(CVE_ENTRY, affected_paths="src/*.cpp")]),
                ("bad-id.json", [dict(CVE_ENTRY, cve_id="CVE-26-1")]),
                ("unknown-field.json", [dict(CVE_ENTRY, extra="nope")]),
                ("empty-paths.json", [dict(CVE_ENTRY, affected_paths=[])]),
                ("not-a-list.json", dict(CVE_ENTRY)),
            ]
            for name, payload in bad_entries:
                (root / name).write_text(
                    json.dumps(payload), encoding="utf-8",
                )
            for name, _ in bad_entries:
                with self.subTest(file=name):
                    with self.assertRaises(ValueError):
                        load_cve_index(root / name)
            # Directory loading aggregates sorted *.json files, skipping
            # schemas, and rejects the first bad entry it meets.
            with self.assertRaises(ValueError):
                load_cve_index(root)
        # The shipped sample index loads and stays a two-entry sample.
        entries = load_cve_index(SAMPLE_INDEX_DIR)
        self.assertEqual(len(entries), 2)
        self.assertEqual(
            [entry["cve_id"] for entry in entries],
            ["CVE-2099-0001", "CVE-2099-0002"],
        )
        self.assertTrue(all("SAMPLE" in entry["summary"] for entry in entries))


class DossierStructureTests(unittest.TestCase):
    def test_dossier_structure_follows_erst_sections(self):
        report = generate_dossier(_finding(), _context())
        self.assertIn("# 漏洞研究报告", report)
        for header in (
            "## 0. 基本信息",
            "## 1. 漏洞概览",
            "## 2. 目标环境",
            "## 3. 技术分析",
            "## 4. 复现指南",
            "## 5. 影响分析",
            "## 6. 修复建议",
        ):
            self.assertIn(header, report)
        # Metadata block carries the eRST-style fields.
        for field in ("内部编号", "漏洞名称", "发现日期", "当前状态", "CVE 编号"):
            self.assertIn(f"**{field}**", report)

    def test_state_mapping_honesty(self):
        confirmed = generate_dossier(_finding(), _context())
        self.assertIn("已通过 ASAN 物理验证", confirmed)
        self.assertIn("高危", confirmed)
        # Semantic support without experiments never claims verification.
        semantic = generate_dossier(
            _finding(
                state="semantic-supported",
                experiment_log=(),
                evidence_records=(),
            ),
            _context(),
        )
        self.assertNotIn("已通过 ASAN 物理验证", semantic)
        self.assertNotIn("已确认", semantic)
        self.assertIn("待复核", semantic)
        self.assertIn("语义支持", semantic)
        self.assertIn("低危", semantic)
        # A runtime-confirmed label without a hit experiment is downgraded
        # at the report boundary: no physical-verification wording.
        unbacked = generate_dossier(
            _finding(state="runtime-confirmed", experiment_log=()),
            _context(),
        )
        self.assertNotIn("已通过 ASAN 物理验证", unbacked)
        self.assertIn("待复核", unbacked)
        self.assertNotIn("高危", unbacked)

    def test_poc_driver_included_with_compile_command(self):
        report = generate_dossier(_finding(), _context())
        self.assertIn(DRIVER.rstrip(), report)
        self.assertIn("```cpp", report)
        # The real workbench commands, paste-ready.
        self.assertIn(
            "clang++-14 -fsanitize=address -g -O1 "
            "third_party/sample-lib/src/db.cpp poc_driver.cpp -o poc_driver",
            report,
        )
        self.assertIn("./poc_driver", report)
        # The executed experiment ledger is rendered as bounded data.
        self.assertIn("heap-use-after-free", report)

    def test_cve_none_marked_pending_review(self):
        without = generate_dossier(_finding(), _context(cve_ids=()))
        self.assertIn("暂无对应公开 CVE", without)
        self.assertIn("OpenHarmony 安全奖励计划", without)
        self.assertIn("待评审", without)
        with_cve = generate_dossier(
            _finding(), _context(cve_ids=("CVE-2026-1001",)),
        )
        self.assertIn("CVE-2026-1001", with_cve)
        self.assertNotIn("暂无对应公开 CVE", with_cve)

    def test_internal_id_auto_increment_format(self):
        results = generate_all_dossiers(
            [_finding(), _finding(target_id="lead-02")],
            _context(internal_id=""),
            [],
        )
        year = datetime.date.today().year
        ids = []
        for _, report in results:
            match = re.search(r"内部编号\*\*: (LIMA-FIND-\d{4}-\d{3})", report)
            self.assertIsNotNone(match)
            ids.append(match.group(1))
        self.assertEqual(
            ids,
            [f"LIMA-FIND-{year}-001", f"LIMA-FIND-{year}-002"],
        )

    def test_escaped_or_fenced_code(self):
        # A driver containing a backtick run must not break the fence.
        hostile_driver = DRIVER + "    printf(\"``` suspicious ```\");\n"
        report = generate_dossier(
            _finding(poc_driver_code=hostile_driver), _context(),
        )
        self.assertIn("````cpp", report)
        self.assertIn('printf("``` suspicious ```");', report)
        # The experiment ledger stays inside a fenced data block.
        text_blocks = re.findall(r"```text\n(.*?)```", report, re.DOTALL)
        self.assertTrue(any("hit=True" in block for block in text_blocks))

    def test_generate_all_sorted_by_severity_then_path(self):
        high_z = _finding(
            target_id="lead-z", path="src/z.cpp", state="runtime-confirmed",
        )
        high_a = _finding(
            target_id="lead-a", path="src/a.cpp", state="runtime-confirmed",
        )
        low_b = _finding(
            target_id="lead-b", path="src/b.cpp",
            state="semantic-supported", experiment_log=(), evidence_records=(),
        )
        results = generate_all_dossiers(
            [high_z, low_b, high_a], _context(internal_id=""), [],
        )
        self.assertEqual(
            [finding.target_id for finding, _ in results],
            ["lead-a", "lead-z", "lead-b"],
        )
        # CVE matching is applied per finding during batch generation.
        sample_entries = load_cve_index(SAMPLE_INDEX_DIR)
        results = generate_all_dossiers(
            [_finding()], _context(internal_id=""), sample_entries,
        )
        self.assertEqual(len(results), 1)
        self.assertIn("CVE-2099-0001", results[0][1])


if __name__ == "__main__":
    unittest.main()
