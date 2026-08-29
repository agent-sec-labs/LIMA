from __future__ import annotations

from html.parser import HTMLParser
from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "web"


class _StrictEnoughHTMLParser(HTMLParser):
    """Exercise the document parser so malformed markup fails loudly."""


def _read(name: str) -> str:
    return (WEB / name).read_text(encoding="utf-8")


def _check_task_oriented_navigation_and_first_run_guidance() -> None:
    html = _read("index.html")
    parser = _StrictEnoughHTMLParser()
    parser.feed(html)
    parser.close()

    assert "砺码 · LIMA" in html
    assert "SecurityAgent" not in html
    assert "EvoAgent" not in html
    for label in ("开始", "发起审计", "审计结果", "系统能力", "模型设置"):
        assert label in html
    assert 'id="demo-login"' in html
    assert 'id="overview-demo"' in html
    assert 'id="load-audit-sample"' in html
    assert html.count('data-step="') == 3
    assert 'data-audit-mode="repository"' in html
    assert 'data-audit-mode="diff"' in html


def _check_report_surface_is_human_readable_not_a_raw_payload_dump() -> None:
    html = _read("index.html")
    script = _read("app.js")

    assert '<div id="task-report"' in html
    assert '<pre id="task-report"' not in html
    assert "function renderTaskReport" in script
    assert "finding-table" in script
    assert "severity-bars" in script
    assert "formatJson" not in script
    assert "JSON.stringify(task" not in script


def _check_frontend_includes_feedback_guards_and_destructive_confirmation() -> None:
    html = _read("index.html")
    script = _read("app.js")

    assert 'id="toast-stack"' in html
    assert 'id="confirm-modal"' in html
    assert "function confirmAction" in script
    assert "await confirmAction" in script
    assert "spinner-large" in script
    assert 'role="alert"' in html


def _check_model_helper_never_persists_or_posts_the_user_api_key() -> None:
    html = _read("index.html")
    script = _read("app.js")

    assert 'id="model-api-key"' in html
    assert 'autocomplete="off"' in html
    assert "function buildModelConfig" in script
    assert "LIMA_DEEPSEEK_API_KEY" in script
    assert "LIMA_OPENROUTER_API_KEY" in script
    assert "LIMA_LLM_API_KEY" in script
    assert "EVOAGENT_LLM_API_KEY" not in script
    assert not re.search(r"(?:localStorage|sessionStorage)\.setItem\([^\n]*api[_-]?key", script, re.I)
    assert "/v1/settings" not in script


def _check_repository_target_normalization_rejects_unsafe_path_shapes() -> None:
    script = _read("app.js")

    assert "function normalizeRepositoryTarget" in script
    assert 'pieces.length !== 2' in script
    assert 'part === ".."' in script
    assert "github.com" in script


def _check_visual_system_has_focus_tooltips_loading_and_responsive_rules() -> None:
    css = _read("app.css")
    html = _read("index.html")

    assert "--primary: #2457d6" in css
    assert "--page: #f4f7fb" in css
    assert ":focus-visible" in css
    assert "[data-tooltip]" in css
    assert "prefers-reduced-motion" in css
    assert "@media (max-width: 700px)" in css
    assert 'data-tooltip="刷新当前页面数据"' in html
    assert 'data-tooltip="显示或隐藏 API Key"' in html


def _check_lima_logo_is_safe_scalable_and_wired_as_favicon() -> None:
    html = _read("index.html")
    logo_path = WEB / "lima-mark.svg"
    logo = logo_path.read_text(encoding="utf-8")
    api = (ROOT / "lima" / "api.py").read_text(encoding="utf-8")

    root = ET.parse(logo_path).getroot()
    assert root.tag.endswith("svg")
    assert root.attrib["viewBox"] == "0 0 64 64"
    assert "<script" not in logo.lower()
    assert '<link rel="icon" type="image/svg+xml"' in html
    assert html.count("/assets/lima-mark.svg") == 3
    assert 'if path == "/assets/lima-mark.svg"' in api


def _check_cxx_report_contract_exposes_layered_evidence_safely() -> None:
    script = _read("app.js")
    css = _read("app.css")

    for token in (
        "function analysisModeLabel", "纯源码候选", "构建支持的静态验证",
        "Sanitizer 动态确认", "纯源码分析，尚未经过目标项目构建验证",
        "工具证据 / trace", "分析降级说明", "不支持自动修复",
        "finding.language", "finding.symbol", "evidence_records", "escapeHtml",
        "automatic_repair !== false", "VERIFIED_STATES",
    ):
        assert token in script
    assert "includes(\"verified\")" not in script
    assert "escapeHtml(finding.language" in script
    assert "escapeHtml(finding.symbol" in script
    assert "escapeHtml(record.snippet" in script
    assert "[内部地址已隐藏]" in script
    assert "[运行路径已隐藏]" in script
    assert "[敏感参数已隐藏]" in script
    assert "finding-analysis-mode" in css
    assert "source-only-warning" in css


def _check_cxx_report_repair_gate_uses_explicit_eligibility() -> None:
    script = _read("app.js")

    assert "function canAutomaticallyRepair" in script
    assert "!isCxxFinding(finding)" in script
    assert "const hasRepairableFinding = findings.some(" in script
    assert "reportReady && repositoryScan && hasRepairableFinding" in script
    assert "reportReady && task.pull_request && hasRepairableFinding" in script


class FrontendUiTests(unittest.TestCase):
    def test_task_oriented_navigation_and_first_run_guidance(self) -> None:
        _check_task_oriented_navigation_and_first_run_guidance()

    def test_report_surface_is_human_readable_not_a_raw_payload_dump(self) -> None:
        _check_report_surface_is_human_readable_not_a_raw_payload_dump()

    def test_feedback_guards_and_destructive_confirmation(self) -> None:
        _check_frontend_includes_feedback_guards_and_destructive_confirmation()

    def test_model_helper_never_persists_or_posts_the_user_api_key(self) -> None:
        _check_model_helper_never_persists_or_posts_the_user_api_key()

    def test_repository_target_normalization_rejects_unsafe_path_shapes(self) -> None:
        _check_repository_target_normalization_rejects_unsafe_path_shapes()

    def test_visual_system_has_focus_tooltips_loading_and_responsive_rules(self) -> None:
        _check_visual_system_has_focus_tooltips_loading_and_responsive_rules()

    def test_lima_logo_is_safe_scalable_and_wired_as_favicon(self) -> None:
        _check_lima_logo_is_safe_scalable_and_wired_as_favicon()

    def test_cxx_report_contract_exposes_layered_evidence_safely(self) -> None:
        _check_cxx_report_contract_exposes_layered_evidence_safely()

    def test_cxx_report_repair_gate_uses_explicit_eligibility(self) -> None:
        _check_cxx_report_repair_gate_uses_explicit_eligibility()
