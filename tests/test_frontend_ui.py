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
    for label in ("开始", "发起审计", "审计结果", "外部评测", "系统能力", "模型设置"):
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
    assert "function reportAdjudication" in script
    assert "function decisionForFinding" in script
    assert "function renderSemanticTriageStatus" in script
    assert "disposition-banner" in script
    assert "semantic-evidence" in script
    assert "模型不可用或输出不符合契约" in script
    assert "需要复核" in script
    assert "确定性缓解证据与模型 clean 结论一致" in script
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


def _check_experiment_center_is_guided_readable_and_fail_closed() -> None:
    html = _read("index.html")
    script = _read("app.js")
    api = (ROOT / "lima" / "api.py").read_text(encoding="utf-8")

    assert 'id="view-experiments"' in html
    assert 'id="experiment-wizard"' in html
    assert html.count('data-experiment-step="') == 3
    assert 'id="load-experiment-sample"' in html
    assert 'id="experiment-list"' in html
    assert 'id="experiment-detail"' in html
    assert 'data-tooltip="刷新实验记录"' in html
    assert "function loadExperiments" in script
    assert "function renderExperimentDetail" in script
    assert "function setExperimentPolling" in script
    assert "function actOnExperiment" in script
    assert "experimentSampleVisible && id === DEMO_EXPERIMENT.id" in script
    assert "renderExperimentDetail(DEMO_EXPERIMENT)" in script
    assert "experimentRefreshInFlight" in script
    assert "风险不变量召回率" in script
    assert "目标人工复核率" in script
    assert "setExperimentPolling(false)" in script
    assert "allow_ambiguous_retry: ambiguous" in script
    assert "await confirmAction" in script
    assert "JSON.stringify(record" not in script
    assert 'path == "/v1/experiments/catalog"' in api


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


def _check_github_source_scan_flow_is_offline_and_pinned() -> None:
    html = _read("index.html")
    script = _read("app.js")

    # 浏览器绝不解析 ref：整个前端不出现 api.github.com。
    assert "api.github.com" not in script
    assert "api.github.com" not in html
    # 请求体必须使用 T4 的 {"source": {...}} envelope。
    assert 'source: {' in script
    assert 'type: "github"' in script
    assert 'url: auditDraft.repository' in script
    # ref 原样透传给后端（worker 解析），并有移动 ref 钉死警告文案。
    assert 'ref: auditDraft.githubRef' in script
    assert "分支/标签会在扫描时被钉死为具体提交" in html
    assert "pinned to a specific commit at scan time" in html
    assert "function isMovingRef" in script
    assert "function normalizeRepositoryTarget" in script


def _check_github_source_capabilities_gating() -> None:
    html = _read("index.html")
    script = _read("app.js")

    # capabilities 驱动门禁：scan_sources.github 为 false 时禁用输入并提示。
    assert "scan_sources" in script
    assert "function updateSourceModeAvailability" in script
    assert "githubButton.disabled = enabled === false" in script
    assert "updateSourceMode(\"local\")" in script
    assert 'id="github-source-unavailable"' in html
    # 用户可见文案不暴露服务端环境变量名（管理员术语不出现在 UI）。
    assert "LIMA_REPOSITORY_SCAN_SOURCES" not in html
    assert "请联系管理员启用" in html
    assert 'data-source-mode="github"' in html
    assert 'data-source-mode="local"' in html


def _check_github_source_report_shows_resolved_sha() -> None:
    script = _read("app.js")

    assert "function renderSnapshotPin" in script
    assert "resolved_revision" in script
    assert "已扫描固定提交" in script
    assert "${renderSnapshotPin(report)}" in script


def _check_github_source_inputs_declare_no_secrets() -> None:
    html = _read("index.html")
    wizard = re.search(r'id="audit-wizard".*?id="wizard-running"', html, re.S)

    # ref 输入与 40/64 位 SHA 提示存在；扫描向导不引入任何 token/API key 输入
    # （登录密码框与模型配置的 key 输入位于向导之外，属于既有合法功能）。
    assert 'id="audit-github-ref"' in html
    assert "完整 40/64 位 commit SHA" in html
    assert 'id="github-ref-pin-warning"' in html
    assert 'id="github-ref-field"' in html
    assert wizard is not None
    assert not re.search(
        r'id="[^"]*(?:token|api[_-]?key|password)[^"]*"', wizard.group(0), re.I
    )


def _check_audit_wizard_recovers_without_refresh_and_task_detail_polls() -> None:
    script = _read("app.js")
    html = _read("index.html")

    # 提交成功后向导立即复位（202 后责任移交任务中心），运行面板不得残留。
    assert "function resetAuditWizard" in script
    assert "resetAuditWizard();" in script
    assert '$("#wizard-running").classList.add("hidden")' in script
    assert "function ensureAuditWizardReady" in script
    assert "ensureAuditWizardReady();" in script
    assert "auditSubmitting" in script
    assert 'if (view === "scan") {' in script
    # 同步失败必须回到可编辑态并保留草稿（setWizardStep(3) 在 catch 分支内）。
    assert "setWizardStep(3);" in script
    # 任务详情轮询：进入任务视图启动、离开/登出/终态/出错停止，防重入守卫存在。
    assert "function setTaskPolling" in script
    assert "function pollSelectedTask" in script
    assert "function taskTerminal" in script
    assert '["SUCCESS", "FAILED", "CANCELLED"].includes(normalizeState(state))' in script
    assert "taskPoller = window.setInterval" in script
    assert "window.clearInterval(taskPoller)" in script
    assert 'setTaskPolling(view === "tasks")' in script
    assert "setTaskPolling(false);" in script
    assert "document.hidden || location.hash.slice(1) !== \"tasks\"" in script
    assert 'id="wizard-running"' in html


class FrontendUiTests(unittest.TestCase):
    def test_task_oriented_navigation_and_first_run_guidance(self) -> None:
        _check_task_oriented_navigation_and_first_run_guidance()

    def test_report_surface_is_human_readable_not_a_raw_payload_dump(self) -> None:
        _check_report_surface_is_human_readable_not_a_raw_payload_dump()

    def test_feedback_guards_and_destructive_confirmation(self) -> None:
        _check_frontend_includes_feedback_guards_and_destructive_confirmation()

    def test_experiment_center_is_guided_readable_and_fail_closed(self) -> None:
        _check_experiment_center_is_guided_readable_and_fail_closed()

    def test_model_helper_never_persists_or_posts_the_user_api_key(self) -> None:
        _check_model_helper_never_persists_or_posts_the_user_api_key()

    def test_repository_target_normalization_rejects_unsafe_path_shapes(self) -> None:
        _check_repository_target_normalization_rejects_unsafe_path_shapes()

    def test_visual_system_has_focus_tooltips_loading_and_responsive_rules(self) -> None:
        _check_visual_system_has_focus_tooltips_loading_and_responsive_rules()

    def test_lima_logo_is_safe_scalable_and_wired_as_favicon(self) -> None:
        _check_lima_logo_is_safe_scalable_and_wired_as_favicon()

    def test_github_source_scan_flow_is_offline_and_pinned(self) -> None:
        _check_github_source_scan_flow_is_offline_and_pinned()

    def test_github_source_capabilities_gating(self) -> None:
        _check_github_source_capabilities_gating()

    def test_github_source_report_shows_resolved_sha(self) -> None:
        _check_github_source_report_shows_resolved_sha()

    def test_github_source_inputs_declare_no_secrets(self) -> None:
        _check_github_source_inputs_declare_no_secrets()

    def test_audit_wizard_recovers_without_refresh_and_task_detail_polls(self) -> None:
        _check_audit_wizard_recovers_without_refresh_and_task_detail_polls()
