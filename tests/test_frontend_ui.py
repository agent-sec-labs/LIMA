"""T10 前端结构契约（issue #43）：React 是唯一前端表面，legacy web/ 已删除。

legacy 时代本文件逐行锚定 web/index.html + web/app.js 的行为，是因为 Vanilla JS
没有测试运行器；React 有 Vitest 之后行为断言由 frontend/ 套件承担，本文件改为
锚定跨栈结构不变量：

- legacy 目录删除、品牌资产迁移；
- api.py 静态路由只服务 React dist（/ 重定向 /app/、无构建产物 fail-closed）；
- 前端源包含任务详情对等功能（修复预览 / 修复分支 / 反馈 / 裁决推导）；
- Docker / CI / 文档不再引用 web/。
"""

from __future__ import annotations

from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[1]


def _read(*parts: str) -> str:
    return (ROOT.joinpath(*parts)).read_text(encoding="utf-8")


class ReactOnlyFrontendContractTests(unittest.TestCase):
    def test_legacy_web_directory_is_removed_and_logo_moves_to_docs(self) -> None:
        self.assertFalse((ROOT / "web").exists(), "legacy web/ 目录必须整体删除")
        self.assertTrue(
            (ROOT / "docs" / "assets" / "lima-mark.svg").is_file(),
            "README 引用的品牌资产应保留在 docs/assets/",
        )
        readme = _read("README.md")
        self.assertIn("docs/assets/lima-mark.svg", readme)
        self.assertNotIn("web/lima-mark.svg", readme)

    def test_api_serves_react_only_with_root_redirect(self) -> None:
        api = _read("lima", "api.py")
        self.assertNotIn("WEB_ROOT", api)
        self.assertNotIn("_serve_file", api)
        self.assertNotIn("/assets/app.js", api)
        self.assertNotIn("/assets/login.css", api)
        # 根路径正式切换（冻结决策 3）：/ → /app/，无构建产物时 fail-closed 404。
        self.assertIn('self.send_header("Location", "/app/")', api)
        self.assertIn("frontend build not present", api)
        # GitHub App 安装回跳指向 React 设置页（legacy #github-install 已退役）。
        self.assertIn('self.send_header("Location", "/app/#/settings?"', api)

    def test_task_detail_parity_anchors_exist_in_react_sources(self) -> None:
        client = _read("frontend", "src", "shared", "api", "client.ts")
        for endpoint in (
            "/repair-preview",
            "/fix",
            "/feedback",
            "/github/installations",
        ):
            self.assertIn(endpoint, client)
        detail = _read("frontend", "src", "features", "tasks", "TaskDetailPage.tsx")
        for surface in (
            "生成修复预览",
            "创建修复分支",
            "这个判断准确吗？",
            "证据处置：",
        ):
            self.assertIn(surface, detail)
        model = _read("frontend", "src", "features", "tasks", "model.ts")
        # 裁决推导 fail-closed 语义（与已删除的 web/app.js 逐字对齐）。
        self.assertIn("legacy-fail-closed", model)
        self.assertIn("unverified-finding-requires-human-review", model)
        self.assertIn("候选 · 需复核", model)

    def test_router_covers_the_workspace_surfaces(self) -> None:
        router = _read("frontend", "src", "router", "index.tsx")
        for route in (
            "audit/new",
            "tasks/:taskId",
            "experiments",
            "skills",
            "settings",
            "evolution",
        ):
            self.assertIn(f'path: "{route}"', router)

    def test_frontend_toolchain_scripts_are_declared(self) -> None:
        package = _read("frontend", "package.json")
        for script in (
            '"typecheck"',
            '"test:coverage"',
            '"build"',
            '"e2e"',
        ):
            self.assertIn(script, package)

    def test_build_pipeline_no_longer_references_legacy_web(self) -> None:
        dockerfile = _read("Dockerfile")
        self.assertNotIn(" ./web", dockerfile)
        self.assertNotIn("COPY web", dockerfile)
        # 运行时无 Node：frontend 仅存在于构建期阶段。
        self.assertIn("AS frontend-build", dockerfile)
        self.assertIn("--from=frontend-build /build/dist", dockerfile)
        workflow = _read(".github", "workflows", "ci.yml")
        self.assertNotIn("node --check", workflow)

    def test_contributor_docs_point_to_the_frontend_toolchain(self) -> None:
        contributing = _read("CONTRIBUTING.md")
        self.assertNotIn("web/app.js", contributing)
        self.assertNotIn("node --check", contributing)
        self.assertIn("npm run typecheck", contributing)
        collaboration = _read("docs", "GITHUB_COLLABORATION.md")
        self.assertNotIn("node --check web", collaboration)
        handoff = _read("docs", "DEVELOPER_HANDOFF.md")
        self.assertNotIn("node --check web", handoff)


class CxxAgentWebContractTests(unittest.TestCase):
    """Task 18：C/C++ Agent finding 的 Web 契约（跨栈结构不变量）。

    React 是唯一前端表面：本类锚定三条不变量——

    - 修复入口永远是任务级按钮（后端 ``automatic_repair=False`` 的 UI 镜像），
      任何 finding 级别（含 ``source="cxx-agent"``）都不得出现修复操作；
    - 验证状态徽标语义 fail-closed：未知状态一律「候选 · 需复核」；
    - 前端无裸 HTML sink（React 文本插值自动转义），报告数据侧由
      ``lima.report`` 对模型产出字段做上下文编码（Task 5 惯例）。
    """

    def test_react_has_no_per_finding_repair_control(self) -> None:
        detail = _read("frontend", "src", "features", "tasks", "TaskDetailPage.tsx")
        # 两个任务级修复入口及其门禁：与单个 finding 的 source/language 无关。
        self.assertIn(
            "const showPreview = repositoryScan && findings.length > 0;", detail,
        )
        self.assertIn("const showFix = Boolean(task.pull_request);", detail)
        self.assertEqual(1, detail.count("api.createRepairPreview("))
        self.assertEqual(1, detail.count("api.createFix("))
        # finding 展开区只渲染解释/证据/建议文案，不含任何操作按钮。
        expanded = detail.split("expandedRowRender:", 1)[1].split("</Space>", 1)[0]
        self.assertIn("为什么是问题：", expanded)
        self.assertIn("关键证据：", expanded)
        self.assertIn("建议修复：", expanded)
        self.assertNotIn("Button", expanded)
        self.assertNotIn("onClick", expanded)

    def test_react_verification_badge_semantics_fail_closed(self) -> None:
        model = _read("frontend", "src", "features", "tasks", "model.ts")
        # verificationLabel：未知状态 fail-closed 为「候选 · 需复核」。
        self.assertIn('return "候选 · 需复核";', model)
        self.assertIn("export function verificationLabel", model)
        self.assertIn("export function isVerifiedState", model)
        # 无 adjudication 键时按 verification_state 推导且禁止自动放行。
        self.assertIn("unverified-finding-requires-human-review", model)

    def test_react_task_surfaces_have_no_raw_html_sink(self) -> None:
        for parts in (
            ("frontend", "src", "features", "tasks", "TaskDetailPage.tsx"),
            ("frontend", "src", "features", "tasks", "TaskListPage.tsx"),
            ("frontend", "src", "features", "tasks", "TaskCenter.test.tsx"),
            ("frontend", "src", "features", "tasks", "TaskDetail.report.test.tsx"),
            ("frontend", "src", "features", "tasks", "model.ts"),
        ):
            self.assertNotIn("dangerouslySetInnerHTML", _read(*parts))

    def test_report_payload_marks_cxx_agent_unrepairable_and_escaped(self) -> None:
        from lima.report import to_markdown

        finding = {
            "rule_id": "cxx.llm.cwe-416",
            "severity": "high",
            "title": "<script>alert(1)</script> use after free",
            "explanation": "free then write\n# injected heading",
            "path": "vuln.c",
            "line": 8,
            "evidence": "leak → free → buf[0]",
            "fix": "",
            "test": "",
            "cwe": "CWE-416",
            "source": "cxx-agent",
            "language": "c++",
            "symbol": "leak",
            "verification_state": "tool-corroborated",
            "automatic_repair": False,
            "candidate_id": "cand-123",
            "agent_role": "memory-lifetime",
            "trigger_path": ["leak", "free", "<img src=x onerror=alert(2)>"],
        }
        rendered = to_markdown({
            "repository": "team/project",
            "pull_request": None,
            "summary": "",
            "risk": "high",
            "reviewer": "local-rules",
            "findings": [finding],
            "collaboration": {},
            "adjudication": {},
        })

        # 注入串被上下文编码，不产生结构或脚本。
        self.assertNotIn("<script>", rendered)
        self.assertNotIn("<img", rendered)
        self.assertIn("&lt;script&gt;", rendered)
        self.assertIn("&lt;img src=x onerror=alert(2)&gt;", rendered)
        self.assertNotIn("\n# injected", rendered)
        # Web 数据契约：验证徽标、Agent 来源与不可修复标记。
        self.assertIn("- Verification state: `tool-corroborated` ·", rendered)
        self.assertIn("- Candidate: `cand-123`", rendered)
        self.assertIn("- Agent roles: `memory-lifetime`", rendered)
        self.assertIn(
            "- Trigger path: leak → free → &lt;img src=x onerror=alert(2)&gt;",
            rendered,
        )
        self.assertIn("不支持自动修复", rendered)


class UafV2WebContractTests(unittest.TestCase):
    """Task 11：UAF v2 审计视图（report.collaboration.uaf_v2）的 Web 契约。

    React 是唯一前端表面；本环境不装 node_modules，vitest 行为断言由
    ``TaskDetail.report.test.tsx`` 携带，这里锚定跨栈结构不变量：

    - 报告含 ``uaf_v2`` 时渲染折叠审计区，零调用 PASS 必须显示
      「确定性证明 · 未调用 LLM」，调用计数来自实际调用；
    - ``fact-verified`` / ``semantic-supported`` 有前端自有精确匹配徽标，
      未知状态仍 fail-closed「候选 · 需复核」；
    - UAF 审计区不含任何修复入口（任务级修复按钮数量不变）；
    - ``uaf_v2`` 是可选键：旧报告无此键零影响。
    """

    def _uaf_card_source(self) -> str:
        detail = _read("frontend", "src", "features", "tasks", "TaskDetailPage.tsx")
        return detail.split("function UafV2Card", 1)[1].split(
            "function ReportCard", 1
        )[0]

    def test_uaf_v2_audit_details_renders_summary_payload(self) -> None:
        detail = _read("frontend", "src", "features", "tasks", "TaskDetailPage.tsx")
        # 渐进读取：只有报告携带 uaf_v2 时才渲染审计区。
        self.assertIn("report.collaboration?.uaf_v2", detail)
        self.assertIn("C/C++ UAF v2（确定性证明）", detail)
        card = self._uaf_card_source()
        # llm_invoked 规则：零调用 PASS 全覆盖显示确定性证明注记。
        self.assertIn("确定性证明 · 未调用 LLM", card)
        self.assertIn("确定性证明 · 未调用 LLM", _read(
            "frontend", "src", "features", "tasks", "TaskDetail.report.test.tsx",
        ))
        # 有调用时显示实际调用次数。
        self.assertIn("LLM 调用：", card)
        # broker 三态都渲染。
        self.assertIn("broker.support", card)
        self.assertIn("broker.contradict", card)
        self.assertIn('broker["no-evidence"]', card)
        self.assertIn("automatic_repair=false", card)

    def test_uaf_v2_badges_use_frontend_label_map_fail_closed(self) -> None:
        model = _read("frontend", "src", "features", "tasks", "model.ts")
        # 两个新状态的精确匹配中文标签（前端自有 map，不依赖后端文本）。
        self.assertIn('"fact-verified": "事实已验证"', model)
        self.assertIn('"semantic-supported": "语义支持 · 需复核"', model)
        # 精确匹配先于子串匹配，且未知状态 fallback 保持不变。
        self.assertIn("EXACT_VERIFICATION_STATE_LABELS[state]", model)
        self.assertIn('return "候选 · 需复核";', model)

    def test_uaf_v2_audit_adds_no_repair_entry(self) -> None:
        detail = _read("frontend", "src", "features", "tasks", "TaskDetailPage.tsx")
        # 任务级修复入口数量与门禁保持 Task 18 契约。
        self.assertEqual(1, detail.count("api.createRepairPreview("))
        self.assertEqual(1, detail.count("api.createFix("))
        card = self._uaf_card_source()
        self.assertNotIn("api.", card)
        self.assertNotIn("Button", card)
        self.assertNotIn("onClick", card)

    def test_uaf_v2_report_type_is_optional_and_legacy_safe(self) -> None:
        types = _read("frontend", "src", "shared", "api", "types.ts")
        self.assertIn("uaf_v2?: UafV2Summary", types)
        self.assertIn("export interface UafV2Summary", types)
        report_tests = _read(
            "frontend", "src", "features", "tasks", "TaskDetail.report.test.tsx",
        )
        # 旧报告无 uaf_v2 键的兼容用例存在。
        self.assertIn("renders legacy reports without the uaf_v2 key unchanged", report_tests)


if __name__ == "__main__":
    unittest.main()
