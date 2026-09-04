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


if __name__ == "__main__":
    unittest.main()
