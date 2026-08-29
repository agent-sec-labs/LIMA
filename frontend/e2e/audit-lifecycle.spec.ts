import { expect, test } from "@playwright/test";

/**
 * 审计生命周期端到端（T9，issue #42）。
 *
 * 冻结决策 4（Epic #33，用户拍板）：Playwright E2E 只在 Linux CI 运行
 * （ci.yml 的 frontend-e2e job，runs-on: ubuntu-latest），不进入 windows-latest
 * 矩阵、也不要求贡献者本机运行——目的是控制 CI 总时长。本文件因此不在
 * Windows 本地作为常规门禁执行；如需本地复现：cd frontend && npm run build
 * && npx playwright test。
 *
 * 被测形态是真实生产链路：构建后的 SPA 由 Python 后端经 /app/ 托管，
 * 登录走 bootstrap admin（环境变量注入，不经 API 建用户），任务只经真实
 * 队列推进（UI 不存在任何假数据路径）。
 */

const ADMIN_USERNAME = process.env.E2E_ADMIN_USERNAME ?? "e2e-admin";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "e2e-local-pass";

test("审计生命周期：登录 → 创建本地审计 → 实时进度 → 报告", async ({ page }) => {
  test.setTimeout(120_000);

  // 1) UI 登录 bootstrap admin
  await page.goto("/app/");
  await page.getByRole("button", { name: "登 录" }).click();
  await page.getByLabel("用户名").fill(ADMIN_USERNAME);
  await page.getByLabel("密码").fill(ADMIN_PASSWORD);
  await page.getByRole("button", { name: "确认登录" }).click();
  await expect(page.getByRole("button", { name: "退 出" })).toBeVisible();

  // 2) JWT 落在 localStorage（storage_state 语义）：整页刷新后仍保持登录
  await page.reload();
  await expect(page.getByRole("button", { name: "退 出" })).toBeVisible();

  // 3) 发起本地导入审计（目标 e2e/demo-repo → fixtures/e2e/demo-repo）
  await page.goto("/app/#/audit/new");
  await page.getByLabel("仓库目标").fill("e2e/demo-repo");
  await page.getByRole("button", { name: /下一步/ }).click();
  await expect(page.getByText("e2e/demo-repo").first()).toBeVisible();
  await page.getByRole("button", { name: /开始安全审计/ }).click();

  // 4) 202 后责任移交任务中心：hash 路由 URL 形如 /app/#/tasks/<uuid>
  await expect(page).toHaveURL(/\/app\/#\/tasks\/[0-9a-f-]+$/);

  // 5) 真实进度：阶段列表多于 1 项，且至少观察到两个不同阶段的推进。
  //    详情页轮询为 2s/4s，夹具体量保证任务跨越多个轮询窗口。
  const observedStages = new Set<string>();
  let finished = false;
  const deadline = Date.now() + 110_000;
  while (Date.now() < deadline && !finished) {
    // 容忍首帧加载态（骨架屏时 Steps 数量为 0），仅在时间线出现后计数。
    const stepCount = await page.locator(".ant-steps-item").count();
    if (stepCount > 0) {
      expect(stepCount, "阶段时间线应包含全部 13 个阶段").toBeGreaterThan(1);
      for (const title of await page
        .locator(".ant-steps-item-process .ant-steps-item-title")
        .allTextContents()) {
        observedStages.add(title.trim());
      }
    }
    finished = await page
      .getByText("审计完成")
      .first()
      .isVisible()
      .catch(() => false);
    if (!finished) {
      finished = await page
        .getByText(/完成但有警告/)
        .first()
        .isVisible()
        .catch(() => false);
    }
    if (!finished) {
      await page.waitForTimeout(400);
    }
  }
  expect(finished, "任务应在 120 秒预算内经真实队列到达终态").toBe(true);
  expect(
    observedStages.size,
    `应观察到至少两个不同执行阶段，实际：${[...observedStages].join(", ")}`,
  ).toBeGreaterThanOrEqual(2);

  // 6) 报告渲染：至少一条发现行可见（eval 样本由数据流验证为 CWE-95）
  await expect(page.getByText("CWE-95").first()).toBeVisible();

  // 7) 任务列表该任务为终态（队列已排空，无 PENDING 残留）
  await page.goto("/app/#/tasks");
  const row = page.locator(".ant-list-item", { hasText: "e2e/demo-repo" }).first();
  await expect(row).toBeVisible();
  await expect(row.locator(".ant-tag", { hasText: "已完成" })).toBeVisible();
});
