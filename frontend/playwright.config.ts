import { defineConfig } from "@playwright/test";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const here = fileURLToPath(new URL(".", import.meta.url));
const repoRoot = join(here, "..");

/**
 * T9 审计生命周期 E2E：只打真实生产形态——
 * 先 `npm run build`，再由 Python 后端（python -m lima）把 frontend/dist
 * 经 /app/ 静态托管（api handler 契约本身即被验证），不使用 vite dev server。
 *
 * 后端环境全部通过 webServer.env 注入：
 * - bootstrap admin 走 LIMA_BOOTSTRAP_ADMIN_*（不通过 API 建用户）；
 * - 每次运行独立 SQLite（runner.temp 语义：本机用 os.tmpdir + 运行 id）；
 * - LIMA_REPOSITORY_SCAN_SOURCES=both（为后续 GitHub 来源用例预留）；
 * - 语义复核 off，E2E 不接任何模型。
 */

const host = process.env.LIMA_HOST ?? "127.0.0.1";
// 默认 18081：本机 8080 常落入 Windows 动态端口保留段（WinError 10013）。
const port = Number(process.env.LIMA_PORT ?? 18081);
const runId = `${process.pid}-${Date.now()}`;

export default defineConfig({
  testDir: "./e2e",
  // 单后端、单数据库：串行执行，绝不并发。
  fullyParallel: false,
  workers: 1,
  // 7g：完整审计生命周期（登录→提交→进度→报告）预算 120 秒。
  timeout: 120_000,
  expect: { timeout: 10_000 },
  retries: process.env.CI ? 1 : 0,
  reporter: [
    ["list"],
    // 报告固定落在 frontend/test-results，绝不进入 tests/。
    ["html", { outputFolder: "test-results/html", open: "never" }],
  ],
  // 产物与 HTML 报告互为兄弟目录：html 报告生成前会清空自身目录，不能嵌套。
  outputDir: "test-results/output",
  use: {
    baseURL: `http://${host}:${port}/app/`,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  webServer: {
    command: "python -m lima",
    cwd: repoRoot,
    url: `http://${host}:${port}/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    env: {
      LIMA_HOST: host,
      LIMA_PORT: String(port),
      LIMA_DB_PATH: join(tmpdir(), `lima-e2e-${runId}.db`),
      LIMA_DATABASE_URL: "",
      // E2E 的后端姿态必须显式自包含：LIMA_AUTH_REQUIRED 默认 false 时
      // /v1/auth/login 返回 409（authentication is disabled）。本机曾靠根目录
      // .env 隐性开启认证而 CI 检出没有 .env，导致 PR #53 的 e2e 失败。
      LIMA_AUTH_REQUIRED: "true",
      // 仅测试用固定密钥（认证开启时 validate_evolution 要求 ≥32 字节）。
      LIMA_AUTH_SECRET: "e2e-insecure-secret-never-use-in-production",
      LIMA_BOOTSTRAP_ADMIN_USERNAME: process.env.E2E_ADMIN_USERNAME ?? "e2e-admin",
      LIMA_BOOTSTRAP_ADMIN_PASSWORD: process.env.E2E_ADMIN_PASSWORD ?? "e2e-local-pass",
      LIMA_REPOSITORY_SCAN_SOURCES: "both",
      LIMA_REPOSITORY_IMPORT_ROOT: join(here, "e2e", "fixtures"),
      LIMA_REPOSITORY_SCAN_LLM_MODE: "off",
      PYTHONUTF8: "1",
      PYTHONIOENCODING: "utf-8",
    },
  },
});
