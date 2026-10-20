# 竞赛运行前只读检查（preflight_competition_run）

在昂贵的验证运行之前，让操作者确认单个竞赛案例的前置条件是否齐备：
案例清单（manifest）、导入根目录、两份 pin 住的 checkout（HEAD、干净树、
compdb、overlay 摘要、文件预算）、模型配置项是否提供，以及（可选）C/C++
分析 Sidecar 的健康状态。整个工具**只读**：只调用 `git` 的识别/比对查询，
不 fetch、不 checkout、不重置、不构建、不执行任何目标代码，也不发送任何
模型或认证请求。

来源任务：issue #311（[Competition][E01][独立工具]）。所有检查复用
`lima/openharmony_validation.py` 的既有校验器（`load_openharmony_case`、
`validate_case_checkouts`、`WorkspaceLimits`、`CheckoutPreflightError`）、
`lima/repository_import.py` 的 `RepositoryImportPolicy` 与
`lima/cxx_memory.py` 的 `CxxMemoryAnalyzerClient.health`；本工具不复制
它们的安全规则，只做结果投影。

> **前提通过不代表漏洞成立，也不代表模型已认证。**

## 1. 用法

```bash
python scripts/preflight_competition_run.py \
  --case <case.json> \
  --repository-import-root <dir> \
  --output <新目录/新文件-preflight.json> \
  [--check-sidecar --analyzer-url <url>]
```

在仓库根目录执行；`--output` 必须指向**尚不存在**的新文件，已存在的输出
路径一律拒绝覆盖（退出码 3）。默认完全离线，不发起任何网络请求；只有
显式传入 `--check-sidecar` 时才会对 Sidecar 发起**一次**
`GET /health` 探测（有限超时、无重试）。

## 2. 参数

| 参数 | 必填 | 说明 |
|---|---|---|
| `--case` | 是 | 案例清单路径（`openharmony-validation-v1` 封闭 schema） |
| `--repository-import-root` | 是 | 管理员预置的只读仓库导入根目录 |
| `--output` | 是 | 报告输出路径；已存在则拒绝覆盖 |
| `--check-sidecar` | 否 | 显式请求 Sidecar 健康探测；缺省标记 `not-requested` |
| `--analyzer-url` | 否 | Sidecar 基地址；缺省用 `LIMA_CXX_ANALYZER_URL`，再缺省 `http://127.0.0.1:8090`。只接受纯 http(s) 来源：拒绝内嵌用户名/密码、query、fragment |

扫描预算沿用验证 CLI 的同一套环境变量与默认值：
`LIMA_REPOSITORY_SCAN_MAX_FILES`（5000）、
`LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES`（512 KiB）、
`LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES`（20 MiB）。模型配置项只检查
是否提供（`LIMA_LLM_BASE_URL`、`LIMA_CXX_AGENT_MODEL` 或
`LIMA_LLM_MODEL`、`LIMA_LLM_API_KEY`），只读取进程环境变量，**不读取
.env 文件**，不回显任何值。

## 3. 退出码

| 码 | 含义 |
|---|---|
| 0 | 所有**请求**的前提检查全部通过（含被请求的 Sidecar） |
| 2 | 前提不满足（报告已写出，含失败原因） |
| 3 | 用法/输出错误（参数缺失或非法、URL 被拒绝、输出路径已存在等；不写报告） |

## 4. 报告（JSON v1）

`schema_version` 为 `competition-preflight-v1`。顶层字段：

| 字段 | 说明 |
|---|---|
| `schema_version` | `competition-preflight-v1` |
| `case_id` | 清单可解析时的案例 ID，否则空串 |
| `checks` | 按固定顺序的检查记录数组 |
| `prerequisites_passed` | 四项必备检查（manifest、导入根、checkouts、model-config）是否全过；不含可选的 Sidecar |
| `sidecar_requested` | 是否请求了 Sidecar 探测 |
| `diagnostics` | 有界诊断字符串（只读说明、model-config 项在场情况、Sidecar 能力布尔值；**不含** Sidecar 地址） |
| `disclaimer` | 固定免责声明文本 |

每条检查记录：`{name, status, reason_code, detail}`，`status` ∈
`pass` / `fail` / `not-requested`，`detail` 为脱敏（`sk-` 令牌打码）且
截断至 200 字符的说明。

| 检查名 | 依赖 | 失败时的 `reason_code` |
|---|---|---|
| `case-manifest` | — | `manifest-invalid`（清单缺失/不可读/不合 schema）、`check-error` |
| `repository-import-root` | — | `import-root-unavailable` |
| `checkouts` | 上两项 | **透传既有稳定类别**：`head-mismatch`、`tracked-files-dirty`、`missing-compdb`、`compdb-missing-entry`、`compdb-ambiguous-entry`、`compdb-invalid`、`compdb-include-escape`、`compdb-include-missing`、`compdb-response-file`、`overlay-digest-mismatch`、`missing-manifest-path`、`untracked-not-allowed`、`inventory-truncated`（预算超限）、`repository-key-unresolvable`、`duplicate-checkout`、`fixed-commit-unresolvable`、`git-unavailable`、`check-error` |
| `model-config` | — | `model-config-missing`（明细只列缺失项名） |
| `sidecar-health` | — | `sidecar-unavailable`（含超时）、`sidecar-protocol-error`、`check-error` |

上游检查失败后，被依赖的检查不会伪造结果：`checkouts` 记为
`not-requested` + `skipped-upstream-failed`。未请求 Sidecar 时该检查记为
`not-requested` + `not-selected`，不填充通过状态。model-config 缺失只陈述
“配置项未提供”，不断言 provider 不可用；在场也不断言认证有效。

## 5. 安全与隐私保证

- **输入只读**：被测目录与案例文件前后逐字节一致（有测试保证）；输出只写
  指定的新文件，绝不写入封存包或覆盖既有结果。
- **默认离线**：缺省模式不发起任何网络请求（有 Mock 测试保证），不构造
  分析客户端，不调用 `run_openharmony_case` / `run_platform_review`。
- **不回显敏感值**：报告与 stdout 不含 API key、不含 Sidecar 地址、不含
  输入文件内容；异常文本经打码与截断后才进入 `detail`。
- **无新增依赖**：仅标准库与仓库既有模块。

## 6. 演示

通过（退出码 0）与失败（退出码 2，脏树）两份合成演示见 issue #311 交付
说明；本地可用合成 fixture 复现：

```bash
python -m unittest tests.test_competition_preflight -v
```

测试自建临时 git checkout 与合成案例（不依赖真实案例），覆盖通过路径、
每个稳定失败原因、坏清单停止依赖检查、输出拒覆盖、URL 拒绝、密钥不
泄露、默认离线与输入只读不变式。
