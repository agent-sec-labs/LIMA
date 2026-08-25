# LIMA v1.4 热门项目外部 Holdout 评测

## 结论

v1.4 已经把“固定公开快照 → 完整性校验 → 全仓库扫描 → label-blind 语义检索 → 真实 LLM 结构化判定 → 安全拒修”工程链路跑通，并通过主机、Docker 和实际服务验证。但在 5 个未参与规则设计的热门项目上，当前检测效果不合格：检索路径 Recall@K 为 20%，目标符号 Recall@K 为 0%，真实 LLM 漏洞召回为 0/5，严格成对区分为 0/5。

这说明 v1.3.1 在 3 个开发案例上的 100% 不能外推为通用能力。当前主要瓶颈是仓库级检索和跨文件根因证据，不是 API 可用性、JSON 契约或容器流程。系统没有把未验证候选送入自动修复，拒修策略遵从率为 100%；这是正确的安全失败方式，但也意味着本轮外部集没有触发真实补丁闭环。

## 样本选择协议

冻结清单：`evaluation_data/popular_external_holdout.json`

- 仓库必须满足 `stars >= 1000` 或 `watchers >= 100`；
- 每个仓库只允许一个漏洞/修复对，避免同仓库信息泄漏；
- 与开发集 aiohttp、Django、GitPython 仓库完全隔离；
- 覆盖 CWE-22、CWE-78、CWE-89；
- 漏洞版和修复版均固定完整 commit SHA 与 codeload 归档 SHA-256；
- 热度快照日期为 2026-08-24，热度只用于选样，不进入检测输入；
- 评测时不向检索器或模型提供 CVE、CWE、目标文件、目标符号或修复差分。

| 项目 | 热度快照 | 漏洞 | CWE | 根因位置 |
|---|---:|---|---|---|
| pypa/pip | 10,270 stars / 315 watchers | CVE-2026-1703 | CWE-22 | `unpacking.py::is_within_directory` |
| danielgatis/rembg | 24,401 / 168 | CVE-2026-40086 | CWE-22 | 三个 custom session 的 `download_models` |
| yt-dlp/yt-dlp | 186,566 / 919 | GHSA-69qj-pvh9-c5wg（上游无 CVE） | CWE-78 | `exec.py::ExecPP.parse_cmd` |
| MervinPraison/PraisonAI | 8,950 / 72 | CVE-2026-40088 | CWE-78 | `execute_command.py::execute_command` |
| janeczku/calibre-web | 18,044 / 172 | CVE-2022-30765 | CWE-89 | `admin.py::list_users` |

MobSF CVE-2026-33545 原计划作为第 6 个 CWE-89 样本，但源码归档超过评测器 100 MiB 下载上限。系统保持 fail-closed，没有为了凑数提高资源上限；该排除及其热度、漏洞和原因已记录在清单。pypa/wheel 只有 571 stars / 29 watchers，不符合冻结选样门槛，未进入候选集。

## 可复现身份

| 身份 | SHA-256 |
|---|---|
| 数据语义指纹 | `02930376a3f18104ec743aa28a316c96e6065bb59d5fd8b7cc49f8b7486948fc` |
| 规范化 manifest 指纹 | `ba1cd8321d510dc8ac439a450da6faca97530cf48bdd05fa845bfea5af7cc354` |
| manifest 文件字节指纹 | `072b3a2d4cc1227fa7d2136897ef87f7806d5776b3fbe0cdabd1aeb702b4d846` |
| 冻结分析器指纹 | `e9000d218084bc0738d9ecef8ec7a8e4c145931042a8ac9cb6f458eec555869b` |

分析器指纹绑定 `fixer.py`、`real_world_evaluation.py`、`repository_scanner.py`、`semantic_retrieval.py`、`verifier.py` 和 `workspace.py`。任一结果相关组件发生漂移，schema v2 清单会拒绝运行，防止“测后调参”仍冒充原始外部 holdout。

快照缓存现在不再只信任元数据文件。每次命中缓存都会重新计算目录树 SHA-256、文件数和解压字节数；路径穿越、符号链接、归档哈希不一致、缓存内容篡改、压缩炸弹和超限下载均会拒绝或重新获取。

## 冻结结果

| 配置 | 路径 Recall@K | 符号 Recall@K | 漏洞召回 | 修复版特异度 | 成对区分 | API / 契约 | 总耗时 |
|---|---:|---:|---:|---:|---:|---:|---:|
| 确定性扫描 + label-blind 检索 | 20% | 0% | 不调用 LLM | — | 0% | — | 24.25 s |
| 检索候选 + 真实 DeepSeek | 20% | 0% | 0% | 80% | 0% | 100% / 100% | 43.64 s |
| 已知文件上下文上界诊断 | 不适用 | 不适用 | 0% | 100% | 0% | 100% / 100% | 66.32 s |

真实 LLM 检索模式共调用 10 次，使用 26,633 tokens，平均模型时延约 1.76 秒。即使把上游已知修复文件直接提供给模型做诊断上界，漏洞召回仍为 0%，说明通用 Prompt 对信任边界、调用意图和微妙语义差分过度保守；Calibre 病例还出现了把修复版 allowlist 误认为漏洞版已有的判断。该上界只能用于根因分析，不能作为 label-blind 主指标。

旧的 Windows bind mount 运行在 Docker Desktop P9 文件系统上，真实 LLM 全链路耗时约 2,258.86 秒，检索平均约 86.84 秒。v1.4 改为持久化 Docker named volume 后，同一主链路降到 43.64 秒，检索平均约 0.89 秒。输出目录仍以只写报告的 bind mount 暴露，源码缓存只读挂载；性能优化没有改变准确率结论。

原始报告：

- `output/v1.4-popular-holdout/popular-fetch.json`
- `output/v1.4-popular-holdout/popular-retrieval-baseline.json`
- `output/v1.4-popular-holdout/popular-llm-retrieval.json`
- `output/v1.4-popular-holdout/llm-localized-upper-bound.json`

## 工程完整性验证

- 主机测试：134 passed，1 skipped；
- Docker Linux 测试：135 tests，全部通过；
- `python -m compileall -q lima scripts`：通过；
- PowerShell AST 语法：通过；
- 实际 Compose 服务：`/health` 返回 `status=ok`、`version=1.4.0`；
- Provider：真实 DeepSeek 10/10 API 成功、10/10 JSON 契约有效，报告不记录 API key；
- 容器：只读根文件系统、drop all capabilities、`no-new-privileges`；快照获取后主评测使用只读缓存。

因此可以确认项目主逻辑和部署路径已经跑通；目前未发现阻断型工程 bug。尚未解决的是通用检测能力，而不是“程序不能运行”。

## 下一迭代计划（工程 70%，研究 30%）

### P0：通用仓库检索与可观测性

1. 输出受支持语言文件覆盖率、被截断字节数、跳过目录原因和目标文件是否进入 inventory，避免把“未扫描”误报为“模型漏检”。
2. 建立与仓库名、CVE、目标符号无关的 source/sink/sanitizer API 索引，优先覆盖路径组合与文件打开、shell/argv 执行、SQL 结构与参数绑定。
3. 从文件级粗排升级为“文件 → 符号 → 调用边”的多阶段检索，并保留每次晋级/淘汰的结构化原因。
4. 为跨文件 import、继承、回调和 wrapper 建立有界调用图；无法解析时明确降级，不伪造 dataflow-verified。

### P1：证据约束的模型判定

1. 模型必须逐项回答：外部可控源、危险汇点、到达路径、已有缓解、缺失前提；证据缺失时返回 abstain，而不是凭 API 名称定性。
2. 先由确定性层提供最小切片，再由模型判断可利用条件；模型输出继续受真实 `path + symbol + line` 契约约束。
3. 增加同一快照的重复运行与一致性统计，但不追求学术上尚不稳定的单一“零日准确率”。

### P1：漏洞到修复闭环

1. 只有 verified evidence 才能进入 CWE-22/78/89 最小修复模板。
2. 保持编译、独立安全 Oracle、全仓差分复扫、项目原生测试、原子提交和 Draft PR 人工批准门禁。
3. 为真实项目增加按语言/框架声明的依赖与测试 profile；缺失 profile 计为 oracle coverage gap，不计为补丁失败或成功。

### P2：新的外部验证

v1.4 这 5 个案例一旦用于实现或调参，就必须改标为 calibration set，不能继续宣称为未见 holdout。功能改进完成后另选 5–10 个仓库隔离、满足相同热度门槛的新 v2 holdout，再报告泛化指标。

下一版工程门禁建议先采用可实现的阶段目标：目标路径 Recall@K ≥ 80%、目标符号 Recall@K ≥ 60%、漏洞召回 ≥ 60%、修复版特异度 ≥ 80%、严格成对区分 ≥ 50%、API/契约成功率 100%，且 5 对命名卷评测在 3 分钟内完成。这些只是继续工程迭代的最低门槛，不是总体安全能力声明。

## 一键复现

```powershell
Set-Location D:\BaseAIProject\LIMA

# 获取固定快照并运行断网确定性/检索基线。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 popular-eval `
  -Output output\v1.4-popular-holdout

# 使用 .env 中真实 Provider，运行 5 个漏洞版 + 5 个修复版。
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 popular-llm-eval `
  -Output output\v1.4-popular-holdout

# 完整回归和实际服务。
python -m pytest -q
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 test
powershell -ExecutionPolicy Bypass -File .\scripts\lima.ps1 up
Invoke-RestMethod http://127.0.0.1:18080/health
```
