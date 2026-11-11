# [Evaluation][C03] 真实工作台评测入口：冻结论据（判据 Issue，实施见姊妹 Issue）

## 本 Issue 是什么
维护者冻结"真实工作台评测"的专业判据。工程实施在姊妹实现 Issue 进行（见本 Issue 尾部链接），本 Issue 只承载判据与验收口径，实施者不得修改判据；疑问一律回报维护者。

## 为什么需要：现状声明（维护者核实）
`scripts/run_platform_evaluation.py` 的两种 LLM 模式（`--fake-llm` 与真实 provider）都使用：canned Sidecar wire（按案例提交的 `/v1/uaf-facts` 捆包）、canned triage leads、按驱动内容哈希判 PoC 的 scripted workbench（`FakePlatformWorkbench`）。因此该评测器的 runtime 类指标是**结构自证**：无论模型真假，运行时结果都不构成真实编译/执行证据。真实工作台评测必须走本判据定义的独立入口，两套结果分开存放、分开表述。

## 冻结判据（维护者 2026-10-14 定稿）

### J1 样本集（正负样本）
- 样本 = 维护者冻结的已审核案例，显式清单文件入库（JSON）：案例 id、源文件清单、构建上下文、期望类别（security-vulnerable / security-fixed / clean / non-security）。
- 初始集 = 现有配对基准 6 案例的源案例投影（4 安全配对 + 1 clean + 1 非安全）。清单扩充/替换需维护者批准并更新清单文件；Codex 不得自行加样本。

### J2 允许执行范围
- 仅限样本清单内源文件的编译与冻结 PoC 驱动的执行；运行于既有容器沙箱（Landlock 分层锁）内。
- 禁止访问清单外仓库路径；普通 CI 不配置模型密钥、不调用付费模型；真实模型运行一律由维护者发起。

### J3 命中 / 环境失败区分（三分类，每样本每 PoC 每次运行）
| 分类 | 判定 |
|---|---|
| `hit` | 出现冻结判据的正向运行时信号：ASan 结构化报告归因到目标 TU/函数，或维护者逐案例冻结的行为哨兵触发 |
| `clean` | 正常退出、无命中信号、无异常噪声 |
| `environment-failed` | 编译失败、超时、容器/网络/Sidecar 错误。**绝不计为安全负例**（不等于 clean），也不计为命中；单列统计 |

ASan 归因规则、行为哨兵定义沿用现有验证合同（不新造）。

### J4 重复次数
- 每样本每 PoC 固定 3 次。3/3 触发记 `stable`；部分触发如实记（如 2/3，标 `partial`）；0/3 且全 clean 记 clean。3 次中出现 environment-failed 则该样本该 PoC 的安全判定按剩余次数计，并保留失败记录与原因；3 次全 environment-failed 记 `unresolved`，不入安全分母。

### J5 汇总冻结规则
- 指标：`hit_rate` / `clean_rate` / `environment_failure_rate` / `poc_stability`（3 次口径）。
- 安全判定分母 = hit + clean 次数（environment-failed 剔除出安全判定、计入执行质量统计）；空分母 → `null` + 原因。
- 报告与 scripted 评测分文件存放；报告头标 `execution: real-workbench`；禁止与 scripted 指标合并、平均或对比成同一图表而不加模式标注。

### J6 边界
- 本入口不改变现有 scripted 评测器及其指标（C01 在其上加工）。
- 不修改裁决合同、ASan 归因判据、沙箱策略；发现需要改的先停手回报。

## 验收归属
判据满足与否由维护者终审；实现 Issue 的工程验收清单见姊妹 Issue。

## 关联
#273（真实运行验收）、#165（全量验收）、V02/V03 专业任务、E01（环境预检查）、E07（环境清单）。实现 Issue：<发布后回填>
