# 双仓库验证记录（Competition Validation）

本文档记录智能体漏洞挖掘平台（内存包）在真实仓库上的论文侧验证状态与
配对基准结果，是 `docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`
§11 评测条款与设计 §9.4/§9.10 诚实纪律的落地台账。核心规则
（沿承 `2026-09-02-cxx-llm-agent-detection-design.md` 验收条款）：

> 环境未提供 Docker、真实模型或真实执行时，对应验证层必须写"未验证"，
> 不得以 Fake 结果推断通过；任何演示性放宽必须逐条标注。

- 记录基线：worktree `D:\Projects\LIMA\.worktrees\cxx-llm-agent-detection`，
  HEAD `7a45bbd`（Task 10 落地时实测，见下文数字）。
- 更新约定：每完成一层验证，把状态表的"未验证"改为"已验证"并附证据
  路径与日期；不删除历史记录，只追加。

## 1. 分类验证状态表（诚实纪律对齐）

| 验证层 | 验证方式 | 状态 | 证据 |
|---|---|---|---|
| 平台管线闭环（Scout→假设→实验→修正→裁决） | `tests/test_platform_evaluation.py`（26 测试，零网络 Fake） | 已验证（Fake，2026-09-11） | 本仓库 unittest；`scripts/run_platform_evaluation.py --fake-llm` 全绿 |
| 配对基准指标（检测率/误报率/非安全过滤/实验收敛/PoC 稳定性） | `scripts/run_platform_evaluation.py` 全 6 案例 Fake 跑批 | 已验证（Fake，按构造确定性） | 报告 `detection_rate=1.0`、`false_positive_rate=0.0`、`non_security_filter_rate=1.0`、`experiment_convergence=1.0`、`poc_stability=1.0`（脚本是哈希判定，稳定性指标仅真实工作台下有信息量） |
| 真实模型分类（Specialist/Critic/Scout 走真实 provider） | `scripts/run_platform_evaluation.py`（不带 `--fake-llm`，配 `--provider-url/--model`） | 未验证（Task 10 范围内禁止真实调用，归主 agent 执行） | — |
| 真实容器 ASan 实证（`runtime-confirmed` 的 D3 证据） | Docker clang-14/ASan 沙箱真实执行 PoC | 未验证（走真实环境验收，独立记录） | — |
| 真实仓库全链检测 | ResInsight 限定子集（UAF v2 全链） | 已验证（诚实 abstain，2026-09-12，见 §2） | `.superpowers/tmp/uaf-demo-outcome.json` |

## 2. ResInsight（油气仓库，已完成的运行记录）

### 2.1 UAF v2 全链真实检测（2026-09-12）

- 对象：ResInsight 限定小范围真实路径（用户授权）。
- 结果：5 个 TU（cvfDebugTimer / Timer / Assert / RenderQueue /
  ModelBasicTree）提取出 **11 条事实（8 allocation + 3 alias）**，
  另有 **10 类 coverage gap**；候选生成 **0 条**——ResInsight 的内存管理
  形态（ctor 分配/dtor 释放、智能指针、循环拆卸）全部在第一阶段支持
  范围之外，管线**诚实 abstain、零编造**。
- 结果工件：`.superpowers/tmp/uaf-demo-outcome.json`。
- 附带战果（真实产品问题，均已修复或入 backlog）：
  1. sidecar/主进程清单白名单漏 `.inl/.ipp/.tpp`（cvfObject.inl 缺失导致
     隔离快照内全部 TU 编译失败）——已修 `0ca7d13`（含指纹第 5 次刷新）；
  2. `_expectation_for` 多 TU 各持合法不同 context hash 时置空崩溃——
     已修 `756c985`（`FactBundleExpectation.allowed_context_hashes`
     集合语义）；
  3. AST 规模边界：真实头文件重的 C++ 单 TU `-ast-dump=json` 达
     100–407 MiB（产品上限 16 MiB），需按函数过滤的提取策略——backlog。
- **演示性放宽 2 处（逐条标注）**：提取脚本去掉 preprocessing-record
  旗标；AST 上限放宽至 512 MiB。其余全部生产代码（隔离快照/指纹核验/
  沙箱 clang/resolver/extractor/adapt/generate/prove/orchestrator）。

### 2.2 纯 Agent 真实仓库实战（2026-09-08，前序记录）

- 战斗集 v1：11 文件（390 KB）；v2：129 文件（1.86 MB，C-API 轴
  21/5063 天花板 + FileInterface 解析器轴 108）。
- v2 窗口化单步分析 40 个最高风险锚点函数：**40/40 零失败零发现**；
  **阳性对照通过**（同格式正确检出合成 UAF CWE-416，conf=1.0），
  证明"零发现"裁定真实。
- 人工复核唯一实质发现：`cvfString.cpp:1268` replaceArgs 无界内层扫描
  （CWE-125 隐患，尾段吞噬不变量当前保护）——建议上游加固。
- 盲区记录：跨函数传播（调用图增强）与 v1 检索 C-API 种子覆盖率为产品
  backlog，不冒充已验证能力。

## 3. 油气仓库 OPM 系（占位——待执行）

OPM 系仓库（如 opm-common / opm-simulators）的论文侧运行尚未执行。
执行清单（每步完成后在本节追加数据与证据路径）：

1. **导入**：仓库快照导入与清单核验（复用 `lima/repository_import.py`
   边界，记录导入清单 SHA-256）；
2. **指纹**：快照指纹（snapshot_hash）与 Build Context 解析状态记录；
3. **分诊**：静态分诊产出线索数、种子分布、coverage gap 清单；
4. **平台跑**：`run_platform_review` 全链（真实 provider 或 Fake 分档
   记录），记录每目标状态机终态、实验台账、预算与降级；
5. **档案**：eRST 式报告 + CVE 离线匹配 + git 影响挖掘
   （`lima/agent_report.py`），结果归档并回填本节表格：

| 步骤 | 状态 | 关键数字 | 证据路径 |
|---|---|---|---|
| 导入 | 未执行 | — | — |
| 指纹 | 未执行 | — | — |
| 分诊 | 未执行 | — | — |
| 平台跑 | 未执行 | — | — |
| 档案 | 未执行 | — | — |

## 4. OpenHarmony（占位——仅仓库接入差异）

内存包行为在 OpenHarmony 与油气仓库上同构（设计 §9.8）；接入差异只在
仓库导入与离线依赖预处理。沙箱不开外网，依赖一律沙箱外预处理；完整
流程（快照限额放开参数组、tmpfs/内存、受信构建门禁、OpenHarmony 注意
事项）见 `deploy/competition/README.md` §4/§5 与
`.env.competition.example`。执行后按 §3 同样格式回填。

## 5. 配对基准（`evaluation_data/platform_cases/`）

- 案例：6 组源码级 vulnerable/fixed 对（SHA-256 钉死于
  `tests/fixtures/platform_cases/`，换行归一口径）：
  `uaf-direct`、`null-deref-direct`、`overflow-direct`（direct）、
  `rebind-revisable`（两轮实验闭环）、`clean-function`（误报纪律）、
  `non-security-filter`（赛题备注 3 机制化）。
- 评测器：`scripts/run_platform_evaluation.py`（无标签：管线输入只有
  workspace + 事实 wire + 分诊线索，标签只在评测侧）。
- 指标（全部可由内嵌 records 重算，零分母输出 null + diagnostic）：
  检测率、误报率、非安全过滤率、实验收敛（≤2 轮）、PoC 稳定性
  （同 PoC 重复 3 次全触发）、LLM 调用/时延。
- 当前状态：**Fake 全绿**（2026-09-11，6 案例 12 revision）：
  检测率 1.0、误报率 0.0、非安全过滤 1.0、实验收敛 1.0、PoC 稳定性 1.0
  （脚本工作台哈希判定下按构造稳定，真实工作台下该指标才有信息量）。
- 有效性边界（评测报告内逐条携带）：合成与钉死对不等价于生产检测能力；
  真实 Clang 提取与真实容器 ASan 为独立验收；null 指标≠满分。
