# LIMA 智能体漏洞挖掘平台（Agent Vulnerability Platform）

面向自动化漏洞挖掘的智能体平台：**智能体是检测主体，静态工具是智能体的仪器，
动态实验（ASan）是终极验证手段**。

## 1. 总体架构：五层漏斗

```text
第0层 静态分诊（望远镜）
  语义检索与模式种子在全量代码上运行，产出"线索"——不是漏洞，
  只是值得看的位置。便宜、高召回，智能体可随时推翻。
        ↓
第1层 侦察筛选（Scout 智能体）
  用搜索/读码/调用关系工具自主排查线索：grep→读→追→排除→升级，
  产出带推理理由的目标清单。
        ↓
第2层 深度分析（Specialist 智能体群 + Critic）
  按漏洞类型包分角色深读代码，追别名链/生命周期/数据流，
  形成结构化漏洞假设（触发条件、路径、CWE 初判）；
  Critic 对抗审查，主动寻找反证。
        ↓
第3层 复现工作台（Reproduction 智能体）
  智能体自己编写 PoC 驱动代码，调用 compile_and_run_asan 在隔离沙箱内
  编译并运行，读取 ASan 崩溃报告与假设比对；命中即实证
  （runtime-confirmed），不命中则修正假设回到第 2 层——实验闭环。
        ↓
第4层 定稿（Reporter 智能体 + 数据挖掘）
  CVE 离线匹配、git 影响范围挖掘（引入提交/分支传播/版本范围）、
  补丁建议 + PoC 回归验证、eRST 式漏洞研究档案生成。
```

## 2. 资产复用（三阶段演进）

| 阶段 | 资产 | 平台中的角色 |
|---|---|---|
| 阶段 A | 五层沙箱（Docker/Landlock/seccomp/身份/预算） | 全平台的执行边界：仓库代码与模型生成的 PoC 进同一座监狱 |
| 阶段 A | clang/ASan/semgrep/cmake 工具链镜像 | 复现工作台的仪器 |
| 阶段 B | 七角色 Agent 管线 + 有界只读工具 | 第 1、2 层主体 |
| 阶段 B | 验证状态机 + 证据等级（D0–D4 × 支持/反驳） | 智能体声明的裁判：runtime-confirmed 只能来自沙箱内真实执行 |
| 阶段 B | 预算/超时/降级机制 | 智能体每次行动可审计、可失败、可恢复 |
| UAF v2 | Build Context 解析器 / clang 事实提取 / 事实协议与校验 | 智能体的精密仪器（可查询的事实与证明） |
| UAF v2 | P1–P7 证明引擎 | 可咨询的反驳工具：PASS/REFUTED 是证据来源之一，不是关卡 |

## 3. 漏洞类型包（插件化）

平台内核类型无关；每种漏洞类型一个包：Specialist 提示与知识 + 分诊种子 +
PoC 驱动模板 + ASan/UBSan 判读规则 + CWE 映射。

- **内存漏洞包**（核心）：UAF、越界读写、双释放、空指针解引用、整数溢出致
  内存破坏。
- **扩展包**（按需）：信息泄露、命令/路径注入等。

## 4. 关键纪律

- PoC 是跑出来的：报告中的 PoC 必须附带真实执行记录。
- 误报保守：无实证发现按低等级汇报；普通功能性问题过滤。
- 沙箱只调房间大小不松锁：模型生成代码与被测仓库代码同狱。
- 快照身份贯穿：分诊、事实、实验、报告绑定同一 snapshot_hash。
- 全程可审计：智能体每次行动有预算、台账与降级记录。

## 5. 规模化与性能采集

三个独立设施（`lima/agent_scale.py`），由 `run_platform_review` 接入：

- **并行**：`parallelism` 让独立目标在受控线程内并行假设/实验；结果恒按
  确定性 Scout 序聚合——并行只影响墙钟，不改输出序。服务侧由
  `LIMA_CXX_AGENT_PARALLELISM` 注入。
- **缓存**：`ResultCache` 按快照指纹 + 目标全字段 + 模式 + 对话轮数复用每
  目标完整结果；命中即零 LLM 调用、零沙箱实验。键必须含 snapshot_hash
  （快照身份贯穿）；坏条目按未命中自愈。`cache=None`（默认）行为与无缓存
  完全一致。
- **增量**：`detect_changed_files` 对两份 `{path: sha256}` 清单做
  新增/修改/删除三方差异，是"仅变更文件重跑"的数据基础；按文件粒度的自动
  增量重跑为接口预留（缓存键锚定整快照指纹，见部署指引 §6）。

**性能采集**：耗时/内存/并行度随 `PlatformReviewStats`（目标数/实验数/
Specialist/Critic/Scout 调用数）与实验台账（每轮 stage/exit/error_type）
自动入报告（交付件 5 的数据来源）；大规模跑批的部署参数组——快照限额放
开、tmpfs/内存、受信构建门禁、离线依赖预处理、OpenHarmony 注意事项——见
`deploy/competition/README.md` 与 `.env.competition.example`。

## 6. 评测

平台配对基准与比赛指标映射由 `scripts/run_platform_evaluation.py`
承载（计划 Task 10，设计 §11）：`evaluation_data/platform_cases/` 提供
6 组源码级 vulnerable/fixed 对（SHA-256 钉死），覆盖 direct、需修正假设
才命中的 revisable（实验闭环）、clean 误报纪律与非安全类过滤样例。评测
无标签：`run_platform_review` 的输入只有 workspace、事实 wire 与分诊
线索，标签只在评测侧。

指标全部由内嵌 records 可重算，零分母输出 `null` + diagnostic：
**检测率**（vulnerable 侧期望正向状态的精确达成）、**误报率**（fixed/
clean/非安全侧出现任何 Finding 即误报——对应赛题误报扣分）、**非安全
过滤率**（赛题备注 3：假设合同用内存包封闭 CWE 词表拒绝非内存安全
缺陷）、**实验收敛**（revisable 案例 ≤2 轮命中）、**PoC 稳定性**（同
PoC 重复 3 次全触发）、LLM 调用/时延采集。双仓库（ResInsight/OPM/
OpenHarmony）的论文侧运行记录与验证状态表见
`docs/COMPETITION_VALIDATION.md`。
