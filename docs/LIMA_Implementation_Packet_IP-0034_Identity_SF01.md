# LIMA Implementation Packet — IP-0034 Identity Expansion + SF-01 Evidence Tightening（#232 / #57 PR3-d-real 身份扩纳与证据通道收紧子叶，零真实调用）

- Packet ID：IP-0034；版本 v1.0（2026-09-28）。
- Coordinator Assignment：CA-IP-0034-v1.0（2026-09-28；Intent Record `.pv_tmp/INTENT_RECORD_IP-0034_2026-09-28.md` 的 I1-I6 与决策点 A-H 由其 R1-R14 裁定；R1-R14 转录见 §16）。
- Source Issue：#232（open，parent #57 保持开放；正文 2678 字符由 Coordinator 经 GitHub API 亲取，范围以 CA-IP-0034-v1.0 §Authoritative Inputs #2 为权威转录——本 P&V 会话零网络，未直取远程正文，远程再核验归主会话派发前完成）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-28 一次性长程授权；**本 Assignment 授权的交付物=离线修复 PR（阶段一），P&V 与 Implementation 全程零真实模型调用、零网络下载、零付费、零远端写**；阶段二/三/四真实执行协议由本 Packet §11 承载，但执行不在本 Assignment 对 P&V/IMPL 的授权内）。
- Base SHA（完整 40 位）：`6d6907855dced9c274e04e5819e862794b740c4f`（= origin/main = 本地 main，亲验；tracked 面干净；71e7fb1【Merge PR #227，IP-0033】∈ 祖先）。
- 基线产物指纹：tests v3 blob `6167e9a0ff4ce420d4ffc376b17818e3a7f26157`；real_run.py blob `cfc3abaf31166b61728a01b97877e15a198b4238`；Dockerfile blob `ef14398610b2c7f4594ffda0a1fdc051471fbcbb`；budget.py blob `6c783848e00f55e05d221e3ab89fb32310d583b9`（本 P&V 会话 `git ls-tree` 亲验，与 CA §Exact Baseline 逐字一致）。
- 本 Packet 的角色：Implementation（阶段 C3+）的唯一实现依据；冻结验收测试 v4（本 Packet §9/§10）的唯一语义来源；ER 复核与 P&V 独立验证的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）与批准工件 `docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md` 与 Dockerfile 恰 2 行 COPY 是 P&V 的 C1 交付物；`tests/test_v4_baseline_real_run.py` 冻结版本 v4 是 P&V 的 C2 交付物；`benchmarks/v4/baseline/real_run.py` 的身份扩纳 + SF-01 有界变换是 **Implementation 的 C3+ 交付物**。边界不得互换：Implementation 不得修改本 Packet、批准工件与测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本 IP 离线交付全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作。全部验收以离线构造（注入 fake transport）证明。真实批次（§11）由主会话在修复 PR 合并 + post-merge PASS + 干净最新 main 后按协议另行执行——真实执行前置条件不满足即停。
3. 预算语义只紧不松：SF-01 是证据面变换，不是失败模式，不得以任何形式放松 usage/身份/字节/调用数门禁；`budget.py`（IP-0031 冻结面）零字节改动；canary 清单五项键名、判定式与 latch 触发条件零改动。

## 1. 需求映射（Packet 头）

```text
Source Issue：#232（open；Scope 1-6 / Non-goals / AC-1..4，经 CA-IP-0034-v1.0 转录）
Issue specification revision：2026-09-28 创建版正文（Authorization 三合一 / Scope / AC-1..4）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、FR-06、AC-1、AC-2、AC-3、AC-4
Not covered requirements：PR3-e 全部真实调用与 90 次预授权；第二批次/重试/加次/上限提高/账本重置/换模型/换仓库 SHA/换机器；thinking 参数形态变更；通配或前缀身份匹配；deepseek-v4-flash-vision-exp 纳入；#223/#226 重开或重审计；#57 关闭或 PR3-d 整体勾选；九类 archetype 矩阵升级；旧样本追认性补证
Delivery role：hardening + migration（身份门 additive 扩纳 + 证据面单向收紧 + 批准工件/冻结面受控演进）
Issue closure impact：PARTIAL（IP-0034 完成 ≠ 真实批次完成 ≠ #232/#57 完成；真实批次与收口另按 §11 协议推进）
Upstream IP/PR/merge commits：IP-0032（PR #224 merge 45a7ec7）；IP-0033（PR #227 merge 71e7fb1）；基线 6d69078（另含 PR #225 retire-legacy-cxx-chain）
```

FR-01..FR-06 为 #232 "Scope (this slice)" 的规范化编号（语义不变，CA-IP-0034-v1.0 §Goal and Scope）；AC 沿用 #232 原文 AC-1..4（CA §Acceptance and Validation 逐条锚定）。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | 身份允许集扩纳：`deepseek-flash` 以最小、明确、可测试形态纳入（三形态并集、无通配、vision-exp 仍拒）；工件承载制（`served_model_forms` 封闭列表取代 `served_as`） | §7.2 | v4 ie1/ie2/ie3 + a2 演进 + rd3/u3/rd1/rd2 演进（AC-1） |
| FR-02 | SF-01 收紧：服务器控制键名与模型身份串不再无界直录持久证据；受控枚举/已批准身份/不可逆摘要三层制；11 检查点可区分保持 | §7.3/§7.4/§7.5/§7.6 | v4 sf1/sf2 + e2/rd5 演进（AC-2） |
| FR-03 | 新一次性批准工件 2026-09-28（R8 逐字段钉值）+ Loader 三钉迁移 + 旧工件历史冻结 + 新旧批分离 | §7.7/§8 | v4 a1/a2/sf3 + v 系演进（AC-1/AC-3） |
| FR-04 | 冻结测试面 v3→v4 受控演进（六条件程序） | §9/§10 | v4 全文件（AC-4） |
| FR-05 | 真实批次协议承载：阶段二硬门/阶段三批次协议/阶段四收口材料三章节逐字对齐授权 | §11 | Packet 承载面（AC-3；执行不在本 Assignment） |
| FR-06 | 兼容与回归：十码/11 检查点/canary 五项/D1-D6/请求形状/估计策略/298 方法零改动/additive-only | §7.1/§7.6/§7.8 | Done Commands 2/3/6/7 + sf4（AC-4） |
| AC-1 | 扩纳一致性：deepseek-flash 正例全链路；vision-exp/未知形态仍拒；工件/解析器/常量/测试/文档五面一致可验（含工件未钉扎形态被拒负例与双源一致断言） | §7.2/§7.7 | ie1/ie2/ie3/a2 |
| AC-2 | SF-01：敌意回声/超长键名/敏感标记构造（键名、model、fingerprint、finish_reason 通道）下全证据树字节扫描零命中；三形态可判；11 检查点互异保持；None 纪律保持 | §7.3-§7.6 | sf1/sf2 + rd 系/e2 演进 |
| AC-3 | 批次协议承载面：三章节在场且与授权逐字对齐；新旧批分离（新工件+新目录+旧工件历史冻结）可验 | §11/§8 | Packet 章节 + sf3/a1 |
| AC-4 | 冻结面兼容：v3→v4 六条件零弱化；九文件 298 方法 blob 不变；全离线（零网络/零 Secret/零付费） | §10/§12 | Done Commands 2/3/6/7 + sf4 |

**Not-covered（全团队不得扩张；= CA §Not covered 1-7 全文）**：PR3-e 的任何真实调用、90 次自动执行或预授权（仅零调用矩阵/设计/估算，落本叶收口呈报材料，不新建仓库工件）；第二批次与任何形式的重试/加次/上限提高/账本重置/换模型/换仓库 SHA/换机器；thinking 参数形态变更、通配或前缀身份匹配、`deepseek-v4-flash-vision-exp` 纳入；canary 清单五项变更、预算语义放松、budget.py 零字节、IP-0024..0031 其余冻结面触碰；历史文档文本修改（IP-0032/0033 Packet、`LIMA_PR3d_Real_Run_Approval_2026-09-27.md`、CANARY_DECISION_PACK 原样冻结为历史证据——演进依据只在本 Packet 显式登记，§5.6）；#223/#226 重开、#57 关闭或 PR3 勾选、LlamaFactory 全仓扫描结论外推、九类 archetype 矩阵升级、旧样本追认；`tests/` 其余九个冻结测试文件、`benchmarks/v4/baseline/` 其余七模块与 `__init__.py`、`lima/**`、`evaluation_data/**`、`scripts/**`、`pyproject.toml`/`requirements.txt`/`.github/**`、前端、`docs/` 其余全部。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0034-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0034_2026-09-28.md` | 范围权威；R1-R14 全文转录见 §16 |
| 2 | Intent Record INTENT-IP-0034-v1 | `.pv_tmp/INTENT_RECORD_IP-0034_2026-09-28.md` | M1-M26 授权语义；F1-F12 决定性事实（F2 身份门现状/F4 测试锚/F5 SF-01 通道/F7 价格页亲读/F10 IP 编号未占用）；N1-N6 推断（N1 三形态并集/N2 vision-exp 拒/N6 内存持久分离均被 CA 采纳为裁定） |
| 3 | Maintainer 授权原文（逐字） | Intent Record 第 2 节（五裁定 + 开工核验 + 四阶段 + 最终呈报） | §7.2/§7.4/§8/§11 的授权依据；§11 三章节逐字对齐源 |
| 4 | Source Issue #232 正文 | CA §Authoritative Inputs #2（Coordinator GitHub API 亲取 2678 字符；本 P&V 零网络） | Scope 1-6/Non-goals/AC-1..4（经 CA 规范化为 FR-01..06） |
| 5 | IP-0033 Packet | `docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md`（@71e7fb1） | §5 文件边界/§7.2-7.8 冻结契约/§10 六条件演进程序/§12 Stop/§14 Done Commands 结构与语义先例 |
| 6 | IP-0032 Packet | `docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md` | §7.3 工件 schema 与身份钉（本 Packet 演进对象之一）、§7.9 证据 schema、§7.10 RealSuiteResult |
| 7 | ER 记录 SF-01 | `.pv_tmp/EVIDENCE_REVIEW_RECORD_IP-0033_2026-09-28.md` | SF-IP-0033-20260928-01 原文 + LK-6..LK-9 探针事实（敌意标记经键名含 \u 转义与 4KB 超长键、220 字符 model 值原样进入 attempt 文档）→ FR-02 设计输入 |
| 8 | 现行产品 | `benchmarks/v4/baseline/real_run.py` @6d69078（blob cfc3aba，1719 行全文亲读） | 演进对象：身份门 L916-919/L1363-1367、`_response_meta` L720-760、`_settle` L1075-1114、canary L1479-1527、证据写出 L1530-1719、工件加载钉扎 L520-680 |
| 9 | 冻结测试 v3 | `tests/test_v4_baseline_real_run.py` @6d69078（blob 6167e9a0，47 方法全文亲读） | 演进基础（§9/§10）：u3 L1207-1230、rd2 L1795-1841、rd3 L1843、rd5 L1896、e2 L1534、工件常量 L99-136、`write_artifact` L654-663 |
| 10 | 现行批准工件 | `docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md`（blob 2e2473c） | 新工件对参照（十节结构、json 块、机器 profile 转写源）；迁移后历史冻结对象 |
| 11 | 上轮失败证据 | `D:\BaseAIProject\LIMA-real-runs\pr3d-real-2026-09-27\attempts\attempt-00.json`（CA 输入 #10） | deepseek-flash 首轮实测形态（response.model="deepseek-flash"、RESPONSE_INVALID、`$.response`）；§8 纳入依据 (b) |
| 12 | Dockerfile | @6d69078 L55-67（blob ef14398）亲读 | C1 +2 行落位依据（L58 后插新工件行、L60 后插本 Packet 行） |
| 13 | 定价页亲读记录 | Intent F7（api-docs.deepseek.com，2026-09-28 WebFetch） | 新工件 pricing 块 retrieval_date 与 deepseek-flash 规范服务名来源 |

哈希真值来源：`git ls-tree 6d6907855dced9c274e04e5819e862794b740c4f -- <paths>`（本 P&V 会话程序化复核，与 CA §Exact Baseline 一致）。冻结前基线绿（C0，本 P&V 会话亲跑并归档于 `.pv_tmp/RED_IP-0034_2026-09-28/baseline.txt`）：v3 文件 47/47 绿；九冻结文件 298/298 绿；全量 discover **2631 OK（skipped=24）**——CA 参照值 2879/26 为 ER-IP-0033 时点（d281365）记录，其后的 PR #225（merge 6d69078）删除 legacy cxx 测试链（`git diff --stat 71e7fb1..6d69078 -- tests/` = 31 文件、-8199 行）；CA 明文要求"冻结前须重跑登记实际值"，实际值=2631/24，Done Command 3 的 skipped 集比对以此为准。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | 主会话候选 (b)：仅代码常量承载第三形态、工件不动 | CA R2 否决：两源一致原则（工件=操作者可见授权面）不允许代码侧隐藏第二授权源；#232 AC-1 负例"工件携带未钉扎形态被拒"只在工件承载制下可判定 |
| 2 | `served_as` 与 `served_model_forms` 双字段并存 | CA R2 否决：单一权威，杜绝 served_as 与 forms 列表的分歧歧义 |
| 3 | 决策包 P5 的"256 字符截断+标记"形态 | CA R4 否决：截断泄露前缀字节，且不在授权偏好序（受控枚举/已批准身份/不可逆摘要）内 |
| 4 | 独立数值上限（主会话建议的 ≤128/≤64 常量） | CA R4 否决：每个原样谓词自身即有界（枚举成员=固定短串；批准形态=钉扎常量；指纹模式 ≤66 字符），独立上限冗余 |
| 5 | 拒绝式处置（敌意/超长键名与未知身份串导致 run 失败、新检查点或新错误码） | CA R5 裁定脱敏而非拒绝：拒绝会翻转"结构异常但合法响应仍成功"的产品语义；十码/11 检查点零新增 |
| 6 | 通配/前缀身份匹配；`deepseek-v4-flash-vision-exp` 纳入 | 授权裁定 1 明文（只接受官方文档与首轮证据共同支持的形态）+ CA Not-covered 3 |
| 7 | 修改 budget.py/orchestrate/run/新测试文件/历史文档/`.gitignore` 以承载本 IP | CA R1 否决（Allowed Files 终形=恰 2 Add + 3 Modify） |
| 8 | 把 `RealSuiteResult.model/system_fingerprint_baseline` 的具体取值（完整串或 token）钉进测试 | CA R4（内存/持久分离）：变换施加于赋值点还是文档构造点由 Implementation 定，冻结语义=身份逻辑不读取已变换值；测试只钉持久面（attempt 文档/manifest.json）与内存判定行为 |
| 9 | 为诊断需要记录正文/凭据/完整体/无界服务器字符串 | §0 第 3 条与 SF-01 底线（授权裁定 2 禁止性规范）；Stop Condition 3 |
| 10 | PR3-e 真实调用、第二批、重试、加次、上限提高、账本重置、换模型/SHA/机器 | 授权裁定 5 + CA Not-covered 1/2；Stop Condition 2 |

## 4. Goal / Non-goals

**Goal**：在 IP-0033 诊断/脱敏/usage 解耦骨架上完成三件一体的离线修复并以此解锁一次有界真实执行的协议承载——① `deepseek-flash` 纳入身份允许集（三形态并集 {deepseekv4flash, deepseekv41flash, deepseekflash}，工件承载制，无通配，vision-exp 仍拒）；② SF-01 证据通道收紧（三张持久面的一切服务器控制字符串经"受控谓词→原样，否则不可逆摘要 token"两层制有界化，零截断、零新失败模式、内存判定不读已变换值）；③ 交付 2026-09-28 新一次性批准工件（R8 逐字段钉值）并承载真实批次协议（§11 阶段二/三/四）；④ 以受控冻结面演进 v3→v4 承载验收（47 演进保留 + 7 新增 = 54 方法），九冻结文件 298 方法零改动。全部以离线构造证明；零预算或超限零外部调用。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。真实批次执行本身不在本 Assignment 授权内。

## 5. 文件边界（CA R1：恰 2 Add + 3 Modify；零 Delete；单 PR）

### 5.1 Files to Add

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0034_Identity_SF01.md` | P&V（C1，本文件） | 本 Packet；v4 冻结测试 a1 断言其在库存在 |
| `docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md` | P&V（C1） | 新一次性批准工件（§8；R8 逐字段钉值；无任何凭据）；v4 冻结测试 fixture 基准（`_APPROVAL_RELATIVE_PATH`/`write_artifact` 深拷贝源切换至此） |

### 5.2 Files Allowed to Modify（恰 3；每文件一次性行为见 §10 演进条件）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与上两文件同一提交） | **恰 +2 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0034_Identity_SF01.md ./docs/`（插 IP-0033 Packet 行【L60】后）+ `COPY --chown=lima:lima docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md ./docs/`（插 2026-09-27 工件行【L58】后）；既有行（含 2026-09-27 工件行）零改动。基线 blob `ef14398610b2c7f4594ffda0a1fdc051471fbcbb` |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v3→v4；**唯一冻结面演进授权，程序见 §10**） | 仅此一文件、一次性；方法预算 ≤56（定稿 54：47 演进保留 + 7 新增，§9）；RED 证据先于冻结落盘；v3 blob `6167e9a0ff4ce420d4ffc376b17818e3a7f26157` 永久在链 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3+） | 身份扩纳（§7.2）+ SF-01 有界变换（§7.3-§7.6）+ 工件三钉迁移（§7.7）；`__all__`/十码/11 检查点/canary 清单/D1-D6/请求形状/估计策略/证据时序不变（§7.1）；零新增 import |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/budget.py`（IP-0031 冻结面，零字节改动）；`orchestrate.py`/`run.py`/`report.py`/`collect.py`/`fixtures.py`/`expert_timing.py`/`offline_flow.py`；`docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md`、`docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md`、`docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md`（历史冻结——迁移后不可再被 loader 解析，作为 docs 历史证据原样保留）、CANARY_DECISION_PACK；`D:\BaseAIProject\LIMA-real-runs\**`（上批证据）；`evaluation_data/**`。

### 5.4 Files Forbidden（diff 必空；Done Command 7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余七模块（collect/expert_timing/fixtures/offline_flow/orchestrate/report/run）与各级 `__init__.py`、`budget.py`；`tests/` 其余九个 v4 冻结测试文件（298 方法）；`evaluation_data/**`；`lima/**`；`scripts/**`；`docs/` 其余全部（含历史 Packet、旧批准工件、决策包）；`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`/前端；不提交任何输出目录/密钥/run 产物。

### 5.5 提交链/拓扑（CA R7；冻结）

C1 = 本 Packet + 新批准工件 + Dockerfile 恰 2 行（2 Add + 1 Modify，同一提交，前缀 `[IP-0034][PV]`）→ C2 = tests v4 冻结（1 Modify；提交信息必须含 `"[IP-0034][PV] Freeze acceptance tests v4 (RED)"` 字样）→ C3 = real_run.py（1 Modify，前缀 `[IP-0034][IMPL]`）→ C-final 之后允许且仅允许修复提交（前缀 `[IP-0034][CI]` 或所属角色前缀），每次必须引用 Stop/DR 编号或 ALLOWED_ONCE 记录。单 PR（`codex/ip-0034-identity-sf01` → main）；实现提交必须以 C2 冻结提交为祖先（Done Command 8）。

### 5.6 与其他活动 IP 的冲突分析（冻结面演进依据登记）

无并行活动 IP 占用本切片路径（Intent F10：`git grep "IP-0034"` 与 `git log --all --grep="IP-0034"` @6d69078 均 0 命中）。**冻结面演进依据显式登记（IP-0033 Packet §5.6 先例）= 2026-09-28 Maintainer 授权（Intent Record 第 2 节，裁定 1/2）**，演进对象：① IP-0032 Packet §7.3 的工件 `model` 块字段集（`served_as`→`served_model_forms`）与 run_name/date/pricing.retrieval_date 三钉；② IP-0032 Packet §7.9 契约标记面 + IP-0033 Packet §7.4 规则 1/4 的服务器控制字符串记录面（改 R4 有界变换）；③ IP-0033 Packet §7.8"身份允许集构造不扩纳"（改 R2 三形态并集）；④ 测试面 v3→v4（§10 六条件）。历史文档（IP-0032/0033 Packet、2026-09-27 工件、决策包）零改动（CA Not-covered 5）；本节即唯一演进依据登记处。IP-0024..0031 一切冻结面禁止触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；real_run.py **零新增 import**（SF-01 token 语法所需 `hashlib`/`re`/`json` 已在白名单内——CA §Frozen Interfaces）；测试文件零新增 import（演进只新增常量/辅助函数/两类七方法）。
- **网络**：测试全离线、注入 fake transport、永不触网（既有 `_forbidden_network_roots` 断言保持）。**本 IP 离线交付期间任何真实网络/下载/付费调用 = Stop Condition 1（绝对禁令）**；真实批次仅按 §11 协议由主会话执行。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（真实执行为仓库外 `D:\BaseAIProject\LIMA-real-runs\pr3d-real-2026-09-28\`，§11 阶段二核验项；离线测试写 tempdir）；库内除 §5.1/§5.2 五文件外零写入；不读环境变量/配置/.env。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +2 COPY 行；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态——合并/推送/评论由主会话按 Maintainer 授权另行核发，R13）。
- **凭据**：api_key 仍为显式必填参数，永不落盘/入日志/入错误消息/入证据；新批准工件零凭据（a3 扫描面覆盖新工件）。

## 7. real_run.py 冻结契约细化（CA R2-R5/R8；Packet 定稿）

### 7.1 不变面（违例即验收失败；IP-0032/0033 冻结面保持）

`__all__` 六符号逐字；`run_real_baseline_suite` 签名/参数序/kwonly/默认值；`RealRunErrorCode` 十成员与 `_STABLE_MESSAGES` 逐字（**零新增错误码**）；11 检查点枚举值与 §7.3（IP-0033）field_path 映射不变；请求形状（含 `{"thinking":{"type":"disabled"}}`、`response_format`、max_tokens=8000、请求体 ≤100000 UTF-8 字节、`temperature` 0、双消息）；`_normalize_identity` 正则；`_worst_case_cost` 公式；价格钉常量 300000/1200000；`_BASELINE_SHA_PIN`/upstream 四钉；canary 清单五项键名/判定式/latch 触发；D1-D6 结算表与 `_settle` 语义；CallEstimate 估计策略（attempt-0 最坏值/attempts 1-9 body 派生）；总执行序 ①-⑨；证据文件集、键集封闭与写出时序（run_repeats 返回后、exclusive）；attempt 文档 12 键、manifest 键集、ledger 三联；`RealSuiteResult` 字段全集（含 `real_run: True` 常量）；evaluator payload（real-world v2）；transport 注入契约；import 白名单零新增；模块 hygiene（零环境/配置读取、api_key 永不落盘/入错）。budget.py 与 IP-0024..0031 一切冻结面零触碰。

### 7.2 身份扩纳（FR-01；CA R2 终形；工件承载制）

- **`_MODEL_FIELDS` 保持 5 键，`served_as` → `served_model_forms` 更名**：`("provider", "request_name", "served_model_forms", "base_url", "system_fingerprint_policy")`。工件 `model` 块字段集封闭（未知键拒 `$.model.<key>`，缺键拒 `$.model.served_model_forms` 等）。
- **模块新增钉扎常量**：`_MODEL_SERVED_FORMS_PIN = ("DeepSeek-V4.1-Flash", "deepseek-flash")`（tuple，顺序敏感；字面量或等价命名由 Implementation 定，语义=与工件值逐位相等）。
- **`_ApprovalContract`**：`model_served_as: str` → `model_served_forms: tuple[str, ...]`（其余字段不动）。
- **loader 校验（冻结）**：`model.served_model_forms` 必须为 list、逐元素 str、与 `_MODEL_SERVED_FORMS_PIN` 长度/顺序/逐值精确相等；任一违例 → `APPROVAL_ARTIFACT_INVALID` `$.model.served_model_forms`（非 list/非 str 元素/含未钉扎形态【如 `deepseek-v4-flash-vision-exp`】/顺序漂移/长度不符同路径拒绝——#232 AC-1 负例）。
- **允许集构造（冻结，additive 不替换）**：`_allowed_model_forms = {_normalize_identity(model_request_name)} | {_normalize_identity(f) for f in model_served_forms}` = {`deepseekv4flash`, `deepseekv41flash`, `deepseekflash`}（N1 三形态并集）。`_normalize_identity("deepseek-v4-flash-vision-exp") = "deepseekv4flashvisionexp"` ∉ 集 → 仍拒（N2）；不开通配、不加前缀匹配（M1）。
- **身份门行为**：`_parse_response` 的 response_identity 检查点语义不变（内存按完整字符串规范化判定）；canary 第 2 项 `identity_matches` 判定式不变（响应 model 匹配工件声明形态且 fingerprint 非空）；批内漂移 latch（`REAL_RUN_IDENTITY_CHANGED`）不变。
- **R4 的 model 原样谓词与身份门判定是两个面**：原样谓词（持久面）= 精确（大小写敏感）∈ `{request_name} ∪ served_model_forms`；身份门（内存）= 规范化 ∈ 允许集。两者来源同为工件钉扎，不冲突。
- **`schema_version` 保持 1**：工件判别=封闭字段集 + run_name 钉（R8 三钉迁移后旧式工件在 `$.run_name` 先行 fail-closed，§7.7）。

### 7.3 SF-01 收紧口径（FR-02；CA R3 全通道覆盖）

覆盖三张持久面的一切服务器控制字符串：

1. `diagnostic.response_meta` 的 `top_level_keys`/`message_keys`（逐项）、`model`、`system_fingerprint`、`finish_reason`；
2. attempt 文档 `response.model`/`response.system_fingerprint`/`response.finish_reason`（含身份拒绝分支原 `record.response_model` 直录面）；
3. `manifest.model`/`manifest.system_fingerprint_baseline`。

run/report/ledger/machine_profile/approval 面经 CA 亲验不含服务器控制响应字符串（`build_payload` 无身份串；ledger 数值；machine_profile/approval 为操作者侧），不涉。"已批准的规范身份可原样"豁免落点=§7.4 逐字段原样谓词。

### 7.4 处置机制（FR-02；CA R4 逐字段两层制；零截断；零新失败模式）

| 持久字段 | 原样（verbatim）谓词 | 否则 |
| --- | --- | --- |
| `top_level_keys`/`message_keys` 逐项 | ∈ 模块封闭枚举 `_EXPECTED_RESPONSE_KEYS`（受控枚举） | token |
| `model`（三面） | 精确 ∈ `{request_name} ∪ served_model_forms`（已批准规范身份，大小写敏感） | token |
| `system_fingerprint`（三面） | 匹配冻结格式模式 `^fp_[A-Za-z0-9]{1,63}$`（格式受控） | token |
| `finish_reason`（两面） | ∈ 模块封闭枚举 `_EXPECTED_FINISH_REASONS`（受控枚举） | token |

- **token 语法（冻结）**：`"~d:<len>:<sha256-hex64>"`——`len` = `len(s)` Python 字符数（与 content_len 先例一致），sha256 为 UTF-8 字节全摘要（非前缀；前缀可碰撞）。token 总长 ≤88 字符，自描述且不可与任何原样谓词命中串碰撞（`~`/`:` 不出现在任何谓词命中面）。**零截断**（截断形态否决，§3 #3）。
- **零新失败模式（CA R5）**：SF-01 是证据面变换不是失败模式——敌意/超长键名与未知身份串不导致 run 失败（脱敏而非拒绝）；身份拒绝仍唯有 `response_identity` 检查点（内存完整串判定）；十码/11 检查点/canary/D1-D6 零变化。
- **排序语义（冻结）**：键名列表先按原键名排序再逐项变换——正常响应输出与 v3 逐字节一致；计数（`choices_count`）与 None 纪律不变（未读取=null，不是 ""/0/[]；token 不是 null 的替代——字段前置条件未达时仍 null）。
- **内存/持久分离（N6 落定）**：身份门、基线与漂移比较、canary 清单、`RealSuiteResult.model/system_fingerprint_baseline` 的**身份逻辑**一律在内存按完整字符串判定；有界变换只施加于持久化边界（`_response_meta` 产出、`record.response_*` 供 `to_document`、`_build_manifest_document`）。变换施加于赋值点还是文档构造点由 Implementation 定；冻结语义=身份逻辑不读取已变换值（测试不钉 `RealSuiteResult.model/system_fingerprint_baseline` 的具体取值形态，§3 #8）。

### 7.5 枚举成员表（Packet 冻结的最小必含集；P&V 可在后续 Decision Record 扩充但不得缩）

- `_EXPECTED_RESPONSE_KEYS` ⊇ `{"id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier", "role", "content", "reasoning_content", "tool_calls", "refusal"}`（13 键）。
- `_EXPECTED_FINISH_REASONS` ⊇ `{"stop", "length", "content_filter", "tool_calls", "function_call", "insufficient_system_resource"}`（6 值）。
- `system_fingerprint` 格式模式：`^fp_[A-Za-z0-9]{1,63}$`。

已知边界（CA 已知缺口）：真实响应出现枚举外合法键/finish_reason 时该键名落 token（计数保持）——非缺陷，按证据如实记录；指纹模式基于公开惯例而非首轮实测（attempt-00 fingerprint=null 未读取）——真实指纹不匹配时落 token（安全侧失败，无功能影响），放宽须 DR。

### 7.6 不变面补充（SF-01 后必须保持）

11 检查点诊断互异保持（rd1 v4 演进钉扎——身份检查点构造换未知形态后 11 对 (checkpoint, field_path) 仍互异）；None 纪律保持；`content_len`/`content_sha256`/`choices_count` 计数与摘要面不变；`record.response.*` 契约推进标记语义不变（identity 拒绝分支仍记录 response_model——只是值经 §7.4 变换）；attempt 文档 12 键、manifest 键集、ledger 三联不变。

### 7.7 工件加载三钉迁移与旧工件历史冻结（FR-03；CA R8）

- **Loader 三钉迁移（冻结）**：run_name 钉 `"pr3d-real-2026-09-28"`、date 钉 `"2026-09-28"`、`_PRICING_RETRIEVAL_DATE_PIN = "2026-09-28"`（字面量或命名常量由 Implementation 定，语义=逐字等于新工件值）。其余钉不变：`schema_version==1`、`approval_type=="PR3D-REAL-RUN-LIMITED"`、`authorized_by=="Maintainer"`、`baseline_sha=="888793f1a46db6924009e7ec33f9ff1b633f01fa"`（授权基线钉不变——真实执行须为其后继）、upstream 四钉、`model.provider/request_name/base_url/system_fingerprint_policy` 钉、价格钉 300000/1200000、attempt_policy 五钉。
- **旧工件处置=历史冻结**：迁移后 `docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md`（run_name="pr3d-real-2026-09-27"）在 `$.run_name` 处 fail-closed、不再可解析；作为 docs 历史证据原样保留，Dockerfile 既有行保留。
- **测试 fixture 基准切换（C2 已执行）**：`_APPROVAL_RELATIVE_PATH`/`_RUN_NAME`/`_AUTHORIZATION_DATE`/`_SERVED_MODEL` → 新工件与新值（`_SERVED_MODEL_FORMS` 元组）；`write_artifact` 深拷贝基准随之切换。
- **新旧批分离**：新工件 + 新仓库外输出目录 `D:\BaseAIProject\LIMA-real-runs\pr3d-real-2026-09-28\`（§11 阶段二核验项）；2026-09-27 已终局批次证据分别留存（M16），旧批剩余次数不得挪用。

### 7.8 证据 schema 演进兼容判据（FR-06/AC-4）

- 键集 additive-only、无重命名/删除：attempt 文档 12 键、manifest 键集、ledger 三联不变；`response`/`response_meta` 内**值形态**的变化（token 化）仅出现在越界输入上；**正常响应证据与 v3 形态一致**（标准键集 + 批准 model + 合规指纹下 `top_level_keys` 原样排序、无 token——v4 sf4 钉扎的兼容判据）。旧读取方行为不变。
- 九冻结面 298 方法零改动由 Done Command 7 blob 守护；budget.py 与其余七模块 blob 不变。

## 8. 批准工件与新钉扎（FR-03；CA R8 逐字段值表）

`docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md`（C1 落盘）：第一 ` ```json ` 围栏块为完整封闭 schema 工件，逐字段钉值：

| 字段 | 钉值 |
| --- | --- |
| `schema_version` | `1` |
| `approval_type` | `"PR3D-REAL-RUN-LIMITED"` |
| `run_name` | `"pr3d-real-2026-09-28"` |
| `date` | `"2026-09-28"` |
| `authorized_by` | `"Maintainer"` |
| `baseline_sha` | `"888793f1a46db6924009e7ec33f9ff1b633f01fa"`（钉不变——授权基线，真实执行须为其后继） |
| `upstream` | 与 2026-09-27 工件逐字相同（`hiyouga/LlamaFactory`@`7fcf5b3b130e5713b52415bb7404c476fada9c8c`、canonical tarball URL、`name_equivalence_note` 原文） |
| `model.provider` | `"deepseek"` |
| `model.request_name` | `"deepseek-v4-flash"` |
| `model.served_model_forms` | `["DeepSeek-V4.1-Flash", "deepseek-flash"]` |
| `model.base_url` | `"https://api.deepseek.com"` |
| `model.system_fingerprint_policy` | `"record-and-latch-on-change"` |
| `pricing.source_url` | `"api-docs.deepseek.com"` |
| `pricing.retrieval_date` | `"2026-09-28"`（F7 亲读） |
| `pricing.basis` | `"peak cache-miss per million tokens"` |
| `pricing.prompt/completion` | `300000` / `1200000`（价格钉常量不变） |
| `budget.per_run/batch` | 七维 = 授权 M4 数值（与 2026-09-27 批同值逐字：100000/1000000、1/10、150000/1500000、8000/80000、1200000/12000000、250000000/500000000、500000000/2000000000） |
| `machine_profile.profile_id` | `"lima-pr3d-real-host-2026-09-28"` |
| `machine_profile` 其余七字段 | 从 2026-09-27 工件转写（同机实测：x86_64/Intel(R) Core(TM) i7-14650HX/24/32/windows/3.12.4/NVIDIA GeForce RTX 4060 Laptop GPU） |
| `attempt_policy` | cold 5 / warm 5 / max_attempts 10 / canary_required true / canary_first_attempt 0（同构） |

正文十节结构对齐 2026-09-27 工件（Document Header / Machine-Readable Approval Block / Seven-Dimension Authorization Table / Pricing Adoption and Source / Model and Routing / Upstream Target and Baseline / Machine Profile / Canary Strategy / Invalidation Conditions / Consumption Record 留空）；prose 说明：身份匹配规则改为三形态（request_name 或 served_model_forms 任一，规范化比较）；`deepseek-flash` 纳入依据 = 官方定价页 2026-09-28 亲读（DeepSeek-V4.1-Flash 规范服务名，F7）+ 首轮 attempt-00 实测；vision-exp 不纳入；一次一批次边界。零凭据（a3 扫描面覆盖）。静态守卫：a1（在库 + Dockerfile 双 COPY 行）/a2（数值与身份钉双源一致）/a3（无 secret）/a4（profile 八字段）+ sf3（旧工件 `$.run_name` 拒绝）。

## 9. 测试矩阵 v4（`tests/test_v4_baseline_real_run.py`；定稿 54 方法 = 47 演进保留 + 7 新增；≤56 预算内）

组织：同文件演进（否决新文件），十二个既有类全部保留，新增恰两类（`TestIdentityExpansion`/`TestSF01Sanitization`）。全离线、注入 fake transport、零仓库写入、永不触网（既有 `_FakeTransport`/`_RawBodyTransport`/`_build_tarball`/`_fixed_sources` 基建复用，纯增量）。

### 9.1 新增方法（7 个，逐个登记断言面）

| 方法（新类.新方法） | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| TestIdentityExpansion.ie1 `test_three_approved_forms_pass_identity_gate_full_chain` | FR-01/AC-1 | 三形态 subTest（`deepseek-v4-flash`/`DeepSeek-V4.1-Flash`/`deepseek-flash` 各自驱动响应）：身份门通过、canary passed、chat_calls==10、status sufficient_sample、attempt-0 checkpoint null、response_meta.model 与 attempt response.model 原样=形态本身（deepseek-flash 全链路 10 次成功含在内） |
| TestIdentityExpansion.ie2 `test_vision_exp_and_unknown_forms_rejected_with_tokenized_evidence` | FR-01/AC-1/N2 | `deepseek-v4-flash-vision-exp` 与未知形态（`deepseek-v9-ultra`）subTest：chat_calls==1、canary failed、error_code REAL_RUN_RESPONSE_INVALID、checkpoint response_identity、三面持久值=response_meta.model 与 attempt response.model 均为按公式导出 token（`~d:<len>:<sha256>`，测试内复算不硬抄）、manifest.model is None（None 纪律——未 latch 基线） |
| TestIdentityExpansion.ie3 `test_artifact_served_model_forms_negative_matrix` | FR-01/AC-1（工件未钉扎形态被拒负例） | 五变体 subTest（非 list / 元素非 str / 含未钉扎形态 `deepseek-v4-flash-vision-exp` / 顺序漂移 / 长度不符）→ `APPROVAL_ARTIFACT_INVALID` `$.model.served_model_forms` |
| TestSF01Sanitization.sf1 `test_hostile_key_names_tokenized_counts_preserved` | FR-02/AC-2（LK-6..LK-8 通道） | 敌意回声键名（含 prompt 标记）、`\u` 转义形态键、4KB 超长键、凭据形键名（sk- 形）注入顶层与 message 层：top_level_keys/message_keys 逐项 = 受控枚举原样或按公式导出 token（列表=先按原键名排序再逐项变换，期望值测试内构造）；choices_count==1、content_len/content_sha256 复算不变；全证据树字节扫描：标记/原始键名字节零命中 |
| TestSF01Sanitization.sf2 `test_identity_string_channels_tokenized_across_three_faces` | FR-02/AC-2（LK-9 通道 + 豁免正控制） | 敌意面：220 字符 model（含标记）→ response_meta.model 与 attempt response.model token、manifest.model is None；异常 fingerprint（非 `^fp_[A-Za-z0-9]{1,63}$`，含标记）于成功 run → response_meta/attempt response/manifest.system_fingerprint_baseline 三面 token；枚举外 finish_reason（含标记）→ response_meta/attempt response 两面 token；字节扫描零命中。正控制：批准形态（deepseek-flash）/合规指纹（`fp_`+`a`*32）/`stop` → 对应面原样 |
| TestSF01Sanitization.sf3 `test_legacy_2026_09_27_artifact_rejected_at_run_name` | FR-03/AC-1（历史冻结证明） | 以库内 2026-09-27 工件为 artifact_path 驱动入口 → `APPROVAL_ARTIFACT_INVALID` `$.run_name`（旧工件不再可解析） |
| TestSF01Sanitization.sf4 `test_normal_response_evidence_matches_v3_shape` | FR-06/AC-4（兼容判据） | 标准键集 + 批准 model（deepseek-flash）+ 合规指纹 + `stop` 的全 10 成功 run：每 attempt response_meta 九键值与 v3 形态一致（top_level_keys 原样排序、message_keys 原样、model/fingerprint/finish_reason 原样）、diagnostic 字符串值域零 token；manifest.model/manifest.system_fingerprint_baseline 原样 |

### 9.2 演进既有方法（47 全保留；hunk 归因见 §10 条件 2 登记）

| 方法 | 演进（additive 或登记的语义值更新） | 归因 |
| --- | --- | --- |
| a1 `test_artifact_in_repo_with_closed_field_set_and_container_copy_line` | 断言 IP-0034 Packet 在库 + Dockerfile 含新 Packet COPY 行与新工件 COPY 行（静态守卫；C1 先落→冻结时按设计通过；旧工件/旧 Packet 行断言保留） | FR-03/§8 |
| a2 `test_authorized_numbers_match_maintainer_constants` | `model.served_as`→`model.served_model_forms == list(_SERVED_MODEL_FORMS)`（钉扎常量双源一致）；新增 model 块字段集封闭断言与 `pricing.retrieval_date == "2026-09-28"` | FR-01/FR-03/AC-1 |
| u3 `test_canary_model_mismatch_rejected` | 未知形态负例保持；`response_meta.model` 断言由原样值改为按公式导出 token（测试内复算） | FR-01/FR-02（R4 值更新） |
| rd1 `test_eleven_checkpoints_produce_distinct_diagnostics` | 身份检查点构造由 `deepseek-flash`（现为批准形态）换未知形态 `deepseek-v9-ultra`；11 对互异断言不变（SF-01 后互异性保持） | FR-01/AC-1 |
| rd2 `test_response_meta_nine_keys_sorting_and_none_discipline` | 身份失败构造换未知形态；fixture 响应键名在受控枚举内 → top_level_keys/message_keys 原样断言保持；`meta.model`/`meta.system_fingerprint`（fixture 值 `fp-stable-001` 不合规式）断言改为按公式导出 token | FR-02（R4 值更新） |
| rd3 `test_success_attempts_carry_null_checkpoint_full_meta` | fixture 响应 model 用 `deepseek-flash`（首轮实测形态，现为批准形态）；`meta.model == "deepseek-flash"` 原样 | FR-01（R2 值更新） |
| e2 `test_evidence_chain_free_of_key_and_raw_content` | 诊断面值域审计纳入 token 模式（收紧式：token 值必须等于 fixture 指纹的期望 token，不允许任意 token） | FR-02/AC-2 |
| rd5 `test_diagnostics_face_leak_free_and_value_domain_audit` | 同 e2 的 token 模式审计扩展 | FR-02/AC-2 |

其余 39 方法（a3/a4、v1-v5、b1/b2'/b4、d1-d5、u1/u2/u4、c1-c3、g1-g4、e1/e3/e4、h1-h3、rd4/rd6、dec1-dec4、ro1-ro2）断言面不变（基线回归锚：预算门/下载/解包/请求界/账本/hygiene/解耦/观测不受演进的证明面）；`_LAST_ROUND_SERVED_FORM` 常量注释语义翻转（deepseek-flash 现为批准形态——ERR-D 锚的失败复现职责移交 `_UNKNOWN_MODEL_FORM`）。模块 docstring 更新为 v4 演进说明（文档 hunk，归因 FR-04）。

### 9.3 新增测试侧冻结常量与辅助（纯增量）

`_SERVED_MODEL_FORMS = ("DeepSeek-V4.1-Flash", "deepseek-flash")`；`_UNKNOWN_MODEL_FORM = "deepseek-v9-ultra"`；`_PRICING_RETRIEVAL_DATE = "2026-09-28"`；`_PACKET_IP0034_RELATIVE_PATH` 与两条 IP-0034 COPY 行常量；`_EXPECTED_RESPONSE_KEYS`/`_EXPECTED_FINISH_REASONS`（§7.5 最小必含集）；`_FINGERPRINT_PATTERN = ^fp_[A-Za-z0-9]{1,63}$`；`_SF01_TOKEN_PATTERN = ^~d:[0-9]+:[0-9a-f]{64}$`；辅助函数 `_sf01_token(value) = "~d:" + f"{len(value)}:" + sha256(value utf-8).hexdigest()`（PC3：token/digest/len 一律复算导出，不硬抄实现值）。

### 9.4 RED 形态（Modify 型 IP；产品已存在）

C2 冻结前对**未修改的 real_run.py（6d69078 版，blob cfc3aba）**运行 v4：预期失败 = 依赖新工件可加载/新字段/身份扩纳/脱敏 token 的方法——几乎所有走 `run_real_baseline_suite` 的 arrange 都在工件加载处红（**新工件被现行 loader 拒于 `$.run_name`**——现行钉为 2026-09-27 值；write_artifact 变体同理由 `$.run_name` 先行拒绝），逐方法归因"新工件被现行 loader 拒绝"；token 期望对现行原样记录必红。按设计通过 = 静态/交付物存在类（a1-a4 需 C1 已落、v1、h1-h3、g3/g4 账本直测）。RED 逐方法归因登记（§10 条件 5），独立日志归档（SF-01 教训）。**基线态证明**：冻结前先登记 v3 文件对现行产品的 47/47 绿 + 九文件 298 绿 + discover 2631/24（Done Command 0，C0 已执行归档），证明 RED 非既有断裂所致。

## 10. 冻结测试面演进程序（v3→v4；CA R6 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0034 的产品语义变更（身份扩纳/SF-01/工件三钉迁移）必然触碰 IP-0032/0033 冻结面 `tests/test_v4_baseline_real_run.py`。**裁定：允许该文件以受控方式演进至冻结版本 v4**。先例=IP-0033 Packet §10（v2→v3）；演进是产品语义驱动（非机械缺陷），ALLOWED_ONCE 不适用、不得以其消化——授权依据=CA-IP-0034-v1.0 R6 + 本节。**演进依据=2026-09-28 Maintainer 授权（§5.6 登记）。**

**演进六条件（全部满足方为合法 v4；任一不满足=Stop Condition 7）**：

1. **对象唯一**：仅 `tests/test_v4_baseline_real_run.py` 一文件、仅此一次；九个其余 v4 冻结测试文件与 budget.py 等产品冻结面 blob 逐字不变（Done Command 7 守护）。IP-0024..0031 冻结面=禁止。
2. **逐 hunk 归因**：v3→v4 每个 hunk 必须映射到 #232 FR-01..FR-06 之一或授权裁定编号并在 Packet 登记。（本 Packet 登记：模块 docstring→FR-04；常量迁移（工件路径/run_name/date/served forms/retrieval date/未知形态/枚举/指纹与 token 模式/`_sf01_token`）→FR-01/FR-03/FR-04；`_LAST_ROUND_SERVED_FORM` 注释翻转→FR-01；a1 增量→FR-03；a2 增量与 served_as→served_model_forms 值更新→FR-01/FR-03【R2】；u3 token 值更新→FR-02【R4】；rd1 身份构造迁移→FR-01【R2】；rd2 未知形态+token 值更新→FR-02【R4】；rd3 成功 model 值更新→FR-01【R2】；e2/rd5 token 模式审计→FR-02【R4】；两新类 7 方法→FR-01/FR-02/FR-03/FR-06。）
3. **禁止弱化**：既有断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因显式登记的语义变更而更新的期望值。**本轮 (b) 类值更新清单（全部由 R2/R4 裁定驱动，无一处为实现便利）**：a2 `served_as`→`served_model_forms`（R2 字段更名）；u3 `meta.model` 原样值→导出 token（R4 model 谓词）；rd1/rd2 身份失败构造 `deepseek-flash`→未知形态（R2 扩纳使旧锚失效）；rd2 `meta.model`/`meta.system_fingerprint` 原样值→导出 token（R4 谓词使 `fp-stable-001` 不再合规）；rd3 成功 model `deepseek-v4-flash`→`deepseek-flash`（R2 批准形态，语义同为"批准身份原样"）；e2/rd5 值域审计允许集扩充=仅限 fixture 指纹的期望 token（收紧式：不允许任意 token 值；正文/凭据/结构外字符串仍拒——敌意通道检测由 sf1/sf2 字节扫描补强）。弱化判定争议 → Decision Request。
4. **版本链保留**：v3 blob（`6167e9a0ff4ce420d4ffc376b17818e3a7f26157`）与 v1/v2/v3 提交永久在链；Packet 记录 v3 与 v4 的 blob id 与演进理由索引（v4 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，v4 测试对未修改的 real_run.py（6d69078 版）运行并留档 RED 证据（独立日志文件归档于 `.pv_tmp/RED_IP-0034_2026-09-28/`，每方法 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（§9.4）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；v4 冻结提交后本 Assignment 的 ALLOWED_ONCE（§12）仅覆盖 v4 的机械缺陷。

**ER 复核面**：ER 将逐 hunk 复核演进正当性（条件 2/3）、独立复跑 RED 归因、复核 §9 矩阵断言与 AC 映射。

## 11. 真实批次协议承载（FR-05；CA R9；逐字对齐 2026-09-28 Maintainer 授权阶段二/三/四）

**本 Assignment 授权边界先行声明**：本 Assignment 授权的交付物=离线修复 PR（阶段一）。P&V 与 Implementation 全程零真实模型调用、零网络下载、零付费、零远端写。以下三章节是阶段二/三/四的执行协议（由本 Packet 承载）；真实执行由主会话在修复 PR 合并 + post-merge PASS + 干净最新 main 后按协议另行执行——**前置条件不满足即停**。

### 11.1 阶段二硬门清单（真实执行前；临调用前逐项核验）

1. 修复 PR 已合并 + post-merge PASS + 代码与批准工件位于干净最新 main（`docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md` 随 main 在场；执行 checkout 为 `baseline_sha` 的后继）。
2. 临调用前实时读 DeepSeek 官方价格页并记录来源与日期；peak cache-miss 输入价高于 US$0.30/百万、输出价高于 US$1.20/百万，或价格不可确认 → **付费调用前停止呈报**。
3. 核验实际模型路由、固定仓库 SHA `7fcf5b3b130e5713b52415bb7404c476fada9c8c`、机器 profile、七维预算、请求体 ≤100000 UTF-8 字节、max_tokens=8000、超时、Secret 注入路径（key 从本机环境人工桥接为显式参数，不入日志/Issue/PR/仓库/证据文件）、一次性仓库外输出目录 `D:\BaseAIProject\LIMA-real-runs\pr3d-real-2026-09-28\`、脱敏扫描。
4. 证明本批账本为全新一次性授权工件，与 2026-09-27 已终局批次分别留存（不挪用旧批剩余 9 次）。
5. 如实声明真实 runner 覆盖的扫描器/evaluator/数据集（12 候选文件工作负载，不外推 LlamaFactory 全仓扫描或 #57 AC-03 完成）。

### 11.2 阶段三批次协议（一次性真实批次）

1. attempt-0 即第一个 cold canary，计入 10 次总数；五项清单逐项核验（身份/system_fingerprint/usage/费用预界定/摘要链/成功样本/批次余量——canary 五项清单键名与判定式不变）。
2. 任一失败 → 立即 latch、后续 9 次零调用、失败样本与脱敏诊断留存、以"失败终局+下一步裁定材料"收口（**不重试**）。
3. 全过后在同一账本、同一 RunSpec、本次七维上限内继续余下 ≤9 次，形成最多 5 cold + 5 warm；任一后续停机条件触发即停止并保留全部成功与失败样本。
4. 逐次记录请求数、模型身份、真实返回 usage、可核对的费用计算、端到端与模型调用耗时、资源观测、RunResult digest。
5. 账本零入账 ≠ 提供方实际收费零；平台账单不可读取时实际扣费标 UNKNOWN 并提出最小人工核对项。
6. 统计纪律：真实成功样本 nearest-rank p50/p95；样本不足明确 `insufficient_sample`；不排除失败 run；不把 canary 单样本写成稳定性能结论。

### 11.3 阶段四收口材料清单

1. post-run 核验、Delivery Ledger、Closure Audit、手工关闭本叶（真实失败分支按原规格为合法终态可关叶，但不代表 #57 完成；#57 保持 open、PR3 整体不勾选）。
2. 对照 #57 的 FR-03/04/05/06、AC-03 与 V5 要求逐行填"已证实/部分/未证实"；特别核对原始候选与压缩队列、专家分钟数、费用、公开 holdout、九类 archetype、immutable before baseline；**缺项不得以 token/耗时数据补称完成**。
3. PR3-e 零调用需求矩阵、最小调用设计与基于本轮实测 usage 的预算估算 = **本叶收口呈报材料（一次性最终呈报 + 收口评论），不新建仓库工件、不新开叶首工件**（I6 裁定）；先证明九类是否真的各需 10 次付费请求；不得自动执行或预授权 90 次。
4. Runtime Attestation、ACTIVE 候选计数、Agent 调用指标按证据等级如实记录，不追认缺证明的旧样本。
5. 最终一次性呈报（M26）：实际 Issue/PR/merge SHA、CI 与 post-merge 结果、修复边界、canary 五项结果、实际模型请求次数、七维账本、可核实 usage 与费用、提供方账单状态、cold/warm 样本数及统计口径、#57 逐项剩余缺口、PR3-e 单独预算建议；任何硬门停止时提交具体失败证据与下一次裁定所需最小材料，不扩大本次授权。

### 11.4 批次隔离与一次一批次边界

授权只覆盖上述一个批次（M5）：任何失败、超时、取消、被拒请求都按既定协议计数和留证；canary 未通过则零后续请求；不得重试、增加次数、重置账本、换模型、换仓库 SHA、换机器、提高任何上限或开启第二批；PR3-e 的额外真实调用不在授权内。

## 12. ALLOWED_ONCE（一次性机械测试修正授权；CA R12）

v4 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v4→v4'），条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 v4 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request；本授权与 §10 演进授权互不折抵、各仅一次。

## 13. Stop Conditions（触发即停并提交 Decision Request；CA R10）

0. 派发前再核验失败：#232 正文/标签状态与本地捕获不一致，或 Base SHA 上 main 出现冲突性实现。
1. **任何真实网络/下载/付费调用（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. 需要 thinking 参数变更、通配/前缀身份匹配、vision-exp 纳入、第二批、重试、加次、上限提高、账本重置、换模型/SHA/机器才能满足任何断言。
3. 需要放松任何 fail-closed 门禁/既有断言（含以"诊断需要"为由记录正文/凭据/完整体/无界服务器字符串）。
4. 需要触碰 Do Not Touch 路径、第 6 个变更文件、或 Dockerfile 超 2 行。
5. 需要修改 budget.py 或其余七模块/九测试文件才能交付。
6. 方法数超 56；298 回归/全量 discover 出现非预期失败。
7. v4 演进六条件（§10）任一不满足，或出现"弱化既有断言才能通过"的 hunk。
8. **授权文本与实现需求冲突**（含本 Assignment 裁定与 Maintainer 授权原文的语义矛盾、或裁定间互斥）——不得自行改写授权或裁定。
9. 需要新依赖/新 import、或非注入式外部输入。
10. 发现勘误/证据/代码间新矛盾影响验收语义——记录并提交，不得自行改写远端记录。
11. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0）。
12. **真实批次阶段专属（主会话执行时适用）**：价格页实时复核超标或不可确认；canary 失败即失败终局——收口呈报而非重试；脱敏扫描在真实批次前发现泄露。

## 14. Done Commands（worktree 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 2 Add+3 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0034_2026-09-28/baseline.txt）：
#    v3 文件 47/47 绿；九冻结文件 298/298 绿；全量 discover 2631 OK (skipped=24)
#    （CA 参照值 2879/26 为 ER-IP-0033 时点记录；PR #225 删除 legacy cxx 测试链后的实际值=2631/24，
#     skipped 集比对以实际登记值为准）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result
PYTHONUTF8=1 python -m unittest discover -s tests
# 0b. RED 证据（C2 冻结前，对未修改 real_run.py @6d69078）：独立日志文件归档
#     （.pv_tmp/RED_IP-0034_2026-09-28/）+ 逐方法归因表（§10 条件 5）
# 1. 定向 v4 测试（C2 冻结时按设计 RED 且归因"新工件被现行 loader 拒绝/新能力缺席"；
#    C-final 后全绿；54 方法）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
# 2. 九冻结文件回归（298 必须全绿）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result
# 3. 全量 CI discover 集合回归（绿；skipped 集与基线 2631/24 一致）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；5. ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_real_run.py
# 6. diff 守护：恰 2 Add（IP-0034 Packet+新工件）+ 3 Modify（Dockerfile/tests/real_run.py）；
#    Dockerfile diff 恰 +2 行
git diff --name-status 6d6907855dced9c274e04e5819e862794b740c4f...HEAD
git diff 6d6907855dced9c274e04e5819e862794b740c4f...HEAD -- Dockerfile   # 恰 +2 行
# 7. blob 守护：九测试文件+budget.py+其余七模块+各级 __init__+三 JSON+lima/config 先例文件
#    blob 与基线一致；tests/test_v4_baseline_real_run.py 登记为"演进文件"
#    （v3 blob 6167e9a0 → v4 blob 记录在案）
git ls-tree 6d6907855dced9c274e04e5819e862794b740c4f -- <守护清单> 与 HEAD 对比
# 8. ancestry：6d69078 → C1 → C2(v4 冻结) → C3 各段 merge-base --is-ancestor exit 0
# 9. 工件一致性守护：新工件 json 块逐字段=R8 钉值（json.loads 解析通过）；模块钉
#    （run_name/date/retrieval_date/served forms）=工件值（双源一致）；旧工件 2026-09-27
#    在 $.run_name 处被拒（历史冻结证明，sf3 留痕）
```

PC1-PC3 标配（IP-0033 同款）：PC1 测试源 secret-token 拼接扫描（含新 token/枚举断言面——a3 运行时自扫 + 归档前静态复核）；PC2 arrange 经冻结校验器（spec_from_mapping/validate_baseline_manifest/validate_role_bindings——g1 面保持，新方法经 `run_entry` 复用同源 arrange）；PC3 派生数值断言（token=按公式导出、digest/len 复算、不硬抄实现值——u3/rd2/ie2/sf1/sf2 期望 token 全部由 `_sf01_token` 复算）。

## 15. PR 与 Completion Summary 契约（CA R13）

- PR：单 PR `codex/ip-0034-identity-sf01` → main；标题禁 close 族关键词与编号组合（含否定句）；提交前缀 `[IP-0034][PV]`/`[IP-0034][IMPL]`/`[IP-0034][CI]`；正文含 Final SHA、变更文件清单（恰 2 Add+3 Modify）、Done Commands 实际输出摘要（0/0b/1-9）、满足/不满足/未验证逐条、下一责任人；合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写；PR 必须写明 "This PR does not auto-close the Source Issue." 与 "Related to #232."（仅此关联形式）。
- Completion Summary 必含：FR-01..06 逐条证据索引（测试 ID）、AC-1..4 判定、v4 blob 与 C1/C2 冻结提交 SHA、RED 归档路径与逐方法归因计数、C0 基线实际值（47/298/2631/24）、零真实调用声明、Dockerfile 恰 +2 行证明。

## 16. 范围裁定 R1-R14 转录（CA-IP-0034-v1.0 决定性内容）

- **R1 范围与文件边界**：Allowed Files 终形=恰 2 Add + 3 Modify（§5 表）；零 Delete；单 PR。否决扩展：budget.py 任何字节、新测试文件、orchestrate/run 注入点、历史文档修改、`.gitignore`。历史文档冲突处置：不改 IP-0032/0033 Packet 与旧工件文本，新 Packet 显式登记"冻结面演进依据=2026-09-28 Maintainer 授权"（§5.6）。
- **R2 身份扩纳载体终形**：工件承载制。`model.served_as` 由 `model.served_model_forms`（封闭字符串列表）取代（不保留双字段）；`_MODEL_FIELDS` 保持 5 键（更名）；模块新增 `_MODEL_SERVED_FORMS_PIN = ("DeepSeek-V4.1-Flash", "deepseek-flash")`（tuple 顺序敏感）；loader 校验列表/逐元素 str/长度/顺序/逐值精确相等，违例 `APPROVAL_ARTIFACT_INVALID` `$.model.served_model_forms`；`schema_version` 保持 1；允许集构造=规范化三形态并集（§7.2）；normalize(vision-exp) ∉ 集仍拒；不开通配、不加前缀。主会话候选 (b)（仅代码常量）否决。
- **R3 SF-01 收紧口径**：全通道覆盖——三张持久面（§7.3）的一切服务器控制字符串；run/report/ledger/machine_profile/approval 面不涉；"已批准规范身份可原样"豁免落点=R4 逐字段谓词。
- **R4 处置机制**：逐字段"受控谓词→原样，否则不可逆摘要 token"两层制（§7.4 表）；token 语法 `"~d:<len>:<sha256-hex64>"`（len=Python 字符数、UTF-8 全摘要、总长 ≤88、不可与谓词命中串碰撞）；不设独立数值上限（对 ≤128/≤64 建议的修正裁定）；截断形态否决；排序语义=先按原键名排序再逐项变换（正常响应与 v3 逐字节一致）；枚举成员最小必含集（§7.5）；内存/持久分离（N6：身份门/基线漂移/canary/Result 身份逻辑在内存按完整字符串判定，变换只施加持久化边界，施加点由 Implementation 定，冻结语义=身份逻辑不读取已变换值）。
- **R5 错误族与检查点面**：确认零新增。十成员与逐字消息字节级不变；11 检查点枚举与 field_path 映射不变；canary 五项清单键名/判定式/latch 触发不变；D1-D6 结算表不变。SF-01 是证据面变换不是失败模式（脱敏而非拒绝）；身份拒绝仍唯有 response_identity。
- **R6 测试面 v3→v4 演进程序**：六条件全文见 §10；方法预算 ≤56（47+≤9；定稿 54）；锚迁移清单（u3 翻转/rd2/rd3/a1/a2/e2/rd5）与新增覆盖必含（§9）；RED 形态=新能力缺席（新工件被现行 loader 拒于 `$.model`/`$.run_name`；token 期望对原样记录必红）。
- **R7 提交链拓扑**：C1（2 Add+1 Modify，`[IP-0034][PV]`）→ C2（tests v4 冻结，提交信息含 `"[IP-0034][PV] Freeze acceptance tests v4 (RED)"`）→ C3（real_run.py，`[IP-0034][IMPL]`）→ C-final 后仅修复提交（引用 Stop/DR/ALLOWED_ONCE）；单 PR；实现提交以 C2 为祖先。
- **R8 新批准工件与钉扎迁移**：逐字段钉值表（§8）；Loader 三钉迁移（run_name/date/retrieval_date=2026-09-28）；旧工件=历史冻结（`$.run_name` fail-closed，docs 保留，Dockerfile 行保留）；测试 fixture 基准切换（`_APPROVAL_RELATIVE_PATH`/`_RUN_NAME`/`_AUTHORIZATION_DATE`/`_SERVED_MODEL`→新值；`write_artifact` 深拷贝基准切换）。
- **R9 真实批次协议承载**：IP-0034 Packet 必须含三章节逐字对齐授权阶段二/三/四（§11.1/§11.2/§11.3）；并记载本 Assignment 的 P&V/IMPL 零真实调用、真实执行前置条件不满足即停。
- **R10 Stop Conditions**：§13（0-12）。
- **R11 Done Commands**：§14（0/0b+1-9）。
- **R12 ALLOWED_ONCE**：§12。
- **R13 PR 纪律**：§15。
- **R14 升级条款**：Implementation 出现跨冻结模块语义约束、同一根因两轮有新证据修复仍失败、或疑似规格矛盾 → 停止并提交 DR；如裁定升级目标档位，实际切换须新建/重配置会话并取得 SESSION-RUNTIME-VERIFIED，文件边界/测试冻结/验收标准不变。

## 17. Decision Record

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0034-PV-1 | 测试侧新增 `_UNKNOWN_MODEL_FORM = "deepseek-v9-ultra"` 承担身份失败负例锚（ERR-D 锚 `deepseek-flash` 语义翻转为批准形态后，失败复现职责移交） | 2026-09-28 | CA R6 锚迁移清单；§9.2 |
| DR-IP-0034-PV-2 | `_chat_response` 默认 fingerprint 保持 `fp-stable-001`（不合规式→证据面 token 化）；合规指纹正控制用 `fp_`+`a`*32（sf2/sf4）；rd2 的 fingerprint 断言改为导出 token | 2026-09-28 | CA R4 谓词（`fp-stable-001` 不匹配 `^fp_[A-Za-z0-9]{1,63}$`）；§10 条件 3(b) 登记 |
| DR-IP-0034-PV-3 | e2/rd5 值域审计的 token 允许采用收紧式：token 值必须等于 fixture 指纹的期望 token（`_sf01_token` 复算），不允许任意 token 值 | 2026-09-28 | CA R6"allowlist 审计纳入 token 模式"+ 条件 3 禁弱化；敌意通道检测由 sf1/sf2 字节扫描补强 |
| DR-IP-0034-PV-4 | 测试不钉 `RealSuiteResult.model/system_fingerprint_baseline` 的取值形态（完整串或 token 均可），只钉持久面与内存判定行为 | 2026-09-28 | CA R4 内存/持久分离（N6）；§3 #8 |
| DR-IP-0034-PV-5 | manifest.model 的 token 化断言不可达（baseline 仅在身份通过后 latch，恒 ∈ 批准形态 ∪ {None}）；ie2/sf2 以"manifest.model is None + response/response_meta 两面 token"钉敌意 model 通道，manifest 敌意通道由 system_fingerprint_baseline 三面钉 | 2026-09-28 | 产品流 L1428-1431 亲读 + CA R3 通道面；§9.1 |
| DR-IP-0034-PV-6 | 全量 discover 基线实际值=2631 OK（skipped=24）（CA 参照值 2879/26 为 ER-IP-0033 时点记录；PR #225 删除 legacy cxx 测试链所致，`git diff --stat` 亲验） | 2026-09-28 | CA §Exact Baseline"冻结前须重跑登记实际值"；§2 登记 |

（无未决 DR；冻结面演进授权=CA R6+§10 正式授权，非未决事项。）

## 18. 已知缺口（不阻塞本 Packet）

- **G1 真实批次前置未满足**：合并+post-merge PASS+干净 main+价格实时复核前不得执行；真实执行归主会话（§11），不在本 Assignment 授权内。
- **G2 指纹格式模式基于公开惯例而非首轮实测**（attempt-00 fingerprint=null 未读取）：真实指纹不匹配 `^fp_[A-Za-z0-9]{1,63}$` 时落 token（安全侧失败，无功能影响）；放宽须 DR。
- **G3 枚举外合法键/finish_reason 落 token**（计数保持）：非缺陷，按证据如实记录；真实批次出现时在收口材料登记。
- **G4 M8 提醒（收口阶段执行）**：5 warm 达到 #57 最少 5 warm 要求；一次 canary 成功≠统计基线；10 次请求≠#57 AC-03 全部满足。
- **G5 #232 远程正文未由本 P&V 会话直取**（零网络边界）：以 CA 转录为权威；主会话派发前已完成远程核验（CA 输入 #2"亲取全文"）。
