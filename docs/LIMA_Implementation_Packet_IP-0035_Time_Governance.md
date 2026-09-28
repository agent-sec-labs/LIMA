# LIMA Implementation Packet — IP-0035 Time Governance（#234 / #57 PR3-d-real 时间治理加固子叶，零真实调用）

- Packet ID：IP-0035；版本 v1.0（2026-09-28）。
- Coordinator Assignment：CA-IP-0035-v1.0（2026-09-28；Intent Record `.pv_tmp/INTENT_RECORD_IP-0035_2026-09-28.md` 的 M1-M14/F1-F8/N1-N7/S1-S5/I-1 与主会话裁定点 A-H 由其 R1-R12 裁定；R1-R12 转录见 §15）。
- Source Issue：#234（open；parent #57 保持 open；正文 Scope 1-6 / Non-goals / AC-1..4 由 Coordinator 经 GitHub API 亲取，范围以 CA-IP-0035-v1.0 §Authoritative Inputs #2 为权威转录——本 P&V 会话除 §8 I-1 节声明的 DeepSeek 官方文档只读外零网络，未直取远程正文，远程再核验归主会话派发前完成）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-28 第二轮长程授权；**本 Assignment 授权的交付物=离线修复 PR，P&V 与 Implementation 全程零真实模型调用、零网络下载、零付费、零远端写**；唯一允许的网络读取=本 Packet §8 I-1 节的 DeepSeek 官方文档只读分析）。
- Base SHA（完整 40 位）：`d59c135b69c4a30a3178c93459d47e49d518f922`（= origin/main = 本地 main；IP-0034 merge PR #233 ∈ HEAD；tracked 面干净，本 P&V 会话亲验）。
- 基线产物指纹（`git ls-tree d59c135b...` 本 P&V 会话亲验，与 CA §Exact Baseline 逐字一致）：tests v4' blob `6f8fe8624da26a56969ec52c3ca191100e74d39a`；real_run.py blob `200836cc7e11b8f5ac69fc51d7dbaa4a7419b12f`；budget.py blob `6c783848e00f55e05d221e3ab89fb32310d583b9`；orchestrate.py blob `8655067e180ffafc2ee2e8b0ca93c5531201e344`；Dockerfile blob `947514a52923eed1e73fbb2fc543361d8c3e938f`。
- 本 Packet 的角色：Implementation（阶段 C3+）的唯一实现依据；冻结验收测试 v5（§9/§10）的唯一语义来源；ER 复核与 P&V 独立验证的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）与 Dockerfile 恰 1 行 COPY 是 P&V 的 C1 交付物；`tests/test_v4_baseline_real_run.py` 冻结版本 v5 是 P&V 的 C2 交付物；`benchmarks/v4/baseline/real_run.py` 的时间治理/取消证据/冷热诚实面/指标分离实现是 **Implementation 的 C3+ 交付物**。边界不得互换：Implementation 不得修改本 Packet 与测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令（本 Assignment 范围内）**：本 IP 离线交付全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作。全部验收以离线注入（fake transport + 注入 clock）证明。`_urllib_transport` 的真实 socket 行为无法离线验证（绝对禁令），以内部有界读取辅助函数的离线单测语义 + 注入面负例共同承载（§7.3 实施面③、§17 G2）。
3. 预算语义只紧不松：deadline/取消是执行面治理，不是门禁放松；`budget.py`（IP-0031 冻结面）零字节改动；`orchestrate.py` 零字节改动；canary 清单五项键名、判定式与 latch 触发零改动；`REAL_RUN_GATE_UNLOCKED=False` 锁面不触碰。
4. 取消/截止的证据保留绝对优先于中止（R3.2-⑤/R4）：证据写出阶段越限只记录观测，全部证据无条件写完；取消路径写部分证据集后无条件重抛原 BaseException。

## 1. 需求映射（Packet 头）

```text
Source Issue：#234（open；Scope 1-6 / Non-goals / AC-1..4，经 CA-IP-0035-v1.0 转录）
Issue specification revision：2026-09-28 创建版正文（Scope 1-6 / AC-1..4；Scope 2 明文"十码目录处置由 Coordinator 裁定"=P6 授权）
Covered requirements：FR-01、FR-02、FR-03、FR-04、FR-05、FR-06、AC-1、AC-2、AC-3、AC-4
Not covered requirements：任何真实调用/下载/付费；新批准工件；PR3-e archetype fixture；#223 重新关闭；#57 关闭或 PR3 勾选；九类矩阵升级；thinking/请求形状/身份三形态/SF-01 变更；mode 标签语义变更；budget.py/orchestrate.py/其余七模块/九冻结测试文件；历史文档；2026-09-28 批数据重算；canary/预算放松；锁面触碰
Delivery role：hardening（执行中截止 + 取消一等公民 + 诚实观测面 + 指标分离；全部 additive）
Issue closure impact：PARTIAL（IP-0035 完成 ≠ #234/#57 完成 ≠ 真实批次完成）
Upstream IP/PR/merge commits：IP-0032（PR #224 merge 45a7ec7）；IP-0033（PR #227 merge 71e7fb1）；IP-0034（PR #233 merge d59c135）；基线 d59c135
```

FR-01..FR-06 为 #234 "Scope (this slice)" 1-6 的规范化编号（语义不变，CA-IP-0035 §Goal and Scope）。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | 单次尝试真实可执行 wall 截止与终止：下载/解包/请求/落盘四阶段执行中截止（非仅调用前预检+事后入账）；批次截止执行中语义 | §7.3 | v5 tg1/tg2/tg3/tg5/tg6（AC-1） |
| FR-02 | 取消/截止一等公民：失败 taxonomy、部分资源记账、预留释放、证据集完整保留（含 BaseException 重抛路径的部分证据集） | §7.2/§7.4 | v5 tg3/tg4 + e1 演进（AC-2） |
| FR-03 | cold/warm 可操作定义：本地状态重置/复用逐项记录（state_reuse）；提供方缓存不可控时的诚实观测（provider_cache）与结论限定规则；不凭 mode 宣称冷启动 | §7.5/§8 | v5 ho1/ho2/ho4 + Packet 规则面（AC-3） |
| FR-04 | 指标分离：API 延迟/尝试 wall/批次 wall/下载解包时间分开记录；统计只用同名测量值；latency_ms 语义不变 | §7.6 | v5 ho3/tg7（AC-1/AC-4 面） |
| FR-05 | 冻结测试面 v4'→v5 受控演进（六条件程序） | §9/§10 | v5 全文件（AC-4） |
| FR-06 | 兼容与回归：十码/11 检查点/canary 五项/D1-D6/请求形状/估计策略/298 方法零改动/additive-only/budget.py+orchestrate.py 零字节 | §7.1/§7.7 | Done Commands 2/3/6/7 + ho5（AC-4） |
| AC-1 | 可执行截止：注入慢流/慢解包/慢响应下截止点到达即中止；部分产物清理与 typed 失败留痕 | §7.2/§7.3 | tg1/tg2/tg3 |
| AC-2 | 取消与截止后证据完整：taxonomy + 部分记账 + 预留释放（D7/D8 对账）+ 证据集写出 | §7.2/§7.3/§7.4 | tg3/tg4（+dec/ro 演进共存断言） |
| AC-3 | cold/warm 诚实面：观测键在场、结论限定规则生效、"cold 标签+缓存命中"可判伪；I-1 DR 如约产出 | §7.5/§8 | ho1/ho2/ho4 + §8 DR-IP-0035-01 |
| AC-4 | 冻结面兼容：v4'→v5 六条件零弱化；九文件 298 与 budget/orchestrate blob 不变；全离线 | §10/§12 | Done Commands 2/3/6/7 + ho5 |

**Not-covered（全团队不得扩张；= CA §Not covered 1-7 全文）**：任何真实模型调用/网络下载/付费动作（含分支上/CI 内/pre-merge）；任何新批准工件（本轮零真实调用）。PR3-e archetype fixture；#223 重新关闭（修复合并+post-merge+独立复核后另行 v3 审计）；#57 关闭或 PR3 整体勾选；九类 archetype 矩阵升级。thinking/请求形状（含 `{"thinking":{"type":"disabled"}}`、response_format、max_tokens=8000、请求体 ≤100000 UTF-8 字节）/身份三形态/SF-01 谓词与 token 语法语义变更；mode 标签语义（0-4 cold/5-9 warm，orchestrate 冻结面）变更。budget.py 任何字节（IP-0031 冻结面）；orchestrate.py 任何字节（含 run_repeats/run_baseline_attempt 的取消重抛与 per-attempt 结果写出语义）；其余七模块与九个其余冻结测试文件；历史文档（IP-0032/0033/0034 Packet、两份批准工件、CANARY_DECISION_PACK）文本修改。2026-09-28 批数据重算或"修正"（保留原口径，M8）；旧样本追认性补证；全仓扫描结论外推。canary 清单五项键名/判定式/latch 触发变更；预算语义放松；`REAL_RUN_GATE_UNLOCKED`/`require_real_run_unlock` 锁面触碰。`lima/**`、`evaluation_data/**`、`scripts/**`、`pyproject.toml`/`requirements.txt`/`.github/**`/前端/`docs/` 其余全部；不提交任何输出目录/密钥/run 产物。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0035-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0035_2026-09-28.md` | 范围权威；R1-R12 全文转录见 §15 |
| 2 | Intent Record INTENT-IP-0035-20260928-v1 | `.pv_tmp/INTENT_RECORD_IP-0035_2026-09-28.md` | M1-M14 授权语义；F1-F8 决定性事实（F1 wall 缺口全子项/F2 cold-warm 现状与 prompt_cache 键零出现/F6 两级 taxonomy 先例/F7 端到端 wall 无键物证）；N1-N7 推断（N1 注入 clock/N7 提供方缓存预判——本 Packet §8 以官方文档亲读证实）；S1-S5 建议（S1 取消复用 TRANSPORT_FAILED 被 R2.2 否决） |
| 3 | Maintainer 授权原文（逐字摘录） | Intent Record 第 2 节（本轮授权边界 + 阶段 B.1-B.4） | §7.3/§7.4/§7.5/§7.6 的授权依据；B.1 句 2 = 证据写出时序面演进依据（§5.6） |
| 4 | Source Issue #234 正文 | CA §Authoritative Inputs #2（Coordinator GitHub API 亲取；本 P&V 零网络） | Scope 1-6/Non-goals/AC-1..4（经 CA 规范化为 FR-01..06） |
| 5 | #223 Reopen Record（issuecomment-5864867664） | 经 CA 头部与 §Goal 引用（#223 REOPENED-SCOPE2-WALL-ENFORCEMENT；本叶=其恢复计划）；本 P&V 会话零网络未直取 | FR-01/FR-02 的恢复计划语境（wall 执行缺口即其重开根因）；以 CA 转录为权威 |
| 6 | #232 补充记录（issuecomment-5864871240） | 经 CA 头部引用（#232 closed completed；两点诚实限定被 M4-M8 回应）；本 P&V 会话零网络未直取 | FR-03/FR-04 的上游语境；以 CA 转录为权威 |
| 7 | IP-0034 Packet | `docs/LIMA_Implementation_Packet_IP-0034_Identity_SF01.md`（@d59c135b） | 结构先例与现行冻结契约：§7.1 不变面、§7.8 additive 兼容判据、§10 六条件演进程序、§12/§14 |
| 8 | 现行产品 | `benchmarks/v4/baseline/real_run.py` @d59c135b（blob 200836cc，1853 行全文亲读） | 演进对象：下载循环 L1276-1286、解包循环 L1360-1374、chat L1424-1443、结算 D1-D6 L1186-1225、manifest L1645-1709、入口/证据写出 L1712-1853、`_urllib_transport` L909-936、`_chat` 的 `time.monotonic` 直读 L1425/L1431/L1442 |
| 9 | 冻结测试 v4' | `tests/test_v4_baseline_real_run.py` @d59c135b（blob 6f8fe862，54 方法全文亲读） | 演进基础（§9/§10）：a1 静态守卫、rd1 `_ATTEMPT_DOC_KEYS`、e1 证据时序、dec 系 D1-D4、ro 系资源观测 |
| 10 | budget.py（只读禁区） | blob 6c783848；reserve L380-500、record_usage L502、record_failure L538（docstring："Failure **or cancellation**: release the reservation, keep the spent"）、`_settle` L583（无 pending 安全不抛）本 P&V 亲读 | D7/D8 结算组合的原语语义依据；零字节改动 |
| 11 | orchestrate.py + run.py（只读禁区） | orchestrate blob 8655067e run_repeats L220-305（BaseException 体=持久化该 attempt 后重抛，无 aggregate/无 summary）；run.py run_baseline_attempt L226-（BaseException 分类、持久化、原样重抛）本 P&V 亲读 | 取消证据唯一落点=real_run.py 侧；run-N 文件计数断言依据（tg4） |
| 12 | Dockerfile | @d59c135b L55-63（blob 947514a5）亲读 | C1 +1 行落位依据（IP-0034 Packet 行=L62 后插入） |
| 13 | DeepSeek 官方文档（I-1 只读亲验） | `https://api-docs.deepseek.com/guides/kv_cache` 与 `https://api-docs.deepseek.com/quick_start/pricing`（2026-09-28 本 P&V 会话 WebFetch；本 IP 唯一获准网络读取） | §8 提供方缓存可控性技术分析；R5.2 观测键语义与价格钉 basis 佐证 |
| 14 | 下游兼容亲验（CA 输入 #11） | report.py/collect.py 零处消费 manifest.failures/error_code | R2.2 error_code=None 的兼容性依据 |
| 15 | 预冻结基线绿（C0，本 P&V 会话亲跑） | `.pv_tmp/RED_IP-0035_2026-09-28/baseline.txt` | v4' 54/54；九冻结文件 298/298；全量 discover 2638 OK（skipped=24）——与 CA 参照值逐项一致 |

哈希真值来源：`git ls-tree d59c135b69c4a30a3178c93459d47e49d518f922 -- <paths>`（本 P&V 会话程序化复核，与 CA §Exact Baseline 一致）。

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | 新增 wire 错误码（如 EXECUTION_TIMEOUT_CODE）或拆分 11 检查点/新增 field_path 新值承载截止族 | R2.1 裁定：十码目录与 11 检查点零触碰，failure_code 自由串通道 + 既有结构路径按相位取值承载可判别性 |
| 2 | EXECUTION_CANCELLED 复用 `REAL_RUN_TRANSPORT_FAILED`（Intent S1 倾向） | R2.2 否决：操作者/控制流中断不是任何十码成员如实描述的 wire 门失败；强行映射造成 taxonomy 诚实性回退（#223 恢复计划核心） |
| 3 | 修改 budget.py/orchestrate.py/run.py 承载截止/取消/部分记账 | #234 AC-4 明文 + R1/Stop 2：截止用循环检查与产品内 deadline 传输实现，不改账本原语 |
| 4 | 改变 prompt（前缀扰动/注入 nonce）以强制提供方冷缓存 | 授权 B.2 句 4 明文禁止"通过改变 prompt 偷换输入"；M6；§8 结论的正面触发条件 |
| 5 | mode 标签语义变更（如按缓存命中重定义 cold/warm） | R5.3：0-4 cold/5-9 warm 为 orchestrate 冻结面；证据面以 state_reuse/provider_cache 如实区分 |
| 6 | provider_cache 键进 CallUsage/预算门/结算/canary | R5.2：只作观测面，永不进预算门；六字段 usage 视图逐字不动 |
| 7 | 真实 sleep/真实网络/真实付费请求验证超时 | M3/N1：负例全部注入式（clock 缝注入）；Stop 1/9 绝对禁令 |
| 8 | 吞噬、转换或延迟重抛 BaseException；证据写出阶段丢弃证据 | R4.3/R3.2-⑤/Stop 12：原异常无条件重抛；证据无条件写完 |
| 9 | 2026-09-28 批数据按新口径重算或"修正" | M8/授权边界第 3 条：原始真实运行目录只读；Packet 仅记载口径分离（§7.6.4） |
| 10 | 第 4 个变更文件、新测试文件、Dockerfile 超 1 行、历史文档修改 | R1：Allowed Files 终形=恰 1 Add + 3 Modify；历史文档冲突处置沿用 IP-0033 §5.6 先例（§5.6） |
| 11 | 放松 canary/预算门禁、触碰 `REAL_RUN_GATE_UNLOCKED`/`require_real_run_unlock` | CA Not-covered 6；test_v4_baseline_budget 钉扎面 |
| 12 | 以 transport 注入契约偏离 4 参（加 deadline 参数）传递截止 | R3.2-③：契约 4 参 `(url, payload, headers, timeout)` 冻结不变；截止经 timeout 钳制 + 内部累计复核承载 |

## 4. Goal / Non-goals

**Goal**：在 IP-0034 身份/SF-01 版产品上完成四件一体的离线时间治理加固——① 单次尝试 wall 上限从"调用前预检 + 事后入账"升级为执行中截止与终止（下载逐块/解包逐块/chat 传输内部流式累计/chat 后复核/证据写出阶段单点判定五实施面；deadline=min(per_run.wall_ms, batch 余量)，monotonic 锚 attempt 起点）；② 取消/截止成为有 taxonomy（EXECUTION_TIMEOUT 族复用 REAL_RUN_TRANSPORT_FAILED+相位 field_path；EXECUTION_CANCELLED 走 failure_code 通道且 error_code=None）、有部分资源记账（D7/D8：release-only + attempt-0 局部观测）、证据集完整保留（正常全集 ∪ 取消部分集五件套）的一等公民；③ cold/warm 从按序号标签升级为可操作定义（state_reuse 四键 + provider_cache 两键合规读取 + 结论限定规则 + I-1 提供方缓存可控性分析与 DR）；④ API 延迟/尝试 wall/批次 wall/下载解包时间分离记录（timings 四键 + manifest batch_wall_ms + deadline 观测块）且统计只用同名测量值。全部以离线注入负例证明（注入 clock，零真实 sleep）；IP-0032/0033/0034 冻结契约零回退；budget.py 与 orchestrate.py 零字节。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。真实批次执行不在本 Assignment 授权内（本轮零真实调用，无批次可批准）。

## 5. 文件边界（CA R1：恰 1 Add + 3 Modify；零 Delete；单 PR）

### 5.1 Files to Add

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0035_Time_Governance.md` | P&V（C1，本文件） | 本 Packet；v5 冻结测试 a1 演进断言其在库存在；承载 §8 I-1 技术分析与 DR-IP-0035-01 草案 |

### 5.2 Files Allowed to Modify（恰 3；每文件一次性行为见 §10 演进条件）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0035_Time_Governance.md ./docs/`（插 IP-0034 Packet 行【L62】后）；既有行零改动。基线 blob `947514a52923eed1e73fbb2fc543361d8c3e938f` |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v4'→v5；**唯一冻结面演进授权，程序见 §10**） | 仅此一文件、一次性；方法预算 ≤66（定稿 66：54 演进保留 + 12 新增，§9）；RED 证据先于冻结落盘；v4' blob `6f8fe8624da26a56969ec52c3ca191100e74d39a` 永久在链 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3+） | R2-R6 全部实现面（§7.2-§7.6）；§7.1 不变面逐条保持；唯一获准新 import=`os`（唯一用途 `os.getpid()`，R5.1） |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/budget.py`（IP-0031 冻结面；record_failure docstring 明文覆盖 cancellation；`_settle` 无 pending 安全）；`orchestrate.py`/`run.py`/`report.py`/`collect.py`/`fixtures.py`/`expert_timing.py`/`offline_flow.py`；IP-0032/0033/0034 Packet、两份批准工件（2026-09-27/2026-09-28）、CANARY_DECISION_PACK；`D:\BaseAIProject\LIMA-real-runs\**`（上批证据，只读）；`evaluation_data/**`；`.pv_tmp/` 各记录。

### 5.4 Files Forbidden（diff 必空；Done Command 7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余七模块（collect/expert_timing/fixtures/offline_flow/orchestrate/report/run）与各级 `__init__.py`、`budget.py`；`tests/` 其余九个 v4 冻结测试文件（298 方法）；`evaluation_data/**`；`lima/**`；`scripts/**`；`docs/` 其余全部（含历史 Packet、两份批准工件、决策包）；`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`/前端；不提交任何输出目录/密钥/run 产物。

### 5.5 提交链拓扑（CA R8；冻结）

C1 = 本 Packet + Dockerfile 恰 1 行（1 Add + 1 Modify，同一提交，前缀 `[IP-0035][PV]`）→ C2 = tests v5 冻结（1 Modify；提交信息**必须含** `"[IP-0035][PV] Freeze acceptance tests v5 (RED)"` 字样）→ C3 = real_run.py（1 Modify，前缀 `[IP-0035][IMPL]`）→ C-final 之后允许且仅允许修复提交（前缀 `[IP-0035][CI]` 或所属角色前缀），每次必须引用 Stop/DR 编号或 ALLOWED_ONCE 记录。单 PR（`codex/ip-0035-time-governance` → main）；实现提交必须以 C2 冻结提交为祖先（Done Command 8）。

### 5.6 与其他活动 IP 的冲突分析（冻结面演进依据登记）

无并行活动 IP 占用本切片路径（IP-0035 编号未占用，Intent F8）。**冻结面演进依据显式登记（IP-0033/IP-0034 Packet §5.6 先例）= 2026-09-28 第二轮 Maintainer 授权（Intent Record 第 2 节，阶段 B.1-B.3）**，演进对象：① IP-0032 Packet §7.9/IP-0034 Packet §7.8 的 attempt 文档键集（12 键 → 12 + 3 个 additive 观测子块，R5/R6）；② manifest 键集（additive `batch_wall_ms` + `deadline` 观测块，R6.2/R6.3）；③ `failure_code` 自由串通道值域（+`EXECUTION_CANCELLED`；EXECUTION_TIMEOUT 已在场）与 `outcome` 值域（+`"cancelled"`，R2.2）；④ 证据写出时序（"严格在 run_repeats 返回后"演进为"正常返回后全集 ∪ BaseException 重抛时部分集"，授权 B.1 句 2，R4.4）；⑤ import 白名单（+`os`，唯一用途 getpid，R5.1）；⑥ 差异表（+D7/D8 两行，R3.3/R4.1）；⑦ 测试面 v4'→v5（§10 六条件）。历史文档零改动；本节即唯一演进依据登记处。IP-0024..0034 一切其余冻结面禁止触碰。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖。产品 real_run.py 唯一获准新 stdlib import=`os`（唯一用途 `os.getpid()`，值仅以摘要 token 持久化，R5.1；除此外零新增 import）。测试文件**零新增 import**（IP-0034 Packet §6 先例；演进只新增常量/辅助类/两新类十二方法，全部以既有 import 实现；process_identity 断言用形式+不变性而非重算 pid，见 §16 DR-IP-0035-PV-2）。
- **网络**：测试全离线、注入 fake transport、永不触网（既有 `_forbidden_network_roots` 断言保持）。**本 IP 离线交付期间任何真实网络/下载/付费调用 = Stop Condition 1（绝对禁令）**；唯一例外=本 Packet 制作阶段的 §8 I-1 DeepSeek 官方文档只读（WebFetch，已完成并落档于本 Packet，此后零网络）。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（离线测试写 tempdir）；库内除 §5.1/§5.2 四文件外零写入；不读环境变量/配置/.env（h1 钉扎面保持；`os` 仅用于 getpid，不得引入 `os.environ` 等读取面）。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行；零远端写（不 push、不开 PR、不关 Issue、不改 Ledger 远端状态——合并/推送/评论由主会话按 Maintainer 授权另行核发，R8）。
- **凭据**：api_key 仍为显式必填参数，永不落盘/入日志/入错误消息/入证据（e2/rd5/a3 探针面保持）。
- **clock**：产品 monotonic 时源收敛为单一模块级内部缝 `_monotonic`（§7.3.4）；测试以确定性注入 clock 替换驱动全部负例，零真实 sleep、零公共签名变化、零环境读取。

## 7. real_run.py 冻结契约细化（CA R2-R6；Packet 定稿）

### 7.1 不变面（违例即验收失败；IP-0032/0033/0034 冻结面保持）

`__all__` 六符号逐字；`run_real_baseline_suite` 签名/参数序/kwonly/默认值；transport 注入契约 4 参 `(url, payload, headers, timeout)`；`RealRunErrorCode` 十成员与 `_STABLE_MESSAGES` 逐字（**零新增错误码**）；11 检查点枚举值与 field_path 映射（"checkpoint never splits"）；`_CHECKPOINT_FIELD_PATHS`/`_RESPONSE_META_KEYS` 九键；SF-01 全套谓词与 token 语法（`_EXPECTED_RESPONSE_KEYS`/`_EXPECTED_FINISH_REASONS`/`_FINGERPRINT_PATTERN`/`_digest_token`/`_bounded_*`）；身份三形态并集构造与 `_MODEL_SERVED_FORMS_PIN`；请求形状（含 thinking/response_format/max_tokens=8000/请求体 ≤100000 UTF-8 字节/temperature 0/双消息）；总执行序 ①-⑨（顺序与语义，证据写出时序的演进面见 §5.6-④）；`RealSuiteResult` 字段全集（含 `real_run: True`）；evaluator payload（real-world v2）；六字段 usage 视图（`_usage_document` 逐字）；D1-D6 结算行与 `_settle` 既有语义；CallEstimate 估计策略（attempt-0 最坏值/attempts 1-9 body 派生；wall 估计 `_WALL_ESTIMATE_MS=1,200,000` 不变）；`_worst_case_cost` 公式；价格钉 300000/1200000；工件 loader 全部钉与校验（本叶零工件变更）；canary 清单五项键名/判定式/latch 触发；模块 hygiene（零环境/配置/.env 读取、api_key 永不落盘/入错、`REAL_RUN_GATE_UNLOCKED=False` 锁面不触碰）；既有入口 `timeout_seconds*1000 > per_run.wall_ms` 预检（L1764-1772）保留不动。budget.py（blob 6c783848）与 orchestrate.py（blob 8655067e）**零字节**；IP-0024..0034 其余冻结面零回退。

### 7.2 错误族处置（FR-01/FR-02；CA R2 终局裁定）

十码目录与 11 检查点零触碰——`failure_code` 自由串通道承载新 taxonomy。截止/取消族完整裁定表（冻结）：

| 场景 | failure_code | error_code | error_field_path | record.outcome | 结算 |
| --- | --- | --- | --- | --- | --- |
| deadline 越限 @ 下载分块循环 | `EXECUTION_TIMEOUT` | `REAL_RUN_TRANSPORT_FAILED` | `$.download` | `"timeout"` | D7（§7.3.3） |
| deadline 越限 @ 解包成员/分块循环 | `EXECUTION_TIMEOUT` | `REAL_RUN_TRANSPORT_FAILED` | `$.archive` | `"timeout"` | D7 |
| deadline 越限 @ chat 传输（产品默认传输内部累计截止） | `EXECUTION_TIMEOUT` | `REAL_RUN_TRANSPORT_FAILED` | `$.transport` | `"timeout"` | D7 |
| deadline 越限 @ chat 返回后复核 | `EXECUTION_TIMEOUT` | `REAL_RUN_TRANSPORT_FAILED` | `$.transport` | `"timeout"` | D7（**永不 success、永不 record_usage**） |
| batch 余量 ≤0 于 attempt 起点（零传输调用，与 reserve 预检"invoke 前拒绝"同构） | `EXECUTION_TIMEOUT` | `REAL_RUN_TRANSPORT_FAILED` | `$.transport` | `"timeout"` | D7（防御分支；离线不可达性见 §17 G3） |
| 既有 socket TimeoutError（下载 L1288-1294/chat L1432-1438 路径，形态不变） | `EXECUTION_TIMEOUT` | `REAL_RUN_TRANSPORT_FAILED` | `$.transport`（既有值不动） | `"timeout"` | D7 族统一（见下） |
| 取消（run_repeats 重抛的 BaseException 经 §7.4 catch） | `EXECUTION_CANCELLED` | `None` | `None` | `"cancelled"`（新增 additive outcome 值；success/failure/timeout 既有值不动） | D8（§7.4） |

- **EXECUTION_TIMEOUT 族结算统一为 D7**（R3.3 的族定义覆盖既有 TimeoutError 分支与新 deadline 分支）：`record_failure(run_id, 部分观测载体)`——attempt-0 载体携带已实测 `wall_ms`（=record.latency_ms，未测则为缺省）/`download_bytes`/`storage_bytes`，其余 attempt 传 None；不走 record_usage（无合规 usage 可言）。这使 attempt-0 的 socket-TimeoutError 从"无载体释放"升级为"携带局部观测释放"——additive 诚实性改进，无既有断言回退（v4' 无该数值钉扎；本 Packet 登记为 (b) 类语义更新，驱动=R3.3）。
- **EXECUTION_CANCELLED**：`error_code=None` 且 `error_field_path=None`（否决 S1 复用建议——下游兼容已亲验：report/collect 零消费 failures.error_code；manifest.failures 条目保持 4 键形状 `attempt_index/failure_code/error_code/error_field_path`，null 值不破坏任何读取方）。
- 若实现中发现上述可判别性不足而需演进十码族 → Stop Condition 3 + Decision Request，不得自行加码。

### 7.3 deadline 机制（FR-01；CA R3 终形）

1. **截止点定义（冻结）**：`attempt deadline = min(per_run.wall_ms, batch wall 余量)`；batch wall 余量 = `batch.wall_ms − batch consumed wall_ms`（attempt 开始时点账本读数；settled 尝试的实测 wall 已入 consumed，pending 在 attempt 边界为零）；以 **attempt 开始锚定**的 monotonic clock 度量（每 attempt 重新锚定）。余量 ≤0 → 立即 typed 截止失败（零传输调用）。既有入口预检（§7.1）保留不动。
2. **五实施面（冻结语义，具体构造由 Implementation 定）**：
   - ① **下载分块循环逐块检查**：越限 → 清理部分文件（destination 删除，与字节上限分支同构）+ §7.2 typed 失败（`$.download`）；
   - ② **解包成员/分块循环逐块检查**：越限 → §7.2 typed 失败（`$.archive`）；
   - ③ **chat 传输**：注入契约 4 参冻结不变——guard 调用前将 timeout 参数计算为 `max(1, min(timeout_seconds, ceil(剩余截止秒)))`（剩余不足 1s 时传 1 并由 ④ 复核兜底）；产品默认 `_urllib_transport` 内部改为 deadline-aware：POST 路径由单次 `response.read()` 改为流式 read 循环 + 累计 clock 的 per-call 截止（GET 下载流同理已由 ① 外层逐块检查覆盖）——**必须以模块内可离线测试的内部形态实现**（作用于任意 file-like/字节累计 + clock 的有界读取辅助函数，`_urllib_transport` 消费之）；冻结测试对注入 fake 不依赖 socket；模块内新私有 wrapper 仅用于产品默认路径为允许形态；
   - ④ **chat 返回后 deadline 复核**：越限 → §7.2 typed 失败（`$.transport`），**永不 success、永不 record_usage**（响应即使合规也不入账）；
   - ⑤ **证据写出阶段**：batch deadline 延续检查，**唯一权威判定点 = manifest 构造时**（attempts 写出后、manifest 序列化前）；越限 → additive manifest 观测（§7.6.3），**全部剩余证据写出无条件完成**（证据保留绝对优先于中止——与 AC-2 取消证据完整同哲学；此时批次已零后续调用，fail-closed 面在调用侧已闭合）。
3. **D7（差异表新行；EXECUTION_TIMEOUT 族）**：release-only——`record_failure(run_id, 部分观测载体)`；attempt-0 载体携带已实测 `wall_ms`/`download_bytes`/`storage_bytes`（D2 局部观测先例延伸到时间族，`_partial_usage` 形态先例），其余 attempt 传 None。纯 real_run.py 侧既有三态原语组合，budget.py 零改动。既有 D1-D6 行零变化（§10 条件 3：dec 系 D8 演进断言不破坏 D1-D6）。
4. **clock 可测缝（冻结）**：模块 monotonic 时源收敛为**单一模块级内部缝 `_monotonic`**（callable，无参，返回 float 秒；初始绑定 `time.monotonic`；模块内一切 wall/deadline/latency/attempt-wall 测量一律经此缝读取，不再直读 `time.monotonic`）。冻结测试以确定性注入 clock 替换该属性驱动全部负例（N1），零真实 sleep、零公共签名变化、零环境读取。BudgetLedger 自身的 `now_ns` 时钟不受此缝影响（禁区原语，测试 g4 面保持独立注入）。

### 7.4 取消路径（FR-02；CA R4 终形）

`run_real_baseline_suite` 在 `run_repeats` 调用点外层 `except BaseException`：

1. **结算（冻结）**：对**恰好尾部未结算 attempt**（`guarded.records` 中 outcome is None 的末位记录——含 reserve 前中断的形态）执行 `record_failure(run_id, attempt-0 局部观测载体或 None)` 释放预留（budget.record_failure docstring 明文覆盖 cancellation；`_settle` 对无 pending 的 run_id 安全不抛）。已结算 attempt（outcome 已置）不二次结算（幂等闸 = outcome 判定）。该 attempt 记录置 `outcome="cancelled"`、`failure_code="EXECUTION_CANCELLED"`、`error_code=None`、`error_field_path=None`。登记差异表新行 **D8（EXECUTION_CANCELLED：释放 + attempt-0 局部观测保留，永不 usage）**。预留**不得保持占用**（保持占用会使部分账本虚增 in-flight，违反 M2）。
2. **部分证据集（冻结）**：写出 approval/ledger/machine_profile/attempts/manifest——与正常路径**同源同序**（exclusive 写出纪律不变；`_write_exclusive`）；`manifest.failures` 含 `EXECUTION_CANCELLED` 条目（§7.2 形态）；`attempt_count=len(guarded.records)`；`batch_wall_ms` 按 §7.6.2 写出（catch 点实测 elapsed）；`cold_count/warm_count` 保持冻结常量值 5/5（语义=工件声明的 attempt policy 形状；实际执行数由 attempt_count 承载——cancelled 批次 attempt_count < cold+warm 即不完整信号 + aggregate/report 缺席即诚实标记，Packet 显式记载）；`deadline` 观测块按 §7.6.3。**aggregate/report 如实缺席**（orchestrate 重抛先于 aggregate 写出——禁区语义不可也不需绕过）；`RealSuiteResult` 不返回（取消路径 re-raise，字段全集不变）。
3. **重抛（冻结）**：原 BaseException 无条件 re-raise（绝不吞）；证据写出的次生异常链式记录但原异常优先；正常 `RealRunError`/`BudgetGateError` 路径不经此 catch（run_repeats 已将 Exception 体转为保留样本继续跑）。
4. **证据写出时序面演进登记**：既有冻结语义"证据文件严格在 run_repeats 返回后写出"演进为"run_repeats 正常返回后（全集）**或**控制流 BaseException 重抛时（部分集，本条）"——演进依据=2026-09-28 第二轮授权 B.1 句 2，登记于 §5.6-④。

### 7.5 cold/warm 诚实面（FR-03；CA R5 终形）

1. **attempt 文档 additive 观测子块 `state_reuse`**（键集冻结）：`{materialized: bool, snapshot_reused: bool, request_body_rebuilt: bool, process_identity: str}`——语义=该 attempt **实际**执行面：materialized=本 attempt 执行了物化；snapshot_reused=读取了已物化快照（反向）；request_body_rebuilt=重建了请求体。**对现行为的如实标注（非行为变更）**：当前实现 attempt-0 = (True, False, True)、attempts 1-9 = (False, True, False)（复用 `self._body_bytes`）；若实现顺带改变重置/复用策略，则以实际行为为准写入，键集语义不变。`process_identity` = 进程身份的摘要 token（**复用 `_digest_token` 形态** `~d:<len>:<sha256-hex64>`；源=`os.getpid()`，本 IP 唯一获准新 stdlib import，唯一用途 getpid，值仅以摘要形态持久化——原始 pid 数字串不得出现在任何证据面）；每 suite 捕获一次，跨 attempt 恒同——重启即改变，作为"未跨进程重启"的诚实标记。
2. **attempt 文档 additive 观测子块 `provider_cache`**（键集冻结）：`{prompt_cache_hit_tokens: int|null, prompt_cache_miss_tokens: int|null}`——来自响应 usage 块的**合规读取**（exact int 且 ≥0 才收录；缺失/非合规 → null，None 纪律，绝不伪造 0）；**只作观测面，永不进 CallUsage/预算门/结算/canary**。六字段 usage 视图逐字不动。语义与来源见 §8（DeepSeek 官方文档：两键为 usage 块的输入缓存命中/未命中 token 计数）。
3. **mode 标签语义不改**（0-4 cold/5-9 warm 为 orchestrate 冻结面）；证据面以 state_reuse/provider_cache 如实区分，不以 mode 冒充提供方冷启动。
4. **结论限定规则（Packet 承载的规范性契约，非 report.py 代码——report.py 为禁区文件）**：(a) 统计/报告/呈报层引用冷热观测只允许引用 `state_reuse`/`provider_cache` 同名键；(b) 任何"冷启动"表述必须满足 materialized=true 且如实披露提供方缓存不可控（或 miss 占比观测）；(c) 仅凭 mode 字段宣称冷启动=违规表述；(d) p50/p95 等统计的口径命名必须与测量键同名（配合 §7.6.4）。
5. **I-1 裁定执行**：见 §8——已证实不可控，DR-IP-0035-01 决议请求草案随本 Packet 附录产出（呈报 Maintainer，不阻塞本叶离线交付）。

### 7.6 指标分离（FR-04；CA R6 终形）

1. **attempt 文档 additive 观测子块 `timings`**（键集冻结）：`{api_latency_ms: int|null, attempt_wall_ms: int|null, download_ms: int|null, extract_ms: int|null}`——`api_latency_ms` 语义=与既有 `latency_ms` **同值同测**（API 调用延迟的指标名面；`latency_ms` 既有键语义与位置不变，两键恒等）；`attempt_wall_ms` = 该 attempt 端到端 monotonic 差（guard 入口锚 → 窗口闭合：成功/typed 失败/budget 拒绝均如实测量，int ≥0；取消时=catch 点实测 elapsed，如实部分值）；`download_ms`/`extract_ms` = 各相位实测耗时（int ≥0），仅 attempt-0 且该相位已执行时非 null（attempt>0 恒 null；执行中被截止中止=已实测的部分耗时 int；相位未执行=null——None 纪律，绝不伪造 0）。
2. **manifest additive 键 `batch_wall_ms`**（int ≥0）：`run_repeats` 调用点外层计时（real_run.py 侧，不触碰 orchestrate）；正常与取消部分集两态均写出（取消态=catch 点实测 elapsed）。
3. **manifest additive 观测块 `deadline`（本 Packet 定稿冻结）**：`{"batch_wall_exceeded": bool}`——证据写出阶段（§7.3.2-⑤ 唯一权威判定点=manifest 构造时）的 batch wall 判定结果：`(batch.wall_ms − book["reserved"]["wall_ms"] − book["consumed"]["wall_ms"]) <= 0`（与 canary `batch_margin_positive` 的 wall 维度判定式同构）。语义=纯观测，**不产生任何失败回注**；正常与取消两态均写出。
4. **统计纪律**：统计端（报告/聚合/呈报）只引用同名键；`latency_ms` 语义不变（N4）；**M8=2026-09-28 批数据保留原口径不重算**（无代码动作，本条即记载）。批数据物证（Intent F7）：latency_ms 1,156-2,094ms 为 API 延迟语义——本叶起端到端尝试 wall 与批次 wall 由 `timings.attempt_wall_ms`/`manifest.batch_wall_ms` 承载，新旧口径以键名区分，不得混称。

### 7.7 证据 schema 演进兼容判据（FR-06/AC-4）

- 键集 additive-only、无重命名/删除：attempt 文档 12 键 → 15 键（+`state_reuse`/`provider_cache`/`timings` 三子块）；manifest 键集 +`batch_wall_ms`+`deadline`；`failure_code` 值域 +`EXECUTION_CANCELLED`；`outcome` 值域 +`"cancelled"`；既有键值语义不变。
- **正常成功路径证据与 v4' 形态一致**（新子块为纯新增；标准响应下 provider_cache 可为 null——None 纪律）；旧读取方行为不变（report/collect 零消费已亲验；manifest.failures 4 键形状保持，null 值不破坏读取）。
- 九冻结面 298 方法零改动由 Done Command 7 blob 守护；budget.py/orchestrate.py 与其余七模块 blob 不变。

## 8. I-1 技术分析：提供方缓存可控性（FR-03/AC-3；R5.5）

**取证渠道与边界**：本 P&V 会话于 2026-09-28 以 WebFetch 只读亲验 DeepSeek 官方文档两页（本 IP 唯一获准网络读取，零请求零调用零付费）：`https://api-docs.deepseek.com/guides/kv_cache`（Context Caching on Disk）与 `https://api-docs.deepseek.com/quick_start/pricing`。

**官方文档事实（亲读）**：
1. Context caching **默认对所有用户启用、全自动服务端管理**——"enabled by default for all users, allowing them to benefit without needing to modify their code"；调用方无需（也无从）配置开启/关闭。
2. **无任何调用方侧 cache-bypass 控制面**：文档不存在强制 cache miss、禁用缓存或绕过缓存的 API 参数、请求头或控制面机制；唯一"间接控制"是缓存单元仅精确匹配前缀（"fully matches" 持久化前缀单元），且缓存是 best-effort（"does not guarantee a 100% cache hit rate"）。
3. 缓存命中/未命中计量：`prompt_cache_hit_tokens`（"The number of tokens in the input of this request that resulted in a cache hit"）与 `prompt_cache_miss_tokens`（"...did not result in a cache hit"）——位于响应 `usage` 块（R5.2 观测键的权威来源与命名依据）。
4. 缓存生命周期：构建以秒计；未用缓存"usually within a few hours to a few days"自动清理。
5. 定价分层（pricing 页亲读，deepseek-flash / DeepSeek-V4.1-Flash）：cache-hit 输入 peak $0.006/百万、cache-miss 输入 peak $0.30/百万、输出 peak $1.20/百万（off-peak 减半）——**与模块价格钉 300000/1200000 micro-USD（peak cache-miss basis）逐值吻合**；命中价为未命中价的 1/50，冷热口径对成本语义影响重大。

**结论（I-1 裁定执行）**：**不可控**。"同一 RunSpec（禁改 prompt）"与"强制提供方冷缓存"**不可同时成立**——唯一能强制 miss 的途径是改变请求前缀（破坏同一 RunSpec，授权 B.2 句 4 明文禁止），等待缓存自然清理（数小时至数日、无保证）不构成可执行的控制面。依 R5.5 产出 DR-IP-0035-01 决议请求草案（附录 §8.1），随 PR/最终呈报提交 Maintainer，**不阻塞本叶离线交付**；本叶的诚实观测面（state_reuse + provider_cache + §7.5.4 结论限定规则）即为不可控前提下的合规承载。

### 8.1 DR-IP-0035-01 决议请求草案（呈报 Maintainer；本叶不阻塞）

- **对象**：#234 Scope 3 / 授权 B.2——提供方缓存不可控时"cold/warm"语义的取舍。
- **依据**：§8 官方文档亲验（自动启用、无 bypass 控制面、命中价 1/50）；M5/M6；R5.5。
- **选项**：
  - (a) **维持本叶语义（推荐）**：cold/warm 仅指**本地状态**维度（state_reuse：attempt-0 物化/重建 vs 其余复用快照/请求体）；提供方侧冷热以 provider_cache 观测键如实记录（hit/miss 计数与占比），任何"冷启动"表述受 §7.5.4 (b) 限定（materialized=true + 披露不可控/miss 占比）。成本影响如实呈报（命中部分按 1/50 计价，账本按 peak cache-miss 上界预算不放松）。
  - (b) prompt 前缀扰动强制冷缓存——**已被授权原文否决**（"不通过改变 prompt 偷换输入"），列出仅为完整性。
  - (c) 批次间隔等待缓存自然清理（数小时至数日）再跑 warm/cold 对照——不可保证、引入时间与成本不确定性，且不改变"同一进程内无法强制"的事实；如需真实批次采用此路径须另行授权与工件。
  - (d) 放弃提供方冷热观测——与 AC-3 相悖，否决。
- **建议**：(a)；本叶已按 (a) 实现（观测面 + 结论限定规则），Maintainer 批准即闭合，无需代码变更。
- **影响面**：仅呈报/统计口径与未来真实批次的解读；零代码影响；预算钉与价格钉不动。

## 9. 测试矩阵 v5（`tests/test_v4_baseline_real_run.py`；定稿 66 方法 = 54 演进保留 + 12 新增；=≤66 预算上限）

组织：同文件演进（否决新文件），十四个既有类全部保留，新增恰两类（`TestTimeGovernance`/`TestHonestObservation`）。全离线、注入 fake transport + 注入 clock（模块缝 `_monotonic`，`patch_monotonic` 辅助含 sentinel 恢复，RED 态 setattr 不触发 arrange 错误）、零真实 sleep、零仓库写入、永不触网（既有基建 `_FakeTransport`/`_RawBodyTransport`/`_build_tarball`/`_fixed_sources` 复用，纯增量）。

### 9.1 新增方法（12 个，逐个登记断言面）

| 方法（新类.方法） | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| TestTimeGovernance.tg1 `test_slow_stream_download_deadline_aborts_cleans_and_types` | FR-01/AC-1/R3.2-① | 注入 clock（常量-跳跃缝）+ 无限 1MB 块流（第 2 块读取时跳 1,500,000ms > deadline 1,200,000）：下载循环逐块截止——chat_calls==0、download_calls==1；attempt-0 failure_code `EXECUTION_TIMEOUT`/error_code `REAL_RUN_TRANSPORT_FAILED`/error_field_path `$.download`/outcome `"timeout"`；部分文件清理（`_materialized` 下 `*.gz` 零残留）；D7 释放对账（reserved 全零、calls==1、consumed.download_bytes 为 [0, 已服务字节] 内 int）；timings None 纪律（api_latency_ms is None == latency_ms is None、attempt_wall_ms int ≥0）；后续 9 attempt `REAL_RUN_CANARY_FAILED`、status insufficient_sample |
| TestTimeGovernance.tg2 `test_slow_extraction_deadline_types_archive_phase` | FR-01/AC-1/R3.2-② | 步进 clock（每次读 +200,000ms）+ 8MB 单成员 tarball（gz ~1 块）：截止落在解包相位（下载相位耗 clock ≤3 次不越限）——chat_calls==0；attempt-0 `EXECUTION_TIMEOUT`/`REAL_RUN_TRANSPORT_FAILED`/`$.archive`/`"timeout"`；reserved 全零、calls==1；后续 canary 拒绝、insufficient_sample |
| TestTimeGovernance.tg3 `test_slow_response_deadline_recheck_never_success_settles_d7` | FR-01/FR-02/AC-1/AC-2/R3.2-④/R3.3 | 默认工件 + chat 传输内跳 2,000,000ms（deadline 1,200,000）：chat 后复核 typed 失败——chat_calls==1、`EXECUTION_TIMEOUT`/`REAL_RUN_TRANSPORT_FAILED`/`$.transport`/`"timeout"`、usage is None（永不 success/永不 record_usage）；D7 数值对账：consumed wall==2,000,000、download==len(happy tarball)、storage==期望和、prompt/completion/cost==0；released 逐维（prompt 100,000、completion 8,000、cost=entry0 cost、download=250M−len、storage=500M−exp、wall 无释放【实际>入账】）；reserved 全零；timings api==latency==2,000,000、attempt_wall ≥ api |
| TestTimeGovernance.tg4 `test_cancellation_writes_partial_evidence_set_and_releases` | FR-02/AC-2/R4（两 subTest） | (a) attempt-2 chat 抛 `KeyboardInterrupt`：原样重抛出 entry；部分证据集五件套在场（approval.json/ledger.json/machine_profile.json/attempts{恰 3 文件}/manifest.json）；manifest.failures==[{attempt_index:2, failure_code:`EXECUTION_CANCELLED`, error_code:None, error_field_path:None}]、attempt_count==3、cold/warm==5/5、batch_wall_ms int ≥0、deadline 块在场；attempt-02 文档 outcome `"cancelled"` 三元组形态；D8 对账：reserved 全零、calls==3（不回收）、consumed.prompt==2,000（前两次成功 usage）；aggregate/report 如实缺席（无 `*-report-*` 文件、run-N 序列最大==3）。(b) attempt-0 chat 抛 `KeyboardInterrupt`：D8 attempt-0 局部观测——consumed.download==len(happy)、storage==期望和、reserved 全零、calls==1、attempt_count==1、failures 单条 attempt_index==0 |
| TestTimeGovernance.tg5 `test_transport_timeout_clamped_to_remaining_deadline` | FR-01/R3.2-③（三 subTest） | 工件 per_run.wall=1,500,000、timeout_seconds=1,500；下载流读取时跳钟：(a) 跳 1,400,000 → 剩余 100,000ms → chat_timeouts[0]==`max(1, min(1500, ceil(100.0)))`==100、后续 attempt（锚点重置）==1500；(b) 跳 1,499,990 → 剩余 10ms → ==1（钳制 ≥1 兜底）；(c) 无跳 → ==1500（min 取 timeout_seconds 分支）。4 参契约不变的 timeout 通道传递可测面 |
| TestTimeGovernance.tg6 `test_batch_wall_margin_clamps_attempt_deadline` | FR-01/AC-1/R3.1（batch 余量参与） | 工件 per_run.wall=2,400,000、batch.wall=7,200,000、timeout_seconds=2,000；每次 chat 跳 1,500,000：attempt 0-3 deadline=per_run（余量 7,200,000→2,700,000 均 >2,400,000）→ timeout==2000、成功（consumed wall 累计 6,000,000）；attempt 4 起 余量==1,200,000 < per_run → deadline==1,200,000 → timeout==1200 且 chat 后复核越限 → 6 次 `EXECUTION_TIMEOUT`/`$.transport`；chat_timeouts==[2000]*4+[1200]*6；outcomes 4 success + 6 timeout；consumed.wall==6,000,000；calls==10 |
| TestTimeGovernance.tg7 `test_manifest_batch_wall_ms_and_deadline_observation` | FR-04/R6.2/R6.3/R3.2-⑤（两态） | 正常态：manifest 增键 `batch_wall_ms` int ≥0、`deadline`=={"batch_wall_exceeded": False}（12M 余量）；越限态：attempt-0 chat 跳 12,500,000 → D7 局部观测入账 consumed.wall==12,500,000 > batch 12,000,000 → canary margin 拒绝（后续 9 次 CANARY_FAILED、calls==1、reserved 全零）→ manifest `deadline.batch_wall_exceeded` is True、batch_wall_ms int ≥0（证据无条件写完） |
| TestHonestObservation.ho1 `test_state_reuse_annotation_and_process_identity` | FR-03/AC-3/R5.1/R5.3 | 全 10 成功 run：每 attempt `state_reuse` 键集==4 键；attempt-0 (materialized,snapshot_reused,request_body_rebuilt)==(True,False,True)、attempts 1-9==(False,True,False)（现行为如实标注）；process_identity 为 str、全批恒同、匹配 `_SF01_TOKEN_PATTERN`（`_digest_token` 形态）；mode 序列==["cold"]*5+["warm"]*5（mode 语义不变，R5.3） |
| TestHonestObservation.ho2 `test_provider_cache_observation_keys_and_null_discipline` | FR-03/AC-3/R5.2（三 subTest） | (a) usage 块带 hit=64/miss=936（exact int ≥0）→ 每 attempt `provider_cache`=={64, 936}；(b) 缺失 → {None, None}（None 纪律，绝不伪造 0）；(c) 非合规值（str/负数）→ null；账本隔离：consumed 键集==六账本维度（cache 两键永不在 consumed/reserved/released/calls 面）、usage 文档六字段视图不变、run 全成功（观测面零门禁影响） |
| TestHonestObservation.ho3 `test_timings_separation_and_none_discipline` | FR-04/AC-1/R6.1（两态） | 成功 run：每 attempt `timings` 键集==4 键；api_latency_ms==latency_ms（int 逐 attempt）；attempt_wall_ms ≥ api_latency_ms；attempt-0 download_ms/extract_ms int ≥0、attempts 1-9 双双 None。None 纪律态（cjk tarball → REQUEST_TOO_LARGE 于 chat 前）：attempt-0 api_latency_ms is None（==latency_ms）、attempt_wall_ms int ≥0、download_ms/extract_ms int ≥0（物化已完成） |
| TestHonestObservation.ho4 `test_cold_label_with_cache_hit_decidable_and_mode_unchanged` | FR-03/AC-3/R5.4（结论限定可测面） | usage 带 hit=64 全批：attempt-0 mode=="cold" 且 provider_cache.prompt_cache_hit_tokens==64 **同时**在场（"cold 标签+缓存命中"可判伪对——仅凭 mode 的冷启动宣称可被证据面证伪）；mode 序列 0-4/5-9 不变；每 attempt state_reuse 块在场（§7.5.4 (a) 同名键引用面的存在性） |
| TestHonestObservation.ho5 `test_frozen_taxonomy_checkpoints_and_canary_static_anchors` | FR-06/AC-4（静态不变锚） | `RealRunErrorCode` 成员值集==冻结十码（零新增）；`RealRunResponseCheckpoint` 11 值 + 模块 `_CHECKPOINT_FIELD_PATHS` 映射==冻结 dict；模块 `_CANARY_CHECK_KEYS`==冻结五键——时间治理演进后三面逐字保持（R2.1 前提锚）。RED 态按设计通过（既有能力） |

### 9.2 演进既有方法（54 全保留；hunk 归因见 §10 条件 2 登记）

| 方法/面 | 演进（additive 或登记的语义值更新） | 归因 |
| --- | --- | --- |
| 模块 docstring | 追加 v5 演进段（时间治理/取消证据/诚实观测/指标分离六条件演进说明） | FR-05 |
| 常量 `_ATTEMPT_DOC_KEYS` | 12 → 15 键（+state_reuse/provider_cache/timings）——rd1 的 attempt 键集断言随之演进 | FR-03/FR-04（R5/R6 additive 子块）【登记 (b) 类值更新】 |
| 新增常量/辅助（纯增量） | `_PACKET_IP0035_RELATIVE_PATH`/`_IP0035_PACKET_COPY_LINE`/`_STATE_REUSE_KEYS`/`_PROVIDER_CACHE_KEYS`/`_TIMINGS_KEYS`/冻结十码集合/`_JumpClock`（常量-跳跃缝）/`_SteppedClock`（步进缝）/`_SlowStream`（无限块流+跳钟）/`_JumpingTarballStream`（有限 tarball+跳钟）/基类 `patch_monotonic`（sentinel 恢复） | FR-01..FR-05 |
| a1 `test_artifact_in_repo_with_closed_field_set_and_container_copy_line` | 增量断言：IP-0035 Packet 在库 + Dockerfile 含 `_IP0035_PACKET_COPY_LINE`（C1 先落→冻结时按设计通过；既有断言全保留） | §5.1/FR-06 |
| e1 `test_evidence_written_after_run_repeats_window` | 注释性 hunk：登记 R4.4 时序面演进（正常路径全集断言不变；取消部分集由 tg4 钉扎）——零断言变更，RED 态保持绿 | FR-02（R4.4 登记） |
| dec1 `test_verdict_failure_with_usage_settles_and_retains_failure` | additive：attempt 文档 `timings`/`state_reuse` 子块与 D1 结算面共存（存在性断言，不钉值） | FR-02/FR-04（D8 不破坏 D1-D6） |
| ro1 `test_attempt0_failure_keeps_resources_and_request_observation` | additive：`timings`/`state_reuse` 与 `resources` 共存（存在性断言） | FR-04（R6 与资源观测并存） |
| ro2 `test_follow_on_failure_observation_and_release_reconciliation` | additive：失败 attempt（index>0）`timings` 子块在场（D5 面 + 新观测共存；既有对账数值零改动） | FR-02/FR-04 |
| 其余 47 方法（a2-a4、v1-v5、b1/b2'/b3…b4、d1-d5、u1-u4、c1-c3、g1-g4、e2-e4、h1-h3、rd1-rd6、dec2-dec4、ie1-ie3、sf1-sf4） | 断言面不变（rd1 经 `_ATTEMPT_DOC_KEYS` 常量更新自动演进——见上） | 基线回归锚：预算门/下载/解包/请求界/账本/hygiene/解耦/身份/SF-01 不受演进的证明面 |

注：v4' 既有 54 方法的完整清单与本文提及的短代号对应关系以文件类组织为准（TestApprovalArtifact 4 / TestRealRunEntryValidation 5 / TestRequestBoundaries 3 / TestDownloadAndExtraction 5+helper / TestUsageAndIdentity 4 / TestCanaryProtocol 3 / TestBudgetIntegration 4 / TestRealSuiteResultAndEvidence 4 / TestRealRunHygiene 3 / TestResponseDiagnostics 6 / TestUsageDecoupling 4 / TestResourceObservation 2 / TestIdentityExpansion 3 / TestSF01Sanitization 4+helper = 54）。

### 9.3 RED 形态（Modify 型 IP；产品已存在）

C2 冻结前对**未修改的 real_run.py（d59c135b 版，blob 200836cc）**运行 v5：预期失败=新能力缺席——tg1（无截止→下载跑满字节上限→DOWNLOAD_EXCEEDED≠EXECUTION_TIMEOUT 断言红）、tg2（无截止→解包完成→chat 成功→红）、tg3（无复核→成功→红）、tg4（无取消证据→manifest.json 缺席断言红）、tg5/tg6（timeout 恒=timeout_seconds→钳制断言红）、tg7（manifest 无新键→红）、ho1-ho4（attempt 文档无三子块→红）、rd1（15 键 vs 12 键→红）、dec1/ro1/ro2（子块缺席→红）。**按设计通过**=静态/交付物/既有能力类（a1-a4 需 C1 已落、e1、h1-h3、g3/g4、sf3、ie3 等 artifact/loader 直测面、ho5 静态锚）。注入 clock 经 `setattr` 落模块缝——RED 态产品不读该缝（属性存在但未被调用），失败全部为行为断言失败，非 arrange/import 错误。逐方法归因登记（§10 条件 5），独立日志归档（`.pv_tmp/RED_IP-0035_2026-09-28/`）。**基线态证明**：冻结前 C0 已登记 v4' 54/54 绿 + 九文件 298/298 + discover 2638 OK skipped=24（§2 #15），证明 RED 非既有断裂所致。

## 10. 冻结测试面演进程序（v4'→v5；CA R7 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0035 的产品语义变更（截止/取消/观测面/指标）必然触碰 IP-0034 冻结面 `tests/test_v4_baseline_real_run.py`。**裁定：允许该文件以受控方式演进至冻结版本 v5**。先例=IP-0033 Packet §10、IP-0034 Packet §10；演进是产品语义驱动（非机械缺陷），ALLOWED_ONCE 不适用、不得以其消化——授权依据=CA-IP-0035-v1.0 R7 + 本节。**演进依据=2026-09-28 第二轮 Maintainer 授权（§5.6 登记）。**

**演进六条件（全部满足方为合法 v5；任一不满足=Stop Condition 7）**：

1. **对象唯一**：仅 `tests/test_v4_baseline_real_run.py` 一文件、仅此一次；九个其余 v4 冻结测试文件与 budget.py 等产品冻结面 blob 逐字不变（Done Command 7 守护）。IP-0024..0031 冻结面=禁止。
2. **逐 hunk 归因**：v4'→v5 每个 hunk 必须映射到 #234 FR-01..FR-06 之一或授权裁定编号并在 Packet 登记。（本 Packet 登记：模块 docstring→FR-05；新常量/辅助→FR-01..FR-05；`_ATTEMPT_DOC_KEYS` 值更新→FR-03/FR-04【R5/R6 additive 子块】；a1 增量→FR-06/§5.1；e1 注释 hunk→FR-02【R4.4】；dec1/ro1/ro2 增量→FR-02/FR-04；两新类 12 方法→FR-01/FR-02/FR-03/FR-04/FR-06。）
3. **禁止弱化**：既有断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因显式登记的语义变更而更新的期望值。**本轮 (b) 类值更新清单（全部由 R5/R6 裁定驱动，无一处为实现便利）**：`_ATTEMPT_DOC_KEYS` 12→15 键（R5/R6 三 additive 子块——rd1 的键集断言随冻结契约演进；无任何既有断言被删除或放松）。弱化判定争议 → Decision Request。
4. **版本链保留**：v4' blob（`6f8fe8624da26a56969ec52c3ca191100e74d39a`）与 v1..v4' 提交永久在链；Packet 记录 v4' 与 v5 的 blob id 与演进理由索引（v5 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，v5 测试对未修改的 real_run.py（d59c135b 版）运行并留档 RED 证据（独立日志文件归档于 `.pv_tmp/RED_IP-0035_2026-09-28/`，每方法 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（§9.3）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；v5 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖 v5 的机械缺陷。

**ER 复核面**：ER 将逐 hunk 复核演进正当性（条件 2/3）、独立复跑 RED 归因、复核 §9 矩阵断言与 AC 映射。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA R11）

v5 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v5→v5'），条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 v5 Frozen Commit 保留；④修正前缺陷证据（原始 traceback 独立日志）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。涉及产品行为、验收语义或文件范围 → Decision Request；本授权与 §10 演进授权互不折抵、各仅一次。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA R10）

0. 派发前再核验失败：#234 正文/标签状态与本地捕获不一致，或 Base SHA 上 main 出现冲突性实现。
1. **任何真实网络/下载/付费调用（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. 需要修改 budget.py 或 orchestrate.py（或其余七模块/九测试文件）任何字节才能交付——**截止用循环检查与产品内 deadline 传输实现，不改账本原语**（#234 AC-4 明文）。
3. 需要演进十码错误族或 11 检查点（含新增 wire 错误码/检查点/field_path 新值）才能满足可判别性——R2 已裁定替代通道；仍不足=DR。
4. 需要放松任何 fail-closed 门禁/既有断言/预留语义；需要 transport 注入契约偏离 4 参。
5. 需要触碰 Do Not Touch 路径、第 5 个变更文件、或 Dockerfile 超 1 行。
6. 方法数超 66；298 回归/全量 discover 出现非预期失败。
7. v5 演进六条件任一不满足，或出现"弱化既有断言才能通过"的 hunk。
8. 授权文本与实现需求冲突（含本 Assignment 裁定与 Maintainer 授权原文的语义矛盾、或裁定间互斥）——不得自行改写授权或裁定。
9. 需要新依赖/新 import（R5.1 登记的 `os` 除外）、或非注入式外部输入、或真实 sleep 驱动的测试。
10. 发现勘误/证据/代码间新矛盾影响验收语义——记录并提交，不得自行改写远端记录。
11. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0；I-1 DR 为预置授权内建路径，按 R5.5/§8.1 执行不另计）。
12. 取消/截止实现需要吞噬、转换或延迟重抛 BaseException（违反 R4.3），或需要在证据写出阶段丢弃证据（违反 R3.2-⑤）。

## 13. Done Commands（worktree 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 1 Add+3 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行并归档 .pv_tmp/RED_IP-0035_2026-09-28/baseline.txt）：
#    v4' 文件 54/54 绿；九冻结文件 298/298 绿；全量 discover 2638 OK (skipped=24)
#    （与 CA 参照值逐项一致，@d59c135b 本 P&V 会话亲跑）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result
PYTHONUTF8=1 python -m unittest discover -s tests
# 0b. RED 证据（C2 冻结前，对未修改 real_run.py @d59c135b）：独立日志归档
#     （.pv_tmp/RED_IP-0035_2026-09-28/）+ 逐方法归因表（§10 条件 5；RED 形态=新能力缺席）
# 1. 定向 v5 测试（C2 冻结时按设计 RED 且归因"新能力缺席"；C-final 后全绿；66 方法）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
# 2. 九冻结文件回归（298 必须全绿）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result
# 3. 全量 discover 回归（绿；skipped 集与基线 2638/24 一致）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；5. ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_real_run.py
# 6. diff 守护：恰 1 Add（IP-0035 Packet）+ 3 Modify（Dockerfile/tests/real_run.py）；
#    Dockerfile diff 恰 +1 行
git diff --name-status d59c135b69c4a30a3178c93459d47e49d518f922...HEAD
git diff d59c135b69c4a30a3178c93459d47e49d518f922...HEAD -- Dockerfile   # 恰 +1 行
# 7. blob 守护：budget.py(6c783848)/orchestrate(8655067e)+其余六模块+九冻结测试文件+各级 __init__
#    + Dockerfile 既有行 + lima/config 先例文件 blob 与基线一致；
#    tests/test_v4_baseline_real_run.py 登记为"演进文件"（v4' blob 6f8fe862 → v5 blob 记录在案）
git ls-tree d59c135b69c4a30a3178c93459d47e49d518f922 -- <守护清单> 与 HEAD 对比
# 8. ancestry：d59c135b → C1 → C2(v5 冻结) → C3 各段 merge-base --is-ancestor exit 0
# 9. 取消路径独立留痕：取消注入负例的 manifest/attempts/ledger 产物摘要 + D7/D8 对账数值
#    （reserved 归零/consumed 局部观测/calls 不回收）登记于 Completion Summary
```

PC1-PC3 标配（IP-0033/0034 同款）：PC1 测试源 secret-token 拼接扫描（新 clock/transport 辅助零凭据）；PC2 arrange 经冻结校验器（spec_from_mapping/validate_baseline_manifest/validate_role_bindings——新方法经 `run_entry` 复用同源 arrange）；PC3 派生数值断言（timeout 期望由冻结公式 `max(1, min(timeout_seconds, ceil(剩余秒)))` 导出、D7/D8 对账数值由 entry−actual 关系复算、process_identity 用形式+不变性断言不硬抄实现值——§16 DR-IP-0035-PV-2）。

## 14. PR 与 Completion Summary 契约（CA R8/R9）

- PR：单 PR `codex/ip-0035-time-governance` → main；标题禁 close 族关键词与编号组合（含否定句）；提交前缀 `[IP-0035][PV]`/`[IP-0035][IMPL]`/`[IP-0035][CI]`；正文含 Final SHA、变更文件清单（恰 1 Add+3 Modify）、Done Commands 实际输出摘要（0/0b/1-9）、满足/不满足/未验证逐条、下一责任人；合并/推送/评论由主会话按 Maintainer 授权执行，P&V/IMPL 零远端写；PR 必须写明 "This PR does not auto-close the Source Issue." 与 "Related to #234."（仅此关联形式）。
- Completion Summary 必含：FR-01..06 逐条证据索引（测试 ID）、AC-1..4 判定、v5 blob 与 C1/C2 冻结提交 SHA、RED 归档路径与逐方法归因计数、C0 基线实际值（54/298/2638/24）、零真实调用声明、Dockerfile 恰 +1 行证明、D7/D8 对账数值（reserved 归零/consumed 局部观测/calls 不回收）、§8 I-1 结论与 DR-IP-0035-01 呈报状态。

## 15. 范围裁定 R1-R12 转录（CA-IP-0035-v1.0 决定性内容）

- **R1 范围与文件边界**：Allowed Files 终形=恰 1 Add + 3 Modify（§5 表）；零 Delete；单 PR；零新批准工件。否决扩展：budget.py/orchestrate.py/run/report 任何字节、新测试文件、`.gitignore`、历史文档修改。历史文档冲突处置沿用 IP-0033 §5.6 先例：不改既有 Packet/工件文本，新 Packet 显式登记冻结面演进依据=2026-09-28 第二轮 Maintainer 授权（B.1-B.3）（§5.6）。
- **R2 错误族处置终局**：十码目录与 11 检查点零触碰——failure_code 自由串通道承载新 taxonomy。① EXECUTION_TIMEOUT：`failure_code="EXECUTION_TIMEOUT"`、`error_code=REAL_RUN_TRANSPORT_FAILED.value`、`error_field_path` 按相位（下载 `$.download`/解包 `$.archive`/chat 传输与 chat 后复核 `$.transport`）、`record.outcome="timeout"`。② EXECUTION_CANCELLED：`failure_code="EXECUTION_CANCELLED"`、`error_code=None` 且 `error_field_path=None`（否决取消复用 TRANSPORT_FAILED——taxonomy 诚实性）；`record.outcome="cancelled"`（additive）。③ 可判别性不足需演进十码族 → Stop+DR。（本 Packet §7.2 定稿，含既有 TimeoutError 分支的 D7 族统一。）
- **R3 deadline 机制终形**：① 截止点=`min(per_run.wall_ms, batch 余量)`，batch 余量=batch.wall_ms−batch consumed wall_ms（attempt 开始时点账本读数），attempt 开始锚定 monotonic；余量 ≤0 → 立即 typed 截止（零传输调用）；既有入口预检保留。② 五实施面（下载逐块/解包逐块/4 参契约不变+timeout=min(timeout_seconds, ceil(剩余))钳制 ≥1+产品默认传输内部流式累计截止【模块内可离线测试形态】/chat 后复核永不 success 永不 record_usage/证据写出阶段单点判定=manifest 构造时且证据无条件写完）。③ D7 结算=release-only record_failure+attempt-0 局部观测（wall/download/storage），其余 None；差异表新行 D7；budget.py 零改动。④ clock 可测缝=单一内部缝（`_monotonic` 或等价私有形态），注入 clock 驱动负例，零真实 sleep/零公共签名变化/零环境读取。（本 Packet §7.3 定稿，缝名冻结 `_monotonic`。）
- **R4 取消路径终形**：run_repeats 调用点外层 except BaseException：① 恰尾部未结算 attempt（outcome is None 末位）record_failure 释放（attempt-0 局部观测载体或 None；幂等闸=outcome 判定）；差异表新行 D8；预留不得保持占用。② 部分证据集五件套（同源同序 exclusive）：manifest.failures 含 EXECUTION_CANCELLED、attempt_count=len(guarded.records)、batch_wall_ms、cold/warm 冻结常量 5/5；aggregate/report 如实缺席。③ 原 BaseException 无条件 re-raise；次生异常链式记录但原异常优先；RealRunError/BudgetGateError 不经此 catch。④ 证据写出时序面演进登记（正常全集 ∪ 取消部分集；RealSuiteResult 字段全集不变，取消路径不返回 Result）。（本 Packet §7.4 定稿。）
- **R5 cold/warm 诚实面终形**：① attempt 文档 additive `state_reuse` 四键（materialized/snapshot_reused/request_body_rebuilt/process_identity；现行为如实标注 attempt-0 (T,F,T) 其余 (F,T,F)；process_identity=_digest_token 形态、源 os.getpid()、每 suite 一次、跨 attempt 恒同）。② additive `provider_cache` 两键（合规读取 exact int ≥0，缺失/非合规 null；只观测永不进 CallUsage/预算门/结算）。③ mode 标签语义不改。④ 结论限定规则 (a)-(d)（Packet 承载规范性契约，report.py 禁区零改动）。⑤ I-1：Packet 阶段必须完成提供方缓存可控性技术分析（DeepSeek 官方文档只读）；证实不可同时成立 → DR 文本随 PR/呈报提交 Maintainer，不阻塞。（本 Packet §7.5/§8 定稿执行：不可控已证实，DR-IP-0035-01 草案 §8.1。）
- **R6 指标分离终形**：① attempt additive `timings` 四键（api_latency_ms==latency_ms 同值同测/attempt_wall_ms 端到端 monotonic 差【取消=catch 点实测】/download_ms 与 extract_ms 仅 attempt-0 非 null——None 纪律）。② manifest additive `batch_wall_ms`（run_repeats 调用点外层计时，两态均写）。③ manifest additive deadline 观测块（字段由 Packet 定稿冻结；纯观测零失败回注）——本 Packet 定稿为 `{"batch_wall_exceeded": bool}`（§7.6.3）。④ 统计纪律（同名键；latency_ms 语义不变；M8 保留原口径）。（本 Packet §7.6 定稿。）
- **R7 测试面 v4'→v5 演进程序**：六条件全文见 §10；方法预算 ≤66（54+≤12；定稿 66）；新增覆盖必含清单（慢流/慢解包/慢响应/取消证据完整/部分记账与释放对账/batch 截止/state_reuse/state 复用反转可判/provider_cache/timings 分离/batch_wall_ms/证据阶段 deadline 观测+结论限定面）——§9.1 落位（tg1-tg7/ho1-ho5，静态不变锚 ho5 为 CA"锚保持"要求）；RED 锚=新能力缺席；负例全部注入式。
- **R8 提交链拓扑与 PR 纪律**：C1（1 Add+1 Modify，`[IP-0035][PV]`）→ C2（tests v5 冻结，提交信息含 `"[IP-0035][PV] Freeze acceptance tests v5 (RED)"`）→ C3（real_run.py，`[IP-0035][IMPL]`）→ C-final 后仅修复提交（引用 Stop/DR/ALLOWED_ONCE）；单 PR；实现提交以 C2 为祖先（§5.5/§13-8/§14）。
- **R9 Done Commands**：§13（0/0b+1-9；blob 守护清单含 budget.py/orchestrate.py）。
- **R10 Stop Conditions**：§12（0-12）。
- **R11 ALLOWED_ONCE**：§11。
- **R12 升级条款**：Implementation 出现跨冻结模块语义约束、同一根因两轮有新证据修复仍失败、或疑似规格矛盾 → 停止并提交 DR；如裁定升级目标档位 `glm-5.3 / max`，实际切换须新建/重新配置会话并取得 SESSION-RUNTIME-VERIFIED（派发文本声明不构成运行切换），文件边界/测试冻结/验收标准不变。

## 16. Decision Record

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0035-PV-1 | deadline 观测块定稿为 manifest 单键子块 `deadline`=`{"batch_wall_exceeded": bool}`（判定式与 canary `batch_margin_positive` 的 wall 维度同构：reserved+consumed vs batch.wall_ms ≤0；manifest 构造时点求值；两态均写出） | 2026-09-28 | CA R6.3"字段由 Packet 定稿冻结"+R3.2-⑤ 唯一权威判定点；最小纯观测面 |
| DR-IP-0035-PV-2 | process_identity 测试锚=形式+不变性（str、全批恒同、匹配 `_SF01_TOKEN_PATTERN`），不复算 `_sf01_token(str(os.getpid()))` 精确值——避免过度钉扎 digest 输入表示（str vs bytes 为实现自由度）并保持测试文件零新增 import | 2026-09-28 | R5.1"复用 _digest_token 形态"（形式冻结、输入表示实现自由）；IP-0034 Packet §6 测试零新增 import 先例；PC3 关系断言 |
| DR-IP-0035-PV-3 | clock 缝名冻结为模块级 `_monotonic`（CA R3.4 示例形态）；测试 `patch_monotonic` 以 sentinel 恢复（属性原缺失时 cleanup 删除），保证 RED 态 setattr 不产生 arrange 副作用 | 2026-09-28 | R3.4"单一内部缝"+测试确定性注入需求 |
| DR-IP-0035-PV-4 | 既有 socket TimeoutError 分支（下载/chat）结算统一升级为 D7 族（attempt-0 携带局部观测载体）；其 error_field_path 保持既有 `$.transport` 不随相位规则改写（相位规则仅约束新 deadline 机制面） | 2026-09-28 | R3.3 族定义（EXECUTION_TIMEOUT 全族 release-only+attempt-0 局部观测）；R2.1"复用既有结构路径"（既有路径不动）；v4' 无该面数值钉扎（亲验） |
| DR-IP-0035-PV-5 | "batch 余量 ≤0 立即 typed 截止"分支登记为离线不可达（在冻结估计策略下，reserve 通过蕴含 batch 余量 ≥ 入账估计 1,200,000 > 0；余量只能在结算越限后为负，而彼时下一次 reserve 已被账本 wall 门先行拒绝）——实现为防御分支，测试不构造该态 | 2026-09-28 | R3.1 防御语义 + CallEstimate 估计策略冻结（§7.1）；§17 G3 |
| DR-IP-0035-PV-6 | R7 新增清单中"证据阶段 deadline 观测"与"batch_wall_ms"合并落位于 tg7（同一 manifest 面、两态同测）；"静态不变锚保持"独立为 ho5（RED 态按设计通过） | 2026-09-28 | 方法预算 ≤66（54+12=66 恰满）；CA R7 清单全覆盖无遗漏 |

（无未决 DR；DR-IP-0035-01 为呈报 Maintainer 的决议请求草案【§8.1】，属 R5.5 预置内建路径，非本 Packet 未决事项。）

## 17. 已知缺口（不阻塞本 Packet）

- **G1 I-1 条件性 DR 已触发**：提供方缓存不可控已由官方文档亲验证实（§8）；DR-IP-0035-01 草案随 PR/最终呈报提交 Maintainer，不阻塞离线交付。
- **G2 `_urllib_transport` 内部 deadline-aware 形态无法以真实 socket 离线验证**（绝对禁令）——以内部有界读取辅助函数的离线可测形态（R3.2-③）+ 注入面（①②④⑤）负例共同证明；真实路径行为归真实批次阶段（另行授权）。
- **G3 batch 余量 ≤0 防御分支离线不可达**（DR-IP-0035-PV-5）：仅在冻结估计策略被未来 IP 降低时可达；届时须新负例与再冻结。
- **G4 取消注入负例模拟的 BaseException 与真实 KeyboardInterrupt 传播路径存在进程级差异**（信号时机）——以语义等价的受控注入证明（catch 点/结算/证据写出/re-raise 全链），tg4 如实承载该边界。
- **G5 cold/warm 观测面是对当前实现行为的如实标注**；若后续叶改变重置/复用策略，观测面随之如实变化（键集语义不变）。
- **G6 #234/#223/#232 远程正文与评论未由本 P&V 会话直取**（零网络边界，除 §8 声明的 DeepSeek 文档只读）：以 CA 转录为权威；主会话派发前已完成远程核验。
- **G7 M8 提醒**：2026-09-28 批数据保留原口径；新旧指标口径以键名区分（§7.6.4），呈报层引用须同名。
