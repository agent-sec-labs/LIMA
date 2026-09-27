# LIMA Implementation Packet — IP-0033 Real-Run Diagnostics Hardening（#226 / #57 PR3-d-real 诊断加固子叶，零真实调用）

- Packet ID：IP-0033；版本 v1.0（2026-09-28）。
- Coordinator Assignment：CA-IP-0033-v1.0（2026-09-28；快轨 Intent+Coordinator 合并轮，Intent Record `.pv_tmp/INTENT_RECORD_IP-0033_2026-09-28.md` 的 Q1-Q12 由其 R1-R12 裁定）。
- Source Issue：#226（parent #57 保持开放；本 IP 是 IP-0032 的诊断加固后继，**零真实调用**）。
- Operating Mode：SHADOW；Execution Authorization：MAINTAINER_AUTHORIZED（2026-09-28 长程授权：本轮零真实 API/下载/付费、零远端写）。
- Base SHA（完整 40 位）：`45a7ec792c260385370e907e7e4070841fe112bf`（= origin/main = 本地 main，PR #224 merge，亲验）。
- 本 Packet 的角色：Implementation（阶段 C3+）的唯一实现依据；冻结验收测试 v3（本 Packet §9/§10）的唯一语义来源；ER 复核（演进正当性/差异表 D1-D6/矩阵）与 P&V 独立验证的基准。

## 0. 交付物角色声明（强制，先于一切）

1. 本 Packet（本文件）是 P&V 的 C1 交付物；`tests/test_v4_baseline_real_run.py` 冻结版本 v3 是 P&V 的 C2 交付物；`benchmarks/v4/baseline/real_run.py` 的诊断增强是 **Implementation 的 C3+ 交付物**。三者边界不得互换：Implementation 不得修改本 Packet 与测试；P&V 不实现产品功能。
2. **零真实调用绝对禁令**：本 IP 全程（含分支上、CI 内、pre-merge"顺手验证"）禁止任何真实模型调用、网络下载、付费动作。全部验收以离线构造（注入 fake transport）证明。真实 canary 重跑需要新的 Maintainer 数值预算批准（G3），不在本 Packet。
3. 预算语义只紧不松：诊断与解耦是观测面/结算策略扩张，不得以任何形式放松 usage/身份/字节/调用数门禁；`budget.py`（IP-0031 冻结面）零字节改动。

## 1. 需求映射（Packet 头；#226 Scope 1-6 → FR-01..FR-06 + AC-1..4）

FR-01..FR-06 为 #226 "Scope (this slice)" 1-6 的规范化编号（语义不变，CA-IP-0033-v1.0）；AC 沿用 #226 原文 AC-1..4。

| 需求 | 内容（规范化语义） | 本 Packet 承载 | 验收面 |
| --- | --- | --- | --- |
| FR-01 | 检查点级失败诊断：11 封闭检查点标记 + 结构化 field_path 细化；十码错误目录不变 | §7.2/§7.3 | v3 矩阵 TestResponseDiagnostics rd1/rd2/rd3/rd4 + u3 演进（AC-1） |
| FR-02 | 脱敏响应元数据：9 键封闭 schema；失败与成功均记；零正文/凭据/完整体 | §7.4 | rd2/rd3/rd4/rd5 + e2 演进（AC-2） |
| FR-03 | usage 解耦记账：verdict 失败+合规 usage→入账+失败保留；无 usage→违规不入账（None≠0）；预算零放松 | §7.5（差异表 D1-D6） | TestUsageDecoupling dec1-dec4（AC-3） |
| FR-04 | 失败资源观测：latency/请求字节/attempt-0 下载与存储字节进 attempt 记录与账本 consumed 观测面；不动预留/释放 | §7.6 | TestResourceObservation ro1/ro2 |
| FR-05 | 离线负例矩阵：#226 Scope 5 全清单；错误分类/canary latch/调用上限/失败账本逐项；零门禁放松 | §9 矩阵落位表 | 全矩阵（十二新增+35 演进保留） |
| FR-06 | IP-0032 其余冻结契约保持：预算门/下载器/身份匹配语义/证据文件集结构兼容；298 方法零改动 | §7.8/§7.7 | Done Commands 2/3/6/7 + 基线回归锚类（AC-4） |
| AC-1 | 检查点逐点可区分（含上轮实测形态 `deepseek-flash` → response_identity 复现） | §7.2/§7.3 + ERR-D 锚（§2 输入 4） | rd1（11 对 (checkpoint, field_path) 互异） |
| AC-2 | 脱敏完整+零泄露（源扫描+字节级探针） | §7.4 泄露审查规则 | rd5 + e2 扩展 |
| AC-3 | usage 解耦语义（consumed/violations 对账） | §7.5 D1/D2/D4 | dec1-dec4 |
| AC-4 | 结构兼容+全离线（十冻结面兼容、blob 守护、discover 绿） | §7.7 + Done Commands | DC 2/3/6/7 |

Not-covered（全团队不得扩张；CA "Not covered" 1-7 全文约束）：任何真实模型调用/下载/付费；thinking 参数形态变更；**身份允许集扩纳**（如接受 `deepseek-flash` 形态——身份门禁语义变更，属下一次 canary 决策包）；PR3-e/矩阵行升级/#85 登记/#57 聚合 Closure；#223 纠正口径重审计（含勘误事实表第 5 行与代码矛盾的处置）；budget.py/orchestrate/run/offline_flow/fixtures/report/collect/expert_timing、九个其余冻结测试文件、`lima/**`、`evaluation_data/**`、决策包/批准工件/注册表/报告 schema 的任何修改；canary 清单五项的键名、判定语义与 latch 触发条件变更。

## 2. Design Input Manifest

| # | 输入 | 版本/位置 | 消费方式 |
| --- | --- | --- | --- |
| 1 | CA-IP-0033-v1.0 | `.pv_tmp/COORDINATOR_ASSIGNMENT_IP-0033_2026-09-28.md` | 范围权威；R1-R12 全文转录见 §13 |
| 2 | Intent Record | `.pv_tmp/INTENT_RECORD_IP-0033_2026-09-28.md`（F1-F14/I1-I9） | 技术事实基线（解析链 11 抛错点、结算原语、v2 测试面） |
| 3 | Source Issue #226 正文 | 本地创建脚本 `.pv_tmp/create_issue_ip0033.py`（逐字）；远程再核验待主会话（Stop Condition 0） | Scope 1-6/Non-goals/AC-1..4（经 CA 规范化为 FR-01..06） |
| 4 | #223 勘误评论 ERR-A/B/C | issuecomment-5856435913（2026-09-27T13:50:01Z，作者 AttentionYourCode；本 P&V 会话经 GitHub API 重定向亲取全文） | ERR-A（根因 UNKNOWN+H1-H4）/ERR-B（费用口径）/ERR-C（null=未读取粒度缺陷）→ FR-01/FR-02 设计输入 |
| 5 | #223 勘误评论 **ERR-D** | issuecomment-5856555608 + 勘误的勘误 issuecomment-5856558808（2026-09-27T14:05-14:06Z；本 P&V 会话 API 亲取） | **决定性锚**：上轮失败检查点演绎判定为身份检查——L1126 拒绝分支也记录 response_model；允许集={deepseekv4flash, deepseekv41flash}（v41 非 41），normalize("deepseek-flash")="deepseekflash" ∉ 集合 → v3 身份复现用例必须以 `model="deepseek-flash"` → checkpoint `response_identity` 为锚（AC-1） |
| 6 | 上轮真实证据 | `D:\BaseAIProject\LIMA-real-runs\pr3d-real-2026-09-27\attempts\attempt-00.json`（字节副本亲读） | 证据 schema v1 基线与失败形态：`response.model="deepseek-flash"`、error REAL_RUN_RESPONSE_INVALID、field_path 恒 `$.response`、fingerprint/finish_reason/content/usage 全 null（未读取） |
| 7 | 合并代码 | `benchmarks/v4/baseline/real_run.py` @45a7ec7（1458 行全文亲读） | 演进对象：`_parse_response` L1109-1215、`_settle` L919-929、`_chat` L1088-1107、`_AttemptRecord.to_document` L382-405 |
| 8 | budget.py 三态原语 | `benchmarks/v4/baseline/budget.py` @45a7ec7 L502-601 亲读 | record_usage（合规全量结算+差值释放）/record_usage(None)（violations+1）/record_failure(partial)（保留+释放）——解耦只调用既有原语 |
| 9 | 冻结测试 v2 | `tests/test_v4_baseline_real_run.py` blob `30a2a119c2fb3672eb8cf786e583d04a86aa415`（35 方法/9 类，全文亲读） | 演进基础（§9/§10） |
| 10 | IP-0032 冻结 Packet | `docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md` §7.1/7.2/7.7/7.9 | 十码/`__all__`/guard 序与结算/证据 schema 不变量来源 |
| 11 | ER 先例 | `.pv_tmp/EVIDENCE_REVIEW_RECORD_IP-0032_2026-09-27.md`（SF-01 归档纪律） | v3 RED/缺陷证据独立日志归档纪律 |
| 12 | Dockerfile | L55-61 docs COPY 块亲读；先例 53053e8（IP-0032 冻结后中途补线） | C1 预授权 +1 行的落位依据 |

## 3. Explicitly Rejected Inputs

| # | 被拒输入 | 拒绝理由 |
| --- | --- | --- |
| 1 | 勘误事实表第 5 行原表述（"model='deepseek-flash' 身份规范化通过"） | 与合并代码矛盾（ERR-D 演绎推翻）；其处置属 #223 重审计（Not-covered 5）；本轮仅取 ERR-D 修正后事实为设计输入 |
| 2 | 上轮 Closure Record 的根因结论（thinking 形态→content 空） | ERR-A 推翻（越证据；根因 UNKNOWN）；且 ERR-D 表明失败点在身份检查、根本未到达 content——thinking 形态变更被 Not-covered 拒绝 |
| 3 | "实际 API 花费≈0 / 最坏 $0.0025" 口径 | ERR-B 撤回；正确口径=请求次数 1 可证、无可核实 usage 入账、实际收费 UNKNOWN |
| 4 | 把 finish_reason/content/usage 的证据 null 解释为"服务端返回空" | ERR-C 纠正：null=未读取（早期检查点抛错）——v3 的 None 纪律（§7.4 规则 6）直接继承 |
| 5 | "身份允许集应扩纳 deepseek-flash" 的实现暗示 | 身份门禁语义变更=下一次 canary 决策包事项（Not-covered 3）；本 Packet 身份集构造不变（§7.8） |
| 6 | 拆分新错误码族（REAL_RUN_RESPONSE_INVALID 一拆多码） | CA R2 裁定拒绝：十码是 manifest/下游聚合口径，拆码破坏兼容且无收益；检查点枚举+field_path 已满足 AC-1 |
| 7 | 修改 budget.py / orchestrate.py / run.py / 新测试文件以承载诊断 | CA R1 否决：解耦只需既有原语；单一验收面=同文件演进 v3 |
| 8 | 为诊断需要而记录正文/凭据/完整体 | §0 第 3 条与 §7.4 规则 5 永禁；Stop Condition 3 |

## 4. Goal / Non-goals

**Goal**：使下一次有预算的真实 canary「失败时根因可判定、成功时账目可核对」——全部以离线构造证明：① 11 检查点级可区分诊断（替代恒 `$.response` 单点报错）；② 失败与成功均记录脱敏响应元数据（H1/H2/H3 等形态在证据中直接可判）；③ usage 与 verdict 解耦记账（真实消耗必记账；无 usage=违规不入账）；④ 失败尝试资源观测入 attempt 记录与 consumed 观测面；⑤ 离线负例矩阵逐项正确且零门禁放松；⑥ 以受控冻结面演进 v2→v3 承载验收，298 方法零改动。

**Non-goals**：见 §1 Not-covered 段（CA 原文）。根因官方口径仍为 UNKNOWN（H5 已由 ERR-D 证实为实际失败原因，但身份集扩纳决策与 #223 重审计不在本 IP）。

## 5. 文件边界（CA R1：恰 1 Add + 3 Modify；零 Delete；单 PR）

### 5.1 Files to Add

| 文件 | Owner/阶段 | 说明 |
| --- | --- | --- |
| `docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md` | P&V（C1，本文件） | 本 Packet；v3 冻结测试 a1 断言其在库存在 |

### 5.2 Files Allowed to Modify（恰 3；每文件一次性行为见 §10 演进条件）

| 文件 | Owner/阶段 | 边界 |
| --- | --- | --- |
| `Dockerfile` | P&V（C1，与 Packet 同一提交） | **恰 +1 行**：`COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md ./docs/`，插入既有 docs COPY 块内紧随 IP-0032 Packet 行（L59）之后；不允许第二行。依据 R1/C1 预授权（避免 53053e8 式冻结后中途补线）。基线 blob `1f5dbbbc72080f7809a29fd179fb54addf4d2cd5` |
| `tests/test_v4_baseline_real_run.py` | P&V（C2，冻结面演进 v2→v3；**唯一冻结面演进授权，程序见 §10**） | 仅此一文件、一次性；方法预算 ≤48（定稿 47：35 演进保留+12 新增，§9）；RED 证据先于冻结落盘；v2 blob `30a2a119c2fb3672eb8cf786e583d04a86aa415` 永久保留在链 |
| `benchmarks/v4/baseline/real_run.py` | Implementation（C3+） | 诊断增强四件套（§7.2-§7.6）；`__all__`/十码/入口签名/请求形状/估计策略/canary 清单/证据时序不变（§7.8）；零新增 import |

### 5.3 Read-only Reference Files（只读消费）

`benchmarks/v4/baseline/budget.py`（**IP-0031 冻结面，零字节改动**——解耦只调用既有原语：record_usage/record_failure(partial)）；`orchestrate.py`/`run.py`/`report.py`/`collect.py`/`fixtures.py`/`expert_timing.py`/`offline_flow.py`；`docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md` 与其余历史 Packet/批准工件/决策包；`D:\BaseAIProject\LIMA-real-runs\**`（上轮证据字节副本）；`evaluation_data/**`。

### 5.4 Files Forbidden（diff 必空；Done Command 6/7 逐 blob 守护）

`benchmarks/v4/baseline/` 其余八模块与各级 `__init__.py`；`tests/` 其余九个 v4 冻结测试文件（298 方法，blob 逐字不变）；`evaluation_data/**`；`lima/**`；`scripts/**`；`docs/` 其余全部；`pyproject.toml`/`requirements.txt`/`.gitignore`/`.gitattributes`/`.github/**`/前端；不提交任何输出目录/密钥/run 产物。任何"必须改上述禁区才能交付"= Stop Condition 4/5。

### 5.5 提交链/拓扑（冻结）

C1 = Packet+Dockerfile 行（1 Add+1 Modify，同一提交）；C2 = tests v3（1 Modify，冻结提交，提交信息含 `[IP-0033][PV] Freeze acceptance tests v3 (RED)` 字样）；C3 = real_run.py（1 Modify）；C-final 之后允许且仅允许修复提交且每次必须引用 Stop/DR 编号或 ALLOWED_ONCE 记录。单 PR（`codex/ip-0033-diagnostics` → main）；PR 标题禁 close 族关键词与编号组合（含否定句）。实现提交必须以 v3 冻结提交为祖先（Done Command 8）。

### 5.6 与其他活动 IP 的冲突分析

IP-0024..0031 冻结面：禁止触碰（派发令 M9；本 Packet 的演进授权不构成任何先例外推）。IP-0032 冻结面：唯一触碰=本 Packet 授权的 tests v2→v3 受控演进（§10）；real_run.py 的产品语义变更由本 Packet §7 细化承载（IP-0032 Packet §7 对该文件的冻结由本 Packet 显式演进，不变量清单见 §7.8）。

## 6. 依赖、网络、文件系统与权限边界

- **依赖**：零新增第三方依赖；real_run.py **零新增 import**（诊断所需原语 json/hashlib/enum/dataclasses 已在白名单内——Intent F12）；测试文件零新增 import（演进只新增常量/类/方法）。
- **网络**：测试全离线、注入 fake transport、永不触网（含既有 `_forbidden_network_roots` 断言）；产品默认 transport 仍是唯一网络代码位置且不在任何测试路径上。**本 IP 期间任何真实网络/下载/付费调用=Stop Condition 1（绝对禁令）**。
- **文件系统**：证据文件只写调用方提供的一次性输出目录（库外 temp）；库内除 §5.1/§5.2 三文件外零写入；不读环境变量/配置/.env（IP-0032 冻结面保持）。
- **数据库/容器/远端写**：无数据库；容器面仅 Dockerfile +1 COPY 行；零远端写（不 push、不关 Issue、不改 Ledger 远端状态——合并/推送由 Coordinator 后续授权）。

## 7. real_run.py 冻结契约细化（CA R2-R5/R8；Packet 定稿）

### 7.1 错误族不变面（IP-0032 Packet 7.1 保持）

`RealRunErrorCode` 十成员与逐字消息**字节级不变**；`RealRunError` 形状不变（code/field_path/稳定消息，不嵌数值/payload/secret）。其余错误码路径的 field_path 不变（`$.usage`/`$.identity`/`$.transport`/`$.download`/`$.archive`/`$.request`/`$.canary`/`$.approval_artifact`/`$.output_root`/`$.timeout_seconds` 等）。v2 冻结测试无 `"$.response"` 断言（Intent F6 亲验），§7.3 的细化不构成对 v2 的断言弱化或矛盾。

### 7.2 检查点枚举（FR-01；**公共符号面冻结**）

- **新增模块级封闭枚举，定名 `RealRunResponseCheckpoint(str, enum.Enum)`**（CA R2 建议名，本 Packet 定稿）。成员值封闭为恰 11 个、逐字：

```
response_json, response_dict, response_model, response_identity,
choices_list, choice0_dict, message_dict, content_str, content_json,
verdict_shape, verdict_types
```

- 覆盖 `_parse_response` 全部抛错点（Intent F2 的 ①-⑪ 一一对应；finish_reason/fingerprint 宽容记录不设检查点）。**不进 `__all__`**（`__all__` 六符号不变——IP-0032 Packet 7.2 面零漂移）；测试经模块属性访问并以成员值（wire 字符串）断言。成员名拼写不冻结（值冻结）；str mixin 保证 `member == "response_json"` 成立、JSON 序列化为该字符串。
- **机器可读主锚**：`record.diagnostic.checkpoint`（§7.4）；field_path 是人读结构锚；二者同时落 attempt 文档与 manifest failures[]（后者经 error_field_path 自动流入，manifest schema 不变）。
- **ERR-D 锚定（AC-1 必测）**：`model="deepseek-flash"`（上轮实测形态）规范化为 `deepseekflash` ∉ 允许集 {`deepseekv4flash`, `deepseekv41flash`} → checkpoint=`response_identity`；v3 矩阵 rd1 以此为复现用例。

### 7.3 error_field_path 细化映射（**冻结表；结构定位、不嵌值**）

| checkpoint | field_path | 触发（构造形态） |
| --- | --- | --- |
| response_json | `$.response` | 响应体非 UTF-8/非法 JSON |
| response_dict | `$.response` | 顶层非 dict |
| response_model | `$.response.model` | model 非 str |
| response_identity | `$.response.model` | 规范化 model ∉ 允许集（**含上轮实测形态 `deepseek-flash`**） |
| choices_list | `$.response.choices` | choices 缺失/非 list/空 list |
| choice0_dict | `$.response.choices[0]` | choices[0] 非 dict |
| message_dict | `$.response.choices[0].message` | message 非 dict |
| content_str | `$.response.choices[0].message.content` | content 非 str（null/list/…） |
| content_json | `$.response.choices[0].message.content` | content 是 str 但 json.loads 失败（**含空串 ""**——H2 判定点） |
| verdict_shape | `$.response.verdict` | verdict 非 dict/键集 ≠ 四键 |
| verdict_types | `$.response.verdict` | is_vulnerable 非 bool；cwe/path 非 str-or-null；reason 非 str |

十码仍为 REAL_RUN_RESPONSE_INVALID（不拆码）；11 对 (checkpoint, field_path) 逐点互异（AC-1 判据）。

### 7.4 diagnostic 脱敏响应元数据（FR-02；9 键封闭 schema 冻结）

`record.diagnostic`（attempt 文档新键，closed schema，逐字段如下）：

```
"diagnostic": null | {
  "checkpoint": null | <11 值之一>,      # 失败检查点；成功/仅 usage 或 identity 失败时为 null
  "response_meta": {                     # 收到响应体即在场（成功与失败均记，#226 Scope 2）
    "top_level_keys":    [排序键名] | null,   # 顶层非 dict 时 null（None=未读取，非空集）
    "choices_count":     int | null,          # choices 为 list 时其长度；非 list/缺失 null
    "message_keys":      [排序键名] | null,   # message 为 dict 时；否则 null
    "content_len":       int | null,          # content 为 str 时 len()；否则 null
    "content_sha256":    hex64 | null,        # content 为 str 即计算（失败亦算——空串=e3b0c442… 可判 H2）
    "finish_reason":     str | null,          # choices[0] 为 dict 且其值为 str 时；否则 null
    "usage_present":     bool | null,         # 顶层为 dict 时 = isinstance(document["usage"], dict)；否则 null
    "model":             str | null,          # 顶层 model 为 str 时（身份串，非正文）
    "system_fingerprint": str | null          # 顶层 system_fingerprint 为 str 时
  }
}
```

- **在场规则**：transport 失败/超时 → `diagnostic: null`（无响应可诊断；latency 照记）；收到响应体（含不可解析字节）→ `diagnostic` 在场（response_json/response_dict 时 response_meta 九键全 null）；响应契约通过（成功、或仅 USAGE_MISSING/IDENTITY_CHANGED）→ `checkpoint: null` + response_meta 完整（usage_present=False 正是 USAGE_MISSING 的诊断证据）。
- **语义澄清（Packet 定稿）**：response_meta 是对已接收响应文档的**事后整档读取**（post-mortem），各字段按自身前置条件取值（如 identity 检查点失败时 system_fingerprint/usage_present 仍按文档实际取值）；既有 `record.response.*` 键（IP-0032 Packet 7.9）语义不变，仍是**契约推进标记**（identity 拒绝分支只记录 response_model，fingerprint/finish_reason 保持 null——与上轮 attempt-00 证据形态一致，ERR-D/ERR-C）。两键集并存、互不改写。
- **逐字段泄露审查规则（AC-2；v3 字节探针逐条锁定）**：
  1. 键集仅收集**键名**并排序序列化——任何字段的**值**不入（键名是结构元数据；与 IP-0032 已冻结的 response_model/response_fingerprint 记录面同级别）。
  2. choices_count/content_len 是整数计数——不含内容。
  3. content_sha256 是单向摘要——不可恢复正文（#226 Scope 2 明文授权"content 长度与 sha256"）。
  4. finish_reason 是服务端枚举型短串；model/system_fingerprint 是身份串——三者均为 IP-0032 已在记录面的先例形态。
  5. **永禁（测试以唯一标记字节扫描证明）**：原始 prompt、模型正文/推理内容（含 reasoning_content 的**值**——其**键名**可出现在 message_keys 中）、凭据/api_key、完整请求体/响应体、Authorization 头。
  6. None 纪律：未读取=null（不是 ""/0/[]——ERR-C 教训：null="未读取"≠"服务端返回空"）。

### 7.5 usage 解耦记账（FR-03；结算差异表 D1-D6 = ER 复核基准；budget.py 零改动）

**机制裁定**：解耦=real_run.py 结算策略变更，**只调用 budget.py 既有原语**：合规 usage → `record_usage(run_id, usage)`（consumed 记账+按差值释放预留）；无合规 usage → `record_usage(run_id, None)`（violations+1，捕获 BudgetGateError）→ `record_failure(run_id, partial)`（释放预留+保留本地观测）。`BudgetLedger`/`CallUsage`/`CallEstimate`/`Pricing` 一字节不改。

**结算差异表（IP-0032 → IP-0033；ER 逐行复核）**：

| # | 情形 | IP-0032（现行） | IP-0033（本轮） | 不变量 |
| --- | --- | --- | --- | --- |
| D1 | RESPONSE_INVALID（任一检查点）+ 响应 dict 携带**合规** usage | `record_failure(run_id)`——usage 丢弃 | `record_usage(run_id, usage)`——usage 记入 consumed、预留按差值释放；样本仍 failure（failure_code=EXECUTION_ERROR、error_code=RESPONSE_INVALID 不变） | 真实消耗必须记账；失败样本保留 |
| D2 | RESPONSE_INVALID + **无**合规 usage（块缺失/字段无效/顶层非 dict 不可读） | `record_failure(run_id)`（无违规计数） | `record_usage(run_id, None)`→violations+1（捕获）→`record_failure(run_id, partial)`——**违规计数新增**；本地观测（attempt-0 下载/存储/墙钟，§7.6）经 partial 保留于 consumed | 无 usage=违规不入账（None≠0）；只紧不松 |
| D3 | 响应契约全过但 usage 缺失/无效（现行 USAGE_MISSING 路径） | violations+1→record_failure | **不变** | 原样 |
| D4 | IDENTITY_CHANGED + 合规 usage（身份检查在 usage 提取之后） | record_failure（usage 丢弃）→latch | `record_usage(run_id, usage)` 入账 → latch（latch 触发条件/时点不变） | 记账与 latch 解耦 |
| D5 | transport 失败/超时（含 REAL_RUN_TRANSPORT_FAILED 全路径） | record_failure，无违规 | **不变**（无可读 usage；latency 已记） | 原样 |
| D6 | 成功 | record_usage(usage) | **不变** | 原样 |

- **合规判定（与成功路径同规，冻结）**：usage 块为 dict 且 prompt_tokens/completion_tokens 为 `type is int` 且 ≥1；cost=`_worst_case_cost`（冻结公式）；wall_ms=该次实测 latency；download/storage 按 index==0 归属（attempt-0 实测、1-9 为 0）。
- **D2 partial 的可观测契约（Packet 定稿，不钉内部载体）**：violations 恰 +1；consumed 的 prompt_tokens/completion_tokens/cost_micro_usd Δ=0（零伪零——不得以伪 usage 入账）；attempt-0 时 consumed.download_bytes/storage_bytes=实测、consumed.wall_ms=该次 latency；预留全额释放（released=entry−actual）；attempts 1-9 无本地观测（partial 维度缺席即可）。partial 载体内部用 None（合法缺席）或 0 表达，账本可观测结果相同。
- **canary 清单五项键名、判定式、latch 触发零改动**——唯一行为交互（必须 v3 钉扎，Intent F8）：解耦后 attempt-0 失败但 usage 合规入账时，清单第 1 项 `usage_within_reservation` 输入从 None 变为已入账 usage（≤ 预留则 True）；canary 仍经第 2/5 项失败 latch。
- **预算语义零放松**：reserve 检查序/上限/at-cap 语义不变；记账只发生在冻结三态原语内；violations 只增不减。

### 7.6 失败资源观测（FR-04；观测面；不动预留/释放语义）

- **attempt 记录（所有人可见）**：`request.body_bytes`/`latency_ms` 现状已覆盖多数失败路径（latency 在解析前记录、body_bytes 在请求构造时记录）——v3 以断言钉扎其在**每类失败**下在场；新增 closed 键 `"resources": {"download_bytes": int|null, "storage_bytes": int|null}`（物化发生=attempt-0 且下载/解压完成时为实测值；否则 null——含 attempts 1-9 与 attempt-0 解包前失败）。
- **账本 consumed 观测面**：经 §7.5 结算表流入——D1/D4 全量 usage（含字节）；D2 经 partial 保留本地观测（见 §7.5 D2 契约）；D3/D5/D6 不变。
- **不动**：CallEstimate 估计策略（含 attempt-0 的 250,000,000/500,000,000 最坏值与 attempts 1-9 的 0）、reserve 检查序、释放/回收语义、批 calls 计数。观测不设新维度、不加 pseudo-run、不占 batch.calls。

### 7.7 证据 schema 演进兼容判据（FR-06/AC-4）

- attempt 文档 v2 = v1 + **恰两新键**（`diagnostic`、`resources`），其余键集/语义不变；manifest.json schema_version 保持 1（failures[] 经 error_field_path 自动携带细化路径，键集不变）；ledger.json 三联不变；文件名集与写出时序（run_repeats 返回后、exclusive）不变。
- **兼容判据**：旧读取方（按 v1 键集消费 attempt/manifest/ledger 的任何工具）在 v2 证据上行为不变——additive-only、无重命名/删除/语义翻转；`top_level_keys` 等新值不进入旧键。e1 证据文件名集断言保持。
- 证据文件集结构兼容=AC-4 的机械判定面；九冻结面 298 方法零改动由 Done Command 7 blob 守护。

### 7.8 real_run.py 其余不变面（IP-0032 Packet 7.2-7.12 保持）

`__all__` 六符号逐字；`run_real_baseline_suite` 签名/参数序/kwonly/默认值；请求形状（含 `thinking: {"type":"disabled"}` 与 `response_format`）；身份允许集构造（工件 request_name/served_as 规范化二元组——**不扩纳**）；`_normalize_identity` 正则；`_worst_case_cost` 公式；CallEstimate 估计策略（attempt-0 最坏值/attempts 1-9 body 派生）；canary 清单五项键名与判定式；总执行序 1-9；证据文件集与写出时序；RealSuiteResult 字段全集；evaluator payload（real-world v2）；transport 注入契约；import 白名单（零新增）；模块 hygiene（零环境/配置读取、api_key 永不落盘/入错）。

## 8. 批准工件与静态守卫（沿用 IP-0032）

批准工件 `docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md` 与其校验逻辑零改动（a2-a4 断言面保持）。v3 新增静态守卫：a1 扩展断言本 Packet 在库存在 + Dockerfile 含本 Packet 的 COPY 行（容器只读 CI 白名单依据，R1）。

## 9. 测试矩阵 v3（`tests/test_v4_baseline_real_run.py`；定稿 47 方法 = 35 演进保留 + 12 新增；≤48 预算内）

组织：同文件演进（否决新文件），九类既有类全部保留，新增恰三类。全离线、注入 fake transport、零仓库写入、永不触网（既有 `_FakeTransport`/`_build_tarball`/`_fixed_sources` 基建复用；新增 `_RawBodyTransport` 子类支持脚本化原始字节响应——纯增量，不改既有 fixture 行为）。

### 9.1 新增方法（12 个，逐个登记断言面）

| 方法（新类.新方法） | 覆盖 | 断言面（冻结） |
| --- | --- | --- |
| TestResponseDiagnostics.rd1 `test_eleven_checkpoints_produce_distinct_diagnostics` | FR-01/AC-1 | 11 检查点逐点 subTest：attempt-0 error_code=REAL_RUN_RESPONSE_INVALID、error_field_path 与 diagnostic.checkpoint 按 §7.3 表逐字匹配、attempt 文档键集=v1+恰两新键；11 对 (checkpoint, field_path) 互异；枚举面：RealRunResponseCheckpoint 存在、str 子类、封闭 11 值、len==11、不进 `__all__`；**ERR-D 锚：model="deepseek-flash" → response_identity/$.response.model** |
| TestResponseDiagnostics.rd2 `test_response_meta_nine_keys_sorting_and_none_discipline` | FR-02 | 身份失败形态：response_meta 9 键封闭、top_level_keys=排序键名、choices_count/message_keys/content_len/content_sha256/finish_reason/usage_present/model/system_fingerprint 逐值；不可解析体：九键全 null（None=未读取）；choices 缺失：顶层结构键在场+下游四键 null |
| TestResponseDiagnostics.rd3 `test_success_attempts_carry_null_checkpoint_full_meta` | FR-02 | 全 10 成功 attempt：diagnostic 在场、checkpoint null、恰两子键、meta 完整（model=请求名、usage_present True、content_len/content_sha256=实测复算） |
| TestResponseDiagnostics.rd4 `test_content_digest_recorded_even_when_verdict_fails` | FR-02（H2/H3 判定） | content=""→checkpoint=content_json、content_len=0、content_sha256=e3b0c442…（空串锚常量）；content="not-json"→content_json、len/digest 复算 |
| TestResponseDiagnostics.rd5 `test_diagnostics_face_leak_free_and_value_domain_audit` | FR-02/AC-2 | verdict 失败+content 内嵌唯一标记：全证据树字节扫描（api_key token/正文标记零命中）；diagnostic 递归字符串值域审查（∈{键名∪身份串∪finish_reason∪checkpoint 名∪hex64}，正文值零出现） |
| TestResponseDiagnostics.rd6 `test_transport_failure_keeps_null_diagnostic_and_latency` | FR-02 | 超时失败：diagnostic 键在场且为 null、latency_ms 在场（int） |
| TestUsageDecoupling.dec1 `test_verdict_failure_with_usage_settles_and_retains_failure` | FR-03/AC-3（D1） | verdict_shape 失败+合规 usage：violations==0；consumed 记入 tokens/cost（公式导出）/download/storage 实测；reserved 全 0；released[prompt]=100,000−1,000、released[completion]=8,000−500（差值释放）；失败样本保留（outcome/failure_code/error_code/error_field_path/checkpoint） |
| TestUsageDecoupling.dec2 `test_verdict_failure_without_usage_counts_violation_and_keeps_observation` | FR-03/AC-3（D2） | verdict 失败+无 usage：violations==1；consumed tokens/cost Δ=0（零伪零）；consumed download/storage=实测、wall_ms==attempt-0 latency_ms（交叉对账）；reserved 全 0 |
| TestUsageDecoupling.dec3 `test_identity_change_records_usage_then_latches` | FR-03（D4） | attempt-0 成功+attempt-1 指纹变化：chat_calls==2、codes[1]=IDENTITY_CHANGED、后续 CANARY_FAILED；violations==0；consumed=两次 usage 之和（公式导出）；reserved 全 0 |
| TestUsageDecoupling.dec4 `test_canary_first_item_true_when_usage_settled_but_canary_still_latches` | FR-03（F8 交互） | attempt-0 verdict 失败+usage 合规：清单第 1 项 True、第 2/5 项 False、status failed、后续 9 次 CANARY_FAILED、violations==0 |
| TestResourceObservation.ro1 `test_attempt0_failure_keeps_resources_and_request_observation` | FR-04 | attempt-0 失败：resources 键在场、恰 {download_bytes,storage_bytes}、值为 tarball/实测存储字节数（复算）；request.body_bytes>0、latency_ms int≥0 在场 |
| TestResourceObservation.ro2 `test_follow_on_failure_observation_and_release_reconciliation` | FR-04 | attempt-1 超时失败：resources 为 null、body_bytes==attempt-0（同一请求体）、latency 在场；六维 released 对账=Σ(entry−actual)（entry 按 §7.8 估计策略导出：attempt-0 最坏值、1-9 body 派生；actual 从 attempt 文档读取）；consumed.wall_ms==成功 attempt latency 之和（D5 不变证明）；calls==10、violations==0 |

### 9.2 演进既有方法（35 全保留，断言不弱化；三处增量登记）

| 方法 | 增量（additive） | 归因 |
| --- | --- | --- |
| a1 `test_artifact_in_repo_with_closed_field_set_and_container_copy_line` | 断言 IP-0033 Packet 在库 + Dockerfile 含本 Packet COPY 行（静态守卫；C1 先落→冻结时按设计通过） | FR-06/§8 |
| u3 `test_canary_model_mismatch_rejected` | 加断 diagnostic.checkpoint==response_identity + response_meta.model=="deepseek-v9-ultra" | FR-01/AC-1 |
| e2 `test_evidence_chain_free_of_key_and_raw_content` | 探针扩展诊断面：每 attempt diagnostic 值域审查（AC-2） | FR-02/AC-2 |

其余 32 方法（b1-b5、req1-req3、d1-d5、u1/u2/u4、c1-c3、g1-g4、e1/e3/e4、h1-h3）**字节不变**（基线回归锚：预算门/下载/解包/请求界/账本/hygiene 不受演进的证明面）。模块 docstring 更新为 v3 演进说明（文档 hunk，归因 FR-05）。

### 9.3 #226 Scope 5 清单逐项落位

缺 choices→rd1(choices_list)；缺 message→rd1(message_dict)；content null→rd1(content_str)/空串→rd4(H2)；非 JSON content→rd4(H3)；verdict 键集错→rd1(verdict_shape)；verdict 类型错→rd1(verdict_types)；finish_reason 异常形态/usage 组合/system_fingerprint 缺失与变化→u1-u4+dec2-dec4+rd2/rd3（宽容记录与 None 纪律面）；非 2xx/网络失败/超时→req3/rd6/ro2（D5 不变）；错误分类→rd1+u3；canary latch→dec4+c1-c3；调用上限→g2/g3；失败账本→dec1-dec3/ro2。零门禁放松：全部既有 fail-closed 断言保留。

### 9.4 RED 形态（Modify 型 IP；产品已存在）

C2 冻结前对**未修改的 real_run.py（45a7ec7 版）**运行 v3：预期失败=依赖新诊断字段/解耦行为/观测键的方法——rd1-rd6（diagnostic/resources 键缺席 KeyError）、dec1-dec4（consumed/violations 期望不匹配）、ro1-ro2（resources 缺键）、u3/e2 演进断言；按设计通过=静态/交付物存在类（a1 需 C1 的 Packet 与 Dockerfile 行先落、h1-h3、g1-g4 账本直测、其余 32 个 v2 原样方法）。RED 逐方法归因登记（§10 条件 5），独立日志归档（SF-01 教训）。**基线态证明**：冻结前先登记 v2 文件对 v2 产品的 35/35 绿 + 九文件 298 绿 + discover 基线（Done Command 0），证明 RED 非既有断裂所致。

## 10. IP-0032 冻结测试面演进程序（v2→v3；CA R6 六条件全文；正式 Packet 级一次性授权）

**冲突裁定**：IP-0033 的产品语义变更（检查点子标记/解耦结算/证据 schema v2）必然触碰 IP-0032 冻结面 `tests/test_v4_baseline_real_run.py`。**裁定：允许该文件以受控方式演进至冻结版本 v3**。先例=IP-0032 自身的 re-freeze 演进链（v1 `7ec533d` → v2 `0834f14`，经 DR-1/DR-2 机械修正）；本轮不同点：演进是**产品语义驱动**（非机械缺陷），故 **ALLOWED_ONCE 不适用、不得以其消化**——授权依据=CA-IP-0033-v1.0 R6 + 本节。

**演进六条件（全部满足方为合法 v3；任一不满足=Stop Condition 10）**：

1. **对象唯一**：仅 `tests/test_v4_baseline_real_run.py` 一文件、仅此一次；九个其余 v4 冻结测试文件与 budget.py 等产品冻结面 blob 逐字不变（Done Command 7 守护）。IP-0024..0031 冻结面=禁止（派发令 M9 原文；本授权不构成任何先例外推）。
2. **逐 hunk 归因**：v2→v3 每个 hunk 必须映射到 #226 FR-01..FR-06 之一并在 Packet 中登记；与六 FR 无关的 hunk 禁止。（本 Packet 登记：模块 docstring→FR-05；新增常量/`_RawBodyTransport`/`_string_values` 与三新类 12 方法→FR-01/02/03/04/05；a1 增量→FR-06；u3 增量→FR-01；e2 增量→FR-02。）
3. **禁止弱化**：既有断言不得删除或放松（fail-closed 门禁、泄露探针、hygiene、`__all__`/签名/数值守卫全部保留）；只允许 (a) 新增断言/方法、(b) 因 R4 差异表**显式登记的语义变更**而更新的期望值（本轮：无——D1-D6 均为新增行为面，既有 35 方法期望值零变化；u1 的 USAGE_MISSING 路径 D3 不变、c2/c3 判定式零改动故期望不变）。弱化判定争议 → Decision Request。
4. **版本链保留**：v2 blob（`30a2a119c2fb3672eb8cf786e583d04a86aa415`）与 v1/v2 提交永久在链；Packet 记录 v2 与 v3 的 blob id 与演进理由索引（v3 blob 由 C2 冻结时登记于提交与验证记录）。
5. **RED 先于冻结**：C2 冻结前，v3 测试对未修改的 real_run.py（45a7ec7 版）运行并留档 RED 证据——Modify 型 IP 的 RED=新诊断能力缺席（锚点例：`read_attempt(root,0)["diagnostic"]["checkpoint"]` 在现行产品上 KeyError/断言失败；解耦用例 consumed 断言失败）。RED 证据按 SF-IP-0032-20260927-01 教训**以独立日志文件归档**（每个失败方法的原始 traceback 可定位），逐方法登记"RED 失败/按设计通过"归因（先例 IP-0032 §9：27 失败/8 通过）。
6. **角色纪律**：演进只在 C2 由 P&V 执行；Implementation 结构性零参与测试修改；v3 冻结提交后本 Assignment 的 ALLOWED_ONCE（§11）仅覆盖 v3 的机械缺陷。

**ER 复核面（F14）**：ER 将逐 hunk 复核演进正当性（条件 2/3）、独立复跑 RED 归因、复算差异表 D1-D6 与矩阵断言。

## 11. ALLOWED_ONCE（一次性机械测试修正授权；CA R11）

v3 冻结后，P&V 可在不新增 Coordinator 调用的情况下自行纠正**一次**纯测试机械缺陷并重新冻结（v3→v3'），条件全部满足：①不改产品语义、公共接口、稳定错误码或文件范围（含 Dockerfile 行数）；②仅限 fixture/arrange/import/lint/测试基础设施缺陷；③旧 v3 Frozen Commit 保留；④修正前缺陷证据（**原始 traceback 独立日志文件**）、修正后有效 RED、新 Frozen Commit 完整记录；⑤Implementation 未参与测试修改。产品语义/验收语义/文件范围 → Decision Request；本授权与 §10 演进授权互不折抵、各仅一次。

## 12. Stop Conditions（触发即停并提交 Decision Request；CA R10）

0. 派发前再核验失败：主会话远程核验 #226 正文/门禁、勘误评论 ID 与本地捕获不一致。
1. **任何真实网络/下载/付费调用（含分支上/CI 内/pre-merge"顺手验证"）——绝对禁令。**
2. 需要 thinking 参数形态变更、或身份允许集扩纳（如接受 `deepseek-flash`）才能满足任何断言——身份/请求门禁语义变更=下一 canary 决策包事项。
3. 需要放松任何 fail-closed 门禁/既有断言（含以"诊断需要"为由记录正文/凭据/完整体）。
4. 需要触碰 Do Not Touch 路径、第 5 个变更文件、或 Dockerfile 超 1 行。
5. 需要修改 budget.py 或其余八模块/九测试文件才能交付解耦或诊断。
6. 方法数超 48；298 回归/全量 discover 出现非预期失败。
7. v3 演进六条件（§10）任一不满足，或出现"弱化既有断言才能通过"的 hunk。
8. 发现 IP-0033 占用冲突或 base SHA 后 main 出现冲突性实现。
9. 需要新依赖/新 import、或非注入式外部输入。
10. 发现勘误/证据/代码间新矛盾（含 Intent F4 矛盾的扩大化）影响验收语义——记录并提交，不得自行改写远端记录。
11. 需要消耗 Maintainer 决策的任何事项（预算 ≤1，预期 0——授权与演进授权已给）。

## 13. 范围裁定 R1-R12 转录（CA-IP-0033-v1.0 决定性内容）

- **R1 Allowed Files 终形**：恰 1 Add（本 Packet）+ 3 Modify（Dockerfile 恰 +1 行 COPY 本 Packet【C1 预授权落线，插 L59 后】；tests v3【唯一冻结面演进授权】；real_run.py【IMPL】）。否决扩展：budget.py 任何字节、新测试文件、orchestrate/run 注入点、IP-0032 Packet/批准工件/决策包、.gitignore。提交链拓扑冻结（§5.5）。
- **R2 错误子码形态**：十码目录+逐字消息字节不变；新增封闭检查点枚举（§7.2 定名定值）；error_field_path 细化映射冻结表（§7.3）；record.diagnostic.checkpoint 为机器可读主锚、field_path 人读结构锚、同落 attempt 与 manifest failures[]；不拆码（manifest/下游聚合口径兼容）。
- **R3 脱敏响应元数据**：9 键封闭 schema（§7.4）；在场规则；逐字段泄露审查六规则（键名/计数/长度/摘要/身份串合法；正文/凭据/完整体永禁；None 纪律）。
- **R4 usage 解耦记账**：机制=budget.py 既有原语（record_usage/record_failure(partial)），BudgetLedger 等一字节不改；结算差异表 D1-D6（§7.5）；合规判定与成功路径同规；canary 清单五项零改动+第 1 项输入交互钉扎（F8）；预算零放松。
- **R5 失败资源观测**：attempt 记录新增 closed resources 键；body_bytes/latency 每类失败在场钉扎；账本 consumed 观测经结算表流入；估计策略/预留/释放/calls 不动。
- **R6 冻结面演进程序**：六条件全文见 §10；ALLOWED_ONCE 不适用；ER 逐 hunk 复核。
- **R7 测试组织**：同文件演进；新增恰三类 TestResponseDiagnostics/TestUsageDecoupling/TestResourceObservation；预算 ≤48（定稿 47）；负例矩阵落位（§9）；RED 形态=新诊断能力缺席（§9.4）。
- **R8 证据 schema 演进兼容**：additive-only 判据（§7.7）。
- **R9 Done Commands**：见 §14（0/0b/1-8）。
- **R10 Stop Conditions**：见 §12（0-11）。
- **R11 ALLOWED_ONCE**：见 §11。
- **R12 PR/commit 纪律**：前缀 `[IP-0033][PV]`/`[IP-0033][IMPL]`/`[IP-0033][CI]`；标题禁 close 族；单 PR；Handoff 模板（Final SHA/恰 1A+3M/命令 1-8 结果/满足-不满足-未验证/下一责任人）；Ledger 草案由主会话经授权写入。

## 14. Done Commands（worktree 根执行；Windows 设 `PYTHONUTF8=1`；成功判据=全绿/为空/恰 1 Add+3 Modify/blob 不变/ancestry exit 0）

```bash
# 0. 预冻结基线（C2 之前登记；本轮已执行归档）：
#    v2 real_run 测试 35/35 绿；九冻结文件 298/298 绿；全量 discover 基线 2867 OK (skipped=26)
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v            # 35 green（v2 文件态）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result   # 298 green
PYTHONUTF8=1 python -m unittest discover -s tests                              # 基线登记
# 0b. RED 证据（C2 冻结前，对未修改 real_run.py）：独立日志文件归档 + 逐方法归因表（§10 条件 5）
# 1. 定向 v3 测试（C2 冻结时按设计 RED 且归因"新诊断能力缺席"；C-final 后全绿；47 方法）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline_real_run -v
# 2. 九冻结文件回归（298 必须全绿）
PYTHONUTF8=1 python -m unittest tests.test_v4_baseline tests.test_v4_baseline_budget tests.test_v4_baseline_cli tests.test_v4_baseline_collection tests.test_v4_baseline_fixtures tests.test_v4_baseline_manifest tests.test_v4_baseline_offline_flow tests.test_v4_baseline_report tests.test_v4_baseline_result
# 3. 全量 CI discover 集合回归（绿；skipped 集与基线一致）
PYTHONUTF8=1 python -m unittest discover -s tests
# 4. 字节编译；5. ruff（--no-cache；bandit 选做，如实登记）
PYTHONUTF8=1 python -m compileall -q benchmarks tests
PYTHONUTF8=1 python -m ruff check --no-cache benchmarks/v4/baseline/real_run.py tests/test_v4_baseline_real_run.py
# 6. diff 守护：恰 1 Add（Packet）+ 3 Modify（Dockerfile/tests/real_run.py）；Dockerfile diff 恰 +1 行
git diff --name-status 45a7ec792c260385370e907e7e4070841fe112bf...HEAD
# 7. blob 守护：九测试文件+budget.py+其余七模块+各级 __init__+三 JSON+lima 先例文件 blob 与基线一致；
#    tests/test_v4_baseline_real_run.py 登记为"演进文件"（v2 blob 30a2a119 → v3 blob 记录在案）
git ls-tree 45a7ec792c260385370e907e7e4070841fe112bf -- <守护清单> 与 HEAD 对比
# 8. ancestry：45a7ec7 → C1 → C2(v3 冻结) → C3 各段 merge-base --is-ancestor exit 0
```

PC1-PC3 标配（IP-0032 同款）：PC1 测试源 secret-token 拼接扫描（含新 diagnostic 断言面——a3 运行时自扫 + 归档前静态复核）；PC2 arrange 经冻结校验器（spec_from_mapping/validate_baseline_manifest/validate_role_bindings——g1 面保持，新方法经 `run_entry` 复用同源 arrange）；PC3 派生数值断言（dec1/dec3 cost、ro2 released 对账、rd2/rd3/rd4 digest 与长度均由冻结公式/实测复算导出，不硬抄实现值）。

## 15. PR 与 Completion Summary 契约

- PR：单 PR `codex/ip-0033-diagnostics` → main；标题禁 close 族关键词与编号组合（含否定句）；正文含 Final SHA、变更文件清单（恰 1 Add+3 Modify）、命令 1-8 实际输出摘要、满足/不满足/未验证逐条、下一责任人。
- Completion Summary 必含：FR-01..06 逐条证据索引（测试 ID）、AC-1..4 判定、D1-D6 差异表实现位置、v3 blob 与冻结提交 SHA、RED 归档路径、零真实调用声明。

## 16. Packet Completion Definition

本 Packet `READY-FOR-CODE`（无 TBD 字段；范围/边界/冻结接口/矩阵/Done Commands/Stop Conditions 齐备）。实施完成的定义=Done Commands 1-8 全绿 + §10 六条件留痕 + ER 复核通过；Issue 关闭与合并判定归 Coordinator（本 Packet 不授予）。

## 17. Decision Record

| # | 决策 | 时间 | 依据 |
| --- | --- | --- | --- |
| DR-IP-0033-PV-1 | 枚举定名 `RealRunResponseCheckpoint`（str, enum.Enum）；成员名不冻结、成员值 11 个逐字冻结；不进 `__all__` | 2026-09-28 | CA R2 授权 Packet 定稿；§7.2 |
| DR-IP-0033-PV-2 | response_meta 定性为"事后整档读取"（与 record.response.* 推进标记并存、互不改写） | 2026-09-28 | CA R3 schema 文档条件式 + ERR-C/D 粒度区分；§7.4 澄清 |
| DR-IP-0033-PV-3 | D2 partial 以可观测契约冻结（violations+1、tokens/cost Δ0、attempt-0 字节/墙钟入 consumed），内部载体不钉 | 2026-09-28 | CA R4/R5 + budget.py record_failure(None 跳过=0) 语义等价；§7.5 |
| DR-IP-0033-PV-4 | v2→v3 的 hunk 全集登记：docstring/新常量/新基建/三新类 12 方法/a1、u3、e3 处增量；既有 35 方法期望值零变化（无 §10 条件 3(b) 类 hunk） | 2026-09-28 | CA R6 条件 2/3；§9.2/§10 |
| DR-IP-0033-PV-5 | 基线绿证据（v2 文件 35/35）+ v3 RED（新增 12 红u3/e2 红、a1/h/g 系按设计绿）分别归档，作为"既有 35 方法未断裂"与"RED 归因新能力缺席"的双重证明 | 2026-09-28 | 派发令 RED 形态 + CA R9 命令 0/0b；§9.4 |

（无未决 DR；冻结面演进授权=CA R6+§10 正式授权，非未决事项。）

## 18. 已知缺口（不阻塞本 Packet）

- **G1 身份允许集政策（H5）未决**：是否扩纳 `deepseek-flash` 属身份门禁语义变更——本轮 Not-covered，随下一次 canary 决策包提交（届时 IP-0033 的 checkpoint 证据将自证）。勘误事实表第 5 行矛盾处置归 #223 重审计（本轮零远端写）。
- **G2 根因官方口径仍为 UNKNOWN**（ERR-A）；H5 已由 ERR-D 证实为实际失败原因，但"根因"终局口径以 #223 重审计为准；thinking 形态不变更。
- **G3 真实重跑未授权**：IP-0032 本批已 latch 终局；下一次 canary 需新数值预算批准。
- **G4 远程再核验**：#226 正文与勘误评论的远程一致性核验由主会话派发前完成（本 P&V 会话已实测 GitHub API 可达并亲取三条勘误评论全文，2026-09-27 时间戳与 ID 与 CA 记载一致；#226 正文远程核验仍归主会话）。
