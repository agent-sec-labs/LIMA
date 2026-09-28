# LIMA PR3-e Expert Review Package（专家人工复核包）

- 文档类型：真人复核流程包（Human Expert Review Package）。
- 版本：v1.0（2026-09-28；IP-0036 C1 交付；Packet：`docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md` §7.3）。
- 承接：#237 Scope 6（专家复核包）；#57 FR-05/V5-AC-01 人工专家面；协议实现=IP-0027（`benchmarks/v4/baseline/expert_timing.py`）。
- Operating Mode：SHADOW；零真实调用；**本包不含任何 api_key/付费通道**；本叶（IP-0036）零真人专家事件——专家分钟保持缺席（K4），本包交付的是流程可用性而非执行证据。

## 1. 适用场景与边界

当一次 baseline 运行的报告需要人工专家复核（security review of the finding/adjudication face）时，评审专家使用本包记录复核时间线。产出物是一个 `.expert-timing.json` sidecar 文档，与对应的 per-attempt 结果文件（`{digest16}-run-{n}.json`）成对放置，由报告层（`benchmarks/v4/baseline/report.py`）按 IP-0027 冻结协议消费聚合。

**边界（缺席纪律，强制）**：

1. 无真人事件 → 专家面如实缺席：`expert.sessions == 0`、`expert.active_time_ms_total == null`、`reviewer_digests == []`。
2. **不得以模型调用或合成事件填充专家分钟**（#237 Scope 6 明文；IP-0036 Packet §0.4）。
3. automation 时间不属于专家分钟：自动化耗时由 `wall_time_ms`/`cpu_time_ms` 承载（IP-0027 协议），与 `active_time_ms` 严格分离。
4. 本包不定义、不携带任何付费调用通道；复核结论本身（agree/disagree/notes）由后续真实评审叶另行承载，本包只冻结计时与身份摘要协议。

## 2. 真人复核流程（开始/暂停/恢复/结束）

评审会话按以下事件序列进行，每个事件带显式**纳秒时间戳**（单调不减；任何倒退时间戳 fail-closed 拒绝且会话不变）：

```text
idle --start(t1)--> active --pause(t2)--> paused --resume(t3)--> active --finish(t4)--> finished
```

- `start`：仅可从初始 idle 状态发起；
- `pause`：仅可从 active 发起；
- `resume`：仅可从 paused 发起；
- `finish`：可从 active 或 paused 发起（暂停中直接结束合法——未闭合活动区间不计入）；
- 任何其他转移、finish 后的任何事件、非 int 时间戳、倒退时间戳：类型化拒绝（`EVENT_SEQUENCE_INVALID`/`INVALID_METRIC_TYPE`/`CLOCK_NOT_MONOTONIC`），会话保持不变（fail-closed）。

**活动时间规则**：`active_time_ms` = 全部已闭合活动区间的纳秒差之和整除 1,000,000（毫秒）；暂停区间不计；查询时仍开放的活动区间不计（不估算）。

工具：`benchmarks.v4.baseline.expert_timing.ExpertTimingSession`（IP-0027 冻结实现，本叶零字节改动）。

```python
from benchmarks.v4.baseline.expert_timing import ExpertTimingSession

session = ExpertTimingSession("<reviewer-id>")   # 原始 id 只在内存，见 §4
session.start(1_000_000_000)      # ns
session.pause(1_005_000_000)
session.resume(1_010_000_000)
session.finish(1_020_000_000)
document = session.to_sidecar_document("<run_spec_digest>")
# session.sidecar_bytes(...) / session.sidecar_digest(...)：canonical 编码与摘要
```

## 3. Sidecar 逐字段表（`.expert-timing.json`，五键冻结闭集）

| 字段 | 类型 | 语义 | 纪律 |
| --- | --- | --- | --- |
| `schema_version` | int（恒 `1`） | sidecar schema 版本（IP-0027 冻结） | 非 1 → `SIDECAR_INVALID`/`ARTIFACT_UNREADABLE` fail-closed |
| `run_spec_digest` | str（64-hex 小写） | 被复核运行的 RunSpec 摘要 | 必须与该运行的 `run_spec_digest` 逐字相等（不匹配 → fail-closed）；实现侧把 sidecar 与 run 的绑定作为校验面 |
| `reviewer_digest` | str（64-hex 小写） | 评审人身份的 SHA-256 摘要 | **原始 reviewer id 永不出现在任何属性、事件或 sidecar 字节**；仅摘要可持久化 |
| `active_time_ms` | int ≥ 0 | 已闭合活动区间总毫秒（§2 规则） | 无闭合区间 → 0（数值面）；会话缺席由"无 sidecar 文件"承载（非 0 冒充） |
| `events` | list[{"event": str, "time_ns": int}] | 事件序列（出现顺序） | 每元素恰两键；`event` ∈ start/pause/resume/finish |

序列化：经 `lima.contracts.codec.canonical_encode`（sorted-key 紧凑 UTF-8 JSON，无 BOM、无尾随换行）；摘要可从字节单独复算。无计数类指标进入 sidecar（IP-0027 协议原文纪律）。

## 4. 评审人身份纪律

- 输入侧：`ExpertTimingSession(reviewer_id)` 只接受非空 str（否则 `INVALID_REVIEWER_ID`）；
- 持久化侧：raw reviewer id 即刻转为 SHA-256 摘要（`hashlib.sha256(reviewer_id.encode("utf-8")).hexdigest()`），后续一切面只携带摘要；
- 本包所有示例使用合成 fixture 身份（`lima-expert-alice-fixture`），非真实人员。

## 5. 示例 Sidecar（完整 JSON；字面通过现行冻结校验器）

以下示例由上述 §2 流程（reviewer id=`lima-expert-alice-fixture`，事件 1,000,000,000/1,005,000,000/1,010,000,000/1,020,000,000 ns）经 `ExpertTimingSession.to_sidecar_document` 生成。`run_spec_digest` 为示例运行摘要（sha256(b"ip-0036-expert-review-package-example")）。**该示例已于 2026-09-28 由 P&V 会话亲验：字面通过 report.py 现行 `_gate_sidecar`（经 `build_baseline_report` 公共路径）与 `_validate_sidecar_artifact`（发现面）双冻结校验器（含负例对照证明校验器在判）**；M2 冻结测试解析本块并断言通过（Packet §7.3 验收面）。

```json
{
  "schema_version": 1,
  "run_spec_digest": "5803dc30a7af3cb0d271be1ec7e3a8f1caba267879696e588f6d827163889c0e",
  "reviewer_digest": "36ed63756dcabce7a73ffa296186294a5f30d41c1e8ba6bdd6e6ae98850c2603",
  "active_time_ms": 15,
  "events": [
    {"event": "start", "time_ns": 1000000000},
    {"event": "pause", "time_ns": 1005000000},
    {"event": "resume", "time_ns": 1010000000},
    {"event": "finish", "time_ns": 1020000000}
  ]
}
```

（活动时间核算：区间 start→pause 5ms + resume→finish 10ms = 15ms。）

## 6. 与 report.py 冻结形状校验的兼容性说明

- 报告层现行校验器（IP-0029 冻结面）：`_gate_sidecar`（注入面：五键闭集、schema_version==1、run_spec_digest hex64 且等于运行摘要、reviewer_digest hex64、active_time_ms int ≥0、events list）与 `_validate_sidecar_artifact`（文件发现面：同一五键集合与同一值域）。
- **IP-0036 的 report schema v2 演进不触碰 `_SIDECAR_FIELDS` 五键**——sidecar schema 零变更（#237 Scope 6 与 Packet §7.1.1-5 不变面明文）。本包与 v2 报告的消费链路兼容性由此结构性保证。
- 放置规则：sidecar 与对应结果文件同目录、按 stem 配对（`{stem}.expert-timing.json`）；孤儿 sidecar（无配对结果文件）不产生条目也不报错（如实缺席）；不可解析的 sidecar fail-closed（`ARTIFACT_UNREADABLE`）。

## 7. 缺席纪律声明（强制复述）

本叶（IP-0036）交付期间**零真人专家事件**：所有报告的专家面必须保持 `sessions=0`/`active_time_ms_total=null`/`reviewer_digests=[]`（缺席由 M2 既有 zero-sidecar 冻结断言钉扎，零弱化）。任何把模型调用、自动化耗时或合成事件计入专家分钟的行为都违反本包协议与 #237 Scope 6，属验收失败。真实评审事件发生时，按 §2-§6 流程产出 sidecar；其真实值的聚合证据归 PR3-e 真实叶（后续授权）。

（包完；勘误按新版本发布，不原地覆盖语义。）
