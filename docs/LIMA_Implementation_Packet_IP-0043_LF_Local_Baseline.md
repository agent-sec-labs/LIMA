# LIMA Implementation Packet — IP-0043 固定 SHA LlamaFactory 本地基线（契约记录）

- IP-0043 · Issue #257。Assignment：CA-IP-0043-v1.0（2026-10-01，含附录 R1-R7）。本文是 C2 交付的契约记录：键集 / 错误族 / 词表 / 版本 / 口径声明（R7）。冻结验收测试 v13（Frozen Test Commit `25124c9f11d57576e01b4716e76873626e169235`）是可执行契约；本文与 v13 一致，冲突时以 v13 与 Assignment 为准。
- 交付物：`benchmarks/v4/baseline/lf_baseline.py`、`benchmarks/v4/baseline/lf_observation.py`、`benchmarks/v4/baseline/expert_review.py`、`scripts/run_lf_baseline.py`、`scripts/run_expert_review.py`；覆盖账与依赖图订正另见 `docs/LIMA_IP0043_Coverage_Account_and_Dependency_Correction.md`。

## 1. 固定身份常量（pinned，永不替换）

| 常量 | 值 |
| --- | --- |
| `LF_TARGET_COMMIT_SHA` | `7fcf5b3b130e5713b52415bb7404c476fada9c8c` |
| `LF_REPOSITORY_IDENTITY` | `hiyouga/LlamaFactory` |
| `LF_DATASET_NAME` | `lima-external-llamafactory-holdout-v1` |
| `LF_DATASET_ROLE` | `external-holdout` |
| `LF_WORKLOAD` | `lf-local-scanner-v1` |
| `LF_CANONICAL_LABEL`（canonical 投影字面量） | `external/llamafactory-replay@7fcf5b3b` |

sealed tarball 只读复用（2026-09-28 物化件，5,346,267 B，sha256 `2f148def60610789d146f9f3ecb1cded1f6bc1b4db8f6f1fbcf7531ac1758626`——由绑定文档声明并由运行亲算核对，产品源不硬编码该期望值）。原件缺失/不匹配 ⇒ typed 终止 ⇒ 仅阻止本项扫描并标 needs-decision；禁换 SHA、禁重新下载。

## 2. 入口签名（R1）

```python
run_lf_local_baseline_suite(
    *,
    output_dir,
    machine_profile,
    source_root,
    binding,
    cold_count=3,
    warm_count=5,
    seed=0,
    sources=None,          # PlatformSources | None（None → 真实平台源）
) -> LFSuiteResult
```

- 全部关键字参数；cold/warm 必须正整数（`type(x) is int` 且 ≥1，bool/float 拒绝），默认 3/5；违例 ⇒ `LF_PARAM_INVALID`，零输出。
- **不路由** `run_baseline_attempt`/`run_repeats`（SF-01 冻结数据集注册表只认三个 popular-python 数据集名，LF 运行专属名必被拒）；自有 attempt 循环复用冻结原语：`spec_from_mapping`+`validate_baseline_manifest`（身份层）、`result_from_mapping`（nearest-rank 聚合+status，不自算分位）、`write_result_file`/`write_exclusive`（`{digest16}-run-{n}.json` 独占命名）、`PlatformSources`/`elapsed_ms`/`require_metric`/`classify_failure`（采集与 taxonomy）。
- zero-call workload：无 wire client、无请求构造、无审批面；`model_calls` 恒 0；每样本 prompt/completion/cost 恒 int 0。
- cold：每次从 sealed tarball 解包全新 per-cold 工作副本 → tree fingerprint 校验 → 显式离线配置真实扫描（SAST/CXX memory/CXX agent/platform LLM 全 off、dataflow on、`SecurityRuleReviewer` 显式、workspace 5000/512KiB/20MiB 显式）；warm：复用最后 cold 快照+扫描结果（receipts 如实记 `snapshot_reused`/`scanner_result_reused`）。
- corrupt-but-hash-consistent 归档：不 raise，逐 attempt 体失败并按冻结 taxonomy 保留失败样本（EXECUTION_ERROR），聚合如实 insufficient_sample；不产出报告与 scanner payload 面（`report_path`/`scanner_payload_sha256` 为 None，不伪造）。

## 3. 三层来源绑定（R2）与 typed 错误族

绑定文档 = 运行专属 schema-v1 manifest（datasets[0] 必含 name/fingerprint/role/entries[{repository,commit_sha}]/archive_sha256/archive_bytes；license/source/layout 等 provenance 字段容忍）。

- 层 1（本模块）：形状+钉死身份（repository/commit 与 §1 冲突 ⇒ `LF_IDENTITY_CONFLICT`；dataset 名/角色偏差 ⇒ `LF_BINDING_INVALID`）。
- 层 2（冻结 spec 层）：spec 七字段真值（repositories=[§1 钉死]，datasets=[{name, fingerprint=绑定声明树指纹, role}]，analyzer_fingerprint/config_digest 派生，seed，machine_profile 声明式 8 字段）经 `spec_from_mapping`+`validate_baseline_manifest` 交叉校验；`BaselineRunSpecError` ⇒ `LF_BINDING_INVALID`。
- 层 3（字节层）：归档 sha256/bytes 与声明比对（`LF_SOURCE_HASH_MISMATCH`）；每 cold 物化树指纹与声明比对（`LF_SNAPSHOT_TREE_MISMATCH`）。

`LFSourceErrorCode` 闭集（`LFSourceError(ValueError)`，消息稳定不嵌 digest/host 路径；`str(code)` 渲染裸值）：

| 码 | 触发 | needs_decision |
| --- | --- | --- |
| `LF_SOURCE_MISSING` | 归档缺失 | 是 |
| `LF_SOURCE_HASH_MISMATCH` | 归档 sha256/bytes 与声明不符 | 是 |
| `LF_SNAPSHOT_TREE_MISMATCH` | 物化树指纹与声明不符 | 是 |
| `LF_IDENTITY_CONFLICT` | 绑定身份与钉死目标冲突 | 是 |
| `LF_OUTPUT_NOT_EMPTY` | 输出目录非空 | 否 |
| `LF_BINDING_INVALID` | 绑定/spec 形状或交叉校验失败 | 否 |
| `LF_PARAM_INVALID` | cold/warm 非正整数 | 否 |

### 3.1 物化与树指纹约定（7.5；DR-IP-0043-CFINAL Option A 订正）

- 解包规则：仅常规文件成员；剥离唯一顶层目录段；拒绝绝对路径/dot 段；**链接类成员（symlink/hardlink）确定性跳过，不物化、不计入物化树与树指纹**；其余异常成员类型（设备/FIFO 等）仍整包拒绝。产物写入采用**平台文本行约定**（每个 `b"\n"` 写为 `os.linesep`；POSIX 恒等、Windows 为 CRLF），与任意文本写出的同内容字节一致。
- 链接跳过的权威依据：① 09-28 权威物化事实——sealed tarball 760 成员恰 1 符号链接（`LlamaFactory-7fcf…/CLAUDE.md` → `.ai/CLAUDE.md`），权威 596 文件物化清单唯含常规文件（链接不入树）；② 生产先例——`lima/real_world_evaluation.py` L424-429 对链接成员既有处理即 omit（"The analysis workspace never follows symlinks, so omit them instead of materializing attacker-controlled link targets"），全仓既定安全语义一致。树指纹本身钉扎链接缺席；不新增 receipt/binding 键，materializations 计数沿用既有面。
- 树指纹规则（`SnapshotStore._tree_identity` 独立转录）：相对 POSIX 路径排序（排除 `.lima-snapshot.json` 标记），`len(path):path:size:\0` 帧+原始字节，SHA-256。
- 绑定声明的 fingerprint 必须等于下列两个规范面**之一**（二者都钉死物化字节，其余一律 fail-closed）：（A）纯快照树=物化工作副本本身；（B）sealed 源目录树=工作副本+复用归档以其自身文件名入帧。

## 4. 输出工件族（闭键集）

目录 `LIMA-real-runs/pr3d-lf-local-baseline-<date>/`（唯一写例外；测试中为 temp 目录）：

- 每尝试与聚合：`{digest16}-run-{n}.json`（n=1..attempt_count+1，聚合最后）；报告：`{digest16}-report-{n}.json`（`build_baseline_report` kind=scanner 不变路径；resources 三键 null 照旧，资源证据全在 companion）。
- `lf-attempts/attempt-NN.json`：`{schema_version:1, run_spec_digest, source_receipt}`；`source_receipt` 恰 12 键：

```
attempt_index, mode, run_spec_digest, workload, commit_sha,
snapshot_tree_sha256, archive_sha256, materializations,
scanner_reexecuted, scanner_result_reused, snapshot_reused,
scanner_payload_sha256
```

- `lf-binding.json` 恰 25 键：

```
schema_version, workload, run_spec_digest, attempt_count, cold_count,
warm_count, repository_identity, commit_sha, dataset_name, dataset_role,
archive_sha256, archive_bytes, snapshot_tree_sha256, analyzer_name,
analyzer_fingerprint, config_digest, scanner_config,
scanner_config_sha256, seed, scanner_payload_sha256, lf_receipts,
lf_receipts_digest, failures, model_calls, declarations
```

- `scanner_config`：`scanner` 子块（sast_mode="off"、sast_adapters=[]、cxx_memory_mode="off"、cxx_memory_adapter=None、cxx_agent_mode="off"、cxx_agent_budget_factory=None、cxx_uaf_llm_factory=None、dataflow_enabled=True、reviewers、should_cancel）+ `workspace` 子块恰 {max_files:5000, max_file_bytes:524288, max_total_bytes:20971520} + workload/身份/seed/cold/warm 面；`scanner_config_sha256 = compute_content_digest(scanner_config)`；`config_digest`（spec 面）同值。快照内容、seed、cold/warm 任一变化 ⇒ run_spec_digest 变化（NFR-01）。
- canonical 投影：`report.repository`/`workspace.root` 替换为 `LF_CANONICAL_LABEL`，wire digest=冻结规则（sorted-key compact UTF-8 JSON SHA-256）；同布局跨目录 digest 相等（DR-C2 Option A），与既有四族零碰撞（run_spec_digest 全新 ⇒ 16 位前缀结构性区分）。

## 5. 资源 observation companion（R3）

`build_lf_observation(*, output_dir)` → `lf-local-observation-v1.json`（与 run 工件同目录、独立命名族；`report.py` 零 hunk）。顶层恰 10 键：

```
schema_version(=1), profile(="lf-local-observation-v1"), run_spec_digest,
aggregate_sha256, scanner_payload_sha256, snapshot_tree_sha256,
archive_sha256, attempts, measurement_semantics, model_usage
```

- `attempts[]` 恰 8 键：`attempt_index, mode, result_sha256, wall_time_ms, cpu_time_ms, memory_rss_peak_bytes, io_read_bytes, io_write_bytes`；`result_sha256`=对应 result 文件原始字节 SHA-256；数值面逐键等于该样本值。
- `measurement_semantics` 六条目（精确字符串）：memory_rss_peak_bytes=process-lifetime cumulative peak (ru_maxrss scope); not a per-attempt delta；io_read/io_write=process-lifetime cumulative counter at read time; not a per-attempt delta；wall/cpu=per-attempt delta between two monotonic reads；platform="windows: no resource module and no /proc/self/io; unavailable platform metrics are null, never zero-filled or guessed"。不可用平台计数=null+原因，禁 0 替代/猜值/fake source。
- `model_usage` 恰五键：prompt_tokens=0、completion_tokens=0、cost_micro_usd=0、source="zero-model-calls-by-construction"、cost_note="zero model usage does not make local compute or human time free"。
- `verify_lf_observation(path)`：重derive 全部回指，fail-closed 四码族 `LFObservationErrorCode`（`LFObservationError(ValueError)`）：`OBSERVATION_VERSION_MISSING`（版本/profile 缺失或错配）、`OBSERVATION_SOURCE_MISMATCH`（工件属另一运行/内部身份不一致）、`OBSERVATION_DIGEST_MISMATCH`（任一回指 digest/数值面被篡改）、`OBSERVATION_ARTIFACT_INVALID`（工件缺失/不可解析）。无 fallback 猜算法。
- 旧 v2 默认零变化：`build_baseline_report` 对 scanner payload 仍出 resources 三键 null，companion 在场不外溢（v13 负例钉死）。

## 6. 真人复核入口（R4）

- `expert_review.py`：`load_review_set(path)`、`validate_timing_events(events)`、`build_review_receipt(*, review_set, reviewer_id, sidecar_bytes, verdict, notes="", synthetic=False)`、`write_review_receipt(receipt, output_dir)`、`summarize_review_receipts(output_dir)`。
- 复用冻结 `ExpertTimingSession`（五键 sidecar 闭集 schema_version/run_spec_digest/reviewer_digest/active_time_ms/events；reviewer 只存 sha256；事件状态机+单调钟；sidecar 协议零改动）。`validate_timing_events` 逐事件重放冻结引擎（非法/非单调/重复/结束后事件/未终结/空序列 ⇒ `TIMING_SEQUENCE_INVALID`）并独立复算整毫秒 active time。
- verdict 词表闭集 `EXPERT_REVIEW_VERDICTS = {agree, disagree, partially-agree, needs-more-evidence}`；越表 ⇒ `VERDICT_VOCABULARY_INVALID`。
- review-set 恰 10 键：`schema_version, review_set_id, run_spec_digest, aggregate_sha256, findings_digest, findings, coverage, unreviewed, representative_result_sha256`；四个 digest 面 hex64；coverage/unreviewed 非空串；findings 为 dict 列表；违例 ⇒ `REVIEW_SET_INVALID`。
- receipt（独立版本化 schema v1，与 sidecar 分离）恰 14 键：

```
schema_version, synthetic, verdict, notes, review_set_digest,
run_spec_digest, aggregate_sha256, findings_digest, coverage, unreviewed,
reviewer_digest, active_time_ms, events_digest, sidecar_sha256
```

- `ExpertReviewErrorCode` 六码闭集（`ExpertReviewError(ValueError)`）：`REVIEW_SET_INVALID`、`TIMING_SEQUENCE_INVALID`、`VERDICT_VOCABULARY_INVALID`、`VERDICT_REVIEW_SET_MISMATCH`（sidecar 绑定另一 review set）、`EVENT_DUPLICATE`（事件集唯一性：同一 events_digest 不得绑定第二个 receipt——同 set 重交、跨 set 复用、复制 sidecar 到多 result 均拒）、`RECEIPT_INVALID`（reviewer id 与 sidecar digest 不一致/形状无效）。
- 文件名族 `expert-review-receipt-v1-NN.json`（独占写，绝不覆盖；写 receipt 永不写 sidecar 文件）。raw reviewer id 不落任何产物字节（只 sha256）。
- `summarize_review_receipts`：`{schema_version, sessions, synthetic_sessions, active_time_ms_total, reviewer_digests, verdict_counts}`；synthetic 单独计数不进人面；无真人回传 ⇒ sessions=0、active_time_ms_total=None（不伪造 0）。
- 合成事件隔离：synthetic 标记显式，仅 temp 目录；agents 不代真人计时/判断（绝对边界）。

## 7. CLI flag 面（薄 CLI，argparse）

- `scripts/run_lf_baseline.py`：`--output-dir`（必填）、`--source-root`（必填）、`--binding`（必填，JSON 文档路径）、`--machine-profile`（必填于运行时；声明式 8 字段 JSON，绝不探测主机）、`--cold-count`（int，默认 3）、`--warm-count`（int，默认 5）、`--seed`（int，默认 0）；`build_parser()` 为可编程面。
- `scripts/run_expert_review.py`：`--review-set`（必填）、`--reviewer-id`（必填）、`--output-dir`（必填）、`--verdict`（必填，choices=词表）、`--notes`（默认空）、`--synthetic`（store_true）；交互 start/pause/resume/finish 由真人按键驱动，时钟实时 `time.perf_counter_ns()`。

## 8. 纪律与零调用声明

- 新模块离线 stdlib+冻结上游只读 import；无网络/无凭据/无 ambient 读取；canonical 编码经 `lima.contracts.codec`；typed 码消息稳定。
- `model_calls` 恒 0；样本 prompt/completion/cost 恒 int 0；scoped 零调用来源="zero-model-calls-by-construction"；本地计算与真人时间的货币成本不因此为 0（提供方实收 UNKNOWN）。
- 旧入口（real_run/b1_real/b1_source/e2e）行为零变化；`lima/**`、report.py、既有 benchmarks/scripts/docs/测试零触碰。

## 9. R7 计数口径声明（强制，随报告/覆盖账携带）

- scanner 面（LF 本地基线）：期望 scanned_files=**447**（measured；skipped={'file-size-limit':7,'sensitive-config':1,'unsupported-extension':141}；truncated=False；total_bytes=2,588,042）、coverage_gap=**7**（reasons={'file-size-limit':7}，`_COVERAGE_AFFECTING_SKIPS` 七类口径——unsupported-extension/sensitive-config 不计入）。
- real-world payload 面（旧 09-28 报告）：scanned_files=**596**（另一计数口径；snapshot 全量 596 文件/13,746,820 B；9 文件>512KiB：7 入 file-size-limit、2 先命中 unsupported-extension）。
- **447 与 596 不可直接对比、不得强行对齐、不得互相冒充**；引用必须并注口径。

## 10. 已知限制与登记

- v13 两个冻结方法因测试自身缺陷受阻（非实现问题，DR `.pv_tmp/DR_IP-0043_C2_2026-10-01.md`）：缺陷 1=hyphenated outcome 字面量被冻结 `_OUTCOME_PATTERN` 拒绝；缺陷 2=guard 组对冻结引擎 unterminated/empty 两面的事实性错误断言。修正归 P&V（ALLOWED_ONCE）。
- corrupt 归档组位于缺陷 1 同方法内，v13 现无法执行到该组；实现按 §2 语义交付并以本地诊断核验（不进执行证据）。
- C-final 真实 3c+5w、真人复核包、真实目录产物归 P&V（C-final）；ER 不复现。
