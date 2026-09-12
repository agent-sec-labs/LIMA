# LIMA Coding Agent IP-0013 正式开发任务交接:PR4 Legacy Adapter

> 交接对象:唯一 Implementation Agent(阶段二 Frozen Test Commit 合并后启动)
>
> 权威文档:本交接书 + `docs/LIMA_Implementation_Packet_IP-0013_PR4_Legacy_Adapter.md`(Packet 正本,设计已冻结单解)
>
> 前置:两份 IP-0013 文档均已合并 `origin/main`;阶段二 Frozen Test Commit 已由 P&V 交付并指明 SHA

## 1. 你要交付什么

按 Packet §D6 文件清单,恰好 9 个新文件:`lima/contracts/compat.py`、3 个测试文件、5 个 fixture。零修改既有面(十三模块、`lima/models.py`、PR3 产物、场景 fixture、既有测试、`contracts/__init__.py`、Dockerfile、pyproject.toml 全部禁改)。

## 2. 必须先读(顺序)

1. `CONTRIBUTING.md`、稳定标准、lifecycle、Implementation Agent 责任书;
2. IP-0013 Packet 正本**全文**(尤其 §7-§D9:依赖方向、逐字段映射表、错误映射、V5-FR-05 接线、测试矩阵、命令与预期数字);
3. `lima/models.py`(只读,理解 fingerprint 材料与 __post_init__ 派生)、`lima/contracts/evidence.py` 与 `summary.py`(只读,冻结词表)、`docs/adr/0027-version-compatibility-policy.md`。

## 3. 硬性口径(最易错点)

- compat 依赖方向**只允许** import:codec/common/errors/evidence/summary(后两者只读类型)+ `lima.models`(只读);禁止其余一切(summary 纳入的依据见 Packet §7 偏差登记);
- payload 层单解:不构造 ArtifactEnvelope、不做 lineage 检查;
- identity 派生逐字符口径:`d = sha256("%s\0%s\0%s\0%s" % (rule_id, path, line, evidence).encode()).hexdigest()`,id = `sig-/issue-/ev-` + `d[:12]`(ev 再加 `-NNN`);
- 哨兵字面量逐字符:`LEGACY_REASON_CODE="LEGACY_MIGRATED"`、`LEGACY_SOURCE_ARTIFACT_ID="legacy-finding"`、`LEGACY_SENTINEL="legacy-finding"`(root_cause_class/sink_identity/trust_boundary 三处)、反向 `source="legacy-adapter"`、`fix="unmapped:fix"`、`test="unmapped:test"`、`title=f"migrated:{issue_id}"`、severity 恒 LOW、cwe 取 `min(cwe_ids) or ""`;
- `review_report_to_workflow_summary` 恒 `source=legacy_audit`、`execution_status=succeeded`、`legacy_artifact_ids=sorted(set(fingerprints))`;空 findings 拒绝;
- lossy/unsupported 只能落 Packet §8/§9 冻结的显式降级(UNMAPPED frozenset 两份)或显式失败(§D4 错误表),禁止静默丢弃、禁止改契约消 gap;
- 错误码只用既有 29 codes,field_path 按 §D4 表。

## 4. 验收命令(在交付 worktree 内执行;预期数字 N 以 Frozen Test Commit 钉死值为准)

```text
python -m pytest tests/contracts -q    # 527+N passed
python -m pytest tests -q              # 871+N passed, 1 skipped
python -m ruff check --no-cache lima/contracts/compat.py tests/contracts/test_compat*.py   # exit 0
```

## 5. 分支与流程

依 lifecycle §9.1 从 Frozen Test Commit 派生 `codex/ip-0013-legacy-adapter` 独立干净 worktree;输出 Scope Confirmation 后先跑 baseline(527 / 871+1 skip)再动工;任何两解、冻结测试需变更、需改既有契约才能自洽——立即停,提交 Decision Request(`.pv_tmp/` 文件 + 回报双通道),保留现场。PR 正文 `Related to #58`,禁 auto-close 关键字。Completion Summary 须含:逐文件清单、实际 N 与命令输出摘要、round-trip 恒等式证据、golden digest 清单。

## 6. Stop Conditions

Packet §12 逐字有效;另:阶段二冻结测试与 Packet §D7 类别出现覆盖缺口时不自行改测试,停下提 DR。
