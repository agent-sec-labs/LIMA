# LIMA IP-0014 Golden Path 运行记录(Run Record)

> 状态:阶段二骨架模板(P&V,Frozen Test Commit 随附)。字段形态冻结自
> Packet §D2;标注 TBD 的 digest/SHA/计数字段由 IMPL-IP-0014 在实现
> worktree 以运行时实测转写(禁手写 digest,测试内以 digest 对拍断言兜底)。
>
> 复现判定:第三方在干净 worktree @实现 Final SHA 重跑命令 1/2,输出与
> 本记录逐字段一致(digest 全等)。

## 1. 复现命令(逐字)

```text
python -B -m pytest tests/contracts/test_integration_golden_path.py -v
python -B -m pytest tests/contracts -q
```

## 2. 执行基线与环境

- 实现基线 commit SHA(实现 Final SHA):TBD(IMPL 转写)
- 环境:Windows 10 26200 + Git Bash;Python 3.12;pytest/ruff 经 `python -B -m`
- Frozen Test Commit:TBD(IMPL 转写完整 40 位 SHA;parent = `669267ff…`)

## 3. 逐 hop 表(Path A 链路径:profile → aep → vep → rvr → workflow/execution → CHAIN summary)

| # | artifact | payload digest(64-hex,codec 实算) | 引用核对结果 |
|---|---|---|---|
| 1 | repository_profile | TBD | == |
| 2 | audit_evidence_package | TBD | == |
| 3 | vulnerability_evidence_package(source_aep → aep) | TBD | == |
| 4 | repair_verification_report(source_vep → vep) | TBD | == |
| 5 | plan | TBD | == |
| 6 | workflow | TBD | == |
| 7 | stage_attempt(attempt-profile-0001) | TBD | == |
| 8 | run_manifest(plan/workflow/stage_attempts) | TBD | == |
| 9 | security_outcome(workflow) | TBD | == |
| 10 | workflow_summary(typed links 全集) | TBD | == |

## 4. 逐 hop 表(Path B legacy 路径:ReviewReport → compat → bundle + LEGACY_AUDIT summary → round-trip)

| # | artifact | payload digest(64-hex,codec 实算) | 引用核对结果 |
|---|---|---|---|
| 1 | evidence_domain_bundle(finding_to_domain_bundle) | TBD | == |
| 2 | workflow_summary(LEGACY_AUDIT/SUCCEEDED) | TBD | == |
| 3 | round-trip:domain_to_finding(…).fingerprint == 原 fingerprint ×2 | n/a(24-hex fp 恒等) | == |

## 5. 聚合 fixture 文件 SHA-256

- `tests/contracts/fixtures/integration/golden_path_chain_v4_golden.json`:TBD(IMPL 转写)
- `tests/contracts/fixtures/integration/golden_path_legacy_audit_v4_golden.json`:TBD(IMPL 转写)

## 6. 测试计数与 PASS 行

- `tests/contracts/test_integration_golden_path.py -v`:TBD(逐行 PASS 输出,IMPL 转写;类别 Path A ≥8 / Path B ≥5 / 负例 ≥6)
- `python -B -m pytest tests/contracts -q`:TBD(预期 585+N passed,0F;N 由 Frozen Test Commit 钉死)
- `python -B -m pytest tests -q`:TBD(预期 929+N passed, 1 skipped)
- `python -B -m ruff check --no-cache lima/contracts tests/contracts`:TBD(预期 exit 0)

---
*骨架签发:LIMA P&V Agent(PKT-IP-0014-D2 阶段二,2026-09-12);转写义务归 IMPL-IP-0014。*
