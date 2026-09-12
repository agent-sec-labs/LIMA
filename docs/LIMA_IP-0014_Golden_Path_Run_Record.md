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

- 实现基线 commit SHA(实现 Final SHA):ce11cfd0cdeb29192cfdbd5b2089e7e4dc50855c
- 环境:Windows 10 26200 + Git Bash;Python 3.12;pytest/ruff 经 `python -B -m`
- Frozen Test Commit:`ef8c1f8b2ef8eecb9c60f1663246810fec40cb37`(parent = `669267ff…`)

## 3. 逐 hop 表(Path A 链路径:profile → aep → vep → rvr → workflow/execution → CHAIN summary)

| # | artifact | payload digest(64-hex,codec 实算) | 引用核对结果 |
|---|---|---|---|
| 1 | repository_profile | ad7d53a0ed22412dbbfc60d0ed9183d7e939e2d14e4eee2d9399944cb5c4dccc | == |
| 2 | audit_evidence_package | f0a985432ebd11dc4b85897653cf443dc2c0b0312e453424648ebc2d164705d0 | == |
| 3 | vulnerability_evidence_package(source_aep → aep) | cd76622b48d11c0300e63d7489701479c75dc2f4b06cc6c4e88af1f453061d01 | == |
| 4 | repair_verification_report(source_vep → vep) | a9a35d358308a2957b9182d2ca5e503903d8c7282c6c43bb09d1680313cb2cac | == |
| 5 | plan | 9390344cd8018f450d115b085b577a7c723fb0abf214c552bd2cc9de6711851c | == |
| 6 | workflow | 3be59c6c7f1736954fbce5f1e74b4c7789ab8a1e956f4229904ea30bbe756146 | == |
| 7 | stage_attempt(attempt-profile-0001) | 34746de4860ae5ce9ec69c43ad8c8ad596d4e79172a284bf3defc1a866edb259 | == |
| 8 | run_manifest(plan/workflow/stage_attempts) | 213fbebd48a966ee9071b5a19f385731e833b17f4d8c7c653c55b2c19eaf9cd7 | == |
| 9 | security_outcome(workflow) | bfa0b2dc55940bcdadf88f8e4991adb4d762f7a8b17ded3fa8817936504ba831 | == |
| 10 | workflow_summary(typed links 全集) | 5df80cd44cf3af456d153f967508e46b8d2a0f0595b3bb306a8fe41638cd0e34 | == |

## 4. 逐 hop 表(Path B legacy 路径:ReviewReport → compat → bundle + LEGACY_AUDIT summary → round-trip)

| # | artifact | payload digest(64-hex,codec 实算) | 引用核对结果 |
|---|---|---|---|
| 1 | evidence_domain_bundle(finding_to_domain_bundle) | 39dba734b20d45bdd10ed35e32128c5bc5238145297aa5a387b32b0a10815b2e | == |
| 2 | workflow_summary(LEGACY_AUDIT/SUCCEEDED) | 84cc69eaf341d40fbb258ceba69845ae69a7aaf76342d6d9dde20158110495e0 | == |
| 3 | round-trip:domain_to_finding(…).fingerprint == 原 fingerprint ×2 | n/a(24-hex fp 恒等) | == |

## 5. 聚合 fixture 文件 SHA-256

- `tests/contracts/fixtures/integration/golden_path_chain_v4_golden.json`:fd2ca2a798c07869e8e3bc0a97d946ef928334bec7953c491459e7ed39d04736
- `tests/contracts/fixtures/integration/golden_path_legacy_audit_v4_golden.json`:984eca43f28a5bbd95bf5d25e707bfcbad18e6356d7290fe3c4da4cf698f13eb

## 6. 测试计数与 PASS 行

- `tests/contracts/test_integration_golden_path.py -v`:
```text
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_chain_round_trip_preserves_every_payload PASSED [  4%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_every_chain_artifact_decodes_via_module PASSED [  9%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_fixture_bytes_pinned_and_codec_canonical PASSED [ 13%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_fixture_digests_recomputed_by_codec_for_every_artifact PASSED [ 18%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_hop_run_manifest_references_plan_workflow_and_stage_attempt PASSED [ 22%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_hop_rvr_references_vep_digest PASSED [ 27%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_hop_security_outcome_references_workflow PASSED [ 31%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_hop_vep_references_aep_digest PASSED [ 36%]
tests/contracts/test_integration_golden_path.py::PathAChainGoldenPathTests::test_summary_typed_links_all_resolved_to_chain_digests PASSED [ 40%]
tests/contracts/test_integration_golden_path.py::PathBLegacyAuditGoldenPathTests::test_bundle_recomputed_from_legacy_finding PASSED [ 45%]
tests/contracts/test_integration_golden_path.py::PathBLegacyAuditGoldenPathTests::test_fixture_bytes_pinned PASSED [ 50%]
tests/contracts/test_integration_golden_path.py::PathBLegacyAuditGoldenPathTests::test_legacy_artifact_ids_sorted_dedup_and_typed_links_absent PASSED [ 54%]
tests/contracts/test_integration_golden_path.py::PathBLegacyAuditGoldenPathTests::test_output_digests_match_frozen_map PASSED [ 59%]
tests/contracts/test_integration_golden_path.py::PathBLegacyAuditGoldenPathTests::test_round_trip_finding_fingerprint_identity_both_inputs PASSED [ 63%]
tests/contracts/test_integration_golden_path.py::PathBLegacyAuditGoldenPathTests::test_summary_recomputed_from_review_report PASSED [ 68%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_chain_summary_missing_run_manifest_rejected PASSED [ 72%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_cross_scenario_outcome_kind_evidence_mismatch_rejected PASSED [ 77%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_legacy_audit_summary_empty_legacy_ids_rejected PASSED [ 81%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_legacy_audit_summary_with_typed_link_rejected PASSED [ 86%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_vep_source_aep_digest_bad_hex_rejected PASSED [ 90%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_vep_source_aep_digest_short_hex_rejected PASSED [ 95%]
tests/contracts/test_integration_golden_path.py::GoldenPathNegativeTests::test_vep_source_aep_major_mismatch_rejected PASSED [100%]
```
- `python -B -m pytest tests/contracts -q`:617 passed, 0F
- `python -B -m pytest tests -q`:961 passed, 1 skipped
- `python -B -m ruff check --no-cache lima/contracts tests/contracts`:All checks passed!(exit 0)

---
*骨架签发:LIMA P&V Agent(PKT-IP-0014-D2 阶段二,2026-09-12);转写义务归 IMPL-IP-0014。*
