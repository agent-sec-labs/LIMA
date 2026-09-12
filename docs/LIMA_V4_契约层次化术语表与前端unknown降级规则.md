# LIMA V4 契约层次化术语表与前端 unknown 降级规则(CR70-03 + CR70-02 文案边界注记)

> 依据:CRDISP-1 处置表(CR70-03 层次化术语表、CR70-02 文案边界注记)。内容结构 = IP-0014 Packet §D5(冻结);全部词条清单 = Packet 附录 C(冻结,@`31449ee` 逐枚举实测,禁重编)。层次规则见文末(冻结入表)。

## 1. 静态层(evidence)

`HypothesisStatus` 五值(proposed/statically_supported/statically_refuted/conflicting_static_evidence/insufficient_static_evidence)、`EvidenceLevel` D0–D4、`EvidencePolarity` wire 仅 supports/refutes(无通用 inconclusive——消费注意事项,源自 CRDISP-1 非 CR 级 #61 条目);

## 2. 验证层(vep)

`VerificationVerdict` 四值(candidate/inconclusive/refuted_scope/verified)——与静态层不可混用:`hypothesis_not_reproduced`(SecurityOutcomeKind)≠ 已反驳(statically_refuted/refuted_scope);静态冲突五值 ≠ VEP inconclusive;

## 3. 修复验证层(rvr)

`CandidateVerdict` 三值 + `GateKind` 恰两值;**CR70-02 文案边界注记(逐字入表)**:"RVR 的'逐候选逐 Gate'以已冻结的两类**汇总 Gate**(functional_preservation / security_preservation)满足(CRDISP-1 亲验 rvr.py L229 枚举两值、L529 `len(self.gates) != 2` 强制);步骤级展示(编译/测试/PoC 逐步)不属于 #58 冻结面,归 #77/#91 后续";

## 4. 结论层(summary/workflow)

`SummarySourceKind`(chain/legacy_audit)互斥与 V5-FR-05 迁移禁映射、`SecurityOutcomeKind` 十二值与六场景映射、sealed AEP revision vs 最新 workflow revision 一致性属消费义务(#70 非 CR 级条目);

## 5. 前端 unknown 降级规则

severity 在权威 producer/API 冻结前(#90/#91/#70 后续 IP),前端一律显示 unknown/未提供,禁止从现有契约字段伪派生(CRDISP-1 CR70-01 裁定)。

## 附录:全部词条清单(Packet 附录 C 冻结,@`31449ee` 逐枚举实测)

| 层 | 枚举 | 值(逐字) |
|---|---|---|
| 静态层(evidence) | EvidenceLevel | D0, D1, D2, D3, D4 |
| 静态层 | EvidencePolarity | supports, refutes |
| 静态层 | EvidenceSubjectKind | signal, security_issue, vulnerability_hypothesis |
| 静态层 | HypothesisStatus | proposed, statically_supported, statically_refuted, conflicting_static_evidence, insufficient_static_evidence |
| 静态层 | RequiredProofKind | runtime_behavior, static_property, configuration_state, external_manual_required |
| 验证层(vep) | VerificationVerdict | candidate, inconclusive, refuted_scope, verified |
| 修复验证层(rvr) | GateKind | functional_preservation, security_preservation |
| 修复验证层 | CandidateVerdict | verified_patch, rejected, inconclusive |
| 结论层(summary) | SummarySourceKind | chain, legacy_audit |
| 结论层 | ExecutionStatus | succeeded, failed, cancelled |
| 结论层(workflow) | SecurityOutcomeKind | no_supported_attack_surface, no_actionable_hypothesis, mining_skipped_by_request, mining_skipped_by_policy, mining_blocked_environment, hypothesis_not_reproduced, vulnerability_verified, repair_unsupported, repair_blocked_environment, no_candidate_passed, verified_patch, full_chain_incomplete |

层次规则(冻结入表):静态层五值 ≠ 验证层四值,不可互换解读;`hypothesis_not_reproduced`(未复现)≠ 已反驳(statically_refuted / refuted_scope);`inconclusive` 仅存在于验证/修复验证层,静态层无通用 inconclusive(静态侧以 conflicting/insufficient 表达);legacy_audit 与 chain 结构性互斥(V5-FR-05);severity 冻结面不存在——前端一律 unknown/未提供。
