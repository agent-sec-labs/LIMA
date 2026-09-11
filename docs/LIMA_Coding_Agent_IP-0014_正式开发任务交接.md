# LIMA Coding Agent IP-0014 正式开发任务交接(closure IP:跨 Artifact 集成 + 真实 Golden Path + Closure Audit + 文档面三项)

> 交接对象:唯一 Implementation Agent(IMPL-IP-0014,由 Coordinator 派发后生效)
> 正本:`docs/LIMA_Implementation_Packet_IP-0014_Closure_Integration_Audit.md`(设计冻结权威,本文与其冲突以 Packet 为准)
> 基线:origin/main = 含本交接书与 Packet 的合并提交;上游锚定基线 `31449ee2c05a08c0ab8e8070d66d30016071ad1e`(IP-0013 squash 后)

## 1. 你要交付什么

恰好 8 个新增文件(Packet §D7):

```text
tests/contracts/test_integration_golden_path.py        # Path A 链 + Path B legacy + 负例
tests/contracts/test_integration_cross_module.py       # §D1 矩阵 M1..M9
tests/contracts/fixtures/integration/golden_path_chain_v4_golden.json
tests/contracts/fixtures/integration/golden_path_legacy_audit_v4_golden.json
docs/LIMA_IP-0014_Golden_Path_Run_Record.md            # 字段形态 Packet §D2
docs/LIMA_IP-0014_Closure_Record.md                    # 模板 Packet 附录 A(20 行 + 17 gates)
docs/LIMA_V4_契约层次化术语表与前端unknown降级规则.md    # 词条 = Packet 附录 C;含 CR70-02 注记(逐字)
docs/LIMA_DR_CR61-02_D2状态矩阵语义勘误.md              # 逐字 = Packet 附录 B
```

## 2. 你不能做什么

- 零 Modify:十四模块、schemas/v4、既有任何测试/fixture/scenario、`lima/models.py`、frontend/、pyproject.toml、Dockerfile、`.github/`;
- 零新模块、零新 schema、零新错误码、零 wire 变更;digest 一律经 `lima.contracts.codec.compute_content_digest`(FR-04);
- 不关闭 #58;PR 正文禁任何 auto-close 关键字(用 `Related to #58`);
- 不实现生产接线(#68)或任何下游 Issue;RAM 图/Oracle 建议/severity 归各 owner 后续 IP(CRDISP-1)。

## 3. 关键技术口径(Packet 已冻结,此处速览)

- `decode_*_payload(value, *, schema_version=SchemaVersion(4, 0))`;`encode_*_payload(domain) -> dict`;digest = `compute_content_digest(canonical_encode(payload))`;
- digest 链核心断言:`digest(aep payload) == vep.source_aep.content_digest`、`digest(vep payload) == rvr.source_vep.content_digest`、summary typed links 同式对拍;
- 已知边界(勿误报缺陷):同格式合法伪造 64-hex 填 source digest,payload 层 decode 不拒绝——存在性核对是你的测试义务,不是契约缺陷;
- 聚合 fixture 字节钉死;全部内部 digest 由 codec 实算,运行记录禁手写 digest;
- 预期数字:`tests/contracts` = 585+N(0F)、全量 = 929+N passed + 1 skipped、`python -B -m ruff check --no-cache lima/contracts tests/contracts` exit 0(N ≥ 20,精确值以 Frozen Test Commit 为准)。

## 4. 流程(lifecycle §9.1/§12.2)

1. 阅读稳定标准、lifecycle、Implementation Agent 责任书、Packet 正本、本文、CONTRIBUTING.md;
2. 确认两份 IP-0014 docs 已在 `origin/main`;从 Frozen Test Commit(Coordinator 在 IMPL Assignment 指定 SHA)派生 `codex/ip-0014-closure-integration` 独立干净 worktree;
3. Scope Confirmation(§D6 十四面零漂移表逐项复验 + 8 个 Add 文件不存在)→ baseline(§D8 命令)→ 实现 → Completion Summary;
4. 任何与冻结面冲突/两解/不可达 → 停,提交 Decision Request,不私改。

## 5. Completion Summary 必含

Final SHA、8 文件清单(逐文件行数)、全部验收命令与实测输出(585+N/929+N+1s/ruff 0)、聚合 fixture SHA-256 ×2、Golden Path 逐 hop digest 表、Closure Record 审读结论(20 行)、确认未修改范围外文件。

---

*签发:LIMA P&V Agent,2026-09-12;上游基线 `31449ee2c05a08c0ab8e8070d66d30016071ad1e`。*
