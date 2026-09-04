# LIMA Coding Agent IP-0002 正式开发任务交接书

> 任务：`IP-0002 Evidence Domain`
>
> 状态：`PREPARED / AUTHORIZED WHEN BOTH IP-0002 DOCUMENTS ARE MERGED TO MAIN`
>
> 唯一施工规范：[LIMA Implementation Packet IP-0002](LIMA_Implementation_Packet_IP-0002_Evidence_Domain.md)
>
> Source Issue：[#58](https://github.com/agent-sec-labs/LIMA/issues/58)，仅完成第二个 slice
>
> 最低代码基线：`d3e73d977c33857e309cd5bc4df64310f29533b3`；实际实现基线为包含两份 IP-0002 文档的最新 `origin/main`
>
> 推荐分支：`codex/ip-0002-evidence-domain`

---

## 0. 交接书的效力与边界

本交接书已完成正式内容冻结；只有当本交接书与 IP-0002 Packet 都已合并到 `origin/main` 后，才正式授权一名 Coding Agent 实现 IP-0002。文档未合并时只允许 Review，不允许编码。

事实优先级：

1. 最新 `main` 的代码和可重复测试说明当前实现；
2. 稳定开发标准说明长期安全、流程和权限不变量；
3. 本地 `PROGRESS.md` 说明当前 NOW/NEXT、Owner 与工作树；
4. IP-0002 Packet 冻结本次目标行为、文件、symbols、wire shape、错误和测试；
5. 本交接书说明如何启动、实施、验证和离场；
6. Source Issue 只提供背景，不能扩大 Packet。

冲突时不得猜测。Agent 必须保留现场并提交 Decision Request。

---

## 1. 正式授权

文档合并后唯一授权任务：

> 在最新 `main` 上新增一个 stdlib-only、无副作用、确定性、fail-closed 的 `lima.contracts.evidence` 叶子模块，使 `Signal → SecurityIssue → VulnerabilityHypothesis → EvidenceRecord` 可以形成完整、可追溯、可版本演化的 `EvidenceDomainBundle`，并安全绑定 IP-0001 `ArtifactEnvelope`。

本次不是 Audit 生产接线，不是 Evidence Fusion 算法，不是 AEP/VEP，也不是三阶段全链路实现。

Agent 完成 IP-0002 后必须停止。不得自行领取 NEXT。

---

## 2. 开工前必须按顺序完整阅读

1. `docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md`
2. 根目录 `PROGRESS.md`
3. `docs/LIMA_Coding_Agent_IP-0002_正式开发任务交接.md`
4. `docs/LIMA_Implementation_Packet_IP-0002_Evidence_Domain.md`
5. `CONTRIBUTING.md`
6. `lima/contracts/__init__.py`
7. `lima/contracts/errors.py`
8. `lima/contracts/codec.py`
9. `lima/contracts/common.py`
10. `tests/contracts/test_errors.py`
11. `tests/contracts/test_codec.py`
12. `tests/contracts/test_common.py`
13. `tests/contracts/test_import_isolation.py`

还必须只读了解以下 legacy 边界，禁止复制或修改：

- `lima/models.py` 的 legacy `EvidenceRecord/Finding/ReviewReport`；
- `lima/adjudication.py` 的 legacy disposition；
- `lima/repository_triage.py` 的 legacy semantic triage。

Packet 必须完整阅读，不能只读摘要、测试名或本交接书。

---

## 3. 已验证的仓库事实

截至本交接书生成时：

```text
branch: main
HEAD: d3e73d977c33857e309cd5bc4df64310f29533b3
commit: feat: add deterministic artifact contract foundation (#98)
Python: 3.12.4
```

合并后验证：

```text
python -m compileall -q lima/contracts tests/contracts
exit 0

python -m unittest discover -s tests/contracts -v
39 tests / 39 passed / 0 failed / 0 skipped

python -m unittest discover -s tests
384 tests / 383 passed / 0 failed / 1 existing Windows symlink privilege skip
```

消费者验证：

- IP-0001 `ArtifactEnvelope.payload` 能承载 Evidence payload；
- payload 摘要、encode/decode 和 byte replay 稳定；
- 不需要修改 common/codec/errors；
- `lima.contracts.__all__` 和 28 个 error codes 继续保持冻结。

这些是交接时参考证据。Implementation Agent 必须在自己的干净 worktree 中重新运行 baseline，并以实际输出为准。

---

## 4. 工作树保护与隔离分支

共享根工作树包含用户未跟踪的规划和交接文件。它们不属于 IP-0002，实现者不得：

- 删除、移动、覆盖或格式化；
- `git clean`；
- `git reset --hard`；
- 未经授权 stash；
- `git add .` 或批量加入 PR；
- 在共享根工作树直接实现功能。

确认两份 IP-0002 文档均已在远端 main 后，必须基于最新远端 main 建立独立 worktree，例如：

```powershell
git fetch origin
git merge-base --is-ancestor d3e73d977c33857e309cd5bc4df64310f29533b3 origin/main
git branch --list codex/ip-0002-evidence-domain
git branch -r --list origin/codex/ip-0002-evidence-domain
git worktree add -b codex/ip-0002-evidence-domain D:\BaseAIProject\LIMA-ip-0002-wt origin/main
git -C D:\BaseAIProject\LIMA-ip-0002-wt status --short --branch
```

路径只是推荐值；若已存在，Agent 不得覆盖，必须选择新的明确路径并记录。

---

## 5. 开工前 Scope Confirmation

在任何代码编辑前，Agent 必须输出：

```text
## Scope Confirmation

Packet：IP-0002 Evidence Domain（Packet 路径；证明文档合并条件已满足）
Base commit：<完整 SHA；证明包含 d3e73d9 和两份 IP-0002 文档>
工作分支：
隔离 worktree：
允许新增文件：5 个完整路径
允许修改既有文件：0 个
外部依赖：0 个
理解的 module public API：16 个 symbols，从 lima.contracts.evidence 导入
理解的关键安全边界：D0-D2 only；D3/D4 拒绝；无 verified/clear/severity/confidence；source lineage required
理解的 Non-goals：
已运行 baseline：否（确认后立即运行）
发现的冲突或 Stop Condition：无 | <详细说明>
```

未输出 Scope Confirmation，不得编辑。

---

## 6. 唯一允许的文件范围

只允许新增：

```text
lima/contracts/evidence.py
tests/contracts/test_evidence.py
tests/contracts/test_evidence_envelope.py
tests/contracts/test_evidence_import_isolation.py
tests/contracts/fixtures/evidence_domain_bundle_v4_golden.json
```

允许修改既有文件数量：

```text
0
```

特别禁止：

- `lima/contracts/__init__.py`；
- `common.py`、`codec.py`、`errors.py`；
- IP-0001 的任何测试或 fixture；
- legacy models/adjudication/triage；
- API/service/store/queue/scanner/sandbox/frontend；
- requirements、pyproject、CI、PROGRESS；
- 任意范围外文档。

发现必须修改 forbidden 文件时立即停止。

---

## 7. 必须实现的公共 Contract

### 7.1 Module-only public API

`lima.contracts.evidence.__all__` 恰好 16 项：

```text
EVIDENCE_DOMAIN_SCHEMA_NAME
EvidenceLevel
EvidencePolarity
EvidenceSubjectKind
HypothesisStatus
RequiredProofKind
SourceLocation
EvidenceRecord
Signal
SecurityIssue
VulnerabilityHypothesis
EvidenceDomainBundle
decode_evidence_payload
encode_evidence_payload
decode_evidence_envelope
encode_evidence_envelope
```

不得修改 `lima.contracts.__all__`。

### 7.2 Domain chain

```text
Signal
  原始观察，保留 rule、analysis family、位置、fingerprint 和 D0/D1 Evidence refs

SecurityIssue
  root-cause/sink/trust-boundary 调查单元，引用一个或多个 Signal

VulnerabilityHypothesis
  对一个 SecurityIssue 的可验证安全命题，声明 invariant、proof kind、capability 和 Evidence refs

EvidenceRecord
  对 Signal/Issue/Hypothesis 的 supports/refutes 证据，保留 level、producer、independence key、lineage 和 dependency
```

### 7.3 Frozen semantics

- Evidence level wire vocabulary 为 D0–D4；
- 当前 bundle 只允许 D0/D1/D2；
- Hypothesis status 只允许 proposed、statically_supported、statically_refuted、conflicting_static_evidence、insufficient_static_evidence；
- status 必须与 Hypothesis 自身 D2 supports/refutes 组合一致；
- 所有 subject 必须有至少一个直接 Evidence；
- Evidence subject refs 必须与 subject 的 `evidence_ids` 完全相等；
- dependency 必须存在、不可 self/cycle、不可依赖更高 Evidence level；
- Issue signal refs 和 Hypothesis issue refs 必须存在；
- 所有 set-like arrays 必须已排序且唯一；Contract 拒绝而非隐式排序；
- 不生成 ID、fingerprint 或 identity digest；
- 不出现 severity、confidence、is_vulnerable、clear、verified 或 raw snippet 字段。

### 7.4 Envelope binding

- schema name 固定 `lima.evidence-domain`；
- schema version 来自 IP-0001 Envelope；
- 只允许 inline payload；
- Evidence `source_artifact_ids` 必须存在于 Envelope lineage；
- classification 不得 public；
- retention 不得 ephemeral；
- payload、bundle 和 content digest 必须一致；
- cross-tenant/snapshot/self/duplicate/conflicting lineage 继续由 IP-0001 fail closed。

字段、构造器、wire shape、数组上限、错误码优先级和 golden fixture 的完整定义以 Packet 第 8–17 节为准，不得凭本节摘要实现。

---

## 8. 明确 Non-goals

Agent 不得实现：

- legacy adapter；
- Signal qualification；
- identity/fingerprint 算法；
- root-cause clustering/dedup；
- Evidence Fusion/Adjudication；
- Repository Profile/RAM；
- AEP/VEP/RVR/Workflow/Manifest；
- Artifact Registry/blob storage；
- API/Service/DB/Queue/UI 接线；
- Mining、Repair 或 Sandbox；
- JSON Schema/Pydantic；
- D3/D4 promotion；
- 任何模型调用、网络或目标代码执行；
- GitHub Issue/Label/PR merge 操作；
- IP-0003。

---

## 9. 开工 Baseline

Scope Confirmation 后、编辑前运行：

```powershell
python -m compileall -q lima scripts tests
python -m unittest discover -s tests/contracts -v
python -m unittest -v tests.test_repository_source tests.test_task_failure
git status --short --branch
```

参考值：contracts 39 PASS；定向兼容 29 PASS。Agent 必须记录完整命令、退出码和数量。

若 baseline 失败：

1. 不修改产品代码；
2. 证明是否为 base 既有失败；
3. 无法可靠归因时提交 Decision Request；
4. 不把环境问题隐藏为测试通过。

---

## 10. 强制开发顺序

严格按 Packet 第 20 节：

1. enum/location tests 先 RED；
2. enums/validators/SourceLocation 实现；
3. 四个 domain object tests 先 RED，再实现；
4. bundle graph/status tests 先 RED，再实现；
5. 生成并验证 golden fixture；
6. Envelope tests 先 RED，再实现 binding；
7. import isolation 和 forbidden-key tests；
8. Slice Gate；
9. Compatibility/File Boundary Gate；
10. Completion Summary。

每个行为必须映射到 AC 和机器测试。不得先实现后弱化测试。

---

## 11. Frozen Golden Vector

Agent 必须逐字使用 Packet 第 17 节 fixture：

```text
file size: 3740 bytes
payload sha256: 1b313f8ce082fd1721805c4eb6d232e104dabaa9e427f9a3f4699659b3796c51
encoding: UTF-8
BOM: none
trailing newline: none
```

若实际 IP-0001 canonical codec 无法重现，属于 Stop Condition，不得更改 fixture 或 digest。

---

## 12. Acceptance Criteria

必须逐项完成：

| AC | 交付要求 |
|---|---|
| IP2-AC-01 | 16 symbols、5 enums、6 constructors exact |
| IP2-AC-02 | scalar/path/location/array/resource fail closed |
| IP2-AC-03 | golden 3740-byte canonical round-trip 和固定 digest |
| IP2-AC-04 | 完整 reference graph、subject exact binding、无 cycle/level inversion |
| IP2-AC-05 | D0-D2 static status matrix；conflict preserved；D3/D4 rejected |
| IP2-AC-06 | Envelope schema/version/payload/digest/lineage/classification/retention binding |
| IP2-AC-07 | current/future minor compatibility 与 unknown enum fail closed |
| IP2-AC-08 | 无 confidence/severity/truth/clear/verified/raw snippet fields |
| IP2-AC-09 | stdlib leaf/import isolation/no top-level API change |
| IP2-AC-10 | 5 added/0 modified/0 deps/full regression |

Packet 冻结至少 45 个新 test methods；不得减少或重命名 required tests。

---

## 13. Slice / Compatibility / Boundary Gates

### Slice Gate

```powershell
python -m compileall -q lima/contracts tests/contracts
python -m unittest discover -s tests/contracts -v
python -m ruff check lima/contracts/evidence.py tests/contracts/test_evidence.py tests/contracts/test_evidence_envelope.py tests/contracts/test_evidence_import_isolation.py
python -m bandit -q -r lima/contracts/evidence.py
git diff --check
```

### Compatibility Gate

```powershell
python -m unittest -v tests.test_repository_source tests.test_task_failure
python -m unittest discover -s tests -v
```

### File Boundary Gate

```powershell
git diff --name-only --diff-filter=ACMRTUXB origin/main...HEAD
git diff --check origin/main...HEAD
```

输出必须恰好为 5 个 allowlist 文件。任一 existing file 被修改即 NOT DONE。

### PR Gate

- 独立 Reviewer；
- required `merge-gate`；
- 只写 `Related to #58`；
- 不使用任何自动关闭 #58 的关键字；
- Agent 不自合并。

---

## 14. Stop Conditions 与 Decision Request

以下情况必须停止：

- 同名实现/Owner/branch 冲突；
- base 不包含 `d3e73d9`；
- 需要修改任一 existing/forbidden file；
- 需要新增 dependency/I/O/权限；
- Packet 对 constructor/wire/error/compatibility 有多解；
- golden bytes/digest 不可重现；
- 需要接受 D3/D4、truth boolean、severity/confidence 或削弱 graph invariant；
- baseline/回归失败无法归因；
- required tests 无法证明 AC；
- 任务实际进入 adapter/Fusion/AEP/VEP/生产接线。

必须报告：

```text
Packet/规则位置：
实际代码证据：
最小复现命令：
为什么无法在 5-file allowlist 内解决：
可选方案及影响：
Agent 建议：
```

---

## 15. Commit 与 PR 说明

推荐 commit/PR title：

```text
feat: add deterministic evidence domain contracts
```

PR 首部关联语句必须是：

```text
Related to #58
```

不要在 PR 的任何肯定、否定、注释或 checklist 中把 close/fix/resolve 类关键字与 `#58` 相邻书写。

PR 必须包含：

- Goal/Non-goals；
- 5 added / 0 modified / 0 dependencies；
- public API 和 wire semantics；
- AC → Test → Result；
- golden bytes/digest；
- 全部真实命令、退出码、pass/fail/skip；
- no production integration/no D3-D4/no top-level API change；
- Findings/Decision Requests；
- 回滚说明：删除 5 个新增文件即可，不影响 legacy runtime。

---

## 16. 强制 Completion Summary

无论 DONE、BLOCKED 或中断，都必须按 Packet 第 25 节原样输出完整 Summary。最低包含：

- base/final commit、branch、worktree；
- 5-file boundary；
- 16 public symbols；
- 10 个 AC 的测试证据；
- 真实命令、版本、exit code、pass/fail/skip；
- graph/D3-D4/Envelope/import/secret review；
- Python 3.11/3.12 的实际覆盖；
- Findings、approved decisions、open requests；
- PR 状态、唯一下一步和禁止动作。

只说“测试通过”不能交接。

---

## 17. 可直接交给 Coding Agent 的任务指令

```text
你是 LIMA IP-0002 Evidence Domain 的唯一 Implementation Agent。

必须按顺序完整阅读：
1. docs/LIMA_CODING_AGENT_DEVELOPMENT_AND_HANDOFF_STANDARD.md
2. 根目录 PROGRESS.md
3. docs/LIMA_Coding_Agent_IP-0002_正式开发任务交接.md
4. docs/LIMA_Implementation_Packet_IP-0002_Evidence_Domain.md
5. CONTRIBUTING.md
6. Packet/交接书列出的 IP-0001 contracts、tests 和 legacy 只读参考

只有在两份 IP-0002 文档已合并到 main 后才开始。基于最新 origin/main（必须包含 d3e73d977c33857e309cd5bc4df64310f29533b3、本 Packet 和正式交接书），创建独立干净 worktree 和 codex/ip-0002-evidence-domain 分支。任何编辑前先输出 Scope Confirmation，再运行 baseline。

唯一允许的变更是新增 Packet 列出的 5 个文件；允许修改既有文件为 0，外部依赖为 0。公共 API 只存在于 lima.contracts.evidence，不修改 lima.contracts.__init__、errors、codec、common 或 legacy 业务代码。

必须测试先行，实现冻结的 Signal、SecurityIssue、VulnerabilityHypothesis、EvidenceRecord、EvidenceDomainBundle 和 Envelope binding。Audit bundle 只允许 D0-D2；D3/D4、verified/clear/is_vulnerable、severity、confidence、raw snippet 均禁止。完整执行 required tests、Ruff、Bandit、全量 unittest 和 file boundary gate。

遇到同名实现、文件越界、Contract 多解、golden digest 不一致、依赖/权限扩张、无法归因的 baseline failure 或任何 Stop Condition，立即停止并提交 Decision Request。不得自行修改 Packet、Issue 或测试以绕过。

完成后按 Packet 第 25 节输出完整 Completion Summary。PR 只能写 Related to #58；不得合并自己的 PR，不得启动 IP-0003。
```

---

## 18. Maintainer 接收标准

维护者只在以下条件全部满足时接收：

- 5 个新增文件，0 个 existing modifications；
- 0 个第三方依赖和 0 个权限扩张；
- module-only 16-symbol public API；
- IP-0001 顶层 API/error/common/codec 完全不变；
- golden fixture bytes/digest 正确；
- 10 个 AC 全部有机器证据；
- 至少 45 个新增 required tests；
- D3/D4、truth/clear/severity/confidence/raw snippet negative gate 通过；
- graph、future minor、Envelope lineage/classification Gate 通过；
- Ruff、Bandit、diff check、全量回归通过；
- Completion Summary 完整；
- 独立 Review 和 `merge-gate` 通过；
- PR 未改变 #58 状态；
- 未提前实现 IP-0003 或生产接线。

---

## 19. 当前唯一下一步

> 先以独立 docs-only PR 将本交接书、IP-0002 Packet 和更新后的 `docs/DEVELOPER_HANDOFF.md` 合并到 `main`。合并并更新本地基线后，再将第 17 节任务指令交给唯一 Coding Agent；该 Agent 在独立干净 worktree 中输出 Scope Confirmation、复跑 baseline，并从第一个 RED test 开始。除此之外不启动并行实现任务。
