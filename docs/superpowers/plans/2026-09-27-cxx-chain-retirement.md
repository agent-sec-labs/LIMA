# C++ Legacy Detection Chain Retirement Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 从 LIMA 主线移除已经被智能体检测平台替代的 C++ legacy 七角色检测链及其专属资产，同时保持 C++ 静态检测、平台整仓检测、UAF 仪器和 V4 报告预览的现有行为。

**Architecture:** 先切断 legacy 的生产消费者并让 capabilities 反映真实能力，再把共享模块收缩为平台仍使用的预算、JSON 边界和路径校验原语，最后删除无消费者的实现、测试、fixtures、评测数据和 CI job。C++ PR/diff 智能体审查随 legacy 链暂时下线，通用 Python PR 审查保持不变；后续由平台链的 `diff-only` 模式重新接入。

**Tech Stack:** Python 3.11/3.12、`unittest`、GitHub Actions、Docker、ruff、现有 LIMA V4 contracts。

**Spec:** Legacy 原始设计见 `docs/superpowers/specs/2026-09-02-cxx-llm-agent-detection-design.md`；替代平台见 `docs/superpowers/plans/2026-09-12-agent-vuln-platform.md`。

## Global Constraints

- 分析基线为 `main@45a7ec7`；执行前必须从最新 `origin/main` 新建 `codex/retire-legacy-cxx-chain` 并重新跑引用核查。
- 只退役 legacy 七角色链、其 C++ PR 接线、legacy 评测资产，以及零生产调用的 `agent_patch`/RVR 预览适配。Python 扫描、通用 Python PR 审查、修复体系、实验平台、contracts 核心、evidence privacy 和 baseline 体系不得改变行为。
- 完整保留 Sidecar 静态检测、平台整仓主链、UAF 仪器和 `collaboration.platform.v4` 报告内预览；本计划不把报告预览升级为独立 Artifact 存储。
- `LIMA_CXX_AGENT_MODE` 和 `LIMA_CXX_AGENT_MODEL` 名称不变。保留 `MAX_CALLS`、`MAX_CONTEXT_FILES`、`MAX_CONTEXT_LINES`、`MAX_OUTPUT_BYTES`、`TIMEOUT_SECONDS`、`PARALLELISM`、`DIALOGUE_ROUNDS`；本次只删除 legacy 专属的 `MAX_CANDIDATES`。
- `TIMEOUT_SECONDS`、`PARALLELISM`、`DIALOGUE_ROUNDS` 当前未完整传入 `run_platform_review()`；本退役 PR 不顺带改变其默认调用行为，另开独立任务修复。
- C++ PR/diff 智能体审查下线是显式兼容性变化：`capabilities.cxx_agent.pull_request_scan` 必须返回 `false`，通用 Python PR 审查仍须成功。
- 删除 `patch_outcome_to_rvr` 是显式公共 Python 符号收缩；核心 V4 contract 类型不删除，并以独立提交实施。
- 不修改或清理执行工作区中与本计划无关的未跟踪文件。

## Review Focus

- `off`、`auto`、`required` 三种模式只能运行平台链一次，不得残留双链 LLM 调用或改变 required 的 fail-closed 语义。
- 删除 C++ PR 注入后，Python PR 审查仍只提交一次结果，且 capabilities 不得继续宣称支持 C++ PR 扫描。
- `CxxAgentBudget` 的调用数、上下文和输出扣费语义不得因工具 registry 删除而变化。
- `cxx_memory.bind_tool_evidence()` 仍须接受结构兼容候选对象，不能为保留静态检测而保留整个 legacy candidate 合同。
- 定时/手动 CI、Docker test image 和活跃文档不得引用已删除的 legacy 评测脚本、数据集或 fixtures。

---

## 1. Retirement Decisions

PR #183 历史上带入了 legacy 七角色链和后来的平台主链。当前扫描器会在同一模式下运行两条 LLM 链；本计划落实平台单链裁决，移除一整条额外调用链。实际费用下降取决于候选数、弃权和预算，不宣称固定减半。

术语：

- **C++ 静态检测**：Sidecar 内 Semgrep、clang、ASan 三层扫描，对应 `cxx_analyzer/` 和 `lima/cxx_memory.py`。
- **平台主链**：`agent_orchestrator.py` + `agent_scout.py` 的 Scout、Specialist、实验、Critic、冻结 Arbiter。
- **legacy 链**：`cxx_agents.py` 的 Planner、三个 Specialist、Critic、Evidence、Verifier、Arbiter。
- **UAF 仪器**：CWE-416 的事实抽取、P1-P7 证明、broker 和语义通道。

明确删除：legacy 整仓链、legacy C++ PR 注入、legacy 符号索引/检索/工具/LLM 协议、legacy 评测资产、零生产调用补丁流及其 RVR 预览转换器。

## 2. Final Shared Boundaries

- `lima/cxx_agent_tools.py` 仅保留 `AgentBudgetExceeded`、`RemainingBudget`、`CxxAgentBudget` 及其内部计量结构；删除所有依赖 `CxxContextIndex` 的工具 registry。
- `lima/cxx_agent_models.py` 仅保留 `parse_untrusted_json`、`_bounded_text`、`_hex_digest`、`_safe_relative_path` 及必要私有依赖。`AGENT_MODES` 和 `MODE_OFF` 实际属于 `agent_scout.py`，不迁入本文件。
- `lima/cxx_llm.py` 仅保留 `unwrap_fenced_json`。
- `lima/cxx_retrieval.py` 仅保留 `_validate_changed_path`；legacy 删除后 `RetrievalBudget` 没有生产消费者，一并删除。

## 3. File Map

### Delete

- `lima/cxx_agents.py`
- `lima/cxx_context.py`
- `lima/agent_patch.py`
- `scripts/run_cxx_llm_agent_evaluation.py`
- `evaluation_data/cxx_llm_agent_cases.json`
- `tests/test_cxx_agents.py`
- `tests/test_cxx_context.py`
- `tests/test_cxx_agent_integration.py`
- `tests/test_cxx_llm_agent_evaluation.py`
- `tests/test_agent_patch.py`
- `tests/fixtures/cxx_agent_context/`
- `tests/fixtures/cxx_llm_agent/`
- `tests/fixtures/patch_flow/`

### Trim

- Runtime/shared: `lima/cxx_agent_tools.py`, `lima/cxx_agent_models.py`, `lima/cxx_llm.py`, `lima/cxx_retrieval.py`, `lima/repository_scanner.py`, `lima/service.py`, `lima/platform_contracts.py`, `lima/report.py`, `lima/config.py`。
- Tests: `tests/test_cxx_agent_tools.py`, `tests/test_cxx_agent_models.py`, `tests/test_cxx_llm.py`, `tests/test_cxx_retrieval.py`, `tests/test_cxx_memory.py`, `tests/test_agent_orchestrator.py`, `tests/test_platform_contracts.py`, `tests/test_service.py`, `tests/test_config.py`。
- CI/image/docs: `.github/workflows/ci.yml`, `tests/test_ci_contract.py`, `Dockerfile`, `.env.example`, `docker-compose.yml`, `README.md`, `docs/CXX_LLM_AGENT_ANALYSIS.md`, `docs/AGENT_VULN_PLATFORM.md`, `docs/competition/技术说明书.md`, `docs/competition/使用说明书.md`, `deploy/competition/README.md`。

## 4. Implementation Tasks

### Task 1: Remove legacy production entry points and make capabilities honest

**Files:**
- Modify: `lima/repository_scanner.py`
- Modify: `lima/service.py`
- Modify: `lima/report.py`
- Modify: `tests/test_agent_orchestrator.py`
- Modify: `tests/test_service.py`

**Interfaces:**
- Consumes: `RepositoryScanner._run_platform_branch(...)` and the generic `ReviewHarness` PR path.
- Produces: repository scans invoke only `_run_platform_branch`; `repository_scan_capabilities()["cxx_agent"]["pull_request_scan"]` is `False`.

- [ ] **Step 1: Add failing single-chain and capabilities tests**

  Extend `ScannerSingleChainTests` to require `_run_platform_branch` and reject `_run_cxx_agent_branch`, `_cxx_agent_collaboration`, `_agent_finding` and the `collaboration["cxx_agent"]` report branch. Extend `ServiceTests` to assert `pull_request_scan is False`, `repository_scan == (mode != "off")`, and a normal Python PR review succeeds without `_CxxAgentMergeReviewer`.

- [ ] **Step 2: Run focused tests and confirm RED**

  Run: `python -m unittest tests.test_agent_orchestrator.ScannerSingleChainTests tests.test_service.ServiceTests -v`

  Expected: FAIL because legacy repository/PR paths and `pull_request_scan=true` still exist.

- [ ] **Step 3: Remove repository-scan legacy wiring**

  Delete `_run_cxx_agent_branch`, `_cxx_agent_collaboration`, `_agent_finding`, `_legacy_all_roles_failed_error`, their imports/constructor arguments, the `scan()` invocation, legacy-only metrics and `collaboration.cxx_agent`. Preserve `_run_platform_branch`, `_seal_platform_v4`, Sidecar fusion and platform findings.

- [ ] **Step 4: Remove only the C++ PR injection path**

  Delete `_CxxAgentMergeReviewer`, `_review_pull_request_snapshot`, legacy C++ merge preparation and C++-specific PR metrics/imports. Preserve generic Python reviewer selection, canary/evolved reviewer behavior, single-result persistence, GitHub materialization used elsewhere and all public PR endpoints.

- [ ] **Step 5: Update capabilities and report rendering**

  Keep the `cxx_agent` capability key for compatibility, redefine it as the platform repository chain, set `pull_request_scan=False`, and remove only the legacy collaboration renderer.

- [ ] **Step 6: Verify and commit**

  Run: `python -m unittest tests.test_agent_orchestrator.ScannerSingleChainTests tests.test_service -v`

  Expected: PASS.

  Commit: `git commit -s -m "refactor: retire legacy cxx runtime entry points"`

### Task 2: Collapse shared modules to the platform primitive set

**Files:**
- Delete: `lima/cxx_agents.py`, `lima/cxx_context.py`
- Modify: `lima/cxx_agent_tools.py`, `lima/cxx_agent_models.py`, `lima/cxx_llm.py`, `lima/cxx_retrieval.py`
- Delete: `tests/test_cxx_agents.py`, `tests/test_cxx_context.py`, `tests/test_cxx_agent_integration.py`, `tests/fixtures/cxx_agent_context/`
- Modify: `tests/test_cxx_agent_tools.py`, `tests/test_cxx_agent_models.py`, `tests/test_cxx_llm.py`, `tests/test_cxx_retrieval.py`, `tests/test_cxx_memory.py`, `tests/test_agent_orchestrator.py`

**Interfaces:**
- Produces: existing signatures for `CxxAgentBudget`, `AgentBudgetExceeded`, shared JSON/bounded-text/path helpers, `unwrap_fenced_json` and `_validate_changed_path`.
- Removes: `CxxAgentCoordinator`, `CxxAgentCandidate`, `CxxLLMClient`, `AgentStep`, `CxxContextIndex`, `RetrievalBudget`, retrieval runs and tool registries.

- [ ] **Step 1: Add failing primitive-surface tests**

  Assert removed public names are absent while retained names remain importable. In `test_cxx_memory.py`, replace `CxxAgentCandidate` with a local frozen dataclass exposing `candidate_id`, `cwe`, `path`, `line` and `symbol`, proving `bind_tool_evidence()` is structurally typed.

- [ ] **Step 2: Run primitive tests and confirm RED**

  Run: `python -m unittest tests.test_cxx_agent_tools tests.test_cxx_agent_models tests.test_cxx_llm tests.test_cxx_retrieval tests.test_cxx_memory -v`

  Expected: FAIL while legacy exports and imports remain.

- [ ] **Step 3: Trim `cxx_agent_tools.py` to budget accounting**

  Keep budget exception, remaining-budget snapshots, charge methods and output/context accounting. Delete context/index imports, tool payload dataclasses, handler factories, review/evidence registries and exports. Retain only budget tests; delete registry/symbol/snippet/type/evidence/prompt-injection test classes.

- [ ] **Step 4: Trim models, LLM and retrieval**

  Models retain only the four shared parsing/path helpers and private dependencies. LLM retains only `unwrap_fenced_json`. Retrieval retains only `_validate_changed_path`; replace its old suite with valid-path and traversal-rejection tests.

- [ ] **Step 5: Delete legacy coordinator/index and compatibility tests**

  Delete the listed modules/tests/fixture and remove `LegacyCwe416IsolationTests`. Preserve `DiffOnlyTests`, `ScannerSingleChainTests`, `ScannerPlatformBranchTests` and all other platform classes.

- [ ] **Step 6: Verify retained platform/static behavior**

  Run: `python -m unittest tests.test_cxx_agent_tools tests.test_cxx_agent_models tests.test_cxx_llm tests.test_cxx_retrieval tests.test_cxx_memory tests.test_agent_scout tests.test_agent_repro_tools tests.test_agent_orchestrator tests.test_uaf_llm_branch tests.test_uaf_models -v`

  Run: `python -c "import lima.agent_orchestrator, lima.agent_scout, lima.repository_scanner, lima.service, lima.cxx_memory, lima.uaf_orchestrator"`

  Expected: both exit 0.

- [ ] **Step 7: Commit**

  Commit: `git commit -s -m "refactor: reduce cxx agent modules to shared primitives"`

### Task 3: Retire legacy evaluation assets and CI job

**Files:**
- Delete: `scripts/run_cxx_llm_agent_evaluation.py`, `evaluation_data/cxx_llm_agent_cases.json`, `tests/test_cxx_llm_agent_evaluation.py`, `tests/fixtures/cxx_llm_agent/`
- Modify: `.github/workflows/ci.yml`, `tests/test_ci_contract.py`, `Dockerfile`

**Interfaces:**
- Produces: CI retains Sidecar, platform and UAF jobs but no `cxx-llm-agent-evaluation` job.

- [ ] **Step 1: Add failing CI/image retirement assertions**

  Assert CI and Dockerfile contain neither `cxx-llm-agent-evaluation` nor `run_cxx_llm_agent_evaluation.py`; assert `cxx-sidecar-integration`, `run_platform_evaluation.py`, `run_uaf_v2_evaluation.py` and `merge-gate` remain.

- [ ] **Step 2: Run and confirm RED**

  Run: `python -m unittest tests.test_ci_contract -v`

  Expected: FAIL because the job and Docker COPY still exist.

- [ ] **Step 3: Delete the legacy evaluation surface**

  Delete script, cases, test and fixture. Remove the complete scheduled/manual legacy job. Remove only the legacy script from Dockerfile line 70; preserve platform/UAF scripts and keep `cxx-sidecar-integration` in `merge-gate.needs`.

- [ ] **Step 4: Verify and commit**

  Run: `python -m unittest tests.test_ci_contract tests.test_container_read_only -v`

  Expected: PASS.

  Commit: `git commit -s -m "ci: retire legacy cxx agent evaluation"`

### Task 4: Remove unused patch flow and RVR preview adapter

**Files:**
- Delete: `lima/agent_patch.py`, `tests/test_agent_patch.py`, `tests/fixtures/patch_flow/`
- Modify: `lima/platform_contracts.py`, `tests/test_platform_contracts.py`

**Interfaces:**
- Removes: `PatchFlowOutcome`, `suggest_patch_flow`, `patch_outcome_to_rvr`.
- Preserves: finding-to-VEP, review-to-AEP, WorkflowSummary, `seal_platform_review` and privacy helpers.

- [ ] **Step 1: Add a failing retired-surface assertion**

  Require `patch_outcome_to_rvr` to be absent while AEP/VEP/WorkflowSummary sealing remains importable. Remove tests whose only subject is `PatchFlowOutcome`; rewrite `PlatformGoldenPathTests` to end at the sealed AEP/VEP/WorkflowSummary chain.

- [ ] **Step 2: Run and confirm RED**

  Run: `python -m unittest tests.test_platform_contracts -v`

  Expected: FAIL while RVR is exported.

- [ ] **Step 3: Delete patch implementation and adapter**

  Delete patch files/fixtures, the `PatchFlowOutcome` import, `patch_outcome_to_rvr`, T3-only helpers and its `__all__` entry. Do not edit core types under `lima/contracts/`.

- [ ] **Step 4: Verify and commit separately**

  Run: `python -m unittest tests.test_platform_contracts tests.test_evidence_privacy -v`

  Expected: PASS.

  Commit: `git commit -s -m "refactor: remove unused cxx patch preview flow"`

### Task 5: Remove legacy-only configuration and update active docs

**Files:**
- Modify: `lima/config.py`, `tests/test_config.py`, `.env.example`, `docker-compose.yml`
- Modify: `README.md`, `docs/CXX_LLM_AGENT_ANALYSIS.md`, `docs/AGENT_VULN_PLATFORM.md`, `docs/competition/技术说明书.md`, `docs/competition/使用说明书.md`, `deploy/competition/README.md`

**Interfaces:**
- Removes: `Settings.cxx_agent_max_candidates` and `LIMA_CXX_AGENT_MAX_CANDIDATES`.
- Preserves: mode/model/budget and documented timeout/parallelism/dialogue compatibility settings.

- [ ] **Step 1: Update configuration tests first**

  Remove max-candidates assertions and assert retained mode, model, budget, timeout, parallelism and dialogue settings still parse configured values.

- [ ] **Step 2: Remove max-candidates surfaces**

  Delete the dataclass field, validation entry, environment parser, `.env.example` line and Compose pass-through. Do not wire or delete the three documented-but-not-yet-connected platform controls in this PR.

- [ ] **Step 3: Rewrite active documentation**

  Replace the README legacy role sequence with the platform sequence. Add a retirement banner to `CXX_LLM_AGENT_ANALYSIS.md` and mark its commands/results historical. Remove patch-suggestion, legacy evaluation and C++ PR scan claims from active competition/deployment docs; document `pull_request_scan=false` and the diff-only backlog.

- [ ] **Step 4: Verify and commit**

  Run: `python -m unittest tests.test_config tests.test_service tests.test_ci_contract -v`

  Expected: PASS.

  Commit: `git commit -s -m "docs: publish platform-only cxx detection topology"`

### Task 6: Residual audit, fingerprint refresh and full verification

**Files:**
- Modify only if required: `evaluation_data/popular_external_calibration_v2.json`
- Verify: every changed file from Tasks 1-5

**Interfaces:**
- Produces: a merge-ready branch with no active legacy consumers or dangling assets.

- [ ] **Step 1: Run scoped residual audit**

  Search `lima/`, `tests/`, `scripts/`, `.github/`, Dockerfile, README and active operational docs for `CxxAgentCoordinator|CxxLLMClient|CxxContextIndex|PatchFlowOutcome|to_agent_finding_payload|LEGACY_AGENT_CWES|retrieve_repository|retrieve_pull_request|run_cxx_llm_agent_evaluation`.

  Expected: zero active references. Exclude historical specs/plans and this retirement record from the zero-residual rule.

- [ ] **Step 2: Run static checks**

  Run: `python -m ruff check lima tests scripts`

  Run: `git diff --check`

  Expected: both exit 0.

- [ ] **Step 3: Run full host suite**

  Run: `python -m unittest discover -s tests -v`

  Expected: PASS. If current main still has Windows-only failures, record exact test IDs and error signatures before editing and require the post-change set to be identical; unnamed failure exemptions are not accepted.

- [ ] **Step 4: Refresh only permitted fingerprint if required**

  Only when the calibration test reports the expected scanner fingerprint drift, update `calibration_analyzer_sha256` in `evaluation_data/popular_external_calibration_v2.json`. Do not change holdout fingerprints or metrics.

- [ ] **Step 5: Run container and capabilities acceptance**

  Build the Docker test image and run repository/platform targets inside it. Verify capabilities under `off`, `auto`, `required`: Sidecar unchanged, platform repository scan accurate, `pull_request_scan=false`, `automatic_repair=false`.

- [ ] **Step 6: Push and require named CI gates**

  Require Linux/Windows unit matrices, frontend, container read-only, security/fix constraints, E2E, `cxx-sidecar-integration` and `merge-gate`. Do not require a fixed total count after deleting the optional evaluation job.

- [ ] **Step 7: Simulate merge against current main**

  Fetch `origin/main`, run merge-tree or an isolated merge simulation, then repeat residual/import checks if main added C++ references.

- [ ] **Step 8: Commit a fingerprint-only change when needed**

  Commit: `git commit -s -m "test: refresh cxx analyzer calibration fingerprint"`

  Skip when no fingerprint changed.

## 5. Acceptance Criteria

- Repository scans execute exactly one LLM detection chain: the platform chain.
- Sidecar findings、平台 findings、UAF evidence 和 V4 报告预览保持基线语义。
- `LIMA_CXX_AGENT_MODE=auto|required` 平台测试通过，默认调用行为不因本次退役改变。
- 通用 Python PR review 仍成功；C++ PR 扫描不再宣称可用，`pull_request_scan=false`。
- 活跃 runtime、tests、CI、Docker 和运维文档不存在指向已删除模块/资产的引用。
- 共享原语通过 focused tests，保留的 `lima.*` 模块全部可导入。
- `cxx-sidecar-integration` 仍是 `merge-gate` 硬依赖。
- 所有具名必过 CI job 成功，不按固定检查数量验收。
- 全量 host 测试通过，或只有逐项记录且与修改前完全一致的基线失败。
- PR 描述明确列出 C++ PR 能力下线和 `patch_outcome_to_rvr` 公共符号移除。

## 6. Risks and Rollback

- **混合测试误删：** 按测试类名保留平台/静态测试，每个任务后跑 targeted suite。
- **配置兼容：** 暂留平台相关环境变量，即使其中三个当前接线不完整；另开任务修复。
- **main 前进：** 合并前重新跑 import/reference audit 和 merge simulation。
- **外部使用 RVR：** Task 4 独立提交，可单独 revert 而不恢复七角色链。
- **临时需要 C++ PR 扫描：** revert Task 1 或加速平台 `diff-only` adapter，不重新开启 legacy 整仓链。
- **整体回退：** 合并前废弃 feature branch；合并后 revert 退役 PR 的 merge commit。若要求单提交回退，PR 必须使用 merge commit。

## 7. Follow-up Work Outside This Plan

- 将 `LIMA_CXX_AGENT_TIMEOUT_SECONDS`、`PARALLELISM`、`DIALOGUE_ROUNDS` 显式接入平台生产调用，并单独验证行为和费用变化。
- 通过 `run_platform_review(..., source_mode="diff-only")` 恢复 C++ PR/diff 审查；端到端测试通过前不恢复 `pull_request_scan=true`。
- C0.1 以注册表驱动 orchestrator 词表，独立完成 #186；本计划后重新评估 #187。
- `review_uaf` 及冻结评测仅在 main V4 baseline 体系完成替代后退役。
