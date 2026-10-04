# OpenHarmony 已知漏洞双版本验证闭环实施计划

> **执行说明：** 实施时使用 `superpowers:executing-plans`（Native）或
> `superpowers:subagent-driven-development`（逐任务独立实现与复核）。每完成一个任务，
> 运行该任务的目标测试并提交一次；不得把真实环境未运行写成“已验证”。

> **开工前置：** 在独立分支或工作树上执行本计划；开工前 main 工作区必须干净
> （既有未提交改动先提交或挪走），本计划的提交不得混入无关变更。

**Goal:** 用一个公开、可构建、能由现有 UAF facts 链自动产生候选的 CWE-416 已知漏洞
建立首个真实闭环：
同一 PoC 在脆弱提交上稳定触发，在修复提交上稳定不触发，并输出可核验的源码、运行、
CWE/CVE、影响范围和修复证据包。案例冻结为**上游 libexpat**（CVE-2022-43680，脆弱
`5ac714074d2639e0b8bb82aa73ef51c4f7498d29` / 修复 `56967f83d68d5fc750f9e66a9a76756c94c7c173`，
即 OpenHarmony third_party_expat 同源组件的上游仓库）：预研实证 OH 镜像的
`BUILD.gn` 全历史未启用 `XML_DTD`，漏洞代码在 OH 实际构建配置下不存在（见
rejection ledger），故案例锚定上游默认构建（外部实体支持开启，与上游发布和发行版
构建一致）。报告必须如实披露：该 CVE 在 OH 镜像的构建配置下不受影响，镜像已于
`d9a7302d` 同步上游修复。

**Architecture:** 新增一个离线优先的比赛验证入口，读取冻结的双版本 case manifest，
只消费管理员预先放入 repository import root 的两个只读快照。入口显式调用现有
`run_platform_review()` 与真实 Sidecar `/v1/repro`，随后用同一目标绑定规则重复运行最终
PoC 三次，并把脆弱版 PoC 原样回放到修复版。结果写入独立的 competition evidence
bundle；现有任务 API 和前端不在本计划中接线。通过该闭环后，再单独规划生产 Artifact
存储和服务端/API 集成。

**Tech Stack:** Python 3.11/3.12、`unittest`、Git、Docker Compose、Clang 14、
AddressSanitizer、现有 C++ Sidecar、现有 OpenAI-compatible LLM provider、V4 AEP/VEP
contracts。

**Requirements source:** 2026-10-02 用户给出的 OpenHarmony 漏洞挖掘赛题要求；
现有平台设计见
`docs/superpowers/specs/2026-09-12-agent-vuln-platform-design.md`，当前能力边界见
`docs/COMPETITION_VALIDATION.md`。

## 1. Frozen scope and acceptance contract

本计划只交付一个可重复运行的 OpenHarmony pilot，不承诺全量 OpenHarmony 覆盖，也不把
已公开 CVE 计为新发现。pilot 用来证明 LIMA 的真实检测、PoC、负对照和报告路径可用。

最终验收同时满足：

1. case manifest 固定上游仓库、组件、CVE、`CWE-416`、脆弱 commit、修复 commit、两个本地
   `repository_key`、翻译单元、目标路径和可信资料来源；commit 使用完整 40 位 SHA。
   可选依赖覆盖层（`dependency_overlay`）逐文件固定相对路径、SHA-256、角色、上游出处和
   许可证，两个 revision 必须使用字节一致的同一组覆盖文件。
2. 两个本地 checkout 的 `HEAD` 与 manifest 一致，受跟踪文件无修改；Workspace
   fingerprint、目标文件和 `compile_commands.json` 均进入运行记录。
3. 脆弱版必须产生与 manifest 的 CWE 和目标路径相符的 `runtime-confirmed` finding；
   最终 PoC 额外回放 3 次，三次均为 `stage=run`、完整 ASan 报告且 faulting frame
   绑定目标文件。
4. 修复版不得产生同一 CWE/目标路径的正向 finding；脆弱版的最终 PoC 在修复版回放
   3 次，三次均编译成功、进入 run 阶段、干净退出且没有目标绑定 ASan 命中。
5. 编译失败、超时、transport failure、缺少符号化 frame、快照/commit 不匹配、覆盖被
   截断或真实 provider 不可用均为 `inconclusive`，不能计为修复成功或安全。
6. 输出 bundle 包含输入 manifest、快照指纹、完整 PoC、每次回放观察、平台 AEP/VEP
   payload、修复差异、中文漏洞报告和性能数据；`SHA256SUMS.json` 覆盖除自身之外的
   全部 bundle 文件，且不得包含 API key。
7. 影响版本分成两类陈述：本地实际验证的两个 commit，以及公开通告声称的版本。不得
   用 `git tag --contains` 单独推出“当前仍受影响”。
8. `docs/COMPETITION_VALIDATION.md` 只有在真实 Sidecar、真实 provider 和真实两个版本
   都运行后才能把对应项改为“已验证”，并记录命令、时间、提交和 bundle 路径。

## 2. Non-goals and integration boundaries

- 不修改现有 repository scan API、service 或前端接线。
- 不让 CLI clone、fetch 或 checkout；源码和依赖由管理员在沙箱外预置。
- 依赖覆盖层只允许承载外部依赖的降级实现（header-only、零仓外链接符号），永远不得
  包含目标组件自身的文件，也不得改变脆弱/修复语义；覆盖层不是给目标代码打补丁的
  后门。
- 不自动提交 OpenHarmony 漏洞奖励计划，不把 PoC 上传到外部服务。
- 不实现通用 OpenHarmony `repo` manifest 管理、全仓 GN/HB 构建或跨设备运行。
- 不把该 pilot 作为无偏检测率样本；案例经过“现有 facts 链可达”筛选，报告必须披露
  这一选择偏差。本计划只验证真实闭环是否可运行。
- 不把 report-embedded V4 preview 宣称为生产 Artifact store；pilot bundle 是验证工件，
  文件清单和 digest 明确标注其 competition-validation 用途。
- 不在此切片生成或应用自动补丁；修复证据来自公开 fixing commit 及双版本 PoC 回归。

## 3. File map

### Create

- `lima/openharmony_validation.py`：case schema、checkout 预检、双版本运行、PoC 三次回放、
  判定和 evidence bundle 写入。
- `scripts/run_openharmony_validation.py`：薄 CLI；读取环境中的 provider 配置和 Sidecar
  URL，不在参数或输出中回显密钥。
- `tests/test_openharmony_validation.py`：零网络合同测试、git fixture 和 fake
  platform/workbench 组合测试。
- `evaluation_data/openharmony/schema.json`：case manifest JSON Schema。
- `evaluation_data/openharmony/pilot_case.json`：经 Task 2 资格审查后冻结的首个真实案例。
- `evaluation_data/openharmony/README.md`：候选准入规则、源码预置方法、许可证和披露边界。
- `evaluation_data/cve_index/openharmony_pilot.json`：与 pilot 一致的真实离线 CVE 条目。

### Modify

- `lima/agent_orchestrator.py`：把现有目标绑定 ASan 命中判断公开为可复用纯函数，平台
  内部与 replay 使用同一实现。
- `lima/agent_report.py`：修复真实 ASan hit 的报告门禁，并允许调用方传入已验证的
  修复建议/修复提交信息。
- `tests/test_agent_orchestrator.py`：冻结公开命中判断的目标/驱动/未知 frame 语义。
- `tests/test_agent_report.py`：真实命中 `ok=False` 仍允许 runtime-confirmed 报告；
  编译失败和伪造 `hit` 仍降级。
- `docs/COMPETITION_VALIDATION.md`：追加 pilot 运行记录，不覆盖历史记录。
- `docs/competition/使用说明书.md`：追加 pilot CLI 和源码预置说明。
- `docs/competition/性能数据.md`：追加真实 pilot 的 wall time、峰值内存、LLM calls、
  reply bytes、Sidecar 实验次数和覆盖率。

### Forbidden in this plan

- `lima/api.py`、`lima/service.py`、`frontend/`：待 pilot 通过后另作生产接线计划。
- `lima/contracts/vep.py`、`lima/contracts/aep.py`：复用冻结契约，不为案例放宽。
- Sidecar 的网络、Landlock、seccomp、capability、只读快照和资源上限。

## 4. Public interfaces frozen by this plan

`lima.openharmony_validation` 提供：

```python
class ValidationStatus(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    INCONCLUSIVE = "inconclusive"

@dataclass(frozen=True)
class OpenHarmonyRevision:
    repository_key: str
    commit: str
    version: str

@dataclass(frozen=True)
class WorkspaceLimits:
    max_files: int
    max_file_bytes: int
    max_total_bytes: int

@dataclass(frozen=True)
class OpenHarmonyCase:
    schema_version: str
    case_id: str
    repository: str
    component: str
    cve_id: str
    cwe: str
    vulnerable: OpenHarmonyRevision
    fixed: OpenHarmonyRevision
    translation_units: tuple[str, ...]
    target_paths: tuple[str, ...]
    build_context_mode: str
    advisory_urls: tuple[str, ...]
    patch_paths: tuple[str, ...]
    remediation: str
    license: str

@dataclass(frozen=True)
class RevisionValidation:
    revision: OpenHarmonyRevision
    status: ValidationStatus
    snapshot_hash: str
    platform_outcome: PlatformReviewOutcome | None
    replay_observations: tuple[ExperimentObservation, ...]
    replay_elapsed_seconds: tuple[float, ...]
    elapsed_seconds: float
    file_coverage: float
    byte_coverage: float
    budget_usage: Mapping[str, int]
    diagnostics: tuple[str, ...]

@dataclass(frozen=True)
class OpenHarmonyValidationResult:
    case: OpenHarmonyCase
    workspace_limits: WorkspaceLimits
    status: ValidationStatus
    reason_codes: tuple[str, ...]
    vulnerable: RevisionValidation
    fixed: RevisionValidation
    total_elapsed_seconds: float

def load_openharmony_case(path: str | Path) -> OpenHarmonyCase:
    """Decode and validate one closed-schema pilot manifest."""

def validate_case_checkouts(
    case: OpenHarmonyCase,
    import_policy: RepositoryImportPolicy,
    workspace_limits: WorkspaceLimits,
) -> tuple[RepositoryWorkspace, RepositoryWorkspace]:
    """Resolve and preflight the vulnerable and fixed read-only snapshots."""

def run_openharmony_case(
    case: OpenHarmonyCase,
    *,
    import_policy: RepositoryImportPolicy,
    workspace_limits: WorkspaceLimits,
    analyzer_client: CxxMemoryAnalyzerClient,
    llm_config: Mapping[str, object],
    budget_factory: Callable[[], CxxAgentBudget],
    timeout: int,
    deadline_seconds: float,
    parallelism: int,
    dialogue_rounds: int,
) -> OpenHarmonyValidationResult:
    """Run both revisions and the fixed three-plus-three replay matrix."""

def write_validation_bundle(
    result: OpenHarmonyValidationResult,
    output_dir: str | Path,
) -> Path:
    """Atomically publish the competition-validation evidence bundle."""
```

`lima.agent_orchestrator` 提供：

```python
def experiment_matches_target(
    observation: ExperimentObservation,
    cwe: str,
    *,
    target_path: str,
    driver_paths: Sequence[str] = (),
) -> bool:
    """Return whether an executed ASan report is bound to the audited target."""

def repro_driver_relative_path(driver_code: str) -> str:
    """The Sidecar's content-derived staging path for one repro driver."""
```

manifest 使用封闭字段集：

```text
schema_version, case_id, repository, component, cve_id, cwe,
vulnerable{repository_key, commit, version},
fixed{repository_key, commit, version},
translation_units, target_paths, build_context_mode,
advisory_urls, patch_paths, remediation, license,
dependency_overlay[]{path, sha256, role, upstream_repo, upstream_commit, license, note}
```

`schema_version` 首版固定为 `openharmony-validation-v1`；`cwe` 首版只接受
`CWE-416`；`build_context_mode` 首版只接受 `snapshot-compdb`；回放次数固定为 3，
不由 manifest 降低。`WorkspaceLimits` 由 CLI 从显式参数或三项
`LIMA_REPOSITORY_SCAN_MAX_*` 环境变量解析，宿主与 Sidecar 必须使用同一组值，并写入
`summary.json`。`dependency_overlay` 为可选数组：`role` 首版只接受 `dependency-header`；
每个文件必须位于 checkout 根 `_overlay/` 子目录、SHA-256 与 manifest 一致、不得与组件
仓内任何路径冲突；脆弱与固定两个 checkout 的覆盖层必须字节一致。覆盖层必须
header-only 且自包含——目标 TU 编译产物除系统库外零未定义外部符号（资格审查用
`nm -u` 判定），不满足即拒绝该候选。

## 5. Review focus

- 真实 ASan 报告的 `ReproResponse.ok` 为 `False`；命中判断依赖 run 阶段、ASan 类型、
  CWE 映射和目标 frame 绑定，不能重新引入 `ok=True` 条件。
- 驱动自身 UAF、未知 faulting file、其他源文件崩溃、compile failure 和 timeout 都不能
  算目标命中。
- 固定版本的“0 finding”不能独立证明已修复；只有旧 PoC 在固定版本上 3 次编译运行且
  均干净，paired case 才能 passed。
- `FAILED` 表示检测或修复结论被运行证据否定；环境、工具和依赖问题统一
  `INCONCLUSIVE`，不得混为安全。
- bundle 写入必须先进入同级临时目录，所有文件成功并生成 digest manifest 后再原子
  rename；输出路径只要已经存在就拒绝执行，避免 Windows 对已有空目录的 rename
  语义造成平台差异。
- 依赖覆盖层是环境依赖的降级替身，不是目标代码的一部分：digest 钉扎、双 revision
  字节一致、零仓外链接符号三条红线任何一条被碰，该次运行就是 `inconclusive`，不是重试。
- 报告中的公开版本范围必须带 advisory URL；没有公开来源时仅写本地验证 commit。
- provider secret 只从环境读取，不进入 case、异常、日志、summary 或 bundle。

---

## Task 1: 修正并复用真实 ASan 命中真值

**Files:**
- Modify: `lima/agent_orchestrator.py`
- Modify: `lima/agent_report.py`
- Modify: `tests/test_agent_orchestrator.py`
- Modify: `tests/test_agent_report.py`

**Interfaces:**
- Produces: `experiment_matches_target(observation, cwe, target_path, driver_paths) -> bool`
  与 `repro_driver_relative_path(driver_code) -> str`（公开现有暂存路径规则），供平台和
  pilot replay 共用。
- Preserves: `_experiment_hit` 若仍被测试或内部消费者引用，只作为兼容别名调用公开函数。

- [ ] **Step 1: 写公开命中判断的失败测试**

  在 `tests/test_agent_orchestrator.py` 增加：真实 UAF observation
  `ok=False, stage="run", error_type="heap-use-after-free"` 且 faulting file 绑定目标时返回
  `True`；驱动文件命中、未知文件、CWE 不匹配、compile 阶段分别返回 `False`。

- [ ] **Step 2: 运行测试并确认 RED**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_agent_orchestrator -v`

  Expected: FAIL，因为 `experiment_matches_target` 尚不存在。

- [ ] **Step 3: 提取公开纯函数并替换平台内部调用**

  将现有 `_experiment_hit` 的冻结逻辑移入 `experiment_matches_target`；保留相同
  CWE marker、路径规范化和 driver 排除语义。平台 loop 只调用该函数。同时把
  `_repro_driver_relative_path` 公开为 `repro_driver_relative_path`，原私有名保留为
  兼容别名。

- [ ] **Step 4: 修正报告门禁测试和实现**

  `tests/test_agent_report.py` 使用真实协议语义：命中记录为
  `stage="run", ok=False, hit=True, error_type` 非空且 `faulting_file` 绑定目标。
  `_has_runtime_hit` 不再要求 `ok=True`；同时要求 run 阶段、`hit is True` 和非空
  `error_type`，防止只有布尔字段的伪记录升级报告。

- [ ] **Step 5: 运行回归**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_agent_orchestrator tests.test_agent_report tests.test_agent_repro_tools -v`

  Expected: PASS。

- [ ] **Step 6: 提交**

  ```powershell
  git add lima/agent_orchestrator.py lima/agent_report.py tests/test_agent_orchestrator.py tests/test_agent_report.py
  git commit -m "fix: align runtime reports with ASan hit semantics"
  ```

## Task 2: 冻结 OpenHarmony pilot case 合同并完成样本资格审查

**Files:**
- Create: `lima/openharmony_validation.py`
- Create: `tests/test_openharmony_validation.py`
- Create: `evaluation_data/openharmony/schema.json`
- Create: `evaluation_data/openharmony/README.md`
- Create: `evaluation_data/openharmony/pilot_case.json`
- Create: `evaluation_data/cve_index/openharmony_pilot.json`

**Interfaces:**
- Produces: `OpenHarmonyCase`、`load_openharmony_case(path)`。
- Case selection gate: 官方或项目维护者公开通告 + 可定位 fixing commit + `CWE-416` +
  C/C++ 目标 + Clang/ASan 可运行 + UAF facts 能自动生成绑定目标路径的 candidate/lead +
  TU 闭包在单仓或单仓加钉扎依赖覆盖层内自洽 + 装进本次声明的同步扫描预算 + 非普通功能
  bug/无安全价值 DoS。

- [ ] **Step 1: 写 manifest schema 的失败测试**

  测试精确字段集、重复 JSON key、未知字段、非 40 位 commit、绝对/反斜杠/`..` 路径、
  非 HTTPS advisory、CVE 格式错误、`cwe` 不是精确 `CWE-416`、空 translation
  unit/target/patch path、非 `snapshot-compdb` 模式。`dependency_overlay` 条目测试：
  非 `_overlay/` 前缀路径、非 64 位十六进制 digest、非法 `role`、与组件仓内路径冲突、
  路径逃逸一律拒绝；合法条目解码为排序去重 tuple。合法 fixture 解码后所有 tuple
  排序去重，输入顺序不影响结果。

- [ ] **Step 2: 运行测试并确认 RED**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.OpenHarmonyCaseContractTests -v`

  Expected: FAIL，因为模块和 schema 尚不存在。

- [ ] **Step 3: 实现封闭 dataclass/parser，并写 JSON Schema**

  parser 使用 UTF-8、拒绝重复 key/NaN/Infinity，边界文本按 UTF-8 字节计量；路径统一为
  relative POSIX。`schema.json` 与 Python parser 的字段和枚举完全一致。

- [ ] **Step 4: 资格审查候选并冻结唯一 pilot**

  环境前置：在筛选候选前，把候选的脆弱/修复快照预置到同一个 repository import root，
  为两者生成根目录 `compile_commands.json`，按本次声明的扫描限额设置
  `LIMA_REPOSITORY_IMPORT_PATH` 和三项 `LIMA_REPOSITORY_SCAN_MAX_*`，并运行
  `docker compose --profile cxx up -d --build cxx-analyzer`。目标 TU 闭包存在仓外依赖头
  时，为两个快照预置字节一致的 `_overlay/` 降级头（header-only、语义等价、文件头注释
  声明上游出处与改写性质），并把 `-I _overlay` 写进两份 compdb。本步骤只调用确定性的
  facts 和 candidate 路径，不需要配置或调用 LLM provider。

  对候选逐项记录：通告 URL、上游仓库、许可证、CVE/CWE、fixing commit、脆弱 parent
  commit、目标路径、是否需要设备/内核/硬件、能否在 Sidecar clang-14 + ASan 中编译、
  TU 闭包（compdb 引用的源文件与头文件，含 `_overlay/`）是否装得进本次声明的扫描预算、
  目标 TU 编译产物除系统库外是否零未定义外部符号（`nm -u` 判定，覆盖层不满足即拒绝）。资格审查必须
  对脆弱快照真实调用 `analyze_uaf_facts` 和 `generate_candidates`，确认至少一个 candidate
  的目标路径落在 manifest `target_paths`；不得把 manifest 的目标位置伪装成调用方提供的
  `ScoutLead`。宿主和 Sidecar 使用完全相同的 `LIMA_REPOSITORY_SCAN_MAX_FILES`、
  `LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES`、`LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES`；默认值为
  5000 / 512 KiB / 20 MiB，确需放大时使用 `deploy/competition/README.md` 的比赛配置并把
  有效值写入资格审查记录。
  选择第一个满足 gate 的候选，写入固定路径 `pilot_case.json`；未满足的候选只在 README
  的 rejection ledger 记录原因，不能用合成样本替代真实 pilot。README 同时声明该案例
  因 facts 可达性而被筛选，不能从本次结果推导全仓检测率或漏报率。

- [ ] **Step 5: 增加真实 CVE 离线索引条目并做一致性测试**

  `openharmony_pilot.json` 的 component、path glob、fixed commit 与 `pilot_case.json`
  一致；introduced commit 只有在公开证据可核实时填写，否则按索引合同留空串，不能把
  “任一脆弱版本”误写成引入提交。测试调用 `load_cve_index` 和 `match_cve`，要求准确
  匹配，任一有值的键改变时不匹配。

- [ ] **Step 6: 运行回归并提交**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.OpenHarmonyCaseContractTests tests.test_agent_report.CveMatchTests -v`

  Expected: PASS。

  ```powershell
  git add lima/openharmony_validation.py tests/test_openharmony_validation.py evaluation_data/openharmony evaluation_data/cve_index/openharmony_pilot.json
  git commit -m "test: freeze OpenHarmony pilot vulnerability pair"
  ```

## Task 3: 校验两个只读 checkout 和构建上下文

**Files:**
- Modify: `lima/openharmony_validation.py`
- Modify: `tests/test_openharmony_validation.py`

**Interfaces:**
- Consumes: `RepositoryImportPolicy.resolve()`、`RepositoryWorkspace.inventory()`。
- Produces: `validate_case_checkouts(case, import_policy, workspace_limits)`，返回
  vulnerable/fixed workspace，并在错误中使用稳定 reason code；不运行
  checkout/fetch/build。

- [ ] **Step 1: 用本地 git fixture 写预检失败测试**

  覆盖正确 HEAD、错误 HEAD、受跟踪文件变脏、缺少目标文件、缺少 translation unit、
  缺少/无效 `compile_commands.json`、inventory truncated、两个 key 指向同一目录、
  repository key 逃逸、布尔值/零值/负值 Workspace 限额、vulnerable checkout 不能解析
  fixed commit、`_overlay/` 文件 digest 与 manifest 不符或存在 manifest 未列文件、
  两个 checkout 的覆盖层字节不一致。
  未跟踪文件只允许仓库根目录的 `compile_commands.json` 和 manifest 逐文件钉扎的
  `_overlay/` 目录；任何其他未跟踪或 ignored
  文件只要进入 Workspace inventory 就拒绝，避免未固定的生成头文件悄悄参与复现。

- [ ] **Step 2: 运行测试并确认 RED**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.CheckoutValidationTests -v`

- [ ] **Step 3: 实现只读 Git/Workspace 预检**

  Git 只允许 `rev-parse HEAD`、`rev-parse --verify <sha>^{commit}`、
  `diff --quiet --no-ext-diff`、`status --porcelain --untracked-files=all` 和 `ls-files -z`，
  使用 argv list、`shell=False`、30 秒 timeout，并禁用 global/system config。两个 HEAD
  必须分别等于 manifest commit，且 vulnerable checkout 必须能解析 vulnerable/fixed
  两个 commit，以便后续在同一对象库生成 fixing diff。读取 `compile_commands.json` 时
  要求每个 manifest translation unit 都有唯一 entry，command 或 arguments 不得引用
  checkout 根目录之外的响应文件；`-I` 只允许指向仓内目录或 `_overlay/`。

- [ ] **Step 4: 固定覆盖门禁**

  用传入的 `WorkspaceLimits` 构造两个 workspace；inventory 必须 `truncated=False`，
  manifest 中的 target、translation unit、patch path 和 compdb 引用的仓内源文件都
  出现在 inventory。除根 `compile_commands.json` 和 `_overlay/`（逐文件 digest 与
  manifest 一致、不多不少）外，每个 inventory 文件都必须出现在单次 `git ls-files -z`
  得到的跟踪集合；否则返回 `inconclusive` 前置错误，不开始 LLM 或实验。覆盖层文件
  进入 inventory 即进入 workspace fingerprint，宿主/Sidecar 覆盖层不一致自然被指纹
  门禁挡下。有效限额随结果保存；部署文档要求把同一组环境变量传给 Sidecar，首次 facts
  请求的 snapshot fingerprint 校验作为运行时一致性门禁，任何不一致均为
  `inconclusive`。

- [ ] **Step 5: 运行回归并提交**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.CheckoutValidationTests tests.test_repository_import -v`

  Expected: PASS。

  ```powershell
  git add lima/openharmony_validation.py tests/test_openharmony_validation.py
  git commit -m "feat: validate immutable OpenHarmony pilot snapshots"
  ```

## Task 4: 实现双版本平台运行和三次 PoC 回放

**Files:**
- Modify: `lima/openharmony_validation.py`
- Modify: `tests/test_openharmony_validation.py`

**Interfaces:**
- Produces: `RevisionValidation`、`OpenHarmonyValidationResult`、
  `run_openharmony_case(case, import_policy, workspace_limits, analyzer_client, llm_config, budget_factory, timeout, deadline_seconds, parallelism, dialogue_rounds)`。
- Calls: `run_platform_review` with `build_context_mode="snapshot-compdb"` and `mode="required"`
  并显式传入 timeout、deadline、parallelism、dialogue_rounds 和每 revision 独立 budget；
  `leads` 保持空 tuple，让生产 facts/candidate 路径自行发现目标，manifest 的目标标签只在
  评测侧匹配结果。

- [ ] **Step 1: 写 paired-run 状态机失败测试**

  使用 fake analyzer、fake provider transport 和 fake workbench 覆盖：

  - vulnerable 匹配 finding + 3/3 目标 hit，fixed 无同一 finding + 3/3 clean => `passed`；
  - vulnerable 只有 2/3 hit => `failed`；
  - fixed 任一次目标 hit => `failed`；
  - fixed 只有零 finding、但旧 PoC compile failure => `inconclusive`；
  - provider/Sidecar timeout、未知 frame、snapshot mismatch => `inconclusive`；
  - fixed 的无关 CWE finding被保留记录，但不改变本 case 的回归判断。

- [ ] **Step 2: 运行测试并确认 RED**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.PairedRunTests -v`

- [ ] **Step 3: 实现 vulnerable 全链与 replay**

  运行全链后按 `(cwe, normalized target path)` 选唯一 `runtime-confirmed` finding；多个匹配
  finding 记为 `inconclusive`。用该 finding 的最终 `poc_driver_code`、目标文件和 vulnerable
  snapshot 调用 `ReproWorkbench.run_experiment` 三次，每次用
  `experiment_matches_target` 重新判定，且传
  `driver_paths=(repro_driver_relative_path(driver),)`，让 PoC 驱动自身崩溃不计入
  目标命中。

- [ ] **Step 4: 实现 fixed 全链与旧 PoC 回放**

  fixed 使用独立 budget 和相同显式运行参数。完整保留其所有 target/finding；随后把
  vulnerable 最终 driver 和同一目标相对路径回放三次。三次必须 `ok=True`、`stage=run`、
  `error_type is None` 才算 clean；compile/transport/timeout 归 inconclusive。

- [ ] **Step 5: 记录性能和覆盖事实**

  每 revision 保存 wall time、Workspace file/byte coverage、平台 stats、budget usage、
  replay 次数与时长；不把 fake provider 指标写入真实运行文档。

- [ ] **Step 6: 运行回归并提交**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.PairedRunTests tests.test_platform_evaluation tests.test_agent_repro_tools -v`

  Expected: PASS。

  ```powershell
  git add lima/openharmony_validation.py tests/test_openharmony_validation.py
  git commit -m "feat: validate OpenHarmony vulnerable and fixed revisions"
  ```

## Task 5: 写入可核验 competition evidence bundle 和报告

**Files:**
- Modify: `lima/openharmony_validation.py`
- Modify: `lima/agent_report.py`
- Modify: `tests/test_openharmony_validation.py`
- Modify: `tests/test_agent_report.py`

**Interfaces:**
- Consumes: `seal_platform_review(outcome, snapshot_sha256, repository)`、
  `generate_all_dossiers(findings, context, cve_index)`、真实 CVE index。
- Produces: `write_validation_bundle(result, output_dir) -> Path`。

- [ ] **Step 1: 写 bundle 失败测试**

  断言固定目录结构：

  ```text
  <output>/
    case.json
    summary.json
    vulnerable/platform.json
    vulnerable/aep.json
    vulnerable/vep-*.json
    vulnerable/poc_driver.cpp
    vulnerable/replay-01.json
    vulnerable/replay-02.json
    vulnerable/replay-03.json
    fixed/platform.json
    fixed/replay-01.json
    fixed/replay-02.json
    fixed/replay-03.json
    patch.diff
    report.md
    SHA256SUMS.json
  ```

  测试 `SHA256SUMS.json` 恰好列出除自身外的全部 bundle 文件、每个 digest 可重算、
  路径稳定排序、输出路径已存在（包括空目录）时拒绝、写入中断不留下完成 bundle、
  secret marker 不出现在任何文件、超预算文本明确省略且不破坏 JSON。

- [ ] **Step 2: 运行测试并确认 RED**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.BundleWriterTests -v`

- [ ] **Step 3: 生成独立 AEP/VEP payload 和 PoC/run 文件**

  使用 `seal_platform_review` 的完整 bundle 对象写出 AEP/VEP payload，不使用
  `RepositoryScanner._seal_platform_v4` 的 512 KiB 报告预览预算。`summary.json` 明确写
  `artifact_scope="competition-validation"`，列出 VEP、oracle PoC 和 replay 文件之间的
  digest 映射；不宣称已进入生产 Artifact store。

- [ ] **Step 4: 生成 fixing diff 和中文报告**

  在已确认同时包含两个 commit 对象的 vulnerable checkout 中，使用只读 argv
  `git diff --no-ext-diff --unified=3 <vulnerable_sha> <fixed_sha> -- <patch_paths>` 生成
  `patch.diff`；两个 SHA 直接来自已校验的 manifest，不把 checkout 目录误当 revision，
  命令受 timeout 和 argv whitelist 约束。报告复用 `generate_all_dossiers`，
  追加“已验证 commit 对”“3+3 回放矩阵”“公开通告来源”“fixing diff digest”和真实性
  边界；修复建议来自 manifest 的 source-backed `remediation`，不能保留占位文案。

- [ ] **Step 5: 原子发布 bundle**

  在 output 同级创建随机临时目录，完成全部 payload 文件后生成不包含自身条目的
  `SHA256SUMS.json`，最后执行一次 rename；任一步失败清理该临时目录。目标路径只要
  已存在就返回错误，不覆盖或删除历史证据。

- [ ] **Step 6: 运行回归并提交**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.BundleWriterTests tests.test_agent_report -v`

  Expected: PASS，且 `git diff --check` 为 0。

  ```powershell
  git add lima/openharmony_validation.py lima/agent_report.py tests/test_openharmony_validation.py tests/test_agent_report.py
  git commit -m "feat: export OpenHarmony competition evidence bundle"
  ```

## Task 6: 增加 CLI、失败码和使用文档

**Files:**
- Create: `scripts/run_openharmony_validation.py`
- Modify: `tests/test_openharmony_validation.py`
- Modify: `docs/competition/使用说明书.md`
- Modify: `deploy/competition/README.md`

**Interfaces:**
- CLI required: `--case`、`--repository-import-root`、`--output`。
- CLI optional: `--cxx-analyzer-url`、`--timeout`、`--deadline-seconds`、
  `--parallelism`、`--dialogue-rounds`、`--provider-url`、`--model`、`--max-files`、
  `--max-file-bytes`、`--max-total-bytes`。三项限额缺省读取同名
  `LIMA_REPOSITORY_SCAN_MAX_*` 环境变量，再回落到 5000 / 512 KiB / 20 MiB。
- Provider API key only via `LIMA_CXX_AGENT_API_KEY`; CLI 不接受 key 参数。
- Exit codes: `0=passed`、`2=failed`、`3=inconclusive/configuration error`。

- [ ] **Step 1: 写 CLI 失败测试**

  覆盖缺参数、非法数值、缺 provider、三种业务终态、输出目录冲突、异常文本脱敏；mock
  `run_openharmony_case`，CLI 单元测试不联网。

- [ ] **Step 2: 运行测试并确认 RED**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation.CliTests -v`

- [ ] **Step 3: 实现薄 CLI**

  CLI 只解析/校验参数、构造 `RepositoryImportPolicy`、`CxxMemoryAnalyzerClient`、
  `WorkspaceLimits`、`CxxAgentBudget` 和 llm config，调用模块并打印 status、bundle path
  和有界 diagnostics。所有实际判定留在 `lima.openharmony_validation`。

- [ ] **Step 4: 写真实运行说明**

  文档给出 PowerShell 命令：准备两个只读 checkout，其中 vulnerable checkout 必须是
  能同时解析 vulnerable/fixed 两个完整 commit 对象的完整克隆，不能使用缺少 fixed
  commit 的 shallow clone；案例声明依赖覆盖层时，为两个 checkout 预置字节一致的
  `_overlay/` 并在 compdb 的 `-I` 中引用；为两者生成可信的根目录 `compile_commands.json`，设置
  `$env:LIMA_REPOSITORY_IMPORT_PATH` 指向与 CLI
  `--repository-import-root` 完全相同的宿主目录，把相同的三项
  `LIMA_REPOSITORY_SCAN_MAX_*` 限额传给 Sidecar，然后启动
  `docker compose --profile cxx up`、设置 provider 环境、执行 CLI、离线复核
  `SHA256SUMS.json`。文档要求用
  `docker compose exec -T cxx-analyzer test -d /repositories/<repository_key>` 分别确认两个
  key 在容器内可见，并明确源码会发送给所选 provider。

- [ ] **Step 5: 运行回归并提交**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation -v`

  Run: `ruff check lima/openharmony_validation.py scripts/run_openharmony_validation.py tests/test_openharmony_validation.py`

  ruff 走 PATH（`.venv` 内未安装 ruff），规则配置读 `pyproject.toml` 的 `[tool.ruff]`。

  Expected: PASS。

  ```powershell
  git add scripts/run_openharmony_validation.py tests/test_openharmony_validation.py docs/competition/使用说明书.md deploy/competition/README.md
  git commit -m "feat: add OpenHarmony pilot validation command"
  ```

## Task 7: 运行真实 pilot、回填证据并做里程碑验收

**Files:**
- Modify: `docs/COMPETITION_VALIDATION.md`
- Modify: `docs/competition/性能数据.md`
- Output only: `output/openharmony/pilot/`（不提交敏感运行产物）

**Interfaces:**
- Consumes: Task 2 的真实 case、两个预置 checkout、真实 Sidecar、真实 provider。
- Produces: 一次 `passed` bundle，或一份明确的 `inconclusive` finding ledger；失败不能通过
  修改 expected verdict 或降低 3 次回放门槛解决。

- [ ] **Step 1: 运行静态验收**

  Run: `.venv\Scripts\python.exe -m unittest tests.test_openharmony_validation tests.test_agent_orchestrator tests.test_agent_report tests.test_agent_repro_tools tests.test_repro_protocol -v`

  Run: `ruff check lima scripts tests`

  Run: `git diff --check`

  Expected: 全部通过。

- [ ] **Step 2: 启动真实 Sidecar 并确认健康性**

  ```powershell
  $env:LIMA_REPOSITORY_IMPORT_PATH = 'D:\OpenHarmonyPilot'
  $env:LIMA_REPOSITORY_SCAN_MAX_FILES = '5000'
  $env:LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES = '524288'
  $env:LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES = '20971520'
  docker compose --profile cxx up -d --build --force-recreate cxx-analyzer
  $pilotCase = Get-Content evaluation_data\openharmony\pilot_case.json -Raw |
    ConvertFrom-Json
  docker compose exec -T cxx-analyzer test -d "/repositories/$($pilotCase.vulnerable.repository_key)"
  docker compose exec -T cxx-analyzer test -d "/repositories/$($pilotCase.fixed.repository_key)"
  ```

  若 Task 2 资格审查记录使用了比赛放大限额，这里和 Step 3 必须替换为同一组值，不能只
  修改 CLI 或只修改 Sidecar。

  Run: `docker compose ps cxx-analyzer`

  Expected: 两次 `test -d` 和容器健康检查都返回 0；不得用 fake workbench 替代。

- [ ] **Step 3: 执行真实双版本 pilot**

  ```powershell
  $pilotArgs = @(
    'scripts\run_openharmony_validation.py',
    '--case', 'evaluation_data\openharmony\pilot_case.json',
    '--repository-import-root', 'D:\OpenHarmonyPilot',
    '--output', 'output\openharmony\pilot',
    '--cxx-analyzer-url', 'http://127.0.0.1:8090',
    '--timeout', '60', '--deadline-seconds', '1800',
    '--parallelism', '1', '--dialogue-rounds', '1',
    '--max-files', $env:LIMA_REPOSITORY_SCAN_MAX_FILES,
    '--max-file-bytes', $env:LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES,
    '--max-total-bytes', $env:LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES
  )
  $pilotProcess = Start-Process -FilePath '.venv\Scripts\python.exe' `
    -ArgumentList $pilotArgs -NoNewWindow -Wait -PassThru
  $pilotProcess.Refresh()
  $pilotProcess.ExitCode
  $pilotProcess.PeakWorkingSet64
  docker compose exec -T cxx-analyzer sh -c `
    'if test -r /sys/fs/cgroup/memory.peak; then cat /sys/fs/cgroup/memory.peak; elif test -r /sys/fs/cgroup/memory/memory.max_usage_in_bytes; then cat /sys/fs/cgroup/memory/memory.max_usage_in_bytes; else exit 44; fi'
  ```

  Expected: exit 0；vulnerable 3/3 target-bound ASan hit；fixed 3/3 clean；同一 finding 在
  fixed 全链为 0；bundle digest 全部可重算。

  `--timeout 60 --deadline-seconds 1800` 只是初始值：真实编译耗时超出时按实测上调并
  在运行记录中注明，不算降低验收门槛；3 次回放与命中判定语义不得放宽。
  `PeakWorkingSet64` 作为宿主 CLI 峰值 RSS；Sidecar 使用 cgroup v2 `memory.peak`，回退到
  cgroup v1 `memory.max_usage_in_bytes`。Step 2 的 `--force-recreate` 用于重置本次 pilot 的
  容器峰值，避免混入此前任务；若两种 cgroup 文件都不可用，性能文档必须写“峰值内存
  未验证”和退出码 44，不能用结束时瞬时内存代替峰值。

- [ ] **Step 4: 人工复核报告和源证据**

  逐项核对 target line、CWE、CVE、PoC、ASan frame、fixing diff、两个 commit、公开版本
  来源和修复建议。若发现目标错绑、普通 DoS、安全影响夸大或通告/代码不一致，本次状态
  改为 inconclusive/failed，并形成 finding，不修饰成通过。

- [ ] **Step 5: 回填验证与性能文档**

  `docs/COMPETITION_VALIDATION.md` 追加运行日期、LIMA commit、OpenHarmony commits、命令、
  bundle 相对路径和 3+3 结果；`docs/competition/性能数据.md` 追加真实 wall time、峰值 RSS、
  LLM calls/reply bytes、实验次数、Workspace coverage。旧 Fake 数字继续明确标注 Fake。

- [ ] **Step 6: 全量项目门禁和提交**

  Run: `powershell -ExecutionPolicy Bypass -File scripts\lima.ps1 test`

  Expected: 项目要求的完整门禁通过；若 Windows 已知例外存在，必须记录精确 test id 和
  既有 issue，不接受笼统“环境失败”。

  ```powershell
  git add docs/COMPETITION_VALIDATION.md docs/competition/性能数据.md
  git commit -m "docs: record real OpenHarmony pilot validation"
  ```

## 6. Completion gate and next plan

只有 Task 7 的真实运行达到 `passed`，才开始下一份生产化计划。下一份计划负责：把 pilot
证明有效的 bundle 写入正式 Artifact store，将 dossier/CVE/影响信息接入 service/API/UI，
并把单案例入口扩展为分片 campaign。若 pilot 未通过，下一步只能从真实 finding ledger
选择一个阻塞问题制作小切片，不能先扩展更多 CWE、更多 Agent 或全仓扫描规模。
