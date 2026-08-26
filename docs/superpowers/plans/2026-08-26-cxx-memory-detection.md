# C/C++ 内存漏洞分层检测 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为 LIMA 的受控整仓扫描增加只检测、不自动修复的 C/C++ 内存漏洞分层分析能力，覆盖 CWE-787、CWE-125、CWE-416 和 CWE-415。

**Architecture:** LIMA 主应用通过版本化内部 HTTP 协议调用独立的 Linux `cxx-analyzer` Sidecar；Sidecar 在校验并复制只读仓库快照后依次运行 Semgrep、Clang Static Analyzer 和可选 ASan。主应用把 Sidecar 输出当作不可信输入进行整包校验，只在保守身份一致时融合证据，并在报告中明确区分 `source-only`、`build-backed` 与 `sanitizer-confirmed`。

**Tech Stack:** Python 3.11/3.12、标准库 `urllib`/`http.server`、Semgrep、LLVM/Clang Static Analyzer、CMake、AddressSanitizer、Docker Compose、原生 `unittest`、HTML/CSS/JavaScript。

**Spec:** `docs/superpowers/specs/2026-08-26-cxx-memory-detection-design.md`

## Global Constraints

- 第一阶段只检测 CWE-787、CWE-125、CWE-416、CWE-415；不生成修复，不接入 C/C++ PR Diff。
- 所有 C/C++ Finding 必须显式设置 `automatic_repair=False`；`None` 仅用于保持现有 Python 修复资格语义。
- 证据等级固定为：Semgrep → `source-only/candidate`，Clang → `build-backed/build-verified`，ASan → `sanitizer-confirmed/confirmed`。
- LIMA 主容器不得挂载 Docker Socket，也不得创建兄弟容器；分析器必须是独立 Compose Sidecar。
- Sidecar 只接受 `repository_key`、`snapshot_sha256`、`request_id` 和枚举化的 `requested_layers`，不接受路径、Shell、环境变量或请求时命令。
- 所有构建与测试步骤均为 argv 数组，使用 `shell=False`、清理后的环境、快照内工作目录和独立超时。
- Sidecar 使用非 root 用户、只读根文件系统、受限 tmpfs、`cap_drop: ALL`、`no-new-privileges`、无宿主端口、无 Docker Socket、无外网网络。
- Schema v1 不接受未知字段；未知版本/CWE、请求关联错误、快照不一致、不安全路径或响应超限时拒绝整份响应。
- `auto` 模式允许降级并记录原因；`required` 只在 Sidecar/协议不可用时使任务失败，目标仓库构建失败仍返回纯源码结果。
- Windows/Linux Python CI 不安装 LLVM，只使用模拟 Sidecar；Linux 容器 CI 才构建真实分析器镜像。
- 现有 Python 行为和当前 165 个测试不得回归。

## 文件结构与职责

### 主应用

- `lima/models.py`：向后兼容的 Finding/Evidence 字段与三态修复策略。
- `lima/config.py`：主应用 C/C++ 模式、URL、超时和响应上限配置。
- `lima/cxx_memory.py`：请求/响应协议、整包校验、HTTP 客户端、CWE/ASan 映射和 Finding 转换。
- `lima/repository_scanner.py`：识别 C/C++ 清单、调用 Adapter、保守融合和降级元数据。
- `lima/service.py`：注入 Adapter、传递 `repository_key`、公开能力状态。
- `lima/fixer.py`、`lima/repair_preview.py`：在规则匹配前拒绝 `automatic_repair=False`。
- `lima/report.py`、`web/app.js`：展示语言、模式、证据、降级原因和不可自动修复提示。

### Sidecar

- `cxx_analyzer/config.py`：解析管理员控制的 argv、预算和功能开关。
- `cxx_analyzer/snapshot.py`：仓库键校验、符号链接防护、快照哈希复算和隔离复制。
- `cxx_analyzer/execution.py`：统一的 `shell=False` 受限子进程执行器。
- `cxx_analyzer/normalizers.py`：严格 Schema v1、工具输出规范化和保守身份。
- `cxx_analyzer/source_scan.py`：Semgrep 编排与 JSON 解析。
- `cxx_analyzer/build_scan.py`：自动 CMake、管理员步骤和 Clang Static Analyzer 编排。
- `cxx_analyzer/sanitizer_scan.py`：ASan 构建/测试与日志解析。
- `cxx_analyzer/server.py`：`POST /v1/analyze` 内部服务和完整分析流水线。
- `cxx_analyzer/rules/cxx-memory.yml`：窄范围纯源码候选规则。
- `cxx_analyzer/Dockerfile`：固定的 Python、Semgrep、CMake、LLVM/Clang 工具链。

### 测试与评测

- `tests/test_cxx_memory.py`：主应用模型、协议、客户端、扫描集成、融合和失败语义。
- `tests/test_cxx_analyzer.py`：Sidecar 配置、快照、执行器、规范化及三层分析单元测试。
- `tests/fixtures/cxx_memory/manifest.json`：24 个合成场景的预期 CWE、符号和允许层。
- `tests/fixtures/cxx_memory/{cwe-787,cwe-125,cwe-416,cwe-415}/`：每类 3 个脆弱和 3 个安全场景。
- `evaluation_data/cxx_memory_cases.json`：固定公开漏洞/修复版本对及来源哈希。
- `scripts/run_cxx_memory_evaluation.py`：离线、可复现评测入口。
- `.github/workflows/ci.yml`：跨平台模拟测试和 Linux Sidecar 集成测试。

---

### Task 1: 向后兼容的数据模型、配置与修复硬门禁

**Files:**
- Modify: `lima/models.py:25-79`
- Modify: `lima/config.py:69-241`
- Modify: `lima/fixer.py:190-207`
- Test: `tests/test_cxx_memory.py`
- Test: `tests/test_config.py`
- Test: `tests/test_security_repair.py`

**Interfaces:**
- Produces: `EvidenceRecord.language: str`、`symbol: str`、`analysis_mode: str`。
- Produces: `Finding.language: str`、`symbol: str`、`analysis_mode: str`、`automatic_repair: Optional[bool]`。
- Produces: `Settings.cxx_memory_mode`、`cxx_analyzer_url`、`cxx_analysis_timeout_seconds`、`cxx_max_response_bytes`。
- Produces: `SafeFixer.repair_eligibility(finding)` 对 `automatic_repair is False` 返回 `{"eligible": False, "reason": "automatic-repair-disabled"}`。

- [ ] **Step 1: 写模型兼容性和修复排除测试**

```python
# tests/test_cxx_memory.py
import unittest

from lima.fixer import SafeFixer
from lima.models import EvidenceRecord, Finding, Severity


class CxxFindingModelTests(unittest.TestCase):
    def test_new_evidence_fields_have_backward_compatible_defaults(self):
        finding = Finding(
            rule_id="SEC-EVAL", severity=Severity.HIGH, title="eval",
            explanation="unsafe", path="app.py", line=1, evidence="eval(x)",
            fix="remove eval", test="exercise input",
        )
        self.assertEqual("", finding.language)
        self.assertEqual("", finding.symbol)
        self.assertEqual("", finding.analysis_mode)
        self.assertIsNone(finding.automatic_repair)
        self.assertEqual("", finding.evidence_records[0].language)

    def test_explicitly_disabled_finding_is_rejected_before_rule_matching(self):
        eligibility = SafeFixer.repair_eligibility({
            "rule_id": "SEC-SQL-CONCAT", "cwe": "CWE-89",
            "verification_state": "dataflow-verified", "automatic_repair": False,
        })
        self.assertEqual(
            {"eligible": False, "reason": "automatic-repair-disabled"},
            eligibility,
        )
```

- [ ] **Step 2: 运行测试并确认因字段/门禁缺失而失败**

Run: `python -m unittest tests.test_cxx_memory.CxxFindingModelTests -v`

Expected: FAIL，分别出现 `Finding` 缺少新属性，以及 C/C++ 禁止修复原因不匹配。

- [ ] **Step 3: 增加字段并把修复禁用检查放在规则判断之前**

```python
# lima/models.py（同时加到 EvidenceRecord 和 Finding）
language: str = ""
symbol: str = ""
analysis_mode: str = ""

# 仅 Finding
automatic_repair: Optional[bool] = None

# lima/fixer.py
if finding.get("automatic_repair") is False:
    return {"eligible": False, "reason": "automatic-repair-disabled"}
```

- [ ] **Step 4: 写主应用配置解析与非法模式测试**

```python
# tests/test_config.py
def test_cxx_memory_settings_are_parsed_and_validated(self):
    values = {
        "LIMA_CXX_MEMORY_MODE": "required",
        "LIMA_CXX_ANALYZER_URL": "http://cxx-analyzer:8090",
        "LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS": "41",
        "LIMA_CXX_MAX_RESPONSE_BYTES": "4096",
    }
    with patch.dict(os.environ, values, clear=True):
        settings = Settings.from_env()
        settings.validate_evolution()
    self.assertEqual("required", settings.cxx_memory_mode)
    self.assertEqual(41, settings.cxx_analysis_timeout_seconds)
    self.assertEqual(4096, settings.cxx_max_response_bytes)

def test_cxx_memory_mode_rejects_unknown_value(self):
    with patch.dict(os.environ, {"LIMA_CXX_MEMORY_MODE": "maybe"}, clear=True):
        with self.assertRaisesRegex(ValueError, "LIMA_CXX_MEMORY_MODE"):
            Settings.from_env().validate_evolution()
```

- [ ] **Step 5: 实现 Settings 字段、环境解析与 `auto|off|required` 校验**

Default values: `auto`、`http://cxx-analyzer:8090`、`300`、`2097152`。URL 只允许 `http://` 或 `https://` 且不得含用户信息、查询或片段。

- [ ] **Step 6: 运行聚焦测试与完整回归**

在 `tests/test_security_repair.py` 增加回归：使用一个与现有可修复规则 ID/CWE 完全相同、但 `automatic_repair=False` 的 finding 调用 `SafeFixer.apply`，断言 `rules=[]`、内容不变、blocked reason 为 `automatic-repair-disabled`。再把同一 finding 放入 `RepositoryRepairPreview.preview` 所用报告，断言状态为 `no-repair` 且没有 diff/repair manifest。

Run: `python -m unittest tests.test_cxx_memory tests.test_config tests.test_security_repair -v`

Expected: PASS。

Run: `python -m unittest discover -s tests -v`

Expected: 现有 165 个测试加新增测试全部 PASS。

- [ ] **Step 7: 提交模型与门禁**

```bash
git add lima/models.py lima/config.py lima/fixer.py tests/test_cxx_memory.py tests/test_config.py tests/test_security_repair.py
git commit -s -m "feat: add C++ memory finding contract"
```

---

### Task 2: 严格的 Sidecar v1 客户端与整包响应校验

**Files:**
- Create: `lima/cxx_memory.py`
- Modify: `tests/test_cxx_memory.py`

**Interfaces:**
- Consumes: Task 1 的 Finding/Evidence 字段和 Settings 预算。
- Produces: `CxxMemoryAdapter` Protocol：`analyze(repository_key: str, snapshot_sha256: str, requested_layers: tuple[str, ...]) -> CxxAnalysisResult`。
- Produces: `CxxMemoryAnalyzerClient(base_url, timeout_seconds, max_response_bytes, opener=urllib.request.urlopen)`。
- Produces: `CxxAnalysisResult(status, tool_runs, findings, coverage, diagnostics)`。
- Produces: `CxxAnalyzerUnavailable` 与 `CxxAnalyzerProtocolError`，供扫描器区分基础设施失败与无效响应。

- [ ] **Step 1: 写成功响应转换测试**

构造带 `Content-Length` 的假响应，断言客户端发送 `POST /v1/analyze`，请求只包含四个允许字段，并把规范 Finding 转成：

```python
Finding(
    rule_id="cxx.double-free", severity=Severity.HIGH,
    title="Potential double free", explanation="free called twice",
    path="src/free.c", line=12, evidence="free(p)", fix="",
    test="Reproduce under AddressSanitizer", confidence=0.72,
    cwe="CWE-415", source="semgrep", evidence_kind="line",
    verification_state="candidate", language="c",
    symbol="release", analysis_mode="source-only",
    automatic_repair=False,
)
```

同时断言 EvidenceRecord 保留工具、规则、路径、行号、snippet、language、symbol 和 analysis_mode。

- [ ] **Step 2: 运行成功路径测试并确认模块不存在**

Run: `python -m unittest tests.test_cxx_memory.CxxMemoryClientTests.test_valid_response_is_converted_to_findings -v`

Expected: FAIL with `ModuleNotFoundError: lima.cxx_memory`。

- [ ] **Step 3: 实现最小请求类型、结果类型和 HTTP 调用**

```python
SUPPORTED_CWES = frozenset({"CWE-787", "CWE-125", "CWE-416", "CWE-415"})
REQUESTED_LAYERS = ("source-only", "build-backed", "sanitizer-confirmed")
ANALYSIS_STATES = {
    "source-only": "candidate",
    "build-backed": "build-verified",
    "sanitizer-confirmed": "confirmed",
}
```

客户端使用 `uuid.uuid4()` 生成 `request_id`，使用 `json.dumps(...).encode("utf-8")`，设置 `Content-Type: application/json`；读取时最多读取 `max_response_bytes + 1` 字节。

- [ ] **Step 4: 写整包拒绝参数化测试**

逐个构造以下响应，并断言每次 `CxxAnalyzerProtocolError` 后没有任何 Finding 被返回：未知顶层字段、`schema_version=2`、错误 `request_id`、错误 `snapshot_sha256`、未知 CWE、绝对路径、`../escape.c`、行号 0、未知严重程度、未知 analysis mode、mode/state 不匹配、超限正文、重复 JSON key、非 UTF-8 和非 JSON。

- [ ] **Step 5: 实现严格 Schema 校验**

顶层键必须恰好是：

```python
{
    "schema_version", "request_id", "status", "snapshot_sha256",
    "tool_runs", "findings", "coverage", "diagnostics",
}
```

使用 `json.loads(..., object_pairs_hook=reject_duplicate_keys)`；先验证整棵结构，再转换任何 Finding。路径使用 `PurePosixPath`，拒绝绝对路径、`.`/`..`、反斜杠、NUL 和空段。

- [ ] **Step 6: 写 ASan 类型映射测试并实现纯函数**

```python
cases = [
    ("heap-buffer-overflow", "WRITE", "CWE-787"),
    ("stack-buffer-overflow", "READ", "CWE-125"),
    ("global-buffer-overflow", "WRITE", "CWE-787"),
    ("heap-use-after-free", "READ", "CWE-416"),
    ("attempting double-free", "FREE", "CWE-415"),
]
```

`map_asan_error(error_type: str, access: str) -> Optional[str]` 对未识别组合返回 `None`，不得猜测 CWE。

- [ ] **Step 7: 运行客户端测试并提交**

Run: `python -m unittest tests.test_cxx_memory.CxxMemoryClientTests -v`

Expected: PASS。

```bash
git add lima/cxx_memory.py tests/test_cxx_memory.py
git commit -s -m "feat: validate C++ analyzer protocol"
```

---

### Task 3: 接入整仓扫描器、证据融合与模式失败语义

**Files:**
- Modify: `lima/workspace.py:11-25`
- Modify: `lima/repository_scanner.py:20-256`
- Modify: `lima/service.py:100-120,352-458`
- Modify: `scripts/scan_repository.py:20-87`
- Modify: `tests/test_cxx_memory.py`
- Modify: `tests/test_workspace.py`
- Modify: `tests/test_service.py`

**Interfaces:**
- Consumes: Task 2 的 `CxxMemoryAdapter` 和 `CxxAnalysisResult`。
- Produces: `RepositoryScanner.scan(workspace, *, repository_key="")`。
- Produces: C/C++ 保守身份 `(cwe, normalized_path, symbol, line)`，不复用 Python 的 `(path, line, cwe-or-rule)`。
- Produces: `report.collaboration["cxx_memory"]`，含 `status`、`mode`、`requested_layers`、`tool_runs`、`coverage`、`diagnostics`。

- [ ] **Step 1: 先补齐 C/C++ 扩展名清单测试**

在 `tests/test_workspace.py` 创建 `.c/.cc/.cpp/.cxx/.h/.hh/.hpp/.hxx/.cmake` 文件和 `CMakeLists.txt`，断言均进入 inventory；`.obj` 和 `.exe` 仍被跳过。实现时新增精确文件名 allowlist，不能为了接纳 `CMakeLists.txt` 放开所有无扩展名文件。

- [ ] **Step 2: 修改 `DEFAULT_EXTENSIONS` 并运行清单测试**

Run: `python -m unittest tests.test_workspace.RepositoryWorkspaceTests.test_inventory_includes_all_supported_cxx_extensions -v`

Expected: PASS。

- [ ] **Step 3: 写 Fake Adapter 的调用/跳过测试**

```python
class FakeCxxAdapter:
    def __init__(self, result=None, error=None):
        self.calls = []
        self.result = result
        self.error = error

    def analyze(self, repository_key, snapshot_sha256, requested_layers):
        self.calls.append((repository_key, snapshot_sha256, requested_layers))
        if self.error:
            raise self.error
        return self.result
```

断言无 C/C++ 文件时零调用；有 `.cpp` 时传入已规范化 repository key 和 `inventory.fingerprint()`；`off` 模式零调用。

- [ ] **Step 4: 写融合与验证等级测试**

使用同一 `(CWE, path, symbol, line)` 的 Semgrep、Clang、ASan 三条结果，断言最终只剩一条 Finding，EvidenceRecord 去重后保留三个工具，最终为 `sanitizer-confirmed/confirmed`。用相同路径和行号但不同 symbol 的两条结果，断言保持独立。把 `build-verified` 加入 `VERIFICATION_RANK`，等级与 `dataflow-verified` 同为 3。

- [ ] **Step 5: 实现扫描器调用、保守融合和协作元数据**

扫描器构造参数增加：

```python
cxx_memory_mode: str = "off"
cxx_memory_adapter: Optional[CxxMemoryAdapter] = None
cxx_requested_layers: tuple[str, ...] = REQUESTED_LAYERS
```

只有 inventory 中存在受支持 C/C++ 源文件或头文件且 mode 非 `off` 时调用；只有 `CMakeLists.txt` 而没有 C/C++ 源文件时不调用。`source-only` 结果不得因多工具合并被提升到 `corroborated`；C/C++ 验证状态完全由三层固定映射决定。

- [ ] **Step 6: 写 auto/required 失败语义测试并实现**

- `auto + CxxAnalyzerUnavailable`：返回现有 Python 结果，`cxx_memory.status=unavailable`。
- `required + CxxAnalyzerUnavailable`：抛出 RuntimeError，使扫描任务失败。
- 任意模式下 Sidecar 返回 `build_failed`：保留 source-only Finding，不抛基础设施异常。
- `CxxAnalyzerProtocolError`：`auto` 拒绝整份 C/C++ 响应并记录 `invalid-response`；`required` 失败。

- [ ] **Step 7: 在 Service 注入客户端并传递 repository key**

`ReviewService` 在 mode 非 `off` 时使用 Settings 构造 `CxxMemoryAnalyzerClient`，调用改为：

```python
result = self.repository_scanner.scan(workspace, repository_key=repository_key)
```

能力接口加入模式、URL 是否配置、支持扩展名/CWE、三个层、构建/测试配置状态和 `automatic_repair=False`；不得把 Sidecar URL 中的凭据或查询参数返回给前端。

- [ ] **Step 8: 更新本地 CLI 并运行扫描回归**

CLI 默认 `--cxx-memory off`，只有明确传入 `auto|required` 且提供合法 `--repository-key` 才调用 Sidecar，避免任意本地路径绕过导入策略。

Run: `python -m unittest tests.test_cxx_memory tests.test_workspace tests.test_service -v`

Expected: PASS。

- [ ] **Step 9: 提交扫描集成**

```bash
git add lima/workspace.py lima/repository_scanner.py lima/service.py scripts/scan_repository.py tests/test_cxx_memory.py tests/test_workspace.py tests/test_service.py
git commit -s -m "feat: integrate layered C++ repository scans"
```

---

### Task 4: Sidecar 配置、快照复制和安全执行边界

**Files:**
- Create: `cxx_analyzer/__init__.py`
- Create: `cxx_analyzer/config.py`
- Create: `cxx_analyzer/snapshot.py`
- Create: `cxx_analyzer/execution.py`
- Create: `tests/test_cxx_analyzer.py`

**Interfaces:**
- Produces: `AnalyzerSettings.from_env()`，字段对应设计中的 6 个 Sidecar 环境变量，并读取与 LIMA 主应用完全相同的三项 repository scan 上限。
- Produces: `parse_steps_json(name, raw) -> tuple[tuple[str, ...], ...]`。
- Produces: `prepare_snapshot(import_root, repository_key, expected_sha256, work_root) -> PreparedSnapshot`。
- Produces: `run_step(argv, cwd, timeout_seconds, max_output_bytes, env) -> ToolExecution`，内部固定 `shell=False`。

- [ ] **Step 1: 写 argv 配置严格解析测试**

接受 `[["cmake", "-S", ".", "-B", "build"]]`；拒绝字符串命令、空 argv、非字符串参数、NUL、超过 64 个步骤、单步超过 128 个参数、单参数超过 4096 字节。断言请求无法覆盖这些设置。

- [ ] **Step 2: 实现 `AnalyzerSettings` 和 `parse_steps_json`**

默认值必须与规格一致：auto CMake true、build/test steps 空、内存 2048 MB、进程 128、输出 1048576 bytes。另设固定的每步超时和总分析超时，均只从 Sidecar 环境读取。`LIMA_REPOSITORY_SCAN_MAX_FILES`、`LIMA_REPOSITORY_SCAN_MAX_FILE_BYTES`、`LIMA_REPOSITORY_SCAN_MAX_TOTAL_BYTES` 复用主应用名称和默认值，Sidecar 用它们重建完全相同的有界 inventory。

- [ ] **Step 3: 写仓库键和快照防逃逸测试**

覆盖：`team/project` 成功；绝对路径、反斜杠、`.`、`..`、隐藏段、NUL、符号链接文件/目录失败；复制后复算哈希不符失败；导入源不被修改；目标只包含 inventory 允许的普通文件；不同 max-files/max-bytes 配置会产生不同哈希并被拒绝；`CMakeLists.txt` 和 `.cmake` 被纳入哈希及复制结果。

- [ ] **Step 4: 实现独立仓库键校验和隔离复制**

不要从 LIMA 包导入 `RepositoryImportPolicy`，Sidecar 必须独立再校验。Sidecar 以同一扩展名、精确文件名、忽略目录、优先级和三个预算重建 `WorkspaceInventory.fingerprint()`；哈希一致后才复制该 inventory 中的文件。复制过程先 `lstat`，再打开源文件，复制后再次校验类型和单文件 SHA-256；临时目录使用 `tempfile.TemporaryDirectory(dir=work_root)`。构建和测试不得读取 inventory 之外的仓库文件。

- [ ] **Step 5: 写执行器测试**

用 `unittest.mock.patch("cxx_analyzer.execution.subprocess.run")` 断言：argv 为 list、`shell=False`、`cwd` 位于 PreparedSnapshot、`env` 只含 allowlist、`stdin=DEVNULL`、独立 timeout、生效的输出截断和 SHA-256 摘要。测试超时返回 `status="timed-out"` 而不泄露完整日志。

- [ ] **Step 6: 实现执行器并运行 Sidecar 基础测试**

清理环境只允许固定的 `PATH=/usr/local/bin:/usr/bin:/bin`、`HOME=/tmp/analyzer-home`、`LANG=C.UTF-8`、`LC_ALL=C.UTF-8`、`TMPDIR=/work/tmp`；不得继承代理、Token、数据库或 LIMA 密钥。

Run: `python -m unittest tests.test_cxx_analyzer.AnalyzerBoundaryTests -v`

Expected: PASS。

- [ ] **Step 7: 提交 Sidecar 安全边界**

```bash
git add cxx_analyzer tests/test_cxx_analyzer.py
git commit -s -m "feat: isolate C++ analyzer snapshots"
```

---

### Task 5: 规范 Schema 与 Semgrep 纯源码层

**Files:**
- Create: `cxx_analyzer/normalizers.py`
- Create: `cxx_analyzer/source_scan.py`
- Create: `cxx_analyzer/rules/cxx-memory.yml`
- Create: `tests/fixtures/cxx_memory/manifest.json`
- Create: `tests/fixtures/cxx_memory/cwe-787/{vulnerable-1.c,vulnerable-2.c,vulnerable-3.cpp,safe-1.c,safe-2.c,safe-3.cpp}`
- Create: `tests/fixtures/cxx_memory/cwe-125/{vulnerable-1.c,vulnerable-2.cpp,vulnerable-3.cpp,safe-1.c,safe-2.cpp,safe-3.cpp}`
- Create: `tests/fixtures/cxx_memory/cwe-416/{vulnerable-1.c,vulnerable-2.cpp,vulnerable-3.cpp,safe-1.c,safe-2.cpp,safe-3.cpp}`
- Create: `tests/fixtures/cxx_memory/cwe-415/{vulnerable-1.c,vulnerable-2.cpp,vulnerable-3.cpp,safe-1.c,safe-2.cpp,safe-3.cpp}`
- Modify: `tests/test_cxx_analyzer.py`

**Interfaces:**
- Consumes: Task 4 的 `run_step` 和 PreparedSnapshot。
- Produces: `NormalizedFinding.to_dict()`，严格输出客户端 Task 2 接受的字段。
- Produces: `run_source_scan(snapshot, settings) -> LayerResult`。

- [ ] **Step 1: 写规范 Finding 约束测试**

断言 CWE 仅四种；severity 仅 low/medium/high/critical；路径为安全 POSIX 相对路径；line ≥ 1；`analysis_mode="source-only"` 固定对应 `verification_state="candidate"`；证据和 trace 均有长度上限。

- [ ] **Step 2: 实现不可变规范类型与 `conservative_identity`**

```python
def conservative_identity(finding: NormalizedFinding) -> tuple[str, str, str, int]:
    return finding.cwe, finding.path, finding.symbol, finding.line
```

序列化时只输出白名单字段；所有字符串在进入响应前截断并记录 diagnostics，不把原始无限日志装入 JSON。

- [ ] **Step 3: 编写 24 个短小、可编译的合成夹具和 manifest**

每类 CWE 的三个脆弱场景分别覆盖不同窄形态，每个安全场景是对应的边界检查、重新赋值/置空或单次释放版本。manifest 每项必须包含：`id`、`cwe`、`path`、`symbol`、`vulnerable`、`allowed_layers`、`asan_expected`。

- [ ] **Step 4: 编写 Semgrep 规则测试**

用保存的 Semgrep JSON 样例验证解析器；若本机安装了 Semgrep，再以子进程跑 24 个夹具，断言 source-only 层只产生 candidate，且 safe 场景不出现同规则同符号命中。规则禁止“匹配所有 memcpy/free/数组索引”的宽泛 pattern。

- [ ] **Step 5: 实现首批窄规则和 Semgrep JSON 解析**

规则 ID 固定前缀：`cxx.source.oob-write`、`cxx.source.oob-read`、`cxx.source.use-after-free`、`cxx.source.double-free`。每条规则 metadata 明确 CWE 和候选性质；解析器拒绝规则 metadata 缺失、未知 CWE、逃逸路径或非法行号。

- [ ] **Step 6: 运行无工具依赖单测，并在 Sidecar 镜像任务中运行真实规则**

Run: `python -m unittest tests.test_cxx_analyzer.SourceScanTests -v`

Expected: PASS（通过保存的工具输出，不要求宿主机安装 Semgrep）。

- [ ] **Step 7: 提交纯源码层**

```bash
git add cxx_analyzer tests/test_cxx_analyzer.py tests/fixtures/cxx_memory
git commit -s -m "feat: add narrow C++ source memory rules"
```

---

### Task 6: 内部 HTTP 服务与安全 Compose Sidecar

**Files:**
- Create: `cxx_analyzer/server.py`
- Create: `cxx_analyzer/Dockerfile`
- Modify: `docker-compose.yml`
- Modify: `.env.example`
- Modify: `tests/test_cxx_analyzer.py`

**Interfaces:**
- Consumes: Task 4 快照边界、Task 5 `run_source_scan` 和规范 Schema。
- Produces: `POST /v1/analyze` 与仅容器内部使用的 `GET /health`。
- Produces: Compose service `cxx-analyzer`，仅连接 `cxx_analysis` internal network。

- [ ] **Step 1: 写 HTTP 请求拒绝测试**

直接调用 handler/service 函数，覆盖非 POST、错误路径、错误 Content-Type、超限请求、未知/缺失字段、非法 UUID、重复 layer、未知 layer、非法 repository key。断言请求 JSON 中出现 `path`、`command`、`environment` 任一字段即整包拒绝。

- [ ] **Step 2: 实现请求 Schema 和流水线服务函数**

`analyze_request(payload, settings) -> dict` 先完成全部请求校验，再 prepare snapshot，再按请求层执行；响应固定包含 8 个顶层字段。目标构建失败是 `status="completed"` 加 diagnostics，不转成 HTTP 5xx。

- [ ] **Step 3: 实现 HTTP handler**

绑定 `0.0.0.0:8090`；请求体设置硬上限；错误响应只返回稳定错误码和 request_id，不返回宿主路径、命令输出或异常堆栈。`/health` 只返回 schema version 和工具可用布尔值。

- [ ] **Step 4: 创建固定版本 Sidecar 镜像**

镜像基于固定 digest 的 Python slim，安装固定主版本 Semgrep、CMake、LLVM/Clang；创建 UID/GID 10002 的 `analyzer` 用户；最终 `USER analyzer:analyzer`；不复制 LIMA 的 `.env`、数据库、skills 或导入仓库。

- [ ] **Step 5: 添加 Compose 安全断言测试**

解析 `docker-compose.yml`，断言 `cxx-analyzer`：没有 `ports`、没有 `/var/run/docker.sock`、仓库挂载 `:ro`、`read_only: true`、`cap_drop: [ALL]`、`no-new-privileges:true`、非 root user、pids/memory/cpu 限制、仅受限 tmpfs、只连 `cxx_analysis`；网络声明 `internal: true`。同时断言 `lima` 仍没有 Docker Socket。

- [ ] **Step 6: 更新 Compose 与示例环境**

LIMA 与 Sidecar 都加入 `cxx_analysis`；LIMA 保留现有应用网络，Sidecar 不加入其他网络。加入主应用四项配置和 Sidecar 六项管理员配置，build/test JSON 默认 `[]`；把同一组 `LIMA_REPOSITORY_SCAN_MAX_*` 值同时传给 LIMA 与 Sidecar，防止双方有界快照策略漂移。

- [ ] **Step 7: 构建镜像并运行 source-only 集成**

Run: `docker compose build cxx-analyzer`

Expected: image build exit 0。

Run: `docker compose run --rm cxx-analyzer python -m unittest tests.test_cxx_analyzer.SourceScanContainerTests -v`

Expected: 24 个 fixture 的 manifest 断言全部 PASS；若测试文件未复制进 runtime image，则使用 Dockerfile `test` target 执行等价命令。

- [ ] **Step 8: 提交 Sidecar 服务和部署约束**

```bash
git add cxx_analyzer docker-compose.yml .env.example tests/test_cxx_analyzer.py
git commit -s -m "feat: deploy isolated C++ analyzer sidecar"
```

---

### Task 7: CMake 与 Clang Static Analyzer build-backed 层

**Files:**
- Create: `cxx_analyzer/build_scan.py`
- Modify: `cxx_analyzer/server.py`
- Modify: `cxx_analyzer/normalizers.py`
- Modify: `tests/test_cxx_analyzer.py`
- Modify: `tests/fixtures/cxx_memory/manifest.json`

**Interfaces:**
- Consumes: Task 4 的安全 argv 执行器和 Task 5 的规范类型。
- Produces: `run_build_scan(snapshot, settings) -> LayerResult`。
- Produces: Clang Finding 固定 `analysis_mode="build-backed"`、`verification_state="build-verified"`。

- [ ] **Step 1: 写构建计划选择测试**

断言存在 `CMakeLists.txt` 且 auto CMake=true 时只生成固定 argv：

```python
(
    ("cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON"),
    ("cmake", "--build", "build", "--parallel", "2"),
)
```

无 CMake 时使用管理员 build steps；两者均为空时返回 `build-not-configured`，不执行仓库提供的脚本字符串。

- [ ] **Step 2: 写构建失败/超时测试**

Mock `run_step` 返回 nonzero/timed-out，断言保留 source-only，tool run 标记 `build_failed`/`timed-out`，Clang findings 为空，diagnostic 有界。

- [ ] **Step 3: 实现构建上下文和 Clang 调用**

只有所有配置步骤成功且存在有效 `compile_commands.json` 才运行 Clang Static Analyzer。解析 compilation database 时拒绝 `command` 字符串，只接受 `arguments` 数组；文件路径必须留在 snapshot 内。Clang 输出优先使用 SARIF/Plist 结构化格式，禁止从人类文本猜测位置。

- [ ] **Step 4: 写 Clang 规范化与融合测试**

保存四种 CWE 的最小结构化样例，断言 checker 映射、trace frame 路径约束、build-backed 状态和 source-only 同身份融合；不一致 symbol/line 保持独立。

- [ ] **Step 5: 在 Sidecar 镜像运行 build-backed fixtures**

Run: `docker compose run --rm cxx-analyzer python -m unittest tests.test_cxx_analyzer.BuildScanContainerTests -v`

Expected: Clang 可分析的 vulnerable fixtures 产生 `build-verified`，safe 对应项不产生同身份 finding；测试输出列出未覆盖项而不是把未运行写成安全。

- [ ] **Step 6: 提交 build-backed 层**

```bash
git add cxx_analyzer tests/test_cxx_analyzer.py tests/fixtures/cxx_memory/manifest.json
git commit -s -m "feat: add Clang build-backed memory analysis"
```

---

### Task 8: ASan 动态确认层

**Files:**
- Create: `cxx_analyzer/sanitizer_scan.py`
- Modify: `cxx_analyzer/server.py`
- Modify: `cxx_analyzer/normalizers.py`
- Modify: `tests/test_cxx_analyzer.py`
- Modify: `tests/fixtures/cxx_memory/manifest.json`

**Interfaces:**
- Consumes: Task 4 的安全执行器、Task 7 的成功构建上下文。
- Produces: `parse_asan_log(text: str) -> tuple[list[NormalizedFinding], list[Diagnostic]]`。
- Produces: `run_sanitizer_scan(snapshot, settings, build_context) -> LayerResult`。

- [ ] **Step 1: 写四类 ASan 日志解析测试**

保存最小日志文本，覆盖 heap/stack/global buffer overflow 的 READ/WRITE、heap-use-after-free、attempting double-free。断言映射到四个目标 CWE，主 frame 必须在 snapshot 内，输出为 `sanitizer-confirmed/confirmed`。

- [ ] **Step 2: 写未知与不完整日志测试**

普通测试退出 1、LeakSanitizer、SEGV、无法解析 frame、截断 ASan 报告均不得映射四类 CWE；只生成 `needs-human-review` diagnostic。日志中的 ANSI、绝对临时路径和环境内容不得进入公开 evidence。

- [ ] **Step 3: 实现 ASan 解析器**

解析 `ERROR: AddressSanitizer:`、READ/WRITE size、首个仓库内 frame、函数符号和行号。通过 Task 2 相同映射表生成 CWE；无法获得安全仓库内主位置时不创建 Finding。

- [ ] **Step 4: 实现可信测试步骤门禁**

只有管理员 `test_steps` 非空且 build context 成功时运行；使用受控 ASan 编译/链接 flags 和环境；每个测试 argv 均 `shell=False`。测试非零但无可识别 ASan 时只记录 `test-failed-without-sanitizer-evidence`。

- [ ] **Step 5: 在 Sidecar 镜像运行 ASan fixture 子集**

Run: `docker compose run --rm cxx-analyzer python -m unittest tests.test_cxx_analyzer.SanitizerContainerTests -v`

Expected: manifest 中 `asan_expected=true` 的 vulnerable 场景得到 confirmed；对应 safe 场景不继承 confirmed；每个运行均受 timeout/output limit。

- [ ] **Step 6: 提交动态层**

```bash
git add cxx_analyzer tests/test_cxx_analyzer.py tests/fixtures/cxx_memory/manifest.json
git commit -s -m "feat: confirm C++ memory findings with ASan"
```

---

### Task 9: Markdown、Web 报告和能力说明

**Files:**
- Modify: `lima/report.py:4-119`
- Modify: `web/app.js:700-790`
- Modify: `web/app.css`
- Modify: `tests/test_cxx_memory.py`
- Modify: `tests/test_frontend_ui.py`

**Interfaces:**
- Consumes: Task 1 Finding 字段、Task 3 `collaboration.cxx_memory`。
- Produces: 用户可读模式标签：`纯源码候选`、`构建支持的静态验证`、`Sanitizer 动态确认`。

- [ ] **Step 1: 写 Markdown 报告测试**

构造一条 source-only Finding 和 build/ASan 降级元数据，断言 Markdown 包含：语言、symbol、CWE、位置、模式、verification state、工具名、证据/trace、`纯源码分析，尚未经过目标项目构建验证`、`不支持自动修复`、构建失败原因和 Sanitizer 未配置原因。

- [ ] **Step 2: 实现 Markdown 渲染**

对非 C/C++ Finding 保持原输出；只有 `analysis_mode="source-only"` 显示醒目候选警告。工具 diagnostics 使用有界稳定码和清理后的消息，不渲染内部 URL、容器路径或命令行密钥。

- [ ] **Step 3: 写前端静态契约测试**

断言 `web/app.js` 包含 `analysisModeLabel`、language/symbol、source-only warning、tool evidence、degradation diagnostics 和 automatic repair disabled 文案；修复预览按钮只在至少存在一个 `automatic_repair !== false` 的 Finding 时显示。

- [ ] **Step 4: 实现 Web 展示和修复按钮门禁**

Finding 表格新增“分析模式”，详情显示 evidence records 与 diagnostics；所有内容继续通过 `escapeHtml`。source-only 使用 warning pill，confirmed 使用 verified pill，不能仅按字符串中是否含 `verified` 判断 confirmed。

- [ ] **Step 5: 运行报告与前端测试**

Run: `python -m unittest tests.test_cxx_memory.CxxReportTests tests.test_frontend_ui -v`

Expected: PASS。

- [ ] **Step 6: 提交报告行为**

```bash
git add lima/report.py web/app.js web/app.css tests/test_cxx_memory.py tests/test_frontend_ui.py
git commit -s -m "feat: explain C++ memory analysis evidence"
```

---

### Task 10: 固定公开版本对、评测指标、CI 与部署文档

**Files:**
- Create: `evaluation_data/cxx_memory_cases.json`
- Create: `scripts/run_cxx_memory_evaluation.py`
- Create: `docs/CXX_MEMORY_ANALYSIS.md`
- Modify: `evaluation_data/README.md`
- Modify: `README.md`
- Modify: `.github/workflows/ci.yml`
- Create: `tests/test_cxx_memory_evaluation.py`

**Interfaces:**
- Consumes: Task 5-8 三层 Sidecar 输出。
- Produces: `run_evaluation(cases, analyzer) -> dict`，包含 precision、recall、F1、pair accuracy、false positives/KLoC、各层数量/覆盖率、构建成功率、耗时和超时率。
- Produces: 可审计 JSON 报告，记录 analyzer image digest、case data hash 和有效性边界。

- [ ] **Step 1: 写评测数据 Schema 测试**

每个 CWE 至少一个 vulnerable/fixed 版本对；每项必须含 `project`、`vulnerable_commit`、`fixed_commit`、两个 archive URL 与 SHA-256、advisory/CVE URL、affected path/symbol、build steps、test steps、selection rationale 和 license。测试拒绝浮动分支、短 commit、缺失 SHA-256、非 HTTPS 来源和请求时 Shell 字符串。

- [ ] **Step 2: 选择并人工核验四个公开版本对**

只使用上游公告/CVE 可追溯、许可允许评测、能固定归档哈希的项目。把下载归档放在 CI cache 或临时目录，不提交第三方源码；在 `THIRD_PARTY_NOTICES.md` 补充评测来源与许可证（若许可证要求）。

- [ ] **Step 3: 写指标计算的确定性单元测试**

用内存中的 vulnerable/fixed 预期和模拟 findings，断言 TP/FP/FN、precision/recall/F1、pair accuracy、每 KLoC 误报、分层覆盖率和 timeout rate 的精确数值；分母为零时返回 `null` 和诊断，不伪造 100%。

- [ ] **Step 4: 实现离线评测 CLI**

参数固定为 `--cases`、`--cache-dir`、`--output`、`--analyzer-url`、`--fail-under-precision`；下载内容先校验 SHA-256 再解压，拒绝归档路径逃逸和符号链接。报告必须打印“合成和固定样本结果不代表真实项目完整检测能力”。

- [ ] **Step 5: 扩展 CI**

保留现有 Windows/Linux 3.11/3.12 单元测试；新增 Ubuntu job：构建 Sidecar、运行 24 个合成 fixture、启动无外网内部网络的 LIMA+Sidecar 集成、验证安全 Compose 配置。公开版本对评测使用固定缓存并可按维护成本设为定时/手动 job，但 Schema 与指标单测必须在每个 PR 运行。

- [ ] **Step 6: 编写部署和协作说明**

`docs/CXX_MEMORY_ANALYSIS.md` 说明三层证据差异、纯源码局限、管理员 argv JSON、资源预算、Compose 启动/健康检查、失败诊断、如何新增 fixture/版本对，以及明确“不自动修复”。README 只加入入口和最小配置，详细内容链接到该文档。

- [ ] **Step 7: 运行最终验证**

Run: `python -m unittest discover -s tests -v`

Expected: 全部测试 PASS，0 failures/errors。

Run: `docker build --target test --tag lima:test .`

Expected: exit 0。

Run: `docker run --rm --read-only --tmpfs /tmp:rw,size=256m lima:test`

Expected: 全部 Python 测试 PASS。

Run: `docker compose build cxx-analyzer`

Expected: exit 0。

Run: `docker compose config`

Expected: exit 0，Sidecar 无宿主端口/Docker Socket/外网网络，安全限制均存在。

- [ ] **Step 8: 提交评测、CI 和文档**

```bash
git add evaluation_data/cxx_memory_cases.json evaluation_data/README.md scripts/run_cxx_memory_evaluation.py docs/CXX_MEMORY_ANALYSIS.md README.md .github/workflows/ci.yml tests/test_cxx_memory_evaluation.py THIRD_PARTY_NOTICES.md
git commit -s -m "test: evaluate layered C++ memory detection"
```

---

## 完成定义

- [ ] 四类 CWE 均有不少于 3 个脆弱和 3 个安全合成场景。
- [ ] 每条 C/C++ Finding 都有 language、symbol、analysis_mode、verification_state 和 `automatic_repair=False`。
- [ ] source-only 永远不超过 candidate；Clang 与 ASan 的等级映射通过单测与容器测试。
- [ ] Sidecar 响应任何一处不可信字段都会导致整包拒绝。
- [ ] 构建/测试失败按规格降级，不把“工具没运行”表述成“没有漏洞”。
- [ ] SafeFixer、修复预览和 Web 按钮均排除 C/C++ Finding。
- [ ] Compose 安全约束由自动测试验证，并且主容器与 Sidecar 都没有 Docker Socket。
- [ ] Windows/Linux 模拟测试和 Ubuntu Sidecar 集成测试通过。
- [ ] 公开版本对数据固定 commit、归档哈希、公告和许可证来源。
- [ ] 报告明确标注纯源码局限和评测有效性边界。
