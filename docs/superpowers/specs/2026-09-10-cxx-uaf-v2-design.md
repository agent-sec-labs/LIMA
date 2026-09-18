# LIMA C++ UAF v2 第一阶段设计

日期：2026-09-10（2026-09-11 根据书面复审修订）
状态：设计已获用户确认，复审修订版待用户复核
目标分支：`codex/cxx-llm-agent-detection`
实现目录：`D:\Projects\LIMA\.worktrees\cxx-llm-agent-detection`

## 1. 决策摘要

本设计只重构 CWE-416（Use After Free，UAF）的检测与验证链路。CWE-415、
CWE-125、CWE-787 继续使用当前实现，不改变其路由、状态升级或报告语义。

UAF v2 的核心变化是将漏洞验证权从多 Agent 共识移交给确定性程序分析：

```text
Repository Snapshot
        ↓
Build Context Resolver
        ↓
Clang AST / CFG UAF Fact Extractor
        ↓
Deterministic Candidate Generator
        ↓
P1–P7 Proof Engine
   ┌────┼───────────────┐
   │    │               │
 PASS  REFUTED        UNKNOWN
   │    │               │
   │    └→ reject        ↓
   │              Lifetime Specialist
   │                     ↓
   │              Adversarial Critic
   │                     ↓
   │          semantic-supported / abstain
   └──────────────┬──────┘
                  ↓
        Evidence Broker
 support / contradict / no-evidence
                  ↓
       Deterministic Arbiter
                  ↓
      Final Finding + Audit Evidence
```

确定性证明能够完成时，LLM 不是必经环节。LLM 只处理 Proof Engine 无法在受支持
范围内回答的语义问题；LLM 不能创造 Clang 事实、修改候选身份或把结论升级到
`fact-verified`。

## 2. 与旧设计的关系

旧设计 `docs/superpowers/specs/2026-09-02-cxx-llm-agent-detection-design.md`
描述了四类 CWE 共用的：

```text
Planner
→ Memory/Bounds/Interprocedural Specialists
→ Critic
→ Evidence LLM
→ Verifier LLM
→ Arbiter
```

该设计保留为历史和非 UAF 流程的依据。对于 CWE-416，本文件覆盖旧设计中的以下规则：

- UAF 不再调用 Planner；
- UAF 不再调用 Bounds 或 Interprocedural Specialist；
- UAF 不再调用 Evidence Agent 或 Verifier LLM；
- UAF 不以第二个 Agent 的意见形成验证升级；
- UAF 的 Proof Engine 在 LLM 之前运行；
- UAF 的 `required` 模式只在 Proof 为 `UNKNOWN` 时要求 LLM 分支成功；
- UAF 的 `fact-verified` 只由 coverage-complete 的确定性 P1–P7 证明产生。

除一项共享安全修正外，非 UAF 行为保持不变：外部或待审计仓库不得再默认执行
`CMakeLists.txt` 或其他 build scripts。当前 `LIMA_CXX_AUTO_CMAKE=true` 的默认行为必须由
新的管理员级 trusted-generation 总门禁约束；这是 UAF v2 依赖共享 Sidecar 时不可绕过的
安全前置条件，不是 CWE-415/125/787 检测语义重构。

未被本文件明确覆盖的安全边界继续沿用旧设计，包括固定快照、严格 JSON、路径绑定、
租户隔离、外部源码最小化发送、任务预算和 C/C++ 禁止自动修复。

## 3. 目标与非目标

### 3.1 第一阶段目标

第一阶段必须可靠处理以下 UAF 形态：

- 同一函数、同一 translation unit；
- 原生 `new` 与匹配的 `delete`；
- `malloc` 与 `free`；
- 释放后通过 `*p` 解引用；
- 释放后通过 `p->member` 访问；
- 局部 raw pointer 的直接 alias 赋值及其有限传递；
- Clang 能完整解析且 Proof Engine 能完整覆盖的控制流；
- vulnerable/fixed 配对样例中的 rebind、不可达路径和 lifetime restart 反例。

### 3.2 第一阶段非目标

以下情况不得产生 `fact-verified`：

- 跨函数或跨 translation unit 的 ownership 传播；
- 返回值、回调、容器、成员字段或全局变量中的逃逸 alias；
- 模板实例化、宏展开或条件编译造成关键生命周期事实不确定；
- 自定义 allocator/deallocator 或重载 `operator new/delete`；
- placement new、显式析构与复杂 lifetime restart；
- 并发、信号、协程、异常展开或未建模的异步控制流；
- 函数指针、虚调用或间接调用参与关键生命周期转换；
- 无界循环、不可完整枚举的路径或 Proof Engine 不支持的 CFG 结构；
- compilation database 缺失、fallback 参数、缺失头文件、关键 Clang diagnostic；
- 仅依靠 LLM、Semgrep 空结果、Clang Static Analyzer 空结果或未命中的 ASan 运行。

这些情况可以形成确定性 candidate，并在允许时进入 LLM 语义分析，但最高只能输出
`semantic-supported` 或 `needs-human-review`，默认不参与 verified-only CI 门禁。

## 4. 不可违反的系统不变量

1. **Candidate identity 确定性生成。** 模型只能引用，不能创建或修改身份。
2. **Proof 在 LLM 之前。** PASS/REFUTED 不调用 UAF 推理模型。
3. **事实与意见分离。** Clang 事实是可验证输入；LLM 输出是非权威语义意见。
4. **Agent 共识不升级证据等级。** Specialist 与 Critic 一致也不能形成 D2。
5. **空工具结果不是安全证明。** 所有无命中、未覆盖和未运行均为 `no-evidence`。
6. **`fact-verified` 等于 D2 静态支持。** 它不表示 D3 运行时复现或 D4 完整漏洞验证。
7. **Coverage fail-closed。** 任何关键 coverage gap 都阻止 `fact-verified`。
8. **同一身份贯穿全链。** Build context、fact、candidate、proof、tool evidence 和报告
   必须绑定同一 snapshot/TU/object/candidate。
9. **不可信仓库默认不执行。** 读取已有 compilation database 不授权运行 CMake、Make、
   scripts 或 tests；trusted generation 必须由管理员显式开启并满足全部隔离能力。
10. **运行身份是复合键。** 缓存、Broker、Arbiter、异步任务和数据库只能用
    `(snapshot_hash, candidate_id)` 定位 UAF candidate。
11. **证据强度与方向正交。** `EvidenceLevel` 与 `EvidencePolarity` 必须使用独立字段。
12. **非 UAF 检测语义不变。** 除共享 build-execution 安全门禁外，CWE-415/125/787 的
    已有流程必须通过快照和回归测试。
13. **C/C++ 永不自动修复。** 所有 UAF 状态的 `automatic_repair` 恒为 `false`。

## 5. 证据等级与输出状态

LIMA 的 D0–D4 含义在 UAF v2 中固定为：

| 等级 | UAF v2 含义 |
|---|---|
| D0 | 原始危险操作、工具信号或未经语义绑定的线索 |
| D1 | 局部上下文和语义支持，但至少一个必要 Proof Obligation 为 `unknown` |
| D2 | coverage-complete 静态事实满足全部 P1–P7，或等价的确定性静态反证 |
| D3 | 受控运行真实执行并确认同一 candidate 的 UAF |
| D4 | 影响、前置条件和 machine Oracle 的完整验证；不属于本阶段 |

D-level 只表示证据深度，不能编码证据方向。UAF v2 必须直接复用现有
`lima.contracts.evidence.EvidenceRecord` 的两个正交字段：

```text
level: EvidenceLevel.D0 | D1 | D2 | D3 | D4
polarity: EvidencePolarity.SUPPORTS | REFUTES
```

规范示例：

```text
静态 UAF proof PASS:
  level = D2
  polarity = SUPPORTS

静态 rebind proof REFUTED:
  level = D2
  polarity = REFUTES

同一 candidate 的 ASan 复现:
  level = D3
  polarity = SUPPORTS
```

禁止建立 `D2-support`、`D2-refutes` 等混合枚举或依靠状态名称推断 polarity。

UAF v2 使用以下最终状态：

| 状态 | 证据要求 | CI 默认门禁 |
|---|---|---|
| `semantic-supported` | Proof 为 UNKNOWN，LLM 意见有真实 fact ID 支撑且 Critic 未推翻 | 否 |
| `fact-verified` | build context 与 coverage 完整，P1–P7 全部 satisfied | 是 |
| `tool-corroborated` | 同一 candidate 的工具证据达到 D2；不能只按工具名称判定 | 是 |
| `runtime-confirmed` | 同一 candidate 的有效 ASan/运行时报告达到 D3 | 是 |
| `human-confirmed` | 授权人工确认；本状态本身不自动等于 D4 | 是 |
| `needs-human-review` | 强证据冲突、身份无法安全绑定或关键不确定性需要人工判断 | 否 |

Proof 中任一 obligation 为 `refuted` 时，候选产生 `level=D2, polarity=REFUTES` evidence 并进入
deterministic rejected disposition；它不作为漏洞 Finding 输出，但必须保留审计记录和
拒绝原因。

现有 `llm-candidate`、`agent-corroborated` 状态继续服务未迁移的 CWE。UAF v2 不产生
`agent-corroborated`，也不把 `semantic-supported` 当作 verified 状态。

## 6. Build Context Resolver

### 6.1 职责

Build Context Resolver 为每个 translation unit 解析并固化：

- compilation database 来源；
- compiler argv；
- working directory；
- include 与 system include 路径；
- `-D`/`-U` 宏定义；
- C/C++ language standard；
- target/sysroot 等影响 AST 的参数；
- source file 与生成头文件是否存在于可信快照；
- Clang 版本、解析 diagnostics 和上下文内容哈希。

现有 `cxx_analyzer/build_scan.py` 中的 `BuildContext`、compilation database 搜索、argv
解析和路径约束应被抽取并复用。compilation database 的 `command` 字符串只允许被拆分成
argv 后逐项校验，不能作为 shell 命令直接执行。

### 6.2 解析优先级

外部、PR 或待审计仓库的默认路径为：

```text
1. 仓库快照中已有的 compile_commands.json
2. 基于扩展名和最小参数的 fallback heuristic
```

默认路径不得为了生成 compilation database 而运行 CMake、Make、Ninja、Meson、Bazel、
Autotools、仓库脚本或测试。允许执行 `cmake` 二进制不等于仓库 `CMakeLists.txt` 可信；
`execute_process()`、`file()`、`configure_file()` 和自定义 command 都可能产生副作用。

只有管理员在 Sidecar 部署配置中显式设置：

```dotenv
LIMA_CXX_TRUSTED_BUILD_CONTEXT_GENERATION=true
```

并且 Sidecar capability probe 证明下列隔离条件全部成立时，才启用扩展路径：

```text
1. 仓库快照中已有的 compile_commands.json
2. 隔离 Sidecar 中受控 CMake configure 导出的 compile_commands.json
3. 隔离 Sidecar 中管理员批准的 build-system adapter
4. 基于扩展名和最小参数的 fallback heuristic
```

该开关只能由管理员部署配置设置，单次 API/PR/repository scan 请求、仓库文件、模型输出和
compilation database 都不能开启它。旧的 `LIMA_CXX_AUTO_CMAKE` 只负责在总门禁开启后选择
CMake adapter；它本身不构成执行授权，并且默认值必须改为 `false`。

trusted generation 至少必须满足：

- verified repository snapshot 只读；
- 进程以非 root、`no-new-privileges` 身份运行；
- 无外部网络；
- 除只读 import/snapshot 与专用工具链外，不存在 host path、Docker socket 或 credential
  mount；
- 只有 ephemeral scratch/build directory 可写，请求结束后销毁；
- CPU、memory、PID/process、输出、文件大小和绝对时间均有限制；
- Landlock/namespace 与 seccomp 或等价 syscall restriction 均通过 capability probe；
- 环境中不提供数据库、Git、LLM、云服务或包仓库凭据；
- 任一隔离能力不可用时 fail closed，不运行 build context generation。

Build Context Resolver 的 CMake adapter 只执行生成 compilation database 所需的 configure
阶段，不隐式执行 `cmake --build`。编译、测试和 ASan reproduction 属于独立的显式受控
工具阶段，不能继承 trusted-generation 的授权。

消费仓库已有 compilation database 也不代表信任其中的任意 compiler argv。response file、
compiler plugin、`-Xclang -load`、`-fplugin`、wrapper、路径逃逸和其他可执行扩展必须拒绝或
安全过滤；一旦过滤可能改变 AST 语义，build context 为 `incomplete`。

### 6.3 完整性判定

`BuildContextResolution` 至少包含：

```text
source_kind:
  repository-compdb | cmake-export | build-adapter | heuristic
status:
  complete | incomplete | unavailable
generation_authorized
isolation_capabilities
translation_unit
working_directory
normalized_arguments
context_hash
diagnostics
coverage_gaps
```

只有同时满足以下条件时为 `complete`：

- 精确找到目标 translation unit 的唯一 compilation database 条目；
- 所有关键路径仍位于可信快照或批准的只读工具链目录；
- 影响语义的 include、macro、standard、target 参数已保留；
- Clang 完成解析且没有缺失头文件或影响目标函数的 error diagnostic；
- 目标函数的 AST 与 CFG 均成功生成。

`heuristic` 永远是 `incomplete`。重复或模糊 compilation database 条目、丢失生成头、
参数被安全过滤后可能改变语义、解析恢复产生的 AST，也都必须是 `incomplete`。

Build Context 只回答“是否按照可信的真实编译语义解析了该 TU”。`UafCoverage` 另行回答
“UAF Fact Extractor 与 Proof Engine 是否完整支持目标函数中的相关语义”。最终允许
`fact-verified` 必须同时满足：

```text
build_context.status == complete
+ uaf_coverage.status == complete
+ no critical coverage_gap
```

## 7. UAF 事实模型

### 7.1 稳定对象身份

allocation object ID 使用以下 canonical tuple 的 SHA-256：

```text
schema version
+ canonical repository-relative path
+ function USR
+ allocation AST node begin/end source range
+ allocation kind
```

`allocation kind` 第一阶段只接受受支持的原生 `new` expression 和 `malloc` call。数组、
重载 operator、placement new 或自定义 wrapper 若不能被明确归入受支持语义，则记录为
coverage gap。allocation ordinal 只允许作为调试显示字段，不参与正式身份。

candidate ID 使用以下 canonical tuple 的 SHA-256：

```text
schema version
+ CWE-416
+ object_id
+ release_fact_id
+ use_fact_id
```

因此同一对象的不同 release/use 对不会被错误合并，代码前方插入无关 allocation 也不会
因 ordinal 改变导致所有后续对象身份漂移。`snapshot_hash` 作为强制的独立 provenance 字段
与 object/candidate 一起校验，但不混入稳定主键；跨 snapshot 证据不能因为主键相同而直接
绑定。function USR 缺失时不生成替代字符串身份，而是记录 coverage gap 并禁止 PASS。

`candidate_id` 是跨 snapshot 可稳定复现的局部 ID，不是全局唯一运行身份。内部正式类型为：

```text
CandidateIdentity {
    snapshot_hash: LowercaseSha256,
    candidate_id: CandidateId
}
```

下列边界必须传递并使用完整 `CandidateIdentity`：

- Candidate Generator 之后的 Proof Engine 输入输出；
- Evidence Broker 的 lookup key；
- Arbiter 输入、去重和冲突判断；
- 内存 map/set key 与任务间 cache key；
- 异步消息、持久化记录和数据库唯一约束；
- API 中 UAF proof/evidence bundle 的主身份。

禁止 `dict[candidate_id, ...]`、仅按 `candidate_id` 的数据库查询或跨 snapshot 缓存复用。
wire format 必须使用包含两个命名字段的对象，不能依靠字符串拼接后再拆分。面向用户仍可
单独显示短 `candidate_id`，但任何 evidence binding 必须同时验证 `snapshot_hash`。
Candidate 生成前的 Fact Adapter 以 fact bundle 顶层 `snapshot_hash` 约束全部 facts；任何
fact 一旦引用 candidate，同样必须携带完整 `CandidateIdentity`。

### 7.2 事实种类

第一阶段至少产生：

- `allocation`：对象创建和 allocation kind；
- `points-to`：局部 raw pointer 指向对象；
- `alias-copy`：简单局部 alias 赋值；
- `release`：匹配的 `delete` 或 `free`；
- `dereference`：`*p`；
- `member-access`：`p->member`；
- `rebind`：pointer/alias 改指向其他对象或有效值；
- `lifetime-restart`：同一 storage 上开始新 lifetime；
- `cfg-node` / `cfg-edge`：目标函数内控制流；
- `coverage-gap`：无法安全提取或判断的语义。

每条事实至少绑定：

```text
fact_id
fact_kind
snapshot_hash
build_context_hash
translation_unit
canonical_path
function_usr
source_range
cfg_block
object_id / pointer_id / related_fact_ids
producer_name
producer_version
tool_run_id
```

Fact Adapter 必须拒绝未知字段、重复 ID、悬空引用、越界 source range、快照或 build
context 哈希不一致、无效 producer/tool-run、路径逃逸和超出大小限制的 bundle。主进程
不能通过正则或行号猜测来补全 Sidecar 未提供的事实。

“简单局部 alias”明确限定为同一函数内 local raw-pointer 变量之间、位于具体 CFG edge 上的
直接 copy assignment。Proof Engine 可以对这些 assignment 做传递闭包，但遇到 pointer
address-taken、reference alias、cast、field/array element、解引用赋值、函数传参/返回、循环
alias cycle 或无法区分的 CFG merge 时，相关 obligation 必须为 `unknown`。

## 8. 确定性 Candidate Generator

Candidate Generator 是纯函数，不调用 LLM，不读取评测标签、CVE 描述、修复 diff 或工具
finding。它只把同一对象上的受支持事实组合为待验证的 release/use 对：

```text
allocation/object
+ reachable release candidate
+ syntactically later use candidate
→ UAF candidate
```

“syntactically later”只用于扩大候选召回，不能视为 UAF 证明。路径可达、rebind、lifetime
restart 和 alias 有效性全部由 Proof Engine 判断。

模型和外部工具只能使用已生成的 `candidate_id`。如果返回的 path、CWE、object、release、
sink 与 candidate contract 不一致，该输出整体拒绝。

## 9. P1–P7 Proof Engine

### 9.1 Obligation 定义

每个 obligation 的结果均为：

```text
satisfied | refuted | unknown
```

并携带支持或反驳它的 `fact_ids`、结构化理由和 witness CFG path。

1. **P1 Concrete object exists**：存在受支持、身份完整的 allocation object。
2. **P2 Pointer/alias refers to object**：release/use 所用指针通过受支持 alias 链绑定该对象。
3. **P3 Object is released**：witness path 上存在匹配该对象的有效 release。
4. **P4 Post-release use exists**：同一对象在 release 后通过受支持操作被解引用或成员访问。
5. **P5 Release-to-use path is reachable**：完整 CFG 中存在 release→use structural path，
   且第一阶段的有限规则能够证明该 path feasible。
6. **P6 No pointer rebind on witness path**：选定 witness path 上，参与 use 的 pointer/alias
   未在 release 后被重新绑定到有效对象。
7. **P7 No lifetime restart on witness path**：选定 witness path 上，在 use 前没有恢复该
   storage/object 有效 lifetime 的受支持操作。

P6/P7 针对具体 witness path，而不是所有 CFG 路径。如果存在一条无 rebind/restart 的可达
路径即可支持 UAF；其他安全路径不消灭该漏洞。若路径枚举、条件一致性或 alias 状态不完整，
结果必须为 `unknown`，不能选择性忽略未知路径。

P5 内部必须显式保存两个子结果，而不是把 CFG reachability 当作 path feasibility：

```text
P5Detail {
    structural_reachability: satisfied | refuted | unknown
    path_feasibility: satisfied | refuted | unknown
    witness_cfg_blocks
    guard_facts
    unresolved_constraints
}
```

映射规则为：

```text
structural_reachability == refuted
or path_feasibility == refuted
    → P5 = refuted

structural_reachability == satisfied
and path_feasibility == satisfied
    → P5 = satisfied

otherwise
    → P5 = unknown
```

第一阶段 `path_feasibility=satisfied` 只允许以下情形：

- release 与 use 之间没有条件边的 straight-line path；
- release 与 use 位于同一个、没有嵌套条件边的 guard region，二者共享完全相同的单一
  guard polarity，guard 变量在该 region 内没有 redefinition，且 Clang 未将该 edge 判为
  constant-unreachable；
- Clang constant evaluation 明确证明 witness edge 可执行。

第一阶段 `path_feasibility=refuted` 只允许 Clang constant evaluation 或完整 CFG 明确证明
witness 不可执行。以下情况一律为 `unknown`，不在第一阶段引入 SAT/SMT、symbolic state 或
启发式条件求解：

- 两个或更多不同 branch predicates 需要联合满足；
- 需要推导 `x > 10` 与 `x <= 10` 等谓词关系；
- guard 变量在相关路径上被写入、alias 或来自未建模调用；
- CFG merge、loop、exception edge 或 macro/template 使 guard provenance 不完整。

例如：

```cpp
if (cond) {
    delete p;
    use(*p);
}
```

在 `cond` 未被重定义且两个操作共享同一 guard region 时可以满足 P5；而：

```cpp
if (x > 10) delete p;
if (x <= 10) use(*p);
```

即使 CFG 存在结构路径，第一阶段仍得到
`structural_reachability=satisfied, path_feasibility=unknown`，因此 P5 为 `unknown`。

### 9.2 裁决规则

```text
if any obligation == refuted:
    proof = REFUTED
elif all obligations == satisfied and coverage == complete:
    proof = PASS
else:
    proof = UNKNOWN
```

- `PASS` 直接产生 `level=D2, polarity=SUPPORTS` evidence 和 `fact-verified`；
- `REFUTED` 产生 `level=D2, polarity=REFUTES` evidence 和 deterministic rejection；
- `UNKNOWN` 才允许进入 LLM 分支；
- coverage 不完整时，即使当前可见事实看似满足 P1–P7，也必须是 `UNKNOWN`。

## 10. UAF LLM 语义分支

### 10.1 角色

第一阶段只保留：

- `MemoryLifetimeSpecialist`：解释未知 alias、lifetime 或控制流语义；
- `AdversarialCritic`：主动寻找 rebind、安全条件、不可达路径和身份错配。

UAF 路径删除 Planner、Bounds Specialist、Interprocedural Specialist、Evidence Agent 和
Verifier LLM。Evidence Broker 与 Arbiter 都是确定性组件。

### 10.2 输入与权限

LLM 只接收：

- 不可变 candidate contract；
- 已验证 UAF facts；
- P1–P7 当前结果；
- 明确列出的 coverage gaps；
- 预算内、绑定快照的代码片段。

LLM 只能引用 `candidate_id`、`fact_id` 和已提供源码范围。它不能：

- 修改 path、CWE、object、release 或 use；
- 生成新的 Clang fact；
- 声称 coverage complete；
- 把 `UNKNOWN` obligation 改成确定性 `satisfied`；
- 输出 `fact-verified`、`tool-corroborated` 或 `runtime-confirmed`。

Specialist 和 Critic 输出均需包含：

```text
candidate_id
supporting_fact_ids
refuting_fact_ids
unresolved_assumptions
semantic_assessment
rationale
```

没有真实 fact ID 支撑的肯定结论只能作为未解决假设。Critic 找到无法排除的安全机制时，
最终必须 abstain；两者意见一致最多产生 D1 `semantic-supported`。

### 10.3 PASS/REFUTED 的解释行为

第一阶段不为 PASS 或 REFUTED 额外调用 LLM。报告解释由 Proof Engine 的结构化 obligation、
fact 引用和 witness path 确定性生成。这样保证简单 UAF 的正确性、延迟和成本不依赖模型。

## 11. Evidence Broker

### 11.1 三态接口

Evidence Broker 对每个 candidate 和每个 producer 输出：

```text
support | contradict | no-evidence
```

- `support`：存在同一 `CandidateIdentity` 的有效
  `EvidencePolarity.SUPPORTS` 记录；
- `contradict`：存在同一 `CandidateIdentity` 的有效、显式
  `EvidencePolarity.REFUTES` 记录；
- `no-evidence`：未运行、无 finding、路径未覆盖、身份不匹配或没有可用记录。

Broker verdict 描述外部证据相对当前 hypothesis 的关系；`EvidenceRecord.level` 独立描述证据
深度。Broker 不得把 `support` 自动等同 D2，也不得从 `contradict` 反推固定 D-level。

### 11.2 `contradict` 的严格条件

`contradict` 必须同时具备：

```text
exact candidate identity
+ completed producer run
+ valid provenance and hashes
+ positive EvidencePolarity.REFUTES record
+ refuted proof obligation and referenced facts
```

以下均不是 contradiction：

- Semgrep 没有报告；
- Clang Static Analyzer 没有报告；
- ASan 运行但没有覆盖 witness path；
- 工具未运行、超时或失败；
- 同一位置报告了另一个 CWE；
- symbol/line/path 只能模糊匹配；
- finding 缺少有效 tool-run identity。

这些情况输出 `no-evidence`，并可附带 `coverage_gap` 或 `binding_gap`。Broker 不把无命中
解释为安全，也不因外部工具漏报降低 `fact-verified`。

如果 Proof PASS 与有效 `level>=D2, polarity=REFUTES` evidence 同时存在，Arbiter 输出
`needs-human-review` 并保留两侧证据，不能静默选择任一方。如果工具只提供 support，则按
证据自身的 `EvidenceLevel` 增强记录；不能仅因为 producer 名称是 Semgrep 或 Clang 就自动
认为达到 D2。

## 12. Orchestrator 与 Arbiter

### 12.1 路由

```text
scan trusted C/C++ snapshot
├─ run UAF v2 discovery/proof for the CWE-416 domain
└─ run existing pipeline with CWE-416 excluded
   └─ preserve CWE-415 / CWE-125 / CWE-787 behavior

merge by immutable finding identity
```

UAF v2 不能依赖 LLM 先给输入标注 CWE；release/use seed 由确定性 Candidate Generator 归入
CWE-416 domain。旧流程必须在执行边界排除 CWE-416，避免同一问题同时产生 legacy Agent
候选和 UAF v2 candidate。该隔离必须由源码级边界测试证明，不能只通过提示词告诉旧 Agent
“按新规则工作”。

### 12.2 模式语义

UAF v2 对 `LIMA_CXX_AGENT_MODE` 的定义为：

| 模式 | Proof PASS/REFUTED | Proof UNKNOWN |
|---|---|---|
| `off` | 正常完成，零 LLM 调用 | 不调用 LLM，abstain |
| `auto` | 正常完成，零 LLM 调用 | 尝试 Specialist/Critic；不可用则记录降级并 abstain |
| `required` | 正常完成，零 LLM 调用 | Specialist/Critic 必须按合同完成，否则任务失败 |

因此 `required` 不再表示“每个 UAF 任务必须人为制造一次模型调用”，而表示“当确定性分析
确实需要 LLM fallback 时，该 fallback 不能静默缺失”。Diff-only、fallback build context 等
不完整输入会产生 Proof UNKNOWN；在 `required` 下如果未发生所需 LLM 调用，任务必须失败。

### 12.3 Arbiter 规则

Arbiter 是纯确定性函数，按以下优先级裁决：

1. 身份、provenance、Proof REFUTED 与有效 `level>=D2, polarity=SUPPORTS` 并存，或
   Proof PASS 与有效 `level>=D2, polarity=REFUTES` 并存：`needs-human-review`；
2. 有效 `level=D3, polarity=SUPPORTS` runtime evidence：`runtime-confirmed`；
3. Proof PASS：`fact-verified`；
4. 等价 `level=D2, polarity=SUPPORTS` 工具 evidence：`tool-corroborated`；
5. Proof REFUTED：rejected；
6. Proof UNKNOWN 且 LLM 形成 `level=D1, polarity=SUPPORTS`：`semantic-supported`；
7. 其余：abstain。

Arbiter 不读取自由文本决定等级，只读取已经过合同验证的 enum、fact IDs、evidence level 和
provenance。置信度分数不得越过上述离散状态门禁。

已有的授权人工裁决继续通过现有 adjudication 边界产生 `human-confirmed`，不由自动 Arbiter
推断。人工状态不自动生成 D4 evidence；D4 仍要求独立的影响、前置条件与 machine Oracle
合同。

## 13. 预算、失败与安全行为

- 总 deadline 覆盖 Build Context、Clang extraction、Proof、可选 LLM、Broker 和报告生成；
- `parallelism` 只影响独立 UNKNOWN candidates，不改变确定性排序和输出；
- `dialogue_rounds` 实际限制 Specialist/Critic 往返，不能只解析配置而不生效；
- LLM 严格 JSON 失败允许一次受预算约束的格式修复，之后按模式失败或 abstain；
- Clang/Sidecar 协议失败使相关 build context/coverage 不完整，禁止 `fact-verified`；
- 未覆盖区域必须显示为 coverage gap，不能报告“未发现即安全”；
- 外部模型不得收到环境变量、密钥、Git credential、数据库内容或快照外文件；
- 发现于未跟踪开发材料中的凭据必须在实现开始前轮换并从开发材料移除；
- 提交必须使用精确文件列表，禁止将 `.superpowers` 临时内容混入提交。

## 14. 报告、API 与前端

每个 UAF candidate 的审计视图至少展示：

- candidate/object identity；
- allocation、release、use 的源码位置；
- build context 来源、状态和 hash；
- fact bundle producer、版本和 hash；
- P1–P7 的状态、fact IDs 与 witness path；
- coverage gaps 和 unsupported constructs；
- LLM 是否实际调用、调用次数、模型、token、延迟和失败原因；
- Specialist/Critic 的结构化 fact 引用和 unresolved assumptions；
- Evidence Broker 的三态结果和 provenance；
- 最终状态、D-level、CI 门禁资格和拒绝/abstain 原因；
- `automatic_repair=false`。

`llm_invoked` 必须由实际成功或已发起的 provider call 记录计算，不能从配置模式、计划角色或
提示词存在与否推断。零 LLM 调用的 Proof PASS 必须明确显示“deterministic proof; LLM not
required”，不能显示“LLM invoked”。

API 扩展需保持旧字段向后兼容；新增结构化字段由前端渐进读取。非 UAF Finding 不应被要求
提供 UAF proof bundle。

## 15. 测试矩阵

### 15.1 Build Context

- 默认配置遇到 `CMakeLists.txt` 不执行 CMake 或任何 build script；
- 恶意 `execute_process()` fixture 在默认配置下没有副作用；
- `LIMA_CXX_AUTO_CMAKE=true` 单独存在仍不能越过 trusted-generation 总门禁；
- trusted generation 只有在管理员开关与全部隔离 capability 同时成立时才能运行；
- network、non-root、read-only snapshot、ephemeral scratch、resource limit、Landlock 或
  seccomp 任一 capability 缺失时 fail closed；
- trusted CMake generation 只 configure，不隐式 `cmake --build`；
- 根目录与 `build/` compilation database 优先级；
- 唯一子目录 database；
- 重复/模糊 TU 条目；
- include、macro、standard、target、working directory 保真；
- response file、路径逃逸和未批准参数拒绝；
- 缺失生成头和关键 diagnostic 导致 incomplete；
- heuristic 永远禁止 fact-verified；
- context hash 对相同输入稳定，对语义参数变化敏感。

### 15.2 Fact 与身份

- `new/delete → *p`；
- `new/delete → p->member`；
- `malloc/free → *p`；
- 一层和有限链式局部 alias；
- 无关 allocation 插入后其他 object ID 保持稳定；
- 同一 object 的多个 release/use pair 具有不同 candidate ID；
- 相同 candidate ID 在两个 snapshot 中形成两个不同 `CandidateIdentity`；
- cache、Broker、Arbiter 和持久化 lookup 缺少 snapshot hash 时合同拒绝；
- snapshot A 的 ASan/Clang evidence 不能绑定 snapshot B 的同 candidate ID；
- 路径、range、USR、hash、悬空 fact 引用的 fail-closed 校验。

### 15.3 Proof

- 直接 UAF：P1–P7 全 satisfied；
- release 后 rebind：P6 refuted；
- 有效 lifetime restart：P7 refuted；
- release/use 不可达：P5 refuted；
- 一个安全分支和一条 UAF witness path：可证明存在性；
- straight-line path：structural reachability 与 path feasibility 均 satisfied；
- 同一单 guard region 内的 release/use：在 guard provenance 完整时 satisfied；
- `x > 10` release 与 `x <= 10` use：structural satisfied、feasibility unknown、P5 unknown；
- Clang constant-unreachable edge：path feasibility refuted；
- 路径条件或 CFG 不完整：P5 unknown；
- alias 无法绑定：P2 unknown；
- macro/template/cross-function/custom allocator/concurrency：unknown；
- coverage incomplete 时禁止 PASS。

### 15.4 LLM 与模式

- PASS/REFUTED 在 `off/auto/required` 下调用数均为零；
- UNKNOWN + `off`：abstain；
- UNKNOWN + `auto` + provider unavailable：降级并 abstain；
- UNKNOWN + `required` + provider unavailable：任务失败；
- UNKNOWN + `required` 不能以零调用成功；
- LLM 伪造 fact/candidate/path/CWE 时拒绝整轮；
- Specialist/Critic 一致仍不能产生 D2；
- `parallelism`、`dialogue_rounds` 和总 deadline 实际生效。

### 15.5 Broker 与 Arbiter

- Semgrep/Clang/ASan 空结果均为 no-evidence；
- ASan 未覆盖 witness path 为 no-evidence；
- 同 candidate 的有效 support 保留；
- 正向、同身份、可追溯 refutation 才是 contradict；
- Broker verdict 与 `EvidenceLevel`/`EvidencePolarity` 分别序列化和校验；
- snapshot hash 不同而 candidate ID 相同：no-evidence 加 binding gap；
- 模糊位置或不同 CWE 不是 contradict；
- PASS + no-evidence 仍为 fact-verified；
- PASS + valid contradict 为 needs-human-review；
- runtime-confirmed 必须绑定 completed run 和同一 candidate。

### 15.6 兼容与端到端

- CWE-415/125/787 的 schema、裁决和检测语义保持不变；
- 使用已有 compilation database 或显式 trusted build 配置时，CWE-415/125/787 通过现有
  输出快照回归；默认不可信模式不再自动构建，允许 coverage 下降但必须如实报告 incomplete；
- 整仓与 PR 固定快照均可运行 UAF v2；
- Diff-only 不得 fact-verified；
- API 旧客户端可忽略新增字段；
- 前端完整显示 proof、coverage、Broker 和实际 LLM 调用；
- C/C++ 所有状态均拒绝自动修复；
- Fake LLM、真实模型、Docker/Clang/ASan 证据分别报告，不相互冒充。

## 16. Benchmark 与诊断指标

评测使用固定 vulnerable/fixed 配对，检索、candidate 和模型输入不得读取 case 标签、CVE
描述、修复 diff 或 ground truth。至少记录：

- Candidate Recall；
- Fact-verified Precision / Recall；
- Abstention Correctness；
- Vulnerable/Fixed Paired Accuracy；
- Coverage Gap Rate；
- LLM Calls、Tokens、Latency；
- Proof Obligation Failure Distribution。

最后一项分别统计 P1–P7 的 `unknown` 与 `refuted` 数量和比例，并按 build-context source、
语言标准、项目和代码形态切片。它用于决定下一阶段优先增强 CFG、alias 还是 build context，
不能被汇总成一个掩盖失败原因的总分。

真实模型 CI/手动任务必须包含至少一个确定性 Proof UNKNOWN、确实需要 Specialist/Critic 的
固定样例。否则零调用只能证明 deterministic fast path 工作，不能声称真实模型集成已验证。

## 17. 实施顺序

实现计划必须按以下依赖顺序拆分为可独立测试和提交的任务：

0. 安全材料清理、凭据轮换、trusted build-execution 总门禁与当前基线重建；
1. UAF contracts/models、复合 CandidateIdentity、EvidenceLevel/Polarity 与状态门禁；
2. Build Context Resolver；
3. Clang UAF Fact Extractor；
4. 主进程 Fact Adapter 与 provenance validation；
5. Deterministic Candidate Generator；
6. P1–P7 Proof Engine，包括 P5 structural/feasibility 子结果；
7. Lifetime Specialist 与 Adversarial Critic 的 UNKNOWN-only 路由；
8. Evidence Broker 三态；
9. UAF v2 Orchestrator 与 deterministic Arbiter；
10. Report/API/UI compatibility；
11. paired benchmark、全量回归和真实环境验证。

每个任务采用 TDD：先记录目标测试的 RED，再实现最小行为并记录 GREEN，然后运行相关回归。
每次提交只暂存该任务的明确文件。设计、实现计划、Fake LLM 测试、真实模型结果、Docker/
Clang/ASan 结果和外部 benchmark 证据必须分别标注，不能互相替代。

## 18. 最终验收标准

1. 简单同函数 UAF 在没有 LLM、Semgrep 和 ASan 时可达到 D2 `fact-verified`；
2. 上述 PASS 在 `required` 模式下允许零 LLM 调用并正常完成；
3. Proof UNKNOWN + `required` 不得在零 LLM 调用时成功；
4. rebind、不可达 release/use 和有效 lifetime restart 能形成确定性 refutation；
5. fallback/incomplete build context 永远不能产生 `fact-verified`；
6. 宏、模板、跨过程、复杂 CFG、并发和自定义 allocator 不被错误提升；
7. 模型只能引用真实 candidate/fact，不能改变身份或证据等级；
8. Agent 共识不产生 D2；
9. 无第二 Specialist、Evidence Agent、Verifier LLM 仍可完成 UAF deterministic fast path；
10. 工具空结果始终为 `no-evidence`，不作为安全证明；
11. 只有正向、同身份、可追溯 refutation 才能形成 `contradict`；
12. P1–P7、witness path、coverage、Broker 和实际 LLM 调用完整进入报告/API/UI；
13. 总 deadline、parallelism 和 dialogue rounds 对 UAF v2 真实生效；
14. 报告不能在调用数为零时声称 LLM 已调用；
15. CWE-415/125/787 的 schema、裁决和检测语义不变；已有 compilation database 或显式
    trusted build 配置下通过行为与输出回归；
16. C/C++ 自动修复继续被所有入口拒绝；
17. Proof Obligation Failure Distribution 可按 P1–P7 重算；
18. 真实模型、Docker/Clang/ASan 或外部 benchmark 未实际运行时明确标记“未验证”。
19. 外部/待审计仓库默认不执行 CMake 或其他 build scripts；旧 auto-CMake 开关不能单独授权；
20. 所有内部 candidate lookup、缓存、Broker、Arbiter 和数据库约束使用
    `(snapshot_hash, candidate_id)`；
21. P5 分别报告 structural reachability 与 path feasibility，复杂谓词关系直接 UNKNOWN；
22. 所有 EvidenceRecord 独立保存并校验 `EvidenceLevel` 与 `EvidencePolarity`。

## 19. 冻结决定

以下决定在第一阶段实现中不得由开发者自行放宽：

- 仅迁移 CWE-416；
- Proof-before-LLM；
- PASS/REFUTED 零 LLM 调用；
- UNKNOWN-only Specialist/Critic；
- `fact-verified` 必须是 coverage-complete P1–P7 全 satisfied；
- Evidence Broker 使用严格三态；
- 空结果永远不是 contradiction；
- 复杂和跨过程语义 abstain；
- 稳定 AST identity，不使用 allocation ordinal 作为正式身份；
- `candidate_id` 不是全局运行身份，所有内部绑定使用复合 `CandidateIdentity`；
- 不可信仓库默认禁止执行 build system，trusted generation 是管理员级 fail-closed 门禁；
- P5 分离 structural reachability 与 path feasibility，第一阶段不引入 SAT/SMT；
- D-level 与 support/refute polarity 使用现有 EvidenceRecord 正交字段；
- D2/D3/D4 边界保持不变；
- 除共享 build-execution 安全门禁外，非 UAF 检测语义保持不变。

若实现发现上述决定与 Clang 能力、现有 wire contract 或兼容性要求冲突，必须先更新本设计并
重新获得用户确认，不能通过扩大启发式、放宽 coverage 或增加 Agent 投票静默绕过。
