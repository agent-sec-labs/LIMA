# repro 实验编译的语言模式与语义上下文参数修订计划

> **性质：** 冻结面修订小切片。依据：OpenHarmony pilot 资格审查实证（见
> `docs/superpowers/plans/2026-10-02-openharmony-pilot-validation.md` 的 rejection
> ledger 与 `.zcode/reports/2026-10-02-openharmony-cwe416-candidates.md` §9-§10）。
> 本切片不改实验语义（sources 范围、命中判定、ASan 解析全部不动）。

**Goal:** 让 `/v1/repro` 的实验编译能处理纯 C 目标：`.c` 源用 C 语言模式编译，
且目标 TU 在可信 `compile_commands.json` 里声明的语义参数（`-I`/`-D`/`-U`/
`-std`/`-target`/`--sysroot`/`-isystem`）进入实验编译命令，与 facts 提取共用同一
构建上下文。

**死因背景（两例实证）：** clang++-14 把 `.c` 当 C++ 编（void* 隐式转换报错）；
冻结 argv 无法传熵源/功能宏（expat 无 `-DXML_POOR_ENTROPY` 直接 `#error`）。

## 设计红线

1. **`.cpp`-only 的 argv 逐字节不变。** 现有冻结断言
   `test_compile_argv_is_pinned_and_deterministic` 不修改、继续绿；`.c` 支持是纯
   扩展。
2. **语言模式：** 命令中每个 `.c` 源前插 `-x c`，driver 前插 `-x c++`（仅当存在
   `.c` 源时）；非 `.c` 源不加 `-x`。
3. **语义参数来源：** `run_repro` 用 `resolve_build_context_execution`（复用
   snapshot-compdb 的既有信任模型：路径必须在快照内、ambiguous/invalid 条目降级
   incomplete）解析每个 source；仅 `resolved` 上下文贡献
   `semantic_arguments(arguments)`。**全部 source 都 resolved 才启用，取交集**
   （首现顺序）；任一 source 未解析（含无 compdb 的启发式模式）→ 零参数，行为与
   现状完全一致。
4. **参数形状防御：** `build_compile_argv` 校验传入的 context flags 必须是
   `SEMANTIC_ARG_OPTIONS` 形状（选项+值或 joined 前缀形式），其余 token 拒绝。
5. **协议不变：** wire 请求/响应零改动（`REPRO_SCHEMA_VERSION` 保持 1），全部
   改动在 sidecar 服务端。

## 文件

- 修改 `cxx_analyzer/repro.py`：`build_compile_argv` 语言模式与 flags 参数；
  `run_repro` 可选 `settings` 参数 + `_context_flags` 解析。
- 修改 `cxx_analyzer/server.py`：`repro_request` 把 settings 传入 `run_repro`。
- 修改 `tests/test_cxx_analyzer.py`：新增 argv/形状防御/run_repro 级测试（C 源 +
  compdb 夹具，只有 `-D` 到位才能编译链接成功），不动现有冻结断言。

## 任务

1. **RED**：新增三个测试——`.c` 语言的 argv 钉死形状（含混合顺序）；context
   flags 的钉死位置与非语义 token 拒绝；`run_repro` 级夹具（`src/feature.c` 的
   函数在 `-DPILOT_FLAG` 下才存在，驱动调用它，期望 `ok=True`）。
2. **实现**：按红线 2-4 改 `repro.py`，`server.py` 传 settings。
3. **回归**：`tests.test_cxx_analyzer` 全绿（含未修改的旧冻结断言）；容器内用
   expat 脆弱快照 + compdb 走真实 `run_repro` 验证编译与运行（pilot 资格审查的
   终验）。
4. 提交，issue 关联 pilot epic。

## 不做

- 不扩展实验 sources 语义（平台仍传单目标；多源能力属后续计划）。
- 不改 `/v1/repro` wire 协议、ASan 解析、命中判定、沙箱安全面。
- 不实现 compdb 生成（trusted generation 门禁维持现状）。
