# CWE 漏洞范围扩展实施计划（C 线）

依据：GitHub Epic [#185](https://github.com/agent-sec-labs/LIMA/issues/185) 及子任务
#186–#197（2026-09-19 用户确认）。核心决策：**链 A（Sidecar 分析器链）冻结不再
开发，一切扩展投入链 B（平台智能体链）**；`cxx_analyzer/repro.py`（复现工作台）
属链 B 仪器，继续开发。

基线：HEAD 以动工时为准（计划编写时 `f657a9c`，宿主全量 1996 tests 双平台绿）。
工作流沿用：每任务 TDD（RED→GREEN）→ 独立复审 → 目标回归 → Signed-off Commit
→ 计划勾选 + issue 同步；里程碑任务跑双平台全量（宿主 mirror + 容器 pathspec 同步法）。

硬边界：
- **链 A 冻结清单，零改动**：`cxx_analyzer/rules/cxx-memory.yml`、
  `cxx_analyzer/source_scan.py`（`_RULE_PREFIXES`）、`cxx_analyzer/normalizers.py`
  （`SUPPORTED_CWES`）、`cxx_analyzer/sanitizer_scan.py`（`_map`）及对应链 A 测试
  文件（作冻结基线，保持绿不编辑）
- 受保护文件（根 `Dockerfile`、`tests/test_service.py`）只运行不编辑
- `.superpowers/` 不入库；沙箱五层锁不放宽
- 改 `ANALYZER_COMPONENTS` 清单内文件的任务，最后一步刷新校准指纹
  （`evaluation_data/popular_external_calibration_v2.json`，先例 ed379dd/85b95c9）；
  C1.4/C1.5 碰 `cxx_analyzer/repro.py` 时先核实该文件是否在清单内
- worktree 现存 A 线未提交改动（`deploy/build-recipes/resinsight/`）：C 线提交
  严格 pathspec 只加自己的文件，不碰不混

通用命令：`PY=./.venv/Scripts/python`（worktree 根目录执行）。

---

## issue / PR 同步协议（每任务强制执行）

分支与 PR：
1. 每任务一分支：`codex/cwe-<任务号>-<短名>`，**fork 自
   `codex/cxx-llm-agent-detection`**（链 B 代码只在该分支；#183 合并 main 后，
   新任务改 fork 自 main 且 PR base 切 main）
2. PR base = `codex/cxx-llm-agent-detection`，squash 合并（仓库惯例），正文含
   `Closes #<issue号>` + 验收标准复述 + 测试证据（数字，不贴大段日志）
3. 一功能点 = 一 issue + 一小 PR；禁止多任务混包（#164 教训）

状态同步（触发点绑定任务循环节点）：
- **开工**（RED 前）：对应 issue 加 `status:in-progress` 标签（git credential
  token 调 API）
- **PR 开启**：PR 描述 `Closes #N` 自动双向引用，无需手动评论
- **合并后**：issue 自动关闭 → **勾 Epic #185 对应 checkbox** → 勾本计划对应
  任务 checkbox（台账；沿用 Python 脚本限定任务标题范围 + 断言翻转计数，防
  write-before-assert 丢失翻转）
- **阻塞/设计**：`status:blocked` / `status:needs-design`；C2.1 在设计过审前
  保持 needs-design
- **偏差处理**：实施中发现 issue 验收标准需修改 → 先更新 issue 正文再继续，
  计划与 issue 谁先改就同步另一个，不允许长期分叉

---

## Task 0: 计划入库

**Files:**
- Add: 本计划文档

**Steps:**
- [ ] 0.1 用户确认后入库：`docs: plan CWE expansion C-line (epic #185)`
- [ ] 0.2 推送后在 Epic #185 评论挂本计划链接（docs/ 路径 + 分支名）

---

## Task C0.1: orchestrator 漏洞包注册表化（#186）

设计要点：兑现 `vuln_packs/__init__.py` "新类别 = 数据 + register_pack，零内核
改动"的承诺。四处 MEMORY_PACK 硬编码改注册表驱动。

**Files:**
- Modify: `lima/agent_orchestrator.py`（`:158` marker 表、`:186` `_PLATFORM_SCHEMA`
  枚举串、`:194` 提示词拼接、`:316` cwe 校验）
- Modify: `lima/vuln_packs/__init__.py`（如需新增注册表并集辅助函数）
- Modify: `tests/test_agent_orchestrator.py`、`tests/test_vuln_packs.py`

**Steps:**
- [ ] C0.1.1 RED：测试临时注册假 pack（含新造 CWE id）→ 断言其出现在 Specialist
  枚举串、通过 cwe 校验、marker 并入命中表；卸载后不残留
- [ ] C0.1.2 GREEN → 全量 golden 对比（零行为变化）
- [ ] C0.1.3 提交：`refactor: drive platform CWE vocabulary from the vuln pack registry`
- [ ] C0.1.4 PR + issue 同步（Closes #186 + 勾 epic）

---

## Task C0.2: 链 B 词汇表自持（#187）

**Files:**
- Modify: `lima/cxx_agents.py`（`:114` import 与 `:438` 门禁切到注册表词汇表）
- Modify: `tests/test_cxx_agents.py`

**Steps:**
- [ ] C0.2.1 RED：注册含新 CWE 的 pack 后 `cxx_agents` 门禁放行；现有 4 类行为
  不变
- [ ] C0.2.2 GREEN → 目标回归（test_cxx_agents + test_agent_orchestrator）
- [ ] C0.2.3 里程碑全量（宿主 + 容器）——**阶段 0 完成点**
- [ ] C0.2.4 提交：`refactor: source agent CWE gate from the pack registry`
- [ ] C0.2.5 PR + issue 同步（Closes #187 + 勾 epic）

---

## Task C1.1: marker 最长具体匹配（#188）

**Files:**
- Modify: `lima/agent_orchestrator.py`（`_experiment_hit:750` 子串匹配改最长优先）
- Modify: `tests/test_agent_orchestrator.py`

**Steps:**
- [ ] C1.1.1 RED：`stack-buffer-overflow` 注入假观察 → 现状归 787/125，断言
  最长匹配后归 121（前提：测试本地注册含 121 的 pack，不依赖 C1.3）
- [ ] C1.1.2 GREEN → 现有 6 类合成评测 + golden 分类零回归
- [ ] C1.1.3 提交：`fix: match runtime markers longest-first`
- [ ] C1.1.4 PR + issue 同步（Closes #188 + 勾 epic）

---

## Task C1.2: 检索层消费 seed_patterns（#189）

**Files:**
- Modify: `lima/cxx_retrieval.py`（`_CandidateAccumulator` 新增 pattern 种子类型）
- Modify: `lima/vuln_packs/__init__.py`（seed_patterns 消费视图，如需）
- Modify: `tests/test_cxx_retrieval.py`

**Steps:**
- [ ] C1.2.1 RED：含 pattern 种子的 pack 注册后，匹配形状产出 lead 并进排名；
  干净形状（带边界检查）不产 lead；排序测试不回归
- [ ] C1.2.2 GREEN → 目标回归（test_cxx_retrieval + test_agent_scout）
- [ ] C1.2.3 提交：`feat: consume pack seed patterns in retrieval`
- [ ] C1.2.4 PR + issue 同步（Closes #189 + 勾 epic）

---

## Task C1.3: CWE-121/122 栈/全局越界包（#190）

**Files:**
- Create: `lima/vuln_packs/stack_global.py`（marker：stack→121、global→122；
  seed_patterns；Specialist addendum）
- Modify: `lima/repro_templates.py`（栈/全局越界 driver 模板）
- Modify: `tests/test_vuln_packs.py`、`evaluation_data/platform_cases/cases.json`
  （1 正 1 负）

**Steps:**
- [ ] C1.3.1 RED：pack 合同测试（六件套完整性 + marker 映射）
- [ ] C1.3.2 GREEN → 端到端：栈越界 PoC 经种子→Scout→假设→ASan
  `stack-buffer-overflow`→最长匹配命中 121→确认（fake 模型即可）
- [ ] C1.3.3 容器实证：真实 clang-14 + ASan 栈/全局各一驱动
- [ ] C1.3.4 提交：`feat: add CWE-121/122 stack and global overflow pack`
- [ ] C1.3.5 PR + issue 同步（Closes #190 + 勾 epic）

---

## Task C1.4: CWE-401 泄漏包 + 非崩溃确认（#191）

**Files:**
- Modify: `cxx_analyzer/repro.py`（正常退出 + 退出码 23 + LSan 块分支；分配栈
  不含快照源不确认）
- Create: `lima/vuln_packs/leak.py`
- Modify: `lima/repro_templates.py`、`tests/test_repro_protocol.py`、
  `tests/test_vuln_packs.py`、`evaluation_data/platform_cases/cases.json`

**Steps:**
- [ ] C1.4.0 核实 `cxx_analyzer/repro.py` 是否属 ANALYZER_COMPONENTS（决定指纹
  刷新义务）
- [ ] C1.4.1 RED：LSan 报告解析（泄漏字节/分配栈/退出码）；fail-closed 三态
  （无泄漏块 / 泄漏在 driver 自身 / 泄漏定位快照源）
- [ ] C1.4.2 GREEN → 容器实证（真实 LSan 报告）
- [ ] C1.4.3 提交：`feat: add CWE-401 leak pack with non-crash confirmation`
- [ ] C1.4.4 PR + issue 同步（Closes #191 + 勾 epic）

---

## Task C1.5: UBSan 进工作台，闭环 CWE-190（#192）

**Files:**
- Modify: `lima/vuln_packs/__init__.py`（VulnPack 声明 sanitizer 集）
- Modify: `cxx_analyzer/repro.py`（按 pack 组装 argv，每类别钉死保确定性；
  `-fno-sanitize-recover=undefined`；UBSan 报告解析器）
- Modify: `lima/vuln_packs/memory.py`（CWE-190 声明 address+undefined）
- Modify: `tests/test_repro_protocol.py`、`tests/test_vuln_packs.py`、
  `evaluation_data/platform_cases/cases.json`

**Steps:**
- [ ] C1.5.1 RED：UBSan 报告解析合同（`runtime error:` 形状、停机语义、未知
  marker 拒认）
- [ ] C1.5.2 GREEN → 容器实证（`n * 6` 环绕 PoC 产 UBSan 报告并确认）；
  ASan-only 类别行为零变化
- [ ] C1.5.3 里程碑全量（宿主 + 容器）——**阶段 1 完成点**；如触发指纹义务，
  全部源码编辑完成后最后刷新
- [ ] C1.5.4 提交：`feat: add UBSan workbench support closing CWE-190`
- [ ] C1.5.5 PR + issue 同步（Closes #192 + 勾 epic）

---

## Task C2.1: 行为哨兵确认通道（#193，先设计后实施）

**Files:**
- Create: `docs/superpowers/specs/2026-09-19-sentinel-confirmation-design.md`
- Modify: `cxx_analyzer/repro.py`（实验前布防/实验后检查步骤）
- Modify: `lima/vuln_packs/__init__.py`（"确认模式"字段：crash-marker/sentinel）
- Modify: `lima/agent_orchestrator.py`（行为证据档位映射 D0-D4）
- Modify: `tests/test_repro_protocol.py`、`tests/test_agent_orchestrator.py`

**Steps:**
- [ ] C2.1.1 设计文档：哨兵三类（PATH shim / 根外哨兵文件 / 高熵秘密串）、
  布防与归因校验（哈希匹配）、payload 禁令清单、landlock 诱饵区方案、
  证据档位映射；**用户过审**
- [ ] C2.1.2 RED：fail-closed 三律（哨兵没碰=不确认 / 崩溃≠确认 / 哈希不匹配
  =不确认）
- [ ] C2.1.3 GREEN → 容器实证（假 pack 走通哨兵通道正反例）
- [ ] C2.1.4 提交：`feat: add sentinel confirmation channel to the workbench`
- [ ] C2.1.5 PR + issue 同步（Closes #193 + 勾 epic）；设计过审前保持
  needs-design

---

## Task C2.2: CWE-78 命令注入包（#194，依赖 C2.1）

**Files:**
- Create: `lima/vuln_packs/command_injection.py`
- Modify: `lima/repro_templates.py`、`tests/test_vuln_packs.py`、
  `evaluation_data/platform_cases/cases.json`

**Steps:**
- [ ] C2.2.1 RED → GREEN：正例端到端行为确认（shim 哨兵 + payload 哈希）；
  负例（quoting/白名单防护）零误报
- [ ] C2.2.2 容器实证 → 提交：`feat: add CWE-78 command injection pack`
- [ ] C2.2.3 PR + issue 同步（Closes #194 + 勾 epic）

---

## Task C2.3: CWE-22 路径遍历包（#195，依赖 C2.1）

**Files:**
- Create: `lima/vuln_packs/path_traversal.py`
- Modify: `lima/repro_templates.py`、`tests/test_vuln_packs.py`、
  `evaluation_data/platform_cases/cases.json`

**Steps:**
- [ ] C2.3.1 RED → GREEN：`../../` 触达诱饵哨兵确认；诱饵区不削弱沙箱其余
  路径限制（安全断言）
- [ ] C2.3.2 容器实证 → 提交：`feat: add CWE-22 path traversal pack`
- [ ] C2.3.3 PR + issue 同步（Closes #195 + 勾 epic）

---

## Task C2.4: CWE-200/532 信息泄露包（#196，可砍，视比赛时间）

**Files:**
- Create: `lima/vuln_packs/info_leak.py`
- Modify: `lima/repro_templates.py`、`tests/test_vuln_packs.py`、
  `evaluation_data/platform_cases/cases.json`

**Steps:**
- [ ] C2.4.1 RED → GREEN：高熵哨兵秘密串出现在输出确认；负例零误报
- [ ] C2.4.2 容器实证 → 提交：`feat: add CWE-200/532 information leak pack`
- [ ] C2.4.3 PR + issue 同步（Closes #196 + 勾 epic）

---

## Task C3: 评测基线与收尾（#197，穿插执行）

**Files:**
- Modify: `evaluation_data/platform_cases/cases.json`（汇总核对每类 1 正 1 负）
- Modify: `tests/test_platform_evaluation.py`

**Steps:**
- [ ] C3.1 全类别平台评测：正例端到端确认、负例零误报、老六案例 + 合成评测
  全绿（detection/FP/convergence/stability 四维）
- [ ] C3.2 里程碑双平台全量——**阶段 3 完成点**；链 A 测试未编辑仍绿（冻结
  基线证明）
- [ ] C3.3 台账与 handoff 更新 → 提交：`test: freeze CWE expansion evaluation baseline`
- [ ] C3.4 PR + issue 同步（Closes #197 + 勾 epic + Epic #185 收尾评论）

---

## 里程碑与时间对齐

- 阶段 0 完成点：C0.2.3（全量）
- 阶段 1 完成点：C1.5.3（全量）；此后任意时点停下平台自洽可交付
- 阶段 2 完成点：C2.x 各自目标回归；CWE-78/22 须赶在 OpenHarmony 大规模检测
  （B2）之前就位
- 阶段 3 完成点：C3.2（全量）
- 比赛截止 2026-10-22；C2.4 为唯一显式可砍项
