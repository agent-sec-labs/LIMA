# Erratum Note: DR-IP-0020-2（IP-0020 Frozen Test Commit v1 → v2）

- DR 编号：DR-IP-0020-2（Frozen test 平台可移植性缺陷重冻结，2026-09-13，Coordinator 裁定 `COORD-IP0020-CI_DR_RULING_2026-09-13.md` §①/§③）
- 勘误对象：Frozen Test Commit v1 `1c4729208e3e1cb8e63bf819bfa28ca89c8b4d30`（分支 `codex/ip-0020-frozen-tests`，6 个冻结文件：2 测试 + 4 fixture）；关联实现 commit `5256392044894fc6f1fa525945978831b473abf2`、PR #175
- 处置产物：Frozen Test Commit v2（分支 `codex/ip-0020-frozen-tests-v2`，基线 = `origin/main` @ `1a98fee8c6e5b0e4bcd04f820b4817e66bbdfa9e`，Packet v1.1 merge，fetch 复核无漂移）
- 旧链处置：`1c47292` / `5256392` / 旧分支原样保留为证据，不改写、不 force 推送
- 关联 DR：DR-IP-0020-3（container 镜像未打包 `scripts/audit_sensitive_artifacts.py`，推荐 Dockerfile 一行 COPY，**Pending Maintainer**，不在本 erratum 处置范围）

## 1. 缺陷事实（证据链）

1. PR #175 CI：unit-ubuntu py3.11/3.12 红，唯一失败源为 `tests/evidence_privacy/test_readonly_audit.py` `test_script_output_inside_target_dir_rejected` 反斜杠变体（v1 :355 `str(FIXTURE_DIR) + "\\nested\\..\\report.json"`）；失败签名 `AssertionError: 0 == 0`（CI 日志 `PV-IP-0020-CI_UBUNTU_PY312_LOG_2026-09-13.log:1579-1589`，Coordinator 亲验）。
2. 根因：POSIX 上 `\` 非路径分隔符，该字面路径 `resolve()` 后真实位置在 target 目录**外**；脚本写 target 外、exit 0，恰恰符合 Packet §8.3.3 契约（`--output` 仅拒绝解析于 target 内的路径）。同理 `Audit_Samples` 大小写变体在大小写敏感 FS 上解析于 target 外，属合法外部输出。
3. 传导路径：Packet §11.5 "覆盖 Windows 变体……各变体均须判越界" 的表述把 Windows 专属分隔符/大小写变体当作跨平台越界断言写入冻结测试，属**冻结测试缺陷**而非产品缺陷（产品三文件在 CI 红前后零改动）。
4. 归类：与 DR-IP-0015-03 同类（生命周期 §22 "Frozen test 错误 → 撤销冻结，修订 Packet/test，重新 RED"），不触发 Packet §14.6 升级。

## 2. 处置（裁定方案："平台条件断言 + 新增 os.sep 跨平台真越界变体"两者结合）

1. 撤销 v1 的 TESTS-FROZEN 状态（旧 commit 保留为证据）。
2. 仅修改 `test_script_output_inside_target_dir_rejected` 的变体表：
   - Windows 专属变体（反斜杠 `\\nested\\..\\report.json`、`Audit_Samples` 大小写变体）以 `sys.platform == "win32" and os.sep == "\\"` 条件化，仅在 Windows 上纳入必断言集；断言强度不削弱（Windows 上仍全量断言非零退出 + 零泄漏 + fixture 不变）。
   - **新增两个 os.sep 构造的跨平台真越界变体**：`FIXTURE_DIR + os.sep + "nested" + os.sep + ".." + os.sep + "report.json"`（`/sub/../report.json` 既有项的跨平台强化补充）与 target 内子目录多级 `..` 回落变体 `FIXTURE_DIR + os.sep + "sub" + os.sep + ".." + os.sep + ".." + os.sep + "audit_samples" + os.sep + "report.json"`——三平台均存在"真实解析于 target 内 → 必须拒绝"的正例，覆盖强度不降反升。
3. 用例名、文件名、§8.3.3/§9 T3/§11.5 锚定注释保留（新增 DR-IP-0020-2 修订注释）；用例数不变；其余 5 个冻结文件零改动（fixture blob 不变，仍确保在 v2 树中）。
4. 产品三文件（`lima/evidence_privacy/vault_port.py`、`lima/evidence_privacy/audit.py`、`scripts/audit_sensitive_artifacts.py`）**零改动**：`5256392` 经 cherry-pick 机械重挂，`git diff 5256392 <v2-impl-head> -- lima/evidence_privacy scripts` 空 diff 逐字节等价。
5. Packet §11.5 表述修订（记录性）："Windows 专属分隔符变体（反斜杠/大小写）仅于 Windows 断言；跨平台真越界变体以 os.sep 构造。"

## 3. v1 → v2 变体表映射（test_script_output_inside_target_dir_rejected）

| v1 变体（1c47292） | v2 处置 |
|---|---|
| `FIXTURE_DIR / "report.json"` | 1:1 保留（跨平台断言） |
| `str(FIXTURE_DIR) + "\\nested\\..\\report.json"` | 保留字面量，**Windows 条件断言**（`sys.platform`/`os.sep`） |
| `str(FIXTURE_DIR) + "/sub/../report.json"` | 1:1 保留（POSIX 分隔符在两平台均解析于 target 内，跨平台断言） |
| `Audit_Samples` 大小写变体 | 保留字面量，**Windows 条件断言**（大小写不敏感 FS 上解析于 target 内） |
| —（新增） | `os.sep` 构造 `nested/..` 回落变体（跨平台断言） |
| —（新增） | `os.sep` 构造多级 `sub/../..` 回落变体（跨平台断言） |

用例数：v1 = v2（单用例内 subTest 变体数：POSIX 4→5，Windows 4→6，均为增强方向）。

## 4. 记录性勘误（不触及冻结接口/测试/Oracle，不改变可观察行为）

1. **Packet §8.3.6 措辞扩写**：脚本对 `DEFAULT_POLICY` 的 import 属 `lima.evidence_privacy.audit` 模块自身 import 闭包（脚本仅依赖 `lima.evidence_privacy.audit` 公开接口，`DEFAULT_POLICY` 不进入脚本命名空间）。记录性澄清，无行为变化。
2. **Packet §8.2.4 澄清**：structured 值整值命中（span 覆盖完整值）时报告该整值 span，不重复报告其内部子 span。记录性澄清，与冻结测试断言一致。

## 5. DR-IP-0020-3 状态记录

container-read-only CI 红因 Dockerfile 未打包 `scripts/audit_sensitive_artifacts.py`（6 用例环境性失败），属 Packet 测试计划与镜像打包之间的范围缺口；推荐方案 (i) Dockerfile 一行 COPY。状态：**Authorized（2026-09-13，Maintainer 授权，原文逐字记录如下）**。本 erratum §1–§4、§6（v2 重冻结）不触及 Dockerfile；§5.1 的文件边界例外为授权后新增处置，仅涉及 Dockerfile test 阶段一行 COPY。

> Maintainer 授权原文（2026-09-13）：
> "授权 DR-IP-0020-3，但仅限在 Dockerfile 的 **FROM base AS test 阶段**增加所提的一行审计脚本 COPY；**不得放入 base 或 runtime 阶段**，不改基镜像、其他构建指令或测试断言。请将文件边界例外记入 DR/Packet 勘误，用 v2 冻结链创建替代 PR，并在最新 main 上核验完整 diff、Linux/Windows 单测及容器 CI。旧 PR #175 保持 HOLD，待替代 PR 可追溯后再关闭。CI 与 P&V 全绿后，把完整审查包交给 Maintainer；未经其书面安全审查，不得标记 G3 PASS 或合并。"

### 5.1 文件边界例外（DR-IP-0020-3 授权范围，Packet 文件边界勘误）

- **授权范围（仅此一项）**：在 Dockerfile `FROM base AS test` 阶段内（既有 test 阶段 COPY 之后）新增一行：`COPY --chown=lima:lima scripts/audit_sensitive_artifacts.py ./scripts/audit_sensitive_artifacts.py`
- **禁止项**：不得放入 base 或 runtime 阶段；不改基镜像（ARG PYTHON_BASE_IMAGE / NODE_BASE_IMAGE digest）；不改任何其他构建指令；不改测试断言。
- **例外效力**：本文件边界例外仅对 IP-0020 本行生效，不构成对 Packet 其他 Must-not-modify 边界的放开；冻结测试零改动。


## 6. v2 重新 RED 与证明（P&V 亲验，2026-09-13，worktree `D:\BaseAIProject\LIMA-ip0020-pv-wt`）

- 有效 RED（v2 commit 树，无产品三文件）：`python -m pytest tests/evidence_privacy -q` 与 `python -m unittest discover -s tests/evidence_privacy -v` 全部失败于 `ModuleNotFoundError: No module named 'lima.evidence_privacy.audit'` / `vault_port`（缺失交付触发，非 arrange 缺陷）。
- 改造后用例在 Windows + 实现下 GREEN（含 Windows 条件变体与新增 os.sep 变体全量断言）。
- 双 runner 计数一致（PI-DR6）；`git grep -c pytest -- tests/evidence_privacy` 零命中。
- §12 全量复跑与等价性空 diff 证明见 `PV-IP-0020-REFREEZE_WORKLOG_2026-09-13.md`。
