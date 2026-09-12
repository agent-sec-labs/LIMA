# Erratum Note: DR-IP-0015-03（IP-0015 Frozen Test Commit v1 → v2）

- DR 编号：DR-IP-0015-03（Frozen test 缺陷重冻结，2026-09-12）
- 裁定：Coordinator Merge Gate HOLD（方案 A：撤销 TESTS-FROZEN v1 → v2 重冻结，产品代码零改动）；依据 `docs/LIMA_ISSUE_TO_IP_TO_PR_TO_CLOSURE_LIFECYCLE.md` §22"Frozen test 错误 → 撤销冻结，修订 Packet/test，重新 RED"
- 勘误对象：Frozen Test Commit v1 `97e0b63`（分支 `codex/ip-0015-integration`，8 个测试文件，78 用例）；关联实现 commit `ed774c1`、PR #154
- 处置产物：Frozen Test Commit v2（分支 `codex/ip-0015-integration-v2`，基线 `origin/main` @ `2b1a319d923b59b399b1c5769664624d1aa83362`）
- 旧链处置：`97e0b63` / `ed774c1` / 旧分支原样保留为证据，不改写、不 force 推送

## 1. 缺陷事实（证据链）

1. PR #154 CI 失败（run 34698454088）：CI 单测 job 通过 `scripts/run_ci_tests.py` 执行 `python -m unittest discover -s tests -v`（纯 unittest runner，环境无 pytest）；
2. v1 冻结测试 5 个文件顶层 `import pytest` → `ModuleNotFoundError: No module named 'pytest'`，三个 unit job（ubuntu/windows × py3.11/3.12）全部失败；
3. 更深一层缺陷：8 个冻结测试文件全部为 pytest 裸函数风格（顶层 `def test_*`，0 个 `unittest.TestCase`）——即使删除 import 语句，unittest discover 也将收集 0 个用例（空转绿），不可接受；
4. 验收盲区根因：P&V 本地装有 pytest，验收命令使用 `python -m pytest`，未按 CI 实际 runner（unittest discover）复核收集计数，导致风格性缺陷穿透 RED/GREEN 证明；
5. 仓库正典参照：`tests/contracts/` 39 个文件全部 unittest.TestCase 风格、0 个 pytest 引用，CI 全绿——v2 对齐此风格。

## 2. 处置（方案 A）

1. 撤销 v1 的 TESTS-FROZEN 状态（旧 commit 保留为证据）；
2. 8 个测试文件全部转换为 `unittest.TestCase` 风格：类组织、原生断言（`assertEqual` 等）、`assertRaises` 上下文管理器替代 `pytest.raises`（`ei.value` → `cm.exception`）、`unittest.mock.patch` 替代 `monkeypatch`（涉及 `test_limits.py` 2 个 time-budget 用例、`test_port_sanitize.py` 1 个 internal-failure 用例）；循环内多断言以 `subTest` 保留逐项归因；
3. **78 用例 1:1 保留**：数量不减、断言强度/边界值/需求 ID 锚定注释原样保留、可观察行为（同输入同期望）不变、文件名与用例名不变；
4. 产品代码零改动（`lima/evidence_privacy/` 不在本 commit 中）；Packet 文档不改（缺陷在测试风格，不在 Packet 冻结条款）；CI workflow 不改（CI 改造属 Maintainer 方案 B 决策，超出本授权）。

## 3. v1 → v2 测试映射摘要（文件 × 用例数前后对照）

| 文件 | v1 用例数 | v2 用例数 | 转换要点 |
|---|---|---|---|
| test_classifier.py | 10 | 10 | 裸函数 → `ClassifierTests` |
| test_error_hygiene.py | 8 | 8 | 去顶层 `import pytest`；`pytest.raises`×2 → `assertRaises` |
| test_fingerprint.py | 12 | 12 | 纯断言改写，无 mock |
| test_limits.py | 8 | 8 | `monkeypatch`×2 → `unittest.mock.patch.object(port_mod.time, "monotonic", ...)` / `patch.object(port_mod, "classify_payload", ...)` 等价 |
| test_models.py | 9 | 9 | `pytest.raises`×6 → `assertRaises` |
| test_policy.py | 6 | 6 | `pytest.raises`×4 → `assertRaises` |
| test_port_sanitize.py | 15 | 15 | `pytest.raises`×10 → `assertRaises`；`monkeypatch`×1 → `mock.patch.object` |
| test_value_kinds.py | 10 | 10 | 纯断言改写，无 mock |
| **合计** | **78** | **78** | 文件名、用例名、断言强度、边界值、锚定注释 1:1 |

## 4. 新增验收条件（PI-DR6 候选条款）

1. **冻结测试必须被 `python -m unittest discover` 完整收集且用例计数与 `python -m pytest` 收集计数一致**——两条 runner 的计数一致才能冻结（防止空转绿穿透）；
2. **冻结测试目录静态零 pytest 引用**（`git grep -c pytest -- tests/<dir>` 零命中，含 import、装饰器、fixture、monkeypatch、注释字样）。

## 5. v2 重新 RED 与三重证明（P&V 亲验，2026-09-12，worktree `D:\BaseAIProject\LIMA-ip0015-pv-wt`，Python 3.12）

- 有效 RED（基线 `origin/main` @ `2b1a319`，无产品代码）：
  - `python -m pytest tests/evidence_privacy -q` → 8 collection errors，全部 `ModuleNotFoundError: No module named 'lima.evidence_privacy'`（exit 2）；
  - `python -m unittest discover -s tests/evidence_privacy -v` → `Ran 8 tests / FAILED (errors=8)`，全部为同一 `ModuleNotFoundError`（exit 1）；
  - 归因：失败来自 `lima.evidence_privacy` 目标行为缺席（8 个模块级 import），非测试 arrange 缺陷。
- scratch GREEN（PI-DR2 复证）：将 impl worktree（`D:\BaseAIProject\LIMA-ip0015-impl-wt`，只读）的 `lima/evidence_privacy/` 7 文件复制到 worktree 外 scratch（`D:\BaseAIProject\.pv_scratch_ip0015`），实跑：
  - `python -m pytest tests/evidence_privacy -q` → **78 passed**（exit 0）；
  - `python -m unittest discover -s tests/evidence_privacy -v` → **Ran 78 tests / OK**（exit 0）；
  - scratch 于记录后销毁，不入 commit。
- 静态检查：`git grep -c pytest -- tests/evidence_privacy` → 0 命中（exit 1）。
- 回归：`python -m pytest tests/contracts -q` → 617 passed（exit 0）。
