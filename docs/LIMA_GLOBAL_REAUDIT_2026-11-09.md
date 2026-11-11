# LIMA 全局复审：修复语义与独立验证（2026-11-09）

本轮接续 `LIMA_GLOBAL_AUDIT_FIXES_2026-11-09.md`，基线为 HEAD `fcd098562001d1d610134c86e3a92e15cde1ea72` 加当前未提交修复。结论针对本地工作区，不代表远程 main 或指定 PR。

本轮未修改生产代码、未提交或推送、未调用 GitHub 写接口。检查 README、交接标准、来源绑定/outbox/取消修复以及修复规划、Oracle、差分复扫和预览链路。主要新发现是下面两项 P1：它们均有运行证据，不能只通过增加文档说明解决。

## F1 / P1：固定可执行文件加 shell=False，仍可能执行不可信代码

位置：`lima/security_repair.py:272` 的 `_command_argv`、`lima/verifier.py:113` 的 `argv-no-shell` Oracle，以及 `lima/verifier.py:305` 的差分放行条件。

当前模板只要求首个 argv 元素为固定字符串、其余动态值为独立参数，再把 `shell=True` 改为 `False`。没有判断固定程序及参数是否会继续把动态值解释为脚本。例如：

```python
import subprocess
value = input()
subprocess.run('python -c ' + value, shell=True)
```

模板会生成语义等价于：

```python
subprocess.run(['python', '-c', value], shell=False)
```

动态值仍然是 Python 源代码。`sh -c` 等解释器入口有同类风险。固定程序并不意味着动态参数只能作为普通数据。

离线探针使用本机 Python 的固定完整路径替代示例中的 `python`，对自己编写的极小夹具进行修复。输入仅为固定的 `print('LIMA_BENIGN_CODE_MARKER')`，修复后确实执行了该表达式并输出标记。未执行目标仓库代码，也未访问外部服务。

验证结果：

- 编译和 security Oracle 均通过；
- 差分复扫通过，目标计数从 2 变为 0；
- 真实 RepositoryRepairPreviewer 返回 `verified-preview`；
- 不可信输入仍然被执行为代码。

根因是生产检测与差分验证只把 `shell=True` 视为此类 subprocess 汇点；去掉这个标志后告警消失，但后续解释器风险没有被独立验证。

建议：修复规划必须证明动态参数的语义安全。当前受限能力至少拒绝无法证明安全的解释器、命令分发器和会执行脚本/表达式的参数位置；不能仅维护几个程序名的黑名单，因为绝对路径、包装程序和不同命令模式均可能产生同类行为。独立 Oracle 应复核该证明，而非只检查 argv 形状；补充解释器及参数解释行为的负例。无法证明的情况返回拒修，不得标为已验证修复。

## F2 / P1：路径根目录的可信证明忽略实际作用域绑定

位置：`lima/security_repair.py:431` 的 `_trusted_root`，尤其是 `:452` 使用模块顶层同名赋值作为证明；`lima/verifier.py:136` 的 confined-path Oracle。

以下代码的模块级 `BASE_ROOT` 是静态路径，但函数参数遮蔽了它：

```python
from pathlib import Path
BASE_ROOT = Path('/approved')

def read_file(BASE_ROOT, user_path):
    return open(BASE_ROOT / user_path).read()

if __name__ == '__main__':
    read_file(Path(input()), input())
```

规划器看到模块级静态赋值便认定根目录可信，生成：

```python
return open(_lima_resolve_under_base(BASE_ROOT, user_path)).read()
```

实际传入 helper 的仍然是调用者控制的函数参数。helper 只能验证目标在这个参数指定的目录内，不能证明它位于模块声明的允许目录内。Oracle 确认 helper AST 正确、调用名称正确，却没有核对根目录的绑定及来源。

探针在自己创建的临时目录中分别建立 safe 和 outside，outside 只含一个无敏感内容的 marker 文件。修复后向函数传入 outside，成功读出 marker。结果同样为编译/Oracle/差分通过、预览 `verified-preview`。原始数据流告警计数为 1，修复后为 0。

建议：以具体 sink 所在作用域解析根目录表达式，证明它引用的是被批准的绑定；参数遮蔽、局部重绑定、模块后续改写或其他无法证明的来源应拒修。还应检查新增 helper 及其依赖名称的作用域绑定，避免仅凭同名 AST 推断实际执行目标。验证器应独立复核根目录信任前提。差分中针对 `confined-path` 的特别放行只能在这些前提已经得到证明时使用。

## 影响及边界

两项问题涉及当前明确提供的 CWE-78/CWE-22 受限修复与只读修复预览，不属于未来完整三阶段平台尚未实现的范围。模板生成和验证器共享了不足的前提，因此模型是否参与、sandbox 是否隔离，都不能补足补丁安全证明。

本轮没有实际发布远程补丁，也没有证明绕过完整 sandbox 门禁。远程发布仍需仓库测试及 sandbox 回执通过；但普通测试不必然覆盖这些输入，所以不能依赖它们自动兜底。建议在修复这两项前，不将相关补丁的 `verified-preview` 状态作为安全成立或可发布的充分依据。

## 验证记录

复现脚本：`output/lima-global-reaudit-2026-11-09/repair_probe.py`。

结构化结果：同目录 `repair-results.json`。路径中的临时目录在探针结束后自动清理。

```powershell
$env:PYTHONUTF8='1'
python output/lima-global-reaudit-2026-11-09/repair_probe.py
```

相关现有测试：48 项通过，2.452 秒。日志：`output/lima-global-reaudit-2026-11-09/focused.log`。

```powershell
python -m unittest tests.test_security_repair tests.test_repair_publication_gates tests.test_repair_publication_service tests.test_webhook_delivery_recovery tests.test_pinned_diff tests.test_pr_final_cancellation -q
```

上一轮来源绑定、outbox 和最终取消的相关回归本轮继续通过，未把它们重复列为未修复。本轮没有重复跑全量测试；上轮全量的 Semgrep 30 秒超时、Docker 成功路径与真实 PostgreSQL/Redis 故障切换验收缺口仍保留，未声称解决。
