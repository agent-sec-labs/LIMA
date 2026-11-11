# LIMA 全局复审：根目录锚定与 SQL 驱动绑定（2026-11-09）

基线为当前未提交工作区，HEAD `fcd098562001d1d610134c86e3a92e15cde1ea72`。本轮复核下载预算、发布恢复与前几轮修复，继续检查修复模板依赖的安全前提。新增两项 P1，均有实际运行证据。本轮只新增报告及 output 下的离线夹具，未修改生产代码、提交、推送或发布远程成果。

## F1 / P1：相对根目录依赖运行时 cwd，静态绑定不等于可信锚点

位置：`lima/repair_bindings.py:96-98` 的 `static_path_proven` 把非空字符串视作静态路径证明；`:123` 的根目录证明接受唯一模块赋值，但未证明其绝对锚点。规划器和 Oracle 都使用该前提。

例如：

```python
from pathlib import Path
import os
BASE_ROOT = Path('approved')

def read(name):
    return open(BASE_ROOT / name).read()

if __name__ == '__main__':
    os.chdir(input())
    print(read(input()))
```

`BASE_ROOT` 没有被重新赋值或遮蔽，因此通过前一轮的绑定检查。但它是相对 Path，生成 helper 内的 `.resolve()` 依赖调用时 cwd。用户可控制的 chdir 使 `approved` 指向另一处目录，不能将它视为已经证明的固定允许根。

探针在自己的临时目录里建立 `initial/approved` 与 `other/approved`，只放无敏感内容的 marker 文件。程序从 initial 启动，输入 other 作为 cwd，再读取 marker。修复后仍输出 `OUTSIDE_INITIAL_ROOT_MARKER`。这是确定性的工作目录依赖，不涉及符号链接或检查后并发修改，不能归入已声明的 TOCTOU 剩余风险。

编译、security Oracle、差分复扫全部通过，差分告警从 1 变为 0，真实修复预览返回 `verified-preview`。

建议：在当前受限能力中，无法证明绝对/固定锚点的根目录应拒修。若支持项目相对路径，应通过可信的项目根或冻结锚点构造，并把证明纳入实际补丁核验；不能仅凭字符串非空或模块变量只赋值一次放行。补充 cwd 改变、驱动器相对路径及目标平台路径语义的负例。规划器与 Oracle 都要复核该前提。

## F2 / P1：SQL 修复仅推断参数风格，未证明实际 execute 接收者是该驱动

位置：`lima/security_repair.py:316` 的 `_plan_sql`，`:322` 主要按 receiver 名称匹配 cursor/connection 等后缀，`:372` 根据文件 import 或源码注释选择参数风格。`lima/verifier.py:157` 的 Oracle 验证常量 SQL、tuple 和占位符数量，未核验真实接收者及其参数绑定语义。

文件中出现 `import sqlite3`、对象名为 `cursor`，不表示 `cursor.execute` 就是标准 SQLite/DB-API 方法。自定义包装器或覆盖实现可以再次把参数拼进 SQL。

探针使用真实内存 SQLite，自己创建两行普通测试数据，并定义：

```python
class LegacyCursor:
    def execute(self, statement, parameters=()):
        for value in parameters:
            statement = statement.replace('?', str(value))
        return connection.execute(statement)

cursor = LegacyCursor()
value = input()
cursor.execute('SELECT name FROM users WHERE id = ' + value)
```

规划器生成 `cursor.execute('SELECT name FROM users WHERE id = ?', (value,))`，但该对象并不提供真正的参数绑定。传入固定的 benign 条件 `0 OR 1=1` 后，两行测试数据仍全部返回；真正的 SQLite 参数绑定应把它作为一个值处理。

该夹具中编译、security Oracle、差分复扫全部通过，告警从 2 变为 0，真实预览同样为 `verified-preview`。没有访问用户数据库、外部服务或执行真实仓库代码。

建议：对真实接收者建立绑定/调用来源证明，而不是从变量名和无关 import 推断。当前窄范围内，未知函数参数、自定义 wrapper、子类覆盖及无法证明的 cursor 来源应拒修；可优先支持明确的标准连接/cursor 构造链。源码参数风格注释不能单独证明调用契约。Oracle 需复核实际调用绑定和参数语义，不能只信任 manifest 或 AST 形状。回归应包含无关 import、receiver 重绑定、包装器、覆盖方法，以及真实标准驱动的正例。

## 全局影响与范围

这两项都属于当前声明支持的受限 CWE-22/CWE-89 修复能力。问题在于安全前提不足，并不是 LLM 判断不稳定，也不是未来完整三阶段平台尚未实现。

两例均说明告警减少不能单独证明漏洞被修好：生产扫描和差分复扫共享的识别边界可能同时漏掉修复后的危险行为。独立 Oracle 应核验前提本身。

本轮没有实际创建远程补丁，也没有运行真实 Docker。完整发布仍有隔离测试门禁；本轮证明的是当前静态安全检查和 `verified-preview` 能接受仍有危险行为的补丁。不能假设普通仓库测试一定覆盖这些负例。

## 证据与验证

脚本：`output/lima-repair-trust-audit-2026-11-09/probes.py`。

结构化结果：同目录 `results.json`。

```powershell
$env:PYTHONUTF8='1'
python output/lima-repair-trust-audit-2026-11-09/probes.py
```

脚本只执行自己编写的极小夹具：临时 marker 文件和内存 SQLite。子进程限定 10 秒，无网络请求，临时目录退出时清理。原审计 finding 由夹具明确提供，差分复扫的原始告警计数另由真实分析器计算；不把手工指定 finding 当成独立驱动绑定证明。

相关回归 128 项通过，3.502 秒。日志：同目录 `focused.log`。

```powershell
python -m unittest tests.test_repair_publication_recovery tests.test_repair_publication_store tests.test_repair_download_budget tests.test_security_repair tests.test_repair_semantic_guards tests.test_repair_publication_gates tests.test_repair_publication_service tests.test_repair_archive_modes tests.test_github_repair_modes tests.test_github_source tests.test_pinned_diff -q
```

前几轮来源绑定、执行参数拒修、目录绑定遮蔽拒修、归档类型、Git 模式、下载预算及发布恢复相关回归继续通过。本轮没有修改生产代码，未重复全量；此前最终全量为 3,807 项、42 跳过、无失败。真实 GitHub 故障恢复、Docker 成功路径、PostgreSQL/Redis 故障切换仍未实机验收。
