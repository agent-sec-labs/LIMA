# 修复语义加固记录（2026-11-09）

对应 `LIMA_GLOBAL_REAUDIT_2026-11-09.md` 的两项 P1。本次修改保留用户及此前已有工作区改动，尚未提交或推送，没有创建远程分支、提交或 PR。

## 命令修复：证明参数用途，无法证明时拒修

`security_repair.py` 将自动命令修复收窄至标准 `echo` 数据参数和固定 `%s` 格式的 `printf`。Python、Shell、PowerShell 等解释器，未知程序、包装器及自定义可执行路径不能仅凭固定字符串和 `shell=False` 获得通过。

额外位置参数、`**kwargs`、`executable`、`env`、`cwd`、`preexec_fn` 等可能改变执行目标或解析环境的形式会拒修。subprocess 的实际导入绑定也须证明没有被覆盖。独立 Oracle 从补丁实际调用和 argv 重新检查这些限制，不信任 manifest 声称的 fixed executable。即使伪造匹配的 expected AST，解释器负例仍失败。

这是受限自动修复能力，不是任意命令的参数安全分析。标准程序名称的可信解析仍是目标环境前提，仓库隔离测试仍然必须运行；本次没有对用户系统安装路径、PATH 或镜像进行修改。

## 路径修复：核验实际绑定及固定 helper

新增 `repair_bindings.py`，供规划器及验证器分析实际 AST。可接受静态路径表达式，或唯一一次无条件模块赋值提供的静态路径。`Path`/`pathlib` 必须绑定至对应标准库导入。

同名函数参数、闭包绑定、局部导入、重赋值、删除、global/nonlocal 声明、异常处理目标、模式匹配捕获及相关属性/下标修改均可能使绑定证明失败。动态命名空间也会保守拒绝。当前实现不是完整 Python 作用域/跨模块分析：其他作用域内的同名绑定也可能触发拒修。源码 `trusted-path-root` 注释不再单独构成信任证明。

生成前检查 helper 及其 Path 别名的绑定冲突。验证器检查实际根目录表达式，并对照固定的 helper AST 规范；不能让 manifest 自选一个删除了包含检查的 helper 来证明自身安全。helper 函数及 `_LIMAPath` 的绑定也要唯一且正确。根目录证明排除固定生成 helper 的局部变量，避免其内部的 `root` 名称误伤原仓库同名全局根目录。

两层仍共享基础 AST 绑定分析和固定 helper 规范；验证器重新分析实际补丁，不调用规划器来取得“通过”结果，不把 manifest 的预期描述当作安全事实。

## 回归及评测

新增 `tests/test_repair_semantic_guards.py`。修复前 8 个测试方法中的负例出现 28 次失败；之后增加发布阻断检查，并扩展重绑定负例。覆盖：

- 解释器、绝对解释器路径、包装器、未知程序、不安全 printf 格式及执行覆盖拒修；
- Oracle 独立拒绝伪造的解释器 manifest；
- 根目录参数/闭包遮蔽、重赋值、局部导入、异常/模式匹配捕获和删除拒修；
- helper 参数遮蔽及 manifest 替换 helper 失败；
- 已证明的模块根目录在函数中继续通过，包括名为 `root` 的变量；
- 两类原审计输入都不能到达远程提交创建流程。

原始审计问题的无执行回归脚本：`output/lima-repair-semantic-fixes-2026-11-09/regression_probe.py`。同目录 `regression-results.json` 确认两类输入均为：0 个 repair、预览 `no-repair`、旧不安全补丁的 Oracle 为 false。脚本只解析自己编写的夹具，不执行夹具或访问服务。

评测继续使用仓库原有 `RepairConstraintEvaluator`。`security_repair_cases.json` 的数据集名称更新为 `lima-cwe-repair-constraints-v2`：24 个受控样例，8 个应修、16 个应拒。旧版 getent 与注释根目录改为拒修，并新增 6 个样例。数据指纹：

```text
d1e32f554637957e13fb865dbb367756b1b1b340a783accd7300b490035d89e4
```

本地 v2 结果：24/24 约束符合预期，8/8 应修通过，16/16 正确拒修。结果文件：`output/lima-repair-semantic-fixes-2026-11-09/repair-evaluation-v2.json`。由于能力范围、样例和预期均发生变化，不能把本轮分数与 v1 直接比较，也不能据此宣称真实仓库修复率或检测召回率提高。

聚焦测试命令和日志：

最新结果：48 项，1 跳过、无失败，0.901 秒。该轮包含新增的发布阻断回归及扩展重绑定负例。

```powershell
python -m unittest tests.test_repair_semantic_guards tests.test_security_repair tests.test_repair_evaluation tests.test_repair_publication_gates tests.test_repair_publication_service tests.test_repair_test_sandbox -q
# output/lima-repair-semantic-fixes-2026-11-09/focused.log
```

全量运行：3,775 项，42 跳过、1 项 error，456.331 秒。日志：`output/lima-repair-semantic-fixes-2026-11-09/full-suite.log`。唯一错误仍是此前已复现的 `test_cxx_analyzer.SourceScanContainerTests.test_fixture_manifest_is_complete_and_semgrep_marks_only_candidates`：本机 Semgrep scan 超过既有 30 秒限制。本轮没有修改该测试、规则或超时设置，也没有把它跳过来获得全绿。全量运行加载测试清单之后补充的发布阻断测试由上面的最新聚焦运行覆盖。全量不能称为全绿。

新模块及新增测试的 Ruff 检查通过，Python 编译检查通过，`git diff --check` 无空白错误，仅有换行规范提示。没有对既有文件做无关整体格式化。

Docker 新版实机成功路径及真实 PostgreSQL/Redis 故障切换仍未验收。本次没有重启 Docker、增加执行权限或调用真实模型。
