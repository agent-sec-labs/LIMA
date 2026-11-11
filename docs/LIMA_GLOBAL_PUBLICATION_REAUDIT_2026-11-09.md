# LIMA 全局复审：归档语义与发布文件模式（2026-11-09）

本轮在当前工作区复核来源绑定、outbox、取消门禁及修复语义加固，并继续检查验证输入到 GitHub 发布的衔接。HEAD 为 `fcd098562001d1d610134c86e3a92e15cde1ea72`，包含此前尚未提交的修复。本报告不能直接代表远程 main 或某个 PR。

新增结论：一项 P1、一项 P2。均已通过本地夹具验证。本轮仅新增本报告及 output 下的探针，没有修改生产代码、提交、推送或远程 GitHub 写入。

## F1 / P1：归档中的符号链接被改写成普通文件，验证对象发生变化

位置：`lima/verifier.py:267` 的 `_safe_extract`，尤其是 `:281-284`。实现只区分目录与非目录，没有读取 ZIP Unix 类型位 `external_attr`；符号链接被当作普通文件，内容是链接目标的路径文本。

例如 Git 仓库有：

```text
config -> payload.txt
payload.txt 内容为 ACTUAL_GIT_LINK_CONTENT
```

ZIP 中 `config` 的 Unix 类型为 symlink，数据为 `payload.txt`。当前解压后 `config` 变成普通文件，其内容就是 `payload.txt`。读取它的测试看到的内容与支持符号链接的正常 Git 检出不同。后续 sandbox staging 的链接拒绝检测也不会再触发，因为链接已经被转换成普通文件。

本地探针构造上述 ZIP，并对同一夹具中的合法 CWE-89 修复调用真实 `RepairVerifier.verify_archive`。自建 unittest 断言 `config` 内容为 `payload.txt`：在转换后的副本上通过，但真实链接语义下该读取应得到 `ACTUAL_GIT_LINK_CONTENT`。编译、Oracle、差分和 repository-tests 均被记录为通过。

测试执行使用现有显式 test-only fixture runner，只运行自己编写的固定 unittest，不是 Docker 实机验收；没有执行外部仓库。该复现证明归档解压改变了输入，及后续验证可在改变后的内容上通过；不宣称已绕过真实 Docker 或实际发布过错误补丁。生产 Docker 接收到的同样是解压后副本，因此隔离执行本身无法恢复丢失的文件类型语义。

建议：在解压前验证归档条目的 Unix 类型。当前 sandbox 明确拒绝链接，因此修复验证应对 symlink/其他特殊文件直接失败并给出稳定原因，不能静默转换，也不能通过跟随链接复制宿主内容解决。若以后支持链接，则必须建立有界、根目录内的解析及验证语义，并保证验证树与发布树一致。补充正常内部链接、外部/悬空链接及特殊类型回归，证明被拒归档不会启动测试或发布。

## F2 / P2：发布修改文件时无条件清除可执行权限

位置：`lima/github.py:248` 的 `create_atomic_commit`，`:261` 为每个修改路径固定写入 `mode="100644"`。

当被修复的 Python CLI 脚本原本为 Git 模式 `100755`，发布提交会将它改为 `100644`。即使代码及通过 `python script.py` 的测试正常，Linux 上 `./script.py` 等原有入口也会因权限变化而失败。这是补丁引入的额外行为变化，不是修复目标所要求的改动。

探针在临时目录内用真实 Git 对象命令建立包含 `100755 script.py` 的源 tree，并用 `git ls-tree` 核对模式；随后通过离线 transport 运行真实 GitHub 提交组装函数。生成的 tree 更新请求将同一路径写为 `100644`。没有发送任何 HTTP 请求，临时 Git 对象在结束后清理。

建议：从同一不可变父提交读取拟修改路径的原始 tree 元数据，普通文件保留 `100644`/`100755`。无法确认文件类型或遇到 symlink/gitlink 等特殊条目时明确拒绝，不应一律重建为普通文件。验证工作副本也应保留所支持的文件模式；为可执行脚本、普通文件及特殊条目分别增加回归。

## 证据与回归

复现脚本：`output/lima-publication-reaudit-2026-11-09/probes.py`。

结构化结果：同目录 `results.json`。

```powershell
$env:PYTHONUTF8='1'
python output/lima-publication-reaudit-2026-11-09/probes.py
```

相关测试运行 54 项，1 跳过、无失败，0.874 秒。日志：同目录 `focused.log`。

```powershell
python -m unittest tests.test_repair_semantic_guards tests.test_security_repair tests.test_repair_evaluation tests.test_repair_publication_gates tests.test_repair_publication_service tests.test_repair_test_sandbox tests.test_github -q
```

上一轮解释器/路径绑定拒修和发布门禁回归继续通过，未将已修复项重复列为缺陷。本轮未改生产代码，因此没有重跑全量；上一轮全量唯一的 Semgrep 30 秒超时仍未解决。真实 Docker 成功路径及 PostgreSQL/Redis 故障切换仍不在本轮已验证范围内。
