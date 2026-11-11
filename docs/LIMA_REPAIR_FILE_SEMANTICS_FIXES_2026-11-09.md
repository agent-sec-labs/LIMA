# 修复归档与 Git 文件模式加固（2026-11-09）

对应 `LIMA_GLOBAL_PUBLICATION_REAUDIT_2026-11-09.md` 的 F1/P1 和 F2/P2。本次修改在当前工作区，保留此前及用户已有改动，尚未提交或推送。没有远程 GitHub 写入。

## 归档输入拒绝语义转换

`RepairVerifier._safe_extract` 在创建任何目录或文件前预检全部条目头和路径。符号链接、FIFO、设备、socket、类型与目录名称不符、特殊权限位及重复目标均失败，不把链接内容作为普通文件解压，也不跟随链接。

`verify_archive` 将拒绝转为失败检查及空 sandbox 回执。链接原因固定为 `repair-archive-link-unsupported`，其他特殊类型为 `repair-archive-type-unsupported`，路径冲突为 `repair-archive-path-conflict`；其他无效归档为 `repair-archive-invalid`。原有发布门禁因此返回 `repair-verification-failed`，不会进入仓库测试或远程提交创建。

普通文件记录 Git 模式 `100644` 或 `100755`。没有 Unix 类型信息的普通 ZIP 文件仍可读取，按非可执行文件处理。归档副本和修复后的文件都保留受支持的 Git 执行位语义。

## 跨 Windows 宿主传递模式

Windows 上 `chmod`/`stat` 无法完整表达 Unix 执行位，因此不能仅靠 staging 文件的宿主权限传递模式。

解压器产生文件模式表；sandbox 验证它与实际 staging 文件集合完全对应、值仅为 `100644`/`100755`。模式表写入服务控制的独立 JSON 文件，以只读文件挂载 `/lima-modes.json` 交给容器，不插入目标仓库或大规模命令行参数。bootstrap 复制输入后，在一次性工作副本中恢复模式再启动测试。JSON 文件对非 root 容器可读，测试用 fixture runner 同步消费该模式表。

不完整、额外、特殊模式或试图逃逸的模式映射不能启动 runner。原有非 root、只读根目录、禁网、noexec、资源及清理回执门禁继续适用。本次没有启用仓库原生二进制执行，也没有把模式传递测试当作原生 CLI 或 Docker 实机验收。

## 发布保留父提交的 Git 模式

`GitHubClient.create_atomic_commit` 从固定父提交读取根 tree，再按目录逐级获取非递归 tree 元数据，缓存同一 tree 的读取。每次元数据读取限制为 1,000,000 字节。

发布仅支持父树中已存在的普通 blob，模式为 `100644`/`100755`。修改路径缺失、歧义、特殊类型、目录遍历类型不符、无效对象 SHA、截断或不可用元数据都会拒绝。所有目标路径完成模式解析后才执行第一个 POST，tree 更新保留原模式。

不通过递归全树返回结果猜测遗漏路径，也不在模式未知时默认改成 `100644`。

## 验证

新增 `tests/test_repair_archive_modes.py` 和 `tests/test_github_repair_modes.py`，修复前已确认红测。覆盖内部/外部/悬空链接、特殊类型、整包预检、拒绝前零写文件、拒绝前不启动测试/提交、普通 ZIP 兼容、Windows 模式元数据、无效模式映射、嵌套目录、普通/可执行文件保留，以及缺失/特殊/截断元数据在任何 POST 前失败。

最新聚焦验证：123 项，1 跳过、无失败，1.150 秒。日志：`output/lima-file-semantics-fixes-2026-11-09/focused.log`。包含元数据响应超预算及“前一个文件有效、后一个为特殊文件”时全批次零 POST 两个补充回归。

```powershell
python -m unittest tests.test_github_repair_modes tests.test_github tests.test_github_source tests.test_pinned_diff tests.test_repair_archive_modes tests.test_repair_test_sandbox tests.test_security_repair tests.test_repair_semantic_guards tests.test_repair_publication_gates tests.test_repair_publication_service tests.test_repair_evaluation -q
```

全量后端验证：3,784 项，42 跳过、无失败或错误，441.859 秒。日志：`output/lima-file-semantics-fixes-2026-11-09/full-suite.log`。此前超时的 Semgrep 用例本次通过，没有修改它的规则、测试或超时。全量运行加载测试清单后补充的上述两个测试已在最新聚焦运行中通过。

离线回归探针：`output/lima-file-semantics-fixes-2026-11-09/regression_probe.py`，结果为同目录 `regression-results.json`：

- 原符号链接夹具返回 `repair-archive-link-unsupported`，写入文件数为 0；
- 用真实本地 Git 对象建立源 tree，运行真实提交组装函数并将请求应用为新 Git tree，`git ls-tree` 确认 `run.py` 仍是 `100755`、`app.py` 仍是 `100644`；
- HTTP transport 为离线替身，没有网络请求；没有执行夹具脚本或 Git hooks。

新增测试及测试 helper 的 Ruff 检查通过，修改的 Python 编译检查通过，`git diff --check` 无空白错误，仅有此前文件的换行提示。既有大文件的历史 lint 问题未作无关清理。

本轮未运行真实 GitHub 发布、Docker 成功路径或 PostgreSQL/Redis 故障切换，相关部署验收缺口继续保留。
