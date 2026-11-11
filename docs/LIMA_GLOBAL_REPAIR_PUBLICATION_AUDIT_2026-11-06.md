# LIMA 全局审计：自动修复发布链

日期：2026-11-06。基线为当前工作树，包含此前两轮全局修复；HEAD 仍为 `fcd098562001d1d610134c86e3a92e15cde1ea72`，修复尚未提交或推送。本轮只读审计生产代码，新增探针和本报告，没有改动运行配置或写入 GitHub。

## 结论与范围

确认三项 P1，集中在现有 GitHub 修复发布路径，而非此前的构建上下文链。触发需要调用修复入口，且仓库已经获准自动修复；其中宿主执行还需要配置仓库测试命令。不能据此认为所有默认只读审计都会执行这些操作。

LIMA 当前定位明确区分已有受限修复能力和未来完整 Audit → Mining → Repair 平台。本报告没有把尚未实现的长期目标列作缺陷；检查的是已存在、可调用的发布路径是否满足固定来源、真实验证和隔离执行要求。

## 1. P1：修复没有绑定生成审计结果时的 PR 提交

位置：`lima/service.py:2423–2427`、`:2451–2467`；`lima/fixer.py:213–216`。

Webhook 已将经过校验的 `head_sha` / `base_sha` 写入任务输入。但 `create_fix()` 只把报告传给 fixer，未传递或比较审计 SHA；fixer 重新查询 PR，并使用当前 head 读取文件和生成提交。

当前工作树探针令任务保存审计 SHA `a…a`、客户端返回当前 head `b…b`。通过实际 `ReviewService.create_fix()` 和 `SafeFixer` 后观察到：

- 读取文件的 ref 为 `b…b`；
- 请求创建修复提交时的父提交也是 `b…b`；
- 没有拒绝旧审计结果或要求重新分析新提交。

GitHub 客户端为记录型内存适配器，没有真实远程写入。这证明版本约束缺失，不代表已对真实 PR 发布错误补丁。

影响：PR 在审计后更新时，旧 Finding 的行号和验证结论可能被用于另一版本。新版本上的局部修复检查不能代替原始审计证据与源码的绑定。

建议：以审计 SHA 为修复入口必需条件，所有取件、归档、验证和提交均使用固定 SHA；当前 head 已改变则返回明确的来源过期结果并重新审计。发布前应再次核对来源状态。任务缺少固定 SHA 时不能走发布路径。

## 2. P1：部分规则只做编译检查就进入发布路径，文案却声称全部门禁通过

位置：`lima/fixer.py:11–29`、`:247–273`；`lima/config.py:156`。

`SEC-HARDCODED-SECRET` 和 `REL-DEBUG-PRINT` 仍在支持列表内，其旧修复路径不生成 `repairs` manifest。只有 `repairs` 非空或配置了测试命令，才会下载归档并执行 `verify_archive()`；默认测试命令为空，因此允许跳过该阶段。

当前探针使用 `syntax-verified` 的 `SEC-HARDCODED-SECRET`：

```json
{
  "archive_calls": 0,
  "verification_checks": [{"name": "compile:app.py", "passed": true}],
  "repair_manifest": []
}
```

同时记录到创建提交及草稿 PR 的调用。草稿正文固定写“Compilation, independent security oracles, full-repository differential rescan, and configured regression tests passed”，与实际检查清单不符。

现有受限 CWE-22/78/89 路径具备 manifest、oracle 和差分检查；缺陷在于不同规则进入发布入口时的验证要求不统一。

建议：发布统一要求明确的修复证明、完整归档验证及必要的仓库测试；没有对应独立验证能力的规则只提供预览。PR 正文根据实际 checks 生成，跳过或未配置的检查必须如实表达，不能写成通过。

## 3. P1：仓库测试以服务宿主权限执行，没有建立 Repair Sandbox

位置：`lima/verifier.py:146–188`、`:191–219`。

`verify_worktree()` 直接以服务进程身份执行 `subprocess.run(command, cwd=root, ...)`。环境变量筛选、临时目录与代理变量置空，不会限制文件系统权限或建立网络隔离。子进程标准输出也先完整捕获，之后才截取报告尾部；超时与临时目录不能替代进程、资源和权限隔离。

本轮创建了一个无敏感数据的临时工作树，配置固定 Python 测试命令。测试脚本只向同一自建临时目录下、工作树之外的哨兵文件写入标记。真实 `RepairVerifier.verify_worktree()` 运行结果：

```json
{
  "verification_passed": true,
  "outside_worktree_written": true,
  "marker_text": "BENIGN_HOST_WRITE"
}
```

没有访问真实敏感文件，也没有发起网络请求。该探针证明测试受宿主权限约束，而不是被限制在临时工作树内。

建议：将不受信任仓库的测试移至独立受限执行环境，固定镜像及输入，约束网络、可写目录、运行用户、CPU/内存/pid、输出和超时清理，并记录执行证据。缺少这项能力时，不能把宿主测试结果称为隔离验证，也不应允许该路径对不受信任代码完成发布。

## 先前修复的复核结果

对构建输入、恢复消费和产物目录进行了有界复核，未发现新的可触发缺陷。复核覆盖输入遍历失败关闭、路径及实际流字节限制、执行回执单调性、恢复的输入摘要/包/目标校验，以及构建容器不挂载产物目录。详情见 `output/lima-final-audit-2026-11-06/build/BUILD_INPUT_RECOVERY_EXECUTION_AUDIT.md`。

没有重新把已处理的 `.env`、junction、根目录替换等情况列为新问题；也没有把需要同等宿主权限持续篡改的场景泛化为远程漏洞。

## 验证证据与限制

证据目录：`output/lima-final-audit-2026-11-06/`。

- `publication_probes.py` / `publication-results.json`：固定审计提交未绑定、legacy 发布门禁跳过，以及宿主工作树外写入的实际探针。
- `targeted-tests.log`：安全修复、API 权限、构建及工作区相关回归 **57 通过**。
- 最近一次全量测试为 **3,723 项，41 跳过，无失败**；本轮没有修改生产代码，因此未重复全量运行。上述探针补充了现有测试没有覆盖的发布边界。

本轮没有向真实 GitHub 创建提交或 PR，没有运行真实模型、Docker、Redis 重领或完整大仓试点。审计重点是当前可调用的修复发布链，不能据此给整个平台作穷尽性安全保证。
