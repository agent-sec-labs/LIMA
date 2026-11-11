# LIMA 全局复审：修复输入预算与发布恢复（2026-11-09）

本轮基于当前未提交工作区，HEAD `fcd098562001d1d610134c86e3a92e15cde1ea72`。先复核此前来源绑定、修复语义、文件类型和模式修复，再检查输入预算及远程发布的失败恢复。未修改生产代码、提交、推送或写入真实 GitHub，仅新增本报告及离线探针。

仍需修改两项：F1/P1 为服务侧输入资源预算，F2/P2 为发布操作恢复。此前已修复的归档链接拒绝和文件模式保留，本轮相关回归继续通过，未重复列为未修复。

## F1 / P1：完整归档下载没有本地字节上限，后置验证预算无法保护下载阶段

位置：`lima/github.py:374` 的 `download_archive` 未传 `max_bytes`；`:149-150` 在该参数缺省时执行 `response.read()`。`lima/fixer.py` 在调用 `verify_archive` 之前先接收完整 bytes。

`verifier.py:28` 的 200 MiB 解压预算在 `:292` 检查 ZIP 条目时才生效。在此之前，整个压缩响应已经读进服务进程内存。含大型模型、资产或其他难压缩数据的仓库，归档本身就可能很大；并发修复会进一步放大内存占用，可能导致进程内存耗尽。HTTP timeout 是等待控制，不是响应大小控制。

探针用虚拟 HTTP 响应截获真实客户端的 read 参数：归档下载调用 `read(-1)`，即无上限读取。它在实际分配响应体前主动停止，没有申请大内存、下载大型文件或触发 OOM。本轮证明的是客户端确实选择了无界读取路径，不宣称做过破坏性资源耗尽实验。

同样检查到修复用的 `get_file`（`:198`）也未传本地响应上限；探针同样记录无界 read。GitHub Contents API 自身有文件大小/返回形式限制，不能据此断言它会返回任意大文件，但这条消费路径也未显式对齐本地 Python 文件预算。主要可用性风险仍是完整归档下载。

建议：为修复归档明确配置压缩响应字节预算，并在读取过程中执行预算，而不是只看 Content-Length 或事后 len。可采用有界流式下载到受控临时文件，再做解压预算校验；保留缺失/伪造 Content-Length 和分块响应的拒绝测试。源码 Contents 响应及解码后的源码也应在 AST 规划前有本地预算。预算拒绝须阻断后续规划/测试/发布，并对临时文件清理留证。

## F2 / P2：发布已成功但响应丢失后，重试会创建第二套分支和 Draft PR

位置：`lima/fixer.py:372` 按当前秒生成新分支，`:436` 创建提交/分支，`:441` 创建 Draft PR；`lima/service.py:2479-2502` 直接调用并返回结果，没有持久化发布意图或远程结果的恢复状态。API 的成功审计也在 create_fix 返回之后才写入。

复现场景：验证通过，GitHub 已创建 Draft PR，但响应在返回途中丢失，调用方得到失败。稍后对同一任务、相同 source SHA 和相同补丁重试。当前流程重新验证并按新时间创建新分支、新 Draft PR，不查询或恢复上一次结果。

探针运行真实 `create_fix_commits` 发布编排，使用测试中准备好的 plan/verifier 和内存 GitHub 替身，专门隔离发布副作用。首次替身保存“已创建 Draft PR”后抛出响应丢失异常；两秒后重试得到：

```text
lima/fix-pr-7-20261109080000 → Draft #100（首次调用失败）
lima/fix-pr-7-20261109080002 → Draft #101（重试调用返回）
```

两次来源 SHA 相同。本轮没有执行真实远程发布，也没有把准备好的 verifier 当作真实 sandbox 验收。复现证明的是成功之后异常的编排恢复缺口。

影响：用户收到失败却已产生远程改动，重试又产生重复 PR；旧分支/PR 缺少本地可恢复的操作回执。若故障发生在创建分支后、创建 PR 前，同样可能留下无法从返回结果获知的部分成果。仅增加随机分支名只能避免碰撞，不能解决恢复问题。

建议：以租户、任务、固定 SHA、补丁摘要及验证身份建立持久发布操作，首次远程写入前保存意图，按阶段记录 commit/branch/PR。重复请求复用或明确关联已有操作。遇到未知成功状态时，按稳定分支/操作标记查询并核对 GitHub 实际内容后继续，避免盲目重新 POST；并发请求需要原子执行权。验证及授权失效的旧操作不能被无条件复用。测试覆盖提交/分支/PR 各阶段的应答丢失、进程重启、并发重试和同秒请求。

## 验证记录与边界

脚本：`output/lima-publication-recovery-audit-2026-11-09/probes.py`。

结构化结果：同目录 `results.json`。无真实网络请求、远程写入或大内存分配。

```powershell
$env:PYTHONUTF8='1'
python output/lima-publication-recovery-audit-2026-11-09/probes.py
```

相关回归：123 项，1 跳过、无失败，1.091 秒。日志：同目录 `focused.log`。

```powershell
python -m unittest tests.test_github_repair_modes tests.test_github tests.test_github_source tests.test_pinned_diff tests.test_repair_archive_modes tests.test_repair_test_sandbox tests.test_security_repair tests.test_repair_semantic_guards tests.test_repair_publication_gates tests.test_repair_publication_service tests.test_repair_evaluation -q
```

本轮未改生产代码，没有重跑全量。此前全量结果为 3,784 项、42 跳过、无失败，见文件语义修复记录。真实 Docker 成功路径及 PostgreSQL/Redis 故障切换仍不是本轮已验证范围。上述发现属于当前修复发布端点的边界，不将文档已声明尚未完成的完整三阶段平台当作缺陷。
