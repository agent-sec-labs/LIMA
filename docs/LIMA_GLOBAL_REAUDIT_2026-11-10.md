# LIMA 全局复审：租户凭据与扫描快照一致性

日期：2026-11-10。范围：`D:\Projects\LIMA` 当前工作区；HEAD 为 `fcd098562001d1d610134c86e3a92e15cde1ea72`，包含此前尚未提交的修复。本报告不代表远端 main 或任何 PR 的状态。

本轮依据 README、Coding Agent 交接标准、赛题差距记录及近期修复报告，检查入口授权、任务交接与恢复、构建上下文消费、修复门禁和扫描身份。只新增审计报告与离线探针，没有修改产品代码、提交、推送或写入真实 GitHub。

## 结论

确认两项 P1 和一项 P2。前两项属于 GitHub installation 的租户隔离，第三项属于扫描证据与快照身份的一致性。它们均有可运行反例，不以代码猜测作为唯一依据。

上一轮绝对路径根目录、标准 SQLite 接收者和独立 Oracle 的回归仍通过。本轮没有把文档明确尚未实现的完整 Audit → Mining → Repair 平台列为实现缺陷，也没有把文件读取覆盖率当成赛题语义审阅覆盖率。

## F1 / P1：修复接口允许调用方选择其他租户的 installation 凭据

位置：`lima/api.py:629–634`、`lima/service.py:2479–2502`，关键调用为 `service.py:2497`。

`create_fix` 检查了任务所属租户、SUCCESS 状态、仓库 auto-fix 授权和固定来源，但随后直接将请求中的 `installation_id` 交给 `github_client_for_installation`。该函数只检查 App 配置并换取令牌，没有核对 installation 的登记租户，也没有从任务的可信来源绑定安装身份。

复现使用真实本机 HTTP 服务、登录鉴权、RBAC、SQLite 和 `ReviewService.create_fix`：

1. installation `222` 已登记给 `tenant-b`；`tenant-a` 有自己的成功任务及显式仓库修复授权。
2. 以仅属于 `tenant-a` 的 maintainer 登录，向自己任务的 fix 接口提交 `installation_id=222`。
3. 接口返回 HTTP 201；服务向认证器请求 `222`，当时数据库中的归属仍是 `tenant-b`；其返回的替身令牌进入 fixer。

影响：具有本租户 fix 权限的用户能够让服务选择其他租户的 GitHub App 身份。实际读取或发布是否成功，还取决于被选 installation 对目标仓库的 GitHub 权限；本探针没有执行真实令牌交换或远端写入，不声称已经完成跨租户仓库写入。

建议：任务准入时持久绑定经过核验的 installation；发布时校验它与任务租户、仓库及当前授权的关系。客户端字段只能用作一致性检查，不能独立决定凭据。缺少参数时也不能无条件转用全局 PAT。授权检查必须先于令牌请求与所有远端操作，拒绝路径应覆盖“其他租户”“未登记”“任务身份不匹配”和“省略参数回落”。

## F2 / P1：租户管理员可覆盖其他租户的 installation 登记，后续 webhook 随之改投

位置：`lima/api.py:576–585`、`lima/store.py:954–961`、`lima/postgres_store.py:1108–1117`；路由消费在 `lima/service.py:2412–2415`。

登记接口要求当前租户的 `manage` 权限，但没有检查现有归属或验证安装所有权，直接把请求中的数字写入全局主键。SQLite 使用 `INSERT OR REPLACE`，PostgreSQL 冲突更新也会覆盖 `tenant_id`。因此“绑定注册者租户”同时允许把已属于其他租户的 installation 转移过来。

真实 HTTP/鉴权/SQLite 探针：installation `222` 原属 `tenant-b`；以只属于 `tenant-a` 的 admin 登录，POST 相同 ID，返回 HTTP 201，数据库归属变为 `tenant-a`。另一个真实服务方法探针在覆盖后送入该 installation 的 PR 事件，生成的 PENDING 任务也属于 `tenant-a`。事件消费探针视 payload 为已通过外层验签的输入，没有伪造或绕过 GitHub HMAC。

影响：另一租户管理员可以改变未来事件的归属，导致任务和报告错误投递，并破坏 F1 修复所需的身份登记可信性。只在 fix 入口增加 `installation_tenant(id) == tenant` 检查还不够：若登记本身可以被抢占，这个检查仍能被满足。

同一入口还有相关的拒绝策略缺口：未知或缺少 installation 的 PR payload 会回落到默认租户。探针中未知 `999` 与缺失 ID 均在默认租户持久化为 PENDING；默认租户未配置仓库 grants 时，只读审阅按兼容策略放行。这是安装登记以外的隐式路由，不能作为多租户隔离保证。

建议：登记必须建立安装所有权与租户的可信关联；单纯客户端数字和 account 字符串不是所有权证明。数据库层原子拒绝跨租户覆盖；同租户幂等更新与受审计的显式迁移分开。多租户 App 模式下未知安装应拒绝或隔离，单租户 PAT 兼容模式应显式配置，不能隐式成为兜底。

## F3 / P2：扫描再次读文件时未核对盘点摘要，报告可绑定未实际分析的快照

位置：`lima/repository_scanner.py:928–948`、`lima/workspace.py:288–291`；身份写入在 `lima/service.py:2041`。

`inventory()` 先读取文件并保存 SHA-256；随后 `workspace.iter_text(inventory)` 再从目录读取内容，仅做路径与文件大小检查，没有将实际读取的字节与盘点中的摘要比较。扫描数据流和 AST 使用第二次读取的内容，报告却继续携带第一次盘点得到的指纹。

探针运行真实 scanner、workspace、Python AST 和跨文件数据流。仅在现有“工作区盘点完成”进度回调中更新临时 `app.py`，不替换扫描器：

- 稳定漏洞版本：发现 1 条 CWE-78；稳定安全版本：0 条。
- 先盘点漏洞版本，再在扫描读取前写入安全版本：报告发现 0 条，但 `result.inventory.fingerprint()` 仍等于漏洞版本的指纹，而不等于实际分析的安全版本。

影响：本地导入目录在审计期间被宿主编辑、同步或替换时，结果会归属于未实际分析的字节，影响复现、后续预览和证据身份。应用只读挂载能限制应用写入，不能保证宿主不更新目录。本探针没有证明固定且不可变的 GitHub 缓存也会自行变化，因此不扩大到所有来源。

建议：建立可复用的实际读取快照，逐文件以读取到的字节核对盘点摘要，漂移时明确失败或重新生成完整快照。AST/数据流、独立文件工具和后续消费者应使用相同物化内容；只在任务末尾再盘点一次不能排除扫描过程中短暂替换后恢复的情形。

## 验证记录

证据目录：`output/lima-global-reaudit-2026-11-10/`。

| 文件 | 用途 |
|---|---|
| `authorization_http_probe.py` / `.json` | 真实 HTTP 登录、租户角色、fix 凭据选择及 installation 覆盖 |
| `publication_probe_installation.py` / `.json` | 真实服务方法和 handler 参数转交的独立探针 |
| `publication_probe_webhook.py` / `.json` | installation 覆盖后的事件改投、未知/缺失 ID 默认路由 |
| `snapshot_probe.py` / `snapshot_probe_results.json` | 稳定正负对照及盘点后内容变更 |
| `focused.log` | 本轮 120 项专项 unittest，全部通过，18.117 秒 |

本轮专项测试包括 API 安全、租户状态、发布恢复、Webhook outbox、固定 diff、workspace 边界、仓库扫描、修复信任边界、构建目标消费及 verified lease。日志中的刻意触发 HTTP 500 属于错误信息脱敏测试，不是本轮失败。现有测试通过不能否定新增探针。

探针运行命令（PowerShell）：

```powershell
$env:PYTHONUTF8='1'
python output/lima-global-reaudit-2026-11-10/authorization_http_probe.py
python output/lima-global-reaudit-2026-11-10/publication_probe_installation.py
python output/lima-global-reaudit-2026-11-10/publication_probe_webhook.py
python output/lima-global-reaudit-2026-11-10/snapshot_probe.py
```

HTTP 探针仅监听 loopback、使用临时数据库；GitHub 认证器与 fixer 使用替身。另两个服务探针还替换了队列投递等无关组件。PostgreSQL 登记覆盖按源码确认，未做真实 PostgreSQL 运行验收。本轮没有执行 Docker、真实 GitHub、Redis 故障切换、付费模型或 OpenHarmony 漏洞复现。

本轮未重跑全量后端；前一轮 3,819 项、跳过 42 项的结果保留为历史证据，不冒充此次全量结果。赛题的真实 OH 受影响案例、合法 PoC 正负对照、Release/LTS 矩阵、性能分母与成品交付，仍需各自的验收记录；本轮平台回归不能替代这些材料。

优先修复 F1/F2 的凭据与登记闭环，再修复 F3 的读取快照一致性，随后进行真实部署和赛题验收。当前问题不宜通过扩大 Agent 角色或提高模型预算来处理。
