const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];

const titles = {
  overview: "开始",
  scan: "发起审计",
  tasks: "审计结果",
  skills: "系统能力",
  settings: "模型设置",
  evolution: "高级实验",
};

const stateLabels = {
  PENDING: "等待中",
  PLANNING: "规划中",
  EXECUTING: "分析中",
  REVIEWING: "证据复核中",
  SUCCESS: "已完成",
  FAILED: "失败",
  CANCELLED: "已取消",
};

const severityLabels = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "提示",
  clean: "未发现风险",
};

const feedbackLabels = {
  false_positive: "误报",
  missed_issue: "漏报",
  bad_fix: "坏修复",
  accepted: "已接受",
};

const providerDefaults = {
  deepseek: {
    model: "deepseek-v4-flash",
    baseUrl: "https://api.deepseek.com",
    label: "DeepSeek",
  },
  "openrouter-deepseek-free": {
    model: "deepseek/deepseek-r1-0528:free",
    baseUrl: "https://openrouter.ai/api/v1",
    label: "OpenRouter · DeepSeek Free",
  },
  "openrouter-free": {
    model: "openrouter/free",
    baseUrl: "https://openrouter.ai/api/v1",
    label: "OpenRouter Free Router",
  },
  custom: {
    model: "",
    baseUrl: "",
    label: "自定义 OpenAI 兼容接口",
  },
  local: {
    model: "local-rules",
    baseUrl: "",
    label: "仅本地规则",
  },
};

const DEMO_TASK = {
  id: "demo-security-audit",
  repository: "demo/vulnerable-python",
  task_type: "repository_scan",
  state: "SUCCESS",
  created_at: "2026-08-24T09:30:00+08:00",
  input: { task_type: "repository_scan", repository_key: "demo/vulnerable-python" },
  report: {
    repository: "demo/vulnerable-python",
    risk: "high",
    reviewer: "LIMA evidence fusion",
    summary: "本次审计发现 3 个需要处理的安全问题。命令注入已由 source-to-sink 数据流确认，应在发布前优先修复；路径遍历和动态 SQL 排序存在可利用边界，建议纳入同一修复迭代。",
    files_reviewed: Array.from({ length: 84 }, (_, index) => `src/module_${String(index + 1).padStart(2, "0")}.py`),
    findings: [
      {
        severity: "high",
        rule_id: "PY-CMD-001",
        cwe: "CWE-78",
        path: "app/tasks.py",
        line: 42,
        title: "用户输入进入 shell 命令",
        verification_state: "dataflow-verified",
        source: "AST + interprocedural dataflow",
        confidence: 0.97,
        evidence: "request.args['target'] 跨函数传入 subprocess.run(..., shell=True)，中间没有白名单或参数化边界。",
        explanation: "攻击者可以构造 shell 元字符执行额外命令。由于输入源和危险调用之间的数据流已经确认，这不是仅基于关键词的候选告警。",
        fix: "移除 shell=True；将命令和参数拆分为固定 argv，并对 target 使用允许值白名单。",
      },
      {
        severity: "medium",
        rule_id: "PY-PATH-003",
        cwe: "CWE-22",
        path: "app/files.py",
        line: 27,
        title: "下载路径缺少目录包含关系校验",
        verification_state: "syntax-verified",
        source: "AST path invariant",
        confidence: 0.89,
        evidence: "Path(root, user_path).resolve() 的结果未检查是否仍位于 root.resolve() 内。",
        explanation: "仅调用 resolve 不能阻止 ../ 越界，攻击者可能读取应用允许目录之外的文件。",
        fix: "解析根目录与候选路径后，通过 relative_to 或等价包含关系断言拒绝越界路径。",
      },
      {
        severity: "medium",
        rule_id: "PY-SQL-002",
        cwe: "CWE-89",
        path: "app/search.py",
        line: 61,
        title: "排序字段直接拼接到 SQL 结构位置",
        verification_state: "syntax-verified",
        source: "AST SQL structure oracle",
        confidence: 0.86,
        evidence: "ORDER BY 后的 sort_key 来自请求参数；参数化查询无法保护 SQL 标识符位置。",
        explanation: "攻击者可改变 SQL 语法结构。这里需要枚举允许列名，而不是仅把值参数化。",
        fix: "将外部排序值映射到服务端固定列名；未知值回退到安全默认列。",
      },
    ],
    collaboration: {
      dataflow_verified_findings: 1,
      interprocedural_call_edges: 18,
      cross_file_call_edges: 5,
      unresolved_dataflow_calls: 2,
      dynamic_import_sites: 0,
    },
  },
};

let selectedTask = null;
let selectedTaskData = null;
let allTasks = [];
let taskFilter = "all";
let accessToken = localStorage.getItem("lima_token") || "";
let isDemoMode = sessionStorage.getItem("lima_demo") === "1";
let lastRuntime = {};
let auditDraft = { mode: "repository", step: 1, sample: false };
let demoFeedback = [];
const reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)");

function icon(name) {
  return `<svg aria-hidden="true"><use href="#i-${escapeHtml(name)}"/></svg>`;
}

function escapeHtml(value) {
  const node = document.createElement("div");
  node.textContent = value ?? "";
  return node.innerHTML;
}

function formatTime(value) {
  if (!value) return "时间未知";
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? String(value)
    : new Intl.DateTimeFormat("zh-CN", {
        month: "2-digit",
        day: "2-digit",
        hour: "2-digit",
        minute: "2-digit",
      }).format(date);
}

function bytesLabel(value) {
  const bytes = Number(value || 0);
  if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
  if (bytes >= 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${bytes} B`;
}

function normalizeState(value) {
  return String(value || "PENDING").toUpperCase();
}

function taskType(task) {
  return task?.task_type || task?.input?.task_type || (task?.pull_request ? "diff_review" : "");
}

function toast(title, message = "", type = "info") {
  const root = $("#toast-stack");
  const item = document.createElement("div");
  const iconName = type === "success" ? "check" : type === "error" || type === "warning" ? "alert" : "info";
  item.className = `toast ${type}`;
  item.setAttribute("role", type === "error" ? "alert" : "status");
  item.innerHTML = `
    ${icon(iconName)}
    <p><b>${escapeHtml(title)}</b>${message ? `<span>${escapeHtml(message)}</span>` : ""}</p>
    <button type="button" aria-label="关闭提示">${icon("close")}</button>
  `;
  root.appendChild(item);
  const close = () => {
    item.classList.add("leaving");
    window.setTimeout(() => item.remove(), reduceMotion.matches ? 0 : 180);
  };
  $("button", item).addEventListener("click", close);
  window.setTimeout(close, type === "error" ? 6000 : 3600);
}

function setButtonBusy(button, busy, busyText = "处理中…") {
  if (!button) return;
  button.setAttribute("aria-busy", String(busy));
  if (busy) {
    if (!button.dataset.label) button.dataset.label = button.innerHTML;
    button.disabled = true;
    button.innerHTML = `<span class="spinner-small"></span>${escapeHtml(busyText)}`;
  } else {
    button.disabled = false;
    if (button.dataset.label) {
      button.innerHTML = button.dataset.label;
      delete button.dataset.label;
    }
  }
}

function emptyState(title, description, actionLabel = "", action = "scan", iconName = "report") {
  return `
    <div class="empty-state">
      <div>
        <div class="empty-illustration">${icon(iconName)}</div>
        <h4>${escapeHtml(title)}</h4>
        <p>${escapeHtml(description)}</p>
        ${actionLabel ? `<button class="button button-primary" type="button" data-empty-action="${escapeHtml(action)}">${escapeHtml(actionLabel)} ${icon("arrow")}</button>` : ""}
      </div>
    </div>
  `;
}

async function mockApi(path, options = {}) {
  await new Promise((resolve) => window.setTimeout(resolve, reduceMotion.matches ? 10 : 180));
  if (path === "/api/dashboard") {
    return {
      queue: "演示环境",
      orchestrator: "运行正常",
      llm: { enabled: true, provider: "demo", model: "evidence-reviewer" },
      stats: {
        tasks_total: 7,
        tasks_success: 6,
        tasks_failed: 1,
        success_rate: 0.86,
        active_skill_versions: 8,
      },
      tasks: [DEMO_TASK],
    };
  }
  if (path === "/api/tasks") return { tasks: [DEMO_TASK] };
  if (path === "/api/skills") {
    return {
      llm: { enabled: true, provider: "demo", model: "evidence-reviewer" },
      skills: [
        { name: "repository-scan", version: "2.0", source: "built-in", sandboxed: true, description: "受控读取 Python 仓库，融合 AST、跨文件数据流和 SAST 证据。" },
        { name: "secure-repair", version: "1.4", source: "built-in", sandboxed: true, description: "针对 CWE-22、CWE-78、CWE-89 生成最小修复，并通过安全 Oracle 验证。" },
        { name: "evidence-arbitration", version: "1.2", source: "built-in", sandboxed: true, description: "区分候选、语法验证和数据流验证，抑制证据不足的自动结论。" },
        { name: "diff-review", version: "1.5", source: "built-in", sandboxed: true, description: "按新增行审查 Unified Diff，为合并前安全门禁提供结构化结论。" },
      ],
    };
  }
  if (path === "/api/repository-scans/capabilities") {
    return {
      enabled: true,
      sast_mode: "hybrid",
      repository_code_executed: false,
      max_files: 5000,
      max_file_bytes: 1048576,
      max_total_bytes: 52428800,
      dataflow_enabled: true,
      dataflow_max_call_depth: 5,
      verified_repair_cwes: ["CWE-22", "CWE-78", "CWE-89"],
      repair_tests_configured: true,
    };
  }
  if (path === "/api/failures") return { cases: demoFeedback };
  if (path.startsWith("/v1/evolution/status")) {
    return { validation_cases: 42, holdout_cases: 18, unresolved_cases: demoFeedback.length, active_version: "1.5.0", ready: true };
  }
  if (path.startsWith("/v1/evolution/runs")) {
    return { runs: [{ candidate_version: "1.5.0", decision: "通过门禁", candidate_score: 0.842, baseline_score: 0.811 }] };
  }
  if (path === "/v1/repository-scans" || path.startsWith("/v1/reviews")) {
    return { id: DEMO_TASK.id, task_id: DEMO_TASK.id, state: "SUCCESS" };
  }
  if (path === "/v1/skills/reload") return { reloaded: 4 };
  if (path.endsWith("/repair-preview")) {
    return { status: "verified-preview", cwe: "CWE-78", changed_files: 1, oracle: "通过", note: "已生成参数化 argv 的最小修复预览。" };
  }
  if (path.endsWith("/fix")) {
    return { status: "created", branch: "security/fix-demo-security-audit", changed_files: 1, note: "演示模式不会写入真实仓库。" };
  }
  if (path.endsWith("/feedback") && options.method === "POST") {
    const body = JSON.parse(options.body || "{}");
    const item = { id: `demo-feedback-${demoFeedback.length + 1}`, task_id: DEMO_TASK.id, category: body.category, payload: body, resolved: false };
    demoFeedback.unshift(item);
    return item;
  }
  if (path.endsWith("/feedback")) return { cases: demoFeedback };
  if (path.startsWith("/v1/tasks/")) return DEMO_TASK;
  if (path === "/v1/evolution/propose" || path === "/v1/evolution/auto") {
    return { decision: "未激活，仅保留候选", candidate_score: 0.842, baseline_score: 0.811, holdout_delta: 0.004, candidate_version: "1.6.0-candidate" };
  }
  if (path === "/health") return { status: "ok", version: "demo" };
  throw new Error("演示数据未覆盖此操作");
}

async function api(path, options = {}) {
  if (isDemoMode) return mockApi(path, options);
  const headers = { ...(options.headers || {}) };
  if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
  const response = await fetch(path, { ...options, headers });
  const contentType = response.headers.get("content-type") || "";
  const data = contentType.includes("json") ? await response.json() : await response.text();
  if (response.status === 401) {
    $("#login-overlay").classList.remove("hidden");
    $("#logout").classList.add("hidden");
  }
  if (!response.ok) {
    const plainText = typeof data === "string" && !/<[a-z][\s\S]*>/i.test(data) ? data.trim() : "";
    const message = typeof data === "object"
      ? data.error || data.detail || data.message
      : plainText || `请求失败 (${response.status})`;
    throw new Error(message || response.statusText || "请求失败");
  }
  return data;
}

function show(view, updateHash = true) {
  if (!titles[view]) view = "overview";
  $$(".view").forEach((element) => element.classList.toggle("active", element.id === `view-${view}`));
  $$(".nav-item").forEach((element) => {
    const active = element.dataset.view === view;
    element.classList.toggle("active", active);
    element.setAttribute("aria-current", active ? "page" : "false");
  });
  $("#page-title").textContent = titles[view];
  document.title = `${titles[view]} · LIMA`;
  if (updateHash) history.replaceState(null, "", `#${view}`);
  if (view === "tasks") loadTasks();
  if (view === "scan") loadRepositoryScanCapabilities();
  if (view === "skills") loadSkills();
  if (view === "settings") renderSettingsRuntime(lastRuntime);
  if (view === "evolution") loadFailures();
  window.scrollTo({ top: 0, behavior: reduceMotion.matches ? "auto" : "smooth" });
}

function statCard(label, value, note, color = "", iconName = "report") {
  return `
    <article class="stat-card">
      <div class="stat-top"><span>${escapeHtml(label)}</span><i class="stat-icon ${escapeHtml(color)}">${icon(iconName)}</i></div>
      <strong>${escapeHtml(value)}</strong><small>${escapeHtml(note)}</small>
    </article>
  `;
}

function taskRows(tasks) {
  if (!tasks.length) return emptyState("还没有审计任务", "从一个仓库或 PR Diff 开始，完成后报告会出现在这里。", "发起第一次审计", "scan", "scan");
  return tasks.map((task) => {
    const state = normalizeState(task.state);
    const repositoryScan = taskType(task) === "repository_scan";
    const detail = repositoryScan ? "完整仓库" : task.pull_request ? `PR #${task.pull_request}` : "Diff 审查";
    return `
      <button class="task-row ${selectedTask === task.id ? "selected" : ""}" data-task="${escapeHtml(task.id)}" type="button">
        <span class="task-main">
          <span class="task-glyph">${icon(repositoryScan ? "github" : "code")}</span>
          <span class="task-copy">
            <span class="task-name">${escapeHtml(task.repository || task?.report?.repository || "未命名审计")}</span>
            <span class="task-meta"><span>${escapeHtml(detail)}</span><span>${escapeHtml(formatTime(task.created_at))}</span></span>
          </span>
        </span>
        <span class="status state-${state.toLowerCase()}">${escapeHtml(stateLabels[state] || state)}</span>
      </button>
    `;
  }).join("");
}

function bindTasks(root) {
  $$("[data-task]", root).forEach((row) => row.addEventListener("click", () => openTask(row.dataset.task)));
  $$("[data-empty-action]", root).forEach((button) => button.addEventListener("click", () => show(button.dataset.emptyAction)));
}

function filteredTasks() {
  const query = $("#task-search")?.value.trim().toLowerCase() || "";
  return allTasks.filter((task) => {
    const state = normalizeState(task.state);
    const filterMatch = taskFilter === "all"
      || (taskFilter === "running" && !["SUCCESS", "FAILED", "CANCELLED"].includes(state))
      || state === taskFilter;
    const haystack = `${task.id || ""} ${task.repository || ""} ${task?.report?.repository || ""}`.toLowerCase();
    return filterMatch && (!query || haystack.includes(query));
  });
}

function renderTaskList() {
  const tasks = filteredTasks();
  $("#all-tasks").innerHTML = tasks.length
    ? taskRows(tasks)
    : emptyState("没有匹配的任务", "调整搜索词或状态筛选，也可以直接发起一项新审计。", "发起新审计", "scan", "report");
  $("#task-count").textContent = `${tasks.length} / ${allTasks.length} 项`;
  bindTasks($("#all-tasks"));
}

function renderLlmRuntime(llm = {}) {
  lastRuntime = llm;
  const enabled = Boolean(llm.enabled);
  const failed = Boolean(llm.error);
  const provider = String(llm.provider || "local");
  const model = String(llm.model || "");
  const statusText = failed ? "读取失败" : enabled ? "已启用" : "本地规则";
  const detail = failed
    ? "暂时无法读取模型运行时，请检查服务连接。"
    : enabled
      ? `${provider} / ${model || "默认模型"} 参与语义复核；确定性安全规则仍负责最终门禁。`
      : "尚未启用远程模型，当前使用本地确定性规则完成基础审计。";
  const status = $("#llm-runtime-status");
  if (status) {
    status.className = `pill ${failed ? "pill-red" : enabled ? "pill-green" : "pill-amber"}`;
    status.textContent = statusText;
  }
  if ($("#llm-capability-detail")) $("#llm-capability-detail").textContent = detail;
  if ($("#llm-runtime-model")) $("#llm-runtime-model").textContent = enabled ? `${provider} / ${model || "默认模型"}` : "Local rules fallback";
  renderSettingsRuntime(llm);
}

function renderSettingsRuntime(llm = {}) {
  const root = $("#settings-runtime");
  if (!root) return;
  const enabled = Boolean(llm.enabled);
  const failed = Boolean(llm.error);
  const provider = llm.provider || (enabled ? "已配置" : "local");
  const model = llm.model || (enabled ? "默认模型" : "local-rules");
  root.innerHTML = `
    <div class="mini-card"><span>分析模式</span><strong>${failed ? "状态未知" : enabled ? "规则 + LLM 证据融合" : "确定性本地规则"}</strong></div>
    <div class="mini-card"><span>Provider / Model</span><strong>${escapeHtml(provider)} / ${escapeHtml(model)}</strong></div>
    <div class="mini-card"><span>密钥来源</span><strong>服务端 .env（网页不可读取）</strong></div>
  `;
  const status = $("#settings-runtime-status");
  status.className = `pill ${failed ? "pill-red" : enabled ? "pill-green" : "pill-amber"}`;
  status.textContent = failed ? "连接异常" : enabled ? "模型已启用" : "本地模式";
}

async function loadDashboard() {
  try {
    const data = await api("/api/dashboard");
    renderLlmRuntime(data.llm || {});
    $("#system-status").textContent = isDemoMode ? "演示模式 · 数据不外传" : `${data.queue || "队列正常"} · ${data.orchestrator || "服务正常"}`;
    const stats = data.stats || {};
    const rawRate = Number(stats.success_rate || 0);
    const rate = Math.round((rawRate > 1 ? rawRate / 100 : rawRate) * 100);
    $("#stats").innerHTML = [
      statCard("累计审计", stats.tasks_total ?? 0, "已创建的审计任务", "", "report"),
      statCard("成功完成", stats.tasks_success ?? 0, "通过执行与质量门禁", "green", "check"),
      statCard("需要关注", stats.tasks_failed ?? 0, "失败或需要人工处理", "red", "alert"),
      statCard("任务成功率", `${rate}%`, "反映系统运行稳定性", "amber", "scan"),
    ].join("");
    const recent = (data.tasks || []).slice(0, 5);
    $("#recent-tasks").innerHTML = recent.length
      ? taskRows(recent)
      : emptyState("还没有审计记录", "运行第一次审计后，这里会显示最近结果。", "开始第一次审计", "scan", "scan");
    bindTasks($("#recent-tasks"));
  } catch (error) {
    renderLlmRuntime({ error: true });
    $("#system-status").textContent = "服务连接异常";
    $("#stats").innerHTML = [
      statCard("服务未连接", "—", "登录或检查本机服务", "red", "alert"),
      statCard("审计任务", "—", "连接后自动更新", "", "report"),
      statCard("安全能力", "—", "连接后自动更新", "", "grid"),
      statCard("运行状态", "离线", "请检查 Docker 服务", "amber", "refresh"),
    ].join("");
    $("#recent-tasks").innerHTML = emptyState("暂时无法读取审计数据", "请先登录；如果已经登录，请检查本机服务是否正常运行。", "体验示例报告", "demo", "report");
    bindTasks($("#recent-tasks"));
    if (!$("#login-overlay").classList.contains("hidden")) return;
    toast("无法连接服务", error.message, "error");
  }
}

async function loadTasks() {
  const root = $("#all-tasks");
  root.innerHTML = '<div class="list-skeleton"></div><div class="list-skeleton"></div>';
  try {
    const data = await api("/api/tasks");
    allTasks = data.tasks || [];
    renderTaskList();
  } catch (error) {
    root.innerHTML = emptyState("任务加载失败", error.message, "返回开始页", "overview", "alert");
    bindTasks(root);
  }
}

async function loadRepositoryScanCapabilities() {
  const root = $("#repository-scan-capabilities");
  try {
    const data = await api("/api/repository-scans/capabilities");
    root.innerHTML = [
      ["扫描状态", data.enabled ? "可用" : "仓库导入目录未就绪"],
      ["代码执行", data.repository_code_executed ? "会执行（请复核配置）" : "不执行目标代码"],
      ["扫描上限", `${Number(data.max_files || 0).toLocaleString()} 文件 · ${bytesLabel(data.max_total_bytes)}`],
      ["数据流", data.dataflow_enabled ? `跨文件 · 最深 ${Number(data.dataflow_max_call_depth || 0)} 层` : "未启用"],
      ["自动修复范围", (data.verified_repair_cwes || []).join(" / ") || "仅提供人工建议"],
      ["修复门禁", data.repair_tests_configured ? "已配置测试与安全 Oracle" : "未配置，不允许自动发布"],
    ].map(([label, value]) => `<div class="mini-card"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value)}</strong></div>`).join("");
  } catch (error) {
    root.innerHTML = `<div class="mini-card"><span>扫描能力</span><strong>${escapeHtml(error.message)}</strong></div>`;
  }
}

function normalizeRepositoryTarget(raw) {
  const value = String(raw || "").trim().replace(/\.git$/i, "");
  if (!value) throw new Error("请输入 GitHub 仓库链接或 owner/project 仓库键。");
  let candidate = value;
  if (/^https?:\/\//i.test(value)) {
    let parsed;
    try {
      parsed = new URL(value);
    } catch {
      throw new Error("仓库链接格式无效。");
    }
    if (!["github.com", "www.github.com"].includes(parsed.hostname.toLowerCase())) {
      throw new Error("当前只接受 github.com 链接；其他来源请先安全导入 repositories 目录。");
    }
    candidate = parsed.pathname.replace(/^\/+|\/+$/g, "").replace(/\.git$/i, "");
  }
  const pieces = candidate.split("/");
  if (pieces.length !== 2 || !pieces.every((part) => /^[A-Za-z0-9_.-]+$/.test(part)) || pieces.some((part) => part === "." || part === "..")) {
    throw new Error("仓库目标应为 owner/project，不能包含绝对路径、目录穿越或额外层级。");
  }
  return pieces.join("/");
}

function updateAuditMode(mode) {
  auditDraft.mode = mode === "diff" ? "diff" : "repository";
  auditDraft.sample = false;
  $$("[data-audit-mode]").forEach((button) => {
    const active = button.dataset.auditMode === auditDraft.mode;
    button.classList.toggle("active", active);
    button.setAttribute("aria-checked", String(active));
  });
  const diff = auditDraft.mode === "diff";
  $("#diff-basic-fields").classList.toggle("hidden", !diff);
  $("#repository-scope").classList.toggle("hidden", diff);
  $("#diff-scope").classList.toggle("hidden", !diff);
  $("#audit-target-label").textContent = diff ? "仓库名称或 GitHub 链接" : "GitHub 仓库链接或仓库键";
  $("#scope-description").textContent = diff
    ? "只检查粘贴的新增代码，不读取或执行完整仓库。"
    : "系统将使用默认工程基线扫描已安全导入的仓库，不执行目标代码。";
}

function setWizardStep(step) {
  auditDraft.step = Math.max(1, Math.min(3, Number(step)));
  $$(".wizard-step").forEach((panel) => panel.classList.toggle("active", Number(panel.dataset.step) === auditDraft.step));
  $$("[data-step-indicator]").forEach((indicator) => {
    const value = Number(indicator.dataset.stepIndicator);
    indicator.classList.toggle("active", value === auditDraft.step);
    indicator.classList.toggle("done", value < auditDraft.step);
  });
  if (auditDraft.step === 3) renderAuditReview();
  $("#audit-wizard").scrollIntoView({ behavior: reduceMotion.matches ? "auto" : "smooth", block: "start" });
}

function validateAuditStep(step) {
  if (step === 1) {
    $("#audit-step-one-error").textContent = "";
    try {
      auditDraft.repository = normalizeRepositoryTarget($("#audit-target").value);
    } catch (error) {
      $("#audit-step-one-error").textContent = error.message;
      $("#audit-target").focus();
      return false;
    }
  }
  if (step === 2 && auditDraft.mode === "diff") {
    const diff = $("#audit-diff").value.trim();
    $("#audit-diff-error").textContent = "";
    if (!diff || !diff.includes("@@") || !diff.split(/\r?\n/).some((line) => line.startsWith("+") && !line.startsWith("+++"))) {
      $("#audit-diff-error").textContent = "请粘贴包含 @@ 区块和新增行的 Unified Diff。";
      $("#audit-diff").focus();
      return false;
    }
    auditDraft.diff = diff;
  }
  return true;
}

function renderAuditReview() {
  const modeText = auditDraft.mode === "repository" ? "完整仓库审计" : "PR / Diff 审查";
  const scopeText = auditDraft.mode === "repository"
    ? "AST + 跨文件数据流 + 可用 SAST；不执行目标代码"
    : `仅审查 ${($("#audit-diff").value.match(/^\+(?!\+\+)/gm) || []).length} 行新增代码`;
  const pr = Number($("#audit-pr-number").value);
  $("#audit-review-summary").innerHTML = `
    <div><span>审计方式</span><strong>${escapeHtml(modeText)}</strong></div>
    <div><span>目标仓库</span><strong>${escapeHtml(auditDraft.repository || "未确认")}${pr > 0 ? ` · PR #${pr}` : ""}</strong></div>
    <div><span>分析范围</span><strong>${escapeHtml(scopeText)}</strong></div>
    <div><span>数据处理</span><strong>${auditDraft.sample ? "内置演示数据，不连接外部服务" : "只处理你有权审查的本机代码或 Diff"}</strong></div>
  `;
}

function loadAuditSample() {
  auditDraft.sample = true;
  $("#audit-target").value = "demo/vulnerable-python";
  if (auditDraft.mode === "diff") {
    $("#audit-pr-number").value = "42";
    $("#audit-diff").value = [
      "--- a/app/tasks.py",
      "+++ b/app/tasks.py",
      "@@ -38,3 +38,5 @@ def run_task(request):",
      "+    target = request.args['target']",
      "+    subprocess.run(f\"ping {target}\", shell=True)",
    ].join("\n");
    updateDiffStats();
  }
  $("#audit-step-one-error").textContent = "";
  toast("示例已加载", "继续下一步即可体验完整审计和可读报告。", "success");
}

async function runAudit() {
  if (!validateAuditStep(1) || !validateAuditStep(2)) return;
  const button = $("#run-audit");
  setButtonBusy(button, true, "正在创建…");
  $$(".wizard-step").forEach((panel) => panel.classList.remove("active"));
  $("#wizard-running").classList.remove("hidden");
  try {
    if (auditDraft.sample) {
      isDemoMode = true;
      sessionStorage.setItem("lima_demo", "1");
      $("#logout").classList.remove("hidden");
      $("#wizard-running-text").textContent = "正在准备内置证据和人类可读报告…";
    }
    const pr = Number($("#audit-pr-number").value);
    const data = auditDraft.mode === "repository"
      ? await api("/v1/repository-scans", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ repository_key: auditDraft.repository }),
        })
      : await api("/v1/reviews?async=true", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            repository: auditDraft.repository,
            diff: $("#audit-diff").value,
            ...(pr > 0 ? { pull_request: pr } : {}),
          }),
        });
    const taskId = data.task_id || data.id;
    toast("审计任务已创建", auditDraft.sample ? "示例报告已准备好。" : "任务会在后台运行，可随时查看状态。", "success");
    await loadDashboard();
    if (taskId) await openTask(taskId);
    else {
      show("tasks");
      await loadTasks();
    }
  } catch (error) {
    toast("审计任务创建失败", error.message, "error");
    $("#wizard-running").classList.add("hidden");
    setWizardStep(3);
  } finally {
    setButtonBusy(button, false);
  }
}

function severityCounts(findings) {
  return findings.reduce((counts, finding) => {
    const severity = String(finding.severity || "info").toLowerCase();
    counts[severity] = (counts[severity] || 0) + 1;
    return counts;
  }, { critical: 0, high: 0, medium: 0, low: 0, info: 0 });
}

function reportRisk(report, findings) {
  const explicit = String(report?.risk || "").toLowerCase();
  if (severityLabels[explicit]) return explicit;
  const counts = severityCounts(findings);
  if (counts.critical) return "critical";
  if (counts.high) return "high";
  if (counts.medium) return "medium";
  if (counts.low || counts.info) return "low";
  return "clean";
}

function confidenceLabel(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return "未提供";
  return `${Math.round((number <= 1 ? number : number / 100) * 100)}%`;
}

function verificationLabel(value) {
  const state = String(value || "candidate").toLowerCase();
  if (state.includes("dataflow")) return "数据流已验证";
  if (state.includes("syntax")) return "语法约束已验证";
  if (state.includes("verified")) return "已验证";
  return "候选 · 需复核";
}

function renderTaskReport(task) {
  const state = normalizeState(task?.state);
  if (!["SUCCESS", "FAILED", "CANCELLED"].includes(state) && !task?.report) {
    return `
      <div class="pending-report">
        <span class="spinner-large"></span>
        <h3>${escapeHtml(stateLabels[state] || "审计进行中")}</h3>
        <p>任务正在后台运行。点击右上角刷新即可获取最新状态。</p>
      </div>
    `;
  }
  if (state === "FAILED" && !task?.report) {
    return emptyState("审计未完成", task.error || "任务执行失败，请检查目标、服务配置和任务日志后重试。", "重新发起审计", "scan", "alert");
  }
  const report = task?.report || {};
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const counts = severityCounts(findings);
  const risk = reportRisk(report, findings);
  const verified = findings.filter((finding) => String(finding.verification_state || "").toLowerCase().includes("verified")).length;
  const files = Array.isArray(report.files_reviewed) ? report.files_reviewed.length : Number(report.files_reviewed || report.file_count || 0);
  const highPriority = counts.critical + counts.high;
  const summary = report.summary || (findings.length
    ? `发现 ${findings.length} 个候选安全问题。请优先处理高风险和证据已验证的结论。`
    : "本次审计没有发现满足当前规则和证据阈值的安全问题。仍建议结合业务威胁模型进行人工复核。");
  const maxCount = Math.max(1, counts.critical, counts.high, counts.medium, counts.low, counts.info);
  const bars = ["critical", "high", "medium", "low"].map((severity) => `
    <div class="bar-row">
      <span>${escapeHtml(severityLabels[severity])}</span>
      <span class="bar-track"><span class="bar-fill ${severity}" style="width:${Math.round((counts[severity] / maxCount) * 100)}%"></span></span>
      <strong>${counts[severity]}</strong>
    </div>
  `).join("");
  const findingRows = findings.map((finding, index) => {
    const severity = String(finding.severity || "info").toLowerCase();
    const safeSeverity = ["critical", "high", "medium", "low", "info"].includes(severity) ? severity : "info";
    const location = `${finding.path || "未知文件"}:${finding.line || "?"}`;
    return `
      <tr>
        <td><span class="pill ${safeSeverity === "critical" || safeSeverity === "high" ? "pill-red" : safeSeverity === "medium" ? "pill-amber" : "pill-green"}">${escapeHtml(severityLabels[safeSeverity] || safeSeverity)}</span></td>
        <td class="finding-title">
          <b>${escapeHtml(finding.title || finding.rule_id || `问题 ${index + 1}`)}</b>
          <small>${escapeHtml(finding.cwe || "CWE 未分类")} · ${escapeHtml(finding.rule_id || "未命名规则")}</small>
          <details class="finding-details">
            <summary>查看证据与修复建议</summary>
            <div>
              <p><strong>为什么是问题：</strong>${escapeHtml(finding.explanation || "当前报告没有提供进一步解释。")}</p>
              <p><strong>关键证据：</strong>${escapeHtml(finding.evidence || "当前报告没有提供证据摘要。")}</p>
              <p><strong>建议修复：</strong>${escapeHtml(finding.fix || "建议由开发者结合业务上下文制定最小修复。")}</p>
            </div>
          </details>
        </td>
        <td><code>${escapeHtml(location)}</code></td>
        <td><span class="pill pill-neutral">${escapeHtml(verificationLabel(finding.verification_state))}</span></td>
        <td class="confidence">${escapeHtml(confidenceLabel(finding.confidence))}</td>
      </tr>
    `;
  }).join("");
  return `
    <div class="report-document">
      <header class="report-header">
        <div class="report-title">
          <span class="eyebrow">SECURITY AUDIT REPORT</span>
          <h2>${escapeHtml(report.repository || task.repository || "代码安全审计")}</h2>
          <p><strong>结论：</strong>${escapeHtml(summary)}</p>
        </div>
        <div class="risk-badge risk-${risk}"><strong>${escapeHtml(severityLabels[risk] || risk)}</strong><span>总体风险</span></div>
      </header>
      <section class="report-metrics" aria-label="报告摘要">
        <div class="report-metric"><span>问题总数</span><strong>${findings.length}</strong></div>
        <div class="report-metric"><span>严重 / 高危</span><strong>${highPriority}</strong></div>
        <div class="report-metric"><span>证据已验证</span><strong>${verified}</strong></div>
        <div class="report-metric"><span>审计文件</span><strong>${files || "—"}</strong></div>
      </section>
      <section class="chart-card" aria-label="严重度分布图">
        <div><h3>严重度分布</h3><p>条形长度按当前报告中的最大类别归一化。</p></div>
        <div class="severity-bars">${bars}</div>
      </section>
      <div class="finding-section-head">
        <div><h3>问题清单</h3><p>按风险、位置和证据状态快速决定处理顺序。</p></div>
        <span class="pill pill-neutral">${findings.length} 项</span>
      </div>
      ${findingRows
        ? `<div class="finding-table-wrap"><table class="finding-table"><thead><tr><th>风险</th><th>问题与依据</th><th>位置</th><th>证据状态</th><th>置信度</th></tr></thead><tbody>${findingRows}</tbody></table></div>`
        : emptyState("未发现达到阈值的问题", "这不等于绝对安全。请结合依赖风险、部署配置和业务权限继续复核。", "发起另一项审计", "scan", "check")}
      <p class="report-footnote">${icon("info")}<span><strong>如何解读：</strong>“数据流已验证”表示系统确认了输入源到危险调用的路径；“候选”仍需要人工结合业务上下文判断。置信度不能替代漏洞可利用性分析。</span></p>
    </div>
  `;
}

async function openTask(id) {
  show("tasks");
  selectedTask = id;
  selectedTaskData = null;
  renderTaskList();
  $("#task-report").className = "";
  $("#task-report").innerHTML = '<div class="pending-report"><span class="spinner-large"></span><h3>正在整理报告</h3><p>加载风险摘要和证据，请稍候…</p></div>';
  $("#feedback-panel").classList.add("hidden");
  $("#create-fix").classList.add("hidden");
  $("#create-repair-preview").classList.add("hidden");
  try {
    const task = await api(`/v1/tasks/${encodeURIComponent(id)}`);
    selectedTaskData = task;
    $("#task-report").innerHTML = renderTaskReport(task);
    const reportReady = normalizeState(task.state) === "SUCCESS" && task.report;
    const repositoryScan = taskType(task) === "repository_scan";
    $("#create-repair-preview").classList.toggle("hidden", !(reportReady && repositoryScan && (task.report.findings || []).length));
    $("#create-fix").classList.toggle("hidden", !(reportReady && task.pull_request));
    $("#feedback-panel").classList.toggle("hidden", !reportReady);
    if (reportReady) {
      populateFeedbackFindings(task.report.findings || []);
      await loadTaskFeedback(id);
    }
    renderTaskList();
  } catch (error) {
    selectedTaskData = null;
    $("#task-report").innerHTML = emptyState("报告加载失败", error.message, "返回任务列表", "tasks", "alert");
    toast("报告加载失败", error.message, "error");
  }
}

function populateFeedbackFindings(findings) {
  $("#feedback-finding").innerHTML = '<option value="">不关联已有问题</option>' + findings.map((finding, index) => {
    const identity = `${finding.rule_id || "未命名规则"} · ${finding.path || "未知文件"}:${finding.line || "?"}`;
    return `<option value="${index}">${escapeHtml(identity)}</option>`;
  }).join("");
  $("#feedback-result").textContent = "";
}

function renderTaskFeedback(cases) {
  const root = $("#task-feedback-history");
  if (!cases.length) {
    root.innerHTML = '<p class="feedback-empty">尚无反馈。提交后，它会进入失败案例集和后续回放评测。</p>';
    return;
  }
  root.innerHTML = '<p class="list-section-label">本任务反馈</p>' + cases.map((item) => {
    const payload = item.payload || {};
    const finding = payload.finding || {};
    const reference = finding.rule_id
      ? `${finding.rule_id} · ${finding.path || "未知文件"}:${finding.line || "?"}`
      : "未关联已有问题";
    return `
      <div class="feedback-case">
        <span class="pill pill-blue">${escapeHtml(feedbackLabels[item.category] || item.category)}</span>
        <span class="feedback-case-copy"><b>${escapeHtml(reference)}</b><small>${escapeHtml(payload.note || "未填写说明")}</small></span>
        <span class="status ${item.resolved ? "state-success" : "state-pending"}">${item.resolved ? "已解决" : "待评测"}</span>
      </div>
    `;
  }).join("");
}

async function loadTaskFeedback(taskId) {
  $("#task-feedback-history").innerHTML = '<p class="feedback-empty">正在读取反馈…</p>';
  try {
    const data = await api(`/v1/tasks/${encodeURIComponent(taskId)}/feedback`);
    if (selectedTask === taskId) renderTaskFeedback(data.cases || []);
  } catch (error) {
    $("#task-feedback-history").innerHTML = `<p class="feedback-empty">无法读取反馈：${escapeHtml(error.message)}</p>`;
  }
}

async function loadSkills() {
  const root = $("#skill-list");
  root.innerHTML = '<div class="skill-card skeleton"></div><div class="skill-card skeleton"></div>';
  try {
    const data = await api("/api/skills");
    renderLlmRuntime(data.llm || {});
    const skills = (data.skills || []).filter((skill) => skill.name !== "llm-review");
    root.innerHTML = skills.length ? skills.map((skill) => `
      <article class="skill-card">
        <span class="skill-icon">${icon(skill.sandboxed ? "shield" : "grid")}</span>
        <h3>${escapeHtml(skill.name)}</h3>
        <p>${escapeHtml(skill.description || "暂无能力描述")}</p>
        <span class="skill-meta">v${escapeHtml(skill.version || "1.0")} · ${escapeHtml(skill.source || "built-in")} · ${skill.sandboxed ? "隔离运行" : "标准运行"}</span>
      </article>
    `).join("") : emptyState("尚未加载分析能力", "重新扫描 Skill 目录以发现可用能力。", "重新扫描能力", "reload-skills", "grid");
    const action = $('[data-empty-action="reload-skills"]', root);
    if (action) action.addEventListener("click", () => $("#reload-skills").click());
  } catch (error) {
    renderLlmRuntime({ error: true });
    root.innerHTML = emptyState("系统能力加载失败", error.message, "检查模型设置", "settings", "alert");
    bindTasks(root);
  }
}

function humanLabel(key) {
  const labels = {
    validation_cases: "Validation 案例",
    holdout_cases: "Holdout 案例",
    unresolved_cases: "待处理反馈",
    active_version: "当前版本",
    ready: "评测是否就绪",
    decision: "门禁结论",
    candidate_score: "候选得分",
    baseline_score: "基线得分",
    holdout_delta: "Holdout 变化",
    candidate_version: "候选版本",
    status: "状态",
    branch: "修复分支",
    changed_files: "修改文件数",
    oracle: "安全 Oracle",
    cwe: "漏洞类型",
    note: "说明",
  };
  return labels[key] || String(key).replaceAll("_", " ");
}

function humanValue(value) {
  if (typeof value === "boolean") return value ? "是" : "否";
  if (value == null || value === "") return "—";
  if (typeof value === "number") return Number.isInteger(value) ? String(value) : value.toFixed(3);
  if (Array.isArray(value)) return value.join("、") || "—";
  if (typeof value === "object") return "详见任务报告";
  return String(value);
}

function renderOperationResult(data, title = "操作结果") {
  const entries = Object.entries(data || {}).filter(([, value]) => typeof value !== "object" || Array.isArray(value));
  return `<h4>${escapeHtml(title)}</h4><dl>${entries.map(([key, value]) => `<dt>${escapeHtml(humanLabel(key))}</dt><dd>${escapeHtml(humanValue(value))}</dd>`).join("")}</dl>`;
}

async function loadFailures() {
  try {
    const [failuresData, status, runsData] = await Promise.all([
      api("/api/failures"),
      api("/v1/evolution/status"),
      api("/v1/evolution/runs?limit=5"),
    ]);
    $("#evolution-status").innerHTML = Object.entries(status || {}).map(([key, value]) => `
      <div class="mini-card"><span>${escapeHtml(humanLabel(key))}</span><strong>${escapeHtml(humanValue(value))}</strong></div>
    `).join("") || '<div class="mini-card"><span>评测状态</span><strong>暂无数据</strong></div>';
    const cases = failuresData.cases || [];
    const runs = runsData.runs || [];
    const failureHtml = cases.length ? cases.slice(0, 8).map((item) => `
      <div class="task-row">
        <span class="task-main"><span class="task-glyph">${icon("alert")}</span><span class="task-copy">
          <span class="task-name">${escapeHtml(feedbackLabels[item.category] || item.category)}</span>
          <span class="task-meta"><span>${escapeHtml(item.task_id || "未知任务")}</span><span>${escapeHtml((item.payload || {}).note || "无说明")}</span></span>
        </span></span>
        <span class="status ${item.resolved ? "state-success" : "state-pending"}">${item.resolved ? "已解决" : "待评测"}</span>
      </div>
    `).join("") : emptyState("暂无失败反馈", "在审计报告中提交误报、漏报或坏修复后，案例会出现在这里。", "查看审计结果", "tasks", "check");
    const historyHtml = runs.length ? '<p class="list-section-label">最近评测</p>' + runs.map((run) => `
      <div class="task-row">
        <span class="task-main"><span class="task-glyph">V${escapeHtml(run.candidate_version || "?")}</span><span class="task-copy">
          <span class="task-name">${escapeHtml(run.decision || "评测完成")}</span>
          <span class="task-meta"><span>候选 ${Number(run.candidate_score || 0).toFixed(3)}</span><span>基线 ${Number(run.baseline_score || 0).toFixed(3)}</span></span>
        </span></span>
      </div>
    `).join("") : "";
    $("#failure-list").innerHTML = failureHtml + historyHtml;
    bindTasks($("#failure-list"));
  } catch (error) {
    $("#evolution-status").innerHTML = '<div class="mini-card"><span>评测状态</span><strong>暂时无法读取</strong></div>';
    $("#failure-list").innerHTML = emptyState("高级实验数据加载失败", error.message, "返回审计结果", "tasks", "alert");
    bindTasks($("#failure-list"));
  }
}

function showOperationInsideReport(data, title) {
  const existing = $(".report-operation", $("#task-report"));
  if (existing) existing.remove();
  const panel = document.createElement("section");
  panel.className = "operation-result report-operation";
  panel.innerHTML = renderOperationResult(data, title);
  $("#task-report").prepend(panel);
}

function confirmAction({ title, description, acceptLabel = "确认" }) {
  const modal = $("#confirm-modal");
  const accept = $("#confirm-accept");
  const cancel = $("#confirm-cancel");
  const close = $("#confirm-close");
  $("#confirm-title").textContent = title;
  $("#confirm-description").textContent = description;
  accept.textContent = acceptLabel;
  modal.classList.remove("hidden");
  const previousFocus = document.activeElement;
  accept.focus();
  return new Promise((resolve) => {
    const finish = (value) => {
      modal.classList.add("hidden");
      accept.removeEventListener("click", onAccept);
      cancel.removeEventListener("click", onCancel);
      close.removeEventListener("click", onCancel);
      modal.removeEventListener("click", onBackdrop);
      document.removeEventListener("keydown", onKeydown);
      if (previousFocus?.focus) previousFocus.focus();
      resolve(value);
    };
    const onAccept = () => finish(true);
    const onCancel = () => finish(false);
    const onBackdrop = (event) => { if (event.target === modal) finish(false); };
    const onKeydown = (event) => { if (event.key === "Escape") finish(false); };
    accept.addEventListener("click", onAccept);
    cancel.addEventListener("click", onCancel);
    close.addEventListener("click", onCancel);
    modal.addEventListener("click", onBackdrop);
    document.addEventListener("keydown", onKeydown);
  });
}

function enterDemo(openReport = false) {
  isDemoMode = true;
  sessionStorage.setItem("lima_demo", "1");
  $("#login-overlay").classList.add("hidden");
  $("#logout").classList.remove("hidden");
  $("#system-status").textContent = "演示模式 · 数据不外传";
  toast("已进入演示模式", "所有数据均为内置示例，不会连接仓库或远程模型。", "success");
  loadDashboard();
  if (openReport) openTask(DEMO_TASK.id);
}

function buildModelConfig(revealSecret = false) {
  const provider = $("#model-provider").value;
  const model = $("#model-name").value.trim();
  const baseUrl = $("#model-base-url").value.trim();
  const secret = $("#model-api-key").value.trim();
  if (provider !== "local" && !model) throw new Error("请输入模型名称。");
  if (provider !== "local") {
    try {
      const parsed = new URL(baseUrl);
      if (!["http:", "https:"].includes(parsed.protocol)) throw new Error();
    } catch {
      throw new Error("请输入有效的 HTTP(S) API URL。");
    }
  }
  const shownSecret = revealSecret ? secret : secret ? `${secret.slice(0, 3)}••••${secret.slice(-3)}` : "<在这里填写 API Key>";
  if (provider === "local") return "LIMA_LLM_PROVIDER=local";
  const keyName = provider === "deepseek"
    ? "LIMA_DEEPSEEK_API_KEY"
    : provider.startsWith("openrouter")
      ? "LIMA_OPENROUTER_API_KEY"
      : "LIMA_LLM_API_KEY";
  return [
    `LIMA_LLM_PROVIDER=${provider}`,
    `LIMA_LLM_MODEL=${model}`,
    `LIMA_LLM_BASE_URL=${baseUrl}`,
    `${keyName}=${shownSecret}`,
  ].join("\n");
}

function updateProviderDefaults() {
  const provider = $("#model-provider").value;
  const defaults = providerDefaults[provider];
  $("#model-name").value = defaults.model;
  $("#model-base-url").value = defaults.baseUrl;
  const local = provider === "local";
  $("#model-name").disabled = local;
  $("#model-base-url").disabled = local;
  $("#model-api-key").disabled = local;
  $("#config-result").classList.add("hidden");
}

function updateDiffStats() {
  const value = $("#audit-diff").value;
  const lines = value ? value.split(/\r?\n/).length : 0;
  $("#diff-stats").textContent = `${lines} 行 · ${value.length} 字符`;
}

$$(".nav-item").forEach((button) => button.addEventListener("click", () => show(button.dataset.view)));
$$("[data-jump]").forEach((button) => button.addEventListener("click", () => show(button.dataset.jump)));
window.addEventListener("hashchange", () => show(location.hash.slice(1), false));

$("#overview-demo").addEventListener("click", () => enterDemo(true));
$("#demo-login").addEventListener("click", () => enterDemo(false));
$$("[data-audit-mode]").forEach((button) => button.addEventListener("click", () => updateAuditMode(button.dataset.auditMode)));
$$("[data-wizard-next]").forEach((button) => button.addEventListener("click", () => {
  if (validateAuditStep(auditDraft.step)) setWizardStep(auditDraft.step + 1);
}));
$$("[data-wizard-back]").forEach((button) => button.addEventListener("click", () => setWizardStep(auditDraft.step - 1)));
$("#load-audit-sample").addEventListener("click", loadAuditSample);
$("#audit-diff").addEventListener("input", updateDiffStats);
$("#run-audit").addEventListener("click", runAudit);

$("#task-search").addEventListener("input", renderTaskList);
$$("[data-task-filter]").forEach((button) => button.addEventListener("click", () => {
  taskFilter = button.dataset.taskFilter;
  $$("[data-task-filter]").forEach((item) => item.classList.toggle("active", item === button));
  renderTaskList();
}));

$("#create-repair-preview").addEventListener("click", async () => {
  if (!selectedTask) return;
  const button = $("#create-repair-preview");
  setButtonBusy(button, true, "正在验证…");
  try {
    const data = await api(`/v1/tasks/${encodeURIComponent(selectedTask)}/repair-preview`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    showOperationInsideReport(data, "自动修复预览");
    toast(data.status === "verified-preview" ? "修复预览已通过门禁" : "未生成自动修复", data.note || "", data.status === "verified-preview" ? "success" : "warning");
  } catch (error) {
    toast("修复预览失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#create-fix").addEventListener("click", async () => {
  if (!selectedTask) return;
  const confirmed = await confirmAction({
    title: "确认创建修复分支？",
    description: "该操作会在目标仓库创建新分支并写入修复提交。不会覆盖当前分支，但可能触发仓库 CI。请确认你有权修改该仓库。",
    acceptLabel: "创建修复分支",
  });
  if (!confirmed) return;
  const button = $("#create-fix");
  setButtonBusy(button, true, "正在创建…");
  try {
    const data = await api(`/v1/tasks/${encodeURIComponent(selectedTask)}/fix`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    showOperationInsideReport(data, "修复分支结果");
    toast("修复分支已创建", data.branch || "请在仓库中检查变更。", "success");
  } catch (error) {
    toast("创建修复分支失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#feedback-category").addEventListener("change", (event) => {
  const missed = event.target.value === "missed_issue";
  $("#feedback-missed-fields").classList.toggle("hidden", !missed);
  $("#feedback-hint").textContent = missed
    ? "补充规则、路径和行号可让后续回放评测更准确。"
    : "提交后可在本任务和高级实验中查看状态。";
});

$("#feedback-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!selectedTask || !selectedTaskData?.report) return;
  const form = event.currentTarget;
  const button = $('button[type="submit"]', form);
  const values = new FormData(form);
  const category = String(values.get("category"));
  const selectedIndex = values.get("finding_index");
  const findings = selectedTaskData.report.findings || [];
  const finding = selectedIndex === "" ? {} : { ...(findings[Number(selectedIndex)] || {}) };
  if (category === "missed_issue") {
    const ruleId = String(values.get("rule_id") || "").trim();
    const path = String(values.get("path") || "").trim();
    const line = Number(values.get("line"));
    if (ruleId) finding.rule_id = ruleId;
    if (path) finding.path = path;
    if (Number.isInteger(line) && line > 0) finding.line = line;
  }
  setButtonBusy(button, true, "正在提交…");
  $("#feedback-result").textContent = "正在保存反馈…";
  try {
    const data = await api(`/v1/tasks/${encodeURIComponent(selectedTask)}/feedback`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        category,
        finding: Object.keys(finding).length ? finding : null,
        note: String(values.get("note") || "").trim(),
      }),
    });
    $("#feedback-result").textContent = `${feedbackLabels[data.category] || data.category}已记录，将进入后续回放评测。`;
    form.reset();
    $("#feedback-missed-fields").classList.add("hidden");
    await loadTaskFeedback(selectedTask);
    toast("反馈已记录", "感谢你帮助系统区分真实漏洞与噪声。", "success");
  } catch (error) {
    $("#feedback-result").textContent = `提交失败：${error.message}`;
    toast("反馈提交失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#reload-skills").addEventListener("click", async () => {
  const button = $("#reload-skills");
  setButtonBusy(button, true, "正在扫描…");
  try {
    await api("/v1/skills/reload", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    await loadSkills();
    toast("系统能力已更新", "已重新扫描可用 Skill。", "success");
  } catch (error) {
    toast("能力扫描失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#evolution-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $('button[type="submit"]', form);
  const values = new FormData(form);
  setButtonBusy(button, true, "正在回放…");
  try {
    const data = await api("/v1/evolution/propose", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill_name: values.get("skill_name"), prompt: values.get("prompt") }),
    });
    $("#evolution-result").classList.remove("hidden");
    $("#evolution-result").innerHTML = renderOperationResult(data, "候选评测结果");
    toast("回放评测已完成", "候选是否激活由 Validation 与 Holdout 门禁共同决定。", "success");
    await loadFailures();
  } catch (error) {
    toast("回放评测失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#auto-evolve").addEventListener("click", async () => {
  const button = $("#auto-evolve");
  setButtonBusy(button, true, "正在生成…");
  try {
    const data = await api("/v1/evolution/auto", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ skill_name: "llm-review" }),
    });
    $("#evolution-result").classList.remove("hidden");
    $("#evolution-result").innerHTML = renderOperationResult(data, "自动候选评测");
    toast("候选评测已完成", "结果已通过可读摘要呈现。", "success");
    await loadFailures();
  } catch (error) {
    toast("自动候选评测失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#load-prompt-template").addEventListener("click", () => {
  $('textarea[name="prompt"]', $("#evolution-form")).value = "Review only actionable security defects introduced by added lines. Require a concrete source-to-sink path or a violated security invariant. Return severity, CWE, evidence, minimal fix, and a regression-test oracle. Mark uncertain findings as candidates instead of verified vulnerabilities.";
  toast("推荐模板已加载", "你仍可以在提交前修改内容。", "success");
});

$("#model-provider").addEventListener("change", updateProviderDefaults);
$("#toggle-api-key").addEventListener("click", () => {
  const input = $("#model-api-key");
  input.type = input.type === "password" ? "text" : "password";
  $("#toggle-api-key").setAttribute("aria-label", input.type === "password" ? "显示 API Key" : "隐藏 API Key");
});
$("#model-config-form").addEventListener("submit", (event) => {
  event.preventDefault();
  try {
    $("#config-preview").textContent = buildModelConfig(false);
    $("#config-result").classList.remove("hidden");
    $("#config-result").scrollIntoView({ behavior: reduceMotion.matches ? "auto" : "smooth", block: "nearest" });
    toast("配置步骤已生成", "API Key 只存在于当前输入框，未保存、未发送。", "success");
  } catch (error) {
    toast("无法生成配置", error.message, "error");
  }
});
$("#copy-model-config").addEventListener("click", async () => {
  try {
    const config = buildModelConfig(true);
    await navigator.clipboard.writeText(config);
    toast("配置已复制", "请写入项目根目录 .env，然后重新运行 up。", "success");
  } catch (error) {
    toast("复制失败", error.message || "请手动选择配置文本。", "error");
  }
});
$("#check-connection").addEventListener("click", async () => {
  const button = $("#check-connection");
  setButtonBusy(button, true, "正在检查…");
  try {
    await api("/health");
    await loadDashboard();
    toast("服务连接正常", "运行时状态已刷新。", "success");
  } catch (error) {
    toast("服务连接失败", error.message, "error");
  } finally {
    setButtonBusy(button, false);
  }
});

$("#refresh").addEventListener("click", async () => {
  const view = location.hash.slice(1) || "overview";
  if (view === "overview") await loadDashboard();
  else if (view === "scan") await loadRepositoryScanCapabilities();
  else if (view === "tasks") await loadTasks();
  else if (view === "skills") await loadSkills();
  else if (view === "settings") await loadDashboard();
  else if (view === "evolution") await loadFailures();
  toast("当前页面已刷新", "", "success");
});

$("#login-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const button = $('button[type="submit"]', form);
  const values = new FormData(form);
  setButtonBusy(button, true, "正在登录…");
  $("#login-error").textContent = "";
  try {
    const response = await fetch("/v1/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: values.get("username"),
        password: values.get("password"),
        tenant_id: values.get("tenant_id"),
      }),
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || data.detail || "用户名或密码错误");
    accessToken = data.access_token;
    localStorage.setItem("lima_token", accessToken);
    isDemoMode = false;
    sessionStorage.removeItem("lima_demo");
    $("#login-overlay").classList.add("hidden");
    $("#logout").classList.remove("hidden");
    toast("登录成功", "正在加载你的安全工作区。", "success");
    await loadDashboard();
  } catch (error) {
    $("#login-error").textContent = error.message;
  } finally {
    setButtonBusy(button, false);
  }
});

$("#logout").addEventListener("click", () => {
  accessToken = "";
  isDemoMode = false;
  localStorage.removeItem("lima_token");
  sessionStorage.removeItem("lima_demo");
  selectedTask = null;
  selectedTaskData = null;
  $("#login-overlay").classList.remove("hidden");
  $("#logout").classList.add("hidden");
  $("#system-status").textContent = "等待登录";
});

document.addEventListener("click", (event) => {
  const action = event.target.closest("[data-empty-action]");
  if (!action) return;
  if (action.dataset.emptyAction === "demo") enterDemo(true);
  else if (titles[action.dataset.emptyAction]) show(action.dataset.emptyAction);
});

updateAuditMode("repository");
setWizardStep(1);
updateDiffStats();
updateProviderDefaults();
if (isDemoMode || accessToken) $("#logout").classList.remove("hidden");
show(location.hash.slice(1) || "overview", false);
loadDashboard();
