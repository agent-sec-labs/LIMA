import React, { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Alert,
  App as AntApp,
  Button,
  Descriptions,
  Input,
  Radio,
  Result,
  Space,
  Steps,
  Switch,
  Typography,
} from "antd";
import { api, ApiError } from "@/shared/api/client";
import {
  type AuditDraft,
  type ScanCapabilitiesPayload,
  type ScanCreatedResponse,
  agentDetectionGate,
  auditResolver,
  buildSubmitPayload,
  clearDraft,
  isMovingRef,
  loadDraft,
  normalizeRepositoryTarget,
  saveDraft,
} from "./model";

/**
 * 发起审计向导（T6）：editing / review / submitting 三态，
 * 202 后责任移交任务中心；同步失败回到 editing 并完整保留草稿。
 * 组件挂载永远从 editing 开始——导航返回天然免刷新恢复，不存在卡死态。
 * 智能体检测（#245）：仓库模式单一开关，capabilities 门禁 + 提交前模型调用确认。
 */

type WizardPhase = "editing" | "review" | "submitting";

const STEP_ITEMS = [
  { title: "选择目标" },
  { title: "确认范围" },
  { title: "提交任务" },
];

/** 具名 400（方案 §3.1）：稳定 code → 用户可读提示；保留草稿并刷新 capabilities。 */
const AGENT_DETECTION_ERROR_LABELS: Record<string, string> = {
  "agent-detection-required":
    "服务端策略要求本次扫描开启智能体检测，不能以关闭状态提交。",
  "agent-detection-unavailable":
    "服务端未配置智能体检测模型，暂时无法开启；请联系管理员配置后重试。",
  "agent-detection-analyzer-unavailable":
    "服务端事实分析器未就绪，暂时无法开启智能体检测；请联系管理员配置后重试。",
};

function fieldError(message: string | undefined): React.JSX.Element | null {
  if (!message) return null;
  return (
    <Typography.Text type="danger" role="alert" style={{ display: "block", fontSize: 12 }}>
      {message}
    </Typography.Text>
  );
}

export function AuditCreatePage(): React.JSX.Element {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const { modal } = AntApp.useApp();
  const [phase, setPhase] = useState<WizardPhase>("editing");
  const [submitError, setSubmitError] = useState<string>("");
  const {
    handleSubmit,
    setValue,
    watch,
    getValues,
    formState: { errors },
  } = useForm<AuditDraft>({
    defaultValues: loadDraft(),
    resolver: auditResolver(),
  });

  const draft = watch();
  const githubScan = draft.mode === "repository" && draft.sourceMode === "github";

  // A 态：草稿随每次变化写回模块缓存，路由往返不丢。
  useEffect(() => {
    const subscription = watch((values) => saveDraft(values as AuditDraft));
    return () => subscription.unsubscribe();
  }, [watch]);

  const capabilities = useQuery({
    queryKey: ["repository-scan-capabilities"],
    queryFn: () =>
      api.get<ScanCapabilitiesPayload>("/api/repository-scans/capabilities"),
  });
  const githubEnabled = capabilities.data?.scan_sources?.github;
  const githubGated = githubEnabled === false;

  const cxxCaps = capabilities.data?.cxx_agent;
  const gate = useMemo(
    () => agentDetectionGate(cxxCaps, draft.agentDetection),
    [cxxCaps, draft.agentDetection],
  );

  // capabilities 就绪后初始化尚未选择的开关；已落为 true/false 的选择不被覆盖（§4.2）。
  useEffect(() => {
    if (gate.ready && cxxCaps && draft.agentDetection === null) {
      setValue("agentDetection", cxxCaps.mode !== "off");
    }
  }, [gate.ready, cxxCaps, draft.agentDetection, setValue]);

  /** 仓库提交的暂停原因：capabilities 未就绪（含 pending）/ 旧服务端 /
   * 默认开启但配置不完整。未就绪期间不得提交——否则会绕过策略检查与
   * 调用确认（审计问题 2）。 */
  const repositoryBlockReason:
    | ""
    | "loading"
    | "load-failed"
    | "stale-server"
    | "config-incomplete" =
    draft.mode !== "repository"
      ? ""
      : capabilities.isError
        ? "load-failed"
        : capabilities.isPending
          ? "loading"
          : capabilities.isSuccess && !gate.ready
            ? "stale-server"
            : gate.defaultOnBlocked
              ? "config-incomplete"
              : "";
  const repositoryBlocked = repositoryBlockReason !== "";
  const agentSwitchChecked = gate.lockedOn || (draft.agentDetection ?? false);
  const agentSwitchDisabled =
    !gate.ready || gate.lockedOn || (!agentSwitchChecked && !gate.canEnable);

  // 提交路径读的最新门禁快照（#262 评审 P2）：modal.confirm 的 onOk 捕获
  // 的是打开弹窗那次渲染的闭包，弹窗停留期间 capabilities 可能被回焦
  // 重取或服务端切换——校验和载荷都必须取当前值，不能用旧闭包。
  const gateRef = useRef({ blocked: repositoryBlocked, ready: gate.ready, effective: gate.effective });
  gateRef.current = { blocked: repositoryBlocked, ready: gate.ready, effective: gate.effective };

  // 能力加载后门禁：GitHub 关闭时回退本地导入（与 legacy 语义一致）。
  useEffect(() => {
    if (githubGated && draft.sourceMode === "github") {
      setValue("sourceMode", "local");
    }
  }, [githubGated, draft.sourceMode, setValue]);

  const createAudit = useMutation({
    mutationFn: async (values: AuditDraft) => {
      // 载荷用有效策略值（最新快照）：required/锁定开启时即使草稿残留
      // false 也必须提交 true，否则后端会一直 400（审计问题 3）。
      const { path, body } = buildSubmitPayload(values, gateRef.current.effective);
      return api.post<ScanCreatedResponse>(path, body);
    },
    onSuccess: (created) => {
      clearDraft();
      navigate(`/tasks/${encodeURIComponent(created.task_id)}`);
    },
    onError: (error) => {
      const code = error instanceof ApiError ? error.code : "";
      if (code !== "" && code in AGENT_DETECTION_ERROR_LABELS) {
        setSubmitError(AGENT_DETECTION_ERROR_LABELS[code]);
        // 具名 400 说明服务端配置与缓存的能力快照不一致：刷新后再放开提交。
        void queryClient.invalidateQueries({
          queryKey: ["repository-scan-capabilities"],
        });
      } else {
        setSubmitError(
          error instanceof ApiError || error instanceof Error
            ? error.message
            : "请求失败",
        );
      }
      setPhase("editing");
    },
  });

  const goToReview = handleSubmit(() => {
    setSubmitError("");
    setPhase("review");
  });

  const doSubmit = (): void => {
    // 最终防线（读 ref 最新值）：弹窗打开期间能力变化（回焦重取、服务端
    // 切换）后，旧弹窗的"确认开启并提交"不得发出请求（#262 评审 P2）。
    // PR / Diff 提交不受智能体检测门禁影响。
    if (draft.mode === "repository" && (gateRef.current.blocked || !gateRef.current.ready)) {
      setSubmitError(
        "智能体检测配置已变化，本次提交已拦下；请确认状态后重试，或改用 PR / Diff 审查。",
      );
      setPhase("editing");
      return;
    }
    setSubmitError("");
    setPhase("submitting");
    createAudit.mutate(getValues());
  };

  /** 有效开关为开启时，提交前必须确认模型调用（含管理员默认开启，§4.2）。
   * 发送前再守卫一次 capabilities 状态：向导停留期间的任何未就绪态都
   * 直接拦下，不发出请求（审计问题 2 的纵深防御）。 */
  const startAudit = (): void => {
    if (draft.mode === "repository" && (repositoryBlocked || !gate.ready)) {
      setSubmitError(
        "智能体检测配置未就绪，仓库扫描暂不可提交；请稍后重试或改用 PR / Diff 审查。",
      );
      setPhase("editing");
      return;
    }
    if (draft.mode !== "repository" || !gate.effective) {
      doSubmit();
      return;
    }
    modal.confirm({
      title: "确认启用智能体检测？",
      content:
        `开启后，配置的模型会接收本次仓库的代码上下文，并可能产生模型调用费用` +
        `（最多 ${gate.maxAgentCalls} 次模型调用）。实际调用次数以服务端执行为准。`,
      okText: "确认开启并提交",
      cancelText: "取消",
      onOk: () => {
        doSubmit();
      },
    });
  };

  const target = (() => {
    try {
      return normalizeRepositoryTarget(draft.repository);
    } catch {
      return "未确认";
    }
  })();

  const targetLabel = draft.mode === "diff"
    ? "仓库名称或 GitHub 链接"
    : draft.sourceMode === "github"
      ? "GitHub 仓库链接或 owner/project"
      : "GitHub 仓库链接或仓库键";

  const targetHint = draft.mode === "diff"
    ? "只检查粘贴的新增代码，不读取或执行完整仓库。"
    : draft.sourceMode === "github"
      ? "服务端会在后台解析 ref 并钉死快照，浏览器不发起 GitHub 请求。"
      : "系统不会自动下载任意仓库；链接会转换为 repositories 目录下的安全相对路径。";

  const stepIndex = phase === "editing" ? 0 : phase === "review" ? 1 : 2;

  const agentDetectionHint = (() => {
    if (repositoryBlockReason === "load-failed")
      return "无法读取服务端智能体检测配置；请重试或联系管理员。";
    if (repositoryBlockReason === "loading")
      return "正在读取服务端智能体检测配置，请稍候…";
    if (repositoryBlockReason === "stale-server")
      return "服务端版本较旧，暂不支持按任务开启智能体检测；请更新服务端后再使用。";
    if (repositoryBlockReason === "config-incomplete")
      return "管理员默认开启了智能体检测，但服务端模型或事实分析器未配置；请联系管理员修复后再提交。";
    if (gate.lockedOn) return "服务端策略要求开启智能体检测，本次任务无法关闭。";
    if (gate.effective) return "本次任务将运行 C++ 智能体检测链；提交前会确认模型调用。";
    if (!gate.canEnable) return "服务端模型或事实分析器未配置，暂不能开启智能体检测。";
    return "开启后由智能体链对 C++ 代码做假设、实验与证明复核（费用在提交前确认）。";
  })();

  return (
    <div style={{ padding: 24, maxWidth: 860 }}>
      <Typography.Title level={3}>发起安全审计</Typography.Title>
      <Steps current={stepIndex} items={STEP_ITEMS} style={{ margin: "16px 0 24px" }} />

      {phase === "editing" && (
        <form onSubmit={goToReview} noValidate>
          {submitError !== "" && (
            <Alert
              type="error"
              showIcon
              closable
              message="审计任务创建失败"
              description={submitError}
              style={{ marginBottom: 16 }}
            />
          )}
          <Space direction="vertical" size="middle" style={{ width: "100%" }}>
            <div>
              <Typography.Text strong>审计方式</Typography.Text>
              <Radio.Group
                value={draft.mode}
                onChange={(event) => setValue("mode", event.target.value)}
                style={{ marginLeft: 16 }}
              >
                <Radio.Button value="repository">完整仓库审计</Radio.Button>
                <Radio.Button value="diff">PR / Diff 审查</Radio.Button>
              </Radio.Group>
            </div>

            {draft.mode === "repository" && (
              <div>
                <Typography.Text strong>仓库来源</Typography.Text>
                <Radio.Group
                  value={draft.sourceMode}
                  onChange={(event) => setValue("sourceMode", event.target.value)}
                  style={{ marginLeft: 16 }}
                >
                  <Radio value="local">本地导入</Radio>
                  <Radio value="github" disabled={githubGated}>
                    GitHub 仓库
                  </Radio>
                </Radio.Group>
                {githubGated && (
                  <Alert
                    type="info"
                    showIcon
                    message="GitHub 来源未启用，请联系管理员在服务端开启后再使用。"
                    style={{ marginTop: 8 }}
                  />
                )}
              </div>
            )}

            <div>
              <label htmlFor="audit-target">仓库目标</label>
              <Input
                id="audit-target"
                placeholder={
                  draft.mode === "diff"
                    ? "仓库名称或 GitHub 链接"
                    : "https://github.com/owner/project 或 owner/project"
                }
                autoComplete="off"
                value={draft.repository}
                onChange={(event) => setValue("repository", event.target.value)}
              />
              {fieldError(errors.repository?.message)}
              <Typography.Text type="secondary" style={{ fontSize: 12 }}>
                {targetLabel}：{targetHint}
              </Typography.Text>
            </div>

            {githubScan && (
              <div>
                <label htmlFor="audit-github-ref">
                  ref（可选：分支 / 标签 / 完整 40/64 位 commit SHA）
                </label>
                <Input
                  id="audit-github-ref"
                  placeholder="分支 / 标签 / 完整 40/64 位 commit SHA"
                  autoComplete="off"
                  value={draft.githubRef}
                  onChange={(event) => setValue("githubRef", event.target.value)}
                />
                {fieldError(errors.githubRef?.message)}
                {isMovingRef(draft.githubRef) && (
                  <Alert
                    type="warning"
                    showIcon
                    message="分支/标签会在扫描时被钉死为具体提交（pinned to a specific commit at scan time）。"
                    style={{ marginTop: 8 }}
                  />
                )}
              </div>
            )}

            {draft.mode === "diff" && (
              <>
                <div>
                  <label htmlFor="audit-diff">PR / Diff 内容（Unified Diff）</label>
                  <Input.TextArea
                    id="audit-diff"
                    rows={10}
                    placeholder="粘贴包含 @@ 区块和新增行（+）的 Unified Diff"
                    value={draft.diff}
                    onChange={(event) => setValue("diff", event.target.value)}
                  />
                  {fieldError(errors.diff?.message)}
                </div>
                <div style={{ maxWidth: 240 }}>
                  <label htmlFor="audit-pr-number">PR 编号（可选）</label>
                  <Input
                    id="audit-pr-number"
                    placeholder="例如 42"
                    inputMode="numeric"
                    value={draft.pullRequest}
                    onChange={(event) => setValue("pullRequest", event.target.value)}
                  />
                  {fieldError(errors.pullRequest?.message)}
                </div>
              </>
            )}

            {draft.mode === "repository" && (
              <div>
                <Space align="center" size="middle">
                  <Typography.Text strong>智能体检测</Typography.Text>
                  <Switch
                    aria-label="智能体检测"
                    checked={agentSwitchChecked}
                    disabled={agentSwitchDisabled}
                    onChange={(checked) => setValue("agentDetection", checked)}
                  />
                  {repositoryBlockReason === "load-failed" && (
                    <Button size="small" onClick={() => void capabilities.refetch()}>
                      重试
                    </Button>
                  )}
                </Space>
                <Typography.Text
                  type="secondary"
                  style={{ display: "block", fontSize: 12, marginTop: 4 }}
                >
                  {agentDetectionHint}
                </Typography.Text>
              </div>
            )}

            <div>
              <Button
                type="primary"
                htmlType="submit"
                disabled={
                  repositoryBlocked && repositoryBlockReason !== "loading"
                }
              >
                下一步：确认范围
              </Button>
              {repositoryBlocked && repositoryBlockReason !== "loading" && (
                <Typography.Text
                  type="secondary"
                  style={{ display: "block", fontSize: 12, marginTop: 4 }}
                >
                  {repositoryBlockReason === "load-failed"
                    ? "智能体检测配置读取失败，仓库扫描暂不可提交（PR / Diff 审查不受影响）。"
                    : agentDetectionHint}
                </Typography.Text>
              )}
            </div>
          </Space>
        </form>
      )}

      {phase === "review" && (
        <Space direction="vertical" size="middle" style={{ width: "100%" }}>
          {githubScan && isMovingRef(draft.githubRef) && (
            <Alert
              type="warning"
              showIcon
              message={`ref “${draft.githubRef.trim()}” 是移动引用，扫描时会被钉死为具体提交。`}
            />
          )}
          {repositoryBlocked && (
            <Alert
              type="warning"
              showIcon
              message="仓库扫描暂不可提交"
              description={agentDetectionHint}
            />
          )}
          <Descriptions bordered column={1} size="small">
            <Descriptions.Item label="审计方式">
              {draft.mode === "repository" ? "完整仓库审计" : "PR / Diff 审查"}
              {draft.mode === "repository"
                ? draft.sourceMode === "github" ? "（GitHub 来源）" : "（本地导入）"
                : ""}
            </Descriptions.Item>
            <Descriptions.Item label="目标仓库">
              {target}
              {githubScan && draft.githubRef.trim() !== "" ? ` @ ${draft.githubRef.trim()}` : ""}
            </Descriptions.Item>
            {draft.mode === "repository" && (
              <Descriptions.Item label="智能体检测">
                {gate.effective ? "开启" : "关闭"}
                {gate.lockedOn ? "（服务端策略要求开启，无法关闭）" : ""}
                {gate.effective && !gate.lockedOn
                  ? `（提交前将确认模型调用，最多 ${gate.maxAgentCalls} 次）`
                  : ""}
              </Descriptions.Item>
            )}
            <Descriptions.Item label="分析范围">
              {draft.mode === "repository"
                ? draft.sourceMode === "github"
                  ? "服务端解析 ref 并物化固定 commit 快照后离线扫描；不执行目标代码"
                  : "AST + 跨文件数据流 + 可用 SAST；不执行目标代码"
                : "只审查粘贴的新增代码，不读取或执行完整仓库"}
            </Descriptions.Item>
            <Descriptions.Item label="数据处理">
              {githubScan
                ? "服务端从 github.com 下载固定快照；浏览器不发起 GitHub 请求"
                : "只处理你有权审查的本机代码或 Diff"}
            </Descriptions.Item>
          </Descriptions>
          <Space>
            <Button onClick={() => setPhase("editing")}>返回修改</Button>
            <Button type="primary" onClick={startAudit} disabled={repositoryBlocked}>
              开始安全审计
            </Button>
          </Space>
        </Space>
      )}

      {phase === "submitting" && (
        <Result
          status="info"
          title="正在创建审计任务"
          subTitle="已收到提交，等待服务端受理（202）后会自动跳转任务详情。"
        />
      )}
    </div>
  );
}
