import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { useForm } from "react-hook-form";
import { useMutation, useQuery } from "@tanstack/react-query";
import {
  Alert,
  Button,
  Descriptions,
  Input,
  Radio,
  Result,
  Space,
  Steps,
  Typography,
} from "antd";
import { api, ApiError } from "@/shared/api/client";
import {
  type AuditDraft,
  type ScanCapabilitiesPayload,
  type ScanCreatedResponse,
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
 */

type WizardPhase = "editing" | "review" | "submitting";

const STEP_ITEMS = [
  { title: "选择目标" },
  { title: "确认范围" },
  { title: "提交任务" },
];

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

  // 能力加载后门禁：GitHub 关闭时回退本地导入（与 legacy 语义一致）。
  useEffect(() => {
    if (githubGated && draft.sourceMode === "github") {
      setValue("sourceMode", "local");
    }
  }, [githubGated, draft.sourceMode, setValue]);

  const createAudit = useMutation({
    mutationFn: async (values: AuditDraft) => {
      const { path, body } = buildSubmitPayload(values);
      return api.post<ScanCreatedResponse>(path, body);
    },
    onSuccess: (created) => {
      clearDraft();
      navigate(`/tasks/${encodeURIComponent(created.task_id)}`);
    },
    onError: (error) => {
      setSubmitError(
        error instanceof ApiError || error instanceof Error
          ? error.message
          : "请求失败",
      );
      setPhase("editing");
    },
  });

  const goToReview = handleSubmit(() => {
    setSubmitError("");
    setPhase("review");
  });

  const startAudit = (): void => {
    setSubmitError("");
    setPhase("submitting");
    createAudit.mutate(getValues());
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

            <div>
              <Button type="primary" htmlType="submit">
                下一步：确认范围
              </Button>
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
            <Button type="primary" onClick={startAudit}>
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
