import type { CxxInvestigationSummary } from "@/shared/api/types";

const STOP_LABELS: Record<string, string> = {
  final: "本轮调查结束",
  "budget-exhausted": "预算耗尽，调查证据待补充",
  "steps-exhausted": "达到动作上限，调查证据待补充",
  cancelled: "已取消",
  "protocol-error": "模型回复未通过校验",
  error: "调查中断",
  incomplete: "调查尚未完成",
};

export function CxxInvestigationTimeline({ investigation }: {
  investigation?: CxxInvestigationSummary;
}): React.JSX.Element | null {
  if (!investigation) return null;
  return (
    <section aria-label="自主调查轨迹">
      <p>
        {STOP_LABELS[investigation.stop_reason ?? ""] ?? investigation.stop_reason}
        {` · ${investigation.action_count ?? investigation.actions?.length ?? 0} 次动作`}
        {` · ${investigation.child_count ?? investigation.children?.length ?? 0} 个子任务`}
      </p>
      {(investigation.actions?.length ?? 0) > 0 ? (
        <ol>
          {investigation.actions?.map((action, index) => (
            <li key={index}>
              <code>{action.tool}</code>{" "}<span>{action.purpose}</span>
              {action.ok === false ? "（执行失败）" : ""}
            </li>
          ))}
        </ol>
      ) : null}
      {investigation.children?.map((child, index) => (
        <details key={index}>
          <summary>{child.role}</summary>
          <p>{child.question}</p>
          <p>{STOP_LABELS[child.stop_reason ?? ""] ?? child.stop_reason}</p>
        </details>
      ))}
      {investigation.detail_omissions?.length ? (
        <p>调查详情因报告字节预算省略，已保留动作和子任务计数。</p>
      ) : null}
    </section>
  );
}
