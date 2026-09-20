#!/usr/bin/env python3
"""Runtime Attestation 抽取脚本（D.0.2.1 修正版，入库包成员）。

用法：
  python runtime_attestation_extract.py --session-id <sess_id> \
      [--agent-id probe-flash=agent_xxx --agent-id probe-tl-low=agent_yyy ...]

D.0.2.1 要求：
- 必须显式 --session-id；禁止从近若干小时任意主回合猜测会话参照；
- 三个探针 Agent ID 必须位于 --session-id 对应的 agents 目录
  （~/.zcode/cli/agents/<session-id>/<agent-id>/），并读取 metadata.json
  核对探针 profile（path/description/name 含探针名，不区分大小写）；
- 主会话 requested model 必须等于 response modelId（逐条 main_turn 检查）；
- 检查该会话**全部** main_turn；存在不同运行配置时判 AMBIGUOUS；
- 子智能体只与已通过 SESSION-RUNTIME-VERIFIED 的会话参照比较；
- 比较四要素：request model、response modelId、output_config、thinking。

退出码：0=全部 CHILD-INHERITANCE-VERIFIED；1=存在 TELEMETRY-MISSING；
2=存在 ROUTING-MISMATCH（含主会话 requested≠response）；3=两者兼有；
4=AMBIGUOUS（会话 main_turn 运行配置不一致，或同 Agent ID 多 rollout 候选）；
5=INCOMPLETE-FIELDS（记录缺关键字段）；6=BINDING/USAGE 错误（session-id 缺失、
会话 rollout 不存在或无 main_turn、Agent ID 不在该会话 agents 目录、
metadata.json 缺失或探针 profile 不匹配）。"""

import argparse
import glob
import hashlib
import json
import os
import sys

ROLL = os.path.expanduser(r"~/.zcode/cli/rollout")
AGENTS = os.path.expanduser(r"~/.zcode/cli/agents")
DEFAULT_AGENT_IDS = {
    "probe-flash": "agent_89d9159b-b181-4f24-a936-0b7a108954ca",
    "probe-tl-low": "agent_cf8a1502-c46f-421e-98e8-3065343ec475",
    "probe-tl-max": "agent_f5f0baca-4e75-44e7-8d1c-e74c64778978",
}
EXIT_OK, EXIT_MISSING, EXIT_MISMATCH, EXIT_BOTH, EXIT_AMBIGUOUS, EXIT_INCOMPLETE, EXIT_BINDING = range(7)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def iter_model_io(path):
    with open(path, encoding="utf-8", errors="replace") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except Exception:
                continue
            if rec.get("type") == "model_io":
                yield rec


def normalize_session(session_id):
    return session_id[5:] if session_id.startswith("sess_") else session_id


def session_reference(session_id):
    """检查该会话**全部** main_turn：requested==response 逐条成立、运行配置完全一致。

    返回 (ref, err)：ref 通过 = SESSION-RUNTIME-VERIFIED 参照。
    err 分类：BINDING（无文件/无 main_turn/字段不全）、MISMATCH（requested≠response）、
    AMBIGUOUS（不同运行配置）。"""
    uuid = normalize_session(session_id)
    path = os.path.join(ROLL, f"model-io-sess_{uuid}.jsonl")
    if not os.path.isfile(path):
        return None, ("BINDING", f"会话 rollout 不存在：{os.path.basename(path)}")
    configs, mismatch, incomplete = set(), False, False
    for rec in iter_model_io(path):
        if rec.get("querySource") != "main_turn":
            continue
        body = rec.get("request", {}).get("body", {})
        resp = rec.get("response", {})
        req_model, resp_model = body.get("model"), resp.get("modelId")
        oc, th = body.get("output_config"), body.get("thinking")
        if None in (req_model, resp_model, oc, th):
            incomplete = True
            continue
        if req_model != resp_model:
            mismatch = True
            continue
        configs.add((req_model, json.dumps(oc, sort_keys=True), json.dumps(th, sort_keys=True)))
    if incomplete:
        return None, ("BINDING", "会话存在字段不全的 main_turn 记录")
    if mismatch:
        return None, ("MISMATCH", "会话 main_turn 存在 requested ≠ response modelId")
    if not configs:
        return None, ("BINDING", "会话 rollout 无 main_turn 记录")
    if len(configs) > 1:
        return None, ("AMBIGUOUS", f"会话 main_turn 存在 {len(configs)} 种不同运行配置")
    model, oc, th = sorted(configs)[0]
    return dict(model=model, output_config=json.loads(oc), thinking=json.loads(th),
                status="SESSION-RUNTIME-VERIFIED"), None


def validate_binding(session_id, probe, agent_id):
    """Agent ID 必须位于该会话 agents 目录，且 metadata.json 探针 profile 匹配。"""
    d = os.path.join(AGENTS, session_id, agent_id)
    if not (agent_id.startswith("agent_") and len(agent_id) > 10):
        return f"Agent ID 格式错误：{agent_id}"
    if not os.path.isdir(d):
        return f"Agent 目录不在会话 {session_id} 下：{agent_id}"
    meta_path = os.path.join(d, "metadata.json")
    if not os.path.isfile(meta_path):
        return f"metadata.json 缺失：{agent_id}"
    try:
        meta = json.load(open(meta_path, encoding="utf-8"))
    except Exception as e:
        return f"metadata.json 解析失败：{agent_id}（{e}）"
    prof = meta.get("profileSnapshot", {}) or {}
    hay = " ".join(str(prof.get(k, "")) for k in ("name", "description", "path")).lower()
    if probe.lower() not in hay:
        return f"探针 profile 不匹配：{agent_id} 的 metadata 未含 {probe}"
    return None


def check_agent(probe, agent_id, ref):
    """返回 (状态, 是否缺失, 是否不匹配, 是否字段不全, 明细)。前置：ref 已 VERIFIED。"""
    candidates = glob.glob(os.path.join(ROLL, f"model-io-sess_subagent_{agent_id}.jsonl"))
    if len(candidates) > 1:
        return "AMBIGUOUS", False, False, False, {"candidates": candidates}
    if not candidates:
        return "TELEMETRY-MISSING", True, False, False, {"rollout": None,
                "note": "无 rollout（未生成或已轮转）；仅可与 VERIFIED 会话参照比较的结论不存在"}
    path = candidates[0]
    records = list(iter_model_io(path))
    if not records:
        return "TELEMETRY-MISSING", True, False, False, {"rollout": path, "note": "文件存在但无 model_io 记录"}
    detail = {"rollout": path, "rollout_sha256": sha256(path), "calls": []}
    incomplete = mismatch = False
    for rec in records:
        body = rec.get("request", {}).get("body", {})
        resp = rec.get("response", {})
        row = dict(requestId=rec.get("requestId"), startedAt=rec.get("startedAt"),
                   req_model=body.get("model"), resp_modelId=resp.get("modelId"),
                   output_config=body.get("output_config"), thinking=body.get("thinking"))
        detail["calls"].append(row)
        if any(row[k] is None for k in ("req_model", "resp_modelId", "output_config", "thinking")):
            incomplete = True
            continue
        if row["req_model"] != row["resp_modelId"] or row["req_model"] != ref["model"] \
                or row["output_config"] != ref["output_config"] or row["thinking"] != ref["thinking"]:
            mismatch = True
    if incomplete:
        return "INCOMPLETE-FIELDS", False, False, True, detail
    if mismatch:
        return "ROUTING-MISMATCH", False, True, False, detail
    return "CHILD-INHERITANCE-VERIFIED", False, False, False, detail


def main():
    ap = argparse.ArgumentParser(description="D.0.2.1 Runtime Attestation 抽取（显式会话与 Agent 绑定）")
    ap.add_argument("--session-id", required=True, help="探针所在会话 ID（sess_...）")
    ap.add_argument("--agent-id", action="append", default=[],
                    metavar="PROBE=AGENT_ID", help="覆盖默认探针 Agent 绑定，可多次")
    args = ap.parse_args()

    bindings = dict(DEFAULT_AGENT_IDS)
    for spec in args.agent_id:
        if "=" not in spec:
            print(f"BINDING-ERROR：--agent-id 需为 PROBE=AGENT_ID 形式，收到 {spec!r}")
            sys.exit(EXIT_BINDING)
        name, aid = spec.split("=", 1)
        bindings[name.strip()] = aid.strip()

    ref, err = session_reference(args.session_id)
    if ref is None:
        kind, msg = err
        print(f"{'BINDING-ERROR' if kind == 'BINDING' else kind}（会话参照未通过，子代理不进行比较）：{msg}")
        sys.exit({"BINDING": EXIT_BINDING, "MISMATCH": EXIT_MISMATCH, "AMBIGUOUS": EXIT_AMBIGUOUS}[kind])
    print(f"会话参照：{ref['status']}（全部 main_turn 一致且 requested==response）→ {json.dumps({k: ref[k] for k in ('model', 'output_config', 'thinking')}, ensure_ascii=False)}")

    missing = mismatch = incomplete = ambiguous = False
    for probe in ("probe-flash", "probe-tl-low", "probe-tl-max"):
        berr = validate_binding(args.session_id, probe, bindings[probe])
        if berr:
            print(f"\n== {probe}（{bindings[probe]}）==\n  BINDING-ERROR：{berr}")
            sys.exit(EXIT_BINDING)
        status, m, x, inc, detail = check_agent(probe, bindings[probe], ref)
        missing |= m
        mismatch |= x
        incomplete |= inc
        ambiguous |= (status == "AMBIGUOUS")
        print(f"\n== {probe}（{bindings[probe]}，agents 目录与 metadata profile 已核验）==\n  状态：{status}")
        print("  " + json.dumps(detail, ensure_ascii=False, default=str)[:800])

    if ambiguous:
        sys.exit(EXIT_AMBIGUOUS)
    if incomplete:
        sys.exit(EXIT_INCOMPLETE)
    if missing and mismatch:
        sys.exit(EXIT_BOTH)
    if mismatch:
        sys.exit(EXIT_MISMATCH)
    if missing:
        sys.exit(EXIT_MISSING)
    print("\n三个探针均 CHILD-INHERITANCE-VERIFIED。")
    sys.exit(EXIT_OK)


if __name__ == "__main__":
    main()
