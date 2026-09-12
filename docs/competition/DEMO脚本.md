# LIMA 智能体漏洞挖掘平台 · DEMO 演示脚本

评委演示分镜脚本。全部命令在仓库根目录（Git Bash）逐字可运行且已实测；
"预期输出"摘自 2026-09-11 实跑记录（HEAD `99a0697`）。除场景 5 外零依赖
（不需要 Docker 与 LLM Provider）。总时长建议 7–9 分钟。

## 场景 1：零依赖全量演示（约 2 分钟）

**目标**：不配 Docker、不配模型，一条命令跑完 6 组配对案例 × 2 版本，
比赛指标映射全绿。

```bash
./.venv/Scripts/python scripts/run_platform_evaluation.py --fake-llm \
  --output output/platform-evaluation.json

./.venv/Scripts/python -c "
import json
r = json.load(open('output/platform-evaluation.json', encoding='utf-8'))
for k in ('detection_rate','false_positive_rate','non_security_filter_rate','experiment_convergence','poc_stability','paired_detection'):
    print(f\"{k}: {r[k]['rate']}\")
for c in r['cases']:
    v = c['revisions']['vulnerable']
    print(c['case_id'], c['kind'], 'vuln_state=' + v['observed_final_state'], 'findings=' + str(v['finding_count']), 'hit_round=' + str(v['first_hit_round']))
"
```

**预期输出**（实测，进程墙钟约 0.3–0.4 秒）：

```text
detection_rate: 1.0
false_positive_rate: 0.0
non_security_filter_rate: 1.0
experiment_convergence: 1.0
poc_stability: 1.0
paired_detection: 1.0
uaf-direct direct vuln_state=runtime-confirmed findings=1 hit_round=1
null-deref-direct direct vuln_state=runtime-confirmed findings=1 hit_round=1
overflow-direct direct vuln_state=runtime-confirmed findings=1 hit_round=1
rebind-revisable revisable vuln_state=runtime-confirmed findings=1 hit_round=2
clean-function clean vuln_state=abstain findings=0 hit_round=None
non-security-filter clean vuln_state=abstain findings=0 hit_round=None
```

**讲解**：指标与赛题评分项映射（检测率/误报率=准确性与完整性；非安全
过滤=赛题备注 3；实验收敛=假设-实验-修正闭环；PoC 稳定性=同 PoC 重复
3 次全触发）；评测无标签——管线输入只有 fixture 工作区、事实 wire 与
分诊线索，标签只在评测侧。

## 场景 2：单案例深挖——uaf-direct 的 PoC 与实验记录（约 2 分钟）

**目标**：PoC 是智能体写出的代码，ASan 观察是结构化实验记录，不是规则
命中文本。

```bash
# 被测源码（平台案例 fixture，真实内容）：第 11 行释放后读
cat tests/fixtures/platform_cases/uaf-direct/vulnerable/src/buffer.cpp

# 平台裁决与实验台账
./.venv/Scripts/python scripts/run_platform_evaluation.py --fake-llm \
  --case-id uaf-direct --output output/platform-eval-uaf-direct.json
./.venv/Scripts/python -c "
import json
r = json.load(open('output/platform-eval-uaf-direct.json', encoding='utf-8'))
t = r['records'][0]['targets'][0]
print('state:', t['state'], '| cwe:', t['cwe'], '| line:', t['line'])
print('experiment_log:', t['experiment_log'])
print('poc_stability:', r['records'][0]['poc_stability'])
print('driver_sha256:', t['driver_sha256'])
"
```

**预期输出**（实测）：

```text
state: runtime-confirmed | cwe: CWE-416 | line: 11
experiment_log: [{'round': 1, 'stage': 'run', 'hit': True, 'error_type': 'heap-use-after-free'}]
poc_stability: {'runs': 3, 'hits': 3, 'stable': True}
driver_sha256: 568066e828af9e32b3ffbe9ba5da78bae29e0fc53b39e03c55937aa9e0dfee47
```

**讲解**：智能体产出的 PoC 驱动形如 `int main() { return packet_size(); }`；
`runtime-confirmed` 只能来自沙箱内已执行且命中同一身份的 ASan 实验，驱动
按内容哈希 stage、绑定快照，同 PoC 重复 3 次全触发。**诚实标注**：本场景
工作台是按驱动内容哈希判定的脚本化替身；经 `/v1/repro` 的真实容器 ASan
对平台链的贯通未验证。

## 场景 3：实验闭环——rebind-revisable 两轮修正（约 1.5 分钟）

**目标**：首轮实验不命中 → Critic 引导修正 → 第二轮命中的闭环真实存在。

```bash
./.venv/Scripts/python scripts/run_platform_evaluation.py --fake-llm \
  --case-id rebind-revisable --output output/platform-eval-rebind.json
./.venv/Scripts/python -c "
import json
r = json.load(open('output/platform-eval-rebind.json', encoding='utf-8'))
for e in r['records'][0]['targets'][0]['experiment_log']:
    print('round', e['round'], '| stage', e['stage'], '| hit', e['hit'], '|', e['error_type'])
print('experiment_convergence:', r['experiment_convergence']['rate'])
"
```

**预期输出**（实测）：

```text
round 1 | stage run | hit False |
round 2 | stage run | hit True | heap-use-after-free
experiment_convergence: 1.0
```

**讲解**：vulnerable 版一条路径把释放指针重绑到新对象、另一条路径读旧
对象；首轮驱动刻意走安全重绑路径（干净运行），Critic 判
`revise-experiment` 并给出修正驱动，第二轮命中第 18 行释放后读；台账两轮
留痕，收敛预算 ≤2 轮。

## 场景 4：误报纪律——零 Finding 两条防线（约 1.5 分钟）

**目标**：实验证据否决假设；非内存安全类被封闭 CWE 词表拒绝。

```bash
./.venv/Scripts/python -c "
import json
r = json.load(open('output/platform-evaluation.json', encoding='utf-8'))
for c in r['cases']:
    if c['case_id'] in ('clean-function', 'non-security-filter'):
        for rev, item in c['revisions'].items():
            print(c['case_id'], rev, 'state=' + item['observed_final_state'], 'findings=' + str(item['finding_count']))
print('false_positive_rate:', r['false_positive_rate']['rate'])
print('non_security_filter_rate:', r['non_security_filter_rate']['rate'])
"
```

**预期输出**（实测）：

```text
clean-function vulnerable state=abstain findings=0
clean-function fixed state=abstain findings=0
non-security-filter vulnerable state=abstain findings=0
non-security-filter fixed state=abstain findings=0
false_positive_rate: 0.0
non_security_filter_rate: 1.0
```

**讲解**：clean-function 里模式种子命中了 null-check 形状、Specialist 也提
了假设，但实验干净运行、Critic 否决——abstain、审计留痕、零 Finding。
non-security-filter（赛题备注 3）里 Specialist 提出内存包封闭词表外的
CWE-703，假设合同拒收回复（一次修复机会后审计弃权），任何版本都不可能
产出 Finding。

## 场景 5（可选）：真实模型模式（约 2 分钟，需 Provider）

```bash
export LIMA_LLM_PROVIDER=deepseek
export LIMA_DEEPSEEK_API_KEY=<密钥>
export LIMA_LLM_MODEL=<模型名>
./.venv/Scripts/python scripts/run_platform_evaluation.py \
  --output output/platform-evaluation-real.json
```

**要点**：报告 `identity.llm_transport = "provider"`、模型名入身份清单，
指标结构与 Fake 模式一致；无凭证时脚本在管线开工前以
`provider-not-configured` 拒绝（已实测），绝不空跑。**口播红线**：平台链
真实模型端到端与真实容器 ASan 贯通**尚未运行，未验证**；可引用的真实
模型历史数据是 UAF v2 冻结评测链一次 7 对全对运行（28.32 秒，见
`性能数据.md` §3），与平台配对基准不是同一评测器，不得混同宣称。

## DEMO 注意事项

1. **录屏前预热**：如演示容器场景，提前 `docker compose build`，首次构建不进镜头。
2. **Fake 与真实模式必须标注**：场景 1–4 角标注明"Scripted LLM + scripted workbench（离线演示）"；真实模型/真实 ASan 画面单独标注，互不冒充。
3. **`--output` 必带**；`null` 指标 = 分母为零而非满分，出现时读 `diagnostics` 字段。
4. **路径**：示例统一用 `output/`（脚本自动建目录）；Windows Git Bash 下不要把 `/tmp` 传给 Windows Python（路径解释不一致）。
5. **PoC 稳定性口径**：脚本化工作台下按构造稳定，只在真实工作台运行中携带信息量——按评测报告 `validity_boundaries` 措辞如实说明。
