# LIMA PR3-d Real-Run Approval — 2026-09-28 (Limited, One-Time)

## 1. Document Header

- Doc id: LIMA-PR3D-REAL-RUN-APPROVAL-2026-09-28
- Version: 1.0
- Date: 2026-09-28
- Status: APPROVED-LIMITED-ONE-TIME
- Author: Packet & Verification Agent (IP-0034, C1) — transcribing the Maintainer
  authorization of 2026-09-28 (Source Issue #232, parent #57); every numeric cell
  in this document is a verbatim transcription from (a) the Maintainer
  authorization of 2026-09-28 (five rulings, preserved verbatim in
  `.pv_tmp/INTENT_RECORD_IP-0034_2026-09-28.md` section 2), (b) the provider
  pricing page read on 2026-09-28 (Intent Record fact F7), (c) the platform
  measurements of 2026-09-27 recorded in the predecessor artifact
  `LIMA_PR3d_Real_Run_Approval_2026-09-27.md` (same physical host; the seven
  measured fields are transcribed per CA-IP-0034-v1.0 R8), or (d) the exact
  repository baseline recorded in CA-IP-0034-v1.0. No cell is estimated, rounded
  without an explicit note, or invented.
- Consumed by: `benchmarks/v4/baseline/real_run.py` (IP-0034 Implementation
  deliverable) as the sole authorization source; the entry module additionally
  cross-checks the identity fields against its own frozen constants (two-source
  agreement, IP-0034 Packet 7.2/7.7).
- Supersedes for execution purposes only: `LIMA_PR3d_Real_Run_Approval_2026-09-27.md`
  (the 2026-09-27 one-time batch is finalized and latched; that document stays in
  the repository unchanged as historical evidence and is no longer loadable by
  the gated entry after the IP-0034 pin migration — it fails closed at
  `$.run_name`).
- Secret disclosure: this document contains no credential of any kind. The
  real-run key is bridged manually by the operator as an explicit entry
  parameter and never enters this repository or the evidence chain.

## 2. Machine-Readable Approval Block

The first ```json fenced block below is the complete, closed-schema approval
artifact consumed by the gated real-run entry (field set frozen by
CA-IP-0034-v1.0 R8 and the IP-0034 Packet 7.7; unknown fields are rejected; the
`model` block carries `served_model_forms`, the closed string list that replaces
the single `served_as` string of the 2026-09-27 schema).

```json
{
  "schema_version": 1,
  "approval_type": "PR3D-REAL-RUN-LIMITED",
  "run_name": "pr3d-real-2026-09-28",
  "date": "2026-09-28",
  "authorized_by": "Maintainer",
  "baseline_sha": "888793f1a46db6924009e7ec33f9ff1b633f01fa",
  "upstream": {
    "repository": "hiyouga/LlamaFactory",
    "requested_name": "hiyouga/LLaMA-Factory",
    "commit_sha": "7fcf5b3b130e5713b52415bb7404c476fada9c8c",
    "tarball_url": "https://codeload.github.com/hiyouga/LlamaFactory/tar.gz/7fcf5b3b130e5713b52415bb7404c476fada9c8c",
    "name_equivalence_note": "The requested repository name hiyouga/LLaMA-Factory and the canonical name hiyouga/LlamaFactory are the same GitHub repository at the same commit; the canonical-name codeload URL is used for the download and the fixture registry records the fetch URL once under the requested name (fixtures.py external identity entry, IP-0030)."
  },
  "model": {
    "provider": "deepseek",
    "request_name": "deepseek-v4-flash",
    "served_model_forms": ["DeepSeek-V4.1-Flash", "deepseek-flash"],
    "base_url": "https://api.deepseek.com",
    "system_fingerprint_policy": "record-and-latch-on-change"
  },
  "pricing": {
    "source_url": "api-docs.deepseek.com",
    "retrieval_date": "2026-09-28",
    "basis": "peak cache-miss per million tokens",
    "prompt_token_price_micro_usd_per_million": 300000,
    "completion_token_price_micro_usd_per_million": 1200000
  },
  "budget": {
    "per_run": {
      "cost_micro_usd": 100000,
      "calls": 1,
      "prompt_tokens": 150000,
      "completion_tokens": 8000,
      "wall_ms": 1200000,
      "download_bytes": 250000000,
      "storage_bytes": 500000000
    },
    "batch": {
      "cost_micro_usd": 1000000,
      "calls": 10,
      "prompt_tokens": 1500000,
      "completion_tokens": 80000,
      "wall_ms": 12000000,
      "download_bytes": 500000000,
      "storage_bytes": 2000000000
    }
  },
  "machine_profile": {
    "profile_id": "lima-pr3d-real-host-2026-09-28",
    "cpu_arch": "x86_64",
    "cpu_model": "Intel(R) Core(TM) i7-14650HX",
    "cores": 24,
    "ram_gb": 32,
    "os_family": "windows",
    "python_version": "3.12.4",
    "gpu_summary": "NVIDIA GeForce RTX 4060 Laptop GPU"
  },
  "attempt_policy": {
    "cold": 5,
    "warm": 5,
    "max_attempts": 10,
    "canary_required": true,
    "canary_first_attempt": 0
  }
}
```

## 3. Seven-Dimension Authorization Table

Maintainer one-time authorization of 2026-09-28 (Source Issue #232, ruling 4):
one batch of at most 5 cold + 5 warm attempts (10 model calls in total),
attempt-0 is the first cold canary and counts inside the 10, canary first, no
reset, no extra attempts, no cap raise, stop at or near any cap. Units are exact
ints; a cap is an explicit int with no `None` form (IP-0031 budget schema).

| dimension | per-attempt (per_run) cap | batch cap | batch = per-attempt x multiplier |
| --- | ---: | ---: | ---: |
| cost_micro_usd | 100000 | 1000000 | 10 |
| calls | 1 | 10 | 10 |
| prompt_tokens | 150000 | 1500000 | 10 |
| completion_tokens | 8000 | 80000 | 10 |
| wall_ms | 1200000 | 12000000 | 10 |
| download_bytes | 250000000 | 500000000 | 2 |
| storage_bytes | 500000000 | 2000000000 | 4 |

Self-consistency (unchanged from the 2026-09-27 authorization arithmetic and
re-verified by the frozen tests): with the worst-case byte-derived estimates,
one attempt costs at most ceil(300000 x 100000 / 1000000) + ceil(1200000 x 8000
/ 1000000) = 30000 + 9600 = 39600 micro-USD (within the 100000 per-attempt
cap), ten attempts cost at most 396000 (within the 1000000 batch cap), ten
completion estimates reach exactly 80000 (the at-cap inclusive semantics of
IP-0031 admits the tenth call and refuses the eleventh), and the
download/storage batch caps are not ten-fold linear — download and extraction
therefore happen once, inside the attempt-0 guarded call, with attempts 1-9
reusing the local snapshot.

## 4. Pricing Adoption and Source

- Source: api-docs.deepseek.com (DeepSeek pricing page, full path
  `https://api-docs.deepseek.com/quick_start/pricing`), retrieved 2026-09-28 by
  WebFetch (recorded as fact F7 of INTENT-RECORD-IP-0034-2026-09-28).
- Adopted figures (peak, cache-miss, per million tokens): input US$0.30, output
  US$1.20 — equal to 300000 and 1200000 micro-USD per million tokens. These are
  the values the Maintainer authorization price gate adopts; off-peak figures
  exist on the same page and are deliberately not adopted (the authorization
  prices the worst case).
- Re-check rule (IP-0034 Packet section 11, stage-2 hard gate): before the real
  execution, the operator re-reads the pricing page once, records the source
  and date, and verifies the peak cache-miss input US$0.30 / output US$1.20
  figures; any drift above those figures, or a price that cannot be confirmed,
  stops the run before the first paid request. The gated entry additionally
  rejects any artifact whose pricing block does not equal the frozen
  300000/1200000 pair (price-drift guard, IP-0034 Packet 7.7).

## 5. Model and Routing

- Request name: `deepseek-v4-flash` (the configured provider request name; sent
  verbatim in the chat-completion request `model` field; unchanged from the
  2026-09-27 authorization).
- Served model forms (closed list, order-sensitive):
  `["DeepSeek-V4.1-Flash", "deepseek-flash"]`.
- Basis for including `deepseek-flash` (Maintainer ruling 1: only forms
  supported by both the official documentation and the first-round evidence):
  (a) the provider pricing page read on 2026-09-28 lists `deepseek-flash` as
  the canonical serving name of DeepSeek-V4.1-Flash (Intent Record fact F7);
  (b) the 2026-09-27 attempt-00 evidence recorded the served model string as
  exactly `deepseek-flash` (D:\BaseAIProject\LIMA-real-runs\pr3d-real-2026-09-27\
  attempts\attempt-00.json). `deepseek-v4-flash-vision-exp` is documented but
  has no first-round evidence and is NOT included; no wildcard or prefix
  matching is opened.
- Identity matching rule (IP-0034 Packet 7.2): the response `model` value,
  normalized by lowercasing and stripping non-alphanumerics, must equal one of
  the normalized three-form union — the normalized request name
  (`deepseekv4flash`) or any normalized served form (`deepseekv41flash`,
  `deepseekflash`). Within persisted evidence, a model string is recorded
  verbatim only when it exactly equals (case-sensitive) the request name or a
  served form; every other string is reduced to the frozen irreversible digest
  token (SF-01, IP-0034 Packet 7.4). The canary observation records the batch
  baseline `(model, system_fingerprint)` in memory and any later change latches
  the batch closed (`REAL_RUN_IDENTITY_CHANGED`).
- Base URL: `https://api.deepseek.com` (chat endpoint `POST /chat/completions`).

## 6. Upstream Target and Baseline

- Upstream repository: `hiyouga/LlamaFactory` (canonical name; requested name
  `hiyouga/LLaMA-Factory` is the same repository) at the immutable commit
  `7fcf5b3b130e5713b52415bb7404c476fada9c8c`. Moving refs (latest main,
  branches, tags) are forbidden substitutions; if this commit cannot be
  materialized, #57 FR-06 escalates the parent issue to needs-decision.
- Download URL (canonical name, codeload tarball):
  `https://codeload.github.com/hiyouga/LlamaFactory/tar.gz/7fcf5b3b130e5713b52415bb7404c476fada9c8c`.
- Authorization baseline: `baseline_sha` = `888793f1a46db6924009e7ec33f9ff1b633f01fa`
  (pinned unchanged from the 2026-09-27 authorization — it is the authorization
  baseline, not the execution commit; the real execution must run from a clean
  main checkout whose merge SHA is a descendant of this baseline, and the
  execution commit is recorded by the operator into the run manifest evidence
  file, outside this repository).

## 7. Machine Profile (Same Host as the 2026-09-27 Measurement)

Eight fields aligned with the frozen `lima.baseline_run_spec._MACHINE_PROFILE_FIELDS`
schema (enum and int discipline included). The seven measured fields are
transcribed from the 2026-09-27 platform measurement of the same physical host
(CA-IP-0034-v1.0 R8); only `profile_id` is newly assigned for this one-time run.

| field | value | measurement note |
| --- | --- | --- |
| profile_id | lima-pr3d-real-host-2026-09-28 | assigned for this one-time run |
| cpu_arch | x86_64 | frozen enum member; AMD64 platform reported |
| cpu_model | Intel(R) Core(TM) i7-14650HX | OS-reported processor string |
| cores | 24 | logical processor count (int) |
| ram_gb | 32 | OS reported 31.8 GiB; recorded as the nearest int per the frozen profile int discipline |
| os_family | windows | frozen enum member |
| python_version | 3.12.4 | interpreter of the executing environment |
| gpu_summary | NVIDIA GeForce RTX 4060 Laptop GPU | OS-reported GPU |

## 8. Canary Strategy

1. The canary is the first real call of the batch: cold attempt-0 (its evaluator
   body performs the download, the safe extraction, the deterministic candidate
   selection, and exactly one bounded chat completion). Attempt-0 counts inside
   the 10-call total.
2. Immediately after the attempt-0 result settles and before the attempt-1
   reservation, the guard evaluates the closed mechanical checklist (five
   items, unchanged from IP-0032/IP-0033): usage within the reservation on all
   seven dimensions; served identity matching the declared forms (the
   three-form union of section 5) with a non-empty system fingerprint
   (recorded as the batch baseline); the attempt-0 result file present with an
   independently recomputed matching byte digest; strictly positive batch
   margin on every accounted dimension; and the canary sample being a success
   sample.
3. All five items pass: the batch continues with attempts 1-9 (5 cold + 5 warm
   total) under the same ledger, the same RunSpec, and the seven-dimension caps
   of this authorization.
4. Any item fails: the batch latches closed — every later guarded call refuses
   before reserving (`REAL_RUN_CANARY_FAILED`), samples are retained, the
   ledger and all diagnostics are preserved, and the suite finishes
   `insufficient_sample`. The batch then ends as a failed final state with the
   next-decision materials; it is not retried.
5. No automatic retry, no ledger reset, no additional attempts, no second
   batch; failed, cancelled, or timed-out samples stay counted (Maintainer
   authorization wording, ruling 5).

## 9. Invalidation Conditions (Stop Before the First Real Call)

- Price drift: the pre-execution pricing re-check (section 4) does not
  reproduce US$0.30 / US$1.20 peak cache-miss per million, exceeds either
  figure, or cannot be confirmed — stop before the first paid request.
- Preconditions unmet: the fix PR is not merged, post-merge verification is not
  PASS, or the code and this approval artifact are not on a clean latest main —
  stop (IP-0034 Packet section 11, stage-2 hard gates).
- Target not materializable: the fixed-commit tarball is unreachable, oversized
  beyond the 250,000,000-byte streaming cap, or fails the safe-extraction
  checks beyond repair — stop, retain diagnostics, escalate #57 FR-06.
- Caps not enforceable: any authorized cap (request bytes, call count,
  timeouts, download or extraction bounds) turns out not to be mechanically
  enforceable — stop.
- Any need for a second batch, a ledger reset, extra attempts, a credential in
  the repository or evidence chain, raw response content on disk, reuse of the
  finalized 2026-09-27 batch's remaining attempts, or a pre-merge real call —
  stop.

## 10. Consumption Record (To Be Filled After the Authorized Real Execution)

This section intentionally carries no numbers until the post-merge authorized
execution happens: the operator records the execution commit SHA, the output
directory absolute path, and the execution timestamp into the run manifest
evidence file (outside this repository) and the #232 evidence comment. This
document is not modified by the execution.
