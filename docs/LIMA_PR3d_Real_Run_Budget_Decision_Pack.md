# LIMA PR3-d Real-Run Budget Decision Pack

## 1. Document Header

- Doc id: LIMA-PR3D-REAL-RUN-BUDGET-DECISION-PACK
- Version: 1.0
- Date: 2026-09-27
- Status: DRAFT-PENDING-AUTHORIZATION
- Author: Packet & Verification Agent (IP-0031, C1)
- Scope: decision material for the future PR3-d real-execution authorization round. This document
  invents no numbers: every cell that has not been measured is the literal token UNKNOWN, and the
  only numeric constants that appear are (a) structural schema constants, (b) the per-run attempt
  count fixed by the frozen orchestration semantics, and (c) the unit divisors of the frozen
  pricing formula.
- Current authorization state (2026-09-27, Maintainer decision plan B): the offline slice ships
  with a real paid budget of zero micro-USD, no authorization for real downloads, real scanning, or
  real model calls, and the real-run gate locked. Nothing in this document may be read as approved.

## 2. Candidate Models

Structure of every row: model / provider / version / pricing source / pricing date. All value
cells are UNKNOWN until a pricing source is authorized and read (see section 3).

| model | provider | version | pricing source | pricing date |
| --- | --- | --- | --- | --- |
| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |
| UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN | UNKNOWN |

A second row is reserved for a backup candidate; both rows stay UNKNOWN until section 3 is
resolved. No candidate may be promoted out of UNKNOWN status by assumption, vendor marketing
material, or memory of prior projects.

## 3. Pricing Sources and Dates

- Current pricing source: UNKNOWN.
- Current pricing source date: UNKNOWN.
- Minimal authorization action to resolve: permission to read the provider pricing page (or
  obtain a written quote) once, performed by a human Maintainer, one-time; the retrieved numbers,
  their source URL, and the retrieval date must be recorded into this section verbatim.
- Standing rule: prices transcribed into this pack keep their source and date attached; a price
  without a source-and-date pair is invalid and must be treated as UNKNOWN.

## 4. Per-Run Estimates

- Attempts per run: 10 (5 cold + 5 warm; frozen `run_repeats` semantics, `repeat=5`). This is the
  only estimate in this section that is fixed by an already-frozen pipeline contract rather than
  measured.
- Prompt tokens per call: UNKNOWN.
- Completion tokens per call: UNKNOWN.
- Calls per run: UNKNOWN (bounded above by the attempts-per-run constant only after the evaluator
  protocol of the real round is fixed; not assumed here).
- Wall-clock time per run (wall_ms): UNKNOWN.
- Download bytes per run: UNKNOWN (the LlamaFactory tarball byte count is not known; the recorded
  precheck of 2026-09-26 verified only that the commit API redirects to the commit and that the
  tarball HEAD responds, not its size, and a precheck is not a download).
- Storage bytes per run: UNKNOWN.
- Minimal authorization actions to resolve each cell: one authorized real pipeline rehearsal or
  one authorized measurement run per unknown, executed under a numeric budget approved in
  advance; each resolution records the measurement command, environment, and raw output.

## 5. Recommended Caps

Formulas only (symbolic); every numeric substitution stays UNKNOWN until section 4 is resolved.

| dimension | per_run cap | batch cap |
| --- | --- | --- |
| cost_micro_usd | safety_factor_cost × worst_case_cost_micro_usd(per-call estimate, section 9 formula) | attempts_per_run × safety_factor_cost × worst_case_cost_micro_usd(per-call estimate) |
| calls | safety_factor_calls × estimated_calls_per_call_sequence | attempts_per_run × safety_factor_calls × estimated_calls_per_call_sequence |
| prompt_tokens | safety_factor_tokens × estimated_prompt_tokens_per_call | attempts_per_run × safety_factor_tokens × estimated_prompt_tokens_per_call |
| completion_tokens | safety_factor_tokens × estimated_completion_tokens_per_call | attempts_per_run × safety_factor_tokens × estimated_completion_tokens_per_call |
| wall_ms | safety_factor_wall × estimated_wall_ms_per_run | attempts_per_run × safety_factor_wall × estimated_wall_ms_per_run |
| download_bytes | safety_factor_download × estimated_download_bytes_per_run | attempts_per_run × safety_factor_download × estimated_download_bytes_per_run |
| storage_bytes | safety_factor_storage × estimated_storage_bytes_per_run | attempts_per_run × safety_factor_storage × estimated_storage_bytes_per_run |

- safety_factor_cost, safety_factor_calls, safety_factor_tokens, safety_factor_wall,
  safety_factor_download, safety_factor_storage: UNKNOWN (to be chosen by the Maintainer when the
  estimates exist; the budget gate implementation already enforces whichever integers are chosen).
- Structural constraints already frozen: every cap is an explicit int (a None cap does not exist);
  batch caps must be greater than or equal to the per_run caps dimension by dimension.

## 6. Over-Cap Behavior

Delivered and testable now (references to the budget gate of IP-0031, no new mechanism needed):

- Pre-call check refuses a call whose reservation would exceed a per-run cap
  (`RUN_BUDGET_EXCEEDED`) or the batch cap (`BATCH_BUDGET_EXCEEDED`); the refusal happens before
  the wrapped callable is invoked, so a refused call performs zero external calls.
- A call whose cost cannot be pre-bounded (unknown or incomplete pricing, missing token bounds) is
  refused with `COST_NOT_PRE_BOUNDED`; unknown pricing is never treated as free.
- A completed call without reported usage is a violation (`USAGE_MISSING`), never recorded as
  zero; the reservation stays occupied.
- Failures and cancellations release the unspent reservation (already-consumed usage is retained)
  while the call count is never given back.
- Real-run execution is locked in this slice; the only behavior of the real-run entry point is
  `REAL_RUN_LOCKED`.

## 7. Machine Profile

Eight fields aligned with the frozen `BaselineRunSpec._MACHINE_PROFILE_FIELDS`. The target machine
for the future real round is not specified, so every field is UNKNOWN.

| field | value |
| --- | --- |
| profile_id | UNKNOWN |
| cpu_arch | UNKNOWN (frozen enum: x86_64 or aarch64) |
| cpu_model | UNKNOWN |
| cores | UNKNOWN (int) |
| ram_gb | UNKNOWN (int) |
| os_family | UNKNOWN (frozen enum: linux, windows, or darwin) |
| python_version | UNKNOWN |
| gpu_summary | UNKNOWN |

Minimal authorization action to resolve: designation of the target machine by the Maintainer,
followed by a one-time read of the platform facts on that machine.

## 8. Failed Run Handling

- Failed attempts are retained, never dropped: the frozen taxonomy codes EXECUTION_ERROR,
  EXECUTION_TIMEOUT, and EXECUTION_CANCELLED keep their samples in the aggregate, and the
  aggregate status becomes insufficient_sample when fewer than three cold successes or fewer than
  five warm successes remain.
- Budget accounting on failure or cancellation: the reservation of the failed call is released
  (already-consumed usage is retained in the consumed books), and the call count is never
  recycled. Subsequent calls of the same run are still checked against the caps normally.
- Real-run failures produce no safety conclusion and no coverage claim; a blocked, timed-out, or
  failed attempt is evidence of failure only.

## 9. Auditable Budget Formulas

Worst-case per-call cost (micro-USD, integer ceiling, identical to the frozen budget gate
formula):

```text
worst_case_cost_micro_usd =
    ceil(price_p × estimate.prompt_tokens / 1_000_000)
  + ceil(price_c × estimate.completion_tokens / 1_000_000)
```

- `price_p` = prompt_token_price_micro_usd_per_million, `price_c` =
  completion_token_price_micro_usd_per_million (both must be known ints; a None price makes the
  cost not pre-bounded and the call is refused).
- Batch aggregation: `batch_cost_bound = ceil(attempts_per_run × worst_case_cost_micro_usd)` is
  the cost floor of a run before any safety factor; token, call, wall-clock, download, and storage
  bounds aggregate linearly the same way.
- Every number that enters these formulas must trace to a measured estimate (section 4) or an
  authorized price (section 3); substituting an UNKNOWN into a formula yields UNKNOWN, never a
  guessed number.

## 10. UNKNOWN Ledger

| item | value | minimal authorization action | approver | scope |
| --- | --- | --- | --- | --- |
| Candidate model identity (both rows of section 2) | UNKNOWN | Maintainer selects the candidate list for the real round | Maintainer | one-time |
| Provider pricing (prompt and completion, both rows) | UNKNOWN | one authorized read of the provider pricing page or a written quote; record source + date | Maintainer | one-time per pricing change |
| Pricing source date | UNKNOWN | recorded with the price read above | Maintainer | one-time per pricing change |
| Prompt tokens per call | UNKNOWN | one authorized measurement run under an approved numeric budget | Maintainer | one-time |
| Completion tokens per call | UNKNOWN | same measurement run as above | Maintainer | one-time |
| Calls per call-sequence | UNKNOWN | fixed together with the real-round evaluator protocol | Maintainer | one-time |
| wall_ms per run | UNKNOWN | same measurement run as above | Maintainer | one-time |
| LlamaFactory tarball download bytes | UNKNOWN | one authorized HEAD/range read of the pinned tarball URL recording the content length, or the first authorized download | Maintainer | one-time |
| Storage bytes per run | UNKNOWN | same measurement run as above | Maintainer | one-time |
| Safety factors (six, section 5) | UNKNOWN | Maintainer chooses them once the estimates exist | Maintainer | one-time |
| Machine profile (eight fields, section 7) | UNKNOWN | Maintainer designates the target machine; one platform read | Maintainer | one-time |

## 11. Authorization Request Checklist

Three prerequisites must all hold before any real run; none of them is satisfied by this slice:

1. A numeric budget: per_run and batch caps for all seven dimensions (ints; batch caps at least
   the per_run caps), derived from resolved estimates and prices through the section 9 formulas,
   recorded in this pack by the Maintainer.
2. A Maintainer approval artifact: a dated approval that names the run, the numeric budget, the
   model identity, and the machine profile, attached to this pack before the gate is touched.
3. A gate-unlock code change: the real-run gate constant and entry behavior are frozen in the
   locked state by this slice; unlocking requires a future, separately reviewed code change (a
   Maintainer authorization with a numeric budget), never a configuration or environment toggle.

Until all three prerequisites exist, the only behavior of the real-run entry point remains
REAL_RUN_LOCKED, and no output of the offline suite may be presented as a real measurement.
