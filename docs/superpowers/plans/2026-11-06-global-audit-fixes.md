# Global Audit Fixes Implementation Plan

> **For agentic workers:** Use test-driven-development and verification-before-completion; independent workers own disjoint files.

**Goal:** Correct the six issues recorded in `docs/LIMA_GLOBAL_AUDIT_2026-11-05.md`.

**Architecture:** Bind build and scan to the same persisted TU scope. Carry consumer receipts and missing-context gaps through the platform outcome into the report and AEP. Protect bounded registry leases, renew during execution, and compensate ambiguous delivery failures. Support the existing host Docker executor explicitly, with deployment preflight and writable artifact storage.

**Tech Stack:** Python, pytest/unittest, Sidecar HTTP protocol, Docker CLI, PowerShell.

**Spec:** `docs/LIMA_GLOBAL_AUDIT_2026-11-05.md`.

## Constraints and review focus

- Preserve unrelated user files and current branch; no merge or comment publication.
- An unavailable context must never be claimed consumed, including the empty-lead early return.
- Build success must cover requested TUs; restored packages must satisfy the current persisted scope.
- Live holders survive capacity admission; metadata and crash leftovers are bounded.
- Renewal must stop before release; ambiguous POST and failed DELETE require bounded cleanup.
- Document supported host execution without exposing a Docker socket to the Web container.

## Tasks

- [x] Add failing consumer/report tests, implement actual TU receipts and required blockage, run platform regressions (main).
- [x] Add missing-target tests, enforce producer postcondition, run build regressions (build worker).
- [x] Add capacity/holder/lease tests, implement atomic admission and expiration (registry worker).
- [x] Unify persisted build/scan scope, remove unused local registry copy, implement client renewal and cleanup retries (main).
- [x] Validate host execution prerequisites, document Compose limits and current deterministic planner, handle artifact retention explicitly (main).
- [x] Run focused integration tests, lint, and project suite; record failures and remaining external verification requirements (main).

## Final verification

- Complete project runner: 3,704 tests, 41 skipped, no failures/errors (`output/lima-global-fixes-2026-11-06/final-full-suite.log`).
- Real Docker/CMake context export: covered targets SUCCEEDED; omitted requested target FAILED with `target-units-missing`.
- New/changed core modules lint clean; baseline comparison found no newly introduced lint violations in the three legacy large modules.
- Source compilation and `git diff --check` passed. No remote publication or merge performed.
