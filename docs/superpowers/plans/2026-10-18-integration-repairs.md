# ResInsight integration repairs implementation plan

> For agentic workers: execute the bounded tasks below with failing regressions before implementation and verify the integrated result.

**Goal:** Repair the concrete failures in `docs/INTEGRATION_ACCEPTANCE_2026-10-18.md` and rerun local acceptance on ResInsight.

**Architecture:** Keep task cancellation local to each worker invocation; distinguish tool process completion from usable analysis evidence; invalidate authenticated query state on session changes. Preserve bounded scanning and explicitly configure matching host/Sidecar limits for this large repository.

**Tech stack:** Python HTTP service, SQLite, React Query, Vitest, Docker Semgrep Sidecar.

**Constraints:** Preserve existing uncommitted changes. Target source is read-only. No paid model calls or GitHub publication. Do not change frozen benchmark artifacts to hide analyzer changes. No new public network exposure.

## Tasks

- [x] Reproduce Semgrep rejection with actual tool output and record the exact parser failure; add parser and semantic-status regressions before patching. Own `cxx_analyzer/source_scan.py`, producer status, associated tests.
- [x] Make repository cancellation observable at queue/stage/finalization boundaries and reset cancellation on resume; add task-level regressions. Worker owns `lima/service.py`, `lima/store.py`, `lima/repository_scanner.py` until handoff.
- [x] Refresh authenticated queries after login and remove old-account cache on logout; test an initial 401 followed by successful login. Worker owns `frontend/src/shared/auth/AuthContext.tsx` and auth tests.
- [x] Limit dynamic-code execution rules to supported language/call semantics so Qt event loops are not SEC-EVAL candidates; retain Python detection regressions.
- [x] Surface C++ failures/degradation in task reports and completion summaries without interpreting failed coverage as clean. Coordinate scanner edits after cancellation handoff.
- [x] Inventory ResInsight and configure matching bounded host/Sidecar budgets in the isolated acceptance launchers. Re-scan and verify absence of budget truncation; do not raise global defaults without evidence.
- [x] Run focused backend/frontend/container tests, rebuild the isolated Sidecar and frontend, rerun authentication, cancellation/resume, report and repair-preview acceptance, and update the acceptance report with remaining environmental limits.

## Review focus

Cancellation must not mark a task FAILED or retry it; resumed work must retain original task settings. A failed Semgrep parser must never retain a successful tool status. Partial parse warnings must preserve honest coverage. Cross-account query data must not survive session changes. Enlarged limits must match across both inventories. Python eval/exec coverage must remain despite Qt false-positive suppression.

## Final acceptance evidence (2026-10-19)

Task `b9c9d9b9-5c3c-4e02-8e75-65c9654669a1` completed with no snapshot budget truncation. C++ recovery completed on 5,622 sources after explicitly excluding 843 parser gaps; the projected status remains partial. Three C++ candidates were checked against snapshot source lines and bound to the completed recovery run. Backend: 450 passed / 20 skipped; frontend: 84 passed, typecheck/build passed; isolated engine tests: 17 passed. See `docs/INTEGRATION_REPAIRS_2026-10-18.md` for verified functions and remaining environment/coverage limits.
