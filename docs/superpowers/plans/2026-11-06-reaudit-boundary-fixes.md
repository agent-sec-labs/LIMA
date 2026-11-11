# Reaudit Boundary Fixes Implementation Plan

**Goal:** Fix the four findings in `docs/LIMA_GLOBAL_REAUDIT_2026-11-06.md` without disturbing the earlier uncommitted fixes or user documents.

**Architecture:** Use a separately hashed, bounded build-input manifest and reject links/reparse points before container entry. Keep legacy tool analysis source-only for build-enabled tasks because that API cannot bind the verified artifact. Reserve execution directories atomically and aggregate build gaps into completion status. Derive sandbox execution claims from executor receipts.

**Ownership:** Build-input worker owns executor/input module/agent/tool metadata. Scanner worker owns scanner/workspace and their new tests. Main owns service integration, concurrency and completion tests, documentation and final checks. Workers do not delegate further.

- [x] Convert copy/junction, required-layer, completion and concurrent namespace probes into failing regression tests.
- [x] Implement bounded build-input copy, digest evidence, cancellation and cleanup; carry real execution metadata.
- [x] Add task-local allowed tool layers and block Windows reparse points in workspace inventory.
- [x] Reserve run directories atomically, persist input identities, validate them before restore reuse, and correct completion/execution reporting.
- [x] Run focused regressions, independently review integration, attempt real Docker/CMake, then run the complete project suite with UTF-8 output.
- [x] Record exact verification results and limitations. Do not push, merge or publish comments.

**Final verification:** complete project runner 3,723 tests, 41 skipped, no failures/errors. Focused integration 144 passed, 1 skipped; subsequent input/service regression 13 passed. Source compilation, new-module lint and diff checks passed; no additional lint findings in legacy large modules. Actual Docker acceptance was attempted but the local Linux engine was unavailable; Desktop was returned to its initial non-running state. See `docs/LIMA_GLOBAL_REAUDIT_FIXES_2026-11-06.md` and `output/lima-reaudit-fixes-2026-11-06/`.

**Review focus:** Source files changing between inventory and copy; excluded sensitive inputs; symlink/junction replacement; cancellation before session launch; stale successful packages whose build-only inputs changed; simultaneous execution of one task; blocked layers with required analyzer mode; truthful task completion and sandbox execution evidence.
