# Repair Publication Fixes Implementation Plan

**Goal:** Fix the three P1 findings in `docs/LIMA_GLOBAL_REPAIR_PUBLICATION_AUDIT_2026-11-06.md`.

**Architecture:** Pass immutable audit SHA through the authorized service entry into all publication reads and writes. Use one publication gate requiring repair manifests, static oracles, differential checks, and successful sandboxed tests. Run repository tests only in a resource-limited, unprivileged, network-disabled container with read-only input and an ephemeral writable copy. Generate draft text from actual checks.

**Ownership:** Publication worker owns fixer and dedicated publication tests. Sandbox worker owns verifier, repair_sandbox and its tests. Main owns service/configuration, integration fixtures, docs and final verification. No GitHub writes during verification, no commits/push/merge.

- [x] Observe red tests for missing/stale SHA, skipped legacy gates and host execution.
- [x] Implement fixed-source publication and checks-driven draft body.
- [x] Implement container-only testing and bounded evidence/confirmed cleanup, with no native fallback.
- [x] Integrate explicit deployment image configuration and source identity at service/API boundary.
- [x] Preserve real functional assertions for trusted synthetic test fixtures through explicit test-only runner injection.
- [x] Run focused tests, independent integration review, source/lint checks and complete project suite; record external validation limits.

**Final verification:** backend complete project runner 3,747 tests, 42 skipped, no failures/errors; frontend all 87 passed, typecheck and production build passed. Source compilation, new-module lint and diff checks passed; baseline comparison found no added lint violations in the touched legacy large modules. Real Docker smoke was attempted but returned image unavailable, executed=false, and host marker unchanged. This does not establish the real container success path. No remote GitHub writes or configuration changes. Details: `docs/LIMA_REPAIR_PUBLICATION_FIXES_2026-11-06.md`.

**Review focus:** Head drift during verification; mixed legacy/supported repairs; missing/partial/false-positive verification receipts; unavailable Docker/image; output overflow and unconfirmed teardown; no tests or missing audit SHA; preserving original task/report permissions; keeping PR publication out of tests.
