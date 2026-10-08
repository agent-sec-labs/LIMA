# C++ container execution coverage

The engineering job must execute the eleven fixed fixture regressions: source
scan, build-backed scan, ASan, four repro cases, the default-off CMake gate and
three UAF fact extraction cases. A successful unittest exit with skipped cases
does not satisfy this job. The runner verifies the exact passed methods and
rejects skips, omissions, failures and unexpected replacements.

Two phases preserve the existing trust gate:

1. `scripts/run_cxx_container_tests.py stage` invokes the repository-owned
   BuildScan/ASan fixture constructors and the real `prepare_snapshot`. It
   copies verified inert source fixtures into an ephemeral Docker volume,
   stopping at the snapshot boundary before any analyzer/build code executes.
   The test-only capability precheck is suppressed only during setup, which
   produces no test verdict. Production trust probes are untouched.
2. Mount that volume read-only at `/work/snapshots`. Mount a separate writable
   executable tmpfs at each fixture's `source/build`, retaining the existing
   CMake relative build layout. Run the unchanged assertions with non-root uid
   10002, no network, no capabilities, no-new-privileges, a read-only rootfs and
   ephemeral scratch. The real trust capabilities must all be true. The runner
   retains normal snapshot preparation and rechecks every mounted source byte
   against the original test-generated inventory. Both read-only source and
   writable build mount are checked, rather than probing an unrelated directory.

Repro/UAF and default-off regressions use their original ephemeral prepared
snapshots and unchanged sandbox boundary. No production command, rule,
finding/report contract, permissions or configured security gate is relaxed.
The fixture volume is removed in the workflow's always-run cleanup step.

This closes a coverage gap found after PR #265: on main run 37747702274,
the sidecar selected three tests but skipped BuildScan/ASan because
`snapshot_readonly` was false; the eight other toolchain-dependent container
cases lacked an execution-enabled CI job. The Stage A Python investigation
tests had passed independently. This change does not close #264 or claim any
new real-model evidence, Stage B or OpenHarmony acceptance (#266/#267).

When adding fixture methods, update the explicit required method set as well
as the selected classes. Keep setup and execution evidence separate, bind CI
results to their actual SHA/attempt, and report any unsupported environment as
a failed required execution check.
