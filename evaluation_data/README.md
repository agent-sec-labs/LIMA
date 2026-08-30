# LIMA Evaluation Data

This directory contains controlled synthetic cases and reproducible manifests
for public security fixes. It is test data, not a claim that every referenced
repository is vulnerable in its current version.

## Contents

- `security_repair_cases.json`: LIMA-authored synthetic root-cause and repair
  constraints for supported CWE templates.
- `real_world_security_cases.json`: pinned public vulnerability and fix commits
  with archive hashes, source references, and isolated Oracles.
- `popular_external_holdout.json`: frozen external holdout manifest.
- `popular_calibration_v1.json`: cases explicitly reclassified for calibration.
- `pr_diff_100.jsonl`: PR-level benchmark records with source metadata and
  expected findings.
- `cxx_memory_cases.json`: four C/C++ memory vulnerability/fix pairs pinned to
  exact upstream commits and codeload archive SHA-256 values.

## Provenance requirements

Every real-world case must keep its repository, immutable commit identifiers,
source URLs, archive hashes, and upstream advisory references. Do not replace a
pinned revision with a moving branch or tag. Generated reports and downloaded
archives belong in ignored cache/output locations, not in Git.

Upstream source code, diffs, commit messages, and advisory text retain their
original copyrights and licenses. Apache-2.0 covers LIMA's original annotations,
selection logic, Oracles, schemas, and tooling; it does not relicense upstream
material. Before adding a case, confirm that its upstream terms permit the
intended inclusion or store only a source manifest and fetch the material at
evaluation time.

## Safety and integrity

Evaluation tooling must verify pinned SHA-256 hashes, reject archive traversal
and symlink escapes, bound archive size and file count, and avoid executing
untrusted repository code unless a case-specific isolated Oracle explicitly
requires it. Real API keys must never be stored in dataset records or reports.

## C/C++ memory pairs

The C/C++ manifest stores metadata only; upstream source is downloaded into the
operator-selected cache and extracted into a temporary shared repository root.
Every pair includes exact 40-hex commits, two HTTPS archive URLs and measured
SHA-256 values, an advisory, upstream fix, affected path/symbol, argv-array
build/test steps, selection rationale, and a pinned license URL. Build steps
must be non-empty; test steps may be empty when no genuine runtime test is
available. Both arrays are reviewed administrator configuration: scheduled CI validates the
full manifest, selects one exact committed case, and starts a fresh Sidecar
with those arrays before evaluating both revisions. The evaluator never sends
commands or environment variables in an analyzer request.

Run schema, deterministic metric, and archive-safety tests on every pull request:

```text
python -m unittest tests.test_cxx_memory_evaluation -v
```

The scheduled/manual public run is a four-case matrix because it downloads
third-party archives and each case needs different trusted build/test argv.
Every matrix leg emits its own auditable report. See
`docs/CXX_MEMORY_ANALYSIS.md` for the shared cache mount, Sidecar isolation,
metric definitions, and validity limits. A case may use a narrowly pinned,
project-generated build-verification target when the upstream archive omits
safe test resources. Compile-only verification stays in `build_steps`; an
absent runtime suite uses empty `test_steps`, and the manifest and report must
not describe it as a passing sanitizer or unit-test run.
