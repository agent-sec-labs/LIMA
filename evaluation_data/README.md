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
