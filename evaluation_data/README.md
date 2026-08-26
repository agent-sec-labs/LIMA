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
- `popular_external_holdout_v2.json`: active repository-disjoint holdout frozen
  against the LIMA 1.6 analyzer. Its two preregistered runs are complete; the
  immutable manifest and artifacts remain the historical external baseline.
- `popular_external_calibration_v2.json`: explicit post-hoc calibration copy of
  the completed v2 holdout. Its case-level failures informed LIMA 1.7, so results
  on this file are engineering calibration only, never a new external claim.
- `pr_diff_100.jsonl`: PR-level benchmark records with source metadata and
  expected findings.

## Provenance requirements

Every real-world case must keep its repository, immutable commit identifiers,
source URLs, archive hashes, and upstream advisory references. Do not replace a
pinned revision with a moving branch or tag. Generated reports and downloaded
archives belong in ignored cache/output locations, not in Git.

An external holdout remains an external result only until its case-level outcome
is inspected for implementation changes. If developers tune retrieval, rules,
prompts, or adjudication from those outcomes, preserve the original report and
reclassify the manifest as calibration before claiming a new external result.

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
