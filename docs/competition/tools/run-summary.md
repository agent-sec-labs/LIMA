# Competition run summary (Issue #312)

## Implementation and acceptance plan

Initial baseline: `bd8ba3441017c3f1463cd9fe0fc9bbbf45c81ad0` (main, fetched
2026-10-19). Before PR publication, main advanced through #316 to
`8c77ea10286ce2146909b16b5d44889dd05128c2`; the branch was updated to that
baseline and compatibility checks repeated. Independent branch:
`codex/issue-312-run-summary`. Only this
document, `tests/test_competition_run_summary.py`,
`lima/competition_run_summary.py`, and `scripts/aggregate_competition_runs.py`
are added. At initial delivery, there was no remote assignment, reviewed Packet,
independent agent verification, Issue claim, or merge. The subsequent independent
review and its open findings are recorded below.

1. Freeze synthetic contract tests before implementing the loader or CLI.
2. Prove RED in Docker with the implementation absent; record the test digest.
3. Implement strict JSON loading, same-side reconciliation, one row per explicit
   input, a single shared table projection, and safe new-directory publication.
4. Run the frozen tests and related existing writer/performance tests in Docker.
5. Generate two synthetic same-case bundles and a manifest using the test module;
   execute the actual script, inspect CSV/Markdown/errors, remove optional
   performance data and repeat into a different output directory. Verify original
   bundle bytes and filenames are unchanged. Record commands and limitations.

All fixtures are synthetic. No models, target execution, repository scanning,
deployment, credential access, or automatic input discovery are involved.

## Usage and output contract

```text
python scripts/aggregate_competition_runs.py --inputs runs.json --output-dir new-results
```

`python -m lima.competition_run_summary` accepts the same arguments. Both entry
points use the standard library only. The output directory must not exist.
Both entry points emit structured stderr diagnostics using ASCII JSON escapes,
so labels containing non-ASCII characters remain parseable with GBK or UTF-8
stderr. Output files are always UTF-8. See **Review corrections** for the original
encoding defect and its regression coverage.

```json
{
  "schema_version": 1,
  "runs": [
    {"run_label": "round-passed", "bundle_dir": "round-passed",
     "performance_file": "performance.json", "execution_label": "synthetic"},
    {"run_label": "round-failed", "bundle_dir": "round-failed"}
  ]
}
```

Relative input paths are relative to the manifest's directory, independent of the
working directory. Absolute paths are permitted. Labels and resolved bundle paths
must be unique; explicitly sharing a performance file between runs is also rejected
to avoid attributing one measurement to two runs. Symlink aliases resolve before
the duplicate check. No directory is searched for additional runs.

The loader reads only `summary.json`, optional `case.json`, optional
`vulnerable/platform.json` and `fixed/platform.json`, and an explicitly supplied
performance file. Missing legacy case/platform files or fields become null with a
reason. Existing malformed files are errors. A missing summary is an input error.
Per-file reads are capped at 16 MiB; non-regular files and evidence-file links
escaping their specified bundle are rejected. Input JSON must be UTF-8, contain an
object, have no duplicate keys, non-finite numbers, or lone Unicode surrogates.

Critical overlapping values are reconciled before use: case ID, commits,
status/validation_status aliases, and known same-side platform fields, including
the original findings array. Null is a recorded value and conflicts with a
different non-null value. Opposite sides never supply missing fields. Unknown
finding states are retained under their original state names. Explicit empty
findings produce `{}`, whereas absent findings produce null.
Reconciliation compares values recursively: numerically equivalent integers and
floats agree, including nested values and signed zero. Booleans remain distinct
from numbers, list order and object keys must agree, and no float conversion is
used to compare large integers. The original first source value is retained.

Outputs are `summary.csv`, `summary.md`, and `errors.json`. Rows sort by the
unescaped run label; the manifest order has no effect. Each specified run produces
one row, including a damaged bundle. `row_status=error` distinguishes damaged data
from a successfully parsed validation whose original status is `failed`. Fields
already read before an error remain available, with the error and remaining
unknowns recorded explicitly. A partially projected row must not be treated as a
complete run.

| Fields | Recorded meaning/source |
| --- | --- |
| run_label, execution_label | Explicit manifest values; execution_label is an operator annotation |
| case_id | case.json / summary.json, reconciled |
| vulnerable_commit, fixed_commit | Each side's case revision commit or an explicit agreeing side commit |
| validation_status | Original summary status; never recomputed from findings |
| vulnerable_validation_status, fixed_validation_status | Original status of that side |
| vulnerable_findings_by_state, fixed_findings_by_state | Count of records under each original state within that one run and side |
| reason_codes | Original summary list, retaining order and duplicates |
| vulnerable_diagnostics, fixed_diagnostics | Original diagnostics for that side |
| total_elapsed_seconds | Original summary value; never replaced by sampling wall time |
| execution_mode, model_identity | Explicit top-level summary fields, otherwise `unknown` plus reason |
| summary_ref, summary_sha256 | Logical relative reference and SHA-256 of the exact summary bytes read |
| performance_ref | Explicit optional input identified by run label, otherwise null |
| field_sources, unknown_reasons | JSON mappings of field provenance and missing-value reasons |

`bundle:<run_label>/summary.json` and similar references resolve through the
explicit manifest's label-to-bundle mapping; `performance:<run_label>` resolves
through that run's optional performance_file. No resolved host path is generated
in the tables or diagnostics. Only projected fields are exported; arbitrary input
metadata, command lines, and environment objects are omitted. Diagnostic messages
contain controlled error codes, logical references, and known field names, never
raw exception text or JSON contents.

The schema-1 performance projection is independent of the collector module:

| Output | Performance schema-1 source |
| --- | --- |
| performance_wall_time_seconds | wall_time_seconds |
| host_sampled_peak_rss_bytes | host.sampled_peak_rss_bytes |
| host_measurement_source, host_sampling_complete | host.measurement_source, host.complete |
| container_sampled_peak_memory_bytes | container.sampled_peak_memory_bytes |
| container_sampled_peak_cpu_percent | container.sampled_peak_cpu_percent |
| container_measurement_source, container_sampling_complete | container.measurement_source, container.complete |
| performance_partial | partial |

No performance file, an unavailable optional file, or an unsupported schema leaves
performance values null with `performance_not_provided`, `performance_unavailable`,
or `performance_schema_unsupported`. Missing metrics in a compatible document use
`not_recorded`. A malformed/duplicate-key JSON document or invalid known metric is
an input error. Zero is preserved only when explicitly recorded. Sampled peaks and
their recorded source/completeness remain sampling measurements; they are not
exact lifetime peaks. No history is averaged and findings across runs are never
added into a vulnerability total. Precision/recall are not calculated.

The complete bundle is **not verified**. The summary digest is only a locator for
the raw summary bytes read; no manifest, AEP, VEP, or complete-bundle integrity
check is performed. There is no `integrity_valid` field. A finding state such as
`runtime-confirmed` never supplies a model identity or proof of real execution.

CSV and Markdown use exactly the same row projection and columns. Null, mappings,
arrays, and booleans are serialized as JSON inside cells (`null`, `{}`, `[]`,
`true`/`false`). CSV free-text cells beginning with `=`, `+`, `-`, `@`, or a tab
receive a leading apostrophe to prevent spreadsheet formula execution. That
apostrophe is presentation escaping, not part of the original label. Markdown
escapes HTML, backslashes, and pipes, and represents line breaks as `<br>`.

| Exit | Meaning |
| --- | --- |
| 0 | Every selected bundle is parseable; optional measurement unknowns are permitted |
| 2 | One or more run inputs are invalid; all rows and errors are retained |
| 3 | Invalid manifest/arguments, duplicate inputs, or output conflict/write failure |

Output conflicts are checked before run loading. A new output cannot contain an
input file, sit inside a bundle, or contain a selected bundle. Files are created
exclusively; existing result directories, even empty ones, are never overwritten.
Usage/output errors are controlled JSON diagnostics on stderr. Run errors are in
`errors.json` as `{run_label, code, ref, field}`. An error-free run writes an empty
`errors` array. Exit 0 means successful aggregation, not validation passed.

## Review corrections

The review of implementation `a4140a9` reproduced two defects, initially recorded
by documentation-only commit `8b8b4d9`. The follow-up code fixes are:

- **P2: equivalent numeric representations.** JSON text comparison incorrectly
  rejected summary-side `file_coverage: 1` versus platform `1.0`. A recursive JSON
  value comparison now accepts equivalent numbers on both sides and in nested
  arrays/objects. Regression cases also require true numeric differences, boolean
  versus numeric values, list reordering/length differences, missing/extra object
  keys, null differences, and numeric strings to remain conflicts. A large integer
  is not rounded to float before comparison. Inputs are not rewritten.
- **P3: module diagnostics with GBK stderr.** Emoji duplicate labels previously
  escaped through the text stream as invalid JSON `\U0001f9ea`. Both controlled
  stderr error paths now use `ensure_ascii=True`, emitting standard JSON Unicode
  escape sequences. The module subprocess regression explicitly sets
  `PYTHONIOENCODING=gbk` and verifies that decoding and parsing recover the exact
  label, while exit 3 and no-output behavior remain intact. The script uses the
  same diagnostic implementation without changing the caller's stream settings.

Six new test methods supplement the original 21. They were committed first in
`c308a36fc13d0029831bd7090602619042964341`; Docker reproduced two failures and one
JSON parsing error on the old implementation before the fixes. All original
test method bodies remain unchanged. These are implementation/regression fixes,
not a new writer, schema, service, or shared utility dependency.

## Repeatable synthetic demonstration

From the repository root, choose fresh directories for each run:

```powershell
python -m tests.test_competition_run_summary --write-demo output/run-summary-demo
python scripts/aggregate_competition_runs.py --inputs output/run-summary-demo/runs.json --output-dir output/run-summary-table
python -m unittest tests.test_competition_run_summary -v
```

The generator creates the two complete small JSON bundles, the manifest above,
and schema-1 synthetic performance data. Both cases have case_id
`synthetic-pair`, vulnerable commit `aaaa…` (40 hex), fixed commit `bbbb…`,
12.5 seconds of recorded validation time, vulnerable states
`runtime-confirmed: 1` and `semantic-supported: 2`, and no fixed findings.
The failed run retains `vulnerable-replay-unstable`; the passed run has `[]`.
Only the passed run explicitly references synthetic sampling data:
wall time 13.25 s and host sampled peak RSS 1048576 bytes.

Actual table excerpt (the exported table also includes provenance and unknowns):

| run_label | case_id | validation_status | reason_codes | host_sampled_peak_rss_bytes | model_identity |
| --- | --- | --- | --- | --- | --- |
| round-failed | synthetic-pair | failed | ["vulnerable-replay-unstable"] | null | unknown |
| round-passed | synthetic-pair | passed | [] | 1048576 | unknown |

Manual missing-performance check: remove only the generated
`output/run-summary-demo/performance.json`, rerun into a different new directory,
and verify that the passed row's sampled RSS becomes null with
`performance_unavailable`, rather than 0. Original bundle files remain unchanged.

## Docker reproduction

The normal Dockerfile is unchanged and does not copy this new script. Use a
clean source context containing tracked main files plus the four new files, with
no `.env`, imported repositories, `.zcode`, or historical output. The executed
local acceptance used a pre-existing dependency image without any network or new
installation, with this small derived Dockerfile (stored only under output):

```dockerfile
FROM lima:pr316-registry
WORKDIR /issue312
COPY --chown=lima:lima . .
USER lima:lima
CMD ["python", "-m", "unittest", "tests.test_competition_run_summary", "-v"]
```

For a fresh checkout the normal project's `test` target can supply the dependency
image instead. No requirement on the unrelated #293 source exists; all imports
are the standard library. To construct the clean context on this Windows setup,
run these commands from the repository root:

```powershell
New-Item -ItemType Directory -Force output/competition-run-summary-312/context
git archive --format=tar --output=output/competition-run-summary-312/main-source.tar HEAD
python -c "import tarfile; tarfile.open('output/competition-run-summary-312/main-source.tar').extractall('output/competition-run-summary-312/context', filter='data')"
$files = @('scripts/aggregate_competition_runs.py', 'lima/competition_run_summary.py', 'tests/test_competition_run_summary.py', 'docs/competition/tools/run-summary.md')
foreach ($file in $files) {
    $target = Join-Path output/competition-run-summary-312/context $file
    New-Item -ItemType Directory -Force (Split-Path -Parent $target) | Out-Null
    Copy-Item -LiteralPath $file -Destination $target
}
docker build --network none --pull=false -f output/competition-run-summary-312/Dockerfile -t lima:issue312-test output/competition-run-summary-312/context
docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 2 --pids-limit 128 --tmpfs /tmp:rw,size=128m lima:issue312-test
```

If a Python build lacks the tar data filter, use a current patched Python 3.11+.
The Windows tar utility on this machine failed to extract some Chinese filenames;
Python extraction completed successfully before the final image was built.

The additional generated acceptance driver is preserved locally at
`output/competition-run-summary-312/acceptance.py`. It creates only synthetic
inputs and uses real subprocess calls to the new script. Reproduction with a
fresh volume and fresh output directory (PowerShell):

```powershell
$auditRoot = (Resolve-Path output/competition-run-summary-312).Path
$driver = Join-Path $auditRoot 'acceptance.py'
$evidence = Join-Path $auditRoot 'evidence'
docker volume create lima-issue312-synthetic-inputs
docker run --rm --user 0:0 --read-only --network none --cap-drop ALL --security-opt no-new-privileges --tmpfs /tmp:rw,size=128m --mount 'type=volume,source=lima-issue312-synthetic-inputs,target=/inputs' --mount "type=bind,source=$driver,target=/issue312/acceptance.py,readonly" lima:issue312-test python acceptance.py prepare --inputs /inputs/fixtures
docker run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges --memory 512m --cpus 2 --pids-limit 128 --tmpfs /tmp:rw,size=128m --mount 'type=volume,source=lima-issue312-synthetic-inputs,target=/inputs,readonly' --mount "type=bind,source=$driver,target=/issue312/acceptance.py,readonly" --mount "type=bind,source=$evidence,target=/evidence" lima:issue312-test python acceptance.py verify --inputs /inputs/fixtures --output /evidence/new-results
```

Use a new volume name if fixtures already exist; fixture creation refuses to
overwrite. The root user is used only to create synthetic files in the fresh
volume; verification runs as UID 10001, with that volume mounted read-only.

## Verification record (2026-10-19, Asia/Shanghai)

- Frozen test SHA-256:
  `d7f6e6f496396c09b6adafb0f61363f9b3937439d199015458e31a7da70b014b`.
  Docker RED: missing implementation module, expected import failure. Frozen tests
  remained byte-identical throughout implementation.
  Publication preserves those tests in the separate commit
  `5cd8a4c095b5d37be63435e0a76825267d6ff1b8`, directly after the updated main.
- Docker专项：21 tests passed, zero failures/errors/skips.
- Related Docker regression command:
  `python -m unittest tests.test_competition_run_summary tests.test_openharmony_validation tests.test_competition_performance tests.test_ci_contract -v`.
  113 discovered, 111 executed successfully, 2 existing Windows Job Object cases
  skipped on Linux, zero failures/errors. The 21 new tests are included in 113.
  Git was copied offline from an existing local test image for the writer tests;
  no existing test or skip condition was modified.
- Before PR publication, the updated-main Docker run also included
  `tests.test_competition_coverage`: 134 discovered, 132 passed, the same 2
  Windows-only cases skipped, zero failures/errors (4.882 seconds). Product-code
  and frozen-test bytes remained unchanged when updating the main baseline.
- Actual CLI acceptance: 19 scenarios, 37 subprocess invocations, plus 3 explicitly
  identified usage/output checks included in those 37. Input write probe denied;
  hashes of 194 regular synthetic input files unchanged. Same-case pass/fail,
  legacy inconclusive, missing/unsupported performance, bad JSON/duplicate keys,
  conflicts, invalid metrics, duplicate labels/paths, output conflicts, symlink
  escape, non-regular files, formula escaping, and actual writer roundtrip passed.
  These invocations are a separate count from unittest cases.
- Linux amd64, Python 3.11.16, Docker Engine 29.2.1 / Desktop 4.65.0. Validation
  containers run as `lima:lima`, read-only root, network none, cap-drop ALL,
  no-new-privileges, explicit resource limits. Final containers exited 0 without OOM.
- Initial acceptance driver expected PermissionError for the write probe; Linux
  returned EROFS instead. Its error-code assertion was corrected and acceptance
  passed into a new directory. No product semantics or frozen tests were changed.
- Windows supplemental tests: 21 passed after selecting a workspace temp directory
  to avoid this desktop sandbox's default temporary-directory permission issue.
- Final-review supplemental CLI checks: 3 passed (lone-surrogate summary JSON,
  lone-surrogate manifest JSON, and a 4000-digit finite integer). They are recorded
  separately from the 19-scenario / 37-invocation acceptance and frozen unittest
  counts. The final regression and 19-scenario acceptance were repeated after
  adding the Unicode rejection; both passed with the counts above unchanged.

### Independent review (2026-10-19, Asia/Shanghai)

Reviewed implementation: `a4140a9e4a8ddbcb7bd2ea4655776e1c584b57a6`.
The [review comment](https://github.com/agent-sec-labs/LIMA/pull/317#issuecomment-6261370669)
records the two open findings and their reproductions.

- An independent Git archive snapshot passed
  `python -m unittest tests.test_competition_run_summary tests.test_competition_coverage tests.test_openharmony_validation tests.test_competition_performance tests.test_ci_contract -v`:
  134 tests in 111.375 seconds, zero failures/errors/skips on Windows.
- The reviewed head's [CI run](https://github.com/agent-sec-labs/LIMA/actions/runs/39193357109)
  had 12 successful jobs, including `merge-gate`. This is the status of the
  reviewed implementation, not a claim about subsequent commits.
- The script demos and a real `write_validation_bundle` synthetic fixture
  roundtrip passed. The fixture retained its status and commits, model identity
  stayed unknown, and input hashes were unchanged.
- Reading the existing local expat pilot bundle preserved its `failed` status,
  two vulnerable-side `semantic-supported` findings, and unknown model identity.
  This checked historical input compatibility; no vulnerability was re-executed.
- Both findings were reproduced separately from that passing suite. The review
  recommended fixing P2 before merge; both P2 and P3 now have the code corrections
  and new regression coverage described above. Independent re-review of those
  corrections is not implied by the earlier review results.

### Verification of review corrections (2026-10-19, Asia/Shanghai)

- Docker RED with the old product code and 27 test methods: two numeric-equivalence
  failures and the GBK diagnostic JSON parsing error reproduced. The original 21
  methods remained unchanged; six new methods capture the review requirements.
- After the fixes, the same five-module Docker regression found 140 tests:
  138 passed, 2 Windows-only Job Object cases skipped, zero failures/errors
  (7.533 seconds). All 27 run-summary tests passed without skips.
- Twelve real subprocess invocations exercised both entry points under GBK and
  UTF-8: numerically equivalent dual-side coverage remained parseable with the
  original failed status, emoji duplicate-label diagnostics parsed with the exact
  label, and output-write failures retained exit 3 and valid JSON. Input bundle
  bytes were unchanged.
- The existing 19-scenario / 37-call CLI acceptance passed again, including the
  real writer roundtrip. All 194 regular synthetic input hashes were unchanged,
  and the read-only input write probe was denied. These counts are separate from
  unittest and the twelve encoding/entry-point checks.
- Bandit and `git diff --check` passed. Product/test file hashes in the tested
  image match the worktree. Test containers used the same restricted Docker
  settings as the original validation, without network or new dependencies.
- Before these corrections, the documentation-only head `8b8b4d9` had an
  unrelated [C++ job failure](https://github.com/agent-sec-labs/LIMA/actions/runs/39211787487/job/117926583544):
  ECR returned HTTP 429 while fetching the base-image manifest, before any C++
  test executed. This PR does not change shared Docker/CI configuration to work
  around that registry failure. Earlier successful CI records do not imply the
  latest head has passed CI; subsequent run status must be checked separately.

Logs, actual tables, exported two-bundle demo, and generated acceptance driver are
under the ignored `output/competition-run-summary-312/` directory. Only the four
Issue allowlist files are source changes. The independent review evidence is
separate from those initial delivery records. Real OpenHarmony scanning, real
model identity, complete-bundle integrity, performance collection accuracy,
full-project regression, and merge remain outside the verified scope.
