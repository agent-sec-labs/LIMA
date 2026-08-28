# Task 5 implementation report

## RED / GREEN

- RED: `python -m unittest tests.test_cxx_analyzer.SourceScanTests -v` failed as
  expected before implementation with `ModuleNotFoundError: No module named
  'cxx_analyzer.normalizers'`.
- GREEN: `python -m unittest tests.test_cxx_analyzer.SourceScanTests -v` passed:
  2 tests passed initially, then 3 tests passed with the host Semgrep regression
  test skipped because Semgrep could not start.

## Commands and results

- `python -m unittest tests.test_cxx_analyzer.SourceScanTests -v` — PASS,
  3 tests, 1 skipped (installed Semgrep exits with Windows X.509-store fatal error).
- `python -m unittest tests.test_cxx_analyzer -v` — PASS, 27 tests, 7 skipped.
- `python -m unittest discover -s tests -v` — PASS, 224 tests, 8 skipped.
- `python -m ruff check cxx_analyzer tests/test_cxx_analyzer.py` — PASS.
- `python -m compileall -q cxx_analyzer` — PASS.
- `git diff --check` — PASS.
- Fixture compilation attempted with `clang` / `clang++` and could not run:
  neither compiler is installed on this host.
- `docker version --format '{{.Server.Version}}'` could not reach the Docker
  daemon, so the Sidecar-image Semgrep check could not run.

## Self-review

- `NormalizedFinding` is frozen; its serializer emits only the exact 17 client
  finding fields.  Source-only findings are fixed to Semgrep + candidate state,
  and all output strings plus non-response trace are byte-bounded with bounded
  diagnostic labels.
- The Semgrep parser requires a fixed narrow-rule prefix, matching CWE metadata,
  explicit candidate metadata, a scanned safe relative POSIX path, and a positive
  integer line.  Malformed tool output is rejected rather than normalized.
- Rules are limited to three fixed-index or same-pointer release/reuse forms per
  CWE; they do not match all `memcpy`, `free`, or array-index expressions.
- `run_source_scan` stages the packaged config in a unique analyzer temporary
  directory outside the prepared snapshot, invokes Semgrep through Task 4
  `run_step`, never returns raw tool output, and declines to create findings
  from failed, truncated, digest-incomplete, or parser-rejected output.

## Concerns

- Real Semgrep fixture execution remains unverified here: the installed Semgrep
  binary fails during startup with `Failed to create system store X509 authenticator`.
- No local C/C++ compiler or usable Docker daemon was available, so fixture
  compilation and the required Linux/Landlock Sidecar run must be performed in
  the image task.

## Fix round 1 — blocking review findings

### RED / GREEN

- RED: after adding behavior checks for three genuinely distinct bounded OOB
  object shapes and same-variable pointer rebinding controls,
  `python -m unittest tests.test_cxx_analyzer.SourceScanTests -v` failed as
  expected: 7 tests ran, 2 failed, and 1 real-Semgrep test was skipped. The
  failures showed that the rules still used a third native-array variant and
  had no rebinding exclusion.
- GREEN: after changing the third OOB shape to a fixed-size `std::array`, adding
  same-variable reassignment exclusions to every UAF/double-free form, and
  adding matching rebinding-safe fixtures, the same command passed: 7 tests
  ran, 1 skipped, 0 failures/errors.

### Changes addressing the five blocking findings

- Rules are staged in a unique temporary directory under the analyzer temp
  root, outside `PreparedSnapshot`; a legitimate inventory file named
  `.lima-semgrep-rules.yml` is neither overwritten nor deleted, and the staged
  file is removed on successful, failed, truncated, digest-incomplete, and
  parser-rejected paths.
- `rule_id`, `cwe`, `path`, and `symbol` are rejected before serialization when
  they exceed the identity field limit. They are never truncated into a
  different rule, unsupported CWE, unsafe/nonexistent path, or ambiguous
  symbol.
- CWE-787 and CWE-125 fixtures now use three object-bound forms: a native fixed
  array, a fixed heap allocation, and `std::array`. Each vulnerable index is at
  the known bound; each paired safe fixture uses a larger known bound.
- Each UAF and double-free rule permits intervening statements but excludes an
  assignment to the same pointer variable between release and access/release.
  All six safe fixtures are same-form rebinding controls.
- Direct `run_source_scan` tests assert the exact Task 4 `run_step` argv,
  `PreparedSnapshot` identity, relative cwd, timeout, output limit, and clean
  environment. They also cover failed, timed-out, truncated,
  digest-incomplete, parser-failure, collision, and temporary-rule lifecycle
  behavior.

### Exact verification commands and results

- `python -m unittest tests.test_cxx_analyzer.SourceScanTests -v` — PASS,
  7 tests, 1 skipped because the installed Semgrep cannot start.
- `python -m unittest tests.test_cxx_analyzer -v` — PASS, 31 tests, 7 skipped.
- `python -m unittest discover -s tests -v` — PASS, 228 tests, 8 skipped.
- `python -m ruff check cxx_analyzer tests/test_cxx_analyzer.py` — PASS,
  `All checks passed!`.
- `python -m compileall -q cxx_analyzer` — PASS, exit 0 with no output.
- `python -c "import yaml, pathlib; data=yaml.safe_load(pathlib.Path('cxx_analyzer/rules/cxx-memory.yml').read_text(encoding='utf-8')); assert len(data['rules']) == 4; print('YAML OK: 4 rules')"`
  — PASS, `YAML OK: 4 rules`.
- `git diff --check` — PASS, exit 0; only checkout line-ending warnings were
  printed.
- `semgrep --json --quiet --config D:\Projects\LIMA\.worktrees\cxx-memory-detection-impl\cxx_analyzer\rules\cxx-memory.yml .`
  from `tests/fixtures/cxx_memory` — unavailable, exit 1 before rule loading:
  `Fatal error: ... Failed to create system store X509 authenticator`.
- `where.exe clang`, `where.exe clang++`, `where.exe gcc`, `where.exe g++`, and
  `where.exe cl` — no compiler found, so local fixture compilation remains
  unavailable.
- `docker version --format '{{.Server.Version}}'` — unavailable: the Docker
  daemon named pipe does not exist.

The independent dirty `Dockerfile` and `tests/test_service.py` CI fixes were
preserved but excluded from this Task 5 change set.
