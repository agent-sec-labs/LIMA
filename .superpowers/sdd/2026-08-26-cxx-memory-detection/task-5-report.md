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
- `run_source_scan` writes the packaged config only inside the prepared snapshot,
  invokes Semgrep through Task 4 `run_step`, never returns raw tool output, and
  declines to create findings from failed, truncated, or digest-incomplete output.

## Concerns

- Real Semgrep fixture execution remains unverified here: the installed Semgrep
  binary fails during startup with `Failed to create system store X509 authenticator`.
- No local C/C++ compiler or usable Docker daemon was available, so fixture
  compilation and the required Linux/Landlock Sidecar run must be performed in
  the image task.
