# LIMA C/C++ Memory Vulnerability Detection Design

Date: 2026-08-26

## 1. Objective

Extend LIMA's bounded full-repository scan with layered C/C++ memory-safety
detection while preserving the project's evidence-first and fail-closed
principles.

The first release detects, but does not automatically repair:

- CWE-787: out-of-bounds write;
- CWE-125: out-of-bounds read;
- CWE-416: use after free;
- CWE-415: double free.

The feature initially applies only to the managed full-repository scan under
the configured `repositories/` import root. PR Diff analysis is a future
extension.

## 2. Scope and Non-Goals

### In scope

- C and C++ source/header inventory for `.c`, `.cc`, `.cpp`, `.cxx`, `.h`,
  `.hh`, `.hpp`, and `.hxx` files.
- A source-only candidate layer implemented with Semgrep.
- A build-backed static layer implemented with Clang Static Analyzer.
- An optional dynamic confirmation layer implemented with AddressSanitizer.
- Linux container execution with automatic CMake support and administrator-
  configured build/test steps.
- Explicit reporting of analysis mode, tool status, degradation, and coverage.
- Synthetic fixtures and pinned public vulnerable/fixed project pairs.

### Out of scope

- Automated repair of C/C++ memory findings.
- PR Diff C/C++ memory analysis.
- Windows/MSVC, Bazel, Meson, or arbitrary build-system auto-detection.
- Fuzzing, exploit generation, or proof-of-concept weaponization.
- Claims of completeness, zero false positives, or zero-day discovery.
- A new in-house pointer, alias, ownership, or interprocedural CPG engine.

## 3. Evidence Model

LIMA must distinguish the mechanism that produced evidence from the conclusion
strength. `Finding` and `EvidenceRecord` gain the following backward-compatible
evidence fields with safe defaults:

```python
language: str = ""
symbol: str = ""
analysis_mode: str = ""
```

`Finding` additionally gains a tri-state repair policy:

```python
automatic_repair: Optional[bool] = None
```

`None` preserves the existing Python rule-based eligibility behavior. C/C++
memory findings explicitly set `False`, which is a hard denial. A future `True`
value may describe tool capability but must never bypass `SafeFixer`'s existing
rule, verification, repository authorization, Oracle, and test gates.

Allowed C/C++ analysis modes are:

| Analysis mode | Meaning |
|---|---|
| `source-only` | No successful target build was used. The result is a candidate. |
| `build-backed` | A valid build configuration and Clang analysis produced evidence. |
| `sanitizer-confirmed` | An authorized test run produced a parsed ASan failure. |

Evidence strength maps to verification state as follows:

| Evidence | `analysis_mode` | `verification_state` |
|---|---|---|
| Semgrep only | `source-only` | `candidate` |
| Clang report with successful compilation context | `build-backed` | `build-verified` |
| Semgrep and Clang agree on a conservative identity | `build-backed` | `build-verified` |
| Parsed ASan reproduction | `sanitizer-confirmed` | `confirmed` |

`RepositoryScanner.VERIFICATION_RANK` treats `build-verified` at the same rank
as `dataflow-verified`, without changing the meaning of existing Python states.
The report always prints the analysis mode separately.

Every C/C++ memory Finding has `automatic_repair=false`. `SafeFixer` and repair
preview must reject it before rule matching, even if a future rule identifier
accidentally overlaps an existing supported rule.

## 4. Architecture

The main LIMA container must not receive the Docker socket or permission to
start sibling containers. A dedicated Compose sidecar performs native-code
analysis:

```text
Repository Scan API
        |
        v
ReviewService -> RepositoryScanner
                       |
                       v
              CxxMemoryAnalyzerAdapter
                       |
                 internal HTTP
                       |
                       v
               lima-cxx-analyzer
                 |      |      |
              Semgrep  Clang   ASan
```

Both services receive the same repository import directory as a read-only
mount. The analyzer resolves only validated repository keys below that mount,
copies the selected snapshot into an isolated temporary work area, and never
writes into the imported repository.

The analyzer service is attached only to a Compose internal network shared
with LIMA. It has no published host port and no outbound network route. LIMA
may remain attached to its normal application network for configured GitHub or
LLM access.

## 5. Components and Files

### Main application

- `lima/cxx_memory.py`
  - versioned sidecar client;
  - request/response validation;
  - tool-output normalization boundary;
  - CWE and ASan error mapping;
  - conversion to `Finding` and `EvidenceRecord`.
- `lima/repository_scanner.py`
  - detect whether the inventory contains C/C++ files;
  - invoke the adapter according to mode;
  - conservatively merge normalized C/C++ findings;
  - record tool status and coverage in report collaboration metadata.
- `lima/models.py`
  - add the backward-compatible evidence fields.
- `lima/config.py`
  - parse and validate analyzer mode, URL, budgets, and trusted build steps.
- `lima/service.py`
  - expose C/C++ scan capabilities and configured layer availability.
- `lima/report.py` and `web/app.js`
  - display language, analysis mode, verification state, tool evidence, and
    degradation reasons.

### Analyzer sidecar

- `cxx_analyzer/server.py`: internal HTTP server and request validation.
- `cxx_analyzer/source_scan.py`: Semgrep orchestration.
- `cxx_analyzer/build_scan.py`: CMake and Clang Static Analyzer orchestration.
- `cxx_analyzer/sanitizer_scan.py`: ASan build/test execution and parsing.
- `cxx_analyzer/normalizers.py`: versioned normalized finding schema.
- `cxx_analyzer/rules/cxx-memory.yml`: narrow source-only candidate rules.
- `cxx_analyzer/Dockerfile`: pinned Semgrep and LLVM/Clang toolchain.

### Tests and data

- `tests/test_cxx_memory.py`: client, schema, normalization, fusion, and failure
  behavior.
- `tests/fixtures/cxx_memory/`: synthetic vulnerable and safe C/C++ programs.
- `evaluation_data/cxx_memory_cases.json`: pinned public vulnerable/fixed pairs.
- `scripts/run_cxx_memory_evaluation.py`: reproducible evaluation runner.

## 6. Sidecar Protocol

The sidecar exposes an internal-only endpoint:

```http
POST /v1/analyze
```

Request schema:

```json
{
  "request_id": "uuid",
  "repository_key": "team/project",
  "snapshot_sha256": "hex-sha256",
  "requested_layers": [
    "source-only",
    "build-backed",
    "sanitizer-confirmed"
  ]
}
```

The endpoint never accepts an absolute path, shell fragment, environment map,
or arbitrary command. Repository keys use the same normalization rules as
`RepositoryImportPolicy` and are independently revalidated by the sidecar.

Response schema:

```json
{
  "schema_version": 1,
  "request_id": "uuid",
  "status": "completed",
  "snapshot_sha256": "hex-sha256",
  "tool_runs": [],
  "findings": [],
  "coverage": {},
  "diagnostics": []
}
```

Each normalized finding contains CWE, rule identifier, severity, language,
path, primary line, symbol, explanation, bounded evidence, analysis mode,
tool name, and optional trace frames. Unknown fields are rejected for schema
version 1. Unknown schema versions, unknown CWEs, snapshot mismatch, invalid
paths, or an incorrect request ID cause the entire response to be rejected.

## 7. Configuration

The main service accepts:

```text
LIMA_CXX_MEMORY_MODE=auto|off|required
LIMA_CXX_ANALYZER_URL=http://cxx-analyzer:8090
LIMA_CXX_ANALYSIS_TIMEOUT_SECONDS=300
LIMA_CXX_MAX_RESPONSE_BYTES=2097152
```

The sidecar accepts administrator-controlled configuration:

```text
LIMA_CXX_AUTO_CMAKE=true
LIMA_CXX_BUILD_STEPS_JSON=[]
LIMA_CXX_TEST_STEPS_JSON=[]
LIMA_CXX_MAX_MEMORY_MB=2048
LIMA_CXX_MAX_PROCESSES=128
LIMA_CXX_MAX_OUTPUT_BYTES=1048576
```

Build and test steps are JSON arrays of argument arrays, for example:

```json
[
  ["cmake", "-S", ".", "-B", "build", "-DCMAKE_BUILD_TYPE=Debug"],
  ["cmake", "--build", "build", "--parallel", "2"]
]
```

Every step is executed with `shell=false`, a cleaned environment, a fixed
working directory below the temporary snapshot, and an individual timeout.
No request-time command override is supported.

Mode behavior:

- `off`: skip C/C++ memory analysis.
- `auto`: continue the repository scan if the sidecar is unavailable; retain
  source-only findings when build or dynamic layers fail.
- `required`: fail the repository scan when the sidecar or required protocol is
  unavailable. A target build failure remains a recorded analysis result rather
  than an infrastructure failure, so source-only results are still returned.

## 8. Analysis Pipeline

1. `RepositoryWorkspace` produces its bounded inventory and snapshot hash.
2. `RepositoryScanner` skips the sidecar when no supported C/C++ files exist.
3. LIMA sends the validated key, snapshot hash, requested layers, and request ID.
4. The sidecar resolves the key, rejects symlink escapes, independently computes
   the snapshot hash, and copies regular files into a temporary work directory.
5. Semgrep always runs first when source-only analysis is requested.
6. If `CMakeLists.txt` exists and automatic CMake is enabled, the sidecar uses
   fixed CMake argument arrays. Otherwise it uses administrator-configured steps.
7. A successful build context permits Clang Static Analyzer execution.
8. ASan is enabled only when trusted test steps are configured. A test failure
   without a recognized sanitizer report is diagnostic information, not a
   memory vulnerability.
9. The sidecar normalizes and bounds outputs, recomputes the snapshot identity,
   and returns the response.
10. LIMA validates the complete response before accepting any finding.
11. LIMA merges evidence only when CWE, normalized path, symbol, and primary
    location agree. Ambiguous matches remain separate.
12. The existing report and store persist accepted results and analysis metadata.

## 9. Source-Only Rules

Source-only rules are deliberately narrow and never claim confirmation. Initial
candidate shapes include:

- fixed-size buffers passed to unbounded copy/format APIs;
- `memcpy`/`memmove` length expressions with an evident destination-size
  mismatch;
- local, same-function use of a pointer after an unconditional `free` without
  an intervening assignment;
- local, same-function repeated `free` without an intervening assignment;
- direct constant array indexes that are outside a statically known bound.

Broad rules such as reporting every `memcpy`, pointer dereference, array index,
or `free` are prohibited because they would make the source-only layer unusable.

## 10. ASan Mapping

Recognized dynamic evidence maps as follows:

| ASan classification | Additional signal | CWE |
|---|---|---|
| `heap-buffer-overflow` / `stack-buffer-overflow` / `global-buffer-overflow` | write access | CWE-787 |
| the same overflow classes | read access | CWE-125 |
| `heap-use-after-free` | any access | CWE-416 |
| `attempting double-free` | free operation | CWE-415 |

Unrecognized sanitizer failures become bounded diagnostics with
`needs-human-review`; they are not coerced into one of the four CWEs.

## 11. Security Controls

The analyzer executes authorized but potentially hostile build logic. Its
container therefore requires:

- non-root user;
- read-only root filesystem;
- writable size-limited tmpfs only for work and temporary files;
- no Docker socket;
- no published port;
- internal-only Compose network with no outbound route;
- all Linux capabilities dropped;
- `no-new-privileges`;
- memory, CPU, process, file-size, output-size, and wall-clock budgets;
- cleaned environment with no LIMA, GitHub, LLM, database, proxy, or user
  secrets;
- no following of imported repository symlinks;
- archive/path containment checks at every copy boundary.

The main LIMA service treats sidecar output as untrusted. It validates response
size, JSON shape, schema version, identifiers, paths, line numbers, enums,
snapshot identity, and request correlation before persistence.

## 12. Failure Semantics

- Sidecar unavailable in `auto`: Python and other scans continue; the report
  records `cxx_memory.status=unavailable`.
- Sidecar unavailable in `required`: the task fails.
- Semgrep failure: record failure; never report this as a clean scan.
- Build failure: retain source-only candidates and record `build_failed`.
- Clang timeout or malformed output: do not promote any candidate.
- Test failure without ASan evidence: record test failure only.
- Unparseable ASan crash: record `needs-human-review` only.
- Output cap reached: retain structured summaries and hashes; mark raw logs as
  truncated.
- Snapshot mismatch, unsafe path, unknown schema/CWE, or response over size:
  reject the complete sidecar response.

## 13. Reporting and API Behavior

Repository scan capabilities report:

- whether the sidecar is configured and reachable;
- selected C/C++ mode;
- supported file extensions and CWEs;
- source, build, and sanitizer layer availability;
- whether build and test steps are configured;
- `automatic_repair=false`.

The Markdown and Web reports show, for every C/C++ finding:

- language and symbol;
- CWE and primary location;
- analysis mode in user-facing language;
- verification state;
- contributing tools;
- bounded trace/evidence;
- explicit warning for source-only candidates;
- build or sanitizer degradation reason;
- statement that automatic repair is unsupported.

## 14. Testing and Evaluation

### Unit tests

Cover Semgrep, Clang, and ASan normalization; response validation; CWE mapping;
evidence fusion; verification rank; source-only labeling; timeout/unavailable
behavior; output limits; snapshot mismatch; unsafe paths; and repair exclusion.

### Synthetic fixtures

Create at least three vulnerable and three safe/fixed scenarios for each of the
four CWEs, for at least 24 scenarios total. Each fixture records expected CWE,
path, symbol, allowed detection layers, and whether ASan confirmation is
expected.

### Public vulnerable/fixed pairs

Select at least one public pair for each CWE. Pin project, vulnerable and fixed
commits, archive SHA-256, upstream advisory/CVE, affected path and symbol, build
steps, test/reproduction entry, and selection rationale. Both halves of every
pair run in evaluation.

### CI

Windows/Linux Python CI uses mocked sidecar responses and requires no LLVM.
Ubuntu container CI builds the analyzer image, runs synthetic fixtures, and
tests LIMA-to-sidecar integration with networking and resource restrictions.

### Metrics

Record precision, recall, F1, vulnerable/fixed pair accuracy, false alerts per
KLoC, candidate count by layer, build-backed coverage, sanitizer-confirmed
coverage, build success rate, analysis duration, and timeout rate.

## 15. Acceptance Criteria

- Every accepted C/C++ finding displays an explicit analysis mode.
- Source-only results never exceed `candidate`.
- The four recognized ASan categories map to the intended CWEs.
- Build failure retains source-only candidates and a visible degradation reason.
- Fixed versions do not inherit vulnerable-version `confirmed` findings.
- Snapshot mismatch and unsafe paths reject the response.
- Request payloads cannot introduce commands or environment variables.
- C/C++ memory findings cannot enter automatic repair or preview.
- The sidecar has no Docker socket, host port, outbound route, root user, or
  additional Linux capabilities.
- Existing Python scan behavior and the current 165-test suite do not regress.
- Evaluation output reports limitations and does not equate synthetic fixture
  success with real-world completeness.

## 16. Rollout Order

1. Backward-compatible data model, protocol types, and mocked client tests.
2. Source-only sidecar layer and synthetic CWE fixtures.
3. Compose integration, security controls, and repository scanner adapter.
4. CMake/Clang build-backed layer.
5. ASan test layer and parser.
6. Markdown/Web reporting and capabilities API.
7. Pinned public vulnerable/fixed pairs and reproducible evaluation report.
8. Optional `auto` rollout first; enable `required` only after operational
   reliability is measured.
