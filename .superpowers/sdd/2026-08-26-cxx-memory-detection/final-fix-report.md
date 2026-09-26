# Final C/C++ whole-branch fix report

Branch: `codex/cxx-memory-detection-impl`

Fix-wave base: `6670cb985747d273cd8e816a0a69b5058c5aebcc`

Commit range: `6670cb9..HEAD`

## Status

- Resolved: **2 Critical + 11 Important** findings from `final-review-report.md`.
- Unresolved Critical/Important: **none**.
- Preserved protocol/product constraints: exactly four analyze-request fields, fail-closed
  sandboxing and protocol acceptance, no C/C++ automatic repair, no evaluation case-ID
  hardcoding, and no invented Docker/ASan/evaluation results.
- Protected pre-existing changes remain outside this wave: root `Dockerfile` and
  `tests/test_service.py`.

## Finding-by-finding resolution and regression evidence

The “review/RED evidence” column records the concrete pre-fix failure identified by the final
review or a RED test observed during this wave. Raw earlier RED transcripts were not persisted in
the repository, so this report does not invent aggregate pre-fix run counts.

| Finding | Review/RED evidence before correction | Resolution | Green guardrail |
|---|---|---|---|
| Critical 1 — mutable verified source | The snapshot root was granted `READ_WRITE_TREE`; later layers could analyze bytes different from the fingerprint. | The verified source tree is mode-frozen and Landlock read-only. Only request-owned `build` and `scratch` roots are writable. Inventory identity/type/size/SHA is rechecked before, between, and after layers. | `test_verified_source_is_read_only_and_only_request_owned_roots_are_writable`; real WSL `test_tool_cannot_mutate_inventory_but_can_write_analyzer_build_output`. |
| Critical 2 — descendants and shared scratch | Descendants were killed only after timeout and all requests shared `/work/tmp`. | Every snapshot owns private scratch/HOME/TMPDIR. A seccomp denylist blocks process-group escape and same-UID process control. The supervisor kills the whole process group and reaps the leader on success, failure, and timeout. | `test_each_snapshot_owns_distinct_private_scratch_and_environment`; real WSL `test_success_failure_and_timeout_reap_all_descendants_even_after_setsid_attempt`. |
| Important 1 — renewable layer timeouts | Source, build, and sanitizer could each start a new total budget. | One `AnalysisDeadline` is created at request entry and passed through snapshot discovery/copy, source, build, Clang, sanitizer, identity checks, and cleanup. | `test_one_entry_deadline_is_passed_to_snapshot_and_every_requested_layer`; `test_expired_deadline_prevents_semgrep_launch`. |
| Important 2 — header/language drift | Headers were omitted by Semgrep/coverage and several C++ header suffixes fell back to C. | One Sidecar map covers `.c/.h/.cc/.cpp/.cxx/.hh/.hpp/.hxx`; Semgrep includes all suffixes and Clang/ASan/coverage reuse the map. | `test_one_language_map_covers_sources_and_all_header_suffixes`. |
| Important 3 — response not bound to local inventory | Main accepted syntactically safe paths without proving membership, line range, language, or coverage. A later audit RED also showed JSON `null` leaked a raw `TypeError` before structural validation. | Main sends a request-private `WorkspaceInventory`, preserves fingerprint semantics, validates every finding structurally first, then binds coverage/path/line/language to the local inventory before converting any finding. | `test_client_rejects_path_line_language_and_coverage_not_bound_to_local_inventory`; `test_invalid_response_rejects_the_entire_payload` (non-object finding). |
| Important 4 — open tool-run state machine | Producer-only sandbox statuses could cross the boundary and contradictory status/return-code/digest records were accepted. | Producer constructors map all internal executions to the closed v1 states; consumer validation enforces status, return code, digest completeness, and truncation invariants. | `test_internal_sandbox_states_are_mapped_to_protocol_failures`; `test_tool_run_state_machine_rejects_cross_field_contradictions`. |
| Important 5 — layered evidence loss | Sidecar fusion replaced lower-layer Semgrep/Clang evidence with the strongest layer. | Sidecar preserves distinct same-identity tool/rule layers; main remains the presentation-fusion boundary. | `test_sidecar_keeps_all_same_identity_layers_for_main_boundary_fusion`. |
| Important 6 — finding/tool-run budget mismatch | Strong findings could survive while their late ASan run record was truncated. | One evidence-aware response budget reserves a protocol-compatible tool run for every retained finding and drops/diagnoses unsupported findings. | `test_response_budget_keeps_tool_evidence_for_every_retained_finding`. |
| Important 7 — non-authoritative health | Health accepted incomplete Clang installations and main treated URL presence as capability. Audit RED additionally showed sanitizer could be advertised with test config but no build context. | Sidecar probes the exact `clang-14` + `clang++-14` pair and returns strict versioned tool/config booleans. Main strictly parses and caches successful health; displayed layer capability comes from health, and sanitizer now requires both build and test configuration. | `test_health_requires_exact_clang_driver_pair_and_reports_safe_configuration`; `test_main_health_probe_is_strict_cached_and_capabilities_are_authoritative`; `test_sanitizer_capability_requires_build_and_test_configuration`. |
| Important 8 — ignored Semgrep errors/broad skip | JSON `errors` were ignored and any Windows exit-2 text containing generic `Fatal error:` could skip tests. | Semgrep errors are bounded, validated, and make the layer fail; only the exact Windows X509 store startup failure is recognized as host unavailability. | `test_semgrep_errors_are_bounded_and_make_the_source_layer_incomplete`; `test_only_exact_windows_x509_semgrep_startup_failure_is_skippable`. |
| Important 9 — Markdown context injection | Fixed fences and unescaped tool text could close evidence blocks, create headings, or inject raw HTML. Audit RED confirmed an explanation beginning directly with `#` still created a heading. | C/C++ prose is single-line and HTML escaped, line-leading Markdown block constructs are neutralized, inline code uses adaptive delimiters, and evidence uses a fence longer than any contained backtick run. | `test_markdown_contexts_cannot_be_closed_or_injected_by_tool_text`. |
| Important 10 — download deadline overrun | A fixed socket timeout and 1 MiB read could exceed the total deadline. | Before every 64 KiB read, the underlying socket timeout is rebound to the smaller of the socket timeout and remaining absolute budget; unsupported socket access fails closed and partial files are removed. | `test_each_download_read_rebinds_socket_timeout_to_remaining_deadline` plus the archive deadline/cleanup tests in `tests.test_cxx_memory_evaluation`. |
| Important 11 — missing image identity/provenance | Evaluator could write a null image digest and the image lacked auditable package manifests. | Evaluator requires exact `sha256:<64 lowercase hex>` host-obtained Docker image ID. CI obtains `.Id` with `docker image inspect`. The analyzer image writes sorted Debian and Python package manifests; docs state that apt repositories are not snapshot-pinned. | `test_evaluator_requires_explicit_ci_obtained_image_identity`; CLI valid/invalid digest check; CI/Dockerfile contract tests. |

## Fresh verification on the final production state

| Check | Result |
|---|---|
| Focused final regressions | `python -m unittest tests.test_cxx_final_fixes -q` — **20 run: 18 passed, 2 skipped on Windows**. |
| Related C/C++ suites | `python -m unittest tests.test_cxx_memory tests.test_cxx_memory_evaluation tests.test_cxx_analyzer -q` — **126 run: 117 passed, 9 skipped**. |
| Full Windows suite | `python -m unittest discover -s tests -q` — **328 run: 316 passed, 12 skipped**. The existing OpenTelemetry “Overriding of current TracerProvider” messages were non-failing output. |
| Real Linux Critical checks | WSL run of the two Critical security tests — **2 passed** in 6.831s. This proves source-mutation denial/build-output writability and descendant cleanup across success/failure/timeout. |
| Compilation | `python -m py_compile` over all Sidecar modules and `tests/test_cxx_final_fixes.py` — passed. |
| Wave lint | Ruff over every changed Sidecar/evaluator/C/C++ regression file — `All checks passed!`. Comparing the five modified main-service files with `HEAD` found 90 pre-existing findings versus 89 now, so this wave adds no main-file Ruff debt. |
| Repository-wide lint | `python -m ruff check cxx_analyzer lima scripts tests --statistics` — still fails on **1,202 pre-existing repository findings**; this is outside the narrow final wave. |
| Serialized configuration | Parsed `.github/workflows/ci.yml`, `docker-compose.yml`, `cxx_analyzer/rules/cxx-memory.yml`, all five `evaluation_data/*.json` files, and both relevant fixture JSON files — passed. |
| Evaluator CLI | Exact lowercase Docker image ID accepted; uppercase/invalid digest rejected with argparse exit 2. |
| Compose | `docker compose config --quiet` — passed with non-production placeholder values for the three required secrets. |
| Docker image build | Attempted `docker build --file cxx_analyzer/Dockerfile --tag lima-cxx-analyzer-final-fix .` — **not runnable** because `dockerDesktopLinuxEngine` does not exist on this host. No build success is claimed. |

## Remaining concerns and environmental gaps

1. Docker Desktop’s Linux daemon is unavailable. Therefore this machine did not freshly build the
   analyzer image or rerun the Docker-hosted Semgrep/Clang/ASan fixtures, integration job, or public
   evaluation matrix. CI remains the authoritative environment for those checks.
2. Debian/Python manifests and exact image ID make provenance auditable, but Debian apt repository
   state is not snapshot-pinned; the documentation now states that limit explicitly.
3. Repository-wide Ruff is not clean. The final-wave Sidecar/evaluator/test surfaces are clean and
   the changed main files add no Ruff debt, but the existing 1,202 findings remain outside scope.
4. Root `Dockerfile` and `tests/test_service.py` remain dirty pre-existing user changes and are
   deliberately excluded from staging and commits.
