# Offline readiness probes for #264 and #93

Run from the repository root with the normal locked runtime dependencies. These
commands accept neither a live model endpoint/credential nor a target repository.
Outputs must be new paths; an earlier or failed run remains available for review.

```sh
python -m benchmarks.v4.preflight.investigation --output output/investigation-preflight
python -m benchmarks.v4.preflight.investigation --verify output/investigation-preflight
python -m benchmarks.v4.preflight.profile_consumer --output output/profile-consumer.json
python -m unittest tests.test_investigation_preflight tests.test_profile_consumer_preflight -v
```

## #264: service-chain rehearsal before paid model acceptance

The four fixtures traverse the real local import policy, repository scanner,
queue, investigator/tool registry, merge and SQLite report store. Only the chat
transport returns scripted actions; socket connections are denied during each
scan. All settings are constructed explicitly, without loading credentials or
live database/queue URLs from environment variables. Fixtures are read, never
imported or executed. The dynamic tool executes its existing canned synthetic
contrast in an isolated interpreter.

| Case | Persisted behavior required |
| --- | --- |
| dynamic-observation | Canned contrast succeeds and its output feeds the next production prompt; the unresolved static finding remains with critical risk and needs_review |
| module-discovery | Zero static findings; observed source supports one AGENT-DISCOVERY candidate at the exact path/line, with high risk and needs_review |
| module-timeout | No finding invented; failure remains visible, with low risk and needs_review as separate dimensions |
| dynamic-tool-error | Unknown contrast sample produces visible error feedback; static evidence is retained and the final verdict stays insufficient |

The bundle contains the inert fixture, inventory snapshot digest, scripted prompt
and action transcript, persisted report and artifact SHA-256 hashes. Verification
checks both hashes and case invariants; changed runtime source bytes invalidate
the bundle. Hashes establish local consistency, not an authenticated signature.

`scripted_transport_calls` and `reserved_budget_requests` include the scripted
timeout attempt. The production report's `usage.requests` counts returned
responses, so that timeout records zero there. `real_model_requests` is always
zero. The report's fake provider usage and scripted tool choice must not be used
as real model evidence.

This prepares the software path and evidence layout for #264 acceptance 3②/4.
It does not demonstrate autonomous real-model tool choice or real-model discovery.
Those remain open and require a separately budgeted real-model run and independent
review of its source, tool observations and final report.

## #93: public Profile consumption boundary

`consume_profile` calls the existing public Profile envelope decoder and checks
the expected tenant, snapshot, task, workflow, stage attempt and artifact identity.
The public codec checks schema, payload digest, protected classification and source
lineage. These checks are not authentication of the producer.

The consumer returns every exact or lexical directory-prefix role match, its
reason codes and source artifact references. It does not prefer a role or apply
qualification policy. Different overlapping roles remain ambiguous; absent roles,
partial/unsupported profiles and coverage gaps require context. A missing role
never becomes an invented production role. Query paths are canonical relative
POSIX paths and must stay within the Profile's component scope.

The CLI builds a real Profile using `lima.audit.build_repository_profile`, checks
that the inert fixture stays unchanged, then consumes its wire envelope. Tests
also consume the existing frozen producer fixture, cover every public role using
explicit valid contract assignments, and reject tampering, wrong identities,
unrecognized role values, lost lineage and component escapes. The all-role cases
test codec consumption; they do not claim the classifier inferred those roles.

The output preserves `qualification=not-run`. #93 still needs its engine/rule
policy, source-control/path evidence, severity ceilings and QualificationResult
implementation. Profile roles alone cannot clear a finding or prove a sink safe.

## Ownership

These probes add only `benchmarks/v4/preflight/` and two separate test modules.
They consume #60's public interfaces and fixtures read-only. They do not change
#60 implementation, frozen tests, implementation packets, identifiers or Ledger;
they do not change #264's frozen investigation modules or tests. #266's Docker
packaging repair is delivered separately on that PR's own branch.
