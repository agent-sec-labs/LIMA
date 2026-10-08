# Baseline analyzer implementation identity

New B1 offline, local LlamaFactory and gated B1-real baseline configurations
record an `implementation` manifest before computing scanner_config_sha256,
analyzer_fingerprint and run_spec_digest. Previously these identities depended
only on the analyzer name and configuration; a changed scanner implementation
could produce different behavior under the same run identity (#57).

The scheme `lima-python-source-v1` hashes each installed LIMA Python source
file using its package-relative path and UTF-8 source with universal newline
normalization. The complete Python source bundle is included conservatively
because shared helpers and inline security rules can affect output. Unrelated
changes inside that bundle also invalidate the identity; documentation outside
the bundle, Git refs, checkout locations and bytecode caches do not. The local
manifest also records Python's implementation and major/minor/patch version,
because the stdlib parser is part of the executing analyzer. The local
baseline disables external SAST, sidecar and model scanners; this manifest is
not a claim about the implementation identity of those disabled external tools.

Source installation is required. Missing essential scanner modules or linked
source entries fail instead of silently returning a configuration-only identity.
The manifest is recomputable provenance, not an authenticity signature. Code
must remain unchanged during a baseline run, as must the approved configuration.

No top-level sealed schema, receipt field set, sample accounting, scanner
behavior, budget or privacy contract changes. The existing config digest binds
the additive manifest and propagates the new identity through every attempt and
report. Historical evidence keeps its own recorded config and digests: read-back
does not replace its identity with today's source manifest. Historical identity
without an implementation manifest remains legacy evidence and cannot establish
implementation-version equality for new comparisons.

The B1-real catalog computes its new configuration pin from the same source
manifest as its runner. An old cost-bearing approval does not authorize a new
implementation/configuration pin; its historical evidence remains readable,
while a new execution needs an approval matching its new pin. This repair does
not run or authorize any real model requests, rewrite historical artifacts or
close #57, #62 or #264.

Regression coverage includes source/rule changes, added helpers, checkout and
newline portability, independent source digest and process agreement, B1/LF
run identity propagation, and historical artifact read-back. The B1-real config
mirror is updated only for this additive identity contract; its execution,
budget, rejection and canonical projection assertions remain in place.
