"""Three-state Evidence Broker for UAF v2 candidates (plan Task 9).

Implements design section 11
(``docs/superpowers/specs/2026-09-10-cxx-uaf-v2-design.md``): for one
candidate identity and one producer the broker answers exactly
``support | contradict | no-evidence`` and attaches the evidence's own
``EvidenceLevel``/``EvidencePolarity`` as independent, separately
serialized fields -- a verdict never implies a fixed D-level and a level
never implies a verdict (design 11.1: no ``support`` auto-promotion to
D2, no level back-derivation from ``contradict``).

``contradict`` requires all five design 11.2 conditions at once:

1. exact candidate identity -- caller contract: ``records`` must already
   be collected for ``identity`` (the broker's evidence type carries no
   identity field of its own; the composite ``(snapshot_hash,
   candidate_id)`` key stays the caller's binding duty);
2. completed producer run -- the cited run id is in
   ``completed_run_ids`` (callers pass the ids of runs that actually
   finished; a producer that never ran contributes no records);
3. valid provenance -- each record carries its ``tool_run_id`` in its
   ``extensions["tool_run_id"]`` (the frozen contract evidence type has
   no dedicated run-id field; provenance lives in validated extensions
   until the wire contract grows one);
4. at least one record with ``EvidencePolarity.REFUTES``;
5. the ``ProofResult`` carries at least one obligation verdict of
   ``refuted`` (the refuted-obligation fact reference).

When a REFUTES record exists and any of the conditions fails, that record
degrades to ``no-evidence`` with the ``provenance-incomplete`` gap -- it
never blocks valid support and never flips into a contradiction.

``BROKER_IS_NOT_CONTRADICTION`` freezes the seven design 11.2 situations
that are never a contradiction (no report, uncovered witness, producer
not run/timeout/failure, different CWE at the same location, fuzzy
position matches, missing tool-run identity): they surface as
``no-evidence`` plus a coverage/binding gap from the binder or caller.
An empty tool result is never safety and never lowers a proof outcome.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from .contracts.evidence import EvidenceLevel, EvidencePolarity, EvidenceRecord
from .cxx_agent_models import _bounded_text
from .uaf_models import CandidateIdentity, ProofResult

__all__ = [
    "BROKER_IS_NOT_CONTRADICTION",
    "BROKER_VERDICTS",
    "BrokerVerdict",
    "broker_verdict",
]

BROKER_VERDICTS = frozenset({"support", "contradict", "no-evidence"})

# The seven design 11.2 situations in design order.  These are surfaced by
# the binder or the caller as coverage/binding gaps; none of them may be
# read as a refutation of the candidate (and none is safety either).
_NOT_CONTRADICTION_CONDITIONS = (
    ("semgrep-no-report", "Semgrep produced no report"),
    ("clang-no-report", "Clang Static Analyzer produced no report"),
    ("asan-witness-not-covered", "ASan ran but did not cover the witness path"),
    ("producer-run-not-completed", "tool did not run, timed out, or failed"),
    ("different-cwe-same-location", "another CWE reported at the same location"),
    ("fuzzy-position-match", "symbol/line/path only match fuzzily"),
    ("missing-tool-run-identity", "finding lacks a valid tool-run identity"),
)
BROKER_IS_NOT_CONTRADICTION = frozenset(
    code for code, _condition in _NOT_CONTRADICTION_CONDITIONS
)

_GAP_PROVENANCE_INCOMPLETE = "provenance-incomplete"
_RUN_ID_EXTENSION = "tool_run_id"
_REFUTED_OBLIGATION = "refuted"


@dataclass(frozen=True)
class BrokerVerdict:
    """One broker answer for one (identity, producer) pair.

    ``verdict`` and the evidence pair are orthogonal: ``support`` and
    ``contradict`` always carry the record's own level and polarity (no
    producer-name promotion), while ``no-evidence`` carries neither --
    a degraded REFUTES record is not surfaced as evidence.
    """

    identity: CandidateIdentity
    producer: str
    verdict: str
    evidence_level: EvidenceLevel | None
    evidence_polarity: EvidencePolarity | None
    gap: str = ""

    def __post_init__(self) -> None:
        if not isinstance(self.identity, CandidateIdentity):
            raise ValueError("identity must be a CandidateIdentity")
        _bounded_text(self.producer, "producer")
        if not isinstance(self.verdict, str) or self.verdict not in BROKER_VERDICTS:
            raise ValueError("verdict is outside the closed broker domain")
        if not isinstance(self.gap, str):
            raise ValueError("gap must be a string")
        if self.gap:
            _bounded_text(self.gap, "gap")
        if self.verdict == "no-evidence":
            if self.evidence_level is not None or self.evidence_polarity is not None:
                raise ValueError("no-evidence must not carry evidence level/polarity")
        else:
            if self.evidence_level is None or self.evidence_polarity is None:
                raise ValueError(f"{self.verdict} must carry evidence level/polarity")
            expected = (
                EvidencePolarity.SUPPORTS
                if self.verdict == "support"
                else EvidencePolarity.REFUTES
            )
            if self.evidence_polarity is not expected:
                raise ValueError(f"{self.verdict} polarity must be {expected.value}")

    def to_dict(self) -> dict:
        """Flat wire form with the four decision keys kept independent."""

        return {
            "snapshot_hash": self.identity.snapshot_hash,
            "candidate_id": self.identity.candidate_id,
            "producer": self.producer,
            "verdict": self.verdict,
            "evidence_level": (
                self.evidence_level.value if self.evidence_level is not None else None
            ),
            "evidence_polarity": (
                self.evidence_polarity.value
                if self.evidence_polarity is not None
                else None
            ),
            "gap": self.gap,
        }


def _record_run_id(record: EvidenceRecord) -> str:
    value = record.extensions.get(_RUN_ID_EXTENSION)
    return value if isinstance(value, str) and value else ""


def broker_verdict(
    identity: CandidateIdentity,
    producer: str,
    records: Iterable[EvidenceRecord],
    completed_run_ids: frozenset[str],
    proof_result: ProofResult | None,
) -> BrokerVerdict:
    """Answer support | contradict | no-evidence for one candidate identity.

    ``records`` must already be bound to ``identity`` by the caller (see
    the condition list in the module docstring).  Pure and deterministic;
    empty or unresolvable evidence is ``no-evidence`` -- never safety.
    """

    if not isinstance(identity, CandidateIdentity):
        raise ValueError("identity must be a CandidateIdentity")
    _bounded_text(producer, "producer")
    if not isinstance(completed_run_ids, frozenset | set):
        raise ValueError("completed_run_ids must be a frozenset of run ids")
    if proof_result is not None and not isinstance(proof_result, ProofResult):
        raise ValueError("proof_result must be a ProofResult or None")

    evidence = tuple(records or ())
    resolvable: list[EvidenceRecord] = []
    for record in evidence:
        if not isinstance(record, EvidenceRecord):
            raise ValueError("records must be contract EvidenceRecord instances")
        if _record_run_id(record) in completed_run_ids:
            resolvable.append(record)

    if not evidence:
        return BrokerVerdict(
            identity=identity, producer=producer, verdict="no-evidence",
            evidence_level=None, evidence_polarity=None,
        )
    if not resolvable:
        return BrokerVerdict(
            identity=identity, producer=producer, verdict="no-evidence",
            evidence_level=None, evidence_polarity=None,
            gap=_GAP_PROVENANCE_INCOMPLETE,
        )

    refuted_obligation = proof_result is not None and any(
        item.verdict == _REFUTED_OBLIGATION for item in proof_result.obligations
    )
    refutes = next(
        (
            record
            for record in resolvable
            if record.polarity is EvidencePolarity.REFUTES
        ),
        None,
    )
    if refutes is not None and refuted_obligation:
        return BrokerVerdict(
            identity=identity, producer=producer, verdict="contradict",
            evidence_level=refutes.level, evidence_polarity=refutes.polarity,
        )

    supports = next(
        (
            record
            for record in resolvable
            if record.polarity is EvidencePolarity.SUPPORTS
        ),
        None,
    )
    if supports is not None:
        # Level comes from the record itself: never promoted because the
        # producer is named Semgrep/Clang/ASan.
        return BrokerVerdict(
            identity=identity, producer=producer, verdict="support",
            evidence_level=supports.level, evidence_polarity=supports.polarity,
        )

    # Resolvable REFUTES records exist but the refuted-obligation reference
    # is missing: the refutation stays unproven and degrades to
    # no-evidence, not to a contradiction.
    return BrokerVerdict(
        identity=identity, producer=producer, verdict="no-evidence",
        evidence_level=None, evidence_polarity=None,
        gap=_GAP_PROVENANCE_INCOMPLETE,
    )
