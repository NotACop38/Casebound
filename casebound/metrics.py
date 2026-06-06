"""Evaluation metrics (PRD Section 12): the headline numbers, made reproducible.

Casebound's value is measured, not asserted (PRD Section 4). This module computes
the four metrics the README reports and the demo regenerates, all deterministically
and offline:

  - Hallucination-rejection rate (FR35): of a seeded set of deliberately fabricated
    claims, the fraction the verifier rejects. Target 1.0. The seeded set is built
    from the live events (see ``build_seeded_fabrications``) so it always aligns
    with the scenario being measured, and each fabrication is the kind of thing a
    language model might invent: a wrong principal, a shifted time, a wrong action
    or object, a wholesale invention citing a nonexistent id, and a malformed
    citation.

  - Citation accuracy: of the claims the verifier emitted (accepted), the fraction
    whose citations resolve to real, field-consistent events. Target 1.0 by
    construction: anything less is a verifier bug, so this re-checks every accepted
    claim rather than trusting the loop.

  - ATT&CK tagging precision and recall: the deterministic tagger's output scored
    against the ground-truth labels at the (event, technique) level. Targets:
    precision at least 0.9, recall at least 0.7.

  - Coverage: the number of distinct techniques observed and represented in the
    Navigator layer.

The model is never in this loop. Every number is a pure function of the
deterministic pipeline output and the ground-truth labels.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from casebound.normalize.schema import Event
from casebound.verify.checks import verify_claim
from casebound.verify.claims import Claim, ClaimAssertion

__all__ = [
    "ATTACK_PRECISION_TARGET",
    "ATTACK_RECALL_TARGET",
    "CITATION_ACCURACY_TARGET",
    "REJECTION_RATE_TARGET",
    "AttackMetrics",
    "Metrics",
    "attack_metrics",
    "build_seeded_fabrications",
    "citation_accuracy",
    "compute_metrics",
    "hallucination_rejection_rate",
]

# The targets the demo must hit (PRD Section 12). A citation accuracy or rejection
# rate below 1.0 is a verifier bug by design.
REJECTION_RATE_TARGET = 1.0
CITATION_ACCURACY_TARGET = 1.0
ATTACK_PRECISION_TARGET = 0.9
ATTACK_RECALL_TARGET = 0.7

# A well-formed but deliberately nonexistent event id for the invented claim. Built
# by repetition so it reads as obviously fake and does not trip the secret scan.
_NONEXISTENT_EVENT_ID = "deadbeef" * 8

# A record-number-shaped string that is not a valid event id, so a claim citing it
# carries only a malformed citation and is rejected for that reason.
_MALFORMED_CITATION = "EVENT-00000"


def _parse_utc(value: str) -> datetime:
    """Parse a canonical UTC datetime string (trailing Z) into an aware instant."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _format_utc(moment: datetime) -> str:
    """Render a UTC instant back to the canonical string with a trailing Z.

    ``moment`` is an aware UTC datetime, so its own fields are already UTC and
    ``strftime`` renders the canonical wall-clock directly.
    """
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _distinct(actual: str | None, *candidates: str) -> str:
    """Return a value guaranteed to differ from ``actual`` under the verifier's check.

    The verifier compares text fields after trimming and case-folding, so a seeded
    fabrication is only guaranteed false if its asserted value differs under that
    same comparison. This returns the first candidate that does; if every candidate
    happens to equal the event's real value (so the fabrication would otherwise turn
    into a true claim), it mutates one into a sentinel that cannot match. That keeps
    the fabrication false no matter what a future scenario records.
    """
    norm = (actual or "").strip().casefold()
    for candidate in candidates:
        if candidate.strip().casefold() != norm:
            return candidate
    return f"{candidates[0]}-impostor" if candidates else "impostor"


def build_seeded_fabrications(events: Sequence[Event]) -> list[Claim]:
    """Build the seeded set of fabricated claims for the hallucination metric.

    The set is constructed from the live events, so it always aligns with the
    scenario being measured: each fabrication cites a real event id (or a
    nonexistent or malformed one) and asserts a fact the evidence does not support.
    The verifier must reject every one. Two fabrications (the wholesale invention and
    the malformed citation) need no anchor event and are always present; the field
    mismatches are added when their anchor event is found, so the set degrades
    gracefully on a scenario that lacks one.
    """
    fabrications: list[Claim] = []

    def add(
        citations: tuple[str, ...], malformed: tuple[str, ...], asserts: ClaimAssertion
    ) -> None:
        fabrications.append(
            Claim(
                index=len(fabrications),
                text="seeded fabrication for the hallucination-rejection metric",
                citations=citations,
                malformed_citations=malformed,
                asserts=asserts,
            )
        )

    powershell = next(
        (
            e
            for e in events
            if e.action == "process_create"
            and e.object is not None
            and "powershell" in e.object.lower()
        ),
        None,
    )
    any_logon = next((e for e in events if e.action == "logon"), None)
    network_logon = next(
        (
            e
            for e in events
            if e.action == "logon" and e.object is not None and e.object != e.principal
        ),
        None,
    )

    # Wholesale invention: the cited id resolves to nothing (missing_id).
    add(
        (_NONEXISTENT_EVENT_ID,),
        (),
        ClaimAssertion(action="file_write", object="C:\\Shares\\Finance\\READ_ME.txt"),
    )
    # A record number instead of an event id: malformed_citation.
    add((), (_MALFORMED_CITATION,), ClaimAssertion(action="process_create"))

    if powershell is not None:
        # Misattribution to another principal: principal_mismatch. The replacement is
        # chosen to differ from the event's real principal, so the fabrication can
        # never accidentally become a true claim (for example on a future scenario
        # where the PowerShell event really is run by CORP\Administrator).
        add(
            (powershell.event_id,),
            (),
            ClaimAssertion(
                datetime=powershell.datetime,
                principal=_distinct(powershell.principal, "CORP\\Administrator", "CORP\\Imposter"),
                action="process_create",
            ),
        )
        # The same event moved hours earlier: time_mismatch.
        shifted = _format_utc(_parse_utc(powershell.datetime) - timedelta(hours=6))
        add(
            (powershell.event_id,),
            (),
            ClaimAssertion(datetime=shifted, action="process_create"),
        )
    if any_logon is not None:
        # A logon recast as a process creation: action_mismatch.
        add(
            (any_logon.event_id,),
            (),
            ClaimAssertion(
                datetime=any_logon.datetime,
                principal=any_logon.principal,
                action="process_create",
            ),
        )
    if network_logon is not None:
        # The right event pointed at the wrong source host: object_mismatch. The
        # replacement endpoint is chosen to differ from the event's real object, so
        # the fabrication stays false on any scenario.
        add(
            (network_logon.event_id,),
            (),
            ClaimAssertion(
                datetime=network_logon.datetime,
                principal=network_logon.principal,
                action="logon",
                object=_distinct(network_logon.object, "10.9.9.9", "10.0.0.254"),
            ),
        )

    return fabrications


def hallucination_rejection_rate(
    events: Sequence[Event], fabrications: Sequence[Claim]
) -> tuple[float, int, int]:
    """Return (rate, rejected, total) for the seeded fabrications against the events.

    Runs each fabricated claim through the deterministic verifier and counts how many
    are rejected. A rate below 1.0 means a fabrication slipped through, which is a
    verifier bug (FR35).
    """
    index = {event.event_id: event for event in events}
    total = len(fabrications)
    rejected = sum(1 for claim in fabrications if not verify_claim(claim, index).ok)
    rate = rejected / total if total else 1.0
    return rate, rejected, total


def citation_accuracy(events: Sequence[Event], accepted: Sequence[Any]) -> tuple[float, int, int]:
    """Return (rate, accurate, emitted) for the verifier's accepted claims.

    Re-checks every accepted claim against the event store rather than trusting the
    loop: an accepted claim is accurate only if its citations resolve to real events
    and a cited event is consistent with every asserted fact. By construction this is
    1.0; a lower value exposes a verifier bug (PRD Section 12).
    """
    index = {event.event_id: event for event in events}
    emitted = len(accepted)
    accurate = 0
    for claim in accepted:
        reconstructed = Claim(
            index=0,
            text=claim.draft_text,
            citations=tuple(claim.citations),
            malformed_citations=(),
            asserts=claim.asserts,
        )
        if verify_claim(reconstructed, index).ok:
            accurate += 1
    rate = accurate / emitted if emitted else 1.0
    return rate, accurate, emitted


@dataclass(frozen=True)
class AttackMetrics:
    """Precision and recall for the deterministic ATT&CK tagger against ground truth.

    Scored at the (event, technique) level: a true positive is a technique the tagger
    assigned to an event that the ground truth also labels on that event.
    """

    precision: float
    recall: float
    true_positives: int
    false_positives: int
    false_negatives: int
    predicted: int
    expected: int

    def to_dict(self) -> dict[str, Any]:
        """Render the ATT&CK metrics as a JSON-ready dict."""
        return {
            "precision": self.precision,
            "recall": self.recall,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "predicted": self.predicted,
            "expected": self.expected,
        }


def attack_metrics(events: Sequence[Event], ground_truth: Mapping[str, Any]) -> AttackMetrics:
    """Score the deterministic tagger against the scenario's ground-truth labels.

    Joins each canonical event to its ground-truth label by the source record id
    (the Hayabusa RecordID preserved in ``raw_ref``), then compares the predicted
    technique set to the labeled set at the (record, technique) level. Precision is
    correct tags over all emitted tags; recall is labeled techniques the tagger found
    (PRD Section 12).
    """
    expected: set[tuple[str, str]] = {
        (str(label["record_id"]), tid)
        for label in ground_truth.get("events", [])
        for tid in label["technique_ids"]
    }
    predicted: set[tuple[str, str]] = {
        (event.raw_ref.record, tech.technique_id)
        for event in events
        for tech in event.attack_techniques
    }

    true_positives = len(predicted & expected)
    false_positives = len(predicted - expected)
    false_negatives = len(expected - predicted)

    precision = true_positives / len(predicted) if predicted else 1.0
    recall = true_positives / len(expected) if expected else 1.0

    return AttackMetrics(
        precision=precision,
        recall=recall,
        true_positives=true_positives,
        false_positives=false_positives,
        false_negatives=false_negatives,
        predicted=len(predicted),
        expected=len(expected),
    )


@dataclass(frozen=True)
class Metrics:
    """The full evaluation metric set (PRD Section 12), regenerated by the demo."""

    hallucination_rejection_rate: float
    rejected_fabrications: int
    seeded_fabrications: int
    citation_accuracy: float
    accurate_claims: int
    emitted_claims: int
    attack: AttackMetrics
    coverage: int
    observed_techniques: tuple[str, ...]

    def meets_targets(self) -> bool:
        """True when every metric meets or exceeds its PRD Section 12 target."""
        return (
            self.hallucination_rejection_rate >= REJECTION_RATE_TARGET
            and self.citation_accuracy >= CITATION_ACCURACY_TARGET
            and self.attack.precision >= ATTACK_PRECISION_TARGET
            and self.attack.recall >= ATTACK_RECALL_TARGET
        )

    def to_dict(self) -> dict[str, Any]:
        """Render the whole metric set as a JSON-ready dict for persistence."""
        return {
            "hallucination_rejection_rate": self.hallucination_rejection_rate,
            "rejected_fabrications": self.rejected_fabrications,
            "seeded_fabrications": self.seeded_fabrications,
            "citation_accuracy": self.citation_accuracy,
            "accurate_claims": self.accurate_claims,
            "emitted_claims": self.emitted_claims,
            "attack": self.attack.to_dict(),
            "coverage": self.coverage,
            "observed_techniques": list(self.observed_techniques),
            "targets": {
                "hallucination_rejection_rate": REJECTION_RATE_TARGET,
                "citation_accuracy": CITATION_ACCURACY_TARGET,
                "attack_precision": ATTACK_PRECISION_TARGET,
                "attack_recall": ATTACK_RECALL_TARGET,
            },
            "meets_targets": self.meets_targets(),
        }


def compute_metrics(
    events: Sequence[Event],
    verification: Any | None,
    ground_truth: Mapping[str, Any],
    *,
    fabrications: Sequence[Claim] | None = None,
) -> Metrics:
    """Compute the full metric set from the pipeline output and the ground truth.

    ``verification`` is the verifier result (or None on the no-model path, where the
    narrative metrics are vacuous: no claim was emitted, so citation accuracy is 1.0,
    and the hallucination metric still runs against the events). ``fabrications``
    defaults to the seeded set built from the events (FR35).
    """
    seeded = list(fabrications) if fabrications is not None else build_seeded_fabrications(events)
    rejection_rate, rejected, total = hallucination_rejection_rate(events, seeded)

    accepted = list(verification.accepted) if verification is not None else []
    citation_rate, accurate, emitted = citation_accuracy(events, accepted)

    attack = attack_metrics(events, ground_truth)

    observed = tuple(
        sorted({tech.technique_id for event in events for tech in event.attack_techniques})
    )

    return Metrics(
        hallucination_rejection_rate=rejection_rate,
        rejected_fabrications=rejected,
        seeded_fabrications=total,
        citation_accuracy=citation_rate,
        accurate_claims=accurate,
        emitted_claims=emitted,
        attack=attack,
        coverage=len(observed),
        observed_techniques=observed,
    )
