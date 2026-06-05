"""The generate-test-refine engine: the loop that fences the model (PRD Section 11).

This module drives the whole verification loop (FR17 to FR25):

  1. Build the compact, id-addressed event view the model is allowed to see
     (FR17, Hard rule 4): event_id plus the addressable fields, never raw files.
  2. Ask the model to draft the narrative as id-cited claims.
  3. Verify every claim deterministically with ``checks.verify_claim``.
  4. Accept the supported claims; for the rejected ones, resubmit just those (with
     their reasons) for revision, up to ``max_rounds`` rounds (default 2).
  5. After the final round, drop any still-unsupported claim and record every
     rejection in the audit log (FR24, FR25).

The model is reached through the ``NarrativeModel`` protocol, so the engine is
provider-agnostic (R8): the real local or cloud providers land in the ``narrate``
module, and the tests drive the loop with a mock. The model only ever receives the
``EventView`` records, never an ``Event`` with its ``details`` or any source file.

Never weaken the loop. An accepted claim is, by construction, one the deterministic
layer confirmed (AGENTS.md prime directive).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from casebound.normalize.schema import Event
from casebound.verify.checks import (
    ClaimVerdict,
    FieldTolerance,
    RejectionReason,
    verify_claim,
)
from casebound.verify.claims import Claim, ClaimAssertion, ClaimParseError, parse_claims

# PRD Section 11 step 6: revise rejected claims up to max_rounds rounds, default 2.
DEFAULT_MAX_ROUNDS = 2

__all__ = [
    "DEFAULT_MAX_ROUNDS",
    "AuditEntry",
    "DraftRequest",
    "EventView",
    "NarrativeModel",
    "RevisionRequest",
    "VerificationResult",
    "VerifiedClaim",
    "build_event_view",
    "verify_narrative",
]


@dataclass(frozen=True)
class EventView:
    """The compact, id-addressed view of one event shown to the model (FR17).

    Exactly the addressable fields: the id plus the fields the verifier can check,
    and the short normalized ``message``. It deliberately omits ``details``, command
    lines, file contents, and any raw artifact, which is the structural fence in
    Hard rule 4: the model can only address events by id and reason over these
    reduced fields.
    """

    event_id: str
    datetime: str
    host: str | None
    principal: str | None
    action: str
    object: str | None
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Render the view as a JSON-ready dict for the model prompt."""
        return {
            "event_id": self.event_id,
            "datetime": self.datetime,
            "host": self.host,
            "principal": self.principal,
            "action": self.action,
            "object": self.object,
            "message": self.message,
        }


def build_event_view(events: Iterable[Event]) -> tuple[EventView, ...]:
    """Reduce canonical events to the compact view the model is allowed to see.

    This is the only event representation that should ever reach a model. It drops
    everything outside the addressable fields, so raw evidence cannot leak into the
    prompt (Hard rule 4, FR17).
    """
    return tuple(
        EventView(
            event_id=event.event_id,
            datetime=event.datetime,
            host=event.host,
            principal=event.principal,
            action=event.action,
            object=event.object,
            message=event.message,
        )
        for event in events
    )


@dataclass(frozen=True)
class RevisionRequest:
    """One rejected claim handed back to the model for revision (FR23).

    Carries the original prose, what it cited, and why it was rejected, so the
    model has a concrete hint about what to fix. It never carries new evidence: the
    event view is unchanged across rounds.
    """

    claim_text: str
    citations: tuple[str, ...]
    reason: RejectionReason
    detail: str

    def to_dict(self) -> dict[str, Any]:
        """Render the revision request as a JSON-ready dict for the model prompt."""
        return {
            "claim_text": self.claim_text,
            "citations": list(self.citations),
            "reason": self.reason.value,
            "detail": self.detail,
        }


@dataclass(frozen=True)
class DraftRequest:
    """What the engine hands the model for one round.

    ``events`` is the compact view (the only evidence the model sees). On the first
    round ``revisions`` is empty; on later rounds it holds the claims to revise.
    ``round_index`` is 0 for the initial draft and increments per revision round.
    """

    events: tuple[EventView, ...]
    round_index: int
    revisions: tuple[RevisionRequest, ...] = ()

    @property
    def is_revision(self) -> bool:
        """True on a revision round (anything after the initial draft)."""
        return self.round_index > 0


@runtime_checkable
class NarrativeModel(Protocol):
    """The provider-agnostic model interface the engine drives (R8).

    An implementation drafts a narrative as id-cited claims, returning the raw
    string defined in ``docs/verification.md``. The real local and cloud providers
    live in the ``narrate`` module; tests supply a mock. The engine never passes a
    raw ``Event`` to ``draft``: only the compact view in the request.
    """

    def draft(self, request: DraftRequest) -> str:
        """Return raw model output (the claim JSON) for one round."""
        ...


@dataclass(frozen=True)
class VerifiedClaim:
    """An accepted claim, carrying only verified facts (FR32).

    The authoritative content is the verified data, never the model's free prose.
    ``asserts`` holds the facts the verifier checked against the backing event, and
    ``backing_event_id`` names that event, so the report renders the claim from
    checked fields only (see ``rendered_statement``) and links it to its evidence.
    ``citations`` all resolve to real events. ``draft_text`` is the model's original
    prose, kept for the audit but deliberately non-authoritative: it must never be
    rendered as fact, because it can state things the verifier did not check. This
    is the fence in code: the model proposes prose, but only verified fields reach
    the report as facts (AGENTS.md prime directive).
    """

    backing_event_id: str
    asserts: ClaimAssertion
    citations: tuple[str, ...]
    round_index: int
    draft_text: str

    def rendered_statement(self) -> str:
        """Render the claim from checked fields only, for the report.

        Built solely from the verified assertions and the backing event id, so the
        statement can never contain a fact the verifier did not confirm. The report
        layer formats from these same checked fields; it must not surface
        ``draft_text`` as a factual claim.
        """
        parts: list[str] = []
        if self.asserts.datetime is not None:
            parts.append(f"at {self.asserts.datetime}")
        if self.asserts.principal is not None:
            parts.append(f"principal {self.asserts.principal}")
        if self.asserts.action is not None:
            parts.append(f"action {self.asserts.action}")
        if self.asserts.object is not None:
            parts.append(f"object {self.asserts.object}")
        facts = ", ".join(parts)
        return f"{facts} [event {self.backing_event_id[:12]}]"

    def to_dict(self) -> dict[str, Any]:
        """Render the verified claim as a JSON-ready dict for the report layer."""
        return {
            "statement": self.rendered_statement(),
            "backing_event_id": self.backing_event_id,
            "asserts": self.asserts.to_dict(),
            "citations": list(self.citations),
            "round_index": self.round_index,
            "draft_text": self.draft_text,
        }


@dataclass(frozen=True)
class AuditEntry:
    """One recorded rejection (FR25).

    Every claim that was verified and rejected in a round produces an entry.
    ``dropped`` is True when the claim was still unsupported after the final round
    (or the model abandoned it during revision) and was therefore dropped and never
    reached the report (FR24). A claim rejected early and fixed later still leaves
    its earlier rejection here, for transparency.
    """

    round_index: int
    claim_text: str
    citations: tuple[str, ...]
    reason: RejectionReason
    detail: str
    dropped: bool

    def to_dict(self) -> dict[str, Any]:
        """Render the audit entry as a JSON-ready dict for the report."""
        return {
            "round_index": self.round_index,
            "claim_text": self.claim_text,
            "citations": list(self.citations),
            "reason": self.reason.value,
            "detail": self.detail,
            "dropped": self.dropped,
        }


@dataclass(frozen=True)
class VerificationResult:
    """The output of the loop: the verified narrative plus the rejection audit.

    ``accepted`` are the claims that reach the report, each carrying only verified
    facts. ``audit`` records every rejection across every round; ``dropped`` is the
    subset that was dropped (still unsupported after the final round, or abandoned
    by the model during revision). ``rounds_used`` is how many model calls the loop
    made.
    """

    accepted: tuple[VerifiedClaim, ...]
    audit: tuple[AuditEntry, ...]
    rounds_used: int

    @property
    def dropped(self) -> tuple[AuditEntry, ...]:
        """The audit entries for claims that were dropped and never emitted (FR24)."""
        return tuple(entry for entry in self.audit if entry.dropped)

    def to_dict(self) -> dict[str, Any]:
        """Render the whole result as a JSON-ready dict for the report layer."""
        return {
            "accepted": [claim.to_dict() for claim in self.accepted],
            "audit": [entry.to_dict() for entry in self.audit],
            "rounds_used": self.rounds_used,
        }


def _safe_parse(raw: str) -> list[Claim]:
    """Parse model output, treating unparseable output as no claims for the round."""
    try:
        return parse_claims(raw)
    except ClaimParseError:
        return []


def _accept(claim: Claim, backing_event_id: str, round_index: int) -> VerifiedClaim:
    """Build a verified claim from a claim the verifier accepted."""
    return VerifiedClaim(
        backing_event_id=backing_event_id,
        asserts=claim.asserts,
        citations=claim.citations,
        round_index=round_index,
        draft_text=claim.text,
    )


def _rejection_entry(
    round_index: int, claim: Claim, verdict: ClaimVerdict, *, dropped: bool
) -> AuditEntry:
    """Build an audit entry for a verified-and-rejected claim."""
    # A rejection always carries a reason; default defensively for the type checker.
    reason = verdict.reason if verdict.reason is not None else RejectionReason.MISSING_ID
    return AuditEntry(
        round_index=round_index,
        claim_text=claim.text,
        citations=claim.all_citations,
        reason=reason,
        detail=verdict.detail,
        dropped=dropped,
    )


def _drop_entry(round_index: int, claim: Claim, verdict: ClaimVerdict) -> AuditEntry:
    """Build a dropped audit entry for a claim the model abandoned during revision.

    Used when a revision round returns no replacement for an outstanding claim (the
    model omitted it or returned unparseable output). The claim is still
    unsupported, so it is dropped and recorded with its last known rejection reason
    (FR24, FR25).
    """
    reason = verdict.reason if verdict.reason is not None else RejectionReason.MISSING_ID
    detail = verdict.detail
    note = "model returned no revision for this claim"
    return AuditEntry(
        round_index=round_index,
        claim_text=claim.text,
        citations=claim.all_citations,
        reason=reason,
        detail=f"{detail}; {note}" if detail else note,
        dropped=True,
    )


def verify_narrative(
    events: Sequence[Event],
    model: NarrativeModel,
    *,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    tolerance: FieldTolerance | None = None,
) -> VerificationResult:
    """Run the generate-test-refine loop and return the verified narrative.

    Drafts claims from the compact event view, verifies each deterministically,
    accepts the supported ones, and resubmits the rejected ones for revision up to
    ``max_rounds`` rounds. In a revision round the model is expected to return a
    revised claim for each outstanding claim, in the same order; an outstanding
    claim the model fails to return (an omission or unparseable output) is treated
    as still unsupported. After the final round, every still-unsupported claim is
    dropped (FR24) and every rejection is recorded in the audit log (FR25). The
    model only ever sees the compact view (Hard rule 4).
    """
    if max_rounds < 0:
        raise ValueError("max_rounds must be zero or greater")

    tol = tolerance if tolerance is not None else FieldTolerance()
    event_index = {event.event_id: event for event in events}
    views = build_event_view(events)

    accepted: list[VerifiedClaim] = []
    audit: list[AuditEntry] = []
    # Each outstanding claim is the last (claim, verdict) we rejected and are
    # awaiting a fix for. Positional order is the contract for matching revisions.
    pending: list[tuple[Claim, ClaimVerdict]] = []

    def verify_round(
        claims: list[Claim],
        round_index: int,
        *,
        is_final: bool,
        sink: list[tuple[Claim, ClaimVerdict]],
    ) -> None:
        """Verify a round's claims: accept fixes, record rejections, refill ``sink``.

        Each still-unsupported claim is recorded in the audit (dropped on the final
        round) and, when more rounds remain, appended to ``sink`` to be revised next.
        """
        for claim in claims:
            verdict = verify_claim(claim, event_index, tol)
            if verdict.ok and verdict.backing_event_id is not None:
                accepted.append(_accept(claim, verdict.backing_event_id, round_index))
                continue
            audit.append(_rejection_entry(round_index, claim, verdict, dropped=is_final))
            if not is_final:
                sink.append((claim, verdict))

    # Round 0: the initial draft.
    initial = _safe_parse(model.draft(DraftRequest(events=views, round_index=0, revisions=())))
    rounds_used = 1
    next_pending: list[tuple[Claim, ClaimVerdict]] = []
    verify_round(initial, round_index=0, is_final=max_rounds == 0, sink=next_pending)
    pending = next_pending

    # Revision rounds.
    round_index = 1
    while pending and round_index <= max_rounds:
        is_final = round_index == max_rounds
        revisions = tuple(
            RevisionRequest(
                claim_text=claim.text,
                citations=claim.citations,
                reason=verdict.reason if verdict.reason is not None else RejectionReason.MISSING_ID,
                detail=verdict.detail,
            )
            for claim, verdict in pending
        )
        revised = _safe_parse(
            model.draft(DraftRequest(events=views, round_index=round_index, revisions=revisions))
        )
        rounds_used = round_index + 1

        next_pending = []
        # Match each outstanding claim to the revision at the same position.
        for position, (orig_claim, orig_verdict) in enumerate(pending):
            if position < len(revised):
                claim = revised[position]
                verdict = verify_claim(claim, event_index, tol)
                if verdict.ok and verdict.backing_event_id is not None:
                    accepted.append(_accept(claim, verdict.backing_event_id, round_index))
                    continue
                audit.append(_rejection_entry(round_index, claim, verdict, dropped=is_final))
                if not is_final:
                    next_pending.append((claim, verdict))
            else:
                # The model returned no revision for this outstanding claim. It is
                # still unsupported, so drop and record it (never silently lose it).
                audit.append(_drop_entry(round_index, orig_claim, orig_verdict))
        # Any extra claims the model added beyond the outstanding set are verified
        # as new claims, so a revision round can never sneak an unverified claim in.
        verify_round(
            revised[len(pending) :], round_index=round_index, is_final=is_final, sink=next_pending
        )

        pending = next_pending
        round_index += 1

    return VerificationResult(
        accepted=tuple(accepted),
        audit=tuple(audit),
        rounds_used=rounds_used,
    )
