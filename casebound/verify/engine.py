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
from casebound.verify.checks import FieldTolerance, RejectionReason, verify_claim
from casebound.verify.claims import ClaimParseError, parse_claims

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
    """An accepted claim, linked to the event that backs it (FR32).

    ``backing_event_id`` is the cited event the verifier confirmed is consistent
    with every asserted fact, so the report can render the inline citation.
    ``round_index`` records which round produced the accepted version.
    """

    text: str
    citations: tuple[str, ...]
    backing_event_id: str
    round_index: int

    def to_dict(self) -> dict[str, Any]:
        """Render the verified claim as a JSON-ready dict."""
        return {
            "text": self.text,
            "citations": list(self.citations),
            "backing_event_id": self.backing_event_id,
            "round_index": self.round_index,
        }


@dataclass(frozen=True)
class AuditEntry:
    """One recorded rejection (FR25).

    Every claim that was rejected in any round produces an entry. ``dropped`` is
    True when the rejection was final (the last round), meaning the claim was
    dropped and never reached the report (FR24). A claim rejected early and fixed
    later still leaves its earlier rejection here, for transparency.
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

    ``accepted`` are the claims that reach the report, each linked to its evidence.
    ``audit`` records every rejection across every round; ``dropped`` is the subset
    that was still unsupported after the final round and was therefore dropped.
    ``rounds_used`` is how many model calls the loop made.
    """

    accepted: tuple[VerifiedClaim, ...]
    audit: tuple[AuditEntry, ...]
    rounds_used: int

    @property
    def dropped(self) -> tuple[AuditEntry, ...]:
        """The audit entries for claims dropped after the final round (FR24)."""
        return tuple(entry for entry in self.audit if entry.dropped)

    def to_dict(self) -> dict[str, Any]:
        """Render the whole result as a JSON-ready dict for the report layer."""
        return {
            "accepted": [claim.to_dict() for claim in self.accepted],
            "audit": [entry.to_dict() for entry in self.audit],
            "rounds_used": self.rounds_used,
        }


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
    ``max_rounds`` rounds. After the final round any still-unsupported claim is
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
    pending: tuple[RevisionRequest, ...] = ()
    rounds_used = 0

    for round_index in range(max_rounds + 1):
        # A revision round only happens if the previous round left work to do.
        if round_index > 0 and not pending:
            break

        request = DraftRequest(events=views, round_index=round_index, revisions=pending)
        raw = model.draft(request)
        rounds_used = round_index + 1

        try:
            claims = parse_claims(raw)
        except ClaimParseError:
            # Unparseable output yields no claims this round. The loop ends because
            # there is nothing to accept and nothing concrete to ask the model to
            # revise.
            claims = []

        is_final = round_index == max_rounds
        next_pending: list[RevisionRequest] = []
        for claim in claims:
            verdict = verify_claim(claim, event_index, tol)
            if verdict.ok:
                # An accepted verdict always names a backing event. The claim is
                # emitted only when it does, so an unbacked accept (impossible by
                # the verify_claim contract) would simply not reach the report,
                # which is the safe direction.
                if verdict.backing_event_id is not None:
                    accepted.append(
                        VerifiedClaim(
                            text=claim.text,
                            citations=claim.citations,
                            backing_event_id=verdict.backing_event_id,
                            round_index=round_index,
                        )
                    )
                continue

            reason = verdict.reason
            if reason is None:  # pragma: no cover - a rejection always carries a reason
                continue
            audit.append(
                AuditEntry(
                    round_index=round_index,
                    claim_text=claim.text,
                    citations=claim.all_citations,
                    reason=reason,
                    detail=verdict.detail,
                    dropped=is_final,
                )
            )
            if not is_final:
                next_pending.append(
                    RevisionRequest(
                        claim_text=claim.text,
                        citations=claim.citations,
                        reason=reason,
                        detail=verdict.detail,
                    )
                )

        pending = tuple(next_pending)
        if not pending:
            break

    return VerificationResult(
        accepted=tuple(accepted),
        audit=tuple(audit),
        rounds_used=rounds_used,
    )
