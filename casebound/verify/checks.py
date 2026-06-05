"""Existence and field-consistency checks: the deterministic core of the fence.

PRD Section 11 step 4: for each claim, confirm every cited event exists, then
check that the claim's asserted facts (time, principal, action, object) are
consistent with a cited event. This module decides, with no model in the loop,
whether a single claim is supported. The rules and tolerances are specified in
``docs/verification.md``.

A claim is accepted only when at least one cited, existing event is consistent
with every field the claim asserts. One event must back the whole assertion, so a
claim cannot stitch one event's principal onto another event's action. The first
field that fails (checked in a fixed order) supplies the rejection reason, which
becomes the revision hint and the audit-log entry.

Never weaken these checks. If a change here would let an unsupported claim pass,
do not make it (AGENTS.md prime directive).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any

from casebound.normalize.schema import Event
from casebound.verify.claims import Claim, ClaimAssertion

# The default tolerance on the asserted time. The event times are already
# canonical UTC and the model is shown the exact datetime, so this only absorbs
# sub-second representation differences. Configurable through FieldTolerance.
DEFAULT_TIME_TOLERANCE = timedelta(seconds=1)

__all__ = [
    "DEFAULT_TIME_TOLERANCE",
    "ClaimVerdict",
    "FieldTolerance",
    "RejectionReason",
    "verify_claim",
]


class RejectionReason(StrEnum):
    """Why a claim was rejected. The values are stable, audit-log-friendly strings.

    A string Enum so a reason serializes to a plain string in JSON output while
    still being a typed member in code.
    """

    NO_CITATIONS = "no_citations"
    MALFORMED_CITATION = "malformed_citation"
    MISSING_ID = "missing_id"
    NO_ASSERTIONS = "no_assertions"
    TIME_MISMATCH = "time_mismatch"
    PRINCIPAL_MISMATCH = "principal_mismatch"
    ACTION_MISMATCH = "action_mismatch"
    OBJECT_MISMATCH = "object_mismatch"


@dataclass(frozen=True)
class FieldTolerance:
    """Tunable tolerances for the field-consistency checks.

    Only the time comparison has a tolerance; principal, action, and object are
    matched as normalized text. Kept as a small record so callers can tighten or
    loosen the verifier without touching its logic.
    """

    time_tolerance: timedelta = DEFAULT_TIME_TOLERANCE


@dataclass(frozen=True)
class ClaimVerdict:
    """The outcome of verifying one claim.

    On acceptance, ``backing_event_id`` names the cited event that satisfied every
    asserted field, so the report can link the claim to its evidence (FR32). On
    rejection, ``reason`` and ``detail`` explain why, for the revision hint and the
    audit log.
    """

    ok: bool
    backing_event_id: str | None = None
    reason: RejectionReason | None = None
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Render the verdict as a JSON-ready dict."""
        return {
            "ok": self.ok,
            "backing_event_id": self.backing_event_id,
            "reason": self.reason.value if self.reason is not None else None,
            "detail": self.detail,
        }


def _parse_utc(value: str) -> datetime | None:
    """Parse an asserted timestamp into a UTC instant, or None if unparseable.

    Accepts ISO 8601 with a trailing Z or an explicit offset, and naive strings
    (assumed UTC). Returns None on anything that is not a real instant, which the
    caller treats as a time mismatch.
    """
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _normalize_text(value: str) -> str:
    """Normalize a text field for comparison: trim and case-fold.

    Principals, actions, and object paths on Windows are case-insensitive, so the
    comparison is too. Surrounding whitespace is never significant.
    """
    return value.strip().casefold()


def _check_datetime(asserted: str, actual: str, tolerance: timedelta) -> str | None:
    """Return a mismatch detail when the asserted time is not within tolerance."""
    asserted_dt = _parse_utc(asserted)
    if asserted_dt is None:
        return f"asserted time {asserted!r} is not a parseable instant"
    actual_dt = _parse_utc(actual)
    # The event datetime is canonical UTC and always parses; guard defensively.
    if actual_dt is None:  # pragma: no cover - canonical events always parse
        return f"event time {actual!r} is not a parseable instant"
    if abs(asserted_dt - actual_dt) > tolerance:
        return (
            f"asserted time {asserted!r} differs from event time {actual!r} "
            f"by more than the tolerance ({tolerance})"
        )
    return None


def _check_event(
    asserts: ClaimAssertion, event: Event, tolerance: FieldTolerance
) -> tuple[RejectionReason, str] | None:
    """Check one cited event against every asserted field.

    Returns None when the event is consistent with every field the claim asserts,
    or the first failing field's reason and detail. Fields are checked in a fixed
    order (datetime, principal, action, object) so the reason is deterministic. A
    field the event does not record (a null principal or object) can never satisfy
    an assertion about it.
    """
    short_id = event.event_id[:12]

    if asserts.datetime is not None:
        detail = _check_datetime(asserts.datetime, event.datetime, tolerance.time_tolerance)
        if detail is not None:
            return RejectionReason.TIME_MISMATCH, f"{detail} (event {short_id})"

    if asserts.principal is not None and (
        event.principal is None
        or _normalize_text(asserts.principal) != _normalize_text(event.principal)
    ):
        return (
            RejectionReason.PRINCIPAL_MISMATCH,
            f"asserted principal {asserts.principal!r} does not match event "
            f"{short_id} principal {event.principal!r}",
        )

    if asserts.action is not None and _normalize_text(asserts.action) != _normalize_text(
        event.action
    ):
        return (
            RejectionReason.ACTION_MISMATCH,
            f"asserted action {asserts.action!r} does not match event "
            f"{short_id} action {event.action!r}",
        )

    if asserts.object is not None and (
        event.object is None or _normalize_text(asserts.object) != _normalize_text(event.object)
    ):
        return (
            RejectionReason.OBJECT_MISMATCH,
            f"asserted object {asserts.object!r} does not match event "
            f"{short_id} object {event.object!r}",
        )

    return None


def verify_claim(
    claim: Claim,
    event_index: Mapping[str, Event],
    tolerance: FieldTolerance | None = None,
) -> ClaimVerdict:
    """Decide whether one claim is supported by the deterministic event store.

    The order is exactly PRD Section 11 step 4: require a usable citation, require
    the claim to assert at least one checkable fact, confirm a cited event exists,
    then confirm a single cited event is consistent with every asserted field. The
    first failure short-circuits with its reason. A malformed-only or
    citation-free claim is rejected before any field is checked, because a
    malformed citation provides no support.
    """
    tol = tolerance if tolerance is not None else FieldTolerance()

    # 1. Every citation must be well-formed. A malformed citation provides no
    #    support, and an accepted claim must never carry one, so any malformed
    #    citation rejects the whole claim rather than being silently tolerated.
    if claim.malformed_citations:
        return ClaimVerdict(
            ok=False,
            reason=RejectionReason.MALFORMED_CITATION,
            detail=f"claim carries malformed citations: {list(claim.malformed_citations)}",
        )
    if not claim.citations:
        return ClaimVerdict(
            ok=False,
            reason=RejectionReason.NO_CITATIONS,
            detail="claim carries no event-id citation",
        )

    # 2. The claim must assert at least one checkable fact.
    if claim.asserts.is_empty():
        return ClaimVerdict(
            ok=False,
            reason=RejectionReason.NO_ASSERTIONS,
            detail=(
                "claim asserts none of the checkable facts (datetime, principal, action, object)"
            ),
        )

    # 3. Every cited id must resolve to a real event. An accepted claim must not
    #    carry a citation that links to nothing, so a single unresolved id (even
    #    alongside a valid one) rejects the claim (FR20, FR32).
    missing = [cid for cid in claim.citations if cid not in event_index]
    if missing:
        return ClaimVerdict(
            ok=False,
            reason=RejectionReason.MISSING_ID,
            detail=f"cited event ids do not exist in the store: {missing}",
        )
    cited_events = [(cid, event_index[cid]) for cid in claim.citations]

    # 4. A single cited event must be consistent with every asserted field. The
    #    first candidate's failure supplies the rejection reason.
    first_failure: tuple[RejectionReason, str] | None = None
    for cid, event in cited_events:
        failure = _check_event(claim.asserts, event, tol)
        if failure is None:
            return ClaimVerdict(ok=True, backing_event_id=cid)
        if first_failure is None:
            first_failure = failure

    # cited_events is non-empty (guarded above), so the loop ran and either
    # returned an acceptance or recorded a first failure.
    if first_failure is None:  # pragma: no cover - unreachable given the guard above
        return ClaimVerdict(
            ok=False,
            reason=RejectionReason.MISSING_ID,
            detail="no cited event was consistent with the claim",
        )
    reason, detail = first_failure
    return ClaimVerdict(ok=False, reason=reason, detail=detail)
