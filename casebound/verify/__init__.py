"""Verification: the fence between the model and the report (PRD Section 11).

This is the prime directive in code. No factual claim reaches a report unless it
resolves to a real, deterministically-extracted event by id and its asserted facts
(time, principal, action, object) are consistent with that event (FR17 to FR25).
The deterministic layer is the source of truth; the model never decides what is
true. Never weaken, bypass, or shortcut this layer.

Layout (PRD Section 13):
  - ``claims`` : parse raw model output into structured, id-cited claims.
  - ``checks`` : existence and field-consistency checks for one claim.
  - ``engine`` : the generate-test-refine loop that gates the narrative.

The claim-and-citation format and the field-consistency rules are specified in
``docs/verification.md``. Every change here ships with both a grounded-accept test
and a fabricated-reject test (AGENTS.md, test-first).
"""

from __future__ import annotations

from casebound.verify.checks import (
    DEFAULT_TIME_TOLERANCE,
    ClaimVerdict,
    FieldTolerance,
    RejectionReason,
    verify_claim,
)
from casebound.verify.claims import (
    ASSERTION_FIELDS,
    EVENT_ID_RE,
    Claim,
    ClaimAssertion,
    ClaimParseError,
    parse_claims,
)
from casebound.verify.engine import (
    DEFAULT_MAX_ROUNDS,
    AuditEntry,
    DraftRequest,
    EventView,
    NarrativeModel,
    RevisionRequest,
    VerificationResult,
    VerifiedClaim,
    build_event_view,
    verify_narrative,
)

__all__ = [
    "ASSERTION_FIELDS",
    "DEFAULT_MAX_ROUNDS",
    "DEFAULT_TIME_TOLERANCE",
    "EVENT_ID_RE",
    "AuditEntry",
    "Claim",
    "ClaimAssertion",
    "ClaimParseError",
    "ClaimVerdict",
    "DraftRequest",
    "EventView",
    "FieldTolerance",
    "NarrativeModel",
    "RejectionReason",
    "RevisionRequest",
    "VerificationResult",
    "VerifiedClaim",
    "build_event_view",
    "parse_claims",
    "verify_claim",
    "verify_narrative",
]
