"""An offline, deterministic stand-in for a language model, used by the demo (FR34).

``OfflineDemoNarrator`` is not a language model. It is a scripted ``NarrativeModel``
that drafts id-cited claims from the compact event view the verifier hands it, so
``casebound demo`` exercises the whole generate-test-refine loop fully offline,
with no network and no API keys. When a real provider is configured, the demo uses
that instead.

It behaves the way a capable but fallible model would, from the compact view alone
(it never sees raw evidence, Hard rule 4):

  - Round 0. It narrates the events a triage would lead with: those carrying an
    ATT&CK technique at medium severity or above. Along the way it makes three
    mistakes a model plausibly makes: it misattributes the PowerShell launch to
    the domain administrator (a principal the event does not record), it claims
    the implant read the NTDS.dit database while citing the LSASS event (an object
    that event does not record), and it invents a ransomware event citing an id
    that does not exist.
  - Revision rounds. Handed each rejection with its reason, it corrects what the
    evidence can support (the misattribution: it re-reads the cited event's
    principal and re-asserts) and abandons what it cannot (the other two), which
    the engine then drops and records.

So the demo report shows accepted claims, one accepted only after revision, and a
rejected-claims audit, all produced by the real verifier.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from casebound.verify.checks import RejectionReason
from casebound.verify.engine import DraftRequest, EventView

__all__ = ["OfflineDemoNarrator"]

# The severities at which a tagged event is narrated. Low and informational
# detections are left out of the story, as an analyst would leave them out.
_NARRATED_SEVERITIES = frozenset({"medium", "high", "critical"})

# A well-formed but deliberately nonexistent event id for the invented claim. Built
# by repetition so it reads as obviously fake and does not trip the secret scan.
_NONEXISTENT_EVENT_ID = "deadbeef" * 8

_MISATTRIBUTION = "The domain administrator launched an encoded PowerShell command from Word."
_WRONG_OBJECT = "The implant read the Active Directory database NTDS.dit."
_INVENTION = "The actor deployed ransomware that encrypted the file server."


def _asserts(view: EventView) -> dict[str, str]:
    """Assert exactly the fields the view records: nothing the event lacks."""
    asserts = {"datetime": view.datetime, "action": view.action}
    if view.principal is not None:
        asserts["principal"] = view.principal
    if view.object is not None:
        asserts["object"] = view.object
    return asserts


def _is_powershell_launch(view: EventView) -> bool:
    return (
        view.action == "process_create"
        and view.object is not None
        and view.object.lower().endswith("\\powershell.exe")
    )


class OfflineDemoNarrator:
    """A scripted, offline ``NarrativeModel`` used by the demo (not an LLM)."""

    # Shown in the report so a reader knows the narrative came from the bundled
    # offline drafter, not a language model.
    LABEL: ClassVar[str] = "offline demo narrator (scripted, no network)"

    def draft(self, request: DraftRequest) -> str:
        """Return the claims for one round: a first draft, or revisions."""
        claims = self._revise(request) if request.is_revision else self._first_draft(request.events)
        return json.dumps({"claims": claims})

    def _first_draft(self, views: tuple[EventView, ...]) -> list[dict[str, Any]]:
        claims: list[dict[str, Any]] = []
        misattributed = False
        for view in views:
            if not view.techniques or view.severity not in _NARRATED_SEVERITIES:
                continue
            if not misattributed and _is_powershell_launch(view):
                # The mistake: the event's principal is the workstation user.
                misattributed = True
                claims.append(
                    {
                        "text": _MISATTRIBUTION,
                        "citations": [view.event_id],
                        "asserts": {
                            **_asserts(view),
                            "principal": "CORP\\Administrator",
                        },
                    }
                )
                continue
            claims.append(
                {"text": view.message, "citations": [view.event_id], "asserts": _asserts(view)}
            )

        lsass = next(
            (
                view
                for view in views
                if view.action == "process_access"
                and view.object is not None
                and view.object.lower().endswith("\\lsass.exe")
                and view.severity in _NARRATED_SEVERITIES
            ),
            None,
        )
        if lsass is not None:
            claims.append(
                {
                    "text": _WRONG_OBJECT,
                    "citations": [lsass.event_id],
                    "asserts": {
                        "datetime": lsass.datetime,
                        "action": "process_access",
                        "object": "C:\\Windows\\NTDS\\ntds.dit",
                    },
                }
            )
        claims.append(
            {
                "text": _INVENTION,
                "citations": [_NONEXISTENT_EVENT_ID],
                "asserts": {"action": "file_write", "object": "C:\\Shares\\Finance\\README.txt"},
            }
        )
        return claims

    def _revise(self, request: DraftRequest) -> list[dict[str, Any]]:
        """Fix a misattribution from the cited event; abandon what cannot be fixed."""
        by_id = {view.event_id: view for view in request.events}
        revised: list[dict[str, Any]] = []
        for revision in request.revisions:
            if revision.reason is not RejectionReason.PRINCIPAL_MISMATCH:
                continue
            view = next((by_id[cid] for cid in revision.citations if cid in by_id), None)
            if view is None:
                continue
            revised.append(
                {
                    "text": view.message,
                    "citations": [view.event_id],
                    "asserts": _asserts(view),
                    "revises": revision.claim_id,
                }
            )
        return revised
