"""An offline, deterministic narrative drafter for the bundled demo (FR34).

This is not a language model and not the provider-agnostic interface that lands in
Phase 5. It is a scripted stand-in: it drafts id-cited claims directly from the
compact event view the verifier hands it, so ``casebound demo`` exercises the
verifier and renders a verified narrative plus a rejected-claims audit fully
offline, with no network and no API keys. The moment a real local provider lands,
the demo uses it instead and this drafter is no longer needed.

It does two things, both from the compact view alone (it never sees raw evidence,
Hard rule 4):

  - draws grounded claims from notable events, asserting exactly the fields the
    view exposes, which the verifier accepts by construction; and
  - seeds a couple of deliberately unsupported claims (a wrong principal, a
    wholesale invention citing a nonexistent id), which the verifier must reject,
    so the rejected-claims audit demonstrates the fence catching a hallucination.

It drafts once, on the initial round; on a revision round it returns no claims, so
a seeded fabrication is dropped rather than retried. The demo runs it in a single
verification pass, so each fabrication produces exactly one audit entry.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from typing import Any, ClassVar

from casebound.verify.engine import DraftRequest, EventView

__all__ = ["OfflineDemoNarrator"]

# Actions whose events carry the attack story. The drafter narrates these and skips
# routine background noise, so the verified narrative reads as the intrusion chain.
_NOTABLE_ACTIONS: frozenset[str] = frozenset(
    {
        "process_create",
        "network_connect",
        "registry_set",
        "scheduled_task_create",
        "process_access",
        "network_share_access",
        "service_install",
        "logon",
    }
)

# A well-formed but deliberately nonexistent event id for the invented claim. Built
# by repetition rather than as a 64-character literal so it reads as obviously fake
# and does not trip the secret scan.
_NONEXISTENT_EVENT_ID = "deadbeef" * 8


class OfflineDemoNarrator:
    """A scripted, offline ``NarrativeModel`` used by the demo (not an LLM)."""

    # Shown in the report masthead so a reader knows the narrative came from the
    # bundled offline drafter, not a language model.
    LABEL: ClassVar[str] = "offline demo narrator (scripted, no network)"

    def draft(self, request: DraftRequest) -> str:
        """Return id-cited claims for one round, drafted from the compact view.

        On the initial round it emits the grounded claims plus the seeded
        fabrications; on any revision round it emits nothing, so a fabrication the
        verifier rejected is dropped rather than retried.
        """
        if request.is_revision:
            return json.dumps({"claims": []})
        claims = self._grounded(request.events) + self._fabricated(request.events)
        return json.dumps({"claims": claims})

    def _grounded(self, views: tuple[EventView, ...]) -> list[dict[str, Any]]:
        """Draft one grounded claim per notable event, asserting its exact fields.

        Only fields the view actually records are asserted, so a claim never asserts
        a fact the event lacks (which the verifier would reject). Routine
        self-logons (where the logon target is the account itself) are skipped as
        benign noise.
        """
        claims: list[dict[str, Any]] = []
        for view in views:
            if view.action not in _NOTABLE_ACTIONS:
                continue
            if view.action == "logon" and view.object == view.principal:
                continue
            asserts: dict[str, str] = {"datetime": view.datetime, "action": view.action}
            if view.principal is not None:
                asserts["principal"] = view.principal
            if view.object is not None:
                asserts["object"] = view.object
            claims.append(
                {
                    "text": view.message,
                    "citations": [view.event_id],
                    "asserts": asserts,
                }
            )
        return claims

    def _fabricated(self, views: tuple[EventView, ...]) -> list[dict[str, Any]]:
        """Seed deliberately unsupported claims so the audit shows the fence working.

        Both are the kind of thing a language model might hallucinate: one
        misattributes a real event to the domain administrator (a principal the
        event does not record), and one invents an event wholesale and cites an id
        that does not exist. The verifier rejects both.
        """
        fabricated: list[dict[str, Any]] = []

        powershell = next(
            (
                view
                for view in views
                if view.action == "process_create"
                and view.object is not None
                and "powershell" in view.object.lower()
            ),
            None,
        )
        if powershell is not None:
            # Misattribution: the event's principal is the workstation user, not the
            # administrator, so this is rejected as a principal mismatch.
            fabricated.append(
                {
                    "text": "The domain administrator launched the encoded PowerShell payload.",
                    "citations": [powershell.event_id],
                    "asserts": {
                        "datetime": powershell.datetime,
                        "principal": "CORP\\Administrator",
                        "action": "process_create",
                    },
                }
            )

        # Wholesale invention: no such event exists, so the citation resolves to
        # nothing and the claim is rejected as a missing id.
        fabricated.append(
            {
                "text": "The actor deployed ransomware that encrypted the file server.",
                "citations": [_NONEXISTENT_EVENT_ID],
                "asserts": {
                    "action": "file_write",
                    "object": "C:\\Shares\\Finance\\READ_ME.txt",
                },
            }
        )
        return fabricated
