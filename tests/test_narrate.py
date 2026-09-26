"""Tests for the offline demo narrator (PRD FR34, the bundled demo drafter).

The narrator is a scripted, network-free stand-in for a language model. Its job is
to let the demo exercise the whole generate, verify, and revise loop offline: it
drafts grounded claims the verifier accepts and makes three mistakes the verifier
must catch, all from the compact event view (Hard rule 4). On a revision round it
corrects the one mistake the evidence can fix and abandons the rest, so the engine
drops them. These tests pin that behavior against the real verifier.

No network, no API keys.
"""

from __future__ import annotations

import pytest

from casebound.enrich.attack import tag_events
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.narrate import OfflineDemoNarrator
from casebound.normalize import Event, normalize_records
from casebound.verify import (
    DraftRequest,
    RejectionReason,
    build_event_view,
    parse_claims,
    verify_narrative,
)
from casebound.verify.engine import RevisionRequest


@pytest.fixture(scope="module")
def events(tmp_path_factory: pytest.TempPathFactory) -> list[Event]:
    csv_path, _ = write_samples(tmp_path_factory.mktemp("scenario"))
    result = normalize_records(HayabusaAdapter().read(csv_path))
    return tag_events(result.events)


def test_first_draft_cites_the_view_and_seeds_three_mistakes(events: list[Event]) -> None:
    views = build_event_view(events)
    claims = parse_claims(OfflineDemoNarrator().draft(DraftRequest(events=views, round_index=0)))
    known_ids = {view.event_id for view in views}

    invented = [claim for claim in claims if not set(claim.citations) <= known_ids]
    assert len(invented) == 1, "expected exactly one claim citing a nonexistent id"
    grounded = [claim for claim in claims if set(claim.citations) <= known_ids]
    assert len(grounded) > 3

    admin = [claim for claim in claims if claim.asserts.principal == "CORP\\Administrator"]
    assert len(admin) == 1, "expected the PowerShell launch misattributed to the admin"
    ntds = [claim for claim in claims if (claim.asserts.object or "").endswith("ntds.dit")]
    assert len(ntds) == 1, "expected the LSASS event cited for an object it lacks"


def test_revision_corrects_a_misattribution_from_the_cited_event(events: list[Event]) -> None:
    views = build_event_view(events)
    target = next(view for view in views if view.principal == "CORP\\jdoe")
    request = DraftRequest(
        events=views,
        round_index=1,
        revisions=(
            RevisionRequest(
                claim_id="C0-1",
                claim_text="misattributed",
                citations=(target.event_id,),
                reason=RejectionReason.PRINCIPAL_MISMATCH,
                detail="asserted principal does not match",
            ),
            RevisionRequest(
                claim_id="C0-2",
                claim_text="invented",
                citations=("deadbeef" * 8,),
                reason=RejectionReason.MISSING_ID,
                detail="cited event ids do not exist",
            ),
        ),
    )
    [revised] = parse_claims(OfflineDemoNarrator().draft(request))
    assert revised.revises == "C0-1"
    assert revised.citations == (target.event_id,)
    assert revised.asserts.principal == target.principal
    assert revised.asserts.datetime == target.datetime


def test_single_pass_rejects_all_three_mistakes(events: list[Event]) -> None:
    result = verify_narrative(events, OfflineDemoNarrator(), max_rounds=0)
    assert len(result.accepted) > 0
    assert sorted(entry.reason.value for entry in result.dropped) == [
        "missing_id",
        "object_mismatch",
        "principal_mismatch",
    ]


def test_revision_loop_recovers_the_fixable_claim_and_drops_the_rest(
    events: list[Event],
) -> None:
    result = verify_narrative(events, OfflineDemoNarrator(), max_rounds=2)
    # The misattribution is corrected and accepted in round 1.
    revised = [claim for claim in result.accepted if claim.round_index == 1]
    assert len(revised) == 1
    assert revised[0].verified.principal == "CORP\\jdoe"
    # The two claims the evidence cannot support are dropped with their reasons.
    assert sorted(entry.reason.value for entry in result.dropped) == [
        "missing_id",
        "object_mismatch",
    ]
    # Every accepted claim is backed by an event in the case.
    known = {event.event_id for event in events}
    assert all(claim.backing_event_id in known for claim in result.accepted)
