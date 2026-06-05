"""Tests for the offline demo narrator (PRD FR34, the bundled demo drafter).

The narrator is a scripted, network-free stand-in for a language model. Its job is
to let the demo exercise the verifier offline: it drafts grounded claims the
verifier accepts and seeds fabrications the verifier rejects, all from the compact
event view (Hard rule 4). These tests assert exactly that, and that it drafts only
on the initial round so a fabrication is dropped rather than retried.

No network, no API keys.
"""

from __future__ import annotations

from pathlib import Path

from casebound.enrich.attack import tag_events
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.narrate import OfflineDemoNarrator
from casebound.normalize import Event, normalize_records
from casebound.verify import DraftRequest, build_event_view, parse_claims, verify_narrative


def _events(tmp_path: Path) -> list[Event]:
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    return tag_events(result.events)


def test_narrator_drafts_grounded_and_fabricated_claims(tmp_path: Path) -> None:
    events = _events(tmp_path)
    views = build_event_view(events)
    narrator = OfflineDemoNarrator()

    claims = parse_claims(narrator.draft(DraftRequest(events=views, round_index=0)))
    assert len(claims) > 1

    known_ids = {view.event_id for view in views}
    # Every grounded citation addresses an event in the view; the one invented claim
    # deliberately cites an id that is not in the store.
    cited = {cid for claim in claims for cid in claim.citations}
    assert cited - known_ids, "expected one fabricated claim citing a nonexistent id"
    assert cited & known_ids, "expected grounded claims citing real events"


def test_narrator_is_silent_on_revision_rounds(tmp_path: Path) -> None:
    events = _events(tmp_path)
    views = build_event_view(events)
    narrator = OfflineDemoNarrator()

    # On any revision round the narrator returns no claims, so a rejected fabrication
    # is carried and dropped rather than retried.
    revised = parse_claims(narrator.draft(DraftRequest(events=views, round_index=1)))
    assert revised == []


def test_narrator_run_through_verifier_accepts_grounded_rejects_fabricated(
    tmp_path: Path,
) -> None:
    events = _events(tmp_path)
    # A single pass: grounded claims are accepted, the two fabrications are rejected
    # and dropped, so the audit is non-empty and every accepted claim is verified.
    result = verify_narrative(events, OfflineDemoNarrator(), max_rounds=0)

    assert len(result.accepted) > 0
    assert len(result.dropped) == 2
    reasons = {entry.reason.value for entry in result.dropped}
    assert reasons == {"principal_mismatch", "missing_id"}
