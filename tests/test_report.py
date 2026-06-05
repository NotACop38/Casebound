"""Tests for the self-contained HTML report renderer (PRD FR28, FR32, FR26).

The load-bearing properties:

  1. Self-contained: the HTML fetches nothing at view time (no external scripts,
     stylesheets, fonts, or images), so the report opens identically offline.
  2. Inline citations link to evidence: every accepted claim's citation resolves to
     an anchored event in the appendix (FR32), and every timeline event is anchored.
  3. Checked fields only: an accepted claim renders from its verified assertions,
     never the model's free prose, so a fact the verifier did not check cannot reach
     the reader as a statement (AGENTS.md prime directive).
  4. The audit is shown: every rejected claim appears with its reason.
  5. The no-model path renders the deterministic report and says so (FR26).
  6. Autoescaping: evidence-derived strings cannot inject markup.

All tests run offline with no API keys; the narrative path uses a mocked model.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from casebound.enrich.attack import tag_events
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, normalize_records
from casebound.normalize.schema import RawRef
from casebound.report import NO_MODEL_LABEL, render_report
from casebound.verify import DraftRequest, VerificationResult, verify_narrative

# Real event ids from the office_intrusion scenario at the default seed: the
# Word-spawned encoded PowerShell process-create event, and the unrelated
# lateral-movement network logon.
PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"
LATERAL_LOGON_ID = "4e959251e72c7f9c2bcf43acbcdf51ac69baf4542c49ff55e363316299b1da5e"


class StubModel:
    """A mocked ``NarrativeModel`` that replays one scripted raw response."""

    def __init__(self, response: str) -> None:
        self.response = response

    def draft(self, request: DraftRequest) -> str:
        return self.response


def _response(*claims: dict[str, Any]) -> str:
    return json.dumps({"claims": list(claims)})


def _events(tmp_path: Path) -> list[Event]:
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    assert result.problem_count == 0
    return tag_events(result.events)


def _verified(events: list[Event]) -> VerificationResult:
    """Build a result with one accepted claim and one rejected-and-dropped claim."""
    model = StubModel(
        _response(
            {
                # Prose names the administrator, but only the action is asserted and
                # checked: the rendered statement must not surface the administrator.
                "text": "The domain administrator spawned the encoded PowerShell process.",
                "citations": [PROCESS_CREATE_ID],
                "asserts": {"action": "process_create"},
            },
            {
                "text": "The domain administrator owned the PowerShell process.",
                "citations": [PROCESS_CREATE_ID],
                "asserts": {"principal": "CORP\\Administrator"},
            },
        )
    )
    # No revision rounds: the mismatched claim is rejected and dropped in one pass.
    return verify_narrative(events, model, max_rounds=0)


def _assert_self_contained(html: str) -> None:
    # No external fetches of any kind at view time (FR28).
    assert "<!DOCTYPE html>" in html
    assert "<script" not in html
    assert "<link" not in html
    assert 'src="http' not in html
    assert 'href="http' not in html
    assert "@import" not in html


def test_report_is_self_contained(tmp_path: Path) -> None:
    events = _events(tmp_path)
    html = render_report(events, _verified(events), scenario="office_intrusion")
    _assert_self_contained(html)


def test_every_event_is_anchored_in_the_appendix(tmp_path: Path) -> None:
    events = _events(tmp_path)
    html = render_report(events, _verified(events), scenario="office_intrusion")
    for event in events:
        assert f'id="event-{event.event_id}"' in html
        # The timeline links each event to its appendix anchor.
        assert f'href="#event-{event.event_id}"' in html


def test_accepted_claim_citation_links_to_its_backing_event(tmp_path: Path) -> None:
    events = _events(tmp_path)
    result = _verified(events)
    html = render_report(events, result, scenario="office_intrusion")

    assert len(result.accepted) == 1
    claim = result.accepted[0]
    # The inline citation links to the backing event, which is anchored in the
    # appendix (FR32): the link target exists in the document.
    assert claim.backing_event_id == PROCESS_CREATE_ID
    assert f'href="#event-{PROCESS_CREATE_ID}"' in html
    assert f'id="event-{PROCESS_CREATE_ID}"' in html


def test_accepted_claim_renders_verified_fields_not_prose(tmp_path: Path) -> None:
    events = _events(tmp_path)
    result = _verified(events)
    html = render_report(events, result, scenario="office_intrusion")

    # The accepted claim asserted only the action, so the verified statement must
    # carry the action and must not surface the prose's "administrator" as a fact.
    narrative = html.split('id="audit"', 1)[0]
    assert "process_create" in narrative
    assert "administrator" not in narrative.lower()


def test_rejected_claim_appears_in_the_audit_with_its_reason(tmp_path: Path) -> None:
    events = _events(tmp_path)
    result = _verified(events)
    html = render_report(events, result, scenario="office_intrusion")

    assert len(result.dropped) == 1
    # The audit section names the rejection reason and flags the drop.
    assert "principal_mismatch" in html
    assert "dropped" in html


def test_appendix_shows_technique_id_and_mapping_source(tmp_path: Path) -> None:
    # The appendix must render the structured ATT&CK tag for each tagged event,
    # both the technique id and the mapping source, for audit. The scenario's tags
    # come through as rule-tag passthrough, so that mapping source appears.
    events = _events(tmp_path)
    html = render_report(events, None, scenario="office_intrusion")

    appendix = html.split('id="appendix"', 1)[1]
    assert "rule_tag" in appendix
    assert "T1059.001" in appendix


def test_accepted_claim_links_backing_event_not_context_citation(tmp_path: Path) -> None:
    # The claim cites the process-create event (which backs the asserted action)
    # plus the unrelated logon event (which resolves but does not back the claim).
    # The inline evidence link must be the backing event; the unrelated citation is
    # shown only as context, never as the evidence for the statement.
    events = _events(tmp_path)
    model = StubModel(
        _response(
            {
                "text": "An encoded PowerShell process was created from Word.",
                "citations": [PROCESS_CREATE_ID, LATERAL_LOGON_ID],
                "asserts": {"action": "process_create"},
            }
        )
    )
    result = verify_narrative(events, model)
    assert len(result.accepted) == 1
    assert result.accepted[0].backing_event_id == PROCESS_CREATE_ID

    html = render_report(events, result, scenario="office_intrusion")
    narrative = html.split('id="audit"', 1)[0]
    # The backing event is the labeled evidence link.
    assert "Backing evidence:" in narrative
    assert f'href="#event-{PROCESS_CREATE_ID}"' in narrative
    # The unrelated citation appears only under the context label, not as evidence.
    assert "also cited for context" in narrative
    assert f'href="#event-{LATERAL_LOGON_ID}"' in narrative


def test_no_model_path_renders_deterministic_report_and_says_so(tmp_path: Path) -> None:
    events = _events(tmp_path)
    html = render_report(events, None, scenario="office_intrusion")

    _assert_self_contained(html)
    assert "No language model configured" in html
    assert NO_MODEL_LABEL in html
    # The deterministic content is still present: every event is anchored.
    for event in events:
        assert f'id="event-{event.event_id}"' in html
    # No claim was produced.
    assert 'class="claim"' not in html


def test_evidence_strings_are_html_escaped(tmp_path: Path) -> None:
    # An event whose message carries markup must never inject it into the report.
    hostile = Event(
        datetime="2026-03-14T08:42:17Z",
        timestamp_raw="2026-03-14 04:42:17.000 -04:00",
        source_timezone="America/New_York",
        timestamp_desc="logged",
        message="<script>alert('xss')</script>",
        action="process_create",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="synthetic_hayabusa.csv", record="line:2"),
        host="WIN-ACCT-07",
        principal="CORP\\jdoe",
        object="C:\\Windows\\System32\\cmd.exe",
    )
    html = render_report([hostile], None, scenario="escaping")
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html
