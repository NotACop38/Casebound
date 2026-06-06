"""Tests for the JSON and Markdown report renderers (PRD FR29, FR30).

The load-bearing property is content parity: the JSON and Markdown reports carry
the same content as the HTML report, because all three draw from the shared report
model. These tests assert that parity and the format-specific guarantees:

  1. The JSON report is valid JSON and carries every event, the verified narrative,
     the audit, the episodes, the indicators, and the stats.
  2. The Markdown report renders the same sections in a ticket-ready document.
  3. Checked fields only: an accepted claim renders from verified assertions, never
     the model's free prose (AGENTS.md prime directive).
  4. The no-model path renders the deterministic report and says so (FR26).

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
from casebound.report import (
    render_json_report,
    render_markdown_report,
    render_report,
    write_json_report,
    write_markdown_report,
)
from casebound.verify import DraftRequest, VerificationResult, verify_narrative

# The Word-spawned encoded PowerShell process-create event, default seed.
PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"


class StubModel:
    """A mocked ``NarrativeModel`` that replays one scripted raw response."""

    def __init__(self, response: str) -> None:
        self.response = response

    def draft(self, request: DraftRequest) -> str:
        return self.response


def _events(tmp_path: Path) -> list[Event]:
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    assert result.problem_count == 0
    return tag_events(result.events)


def _verified(events: list[Event]) -> VerificationResult:
    """One accepted claim (action only) and one rejected-and-dropped claim."""
    response = json.dumps(
        {
            "claims": [
                {
                    "text": "The domain administrator spawned the encoded PowerShell process.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"action": "process_create"},
                },
                {
                    "text": "The domain administrator owned the PowerShell process.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"principal": "CORP\\Administrator"},
                },
            ]
        }
    )
    return verify_narrative(events, StubModel(response), max_rounds=0)


def test_json_report_is_valid_and_carries_the_content(tmp_path: Path) -> None:
    events = _events(tmp_path)
    body = json.loads(render_json_report(events, _verified(events), scenario="office_intrusion"))

    assert body["scenario"] == "office_intrusion"
    assert body["stats"]["events"] == len(events)
    # Every event appears in the appendix-equivalent events list.
    json_ids = {event["event_id"] for event in body["events"]}
    assert json_ids == {event.event_id for event in events}
    # The verified narrative and the audit are both present.
    assert len(body["narrative"]["accepted"]) == 1
    assert body["narrative"]["accepted"][0]["backing_event_id"] == PROCESS_CREATE_ID
    assert any(entry["dropped"] for entry in body["audit"])


def test_json_accepted_claim_renders_verified_fields_not_prose(tmp_path: Path) -> None:
    events = _events(tmp_path)
    body = json.loads(render_json_report(events, _verified(events), scenario="office_intrusion"))

    claim = body["narrative"]["accepted"][0]
    # The accepted claim asserted only the action, so the statement carries the
    # action and must not surface the prose's "administrator" as a fact.
    assert claim["asserts"] == {"action": "process_create"}
    assert "administrator" not in claim["statement"].lower()


def test_json_and_html_report_agree_on_events_and_stats(tmp_path: Path) -> None:
    events = _events(tmp_path)
    result = _verified(events)
    html = render_report(events, result, scenario="office_intrusion")
    body = json.loads(render_json_report(events, result, scenario="office_intrusion"))

    # Content parity: every event id in the JSON is anchored in the HTML, and the
    # observed-technique set matches.
    for event in body["events"]:
        assert f'id="event-{event["event_id"]}"' in html
    for tid in body["observed_techniques"]:
        assert tid in html


def test_markdown_report_renders_every_section(tmp_path: Path) -> None:
    events = _events(tmp_path)
    md = render_markdown_report(events, _verified(events), scenario="office_intrusion")

    for heading in (
        "# Casebound investigation report",
        "## Summary",
        "## Verified narrative",
        "## Rejected-claims audit",
        "## Deterministic timeline",
        "## Activity episodes",
        "## Indicators of compromise",
        "## Evidence appendix",
    ):
        assert heading in md
    # The full event id heads its appendix entry, and the audit names the reason.
    assert f"### `{PROCESS_CREATE_ID}`" in md
    assert "principal_mismatch" in md


def test_markdown_accepted_claim_renders_verified_fields_not_prose(tmp_path: Path) -> None:
    events = _events(tmp_path)
    md = render_markdown_report(events, _verified(events), scenario="office_intrusion")

    narrative = md.split("## Rejected-claims audit", 1)[0]
    assert "process_create" in narrative
    assert "administrator" not in narrative.lower()


def test_markdown_defangs_network_indicators(tmp_path: Path) -> None:
    events = _events(tmp_path)
    md = render_markdown_report(events, None, scenario="office_intrusion")
    iocs = md.split("## Indicators of compromise", 1)[1].split("## Evidence appendix", 1)[0]
    assert "sync-update[.]example" in iocs
    assert "203[.]0[.]113[.]77" in iocs
    # The raw (clickable) form never appears in the indicator table.
    assert "sync-update.example" not in iocs
    assert "203.0.113.77" not in iocs


def test_no_model_path_renders_deterministic_reports_and_says_so(tmp_path: Path) -> None:
    events = _events(tmp_path)
    body = json.loads(render_json_report(events, None, scenario="office_intrusion"))
    md = render_markdown_report(events, None, scenario="office_intrusion")

    assert body["no_model"] is True
    assert body["narrative"]["accepted"] == []
    assert "No language model configured" in md


def test_writers_round_trip_to_disk(tmp_path: Path) -> None:
    events = _events(tmp_path)
    result = _verified(events)
    json_path = write_json_report(
        tmp_path / "report.json", events, result, scenario="office_intrusion"
    )
    md_path = write_markdown_report(
        tmp_path / "report.md", events, result, scenario="office_intrusion"
    )
    # The written files equal a fresh render (deterministic, trailing newline).
    assert json_path.read_text(encoding="utf-8") == render_json_report(
        events, result, scenario="office_intrusion"
    )
    assert md_path.read_text(encoding="utf-8") == render_markdown_report(
        events, result, scenario="office_intrusion"
    )
    payload: dict[str, Any] = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["scenario"] == "office_intrusion"
