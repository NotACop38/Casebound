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


def test_html_and_json_agree_on_field_values_including_nulls(tmp_path: Path) -> None:
    # Content parity at the field level: the HTML and the JSON must agree on the
    # canonical fields. This is the drift class the shared model exists to prevent;
    # in particular a null host, principal, or object must render as a blank cell in
    # the HTML (never the literal text "None"), matching the JSON's real null and the
    # Markdown's blank cell. The office_intrusion scenario carries several such nulls.
    events = _events(tmp_path)
    html = render_report(events, None, scenario="office_intrusion")
    body = json.loads(render_json_report(events, None, scenario="office_intrusion"))

    # The HTML must never surface a Python None as text for a nullable field.
    assert ">None<" not in html

    saw_null = False
    for event in body["events"]:
        for field in ("host", "principal", "object", "action"):
            value = event[field]
            if value is None:
                saw_null = True
            else:
                # Every present canonical value the JSON carries is shown in the HTML
                # (these fields are plain ASCII paths, accounts, ips, and verbs, so
                # they are not transformed by HTML escaping).
                assert value in html
    # The scenario is only an honest null-parity test if it actually has a null.
    assert saw_null


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


def test_markdown_appendix_includes_event_details(tmp_path: Path) -> None:
    # Parity with the HTML appendix: the ticket-ready Markdown must carry the
    # source-specific detail fields (the Hayabusa command line, destination fields,
    # and so on) so an analyst can audit an event without opening the HTML or JSON.
    events = _events(tmp_path)
    md = render_markdown_report(events, None, scenario="office_intrusion")
    appendix = md.split("## Evidence appendix", 1)[1]

    assert "- details:" in appendix
    # The nested Hayabusa fields block and a concrete field value are both present.
    assert "- fields:" in appendix
    assert "CommandLine" in appendix


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


def test_report_timeline_orders_subsecond_events_chronologically(tmp_path: Path) -> None:
    # The shared report model sorts on the parsed instant: the canonical form
    # trims trailing zeros, so a plain string sort would put "...17.5Z" before
    # "...17Z" while it is half a second later.
    from casebound.normalize import RawRef
    from casebound.report.model import build_report_model

    def _stamped(stamp: str, record: str) -> Event:
        return Event(
            datetime=stamp,
            timestamp_raw=stamp,
            source_timezone="UTC",
            timestamp_desc="logged",
            message=f"event at {stamp}",
            action="process_create",
            source_tool="hayabusa",
            source_artifact="Security.evtx",
            raw_ref=RawRef(source_file="x.csv", record=record),
            host="HOST-1",
        )

    whole = _stamped("2026-03-14T09:00:17Z", "1")
    fractional = _stamped("2026-03-14T09:00:17.5Z", "2")

    model = build_report_model([fractional, whole], None, scenario="subsecond-order")
    assert [entry["event_id"] for entry in model.events] == [
        whole.event_id,
        fractional.event_id,
    ]


def test_markdown_neutralizes_hostile_evidence_content(tmp_path: Path) -> None:
    # Evidence fields are attacker-controlled: a crafted message, principal, or
    # object must not be able to inject raw HTML, a javascript: link, a code-span
    # breakout, or new document structure into the ticket-ready Markdown.
    from casebound.normalize import RawRef
    from casebound.report.markdown import render_markdown_report

    hostile = Event(
        datetime="2026-03-14T09:00:17Z",
        timestamp_raw="2026-03-14T09:00:17Z",
        source_timezone="UTC",
        timestamp_desc="logged",
        message="<script>alert(1)</script> [click me](javascript:alert(1))\n# fake heading",
        action="process_create",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record="1"),
        host="HOST-1",
        principal="CORP\\evil`whoami`",
        object="C:\\tools\\a|b`c.exe",
        details={"Cmd`Line": "run `this` | that"},
    )

    markdown = render_markdown_report([hostile], None, scenario="hostile<&>case")

    # Raw HTML and the javascript: link are escaped, not emitted.
    assert "<script>" not in markdown
    assert "[click me](javascript:" not in markdown
    # The embedded newline cannot start a new heading line.
    assert "\n# fake heading" not in markdown
    # No code span in the document carries an interior backtick or raw pipe; the
    # hostile principal and object render with backticks replaced.
    assert "evil'whoami'" in markdown
    assert "a\\|b'c.exe" in markdown
