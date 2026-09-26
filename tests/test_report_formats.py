"""Tests for the JSON report, the Markdown report, the events file, and the writer
(PRD FR29, FR30).

The load-bearing properties:

  1. One content model: the HTML, JSON, and Markdown reports carry the same events,
     statistics, narrative, and audit, so the formats can never drift apart.
  2. The JSON report is complete: it always carries every event, even when the
     HTML and Markdown are capped for readability, and it round-trips through JSON.
  3. ``events.jsonl`` is the canonical timeline, one event per line, loadable back
     into ``Event`` with every id intact (it is what ``casebound verify`` reads).
  4. The Markdown is safe to paste into a ticket: attacker-controlled evidence
     cannot inject HTML, links, headings, or table structure, and URLs are defanged.
  5. The writer produces every artifact deterministically.

All tests run offline with no API keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from casebound.generate.synth import write_samples
from casebound.normalize.schema import AttackTechnique, Event, RawRef
from casebound.pipeline import Case, EvidenceInput, analyze, case_from_events
from casebound.report import (
    EVENTS_NAME,
    LAYER_NAME,
    REPORT_HTML_NAME,
    REPORT_JSON_NAME,
    REPORT_MARKDOWN_NAME,
    build_report_model,
    phrase_event,
    render_events_jsonl,
    render_html,
    render_json,
    render_markdown,
    write_reports,
)
from casebound.verify import verify_narrative

PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"


class StubModel:
    def __init__(self, *claims: dict[str, Any]) -> None:
        self.response = json.dumps({"claims": list(claims)})

    def draft(self, request: object) -> str:
        return self.response


@pytest.fixture(scope="module")
def case(tmp_path_factory: pytest.TempPathFactory) -> Case:
    timeline, _ = write_samples(tmp_path_factory.mktemp("scenario"))
    base = analyze([EvidenceInput(source="hayabusa", path=timeline)], name="office_intrusion")
    model = StubModel(
        {
            "text": "PowerShell ran.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"action": "process_create", "principal": "corp\\JDOE"},
        },
        {
            "text": "The administrator ran PowerShell.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\Administrator"},
        },
    )
    result = verify_narrative(list(base.events), model, max_rounds=0)
    return case_from_events(
        base.events,
        name=base.name,
        verification=result,
        narrative_label="stub model",
        provenance=base.provenance,
        inputs=base.inputs,
    )


def _event(**overrides: Any) -> Event:
    base: dict[str, Any] = {
        "datetime": "2026-03-14T09:00:17Z",
        "timestamp_raw": "2026-03-14T09:00:17Z",
        "source_timezone": "UTC",
        "timestamp_desc": "logged",
        "message": "synthetic",
        "action": "process_create",
        "source_tool": "hayabusa",
        "source_artifact": "Security.evtx",
        "raw_ref": RawRef(source_file="x.csv", record="1"),
        "host": "HOST-1",
        "principal": "CORP\\jdoe",
        "object": "C:\\tools\\a.exe",
    }
    base.update(overrides)
    return Event(**base)


# 1 and 2. One content model, and a complete JSON report.


def test_json_report_carries_the_whole_model(case: Case) -> None:
    report = json.loads(render_json(case))
    assert report["generator"].startswith("Casebound ")
    assert report["schema_version"] == "0.2"
    assert report["case"]["inputs"] == [
        {"source": "hayabusa", "file": "synthetic_hayabusa.csv", "records": 37}
    ]
    assert len(report["events"]) == report["stats"]["events"] == len(case.events)
    [entry] = report["narrative"]["entries"]
    backing = case.event(PROCESS_CREATE_ID)
    assert backing is not None
    assert entry["backing_event_id"] == PROCESS_CREATE_ID
    assert entry["statement"] == phrase_event(backing)
    assert entry["verified_fields"] == ["principal", "action"]
    [rejected] = report["audit"]
    assert rejected["reason"] == "principal_mismatch" and rejected["dropped"] is True
    # The model's spelling of the principal never reaches the report.
    assert "corp\\\\JDOE" not in json.dumps(report)


def test_json_report_is_never_capped(case: Case) -> None:
    model = build_report_model(case)
    shown, capped = model.displayed_events(3)
    assert capped and len(shown) == 3
    assert len(json.loads(render_json(case, model=model))["events"]) == len(case.events)


def test_json_events_carry_annotations_and_provenance(case: Case) -> None:
    events = {event["event_id"]: event for event in json.loads(render_json(case))["events"]}
    powershell = events[PROCESS_CREATE_ID]
    assert powershell["provenance"] == ["synthetic_hayabusa.csv#81104"]
    assert powershell["severity"] == "high"
    assert powershell["episode_id"].startswith("EP-")
    assert powershell["notable"] is True
    assert {tech["technique_id"] for tech in powershell["techniques"]} == {
        "T1059.001",
        "T1566.001",
    }
    assert all(tech["status"] == "active" for tech in powershell["techniques"])
    log_clear = next(event for event in events.values() if event["action"] == "log_clear")
    assert log_clear["techniques"][0]["source_id"] == "T1070.001"


def test_formats_agree_on_events_and_statistics(case: Case) -> None:
    report = json.loads(render_json(case))
    html = render_html(case)
    markdown = render_markdown(case)
    for event in report["events"]:
        assert f'id="event-{event["event_id"]}"' in html
        assert f"`{event['event_id'][:12]}`" in markdown
    assert f"|Events|{report['stats']['events']}|" in markdown
    assert f"|Verified claims|{report['stats']['narrative_entries']}|" in markdown
    statement = report["narrative"]["entries"][0]["statement"]
    assert statement in html


# 3. The events file.


def test_events_jsonl_round_trips_every_event(case: Case) -> None:
    lines = render_events_jsonl(case.events).splitlines()
    assert len(lines) == len(case.events)
    loaded = [Event.from_dict(json.loads(line)) for line in lines]
    assert [event.event_id for event in loaded] == [event.event_id for event in case.events]
    assert loaded == list(case.events)


# 4. Markdown is safe to paste.


def test_markdown_renders_every_section(case: Case) -> None:
    markdown = render_markdown(case)
    for heading in (
        "## Summary",
        "## Verified narrative",
        "## Rejected-claims audit",
        "## ATT&CK matrix",
        "## Activity episodes",
        "## Indicators of compromise",
        "## Timeline",
    ):
        assert heading in markdown
    assert markdown.endswith("\n") and not markdown.endswith("\n\n")


def test_markdown_defangs_network_indicators(case: Case) -> None:
    iocs = render_markdown(case).split("## Indicators of compromise", 1)[1].split("## Timeline")[0]
    assert "203[.]0[.]113[.]77" in iocs
    assert "203.0.113.77" not in iocs


def test_markdown_neutralizes_hostile_evidence() -> None:
    hostile = _event(
        message="<script>alert(1)</script> [click me](javascript:alert(1))\n# fake heading",
        principal="CORP\\evil`whoami`",
        object="C:\\tools\\a|b`c.exe",
        details={"Cmd`Line": "run `this` | that"},
        attack_techniques=[AttackTechnique("T1059.001", "rule_tag")],
    )
    markdown = render_markdown(case_from_events([hostile], name="hostile<&>case"))
    assert "<script>" not in markdown
    assert "[click me](javascript:" not in markdown
    assert "\n# fake heading" not in markdown
    assert "evil'whoami'" in markdown
    assert "a\\|b'c.exe" in markdown


def test_markdown_neutralizes_model_authored_strings_and_urls() -> None:
    hostile = _event(message="stager pulled from http://evil.example/payload", object="C:\\a`b.exe")
    citation = "x`\n# injected heading\n<script>alert(1)</script>y"
    verification = verify_narrative(
        [hostile],
        StubModel(
            {
                "text": "A fabricated claim with a hostile citation.",
                "citations": [citation],
                "asserts": {"action": "process_create"},
            }
        ),
        max_rounds=0,
    )
    assert verification.accepted == ()
    markdown = render_markdown(
        case_from_events([hostile], name="audit-injection", verification=verification)
    )
    assert "\n# injected heading" not in markdown
    assert "`x' # injected heading" in markdown
    assert "a`b.exe" not in markdown
    assert "hxxp://evil.example/payload" in markdown
    assert "http://evil.example" not in markdown


def test_no_model_formats_say_so(tmp_path: Path) -> None:
    timeline, _ = write_samples(tmp_path)
    case = analyze([EvidenceInput(source="hayabusa", path=timeline)], name="office_intrusion")
    markdown = render_markdown(case)
    assert "## Key findings" in markdown
    assert "No language model configured" in markdown
    assert "## Rejected-claims audit" not in markdown
    report = json.loads(render_json(case))
    assert report["narrative"]["no_model"] is True
    assert report["narrative"]["entries"] == []
    assert len(report["findings"]) == sum(1 for event in case.events if event.attack_techniques)


def test_findings_include_severe_detections_without_a_technique() -> None:
    severe = _event(details={"level": "crit"}, object="C:\\x.exe")
    quiet = _event(details={"level": "info"}, object="C:\\y.exe", datetime="2026-03-14T09:01:00Z")
    report = json.loads(render_json(case_from_events([severe, quiet], name="severity")))
    assert [entry["backing_event_id"] for entry in report["findings"]] == [severe.event_id]
    assert report["findings"][0]["severity"] == "critical"


def test_subsecond_events_order_chronologically() -> None:
    whole = _event(datetime="2026-03-14T09:00:17Z")
    fractional = _event(datetime="2026-03-14T09:00:17.5Z", object="C:\\b.exe")
    model = build_report_model(case_from_events([fractional, whole], name="order"))
    assert [entry["event_id"] for entry in model.events] == [whole.event_id, fractional.event_id]


# 5. The writer.


def test_writer_produces_every_artifact_deterministically(case: Case, tmp_path: Path) -> None:
    first = write_reports(case, tmp_path / "a")
    second = write_reports(case, tmp_path / "b")
    names = [path.name for path in first.all()]
    assert names == [
        REPORT_HTML_NAME,
        REPORT_MARKDOWN_NAME,
        REPORT_JSON_NAME,
        EVENTS_NAME,
        LAYER_NAME,
    ]
    for left, right in zip(first.all(), second.all(), strict=True):
        assert left.read_bytes() == right.read_bytes(), left.name
