"""Tests for the self-contained HTML report (PRD FR28, FR32, FR26).

The load-bearing properties:

  1. Self-contained: the HTML fetches nothing at view time (no scripts, external
     stylesheets, fonts, or images), so it opens identically offline.
  2. Every link resolves: each narrative sentence links to its backing event,
     every link target is anchored in the document, and when a large case is
     capped a reference to an event left out is plain text, never a dead link.
  3. Evidence, not prose: each narrative sentence is phrased from its backing
     event's own fields, and a model's draft appears only in the labeled audit.
  4. The no-model path renders the deterministic key findings and says so (FR26).
  5. The ATT&CK matrix names techniques from the bundled catalog, shows a revoked
     id's translation, and keeps ids that are not current techniques off it.
  6. Autoescaping: evidence-derived strings cannot inject markup.

All tests run offline with no API keys; the narrative path uses a mocked model.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path
from typing import Any

import pytest

from casebound.generate.synth import write_samples
from casebound.narrate import OfflineDemoNarrator
from casebound.normalize.schema import AttackTechnique, Event, RawRef
from casebound.pipeline import Case, EvidenceInput, analyze, case_from_events
from casebound.report import NO_MODEL_LABEL, build_report_model, phrase_event, render_html
from casebound.verify import DraftRequest, verify_narrative

# Real event ids from the office_intrusion scenario at the default seed: the
# Word-spawned encoded PowerShell process-create event, and the lateral-movement
# network logon on the file server.
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


@pytest.fixture(scope="module")
def no_model_case(tmp_path_factory: pytest.TempPathFactory) -> Case:
    timeline, _ = write_samples(tmp_path_factory.mktemp("scenario"))
    return analyze([EvidenceInput(source="hayabusa", path=timeline)], name="office_intrusion")


@pytest.fixture(scope="module")
def narrated_case(no_model_case: Case) -> Case:
    """One accepted claim (with a context citation) and one rejected, dropped claim."""
    model = StubModel(
        _response(
            {
                # The prose names the administrator, but only the action is asserted:
                # the sentence a reader sees must come from the event, not the prose.
                "text": "The domain administrator spawned the encoded PowerShell process.",
                "citations": [PROCESS_CREATE_ID, LATERAL_LOGON_ID],
                "asserts": {"action": "process_create"},
            },
            {
                "text": "The domain administrator owned the PowerShell process.",
                "citations": [PROCESS_CREATE_ID],
                "asserts": {"principal": "CORP\\Administrator"},
            },
        )
    )
    result = verify_narrative(list(no_model_case.events), model, max_rounds=0)
    return case_from_events(
        no_model_case.events,
        name="office_intrusion",
        verification=result,
        narrative_label="stub model",
        provenance=no_model_case.provenance,
        inputs=no_model_case.inputs,
    )


def _event(**overrides: Any) -> Event:
    base: dict[str, Any] = {
        "datetime": "2026-03-14T08:42:17Z",
        "timestamp_raw": "2026-03-14 04:42:17.000 -04:00",
        "source_timezone": "UTC-04:00",
        "timestamp_desc": "logged",
        "message": "synthetic event",
        "action": "process_create",
        "source_tool": "hayabusa",
        "source_artifact": "Security.evtx",
        "raw_ref": RawRef(source_file="synthetic.csv", record="line:2"),
        "host": "WIN-ACCT-07",
        "principal": "CORP\\jdoe",
        "object": "C:\\Windows\\System32\\cmd.exe",
    }
    base.update(overrides)
    return Event(**base)


def _section(html: str, section_id: str) -> str:
    return html.split(f'<section id="{section_id}">', 1)[1].split("</section>", 1)[0]


def _assert_self_contained(html: str) -> None:
    assert html.startswith("<!DOCTYPE html>")
    assert "<script" not in html
    assert "<link" not in html
    assert "<img" not in html
    assert "@import" not in html
    assert "url(" not in html
    assert not re.search(r"(?:src|href)=\"(?!#)", html), "only in-page links are allowed"


def _assert_links_resolve(html: str) -> None:
    anchors = set(re.findall(r'id="(event-[0-9a-f]{64})"', html))
    targets = set(re.findall(r'href="#(event-[0-9a-f]{64})"', html))
    assert targets, "expected in-page evidence links"
    assert targets <= anchors, f"dangling links: {sorted(targets - anchors)[:3]}"


# 1 and 2. Self-contained, and every link resolves.


def test_report_is_self_contained(narrated_case: Case, no_model_case: Case) -> None:
    _assert_self_contained(render_html(narrated_case))
    _assert_self_contained(render_html(no_model_case))


def test_every_event_is_anchored_and_linked(no_model_case: Case) -> None:
    html = render_html(no_model_case)
    for event in no_model_case.events:
        assert f'id="event-{event.event_id}"' in html
        assert f'href="#event-{event.event_id}"' in html
    _assert_links_resolve(html)


def test_capped_report_never_links_to_an_event_it_left_out(narrated_case: Case) -> None:
    html = render_html(narrated_case, max_events=5)
    assert "This case has" in html
    model = build_report_model(narrated_case)
    shown, capped = model.displayed_events(5)
    assert capped and len(shown) == 5
    assert all(event["notable"] for event in shown)
    _assert_links_resolve(html)
    anchored = re.findall(r'id="event-([0-9a-f]{64})"', html)
    assert sorted(anchored) == sorted(event["event_id"] for event in shown)


# 3. Evidence, not prose.


def test_narrative_sentence_is_phrased_from_the_backing_event(narrated_case: Case) -> None:
    html = render_html(narrated_case)
    narrative = _section(html, "narrative")
    backing = narrated_case.event(PROCESS_CREATE_ID)
    assert backing is not None
    assert phrase_event(backing) in narrative
    assert "administrator" not in narrative.lower()
    assert "verified: action" in narrative
    # The backing event is the evidence link; the other citation is only context.
    assert f'Backing evidence: <a href="#event-{PROCESS_CREATE_ID}"' in narrative
    assert "also cited for context" in narrative
    assert f'href="#event-{LATERAL_LOGON_ID}"' in narrative.split("also cited for context", 1)[1]


def test_rejected_claim_appears_only_in_the_audit(narrated_case: Case) -> None:
    html = render_html(narrated_case)
    audit = _section(html, "audit")
    assert "principal_mismatch" in audit
    assert "dropped" in audit
    assert 'Model draft (rejected): "The domain administrator owned' in audit
    # The asserted account in the rejection detail is quoted as written (and the
    # quotes are HTML-escaped like every other evidence-derived string).
    assert "&#39;CORP\\Administrator&#39;" in audit
    assert "owned the PowerShell process" not in _section(html, "narrative")


def test_masthead_names_the_inputs_and_the_narrative_source(narrated_case: Case) -> None:
    html = render_html(narrated_case)
    assert "synthetic_hayabusa.csv (37 records)" in html
    assert "stub model" in html


# 4. The no-model path.


def test_no_model_report_shows_key_findings_and_says_so(no_model_case: Case) -> None:
    html = render_html(no_model_case)
    narrative = _section(html, "narrative")
    assert "No language model configured" in narrative
    assert NO_MODEL_LABEL in html
    assert 'class="entry claim"' not in html
    assert '<section id="audit">' not in html
    tagged = [event for event in no_model_case.events if event.attack_techniques]
    assert narrative.count('class="entry"') == len(tagged)
    for event in tagged:
        assert phrase_event(event) in narrative


def test_offline_narrator_report_shows_a_revised_claim(tmp_path: Path) -> None:
    timeline, _ = write_samples(tmp_path)
    case = analyze(
        [EvidenceInput(source="hayabusa", path=timeline)],
        name="office_intrusion",
        model=OfflineDemoNarrator(),
        model_label=OfflineDemoNarrator.LABEL,
    )
    html = render_html(case)
    assert "accepted after revision round 1" in html
    assert OfflineDemoNarrator.LABEL in html
    _assert_links_resolve(html)


# 5. The ATT&CK matrix.


def test_matrix_follows_the_enterprise_tactic_order(no_model_case: Case) -> None:
    matrix = _section(render_html(no_model_case), "attack")
    headings = re.findall(r"<h3>([^<]+)</h3>", matrix)
    assert headings[0] == "Initial Access"
    assert headings.index("Execution") < headings.index("Persistence")
    assert headings.index("Credential Access") < headings.index("Lateral Movement")
    assert "Exfiltration" in headings


def test_revoked_rule_tag_is_shown_under_its_successor(no_model_case: Case) -> None:
    html = render_html(no_model_case)
    assert "T1685.005" in _section(html, "attack")
    assert "T1070.001" not in _section(html, "attack")
    assert "written as T1070.001" in _section(html, "appendix")


def test_ids_that_are_not_current_techniques_stay_off_the_matrix() -> None:
    event = _event(attack_techniques=[AttackTechnique("T9999.001", "rule_tag")])
    html = render_html(case_from_events([event], name="unknown-technique"))
    matrix = _section(html, "attack")
    assert "Not current ATT&amp;CK techniques" in matrix
    assert "T9999.001" in matrix
    assert '<div class="matrix">' not in matrix


# Episodes, indicators, problems.


def test_episodes_and_defanged_indicators_are_shown(no_model_case: Case) -> None:
    html = render_html(no_model_case)
    assert 'class="chip ep">EP-' in _section(html, "episodes")
    iocs = _section(html, "iocs")
    assert "203[.]0[.]113[.]77" in iocs
    assert "203.0.113.77" not in iocs


def test_unparsed_rows_are_listed(tmp_path: Path) -> None:
    timeline, _ = write_samples(tmp_path)
    lines = timeline.read_text(encoding="utf-8").splitlines()
    broken = lines[1].replace("2026-03-14", "2026-13-99", 1)
    timeline.write_text("\n".join([*lines, broken]) + "\n", encoding="utf-8")
    record_id = next(csv.DictReader(io.StringIO("\n".join([lines[0], broken]))))["RecordID"]
    case = analyze([EvidenceInput(source="hayabusa", path=timeline)], name="broken")
    html = render_html(case)
    problems = html.split('<section id="problems">', 1)[1]
    assert "1 source row could not be" in problems
    assert f'hayabusa: {timeline.name}</td><td class="mono">{record_id}<' in problems


# Presentation and escaping.


def test_report_supports_dark_mode(no_model_case: Case) -> None:
    assert "@media (prefers-color-scheme: dark)" in render_html(no_model_case)


def test_null_fields_render_blank_not_the_literal_none() -> None:
    sparse = _event(host=None, principal=None, object=None, action="network_connect")
    html = render_html(case_from_events([sparse], name="nulls"))
    assert ">None<" not in html
    assert f'id="event-{sparse.event_id}"' in html


def test_evidence_strings_are_html_escaped() -> None:
    hostile = _event(
        message="<script>alert('xss')</script>",
        object='C:\\x"><img src=x onerror=alert(1)>.exe',
        attack_techniques=[AttackTechnique("T1059.001", "rule_tag")],
    )
    html = render_html(case_from_events([hostile], name="<b>case</b>"))
    assert "<script>alert" not in html
    assert "<img" not in html
    assert "&lt;script&gt;" in html
    assert "&lt;b&gt;case&lt;/b&gt;" in html
