"""Tests for the ATT&CK Navigator layer (PRD FR31).

The load-bearing properties:

  1. Shape: the layer is a Navigator layer-format 4.5 document for the Enterprise
     domain, pinned to the bundled ATT&CK release, that the Navigator can load.
  2. Content: each observed current technique is one scored entry whose score is
     the number of events exhibiting it and whose comment is its ATT&CK name.
  3. Robustness: an id that is not a current technique (unknown to the catalog, or
     deprecated) never fails the run and never reaches the Navigator as an
     unloadable cell; it is named in the description instead.
  4. Determinism: the same events always render byte-identical JSON.
  5. The committed sample layer is exactly what the demo regenerates.
"""

from __future__ import annotations

import json
from pathlib import Path

from casebound.enrich.attack import tag_events
from casebound.enrich.catalog import load_catalog
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, RawRef, normalize_records
from casebound.normalize.schema import AttackTechnique
from casebound.report.attack_layer import (
    LAYER_VERSION,
    build_navigator_layer,
    render_navigator_layer,
    technique_counts,
    write_navigator_layer,
)

ROOT = Path(__file__).resolve().parents[1]


def _event(record: str, *technique_ids: str) -> Event:
    return Event(
        datetime="2026-03-14T08:42:17Z",
        timestamp_raw="2026-03-14T08:42:17Z",
        source_timezone="UTC",
        timestamp_desc="logged",
        message=f"synthetic event {record}",
        action="process_create",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record=record),
        attack_techniques=[AttackTechnique(tid, "rule_tag") for tid in technique_ids],
    )


def _scenario_events(tmp_path: Path) -> list[Event]:
    csv_path, _ = write_samples(tmp_path)
    return tag_events(normalize_records(HayabusaAdapter().read(csv_path)).events)


def test_layer_shape_is_loadable_by_the_navigator() -> None:
    layer = build_navigator_layer([_event("1", "T1059.001")], name="unit")
    catalog = load_catalog()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"] == {
        "attack": catalog.major_version,
        "navigator": layer["versions"]["navigator"],
        "layer": LAYER_VERSION,
    }
    assert layer["name"] == "Casebound: unit"
    assert layer["gradient"]["minValue"] == 0
    assert set(layer["techniques"][0]) == {"techniqueID", "score", "comment", "enabled"}


def test_scores_count_events_and_comments_name_the_technique() -> None:
    events = [
        _event("1", "T1059.001", "T1566.001"),
        _event("2", "T1059.001"),
        # A technique listed twice on one event still counts that event once.
        _event("3", "T1003.001", "T1003.001"),
    ]
    layer = build_navigator_layer(events, name="unit")
    by_id = {tech["techniqueID"]: tech for tech in layer["techniques"]}
    assert {tid: tech["score"] for tid, tech in by_id.items()} == {
        "T1003.001": 1,
        "T1059.001": 2,
        "T1566.001": 1,
    }
    assert by_id["T1059.001"]["comment"] == "Command and Scripting Interpreter: PowerShell"
    assert layer["gradient"]["maxValue"] == 2
    assert [tech["techniqueID"] for tech in layer["techniques"]] == sorted(by_id)


def test_ids_that_are_not_current_techniques_are_left_out_and_named() -> None:
    # T9999 is unknown to the catalog; T1070.001 was revoked in ATT&CK v19. Neither
    # may reach the Navigator, and neither may fail the run.
    layer = build_navigator_layer(
        [_event("1", "T1059.001", "T9999"), _event("2", "T1070.001")], name="unit"
    )
    assert [tech["techniqueID"] for tech in layer["techniques"]] == ["T1059.001"]
    assert "T9999" in layer["description"]
    assert "T1070.001" in layer["description"]


def test_a_case_without_techniques_still_yields_a_layer() -> None:
    layer = build_navigator_layer([_event("1")], name="quiet")
    assert layer["techniques"] == []
    assert layer["gradient"]["maxValue"] == 1


def test_technique_counts() -> None:
    assert technique_counts([_event("1", "T1059.001"), _event("2", "T1059.001", "T1105")]) == {
        "T1059.001": 2,
        "T1105": 1,
    }


def test_rendering_is_deterministic_and_newline_terminated(tmp_path: Path) -> None:
    events = _scenario_events(tmp_path)
    first = render_navigator_layer(events, name="office_intrusion")
    second = render_navigator_layer(list(reversed(events)), name="office_intrusion")
    assert first == second
    assert first.endswith("}\n")
    written = write_navigator_layer(
        tmp_path / "out" / "layer.json", events, name="office_intrusion"
    )
    assert written.read_text(encoding="utf-8") == first


def test_scenario_layer_holds_every_labeled_technique(tmp_path: Path) -> None:
    events = _scenario_events(tmp_path)
    labels = json.loads((tmp_path / "ground_truth.json").read_text(encoding="utf-8"))
    layer = build_navigator_layer(events, name="office_intrusion")
    assert {tech["techniqueID"] for tech in layer["techniques"]} == set(labels["techniques"])


def test_committed_sample_layer_matches_a_fresh_render(tmp_path: Path) -> None:
    events = _scenario_events(tmp_path)
    committed = (ROOT / "samples" / "attack_navigator_layer.json").read_text(encoding="utf-8")
    assert committed == render_navigator_layer(events, name="office_intrusion")
