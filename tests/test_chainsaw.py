"""Tests for the Chainsaw adapter (PRD FR5, FR7 to FR14).

The load-bearing properties:

  1. Golden mapping: a known Chainsaw ``--json`` detections file maps to a known,
     frozen set of canonical events (FR8 to FR11).
  2. Field derivation: EventID drives the action, principal, and object; an
     uncovered EventID still produces an event at reduced confidence (FR8).
  3. ATT&CK passthrough: Sigma ``attack.tXXXX`` tags normalize to canonical ids in
     details and the later tagging step promotes them (FR13).
  4. Timestamp fallback: a detection with no top-level timestamp is timed from the
     wrapped event's System.TimeCreated.
  5. De-duplication: identical detections collapse while provenance is retained
     (FR12).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from casebound.enrich.attack import tag_events
from casebound.ingest import ChainsawAdapter
from casebound.normalize import Event, NormalizationResult, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, ChainsawMapper
from casebound.normalize.mappers.chainsaw import normalize_attack_tag

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE_JSON = FIXTURES / "chainsaw_detections.json"
SLICE_GOLDEN = FIXTURES / "chainsaw_detections.events.json"


def _normalize(path: Path) -> NormalizationResult:
    return normalize_records(ChainsawAdapter().read(path))


# 1. Golden mapping.


def test_slice_maps_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    result = _normalize(SLICE_JSON)
    assert result.event_count == golden["event_count"]
    assert result.problem_count == 0
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_golden_events_are_self_consistent() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        assert Event.from_dict(data).event_id == data["event_id"]


# 2. Field derivation.


def test_eventid_drives_action_principal_and_object() -> None:
    events = {e.action: e for e in _normalize(SLICE_JSON).events}
    process_create = events["process_create"]
    assert process_create.host == "WIN-ACCT-07"
    assert process_create.principal == "CORP\\jdoe"
    assert process_create.object is not None
    assert process_create.object.endswith("powershell.exe")
    assert process_create.source_artifact == "Security.evtx"

    network_connect = events["network_connect"]
    assert network_connect.object == "203.0.113.77:443"
    assert network_connect.message == "PowerShell Network Connection to Rare External Host"


def test_uncovered_eventid_still_maps_at_reduced_confidence() -> None:
    events = [e for e in _normalize(SLICE_JSON).events if e.action == "other"]
    assert len(events) == 1
    assert events[0].confidence == 0.5
    assert events[0].details["win_event_id"] == 9999


# 3. ATT&CK passthrough.


def test_sigma_attack_tags_normalize_and_promote() -> None:
    events = {e.action: e for e in _normalize(SLICE_JSON).events}
    # The raw Sigma tags are normalized to canonical technique ids in details.
    assert events["process_create"].details["rule_mitre_tags"] == ["T1566.001", "T1059.001"]
    # Normalization itself: only real technique tags survive, uppercased.
    assert normalize_attack_tag("attack.t1059.001") == "T1059.001"
    assert normalize_attack_tag("attack.execution") is None
    # The deterministic tagging step promotes them as rule_tag passthrough (FR13).
    tagged = {e.action: e for e in tag_events(_normalize(SLICE_JSON).events)}
    ids = {t.technique_id for t in tagged["process_create"].attack_techniques}
    assert ids == {"T1566.001", "T1059.001"}
    assert all(t.mapping_source == "rule_tag" for t in tagged["process_create"].attack_techniques)


# 4. Timestamp fallback.


def test_timestamp_falls_back_to_system_time_created() -> None:
    # The Sysmon network detection carries no top-level timestamp, so it is timed
    # from the wrapped event's System.TimeCreated SystemTime.
    network = next(e for e in _normalize(SLICE_JSON).events if e.action == "network_connect")
    assert network.datetime == "2026-03-14T08:43:05Z"
    assert network.source_timezone == "UTC"


# 5. De-duplication and the registry.


def test_identical_detections_dedupe_and_keep_all_provenance(tmp_path: Path) -> None:
    detection = {
        "name": "Repeated",
        "timestamp": "2026-03-14T08:00:00Z",
        "tags": [],
        "document": {
            "path": "C:\\evidence\\h\\Security.evtx",
            "data": {
                "Event": {
                    "System": {
                        "EventID": 4688,
                        "Channel": "Security",
                        "Computer": "H",
                        "EventRecordID": 1,
                    },
                    "EventData": {"NewProcessName": "C:\\x.exe", "SubjectUserName": "u"},
                }
            },
        },
    }
    second = json.loads(json.dumps(detection))
    second["document"]["data"]["Event"]["System"]["EventRecordID"] = 2
    path = tmp_path / "dupe.json"
    path.write_text(json.dumps([detection, second]), encoding="utf-8")
    result = _normalize(path)
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    assert {ref.record for ref in refs} == {"1", "2"}


def test_non_array_document_yields_nothing(tmp_path: Path) -> None:
    path = tmp_path / "obj.json"
    path.write_text('{"not": "an array"}', encoding="utf-8")
    assert list(ChainsawAdapter().read(path)) == []


def test_default_registry_has_chainsaw() -> None:
    assert isinstance(DEFAULT_MAPPERS["chainsaw"], ChainsawMapper)
