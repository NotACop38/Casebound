"""Tests for the Velociraptor JSONL adapter (PRD FR6, FR7 to FR12).

The load-bearing properties:

  1. Golden mapping: a known Velociraptor JSONL export maps to a known, frozen set
     of canonical events (FR8 to FR11).
  2. Field derivation: EventID drives action, principal, and object; an uncovered
     EventID still maps at reduced confidence (FR8).
  3. Robustness: blank lines are skipped and an unparseable timestamp is reported,
     not fatal (FR7).
  4. De-duplication: identical rows collapse while provenance is retained (FR12).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from casebound.ingest import VelociraptorAdapter
from casebound.normalize import Event, NormalizationResult, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, VelociraptorMapper

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE_JSONL = FIXTURES / "velociraptor_evtx.jsonl"
SLICE_GOLDEN = FIXTURES / "velociraptor_evtx.events.json"


def _normalize(path: Path) -> NormalizationResult:
    return normalize_records(VelociraptorAdapter().read(path))


# 1. Golden mapping.


def test_slice_maps_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    result = _normalize(SLICE_JSONL)
    assert result.event_count == golden["event_count"]
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_golden_events_are_self_consistent() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        assert Event.from_dict(data).event_id == data["event_id"]


# 2. Field derivation.


def test_eventid_drives_canonical_fields() -> None:
    events = {e.action: e for e in _normalize(SLICE_JSONL).events}
    process_create = events["process_create"]
    assert process_create.host == "WIN-ACCT-07"
    assert process_create.principal == "CORP\\jdoe"
    assert process_create.object is not None
    assert process_create.object.endswith("powershell.exe")
    assert process_create.source_artifact == "Security.evtx"
    assert process_create.details["vql_artifact"] == "Windows.EventLogs.Evtx"

    network = events["network_connect"]
    assert network.object == "203.0.113.77:443"
    assert network.source_artifact == "Microsoft-Windows-Sysmon%4Operational.evtx"


def test_uncovered_eventid_still_maps_at_reduced_confidence() -> None:
    others = [e for e in _normalize(SLICE_JSONL).events if e.action == "other"]
    assert len(others) == 1
    assert others[0].confidence == 0.5
    assert others[0].details["win_event_id"] == 9999


# 3. Robustness (FR7).


def test_blank_lines_skipped_and_bad_timestamp_reported() -> None:
    result = _normalize(SLICE_JSONL)
    # The fixture has a blank line (ignored) and one unparseable-timestamp row.
    assert result.problem_count == 1
    assert result.problems[0].raw_ref.record == "80999"
    assert "timestamp" in result.problems[0].reason.lower()
    assert result.event_count == 4


# 4. De-duplication and the registry.


def test_identical_rows_dedupe_and_keep_all_provenance(tmp_path: Path) -> None:
    row = {
        "Timestamp": "2026-03-14T08:00:00Z",
        "Computer": "H",
        "Channel": "Security",
        "EventID": 4688,
        "Artifact": "Windows.EventLogs.Evtx",
        "EventData": {"NewProcessName": "C:\\x.exe", "SubjectUserName": "u"},
    }
    first = dict(row, EventRecordID=1)
    second = dict(row, EventRecordID=2)
    path = tmp_path / "dupe.jsonl"
    path.write_text(json.dumps(first) + "\n" + json.dumps(second) + "\n", encoding="utf-8")
    result = _normalize(path)
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    assert {ref.record for ref in refs} == {"1", "2"}


def test_default_registry_has_velociraptor() -> None:
    assert isinstance(DEFAULT_MAPPERS["velociraptor"], VelociraptorMapper)
