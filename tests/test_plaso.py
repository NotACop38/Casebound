"""Tests for the Plaso l2tcsv adapter (PRD FR6, FR7 to FR12).

The load-bearing properties:

  1. Golden mapping: a known Plaso l2tcsv export maps to a known, frozen set of
     canonical events (FR8 to FR11).
  2. Type semantics: the l2tcsv ``type`` column drives the timestamp descriptor and
     action; date, time, and timezone combine into a UTC instant (FR9).
  3. Robustness: a row with an impossible date is reported, not fatal (FR7).
  4. De-duplication: identical rows collapse while provenance is retained (FR12).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from casebound.ingest import PlasoAdapter
from casebound.normalize import Event, NormalizationResult, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, PlasoMapper
from casebound.normalize.mappers.plaso import parse_extra

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE_CSV = FIXTURES / "plaso_l2t.csv"
SLICE_GOLDEN = FIXTURES / "plaso_l2t.events.json"


def _normalize(path: Path) -> NormalizationResult:
    return normalize_records(PlasoAdapter().read(path))


# 1. Golden mapping.


def test_slice_maps_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    result = _normalize(SLICE_CSV)
    assert result.event_count == golden["event_count"]
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_golden_events_are_self_consistent() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        assert Event.from_dict(data).event_id == data["event_id"]


# 2. Type semantics and timestamp combination.


def test_type_drives_descriptor_and_action() -> None:
    events = _normalize(SLICE_CSV).events
    by_object = {(e.object, e.timestamp_desc): e for e in events}
    updater = "/Users/jdoe/AppData/Roaming/Microsoft/Windows/updater.exe"
    created = by_object[(updater, "created")]
    assert created.action == "file_create"
    assert created.datetime == "2026-03-14T08:44:12Z"
    assert created.source_timezone == "UTC"
    assert created.source_artifact == "NTFS $MFT"
    modified = by_object[(updater, "modified")]
    assert modified.action == "file_write"
    # An Event Logged row becomes a logged event from the WinEVTX source.
    logged = [e for e in events if e.timestamp_desc == "logged"]
    assert len(logged) == 1
    assert logged[0].action == "logged"
    assert logged[0].details["MACB"] == "...."
    assert logged[0].details["extra"]["event_identifier"] == "7045"


def test_unknown_user_placeholder_is_null() -> None:
    # Plaso writes "-" for an unknown user; it becomes a null principal.
    assert all(e.principal is None for e in _normalize(SLICE_CSV).events)


# 3. Robustness (FR7).


def test_impossible_date_is_reported_not_fatal() -> None:
    result = _normalize(SLICE_CSV)
    assert result.problem_count == 1
    assert result.problems[0].raw_ref.record == "line:6"
    assert "timestamp" in result.problems[0].reason.lower() or "month" in result.problems[0].reason
    assert result.event_count == 4


# 4. De-duplication and helpers.


def test_identical_rows_dedupe_and_keep_all_provenance(tmp_path: Path) -> None:
    header = ",".join(
        (
            "date,time,timezone,MACB,source,sourcetype,type,user,host,short,desc",
            "version,filename,inode,notes,format,extra",
        )
    )
    row = "03/14/2026,08:00:00,UTC,..B.,FILE,NTFS $MFT,Creation Time,-,H,s,d,2,/a.txt,1,,mft,"
    path = tmp_path / "dupe.csv"
    path.write_text(f"{header}\n{row}\n{row}\n", encoding="utf-8")
    result = _normalize(path)
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    assert {ref.record for ref in refs} == {"line:2", "line:3"}


def test_parse_extra_splits_on_first_colon() -> None:
    fields = parse_extra("sha256: 41686f19; url: http://x.example/a; noop")
    assert fields["sha256"] == "41686f19"
    assert fields["url"] == "http://x.example/a"
    assert "noop" not in fields


def test_default_registry_has_plaso() -> None:
    assert isinstance(DEFAULT_MAPPERS["plaso"], PlasoMapper)
