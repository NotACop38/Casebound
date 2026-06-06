"""Tests for the generic CSV adapter and its column-mapping config (PRD FR4, FR7 to FR12).

The load-bearing properties:

  1. Golden mapping: a known CSV plus its documented column-mapping config maps to
     a known, frozen set of canonical events (FR4, FR8 to FR11).
  2. Config behavior: free-form action labels normalize to canonical verbs, unmapped
     columns are preserved as details, and a missing message is synthesized.
  3. Robustness: a row with an unparseable timestamp is reported, not fatal (FR7).
  4. De-duplication: identical events collapse while provenance is retained (FR12).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from casebound.ingest import ColumnMap, GenericCsvAdapter
from casebound.normalize import Event, NormalizationResult, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, GenericCsvMapper

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE_CSV = FIXTURES / "generic_edr_slice.csv"
SLICE_GOLDEN = FIXTURES / "generic_edr_slice.events.json"
SLICE_MAP = FIXTURES / "generic_edr_map.json"


def _normalize(path: Path, column_map: ColumnMap) -> NormalizationResult:
    return normalize_records(GenericCsvAdapter(column_map).read(path))


# 1. Golden mapping: known input plus config maps to a known set of events.


def test_slice_maps_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    column_map = ColumnMap.from_json(SLICE_MAP)
    result = _normalize(SLICE_CSV, column_map)
    assert result.event_count == golden["event_count"]
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_golden_events_are_self_consistent() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        assert Event.from_dict(data).event_id == data["event_id"]


# 2. Config behavior.


def test_free_form_action_labels_normalize_to_canonical_verbs() -> None:
    events = {e.action for e in _normalize(SLICE_CSV, ColumnMap.from_json(SLICE_MAP)).events}
    # "Process Create" -> process_create, "Network Connect" -> network_connect, etc.
    assert {"process_create", "network_connect", "registry_set", "logon"} <= events


def test_unmapped_columns_are_preserved_as_details() -> None:
    events = _normalize(SLICE_CSV, ColumnMap.from_json(SLICE_MAP)).events
    first = events[0]
    # Severity is not mapped to a canonical field, so it lands in details by default.
    assert first.details == {"Severity": "high"}
    assert first.timestamp_desc == "logged"
    assert first.source_artifact == "edr_export.csv"
    assert first.source_timezone == "UTC"


def test_missing_message_column_synthesizes_a_message(tmp_path: Path) -> None:
    csv_text = "When,Who,Verb,Thing\n2026-03-14T08:00:00Z,jdoe,Logon,10.0.0.5\n"
    path = tmp_path / "no_message.csv"
    path.write_text(csv_text, encoding="utf-8")
    column_map = ColumnMap(
        timestamp="When",
        principal_column="Who",
        action_column="Verb",
        object_column="Thing",
    )
    event = _normalize(path, column_map).events[0]
    assert event.message == "logon 10.0.0.5"


def test_detail_columns_can_be_selected_explicitly(tmp_path: Path) -> None:
    csv_text = "When,Verb,Keep,Drop\n2026-03-14T08:00:00Z,Logon,yes,no\n"
    path = tmp_path / "details.csv"
    path.write_text(csv_text, encoding="utf-8")
    column_map = ColumnMap(timestamp="When", action_column="Verb", detail_columns=("Keep",))
    event = _normalize(path, column_map).events[0]
    assert event.details == {"Keep": "yes"}


def test_assume_timezone_is_honored_for_offsetless_timestamps(tmp_path: Path) -> None:
    csv_text = "When,Verb\n2026-03-14 04:00:00,Logon\n"
    path = tmp_path / "naive.csv"
    path.write_text(csv_text, encoding="utf-8")
    column_map = ColumnMap(
        timestamp="When", action_column="Verb", assume_timezone="America/New_York"
    )
    event = _normalize(path, column_map).events[0]
    assert event.datetime == "2026-03-14T08:00:00Z"
    assert event.source_timezone == "America/New_York"


def test_record_id_column_becomes_the_audit_handle(tmp_path: Path) -> None:
    csv_text = "Id,When,Verb\nrow-7,2026-03-14T08:00:00Z,Logon\n"
    path = tmp_path / "ids.csv"
    path.write_text(csv_text, encoding="utf-8")
    column_map = ColumnMap(timestamp="When", action_column="Verb", record_id_column="Id")
    records = list(GenericCsvAdapter(column_map).read(path))
    assert records[0].raw_ref.record == "row-7"


# 3. Robustness (FR7).


def test_unparseable_timestamp_row_is_reported_not_fatal() -> None:
    result = _normalize(SLICE_CSV, ColumnMap.from_json(SLICE_MAP))
    assert result.problem_count == 1
    assert result.problems[0].raw_ref.record == "line:6"
    assert "timestamp" in result.problems[0].reason.lower()
    assert result.event_count == 4


# 4. De-duplication with provenance retained (FR12).


def test_identical_events_dedupe_and_keep_all_provenance(tmp_path: Path) -> None:
    csv_text = (
        "Id,When,Verb,Thing\n"
        "a,2026-03-14T08:00:00Z,Logon,10.0.0.5\n"
        "b,2026-03-14T08:00:00Z,Logon,10.0.0.5\n"
    )
    path = tmp_path / "dupe.csv"
    path.write_text(csv_text, encoding="utf-8")
    column_map = ColumnMap(
        timestamp="When", action_column="Verb", object_column="Thing", record_id_column="Id"
    )
    result = _normalize(path, column_map)
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    assert {ref.record for ref in refs} == {"a", "b"}


# 5. Config validation and the registry.


def test_column_map_requires_a_timestamp() -> None:
    with pytest.raises(ValueError, match="timestamp"):
        ColumnMap(timestamp="   ")


def test_column_map_rejects_a_non_snake_case_default_action() -> None:
    with pytest.raises(ValueError, match="default_action"):
        ColumnMap(timestamp="When", default_action="Process Create")


def test_column_map_rejects_an_unknown_default_timestamp_desc() -> None:
    with pytest.raises(ValueError, match="default_timestamp_desc"):
        ColumnMap(timestamp="When", default_timestamp_desc="invented")


def test_default_registry_has_generic_csv() -> None:
    assert isinstance(DEFAULT_MAPPERS["generic_csv"], GenericCsvMapper)
