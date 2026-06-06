"""Tests for the Eric Zimmerman / Timeline Explorer CSV adapter (PRD FR3, FR7 to FR12).

The load-bearing properties:

  1. Golden mapping: a known MFTECmd ``$MFT`` slice maps to a known, frozen set of
     canonical events, with each Standard Information timestamp expanded into its
     own event (FR8 to FR11).
  2. MACB semantics: the four 0x10 timestamps become created, modified, accessed,
     and record-change events with the matching action verbs, and an empty
     timestamp produces no event rather than a malformed one (FR3, FR7).
  3. Provenance: every expanded record carries the source tool, the ``$MFT``
     artifact, and a raw reference back to the MFT entry and timestamp (FR1, FR11).
  4. De-duplication: identical observations collapse to one event while every
     provenance pointer is retained (FR12).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from casebound.ingest import EZToolsAdapter, RawRecord
from casebound.normalize import Event, NormalizationResult, RawRef, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, EZToolsMapper
from casebound.normalize.mappers.eztools import (
    EZ_TIMESTAMP_DESC_KEY,
    EZ_TIMESTAMP_KEY,
    build_path,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE_CSV = FIXTURES / "eztools_mft_slice.csv"
SLICE_GOLDEN = FIXTURES / "eztools_mft_slice.events.json"


def _normalize(path: Path) -> NormalizationResult:
    return normalize_records(EZToolsAdapter().read(path))


# 1. Golden mapping: known input maps to a known set of canonical events.


def test_slice_maps_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    result = _normalize(SLICE_CSV)
    assert result.event_count == golden["event_count"]
    assert result.problem_count == 0
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_golden_events_are_self_consistent() -> None:
    # Every committed golden event reloads with a matching, freshly derived id, so
    # the frozen ids can never silently drift from the core fields they hash.
    golden: dict[str, Any] = json.loads(SLICE_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        rebuilt = Event.from_dict(data)
        assert rebuilt.event_id == data["event_id"]


# 2. MACB semantics: each Standard Information timestamp is its own event.


def test_one_mft_record_expands_into_its_macb_events() -> None:
    events = _normalize(SLICE_CSV).events
    updater = [e for e in events if e.object and e.object.endswith("updater.exe")]
    by_desc = {e.timestamp_desc: e for e in updater}
    # The updater.exe record has all four 0x10 timestamps, so it yields four events.
    assert set(by_desc) == {"created", "modified", "accessed", "other"}
    assert by_desc["created"].action == "file_create"
    assert by_desc["modified"].action == "file_write"
    assert by_desc["accessed"].action == "file_read"
    assert by_desc["other"].action == "file_metadata_change"
    # EZ tools emit UTC, so the source zone is recorded as UTC, not assumed_utc.
    assert by_desc["created"].source_timezone == "UTC"
    assert by_desc["created"].datetime == "2026-03-14T08:44:12.123456Z"


def test_empty_timestamps_produce_no_event() -> None:
    # The quarterly-report.docx row has every 0x10 timestamp blank, so it yields no
    # event at all and no malformed-row problem (FR7).
    result = _normalize(SLICE_CSV)
    assert not any(e.object and e.object.endswith("quarterly-report.docx") for e in result.events)
    assert result.problem_count == 0


def test_partial_timestamps_yield_only_present_events() -> None:
    # The archive row has no access time, so it yields three events, not four.
    events = _normalize(SLICE_CSV).events
    archive = [e for e in events if e.object and e.object.endswith("collected.7z")]
    assert {e.timestamp_desc for e in archive} == {"created", "modified", "other"}


# 3. Provenance on records and events (FR1, FR11).


def test_adapter_emits_provenance() -> None:
    records = list(EZToolsAdapter().read(SLICE_CSV))
    assert records
    for record in records:
        assert record.source_tool == "eztools"
        assert record.source_artifact == "$MFT"
        assert record.raw_ref.source_file == "eztools_mft_slice.csv"
        assert record.raw_ref.record  # non-empty audit handle
        # The reserved annotation keys are present on every expanded record.
        assert record.data[EZ_TIMESTAMP_KEY]
        assert record.data[EZ_TIMESTAMP_DESC_KEY]


def test_raw_ref_names_the_mft_entry_and_timestamp() -> None:
    records = list(EZToolsAdapter().read(SLICE_CSV))
    # The first expanded record is the updater.exe creation.
    assert records[0].raw_ref.record == "entry:8042 seq:3 created"


# 4. De-duplication with provenance retained (FR12).


def test_identical_records_dedupe_and_keep_all_provenance(tmp_path: Path) -> None:
    # Two MFT rows describing the same file with the same single creation timestamp
    # collapse to one event, but both source refs survive.
    csv_text = (
        "EntryNumber,SequenceNumber,ParentPath,FileName,"
        "Created0x10,LastModified0x10,LastRecordChange0x10,LastAccess0x10\n"
        "100,1,.\\Windows\\Temp,a.exe,2026-03-14 08:00:00.0000000,,,\n"
        "200,2,.\\Windows\\Temp,a.exe,2026-03-14 08:00:00.0000000,,,\n"
    )
    path = tmp_path / "dupe.csv"
    path.write_text(csv_text, encoding="utf-8")
    result = _normalize(path)
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    assert {ref.record for ref in refs} == {"entry:100 seq:1 created", "entry:200 seq:2 created"}


# 5. Helpers and the mapper registry.


def test_build_path_joins_parent_and_name() -> None:
    assert build_path(".\\Windows\\Temp", "a.exe") == ".\\Windows\\Temp\\a.exe"
    assert build_path(".\\Windows\\Temp\\", "a.exe") == ".\\Windows\\Temp\\a.exe"
    assert build_path(None, "a.exe") == "a.exe"
    assert build_path(".\\Windows", None) == ".\\Windows"
    assert build_path(None, None) is None


def test_default_registry_has_eztools() -> None:
    assert isinstance(DEFAULT_MAPPERS["eztools"], EZToolsMapper)


def test_unparseable_timestamp_is_reported_not_fatal() -> None:
    # A record whose annotated timestamp cannot be parsed is reported, not fatal.
    record = RawRecord(
        source_tool="eztools",
        source_artifact="$MFT",
        raw_ref=RawRef(source_file="x.csv", record="entry:1 created"),
        data={EZ_TIMESTAMP_KEY: "not-a-timestamp", EZ_TIMESTAMP_DESC_KEY: "created"},
    )
    result = normalize_records([record])
    assert result.event_count == 0
    assert result.problem_count == 1
    assert "timestamp" in result.problems[0].reason.lower()
