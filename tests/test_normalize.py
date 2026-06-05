"""Tests for ingestion and normalization (PRD FR1, FR2, FR7 to FR12).

The load-bearing properties for this vertical slice:

  1. Golden mapping: a known slice of Hayabusa output maps to a known, frozen set
     of canonical events (FR8 to FR11).
  2. Timezone handling: timestamps normalize to UTC with the source zone tracked,
     and an unparseable timestamp is reported rather than fatal (FR9, FR7).
  3. De-duplication: identical events collapse to one while every provenance
     pointer is retained (FR12).
  4. Robustness: a malformed row is reported as a problem and an uncovered event id
     still produces an event, so one bad or unknown row never sinks the run (FR7).
  5. Provenance: every record and event carries source tool, source artifact, and a
     raw reference back to the source row (FR1, FR11).
"""

from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest
from casebound.ingest import HayabusaAdapter, RawRecord, channel_to_artifact
from casebound.normalize import (
    Event,
    NormalizationResult,
    RawRef,
    normalize_records,
    normalize_timestamp,
)
from casebound.normalize.mappers import DEFAULT_MAPPERS
from casebound.normalize.mappers.hayabusa import HayabusaMapper, parse_details
from casebound.normalize.timezone import ASSUMED_UTC, TimestampError, format_utc_offset

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE_CSV = FIXTURES / "hayabusa_slice.csv"
SLICE_GOLDEN = FIXTURES / "hayabusa_slice.events.json"
EDGE_CSV = FIXTURES / "hayabusa_edge.csv"


def _normalize(path: Path) -> NormalizationResult:
    return normalize_records(HayabusaAdapter().read(path))


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


def test_slice_event_semantics() -> None:
    # Spot-check the derived canonical fields independently of the frozen hashes.
    events = {event.action: event for event in _normalize(SLICE_CSV).events}

    process_create = events["process_create"]
    assert process_create.host == "WIN-ACCT-07"
    assert process_create.principal == "CORP\\jdoe"
    assert process_create.object == (
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    )
    assert process_create.datetime == "2026-03-14T08:42:17Z"
    assert process_create.source_artifact == "Security.evtx"

    network_connect = events["network_connect"]
    # Sysmon network rows carry no user, so the principal is honestly null.
    assert network_connect.principal is None
    assert network_connect.object == "203.0.113.77:443"
    assert network_connect.source_artifact == "Microsoft-Windows-Sysmon%4Operational.evtx"

    logon = events["logon"]
    assert logon.principal == "CORP\\svc-backup"
    assert logon.object == "10.4.12.66"


def test_raw_rule_tags_are_preserved_but_not_promoted() -> None:
    # The ATT&CK step is later: normalization keeps the raw rule tags in details
    # and leaves attack_techniques empty.
    events = {event.action: event for event in _normalize(SLICE_CSV).events}
    process_create = events["process_create"]
    assert process_create.attack_techniques == []
    assert process_create.details["rule_mitre_tags"] == ["T1566.001", "T1059.001"]


# 2. Timezone handling (FR9).


def test_offset_timestamp_normalizes_to_utc() -> None:
    stamp = normalize_timestamp("2026-03-14 04:30:05.000 -04:00")
    assert stamp.datetime_utc == "2026-03-14T08:30:05Z"
    assert stamp.timestamp_raw == "2026-03-14 04:30:05.000 -04:00"
    assert stamp.source_timezone == "UTC-04:00"


def test_utc_timestamp_is_labeled_utc() -> None:
    stamp = normalize_timestamp("2026-03-14T08:30:05Z")
    assert stamp.datetime_utc == "2026-03-14T08:30:05Z"
    assert stamp.source_timezone == "UTC"


def test_naive_timestamp_without_zone_is_flagged_assumed_utc() -> None:
    stamp = normalize_timestamp("2026-03-14 08:30:05")
    assert stamp.datetime_utc == "2026-03-14T08:30:05Z"
    assert stamp.source_timezone == ASSUMED_UTC


def test_naive_timestamp_with_iana_hint_is_localized() -> None:
    stamp = normalize_timestamp("2026-03-14 04:30:05", assume_timezone="America/New_York")
    assert stamp.datetime_utc == "2026-03-14T08:30:05Z"
    assert stamp.source_timezone == "America/New_York"


def test_offset_timestamp_relabels_with_iana_hint_but_keeps_instant() -> None:
    stamp = normalize_timestamp(
        "2026-03-14 04:30:05.000 -04:00", assume_timezone="America/New_York"
    )
    # The offset in the string still fixes the instant; the hint only relabels.
    assert stamp.datetime_utc == "2026-03-14T08:30:05Z"
    assert stamp.source_timezone == "America/New_York"


def test_subsecond_precision_is_preserved() -> None:
    stamp = normalize_timestamp("2026-03-14 04:30:05.500000 -04:00")
    assert stamp.datetime_utc == "2026-03-14T08:30:05.5Z"


@pytest.mark.parametrize("bad", ["not-a-timestamp", "", "   "])
def test_unparseable_timestamp_raises(bad: str) -> None:
    with pytest.raises(TimestampError):
        normalize_timestamp(bad)


def test_unknown_assume_timezone_raises() -> None:
    with pytest.raises(TimestampError):
        normalize_timestamp("2026-03-14 04:30:05", assume_timezone="Mars/Olympus")


@pytest.mark.parametrize(
    ("minutes", "label"),
    [(0, "UTC"), (-240, "UTC-04:00"), (330, "UTC+05:30"), (60, "UTC+01:00")],
)
def test_format_utc_offset(minutes: int, label: str) -> None:
    assert format_utc_offset(timedelta(minutes=minutes)) == label


# 3. De-duplication with provenance retained (FR12).


def test_identical_events_dedupe_and_keep_all_provenance() -> None:
    result = _normalize(EDGE_CSV)
    process_creates = [event for event in result.events if event.action == "process_create"]
    assert len(process_creates) == 1
    event = process_creates[0]
    # The two identical rows collapse to one event, but both source refs survive.
    refs = result.provenance[event.event_id]
    assert {ref.record for ref in refs} == {"80038", "99999"}
    assert result.duplicate_count == 1


# 4. Robustness: malformed reported, uncovered event id still mapped (FR7, FR8).


def test_malformed_row_is_reported_not_fatal() -> None:
    result = _normalize(EDGE_CSV)
    assert result.problem_count == 1
    problem = result.problems[0]
    assert problem.raw_ref.record == "80040"
    assert problem.source_tool == "hayabusa"
    assert "timestamp" in problem.reason.lower()
    # The run still produced events despite the bad row.
    assert result.event_count >= 1


def test_uncovered_event_id_still_maps_to_a_generic_event() -> None:
    result = _normalize(EDGE_CSV)
    others = [event for event in result.events if event.action == "other"]
    assert len(others) == 1
    generic = others[0]
    assert generic.confidence == 0.5
    assert generic.details["win_event_id"] == 9999


def test_unregistered_source_tool_is_reported() -> None:
    record = RawRecord(
        source_tool="chainsaw",  # a valid tool, but no mapper registered yet
        source_artifact="Sysmon.evtx",
        raw_ref=RawRef(source_file="x.csv", record="1"),
        data={"Timestamp": "2026-03-14T08:30:05Z"},
    )
    result = normalize_records([record])
    assert result.event_count == 0
    assert result.problem_count == 1
    assert "no mapper" in result.problems[0].reason


# 5. Provenance on records and events (FR1, FR11).


def test_adapter_emits_provenance() -> None:
    records = list(HayabusaAdapter().read(SLICE_CSV))
    assert records
    for record in records:
        assert record.source_tool == "hayabusa"
        assert record.source_artifact.endswith(".evtx")
        assert record.raw_ref.source_file == "hayabusa_slice.csv"
        assert record.raw_ref.record  # non-empty record id


def test_adapter_uses_record_id_as_audit_handle() -> None:
    records = list(HayabusaAdapter().read(SLICE_CSV))
    # The first slice row is the benign logon with RecordID 79989.
    assert records[0].raw_ref.record == "79989"


@pytest.mark.parametrize(
    ("channel", "artifact"),
    [
        ("Security", "Security.evtx"),
        ("System", "System.evtx"),
        ("Microsoft-Windows-Sysmon/Operational", "Microsoft-Windows-Sysmon%4Operational.evtx"),
        ("", "Unknown.evtx"),
    ],
)
def test_channel_to_artifact(channel: str, artifact: str) -> None:
    assert channel_to_artifact(channel) == artifact


def test_raw_record_rejects_unknown_source_tool() -> None:
    with pytest.raises(ValueError, match="source_tool"):
        RawRecord(
            source_tool="splunk",  # not in SOURCE_TOOLS
            source_artifact="x.evtx",
            raw_ref=RawRef(source_file="x.csv", record="1"),
            data={},
        )


# Helpers and the mapper registry.


def test_parse_details_splits_on_first_colon() -> None:
    fields = parse_details("CallTrace: C:\\Windows\\ntdll.dll ¦ GrantedAccess: 0x1410 ¦ noop")
    assert fields["CallTrace"] == "C:\\Windows\\ntdll.dll"
    assert fields["GrantedAccess"] == "0x1410"
    # A fragment with no colon is skipped rather than guessed at.
    assert "noop" not in fields


def test_default_registry_has_hayabusa() -> None:
    assert isinstance(DEFAULT_MAPPERS["hayabusa"], HayabusaMapper)
