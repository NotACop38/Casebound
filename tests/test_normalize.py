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


@pytest.mark.parametrize("partial", ["08:42:17", "4624", "March", "03-14 08:42:17"])
def test_partial_timestamp_is_rejected_not_filled_from_today(partial: str) -> None:
    # dateutil would silently complete a partial timestamp from the current date,
    # fabricating an instant and making the content-derived event ids differ
    # between runs. A string that does not pin its own date must be reported as
    # malformed (FR7), never completed.
    with pytest.raises(TimestampError, match="complete date"):
        normalize_timestamp(partial)


def test_date_only_timestamp_resolves_to_midnight_deterministically() -> None:
    # A date without a time pins its own date, so it resolves the same way on
    # every run: midnight, with the UTC assumption flagged.
    stamp = normalize_timestamp("2026-03-14")
    assert stamp.datetime_utc == "2026-03-14T00:00:00Z"
    assert stamp.source_timezone == "assumed_utc"


def test_unknown_assume_timezone_raises() -> None:
    with pytest.raises(TimestampError):
        normalize_timestamp("2026-03-14 04:30:05", assume_timezone="Mars/Olympus")


def test_unknown_assume_timezone_raises_even_with_offset() -> None:
    # A bogus hint must be rejected even when the string already carries an offset,
    # so a typo can never be written into the audit metadata as a real zone.
    with pytest.raises(TimestampError):
        normalize_timestamp("2026-03-14 04:30:05.000 -04:00", assume_timezone="Mars/Olympus")


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


_DEDUP_HEADER = (
    '"Timestamp","Computer","Channel","EventID","Level",'
    '"MitreTactics","MitreTags","RecordID","RuleTitle","Details"'
)
_DEDUP_ROW_UNTAGGED = (
    '"2026-03-14 04:42:17.000 -04:00","WIN-ACCT-07","Security","4688","high",'
    '"","","80038","Suspicious Process Lineage",'
    '"NewProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
    '¦ SubjectUserName: jdoe ¦ SubjectDomainName: CORP"'
)
_DEDUP_ROW_TAGGED = (
    '"2026-03-14 04:42:17.000 -04:00","WIN-ACCT-07","Security","4688","high",'
    '"Execution","T1059.001","80038","Office Application Spawned PowerShell",'
    '"NewProcessName: C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe '
    '¦ SubjectUserName: jdoe ¦ SubjectDomainName: CORP"'
)


@pytest.mark.parametrize(
    "rows",
    [
        pytest.param([_DEDUP_ROW_UNTAGGED, _DEDUP_ROW_TAGGED], id="untagged-first"),
        pytest.param([_DEDUP_ROW_TAGGED, _DEDUP_ROW_UNTAGGED], id="tagged-first"),
    ],
)
def test_dedup_merges_rule_tags_from_collapsing_detections(rows: list[str], tmp_path: Path) -> None:
    # Detection tools emit one row per rule match, so two rules firing on the same
    # underlying record collapse to one event (FR12). The collapse must merge the
    # detections' ATT&CK rule tags and titles: which row arrives first is an
    # artifact of the export, and a technique mapping must never depend on it.
    from casebound.enrich.attack import tag_events

    csv_path = tmp_path / "double_detection.csv"
    csv_path.write_text("\n".join([_DEDUP_HEADER, *rows]) + "\n", encoding="utf-8")
    result = normalize_records(HayabusaAdapter().read(csv_path))

    assert result.event_count == 1
    assert result.duplicate_count == 1
    [event] = result.events
    assert event.details["rule_mitre_tags"] == ["T1059.001"]
    titles = {event.details["rule_title"], *event.details.get("additional_rule_titles", [])}
    assert titles == {"Suspicious Process Lineage", "Office Application Spawned PowerShell"}

    # The merged tag is promoted by the deterministic tagger, whatever the order.
    [tagged] = tag_events(result.events)
    assert "T1059.001" in {tech.technique_id for tech in tagged.attack_techniques}


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
    # A record whose source_tool has no mapper in the supplied registry is reported,
    # not fatal (FR7). Every default source tool now has a mapper, so this drives the
    # pipeline's missing-mapper branch directly with a registry that omits the tool.
    record = RawRecord(
        source_tool="dissect",
        source_artifact="Sysmon.evtx",
        raw_ref=RawRef(source_file="x.csv", record="1"),
        data={"Timestamp": "2026-03-14T08:30:05Z"},
    )
    result = normalize_records([record], mappers={})
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


def test_adapter_prefers_evtx_file_for_artifact(tmp_path: Path) -> None:
    # When a row carries Hayabusa's EvtxFile column, it is the exact source file and
    # is preferred over the channel-derived name for provenance (FR11).
    csv_text = (
        '"Timestamp","Computer","Channel","EventID","EvtxFile","Details"\n'
        '"2026-03-14 04:42:17.000 -04:00","WIN-ACCT-07","Security","4688",'
        '"D:\\evidence\\host-a-Security.evtx","NewProcessName: C:\\Windows\\x.exe"\n'
    )
    path = tmp_path / "with_evtx.csv"
    path.write_text(csv_text, encoding="utf-8")
    records = list(HayabusaAdapter().read(path))
    assert records[0].source_artifact == "D:\\evidence\\host-a-Security.evtx"


def test_adapter_falls_back_to_channel_when_no_evtx_file() -> None:
    # The slice fixture has no EvtxFile column, so the channel mapping is used.
    records = list(HayabusaAdapter().read(SLICE_CSV))
    assert records[0].source_artifact == "Security.evtx"


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
