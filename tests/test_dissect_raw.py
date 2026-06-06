"""Tests for the optional Dissect raw-mode adapters (PRD Section 5 Raw mode, D2).

These prove the raw-artifact path parses EVTX and the NTFS ``$MFT`` directly into
the canonical schema, exactly as the tool-output adapters do, while keeping the
AGPL-licensed Dissect dependency optional.

Dissect is not installed in CI, so the suite does not depend on it. The split that
the adapters use, a thin Dissect-facing reader over pure transformation functions,
is what makes this possible:

  1. Golden mapping: the flattened records (EVTX) and the distilled facts (MFT)
     map through the pure transform plus the Dissect mapper to a known, frozen set
     of canonical events. This exercises everything except the Dissect byte parse.
  2. Reader logic with a fake parser: ``read`` is driven end to end against an
     injected fake that mimics the Dissect API (a dict-subclass record, a wrapped
     substitution value, datetime fields), so the Dissect-facing glue is covered
     offline.
  3. Dependency gating: with Dissect absent the loaders raise a clear,
     install-hint error rather than a bare ImportError.

Re-verified against the dissect.eventlog and dissect.ntfs APIs at author time.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import casebound.ingest.raw.evtx as evtx_mod
import casebound.ingest.raw.mft as mft_mod
import pytest
from casebound.ingest.base import RawRecord
from casebound.ingest.raw import DissectEvtxAdapter, DissectMftAdapter, RawModeDependencyError
from casebound.ingest.raw._loader import load_evtx_class, load_mft_class
from casebound.ingest.raw.evtx import evtx_record_to_raw
from casebound.ingest.raw.mft import MftFileFacts, mft_facts_to_raws
from casebound.normalize import Event, RawRef, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, DissectMapper
from casebound.normalize.mappers.dissect import DISSECT_KIND_KEY

FIXTURES = Path(__file__).resolve().parent / "fixtures"
EVTX_RECORDS = FIXTURES / "dissect_evtx.records.json"
EVTX_GOLDEN = FIXTURES / "dissect_evtx.events.json"
MFT_FACTS = FIXTURES / "dissect_mft.facts.json"
MFT_GOLDEN = FIXTURES / "dissect_mft.events.json"


def _evtx_records() -> list[RawRecord]:
    data = json.loads(EVTX_RECORDS.read_text(encoding="utf-8"))
    return [
        evtx_record_to_raw(entry["fields"], source_file=entry["artifact"], line_number=i)
        for i, entry in enumerate(data["records"], start=1)
    ]


def _mft_records() -> list[RawRecord]:
    data = json.loads(MFT_FACTS.read_text(encoding="utf-8"))
    out: list[RawRecord] = []
    for fact in data["facts"]:
        out.extend(mft_facts_to_raws(MftFileFacts(**fact), source_file="$MFT"))
    return out


# 1a. EVTX golden mapping.


def test_evtx_records_map_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(EVTX_GOLDEN.read_text(encoding="utf-8"))
    result = normalize_records(_evtx_records())
    assert result.problem_count == 0
    assert result.event_count == golden["event_count"]
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_evtx_golden_events_are_self_consistent() -> None:
    golden: dict[str, Any] = json.loads(EVTX_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        assert Event.from_dict(data).event_id == data["event_id"]


def test_evtx_eventid_drives_canonical_fields() -> None:
    events = {e.action: e for e in normalize_records(_evtx_records()).events}
    process_create = events["process_create"]
    assert process_create.source_tool == "dissect"
    assert process_create.host == "WIN-ACCT-07"
    assert process_create.principal == "CORP\\jdoe"
    assert process_create.object is not None and process_create.object.endswith("powershell.exe")
    assert process_create.source_artifact == "Security.evtx"
    assert process_create.details["provider"] == "Microsoft-Windows-Security-Auditing"

    network = events["network_connect"]
    assert network.object == "203.0.113.77:443"
    assert network.source_artifact == "Microsoft-Windows-Sysmon%4Operational.evtx"


def test_evtx_uncovered_eventid_still_maps_at_reduced_confidence() -> None:
    others = [e for e in normalize_records(_evtx_records()).events if e.action == "other"]
    assert len(others) == 1
    assert others[0].confidence == 0.5
    assert others[0].details["win_event_id"] == 9999
    assert others[0].principal is None and others[0].object is None


# 1b. MFT golden mapping.


def test_mft_facts_map_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(MFT_GOLDEN.read_text(encoding="utf-8"))
    result = normalize_records(_mft_records())
    assert result.problem_count == 0
    assert result.event_count == golden["event_count"]
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_mft_golden_events_are_self_consistent() -> None:
    golden: dict[str, Any] = json.loads(MFT_GOLDEN.read_text(encoding="utf-8"))
    for data in golden["events"]:
        assert Event.from_dict(data).event_id == data["event_id"]


def test_mft_record_expands_into_its_macb_events() -> None:
    events = normalize_records(_mft_records()).events
    invoice = [e for e in events if e.object and e.object.endswith("invoice.exe")]
    by_desc = {e.timestamp_desc: e for e in invoice}
    assert set(by_desc) == {"created", "modified", "accessed", "other"}
    assert by_desc["created"].action == "file_create"
    assert by_desc["modified"].action == "file_write"
    assert by_desc["accessed"].action == "file_read"
    assert by_desc["other"].action == "file_metadata_change"
    assert by_desc["created"].source_tool == "dissect"
    assert by_desc["created"].source_artifact == "$MFT"
    assert by_desc["created"].source_timezone == "UTC"
    assert by_desc["created"].details["FileSize"] == "54321"


def test_mft_partial_timestamps_yield_only_present_events() -> None:
    events = normalize_records(_mft_records()).events
    report = [e for e in events if e.object and e.object.endswith("report.docx")]
    # report.docx has no access time, so it yields three events, not four.
    assert {e.timestamp_desc for e in report} == {"created", "modified", "other"}


def test_mft_facts_with_no_timestamps_yield_no_records() -> None:
    facts = MftFileFacts(
        segment=42,
        sequence="1",
        path="Windows/empty.bin",
        file_name="empty.bin",
        is_dir=False,
        file_size="0",
        created=None,
        modified=None,
        accessed=None,
        record_changed=None,
    )
    assert mft_facts_to_raws(facts, source_file="$MFT") == []


# 2. Reader logic exercised against a fake Dissect parser (no Dissect installed).


class _FakeSub:
    """Mimics a Dissect substitution value: a no-argument get() unwraps it."""

    def __init__(self, value: Any) -> None:
        self._value = value

    def get(self) -> Any:
        return self._value


class _FakeKVC(dict[str, Any]):
    """Mimics dissect.eventlog's KeyValueCollection (a dict subclass)."""


def _fake_evtx_class(records: list[_FakeKVC]) -> Any:
    class _FakeEvtx:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def __iter__(self) -> Any:
            return iter(records)

    return _FakeEvtx


def test_evtx_read_drives_full_chain_with_fake_parser(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = _FakeKVC(
        {
            "EventID": "4688",
            "Computer": "HOST1",
            "Channel": "Security",
            "Provider_Name": "Microsoft-Windows-Security-Auditing",
            # A real datetime (as Dissect yields for SystemTime) is isoformatted.
            "TimeCreated_SystemTime": datetime(2026, 3, 14, 8, 42, 17, 123456, tzinfo=UTC),
            "EventRecordID": "555",
            # A wrapped substitution value is unwrapped via get().
            "SubjectUserName": _FakeSub("jdoe"),
            "SubjectDomainName": "CORP",
            "NewProcessName": _FakeSub("C:\\Windows\\System32\\cmd.exe"),
        }
    )
    monkeypatch.setattr(evtx_mod, "load_evtx_class", lambda: _fake_evtx_class([record]))
    source = tmp_path / "Security.evtx"
    source.write_bytes(b"\x00ElfFile\x00")

    raws = list(DissectEvtxAdapter().read(source))
    assert len(raws) == 1
    result = normalize_records(raws)
    assert result.event_count == 1
    event = result.events[0]
    assert event.source_tool == "dissect"
    assert event.action == "process_create"
    assert event.host == "HOST1"
    assert event.principal == "CORP\\jdoe"
    assert event.object == "C:\\Windows\\System32\\cmd.exe"
    assert event.datetime == "2026-03-14T08:42:17.123456Z"
    assert event.source_artifact == "Security.evtx"
    assert event.raw_ref.record == "555"


def test_evtx_read_uses_line_number_when_no_record_id(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    record = _FakeKVC(
        {
            "EventID": "4688",
            "Computer": "HOST1",
            "Channel": "Security",
            "TimeCreated_SystemTime": "2026-03-14T08:42:17+00:00",
            "NewProcessName": "C:\\x.exe",
            "SubjectUserName": "u",
        }
    )
    monkeypatch.setattr(evtx_mod, "load_evtx_class", lambda: _fake_evtx_class([record]))
    source = tmp_path / "Security.evtx"
    source.write_bytes(b"\x00")
    raws = list(DissectEvtxAdapter().read(source))
    assert raws[0].raw_ref.record == "line:1"


# Fakes mirroring the dissect.ntfs MftRecord surface the adapter reads.


class _FakeStdInfo:
    def __init__(self, created: Any, modified: Any, accessed: Any, changed: Any) -> None:
        self.creation_time = created
        self.last_modification_time = modified
        self.last_access_time = accessed
        self.last_change_time = changed


class _FakeFileName:
    def __init__(self, name: str, size: int) -> None:
        self.file_name = name
        self.file_size = size


class _FakeAttrs:
    def __init__(self, std_info: list[Any], file_name: list[Any]) -> None:
        self.STANDARD_INFORMATION = std_info
        self.FILE_NAME = file_name


class _FakeHeader:
    def __init__(self, sequence: int) -> None:
        self.SequenceNumber = sequence


class _FakeMftRecord:
    def __init__(
        self,
        *,
        segment: int,
        sequence: int,
        path: str | None,
        is_dir: bool,
        std_info: list[Any],
        file_name: list[Any],
    ) -> None:
        self.segment = segment
        self.header = _FakeHeader(sequence)
        self.attributes = _FakeAttrs(std_info, file_name)
        self._path = path
        self._is_dir = is_dir

    def full_path(self) -> str | None:
        return self._path

    def is_dir(self) -> bool:
        return self._is_dir


def _fake_mft_class(records: list[Any]) -> Any:
    class _FakeMft:
        def __init__(self, handle: Any) -> None:
            self._handle = handle

        def segments(self) -> Any:
            return iter(records)

    return _FakeMft


def test_mft_read_drives_full_chain_with_fake_parser(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    file_record = _FakeMftRecord(
        segment=8042,
        sequence=3,
        path="Users/jdoe/Downloads/invoice.exe",
        is_dir=False,
        std_info=[
            _FakeStdInfo(
                datetime(2026, 3, 14, 8, 44, 12, 123456, tzinfo=UTC),
                datetime(2026, 3, 14, 8, 50, 0, tzinfo=UTC),
                datetime(2026, 3, 14, 8, 51, 0, tzinfo=UTC),
                datetime(2026, 3, 14, 8, 50, 1, tzinfo=UTC),
            )
        ],
        file_name=[_FakeFileName("invoice.exe", 54321)],
    )
    # A record with no Standard Information (an unused segment) is skipped.
    empty_record = _FakeMftRecord(
        segment=43,
        sequence=1,
        path=None,
        is_dir=False,
        std_info=[],
        file_name=[],
    )
    monkeypatch.setattr(
        mft_mod, "load_mft_class", lambda: _fake_mft_class([file_record, empty_record])
    )
    source = tmp_path / "$MFT"
    source.write_bytes(b"FILE0\x00")

    raws = list(DissectMftAdapter().read(source))
    result = normalize_records(raws)
    assert result.event_count == 4  # the empty segment contributed nothing
    by_desc = {e.timestamp_desc: e for e in result.events}
    assert set(by_desc) == {"created", "modified", "accessed", "other"}
    assert by_desc["created"].object == "Users/jdoe/Downloads/invoice.exe"
    assert by_desc["created"].source_artifact == "$MFT"
    assert by_desc["created"].raw_ref.record == "segment:8042 seq:3 created"
    assert by_desc["created"].details["FileName"] == "invoice.exe"
    assert by_desc["created"].details["FileSize"] == "54321"


# 3. Robustness and dependency gating.


def test_unknown_kind_is_reported_not_fatal() -> None:
    record = RawRecord(
        source_tool="dissect",
        source_artifact="mystery.bin",
        raw_ref=RawRef(source_file="mystery.bin", record="1"),
        data={DISSECT_KIND_KEY: "pcap"},
    )
    result = normalize_records([record])
    assert result.event_count == 0
    assert result.problem_count == 1
    assert "kind" in result.problems[0].reason.lower()


def test_bad_evtx_timestamp_is_reported_not_fatal() -> None:
    raw = evtx_record_to_raw(
        {"EventID": "4688", "Channel": "Security", "TimeCreated_SystemTime": "not-a-time"},
        source_file="Security.evtx",
        line_number=1,
    )
    result = normalize_records([raw])
    assert result.event_count == 0
    assert result.problem_count == 1
    assert "timestamp" in result.problems[0].reason.lower()


def test_identical_dissect_records_dedupe_and_keep_provenance() -> None:
    # Two MFT rows describing the same file with the same single creation timestamp
    # collapse to one event, but both source refs survive (FR12).
    facts = MftFileFacts(
        segment=None,
        sequence=None,
        path="Windows/Temp/a.exe",
        file_name="a.exe",
        is_dir=False,
        file_size="10",
        created="2026-03-14T08:00:00+00:00",
        modified=None,
        accessed=None,
        record_changed=None,
    )
    first = mft_facts_to_raws(facts, source_file="A.$MFT")
    second = mft_facts_to_raws(facts, source_file="B.$MFT")
    result = normalize_records(first + second)
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    assert {ref.source_file for ref in refs} == {"A.$MFT", "B.$MFT"}


def test_default_registry_has_dissect() -> None:
    assert isinstance(DEFAULT_MAPPERS["dissect"], DissectMapper)


def _dissect_available() -> bool:
    """True when Dissect is installed (the loaders return rather than raise)."""
    try:
        load_evtx_class()
        load_mft_class()
    except RawModeDependencyError:
        return False
    return True


def test_loaders_raise_friendly_error_when_dissect_missing() -> None:
    if _dissect_available():
        pytest.skip("Dissect is installed; the missing-dependency path is not exercised here.")

    with pytest.raises(RawModeDependencyError) as evtx_err:
        load_evtx_class()
    assert "casebound[raw]" in str(evtx_err.value)

    with pytest.raises(RawModeDependencyError) as mft_err:
        load_mft_class()
    assert "casebound[raw]" in str(mft_err.value)


def test_read_surfaces_missing_dependency(tmp_path: Path) -> None:
    if _dissect_available():
        pytest.skip("Dissect is installed; the missing-dependency path is not exercised here.")

    source = tmp_path / "Security.evtx"
    source.write_bytes(b"\x00")
    with pytest.raises(RawModeDependencyError):
        list(DissectEvtxAdapter().read(source))
