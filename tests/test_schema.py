"""Tests for the canonical event schema (PRD Section 10): the keystone record.

These cover the four properties the schema must hold from day one:

  1. a valid event validates (against both the dataclass and the JSON Schema),
  2. an invalid event is rejected,
  3. the same logical event always yields the same event_id (determinism), and
  4. two different events do not collide.
"""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError
from typing import Any

import jsonschema
import pytest
from casebound.normalize.schema import (
    CORE_ID_FIELDS,
    SCHEMA_PATH,
    AttackTechnique,
    Event,
    RawRef,
    SchemaError,
    compute_event_id,
    load_schema,
    validate_event_dict,
)


def make_event(**overrides: Any) -> Event:
    """A valid Windows process-create event, with optional field overrides."""
    base: dict[str, Any] = {
        "datetime": "2026-03-14T08:42:17Z",
        "timestamp_raw": "2026-03-14 03:42:17",
        "source_timezone": "America/New_York",
        "timestamp_desc": "logged",
        "message": "winword.exe spawned powershell.exe with an encoded command",
        "action": "process_create",
        "source_tool": "hayabusa",
        "source_artifact": "Security.evtx",
        "raw_ref": RawRef(source_file="hayabusa-timeline.csv", record="1487"),
        "host": "WIN-ACCT-07",
        "principal": "CORP\\jdoe",
        "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "details": {"process_id": 6042, "event_id": 4688},
        "attack_techniques": [AttackTechnique("T1059.001", "rule_tag")],
        "ioc_refs": ["ioc-0007"],
        "confidence": 0.95,
        "tags": ["episode-initial-access"],
    }
    base.update(overrides)
    return Event(**base)


# 1. A valid event validates.


def test_valid_event_constructs_and_assigns_id() -> None:
    event = make_event()
    assert event.event_id != ""
    assert len(event.event_id) == 64
    assert all(c in "0123456789abcdef" for c in event.event_id)


def test_valid_event_dict_matches_json_schema() -> None:
    # The dataclass output is accepted by the JSON Schema source of truth.
    validate_event_dict(make_event().to_dict())


def test_round_trip_through_dict_preserves_id() -> None:
    event = make_event()
    rebuilt = Event.from_dict(event.to_dict())
    assert rebuilt.event_id == event.event_id
    assert rebuilt.to_dict() == event.to_dict()


def test_minimal_event_with_null_fields_is_valid() -> None:
    event = make_event(host=None, principal=None, object=None)
    validate_event_dict(event.to_dict())
    assert event.event_id != ""


def test_committed_examples_validate() -> None:
    # The worked examples shipped for docs and CI must conform.
    examples_dir = SCHEMA_PATH.parent / "examples"
    files = sorted(examples_dir.glob("*.json"))
    assert files, "expected committed example events under schema/examples/"
    for path in files:
        instance = json.loads(path.read_text(encoding="utf-8"))
        validate_event_dict(instance)
        # The committed event_id must equal the freshly derived one.
        assert Event.from_dict(instance).event_id == instance["event_id"]


# 2. An invalid event is rejected.


@pytest.mark.parametrize(
    "overrides",
    [
        {"datetime": "2026-03-14 08:42:17"},  # not ISO 8601 UTC with a Z
        {"datetime": "not-a-time"},
        {"timestamp_desc": "happened"},  # outside the controlled vocabulary
        {"source_tool": "splunk"},  # not a known source tool
        {"action": "Process Create"},  # not snake_case
        {"confidence": 1.5},  # out of range
        {"confidence": -0.1},
        {"message": ""},  # required non-empty
        {"source_artifact": ""},
    ],
)
def test_invalid_event_is_rejected_by_dataclass(overrides: dict[str, Any]) -> None:
    with pytest.raises(SchemaError):
        make_event(**overrides)


def test_invalid_technique_id_is_rejected() -> None:
    with pytest.raises(SchemaError):
        AttackTechnique("1059", "rule_tag")


def test_empty_raw_ref_is_rejected() -> None:
    with pytest.raises(SchemaError):
        RawRef(source_file="", record="1")


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d.pop("event_id"),  # missing required field
        lambda d: d.update(action="Process Create"),  # bad pattern
        lambda d: d.update(timestamp_desc="happened"),  # bad enum
        lambda d: d.update(confidence=2),  # out of range
        lambda d: d.update(extra_field="nope"),  # additionalProperties false
        lambda d: d.update(event_id="short"),  # bad id pattern
    ],
)
def test_invalid_dict_is_rejected_by_json_schema(mutate: Any) -> None:
    data = make_event().to_dict()
    mutate(data)
    with pytest.raises(jsonschema.ValidationError):
        validate_event_dict(data)


def test_tampered_event_id_is_rejected_on_load() -> None:
    data = make_event().to_dict()
    data["event_id"] = "0" * 64  # valid shape, wrong value
    with pytest.raises(SchemaError):
        Event.from_dict(data)


# 3. The same logical event always yields the same event_id.


def test_event_id_is_deterministic() -> None:
    assert make_event().event_id == make_event().event_id


def test_event_id_ignores_non_core_fields() -> None:
    # Enrichment and presentation fields are not part of identity.
    a = make_event()
    b = make_event(
        message="a completely different summary",
        details={"unrelated": True},
        attack_techniques=[AttackTechnique("T1003", "mapping_table")],
        ioc_refs=[],
        confidence=0.1,
        tags=["other-episode"],
        timestamp_raw="whatever",
        source_timezone="UTC",
        raw_ref=RawRef(source_file="other.csv", record="9999"),
    )
    assert a.event_id == b.event_id


def test_compute_event_id_matches_event() -> None:
    event = make_event()
    derived = compute_event_id({name: getattr(event, name) for name in CORE_ID_FIELDS})
    assert derived == event.event_id


# 4. Two different events do not collide.


@pytest.mark.parametrize("core_field", list(CORE_ID_FIELDS))
def test_changing_any_core_field_changes_the_id(core_field: str) -> None:
    base = make_event()
    new_values: dict[str, Any] = {
        "datetime": "2026-03-14T09:00:00Z",
        "timestamp_desc": "created",
        "host": "WIN-OTHER-99",
        "principal": "CORP\\someone-else",
        "action": "file_write",
        "object": "C:\\Windows\\Temp\\evil.dll",
        "source_tool": "chainsaw",
        "source_artifact": "Sysmon.evtx",
    }
    changed = make_event(**{core_field: new_values[core_field]})
    assert changed.event_id != base.event_id


def test_two_distinct_events_do_not_collide() -> None:
    process_create = make_event()
    logon = make_event(
        datetime="2026-03-14T08:55:03Z",
        action="logon",
        host="WIN-FILE-02",
        principal="CORP\\svc-backup",
        object="10.4.12.66",
        message="Successful network logon",
    )
    assert process_create.event_id != logon.event_id


# Integrity hardening: the id stays a faithful handle to the core fields.


def test_event_is_frozen() -> None:
    # Core identity fields cannot be reassigned, so the id can never go stale.
    event = make_event()
    with pytest.raises(FrozenInstanceError):
        event.action = "logon"  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        event.event_id = "0" * 64  # type: ignore[misc]


def test_timestamp_is_canonicalized() -> None:
    # The same instant spelled with redundant fractional zeros canonicalizes to
    # one representation and so yields one id.
    plain = make_event(datetime="2026-03-14T08:42:17Z")
    padded = make_event(datetime="2026-03-14T08:42:17.000Z")
    assert padded.datetime == "2026-03-14T08:42:17Z"
    assert padded.event_id == plain.event_id


def test_subsecond_precision_is_preserved_and_distinguishes_events() -> None:
    # Real sub-second precision is kept, so two close-but-distinct events do not
    # collide.
    whole = make_event(datetime="2026-03-14T08:42:17Z")
    fractional = make_event(datetime="2026-03-14T08:42:17.5Z")
    assert fractional.datetime == "2026-03-14T08:42:17.5Z"
    assert fractional.event_id != whole.event_id


def test_impossible_instant_is_rejected_by_dataclass() -> None:
    with pytest.raises(SchemaError):
        make_event(datetime="2026-02-30T08:42:17Z")


def test_impossible_instant_is_rejected_by_json_schema() -> None:
    data = make_event().to_dict()
    data["datetime"] = "2026-99-99T99:99:99Z"  # matches the shape, not a real instant
    with pytest.raises(jsonschema.ValidationError):
        validate_event_dict(data)


def test_from_dict_rejects_string_where_array_expected() -> None:
    # A scalar ioc_refs must not be split into single-character references.
    data = make_event().to_dict()
    data["ioc_refs"] = "ioc-0007"
    with pytest.raises(jsonschema.ValidationError):
        Event.from_dict(data)


def test_from_dict_rejects_null_required_string() -> None:
    # A null in a required string field must fail, not become the literal "None".
    data = make_event().to_dict()
    data["timestamp_raw"] = None
    with pytest.raises(jsonschema.ValidationError):
        Event.from_dict(data)


# Schema document sanity.


def test_schema_document_is_valid() -> None:
    jsonschema.Draft202012Validator.check_schema(load_schema())
