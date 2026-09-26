"""Hayabusa output formats all normalize to the same canonical events (PRD FR2).

Hayabusa writes a timeline as CSV in several profiles (``csv-timeline``) or as JSON
(``json-timeline``: a stream of pretty-printed objects by default, one object per
line with ``-L``). An analyst should get the same case whichever they ran, so the
bundled scenario is rendered in each form here and every rendering must normalize to
the same events with the same ids:

  - the verbose CSV profile the generator writes (with ``EvtxFile``, MITRE tags,
    and ``ExtraFieldInfo``);
  - a standard-profile CSV without those columns, where the source artifact must
    be recovered from the abbreviated channel;
  - JSONL, a pretty-printed JSON object stream, and a JSON array, with typed
    values and nested ``Details`` objects as Hayabusa emits them.

No network, no API keys.
"""

from __future__ import annotations

import csv
import io
import json
from pathlib import Path
from typing import Any

import pytest

from casebound.generate import generate
from casebound.generate.synth import HAYABUSA_SEP
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, normalize_records
from casebound.normalize.mappers.hayabusa import expand_channel, parse_details, resolve_fields
from casebound.normalize.severity import normalize_severity

# The columns of Hayabusa's standard profile.
STANDARD_COLUMNS = (
    "Timestamp",
    "RuleTitle",
    "Level",
    "Computer",
    "Channel",
    "EventID",
    "RecordID",
    "Details",
    "ExtraFieldInfo",
    "RuleID",
)


def _rows() -> list[dict[str, str]]:
    return list(csv.DictReader(io.StringIO(generate().csv_text)))


def _typed(value: str) -> Any:
    """Hayabusa's JSON writes integer-valued fields as numbers."""
    return int(value) if value.isdigit() else value


def _pairs(cell: str) -> dict[str, Any]:
    return {key: _typed(value) for key, value in parse_details(cell).items()}


def _tags(cell: str) -> list[str]:
    return [tag.strip() for tag in cell.split(HAYABUSA_SEP) if tag.strip() not in ("", "-")]


def _as_json_object(row: dict[str, str]) -> dict[str, Any]:
    obj: dict[str, Any] = {
        "Timestamp": row["Timestamp"],
        "RuleTitle": row["RuleTitle"],
        "Level": row["Level"],
        "Computer": row["Computer"],
        "Channel": row["Channel"],
        "EventID": int(row["EventID"]),
        "RecordID": int(row["RecordID"]),
        "Details": _pairs(row["Details"]),
        "ExtraFieldInfo": _pairs(row["ExtraFieldInfo"]),
        "RuleFile": row["RuleFile"],
        "RuleID": row["RuleID"],
        "EvtxFile": row["EvtxFile"],
    }
    for column in ("MitreTactics", "MitreTags", "OtherTags"):
        tags = _tags(row[column])
        if tags:
            obj[column] = tags
    return obj


def _events(path: Path) -> list[Event]:
    result = normalize_records(HayabusaAdapter().read(path))
    assert result.problem_count == 0
    return sorted(result.events, key=lambda event: event.event_id)


def _core(events: list[Event]) -> list[tuple[Any, ...]]:
    return [
        (
            event.event_id,
            event.datetime,
            event.host,
            event.principal,
            event.action,
            event.object,
            event.source_artifact,
            event.raw_ref.record,
            event.message,
        )
        for event in events
    ]


@pytest.fixture(scope="module")
def verbose_csv(tmp_path_factory: pytest.TempPathFactory) -> list[Event]:
    path = tmp_path_factory.mktemp("csv") / "timeline.csv"
    path.write_text(generate().csv_text, encoding="utf-8")
    return _events(path)


def test_standard_profile_csv_matches_the_verbose_profile(
    verbose_csv: list[Event], tmp_path: Path
) -> None:
    buffer = io.StringIO()
    writer = csv.DictWriter(buffer, fieldnames=STANDARD_COLUMNS, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(_rows())
    path = tmp_path / "standard.csv"
    path.write_text(buffer.getvalue(), encoding="utf-8")
    assert _core(_events(path)) == _core(verbose_csv)


@pytest.mark.parametrize("layout", ["jsonl", "stream", "array"])
def test_json_timelines_match_the_csv(
    verbose_csv: list[Event], tmp_path: Path, layout: str
) -> None:
    objects = [_as_json_object(row) for row in _rows()]
    if layout == "jsonl":
        path = tmp_path / "timeline.jsonl"
        text = "".join(json.dumps(obj, ensure_ascii=False) + "\n" for obj in objects)
    elif layout == "stream":
        # Hayabusa's default json-timeline: pretty-printed objects, one after another.
        path = tmp_path / "timeline.json"
        text = "\n".join(json.dumps(obj, ensure_ascii=False, indent=4) for obj in objects)
    else:
        path = tmp_path / "timeline.json"
        text = json.dumps(objects, ensure_ascii=False, indent=2)
    path.write_text(text, encoding="utf-8")
    events = _events(path)
    assert _core(events) == _core(verbose_csv)
    # Tags and severity survive the JSON form too.
    assert [event.details.get("rule_mitre_tags") for event in events] == [
        event.details.get("rule_mitre_tags") for event in verbose_csv
    ]


def test_json_stream_skips_stray_values(tmp_path: Path) -> None:
    good = _as_json_object(_rows()[0])
    path = tmp_path / "timeline.jsonl"
    path.write_text(
        json.dumps(good) + "\n" + "[1, 2]\n" + "{truncated\n" + json.dumps(good) + "\n",
        encoding="utf-8",
    )
    result = normalize_records(HayabusaAdapter().read(path))
    assert result.event_count == 1
    assert result.duplicate_count == 1


def test_channel_abbreviations_expand() -> None:
    assert expand_channel("Sec") == "Security"
    assert expand_channel("Sysmon") == "Microsoft-Windows-Sysmon/Operational"
    assert expand_channel("TaskSch") == "Microsoft-Windows-TaskScheduler/Operational"
    # An unknown or already full name passes through.
    assert expand_channel("Security") == "Security"
    assert expand_channel("AppLocker") == "AppLocker"


def test_the_same_abbreviation_resolves_per_event() -> None:
    # "Proc" is NewProcessName on Security 4688 but Image on Sysmon 1.
    security = resolve_fields("Security", 4688, {"Details": "Proc: C:\\a.exe"})
    sysmon = resolve_fields(
        "Microsoft-Windows-Sysmon/Operational", 1, {"Details": "Proc: C:\\a.exe"}
    )
    assert security == {"NewProcessName": "C:\\a.exe"}
    assert sysmon == {"Image": "C:\\a.exe"}


def test_extra_field_info_recovers_what_details_omitted() -> None:
    fields = resolve_fields(
        "Security",
        4624,
        {
            "Details": "Type: 3 ¦ TgtUser: jdoe ¦ SrcIP: n/a",
            "ExtraFieldInfo": "TargetDomainName: CORP ¦ TargetUserName: ignored",
        },
    )
    # Details wins over ExtraFieldInfo on a shared key; n/a means absent.
    assert fields == {
        "LogonType": "3",
        "TargetUserName": "jdoe",
        "TargetDomainName": "CORP",
    }


def test_all_field_info_is_authoritative() -> None:
    fields = resolve_fields(
        "Security",
        4624,
        {"AllFieldInfo": "TargetUserName: jdoe", "Details": "TgtUser: someone-else"},
    )
    assert fields["TargetUserName"] == "jdoe"


@pytest.mark.parametrize(
    ("raw", "normalized"),
    [
        ("crit", "critical"),
        ("critical", "critical"),
        ("high", "high"),
        ("med", "medium"),
        ("medium", "medium"),
        ("low", "low"),
        ("info", "informational"),
        ("informational", "informational"),
        ("", None),
        (None, None),
        ("bogus", None),
    ],
)
def test_hayabusa_levels_normalize(raw: str | None, normalized: str | None) -> None:
    assert normalize_severity(raw) == normalized
