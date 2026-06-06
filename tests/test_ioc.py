"""Tests for IOC extraction and defanging (PRD FR16, Phase 4).

The load-bearing properties:

  1. Defanging correctness: an IP or domain is rendered unclickable (dots bracketed,
     http rewritten to hxxp), and the transform is reversible in shape; a hash or a
     path is unchanged.
  2. Classification: IPs, domains, hashes, and Windows paths are extracted from the
     event fields, a file name in free text is not mistaken for a domain, and a path
     containing spaces survives intact.
  3. Structured set and references: indicators de-duplicate across events, each
     carries the events that reference it, and every referencing event names the
     indicator in ioc_refs without its event_id moving.
"""

from __future__ import annotations

from pathlib import Path

from casebound.enrich import (
    IOC_TYPE_DOMAIN,
    IOC_TYPE_HASH,
    IOC_TYPE_IP,
    IOC_TYPE_PATH,
    defang,
    extract_iocs,
    tag_events,
)
from casebound.enrich.ioc import _candidates_from_value
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, RawRef, normalize_records


def _event(
    *,
    obj: str | None = None,
    message: str = "synthetic event for ioc extraction",
    details: dict[str, object] | None = None,
    record: str = "1",
) -> Event:
    return Event(
        datetime="2026-03-14T09:00:00Z",
        timestamp_raw="2026-03-14T09:00:00Z",
        source_timezone="UTC",
        timestamp_desc="logged",
        message=message,
        action="process_create",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record=record),
        object=obj,
        details=details or {},
    )


# 1. Defanging correctness.


def test_defang_brackets_ip_octets() -> None:
    assert defang("203.0.113.77", IOC_TYPE_IP) == "203[.]0[.]113[.]77"
    # No bare (unbracketed) dot survives.
    assert "." not in defang("10.4.12.66", IOC_TYPE_IP).replace("[.]", "")


def test_defang_brackets_domain_dots() -> None:
    assert defang("sync-update.example", IOC_TYPE_DOMAIN) == "sync-update[.]example"
    assert "." not in defang("a.b.c.example", IOC_TYPE_DOMAIN).replace("[.]", "")


def test_defang_rewrites_http_scheme() -> None:
    assert defang("http://evil.example", IOC_TYPE_DOMAIN) == "hxxp://evil[.]example"
    assert defang("HTTPS://Evil.Example", IOC_TYPE_DOMAIN) == "hxxpS://Evil[.]Example"


def test_defang_leaves_hashes_and_paths_unchanged() -> None:
    digest = "a" * 64
    assert defang(digest, IOC_TYPE_HASH) == digest
    path = "C:\\Windows\\System32\\lsass.exe"
    assert defang(path, IOC_TYPE_PATH) == path


# 2. Classification.


def test_extracts_each_type_from_one_value() -> None:
    digest = "ab" * 32  # 64 hex chars
    assert _candidates_from_value("203.0.113.77") == [(IOC_TYPE_IP, "203.0.113.77")]
    assert _candidates_from_value("sync-update.example") == [
        (IOC_TYPE_DOMAIN, "sync-update.example")
    ]
    assert _candidates_from_value(digest) == [(IOC_TYPE_HASH, digest)]
    assert _candidates_from_value("C:\\Windows\\Temp\\x.exe") == [
        (IOC_TYPE_PATH, "C:\\Windows\\Temp\\x.exe")
    ]


def test_file_name_in_free_text_is_not_a_domain() -> None:
    found = _candidates_from_value("winword.exe spawned powershell.exe with an encoded command")
    assert all(kind != IOC_TYPE_DOMAIN for kind, _ in found)


def test_a_path_with_spaces_survives_as_one_indicator() -> None:
    value = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
    assert _candidates_from_value(value) == [(IOC_TYPE_PATH, value)]


def test_a_command_line_yields_its_embedded_path_not_the_exe_name() -> None:
    found = _candidates_from_value("7z.exe a -p REDACTED C:\\Windows\\Temp\\backup.7z")
    assert (IOC_TYPE_PATH, "C:\\Windows\\Temp\\backup.7z") in found
    assert all(kind != IOC_TYPE_DOMAIN for kind, _ in found)


def test_ip_in_a_host_port_object_is_extracted() -> None:
    extraction = extract_iocs([_event(obj="203.0.113.77:443")])
    values = {(ioc.ioc_type, ioc.value) for ioc in extraction.iocs}
    assert (IOC_TYPE_IP, "203.0.113.77") in values


# 3. Structured set and references.


def test_indicators_dedupe_across_events_and_keep_references() -> None:
    shared = "203.0.113.77"
    one = _event(obj=f"{shared}:443", record="1")
    two = _event(message=f"outbound to {shared}", record="2")
    extraction = extract_iocs([one, two])

    ips = extraction.iocs.by_type(IOC_TYPE_IP)
    assert len(ips) == 1
    ioc = ips[0]
    assert ioc.value == shared
    assert set(ioc.event_ids) == {one.event_id, two.event_id}


def test_referencing_event_names_the_indicator_in_ioc_refs() -> None:
    event = _event(obj="sync-update.example:443")
    extraction = extract_iocs([event])
    tagged = extraction.events[0]
    domain = extraction.iocs.by_type(IOC_TYPE_DOMAIN)[0]
    assert domain.ioc_id in tagged.ioc_refs
    # Extraction never moves an event_id.
    assert tagged.event_id == event.event_id


def test_extraction_is_idempotent() -> None:
    event = _event(obj="C:\\Windows\\System32\\lsass.exe")
    once = extract_iocs([event]).events[0]
    twice = extract_iocs([once]).events[0]
    assert once.ioc_refs == twice.ioc_refs


# 4. On the showcase scenario.


def _scenario_events(tmp_path: Path) -> list[Event]:
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    assert result.problem_count == 0
    return tag_events(result.events)


def test_scenario_recovers_the_known_iocs(tmp_path: Path) -> None:
    events = _scenario_events(tmp_path)
    extraction = extract_iocs(events)
    values_by_type: dict[str, set[str]] = {}
    for ioc in extraction.iocs:
        values_by_type.setdefault(ioc.ioc_type, set()).add(ioc.value)

    # The external C2 endpoint and an internal address are recovered as IPs.
    assert "203.0.113.77" in values_by_type.get(IOC_TYPE_IP, set())
    assert "10.4.12.66" in values_by_type.get(IOC_TYPE_IP, set())
    # The C2 domain is recovered and is defanged for display.
    assert "sync-update.example" in values_by_type.get(IOC_TYPE_DOMAIN, set())
    domain = next(i for i in extraction.iocs if i.value == "sync-update.example")
    assert domain.defanged == "sync-update[.]example"
    # The implant and service-binary paths are recovered as path indicators.
    paths = values_by_type.get(IOC_TYPE_PATH, set())
    assert any(p.endswith("updater.exe") for p in paths)
    assert any(p.endswith("winhelpsvc.exe") for p in paths)
    # The seed-derived service-binary hash is recovered as a 64-hex hash indicator.
    hashes = values_by_type.get(IOC_TYPE_HASH, set())
    assert any(len(h) == 64 for h in hashes)
