"""Cross-source de-duplication with provenance retained (PRD FR12, Phase 3).

The normalize pipeline de-duplicates by the content-derived ``event_id`` and keeps
every provenance pointer that produced an event (see
``casebound.normalize.pipeline``). The ``event_id`` hashes the core identity fields
(time, principal, action, object, source_tool, source_artifact) but not the source
file path, which lives in ``raw_ref`` and is deliberately kept out of the hash (see
``RawRef``). Two consequences define cross-source de-duplication, and these tests
pin both so the behavior cannot silently regress:

  1. The same observation exported into two different source files (two overlapping
     collections, or one tool run twice) collapses to a single event while both
     source-file provenance pointers are retained.
  2. A heterogeneous stream mixing every adapter de-duplicates correctly: identical
     observations collapse, distinct ones do not, and no event is lost.

Note on identity: because ``source_tool`` and ``source_artifact`` are part of the
event identity, the same real-world event observed by two different tools stays two
distinct events, each keeping its own provenance. That is intentional, not a bug:
collapsing across tools would change the identity definition, which is a
stop-and-ask per the schema design note. These tests assert that distinction so the
guarantee is explicit.
"""

from __future__ import annotations

from collections.abc import Iterator
from itertools import chain
from pathlib import Path

from casebound.ingest import (
    ChainsawAdapter,
    ColumnMap,
    EZToolsAdapter,
    GenericCsvAdapter,
    HayabusaAdapter,
    PlasoAdapter,
    RawRecord,
    VelociraptorAdapter,
)
from casebound.normalize import normalize_records

FIXTURES = Path(__file__).resolve().parent / "fixtures"

# One Hayabusa logon row, identical in content, that two separate exports both
# contain. The RecordID differs to prove the audit handles are kept distinct even
# as the event collapses.
_HAYABUSA_HEADER = (
    '"Timestamp","Computer","Channel","EventID","Level","MitreTactics",'
    '"MitreTags","RecordID","RuleTitle","Details"\n'
)
_HAYABUSA_ROW = (
    '"2026-03-14 04:30:05.000 -04:00","WIN-ACCT-07","Security","4624","info","","",'
    '"{record}","Successful Interactive Logon",'
    '"LogonType: 2 ¦ TargetUserName: jdoe ¦ TargetDomainName: CORP"\n'
)


def _write_hayabusa(path: Path, record: str) -> None:
    path.write_text(_HAYABUSA_HEADER + _HAYABUSA_ROW.format(record=record), encoding="utf-8")


# 1. Cross-export de-duplication: same observation, two files, both retained.


def test_same_event_across_two_exports_collapses_and_keeps_both_files(tmp_path: Path) -> None:
    export_a = tmp_path / "collection_a.csv"
    export_b = tmp_path / "collection_b.csv"
    _write_hayabusa(export_a, record="79989")
    _write_hayabusa(export_b, record="51001")

    combined = chain(HayabusaAdapter().read(export_a), HayabusaAdapter().read(export_b))
    result = normalize_records(combined)

    # The identical logon from two exports collapses to one event.
    assert result.event_count == 1
    assert result.duplicate_count == 1
    refs = result.provenance[result.events[0].event_id]
    # Both source files survive in provenance, each with its own record id (FR12).
    assert {ref.source_file for ref in refs} == {"collection_a.csv", "collection_b.csv"}
    assert {ref.record for ref in refs} == {"79989", "51001"}


def test_dedup_is_independent_of_source_file_path(tmp_path: Path) -> None:
    # The same content under a different file name yields the same event_id, which
    # is what makes cross-export de-duplication possible at all.
    export_a = tmp_path / "a.csv"
    export_b = tmp_path / "b.csv"
    _write_hayabusa(export_a, record="1")
    _write_hayabusa(export_b, record="1")
    id_a = next(iter(normalize_records(HayabusaAdapter().read(export_a)).events)).event_id
    id_b = next(iter(normalize_records(HayabusaAdapter().read(export_b)).events)).event_id
    assert id_a == id_b


# 2. Heterogeneous multi-source stream: dedup invariant holds across all adapters.


def _all_source_streams() -> list[Iterator[RawRecord]]:
    column_map = ColumnMap.from_json(FIXTURES / "generic_edr_map.json")
    return [
        HayabusaAdapter().read(FIXTURES / "hayabusa_slice.csv"),
        EZToolsAdapter().read(FIXTURES / "eztools_mft_slice.csv"),
        GenericCsvAdapter(column_map).read(FIXTURES / "generic_edr_slice.csv"),
        ChainsawAdapter().read(FIXTURES / "chainsaw_detections.json"),
        VelociraptorAdapter().read(FIXTURES / "velociraptor_evtx.jsonl"),
        PlasoAdapter().read(FIXTURES / "plaso_l2t.csv"),
    ]


def test_heterogeneous_stream_does_not_over_or_under_merge() -> None:
    result = normalize_records(chain(*_all_source_streams()))
    # Each adapter's events survive intact; nothing collapses across tools because
    # the source tool is part of the identity. 6 + 11 + 4 + 4 + 4 + 4 = 33.
    assert result.event_count == 33
    assert result.duplicate_count == 0
    # The three malformed-row fixtures (generic, velociraptor, plaso) are reported.
    assert result.problem_count == 3
    per_tool: dict[str, int] = {}
    for event in result.events:
        per_tool[event.source_tool] = per_tool.get(event.source_tool, 0) + 1
    assert per_tool == {
        "hayabusa": 6,
        "eztools": 11,
        "generic_csv": 4,
        "chainsaw": 4,
        "velociraptor": 4,
        "plaso": 4,
    }


def test_duplicate_injected_into_mixed_stream_collapses_with_provenance(tmp_path: Path) -> None:
    # A second Hayabusa export overlapping one event, dropped into the middle of the
    # mixed stream, still collapses and keeps its provenance, proving de-dup is not
    # confused by interleaved records from other sources.
    overlap = tmp_path / "overlap.csv"
    # This logon matches the WIN-FILE-02 svc-backup logon in the Hayabusa slice.
    overlap.write_text(
        _HAYABUSA_HEADER
        + '"2026-03-14 04:55:03.000 -04:00","WIN-FILE-02","Security","4624","high",'
        '"Lateral Movement","T1078.002","99001",'
        '"Network Logon with Stolen Service Account Credentials",'
        '"LogonType: 3 ¦ TargetUserName: svc-backup ¦ TargetDomainName: CORP ¦ '
        'IpAddress: 10.4.12.66 ¦ AuthenticationPackageName: NTLM"\n',
        encoding="utf-8",
    )
    streams = _all_source_streams()
    streams.insert(3, HayabusaAdapter().read(overlap))
    result = normalize_records(chain(*streams))

    # Still 33 unique events: the injected row collapsed into the existing one.
    assert result.event_count == 33
    assert result.duplicate_count == 1
    # The collapsed event now carries provenance from both Hayabusa exports.
    target = next(
        e
        for e in result.events
        if e.source_tool == "hayabusa" and e.principal == "CORP\\svc-backup"
    )
    records = {ref.record for ref in result.provenance[target.event_id]}
    assert {"80356", "99001"} == records
