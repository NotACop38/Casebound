"""A UTF-8 BOM on the evidence file must not corrupt ingestion (FR7, FR9).

Windows tooling routinely writes BOM-prefixed UTF-8: PowerShell's Export-Csv,
Excel's CSV export, and Notepad all do. Before the utf-8-sig fix the BOM glued
itself onto the first header or line and every adapter failed differently: the
CSV adapters lost their first column (Hayabusa reported every row malformed;
Plaso silently mis-dated events), Chainsaw's whole-file JSON parse raised, and
Velociraptor silently dropped its first line.

The property pinned here: for every adapter, a byte-identical fixture with a BOM
prefix normalizes to exactly the same events, with no problems, as the original.

No network, no API keys.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from casebound.ingest import (
    ChainsawAdapter,
    ColumnMap,
    EZToolsAdapter,
    GenericCsvAdapter,
    HayabusaAdapter,
    IngestAdapter,
    PlasoAdapter,
    VelociraptorAdapter,
)
from casebound.normalize import normalize_records

FIXTURES = Path(__file__).resolve().parent / "fixtures"

BOM = b"\xef\xbb\xbf"


def _adapters() -> list[tuple[str, IngestAdapter, Path]]:
    return [
        ("hayabusa", HayabusaAdapter(), FIXTURES / "hayabusa_slice.csv"),
        ("eztools", EZToolsAdapter(), FIXTURES / "eztools_mft_slice.csv"),
        ("chainsaw", ChainsawAdapter(), FIXTURES / "chainsaw_detections.json"),
        ("velociraptor", VelociraptorAdapter(), FIXTURES / "velociraptor_evtx.jsonl"),
        ("plaso", PlasoAdapter(), FIXTURES / "plaso_l2t.csv"),
        (
            "generic_csv",
            GenericCsvAdapter(ColumnMap.from_json(FIXTURES / "generic_edr_map.json")),
            FIXTURES / "generic_edr_slice.csv",
        ),
    ]


@pytest.mark.parametrize(
    ("adapter", "fixture"),
    [pytest.param(adapter, fixture, id=name) for name, adapter, fixture in _adapters()],
)
def test_bom_prefixed_evidence_normalizes_identically(
    adapter: IngestAdapter, fixture: Path, tmp_path: Path
) -> None:
    bom_copy = tmp_path / fixture.name
    bom_copy.write_bytes(BOM + fixture.read_bytes())

    plain = normalize_records(adapter.read(fixture))
    with_bom = normalize_records(adapter.read(bom_copy))

    # Some fixtures deliberately carry a malformed row (FR7 coverage); the BOM
    # must change nothing: same events, same problems.
    assert plain.event_count > 0
    assert with_bom.event_count == plain.event_count
    assert with_bom.problem_count == plain.problem_count
    assert [event.event_id for event in with_bom.events] == [
        event.event_id for event in plain.events
    ]
