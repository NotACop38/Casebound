"""The Hayabusa CSV ingest adapter (PRD FR2).

Hayabusa is a Windows event-log fast-forensics tool that emits a timeline as CSV.
This adapter reads the verbose ``csv-timeline`` profile the synthetic generator
produces (``casebound.generate.synth``), whose columns are Timestamp, Computer,
Channel, EventID, Level, MitreTactics, MitreTags, RecordID, RuleTitle, Details.
See https://github.com/Yamato-Security/hayabusa/wiki.

The adapter is a thin reader: it splits the CSV into rows and attaches provenance
(source tool, source artifact, raw reference). It does not interpret a row into a
canonical event; the Hayabusa mapper in ``casebound.normalize.mappers.hayabusa``
does that. For the source artifact it prefers the ``EvtxFile`` column the verbose
profiles emit (the exact EVTX file the event came from), and otherwise derives the
artifact from the Channel column (for example ``Security`` to ``Security.evtx``),
so each emitted record carries the most precise artifact available.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord, coerce_row
from casebound.normalize.schema import RawRef

__all__ = ["HayabusaAdapter", "channel_to_artifact"]

# The columns the verbose csv-timeline profile emits, in order. The adapter does
# not require every column to be present, but it names them here so a reader can
# see the shape it expects.
EXPECTED_COLUMNS: tuple[str, ...] = (
    "Timestamp",
    "Computer",
    "Channel",
    "EventID",
    "Level",
    "MitreTactics",
    "MitreTags",
    "RecordID",
    "RuleTitle",
    "Details",
)

# The Windows event-log channel that a row with no Channel value is attributed to.
_DEFAULT_CHANNEL = "Unknown"


def channel_to_artifact(channel: str) -> str:
    """Render a Windows event-log channel as its on-disk EVTX file name.

    Channels map to ``.evtx`` files by replacing the ``/`` separator with the
    ``%4`` escape Windows uses, so ``Security`` becomes ``Security.evtx`` and
    ``Microsoft-Windows-Sysmon/Operational`` becomes
    ``Microsoft-Windows-Sysmon%4Operational.evtx``. An empty channel falls back to
    a stable placeholder so provenance is never blank.
    """
    name = channel.strip() or _DEFAULT_CHANNEL
    return f"{name.replace('/', '%4')}.evtx"


class HayabusaAdapter(IngestAdapter):
    """Read a Hayabusa csv-timeline export into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "hayabusa"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per data row in the Hayabusa CSV at ``source``.

        Rows are yielded in file order. The ``raw_ref.record`` is the Hayabusa
        RecordID when present (the EVTX record number, the most useful audit
        handle) and otherwise the 1-based source line number, so every record is
        traceable even when a row lacks a RecordID.
        """
        with source.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            # csv counts the header as line 1, so the first data row is line 2.
            for line_number, row in enumerate(reader, start=2):
                yield self._to_record(source, line_number, row)

    def _to_record(self, source: Path, line_number: int, row: dict[str, str | None]) -> RawRecord:
        data = coerce_row(row)
        channel = data.get("Channel", "")
        record_id = (data.get("RecordID") or "").strip()
        record = record_id if record_id else f"line:{line_number}"
        return RawRecord(
            source_tool=self.source_tool,
            source_artifact=self._artifact(data, channel),
            raw_ref=RawRef(source_file=source.name, record=record),
            data=data,
        )

    @staticmethod
    def _artifact(data: dict[str, str], channel: str) -> str:
        """Pick the most precise source artifact available for the row.

        Hayabusa's verbose, all-field-info, super-verbose, and Timesketch profiles
        emit an ``EvtxFile`` column naming the exact EVTX file the event came from.
        That is the strongest provenance (FR11), so it is preferred when present;
        otherwise the artifact is derived from the Windows channel. A scan over many
        or renamed EVTX files thus records the true file rather than a generic name.
        """
        evtx_file = (data.get("EvtxFile") or "").strip()
        return evtx_file if evtx_file else channel_to_artifact(channel)
