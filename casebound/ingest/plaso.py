"""The Plaso l2tcsv ingest adapter (PRD FR6).

Plaso (log2timeline) builds a super timeline and ``psort`` exports it. This adapter
reads the l2tcsv output module, a CSV with 17 fixed columns: date, time, timezone,
MACB, source, sourcetype, type, user, host, short, desc, version, filename, inode,
notes, format, extra. See
https://plaso.readthedocs.io/en/latest/sources/user/Output-format-l2tcsv.html.

The adapter is a thin reader: it splits the CSV into rows and attaches provenance
(source tool, source artifact, raw reference). It does not interpret a row into a
canonical event; the Plaso mapper does that. The source artifact is the
``sourcetype`` (for example ``NTFS $MFT`` or ``WinEVTX``) when present, otherwise
the ``source``, so each record names the kind of evidence it came from (FR11). The
``raw_ref.record`` is the 1-based source line number, since l2tcsv rows carry no
stable record id.

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

__all__ = ["L2TCSV_COLUMNS", "PlasoAdapter"]

# The 17 fixed l2tcsv columns, in order, for reference. The adapter does not require
# every column to be present but names them here so a reader sees the expected shape.
L2TCSV_COLUMNS: tuple[str, ...] = (
    "date",
    "time",
    "timezone",
    "MACB",
    "source",
    "sourcetype",
    "type",
    "user",
    "host",
    "short",
    "desc",
    "version",
    "filename",
    "inode",
    "notes",
    "format",
    "extra",
)

_DEFAULT_ARTIFACT = "plaso_timeline"


class PlasoAdapter(IngestAdapter):
    """Read a Plaso l2tcsv export into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "plaso"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per data row in the l2tcsv at ``source``.

        Rows are yielded in file order. The ``raw_ref.record`` is the 1-based source
        line number (the header is line 1, so the first data row is line 2).
        """
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            for line_number, row in enumerate(reader, start=2):
                yield self._to_record(source, line_number, row)

    def _to_record(self, source: Path, line_number: int, row: dict[str, str | None]) -> RawRecord:
        data = coerce_row(row)
        return RawRecord(
            source_tool=self.source_tool,
            source_artifact=self._artifact(data),
            raw_ref=RawRef(source_file=source.name, record=f"line:{line_number}"),
            data=data,
        )

    @staticmethod
    def _artifact(data: dict[str, str]) -> str:
        sourcetype = (data.get("sourcetype") or "").strip()
        if sourcetype:
            return sourcetype
        source_label = (data.get("source") or "").strip()
        return source_label or _DEFAULT_ARTIFACT
