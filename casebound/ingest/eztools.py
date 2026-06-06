"""The Eric Zimmerman / Timeline Explorer CSV ingest adapter (PRD FR3).

KAPE triage collections ship the Eric Zimmerman tools' CSV output, which analysts
review in Timeline Explorer. This adapter reads the MFTECmd ``$MFT`` CSV, the
keystone EZ-tools timeline artifact, whose columns are EntryNumber,
SequenceNumber, InUse, ParentEntryNumber, ParentSequenceNumber, ParentPath,
FileName, Extension, FileSize, ... Created0x10, LastModified0x10,
LastRecordChange0x10, LastAccess0x10, and so on. See
https://github.com/EricZimmerman/MFTECmd.

One ``$MFT`` record carries several Standard Information (0x10) timestamps, each a
distinct timeline moment: when the file was created, last written, last accessed,
and when its MFT record last changed. Because a mapper turns one record into one
event, this adapter expands one MFT row into one ``RawRecord`` per populated
Standard Information timestamp, annotating each with the chosen timestamp string
and its descriptor under the two reserved keys the EZ-tools mapper reads
(``EZ_TIMESTAMP_KEY`` and ``EZ_TIMESTAMP_DESC_KEY``). The full row is preserved
alongside the annotations, so no source field is lost. A timestamp column that is
absent or empty produces no record, so a file with no recorded access time simply
yields fewer events rather than a malformed one.

The ``raw_ref.record`` is the MFT entry and sequence number plus the descriptor
(for example ``entry:8042 seq:3 created``), so every expanded event points back to
the exact record and timestamp it came from (FR11).

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
from collections.abc import Iterator
from pathlib import Path
from typing import ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.normalize.mappers.eztools import EZ_TIMESTAMP_DESC_KEY, EZ_TIMESTAMP_KEY
from casebound.normalize.schema import RawRef

__all__ = ["SI_TIMESTAMP_COLUMNS", "EZToolsAdapter"]

# The source artifact every row describes. MFTECmd parses the NTFS master file
# table, so the originating artifact is the ``$MFT`` itself.
_ARTIFACT = "$MFT"

# The Standard Information (0x10) timestamp columns this adapter expands, each
# paired with the canonical descriptor it represents. Order is the analyst's
# natural MACB reading order (created, modified, accessed, record change). Only the
# 0x10 attribute is expanded: it is the Standard Information set an analyst times a
# file by; the 0x30 FileName attribute timestamps remain in the preserved row for
# anti-timestomping cross-reference but are not promoted to their own events.
SI_TIMESTAMP_COLUMNS: tuple[tuple[str, str], ...] = (
    ("Created0x10", "created"),
    ("LastModified0x10", "modified"),
    ("LastAccess0x10", "accessed"),
    ("LastRecordChange0x10", "other"),
)


class EZToolsAdapter(IngestAdapter):
    """Read an MFTECmd ``$MFT`` CSV into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "eztools"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per populated Standard Information timestamp.

        Rows are read in file order; within a row the timestamps are emitted in
        MACB reading order. A row with no populated Standard Information timestamp
        yields nothing, so an empty-timestamp record never becomes a malformed
        event downstream.
        """
        with source.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for line_number, row in enumerate(reader, start=2):
                yield from self._expand_row(source, line_number, row)

    def _expand_row(
        self, source: Path, line_number: int, row: dict[str, str | None]
    ) -> Iterator[RawRecord]:
        # DictReader yields None for a column the row is missing; normalize to "".
        data: dict[str, str] = {
            key: (value if value is not None else "")
            for key, value in row.items()
            if key is not None
        }
        identity = self._record_identity(data, line_number)
        for column, desc in SI_TIMESTAMP_COLUMNS:
            timestamp = (data.get(column) or "").strip()
            if not timestamp:
                continue
            annotated = dict(data)
            annotated[EZ_TIMESTAMP_KEY] = timestamp
            annotated[EZ_TIMESTAMP_DESC_KEY] = desc
            yield RawRecord(
                source_tool=self.source_tool,
                source_artifact=_ARTIFACT,
                raw_ref=RawRef(source_file=source.name, record=f"{identity} {desc}"),
                data=annotated,
            )

    @staticmethod
    def _record_identity(data: dict[str, str], line_number: int) -> str:
        """Build the per-record audit handle from the MFT entry and sequence.

        The entry and sequence number together identify an MFT record uniquely;
        when the entry number is missing the 1-based source line is used so every
        record stays traceable.
        """
        entry = (data.get("EntryNumber") or "").strip()
        if not entry:
            return f"line:{line_number}"
        sequence = (data.get("SequenceNumber") or "").strip()
        return f"entry:{entry} seq:{sequence}" if sequence else f"entry:{entry}"
