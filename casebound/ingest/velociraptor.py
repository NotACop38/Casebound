"""The Velociraptor ingest adapter (PRD FR6).

Velociraptor exports each collected artifact's VQL results as JSONL: one JSON
object per line. This adapter reads that JSONL and emits one ``RawRecord`` per
line for the common Windows event-log shape (the ``Windows.EventLogs.Evtx``
family), where each row carries a ``Timestamp``, ``Computer``, ``Channel``,
``EventID``, optional ``Message``, the VQL ``Artifact`` name, and a nested
``EventData`` object. See https://docs.velociraptor.app.

The adapter is a thin reader: it keeps the scalar columns under their natural
Velociraptor names and lifts each ``EventData`` field under the reserved prefix the
Velociraptor mapper reads, then attaches provenance. It does not interpret the row
into the canonical schema; the Velociraptor mapper does that.

Blank lines, and lines that are not a JSON object (including a truncated or
otherwise unparseable line), are skipped, so one bad line never aborts an
otherwise good export. The ``source_artifact`` is the event-log channel rendered
as its EVTX file name when present, otherwise the VQL artifact name, so each record
names the evidence it came from (FR11). The ``raw_ref.record`` is the
``EventRecordID`` when present and otherwise the 1-based source line number.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.normalize.mappers.velociraptor import (
    VELOCIRAPTOR_EVENTDATA_PREFIX,
    VELOCIRAPTOR_KEY_ARTIFACT,
    VELOCIRAPTOR_KEY_CHANNEL,
    VELOCIRAPTOR_KEY_COMPUTER,
    VELOCIRAPTOR_KEY_EVENTID,
    VELOCIRAPTOR_KEY_MESSAGE,
    VELOCIRAPTOR_KEY_TIMESTAMP,
)
from casebound.normalize.schema import RawRef

__all__ = ["VelociraptorAdapter"]

_DEFAULT_ARTIFACT = "velociraptor_result"

# The scalar columns lifted by their natural name (everything else with a scalar
# value is preserved too, so a richer artifact loses nothing).
_SCALAR_KEYS = (
    VELOCIRAPTOR_KEY_TIMESTAMP,
    VELOCIRAPTOR_KEY_COMPUTER,
    VELOCIRAPTOR_KEY_CHANNEL,
    VELOCIRAPTOR_KEY_EVENTID,
    VELOCIRAPTOR_KEY_MESSAGE,
    VELOCIRAPTOR_KEY_ARTIFACT,
)


def _as_str(value: Any) -> str:
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class VelociraptorAdapter(IngestAdapter):
    """Read a Velociraptor JSONL export into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "velociraptor"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per non-blank JSONL line at ``source``."""
        with source.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    row = json.loads(stripped)
                except json.JSONDecodeError:
                    # A line that is not valid JSON cannot become a record. Skip it
                    # rather than aborting the whole export, the same as a line whose
                    # JSON is not an object (below): one truncated line never sinks an
                    # otherwise good run.
                    continue
                if isinstance(row, dict):
                    yield self._to_record(source, line_number, row)

    def _to_record(self, source: Path, line_number: int, row: dict[str, Any]) -> RawRecord:
        event_data = row.get("EventData", {})
        event_data = event_data if isinstance(event_data, dict) else {}

        data: dict[str, str] = {}
        for key, value in row.items():
            if key == "EventData":
                continue
            if not isinstance(value, (dict, list)):
                data[key] = _as_str(value)
        for key, value in event_data.items():
            data[f"{VELOCIRAPTOR_EVENTDATA_PREFIX}{key}"] = _as_str(value)

        return RawRecord(
            source_tool=self.source_tool,
            source_artifact=self._artifact(row),
            raw_ref=RawRef(source_file=source.name, record=self._record_id(row, line_number)),
            data=data,
        )

    @staticmethod
    def _artifact(row: dict[str, Any]) -> str:
        channel = _as_str(row.get(VELOCIRAPTOR_KEY_CHANNEL)).strip()
        if channel:
            return f"{channel.replace('/', '%4')}.evtx"
        artifact = _as_str(row.get(VELOCIRAPTOR_KEY_ARTIFACT)).strip()
        return artifact or _DEFAULT_ARTIFACT

    @staticmethod
    def _record_id(row: dict[str, Any], line_number: int) -> str:
        record_id = _as_str(row.get("EventRecordID")).strip()
        return record_id if record_id else f"line:{line_number}"
