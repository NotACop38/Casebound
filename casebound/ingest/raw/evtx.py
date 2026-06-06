"""Dissect-backed EVTX ingest adapter (PRD Section 5 Raw mode).

Reads a Windows ``.evtx`` event log directly with Dissect's ``dissect.eventlog``
parser, for users who have not pre-run a tool over it. Re-verified against the
``dissect.eventlog`` API at author time: ``Evtx(fh)`` takes a binary file handle
and is iterable, yielding one ``KeyValueCollection`` (a ``dict`` subclass) per
record. Keys are the flattened XML element names: System children appear as
``EventID``, ``Computer``, ``Channel``, ``Provider_Name``,
``TimeCreated_SystemTime``, ``EventRecordID``, and so on, while each EventData
``Data Name="X"`` entry appears directly under ``X``. Substitution values may be
wrapped objects exposing ``get()``.

This adapter is deliberately thin over Dissect. The two functions that shape a
record, ``_flatten_record`` (resolve wrapped values, stringify) and
``evtx_record_to_raw`` (split System from EventData and attach provenance), are
pure and have no Dissect dependency, so they are unit-tested offline. The Dissect
import is lazy (see ``_loader``) so importing this module loads no AGPL code.

Each ``RawRecord`` carries ``source_tool="dissect"`` and the ``DISSECT_KIND_EVTX``
annotation; the Dissect mapper turns it into a canonical event, mapping EventIDs
through the same shared table Velociraptor uses. The ``source_artifact`` is the
``.evtx`` file name, and ``raw_ref.record`` is the ``EventRecordID`` when present,
otherwise the 1-based record ordinal.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.ingest.raw._loader import load_evtx_class
from casebound.normalize.mappers.dissect import (
    DISSECT_EVTX_CHANNEL_KEY,
    DISSECT_EVTX_COMPUTER_KEY,
    DISSECT_EVTX_EVENTDATA_PREFIX,
    DISSECT_EVTX_EVENTID_KEY,
    DISSECT_EVTX_PROVIDER_KEY,
    DISSECT_EVTX_TIMESTAMP_KEY,
    DISSECT_KIND_EVTX,
    DISSECT_KIND_KEY,
)
from casebound.normalize.schema import RawRef

__all__ = ["DissectEvtxAdapter", "evtx_record_to_raw"]

# The flattened EVTX System element keys. Everything else a record carries is an
# EventData field, lifted under the reserved prefix so the mapper can rebuild it
# and so a System name can never be shadowed by an EventData field of the same
# name. The timestamp, computer, channel, EventID, and provider are promoted to
# their own reserved keys; the rest are kept as record metadata, not EventData.
_SYSTEM_KEYS: frozenset[str] = frozenset(
    {
        "Provider_Name",
        "Provider_Guid",
        "EventID",
        "EventID_Qualifiers",
        "Version",
        "Level",
        "Task",
        "Opcode",
        "Keywords",
        "TimeCreated_SystemTime",
        "EventRecordID",
        "Correlation_ActivityID",
        "Correlation_RelatedActivityID",
        "Execution_ProcessID",
        "Execution_ThreadID",
        "Channel",
        "Computer",
        "Security_UserID",
    }
)


def _resolve(value: Any) -> Any:
    """Unwrap a Dissect substitution value, leaving plain values untouched.

    Dissect wraps some EVTX values in a small object exposing a no-argument
    ``get()``. Primitives, datetimes, and bytes are returned as is; anything else
    with a callable ``get`` is unwrapped, which covers the wrapper without
    mis-firing on a plain mapping (``dict.get`` needs an argument and is skipped).
    """
    if value is None or isinstance(value, (str, bytes, bool, int, float, datetime)):
        return value
    getter = getattr(value, "get", None)
    if callable(getter):
        try:
            return getter()
        except TypeError:
            return value
    return value


def _stringify(value: Any) -> str:
    """Render a resolved value as a string for the flat record."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _flatten_record(record: Mapping[str, Any]) -> dict[str, str]:
    """Resolve and stringify every field of one parsed EVTX record."""
    return {str(key): _stringify(_resolve(raw)) for key, raw in record.items()}


def evtx_record_to_raw(flat: Mapping[str, str], *, source_file: str, line_number: int) -> RawRecord:
    """Build a provenance-bearing raw record from one flattened EVTX record.

    Pure: it does not touch Dissect. The System fields are promoted to reserved
    keys, every other field is lifted under the EventData prefix, and the kind
    annotation marks the record for the Dissect EVTX mapper.
    """
    data: dict[str, str] = {
        DISSECT_KIND_KEY: DISSECT_KIND_EVTX,
        DISSECT_EVTX_TIMESTAMP_KEY: flat.get("TimeCreated_SystemTime", ""),
        DISSECT_EVTX_COMPUTER_KEY: flat.get("Computer", ""),
        DISSECT_EVTX_CHANNEL_KEY: flat.get("Channel", ""),
        DISSECT_EVTX_EVENTID_KEY: flat.get("EventID", ""),
        DISSECT_EVTX_PROVIDER_KEY: flat.get("Provider_Name", ""),
    }
    for key, value in flat.items():
        if key in _SYSTEM_KEYS:
            continue
        data[f"{DISSECT_EVTX_EVENTDATA_PREFIX}{key}"] = value

    record_id = (flat.get("EventRecordID") or "").strip()
    record = record_id if record_id else f"line:{line_number}"
    return RawRecord(
        source_tool="dissect",
        source_artifact=source_file,
        raw_ref=RawRef(source_file=source_file, record=record),
        data=data,
    )


class DissectEvtxAdapter(IngestAdapter):
    """Read a Windows ``.evtx`` event log into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "dissect"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per EVTX record at ``source``.

        Raises ``RawModeDependencyError`` if Dissect is not installed (the optional
        ``raw`` extra). The file is opened read-only and closed when iteration ends.
        """
        evtx_class = load_evtx_class()
        with source.open("rb") as handle:
            for line_number, record in enumerate(evtx_class(handle), start=1):
                flat = _flatten_record(record)
                yield evtx_record_to_raw(flat, source_file=source.name, line_number=line_number)
