"""The Hayabusa timeline ingest adapter (PRD FR2).

Hayabusa is a Windows event-log fast-forensics tool that emits a detection
timeline. This adapter reads both of its timeline formats:

  - ``csv-timeline`` output, in any built-in profile (minimal, standard, verbose,
    all-field-info, super-verbose, timesketch). Columns are read by name, so the
    profile does not matter.
  - ``json-timeline`` output, either JSONL (``-L``) or the default pretty-printed
    stream of objects, or a JSON array. Nested ``Details``, ``ExtraFieldInfo``,
    and ``AllFieldInfo`` objects and the MITRE tag lists are carried through as
    JSON text for the mapper to decode.

See https://yamato-security.github.io/hayabusa/output/.

The adapter is a thin reader: it splits the export into rows and attaches
provenance (source tool, source artifact, raw reference). It does not interpret a
row into a canonical event; the Hayabusa mapper in
``casebound.normalize.mappers.hayabusa`` does that. For the source artifact it
prefers the ``EvtxFile`` column the verbose profiles emit (the exact EVTX file the
event came from), and otherwise derives the artifact from the channel, expanding
Hayabusa's channel abbreviations (``Sec`` becomes ``Security.evtx``), so each record
carries the most precise artifact available.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
import json
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord, coerce_row, scalar_to_str
from casebound.normalize.mappers.hayabusa import expand_channel
from casebound.normalize.schema import RawRef

__all__ = ["HayabusaAdapter", "channel_to_artifact"]

# The channel that a row with no Channel value is attributed to.
_DEFAULT_CHANNEL = "Unknown"

# File suffixes read as a JSON timeline rather than CSV.
_JSON_SUFFIXES = frozenset({".json", ".jsonl"})


def channel_to_artifact(channel: str) -> str:
    """Render a Windows event-log channel as its on-disk EVTX file name.

    Channels map to ``.evtx`` files by replacing the ``/`` separator with the
    ``%4`` escape Windows uses, so ``Security`` becomes ``Security.evtx`` and
    ``Microsoft-Windows-Sysmon/Operational`` becomes
    ``Microsoft-Windows-Sysmon%4Operational.evtx``. Hayabusa's channel
    abbreviations are expanded first. An empty channel falls back to a stable
    placeholder so provenance is never blank.
    """
    name = expand_channel(channel) or _DEFAULT_CHANNEL
    return f"{name.replace('/', '%4')}.evtx"


def _flatten(row: Mapping[str, Any]) -> dict[str, str]:
    """Flatten one JSON timeline object into the string row a CSV export carries.

    Scalars become strings; nested objects and lists (the Details family and the
    MITRE tag lists) become compact JSON text the mapper decodes.
    """
    flat: dict[str, str] = {}
    for key, value in row.items():
        if isinstance(value, (dict, list)):
            flat[str(key)] = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
        else:
            flat[str(key)] = scalar_to_str(value)
    return flat


def _iter_json_objects(source: Path) -> Iterator[tuple[int, dict[str, Any]]]:
    """Yield ``(ordinal, object)`` for every object in a Hayabusa JSON timeline.

    JSONL is streamed line by line. A JSON array, or Hayabusa's default stream of
    pretty-printed objects, is decoded from the whole text. Anything that is not a
    JSON object is skipped, so one stray value never sinks an export.
    """
    with source.open("r", encoding="utf-8-sig") as handle:
        first_line = ""
        for line in handle:
            if line.strip():
                first_line = line
                break
        stripped = first_line.strip()
        streamable = False
        if stripped.startswith("{"):
            try:
                streamable = isinstance(json.loads(stripped), dict)
            except json.JSONDecodeError:
                streamable = False
        if streamable:
            ordinal = 1
            yield ordinal, json.loads(stripped)
            for line in handle:
                text = line.strip()
                if not text:
                    continue
                ordinal += 1
                try:
                    decoded = json.loads(text)
                except json.JSONDecodeError:
                    continue
                if isinstance(decoded, dict):
                    yield ordinal, decoded
            return
        text = first_line + handle.read()

    decoder = json.JSONDecoder()
    position = 0
    ordinal = 0
    while position < len(text):
        while position < len(text) and text[position] in " \t\r\n,":
            position += 1
        if position >= len(text):
            break
        try:
            decoded, position = decoder.raw_decode(text, position)
        except json.JSONDecodeError:
            return
        items = decoded if isinstance(decoded, list) else [decoded]
        for item in items:
            ordinal += 1
            if isinstance(item, dict):
                yield ordinal, item


class HayabusaAdapter(IngestAdapter):
    """Read a Hayabusa CSV or JSON timeline into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "hayabusa"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per timeline row at ``source``, in file order.

        The ``raw_ref.record`` is the Hayabusa RecordID when present (the EVTX
        record number, the most useful audit handle) and otherwise the 1-based line
        number (CSV) or object ordinal (JSON), so every record stays traceable.
        """
        if source.suffix.lower() in _JSON_SUFFIXES:
            for ordinal, obj in _iter_json_objects(source):
                yield self._to_record(source, f"entry:{ordinal}", _flatten(obj))
            return
        with source.open("r", encoding="utf-8-sig", newline="") as handle:
            reader = csv.DictReader(handle)
            # csv counts the header as line 1, so the first data row is line 2.
            for line_number, row in enumerate(reader, start=2):
                yield self._to_record(source, f"line:{line_number}", coerce_row(row))

    def _to_record(self, source: Path, fallback: str, data: dict[str, str]) -> RawRecord:
        record_id = (data.get("RecordID") or "").strip()
        return RawRecord(
            source_tool=self.source_tool,
            source_artifact=self._artifact(data),
            raw_ref=RawRef(
                source_file=source.name,
                record=record_id if record_id and record_id != "-" else fallback,
            ),
            data=data,
        )

    @staticmethod
    def _artifact(data: Mapping[str, str]) -> str:
        """Pick the most precise source artifact available for the row.

        Hayabusa's verbose, all-field-info, super-verbose, and Timesketch profiles
        emit an ``EvtxFile`` column naming the exact EVTX file the event came from.
        That is the strongest provenance (FR11), so it is preferred when present;
        otherwise the artifact is derived from the channel. Only the file's base
        name is kept, matching the Chainsaw adapter: ``source_artifact`` is an
        identity field, so the same event exported from collections mounted at
        different paths must still collapse in cross-source dedup (FR12).
        """
        evtx_file = (data.get("EvtxFile") or "").strip()
        if evtx_file and evtx_file != "-":
            return Path(evtx_file.replace("\\", "/")).name or evtx_file
        return channel_to_artifact(data.get("Channel", ""))
