"""The generic CSV ingest adapter, driven by a column-mapping config (PRD FR4).

Not every timeline source warrants a bespoke adapter. This adapter ingests any
delimited CSV once an analyst describes which columns hold the canonical fields,
so a one-off or in-house export can join the timeline without code. The mapping is
a small, documented ``ColumnMap`` (see ``docs/ingest-generic-csv.md``), loadable
from a JSON file with ``ColumnMap.from_json``.

The adapter owns all config interpretation. For each row it:

  - reads the configured timestamp column (required) and carries any configured
    ``assume_timezone`` so the source's known local zone is honored (FR9);
  - resolves message, host, principal, object, action, and timestamp descriptor
    from their configured columns, normalizing a free-form action label into a
    canonical snake_case verb and validating the descriptor against the allowed
    set, each falling back to a configured default when absent or unusable;
  - copies the configured detail columns (or, by default, every column not already
    mapped to a canonical field) into the preserved details; and
  - writes the resolved values under the reserved keys the generic CSV mapper
    reads, so the mapper stays a thin, config-free reassembler.

A row whose timestamp cannot be parsed is still emitted; the mapper reports it as a
malformed row rather than the adapter aborting the run (FR7).

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.normalize.mappers.generic_csv import (
    GENERIC_DETAIL_PREFIX,
    GENERIC_KEY_ACTION,
    GENERIC_KEY_ASSUME_TZ,
    GENERIC_KEY_DATETIME,
    GENERIC_KEY_HOST,
    GENERIC_KEY_MESSAGE,
    GENERIC_KEY_OBJECT,
    GENERIC_KEY_PRINCIPAL,
    GENERIC_KEY_SOURCE_ARTIFACT,
    GENERIC_KEY_TIMESTAMP_DESC,
)
from casebound.normalize.schema import TIMESTAMP_DESCS, RawRef

__all__ = ["ColumnMap", "GenericCsvAdapter"]

# Turn a free-form action label (for example "Process Create" or "LOGON") into a
# canonical snake_case verb. Non-alphanumeric runs become single underscores.
_ACTION_CLEAN_RE = re.compile(r"[^a-z0-9]+")
_VALID_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]*$")


@dataclass(frozen=True)
class ColumnMap:
    """How a generic CSV's columns map to the canonical event fields (FR4).

    Only ``timestamp`` is required. The ``*_column`` fields name the source column
    that holds each canonical value; a value of None means the source has no such
    column and the field is left null (for host, principal, object) or filled from
    a default (action, timestamp descriptor). ``source_artifact`` labels the origin
    of every row. ``assume_timezone`` is an optional IANA zone used when the
    timestamp column carries no offset. ``detail_columns`` selects which columns to
    preserve in details; None preserves every column not mapped to a canonical
    field. ``record_id_column`` names a column to use as the audit handle; without
    it the 1-based source line number is used.
    """

    timestamp: str
    message_column: str | None = None
    host_column: str | None = None
    principal_column: str | None = None
    object_column: str | None = None
    action_column: str | None = None
    timestamp_desc_column: str | None = None
    record_id_column: str | None = None
    default_action: str = "other"
    default_timestamp_desc: str = "other"
    source_artifact: str = "generic_csv"
    assume_timezone: str | None = None
    detail_columns: tuple[str, ...] | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.timestamp, str) or not self.timestamp.strip():
            raise ValueError("ColumnMap.timestamp must name a non-empty timestamp column")
        if not _VALID_ACTION_RE.match(self.default_action):
            raise ValueError(
                f"default_action must be a snake_case verb, got {self.default_action!r}"
            )
        if self.default_timestamp_desc not in TIMESTAMP_DESCS:
            raise ValueError(
                f"default_timestamp_desc must be one of {sorted(TIMESTAMP_DESCS)}, "
                f"got {self.default_timestamp_desc!r}"
            )

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> ColumnMap:
        """Build a ColumnMap from a plain mapping (for example parsed JSON)."""
        details = data.get("detail_columns")
        return cls(
            timestamp=str(data["timestamp"]),
            message_column=_opt_str(data.get("message_column")),
            host_column=_opt_str(data.get("host_column")),
            principal_column=_opt_str(data.get("principal_column")),
            object_column=_opt_str(data.get("object_column")),
            action_column=_opt_str(data.get("action_column")),
            timestamp_desc_column=_opt_str(data.get("timestamp_desc_column")),
            record_id_column=_opt_str(data.get("record_id_column")),
            default_action=str(data.get("default_action", "other")),
            default_timestamp_desc=str(data.get("default_timestamp_desc", "other")),
            source_artifact=str(data.get("source_artifact", "generic_csv")),
            assume_timezone=_opt_str(data.get("assume_timezone")),
            detail_columns=tuple(str(c) for c in details) if details is not None else None,
        )

    @classmethod
    def from_json(cls, path: Path) -> ColumnMap:
        """Load a ColumnMap from a JSON config file (the documented format)."""
        return cls.from_dict(json.loads(path.read_text(encoding="utf-8")))

    def mapped_columns(self) -> set[str]:
        """The set of source columns already bound to a canonical field."""
        bound = {
            self.timestamp,
            self.message_column,
            self.host_column,
            self.principal_column,
            self.object_column,
            self.action_column,
            self.timestamp_desc_column,
            self.record_id_column,
        }
        bound.discard(None)
        return {column for column in bound if column is not None}


def _opt_str(value: Any) -> str | None:
    """Coerce an optional config value to a non-empty string or None."""
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _cell(row: Mapping[str, str], column: str | None) -> str | None:
    """Read a configured column from a row as a non-empty string or None."""
    if column is None:
        return None
    value = row.get(column)
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _to_action(label: str | None, default: str) -> str:
    """Normalize a free-form action label into a canonical snake_case verb."""
    if label is None:
        return default
    cleaned = _ACTION_CLEAN_RE.sub("_", label.strip().lower()).strip("_")
    return cleaned if _VALID_ACTION_RE.match(cleaned) else default


class GenericCsvAdapter(IngestAdapter):
    """Read any delimited CSV into raw records using a column-mapping config."""

    source_tool: ClassVar[str] = "generic_csv"

    def __init__(self, column_map: ColumnMap) -> None:
        self._map = column_map

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per data row, with canonical values resolved.

        Rows are yielded in file order. The ``raw_ref.record`` is the configured
        record-id column when present and otherwise the 1-based source line number.
        """
        with source.open("r", encoding="utf-8", newline="") as handle:
            reader = csv.DictReader(handle)
            for line_number, row in enumerate(reader, start=2):
                clean = {key: (value or "") for key, value in row.items() if key is not None}
                yield self._to_record(source, line_number, clean)

    def _to_record(self, source: Path, line_number: int, row: dict[str, str]) -> RawRecord:
        cmap = self._map
        message = _cell(row, cmap.message_column)
        obj = _cell(row, cmap.object_column)
        action = _to_action(_cell(row, cmap.action_column), cmap.default_action)

        desc = _cell(row, cmap.timestamp_desc_column)
        timestamp_desc = desc if desc in TIMESTAMP_DESCS else cmap.default_timestamp_desc

        data: dict[str, str] = {
            GENERIC_KEY_DATETIME: row.get(cmap.timestamp, ""),
            GENERIC_KEY_TIMESTAMP_DESC: timestamp_desc,
            GENERIC_KEY_MESSAGE: message
            if message is not None
            else self._fallback_message(action, obj),
            GENERIC_KEY_ACTION: action,
            GENERIC_KEY_SOURCE_ARTIFACT: cmap.source_artifact,
        }
        host = _cell(row, cmap.host_column)
        if host is not None:
            data[GENERIC_KEY_HOST] = host
        principal = _cell(row, cmap.principal_column)
        if principal is not None:
            data[GENERIC_KEY_PRINCIPAL] = principal
        if obj is not None:
            data[GENERIC_KEY_OBJECT] = obj
        if cmap.assume_timezone is not None:
            data[GENERIC_KEY_ASSUME_TZ] = cmap.assume_timezone

        for column, value in self._detail_columns(row).items():
            data[f"{GENERIC_DETAIL_PREFIX}{column}"] = value

        record_id = _cell(row, cmap.record_id_column)
        record = record_id if record_id is not None else f"line:{line_number}"
        return RawRecord(
            source_tool=self.source_tool,
            source_artifact=cmap.source_artifact,
            raw_ref=RawRef(source_file=source.name, record=record),
            data=data,
        )

    def _detail_columns(self, row: Mapping[str, str]) -> dict[str, str]:
        configured = self._map.detail_columns
        if configured is not None:
            return {column: row.get(column, "") for column in configured if column in row}
        # Default: every column not already bound to a canonical field, non-empty.
        mapped = self._map.mapped_columns()
        return {
            column: value for column, value in row.items() if column not in mapped and value.strip()
        }

    @staticmethod
    def _fallback_message(action: str, obj: str | None) -> str:
        """Build a short message when the source has no message column."""
        return f"{action} {obj}" if obj is not None else action
