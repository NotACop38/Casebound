"""Map Plaso l2tcsv timeline rows to canonical events (PRD FR6).

Plaso (log2timeline) builds a super timeline and ``psort`` writes it out. The
l2tcsv output module emits 17 fixed columns: date, time, timezone, MACB, source,
sourcetype, type, user, host, short, desc, version, filename, inode, notes,
format, extra. See
https://plaso.readthedocs.io/en/latest/sources/user/Output-format-l2tcsv.html.

This mapper derives the canonical fields from those columns:

  - ``datetime`` and ``source_timezone`` come from combining the date and time
    columns and interpreting them in the row's timezone column via the timezone
    normalizer (FR9); a blank timezone falls back to assumed UTC.
  - ``timestamp_desc`` and ``action`` follow from the ``type`` column through a
    small documented table (a Creation Time is a ``file_create`` created event, a
    Content Modification Time is a ``file_write`` modified event, an Event Logged
    is a ``logged`` event, and so on); an unrecognized type still produces an event
    with descriptor ``other`` and action ``other`` (FR8).
  - ``message`` is the ``desc`` column (the long description), falling back to
    ``short``.
  - ``host`` and ``principal`` come from the host and user columns.
  - ``object`` is the ``filename`` column (the file or path the event concerns).
  - ``details`` preserves the MACB string, the source and sourcetype, the inode,
    the format, any notes, and the parsed ``extra`` key/value pairs.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

Plaso timelines carry no native ATT&CK tags, so ``attack_techniques`` is left for
the deterministic mapping-table step (FR14).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
from casebound.normalize.schema import Event
from casebound.normalize.timezone import TimestampError, normalize_timestamp

if TYPE_CHECKING:
    # Annotation-only: keeps normalize free of a runtime dependency on ingest.
    from casebound.ingest.base import RawRecord

__all__ = ["PlasoMapper", "parse_extra"]

# How a Plaso ``type`` string becomes a canonical (timestamp_desc, action) pair.
# Focused on the common file-system and log types; an unlisted type falls back to
# the generic descriptor and action so the row still becomes an event.
_TYPE_MAP: dict[str, tuple[str, str]] = {
    "Creation Time": ("created", "file_create"),
    "Content Modification Time": ("modified", "file_write"),
    "Last Access Time": ("accessed", "file_read"),
    "Metadata Modification Time": ("other", "file_metadata_change"),
    "Last Time Executed": ("other", "process_create"),
    "Event Logged": ("logged", "logged"),
    "Creation": ("created", "file_create"),
    "Last Written": ("modified", "registry_set"),
}
_FALLBACK_DESC = "other"
_FALLBACK_ACTION = "other"


def _nullable(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _l2t_value(value: str | None) -> str | None:
    """Like ``_nullable`` but also treats the l2tcsv ``-`` placeholder as empty.

    Plaso writes a bare ``-`` in the user (and similar) columns when it has no
    value, so an unknown user becomes a null principal rather than the literal
    string "-".
    """
    trimmed = _nullable(value)
    return None if trimmed == "-" else trimmed


def parse_extra(raw: str) -> dict[str, str]:
    """Parse a Plaso l2tcsv ``extra`` cell into a key/value mapping.

    The extra field joins ``key: value`` pairs with a semicolon. Each pair is split
    on its first colon so a value containing a colon (a path, a URL) is preserved.
    A fragment with no colon is skipped rather than guessed at.
    """
    fields: dict[str, str] = {}
    for fragment in raw.split(";"):
        key, sep, value = fragment.partition(":")
        if not sep:
            continue
        name = key.strip()
        if name:
            fields[name] = value.strip()
    return fields


class PlasoMapper(Mapper):
    """Map Plaso l2tcsv rows into canonical events."""

    source_tool: ClassVar[str] = "plaso"

    def map(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(
                self._combined_timestamp(data),
                assume_timezone=_nullable(data.get("timezone")),
            )
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        type_value = (data.get("type") or "").strip()
        timestamp_desc, action = _TYPE_MAP.get(type_value, (_FALLBACK_DESC, _FALLBACK_ACTION))

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc=timestamp_desc,
                message=self._message(data),
                action=action,
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=_l2t_value(data.get("host")),
                principal=_l2t_value(data.get("user")),
                object=_l2t_value(data.get("filename")),
                details=self._details(data),
                confidence=1.0,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc

    @staticmethod
    def _combined_timestamp(data: Mapping[str, str]) -> str:
        """Join the l2tcsv date and time columns into one parseable string."""
        date = (data.get("date") or "").strip()
        time = (data.get("time") or "").strip()
        combined = f"{date} {time}".strip()
        if not combined:
            raise TimestampError("timestamp is empty")
        return combined

    @staticmethod
    def _message(data: Mapping[str, str]) -> str:
        desc = _nullable(data.get("desc"))
        if desc is not None:
            return desc
        short = _nullable(data.get("short"))
        if short is not None:
            return short
        type_value = _nullable(data.get("type")) or "event"
        source = _nullable(data.get("source")) or "plaso"
        return f"{source} {type_value}"

    @staticmethod
    def _details(data: Mapping[str, str]) -> dict[str, Any]:
        details: dict[str, Any] = {}
        for key in ("MACB", "source", "sourcetype", "type", "inode", "format", "notes"):
            value = _nullable(data.get(key))
            if value is not None:
                details[key] = value
        extra = parse_extra(data.get("extra", ""))
        if extra:
            details["extra"] = extra
        return details
