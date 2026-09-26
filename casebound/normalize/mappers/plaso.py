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
  - A logged Windows event (an ``Event Logged`` row read from an ``.evtx`` file)
    takes its action from the shared Windows EventID tables, keyed by the channel
    the file holds and the ``event_identifier`` in ``extra``, so a System 7045 is a
    ``service_install`` whatever tool parsed it. Its object is left empty rather
    than set to the log file, which is where the record was stored, not what it
    is about; the log path is kept in ``details``.
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
from casebound.normalize.mappers.winevent import coerce_event_id, mapping_for
from casebound.normalize.schema import Event
from casebound.normalize.timezone import TimestampError, normalize_timestamp

if TYPE_CHECKING:
    # Annotation-only: keeps normalize free of a runtime dependency on ingest.
    from casebound.ingest.base import RawRecord

__all__ = ["PlasoMapper", "evtx_channel", "parse_extra"]

# How a Plaso ``type`` string becomes a canonical (timestamp_desc, action) pair.
# Focused on the common file-system and log types; an unlisted type falls back to
# the generic descriptor and action so the row still becomes an event.
_TYPE_MAP: dict[str, tuple[str, str]] = {
    "Creation Time": ("created", "file_create"),
    "Content Modification Time": ("modified", "file_write"),
    "Last Access Time": ("accessed", "file_read"),
    "Metadata Modification Time": ("other", "file_metadata_change"),
    "Last Time Executed": ("other", "process_create"),
    # A logged record's meaning lives in the record, not in its timestamp type:
    # EVTX records are resolved through the EventID tables, anything else is other.
    "Event Logged": ("logged", "other"),
    "Creation": ("created", "file_create"),
    "Last Written": ("modified", "registry_set"),
}
_FALLBACK_DESC = "other"
_FALLBACK_ACTION = "other"

_EVTX_SUFFIX = ".evtx"


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


def evtx_channel(filename: str | None) -> str | None:
    """The event-log channel an ``.evtx`` file holds, or None for any other file.

    Windows names a channel's log file after the channel with ``/`` escaped as
    ``%4``, so ``Microsoft-Windows-Sysmon%4Operational.evtx`` holds the
    ``Microsoft-Windows-Sysmon/Operational`` channel.
    """
    if not filename:
        return None
    name = filename.replace("\\", "/").rsplit("/", 1)[-1]
    if not name.lower().endswith(_EVTX_SUFFIX):
        return None
    return name[: -len(_EVTX_SUFFIX)].replace("%4", "/") or None


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
        filename = _l2t_value(data.get("filename"))
        extra = parse_extra(data.get("extra", ""))
        details = self._details(data, extra)
        obj = filename
        channel = evtx_channel(filename) if type_value == "Event Logged" else None
        if channel is not None:
            # A logged Windows event: the file is the log that stored it, not its
            # object. Resolve the action from the EventID tables when covered.
            obj = None
            details["filename"] = filename
            event_id = (extra.get("event_identifier") or "").strip()
            mapping = mapping_for(channel, coerce_event_id(event_id)) if event_id else None
            if mapping is not None:
                action = mapping.action

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
                object=obj,
                details=details,
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
    def _details(data: Mapping[str, str], extra: Mapping[str, str]) -> dict[str, Any]:
        details: dict[str, Any] = {}
        for key in ("MACB", "source", "sourcetype", "type", "inode", "format", "notes"):
            value = _nullable(data.get(key))
            if value is not None:
                details[key] = value
        if extra:
            details["extra"] = dict(extra)
        return details
