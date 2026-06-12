"""Timestamp normalization to UTC with source-timezone tracking (FR9).

Source timelines spell time in whatever zone the collecting host used. The
canonical schema stores one UTC instant per event (``datetime``) while keeping the
original string (``timestamp_raw``) and a record of the zone that produced the
instant (``source_timezone``), so an analyst can always trace a normalized time
back to what the evidence actually said.

This module owns that conversion. Given a raw timestamp string it returns the UTC
instant in the canonical ISO 8601 shape the schema expects, the original string
untouched, and a ``source_timezone`` label:

  - when the string carries an explicit UTC offset, the offset is authoritative
    for the instant and the label records it (``UTC``, or ``UTC-04:00``); a caller
    that knows the real IANA zone can pass ``assume_timezone`` to record that name
    instead, which is purely a label and never changes the instant;
  - when the string has no offset and ``assume_timezone`` is given, the instant is
    derived by interpreting the string in that IANA zone and the label is the zone
    name;
  - when the string has no offset and no zone is known, the instant is read as UTC
    and the label is the literal ``assumed_utc`` so the assumption is visible.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from dateutil import parser as date_parser

__all__ = ["NormalizedTimestamp", "format_utc_offset", "normalize_timestamp"]

# The label recorded when no zone is known and UTC had to be assumed.
ASSUMED_UTC = "assumed_utc"

# dateutil fills any date component the string omits from its ``default``
# argument, which defaults to the moment of the run: a time-only or fragment
# string ("08:42:17", "March", a stray numeric cell) would be silently stamped
# with today's date, fabricating an instant and making the content-derived
# event ids differ between runs. Parsing against two sentinels that differ in
# year, month, and day exposes any filled-in component: when the two results
# disagree, the string did not pin its own date and is rejected. Both sentinels
# carry a zero time so a date-only string still resolves (to midnight) the same
# way under both, deterministically.
_DEFAULT_A = datetime(2001, 1, 1)
_DEFAULT_B = datetime(2002, 2, 2)


class TimestampError(ValueError):
    """Raised when a raw timestamp string cannot be parsed into an instant."""


@dataclass(frozen=True)
class NormalizedTimestamp:
    """The result of normalizing one raw timestamp.

    ``datetime_utc`` is the instant in canonical ISO 8601 UTC (trailing ``Z``),
    ready to hand to ``Event``. ``timestamp_raw`` is the original string verbatim.
    ``source_timezone`` records the zone used to derive the instant.
    """

    datetime_utc: str
    timestamp_raw: str
    source_timezone: str


def format_utc_offset(offset: timedelta) -> str:
    """Render a UTC offset as a stable label: ``UTC``, ``UTC-04:00``, ``UTC+05:30``."""
    total_minutes = round(offset.total_seconds() / 60)
    if total_minutes == 0:
        return "UTC"
    sign = "+" if total_minutes > 0 else "-"
    magnitude = abs(total_minutes)
    return f"UTC{sign}{magnitude // 60:02d}:{magnitude % 60:02d}"


def _resolve_zone(name: str) -> ZoneInfo:
    try:
        return ZoneInfo(name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise TimestampError(f"unknown timezone {name!r}") from exc


def _to_canonical_utc(instant: datetime) -> str:
    """Render an aware datetime as canonical ISO 8601 UTC with a trailing Z.

    Sub-second precision is preserved but trailing zeros are trimmed, matching the
    canonicalization ``Event`` applies, so the two never disagree on the same
    instant.
    """
    utc = instant.astimezone(UTC)
    base = utc.strftime("%Y-%m-%dT%H:%M:%S")
    if utc.microsecond:
        return f"{base}.{utc.microsecond:06d}".rstrip("0") + "Z"
    return f"{base}Z"


def normalize_timestamp(raw: str, *, assume_timezone: str | None = None) -> NormalizedTimestamp:
    """Normalize ``raw`` to a UTC instant, tracking the source timezone (FR9).

    Raises ``TimestampError`` when the string cannot be parsed or when
    ``assume_timezone`` is given but is not a known IANA zone, so the caller can
    report the row as malformed rather than aborting (FR7).
    """
    if not isinstance(raw, str) or not raw.strip():
        raise TimestampError("timestamp is empty")

    try:
        parsed = date_parser.parse(raw, default=_DEFAULT_A)
        check = date_parser.parse(raw, default=_DEFAULT_B)
    except (ValueError, OverflowError, TypeError) as exc:
        raise TimestampError(f"cannot parse timestamp {raw!r}: {exc}") from exc
    if parsed != check:
        raise TimestampError(
            f"timestamp {raw!r} does not carry a complete date; refusing to fill the missing parts"
        )

    if parsed.tzinfo is not None and parsed.utcoffset() is not None:
        # The string fixes the instant via its offset. assume_timezone, if given,
        # only relabels; it never overrides the offset that determines the moment.
        # The hint is still validated so a typo cannot write a bogus zone into the
        # audit metadata of every event.
        offset = parsed.utcoffset() or timedelta(0)
        if assume_timezone:
            _resolve_zone(assume_timezone)
            label = assume_timezone
        else:
            label = format_utc_offset(offset)
        return NormalizedTimestamp(_to_canonical_utc(parsed), raw, label)

    # No offset in the string: interpret it in the assumed zone, or fall back to
    # UTC and flag that we did so.
    if assume_timezone:
        aware = parsed.replace(tzinfo=_resolve_zone(assume_timezone))
        return NormalizedTimestamp(_to_canonical_utc(aware), raw, assume_timezone)
    aware = parsed.replace(tzinfo=UTC)
    return NormalizedTimestamp(_to_canonical_utc(aware), raw, ASSUMED_UTC)
