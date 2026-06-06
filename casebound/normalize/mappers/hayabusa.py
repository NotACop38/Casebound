"""Map Hayabusa csv-timeline rows to canonical events (PRD FR2, FR8 to FR11).

Hayabusa rows describe Windows event-log records. This mapper reads the columns
the Hayabusa adapter emits and derives the canonical fields:

  - ``datetime`` and ``source_timezone`` come from the Timestamp column via the
    timezone normalizer (FR9); ``timestamp_raw`` keeps the original string.
  - ``action``, ``principal``, and ``object`` are derived from the Windows channel
    and event id through the shared ``winevent`` table, reading the relevant keys
    out of the Details field. An event id the table does not cover still produces
    an event (a generic ``other`` action at reduced confidence) rather than being
    dropped, so the timeline stays complete (FR8).
  - ``message`` is the Hayabusa rule title, the most human-readable summary on the
    row.
  - ``details`` preserves the source specifics: the Windows event id, channel,
    level, rule title, the parsed Details key/value pairs, and the raw MITRE
    tactic and rule-tag strings. The raw rule tags are kept here, not promoted to
    ``attack_techniques``, because deterministic ATT&CK tagging is a later step;
    this step does not decide techniques.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

The EventID to canonical-field rule lives in ``winevent`` so every Windows
event-log source (Hayabusa, Chainsaw, Velociraptor, the Dissect raw EVTX adapter)
maps the same events identically. The ``event_id`` is then derived by ``Event``
from the core fields, so identical observations collapse to one id and the
normalize pipeline can de-duplicate them while keeping every provenance pointer
(FR10, FR12).

Input assumption: the Detail keys are expected in their unabbreviated Windows
form (``SubjectUserName``, ``TargetUserName``, ``DestinationIp``, and so on), which
is what the synthetic generator emits and what Hayabusa produces with
``--disable-abbreviations``. Hayabusa abbreviates field names by default, so until
an abbreviation-normalization pass lands, evidence from a default Hayabusa run
should be generated with abbreviations disabled or the principal and object may be
incomplete. Handling the default abbreviations is a Phase 3 breadth follow-up.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
from casebound.normalize.mappers.winevent import (
    FALLBACK_ACTION,
    FALLBACK_CONFIDENCE,
    MAPPED_CONFIDENCE,
    WinEventMapping,
    coerce_event_id,
    derive_object,
    derive_principal,
    mapping_for,
    nullable,
)
from casebound.normalize.schema import Event
from casebound.normalize.timezone import TimestampError, normalize_timestamp

if TYPE_CHECKING:
    # Annotation-only: keeps normalize free of a runtime dependency on ingest.
    from casebound.ingest.base import RawRecord

__all__ = ["HayabusaMapper", "WinEventMapping", "parse_details"]

# Hayabusa's multi-value separator is a space-padded broken bar (U+00A6). Splitting
# on the bar itself and stripping is robust to the exact spacing a profile uses.
_FIELD_SEP = "¦"

# How a row whose timestamp has no offset is labeled by default: the Hayabusa
# csv-timeline profile prints an explicit offset, so None means trust that offset.
# A caller can pass an IANA zone to relabel instead (see normalize_timestamp).
_DEFAULT_ASSUME_TZ: str | None = None


def parse_details(raw: str) -> dict[str, str]:
    """Parse a Hayabusa Details cell into an ordered key/value mapping.

    The cell joins ``Key: Value`` pairs with the broken-bar separator. Each pair is
    split on its first colon, so a value that itself contains a colon (a Windows
    path such as ``C:\\Windows``) is preserved intact. A fragment with no colon is
    skipped rather than guessed at.
    """
    fields: dict[str, str] = {}
    for fragment in raw.split(_FIELD_SEP):
        key, sep, value = fragment.partition(":")
        if not sep:
            continue
        name = key.strip()
        if name:
            fields[name] = value.strip()
    return fields


def _split_multi(raw: str) -> list[str]:
    """Split a Hayabusa multi-value cell into its non-empty, stripped values."""
    return [piece.strip() for piece in raw.split(_FIELD_SEP) if piece.strip()]


class HayabusaMapper(Mapper):
    """Map Hayabusa csv-timeline records into canonical events."""

    source_tool: ClassVar[str] = "hayabusa"

    def __init__(self, assume_timezone: str | None = _DEFAULT_ASSUME_TZ) -> None:
        # An optional IANA zone label for the source host. It only labels the
        # source_timezone; the offset printed in each Timestamp fixes the instant.
        self._assume_timezone = assume_timezone

    def map(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(
                data.get("Timestamp", ""), assume_timezone=self._assume_timezone
            )
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        channel = (data.get("Channel") or "").strip()
        win_event_id = coerce_event_id(data.get("EventID", ""))
        fields = parse_details(data.get("Details", ""))
        mapping = mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else FALLBACK_ACTION
        confidence = MAPPED_CONFIDENCE if mapping is not None else FALLBACK_CONFIDENCE
        host = nullable(data.get("Computer"))
        message = self._message(data, channel, win_event_id, host)

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc="logged",
                message=message,
                action=action,
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=host,
                principal=derive_principal(fields, mapping),
                object=derive_object(fields, mapping),
                details=self._details(data, channel, win_event_id, fields),
                confidence=confidence,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc

    @staticmethod
    def _message(
        data: Mapping[str, str], channel: str, win_event_id: int | str, host: str | None
    ) -> str:
        title = nullable(data.get("RuleTitle"))
        if title is not None:
            return title
        where = host or channel or "unknown host"
        return f"{channel or 'Windows'} event {win_event_id} on {where}"

    @staticmethod
    def _details(
        data: Mapping[str, str],
        channel: str,
        win_event_id: int | str,
        fields: Mapping[str, str],
    ) -> dict[str, Any]:
        details: dict[str, Any] = {
            "win_event_id": win_event_id,
            "channel": channel,
            "fields": dict(fields),
        }
        level = nullable(data.get("Level"))
        if level is not None:
            details["level"] = level
        rule_title = nullable(data.get("RuleTitle"))
        if rule_title is not None:
            details["rule_title"] = rule_title
        tactics = _split_multi(data.get("MitreTactics", ""))
        if tactics:
            details["mitre_tactics"] = tactics
        # Raw rule tags are preserved for the later ATT&CK step; this step does not
        # promote them to attack_techniques.
        rule_tags = _split_multi(data.get("MitreTags", ""))
        if rule_tags:
            details["rule_mitre_tags"] = rule_tags
        return details
