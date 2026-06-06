"""Map Chainsaw detections to canonical events (PRD FR5).

Chainsaw (WithSecure) hunts Windows event logs with Sigma and its own rules and
emits matched detections. Run with ``--json`` it produces an array of detection
objects, each wrapping the source event under ``document.data.Event`` (a ``System``
block with the timestamp, EventID, Channel, and Computer, and an ``EventData``
block with the event-specific fields). See
https://github.com/WithSecureLabs/chainsaw.

The Chainsaw adapter flattens that nested structure and writes the fields this
mapper needs under reserved keys; this mapper derives the canonical fields:

  - ``datetime`` and ``source_timezone`` come from the detection timestamp via the
    timezone normalizer (FR9); Chainsaw emits RFC3339 UTC.
  - ``action``, ``principal``, and ``object`` follow from the Windows EventID
    through the shared ``winevent`` table reading the relevant EventData keys. An
    EventID the table does not cover still produces an event (a generic ``other``
    action at reduced confidence) rather than being dropped (FR8).
  - ``message`` is the Chainsaw rule name, the most human-readable summary.
  - ``details`` preserves the EventID, channel, level, rule name, the EventData
    key/value pairs, and the raw detection tags. Sigma rule tags of the form
    ``attack.t1059.001`` are normalized to ``T1059.001`` and stashed under
    ``rule_mitre_tags`` so the later deterministic ATT&CK step promotes them, the
    same passthrough contract the Hayabusa mapper uses; this step does not decide
    techniques.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

The EventID to canonical-field rule lives in ``winevent`` so every Windows
event-log source (Chainsaw, Velociraptor, the Dissect raw EVTX adapter) maps the
same events identically.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
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

__all__ = [
    "CHAINSAW_DATA_PREFIX",
    "CHAINSAW_KEY_CHANNEL",
    "CHAINSAW_KEY_COMPUTER",
    "CHAINSAW_KEY_EVENTID",
    "CHAINSAW_KEY_LEVEL",
    "CHAINSAW_KEY_NAME",
    "CHAINSAW_KEY_TAGS",
    "CHAINSAW_KEY_TIMESTAMP",
    "ChainsawMapper",
    "WinEventMapping",
    "normalize_attack_tag",
]

# The reserved keys the Chainsaw adapter writes the flattened detection under, plus
# the prefix for each EventData field. Namespaced so they cannot collide with a
# real EventData key. The adapter imports these so producer and consumer agree.
CHAINSAW_KEY_TIMESTAMP = "_cs_timestamp"
CHAINSAW_KEY_NAME = "_cs_name"
CHAINSAW_KEY_EVENTID = "_cs_eventid"
CHAINSAW_KEY_CHANNEL = "_cs_channel"
CHAINSAW_KEY_COMPUTER = "_cs_computer"
CHAINSAW_KEY_LEVEL = "_cs_level"
CHAINSAW_KEY_TAGS = "_cs_tags"
CHAINSAW_DATA_PREFIX = "_cs_data:"

# The Chainsaw tags multi-value separator the adapter joins on.
CHAINSAW_TAG_SEP = "¦"

# A Sigma ATT&CK tag such as "attack.t1059.001" or "attack.t1003"; the technique id
# is captured and uppercased to the canonical "T1059.001" form.
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


def normalize_attack_tag(tag: str) -> str | None:
    """Return the canonical technique id for a Sigma ATT&CK tag, or None.

    ``attack.t1059.001`` becomes ``T1059.001``; a tag that is not an ATT&CK
    technique tag (for example ``attack.execution``) returns None so only real
    technique ids are promoted.
    """
    match = _ATTACK_TAG_RE.match(tag.strip())
    return match.group(1).upper() if match else None


def _event_data(data: Mapping[str, str]) -> dict[str, str]:
    """Pull the EventData key/value pairs back out of the reserved-prefixed keys."""
    return {
        key[len(CHAINSAW_DATA_PREFIX) :]: value
        for key, value in data.items()
        if key.startswith(CHAINSAW_DATA_PREFIX)
    }


class ChainsawMapper(Mapper):
    """Map Chainsaw JSON detections into canonical events."""

    source_tool: ClassVar[str] = "chainsaw"

    def map(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(data.get(CHAINSAW_KEY_TIMESTAMP, ""))
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        channel = (data.get(CHAINSAW_KEY_CHANNEL) or "").strip()
        win_event_id = coerce_event_id(data.get(CHAINSAW_KEY_EVENTID, ""))
        fields = _event_data(data)
        mapping = mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else FALLBACK_ACTION
        confidence = MAPPED_CONFIDENCE if mapping is not None else FALLBACK_CONFIDENCE
        host = nullable(data.get(CHAINSAW_KEY_COMPUTER))

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc="logged",
                message=self._message(data, channel, win_event_id, host),
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
        name = nullable(data.get(CHAINSAW_KEY_NAME))
        if name is not None:
            return name
        where = host or channel or "unknown host"
        return f"Chainsaw detection on {channel or 'Windows'} event {win_event_id} on {where}"

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
        level = nullable(data.get(CHAINSAW_KEY_LEVEL))
        if level is not None:
            details["level"] = level
        name = nullable(data.get(CHAINSAW_KEY_NAME))
        if name is not None:
            details["rule_name"] = name
        raw_tags = [
            tag.strip()
            for tag in (data.get(CHAINSAW_KEY_TAGS) or "").split(CHAINSAW_TAG_SEP)
            if tag.strip()
        ]
        if raw_tags:
            details["rule_tags"] = raw_tags
        # Normalize Sigma ATT&CK tags to canonical ids for the later tagging step.
        technique_ids: list[str] = []
        for tag in raw_tags:
            tid = normalize_attack_tag(tag)
            if tid is not None and tid not in technique_ids:
                technique_ids.append(tid)
        if technique_ids:
            details["rule_mitre_tags"] = technique_ids
        return details
