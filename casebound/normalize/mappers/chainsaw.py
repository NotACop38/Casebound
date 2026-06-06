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
    through a small documented table, reading the relevant EventData keys. An
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

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
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

_FALLBACK_ACTION = "other"
_MAPPED_CONFIDENCE = 1.0
_FALLBACK_CONFIDENCE = 0.5

# A Sigma ATT&CK tag such as "attack.t1059.001" or "attack.t1003"; the technique id
# is captured and uppercased to the canonical "T1059.001" form.
_ATTACK_TAG_RE = re.compile(r"^attack\.(t\d{4}(?:\.\d{3})?)$", re.IGNORECASE)


@dataclass(frozen=True)
class WinEventMapping:
    """How one Windows EventID becomes canonical fields, from Chainsaw EventData."""

    action: str
    object_keys: tuple[str, ...] = ()
    principal_user_key: str | None = None
    principal_domain_key: str | None = None
    network_endpoint: bool = False


# The classic Security/System channels keyed by EventID, and the Sysmon channel
# kept separate because its small EventIDs would collide. Focused on the showcase
# scenario; new ids are added here as sources need them.
_WINDOWS_EVENTS: dict[int, WinEventMapping] = {
    4624: WinEventMapping(
        action="logon",
        object_keys=("IpAddress",),
        principal_user_key="TargetUserName",
        principal_domain_key="TargetDomainName",
    ),
    4688: WinEventMapping(
        action="process_create",
        object_keys=("NewProcessName",),
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    ),
    4698: WinEventMapping(
        action="scheduled_task_create",
        object_keys=("TaskName",),
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    ),
    7045: WinEventMapping(action="service_install", object_keys=("ServiceName",)),
}

_SYSMON_EVENTS: dict[int, WinEventMapping] = {
    1: WinEventMapping(action="process_create", object_keys=("Image",), principal_user_key="User"),
    3: WinEventMapping(action="network_connect", network_endpoint=True, principal_user_key="User"),
    10: WinEventMapping(action="process_access", object_keys=("TargetImage",)),
    11: WinEventMapping(action="file_create", object_keys=("TargetFilename",)),
    13: WinEventMapping(action="registry_set", object_keys=("TargetObject",)),
}


def normalize_attack_tag(tag: str) -> str | None:
    """Return the canonical technique id for a Sigma ATT&CK tag, or None.

    ``attack.t1059.001`` becomes ``T1059.001``; a tag that is not an ATT&CK
    technique tag (for example ``attack.execution``) returns None so only real
    technique ids are promoted.
    """
    match = _ATTACK_TAG_RE.match(tag.strip())
    return match.group(1).upper() if match else None


def _nullable(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _event_data(data: Mapping[str, str]) -> dict[str, str]:
    """Pull the EventData key/value pairs back out of the reserved-prefixed keys."""
    return {
        key[len(CHAINSAW_DATA_PREFIX) :]: value
        for key, value in data.items()
        if key.startswith(CHAINSAW_DATA_PREFIX)
    }


def _principal(fields: Mapping[str, str], mapping: WinEventMapping) -> str | None:
    if mapping.principal_user_key is None:
        return None
    user = _nullable(fields.get(mapping.principal_user_key))
    if user is None:
        return None
    domain = (
        _nullable(fields.get(mapping.principal_domain_key))
        if mapping.principal_domain_key is not None
        else None
    )
    return f"{domain}\\{user}" if domain is not None else user


def _object(fields: Mapping[str, str], mapping: WinEventMapping) -> str | None:
    if mapping.network_endpoint:
        target = _nullable(fields.get("DestinationIp")) or _nullable(
            fields.get("DestinationHostname")
        )
        if target is None:
            return None
        port = _nullable(fields.get("DestinationPort"))
        return f"{target}:{port}" if port is not None else target
    for key in mapping.object_keys:
        value = _nullable(fields.get(key))
        if value is not None:
            return value
    return None


def _coerce_event_id(raw: str) -> int | str:
    text = raw.strip()
    try:
        return int(text)
    except ValueError:
        return text


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
        win_event_id = _coerce_event_id(data.get(CHAINSAW_KEY_EVENTID, ""))
        fields = _event_data(data)
        mapping = self._mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else _FALLBACK_ACTION
        confidence = _MAPPED_CONFIDENCE if mapping is not None else _FALLBACK_CONFIDENCE
        principal = _principal(fields, mapping) if mapping is not None else None
        obj = _object(fields, mapping) if mapping is not None else None
        host = _nullable(data.get(CHAINSAW_KEY_COMPUTER))

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
                principal=principal,
                object=obj,
                details=self._details(data, channel, win_event_id, fields),
                confidence=confidence,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc

    @staticmethod
    def _mapping_for(channel: str, win_event_id: int | str) -> WinEventMapping | None:
        if not isinstance(win_event_id, int):
            return None
        table = _SYSMON_EVENTS if "Sysmon" in channel else _WINDOWS_EVENTS
        return table.get(win_event_id)

    @staticmethod
    def _message(
        data: Mapping[str, str], channel: str, win_event_id: int | str, host: str | None
    ) -> str:
        name = _nullable(data.get(CHAINSAW_KEY_NAME))
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
        level = _nullable(data.get(CHAINSAW_KEY_LEVEL))
        if level is not None:
            details["level"] = level
        name = _nullable(data.get(CHAINSAW_KEY_NAME))
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
