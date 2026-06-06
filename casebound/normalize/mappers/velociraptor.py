"""Map Velociraptor JSONL rows to canonical events (PRD FR6).

Velociraptor collects evidence with VQL and exports each artifact's results as
JSONL (one JSON object per line). The column set is defined by the VQL, so this
mapper targets the common Windows event-log shape produced by the
``Windows.EventLogs.Evtx`` family: each row carries a ``Timestamp`` (RFC3339), a
``Computer``, a ``Channel``, an ``EventID``, an optional ``Message``, the VQL
``Artifact`` name, and an ``EventData`` object of event-specific fields. See
https://docs.velociraptor.app.

The Velociraptor adapter flattens that row (lifting each ``EventData`` field under
a reserved prefix) and this mapper derives the canonical fields:

  - ``datetime`` and ``source_timezone`` come from the row timestamp via the
    timezone normalizer (FR9); Velociraptor emits RFC3339 UTC.
  - ``action``, ``principal``, and ``object`` follow from the Windows EventID
    through a small documented table reading the relevant EventData keys. An
    EventID the table does not cover still produces an event (a generic ``other``
    action at reduced confidence) rather than being dropped (FR8).
  - ``message`` is the row ``Message`` when present, otherwise a short summary.
  - ``details`` preserves the EventID, channel, the VQL artifact name, and the
    EventData key/value pairs.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

Velociraptor timelines carry no native ATT&CK tags, so ``attack_techniques`` is
left for the deterministic mapping-table step (FR14) to fill from the canonical
action and object.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

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
    "VELOCIRAPTOR_EVENTDATA_PREFIX",
    "VELOCIRAPTOR_KEY_ARTIFACT",
    "VELOCIRAPTOR_KEY_CHANNEL",
    "VELOCIRAPTOR_KEY_COMPUTER",
    "VELOCIRAPTOR_KEY_EVENTID",
    "VELOCIRAPTOR_KEY_MESSAGE",
    "VELOCIRAPTOR_KEY_TIMESTAMP",
    "VelociraptorMapper",
    "WinEventMapping",
]

# The keys the Velociraptor adapter writes the flattened row under. The scalar
# columns keep their natural Velociraptor names; each EventData field is lifted
# under the reserved prefix so the mapper can rebuild the EventData object. The
# adapter imports these so producer and consumer agree.
VELOCIRAPTOR_KEY_TIMESTAMP = "Timestamp"
VELOCIRAPTOR_KEY_COMPUTER = "Computer"
VELOCIRAPTOR_KEY_CHANNEL = "Channel"
VELOCIRAPTOR_KEY_EVENTID = "EventID"
VELOCIRAPTOR_KEY_MESSAGE = "Message"
VELOCIRAPTOR_KEY_ARTIFACT = "Artifact"
VELOCIRAPTOR_EVENTDATA_PREFIX = "_vr_data:"

_FALLBACK_ACTION = "other"
_MAPPED_CONFIDENCE = 1.0
_FALLBACK_CONFIDENCE = 0.5


@dataclass(frozen=True)
class WinEventMapping:
    """How one Windows EventID becomes canonical fields, from EventData."""

    action: str
    object_keys: tuple[str, ...] = ()
    principal_user_key: str | None = None
    principal_domain_key: str | None = None
    network_endpoint: bool = False


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


def _nullable(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _event_data(data: Mapping[str, str]) -> dict[str, str]:
    return {
        key[len(VELOCIRAPTOR_EVENTDATA_PREFIX) :]: value
        for key, value in data.items()
        if key.startswith(VELOCIRAPTOR_EVENTDATA_PREFIX)
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


class VelociraptorMapper(Mapper):
    """Map Velociraptor JSONL event-log rows into canonical events."""

    source_tool: ClassVar[str] = "velociraptor"

    def map(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(data.get(VELOCIRAPTOR_KEY_TIMESTAMP, ""))
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        channel = (data.get(VELOCIRAPTOR_KEY_CHANNEL) or "").strip()
        win_event_id = _coerce_event_id(data.get(VELOCIRAPTOR_KEY_EVENTID, ""))
        fields = _event_data(data)
        mapping = self._mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else _FALLBACK_ACTION
        confidence = _MAPPED_CONFIDENCE if mapping is not None else _FALLBACK_CONFIDENCE
        principal = _principal(fields, mapping) if mapping is not None else None
        obj = _object(fields, mapping) if mapping is not None else None
        host = _nullable(data.get(VELOCIRAPTOR_KEY_COMPUTER))

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
        message = _nullable(data.get(VELOCIRAPTOR_KEY_MESSAGE))
        if message is not None:
            return message
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
        artifact = _nullable(data.get(VELOCIRAPTOR_KEY_ARTIFACT))
        if artifact is not None:
            details["vql_artifact"] = artifact
        return details
