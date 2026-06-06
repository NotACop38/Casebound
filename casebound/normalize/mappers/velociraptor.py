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
    through the shared ``winevent`` table reading the relevant EventData keys. An
    EventID the table does not cover still produces an event (a generic ``other``
    action at reduced confidence) rather than being dropped (FR8).
  - ``message`` is the row ``Message`` when present, otherwise a short summary.
  - ``details`` preserves the EventID, channel, the VQL artifact name, and the
    EventData key/value pairs.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

The EventID to canonical-field rule lives in ``winevent`` so the optional Dissect
raw-mode EVTX adapter maps the same events identically.

Velociraptor timelines carry no native ATT&CK tags, so ``attack_techniques`` is
left for the deterministic mapping-table step (FR14) to fill from the canonical
action and object.

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


def _event_data(data: Mapping[str, str]) -> dict[str, str]:
    return {
        key[len(VELOCIRAPTOR_EVENTDATA_PREFIX) :]: value
        for key, value in data.items()
        if key.startswith(VELOCIRAPTOR_EVENTDATA_PREFIX)
    }


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
        win_event_id = coerce_event_id(data.get(VELOCIRAPTOR_KEY_EVENTID, ""))
        fields = _event_data(data)
        mapping = mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else FALLBACK_ACTION
        confidence = MAPPED_CONFIDENCE if mapping is not None else FALLBACK_CONFIDENCE
        principal = derive_principal(fields, mapping)
        obj = derive_object(fields, mapping)
        host = nullable(data.get(VELOCIRAPTOR_KEY_COMPUTER))

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
    def _message(
        data: Mapping[str, str], channel: str, win_event_id: int | str, host: str | None
    ) -> str:
        message = nullable(data.get(VELOCIRAPTOR_KEY_MESSAGE))
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
        artifact = nullable(data.get(VELOCIRAPTOR_KEY_ARTIFACT))
        if artifact is not None:
            details["vql_artifact"] = artifact
        return details
