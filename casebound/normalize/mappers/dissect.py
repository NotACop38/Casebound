"""Map Dissect raw-artifact records to canonical events (PRD Section 5 Raw mode).

The optional raw-mode adapters under ``casebound/ingest/raw`` parse evidence
artifacts directly with Dissect (an EVTX event log, an NTFS ``$MFT``) and emit
provenance-bearing raw records. This mapper turns those records into canonical
events. Crucially, it is pure: it reads only the flattened string fields the
adapters produce and never imports Dissect itself. That is what keeps the
AGPL-licensed Dissect dependency confined to ``casebound/ingest/raw`` while the
normalization of its output stays in the Apache-2.0 core and is fully testable
offline with golden fixtures (see ``tests/test_dissect_raw.py``).

One ``source_tool`` value, ``dissect``, covers every raw artifact. Each record
names which artifact kind it carries under the reserved ``DISSECT_KIND_KEY``, and
this mapper dispatches accordingly:

  - ``evtx``: a Windows event-log record. ``action``, ``principal``, and
    ``object`` follow from the EventID through the shared ``winevent`` table, so a
    Dissect-parsed EVTX maps identically to the same event seen through
    Velociraptor. An uncovered EventID still maps at reduced confidence (FR8).
  - ``mft``: one Standard Information timestamp of an NTFS file record. The
    descriptor (created, modified, accessed, or a record change) drives the
    ``action`` verb, and the object is the file's full path, mirroring the Eric
    Zimmerman ``$MFT`` mapper.

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
    "DISSECT_EVTX_CHANNEL_KEY",
    "DISSECT_EVTX_COMPUTER_KEY",
    "DISSECT_EVTX_EVENTDATA_PREFIX",
    "DISSECT_EVTX_EVENTID_KEY",
    "DISSECT_EVTX_PROVIDER_KEY",
    "DISSECT_EVTX_TIMESTAMP_KEY",
    "DISSECT_KIND_EVTX",
    "DISSECT_KIND_KEY",
    "DISSECT_KIND_MFT",
    "DISSECT_MFT_FILENAME_KEY",
    "DISSECT_MFT_ISDIR_KEY",
    "DISSECT_MFT_PATH_KEY",
    "DISSECT_MFT_SEGMENT_KEY",
    "DISSECT_MFT_SEQUENCE_KEY",
    "DISSECT_MFT_SIZE_KEY",
    "DISSECT_MFT_TIMESTAMP_DESC_KEY",
    "DISSECT_MFT_TIMESTAMP_KEY",
    "DissectMapper",
]

# The reserved key naming the artifact kind a raw record carries, and its values.
# Namespaced so they cannot collide with a real artifact field. The adapters write
# these and this mapper reads them, so producer and consumer agree on one spelling
# (ingest may depend on normalize; the reverse is avoided).
DISSECT_KIND_KEY = "_dissect_kind"
DISSECT_KIND_EVTX = "evtx"
DISSECT_KIND_MFT = "mft"

# EVTX scalar keys, kept under their natural Windows names; the EventData fields
# are lifted under the reserved prefix so the mapper can rebuild them and so an
# EventData field that happens to share a System name cannot shadow it.
DISSECT_EVTX_TIMESTAMP_KEY = "Timestamp"
DISSECT_EVTX_COMPUTER_KEY = "Computer"
DISSECT_EVTX_CHANNEL_KEY = "Channel"
DISSECT_EVTX_EVENTID_KEY = "EventID"
DISSECT_EVTX_PROVIDER_KEY = "Provider"
DISSECT_EVTX_EVENTDATA_PREFIX = "_dissect_evtx_data:"

# MFT keys: the chosen Standard Information timestamp string and its canonical
# descriptor, plus the file-identity columns the mapper preserves in details.
DISSECT_MFT_TIMESTAMP_KEY = "_dissect_mft_timestamp"
DISSECT_MFT_TIMESTAMP_DESC_KEY = "_dissect_mft_timestamp_desc"
DISSECT_MFT_SEGMENT_KEY = "Segment"
DISSECT_MFT_SEQUENCE_KEY = "SequenceNumber"
DISSECT_MFT_PATH_KEY = "Path"
DISSECT_MFT_FILENAME_KEY = "FileName"
DISSECT_MFT_ISDIR_KEY = "IsDirectory"
DISSECT_MFT_SIZE_KEY = "FileSize"

# NTFS records normalize to UTC, so a Standard Information time is interpreted and
# labeled as UTC rather than flagged assumed_utc.
_MFT_SOURCE_TIMEZONE = "UTC"

# How a Standard Information timestamp descriptor becomes a canonical action verb,
# mirroring the Eric Zimmerman ``$MFT`` mapper so the two raw and tool-output MFT
# paths agree.
_MFT_DESC_ACTIONS: dict[str, str] = {
    "created": "file_create",
    "modified": "file_write",
    "accessed": "file_read",
    "other": "file_metadata_change",
}
_MFT_FALLBACK_ACTION = "file_metadata_change"


class DissectMapper(Mapper):
    """Map Dissect raw-artifact records into canonical events, dispatched by kind."""

    source_tool: ClassVar[str] = "dissect"

    def map(self, record: RawRecord) -> Event:
        kind = (record.data.get(DISSECT_KIND_KEY) or "").strip()
        if kind == DISSECT_KIND_EVTX:
            return self._map_evtx(record)
        if kind == DISSECT_KIND_MFT:
            return self._map_mft(record)
        raise MappingError(
            f"dissect record has unknown or missing artifact kind {kind!r}; "
            f"expected one of {DISSECT_KIND_EVTX!r} or {DISSECT_KIND_MFT!r}"
        )

    # EVTX: a Windows event-log record, mapped through the shared winevent table.

    def _map_evtx(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(data.get(DISSECT_EVTX_TIMESTAMP_KEY, ""))
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        channel = (data.get(DISSECT_EVTX_CHANNEL_KEY) or "").strip()
        win_event_id = coerce_event_id(data.get(DISSECT_EVTX_EVENTID_KEY, ""))
        fields = self._event_data(data)
        mapping = mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else FALLBACK_ACTION
        confidence = MAPPED_CONFIDENCE if mapping is not None else FALLBACK_CONFIDENCE
        principal = derive_principal(fields, mapping) if mapping is not None else None
        obj = derive_object(fields, mapping) if mapping is not None else None
        host = nullable(data.get(DISSECT_EVTX_COMPUTER_KEY))
        provider = nullable(data.get(DISSECT_EVTX_PROVIDER_KEY))

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc="logged",
                message=self._evtx_message(provider, channel, win_event_id, host),
                action=action,
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=host,
                principal=principal,
                object=obj,
                details=self._evtx_details(channel, win_event_id, provider, fields),
                confidence=confidence,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc

    @staticmethod
    def _event_data(data: Mapping[str, str]) -> dict[str, str]:
        return {
            key[len(DISSECT_EVTX_EVENTDATA_PREFIX) :]: value
            for key, value in data.items()
            if key.startswith(DISSECT_EVTX_EVENTDATA_PREFIX)
        }

    @staticmethod
    def _evtx_message(
        provider: str | None, channel: str, win_event_id: int | str, host: str | None
    ) -> str:
        where = host or channel or "unknown host"
        source = provider or channel or "Windows"
        return f"{source} event {win_event_id} on {where}"

    @staticmethod
    def _evtx_details(
        channel: str,
        win_event_id: int | str,
        provider: str | None,
        fields: Mapping[str, str],
    ) -> dict[str, Any]:
        details: dict[str, Any] = {
            "win_event_id": win_event_id,
            "channel": channel,
            "fields": dict(fields),
        }
        if provider is not None:
            details["provider"] = provider
        return details

    # MFT: one Standard Information timestamp of an NTFS file record.

    def _map_mft(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(
                data.get(DISSECT_MFT_TIMESTAMP_KEY, ""), assume_timezone=_MFT_SOURCE_TIMEZONE
            )
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        desc = (data.get(DISSECT_MFT_TIMESTAMP_DESC_KEY) or "other").strip() or "other"
        action = _MFT_DESC_ACTIONS.get(desc, _MFT_FALLBACK_ACTION)
        path = nullable(data.get(DISSECT_MFT_PATH_KEY))

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc=desc,
                message=self._mft_message(desc, path),
                action=action,
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=None,
                principal=None,
                object=path,
                details=self._mft_details(data),
                confidence=MAPPED_CONFIDENCE,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc

    @staticmethod
    def _mft_message(desc: str, path: str | None) -> str:
        where = path if path is not None else "unknown path"
        return f"MFT standard information {desc} timestamp for {where}"

    @staticmethod
    def _mft_details(data: Mapping[str, str]) -> dict[str, Any]:
        details: dict[str, Any] = {"artifact": "$MFT"}
        for key in (
            DISSECT_MFT_SEGMENT_KEY,
            DISSECT_MFT_SEQUENCE_KEY,
            DISSECT_MFT_FILENAME_KEY,
            DISSECT_MFT_ISDIR_KEY,
            DISSECT_MFT_SIZE_KEY,
        ):
            value = nullable(data.get(key))
            if value is not None:
                details[key] = value
        return details
