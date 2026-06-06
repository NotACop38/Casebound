"""The Chainsaw ingest adapter (PRD FR5).

Chainsaw (WithSecure) hunts Windows event logs with Sigma and its own rules. Run
with ``--json`` it writes an array of detection objects. This adapter reads that
array and emits one ``RawRecord`` per detection. Each detection wraps the matched
event under ``document.data.Event``, with a ``System`` block (Provider, EventID,
Channel, Computer, EventRecordID, and the ``TimeCreated`` system time) and an
``EventData`` block of event-specific fields. The detection also carries the rule
``name``, a ``level``, an optional ``timestamp``, optional ``tags`` (Sigma rule
tags such as ``attack.t1059.001``), and a ``document.path`` naming the source
artifact. See https://github.com/WithSecureLabs/chainsaw.

The adapter is a thin reader: it flattens the nested detection into the reserved
keys the Chainsaw mapper reads (timestamp, rule name, EventID, channel, computer,
level, joined tags, and each EventData field under a reserved prefix) and attaches
provenance. It does not interpret the event into the canonical schema; the Chainsaw
mapper does that.

The detection timestamp is taken from the top-level ``timestamp`` when present and
otherwise from ``System.TimeCreated`` (its ``#attributes.SystemTime`` or a plain
string), so a detection is timestamped from the event it matched even when Chainsaw
does not lift the time to the top level. The ``raw_ref.record`` is the
``EventRecordID`` when present and otherwise the 1-based detection index.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.normalize.mappers.chainsaw import (
    CHAINSAW_DATA_PREFIX,
    CHAINSAW_KEY_CHANNEL,
    CHAINSAW_KEY_COMPUTER,
    CHAINSAW_KEY_EVENTID,
    CHAINSAW_KEY_LEVEL,
    CHAINSAW_KEY_NAME,
    CHAINSAW_KEY_TAGS,
    CHAINSAW_KEY_TIMESTAMP,
    CHAINSAW_TAG_SEP,
)
from casebound.normalize.schema import RawRef

__all__ = ["ChainsawAdapter"]

# The placeholder source artifact when a detection names no source path or channel.
_DEFAULT_ARTIFACT = "chainsaw_detection"


def _as_str(value: Any) -> str:
    """Render a scalar JSON value as a string; containers become an empty string."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class ChainsawAdapter(IngestAdapter):
    """Read a Chainsaw ``--json`` detections file into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "chainsaw"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per Chainsaw detection in the JSON at ``source``.

        The file is expected to be a JSON array of detection objects, as
        ``chainsaw hunt ... --json`` produces. A non-array document yields nothing.
        """
        document = json.loads(source.read_text(encoding="utf-8"))
        if not isinstance(document, list):
            return
        for index, detection in enumerate(document, start=1):
            if isinstance(detection, dict):
                yield self._to_record(source, index, detection)

    def _to_record(self, source: Path, index: int, detection: dict[str, Any]) -> RawRecord:
        event = self._event(detection)
        system = event.get("System", {}) if isinstance(event, dict) else {}
        event_data = event.get("EventData", {}) if isinstance(event, dict) else {}
        system = system if isinstance(system, dict) else {}
        event_data = event_data if isinstance(event_data, dict) else {}

        data: dict[str, str] = {
            CHAINSAW_KEY_TIMESTAMP: self._timestamp(detection, system),
            CHAINSAW_KEY_NAME: _as_str(detection.get("name")),
            CHAINSAW_KEY_EVENTID: self._event_id(system),
            CHAINSAW_KEY_CHANNEL: _as_str(system.get("Channel")),
            CHAINSAW_KEY_COMPUTER: _as_str(system.get("Computer")),
            CHAINSAW_KEY_LEVEL: _as_str(detection.get("level")),
            CHAINSAW_KEY_TAGS: self._tags(detection),
        }
        for key, value in event_data.items():
            data[f"{CHAINSAW_DATA_PREFIX}{key}"] = _as_str(value)

        return RawRecord(
            source_tool=self.source_tool,
            source_artifact=self._artifact(detection, system),
            raw_ref=RawRef(source_file=source.name, record=self._record_id(system, index)),
            data=data,
        )

    @staticmethod
    def _event(detection: dict[str, Any]) -> dict[str, Any]:
        document = detection.get("document", {})
        document = document if isinstance(document, dict) else {}
        payload = document.get("data", {})
        payload = payload if isinstance(payload, dict) else {}
        event = payload.get("Event", {})
        return event if isinstance(event, dict) else {}

    @staticmethod
    def _timestamp(detection: dict[str, Any], system: dict[str, Any]) -> str:
        top = detection.get("timestamp")
        if top:
            return _as_str(top)
        time_created = system.get("TimeCreated")
        if isinstance(time_created, dict):
            attributes = time_created.get("#attributes")
            if isinstance(attributes, dict) and attributes.get("SystemTime"):
                return _as_str(attributes.get("SystemTime"))
        return _as_str(time_created)

    @staticmethod
    def _event_id(system: dict[str, Any]) -> str:
        event_id = system.get("EventID")
        # The EventID can be a scalar or, in verbose evtx JSON, an object with the
        # value under "#text"; prefer the latter when present.
        if isinstance(event_id, dict):
            return _as_str(event_id.get("#text"))
        return _as_str(event_id)

    @staticmethod
    def _tags(detection: dict[str, Any]) -> str:
        tags = detection.get("tags")
        if not isinstance(tags, list):
            return ""
        return CHAINSAW_TAG_SEP.join(_as_str(tag) for tag in tags if _as_str(tag))

    @staticmethod
    def _artifact(detection: dict[str, Any], system: dict[str, Any]) -> str:
        document = detection.get("document", {})
        if isinstance(document, dict):
            path = _as_str(document.get("path")).strip()
            if path:
                # The source artifact is the file the detection came from; use its
                # base name so provenance is stable across collection paths.
                return Path(path.replace("\\", "/")).name or path
        channel = _as_str(system.get("Channel")).strip()
        if channel:
            return f"{channel.replace('/', '%4')}.evtx"
        return _DEFAULT_ARTIFACT

    @staticmethod
    def _record_id(system: dict[str, Any], index: int) -> str:
        record_id = _as_str(system.get("EventRecordID")).strip()
        return record_id if record_id else f"detection:{index}"
