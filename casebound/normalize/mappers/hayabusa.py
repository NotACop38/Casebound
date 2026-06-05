"""Map Hayabusa csv-timeline rows to canonical events (PRD FR2, FR8 to FR11).

Hayabusa rows describe Windows event-log records. This mapper reads the columns
the Hayabusa adapter emits and derives the canonical fields:

  - ``datetime`` and ``source_timezone`` come from the Timestamp column via the
    timezone normalizer (FR9); ``timestamp_raw`` keeps the original string.
  - ``action``, ``principal``, and ``object`` are derived from the Windows channel
    and event id through a small, documented mapping table, reading the relevant
    keys out of the Details field. An event id the table does not cover still
    produces an event (a generic ``other`` action at reduced confidence) rather
    than being dropped, so the timeline stays complete (FR8).
  - ``message`` is the Hayabusa rule title, the most human-readable summary on the
    row.
  - ``details`` preserves the source specifics: the Windows event id, channel,
    level, rule title, the parsed Details key/value pairs, and the raw MITRE
    tactic and rule-tag strings. The raw rule tags are kept here, not promoted to
    ``attack_techniques``, because deterministic ATT&CK tagging is a later step;
    this step does not decide techniques.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

The ``event_id`` is derived by ``Event`` from the core fields, so identical
observations collapse to one id and the normalize pipeline can de-duplicate them
while keeping every provenance pointer (FR10, FR12).

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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
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

# Confidence for a row whose event id the table covers, versus the generic
# fallback used for an event id it does not.
_MAPPED_CONFIDENCE = 1.0
_FALLBACK_CONFIDENCE = 0.5

_FALLBACK_ACTION = "other"


@dataclass(frozen=True)
class WinEventMapping:
    """How one Windows (channel family, event id) becomes canonical fields.

    ``action`` is the normalized verb. ``principal_user_key`` and
    ``principal_domain_key`` name the Details keys that spell the actor; when both
    resolve, the principal is ``DOMAIN\\user``, otherwise just the user (or None).
    ``object_keys`` are tried in order for the primary target; the first present,
    non-empty one wins. When ``network_endpoint`` is set, the object is instead
    built from the destination ip, hostname, and port.
    """

    action: str
    object_keys: tuple[str, ...] = ()
    principal_user_key: str | None = None
    principal_domain_key: str | None = None
    network_endpoint: bool = False
    timestamp_desc: str = "logged"


# Channel-family-keyed mapping tables. "windows" covers the classic channels
# (Security, System, Application); "sysmon" covers Microsoft-Windows-Sysmon, whose
# small event ids would otherwise collide with the classic ones. The set is
# intentionally small and focused on the showcase scenario; new event ids are
# added here as sources need them.
_WINDOWS_EVENTS: dict[int, WinEventMapping] = {
    # Security 4624: an account was logged on. The source host (when present) is
    # the object; the target account is the principal.
    4624: WinEventMapping(
        action="logon",
        object_keys=("IpAddress",),
        principal_user_key="TargetUserName",
        principal_domain_key="TargetDomainName",
    ),
    # Security 4688: a new process was created.
    4688: WinEventMapping(
        action="process_create",
        object_keys=("NewProcessName",),
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    ),
    # Security 4698: a scheduled task was created.
    4698: WinEventMapping(
        action="scheduled_task_create",
        object_keys=("TaskName",),
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    ),
    # Security 5140: a network share object was accessed.
    5140: WinEventMapping(
        action="network_share_access",
        object_keys=("ShareName",),
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    ),
    # System 7045: a service was installed.
    7045: WinEventMapping(
        action="service_install",
        object_keys=("ServiceName",),
    ),
    # System 7036: a service reported a control state change (start, stop).
    7036: WinEventMapping(
        action="service_control",
        object_keys=("ServiceName",),
    ),
}

_SYSMON_EVENTS: dict[int, WinEventMapping] = {
    # Sysmon 1: process creation.
    1: WinEventMapping(
        action="process_create",
        object_keys=("Image",),
        principal_user_key="User",
    ),
    # Sysmon 3: network connection.
    3: WinEventMapping(
        action="network_connect",
        network_endpoint=True,
        principal_user_key="User",
    ),
    # Sysmon 10: one process opened a handle into another.
    10: WinEventMapping(
        action="process_access",
        object_keys=("TargetImage",),
    ),
    # Sysmon 11: a file was created.
    11: WinEventMapping(
        action="file_create",
        object_keys=("TargetFilename",),
    ),
    # Sysmon 13: a registry value was set.
    13: WinEventMapping(
        action="registry_set",
        object_keys=("TargetObject",),
    ),
}


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


def _nullable(value: str | None) -> str | None:
    """Collapse an empty or missing string to None for the nullable core fields."""
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


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
        return _network_endpoint(fields)
    for key in mapping.object_keys:
        value = _nullable(fields.get(key))
        if value is not None:
            return value
    return None


def _network_endpoint(fields: Mapping[str, str]) -> str | None:
    """Build a ``host:port`` target from Sysmon network-connection details.

    The destination ip is preferred over the hostname as the canonical target
    because an ip is unambiguous; the port is appended when present. Both the ip
    and the hostname remain available in the preserved Details for enrichment.
    """
    target = _nullable(fields.get("DestinationIp")) or _nullable(fields.get("DestinationHostname"))
    if target is None:
        return None
    port = _nullable(fields.get("DestinationPort"))
    return f"{target}:{port}" if port is not None else target


def _coerce_event_id(raw: str) -> int | str:
    """Return the Windows event id as an int when numeric, else the raw string."""
    text = raw.strip()
    try:
        return int(text)
    except ValueError:
        return text


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
        win_event_id = _coerce_event_id(data.get("EventID", ""))
        fields = parse_details(data.get("Details", ""))
        mapping = self._mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else _FALLBACK_ACTION
        confidence = _MAPPED_CONFIDENCE if mapping is not None else _FALLBACK_CONFIDENCE
        timestamp_desc = mapping.timestamp_desc if mapping is not None else "logged"
        principal = _principal(fields, mapping) if mapping is not None else None
        obj = _object(fields, mapping) if mapping is not None else None
        host = _nullable(data.get("Computer"))
        message = self._message(data, channel, win_event_id, host)

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc=timestamp_desc,
                message=message,
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
        title = _nullable(data.get("RuleTitle"))
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
        level = _nullable(data.get("Level"))
        if level is not None:
            details["level"] = level
        rule_title = _nullable(data.get("RuleTitle"))
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
