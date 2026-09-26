"""Shared Windows event-log to canonical-field mapping (PRD FR8, FR13).

Several sources carry Windows event-log records: Hayabusa and Chainsaw emit
detections over them, Velociraptor exports the ``Windows.EventLogs.Evtx`` family as
JSONL, and the optional Dissect raw-mode adapter parses ``.evtx`` files directly.
All of them describe the same underlying Windows events, so the rule that turns one
EventID into canonical fields lives here, once, rather than being copied per source.

Given the EventData fields of a Windows event and the channel it came from, the
helpers resolve the canonical ``action`` verb, the acting ``principal``
(``DOMAIN\\user`` when a domain is present), and the primary ``object`` (a target
path, a service or task name, a share, or a network endpoint). An EventID the
tables do not cover yields no mapping, and the caller falls back to a generic
``other`` action at reduced confidence rather than dropping the event.

The tables are keyed by channel, because EventID numbering is per channel: Sysmon's
event 3 is a network connection, the Security log has no event 3 at all. The field
names follow the Windows event schemas (Security auditing, System, Sysmon,
TaskScheduler), re-verified at author time; the coverage is deliberately focused on
the activity an intrusion narrative turns on.

Windows writes ``-`` for an empty field and Hayabusa writes ``n/a`` for a field
its template could not fill; both mean "no value" and are read as null.

This module is pure: it depends only on the canonical schema vocabulary and never
imports any parser. It is Apache-2.0 core code and stays free of the optional,
AGPL-licensed Dissect dependency, which lives only under ``casebound/ingest/raw``.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = [
    "CHANNEL_SECURITY",
    "CHANNEL_SYSMON",
    "CHANNEL_SYSTEM",
    "CHANNEL_TASKSCHEDULER",
    "FALLBACK_ACTION",
    "FALLBACK_CONFIDENCE",
    "MAPPED_CONFIDENCE",
    "WinEventMapping",
    "coerce_event_id",
    "derive_object",
    "derive_principal",
    "mapping_for",
    "nullable",
    "table_for_channel",
]

# The action and confidence used when no EventID mapping applies: the event is
# still emitted (FR8) as a generic ``other`` at reduced confidence rather than
# dropped, so an uncovered EventID never silently disappears from the timeline.
FALLBACK_ACTION = "other"
MAPPED_CONFIDENCE = 1.0
FALLBACK_CONFIDENCE = 0.5

# The canonical channel names the tables are keyed by.
CHANNEL_SECURITY = "Security"
CHANNEL_SYSTEM = "System"
CHANNEL_SYSMON = "Microsoft-Windows-Sysmon/Operational"
CHANNEL_TASKSCHEDULER = "Microsoft-Windows-TaskScheduler/Operational"

# Placeholders that mean "no value": Windows writes "-" for an empty field, and
# Hayabusa writes "n/a" when a details template names a field the record lacks.
_NULL_TOKENS = frozenset({"-", "n/a", "N/A"})


@dataclass(frozen=True)
class WinEventMapping:
    """How one Windows EventID becomes canonical fields, read from EventData.

    ``action`` is the canonical verb. ``object_keys`` are the EventData keys to try
    in order for the primary object; ``object_constant`` names a fixed object when
    the event itself is about one thing (the Security log, for event 1102).
    ``principal_user_key`` and ``principal_domain_key`` name the fields that carry
    the acting account. ``network_endpoint`` switches the object to a destination
    address plus port for network events.
    """

    action: str
    object_keys: tuple[str, ...] = ()
    object_constant: str | None = None
    principal_user_key: str | None = None
    principal_domain_key: str | None = None
    network_endpoint: bool = False


def _subject(action: str, *object_keys: str, constant: str | None = None) -> WinEventMapping:
    """A Security-log mapping whose actor is the event's Subject account."""
    return WinEventMapping(
        action=action,
        object_keys=object_keys,
        object_constant=constant,
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    )


def _target(action: str, *object_keys: str) -> WinEventMapping:
    """A logon-style mapping whose actor is the event's Target account."""
    return WinEventMapping(
        action=action,
        object_keys=object_keys,
        principal_user_key="TargetUserName",
        principal_domain_key="TargetDomainName",
    )


# Security auditing (the Security channel).
SECURITY_EVENTS: dict[int, WinEventMapping] = {
    1102: _subject("log_clear", constant=CHANNEL_SECURITY),
    4624: _target("logon", "IpAddress"),
    4625: _target("logon_failure", "IpAddress"),
    4688: _subject("process_create", "NewProcessName"),
    4689: _subject("process_terminate", "ProcessName"),
    4697: _subject("service_install", "ServiceName"),
    4698: _subject("scheduled_task_create", "TaskName"),
    4720: _subject("account_create", "TargetUserName"),
    5140: _subject("network_share_access", "ShareName"),
    5145: _subject("network_share_access", "ShareName"),
}

# The System channel. Service Control Manager events name the service in the
# positional param fields (7036: param1 is the display name; 7040: param4 is the
# service key name); ServiceName is accepted too for exports that relabel them.
SYSTEM_EVENTS: dict[int, WinEventMapping] = {
    104: _subject("log_clear", "Channel"),
    7036: WinEventMapping(action="service_control", object_keys=("param1", "ServiceName")),
    7040: WinEventMapping(action="service_control", object_keys=("param4", "param1")),
    7045: WinEventMapping(action="service_install", object_keys=("ServiceName",)),
}

# Sysmon (Microsoft-Windows-Sysmon/Operational). The acting account is the ``User``
# field, already rendered as DOMAIN\\user; process access and remote thread events
# name it ``SourceUser``.
SYSMON_EVENTS: dict[int, WinEventMapping] = {
    1: WinEventMapping(action="process_create", object_keys=("Image",), principal_user_key="User"),
    3: WinEventMapping(action="network_connect", network_endpoint=True, principal_user_key="User"),
    8: WinEventMapping(
        action="remote_thread_create", object_keys=("TargetImage",), principal_user_key="SourceUser"
    ),
    10: WinEventMapping(
        action="process_access", object_keys=("TargetImage",), principal_user_key="SourceUser"
    ),
    11: WinEventMapping(
        action="file_create", object_keys=("TargetFilename",), principal_user_key="User"
    ),
    13: WinEventMapping(
        action="registry_set", object_keys=("TargetObject",), principal_user_key="User"
    ),
    22: WinEventMapping(action="dns_query", object_keys=("QueryName",), principal_user_key="User"),
    23: WinEventMapping(
        action="file_delete", object_keys=("TargetFilename",), principal_user_key="User"
    ),
    26: WinEventMapping(
        action="file_delete", object_keys=("TargetFilename",), principal_user_key="User"
    ),
}

# Task Scheduler operational log.
TASKSCHEDULER_EVENTS: dict[int, WinEventMapping] = {
    106: WinEventMapping(
        action="scheduled_task_create", object_keys=("TaskName",), principal_user_key="UserContext"
    ),
}

_TABLES: dict[str, dict[int, WinEventMapping]] = {
    CHANNEL_SECURITY.casefold(): SECURITY_EVENTS,
    CHANNEL_SYSTEM.casefold(): SYSTEM_EVENTS,
    CHANNEL_SYSMON.casefold(): SYSMON_EVENTS,
    CHANNEL_TASKSCHEDULER.casefold(): TASKSCHEDULER_EVENTS,
}


def nullable(value: str | None) -> str | None:
    """Collapse an empty, missing, or placeholder string to None."""
    if value is None:
        return None
    trimmed = value.strip()
    if not trimmed or trimmed in _NULL_TOKENS:
        return None
    return trimmed


def coerce_event_id(raw: str) -> int | str:
    """Parse a raw EventID into an int, leaving an unparseable value as its string."""
    text = raw.strip()
    try:
        return int(text)
    except ValueError:
        return text


def table_for_channel(channel: str) -> dict[int, WinEventMapping] | None:
    """Return the EventID table for a channel name, or None for an unmapped channel.

    Matching is case-insensitive on the full channel name, and any channel that
    names Sysmon selects the Sysmon table, so an export that shortens the channel
    still maps.
    """
    key = channel.strip().casefold()
    if "sysmon" in key:
        return SYSMON_EVENTS
    return _TABLES.get(key)


def mapping_for(channel: str, event_id: int | str) -> WinEventMapping | None:
    """Return the mapping for ``event_id`` on ``channel``, or None if uncovered.

    A non-integer EventID never maps. When the channel is empty (a source that does
    not record it), the Security and then the System table are tried, which is where
    a bare Windows EventID most often comes from.
    """
    if not isinstance(event_id, int):
        return None
    if channel.strip():
        table = table_for_channel(channel)
        return table.get(event_id) if table is not None else None
    return SECURITY_EVENTS.get(event_id) or SYSTEM_EVENTS.get(event_id)


def derive_principal(fields: Mapping[str, str], mapping: WinEventMapping | None) -> str | None:
    """Build the acting principal as ``DOMAIN\\user`` or ``user`` from EventData.

    An uncovered EventID has no mapping, so ``mapping`` may be None; that yields no
    principal, the same as a mapping that names no principal key.
    """
    if mapping is None or mapping.principal_user_key is None:
        return None
    user = nullable(fields.get(mapping.principal_user_key))
    if user is None:
        return None
    domain = (
        nullable(fields.get(mapping.principal_domain_key))
        if mapping.principal_domain_key is not None
        else None
    )
    return f"{domain}\\{user}" if domain is not None and "\\" not in user else user


def derive_object(fields: Mapping[str, str], mapping: WinEventMapping | None) -> str | None:
    """Resolve the primary object: a constant, a network endpoint, or the first key.

    For a network event the destination address is preferred over the hostname (an
    address is unambiguous) and the port is appended when present; both remain in
    the preserved EventData for enrichment.
    """
    if mapping is None:
        return None
    if mapping.object_constant is not None:
        return mapping.object_constant
    if mapping.network_endpoint:
        target = nullable(fields.get("DestinationIp")) or nullable(
            fields.get("DestinationHostname")
        )
        if target is None:
            return None
        port = nullable(fields.get("DestinationPort"))
        return f"{target}:{port}" if port is not None else target
    for key in mapping.object_keys:
        value = nullable(fields.get(key))
        if value is not None:
            return value
    return None
