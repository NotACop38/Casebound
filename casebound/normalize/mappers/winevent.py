"""Shared Windows event-log to canonical-field mapping (PRD FR8, FR13).

More than one source carries Windows event-log records: Velociraptor exports the
``Windows.EventLogs.Evtx`` family as JSONL, and the optional Dissect raw-mode
adapter parses ``.evtx`` files directly. Both describe the same underlying
Windows events, so the rule that turns one EventID into canonical fields belongs
in one place rather than being copied per source. This module is that place.

Given the EventData fields of a Windows event and the channel it came from, the
helpers here resolve the canonical ``action`` verb, the acting ``principal``
(``DOMAIN\\user`` when a domain is present), and the primary ``object`` (a target
path, a service or task name, or a network endpoint). An EventID the tables do
not cover yields no mapping, and the caller falls back to a generic ``other``
action at reduced confidence rather than dropping the event.

This module is pure: it depends only on the canonical schema vocabulary and never
imports any parser. It is Apache-2.0 core code and stays free of the optional,
AGPL-licensed Dissect dependency, which lives only under ``casebound/ingest/raw``.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

__all__ = [
    "FALLBACK_ACTION",
    "FALLBACK_CONFIDENCE",
    "MAPPED_CONFIDENCE",
    "SYSMON_EVENTS",
    "WINDOWS_EVENTS",
    "WinEventMapping",
    "coerce_event_id",
    "derive_object",
    "derive_principal",
    "mapping_for",
    "nullable",
]

# The action and confidence used when no EventID mapping applies: the event is
# still emitted (FR8) as a generic ``other`` at reduced confidence rather than
# dropped, so an uncovered EventID never silently disappears from the timeline.
FALLBACK_ACTION = "other"
MAPPED_CONFIDENCE = 1.0
FALLBACK_CONFIDENCE = 0.5


@dataclass(frozen=True)
class WinEventMapping:
    """How one Windows EventID becomes canonical fields, read from EventData.

    ``action`` is the canonical verb. ``object_keys`` are the EventData keys to
    try in order for the primary object. ``principal_user_key`` and
    ``principal_domain_key`` name the EventData fields that carry the acting
    account. ``network_endpoint`` switches the object derivation to a
    destination host plus port for network events.
    """

    action: str
    object_keys: tuple[str, ...] = ()
    principal_user_key: str | None = None
    principal_domain_key: str | None = None
    network_endpoint: bool = False


# Windows Security and System channel EventIDs. The EventData field names mirror
# the standard Windows event schema, so the same table serves any source that
# parses these logs. Re-verify against the Windows event documentation when
# extending: these field names are stable but the coverage here is deliberately
# small and focused on the showcase activity.
WINDOWS_EVENTS: dict[int, WinEventMapping] = {
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
    5140: WinEventMapping(
        action="network_share_access",
        object_keys=("ShareName",),
        principal_user_key="SubjectUserName",
        principal_domain_key="SubjectDomainName",
    ),
    7036: WinEventMapping(action="service_control", object_keys=("ServiceName",)),
    7045: WinEventMapping(action="service_install", object_keys=("ServiceName",)),
}

# Sysmon (Microsoft-Windows-Sysmon/Operational) EventIDs. Selected on the channel
# carrying "Sysmon" so Sysmon's distinct EventID numbering never collides with the
# Security channel's.
SYSMON_EVENTS: dict[int, WinEventMapping] = {
    1: WinEventMapping(action="process_create", object_keys=("Image",), principal_user_key="User"),
    3: WinEventMapping(action="network_connect", network_endpoint=True, principal_user_key="User"),
    10: WinEventMapping(action="process_access", object_keys=("TargetImage",)),
    11: WinEventMapping(action="file_create", object_keys=("TargetFilename",)),
    13: WinEventMapping(action="registry_set", object_keys=("TargetObject",)),
}


def nullable(value: str | None) -> str | None:
    """Collapse an empty or missing string to None for the nullable core fields."""
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def coerce_event_id(raw: str) -> int | str:
    """Parse a raw EventID into an int, leaving an unparseable value as its string."""
    text = raw.strip()
    try:
        return int(text)
    except ValueError:
        return text


def mapping_for(channel: str, event_id: int | str) -> WinEventMapping | None:
    """Return the mapping for ``event_id`` on ``channel``, or None if uncovered.

    A non-integer EventID never maps. The Sysmon table is used when the channel
    names Sysmon, otherwise the Security and System table.
    """
    if not isinstance(event_id, int):
        return None
    table = SYSMON_EVENTS if "Sysmon" in channel else WINDOWS_EVENTS
    return table.get(event_id)


def derive_principal(fields: Mapping[str, str], mapping: WinEventMapping | None) -> str | None:
    """Build the acting principal as ``DOMAIN\\user`` or ``user`` from EventData.

    An uncovered EventID has no mapping, so ``mapping`` may be None; that yields no
    principal, the same as a mapping that names no principal key. Letting the helper
    absorb the None case keeps the per-source callers free of a repeated guard.
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
    return f"{domain}\\{user}" if domain is not None else user


def derive_object(fields: Mapping[str, str], mapping: WinEventMapping | None) -> str | None:
    """Resolve the primary object: a network endpoint or the first present key.

    ``mapping`` may be None for an uncovered EventID, which yields no object. For a
    network event the destination ip is preferred over the hostname (an ip is
    unambiguous) and the port is appended when present; both the ip and the hostname
    remain in the preserved EventData for enrichment.
    """
    if mapping is None:
        return None
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
