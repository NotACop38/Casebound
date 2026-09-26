"""Tests for the shared Windows event-log tables (``casebound.normalize.mappers.winevent``).

Every Windows source (Hayabusa, Chainsaw, Velociraptor, raw EVTX, Plaso's EVTX rows)
maps an EventID through these tables, so they must key on the channel (EventID
numbering is per channel), read Windows' and Hayabusa's "no value" placeholders as
absent, and build principals and objects the same way for every source.
"""

from __future__ import annotations

import pytest

from casebound.normalize.mappers.winevent import (
    CHANNEL_SECURITY,
    CHANNEL_SYSMON,
    CHANNEL_SYSTEM,
    CHANNEL_TASKSCHEDULER,
    SECURITY_EVENTS,
    SYSMON_EVENTS,
    SYSTEM_EVENTS,
    TASKSCHEDULER_EVENTS,
    coerce_event_id,
    derive_object,
    derive_principal,
    mapping_for,
    nullable,
    table_for_channel,
)
from casebound.normalize.schema import KNOWN_ACTIONS


def test_every_table_action_is_canonical() -> None:
    for table in (SECURITY_EVENTS, SYSTEM_EVENTS, SYSMON_EVENTS, TASKSCHEDULER_EVENTS):
        for event_id, mapping in table.items():
            assert mapping.action in KNOWN_ACTIONS, (event_id, mapping.action)


@pytest.mark.parametrize(
    ("channel", "event_id", "action"),
    [
        (CHANNEL_SYSMON, 3, "network_connect"),
        (CHANNEL_SECURITY, 3, None),
        (CHANNEL_SYSTEM, 7045, "service_install"),
        (CHANNEL_SECURITY, 7045, None),
        (CHANNEL_SECURITY, 4697, "service_install"),
        (CHANNEL_TASKSCHEDULER, 106, "scheduled_task_create"),
        (CHANNEL_SECURITY, 4698, "scheduled_task_create"),
        ("Application", 1000, None),
    ],
)
def test_event_ids_are_resolved_per_channel(
    channel: str, event_id: int, action: str | None
) -> None:
    mapping = mapping_for(channel, event_id)
    assert (mapping.action if mapping else None) == action


def test_channel_matching_is_forgiving() -> None:
    assert table_for_channel("security") is SECURITY_EVENTS
    assert table_for_channel("  SYSTEM ") is SYSTEM_EVENTS
    # Any spelling that names Sysmon selects the Sysmon table.
    assert table_for_channel("Sysmon") is SYSMON_EVENTS
    assert table_for_channel("microsoft-windows-sysmon/operational") is SYSMON_EVENTS
    assert table_for_channel("Microsoft-Windows-PowerShell/Operational") is None


def test_a_missing_channel_tries_security_then_system() -> None:
    assert mapping_for("", 4688) is SECURITY_EVENTS[4688]
    assert mapping_for("", 7045) is SYSTEM_EVENTS[7045]
    assert mapping_for("", 1) is None


def test_event_ids_are_parsed_strictly() -> None:
    assert coerce_event_id(" 4624 ") == 4624
    assert coerce_event_id("4624a") == "4624a"
    assert mapping_for(CHANNEL_SECURITY, "4624a") is None


@pytest.mark.parametrize("placeholder", ["", "  ", "-", "n/a", "N/A", None])
def test_placeholders_read_as_absent(placeholder: str | None) -> None:
    assert nullable(placeholder) is None


def test_principal_composes_the_domain_once() -> None:
    logon = SECURITY_EVENTS[4624]
    fields = {"TargetUserName": "jdoe", "TargetDomainName": "CORP"}
    assert derive_principal(fields, logon) == "CORP\\jdoe"
    assert derive_principal({"TargetUserName": "jdoe", "TargetDomainName": "-"}, logon) == "jdoe"
    # Sysmon writes the account already qualified; it is not prefixed again.
    assert derive_principal({"User": "CORP\\jdoe"}, SYSMON_EVENTS[1]) == "CORP\\jdoe"
    assert derive_principal({"TargetUserName": "-"}, logon) is None
    assert derive_principal(fields, None) is None


def test_objects_come_from_a_constant_an_endpoint_or_the_first_present_key() -> None:
    assert derive_object({}, SECURITY_EVENTS[1102]) == "Security"
    network = SYSMON_EVENTS[3]
    assert (
        derive_object(
            {
                "DestinationIp": "203.0.113.77",
                "DestinationHostname": "x.example",
                "DestinationPort": "443",
            },
            network,
        )
        == "203.0.113.77:443"
    )
    assert derive_object({"DestinationHostname": "x.example"}, network) == "x.example"
    assert derive_object({"DestinationPort": "443"}, network) is None
    assert derive_object({"param1": "-", "ServiceName": "Spooler"}, SYSTEM_EVENTS[7036]) == (
        "Spooler"
    )
    assert derive_object({"ServiceName": "x"}, None) is None
