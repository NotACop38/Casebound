"""Map Hayabusa timeline rows to canonical events (PRD FR2, FR8 to FR11).

Hayabusa rows describe Windows event-log records that a detection rule matched.
This mapper reads what the Hayabusa adapter emits (from a CSV or a JSON/JSONL
timeline, any built-in output profile) and derives the canonical fields.

Hayabusa output is compact by design, and a faithful mapping has to undo that:

  - Channels are abbreviated by default (``Sec``, ``Sys``, ``Sysmon``, ``PwSh``,
    ``TaskSch``, and so on); ``HAYABUSA_CHANNELS`` restores the full channel name,
    which selects the EventID table and names the source artifact.
  - The ``Details`` column labels fields with per-rule abbreviations (``Proc``,
    ``TgtUser``, ``SrcIP``). The same abbreviation means different fields on
    different events (``Proc`` is ``NewProcessName`` on Security 4688 but ``Image``
    on Sysmon 1), so ``HAYABUSA_FIELD_ALIASES`` is keyed by (channel, EventID). Its
    spellings were extracted from the Hayabusa rule set's ``details`` templates and
    its ``default_details.txt`` at author time.
  - ``ExtraFieldInfo`` (standard and verbose profiles) lists, under their original
    names, the record fields whose values Details did not show, and
    ``AllFieldInfo`` (all-field-info profiles) lists every field. Both are merged
    in, so for example the ``SubjectDomainName`` a 4688 Details template omits is
    recovered and the principal reads ``CORP\\jdoe`` rather than ``jdoe``.

From the resulting EventData the shared ``winevent`` table derives ``action``,
``principal``, and ``object``, so a Hayabusa row maps exactly like the same event
seen through Chainsaw, Velociraptor, or raw EVTX. An EventID the table does not
cover still produces an event (a generic ``other`` action at reduced confidence).
``message`` is the rule title. ``details`` keeps the EventID, channel, level, rule
title and file, the de-abbreviated fields, and the raw MITRE tactic, technique, and
other tags; techniques are decided later by the tagger, not here.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
from casebound.normalize.mappers.winevent import (
    CHANNEL_SECURITY,
    CHANNEL_SYSMON,
    CHANNEL_SYSTEM,
    CHANNEL_TASKSCHEDULER,
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
    "HAYABUSA_CHANNELS",
    "HAYABUSA_FIELD_ALIASES",
    "HayabusaMapper",
    "expand_channel",
    "parse_details",
    "resolve_fields",
]

# Hayabusa's multi-value separator is a space-padded broken bar (U+00A6). Splitting
# on the bar itself and stripping is robust to the exact spacing a profile uses.
_FIELD_SEP = "¦"

# What Hayabusa prints in Details for a template field the record does not have.
_TEMPLATE_MISSING = "n/a"

# Hayabusa's channel abbreviations (hayabusa-rules config/channel_abbreviations.txt),
# mapped back to the full channel name. Abbreviations Hayabusa shares between
# several logs (AppLocker, SecMitig) are left as written, since the exact log
# cannot be recovered from the abbreviation alone.
HAYABUSA_CHANNELS: dict[str, str] = {
    "App": "Application",
    "BitsCli": "Microsoft-Windows-Bits-Client/Operational",
    "CodeInteg": "Microsoft-Windows-CodeIntegrity/Operational",
    "Defender": "Microsoft-Windows-Windows Defender/Operational",
    "DHCP-Svr": "Microsoft-Windows-DHCP-Server/Operational",
    "DNS-Svr": "DNS Server",
    "DvrFmwk": "Microsoft-Windows-DriverFrameworks-UserMode/Operational",
    "Exchange": "MSExchange Management",
    "Firewall": "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
    "Forwarding": "Microsoft-Windows-Forwarding/Operational",
    "GroupPolicy": "Microsoft-Windows-GroupPolicy/Operational",
    "KeyMgtSvc": "Key Management Service",
    "LDAP-Cli": "Microsoft-Windows-LDAP-Client/Debug",
    "NTLM": "Microsoft-Windows-NTLM/Operational",
    "OpenSSH": "OpenSSH/Operational",
    "PrintAdm": "Microsoft-Windows-PrintService/Admin",
    "PrintOp": "Microsoft-Windows-PrintService/Operational",
    "PwSh": "Microsoft-Windows-PowerShell/Operational",
    "PwShClassic": "Windows PowerShell",
    "PwShCore": "PowerShellCore",
    "RDP-Cli": "Microsoft-Windows-TerminalServices-RDPClient/Operational",
    "RDP-CoreTS": "Microsoft-Windows-RemoteDesktopServices-RdpCoreTS/Operational",
    "RDS-GTW": "Microsoft-Windows-TerminalServices-Gateway/Operational",
    "RDS-LSM": "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational",
    "RDS-RCM": "Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational",
    "Sec": CHANNEL_SECURITY,
    "SmbCliSec": "Microsoft-Windows-SmbClient/Security",
    "SvcBusCli": "Microsoft-ServiceBus-Client",
    "Sys": CHANNEL_SYSTEM,
    "Sysmon": CHANNEL_SYSMON,
    "TaskSch": CHANNEL_TASKSCHEDULER,
    "WinRM": "Microsoft-Windows-WinRM/Operational",
    "WMI": "Microsoft-Windows-WMI-Activity/Operational",
}

# Hayabusa's Details abbreviations for the events the shared winevent table maps,
# per (full channel, EventID): abbreviation -> original EventData field name. A key
# absent here is already an original name (a --disable-abbreviations run, or a
# template that uses the field name itself) and passes through unchanged.
_SYSMON_PROCESS = {"Proc": "Image", "PID": "ProcessId", "PGUID": "ProcessGuid", "Rule": "RuleName"}
HAYABUSA_FIELD_ALIASES: dict[tuple[str, int], dict[str, str]] = {
    (CHANNEL_SECURITY, 1102): {"User": "SubjectUserName"},
    (CHANNEL_SECURITY, 4624): {
        "Type": "LogonType",
        "TgtUser": "TargetUserName",
        "SrcComp": "WorkstationName",
        "SrcIP": "IpAddress",
        "LID": "TargetLogonId",
    },
    (CHANNEL_SECURITY, 4625): {
        "Type": "LogonType",
        "TgtUser": "TargetUserName",
        "SrcComp": "WorkstationName",
        "SrcIP": "IpAddress",
        "AuthPkg": "AuthenticationPackageName",
        "Proc": "ProcessName",
    },
    (CHANNEL_SECURITY, 4688): {
        "Cmdline": "CommandLine",
        "Proc": "NewProcessName",
        "PID": "NewProcessId",
        "User": "SubjectUserName",
        "LID": "SubjectLogonId",
    },
    (CHANNEL_SECURITY, 4697): {
        "Svc": "ServiceName",
        "Path": "ServiceFileName",
        "User": "SubjectUserName",
        "SvcAcct": "ServiceAccount",
        "SvcType": "ServiceType",
        "SvcStartType": "ServiceStartType",
        "LID": "SubjectLogonId",
    },
    (CHANNEL_SECURITY, 4698): {
        "Name": "TaskName",
        "Content": "TaskContent",
        "User": "SubjectUserName",
        "LID": "SubjectLogonId",
    },
    (CHANNEL_SECURITY, 4720): {"TgtUser": "TargetUserName", "TgtSID": "TargetSid"},
    (CHANNEL_SECURITY, 5140): {
        "SrcUser": "SubjectUserName",
        "SharePath": "ShareLocalPath",
        "SrcIP": "IpAddress",
        "LID": "SubjectLogonId",
    },
    (CHANNEL_SECURITY, 5145): {
        "SrcUser": "SubjectUserName",
        "SharePath": "ShareLocalPath",
        "Path": "RelativeTargetName",
        "SrcIP": "IpAddress",
        "LID": "SubjectLogonId",
    },
    (CHANNEL_SYSTEM, 104): {"Log": "Channel", "User": "SubjectUserName"},
    (CHANNEL_SYSTEM, 7040): {"OldSetting": "param2", "NewSetting": "param3"},
    (CHANNEL_SYSTEM, 7045): {
        "Svc": "ServiceName",
        "Path": "ImagePath",
        "Acct": "AccountName",
    },
    (CHANNEL_SYSMON, 1): {
        **_SYSMON_PROCESS,
        "Cmdline": "CommandLine",
        "ParentCmdline": "ParentCommandLine",
        "LID": "LogonId",
        "LGUID": "LogonGuid",
        "ParentPID": "ParentProcessId",
        "ParentPGUID": "ParentProcessGuid",
    },
    (CHANNEL_SYSMON, 3): {
        **_SYSMON_PROCESS,
        "Proto": "Protocol",
        "SrcIP": "SourceIp",
        "SrcPort": "SourcePort",
        "SrcHost": "SourceHostname",
        "TgtIP": "DestinationIp",
        "TgtPort": "DestinationPort",
        "TgtHost": "DestinationHostname",
    },
    (CHANNEL_SYSMON, 8): {
        "SrcProc": "SourceImage",
        "TgtProc": "TargetImage",
        "SrcPID": "SourceProcessId",
        "SrcPGUID": "SourceProcessGuid",
        "TgtPID": "TargetProcessId",
        "TgtPGUID": "TargetProcessGuid",
        "Rule": "RuleName",
    },
    (CHANNEL_SYSMON, 10): {
        "SrcProc": "SourceImage",
        "TgtProc": "TargetImage",
        "SrcUser": "SourceUser",
        "TgtUser": "TargetUser",
        "Access": "GrantedAccess",
        "SrcPID": "SourceProcessId",
        "SrcPGUID": "SourceProcessGUID",
        "TgtPID": "TargetProcessId",
        "TgtPGUID": "TargetProcessGUID",
        "Rule": "RuleName",
    },
    (CHANNEL_SYSMON, 11): {**_SYSMON_PROCESS, "Path": "TargetFilename"},
    (CHANNEL_SYSMON, 13): {**_SYSMON_PROCESS, "RegKey": "TargetObject", "TgtObj": "TargetObject"},
    (CHANNEL_SYSMON, 22): {**_SYSMON_PROCESS, "Query": "QueryName", "Result": "QueryResults"},
    (CHANNEL_SYSMON, 23): {**_SYSMON_PROCESS, "Path": "TargetFilename"},
    (CHANNEL_SYSMON, 26): {**_SYSMON_PROCESS, "Path": "TargetFilename"},
    (CHANNEL_TASKSCHEDULER, 106): {"Name": "TaskName"},
}

# How a row whose timestamp has no offset is labeled by default: Hayabusa prints an
# explicit offset (or Z), so None means trust it. A caller can pass an IANA zone to
# relabel instead (see normalize_timestamp).
_DEFAULT_ASSUME_TZ: str | None = None


def expand_channel(channel: str) -> str:
    """Return the full channel name for a Hayabusa channel abbreviation."""
    stripped = channel.strip()
    return HAYABUSA_CHANNELS.get(stripped, stripped)


def parse_details(raw: str) -> dict[str, str]:
    """Parse a Hayabusa ``Key: Value ¦ Key: Value`` cell into an ordered mapping.

    Also accepts the JSON object form the adapter writes for a JSON or JSONL
    timeline. Each pair is split on its first colon, so a value that itself
    contains a colon (a Windows path such as ``C:\\Windows``) is preserved intact.
    A fragment with no colon, and the ``-`` Hayabusa writes for an empty column, are
    skipped rather than guessed at.
    """
    text = raw.strip()
    if text.startswith("{"):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, dict):
            return {str(key): _scalar(value) for key, value in decoded.items()}
    fields: dict[str, str] = {}
    for fragment in text.split(_FIELD_SEP):
        key, sep, value = fragment.partition(":")
        if not sep:
            continue
        name = key.strip()
        if name:
            fields[name] = value.strip()
    return fields


def _scalar(value: Any) -> str:
    """Render one JSON field value as the string a CSV cell would have carried."""
    if isinstance(value, list):
        return " ".join(_scalar(item) for item in value)
    if value is None:
        return ""
    return str(value)


def resolve_fields(channel: str, event_id: int | str, data: Mapping[str, str]) -> dict[str, str]:
    """Rebuild a record's EventData under original field names.

    ``AllFieldInfo`` (when present) is the complete set; the de-abbreviated
    ``Details`` pairs come next; ``ExtraFieldInfo`` fills in what Details left
    out. An earlier source wins on a conflicting key, so the full-name profiles
    are authoritative and an abbreviation can never shadow a real field. A Details
    value of ``n/a`` (a template field the record lacks) is dropped.
    """
    aliases = (
        HAYABUSA_FIELD_ALIASES.get((channel, event_id), {}) if isinstance(event_id, int) else {}
    )
    fields: dict[str, str] = dict(parse_details(data.get("AllFieldInfo", "")))
    for key, value in parse_details(data.get("Details", "")).items():
        # "n/a" is Hayabusa's own marker for a template field the record lacks, so
        # the field is absent rather than present with that value.
        if value != _TEMPLATE_MISSING:
            fields.setdefault(aliases.get(key, key), value)
    for key, value in parse_details(data.get("ExtraFieldInfo", "")).items():
        fields.setdefault(key, value)
    return fields


def _split_multi(raw: str) -> list[str]:
    """Split a Hayabusa multi-value cell into its non-empty, stripped values."""
    text = raw.strip()
    if text.startswith("["):
        try:
            decoded = json.loads(text)
        except json.JSONDecodeError:
            decoded = None
        if isinstance(decoded, list):
            return [str(item).strip() for item in decoded if str(item).strip()]
    return [piece.strip() for piece in text.split(_FIELD_SEP) if piece.strip() not in ("", "-")]


class HayabusaMapper(Mapper):
    """Map Hayabusa timeline records into canonical events."""

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

        channel = expand_channel(data.get("Channel") or "")
        win_event_id = coerce_event_id(data.get("EventID", ""))
        fields = resolve_fields(channel, win_event_id, data)
        mapping = mapping_for(channel, win_event_id)

        action = mapping.action if mapping is not None else FALLBACK_ACTION
        confidence = MAPPED_CONFIDENCE if mapping is not None else FALLBACK_CONFIDENCE
        host = nullable(data.get("Computer"))

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
        title = nullable(data.get("RuleTitle"))
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
        for column, key in (
            ("Level", "level"),
            ("RuleTitle", "rule_title"),
            ("RuleFile", "rule_file"),
            ("RuleID", "rule_id"),
            ("Provider", "provider"),
        ):
            value = nullable(data.get(column))
            if value is not None:
                details[key] = value
        tactics = _split_multi(data.get("MitreTactics", ""))
        if tactics:
            details["mitre_tactics"] = tactics
        # Raw technique tags are kept for the tagger (enrich.attack), which alone
        # decides techniques; group and software ids are filtered out there.
        rule_tags = _split_multi(data.get("MitreTags", ""))
        if rule_tags:
            details["rule_mitre_tags"] = rule_tags
        other_tags = _split_multi(data.get("OtherTags", ""))
        if other_tags:
            details["other_tags"] = other_tags
        return details
