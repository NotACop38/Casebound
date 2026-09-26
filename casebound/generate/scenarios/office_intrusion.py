"""The "office_intrusion" ground-truth scenario (PRD Section 12, FR33).

A synthetic, multi-stage intrusion across a workstation and a file server, set in a
morning of ordinary activity:

  1. Initial access: a phishing macro in Word spawns an encoded PowerShell.
  2. Command and control: PowerShell pulls a stager over HTTPS.
  3. Persistence: a Run key and a scheduled task both point at the implant.
  4. Credential access: the implant reads LSASS memory.
  5. Lateral movement: a network logon with a stolen service account, an ADMIN$
     share mount, and a remote service that is installed and then runs.
  6. Collection and exfiltration: data is archived and pushed to an outside host.
  7. Defense impairment: the Security log on the file server is cleared.

Around it sit benign events a real triage would also contain: service logons,
privilege assignments, a mistyped password, service state changes, a browser, an
OneDrive autostart, a Defender scan that opens LSASS, a Windows maintenance task, an
Edge updater service install, and an administrator's scheduled PowerShell. Several
of these look like attack techniques to a context-free mapping table, which is
exactly what makes the tagger's precision measurable.

Each event carries its Windows EventData under the original field names; the
generator renders it the way Hayabusa's verbose profile prints it (abbreviated
channels and Details keys, ExtraFieldInfo, rule metadata). The canonical
``principal``, ``action``, and ``object`` recorded here are what the normalizer must
derive from that rendering, and the test suite holds the two in lockstep.

Everything here is synthetic and safe (Hard rule 3): lab hostnames, a fictional
CORP domain, obviously fake SIDs, external addresses from the RFC 5737 documentation
ranges, internal addresses from RFC 1918 space, domains under the reserved
``.example`` TLD (RFC 2606), and no working payload (the encoded command is a
truncated, inert placeholder).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

# The scenario clock. The first attack event is anchored in UTC; every other event
# is an offset from it. The generated timeline renders timestamps in the analyst's
# local zone (US Eastern, UTC-4 on this March date because daylight time is in
# effect), while the ground truth records the canonical UTC instant.
SCENARIO_START_UTC = datetime(2026, 3, 14, 8, 42, 17, tzinfo=UTC)
OUTPUT_TIMEZONE = "America/New_York"
OUTPUT_UTC_OFFSET = timedelta(hours=-4)
OUTPUT_OFFSET_LABEL = "-04:00"

# The stages a complete scenario must cover. The generator and its tests assert the
# labeled events span at least these, so the corpus always exercises the full
# attack lifecycle the PRD calls out.
REQUIRED_STAGES: frozenset[str] = frozenset(
    {
        "initial_access",
        "command_and_control",
        "persistence",
        "credential_access",
        "lateral_movement",
        "collection",
        "exfiltration",
    }
)

SECURITY = "Security"
SYSTEM = "System"
SYSMON = "Microsoft-Windows-Sysmon/Operational"


@dataclass(frozen=True)
class ScenarioEvent:
    """One synthetic Windows event, before any seed-driven rendering.

    ``event_data`` is the record's EventData (or UserData) under the original field
    names, in record order. ``principal``, ``action``, and ``object`` are the
    canonical values the pipeline must derive from it. ``rule_tags`` are the ATT&CK
    ids the detection rule that fired on it carries, exactly as a rule would write
    them (possibly a revoked id); ``technique_ids`` are the ground-truth labels in
    the current ATT&CK release. An event with no ``technique_ids`` is benign: it is
    in the timeline, but it is not a labeled ground-truth event.
    """

    label_id: str
    stage: str
    offset_seconds: int
    computer: str
    channel: str
    win_event_id: int
    level: str
    rule_title: str
    event_data: tuple[tuple[str, str], ...]
    principal: str | None
    action: str
    object: str | None
    message: str
    technique_ids: tuple[str, ...] = ()
    rule_tags: tuple[str, ...] = ()
    # When set, the named synthetic hash is added to the event as Sysmon's Hashes
    # field, and to the ground-truth IOC set, from the same seed-derived value.
    hash_ioc: str | None = None

    @property
    def is_labeled(self) -> bool:
        """True when this event is a ground-truth labeled event (has techniques)."""
        return bool(self.technique_ids)

    def datetime_utc(self) -> datetime:
        """The canonical UTC instant for this event."""
        return SCENARIO_START_UTC + timedelta(seconds=self.offset_seconds)


@dataclass(frozen=True)
class Scenario:
    """A complete scenario: ordered events plus the entities they reference."""

    name: str
    description: str
    hosts: tuple[str, ...]
    principals: tuple[str, ...]
    ip_iocs: tuple[str, ...]
    domain_iocs: tuple[str, ...]
    file_iocs: tuple[str, ...]
    # Named hashes: each becomes a synthetic, seed-derived SHA-256, so different
    # seeds yield different hashes while the same seed is reproducible.
    hash_iocs: tuple[str, ...]
    events: tuple[ScenarioEvent, ...] = field(default_factory=tuple)

    def labeled_events(self) -> tuple[ScenarioEvent, ...]:
        """The ground-truth labeled events, in chronological order."""
        return tuple(event for event in self.ordered_events() if event.is_labeled)

    def ordered_events(self) -> tuple[ScenarioEvent, ...]:
        """Every event, benign and malicious, in chronological order."""
        return tuple(sorted(self.events, key=lambda event: event.offset_seconds))


# A truncated, inert placeholder standing in for a base64 encoded command. It is
# deliberately not decodable to anything: no working payload ships here.
_INERT_ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"

_WORKSTATION = "WIN-ACCT-07"
_SERVER = "WIN-FILE-02"
_DOMAIN = "CORP"
_USER = "jdoe"
_SVC = "svc-backup"
_ADMIN = "it-admin"
_SYSTEM_DOMAIN = "NT AUTHORITY"
_WS_IP = "10.4.12.66"
_SERVER_IP = "10.4.20.5"
_ADMIN_IP = "10.4.30.12"
_INTRANET_IP = "198.51.100.20"
_C2_IP = "203.0.113.77"
_C2_DOMAIN = "sync-update.example"
_INTRANET_DOMAIN = "intranet.example"
_USER_SID = "S-1-5-21-1111111111-2222222222-3333333333-1104"
_SVC_SID = "S-1-5-21-1111111111-2222222222-3333333333-1188"
_ADMIN_SID = "S-1-5-21-1111111111-2222222222-3333333333-1021"
_SYSTEM_SID = "S-1-5-18"
_POWERSHELL = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
_WINWORD = "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"
_CHROME = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"
_ONEDRIVE = "C:\\Users\\jdoe\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe"
_DEFENDER = "C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\4.18.24090.11-0\\MsMpEng.exe"
_LSASS = "C:\\Windows\\System32\\lsass.exe"
_IMPLANT_PATH = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\updater.exe"
_SVC_BINARY = "C:\\Windows\\Temp\\winhelpsvc.exe"
_ARCHIVE_PATH = "C:\\Windows\\Temp\\backup.7z"
_RUN_KEY = f"HKU\\{_USER_SID}\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
_USER_QUALIFIED = f"{_DOMAIN}\\{_USER}"
_SVC_QUALIFIED = f"{_DOMAIN}\\{_SVC}"
_ADMIN_QUALIFIED = f"{_DOMAIN}\\{_ADMIN}"
_SYSTEM_QUALIFIED = f"{_SYSTEM_DOMAIN}\\SYSTEM"


def _subject(user: str, domain: str, sid: str, logon_id: str) -> tuple[tuple[str, str], ...]:
    """The Security log's Subject block."""
    return (
        ("SubjectUserSid", sid),
        ("SubjectUserName", user),
        ("SubjectDomainName", domain),
        ("SubjectLogonId", logon_id),
    )


def _logon(
    label_id: str,
    offset: int,
    computer: str,
    *,
    user: str,
    domain: str,
    sid: str,
    logon_type: str,
    ip: str,
    workstation: str,
    process: str,
    package: str,
    level: str = "info",
    title: str = "Logon",
    stage: str = "benign",
    technique_ids: tuple[str, ...] = (),
    rule_tags: tuple[str, ...] = (),
) -> ScenarioEvent:
    """A Security 4624 successful logon."""
    return ScenarioEvent(
        label_id=label_id,
        stage=stage,
        offset_seconds=offset,
        computer=computer,
        channel=SECURITY,
        win_event_id=4624,
        level=level,
        rule_title=title,
        event_data=(
            ("SubjectUserSid", _SYSTEM_SID),
            ("SubjectUserName", f"{computer}$"),
            ("SubjectDomainName", _DOMAIN),
            ("SubjectLogonId", "0x3e7"),
            ("TargetUserSid", sid),
            ("TargetUserName", user),
            ("TargetDomainName", domain),
            ("TargetLogonId", f"0x{_stable_number(label_id) % 0xFFFFFF:x}"),
            ("LogonType", logon_type),
            ("AuthenticationPackageName", package),
            ("WorkstationName", workstation),
            ("ProcessName", process),
            ("IpAddress", ip),
        ),
        principal=f"{domain}\\{user}",
        action="logon",
        object=None if ip in ("-", "") else ip,
        message=f"Logon type {logon_type} for {domain}\\{user} on {computer}",
        technique_ids=technique_ids,
        rule_tags=rule_tags,
    )


def _stable_number(text: str) -> int:
    """A small, stable integer derived from text, for synthetic identifiers.

    Deterministic across runs and platforms (Python's built-in ``hash`` is salted per
    process, so it cannot be used for reproducible evidence).
    """
    value = 0
    for char in text:
        value = (value * 131 + ord(char)) % 0xFFFFFFF
    return value


def _special_privileges(label_id: str, offset: int, computer: str) -> ScenarioEvent:
    """A Security 4672 special-privileges assignment to SYSTEM (unmapped: action other)."""
    return ScenarioEvent(
        label_id=label_id,
        stage="benign",
        offset_seconds=offset,
        computer=computer,
        channel=SECURITY,
        win_event_id=4672,
        level="info",
        rule_title="Admin Logon",
        event_data=(
            ("SubjectUserSid", _SYSTEM_SID),
            ("SubjectUserName", "SYSTEM"),
            ("SubjectDomainName", _SYSTEM_DOMAIN),
            ("SubjectLogonId", "0x3e7"),
            ("PrivilegeList", "SeAssignPrimaryTokenPrivilege SeTcbPrivilege SeDebugPrivilege"),
        ),
        principal=None,
        action="other",
        object=None,
        message=f"Special privileges assigned to SYSTEM on {computer}",
    )


def _service_state(
    label_id: str, offset: int, computer: str, service: str, state: str
) -> ScenarioEvent:
    """A System 7036 service state change."""
    return ScenarioEvent(
        label_id=label_id,
        stage="benign",
        offset_seconds=offset,
        computer=computer,
        channel=SYSTEM,
        win_event_id=7036,
        level="info",
        rule_title="Service State Changed",
        event_data=(("param1", service), ("param2", state)),
        principal=None,
        action="service_control",
        object=service,
        message=f"{service} entered the {state} state",
    )


def _sysmon_process(
    label_id: str,
    offset: int,
    computer: str,
    *,
    image: str,
    command_line: str,
    parent_image: str,
    user: str,
    pid: str,
    level: str = "info",
    title: str = "Proc Exec",
    stage: str = "benign",
    technique_ids: tuple[str, ...] = (),
    rule_tags: tuple[str, ...] = (),
    hash_ioc: str | None = None,
    message: str = "",
) -> ScenarioEvent:
    """A Sysmon 1 process creation."""
    return ScenarioEvent(
        label_id=label_id,
        stage=stage,
        offset_seconds=offset,
        computer=computer,
        channel=SYSMON,
        win_event_id=1,
        level=level,
        rule_title=title,
        event_data=(
            ("RuleName", "-"),
            ("ProcessId", pid),
            ("Image", image),
            ("CommandLine", command_line),
            ("CurrentDirectory", "C:\\Windows\\system32\\"),
            ("User", user),
            ("IntegrityLevel", "Medium" if user == _USER_QUALIFIED else "High"),
            ("ParentImage", parent_image),
        ),
        principal=user,
        action="process_create",
        object=image,
        message=message or f"{image.rsplit(chr(92), 1)[-1]} started on {computer}",
        technique_ids=technique_ids,
        rule_tags=rule_tags,
        hash_ioc=hash_ioc,
    )


def _sysmon_connect(
    label_id: str,
    offset: int,
    computer: str,
    *,
    image: str,
    user: str,
    source_ip: str,
    destination_ip: str,
    destination_host: str,
    port: str,
    level: str = "info",
    title: str = "Net Conn",
    stage: str = "benign",
    technique_ids: tuple[str, ...] = (),
    rule_tags: tuple[str, ...] = (),
    message: str = "",
) -> ScenarioEvent:
    """A Sysmon 3 outbound network connection."""
    return ScenarioEvent(
        label_id=label_id,
        stage=stage,
        offset_seconds=offset,
        computer=computer,
        channel=SYSMON,
        win_event_id=3,
        level=level,
        rule_title=title,
        event_data=(
            ("RuleName", "-"),
            ("ProcessId", str(4000 + _stable_number(label_id) % 4000)),
            ("Image", image),
            ("User", user),
            ("Protocol", "tcp"),
            ("Initiated", "true"),
            ("SourceIp", source_ip),
            ("SourcePort", str(49152 + _stable_number(label_id) % 16000)),
            ("DestinationIp", destination_ip),
            ("DestinationHostname", destination_host),
            ("DestinationPort", port),
        ),
        principal=user,
        action="network_connect",
        object=f"{destination_ip}:{port}",
        message=message or f"{image.rsplit(chr(92), 1)[-1]} connected to {destination_host}",
        technique_ids=technique_ids,
        rule_tags=rule_tags,
    )


_ATTACK: tuple[ScenarioEvent, ...] = (
    # 1. Initial access: Word spawns an encoded PowerShell.
    ScenarioEvent(
        label_id="ia-office-spawn-powershell",
        stage="initial_access",
        offset_seconds=0,  # 08:42:17Z
        computer=_WORKSTATION,
        channel=SECURITY,
        win_event_id=4688,
        level="high",
        rule_title="Office Application Spawned PowerShell (Possible Phishing Macro)",
        event_data=(
            *_subject(_USER, _DOMAIN, _USER_SID, "0x3e7a91"),
            ("NewProcessId", "0x1a2c"),
            ("NewProcessName", _POWERSHELL),
            ("TokenElevationType", "%%1938"),
            ("ProcessId", "0x105c"),
            ("CommandLine", f"powershell.exe -nop -w hidden -enc {_INERT_ENC}"),
            ("ParentProcessName", _WINWORD),
        ),
        principal=_USER_QUALIFIED,
        action="process_create",
        object=_POWERSHELL,
        message="winword.exe spawned powershell.exe with an encoded command",
        technique_ids=("T1566.001", "T1059.001"),
        rule_tags=("T1566.001", "T1059.001"),
    ),
    # 2. Command and control: PowerShell pulls a stager over HTTPS.
    _sysmon_connect(
        "c2-stager-download",
        48,  # 08:43:05Z
        _WORKSTATION,
        image=_POWERSHELL,
        user=_USER_QUALIFIED,
        source_ip=_WS_IP,
        destination_ip=_C2_IP,
        destination_host=_C2_DOMAIN,
        port="443",
        level="high",
        title="PowerShell Network Connection to Rare External Host",
        stage="command_and_control",
        technique_ids=("T1071.001", "T1105"),
        rule_tags=("T1071.001", "T1105"),
        message=f"powershell.exe connected to {_C2_DOMAIN} to retrieve a stager",
    ),
    # 3a. Persistence: a Run key points at the implant.
    ScenarioEvent(
        label_id="persist-run-key",
        stage="persistence",
        offset_seconds=133,  # 08:44:30Z
        computer=_WORKSTATION,
        channel=SYSMON,
        win_event_id=13,
        level="high",
        rule_title="Autorun Registry Run Key Set to User AppData Executable",
        event_data=(
            ("RuleName", "-"),
            ("EventType", "SetValue"),
            ("ProcessId", "7212"),
            ("Image", "C:\\Windows\\System32\\reg.exe"),
            ("TargetObject", f"{_RUN_KEY}\\Updater"),
            ("Details", _IMPLANT_PATH),
            ("User", _USER_QUALIFIED),
        ),
        principal=_USER_QUALIFIED,
        action="registry_set",
        object=f"{_RUN_KEY}\\Updater",
        message="Run key Updater set to launch the implant at logon",
        technique_ids=("T1547.001",),
        rule_tags=("T1547.001",),
    ),
    # 3b. Persistence: a scheduled task also relaunches the implant.
    ScenarioEvent(
        label_id="persist-scheduled-task",
        stage="persistence",
        offset_seconds=173,  # 08:45:10Z
        computer=_WORKSTATION,
        channel=SECURITY,
        win_event_id=4698,
        level="high",
        rule_title="Scheduled Task Created Pointing at User AppData Executable",
        event_data=(
            *_subject(_USER, _DOMAIN, _USER_SID, "0x3e7a91"),
            ("TaskName", "\\MicrosoftUpdaterTask"),
            (
                "TaskContent",
                f"<Task><Triggers><LogonTrigger/></Triggers><Actions><Exec>"
                f"<Command>{_IMPLANT_PATH}</Command></Exec></Actions></Task>",
            ),
        ),
        principal=_USER_QUALIFIED,
        action="scheduled_task_create",
        object="\\MicrosoftUpdaterTask",
        message="Scheduled task MicrosoftUpdaterTask created to run the implant",
        technique_ids=("T1053.005",),
        rule_tags=("T1053.005",),
    ),
    # 4. Credential access: the implant reads LSASS memory.
    ScenarioEvent(
        label_id="cred-lsass-access",
        stage="credential_access",
        offset_seconds=365,  # 08:48:22Z
        computer=_WORKSTATION,
        channel=SYSMON,
        win_event_id=10,
        level="crit",
        rule_title="LSASS Memory Access from Unsigned Process",
        event_data=(
            ("RuleName", "-"),
            ("SourceProcessId", "7300"),
            ("SourceImage", _IMPLANT_PATH),
            ("TargetProcessId", "684"),
            ("TargetImage", _LSASS),
            ("GrantedAccess", "0x1410"),
            ("CallTrace", "C:\\Windows\\SYSTEM32\\ntdll.dll+9d2e4"),
            ("SourceUser", _USER_QUALIFIED),
            ("TargetUser", _SYSTEM_QUALIFIED),
        ),
        principal=_USER_QUALIFIED,
        action="process_access",
        object=_LSASS,
        message="updater.exe opened lsass.exe with memory-read access",
        technique_ids=("T1003.001",),
        rule_tags=("T1003.001",),
    ),
    # 5a. Lateral movement: a network logon to the file server with a stolen domain
    # service account. A bare 4624 evidences valid-account reuse, not a specific
    # remote-service protocol, so it is labeled Valid Accounts: Domain Accounts.
    _logon(
        "lateral-network-logon",
        766,  # 08:55:03Z
        _SERVER,
        user=_SVC,
        domain=_DOMAIN,
        sid=_SVC_SID,
        logon_type="3",
        ip=_WS_IP,
        workstation=_WORKSTATION,
        process="-",
        package="NTLM",
        level="high",
        title="Network Logon with Stolen Service Account Credentials",
        stage="lateral_movement",
        technique_ids=("T1078.002",),
        rule_tags=("T1078.002",),
    ),
    # 5b. Lateral movement: the ADMIN$ share is mounted from the workstation.
    ScenarioEvent(
        label_id="lateral-admin-share",
        stage="lateral_movement",
        offset_seconds=786,  # 08:55:23Z
        computer=_SERVER,
        channel=SECURITY,
        win_event_id=5140,
        level="high",
        rule_title="Administrative Share Access from Remote Host",
        event_data=(
            *_subject(_SVC, _DOMAIN, _SVC_SID, "0x8f2a31"),
            ("ObjectType", "File"),
            ("IpAddress", _WS_IP),
            ("IpPort", "51022"),
            ("ShareName", "\\\\*\\ADMIN$"),
            ("ShareLocalPath", "\\??\\C:\\Windows"),
            ("AccessMask", "0x1"),
        ),
        principal=_SVC_QUALIFIED,
        action="network_share_access",
        object="\\\\*\\ADMIN$",
        message=f"ADMIN$ share on {_SERVER} accessed from {_WS_IP}",
        technique_ids=("T1021.002",),
        rule_tags=("T1021.002",),
    ),
    # 5c. Lateral movement: a remote service is installed on the file server...
    ScenarioEvent(
        label_id="lateral-remote-service",
        stage="lateral_movement",
        offset_seconds=863,  # 08:56:40Z
        computer=_SERVER,
        channel=SYSTEM,
        win_event_id=7045,
        level="crit",
        rule_title="Service Installed from World-Writable Temp Path",
        event_data=(
            ("ServiceName", "WinHelpSvc"),
            ("ImagePath", _SVC_BINARY),
            ("ServiceType", "user mode service"),
            ("StartType", "auto start"),
            ("AccountName", "LocalSystem"),
        ),
        principal=None,
        action="service_install",
        object="WinHelpSvc",
        message=f"Service WinHelpSvc installed on {_SERVER} from a Temp path",
        technique_ids=("T1543.003",),
        rule_tags=("T1543.003",),
    ),
    # 5d. ...and runs, started by the Service Control Manager.
    _sysmon_process(
        "lateral-service-exec",
        866,  # 08:56:43Z
        _SERVER,
        image=_SVC_BINARY,
        command_line=_SVC_BINARY,
        parent_image="C:\\Windows\\System32\\services.exe",
        user=_SYSTEM_QUALIFIED,
        pid="5480",
        level="high",
        title="Service Binary Executed from Temp Directory",
        stage="lateral_movement",
        technique_ids=("T1569.002",),
        rule_tags=("T1569.002",),
        hash_ioc="service_binary",
        message="winhelpsvc.exe started by the Service Control Manager",
    ),
    # 6a. Collection: data staged into a single archive.
    ScenarioEvent(
        label_id="collect-archive",
        stage="collection",
        offset_seconds=1198,  # 09:02:15Z
        computer=_SERVER,
        channel=SECURITY,
        win_event_id=4688,
        level="high",
        rule_title="Archive Utility Compressing Share Contents to Temp",
        event_data=(
            *_subject(_SVC, _DOMAIN, _SVC_SID, "0x8f2a31"),
            ("NewProcessId", "0x2210"),
            ("NewProcessName", "C:\\Program Files\\7-Zip\\7z.exe"),
            ("TokenElevationType", "%%1937"),
            ("ProcessId", "0x1f04"),
            ("CommandLine", f"7z.exe a -pREDACTED {_ARCHIVE_PATH} \\\\{_SERVER}\\Finance\\*"),
            ("ParentProcessName", "C:\\Windows\\System32\\cmd.exe"),
        ),
        principal=_SVC_QUALIFIED,
        action="process_create",
        object="C:\\Program Files\\7-Zip\\7z.exe",
        message=f"7z.exe archived the Finance share into {_ARCHIVE_PATH}",
        technique_ids=("T1560.001",),
        rule_tags=("T1560.001",),
    ),
    # 6b. Exfiltration: the archive is pushed to the outside host.
    _sysmon_connect(
        "exfil-outbound",
        1590,  # 09:08:47Z
        _SERVER,
        image="C:\\Windows\\System32\\curl.exe",
        user=_SVC_QUALIFIED,
        source_ip=_SERVER_IP,
        destination_ip=_C2_IP,
        destination_host=_C2_DOMAIN,
        port="443",
        level="crit",
        title="Large Outbound Transfer to Rare External Host",
        stage="exfiltration",
        technique_ids=("T1041",),
        rule_tags=("T1041",),
        message=f"curl.exe on {_SERVER} sent the archive to {_C2_IP}",
    ),
    # 7. Defense impairment: the Security log is cleared. The detection rule still
    # carries the ATT&CK 18 id T1070.001, which ATT&CK 19 revoked into T1685.005: the
    # pipeline must translate it, and the label is the current id.
    ScenarioEvent(
        label_id="impair-log-clear",
        stage="defense_impairment",
        offset_seconds=1680,  # 09:10:17Z
        computer=_SERVER,
        channel=SECURITY,
        win_event_id=1102,
        level="high",
        rule_title="Security Log Cleared",
        event_data=_subject(_SVC, _DOMAIN, _SVC_SID, "0x8f2a31"),
        principal=_SVC_QUALIFIED,
        action="log_clear",
        object="Security",
        message=f"The Security log on {_SERVER} was cleared",
        technique_ids=("T1685.005",),
        rule_tags=("T1070.001",),
    ),
)


_BENIGN: tuple[ScenarioEvent, ...] = (
    # The file server's morning: service logons, privileges, an administrator.
    _logon(
        "noise-server-service-logon-1",
        -1800,
        _SERVER,
        user="SYSTEM",
        domain=_SYSTEM_DOMAIN,
        sid=_SYSTEM_SID,
        logon_type="5",
        ip="-",
        workstation="-",
        process="C:\\Windows\\System32\\services.exe",
        package="Negotiate",
        title="Logon (Service)",
    ),
    _special_privileges("noise-server-privileges-1", -1799, _SERVER),
    _logon(
        "noise-admin-network-logon",
        -1200,
        _SERVER,
        user=_ADMIN,
        domain=_DOMAIN,
        sid=_ADMIN_SID,
        logon_type="3",
        ip=_ADMIN_IP,
        workstation="IT-ADMIN-01",
        process="-",
        package="Kerberos",
        title="Logon (Network)",
    ),
    ScenarioEvent(
        label_id="noise-admin-ipc-share",
        stage="benign",
        offset_seconds=-1199,
        computer=_SERVER,
        channel=SECURITY,
        win_event_id=5140,
        level="info",
        rule_title="NetShare Access",
        event_data=(
            *_subject(_ADMIN, _DOMAIN, _ADMIN_SID, "0x6c1d02"),
            ("ObjectType", "File"),
            ("IpAddress", _ADMIN_IP),
            ("IpPort", "50311"),
            ("ShareName", "\\\\*\\IPC$"),
            ("ShareLocalPath", ""),
            ("AccessMask", "0x1"),
        ),
        principal=_ADMIN_QUALIFIED,
        action="network_share_access",
        object="\\\\*\\IPC$",
        message="IPC$ accessed by the administrator's workstation",
    ),
    _sysmon_process(
        "noise-admin-powershell",
        -1150,
        _SERVER,
        image=_POWERSHELL,
        command_line=f"{_POWERSHELL} -NoProfile -File C:\\Scripts\\Rotate-Logs.ps1",
        parent_image="C:\\Windows\\System32\\wsmprovhost.exe",
        user=_ADMIN_QUALIFIED,
        pid="3920",
        message="The administrator's log rotation script ran in PowerShell",
    ),
    ScenarioEvent(
        label_id="noise-edge-update-service",
        stage="benign",
        offset_seconds=-500,
        computer=_SERVER,
        channel=SYSTEM,
        win_event_id=7045,
        level="info",
        rule_title="Svc Installed",
        event_data=(
            ("ServiceName", "edgeupdate"),
            (
                "ImagePath",
                '"C:\\Program Files (x86)\\Microsoft\\EdgeUpdate\\MicrosoftEdgeUpdate.exe" /svc',
            ),
            ("ServiceType", "user mode service"),
            ("StartType", "auto start"),
            ("AccountName", "LocalSystem"),
        ),
        principal=None,
        action="service_install",
        object="edgeupdate",
        message="The Microsoft Edge updater service was installed",
    ),
    _service_state("noise-edge-update-running", -499, _SERVER, "edgeupdate", "running"),
    _service_state("noise-defender-running", 1063, _SERVER, "WinDefend", "running"),
    ScenarioEvent(
        label_id="noise-server-dns",
        stage="benign",
        offset_seconds=1300,
        computer=_SERVER,
        channel=SYSMON,
        win_event_id=22,
        level="info",
        rule_title="DNS Query",
        event_data=(
            ("RuleName", "-"),
            ("ProcessId", "1288"),
            ("QueryName", _INTRANET_DOMAIN),
            ("QueryResults", f"::ffff:{_INTRANET_IP};"),
            ("Image", "C:\\Windows\\System32\\svchost.exe"),
            ("User", _SYSTEM_QUALIFIED),
        ),
        principal=_SYSTEM_QUALIFIED,
        action="dns_query",
        object=_INTRANET_DOMAIN,
        message=f"svchost.exe resolved {_INTRANET_DOMAIN}",
    ),
    _logon(
        "noise-server-service-logon-2",
        2000,
        _SERVER,
        user="SYSTEM",
        domain=_SYSTEM_DOMAIN,
        sid=_SYSTEM_SID,
        logon_type="5",
        ip="-",
        workstation="-",
        process="C:\\Windows\\System32\\services.exe",
        package="Negotiate",
        title="Logon (Service)",
    ),
    # The workstation's morning: boot services, the user arriving, ordinary work.
    _logon(
        "noise-ws-service-logon-1",
        -1500,
        _WORKSTATION,
        user="SYSTEM",
        domain=_SYSTEM_DOMAIN,
        sid=_SYSTEM_SID,
        logon_type="5",
        ip="-",
        workstation="-",
        process="C:\\Windows\\System32\\services.exe",
        package="Negotiate",
        title="Logon (Service)",
    ),
    _special_privileges("noise-ws-privileges-1", -1499, _WORKSTATION),
    _service_state("noise-ws-wuauserv-running", -1300, _WORKSTATION, "Windows Update", "running"),
    ScenarioEvent(
        label_id="noise-ws-failed-logon",
        stage="benign",
        offset_seconds=-752,
        computer=_WORKSTATION,
        channel=SECURITY,
        win_event_id=4625,
        level="low",
        rule_title="Logon Failure (Wrong Password)",
        event_data=(
            ("TargetUserSid", "S-1-0-0"),
            ("TargetUserName", _USER),
            ("TargetDomainName", _DOMAIN),
            ("Status", "0xc000006d"),
            ("SubStatus", "0xc000006a"),
            ("LogonType", "2"),
            ("AuthenticationPackageName", "Negotiate"),
            ("WorkstationName", _WORKSTATION),
            ("ProcessName", "C:\\Windows\\System32\\svchost.exe"),
            ("IpAddress", "127.0.0.1"),
        ),
        principal=_USER_QUALIFIED,
        action="logon_failure",
        object="127.0.0.1",
        message="The user mistyped their password at the lock screen",
    ),
    _logon(
        "noise-morning-logon",
        -732,
        _WORKSTATION,
        user=_USER,
        domain=_DOMAIN,
        sid=_USER_SID,
        logon_type="2",
        ip="127.0.0.1",
        workstation=_WORKSTATION,
        process="C:\\Windows\\System32\\svchost.exe",
        package="Negotiate",
        title="Logon (Interactive)",
    ),
    _sysmon_process(
        "noise-explorer",
        -700,
        _WORKSTATION,
        image="C:\\Windows\\explorer.exe",
        command_line="C:\\Windows\\Explorer.EXE",
        parent_image="C:\\Windows\\System32\\userinit.exe",
        user=_USER_QUALIFIED,
        pid="4412",
    ),
    ScenarioEvent(
        label_id="noise-onedrive-autostart",
        stage="benign",
        offset_seconds=-690,
        computer=_WORKSTATION,
        channel=SYSMON,
        win_event_id=13,
        level="info",
        rule_title="Reg Key Value Set",
        event_data=(
            ("RuleName", "-"),
            ("EventType", "SetValue"),
            ("ProcessId", "5208"),
            ("Image", _ONEDRIVE),
            ("TargetObject", f"{_RUN_KEY}\\OneDrive"),
            ("Details", f'"{_ONEDRIVE}" /background'),
            ("User", _USER_QUALIFIED),
        ),
        principal=_USER_QUALIFIED,
        action="registry_set",
        object=f"{_RUN_KEY}\\OneDrive",
        message="OneDrive refreshed its own autostart entry",
    ),
    _sysmon_process(
        "noise-chrome",
        -600,
        _WORKSTATION,
        image=_CHROME,
        command_line=f'"{_CHROME}"',
        parent_image="C:\\Windows\\explorer.exe",
        user=_USER_QUALIFIED,
        pid="6120",
    ),
    ScenarioEvent(
        label_id="noise-chrome-dns",
        stage="benign",
        offset_seconds=-590,
        computer=_WORKSTATION,
        channel=SYSMON,
        win_event_id=22,
        level="info",
        rule_title="DNS Query",
        event_data=(
            ("RuleName", "-"),
            ("ProcessId", "6120"),
            ("QueryName", _INTRANET_DOMAIN),
            ("QueryResults", f"::ffff:{_INTRANET_IP};"),
            ("Image", _CHROME),
            ("User", _USER_QUALIFIED),
        ),
        principal=_USER_QUALIFIED,
        action="dns_query",
        object=_INTRANET_DOMAIN,
        message=f"chrome.exe resolved {_INTRANET_DOMAIN}",
    ),
    _sysmon_connect(
        "noise-chrome-intranet",
        -589,
        _WORKSTATION,
        image=_CHROME,
        user=_USER_QUALIFIED,
        source_ip=_WS_IP,
        destination_ip=_INTRANET_IP,
        destination_host=_INTRANET_DOMAIN,
        port="443",
    ),
    _sysmon_process(
        "noise-winword-opens-document",
        -400,
        _WORKSTATION,
        image=_WINWORD,
        command_line=f'"{_WINWORD}" /n "C:\\Users\\jdoe\\Downloads\\Q1-invoice.docm"',
        parent_image="C:\\Windows\\explorer.exe",
        user=_USER_QUALIFIED,
        pid="4188",
        message="Word opened Q1-invoice.docm from the Downloads folder",
    ),
    ScenarioEvent(
        label_id="noise-defender-lsass-scan",
        stage="benign",
        offset_seconds=-300,
        computer=_WORKSTATION,
        channel=SYSMON,
        win_event_id=10,
        level="info",
        rule_title="Proc Access",
        event_data=(
            ("RuleName", "-"),
            ("SourceProcessId", "3072"),
            ("SourceImage", _DEFENDER),
            ("TargetProcessId", "684"),
            ("TargetImage", _LSASS),
            ("GrantedAccess", "0x1000"),
            ("SourceUser", _SYSTEM_QUALIFIED),
            ("TargetUser", _SYSTEM_QUALIFIED),
        ),
        principal=_SYSTEM_QUALIFIED,
        action="process_access",
        object=_LSASS,
        message="Microsoft Defender opened lsass.exe during a scan",
    ),
    _service_state(
        "noise-ws-bits-running",
        600,
        _WORKSTATION,
        "Background Intelligent Transfer Service",
        "running",
    ),
    ScenarioEvent(
        label_id="noise-ws-maintenance-task",
        stage="benign",
        offset_seconds=900,
        computer=_WORKSTATION,
        channel=SECURITY,
        win_event_id=4698,
        level="info",
        rule_title="Task Created",
        event_data=(
            *_subject(f"{_WORKSTATION}$", _DOMAIN, _SYSTEM_SID, "0x3e7"),
            ("TaskName", "\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan"),
            (
                "TaskContent",
                "<Task><Actions><Exec><Command>%systemroot%\\system32\\usoclient.exe"
                "</Command><Arguments>StartScan</Arguments></Exec></Actions></Task>",
            ),
        ),
        principal=f"{_DOMAIN}\\{_WORKSTATION}$",
        action="scheduled_task_create",
        object="\\Microsoft\\Windows\\UpdateOrchestrator\\Schedule Scan",
        message="Windows Update registered its scheduled scan task",
    ),
    _logon(
        "noise-ws-service-logon-2",
        1500,
        _WORKSTATION,
        user="SYSTEM",
        domain=_SYSTEM_DOMAIN,
        sid=_SYSTEM_SID,
        logon_type="5",
        ip="-",
        workstation="-",
        process="C:\\Windows\\System32\\services.exe",
        package="Negotiate",
        title="Logon (Service)",
    ),
)


OFFICE_INTRUSION = Scenario(
    name="office_intrusion",
    description=(
        "A multi-stage intrusion on a workstation and a file server: a phishing macro "
        "spawns PowerShell, which pulls a stager, persists through a Run key and a "
        "scheduled task, and reads LSASS; a stolen service account then reaches the "
        "file server over SMB, installs and runs a service, archives and exfiltrates "
        "the Finance share, and clears the Security log. Benign activity surrounds it."
    ),
    hosts=(_WORKSTATION, _SERVER),
    principals=(_USER_QUALIFIED, _SVC_QUALIFIED),
    # Every declared indicator must be recoverable from the evidence;
    # test_declared_network_and_file_iocs_appear_in_evidence enforces it.
    ip_iocs=(_WS_IP, _C2_IP),
    domain_iocs=(_C2_DOMAIN,),
    file_iocs=(_IMPLANT_PATH, _SVC_BINARY, _ARCHIVE_PATH),
    hash_iocs=("service_binary",),
    events=_ATTACK + _BENIGN,
)
