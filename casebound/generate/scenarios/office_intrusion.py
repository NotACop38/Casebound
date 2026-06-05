"""The "office_intrusion" ground-truth scenario (PRD Section 12, FR33).

A small, multi-stage synthetic intrusion that exercises the whole pipeline on one
believable chain of activity:

  1. Initial access: a phishing macro spawns an encoded PowerShell from Word.
  2. Command and control: PowerShell pulls a stager over HTTPS.
  3. Persistence: a Run key and a scheduled task both point at the implant.
  4. Credential access: the implant reads LSASS memory.
  5. Lateral movement: a network logon and a remote service install on a server.
  6. Collection and exfiltration: data is archived and pushed to an outside host.

Everything here is synthetic and safe (Hard rule 3). Hosts are lab names,
principals are a fictional CORP domain, the external endpoint uses the RFC 5737
documentation range 203.0.113.0/24, internal endpoints use RFC 1918 space, the
one domain uses the reserved ``.example`` TLD (RFC 2606), and no command line is
a working payload (the encoded blob is a truncated, inert placeholder).

The scenario is the source of truth for the ground-truth labels: every event that
carries one or more ``technique_ids`` becomes a labeled ground-truth event, and
the deterministic ATT&CK tagger is later measured against exactly these labels.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

# The scenario clock. The first event is anchored in UTC; every later event is an
# offset from it. The Hayabusa-style CSV renders timestamps in the analyst's
# local zone (here US Eastern, which is UTC-4 on this March date because daylight
# time is in effect), while the ground truth records the canonical UTC instant.
SCENARIO_START_UTC = datetime(2026, 3, 14, 8, 42, 17, tzinfo=UTC)
OUTPUT_TIMEZONE = "America/New_York"
OUTPUT_UTC_OFFSET = timedelta(hours=-4)
OUTPUT_OFFSET_LABEL = "-04:00"

# The stages a complete scenario must cover. The generator and its tests assert
# the labeled events span at least these, so the corpus always exercises the full
# attack lifecycle the PRD calls out.
REQUIRED_STAGES: frozenset[str] = frozenset(
    {
        "initial_access",
        "persistence",
        "credential_access",
        "lateral_movement",
        "collection",
        "exfiltration",
    }
)


@dataclass(frozen=True)
class ScenarioEvent:
    """One synthetic event in a scenario, before any seed-driven rendering.

    The fields split into three groups:

    - Provenance and presentation, rendered into the Hayabusa-style CSV row:
      ``computer``, ``channel``, ``win_event_id``, ``level``, ``rule_title``,
      ``mitre_tactics``, and the ordered ``details`` key/value pairs.
    - Ground-truth identity, used to label the event for the metrics:
      ``label_id``, ``stage``, ``action``, ``object``, ``principal``,
      ``technique_ids``, and ``message``.
    - Timing: ``offset_seconds`` from the scenario start.

    An event with no ``technique_ids`` is benign background noise: it appears in
    the CSV (so the tagger has false-positive opportunities and precision is
    measurable) but is not a labeled ground-truth event.
    """

    label_id: str
    stage: str
    offset_seconds: int
    computer: str
    channel: str
    win_event_id: int
    level: str
    rule_title: str
    principal: str
    action: str
    object: str
    message: str
    mitre_tactics: tuple[str, ...] = ()
    technique_ids: tuple[str, ...] = ()
    details: tuple[tuple[str, str], ...] = ()
    # When set, the named IOC hash is spliced into the details and the IOC set so
    # the same seed-derived value appears in both the CSV and the ground truth.
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
    # Named hashes: each maps a logical artifact to a short seed input. The
    # generator turns each into a synthetic SHA-256 so different seeds yield
    # different hashes while the same seed is reproducible.
    hash_iocs: tuple[str, ...]
    events: tuple[ScenarioEvent, ...] = field(default_factory=tuple)

    def labeled_events(self) -> tuple[ScenarioEvent, ...]:
        """The ground-truth labeled events, in chronological order."""
        return tuple(e for e in sorted(self.events, key=lambda e: e.offset_seconds) if e.is_labeled)

    def ordered_events(self) -> tuple[ScenarioEvent, ...]:
        """Every event, benign and malicious, in chronological order."""
        return tuple(sorted(self.events, key=lambda e: e.offset_seconds))


# A truncated, inert placeholder standing in for a base64 encoded command. It is
# deliberately not decodable to anything: no working payload ships here.
_INERT_ENC = "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA"

_WORKSTATION = "WIN-ACCT-07"
_SERVER = "WIN-FILE-02"
_USER = "CORP\\jdoe"
_SVC = "CORP\\svc-backup"
_WS_IP = "10.4.12.66"
_SRV_IP = "10.4.12.40"
_C2_IP = "203.0.113.77"
_C2_DOMAIN = "sync-update.example"
_IMPLANT_PATH = "C:\\Users\\jdoe\\AppData\\Roaming\\Microsoft\\Windows\\updater.exe"
_SVC_BINARY = "C:\\Windows\\Temp\\winhelpsvc.exe"
_ARCHIVE_PATH = "C:\\Windows\\Temp\\backup.7z"


_EVENTS: tuple[ScenarioEvent, ...] = (
    # Benign morning logon, before the intrusion. Background noise for precision.
    ScenarioEvent(
        label_id="noise-morning-logon",
        stage="benign",
        offset_seconds=-732,  # 08:30:05Z
        computer=_WORKSTATION,
        channel="Security",
        win_event_id=4624,
        level="info",
        rule_title="Successful Interactive Logon",
        principal=_USER,
        action="logon",
        object=_USER,
        message="Routine interactive logon for the workstation user",
        details=(
            ("LogonType", "2"),
            ("TargetUserName", "jdoe"),
            ("TargetDomainName", "CORP"),
            ("WorkstationName", _WORKSTATION),
        ),
    ),
    # 1. Initial access: Word spawns an encoded PowerShell.
    ScenarioEvent(
        label_id="ia-office-spawn-powershell",
        stage="initial_access",
        offset_seconds=0,  # 08:42:17Z
        computer=_WORKSTATION,
        channel="Security",
        win_event_id=4688,
        level="high",
        rule_title="Office Application Spawned PowerShell (Possible Phishing Macro)",
        principal=_USER,
        action="process_create",
        object="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        message="winword.exe spawned powershell.exe with an encoded command",
        mitre_tactics=("Initial Access", "Execution"),
        technique_ids=("T1566.001", "T1059.001"),
        details=(
            ("NewProcessName", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            (
                "ParentProcessName",
                "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
            ),
            ("CommandLine", f"powershell.exe -nop -w hidden -enc {_INERT_ENC}"),
            ("SubjectUserName", "jdoe"),
            ("SubjectDomainName", "CORP"),
        ),
    ),
    # 2. Command and control: PowerShell pulls a stager over HTTPS.
    ScenarioEvent(
        label_id="c2-stager-download",
        stage="command_and_control",
        offset_seconds=48,  # 08:43:05Z
        computer=_WORKSTATION,
        channel="Microsoft-Windows-Sysmon/Operational",
        win_event_id=3,
        level="high",
        rule_title="PowerShell Network Connection to Rare External Host",
        principal=_USER,
        action="network_connect",
        object=f"{_C2_DOMAIN}:443",
        message=f"powershell.exe connected to {_C2_DOMAIN} to retrieve a stager",
        mitre_tactics=("Command and Control",),
        technique_ids=("T1071.001", "T1105"),
        details=(
            ("Image", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"),
            ("DestinationHostname", _C2_DOMAIN),
            ("DestinationIp", _C2_IP),
            ("DestinationPort", "443"),
            ("Protocol", "tcp"),
        ),
    ),
    # 3a. Persistence: a Run key points at the implant.
    ScenarioEvent(
        label_id="persist-run-key",
        stage="persistence",
        offset_seconds=133,  # 08:44:30Z
        computer=_WORKSTATION,
        channel="Microsoft-Windows-Sysmon/Operational",
        win_event_id=13,
        level="high",
        rule_title="Autorun Registry Run Key Set to User AppData Executable",
        principal=_USER,
        action="registry_set",
        object="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        message="Run key Updater set to launch the implant at logon",
        mitre_tactics=("Persistence", "Privilege Escalation"),
        technique_ids=("T1547.001",),
        details=(
            ("EventType", "SetValue"),
            (
                "TargetObject",
                "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
            ),
            ("Image", "C:\\Windows\\System32\\reg.exe"),
            ("Details", _IMPLANT_PATH),
        ),
    ),
    # 3b. Persistence: a scheduled task also relaunches the implant.
    ScenarioEvent(
        label_id="persist-scheduled-task",
        stage="persistence",
        offset_seconds=173,  # 08:45:10Z
        computer=_WORKSTATION,
        channel="Security",
        win_event_id=4698,
        level="high",
        rule_title="Scheduled Task Created Pointing at User AppData Executable",
        principal=_USER,
        action="scheduled_task_create",
        object="\\MicrosoftUpdaterTask",
        message="Scheduled task MicrosoftUpdaterTask created to run the implant",
        mitre_tactics=("Persistence", "Privilege Escalation", "Execution"),
        technique_ids=("T1053.005",),
        details=(
            ("TaskName", "\\MicrosoftUpdaterTask"),
            ("SubjectUserName", "jdoe"),
            ("Command", _IMPLANT_PATH),
            ("Trigger", "AtLogon"),
        ),
    ),
    # 4. Credential access: the implant reads LSASS memory.
    ScenarioEvent(
        label_id="cred-lsass-access",
        stage="credential_access",
        offset_seconds=365,  # 08:48:22Z
        computer=_WORKSTATION,
        channel="Microsoft-Windows-Sysmon/Operational",
        win_event_id=10,
        level="crit",
        rule_title="LSASS Memory Access from Unsigned Process",
        principal=_USER,
        action="process_access",
        object="C:\\Windows\\System32\\lsass.exe",
        message="updater.exe opened lsass.exe with memory-read access",
        mitre_tactics=("Credential Access",),
        technique_ids=("T1003.001",),
        details=(
            ("SourceImage", _IMPLANT_PATH),
            ("TargetImage", "C:\\Windows\\System32\\lsass.exe"),
            ("GrantedAccess", "0x1410"),
            ("CallTrace", "C:\\Windows\\System32\\ntdll.dll+9d2e4"),
        ),
    ),
    # 5a. Lateral movement: a network logon to the file server.
    ScenarioEvent(
        label_id="lateral-network-logon",
        stage="lateral_movement",
        offset_seconds=766,  # 08:55:03Z
        computer=_SERVER,
        channel="Security",
        win_event_id=4624,
        level="high",
        rule_title="Network Logon with Stolen Service Account Credentials",
        principal=_SVC,
        action="logon",
        object=_WS_IP,
        message=f"Network logon for {_SVC} on {_SERVER} from {_WS_IP}",
        mitre_tactics=("Lateral Movement",),
        technique_ids=("T1021.002",),
        details=(
            ("LogonType", "3"),
            ("TargetUserName", "svc-backup"),
            ("TargetDomainName", "CORP"),
            ("IpAddress", _WS_IP),
            ("AuthenticationPackageName", "NTLM"),
        ),
    ),
    # 5b. Lateral movement: a remote service install on the file server.
    ScenarioEvent(
        label_id="lateral-remote-service",
        stage="lateral_movement",
        offset_seconds=863,  # 08:56:40Z
        computer=_SERVER,
        channel="System",
        win_event_id=7045,
        level="crit",
        rule_title="Service Installed from World-Writable Temp Path",
        principal=_SVC,
        action="service_install",
        object="WinHelpSvc",
        message=f"Service WinHelpSvc installed on {_SERVER} from a Temp path",
        mitre_tactics=("Lateral Movement", "Execution", "Persistence"),
        technique_ids=("T1021.002", "T1543.003", "T1569.002"),
        details=(
            ("ServiceName", "WinHelpSvc"),
            ("ImagePath", _SVC_BINARY),
            ("ServiceType", "user mode service"),
            ("StartType", "auto start"),
        ),
        hash_ioc="service_binary",
    ),
    # Benign noise on the server: a routine signed service starting.
    ScenarioEvent(
        label_id="noise-defender-update",
        stage="benign",
        offset_seconds=1063,  # 09:00:00Z
        computer=_SERVER,
        channel="System",
        win_event_id=7036,
        level="info",
        rule_title="Service Entered Running State",
        principal="NT AUTHORITY\\SYSTEM",
        action="service_start",
        object="WinDefend",
        message="Microsoft Defender Antivirus Service entered the running state",
        details=(
            ("ServiceName", "WinDefend"),
            ("State", "running"),
        ),
    ),
    # 6a. Collection: data staged into a single archive.
    ScenarioEvent(
        label_id="collect-archive",
        stage="collection",
        offset_seconds=1198,  # 09:02:15Z
        computer=_SERVER,
        channel="Security",
        win_event_id=4688,
        level="high",
        rule_title="Archive Utility Compressing Share Contents to Temp",
        principal=_SVC,
        action="process_create",
        object=_ARCHIVE_PATH,
        message=f"7z.exe archived collected files into {_ARCHIVE_PATH}",
        mitre_tactics=("Collection",),
        technique_ids=("T1560.001",),
        details=(
            ("NewProcessName", "C:\\Program Files\\7-Zip\\7z.exe"),
            (
                "CommandLine",
                f"7z.exe a -p REDACTED {_ARCHIVE_PATH} \\\\{_SERVER}\\Finance\\*",
            ),
            ("SubjectUserName", "svc-backup"),
            ("SubjectDomainName", "CORP"),
        ),
    ),
    # 6b. Exfiltration: the archive is pushed to the outside host.
    ScenarioEvent(
        label_id="exfil-outbound",
        stage="exfiltration",
        offset_seconds=1590,  # 09:08:47Z
        computer=_SERVER,
        channel="Microsoft-Windows-Sysmon/Operational",
        win_event_id=3,
        level="crit",
        rule_title="Large Outbound Transfer to Rare External Host",
        principal=_SVC,
        action="network_connect",
        object=f"{_C2_IP}:443",
        message=f"Outbound connection from {_SERVER} to {_C2_IP} carrying the archive",
        mitre_tactics=("Exfiltration",),
        technique_ids=("T1041",),
        details=(
            ("Image", "C:\\Windows\\System32\\curl.exe"),
            ("DestinationIp", _C2_IP),
            ("DestinationHostname", _C2_DOMAIN),
            ("DestinationPort", "443"),
            ("Protocol", "tcp"),
        ),
    ),
)


OFFICE_INTRUSION = Scenario(
    name="office_intrusion",
    description=(
        "A multi-stage host intrusion: a phishing macro spawns PowerShell, which "
        "pulls a stager, persists via a Run key and a scheduled task, reads LSASS, "
        "moves laterally to a file server via a network logon and a remote service, "
        "then archives and exfiltrates collected data to an external host."
    ),
    hosts=(_WORKSTATION, _SERVER),
    principals=(_USER, _SVC),
    ip_iocs=(_WS_IP, _SRV_IP, _C2_IP),
    domain_iocs=(_C2_DOMAIN,),
    file_iocs=(_IMPLANT_PATH, _SVC_BINARY, _ARCHIVE_PATH),
    hash_iocs=("service_binary", "implant"),
    events=_EVENTS,
)
