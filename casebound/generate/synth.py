"""The synthetic evidence generator (PRD FR33).

Renders a ground-truth scenario (see ``casebound.generate.scenarios``) into the two
bundled artifacts the demo, the tests, and the evaluation run on, fully offline:

  - a Hayabusa ``csv-timeline`` in the verbose profile (the evidence the ingest
    layer consumes), and
  - a ground-truth label file (the attack events and their ATT&CK technique ids
    that the evaluation scores the tagger against).

The timeline is rendered the way Hayabusa itself prints one, so the demo exercises
the same parsing path real output takes:

  - columns in the verbose profile's order (Timestamp, Computer, Channel, EventID,
    Level, MitreTactics, MitreTags, OtherTags, RecordID, RuleTitle, Details,
    ExtraFieldInfo, RuleFile, RuleID, EvtxFile);
  - timestamps in the analyst's local zone with an explicit offset;
  - abbreviated channels (``Sec``, ``Sys``, ``Sysmon``), levels (``crit``, ``med``),
    and tactics (``InitAccess``, ``CredAccess``);
  - ``Details`` built from Hayabusa's own abbreviated templates (``Proc``,
    ``TgtUser``, ``SrcIP``), with ``n/a`` for a template field the record lacks;
  - ``ExtraFieldInfo`` listing, sorted and under original names, every field whose
    value Details did not show, exactly as Hayabusa derives it.

Determinism is a hard requirement: the same seed always yields byte-identical
output. The scenario (times, hosts, actions, techniques) is fixed data; the seed
drives only cosmetic identifiers (the EVTX record numbers and the synthetic file
hash), so a different seed gives visibly different evidence with the same labels.

Everything emitted is synthetic and safe (Hard rule 3). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import uuid
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Any

from casebound.enrich.catalog import load_catalog
from casebound.generate.scenarios import OFFICE_INTRUSION, Scenario, ScenarioEvent
from casebound.generate.scenarios.office_intrusion import (
    OUTPUT_OFFSET_LABEL,
    OUTPUT_TIMEZONE,
    OUTPUT_UTC_OFFSET,
    SECURITY,
    SYSMON,
    SYSTEM,
)

__all__ = [
    "CSV_COLUMNS",
    "CSV_FILENAME",
    "DEFAULT_SEED",
    "GROUND_TRUTH_FILENAME",
    "HAYABUSA_SEP",
    "GeneratedScenario",
    "generate",
    "write_samples",
]

# The default seed for the bundled samples. Pinned so a clean clone regenerates
# byte-identical evidence (FR34).
DEFAULT_SEED = 1337

# Hayabusa's multi-value separator: a space-padded broken bar (U+00A6).
HAYABUSA_SEP = " ¦ "

# The verbose csv-timeline profile's columns, in Hayabusa's order.
CSV_COLUMNS: tuple[str, ...] = (
    "Timestamp",
    "Computer",
    "Channel",
    "EventID",
    "Level",
    "MitreTactics",
    "MitreTags",
    "OtherTags",
    "RecordID",
    "RuleTitle",
    "Details",
    "ExtraFieldInfo",
    "RuleFile",
    "RuleID",
    "EvtxFile",
)

CSV_FILENAME = "synthetic_hayabusa.csv"
GROUND_TRUTH_FILENAME = "ground_truth.json"
GROUND_TRUTH_VERSION = "0.2"

# Hayabusa's channel abbreviations for the channels the scenario uses.
_CHANNEL_ABBREVIATIONS = {SECURITY: "Sec", SYSTEM: "Sys", SYSMON: "Sysmon"}

# Hayabusa's tactic abbreviations (config/mitre_tactics.txt), by ATT&CK shortname.
_TACTIC_ABBREVIATIONS = {
    "reconnaissance": "Recon",
    "resource-development": "ResDev",
    "initial-access": "InitAccess",
    "execution": "Exec",
    "persistence": "Persis",
    "privilege-escalation": "PrivEsc",
    "stealth": "Stealth",
    "defense-impairment": "DefImpair",
    "credential-access": "CredAccess",
    "discovery": "Disc",
    "lateral-movement": "LatMov",
    "collection": "Collect",
    "command-and-control": "C2",
    "exfiltration": "Exfil",
    "impact": "Impact",
}

# Hayabusa's Details templates for the events the scenario contains, as ordered
# (abbreviated key, EventData field) pairs, from the Hayabusa rule set's default
# details (hayabusa-rules config/default_details.txt). An event with no template
# prints every field, under its own name, in Details.
_DETAILS_TEMPLATES: dict[tuple[str, int], tuple[tuple[str, str], ...]] = {
    (SECURITY, 1102): (("User", "SubjectUserName"),),
    (SECURITY, 4624): (
        ("Type", "LogonType"),
        ("TgtUser", "TargetUserName"),
        ("SrcComp", "WorkstationName"),
        ("SrcIP", "IpAddress"),
        ("LID", "TargetLogonId"),
    ),
    (SECURITY, 4625): (
        ("Type", "LogonType"),
        ("TgtUser", "TargetUserName"),
        ("SrcComp", "WorkstationName"),
        ("SrcIP", "IpAddress"),
        ("AuthPkg", "AuthenticationPackageName"),
        ("Proc", "ProcessName"),
    ),
    (SECURITY, 4672): (("TgtUser", "SubjectUserName"), ("LID", "SubjectLogonId")),
    (SECURITY, 4688): (
        ("Cmdline", "CommandLine"),
        ("Proc", "NewProcessName"),
        ("PID", "NewProcessId"),
        ("User", "SubjectUserName"),
        ("LID", "SubjectLogonId"),
    ),
    (SECURITY, 4698): (
        ("Name", "TaskName"),
        ("Content", "TaskContent"),
        ("User", "SubjectUserName"),
        ("LID", "SubjectLogonId"),
    ),
    (SECURITY, 5140): (
        ("SrcUser", "SubjectUserName"),
        ("ShareName", "ShareName"),
        ("SharePath", "ShareLocalPath"),
        ("SrcIP", "IpAddress"),
        ("LID", "SubjectLogonId"),
    ),
    (SYSTEM, 7045): (
        ("Svc", "ServiceName"),
        ("Path", "ImagePath"),
        ("Acct", "AccountName"),
        ("StartType", "StartType"),
    ),
    (SYSMON, 1): (
        ("Cmdline", "CommandLine"),
        ("Proc", "Image"),
        ("User", "User"),
        ("ParentCmdline", "ParentCommandLine"),
        ("LID", "LogonId"),
        ("PID", "ProcessId"),
        ("Hashes", "Hashes"),
    ),
    (SYSMON, 3): (
        ("Proto", "Protocol"),
        ("SrcIP", "SourceIp"),
        ("SrcPort", "SourcePort"),
        ("TgtIP", "DestinationIp"),
        ("TgtPort", "DestinationPort"),
        ("TgtHost", "DestinationHostname"),
        ("User", "User"),
        ("Proc", "Image"),
        ("PID", "ProcessId"),
    ),
    (SYSMON, 10): (
        ("SrcProc", "SourceImage"),
        ("TgtProc", "TargetImage"),
        ("SrcUser", "SourceUser"),
        ("TgtUser", "TargetUser"),
        ("Access", "GrantedAccess"),
        ("SrcPID", "SourceProcessId"),
        ("TgtPID", "TargetProcessId"),
    ),
    (SYSMON, 13): (
        ("EventType", "EventType"),
        ("RegKey", "TargetObject"),
        ("Details", "Details"),
        ("Proc", "Image"),
        ("PID", "ProcessId"),
        ("User", "User"),
    ),
    (SYSMON, 22): (
        ("Query", "QueryName"),
        ("Result", "QueryResults"),
        ("Proc", "Image"),
        ("PID", "ProcessId"),
    ),
}

# The value Hayabusa prints for a template field the record lacks.
_MISSING = "n/a"


@dataclass(frozen=True)
class GeneratedScenario:
    """The rendered output of one generation run.

    ``csv_text`` is the Hayabusa timeline. ``ground_truth`` is the label structure
    (also available serialized as ``ground_truth_json``). ``record_ids`` maps every
    scenario event's ``label_id`` to the EVTX record id it was assigned, so callers
    can cross-reference the timeline and the labels.
    """

    seed: int
    csv_text: str
    ground_truth: dict[str, Any]
    record_ids: dict[str, str]

    @property
    def ground_truth_json(self) -> str:
        """The ground truth serialized to deterministic, human-readable JSON."""
        return json.dumps(self.ground_truth, indent=2, ensure_ascii=False) + "\n"


def _synthetic_hash(scenario_name: str, seed: int, name: str) -> str:
    """A deterministic, obviously synthetic SHA-256 for a named artifact.

    Derived from the seed so different seeds produce different hashes, while the
    same seed always reproduces the same value. It is not the hash of any file.
    """
    material = f"casebound-synth/{scenario_name}/{seed}/{name}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _local_timestamp(event: ScenarioEvent) -> str:
    """Render an event time the way Hayabusa prints it: local time plus offset."""
    local = (event.datetime_utc() + OUTPUT_UTC_OFFSET).replace(tzinfo=None)
    return f"{local:%Y-%m-%d %H:%M:%S}.000 {OUTPUT_OFFSET_LABEL}"


def _utc_iso(event: ScenarioEvent) -> str:
    """Render an event time as canonical ISO 8601 UTC with a trailing Z."""
    return f"{event.datetime_utc():%Y-%m-%dT%H:%M:%S}Z"


def _event_data(event: ScenarioEvent, hashes: dict[str, str]) -> list[tuple[str, str]]:
    """The event's fields, with its seed-derived hash spliced in when it names one."""
    fields = list(event.event_data)
    if event.hash_ioc is not None:
        fields.append(("Hashes", f"SHA256={hashes[event.hash_ioc].upper()}"))
    return fields


def _details_and_extra(
    fields: list[tuple[str, str]], template_key: tuple[str, int]
) -> tuple[str, str]:
    """Render the Details and ExtraFieldInfo columns as Hayabusa derives them."""
    template = _DETAILS_TEMPLATES.get(template_key)
    lookup = dict(fields)
    if template is None:
        pairs = sorted(f"{name}: {value}" for name, value in fields)
        return (HAYABUSA_SEP.join(pairs) if pairs else "-"), "-"
    shown = [(abbr, lookup.get(name, _MISSING)) for abbr, name in template]
    details = HAYABUSA_SEP.join(f"{abbr}: {value}" for abbr, value in shown)
    shown_values = {value for _, value in shown}
    extra = sorted(f"{name}: {value}" for name, value in fields if value not in shown_values)
    return details, (HAYABUSA_SEP.join(extra) if extra else "-")


def _tactics(rule_tags: tuple[str, ...]) -> str:
    """The abbreviated tactics of a rule's techniques, in Enterprise matrix order."""
    catalog = load_catalog()
    shortnames: set[str] = set()
    for tag in rule_tags:
        resolution = catalog.resolve(tag)
        if resolution.technique is not None:
            shortnames.update(resolution.technique.tactics)
    ordered = [t.shortname for t in catalog.tactics if t.shortname in shortnames]
    return HAYABUSA_SEP.join(_TACTIC_ABBREVIATIONS[name] for name in ordered)


def _rule_file(event: ScenarioEvent) -> str:
    """A plausible Hayabusa rule file name for the rule that fired."""
    words = re.findall(r"[A-Za-z0-9]+", event.rule_title)
    slug = "".join(word[:1].upper() + word[1:] for word in words)
    level = {"crit": "Crit", "high": "High", "med": "Med", "low": "Low", "info": "Info"}
    channel = _CHANNEL_ABBREVIATIONS[event.channel]
    return f"{channel}_{event.win_event_id}_{level[event.level]}_{slug}.yml"


def _rule_id(event: ScenarioEvent) -> str:
    """A stable, synthetic rule id derived from the rule title."""
    return str(
        uuid.uuid5(uuid.NAMESPACE_URL, f"https://rules.casebound.example/{event.rule_title}")
    )


def _evtx_file(event: ScenarioEvent) -> str:
    """The path of the EVTX file the event came from, as the collector saved it."""
    log = event.channel.replace("/", "%4")
    return f"C:\\Triage\\{event.computer}\\Logs\\{log}.evtx"


def _assign_record_ids(scenario: Scenario, rng: Random) -> dict[str, str]:
    """Assign each event a plausible, strictly increasing EVTX record id.

    Hayabusa output is sorted by time, so record ids climb with the timeline. The
    base and the gaps are seed-driven, which is what makes a different seed yield
    visibly different evidence.
    """
    record = rng.randint(10_000, 90_000)
    record_ids: dict[str, str] = {}
    for event in scenario.ordered_events():
        record += rng.randint(3, 97)
        record_ids[event.label_id] = str(record)
    return record_ids


def _render_csv(scenario: Scenario, record_ids: dict[str, str], hashes: dict[str, str]) -> str:
    """Render the scenario as a Hayabusa verbose csv-timeline."""
    buffer = io.StringIO()
    # QUOTE_ALL and a plain newline mirror Hayabusa's quoting and keep the bytes
    # identical across platforms.
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for event in scenario.ordered_events():
        details, extra = _details_and_extra(
            _event_data(event, hashes), (event.channel, event.win_event_id)
        )
        writer.writerow(
            [
                _local_timestamp(event),
                event.computer,
                _CHANNEL_ABBREVIATIONS[event.channel],
                str(event.win_event_id),
                event.level,
                _tactics(event.rule_tags) or "-",
                HAYABUSA_SEP.join(event.rule_tags) or "-",
                "sysmon" if event.channel == SYSMON else "-",
                record_ids[event.label_id],
                event.rule_title,
                details,
                extra,
                _rule_file(event),
                _rule_id(event),
                _evtx_file(event),
            ]
        )
    return buffer.getvalue()


def _build_ground_truth(
    scenario: Scenario,
    seed: int,
    record_ids: dict[str, str],
    hashes: dict[str, str],
) -> dict[str, Any]:
    """Build the ground-truth label structure the evaluation scores against."""
    labeled = scenario.labeled_events()
    events = [
        {
            "label_id": event.label_id,
            "stage": event.stage,
            "record_id": record_ids[event.label_id],
            "timestamp_utc": _utc_iso(event),
            "computer": event.computer,
            "channel": event.channel,
            "win_event_id": event.win_event_id,
            "principal": event.principal,
            "action": event.action,
            "object": event.object,
            "technique_ids": list(event.technique_ids),
            "rule_tags": list(event.rule_tags),
            "rule_title": event.rule_title,
            "message": event.message,
        }
        for event in labeled
    ]
    return {
        "scenario": scenario.name,
        "description": scenario.description,
        "version": GROUND_TRUTH_VERSION,
        "seed": seed,
        "source_csv": CSV_FILENAME,
        "source_tool": "hayabusa",
        "output_timezone": OUTPUT_TIMEZONE,
        "attack_version": load_catalog().version,
        "hosts": list(scenario.hosts),
        "principals": list(scenario.principals),
        "stages": sorted({event.stage for event in labeled}),
        "techniques": sorted({tid for event in labeled for tid in event.technique_ids}),
        "iocs": {
            "ips": list(scenario.ip_iocs),
            "domains": list(scenario.domain_iocs),
            "files": list(scenario.file_iocs),
            "hashes": [hashes[name] for name in scenario.hash_iocs],
        },
        "total_events": len(scenario.events),
        "benign_events": len(scenario.events) - len(labeled),
        "event_count": len(events),
        "events": events,
    }


def generate(scenario: Scenario = OFFICE_INTRUSION, seed: int = DEFAULT_SEED) -> GeneratedScenario:
    """Render a scenario into a Hayabusa timeline plus a ground-truth label set.

    Deterministic: the same ``scenario`` and ``seed`` always produce byte-identical
    ``csv_text`` and ``ground_truth``.
    """
    rng = Random(seed)  # nosec B311  # cosmetic ids only, never for security
    # Hashes derive from the seed directly (not the rng stream) so they do not
    # depend on how many other draws happen first.
    hashes = {name: _synthetic_hash(scenario.name, seed, name) for name in scenario.hash_iocs}
    record_ids = _assign_record_ids(scenario, rng)
    return GeneratedScenario(
        seed=seed,
        csv_text=_render_csv(scenario, record_ids, hashes),
        ground_truth=_build_ground_truth(scenario, seed, record_ids, hashes),
        record_ids=record_ids,
    )


def write_samples(
    dest_dir: Path,
    scenario: Scenario = OFFICE_INTRUSION,
    seed: int = DEFAULT_SEED,
) -> tuple[Path, Path]:
    """Generate the scenario and write both artifacts under ``dest_dir``.

    Returns the (timeline_path, ground_truth_path) written. Offline, no network.
    """
    result = generate(scenario, seed)
    dest_dir.mkdir(parents=True, exist_ok=True)
    csv_path = dest_dir / CSV_FILENAME
    ground_truth_path = dest_dir / GROUND_TRUTH_FILENAME
    csv_path.write_text(result.csv_text, encoding="utf-8")
    ground_truth_path.write_text(result.ground_truth_json, encoding="utf-8")
    return csv_path, ground_truth_path
