"""Deterministic ATT&CK tagging (PRD FR13, FR14).

Turns a normalized event into the same event with its ``attack_techniques``
filled in, using two deterministic sources and nothing else. No model is ever in
this loop: tagging is a pure function of the event's fields and the bundled
ATT&CK catalog, so the same event always yields the same tags.

Two layers, in priority order:

  1. Rule-tag passthrough (FR13). When a detection source already carried ATT&CK
     technique ids on the event (the Hayabusa and Chainsaw mappers stash them in
     ``details["rule_mitre_tags"]``), those are promoted to ``attack_techniques``
     with ``mapping_source = "rule_tag"``. Each id is resolved against the bundled
     catalog first: an id MITRE has revoked is replaced by its current successor
     and the original is kept as ``source_id``, so a rule written against an older
     ATT&CK release still lands on today's matrix. Strings that are not technique
     ids at all (group or software ids such as ``G0016``, tactic names) are
     ignored rather than guessed at.

  2. Mapping table (FR14). An event from a source with no detection layer (raw
     event logs, Plaso, file-system timelines, a generic CSV) is matched against a
     small, documented table keyed on the canonical ``action`` verb plus an
     optional ``object`` refinement. A match is tagged with
     ``mapping_source = "mapping_table"``. Each rule fires only on a canonical
     signature that is by itself evidence of the technique as ATT&CK defines it
     (creating a service is Windows Service; starting powershell.exe is
     PowerShell). ATT&CK describes behaviour, not intent, so a legitimate service
     install is still T1543.003: the table's precision against malicious-only
     ground truth is measured, not assumed (see ``casebound.evaluation``).

A detection source (``DETECTION_SOURCES``: Hayabusa, Chainsaw) is never run through
the table. Every row it emits is a rule match, and the rule has already judged
which techniques the row shows: a row without tags comes from an informational
rule (a routine logon, a process start) and is context, not an observed
technique. Second-guessing it with the table would put routine administration on
the report's ATT&CK matrix. Every emitted tag records how it was made in
``mapping_source`` (FR14).

Every technique id in the table is checked against the bundled ATT&CK catalog by
the test suite, so a stale or mistyped id cannot ship (AGENTS.md: re-verify
external specifics).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace

from casebound.enrich.catalog import load_catalog
from casebound.normalize.schema import AttackTechnique, Event

__all__ = [
    "DETECTION_SOURCES",
    "MAPPING_SOURCE_RULE_TAG",
    "MAPPING_SOURCE_TABLE",
    "MAPPING_TABLE",
    "MappingRule",
    "tag_event",
    "tag_events",
]

# The two provenance labels recorded on every tag (PRD Section 10's
# ``mapping_source``). Passthrough tags come from a detection rule on the source;
# table tags come from the documented mapping table below.
MAPPING_SOURCE_RULE_TAG = "rule_tag"
MAPPING_SOURCE_TABLE = "mapping_table"

# Where the normalize mappers stash a source's native ATT&CK tags, so this tagging
# step is the single place that decides techniques.
_RULE_TAG_DETAIL_KEY = "rule_mitre_tags"

# An ATT&CK technique or sub-technique id, mirroring the schema's own check.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")

# Sources whose every row is a detection-rule match carrying the rule's own ATT&CK
# judgment (canonical ``source_tool`` values). Their rows are tagged from the rule
# only; the mapping table is for sources with no detection layer.
DETECTION_SOURCES: frozenset[str] = frozenset({"hayabusa", "chainsaw"})


@dataclass(frozen=True)
class MappingRule:
    """One documented (action, optional object refinement) to technique mapping.

    ``action`` is the canonical, source-agnostic verb the rule keys on. At most one
    object refinement applies, compared case-insensitively: ``object_contains``
    requires a substring (a registry Run key path), ``object_endswith`` requires
    one of the suffixes (a process image name such as ``\\powershell.exe``). With
    neither, the action alone is sufficient evidence of the technique.
    """

    technique_id: str
    action: str
    object_contains: str | None = None
    object_endswith: tuple[str, ...] = ()
    rationale: str = ""

    def matches(self, event: Event) -> bool:
        if event.action != self.action:
            return False
        target = (event.object or "").lower()
        if self.object_contains is not None and self.object_contains.lower() not in target:
            return False
        return not self.object_endswith or target.endswith(
            tuple(suffix.lower() for suffix in self.object_endswith)
        )


# The documented mapping table (FR14). Small and high-signal by design: each entry
# maps one canonical signature to exactly one technique of the bundled ATT&CK
# release. Names below are the ATT&CK 19 display names.
MAPPING_TABLE: tuple[MappingRule, ...] = (
    MappingRule(
        "T1053.005",
        "scheduled_task_create",
        rationale="Scheduled Task/Job: Scheduled Task. Registering a task is the technique.",
    ),
    MappingRule(
        "T1053.005",
        "process_create",
        object_endswith=("\\schtasks.exe",),
        rationale="Scheduled Task/Job: Scheduled Task, via the schtasks utility.",
    ),
    MappingRule(
        "T1543.003",
        "service_install",
        rationale="Create or Modify System Process: Windows Service.",
    ),
    MappingRule(
        "T1003.001",
        "process_access",
        object_endswith=("\\lsass.exe",),
        rationale="OS Credential Dumping: LSASS Memory. Other access targets are not.",
    ),
    MappingRule(
        "T1547.001",
        "registry_set",
        object_contains="\\currentversion\\run",
        rationale="Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder "
        "(Run and RunOnce).",
    ),
    MappingRule(
        "T1021.002",
        "network_share_access",
        object_endswith=("\\admin$", "\\c$"),
        rationale="Remote Services: SMB/Windows Admin Shares. IPC$ is excluded as routine.",
    ),
    MappingRule(
        "T1059.001",
        "process_create",
        object_endswith=("\\powershell.exe", "\\pwsh.exe", "\\powershell_ise.exe"),
        rationale="Command and Scripting Interpreter: PowerShell.",
    ),
    MappingRule(
        "T1560.001",
        "process_create",
        object_endswith=("\\7z.exe", "\\7za.exe", "\\rar.exe", "\\winrar.exe"),
        rationale="Archive Collected Data: Archive via Utility.",
    ),
    MappingRule(
        "T1047",
        "process_create",
        object_endswith=("\\wmic.exe",),
        rationale="Windows Management Instrumentation.",
    ),
    MappingRule(
        "T1685.005",
        "log_clear",
        rationale="Clear Windows Event Logs (revoked T1070.001's successor in ATT&CK 19).",
    ),
    MappingRule(
        "T1055",
        "remote_thread_create",
        rationale="Process Injection: a thread created in another process.",
    ),
    MappingRule(
        "T1136",
        "account_create",
        rationale="Create Account. Local and domain creation share the event, so the "
        "parent technique is the most precise claim.",
    ),
)


def _native_technique_tags(event: Event) -> list[AttackTechnique]:
    """Return the source's own ATT&CK tags, resolved against the catalog.

    Keeps only strings that are well-formed technique ids, translates a revoked id
    to its current successor (keeping the original as ``source_id``), and drops
    duplicates while preserving first-seen order so the passthrough is stable. An
    id the catalog does not know is kept as written: it may be newer than the
    bundled release, and the report flags it rather than silently dropping it.
    """
    raw = event.details.get(_RULE_TAG_DETAIL_KEY)
    if not isinstance(raw, list):
        return []
    catalog = load_catalog()
    tags: list[AttackTechnique] = []
    seen: set[str] = set()
    for item in raw:
        requested = str(item).strip().upper()
        if not _TECHNIQUE_RE.match(requested):
            continue
        resolution = catalog.resolve(requested)
        if resolution.technique_id in seen:
            continue
        seen.add(resolution.technique_id)
        tags.append(
            AttackTechnique(
                technique_id=resolution.technique_id,
                mapping_source=MAPPING_SOURCE_RULE_TAG,
                source_id=requested if resolution.translated else None,
            )
        )
    return tags


def _table_technique_tags(event: Event) -> list[AttackTechnique]:
    """Return the technique tags the mapping table assigns this event, in order."""
    tags: list[AttackTechnique] = []
    seen: set[str] = set()
    for rule in MAPPING_TABLE:
        if rule.matches(event) and rule.technique_id not in seen:
            seen.add(rule.technique_id)
            tags.append(AttackTechnique(rule.technique_id, MAPPING_SOURCE_TABLE))
    return tags


def tag_event(event: Event, *, use_rule_tags: bool = True) -> Event:
    """Return ``event`` with its ATT&CK tags resolved deterministically.

    Native rule tags win (FR13). An event with none falls back to the documented
    mapping table (FR14), unless it comes from a detection source, whose untagged
    rows are informational by the rule's own judgment. ``use_rule_tags=False``
    ignores the source's own tags and applies the table to every event, whatever
    its source, which is how the evaluation isolates the table's own precision and
    recall. Every tag records its ``mapping_source``.
    The returned event is a copy with ``attack_techniques`` set; the input is left
    untouched and the core fields (and therefore the ``event_id``) are unchanged.
    The operation is idempotent: tagging an already-tagged event yields the same
    tags.
    """
    if use_rule_tags:
        native = _native_technique_tags(event)
        if native or event.source_tool in DETECTION_SOURCES:
            resolved = native
        else:
            resolved = _table_technique_tags(event)
    else:
        resolved = _table_technique_tags(event)

    # Merge into anything already present without duplicating a (technique, source)
    # pair, so re-tagging is a no-op and any pre-existing tags are preserved.
    merged = list(event.attack_techniques)
    present = {(tech.technique_id, tech.mapping_source) for tech in merged}
    for tech in resolved:
        key = (tech.technique_id, tech.mapping_source)
        if key not in present:
            present.add(key)
            merged.append(tech)

    if merged == list(event.attack_techniques):
        return event
    return replace(event, attack_techniques=merged)


def tag_events(events: Iterable[Event], *, use_rule_tags: bool = True) -> list[Event]:
    """Tag a stream of events, returning the tagged copies in the same order."""
    return [tag_event(event, use_rule_tags=use_rule_tags) for event in events]
