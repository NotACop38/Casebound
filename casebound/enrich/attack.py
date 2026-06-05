"""Deterministic ATT&CK tagging (PRD FR13, FR14).

Turns a normalized event into the same event with its ``attack_techniques``
filled in, using two deterministic sources and nothing else. No model is ever in
this loop: tagging is a pure function of the event's fields, so the same event
always yields the same tags.

Two layers, in priority order:

  1. Rule-tag passthrough (FR13). When a rule-based source already carried ATT&CK
     technique ids on the event (Hayabusa stashes them in
     ``details["rule_mitre_tags"]`` during normalization, see the Hayabusa
     mapper), those are promoted verbatim to ``attack_techniques`` with
     ``mapping_source = "rule_tag"``. Only well-formed technique ids pass; any
     other string a source put in that field is ignored rather than guessed at.

  2. Mapping table (FR14). An event that arrived with no native technique ids is
     matched against a small, documented table keyed on the canonical ``action``
     verb plus an optional ``object`` refinement. A match is tagged with
     ``mapping_source = "mapping_table"``. The table is intentionally small and
     high-precision: an entry fires only when the canonical fields are
     unambiguous evidence of one technique (creating a service is Windows
     Service; opening a handle into lsass.exe is LSASS Memory), so a source with
     no native tags still gets a defensible baseline without inflating false
     positives.

Every emitted tag records how it was made in ``mapping_source`` (FR14), so the
provenance of each tag is auditable downstream. An event with native tags is not
also run through the table: passthrough wins and the table is a fallback for the
untagged, exactly as the two requirements split the work.

Technique ids below were re-verified against the live ATT&CK matrix at author
time (all current as of the 12 May 2026 revision), per the standing instruction
not to trust memory for external specifics (PRD Section 15, AGENTS.md).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass, replace

from casebound.normalize.schema import AttackTechnique, Event

__all__ = [
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

# Where the normalize mappers stash a source's native ATT&CK tags. The Hayabusa
# mapper keeps the raw MitreTags here rather than promoting them, so this tagging
# step is the single place that decides techniques.
_RULE_TAG_DETAIL_KEY = "rule_mitre_tags"

# An ATT&CK technique or sub-technique id, mirroring the schema's own check, so a
# stray non-id string in a source's tag field is dropped instead of promoted.
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


@dataclass(frozen=True)
class MappingRule:
    """One documented (action, optional object) to ATT&CK technique mapping.

    ``action`` is the canonical, source-agnostic verb the rule keys on.
    ``object_substring``, when set, is a case-insensitive substring the event's
    ``object`` must contain for the rule to fire; it refines an action that is
    only a technique for a specific target (a registry set is autostart only for a
    Run key, a process access is credential dumping only against lsass). When it
    is None the action alone is sufficient evidence of the technique.
    """

    technique_id: str
    action: str
    object_substring: str | None = None

    def matches(self, event: Event) -> bool:
        if event.action != self.action:
            return False
        if self.object_substring is None:
            return True
        target = (event.object or "").lower()
        return self.object_substring.lower() in target


# The documented mapping table (FR14). Small and high-precision by design: each
# entry maps an unambiguous canonical signature to exactly one technique. Every id
# was re-verified against the live ATT&CK matrix at author time.
#
#   T1053.005 Scheduled Task        (parent T1053 Scheduled Task/Job)
#   T1543.003 Windows Service       (parent T1543 Create or Modify System Process)
#   T1003.001 LSASS Memory          (parent T1003 OS Credential Dumping)
#   T1547.001 Registry Run Keys / Startup Folder
#             (parent T1547 Boot or Logon Autostart Execution)
#   T1021.002 SMB/Windows Admin Shares (parent T1021 Remote Services)
MAPPING_TABLE: tuple[MappingRule, ...] = (
    # Creating a scheduled task is itself the technique, regardless of target.
    MappingRule(technique_id="T1053.005", action="scheduled_task_create"),
    # Installing a Windows service is itself the technique.
    MappingRule(technique_id="T1543.003", action="service_install"),
    # Opening a handle into LSASS is credential dumping; other targets are not.
    MappingRule(technique_id="T1003.001", action="process_access", object_substring="lsass"),
    # Writing an autostart Run key is the autostart technique; other keys are not.
    MappingRule(
        technique_id="T1547.001",
        action="registry_set",
        object_substring="\\currentversion\\run",
    ),
    # Touching an administrative share is the SMB admin-share technique.
    MappingRule(
        technique_id="T1021.002",
        action="network_share_access",
        object_substring="admin$",
    ),
)


def _native_technique_ids(event: Event) -> list[str]:
    """Return the well-formed ATT&CK ids a source already attached, deduplicated.

    Reads the raw tags the normalize layer preserved in details, keeps only the
    strings that are valid technique ids, and drops duplicates while preserving
    first-seen order so the passthrough is stable.
    """
    raw = event.details.get(_RULE_TAG_DETAIL_KEY)
    if not isinstance(raw, list):
        return []
    ordered: list[str] = []
    seen: set[str] = set()
    for item in raw:
        tid = str(item).strip()
        if _TECHNIQUE_RE.match(tid) and tid not in seen:
            seen.add(tid)
            ordered.append(tid)
    return ordered


def _table_technique_ids(event: Event) -> list[str]:
    """Return the technique ids the mapping table assigns this event, in order."""
    ordered: list[str] = []
    seen: set[str] = set()
    for rule in MAPPING_TABLE:
        if rule.matches(event) and rule.technique_id not in seen:
            seen.add(rule.technique_id)
            ordered.append(rule.technique_id)
    return ordered


def tag_event(event: Event) -> Event:
    """Return ``event`` with its ATT&CK tags resolved deterministically.

    Native rule tags win (FR13); an event with none falls back to the documented
    mapping table (FR14). Every tag records its ``mapping_source``. The returned
    event is a copy with ``attack_techniques`` set; the input is left untouched,
    and the core fields (and therefore the ``event_id``) are unchanged. The
    operation is idempotent: tagging an already-tagged event yields the same tags.
    """
    native = _native_technique_ids(event)
    if native:
        resolved = [AttackTechnique(tid, MAPPING_SOURCE_RULE_TAG) for tid in native]
    else:
        resolved = [
            AttackTechnique(tid, MAPPING_SOURCE_TABLE) for tid in _table_technique_ids(event)
        ]

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


def tag_events(events: Iterable[Event]) -> list[Event]:
    """Tag a stream of events, returning the tagged copies in the same order."""
    return [tag_event(event) for event in events]
