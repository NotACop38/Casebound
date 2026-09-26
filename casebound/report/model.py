"""The shared report content model (PRD FR28 to FR30).

The HTML report (the hero deliverable), the machine-readable JSON report (FR29),
and the ticket-ready Markdown report (FR30) must all carry the same content. This
module builds one structured view of a ``Case``, so the renderers draw from a single
source of truth and can never drift apart.

The model is derived only from the deterministic pipeline. In particular, every
narrative sentence is phrased from the cited event's own canonical fields
(``casebound.report.phrasing``), never from the model's prose, so a fact the
verifier did not confirm can never reach a reader as a statement (AGENTS.md prime
directive). The model's drafts appear only in the rejected-claims audit, labeled as
rejected.

Everything in the model is JSON-ready (strings, numbers, booleans, and lists and
dicts of those), so ``ReportModel.to_dict`` is the JSON report body.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from casebound import __version__
from casebound.enrich.catalog import TechniqueStatus, load_catalog
from casebound.enrich.cluster import Episode
from casebound.enrich.ioc import Ioc
from casebound.normalize.schema import SCHEMA_VERSION, AttackTechnique, Event
from casebound.normalize.severity import normalize_severity, severity_rank
from casebound.pipeline import Case
from casebound.report.phrasing import phrase_event
from casebound.verify.engine import VerifiedClaim

__all__ = [
    "NO_MODEL_LABEL",
    "AttackCell",
    "AttackColumn",
    "AttackSummary",
    "NarrativeEntry",
    "ReportModel",
    "TechniqueRef",
    "build_report_model",
]

# The narrative label shown when the deterministic no-model path is taken (FR26).
NO_MODEL_LABEL = "none (deterministic report)"

# Severities at or above which an untagged event is still notable enough to show in
# a size-capped HTML or Markdown report.
_NOTABLE_SEVERITY = severity_rank("high")


@dataclass(frozen=True)
class TechniqueRef:
    """An ATT&CK technique attached to an event, named from the bundled catalog.

    ``status`` is ``active`` for a current technique, ``deprecated`` for one MITRE
    retired without a successor, and ``unknown`` for an id the catalog does not
    list. ``source_id`` is the revoked id a source wrote, when the tagger translated
    it to its successor.
    """

    technique_id: str
    name: str
    mapping_source: str
    status: str
    source_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Render the reference as a JSON-ready dict."""
        rendered: dict[str, Any] = {
            "technique_id": self.technique_id,
            "name": self.name,
            "mapping_source": self.mapping_source,
            "status": self.status,
        }
        if self.source_id is not None:
            rendered["source_id"] = self.source_id
        return rendered


def _technique_refs(techniques: Iterable[AttackTechnique]) -> tuple[TechniqueRef, ...]:
    catalog = load_catalog()
    refs: list[TechniqueRef] = []
    for tech in techniques:
        entry = catalog.get(tech.technique_id)
        if entry is None:
            status, name = TechniqueStatus.UNKNOWN, "not in the bundled ATT&CK catalog"
        elif entry.deprecated:
            status, name = TechniqueStatus.DEPRECATED, entry.display_name
        else:
            status, name = TechniqueStatus.ACTIVE, entry.display_name
        refs.append(
            TechniqueRef(
                technique_id=tech.technique_id,
                name=name,
                mapping_source=tech.mapping_source,
                status=status.value,
                source_id=tech.source_id,
            )
        )
    return tuple(refs)


@dataclass(frozen=True)
class NarrativeEntry:
    """One sentence of the narrative (or of the deterministic findings).

    ``statement`` is phrased from the backing event's canonical fields; ``detection``
    is that event's own message (for a detection source, the rule title). For a
    verified claim, ``verified_fields`` lists the facts the model asserted and the
    verifier confirmed against the backing event, ``context_citations`` are the other
    ids the claim cited (each resolves to a real event but did not back the facts),
    and ``round_index`` is the verification round that accepted it. For a
    deterministic finding those are empty and ``round_index`` is None.
    """

    backing_event_id: str
    datetime: str
    host: str | None
    statement: str
    detection: str
    severity: str | None
    techniques: tuple[TechniqueRef, ...]
    episode_id: str | None
    verified_fields: tuple[str, ...] = ()
    context_citations: tuple[str, ...] = ()
    round_index: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Render the entry as a JSON-ready dict."""
        return {
            "backing_event_id": self.backing_event_id,
            "datetime": self.datetime,
            "host": self.host,
            "statement": self.statement,
            "detection": self.detection,
            "severity": self.severity,
            "techniques": [tech.to_dict() for tech in self.techniques],
            "episode_id": self.episode_id,
            "verified_fields": list(self.verified_fields),
            "context_citations": list(self.context_citations),
            "round_index": self.round_index,
        }


def _entry(
    event: Event,
    episode_id: str | None,
    *,
    claim: VerifiedClaim | None = None,
) -> NarrativeEntry:
    context: tuple[str, ...] = ()
    verified: tuple[str, ...] = ()
    round_index: int | None = None
    if claim is not None:
        context = tuple(cid for cid in claim.citations if cid != claim.backing_event_id)
        verified = claim.verified.asserted_fields()
        round_index = claim.round_index
    return NarrativeEntry(
        backing_event_id=event.event_id,
        datetime=event.datetime,
        host=event.host,
        statement=phrase_event(event),
        detection=event.message,
        severity=normalize_severity(event.details.get("level")),
        techniques=_technique_refs(event.attack_techniques),
        episode_id=episode_id,
        verified_fields=verified,
        context_citations=context,
        round_index=round_index,
    )


@dataclass(frozen=True)
class AttackCell:
    """One observed technique in the ATT&CK matrix, with the events exhibiting it."""

    technique_id: str
    name: str
    count: int
    event_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Render the cell as a JSON-ready dict."""
        return {
            "technique_id": self.technique_id,
            "name": self.name,
            "count": self.count,
            "event_ids": list(self.event_ids),
        }


@dataclass(frozen=True)
class AttackColumn:
    """One tactic of the Enterprise matrix that has at least one observed technique."""

    tactic_id: str
    name: str
    cells: tuple[AttackCell, ...]

    def to_dict(self) -> dict[str, Any]:
        """Render the column as a JSON-ready dict."""
        return {
            "tactic_id": self.tactic_id,
            "name": self.name,
            "techniques": [cell.to_dict() for cell in self.cells],
        }


@dataclass(frozen=True)
class AttackSummary:
    """The ATT&CK view of the case: the observed matrix and anything off it.

    ``columns`` follow the Enterprise matrix's left-to-right tactic order and hold
    only tactics with an observation; a technique under several tactics appears in
    each. ``unmapped`` lists observed ids that are not current techniques
    (deprecated, or unknown to the bundled catalog), with their event counts.
    """

    attack_version: str
    columns: tuple[AttackColumn, ...]
    unmapped: tuple[dict[str, Any], ...]
    technique_count: int
    max_count: int

    def to_dict(self) -> dict[str, Any]:
        """Render the summary as a JSON-ready dict."""
        return {
            "attack_version": self.attack_version,
            "technique_count": self.technique_count,
            "tactics": [column.to_dict() for column in self.columns],
            "unmapped": [dict(item) for item in self.unmapped],
        }


def _attack_summary(events: Sequence[Event]) -> AttackSummary:
    catalog = load_catalog()
    members: dict[str, list[str]] = {}
    for event in events:
        for technique_id in dict.fromkeys(tech.technique_id for tech in event.attack_techniques):
            members.setdefault(technique_id, []).append(event.event_id)

    by_tactic: dict[str, list[AttackCell]] = {}
    unmapped: list[dict[str, Any]] = []
    for technique_id in sorted(members):
        technique = catalog.get(technique_id)
        ids = tuple(members[technique_id])
        if technique is None or not technique.is_active:
            status = TechniqueStatus.UNKNOWN if technique is None else TechniqueStatus.DEPRECATED
            unmapped.append(
                {"technique_id": technique_id, "status": status.value, "count": len(ids)}
            )
            continue
        cell = AttackCell(technique_id, technique.display_name, len(ids), ids)
        for shortname in technique.tactics:
            by_tactic.setdefault(shortname, []).append(cell)

    columns = tuple(
        AttackColumn(
            tactic_id=tactic.tactic_id,
            name=tactic.name,
            cells=tuple(sorted(by_tactic[tactic.shortname], key=lambda c: (-c.count, c.name))),
        )
        for tactic in catalog.tactics
        if tactic.shortname in by_tactic
    )
    active_ids = {cell.technique_id for column in columns for cell in column.cells}
    return AttackSummary(
        attack_version=catalog.version,
        columns=columns,
        unmapped=tuple(unmapped),
        technique_count=len(active_ids),
        max_count=max((len(members[tid]) for tid in active_ids), default=0),
    )


def _is_severe(event: Event) -> bool:
    """True when the event's detection rule rated it high or critical."""
    return severity_rank(normalize_severity(event.details.get("level"))) >= _NOTABLE_SEVERITY


def _episode_dict(episode: Episode, techniques: Sequence[str]) -> dict[str, Any]:
    rendered = episode.to_dict()
    rendered["techniques"] = list(techniques)
    return rendered


def _event_dict(
    event: Event,
    case: Case,
    episode_id: str | None,
    iocs: Sequence[Ioc],
    *,
    notable: bool,
) -> dict[str, Any]:
    """The canonical record plus the annotations every report format shows."""
    entry = event.to_dict()
    entry["techniques"] = [tech.to_dict() for tech in _technique_refs(event.attack_techniques)]
    entry["severity"] = normalize_severity(event.details.get("level"))
    entry["episode_id"] = episode_id
    entry["provenance"] = [
        f"{ref.source_file}#{ref.record}" for ref in case.provenance.get(event.event_id, ())
    ]
    entry["referenced_iocs"] = [{"type": ioc.ioc_type, "defanged": ioc.defanged} for ioc in iocs]
    entry["notable"] = notable
    return entry


@dataclass(frozen=True)
class ReportModel:
    """The single structured view of a case that every report renderer draws from."""

    case_name: str
    generator: str
    schema_version: str
    inputs: tuple[dict[str, Any], ...]
    narrative_label: str
    no_model: bool
    narrative: tuple[NarrativeEntry, ...]
    findings: tuple[NarrativeEntry, ...]
    audit: tuple[dict[str, Any], ...]
    attack: AttackSummary
    episodes: tuple[dict[str, Any], ...]
    iocs: tuple[dict[str, Any], ...]
    problems: tuple[dict[str, Any], ...]
    stats: dict[str, int]
    events: tuple[dict[str, Any], ...]

    def displayed_events(self, limit: int | None) -> tuple[tuple[dict[str, Any], ...], bool]:
        """The events a size-capped renderer should show, and whether it was capped.

        Within the limit every event is shown. Past it, only notable events are
        (ATT&CK-tagged, cited by the narrative, or high-severity detections), up to
        the limit, in chronological order; the JSON report always carries them all.
        """
        if limit is None or len(self.events) <= limit:
            return self.events, False
        notable = tuple(event for event in self.events if event["notable"])
        return notable[:limit], True

    def to_dict(self) -> dict[str, Any]:
        """Render the whole model as a JSON-ready dict (the JSON report body)."""
        return {
            "generator": self.generator,
            "schema_version": self.schema_version,
            "case": {"name": self.case_name, "inputs": [dict(item) for item in self.inputs]},
            "stats": dict(self.stats),
            "narrative": {
                "label": self.narrative_label,
                "no_model": self.no_model,
                "entries": [entry.to_dict() for entry in self.narrative],
            },
            "findings": [entry.to_dict() for entry in self.findings],
            "audit": [dict(entry) for entry in self.audit],
            "attack": self.attack.to_dict(),
            "episodes": [dict(episode) for episode in self.episodes],
            "iocs": [dict(ioc) for ioc in self.iocs],
            "problems": [dict(problem) for problem in self.problems],
            "events": [dict(event) for event in self.events],
        }


def _narrative(case: Case, episode_of: dict[str, str]) -> tuple[NarrativeEntry, ...]:
    """One entry per distinct backing event, chronological, earliest round kept."""
    if case.verification is None:
        return ()
    chosen: dict[str, VerifiedClaim] = {}
    for claim in case.verification.accepted:
        chosen.setdefault(claim.backing_event_id, claim)
    return tuple(
        _entry(event, episode_of.get(event.event_id), claim=chosen[event.event_id])
        for event in case.events
        if event.event_id in chosen
    )


def build_report_model(case: Case) -> ReportModel:
    """Build the shared report content model from a ``Case``."""
    episode_of = {
        event_id: episode.episode_id for episode in case.episodes for event_id in episode.event_ids
    }
    iocs_of: dict[str, list[Ioc]] = {}
    for ioc in case.iocs:
        for event_id in ioc.event_ids:
            iocs_of.setdefault(event_id, []).append(ioc)

    narrative = _narrative(case, episode_of)
    # The deterministic findings: every event that exhibits an ATT&CK technique or
    # that its detection rule rated high or critical.
    findings = tuple(
        _entry(event, episode_of.get(event.event_id))
        for event in case.events
        if event.attack_techniques or _is_severe(event)
    )
    cited = {entry.backing_event_id for entry in narrative} | {
        cid for entry in narrative for cid in entry.context_citations
    }
    events = tuple(
        _event_dict(
            event,
            case,
            episode_of.get(event.event_id),
            iocs_of.get(event.event_id, ()),
            notable=bool(event.attack_techniques) or event.event_id in cited or _is_severe(event),
        )
        for event in case.events
    )

    techniques_of_episode: dict[str, list[str]] = {}
    for event in case.events:
        episode_id = episode_of.get(event.event_id)
        if episode_id is None:
            continue
        bucket = techniques_of_episode.setdefault(episode_id, [])
        for tech in event.attack_techniques:
            if tech.technique_id not in bucket:
                bucket.append(tech.technique_id)

    audit = tuple(entry.to_dict() for entry in case.verification.audit) if case.verification else ()
    attack = _attack_summary(case.events)
    hosts = {event.host for event in case.events if event.host}
    stats = {
        "events": len(case.events),
        "records_read": case.records_read,
        "duplicates": case.duplicate_count,
        "problems": len(case.problems),
        "hosts": len(hosts),
        "techniques": attack.technique_count,
        "episodes": len(case.episodes),
        "iocs": len(case.iocs),
        "narrative_entries": len(narrative),
        "rejected_claims": len(audit),
    }

    return ReportModel(
        case_name=case.name,
        generator=f"Casebound {__version__}",
        schema_version=SCHEMA_VERSION,
        inputs=tuple(item.to_dict() for item in case.inputs),
        narrative_label=case.narrative_label or NO_MODEL_LABEL,
        no_model=case.no_model,
        narrative=narrative,
        findings=findings,
        audit=audit,
        attack=attack,
        episodes=tuple(
            _episode_dict(episode, techniques_of_episode.get(episode.episode_id, ()))
            for episode in case.episodes
        ),
        iocs=tuple(ioc.to_dict() for ioc in case.iocs),
        problems=tuple(
            {
                "source_tool": problem.source_tool,
                "source_file": problem.raw_ref.source_file,
                "record": problem.raw_ref.record,
                "reason": problem.reason,
            }
            for problem in case.problems
        ),
        stats=stats,
        events=events,
    )
