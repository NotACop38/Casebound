"""The shared report content model (PRD FR28 to FR30).

The HTML report (the hero deliverable), the machine-readable JSON report (FR29),
and the ticket-ready Markdown report (FR30) must all carry the same content. This
module builds one structured view of a case from the pipeline output, so the three
renderers draw from a single source of truth and can never drift apart.

The model is derived only from the deterministic pipeline: the normalized,
ATT&CK-tagged events; the activity episodes and the indicator set (derived here
when the caller does not pass them, exactly as the HTML renderer does); and the
verifier output. An accepted claim is rendered from the fields the verifier
checked (see ``verified_statement``), never from the model's free prose, so a fact
the verifier did not confirm can never reach a reader as a statement (AGENTS.md
prime directive). When no model is configured, ``no_model`` is True and the
narrative is empty: the report is the deterministic timeline, tags, episodes,
indicators, and appendix (FR26).

Everything in the model is JSON-ready (strings, numbers, booleans, lists, and
dicts of those), so ``ReportModel.to_dict`` serializes directly.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from casebound.enrich.cluster import Episode, cluster_events
from casebound.enrich.ioc import Ioc, IocSet, extract_iocs
from casebound.normalize.schema import Event, RawRef
from casebound.verify.claims import ClaimAssertion
from casebound.verify.engine import VerificationResult, VerifiedClaim

__all__ = [
    "NO_MODEL_LABEL",
    "ReportClaim",
    "ReportModel",
    "build_report_model",
    "verified_statement",
]

# The narrative label shown when the deterministic no-model path is taken (FR26).
NO_MODEL_LABEL = "none (deterministic report)"


def verified_statement(asserts: ClaimAssertion) -> str:
    """Render an accepted claim as a sentence built only from verified facts.

    Uses solely the fields the verifier checked against the backing event, so the
    statement can never contain a fact the verifier did not confirm. The model's
    free prose is never surfaced as an accepted-claim statement; only the model
    drafts that were rejected appear, in the audit, clearly marked as rejected. Every
    report format renders accepted claims through this one function so they read
    identically (AGENTS.md prime directive).
    """
    subject = asserts.principal if asserts.principal is not None else "An actor"
    action = asserts.action if asserts.action is not None else "was involved in an event"

    sentence = f"{subject} {action}".rstrip()
    if asserts.object is not None:
        sentence += f" on {asserts.object}"
    if asserts.datetime is not None:
        sentence += f" at {asserts.datetime}"
    return sentence + "."


@dataclass(frozen=True)
class ReportClaim:
    """One accepted claim, rendered from verified fields with its citation links.

    ``backing_event_id`` is the single cited event the verifier confirmed is
    consistent with every fact the claim asserts; it is the claim's evidence link.
    ``context_citations`` are the other cited ids: each resolves to a real event
    (the verifier requires that) but did not back the checked facts, so they are
    surfaced as context, never as the evidence for the statement.
    """

    statement: str
    backing_event_id: str
    asserts: dict[str, str]
    citations: tuple[str, ...]
    context_citations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        """Render the claim as a JSON-ready dict."""
        return {
            "statement": self.statement,
            "backing_event_id": self.backing_event_id,
            "asserts": dict(self.asserts),
            "citations": list(self.citations),
            "context_citations": list(self.context_citations),
        }


def _report_claim(claim: VerifiedClaim) -> ReportClaim:
    """Build the renderer-agnostic view of one accepted claim."""
    backing = claim.backing_event_id
    context = tuple(cid for cid in claim.citations if cid != backing)
    return ReportClaim(
        statement=verified_statement(claim.asserts),
        backing_event_id=backing,
        asserts=claim.asserts.to_dict(),
        citations=tuple(claim.citations),
        context_citations=context,
    )


def _report_event(
    event: Event,
    provenance: Sequence[RawRef],
    *,
    episode_id: str | None,
    iocs: Sequence[Ioc],
) -> dict[str, Any]:
    """Build the per-event entry that backs both the timeline and the appendix.

    Carries the full canonical record (every Section 10 field) plus the report
    annotations every format shows: the technique-id list, the episode the event
    belongs to, its referenced indicators, and the source provenance for audit.
    """
    entry = event.to_dict()
    entry["techniques"] = [tech.technique_id for tech in event.attack_techniques]
    entry["episode_id"] = episode_id
    entry["provenance"] = [f"{ref.source_file}#{ref.record}" for ref in provenance]
    entry["referenced_iocs"] = [{"type": ioc.ioc_type, "defanged": ioc.defanged} for ioc in iocs]
    return entry


@dataclass(frozen=True)
class ReportModel:
    """The single structured view of a case that every report renderer draws from.

    ``events`` are the full canonical records (timeline rows and appendix entries
    are the same data). ``accepted`` and ``audit`` are the verifier output;
    ``episodes`` and ``iocs`` are the enrichment output. All fields are JSON-ready,
    so ``to_dict`` is a direct serialization (FR29).
    """

    scenario: str
    source_tool: str
    model_label: str
    no_model: bool
    stats: dict[str, int]
    observed_techniques: tuple[str, ...]
    episodes: tuple[dict[str, Any], ...]
    iocs: tuple[dict[str, Any], ...]
    accepted: tuple[ReportClaim, ...]
    audit: tuple[dict[str, Any], ...]
    events: tuple[dict[str, Any], ...]

    def to_dict(self) -> dict[str, Any]:
        """Render the whole model as a JSON-ready dict (the JSON report body)."""
        return {
            "scenario": self.scenario,
            "source_tool": self.source_tool,
            "model_label": self.model_label,
            "no_model": self.no_model,
            "stats": dict(self.stats),
            "observed_techniques": list(self.observed_techniques),
            "narrative": {
                "model_label": self.model_label,
                "no_model": self.no_model,
                "accepted": [claim.to_dict() for claim in self.accepted],
            },
            "audit": [dict(entry) for entry in self.audit],
            "episodes": [dict(episode) for episode in self.episodes],
            "iocs": [dict(ioc) for ioc in self.iocs],
            "events": [dict(event) for event in self.events],
        }


def build_report_model(
    events: Sequence[Event],
    verification: VerificationResult | None,
    *,
    scenario: str,
    source_tool: str = "hayabusa",
    model_label: str | None = None,
    provenance: Mapping[str, Sequence[RawRef]] | None = None,
    episodes: Sequence[Episode] | None = None,
    iocs: IocSet | None = None,
) -> ReportModel:
    """Build the shared report content model from the pipeline output.

    Mirrors the HTML renderer's inputs exactly. ``episodes`` and ``iocs`` are
    optional: when omitted they are derived deterministically from ``events`` (FR15,
    FR16), so a report always surfaces the activity episodes and the indicator set
    whether or not the caller pre-computed them. Pass ``verification`` as None for
    the deterministic no-model path (FR26).
    """
    ordered = sorted(events, key=lambda e: (e.datetime, e.event_id))
    prov = provenance or {}

    resolved_episodes = list(episodes) if episodes is not None else cluster_events(ordered).episodes
    resolved_iocs = list(iocs) if iocs is not None else list(extract_iocs(ordered).iocs)

    episode_of: dict[str, str] = {
        event_id: episode.episode_id
        for episode in resolved_episodes
        for event_id in episode.event_ids
    }
    iocs_of: dict[str, list[Ioc]] = {}
    for ioc in resolved_iocs:
        for event_id in ioc.event_ids:
            iocs_of.setdefault(event_id, []).append(ioc)

    no_model = verification is None
    accepted: list[VerifiedClaim] = list(verification.accepted) if verification else []
    audit_entries = list(verification.audit) if verification else []

    observed_techniques = tuple(
        sorted({tech.technique_id for event in ordered for tech in event.attack_techniques})
    )
    hosts = {event.host for event in ordered if event.host}

    event_entries = tuple(
        _report_event(
            event,
            prov.get(event.event_id, ()),
            episode_id=episode_of.get(event.event_id),
            iocs=iocs_of.get(event.event_id, ()),
        )
        for event in ordered
    )

    stats = {
        "events": len(ordered),
        "hosts": len(hosts),
        "techniques": len(observed_techniques),
        "accepted": len(accepted),
        "rejected": len(audit_entries),
        "episodes": len(resolved_episodes),
        "iocs": len(resolved_iocs),
    }

    return ReportModel(
        scenario=scenario,
        source_tool=source_tool,
        model_label=model_label if model_label is not None else NO_MODEL_LABEL,
        no_model=no_model,
        stats=stats,
        observed_techniques=observed_techniques,
        episodes=tuple(episode.to_dict() for episode in resolved_episodes),
        iocs=tuple(ioc.to_dict() for ioc in resolved_iocs),
        accepted=tuple(_report_claim(claim) for claim in accepted),
        audit=tuple(entry.to_dict() for entry in audit_entries),
        events=event_entries,
    )
