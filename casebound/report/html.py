"""The self-contained HTML report renderer (PRD FR28, FR32; the hero deliverable).

Renders one Jinja2 template into a single HTML file that fetches nothing at view
time (no external scripts, stylesheets, fonts, or images): the stylesheet is
inlined and every value comes from the deterministic pipeline. The report carries
four things the Phase 1 slice proves end to end:

  - the deterministic timeline, every event normalized and ATT&CK-tagged;
  - the verified narrative, each accepted claim rendered from the fields the
    verifier checked (never the model's free prose), with inline citations that
    link to the backing event in the evidence appendix (FR32);
  - the rejected-claims audit, every claim the verifier refused, with its reason; and
  - the evidence appendix, the full canonical record for every event, which is the
    deterministic source of truth the narrative is fenced to.

Like the JSON and Markdown renderers, this one draws from the shared
``ReportModel`` (see ``casebound.report.model``), so the three formats derive the
timeline order, the episodes, the indicators, the observed techniques, and the
summary counts once and can never drift apart. This renderer only shapes that
model into the HTML template's view (short id handles, citation links, the details
key/value list); it never re-derives content.

The model is never the source of truth here. An accepted claim is rendered from
its verified ``asserts`` and its backing event id, so a fact the verifier did not
check can never reach the reader as a statement (AGENTS.md prime directive). When
no model is configured, ``verification`` is None and the report is the
deterministic no-model path: timeline, tags, and appendix, with a notice saying so
(FR26).

Autoescaping is on, so every evidence-derived string (messages, paths, command
lines preserved in details) is HTML-escaped: hostile content in synthetic evidence
cannot inject markup into the report.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from casebound.enrich.cluster import Episode
from casebound.enrich.ioc import IocSet
from casebound.normalize.schema import Event, RawRef
from casebound.report.model import NO_MODEL_LABEL, ReportClaim, build_report_model
from casebound.verify.engine import VerificationResult

__all__ = ["NO_MODEL_LABEL", "render_report", "write_report"]

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TEMPLATE_NAME = "report.html.j2"

# How many leading hex characters of an event id to show as its short handle. The
# full id is always the anchor and link target; this is only the visible label.
_SHORT_ID_LEN = 12


def _environment() -> Environment:
    """Build the Jinja2 environment with autoescaping on for the HTML template."""
    return Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )


def _handle(event_id: str) -> dict[str, str]:
    """Render an event id as its full link target plus a short visible label."""
    return {"id": event_id, "short": event_id[:_SHORT_ID_LEN]}


def _claim_context(claim: ReportClaim) -> dict[str, Any]:
    """Build the template context for one accepted claim, with citation links.

    The inline evidence link is the backing event: the single cited event the
    verifier confirmed is consistent with every fact the claim asserts. Any other
    citation resolves to a real event (the verifier requires that) but did not back
    the checked facts, so it is rendered separately as context, never as the
    evidence for the statement. Both the statement and the backing/context split are
    decided in the shared model; this only adds the short link handles.
    """
    return {
        "statement": claim.statement,
        "backing": _handle(claim.backing_event_id),
        "context_citations": [_handle(cid) for cid in claim.context_citations],
    }


def _episode_context(episode: Mapping[str, Any]) -> dict[str, Any]:
    """Build the template context for one activity episode (from the shared model)."""
    return {
        "episode_id": episode["episode_id"],
        "host": episode["host"],
        "principal": episode["principal"],
        "start": episode["start"],
        "end": episode["end"],
        "event_count": episode["event_count"],
        "members": [_handle(eid) for eid in episode["event_ids"]],
    }


def _ioc_context(ioc: Mapping[str, Any]) -> dict[str, Any]:
    """Build the template context for one extracted indicator (from the shared model)."""
    # Ioc.to_dict omits the event_count property, so derive it from the ids.
    event_ids = ioc["event_ids"]
    return {
        "ioc_id": ioc["ioc_id"],
        "ioc_type": ioc["ioc_type"],
        "defanged": ioc["defanged"],
        "event_count": len(event_ids),
        "events": [_handle(eid) for eid in event_ids],
    }


def _event_context(event: Mapping[str, Any]) -> dict[str, Any]:
    """Shape one shared-model event into the timeline-row and appendix-entry view."""
    return {
        "event_id": event["event_id"],
        "short_id": event["event_id"][:_SHORT_ID_LEN],
        "datetime": event["datetime"],
        "timestamp_desc": event["timestamp_desc"],
        "host": event["host"],
        "principal": event["principal"],
        "action": event["action"],
        "object": event["object"],
        "message": event["message"],
        "source_tool": event["source_tool"],
        "source_artifact": event["source_artifact"],
        "techniques": event["techniques"],
        # The appendix shows the structured tags with their mapping source.
        "attack_techniques": event["attack_techniques"],
        "details": list(event["details"].items()),
        "provenance": event["provenance"],
        "episode_id": event["episode_id"],
        "iocs": event["referenced_iocs"],
    }


def render_report(
    events: Sequence[Event],
    verification: VerificationResult | None,
    *,
    scenario: str,
    source_tool: str = "hayabusa",
    model_label: str | None = None,
    provenance: Mapping[str, Sequence[RawRef]] | None = None,
    episodes: Sequence[Episode] | None = None,
    iocs: IocSet | None = None,
) -> str:
    """Render the self-contained HTML report from the pipeline output.

    ``events`` are the normalized, ATT&CK-tagged canonical events.
    ``verification`` is the verifier output (accepted claims plus the rejection
    audit); pass None for the deterministic no-model path (FR26), which renders the
    timeline, tags, and appendix with a notice that no narrative was produced.

    ``episodes`` and ``iocs`` are the enrichment output (FR15, FR16). They are
    optional: when omitted they are derived deterministically from ``events`` by the
    shared model, so a report always surfaces the activity episodes and the
    indicator set, whether or not the caller pre-computed them.

    The HTML is self-contained: the stylesheet is inlined and no asset is fetched
    at view time. Every accepted claim is rendered from verified fields with inline
    citations that link to the backing event in the appendix (FR32).
    """
    model = build_report_model(
        events,
        verification,
        scenario=scenario,
        source_tool=source_tool,
        model_label=model_label,
        provenance=provenance,
        episodes=episodes,
        iocs=iocs,
    )

    event_views = [_event_context(event) for event in model.events]

    context: dict[str, Any] = {
        "scenario": model.scenario,
        "source_tool": model.source_tool,
        "model_label": model.model_label,
        "no_model": model.no_model,
        "stats": model.stats,
        "observed_techniques": list(model.observed_techniques),
        "episodes": [_episode_context(episode) for episode in model.episodes],
        "iocs": [_ioc_context(ioc) for ioc in model.iocs],
        "accepted": [_claim_context(claim) for claim in model.accepted],
        # The shared model already renders each audit entry as a JSON-ready dict
        # with exactly the fields the template reads.
        "audit": [dict(entry) for entry in model.audit],
        "timeline": event_views,
        "appendix": event_views,
    }

    template = _environment().get_template(_TEMPLATE_NAME)
    return template.render(**context)


def write_report(
    path: Path,
    events: Sequence[Event],
    verification: VerificationResult | None,
    *,
    scenario: str,
    source_tool: str = "hayabusa",
    model_label: str | None = None,
    provenance: Mapping[str, Sequence[RawRef]] | None = None,
    episodes: Sequence[Episode] | None = None,
    iocs: IocSet | None = None,
) -> Path:
    """Render the HTML report and write it to ``path``, returning the path written.

    Creates the parent directory if needed. Offline, no network.
    """
    html = render_report(
        events,
        verification,
        scenario=scenario,
        source_tool=source_tool,
        model_label=model_label,
        provenance=provenance,
        episodes=episodes,
        iocs=iocs,
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
