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

from casebound.normalize.schema import Event, RawRef
from casebound.verify.engine import VerificationResult, VerifiedClaim

__all__ = ["NO_MODEL_LABEL", "render_report", "write_report"]

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"
_TEMPLATE_NAME = "report.html.j2"

# The narrative label shown when the deterministic no-model path is taken (FR26).
NO_MODEL_LABEL = "none (deterministic report)"

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


def _verified_statement(claim: VerifiedClaim) -> str:
    """Render an accepted claim as a sentence built only from verified facts.

    Uses solely the fields the verifier checked against the backing event, so the
    statement can never contain a fact the verifier did not confirm. The model's
    free prose is never surfaced as an accepted-claim statement; only the model
    drafts that were rejected appear, in the audit, clearly marked as rejected.
    """
    asserts = claim.asserts
    subject = asserts.principal if asserts.principal is not None else "An actor"
    action = asserts.action if asserts.action is not None else "was involved in an event"

    sentence = f"{subject} {action}".rstrip()
    if asserts.object is not None:
        sentence += f" on {asserts.object}"
    if asserts.datetime is not None:
        sentence += f" at {asserts.datetime}"
    return sentence + "."


def _claim_context(claim: VerifiedClaim) -> dict[str, Any]:
    """Build the template context for one accepted claim, with citation links.

    The inline evidence link is the backing event: the single cited event the
    verifier confirmed is consistent with every fact the claim asserts. Any other
    citation resolves to a real event (the verifier requires that) but did not back
    the checked facts, so it is rendered separately as context, never as the
    evidence for the statement.
    """
    backing = claim.backing_event_id
    context = [cid for cid in claim.citations if cid != backing]
    return {
        "statement": _verified_statement(claim),
        "backing": {"id": backing, "short": backing[:_SHORT_ID_LEN]},
        "context_citations": [{"id": cid, "short": cid[:_SHORT_ID_LEN]} for cid in context],
    }


def _event_context(event: Event, provenance: Sequence[RawRef]) -> dict[str, Any]:
    """Build the template context for one event (timeline row and appendix entry)."""
    technique_ids = [tech.technique_id for tech in event.attack_techniques]
    return {
        "event_id": event.event_id,
        "short_id": event.event_id[:_SHORT_ID_LEN],
        "datetime": event.datetime,
        "timestamp_desc": event.timestamp_desc,
        "host": event.host,
        "principal": event.principal,
        "action": event.action,
        "object": event.object,
        "message": event.message,
        "source_tool": event.source_tool,
        "source_artifact": event.source_artifact,
        "techniques": technique_ids,
        # The appendix shows the structured tags with their mapping source.
        "attack_techniques": [tech.to_dict() for tech in event.attack_techniques],
        "details": list(event.details.items()),
        "provenance": [f"{ref.source_file}#{ref.record}" for ref in provenance],
    }


def render_report(
    events: Sequence[Event],
    verification: VerificationResult | None,
    *,
    scenario: str,
    source_tool: str = "hayabusa",
    model_label: str | None = None,
    provenance: Mapping[str, Sequence[RawRef]] | None = None,
) -> str:
    """Render the self-contained HTML report from the pipeline output.

    ``events`` are the normalized, ATT&CK-tagged canonical events.
    ``verification`` is the verifier output (accepted claims plus the rejection
    audit); pass None for the deterministic no-model path (FR26), which renders the
    timeline, tags, and appendix with a notice that no narrative was produced.

    The HTML is self-contained: the stylesheet is inlined and no asset is fetched
    at view time. Every accepted claim is rendered from verified fields with inline
    citations that link to the backing event in the appendix (FR32).
    """
    ordered = sorted(events, key=lambda e: (e.datetime, e.event_id))
    prov = provenance or {}

    no_model = verification is None
    accepted: list[VerifiedClaim] = list(verification.accepted) if verification else []
    audit_entries = list(verification.audit) if verification else []

    observed_techniques = sorted(
        {tech.technique_id for event in ordered for tech in event.attack_techniques}
    )
    hosts = {event.host for event in ordered if event.host}

    event_views = [_event_context(event, prov.get(event.event_id, ())) for event in ordered]

    context: dict[str, Any] = {
        "scenario": scenario,
        "source_tool": source_tool,
        "model_label": model_label if model_label is not None else NO_MODEL_LABEL,
        "no_model": no_model,
        "stats": {
            "events": len(ordered),
            "hosts": len(hosts),
            "techniques": len(observed_techniques),
            "accepted": len(accepted),
            "rejected": len(audit_entries),
        },
        "observed_techniques": observed_techniques,
        "accepted": [_claim_context(claim) for claim in accepted],
        "audit": [
            {
                "round_index": entry.round_index,
                "claim_text": entry.claim_text,
                "citations": list(entry.citations),
                "reason": entry.reason.value,
                "detail": entry.detail,
                "dropped": entry.dropped,
            }
            for entry in audit_entries
        ],
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
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(html, encoding="utf-8")
    return path
