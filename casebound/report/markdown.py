"""The Markdown report renderer (PRD FR30).

Emits the same content as the HTML report (the hero deliverable) as Markdown
suitable for pasting into a ticket or a chat. Both renderers draw from the shared
``ReportModel`` (see ``casebound.report.model``), so the Markdown and the HTML can
never drift apart: the summary, the verified narrative with its citations, the
rejected-claims audit, the deterministic timeline, the activity episodes, the
indicator set, and the evidence appendix are all present.

An accepted claim is rendered from the fields the verifier checked, never from the
model's free prose, so a fact the verifier did not confirm can never reach a reader
as a statement (AGENTS.md prime directive). When no model is configured the
narrative section says so and the deterministic report stands on its own (FR26).

The output is deterministic and ends with a single trailing newline.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from casebound.enrich.cluster import Episode
from casebound.enrich.ioc import IocSet
from casebound.normalize.schema import Event, RawRef
from casebound.report.model import ReportModel, build_report_model
from casebound.verify.engine import VerificationResult

__all__ = ["render_markdown_report", "write_markdown_report"]

# How many leading hex characters of an event id to show as its short handle in
# prose. The full id is always carried in the appendix heading and the JSON report.
_SHORT_ID_LEN = 12


def _short(event_id: str) -> str:
    """The short, human-readable handle for an event id."""
    return event_id[:_SHORT_ID_LEN]


# The structurally dangerous Markdown punctuation neutralized in evidence-derived
# prose: a backslash escape kills links and images ([]()), code spans (backtick),
# raw HTML (<>), and table breaks (|). Backslash itself is in the class so an
# existing one cannot un-escape what follows. Emphasis characters (*_) are left
# alone: they are cosmetic, and escaping them would mangle snake_case verbs and
# Windows paths in the raw text.
_MD_SPECIAL_RE = re.compile(r"[\\`\[\]<>()|]")


def _collapse(value: Any) -> str:
    """Stringify and collapse all whitespace runs (newlines included) to a space.

    Evidence can carry embedded newlines; collapsed, a value can never break out
    of its bullet or table row into new document structure.
    """
    return " ".join(str(value).split())


def _cell(value: Any) -> str:
    """Render evidence text inert, for prose and table cells alike.

    Evidence fields are attacker-controlled by definition, and this report is
    pasted into ticket renderers that may honor raw HTML and links. Whitespace
    collapses so a value cannot break the structure, and the Markdown-significant
    punctuation is backslash-escaped so a value cannot open a link, a code span,
    raw HTML, emphasis, or a heading. None renders as an empty string, matching
    how the HTML table leaves an absent field blank.
    """
    if value is None:
        return ""
    return _MD_SPECIAL_RE.sub(lambda match: "\\" + match.group(0), _collapse(value))


def _code_span(text: str) -> str:
    """Wrap already-collapsed text in a code span it cannot break out of.

    A backslash does not escape inside a code span, so backticks are replaced
    outright; pipes are escaped because GFM splits table rows before code spans
    are parsed.
    """
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def _mono(value: Any) -> str:
    """Render a value as inline code for a table cell, or blank when absent."""
    if value is None or value == "":
        return ""
    return _code_span(_collapse(value))


def _inline(value: Any) -> str:
    """Render a scalar detail value as a safe inline code span."""
    text = "" if value is None else _collapse(value)
    if text == "":
        return "(empty)"
    return _code_span(text)


def _detail_lines(key: str, value: Any, indent: str) -> list[str]:
    """Render one details entry as a nested Markdown bullet, recursing into mappings.

    A mapping (the Hayabusa ``fields`` block, say) becomes a nested bullet list, a
    list renders inline, and a scalar renders as an inline code span. This carries
    the same source specifics the HTML appendix shows, for ticket-only audit.
    Keys are evidence-derived too, so they are neutralized like any other text.
    """
    label = _cell(key)
    if isinstance(value, dict):
        if not value:
            return [f"{indent}- {label}: (none)"]
        out = [f"{indent}- {label}:"]
        for sub_key, sub_value in value.items():
            out.extend(_detail_lines(str(sub_key), sub_value, indent + "  "))
        return out
    if isinstance(value, (list, tuple)):
        if not value:
            return [f"{indent}- {label}: (none)"]
        return [f"{indent}- {label}: " + ", ".join(_inline(item) for item in value)]
    return [f"{indent}- {label}: {_inline(value)}"]


def _render(model: ReportModel) -> str:
    """Render the shared report model to a Markdown document."""
    lines: list[str] = []

    lines.append("# Casebound investigation report")
    lines.append("")
    lines.append(
        f"Scenario: {_cell(model.scenario)}. Source tool: {_cell(model.source_tool)}. "
        f"Narrative: {_cell(model.model_label)}."
    )
    lines.append("")
    lines.append(
        "> The guarantee. No factual claim appears in the narrative below unless it "
        "resolves to a real, deterministically extracted timeline event by id and its "
        "asserted facts (time, principal, action, object) are consistent with that event. "
        "The deterministic timeline and appendix are the source of truth; the language "
        "model never decides what is true."
    )
    lines.append("")

    # Summary.
    stats = model.stats
    lines.append("## Summary")
    lines.append("")
    lines.append("|Metric|Count|")
    lines.append("|------|----:|")
    lines.append(f"|Timeline events|{stats['events']}|")
    lines.append(f"|Hosts|{stats['hosts']}|")
    lines.append(f"|ATT&CK techniques|{stats['techniques']}|")
    lines.append(f"|Verified claims|{stats['accepted']}|")
    lines.append(f"|Rejected claims|{stats['rejected']}|")
    lines.append(f"|Activity episodes|{stats['episodes']}|")
    lines.append(f"|Indicators|{stats['iocs']}|")
    lines.append("")
    if model.observed_techniques:
        observed = ", ".join(f"`{tid}`" for tid in model.observed_techniques)
        lines.append(f"Observed techniques: {observed}")
        lines.append("")

    # Verified narrative.
    lines.append("## Verified narrative")
    lines.append("")
    if model.no_model:
        lines.append(
            "No language model configured. This is the deterministic report (the no-model "
            "path): the normalized timeline, the ATT&CK tags, the episodes, the indicators, "
            "and the evidence appendix below. Configure a local model to add the verified "
            "narrative."
        )
        lines.append("")
    elif model.accepted:
        lines.append(
            "Each statement is rendered from fields the verifier checked against the cited "
            "event, never from the model's free prose. Every citation resolves to an event "
            "in the appendix below."
        )
        lines.append("")
        for claim in model.accepted:
            lines.append(f"- {_cell(claim.statement)}")
            cite = f"  Backing evidence: `{_short(claim.backing_event_id)}`"
            if claim.context_citations:
                context = ", ".join(f"`{_short(cid)}`" for cid in claim.context_citations)
                cite += f" (also cited for context: {context})"
            lines.append(cite)
        lines.append("")
    else:
        lines.append("The model proposed no claim that survived verification.")
        lines.append("")

    # Rejected-claims audit.
    lines.append("## Rejected-claims audit")
    lines.append("")
    lines.append(
        "Every claim the verifier rejected is recorded here for transparency, with the "
        "reason it failed. A dropped claim never reached the narrative above."
    )
    lines.append("")
    if model.audit:
        for entry in model.audit:
            flags = entry["reason"]
            if entry["dropped"]:
                flags += ", dropped"
            lines.append(f"- [{flags}] (round {entry['round_index']}) {_cell(entry['claim_text'])}")
            lines.append(f"  Reason: {_cell(entry['detail'])}")
            if entry["citations"]:
                cited = ", ".join(f"`{cid}`" for cid in entry["citations"])
                lines.append(f"  Cited: {cited}")
        lines.append("")
    else:
        lines.append("No claims were rejected.")
        lines.append("")

    # Deterministic timeline.
    lines.append("## Deterministic timeline")
    lines.append("")
    lines.append(
        "Every event normalized to the canonical schema and tagged with ATT&CK "
        "deterministically. The event handle links to its full record in the appendix."
    )
    lines.append("")
    lines.append("|Time (UTC)|Host|Principal|Action|Object|ATT&CK|Event|")
    lines.append("|----------|----|---------|------|------|------|-----|")
    for event in model.events:
        techniques = " ".join(f"`{tid}`" for tid in event["techniques"]) or ""
        lines.append(
            "|"
            + "|".join(
                [
                    _cell(event["datetime"]),
                    _cell(event["host"]),
                    _mono(event["principal"]),
                    _mono(event["action"]),
                    _mono(event["object"]),
                    techniques,
                    f"`{_short(event['event_id'])}`",
                ]
            )
            + "|"
        )
    lines.append("")

    # Activity episodes.
    lines.append("## Activity episodes")
    lines.append("")
    lines.append(
        "Events grouped into episodes by host, principal, and time proximity. Each episode "
        "is one actor's coherent run of activity on one host."
    )
    lines.append("")
    if model.episodes:
        for episode in model.episodes:
            host = _cell(episode["host"]) or "unattributed"
            principal = _mono(episode["principal"]) or "`unattributed`"
            members = ", ".join(f"`{_short(eid)}`" for eid in episode["event_ids"])
            lines.append(
                f"- `{episode['episode_id']}` on {host}, principal {principal}: "
                f"{episode['event_count']} event(s) from {episode['start']} to {episode['end']}."
            )
            lines.append(f"  Events: {members}")
        lines.append("")
    else:
        lines.append("No episodes were formed.")
        lines.append("")

    # Indicators of compromise.
    lines.append("## Indicators of compromise")
    lines.append("")
    lines.append(
        "Indicators extracted from the events and defanged for safe handling: IPs and "
        "domains have their dots bracketed, hashes and paths are listed verbatim."
    )
    lines.append("")
    if model.iocs:
        lines.append("|Type|Indicator (defanged)|Events|")
        lines.append("|----|--------------------|-----:|")
        for ioc in model.iocs:
            lines.append(
                "|"
                + "|".join(
                    [
                        _cell(ioc["ioc_type"]),
                        _mono(ioc["defanged"]),
                        str(ioc["event_count"]),
                    ]
                )
                + "|"
            )
        lines.append("")
    else:
        lines.append("No indicators were extracted.")
        lines.append("")

    # Evidence appendix.
    lines.append("## Evidence appendix")
    lines.append("")
    lines.append(
        "The full canonical record for every event, with its source provenance for audit. "
        "This is the deterministic source of truth the narrative is fenced to."
    )
    lines.append("")
    for event in model.events:
        lines.append(f"### `{event['event_id']}`")
        lines.append("")
        lines.append(f"- message: {_cell(event['message'])}")
        lines.append(f"- datetime: `{_cell(event['datetime'])}` ({_cell(event['timestamp_desc'])})")
        lines.append(f"- host: {_cell(event['host'])}")
        lines.append(f"- principal: {_mono(event['principal'])}")
        lines.append(f"- action: {_mono(event['action'])}")
        lines.append(f"- object: {_mono(event['object'])}")
        lines.append(f"- source: {_cell(event['source_tool'])} / {_cell(event['source_artifact'])}")
        if event["attack_techniques"]:
            tags = ", ".join(
                f"`{tag['technique_id']}` ({tag['mapping_source']})"
                for tag in event["attack_techniques"]
            )
            lines.append(f"- attack_techniques: {tags}")
        if event["episode_id"]:
            lines.append(f"- episode: `{event['episode_id']}`")
        if event["referenced_iocs"]:
            iocs = ", ".join(
                f"`{ioc['defanged']}` ({ioc['type']})" for ioc in event["referenced_iocs"]
            )
            lines.append(f"- iocs: {iocs}")
        if event["details"]:
            lines.append("- details:")
            for key, value in event["details"].items():
                lines.extend(_detail_lines(str(key), value, "  "))
        if event["provenance"]:
            provenance = ", ".join(_mono(ref) for ref in event["provenance"])
            lines.append(f"- provenance: {provenance}")
        lines.append("")

    lines.append(
        "Generated by Casebound, offline, from synthetic evidence. Citation accuracy is 1.0 "
        "by construction: every claim above resolves to a field-consistent event."
    )
    lines.append("")
    return "\n".join(lines)


def render_markdown_report(
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
    """Render the ticket-ready Markdown report from the pipeline output (FR30).

    Mirrors ``render_report`` (HTML) exactly in its inputs and content. Returns a
    deterministic Markdown string with a trailing newline.
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
    return _render(model)


def write_markdown_report(
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
    """Render the Markdown report and write it to ``path``, returning the path written.

    Creates the parent directory if needed. Offline, no network.
    """
    text = render_markdown_report(
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
    path.write_text(text, encoding="utf-8")
    return path
