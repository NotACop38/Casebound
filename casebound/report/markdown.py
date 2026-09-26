"""The Markdown report renderer (PRD FR30).

Emits the same content as the HTML report as Markdown suitable for pasting into a
ticket or a chat. Both renderers draw from the shared ``ReportModel``, so the
narrative, the audit, the ATT&CK matrix, the episodes, the indicators, the timeline,
and the evidence appendix can never drift between formats.

Evidence fields are attacker-controlled by definition, and a ticket renderer may
honor raw HTML and links, so every evidence-derived string is neutralized: whitespace
collapses (a value cannot break out of its bullet or table row), Markdown-significant
punctuation is backslash-escaped (no links, images, code-span breakouts, raw HTML, or
table breaks), and a bare http(s) URL is defanged to hxxp(s) so autolinking cannot
make it clickable.

The output is deterministic and ends with a single trailing newline.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from casebound.pipeline import Case
from casebound.report.model import NarrativeEntry, ReportModel, build_report_model

__all__ = ["DEFAULT_MARKDOWN_MAX_EVENTS", "render_markdown", "write_markdown"]

# The most events the Markdown timeline and appendix render before switching to the
# notable events only. A ticket is a worse place than a browser for a long document.
DEFAULT_MARKDOWN_MAX_EVENTS = 500

_SHORT_ID_LEN = 12
_PROBLEM_LIST_LIMIT = 50

# The structurally dangerous Markdown punctuation neutralized in evidence-derived
# prose: a backslash escape kills links and images ([]()), code spans (backtick),
# raw HTML (<>), and table breaks (|). Backslash itself is in the class so an
# existing one cannot un-escape what follows. Emphasis characters (*_) are left
# alone: they are cosmetic, and escaping them would mangle snake_case verbs and
# Windows paths in the raw text.
_MD_SPECIAL_RE = re.compile(r"[\\`\[\]<>()|]")

# GFM autolinks a bare http(s) URL even with every bracket escaped, so a URL in
# evidence prose is defanged to the DFIR-conventional hxxp(s) instead.
_URL_SCHEME_RE = re.compile(r"(?i)\bhttp(s?)://")


def _short(event_id: str) -> str:
    return event_id[:_SHORT_ID_LEN]


def _time(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("T", " ").removesuffix("Z") + " UTC"


def _collapse(value: Any) -> str:
    """Stringify and collapse all whitespace runs (newlines included) to a space."""
    return " ".join(str(value).split())


def _cell(value: Any) -> str:
    """Render evidence text inert, for prose and table cells alike (None is blank)."""
    if value is None:
        return ""
    escaped = _MD_SPECIAL_RE.sub(lambda match: "\\" + match.group(0), _collapse(value))
    return _URL_SCHEME_RE.sub(lambda match: f"hxxp{match.group(1)}://", escaped)


def _code_span(text: str) -> str:
    """Wrap already-collapsed text in a code span it cannot break out of.

    A backslash does not escape inside a code span, so backticks are replaced
    outright; pipes are escaped because GFM splits table rows before code spans are
    parsed.
    """
    return "`" + text.replace("`", "'").replace("|", "\\|") + "`"


def _mono(value: Any) -> str:
    """Render a value as inline code, or blank when absent."""
    if value is None or value == "":
        return ""
    return _code_span(_collapse(value))


def _detail_lines(key: str, value: Any, indent: str) -> list[str]:
    """Render one details entry as a nested bullet, recursing into mappings."""
    label = _cell(key)
    if isinstance(value, Mapping):
        if not value:
            return [f"{indent}- {label}: (none)"]
        out = [f"{indent}- {label}:"]
        for sub_key, sub_value in value.items():
            out.extend(_detail_lines(str(sub_key), sub_value, indent + "  "))
        return out
    if isinstance(value, (list, tuple)):
        if not value:
            return [f"{indent}- {label}: (none)"]
        return [f"{indent}- {label}: " + ", ".join(_mono(item) or "(empty)" for item in value)]
    return [f"{indent}- {label}: {_mono(value) or '(empty)'}"]


def _entry_lines(entry: NarrativeEntry, verified: bool) -> list[str]:
    techniques = " ".join(f"`{tech.technique_id}`" for tech in entry.techniques)
    lines = [f"- `{_time(entry.datetime)}` {_cell(entry.statement)}"]
    detail = f"  {_cell(entry.detection)}"
    if entry.host:
        detail = f"  {_cell(entry.host)}: {_cell(entry.detection)}"
    if techniques:
        detail += f" {techniques}"
    lines.append(detail)
    evidence = f"  Backing evidence: `{_short(entry.backing_event_id)}`"
    if verified:
        evidence += f" (verified: {', '.join(entry.verified_fields)}"
        if entry.round_index:
            evidence += f"; accepted after revision round {entry.round_index}"
        evidence += ")"
    if entry.context_citations:
        context = ", ".join(f"`{_short(cid)}`" for cid in entry.context_citations)
        evidence += f"; also cited for context: {context}"
    lines.append(evidence)
    return lines


def _grouped(model: ReportModel, entries: Sequence[NarrativeEntry], verified: bool) -> list[str]:
    lines: list[str] = []
    by_episode: dict[str | None, list[NarrativeEntry]] = {}
    for entry in entries:
        by_episode.setdefault(entry.episode_id, []).append(entry)
    for episode in model.episodes:
        members = by_episode.get(episode["episode_id"])
        if not members:
            continue
        host = _cell(episode["host"]) or "unattributed host"
        principal = _mono(episode["principal"]) or "unattributed"
        lines.append(
            f"### `{episode['episode_id']}` {host}, {principal}, "
            f"{_time(episode['start'])} to {_time(episode['end'])}"
        )
        lines.append("")
        for entry in members:
            lines.extend(_entry_lines(entry, verified))
        lines.append("")
    for entry in by_episode.get(None, []):
        lines.extend(_entry_lines(entry, verified))
    return lines


def _render(model: ReportModel, max_events: int | None) -> str:
    lines: list[str] = []
    stats = model.stats

    lines.append(f"# {_cell(model.case_name)}")
    lines.append("")
    evidence = "; ".join(
        f"{_cell(item['source'])}: {_mono(item['file'])} ({item['records']} records)"
        for item in model.inputs
    )
    lines.append(f"Casebound investigation report. Evidence: {evidence}.")
    lines.append(
        f"Narrative: {_cell(model.narrative_label)}. ATT&CK Enterprise "
        f"{model.attack.attack_version}. Generated by {model.generator}, offline."
    )
    lines.append("")
    lines.append(
        "> The guarantee. Every sentence in the narrative is composed from the fields of "
        "the timeline event it cites. A claim reaches this report only after a "
        "deterministic verifier confirmed its cited event exists and matches every fact "
        "it asserted (time, principal, action, object); rejected claims appear only in "
        "the audit."
    )
    lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append("|Measure|Count|")
    lines.append("|-------|----:|")
    rows = [
        ("Events", stats["events"]),
        ("Hosts", stats["hosts"]),
        ("ATT&CK techniques", stats["techniques"]),
        ("Activity episodes", stats["episodes"]),
        ("Indicators", stats["iocs"]),
    ]
    if not model.no_model:
        rows += [
            ("Verified claims", stats["narrative_entries"]),
            ("Rejected claims", stats["rejected_claims"]),
        ]
    if stats["problems"]:
        rows.append(("Unparsed rows", stats["problems"]))
    lines.extend(f"|{label}|{count}|" for label, count in rows)
    lines.append("")

    if model.no_model:
        lines.append("## Key findings")
        lines.append("")
        lines.append(
            "No language model configured. This is the deterministic report: every event "
            "that exhibits an ATT&CK technique or that its detection rule rated high or "
            "critical, phrased from its own fields and grouped by episode."
        )
        lines.append("")
        if model.findings:
            lines.extend(_grouped(model, model.findings[: max_events or None], verified=False))
        else:
            lines.append("No event carries an ATT&CK technique or a high severity.")
            lines.append("")
    else:
        lines.append("## Verified narrative")
        lines.append("")
        lines.append(
            "Each sentence is composed from the fields of the event it cites. The model "
            "selected the events; the verifier confirmed each claim against its event."
        )
        lines.append("")
        if model.narrative:
            lines.extend(_grouped(model, model.narrative, verified=True))
        else:
            lines.append("The model proposed no claim that survived verification.")
            lines.append("")

        lines.append("## Rejected-claims audit")
        lines.append("")
        lines.append(
            "Every claim the verifier rejected, with the reason. A rejected draft is shown "
            "only for review; it is not a finding."
        )
        lines.append("")
        if model.audit:
            for entry in model.audit:
                flags = entry["reason"] + (", dropped" if entry["dropped"] else "")
                lines.append(
                    f"- \\[{flags}\\] (round {entry['round_index']}) model draft: "
                    f"{_cell(entry['claim_text'])}"
                )
                lines.append(f"  Reason: {_cell(entry['detail'])}")
                if entry["citations"]:
                    cited = ", ".join(_mono(cid) for cid in entry["citations"])
                    lines.append(f"  Cited: {cited}")
            lines.append("")
        else:
            lines.append("No claims were rejected.")
            lines.append("")

    lines.append("## ATT&CK matrix")
    lines.append("")
    if model.attack.columns:
        for column in model.attack.columns:
            cells = ", ".join(
                f"`{cell.technique_id}` {_cell(cell.name)} ({cell.count})" for cell in column.cells
            )
            lines.append(f"- **{_cell(column.name)}**: {cells}")
    else:
        lines.append("No event carries an ATT&CK technique.")
    for item in model.attack.unmapped:
        lines.append(
            f"- Not a current technique: `{item['technique_id']}` ({item['status']}, "
            f"{item['count']} events)"
        )
    lines.append("")

    lines.append("## Activity episodes")
    lines.append("")
    if model.episodes:
        lines.append("|Episode|Host|Principal|From (UTC)|To (UTC)|Events|Techniques|")
        lines.append("|-------|----|---------|----------|--------|-----:|----------|")
        for episode in model.episodes:
            techniques = " ".join(f"`{tid}`" for tid in episode["techniques"])
            lines.append(
                "|"
                + "|".join(
                    [
                        f"`{episode['episode_id']}`",
                        _cell(episode["host"]) or "unattributed",
                        _mono(episode["principal"]) or "unattributed",
                        _cell(episode["start"]),
                        _cell(episode["end"]),
                        str(episode["event_count"]),
                        techniques,
                    ]
                )
                + "|"
            )
    else:
        lines.append("No episodes were formed.")
    lines.append("")

    lines.append("## Indicators of compromise")
    lines.append("")
    if model.iocs:
        lines.append("|Type|Indicator (defanged)|Events|")
        lines.append("|----|--------------------|-----:|")
        for ioc in model.iocs:
            lines.append(
                f"|{_cell(ioc['ioc_type'])}|{_mono(ioc['defanged'])}|{ioc['event_count']}|"
            )
    else:
        lines.append("No indicators were extracted.")
    lines.append("")

    shown, capped = model.displayed_events(max_events)
    lines.append("## Timeline")
    lines.append("")
    if capped:
        lines.append(
            f"This case has {stats['events']} events; the {len(shown)} notable ones are "
            "shown here. Every event is in report.json and events.jsonl."
        )
        lines.append("")
    lines.append("|Time (UTC)|Host|Principal|Action|Object|ATT&CK|Event|")
    lines.append("|----------|----|---------|------|------|------|-----|")
    for event in shown:
        techniques = " ".join(f"`{tech['technique_id']}`" for tech in event["techniques"])
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

    lines.append("## Evidence appendix")
    lines.append("")
    lines.append("The full canonical record of each event, with the source records it came from.")
    lines.append("")
    for event in shown:
        lines.append(f"### `{event['event_id']}`")
        lines.append("")
        lines.append(f"- message: {_cell(event['message'])}")
        lines.append(f"- datetime: `{_cell(event['datetime'])}` ({_cell(event['timestamp_desc'])})")
        lines.append(f"- timestamp_raw: {_mono(event['timestamp_raw'])}")
        lines.append(f"- host: {_cell(event['host'])}")
        lines.append(f"- principal: {_mono(event['principal'])}")
        lines.append(f"- action: {_mono(event['action'])}")
        lines.append(f"- object: {_mono(event['object'])}")
        lines.append(f"- source: {_cell(event['source_tool'])} / {_cell(event['source_artifact'])}")
        if event["techniques"]:
            tags = ", ".join(
                f"`{tech['technique_id']}` ({_cell(tech['mapping_source'])})"
                for tech in event["techniques"]
            )
            lines.append(f"- attack_techniques: {tags}")
        if event["episode_id"]:
            lines.append(f"- episode: `{event['episode_id']}`")
        if event["referenced_iocs"]:
            iocs = ", ".join(
                f"{_mono(ioc['defanged'])} ({_cell(ioc['type'])})"
                for ioc in event["referenced_iocs"]
            )
            lines.append(f"- iocs: {iocs}")
        if event["details"]:
            lines.append("- details:")
            for key, value in event["details"].items():
                lines.extend(_detail_lines(str(key), value, "  "))
        if event["provenance"]:
            lines.append("- provenance: " + ", ".join(_mono(ref) for ref in event["provenance"]))
        lines.append("")

    if model.problems:
        lines.append("## Unparsed rows")
        lines.append("")
        for problem in model.problems[:_PROBLEM_LIST_LIMIT]:
            lines.append(
                f"- {_mono(problem['source_file'])} {_mono(problem['record'])}: "
                f"{_cell(problem['reason'])}"
            )
        if len(model.problems) > _PROBLEM_LIST_LIMIT:
            lines.append(
                f"- and {len(model.problems) - _PROBLEM_LIST_LIMIT} more (see report.json)"
            )
        lines.append("")

    lines.append(
        f"Generated by {model.generator} from already-collected evidence, read-only. "
        "Casebound assists a qualified analyst; it does not replace one."
    )
    lines.append("")
    return "\n".join(lines)


def render_markdown(
    case: Case,
    *,
    model: ReportModel | None = None,
    max_events: int | None = DEFAULT_MARKDOWN_MAX_EVENTS,
) -> str:
    """Render the ticket-ready Markdown report for ``case`` (FR30)."""
    return _render(model if model is not None else build_report_model(case), max_events)


def write_markdown(
    path: Path,
    case: Case,
    *,
    model: ReportModel | None = None,
    max_events: int | None = DEFAULT_MARKDOWN_MAX_EVENTS,
) -> Path:
    """Render the Markdown report and write it to ``path``, returning the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_markdown(case, model=model, max_events=max_events), encoding="utf-8")
    return path
