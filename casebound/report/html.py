"""The self-contained HTML report renderer (PRD FR28, FR32; the hero deliverable).

Renders one Jinja2 template into a single HTML file that fetches nothing at view
time: no scripts, stylesheets, fonts, images, or links to other sites. The
stylesheet is inlined and every value comes from the shared ``ReportModel``, so the
HTML, JSON, and Markdown reports carry the same content and never drift apart.

What the report shows, in reading order: the case and its evidence; the verified
narrative (or, with no model, the deterministic key findings), grouped by activity
episode with every sentence linked to its backing event; the rejected-claims audit;
the ATT&CK matrix of observed techniques; the episodes; the indicators; the
timeline; the evidence appendix; and any rows that failed to normalize.

A large case is capped for readability (``DEFAULT_HTML_MAX_EVENTS``): past the cap,
the timeline and appendix show the notable events and say so, while the JSON report
and the events file always carry every event.

Autoescaping is on, so every evidence-derived string (messages, paths, command
lines preserved in details) is HTML-escaped: hostile content in the evidence cannot
inject markup into the report.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from functools import lru_cache
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from casebound.pipeline import Case
from casebound.report.model import NarrativeEntry, ReportModel, build_report_model

__all__ = ["DEFAULT_HTML_MAX_EVENTS", "render_html", "write_html"]

# The most events the HTML timeline and appendix render before switching to the
# notable events only. A few thousand keeps the page responsive in a browser.
DEFAULT_HTML_MAX_EVENTS = 2000

# How many leading hex characters of an event id to show as its short handle. The
# full id is always the anchor and link target; this is only the visible label.
SHORT_ID_LEN = 12

# How many malformed rows the problems section lists before summarizing the rest.
_PROBLEM_LIST_LIMIT = 100


def _display_time(value: str | None) -> str:
    """Render a canonical UTC datetime for reading: ``2026-03-14 08:42:17 UTC``."""
    if not value:
        return ""
    return value.replace("T", " ").removesuffix("Z") + " UTC"


@lru_cache(maxsize=1)
def _environment() -> Environment:
    """Build the Jinja2 environment once, with autoescaping on for the template."""
    env = Environment(
        loader=PackageLoader("casebound.report", "templates"),
        autoescape=select_autoescape(default=True, default_for_string=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["short"] = lambda value: str(value)[:SHORT_ID_LEN]
    env.filters["utc"] = _display_time
    return env


def _group_by_episode(
    entries: Sequence[NarrativeEntry], episodes: Sequence[Mapping[str, Any]]
) -> list[dict[str, Any]]:
    """Group narrative entries under their episodes, in chronological episode order."""
    by_episode: dict[str | None, list[NarrativeEntry]] = {}
    for entry in entries:
        by_episode.setdefault(entry.episode_id, []).append(entry)
    groups: list[dict[str, Any]] = [
        {"episode": episode, "entries": by_episode[episode["episode_id"]]}
        for episode in episodes
        if episode["episode_id"] in by_episode
    ]
    if None in by_episode:
        groups.append({"episode": None, "entries": by_episode[None]})
    return groups


def render_html(
    case: Case,
    *,
    model: ReportModel | None = None,
    max_events: int | None = DEFAULT_HTML_MAX_EVENTS,
) -> str:
    """Render the self-contained HTML report for ``case``.

    ``model`` may be passed when the caller already built it (so the formats share
    one build); ``max_events`` caps the timeline and appendix (None renders every
    event).
    """
    report = model if model is not None else build_report_model(case)
    shown, capped = report.displayed_events(max_events)
    shown_ids = {event["event_id"] for event in shown}
    entries = report.findings if report.no_model else report.narrative
    context: dict[str, Any] = {
        "report": report,
        "groups": _group_by_episode(entries, report.episodes),
        "events": shown,
        "shown_ids": shown_ids,
        "capped": capped,
        "problems": report.problems[:_PROBLEM_LIST_LIMIT],
        "problems_omitted": max(len(report.problems) - _PROBLEM_LIST_LIMIT, 0),
    }
    return _environment().get_template("report.html.j2").render(**context)


def write_html(
    path: Path,
    case: Case,
    *,
    model: ReportModel | None = None,
    max_events: int | None = DEFAULT_HTML_MAX_EVENTS,
) -> Path:
    """Render the HTML report and write it to ``path``, returning the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_html(case, model=model, max_events=max_events), encoding="utf-8")
    return path
