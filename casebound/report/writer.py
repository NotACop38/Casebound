"""Write every report output for a case in one call.

The CLI, the demo, and any library caller write the same set of files, from one
shared ``ReportModel`` build so the formats cannot disagree:

  - ``report.html``: the self-contained HTML report (the hero deliverable).
  - ``report.md``: the ticket-ready Markdown report.
  - ``report.json``: the machine-readable report, every event included.
  - ``events.jsonl``: the canonical timeline, one event per line.
  - ``attack_navigator_layer.json``: the ATT&CK Navigator layer.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from casebound.pipeline import Case
from casebound.report.attack_layer import write_navigator_layer
from casebound.report.html import DEFAULT_HTML_MAX_EVENTS, write_html
from casebound.report.json_report import write_events_jsonl, write_json
from casebound.report.markdown import DEFAULT_MARKDOWN_MAX_EVENTS, write_markdown
from casebound.report.model import build_report_model

__all__ = [
    "EVENTS_NAME",
    "LAYER_NAME",
    "REPORT_HTML_NAME",
    "REPORT_JSON_NAME",
    "REPORT_MARKDOWN_NAME",
    "ReportPaths",
    "write_reports",
]

REPORT_HTML_NAME = "report.html"
REPORT_MARKDOWN_NAME = "report.md"
REPORT_JSON_NAME = "report.json"
EVENTS_NAME = "events.jsonl"
LAYER_NAME = "attack_navigator_layer.json"


@dataclass(frozen=True)
class ReportPaths:
    """Where each output of one report run was written."""

    html: Path
    markdown: Path
    json: Path
    events: Path
    layer: Path

    def all(self) -> tuple[Path, ...]:
        """Every written path, in a stable order."""
        return (self.html, self.markdown, self.json, self.events, self.layer)


def write_reports(
    case: Case,
    out_dir: Path,
    *,
    html_max_events: int | None = DEFAULT_HTML_MAX_EVENTS,
    markdown_max_events: int | None = DEFAULT_MARKDOWN_MAX_EVENTS,
) -> ReportPaths:
    """Write every report output for ``case`` into ``out_dir`` and return the paths."""
    out_dir.mkdir(parents=True, exist_ok=True)
    model = build_report_model(case)
    return ReportPaths(
        html=write_html(out_dir / REPORT_HTML_NAME, case, model=model, max_events=html_max_events),
        markdown=write_markdown(
            out_dir / REPORT_MARKDOWN_NAME, case, model=model, max_events=markdown_max_events
        ),
        json=write_json(out_dir / REPORT_JSON_NAME, case, model=model),
        events=write_events_jsonl(out_dir / EVENTS_NAME, case.events),
        layer=write_navigator_layer(out_dir / LAYER_NAME, case.events, name=case.name),
    )
