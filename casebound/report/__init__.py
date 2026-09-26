"""Reporting: the hero deliverable and its machine-readable siblings.

Renders a ``Case`` as a self-contained HTML report, a Markdown report, a JSON
report, a JSONL timeline, and an ATT&CK Navigator layer (FR28 to FR32). Every format
draws from one shared content model (``casebound.report.model``), so they never
drift apart, and every narrative sentence is phrased from the cited event's own
fields (``casebound.report.phrasing``), never from a model's prose.

Layout (PRD Section 13):

  - ``model``        : the shared content model built from a case.
  - ``phrasing``     : deterministic sentences from canonical event fields.
  - ``html``         : the self-contained HTML report (the hero deliverable).
  - ``markdown``     : the ticket-ready Markdown report (FR30).
  - ``json_report``  : the JSON report (FR29) and the ``events.jsonl`` timeline.
  - ``attack_layer`` : the ATT&CK Navigator layer of observed techniques (FR31).
  - ``writer``       : writes all of the above for a case in one call.
"""

from __future__ import annotations

from casebound.report.attack_layer import (
    build_navigator_layer,
    render_navigator_layer,
    write_navigator_layer,
)
from casebound.report.html import DEFAULT_HTML_MAX_EVENTS, render_html, write_html
from casebound.report.json_report import (
    render_events_jsonl,
    render_json,
    write_events_jsonl,
    write_json,
)
from casebound.report.markdown import DEFAULT_MARKDOWN_MAX_EVENTS, render_markdown, write_markdown
from casebound.report.model import NO_MODEL_LABEL, ReportModel, build_report_model
from casebound.report.phrasing import phrase_event
from casebound.report.writer import (
    EVENTS_NAME,
    LAYER_NAME,
    REPORT_HTML_NAME,
    REPORT_JSON_NAME,
    REPORT_MARKDOWN_NAME,
    ReportPaths,
    write_reports,
)

__all__ = [
    "DEFAULT_HTML_MAX_EVENTS",
    "DEFAULT_MARKDOWN_MAX_EVENTS",
    "EVENTS_NAME",
    "LAYER_NAME",
    "NO_MODEL_LABEL",
    "REPORT_HTML_NAME",
    "REPORT_JSON_NAME",
    "REPORT_MARKDOWN_NAME",
    "ReportModel",
    "ReportPaths",
    "build_navigator_layer",
    "build_report_model",
    "phrase_event",
    "render_events_jsonl",
    "render_html",
    "render_json",
    "render_markdown",
    "render_navigator_layer",
    "write_events_jsonl",
    "write_html",
    "write_json",
    "write_markdown",
    "write_navigator_layer",
    "write_reports",
]
