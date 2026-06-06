"""Reporting: the hero deliverable and its machine-readable siblings.

Renders the self-contained HTML report (timeline, verified narrative with inline
citations, ATT&CK heatmap, IOC table, evidence appendix, rejected-claims audit),
plus JSON and Markdown, and the ATT&CK Navigator layer (FR28 to FR32). The HTML
fetches no external assets at view time. All three report formats draw from one
shared content model (``casebound.report.model``), so they never drift apart.

Layout (PRD Section 13): html.py, json_report.py, markdown.py, attack_layer.py,
model.py, templates/.

  - ``html``         : the self-contained HTML report (the hero deliverable).
  - ``json_report``  : the machine-readable JSON report (FR29).
  - ``markdown``     : the ticket-ready Markdown report (FR30).
  - ``attack_layer`` : the ATT&CK Navigator layer of observed techniques (FR31).
"""

from __future__ import annotations

from casebound.report.attack_layer import (
    ATTACK_TECHNIQUES,
    UnknownTechniqueError,
    build_navigator_layer,
    render_navigator_layer,
    write_navigator_layer,
)
from casebound.report.html import NO_MODEL_LABEL, render_report, write_report
from casebound.report.json_report import render_json_report, write_json_report
from casebound.report.markdown import render_markdown_report, write_markdown_report
from casebound.report.model import ReportModel, build_report_model

__all__ = [
    "ATTACK_TECHNIQUES",
    "NO_MODEL_LABEL",
    "ReportModel",
    "UnknownTechniqueError",
    "build_navigator_layer",
    "build_report_model",
    "render_json_report",
    "render_markdown_report",
    "render_navigator_layer",
    "render_report",
    "write_json_report",
    "write_markdown_report",
    "write_navigator_layer",
    "write_report",
]
