"""Reporting: the hero deliverable and its machine-readable siblings.

Renders the self-contained HTML report (timeline, verified narrative with inline
citations, ATT&CK heatmap, IOC table, evidence appendix, rejected-claims audit),
plus JSON and Markdown, and the ATT&CK Navigator layer (FR28 to FR32). The HTML
fetches no external assets at view time.

Layout (PRD Section 13): html.py, templates/ (this Phase 1 slice), with json_report.py,
markdown.py, and attack_layer.py to follow.

  - ``html`` : the self-contained HTML report (timeline, verified narrative with
    inline citations linking to the evidence appendix, rejected-claims audit).

TODO(Phase 4): JSON and Markdown renderers and the Navigator layer.
"""

from __future__ import annotations

from casebound.report.html import NO_MODEL_LABEL, render_report, write_report

__all__ = ["NO_MODEL_LABEL", "render_report", "write_report"]
