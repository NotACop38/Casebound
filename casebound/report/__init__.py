"""Reporting: the hero deliverable and its machine-readable siblings.

Renders the self-contained HTML report (timeline, verified narrative with inline
citations, ATT&CK heatmap, IOC table, evidence appendix, rejected-claims audit),
plus JSON and Markdown, and the ATT&CK Navigator layer (FR28 to FR32). The HTML
fetches no external assets at view time.

Planned layout (PRD Section 13): html.py, json_report.py, markdown.py,
attack_layer.py, templates/.

TODO(Phase 1): the HTML renderer with the timeline, the verified narrative with
  inline citations, and the evidence appendix.
TODO(Phase 4): JSON and Markdown renderers and the Navigator layer.
"""

from __future__ import annotations
