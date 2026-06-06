"""The machine-readable JSON report renderer (PRD FR29).

Emits the same content as the HTML report (the hero deliverable) as one JSON
document, so a downstream tool can consume the case without scraping HTML. Both
renderers draw from the shared ``ReportModel`` (see ``casebound.report.model``), so
the JSON and the HTML can never drift apart: the timeline, the verified narrative
with its citations, the ATT&CK tags, the activity episodes, the indicator set, the
evidence appendix, and the rejected-claims audit are all present.

The output is deterministic: keys are emitted in a stable order and the document
ends with a trailing newline, so a clean clone regenerates byte-identical JSON and
the committed sample never drifts silently.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from casebound.enrich.cluster import Episode
from casebound.enrich.ioc import IocSet
from casebound.normalize.schema import Event, RawRef
from casebound.report.model import build_report_model
from casebound.verify.engine import VerificationResult

__all__ = ["render_json_report", "write_json_report"]


def render_json_report(
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
    """Render the machine-readable JSON report from the pipeline output (FR29).

    Mirrors ``render_report`` (HTML) exactly in its inputs and content. Returns a
    deterministic, human-readable JSON string with a trailing newline.
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
    body: dict[str, Any] = model.to_dict()
    return json.dumps(body, indent=2, ensure_ascii=False) + "\n"


def write_json_report(
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
    """Render the JSON report and write it to ``path``, returning the path written.

    Creates the parent directory if needed. Offline, no network.
    """
    text = render_json_report(
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
