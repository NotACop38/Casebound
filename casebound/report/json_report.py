"""The machine-readable outputs: the JSON report (PRD FR29) and the events file.

``report.json`` carries the same content as the HTML report as one JSON document,
drawn from the shared ``ReportModel``, so a downstream tool can consume a case
without scraping HTML. It always carries every event, however large the case.

``events.jsonl`` is the timeline itself: one canonical event per line, exactly the
schema in ``casebound/data/event.schema.json``. It is what ``casebound verify``
checks externally drafted claims against, and its ``message``, ``datetime``, and
``timestamp_desc`` fields are the ones Timesketch requires for a JSONL import.

Both outputs are deterministic (stable key order, a trailing newline), so the same
case always regenerates byte-identical files.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from casebound.normalize.schema import Event
from casebound.pipeline import Case
from casebound.report.model import ReportModel, build_report_model

__all__ = ["render_events_jsonl", "render_json", "write_events_jsonl", "write_json"]


def render_json(case: Case, *, model: ReportModel | None = None) -> str:
    """Render the JSON report for ``case`` as deterministic, readable JSON."""
    report = model if model is not None else build_report_model(case)
    return json.dumps(report.to_dict(), indent=2, ensure_ascii=False) + "\n"


def write_json(path: Path, case: Case, *, model: ReportModel | None = None) -> Path:
    """Render the JSON report and write it to ``path``, returning the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_json(case, model=model), encoding="utf-8")
    return path


def render_events_jsonl(events: Iterable[Event]) -> str:
    """Render canonical events as JSONL: one schema-valid event per line."""
    return "".join(
        json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")) + "\n"
        for event in events
    )


def write_events_jsonl(path: Path, events: Iterable[Event]) -> Path:
    """Write canonical events to ``path`` as JSONL, returning the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for event in events:
            handle.write(json.dumps(event.to_dict(), ensure_ascii=False, separators=(",", ":")))
            handle.write("\n")
    return path
