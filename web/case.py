"""Case assembly for the optional web UI (PRD Section 8, decision D4, Phase 9).

A ``Case`` is everything the report layer needs to render: the normalized,
ATT&CK-tagged canonical events, the verifier output (or None for the
deterministic no-model path), and the enrichment outputs (episodes and
indicators). The web app builds one ``Case`` per loaded timeline and hands it
straight to the existing report renderer.

The keystone here is that the web UI never forks the report logic. Both
``render_case_report`` and ``case_report_model`` call the unchanged
``casebound.report`` functions with exactly the inputs the CLI uses, so the page
the browser shows is byte for byte the report ``casebound demo`` writes to disk.
The web layer only assembles the case; it never decides what a report says.

The bundled demo case mirrors the default ``casebound demo`` pipeline (regenerate
the synthetic scenario, normalize, tag, cluster, extract indicators, then draft
and verify with the offline narrator), so the demo report served here equals the
one the CLI produces. An uploaded timeline takes the deterministic no-model path:
it is parsed read-only into the schema and rendered with no narrative, since the
scripted demo narrator is specific to the bundled scenario.

Everything here runs fully offline. No evidence leaves the host: the only file
handling is writing the timeline text to a private temporary file so the existing
file-based ingest adapter can read it, and that file is removed immediately. The
adapters are read-only and never open, fetch, or execute anything (Hard rule 1).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from casebound.enrich.attack import tag_events
from casebound.enrich.cluster import Episode, cluster_events
from casebound.enrich.ioc import IocSet, extract_iocs
from casebound.generate import CSV_FILENAME, DEFAULT_SEED, generate
from casebound.ingest import HayabusaAdapter
from casebound.narrate import OfflineDemoNarrator
from casebound.normalize import normalize_records
from casebound.normalize.schema import Event, RawRef
from casebound.report import ReportModel, build_report_model, render_report
from casebound.verify import NarrativeModel, VerificationResult, verify_narrative

__all__ = [
    "DEMO_CASE_ID",
    "Case",
    "build_demo_case",
    "build_uploaded_case",
    "case_report_model",
    "render_case_report",
]

# The stable id of the bundled demo case, always present in the store.
DEMO_CASE_ID = "demo"
_DEMO_TITLE = "Bundled synthetic scenario (office_intrusion)"

# The source tool every MVP timeline is read as. The web UI ingests Hayabusa CSV,
# the same single source the CLI demo proves end to end (PRD Section 5).
_SOURCE_TOOL = "hayabusa"

# A safe fallback name for an upload whose filename is empty after sanitizing.
_FALLBACK_UPLOAD_NAME = "upload.csv"


@dataclass(frozen=True)
class Case:
    """One loaded timeline, ready for the report layer.

    ``events`` are the normalized, ATT&CK-tagged canonical events. ``verification``
    is the verifier output, or None for the deterministic no-model path (FR26).
    ``provenance``, ``episodes``, and ``iocs`` are the pipeline outputs the report
    annotates with. ``model_label`` names the narrative source, or None when there
    is no narrative. The ``report_kwargs`` property packages the keyword arguments
    the report renderer expects, so the case feeds the unchanged report layer
    directly.
    """

    case_id: str
    title: str
    source_label: str
    scenario: str
    source_tool: str
    model_label: str | None
    events: tuple[Event, ...]
    verification: VerificationResult | None
    provenance: Mapping[str, Sequence[RawRef]]
    episodes: tuple[Episode, ...]
    iocs: IocSet

    @property
    def event_count(self) -> int:
        """How many canonical events the case carries."""
        return len(self.events)

    @property
    def has_narrative(self) -> bool:
        """True when a verified narrative was produced (not the no-model path)."""
        return self.verification is not None

    @property
    def report_kwargs(self) -> dict[str, Any]:
        """The keyword arguments the report renderers expect for this case."""
        return {
            "scenario": self.scenario,
            "source_tool": self.source_tool,
            "model_label": self.model_label,
            "provenance": self.provenance,
            "episodes": self.episodes,
            "iocs": self.iocs,
        }


def render_case_report(case: Case) -> str:
    """Render the self-contained HTML report for a case (the unchanged hero).

    Calls ``casebound.report.render_report`` with exactly the inputs the CLI uses,
    so the served report is identical to the one ``casebound demo`` writes.
    """
    return render_report(list(case.events), case.verification, **case.report_kwargs)


def case_report_model(case: Case) -> ReportModel:
    """Build the shared report content model for a case (for the timeline view).

    The timeline page reuses the same deterministic content model the report
    formats draw from, so the browsable timeline never drifts from the report.
    """
    return build_report_model(list(case.events), case.verification, **case.report_kwargs)


def _analyze_csv(
    csv_path: Path,
    *,
    case_id: str,
    title: str,
    source_label: str,
    scenario: str,
    model: NarrativeModel | None,
    model_label: str | None,
    max_rounds: int,
) -> tuple[Case, int]:
    """Run the ingest, normalize, enrich, and verify pipeline over one CSV.

    Returns the assembled case and the count of malformed rows reported without
    aborting (FR7). When ``model`` is None the deterministic no-model path is
    taken: no narrative is drafted and the report carries timeline, tags,
    episodes, indicators, and the appendix (FR26).
    """
    normalized = normalize_records(HayabusaAdapter().read(csv_path))
    tagged = tag_events(normalized.events)
    clustered = cluster_events(tagged)
    extracted = extract_iocs(clustered.events)
    enriched = extracted.events

    verification = (
        verify_narrative(enriched, model, max_rounds=max_rounds) if model is not None else None
    )

    case = Case(
        case_id=case_id,
        title=title,
        source_label=source_label,
        scenario=scenario,
        source_tool=_SOURCE_TOOL,
        model_label=model_label,
        events=tuple(enriched),
        verification=verification,
        provenance=normalized.provenance,
        episodes=tuple(clustered.episodes),
        iocs=extracted.iocs,
    )
    return case, normalized.problem_count


def build_demo_case() -> Case:
    """Build the bundled demo case, mirroring the default ``casebound demo`` run.

    Regenerates the synthetic scenario at the pinned seed, runs the same pipeline,
    and drafts the narrative with the offline narrator in a single verification
    pass. The CSV is written under the canonical filename so provenance matches the
    CLI exactly, which keeps the served report byte for byte identical to the one
    ``casebound demo`` writes. Fully offline, no keys.
    """
    scenario = generate(seed=DEFAULT_SEED)
    scenario_name: str = scenario.ground_truth["scenario"]
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / CSV_FILENAME
        csv_path.write_text(scenario.csv_text, encoding="utf-8")
        case, _ = _analyze_csv(
            csv_path,
            case_id=DEMO_CASE_ID,
            title=_DEMO_TITLE,
            source_label=f"{CSV_FILENAME} (regenerated, bundled scenario)",
            scenario=scenario_name,
            model=OfflineDemoNarrator(),
            model_label=OfflineDemoNarrator.LABEL,
            max_rounds=0,
        )
    return case


def sanitize_upload_name(filename: str) -> str:
    """Reduce an uploaded filename to a safe, path-free basename ending in .csv.

    Only the basename is kept (no directory components), so a crafted name can
    never escape the private temporary directory the timeline is written into. The
    sanitized name is used solely as the provenance source file and the temp file
    name; the upload is never opened or fetched by any path the user supplies.
    """
    base = Path(filename).name.strip()
    if not base or base in {".", ".."}:
        return _FALLBACK_UPLOAD_NAME
    if not base.lower().endswith(".csv"):
        base = f"{base}.csv"
    return base


def build_uploaded_case(case_id: str, filename: str, csv_text: str) -> tuple[Case, int]:
    """Build a deterministic case from an uploaded Hayabusa CSV timeline.

    The upload takes the no-model path: it is parsed read-only into the canonical
    schema and rendered with no narrative. The text is written to a private
    temporary file (named only with a sanitized basename) so the file-based ingest
    adapter can read it, then removed. Nothing is opened, executed, or fetched.

    Returns the case and the malformed-row count. A caller checks ``event_count``
    and rejects an upload that yields no events.
    """
    safe_name = sanitize_upload_name(filename)
    with tempfile.TemporaryDirectory() as tmp:
        csv_path = Path(tmp) / safe_name
        csv_path.write_text(csv_text, encoding="utf-8")
        return _analyze_csv(
            csv_path,
            case_id=case_id,
            title=f"Uploaded timeline: {safe_name}",
            source_label=safe_name,
            scenario=f"uploaded: {safe_name}",
            model=None,
            model_label=None,
            max_rounds=0,
        )
