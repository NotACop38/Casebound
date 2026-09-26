"""Case assembly for the optional web viewer (PRD Section 8, decision D4).

A loaded case is a ``casebound.pipeline.Case``, built by the same ``analyze`` call
the command line uses, and rendered by the same report layer, so the page the
browser shows is byte for byte the report ``casebound report`` or ``casebound demo``
writes for the same evidence. The web layer only assembles cases; it never decides
what a report says.

The bundled demo case mirrors ``casebound demo``: the synthetic scenario at the
pinned seed, narrated by the offline demo narrator and verified. An uploaded file
takes the deterministic no-model path: it is parsed read-only and rendered with no
narrative, since the scripted narrator is specific to the bundled scenario.

Everything here runs offline. The only file handling is writing an upload to a
private temporary file so the file-based ingest adapters can read it; the file is
removed immediately afterwards and is never opened as anything but text.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import tempfile
from dataclasses import dataclass
from pathlib import Path

from casebound.generate import CSV_FILENAME, DEFAULT_SEED, generate
from casebound.narrate import OfflineDemoNarrator
from casebound.pipeline import Case, EvidenceInput, analyze

__all__ = [
    "DEMO_CASE_ID",
    "LoadedCase",
    "build_demo_case",
    "build_uploaded_case",
    "sanitize_upload_name",
]

# The stable id of the bundled demo case, always present in the store.
DEMO_CASE_ID = "demo"

# A safe fallback name for an upload whose file name is empty after sanitizing.
_FALLBACK_UPLOAD_NAME = "upload"


@dataclass(frozen=True)
class LoadedCase:
    """One case held by the viewer: its id, a title, and the analyzed ``Case``."""

    case_id: str
    title: str
    source_label: str
    case: Case


def build_demo_case() -> LoadedCase:
    """Build the bundled demo case, exactly as ``casebound demo`` analyzes it."""
    scenario = generate(seed=DEFAULT_SEED)
    with tempfile.TemporaryDirectory() as tmp:
        timeline = Path(tmp) / CSV_FILENAME
        timeline.write_text(scenario.csv_text, encoding="utf-8")
        case = analyze(
            [EvidenceInput(source="hayabusa", path=timeline)],
            name=str(scenario.ground_truth["scenario"]),
            model=OfflineDemoNarrator(),
            model_label=OfflineDemoNarrator.LABEL,
        )
    return LoadedCase(
        case_id=DEMO_CASE_ID,
        title="Bundled synthetic intrusion (office_intrusion)",
        source_label=f"hayabusa: {CSV_FILENAME} (regenerated)",
        case=case,
    )


def sanitize_upload_name(filename: str, suffix: str) -> str:
    """Reduce an uploaded file name to a safe, path-free base name ending in ``suffix``.

    Only the base name is kept, so a crafted name can never escape the private
    temporary directory the upload is written into. The sanitized name is used only
    as the provenance file name; nothing is ever opened by a client-supplied path.
    """
    base = Path(filename.replace("\\", "/")).name.strip()
    if not base or base in {".", ".."}:
        base = _FALLBACK_UPLOAD_NAME
    if not base.lower().endswith(suffix):
        base = f"{base}{suffix}"
    return base


def build_uploaded_case(case_id: str, source: str, filename: str, text: str) -> LoadedCase:
    """Analyze an uploaded tool-output file on the deterministic no-model path.

    ``source`` names the tool that produced the file. Raises
    ``casebound.pipeline.EmptyCaseError`` when nothing in the file normalizes.
    """
    suffix = Path(filename).suffix.lower()
    safe_name = sanitize_upload_name(filename, suffix or ".csv")
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / safe_name
        path.write_text(text, encoding="utf-8")
        case = analyze([EvidenceInput(source=source, path=path)], name=safe_name)
    return LoadedCase(
        case_id=case_id,
        title=f"Uploaded: {safe_name}",
        source_label=f"{source}: {safe_name}",
        case=case,
    )
