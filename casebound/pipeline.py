"""The analysis pipeline: evidence in, one ``Case`` out.

Every entry point (the ``report`` and ``demo`` commands, the web viewer, the tests)
runs the same chain through ``analyze``, so there is exactly one definition of what
Casebound does to evidence:

  1. Ingest each input with the adapter its source names (``casebound.sources``),
     read-only (Hard rule 1).
  2. Normalize every record to the canonical schema, reporting malformed rows
     instead of aborting (FR7) and collapsing duplicates across inputs while
     keeping every provenance pointer (FR12).
  3. Enrich deterministically: ATT&CK tags (FR13, FR14), activity episodes (FR15),
     and defanged indicators (FR16).
  4. Optionally draft and verify a narrative (FR17 to FR25). With no model the
     case is the deterministic no-model path (FR26); with one, every claim is
     fenced by the verifier and the model only ever sees the compact event view.

The result is an immutable ``Case`` that the report layer renders and the
evaluation scores. Nothing here reaches the network; a configured model is the
only component that may, and only through its own opt-in provider.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from casebound.enrich.attack import tag_events
from casebound.enrich.cluster import Episode, cluster_events
from casebound.enrich.ioc import IocSet, extract_iocs
from casebound.normalize.pipeline import NormalizationProblem, normalize_records
from casebound.normalize.schema import Event, RawRef
from casebound.sources import SourceSpec, build_adapter, get_source
from casebound.verify.engine import (
    DEFAULT_MAX_ROUNDS,
    DEFAULT_VIEW_BUDGET,
    NarrativeModel,
    VerificationResult,
    verify_narrative,
)

if TYPE_CHECKING:
    from casebound.ingest.base import RawRecord
    from casebound.ingest.generic_csv import ColumnMap

__all__ = [
    "Case",
    "EmptyCaseError",
    "EvidenceInput",
    "InputSummary",
    "analyze",
    "case_from_events",
]


class EmptyCaseError(ValueError):
    """The evidence yielded no canonical events, so there is nothing to analyze.

    Almost always a wrong source for the file (every row failed to normalize) or an
    empty export. ``problems`` carries the per-row reasons so a caller can show why
    nothing parsed.
    """

    def __init__(self, problems: Sequence[NormalizationProblem], records: int) -> None:
        if records:
            message = (
                f"no events could be normalized from {records} record(s); "
                "is the source right for this file?"
            )
        else:
            message = "the evidence contained no records"
        super().__init__(message)
        self.problems = tuple(problems)
        self.records = records


@dataclass(frozen=True)
class EvidenceInput:
    """One evidence file and the source that produced it."""

    source: str
    path: Path
    column_map: ColumnMap | None = None

    @property
    def spec(self) -> SourceSpec:
        """The registry entry for this input's source."""
        return get_source(self.source)


@dataclass(frozen=True)
class InputSummary:
    """What one input contributed: its source, file name, and records read."""

    source: str
    file: str
    records: int

    def to_dict(self) -> dict[str, object]:
        """Render the summary as a JSON-ready dict."""
        return {"source": self.source, "file": self.file, "records": self.records}


def _instant(event: Event) -> datetime:
    return datetime.fromisoformat(event.datetime.replace("Z", "+00:00"))


@dataclass(frozen=True)
class Case:
    """Everything the pipeline derived from one set of evidence.

    ``events`` are the enriched canonical events in chronological order (ties
    broken by id). ``provenance`` maps each event id to every source record that
    produced it. ``problems`` are the rows that could not be normalized.
    ``verification`` is the verifier's output, or None on the no-model path, and
    ``narrative_label`` names the narrative source for the report.
    """

    name: str
    inputs: tuple[InputSummary, ...]
    events: tuple[Event, ...]
    provenance: Mapping[str, tuple[RawRef, ...]]
    problems: tuple[NormalizationProblem, ...]
    episodes: tuple[Episode, ...]
    iocs: IocSet
    verification: VerificationResult | None = None
    narrative_label: str | None = None
    _index: dict[str, Event] = field(default_factory=dict, init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        self._index.update({event.event_id: event for event in self.events})

    @property
    def no_model(self) -> bool:
        """True on the deterministic no-model path (no narrative was drafted)."""
        return self.verification is None

    @property
    def records_read(self) -> int:
        """How many source records the inputs yielded in total."""
        return sum(item.records for item in self.inputs)

    @property
    def duplicate_count(self) -> int:
        """How many records collapsed into an already-seen event (FR12)."""
        return sum(len(refs) for refs in self.provenance.values()) - len(self.events)

    def event(self, event_id: str) -> Event | None:
        """Return the event with this id, or None."""
        return self._index.get(event_id)

    def technique_ids(self) -> tuple[str, ...]:
        """Every distinct technique id observed in the case, sorted."""
        return tuple(
            sorted({tech.technique_id for event in self.events for tech in event.attack_techniques})
        )


def _read_inputs(
    inputs: Sequence[EvidenceInput], summaries: list[InputSummary]
) -> Iterator[RawRecord]:
    """Stream every record from every input, recording per-input counts."""
    for item in inputs:
        adapter = build_adapter(item.source, column_map=item.column_map)
        count = 0
        for record in adapter.read(item.path):
            count += 1
            yield record
        summaries.append(InputSummary(source=item.spec.name, file=item.path.name, records=count))


def case_from_events(
    events: Sequence[Event],
    *,
    name: str,
    verification: VerificationResult | None = None,
    narrative_label: str | None = None,
    provenance: Mapping[str, Sequence[RawRef]] | None = None,
    problems: Sequence[NormalizationProblem] = (),
    inputs: Sequence[InputSummary] = (),
) -> Case:
    """Assemble a ``Case`` from events that are already normalized.

    Runs the deterministic enrichment (ATT&CK tags, episodes, indicators), all of
    it idempotent, so events that were already enriched pass through unchanged. A
    missing ``provenance`` defaults to each event's own ``raw_ref``. This is the
    entry point for a caller with its own ingest step, and for tests.
    """
    tagged = tag_events(events)
    clustered = cluster_events(tagged)
    extracted = extract_iocs(clustered.events)
    ordered = sorted(extracted.events, key=lambda event: (_instant(event), event.event_id))
    prov = (
        {event_id: tuple(refs) for event_id, refs in provenance.items()}
        if provenance is not None
        else {event.event_id: (event.raw_ref,) for event in ordered}
    )
    return Case(
        name=name,
        inputs=tuple(inputs),
        events=tuple(ordered),
        provenance=prov,
        problems=tuple(problems),
        episodes=tuple(clustered.episodes),
        iocs=extracted.iocs,
        verification=verification,
        narrative_label=(narrative_label or "configured model") if verification else None,
    )


def analyze(
    inputs: Sequence[EvidenceInput],
    *,
    name: str,
    model: NarrativeModel | None = None,
    model_label: str | None = None,
    max_rounds: int = DEFAULT_MAX_ROUNDS,
    view_budget: int | None = DEFAULT_VIEW_BUDGET,
) -> Case:
    """Run the whole pipeline over ``inputs`` and return the resulting ``Case``.

    Raises ``EmptyCaseError`` when no input record normalizes into an event,
    ``casebound.sources.UnknownSourceError`` for an unknown source or a bad column
    map combination, and whatever a configured model's provider raises when a
    draft call fails (``casebound.narrate.llm.ProviderError`` for the bundled
    providers). File-level read errors (``OSError``, a malformed JSON document)
    propagate unchanged for the caller to report.
    """
    if not inputs:
        raise ValueError("analyze needs at least one evidence input")
    summaries: list[InputSummary] = []
    normalized = normalize_records(_read_inputs(inputs, summaries))
    if not normalized.events:
        raise EmptyCaseError(normalized.problems, sum(item.records for item in summaries))

    tagged = tag_events(normalized.events)
    clustered = cluster_events(tagged)
    extracted = extract_iocs(clustered.events)
    events = sorted(extracted.events, key=lambda event: (_instant(event), event.event_id))

    verification = (
        verify_narrative(events, model, max_rounds=max_rounds, view_budget=view_budget)
        if model is not None
        else None
    )
    return Case(
        name=name,
        inputs=tuple(summaries),
        events=tuple(events),
        provenance={event_id: tuple(refs) for event_id, refs in normalized.provenance.items()},
        problems=tuple(normalized.problems),
        episodes=tuple(clustered.episodes),
        iocs=extracted.iocs,
        verification=verification,
        narrative_label=(model_label or "configured model") if model is not None else None,
    )
