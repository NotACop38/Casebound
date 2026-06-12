"""The normalization pipeline: raw records to canonical events (FR8 to FR12).

This is the entry point that turns a stream of ``RawRecord`` (from any ingest
adapter) into a set of canonical ``Event`` objects. It:

  - dispatches each record to the mapper registered for its ``source_tool`` (FR8);
  - lets each mapper assign the stable, content-derived ``event_id`` and preserve
    the ``raw_ref`` provenance (FR10, FR11);
  - de-duplicates identical events (same ``event_id``) while keeping every source
    pointer that produced one, so no provenance is lost (FR12); and
  - records any malformed row as a reported problem instead of aborting, so one
    bad row never sinks the run (FR7).

The result is a ``NormalizationResult`` carrying the de-duplicated events in
first-seen (chronological, since adapters read in order) order, the full
provenance per event id, and the list of problems.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from casebound.normalize.mappers import DEFAULT_MAPPERS, MappingError
from casebound.normalize.mappers.base import Mapper
from casebound.normalize.schema import Event, RawRef

if TYPE_CHECKING:
    # Annotation-only import: normalize never depends on ingest at runtime, which
    # keeps the ingest -> normalize.schema dependency one-directional.
    from casebound.ingest.base import RawRecord

__all__ = ["NormalizationProblem", "NormalizationResult", "normalize_records"]

# The detail keys the dedup merge folds together when records collapse. The rule
# tags are read by the ATT&CK tagger (enrich.attack); the titles are informative.
_RULE_TAGS_KEY = "rule_mitre_tags"
_RULE_TITLE_KEY = "rule_title"
_EXTRA_TITLES_KEY = "additional_rule_titles"


def _merge_duplicate_details(kept: Event, duplicate: Event) -> None:
    """Fold a collapsing record's enrichment-bearing details into the kept event.

    Detection sources like Hayabusa and Chainsaw emit one row per rule match, so
    two rules firing on the same underlying record collapse to one event (FR12,
    same identity fields). The later row can carry ATT&CK rule tags or a rule
    title the kept row lacks; discarding them would lose technique mappings
    depending on nothing but input order. Only the enrichment-bearing keys are
    merged. Everything else stays first-seen: the identity fields are equal by
    construction, and ``details`` is intentionally mutable on the frozen event.
    """
    extra_tags = duplicate.details.get(_RULE_TAGS_KEY)
    if isinstance(extra_tags, list):
        merged = kept.details.get(_RULE_TAGS_KEY)
        if isinstance(merged, list):
            merged.extend(tag for tag in extra_tags if tag not in merged)
        else:
            kept.details[_RULE_TAGS_KEY] = list(extra_tags)

    title = duplicate.details.get(_RULE_TITLE_KEY)
    if isinstance(title, str):
        kept_title = kept.details.get(_RULE_TITLE_KEY)
        if kept_title is None:
            kept.details[_RULE_TITLE_KEY] = title
        elif title != kept_title:
            extras = kept.details.setdefault(_EXTRA_TITLES_KEY, [])
            if isinstance(extras, list) and title not in extras:
                extras.append(title)


@dataclass(frozen=True)
class NormalizationProblem:
    """A row that could not be normalized, reported rather than fatal (FR7).

    ``raw_ref`` points back at the offending source record, ``source_tool`` says
    which adapter produced it, and ``reason`` is the human-readable cause.
    """

    raw_ref: RawRef
    source_tool: str
    reason: str


@dataclass
class NormalizationResult:
    """The output of a normalization run.

    ``events`` are the unique canonical events in first-seen order.
    ``provenance`` maps each ``event_id`` to every ``raw_ref`` that produced it, so
    a de-duplicated event still names all of its sources (FR12). ``problems`` lists
    the rows that could not be normalized (FR7).
    """

    events: list[Event] = field(default_factory=list)
    provenance: dict[str, list[RawRef]] = field(default_factory=dict)
    problems: list[NormalizationProblem] = field(default_factory=list)

    @property
    def event_count(self) -> int:
        """The number of unique events."""
        return len(self.events)

    @property
    def duplicate_count(self) -> int:
        """How many records collapsed into an already-seen event (FR12)."""
        return sum(len(refs) for refs in self.provenance.values()) - len(self.events)

    @property
    def problem_count(self) -> int:
        """The number of rows reported as malformed."""
        return len(self.problems)


def normalize_records(
    records: Iterable[RawRecord],
    *,
    mappers: Mapping[str, Mapper] = DEFAULT_MAPPERS,
) -> NormalizationResult:
    """Normalize a stream of raw records into de-duplicated canonical events.

    Records whose ``source_tool`` has no registered mapper, and rows a mapper
    rejects, are recorded as problems and skipped; everything else becomes an
    event. Two records that resolve to the same ``event_id`` collapse to one event
    while both ``raw_ref`` pointers are retained.
    """
    result = NormalizationResult()
    seen: dict[str, Event] = {}

    for record in records:
        mapper = mappers.get(record.source_tool)
        if mapper is None:
            result.problems.append(
                NormalizationProblem(
                    raw_ref=record.raw_ref,
                    source_tool=record.source_tool,
                    reason=f"no mapper registered for source_tool {record.source_tool!r}",
                )
            )
            continue
        try:
            event = mapper.map(record)
        except MappingError as exc:
            result.problems.append(
                NormalizationProblem(
                    raw_ref=record.raw_ref,
                    source_tool=record.source_tool,
                    reason=str(exc),
                )
            )
            continue

        if event.event_id not in seen:
            seen[event.event_id] = event
            result.events.append(event)
            result.provenance[event.event_id] = [event.raw_ref]
        else:
            # Identical event already recorded: keep this row's provenance (FR12)
            # and fold its detection details into the kept event, so a second
            # rule firing on the same record never loses its ATT&CK tags.
            _merge_duplicate_details(seen[event.event_id], event)
            result.provenance[event.event_id].append(record.raw_ref)

    return result
