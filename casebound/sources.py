"""The evidence-source registry: every input format Casebound reads, by name.

A source name (``hayabusa``, ``eztools``, ``evtx``, ...) is what an analyst passes on
the command line and what the web viewer offers for upload. Each ``SourceSpec``
records what the source is, which file types it arrives as, and how to build its
ingest adapter, so the CLI, the pipeline, and the web viewer all resolve sources
through this one table.

Two groups of sources exist:

  - Tool output (the default install): timelines and detections that responders'
    tools already produced. Read by the adapters in ``casebound.ingest``.
  - Raw artifacts (the optional ``raw`` extra): a Windows ``.evtx`` log or an NTFS
    ``$MFT`` parsed directly with Dissect. Dissect is AGPL-3.0, so these adapters
    live in the isolated ``casebound.ingest.raw`` subpackage (decision D2). This
    module is the single place that may load that subpackage, and only lazily,
    inside ``build_adapter``, when an operator selects a raw source. Even then no
    Dissect code loads until an artifact is actually read, and a missing extra
    surfaces as a clear ``RawModeDependencyError`` naming the install command.
    ``tests/test_license_boundary.py`` enforces both properties.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from casebound.ingest.base import IngestAdapter
    from casebound.ingest.generic_csv import ColumnMap

__all__ = [
    "SOURCES",
    "SourceSpec",
    "UnknownSourceError",
    "build_adapter",
    "get_source",
    "source_names",
]


class UnknownSourceError(ValueError):
    """Raised for a source name the registry does not define, or a bad combination."""


@dataclass(frozen=True)
class SourceSpec:
    """One evidence source Casebound can ingest.

    ``name`` is the command-line spelling. ``tool`` is the canonical
    ``source_tool`` its events carry. ``suffixes`` are the file types it arrives as
    (the web viewer's upload gate uses them; an ``$MFT`` has no fixed suffix, so it
    lists none). ``needs_column_map`` marks the
    generic CSV source, which needs a column-mapping config. ``extra`` names the
    optional install extra the source requires, if any.
    """

    name: str
    tool: str
    description: str
    suffixes: tuple[str, ...]
    needs_column_map: bool = False
    extra: str | None = None


SOURCES: dict[str, SourceSpec] = {
    spec.name: spec
    for spec in (
        SourceSpec(
            "hayabusa",
            "hayabusa",
            "Hayabusa csv-timeline or json-timeline output, any profile",
            (".csv", ".json", ".jsonl"),
        ),
        SourceSpec(
            "chainsaw",
            "chainsaw",
            "Chainsaw hunt detections written with --json",
            (".json",),
        ),
        SourceSpec(
            "eztools",
            "eztools",
            "Eric Zimmerman MFTECmd $MFT CSV (KAPE triage output)",
            (".csv",),
        ),
        SourceSpec(
            "velociraptor",
            "velociraptor",
            "Velociraptor Windows.EventLogs.Evtx results exported as JSONL",
            (".jsonl", ".json"),
        ),
        SourceSpec(
            "plaso",
            "plaso",
            "Plaso psort l2tcsv super timeline",
            (".csv",),
        ),
        SourceSpec(
            "generic_csv",
            "generic_csv",
            "any delimited CSV timeline, described by a column-mapping JSON",
            (".csv",),
            needs_column_map=True,
        ),
        SourceSpec(
            "evtx",
            "dissect",
            "a raw Windows .evtx event log, parsed with Dissect",
            (".evtx",),
            extra="raw",
        ),
        SourceSpec(
            "mft",
            "dissect",
            "a raw NTFS $MFT, parsed with Dissect",
            (),
            extra="raw",
        ),
    )
}


def source_names() -> tuple[str, ...]:
    """Every registered source name, in registry order."""
    return tuple(SOURCES)


def get_source(name: str) -> SourceSpec:
    """Return the spec for a source name, or raise ``UnknownSourceError``."""
    spec = SOURCES.get(name.strip().lower())
    if spec is None:
        raise UnknownSourceError(
            f"unknown source {name!r}; expected one of: {', '.join(source_names())}"
        )
    return spec


def build_adapter(name: str, *, column_map: ColumnMap | None = None) -> IngestAdapter:
    """Build the ingest adapter for a source, validating the column-map usage.

    ``generic_csv`` requires a column map (docs/ingest-generic-csv.md); every other
    source takes none. A raw source loads the license-gated raw subpackage here,
    lazily, and only because the operator asked for it (D2).
    """
    spec = get_source(name)
    if not spec.needs_column_map and column_map is not None:
        raise UnknownSourceError(f"a column map applies only to generic_csv, not {spec.name!r}")

    # Imports are local so building one adapter loads only what that source needs.
    if spec.name == "hayabusa":
        from casebound.ingest.hayabusa import HayabusaAdapter

        return HayabusaAdapter()
    if spec.name == "chainsaw":
        from casebound.ingest.chainsaw import ChainsawAdapter

        return ChainsawAdapter()
    if spec.name == "eztools":
        from casebound.ingest.eztools import EZToolsAdapter

        return EZToolsAdapter()
    if spec.name == "velociraptor":
        from casebound.ingest.velociraptor import VelociraptorAdapter

        return VelociraptorAdapter()
    if spec.name == "plaso":
        from casebound.ingest.plaso import PlasoAdapter

        return PlasoAdapter()
    if spec.name == "generic_csv":
        from casebound.ingest.generic_csv import GenericCsvAdapter

        if column_map is None:
            raise UnknownSourceError(
                "source 'generic_csv' needs a column map (see docs/ingest-generic-csv.md)"
            )
        return GenericCsvAdapter(column_map)
    if spec.name == "evtx":
        from casebound.ingest.raw import DissectEvtxAdapter

        return DissectEvtxAdapter()
    if spec.name == "mft":
        from casebound.ingest.raw import DissectMftAdapter

        return DissectMftAdapter()
    raise UnknownSourceError(f"no adapter is wired for source {spec.name!r}")  # pragma: no cover
