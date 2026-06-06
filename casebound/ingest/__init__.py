"""Ingestion: one adapter per evidence source (PRD Sections 8 and 9, FR1 to FR7).

Adapters read already-collected tool output (CSV or JSON timelines) and emit raw,
provenance-bearing records ready for normalization. They never acquire, never
collect remotely, and never execute anything (Hard rule 1, defensive scope).

The base interface (``IngestAdapter``, ``RawRecord``) lives in ``base``. The first
concrete adapter is ``HayabusaAdapter`` for Hayabusa csv-timeline output; the
``EZToolsAdapter`` reads Eric Zimmerman / Timeline Explorer MFTECmd CSV.

Planned adapters (PRD Section 13): base, hayabusa, eztools, chainsaw,
velociraptor, plaso, generic_csv.

TODO(Phase 3): add the remaining source adapters, each with a fixture and a
  normalization golden test.
"""

from __future__ import annotations

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.ingest.chainsaw import ChainsawAdapter
from casebound.ingest.eztools import EZToolsAdapter
from casebound.ingest.generic_csv import ColumnMap, GenericCsvAdapter
from casebound.ingest.hayabusa import HayabusaAdapter, channel_to_artifact
from casebound.ingest.plaso import PlasoAdapter
from casebound.ingest.velociraptor import VelociraptorAdapter

__all__ = [
    "ChainsawAdapter",
    "ColumnMap",
    "EZToolsAdapter",
    "GenericCsvAdapter",
    "HayabusaAdapter",
    "IngestAdapter",
    "PlasoAdapter",
    "RawRecord",
    "VelociraptorAdapter",
    "channel_to_artifact",
]
