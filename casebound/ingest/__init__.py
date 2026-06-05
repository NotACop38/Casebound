"""Ingestion: one adapter per evidence source (PRD Sections 8 and 9, FR1 to FR7).

Adapters read already-collected tool output (CSV or JSON timelines) and emit raw,
provenance-bearing records ready for normalization. They never acquire, never
collect remotely, and never execute anything (Hard rule 1, defensive scope).

The base interface (``IngestAdapter``, ``RawRecord``) lives in ``base``. The first
concrete adapter is ``HayabusaAdapter`` for Hayabusa csv-timeline output.

Planned adapters (PRD Section 13): base, hayabusa, eztools, chainsaw,
velociraptor, plaso, generic_csv.

TODO(Phase 3): add the remaining source adapters, each with a fixture and a
  normalization golden test.
"""

from __future__ import annotations

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.ingest.hayabusa import HayabusaAdapter, channel_to_artifact

__all__ = [
    "HayabusaAdapter",
    "IngestAdapter",
    "RawRecord",
    "channel_to_artifact",
]
