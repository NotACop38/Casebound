"""Ingestion: one adapter per evidence source (PRD Sections 8 and 9, FR1 to FR7).

Adapters read already-collected tool output (CSV or JSON timelines) and emit raw,
provenance-bearing records ready for normalization. They never acquire, never
collect remotely, and never execute anything (Hard rule 1, defensive scope).

The base interface (``IngestAdapter``, ``RawRecord``) lives in ``base``. The
tool-output adapters exported here cover the sources responders run during
collection (PRD Section 13): hayabusa, eztools, chainsaw, velociraptor, plaso, and
the column-mapped generic_csv. Each ships with a fixture and a normalization golden
test.

The optional raw-artifact adapters (parsing EVTX and the NTFS ``$MFT`` directly
with Dissect) deliberately do not appear here. They live in the isolated
``casebound.ingest.raw`` subpackage and are imported only from there, so the
AGPL-licensed Dissect dependency stays off the core import path (decision D2). See
``docs/raw-mode.md``.
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
