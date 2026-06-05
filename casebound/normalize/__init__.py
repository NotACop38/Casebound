"""Normalization: map raw records to the canonical event schema (PRD Section 10).

This module owns the keystone schema, the per-source field mappers, UTC timezone
normalization with source-timezone tracking, stable content-derived event ids, and
provenance preservation (FR8 to FR12).

Layout (PRD Section 13):
  - ``schema``   : the canonical event record and its validation (the keystone).
  - ``timezone`` : timestamp normalization to UTC with source-timezone tracking.
  - ``mappers``  : per-source field mappers (Hayabusa is the first).
  - ``pipeline`` : raw records to de-duplicated canonical events.

The validation source of truth is ``schema/event.schema.json``.
"""

from __future__ import annotations

from casebound.normalize.pipeline import (
    NormalizationProblem,
    NormalizationResult,
    normalize_records,
)
from casebound.normalize.schema import Event, RawRef
from casebound.normalize.timezone import NormalizedTimestamp, normalize_timestamp

__all__ = [
    "Event",
    "NormalizationProblem",
    "NormalizationResult",
    "NormalizedTimestamp",
    "RawRef",
    "normalize_records",
    "normalize_timestamp",
]
