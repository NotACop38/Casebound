"""Normalization: map raw records to the canonical event schema (PRD Section 10).

This module owns the keystone schema, the per-source field mappers, UTC timezone
normalization with source-timezone tracking, stable content-derived event ids, and
provenance preservation (FR8 to FR12).

Planned layout (PRD Section 13): schema.py, timezone.py, mappers/.

TODO(Phase 0): the validation source of truth is schema/event.schema.json.
TODO(Phase 1): implement normalization to the canonical schema with UTC handling
  and stable event ids.
"""

from __future__ import annotations
