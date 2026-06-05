"""Enrichment: deterministic ATT&CK mapping, clustering, and IOC extraction.

Adds analysis to normalized events without any model in the loop (FR13 to FR16):
rule-tag passthrough plus a documented ATT&CK mapping table, activity clustering
into episodes by time, host, and principal, and IOC extraction with defanging.

Layout (PRD Section 13): attack.py (done), cluster.py, ioc.py.

TODO(Phase 4): episode clustering and IOC extraction surfaced in reports.
"""

from __future__ import annotations

from casebound.enrich.attack import (
    MAPPING_SOURCE_RULE_TAG,
    MAPPING_SOURCE_TABLE,
    MAPPING_TABLE,
    MappingRule,
    tag_event,
    tag_events,
)

__all__ = [
    "MAPPING_SOURCE_RULE_TAG",
    "MAPPING_SOURCE_TABLE",
    "MAPPING_TABLE",
    "MappingRule",
    "tag_event",
    "tag_events",
]
