"""Enrichment: deterministic ATT&CK mapping, clustering, and IOC extraction.

Adds analysis to normalized events without any model in the loop (FR13 to FR16):
rule-tag passthrough plus a documented ATT&CK mapping table, activity clustering
into episodes by time, host, and principal, and IOC extraction with defanging.

Planned layout (PRD Section 13): attack.py, cluster.py, ioc.py.

TODO(Phase 1): deterministic ATT&CK tagging via rule-tag passthrough plus a small
  mapping table.
TODO(Phase 4): episode clustering and IOC extraction surfaced in reports.
"""

from __future__ import annotations
