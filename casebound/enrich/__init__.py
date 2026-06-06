"""Enrichment: deterministic ATT&CK mapping, clustering, and IOC extraction.

Adds analysis to normalized events without any model in the loop (FR13 to FR16):
rule-tag passthrough plus a documented ATT&CK mapping table, activity clustering
into episodes by time, host, and principal, and IOC extraction with defanging.

Layout (PRD Section 13): attack.py, cluster.py, ioc.py.
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
from casebound.enrich.cluster import (
    DEFAULT_MAX_GAP_SECONDS,
    EPISODE_TAG_PREFIX,
    ClusterResult,
    Episode,
    cluster_events,
    episode_id_for_tag,
)
from casebound.enrich.ioc import (
    IOC_TYPE_DOMAIN,
    IOC_TYPE_HASH,
    IOC_TYPE_IP,
    IOC_TYPE_PATH,
    Ioc,
    IocExtraction,
    IocSet,
    defang,
    extract_iocs,
)

__all__ = [
    "DEFAULT_MAX_GAP_SECONDS",
    "EPISODE_TAG_PREFIX",
    "IOC_TYPE_DOMAIN",
    "IOC_TYPE_HASH",
    "IOC_TYPE_IP",
    "IOC_TYPE_PATH",
    "MAPPING_SOURCE_RULE_TAG",
    "MAPPING_SOURCE_TABLE",
    "MAPPING_TABLE",
    "ClusterResult",
    "Episode",
    "Ioc",
    "IocExtraction",
    "IocSet",
    "MappingRule",
    "cluster_events",
    "defang",
    "episode_id_for_tag",
    "extract_iocs",
    "tag_event",
    "tag_events",
]
