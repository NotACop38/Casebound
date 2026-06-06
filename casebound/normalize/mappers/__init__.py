"""Per-source field mappers (PRD Section 8, FR8).

Each mapper turns a source tool's raw records into canonical events. The registry
below maps a ``source_tool`` to the mapper that handles it, so the normalize
pipeline can dispatch a mixed stream of records to the right mapper. New sources
register their mapper here as they land.
"""

from __future__ import annotations

from casebound.normalize.mappers.base import Mapper, MappingError
from casebound.normalize.mappers.eztools import EZToolsMapper
from casebound.normalize.mappers.hayabusa import HayabusaMapper

__all__ = [
    "DEFAULT_MAPPERS",
    "EZToolsMapper",
    "HayabusaMapper",
    "Mapper",
    "MappingError",
    "default_mappers",
]


def default_mappers() -> dict[str, Mapper]:
    """Build the default ``source_tool`` to mapper registry.

    A fresh dict per call so a caller can extend or swap entries without mutating
    shared state.
    """
    return {
        HayabusaMapper.source_tool: HayabusaMapper(),
        EZToolsMapper.source_tool: EZToolsMapper(),
    }


# A shared, ready-to-use registry for the common case.
DEFAULT_MAPPERS: dict[str, Mapper] = default_mappers()
