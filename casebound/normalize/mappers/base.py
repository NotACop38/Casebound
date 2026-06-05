"""The base field-mapper interface (PRD Section 8, FR8).

A mapper turns one ``RawRecord`` from a given source tool into one canonical
``Event``. Each source has its own quirks (column names, timestamp formats, how
principal and object are spelled), so each gets its own small mapper, while the
canonical-event contract stays identical across all of them.

A mapper raises ``MappingError`` when a row cannot become a valid event (for
example an unparseable timestamp). The normalize pipeline catches that and records
the row as a reported problem rather than aborting the run (FR7), so one bad row
never sinks a timeline.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar

from casebound.normalize.schema import Event

if TYPE_CHECKING:
    # Annotation-only: keeps normalize free of a runtime dependency on ingest.
    from casebound.ingest.base import RawRecord

__all__ = ["Mapper", "MappingError"]


class MappingError(ValueError):
    """Raised when a raw record cannot be mapped to a valid canonical event."""


class Mapper(ABC):
    """Maps raw records from one ``source_tool`` into canonical events."""

    source_tool: ClassVar[str]

    @abstractmethod
    def map(self, record: RawRecord) -> Event:
        """Return the canonical event for ``record`` or raise ``MappingError``."""
        raise NotImplementedError
