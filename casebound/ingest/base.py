"""The base ingest adapter interface (PRD Sections 8 and 9, FR1).

An adapter reads already-collected tool output (a CSV or JSON timeline that a
responder produced during collection) and yields one ``RawRecord`` per source
row. A ``RawRecord`` carries the row's fields verbatim plus its provenance: the
tool that produced it, the artifact it came from, and a pointer back to the exact
source record for audit (FR11). The adapter performs no interpretation of the
fields into the canonical schema; that is the normalize layer's job. The split
keeps each source's quirks in one small adapter and the canonical-event logic in
one place.

Adapters are strictly read-only over evidence that already exists. They never
acquire, never collect remotely, and never execute anything (Hard rule 1, the
defensive scope).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from casebound.normalize.schema import SOURCE_TOOLS, RawRef

__all__ = ["IngestAdapter", "RawRecord", "coerce_row", "scalar_to_str"]


def coerce_row(row: Mapping[str, str | None]) -> dict[str, str]:
    """Normalize a ``csv.DictReader`` row to a clean ``str`` to ``str`` mapping.

    DictReader yields ``None`` for a column a short row omits, and collects any
    extra cells under the ``None`` restkey. Replace a missing value with ``""`` and
    drop the ``None`` key, so a mapper always sees plain strings. The CSV adapters
    share this so the contract lives in one place.
    """
    return {
        key: (value if value is not None else "") for key, value in row.items() if key is not None
    }


def scalar_to_str(value: Any) -> str:
    """Render a scalar JSON value as a string; a container becomes an empty string.

    A ``None`` or a nested object or array yields ``""`` (the JSON adapters lift
    nested structure separately), and a boolean renders as lowercase ``true`` or
    ``false`` rather than Python's capitalized ``str(bool)``. The JSONL and JSON
    adapters share this so the conversion never drifts between them.
    """
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


@dataclass(frozen=True)
class RawRecord:
    """One raw row from an evidence source, with its provenance.

    ``source_tool`` is the tool whose output produced the row (one of
    ``SOURCE_TOOLS``). ``source_artifact`` is the originating artifact the row
    describes, for example ``Security.evtx``. ``raw_ref`` points back to the exact
    source record (file plus record or line id) so any derived event can be
    audited (FR11). ``data`` is the row's fields exactly as read, with no
    canonical interpretation applied yet; the normalize layer maps these into a
    canonical event.
    """

    source_tool: str
    source_artifact: str
    raw_ref: RawRef
    data: Mapping[str, str]

    def __post_init__(self) -> None:
        if self.source_tool not in SOURCE_TOOLS:
            raise ValueError(
                f"source_tool must be one of {sorted(SOURCE_TOOLS)}, got {self.source_tool!r}"
            )
        if not isinstance(self.source_artifact, str) or not self.source_artifact.strip():
            raise ValueError("source_artifact must be a non-empty string")
        if not isinstance(self.raw_ref, RawRef):
            raise ValueError("raw_ref must be a RawRef")


class IngestAdapter(ABC):
    """The interface every source adapter implements (FR1).

    A concrete adapter declares the ``source_tool`` it emits and implements
    ``read`` to yield one ``RawRecord`` per source row. Reading is lazy: ``read``
    returns an iterator so large timelines stream without being held in memory.

    Structurally readable rows are always yielded, even when a field is missing or
    unexpected; deciding that a row cannot become a canonical event (a malformed
    timestamp, say) is the normalize layer's responsibility, so that malformed
    rows are reported there rather than silently dropped at ingest (FR7).
    """

    source_tool: ClassVar[str]

    @abstractmethod
    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per row in the evidence at ``source``."""
        raise NotImplementedError
