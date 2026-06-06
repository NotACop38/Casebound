"""Dissect-backed NTFS ``$MFT`` ingest adapter (PRD Section 5 Raw mode).

Reads an NTFS master file table directly with Dissect's ``dissect.ntfs`` parser,
for users who have not pre-run a tool over it. Re-verified against the
``dissect.ntfs`` API at author time: ``Mft(fh)`` takes a binary file handle and
``mft.segments()`` yields ``MftRecord`` objects; a record exposes
``attributes.STANDARD_INFORMATION`` (with ``creation_time``,
``last_modification_time``, ``last_access_time``, and ``last_change_time``
datetimes), ``attributes.FILE_NAME`` (with ``file_name`` and ``file_size``),
``full_path()``, ``is_dir()``, ``segment``, and ``header.SequenceNumber``.

One ``$MFT`` record carries several Standard Information timestamps, each a
distinct timeline moment, so this adapter expands one record into one
``RawRecord`` per populated Standard Information timestamp, mirroring the Eric
Zimmerman ``$MFT`` adapter. ``_facts_from_record`` (the only Dissect-facing step)
distils a record into a plain ``MftFileFacts``, and ``mft_facts_to_raws`` (pure,
no Dissect dependency) does the expansion, so the expansion is unit-tested
offline. The Dissect import is lazy (see ``_loader``).

Each ``RawRecord`` carries ``source_tool="dissect"``, the ``$MFT`` artifact, the
``DISSECT_KIND_MFT`` annotation, and a ``raw_ref`` naming the MFT segment and the
timestamp it came from.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.ingest.raw._loader import load_mft_class
from casebound.normalize.mappers.dissect import (
    DISSECT_KIND_KEY,
    DISSECT_KIND_MFT,
    DISSECT_MFT_FILENAME_KEY,
    DISSECT_MFT_ISDIR_KEY,
    DISSECT_MFT_PATH_KEY,
    DISSECT_MFT_SEGMENT_KEY,
    DISSECT_MFT_SEQUENCE_KEY,
    DISSECT_MFT_SIZE_KEY,
    DISSECT_MFT_TIMESTAMP_DESC_KEY,
    DISSECT_MFT_TIMESTAMP_KEY,
)
from casebound.normalize.schema import RawRef

__all__ = ["DissectMftAdapter", "MftFileFacts", "mft_facts_to_raws"]

# The artifact every record describes; the MFT is the originating artifact itself.
_ARTIFACT = "$MFT"


@dataclass(frozen=True)
class MftFileFacts:
    """The plain, Dissect-free facts of one MFT file record.

    Timestamps are ISO 8601 strings (or None when absent). This is the boundary
    between the Dissect-facing extraction and the pure expansion, so the expansion
    can be tested with hand-written facts and no Dissect installed.
    """

    segment: int | None
    sequence: str | None
    path: str | None
    file_name: str | None
    is_dir: bool
    file_size: str | None
    created: str | None
    modified: str | None
    accessed: str | None
    record_changed: str | None


def _identity(facts: MftFileFacts) -> str:
    """Build the per-record audit handle from the MFT segment and sequence."""
    if facts.segment is not None:
        if facts.sequence:
            return f"segment:{facts.segment} seq:{facts.sequence}"
        return f"segment:{facts.segment}"
    return f"path:{facts.path}" if facts.path else "unknown"


def mft_facts_to_raws(facts: MftFileFacts, *, source_file: str) -> list[RawRecord]:
    """Expand one MFT file record into one raw record per Standard Information time.

    Pure: it does not touch Dissect. The timestamps are emitted in MACB reading
    order (created, modified, accessed, record change), and an absent timestamp
    yields no record, so a file with no recorded access time simply yields fewer
    events rather than a malformed one.
    """
    identity = _identity(facts)
    base: dict[str, str] = {
        DISSECT_KIND_KEY: DISSECT_KIND_MFT,
        DISSECT_MFT_SEGMENT_KEY: "" if facts.segment is None else str(facts.segment),
        DISSECT_MFT_SEQUENCE_KEY: facts.sequence or "",
        DISSECT_MFT_PATH_KEY: facts.path or "",
        DISSECT_MFT_FILENAME_KEY: facts.file_name or "",
        DISSECT_MFT_ISDIR_KEY: "true" if facts.is_dir else "false",
        DISSECT_MFT_SIZE_KEY: facts.file_size or "",
    }

    records: list[RawRecord] = []
    for timestamp, desc in (
        (facts.created, "created"),
        (facts.modified, "modified"),
        (facts.accessed, "accessed"),
        (facts.record_changed, "other"),
    ):
        if not timestamp:
            continue
        data = dict(base)
        data[DISSECT_MFT_TIMESTAMP_KEY] = timestamp
        data[DISSECT_MFT_TIMESTAMP_DESC_KEY] = desc
        records.append(
            RawRecord(
                source_tool="dissect",
                source_artifact=_ARTIFACT,
                raw_ref=RawRef(source_file=source_file, record=f"{identity} {desc}"),
                data=data,
            )
        )
    return records


def _iso(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return str(value.isoformat())
    except (AttributeError, ValueError, OverflowError):
        return None


def _first_attr(record: Any, name: str) -> list[Any]:
    try:
        return list(getattr(record.attributes, name))
    except Exception:  # a malformed attribute list is skipped, not fatal
        return []


def _facts_from_record(record: Any) -> MftFileFacts | None:
    """Distil one Dissect ``MftRecord`` into plain facts, or None to skip it.

    A record with no Standard Information attribute (an empty or unused segment)
    yields None and is skipped. This is the only function that touches the Dissect
    record API, so any change there is contained here.
    """
    stdinfo = _first_attr(record, "STANDARD_INFORMATION")
    if not stdinfo:
        return None
    si = stdinfo[0]

    file_name: str | None = None
    file_size: str | None = None
    for fn in _first_attr(record, "FILE_NAME"):
        name = getattr(fn, "file_name", None)
        if name and file_name is None:
            file_name = str(name)
        size = getattr(fn, "file_size", None)
        if size is not None and file_size is None:
            file_size = str(size)

    try:
        path = record.full_path() or None
    except Exception:
        path = None
    try:
        is_dir = bool(record.is_dir())
    except Exception:
        is_dir = False
    try:
        sequence: str | None = str(record.header.SequenceNumber)
    except Exception:
        sequence = None

    return MftFileFacts(
        segment=getattr(record, "segment", None),
        sequence=sequence,
        path=path,
        file_name=file_name,
        is_dir=is_dir,
        file_size=file_size,
        created=_iso(getattr(si, "creation_time", None)),
        modified=_iso(getattr(si, "last_modification_time", None)),
        accessed=_iso(getattr(si, "last_access_time", None)),
        record_changed=_iso(getattr(si, "last_change_time", None)),
    )


class DissectMftAdapter(IngestAdapter):
    """Read an NTFS ``$MFT`` into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "dissect"

    def read(self, source: Path) -> Iterator[RawRecord]:
        """Yield one ``RawRecord`` per populated Standard Information timestamp.

        Raises ``RawModeDependencyError`` if Dissect is not installed (the optional
        ``raw`` extra). The file is opened read-only and closed when iteration ends.
        A record that cannot be parsed is skipped rather than aborting the run.
        """
        mft_class = load_mft_class()
        with source.open("rb") as handle:
            mft = mft_class(handle)
            for record in mft.segments():
                facts = _facts_from_record(record)
                if facts is None:
                    continue
                yield from mft_facts_to_raws(facts, source_file=source.name)
