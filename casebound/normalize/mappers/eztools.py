"""Map Eric Zimmerman / Timeline Explorer style CSV rows to canonical events (FR3).

KAPE triage runs the Eric Zimmerman tools and ships their CSV output, which an
analyst reviews in Timeline Explorer. This mapper handles the MFTECmd ``$MFT``
CSV, the keystone EZ-tools timeline artifact: one row per MFT record, carrying the
file's Standard Information (0x10) MACB timestamps. See
https://github.com/EricZimmerman/MFTECmd.

A single ``$MFT`` record describes several distinct timeline moments (when the
file was created, last written, last accessed, and when its MFT record last
changed). The EZ-tools adapter therefore expands one MFT row into one raw record
per populated Standard Information timestamp, annotating each with the chosen
timestamp string and its descriptor under the two reserved keys defined here
(``EZ_TIMESTAMP_KEY`` and ``EZ_TIMESTAMP_DESC_KEY``). This mapper reads those
annotations and the file-identity columns and derives the canonical fields:

  - ``datetime`` and ``source_timezone`` come from the annotated timestamp via the
    timezone normalizer (FR9); EZ tools emit UTC, so the source zone is recorded
    as ``UTC`` rather than the assumed-UTC fallback. ``timestamp_raw`` keeps the
    original string.
  - ``timestamp_desc`` is the annotated descriptor (created, modified, accessed,
    or other), and ``action`` follows from it through a small documented table
    (a creation is ``file_create``, a write is ``file_write``, an access is
    ``file_read``, an MFT record change is ``file_metadata_change``).
  - ``object`` is the file's full path, built from ParentPath and FileName.
  - ``host`` and ``principal`` are null: the ``$MFT`` CSV names neither.
  - ``message`` is a short, human-readable summary of the timestamped file event.
  - ``details`` preserves the source specifics: the MFT entry and sequence numbers,
    the file size, whether it is a directory, the extension, and all four SI
    timestamps for cross-reference.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

The ``event_id`` is derived by ``Event`` from the core fields, so the four MACB
moments of one file become four distinct events (they differ in datetime,
timestamp_desc, and action) while two genuinely identical observations collapse
and keep every provenance pointer (FR10, FR12).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
from casebound.normalize.schema import Event
from casebound.normalize.timezone import TimestampError, normalize_timestamp

if TYPE_CHECKING:
    # Annotation-only: keeps normalize free of a runtime dependency on ingest.
    from casebound.ingest.base import RawRecord

__all__ = [
    "EZ_TIMESTAMP_DESC_KEY",
    "EZ_TIMESTAMP_KEY",
    "EZToolsMapper",
    "build_path",
]

# The two reserved keys the EZ-tools adapter writes onto each expanded record: the
# chosen Standard Information timestamp string and its canonical descriptor. They
# are namespaced with a leading underscore so they cannot collide with a real
# MFTECmd column. The adapter imports these so the producer and consumer agree on
# one spelling (ingest may depend on normalize; the reverse is avoided).
EZ_TIMESTAMP_KEY = "_ez_timestamp"
EZ_TIMESTAMP_DESC_KEY = "_ez_timestamp_desc"

# EZ tools normalize every timestamp to UTC, so a naive Standard Information time
# is interpreted as UTC and labeled as such rather than flagged assumed_utc.
_SOURCE_TIMEZONE = "UTC"

# How a Standard Information timestamp descriptor becomes a canonical action verb.
# Keys mirror the descriptors the adapter emits; an unexpected descriptor falls
# back to a generic file event rather than aborting the row.
_DESC_ACTIONS: dict[str, str] = {
    "created": "file_create",
    "modified": "file_write",
    "accessed": "file_read",
    "other": "file_metadata_change",
}
_FALLBACK_ACTION = "file_metadata_change"


def _nullable(value: str | None) -> str | None:
    """Collapse an empty or missing string to None for the nullable core fields."""
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def build_path(parent_path: str | None, file_name: str | None) -> str | None:
    """Join an MFTECmd ParentPath and FileName into one full path.

    MFTECmd reports the parent directory and the file name separately, with the
    parent rooted at ``.`` (for example ``.\\Users\\jdoe``). They are joined with a
    backslash. When only one part is present that part is returned; when neither
    is present the path is None so the object stays honestly empty.
    """
    parent = _nullable(parent_path)
    name = _nullable(file_name)
    if parent is None:
        return name
    if name is None:
        return parent
    separator = "\\"
    return f"{parent.rstrip(separator)}{separator}{name}"


class EZToolsMapper(Mapper):
    """Map Eric Zimmerman MFTECmd ``$MFT`` records into canonical events."""

    source_tool: ClassVar[str] = "eztools"

    def map(self, record: RawRecord) -> Event:
        data = record.data
        raw_timestamp = data.get(EZ_TIMESTAMP_KEY, "")
        try:
            stamp = normalize_timestamp(raw_timestamp, assume_timezone=_SOURCE_TIMEZONE)
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        desc = (data.get(EZ_TIMESTAMP_DESC_KEY) or "other").strip() or "other"
        action = _DESC_ACTIONS.get(desc, _FALLBACK_ACTION)
        path = build_path(data.get("ParentPath"), data.get("FileName"))

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc=desc,
                message=self._message(desc, path),
                action=action,
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=None,
                principal=None,
                object=path,
                details=self._details(data),
                confidence=1.0,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc

    @staticmethod
    def _message(desc: str, path: str | None) -> str:
        where = path if path is not None else "unknown path"
        return f"MFT standard information {desc} timestamp for {where}"

    @staticmethod
    def _details(data: Any) -> dict[str, Any]:
        details: dict[str, Any] = {"artifact": "$MFT"}
        # Preserve the file-identity and the full MACB set for cross-reference, but
        # never the reserved annotation keys, which are control metadata.
        for key in (
            "EntryNumber",
            "SequenceNumber",
            "InUse",
            "ParentPath",
            "FileName",
            "Extension",
            "FileSize",
            "IsDirectory",
            "Created0x10",
            "LastModified0x10",
            "LastAccess0x10",
            "LastRecordChange0x10",
        ):
            value = _nullable(data.get(key))
            if value is not None:
                details[key] = value
        return details
