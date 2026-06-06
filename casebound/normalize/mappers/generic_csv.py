"""Map generic CSV rows to canonical events via a column-mapping config (FR4).

Not every source has a bespoke adapter. The generic CSV path lets an analyst point
Casebound at any delimited timeline by describing, once, which columns hold the
canonical fields (see ``casebound.ingest.generic_csv.ColumnMap``). The generic CSV
adapter does the config interpretation at read time and resolves every canonical
value, so this mapper is a thin reassembler: it reads the resolved values the
adapter wrote under the reserved keys defined here and builds the ``Event``.

Keeping all configuration in the adapter (which the caller constructs with the
config) and none in the mapper means the normalize pipeline can dispatch generic
CSV records the same way it dispatches every other source, with no special casing.

  - ``datetime`` and ``source_timezone`` come from the resolved timestamp string
    via the timezone normalizer (FR9); the adapter passes through any configured
    ``assume_timezone`` so a source's known local zone is honored.
  - ``timestamp_desc``, ``message``, ``host``, ``principal``, ``object``,
    ``action``, and ``source_artifact`` are read from the resolved reserved keys.
    A nullable field the adapter resolved to None is simply absent.
  - ``details`` is rebuilt from the resolved detail columns, each preserved under
    its original column name.
  - ``raw_ref`` is carried straight through from the record's provenance (FR11).

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
    "GENERIC_DETAIL_PREFIX",
    "GENERIC_KEY_ACTION",
    "GENERIC_KEY_ASSUME_TZ",
    "GENERIC_KEY_DATETIME",
    "GENERIC_KEY_HOST",
    "GENERIC_KEY_MESSAGE",
    "GENERIC_KEY_OBJECT",
    "GENERIC_KEY_PRINCIPAL",
    "GENERIC_KEY_SOURCE_ARTIFACT",
    "GENERIC_KEY_TIMESTAMP_DESC",
    "GenericCsvMapper",
]

# The reserved keys the generic CSV adapter writes the resolved canonical values
# under. They are namespaced so they cannot collide with a real source column.
# The adapter imports these so producer and consumer agree on one spelling (ingest
# may depend on normalize; the reverse is avoided).
GENERIC_KEY_DATETIME = "__cb_datetime"
GENERIC_KEY_TIMESTAMP_DESC = "__cb_timestamp_desc"
GENERIC_KEY_MESSAGE = "__cb_message"
GENERIC_KEY_HOST = "__cb_host"
GENERIC_KEY_PRINCIPAL = "__cb_principal"
GENERIC_KEY_OBJECT = "__cb_object"
GENERIC_KEY_ACTION = "__cb_action"
GENERIC_KEY_SOURCE_ARTIFACT = "__cb_source_artifact"
GENERIC_KEY_ASSUME_TZ = "__cb_assume_tz"

# Each resolved detail column is written under this prefix plus its original column
# name, so the mapper can rebuild the details object without knowing the config.
GENERIC_DETAIL_PREFIX = "__cb_detail:"


class GenericCsvMapper(Mapper):
    """Reassemble canonical events from generic-CSV records the adapter resolved."""

    source_tool: ClassVar[str] = "generic_csv"

    def map(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(
                data.get(GENERIC_KEY_DATETIME, ""),
                assume_timezone=(data.get(GENERIC_KEY_ASSUME_TZ) or None),
            )
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        details: dict[str, Any] = {
            key[len(GENERIC_DETAIL_PREFIX) :]: value
            for key, value in data.items()
            if key.startswith(GENERIC_DETAIL_PREFIX)
        }

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc=data.get(GENERIC_KEY_TIMESTAMP_DESC, "other"),
                message=data.get(GENERIC_KEY_MESSAGE, ""),
                action=data.get(GENERIC_KEY_ACTION, "other"),
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=data.get(GENERIC_KEY_HOST),
                principal=data.get(GENERIC_KEY_PRINCIPAL),
                object=data.get(GENERIC_KEY_OBJECT),
                details=details,
                confidence=1.0,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc
