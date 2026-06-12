# Add an ingestion source in an afternoon

Casebound normalizes the output of the DFIR tools responders already run. Adding a
new source is the most common contribution, and the architecture is shaped so it
takes an afternoon, not a rewrite. This guide walks the whole path with working
code, then gives you a copy-paste checklist.

If your source is just a delimited CSV, read
[`docs/ingest-generic-csv.md`](ingest-generic-csv.md) first: the generic CSV
adapter may already cover it with a small column-mapping config, and you can skip
writing code entirely.

## The mental model

Two small pieces, one canonical event:

```
raw tool output  --[adapter]-->  RawRecord (verbatim fields + provenance)
RawRecord        --[mapper]--->  Event (the canonical schema)
```

- The **adapter** (`casebound/ingest/<source>.py`) is a thin, read-only reader. It
  yields one `RawRecord` per source row, carrying the row's fields exactly as read
  plus its provenance (which tool, which artifact, which record). It does no
  interpretation, and it yields every structurally readable row. Deciding that a
  row cannot become a valid event is the mapper's job, so malformed rows are
  reported rather than silently dropped (FR7).
- The **mapper** (`casebound/normalize/mappers/<source>.py`) turns one
  `RawRecord` into one canonical `Event`, or raises `MappingError`. The normalize
  pipeline (`casebound/normalize/pipeline.py`) catches that, records the row as a
  problem, and keeps going.

The pipeline dispatches each record to the mapper registered for its
`source_tool`, assigns the stable content-derived `event_id`, de-duplicates
identical events while keeping every provenance pointer (FR12), and collects the
problems. You write the adapter and the mapper; the pipeline does the rest.

This split keeps each source's quirks in one small adapter and the canonical-event
logic in one place.

## The afternoon, step by step

We will add an illustrative source called `acme_edr`: a JSON-lines EDR export. Each
line is one detection:

```json
{"ts": "2026-03-14T08:42:17Z", "host": "WIN-ACCT-07", "user": "CORP\\jdoe", "verb": "ProcessCreate", "target": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "id": "evt-7", "severity": "high"}
```

A JSON-lines shape with a nested feel is a good example of when a bespoke adapter
earns its keep over the generic CSV path.

### 1. Name the source and add it to the vocabulary

`source_tool` is a controlled vocabulary in `casebound/normalize/schema.py`. Add
your name to it so both `RawRecord` and `Event` will accept it:

```python
# casebound/normalize/schema.py
SOURCE_TOOLS: frozenset[str] = frozenset(
    {
        "hayabusa",
        "eztools",
        "chainsaw",
        "velociraptor",
        "plaso",
        "generic_csv",
        "dissect",
        "acme_edr",  # new
    }
)
```

### 2. Write the adapter

The adapter implements `IngestAdapter`: declare the `source_tool` and implement
`read`, which returns an iterator of `RawRecord`. Read lazily so large timelines
stream. Keep every value in `data` a string, and carry provenance in `raw_ref`.

```python
# casebound/ingest/acme_edr.py
"""The Acme EDR ingest adapter (illustrative).

Reads an Acme EDR JSON-lines export and emits one RawRecord per detection. It is a
thin reader: it copies each line's fields verbatim and attaches provenance. It does
not interpret the fields into the canonical schema; the Acme EDR mapper does that.

Read-only over already-collected evidence (Hard rule 1). Style: no em dashes or en
dashes anywhere.
"""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any, ClassVar

from casebound.ingest.base import IngestAdapter, RawRecord
from casebound.normalize.schema import RawRef

__all__ = ["AcmeEdrAdapter"]

_DEFAULT_ARTIFACT = "acme_edr_export.jsonl"


def _as_str(value: Any) -> str:
    """Render a scalar JSON value as a string; containers become an empty string."""
    if value is None or isinstance(value, (dict, list)):
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


class AcmeEdrAdapter(IngestAdapter):
    """Read an Acme EDR JSON-lines export into raw, provenance-bearing records."""

    source_tool: ClassVar[str] = "acme_edr"

    def read(self, source: Path) -> Iterator[RawRecord]:
        # utf-8-sig consumes a leading BOM (PowerShell, Excel, and Notepad all
        # write one) and reads plain UTF-8 unchanged; every adapter does this.
        with source.open(encoding="utf-8-sig") as handle:
            for index, line in enumerate(handle, start=1):
                line = line.strip()
                if not line:
                    continue
                row = json.loads(line)
                if not isinstance(row, dict):
                    continue
                record_id = _as_str(row.get("id")).strip() or f"line:{index}"
                yield RawRecord(
                    source_tool=self.source_tool,
                    source_artifact=_DEFAULT_ARTIFACT,
                    raw_ref=RawRef(source_file=source.name, record=record_id),
                    data={key: _as_str(val) for key, val in row.items()},
                )
```

Export it from the ingest package so callers can import it:

```python
# casebound/ingest/__init__.py
from casebound.ingest.acme_edr import AcmeEdrAdapter
# ... and add "AcmeEdrAdapter" to __all__
```

### 3. Write the mapper

The mapper implements `Mapper`: declare the matching `source_tool` and implement
`map`, which returns one `Event` or raises `MappingError`. Use
`normalize_timestamp` for UTC handling (FR9). Normalize the action verb into a
canonical snake_case form. Wrap the `Event` construction so any schema violation
becomes a reported `MappingError` rather than a crash.

```python
# casebound/normalize/mappers/acme_edr.py
"""Map Acme EDR records to canonical events (illustrative).

Style: no em dashes or en dashes anywhere.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, ClassVar

from casebound.normalize.mappers.base import Mapper, MappingError
from casebound.normalize.schema import Event
from casebound.normalize.timezone import TimestampError, normalize_timestamp

if TYPE_CHECKING:
    from casebound.ingest.base import RawRecord

__all__ = ["AcmeEdrMapper"]

# Acme verbs to canonical snake_case actions. Unknown verbs fall back to a generic
# action at reduced confidence so the timeline stays complete (FR8).
_VERB_TO_ACTION = {
    "ProcessCreate": "process_create",
    "Logon": "logon",
    "NetworkConnect": "network_connect",
    "FileCreate": "file_create",
    "RegistrySet": "registry_set",
}
_FALLBACK_ACTION = "other"
_NON_SNAKE = re.compile(r"[^a-z0-9]+")


def _nullable(value: str | None) -> str | None:
    if value is None:
        return None
    trimmed = value.strip()
    return trimmed or None


def _to_snake(verb: str) -> str | None:
    slug = _NON_SNAKE.sub("_", verb.strip().lower()).strip("_")
    return slug or None


class AcmeEdrMapper(Mapper):
    """Map Acme EDR records into canonical events."""

    source_tool: ClassVar[str] = "acme_edr"

    def map(self, record: RawRecord) -> Event:
        data = record.data
        try:
            stamp = normalize_timestamp(data.get("ts", ""))
        except TimestampError as exc:
            raise MappingError(str(exc)) from exc

        verb = data.get("verb", "")
        action = _VERB_TO_ACTION.get(verb) or _to_snake(verb) or _FALLBACK_ACTION
        mapped = verb in _VERB_TO_ACTION
        host = _nullable(data.get("host"))
        principal = _nullable(data.get("user"))
        obj = _nullable(data.get("target"))
        message = _nullable(data.get("message")) or f"Acme EDR {verb or 'event'}"

        details = {
            key: value
            for key, value in data.items()
            if key not in {"ts", "host", "user", "verb", "target", "id"}
        }

        try:
            return Event(
                datetime=stamp.datetime_utc,
                timestamp_raw=stamp.timestamp_raw,
                source_timezone=stamp.source_timezone,
                timestamp_desc="logged",
                message=message,
                action=action,
                source_tool=record.source_tool,
                source_artifact=record.source_artifact,
                raw_ref=record.raw_ref,
                host=host,
                principal=principal,
                object=obj,
                details=details,
                confidence=1.0 if mapped else 0.5,
            )
        except Exception as exc:  # a schema violation is a malformed row, not fatal
            raise MappingError(f"could not build a canonical event: {exc}") from exc
```

`event_id` is derived by `Event` from the core fields, so you never set it. The
record is frozen and the id is always a faithful hash of the core fields, which is
what lets the pipeline de-duplicate while keeping provenance.

### 4. Register the mapper

Add the mapper to the registry so the pipeline can dispatch to it:

```python
# casebound/normalize/mappers/__init__.py
from casebound.normalize.mappers.acme_edr import AcmeEdrMapper
# add "AcmeEdrMapper" to __all__, then in default_mappers():
#     AcmeEdrMapper.source_tool: AcmeEdrMapper(),
```

### 5. Add a fixture and a golden file

Keep the fixture small and real-shaped, with at least one good row, one row that
exercises the fallback, and one malformed row to prove FR7.

`tests/fixtures/acme_edr_slice.jsonl`:

```text
{"ts": "2026-03-14T08:42:17Z", "host": "WIN-ACCT-07", "user": "CORP\\jdoe", "verb": "ProcessCreate", "target": "C:\\...\\powershell.exe", "id": "evt-7", "severity": "high"}
{"ts": "not-a-timestamp", "host": "WIN-ACCT-07", "verb": "ProcessCreate", "id": "evt-8"}
```

The golden file is the exact canonical output your mapper must produce. The easiest
way to author it correctly is to write the test first (next step), run it once to
print `[event.to_dict() for event in result.events]`, eyeball every field, then
paste the verified result into `tests/fixtures/acme_edr_slice.events.json`. Never
hand-wave the golden: it is the thing that locks your mapping down.

### 6. Write the golden test

Pin the fixture to the golden output, and assert the load-bearing properties. Model
it on `tests/test_chainsaw.py`.

```python
# tests/test_acme_edr.py
import json
from pathlib import Path
from typing import Any

from casebound.ingest import AcmeEdrAdapter
from casebound.normalize import NormalizationResult, normalize_records
from casebound.normalize.mappers import DEFAULT_MAPPERS, AcmeEdrMapper

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SLICE = FIXTURES / "acme_edr_slice.jsonl"
GOLDEN = FIXTURES / "acme_edr_slice.events.json"


def _normalize(path: Path) -> NormalizationResult:
    return normalize_records(AcmeEdrAdapter().read(path))


def test_slice_maps_to_golden_events() -> None:
    golden: dict[str, Any] = json.loads(GOLDEN.read_text(encoding="utf-8"))
    result = _normalize(SLICE)
    assert result.event_count == golden["event_count"]
    assert [event.to_dict() for event in result.events] == golden["events"]


def test_malformed_row_is_reported_not_fatal() -> None:
    # The bad-timestamp row is reported as a problem, the good row still maps (FR7).
    result = _normalize(SLICE)
    assert result.problem_count == 1
    assert result.event_count >= 1


def test_default_registry_has_acme_edr() -> None:
    assert isinstance(DEFAULT_MAPPERS["acme_edr"], AcmeEdrMapper)
```

If your source carries detection rule tags (Sigma `attack.tXXXX` or similar), also
assert they normalize to canonical technique ids and that the deterministic
tagging step promotes them, the way `tests/test_chainsaw.py` does. The mapper
preserves rule tags in `details`; it never decides techniques itself.

### 7. Run the gate

```bash
make ci
```

Lint, types, the full test suite, schema validation, the secret scan, bandit, and
the dependency audit all run offline. Green means you are done. Open a pull request
with the "new source" checklist.

## The new-source checklist

- [ ] `source_tool` name added to `SOURCE_TOOLS` in `casebound/normalize/schema.py`.
- [ ] Adapter in `casebound/ingest/<source>.py` implements `IngestAdapter`, is
      read-only, and yields every structurally readable row.
- [ ] Adapter exported from `casebound/ingest/__init__.py`.
- [ ] Mapper in `casebound/normalize/mappers/<source>.py` implements `Mapper` and
      raises `MappingError` on a row that cannot become a valid event.
- [ ] Mapper registered in `default_mappers()` and exported from
      `casebound/normalize/mappers/__init__.py`.
- [ ] Fixture in `tests/fixtures/<source>_slice.*` with a good row, a fallback
      row, and a malformed row.
- [ ] Golden file in `tests/fixtures/<source>_slice.events.json` verified field by
      field.
- [ ] Golden test in `tests/test_<source>.py` pinning the fixture to the golden
      output and proving malformed rows are reported (FR7).
- [ ] `make ci` is green.
- [ ] No real case data, no secrets, no em dashes or en dashes.

## The defensive line

An adapter reads already-collected evidence and nothing more. It never acquires,
never collects remotely, never executes anything, and never reaches the network.
`tests/test_defensive_scope.py` enforces this across the whole package and runs on
every `make ci`. Keep your adapter a pure reader and it will pass.
