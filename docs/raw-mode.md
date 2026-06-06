# Raw mode (optional, license-gated)

Most of Casebound consumes tool output a responder already produced (Hayabusa,
the Eric Zimmerman tools, Chainsaw, Velociraptor, Plaso, generic CSV). Raw mode is
the exception: it parses evidence artifacts directly for users who have not
pre-run those tools. The MVP raw adapters parse a Windows EVTX event log and an
NTFS `$MFT`, normalizing both into the same canonical event schema as every other
source.

Raw mode is built on Dissect (Fox-IT, NCC Group), a pure-Python, read-only
forensic parser. It is optional and isolated for license reasons (see below).

## Installing

Dissect is not a core dependency. A default install pulls in no Dissect:

```
pip install casebound
```

Raw mode is an opt-in extra:

```
pip install "casebound[raw]"
```

This installs `dissect.eventlog` (EVTX) and `dissect.ntfs` (`$MFT`).

## Using the adapters

The raw adapters implement the same `IngestAdapter` interface as every other
source, so their records flow through the existing normalize pipeline unchanged.
They are imported from the isolated `casebound.ingest.raw` subpackage, not the
top-level `casebound.ingest` package, so that nothing on the core import path ever
references them.

```python
from pathlib import Path

from casebound.ingest.raw import DissectEvtxAdapter, DissectMftAdapter
from casebound.normalize import normalize_records

# Parse a Windows event log directly.
evtx_records = DissectEvtxAdapter().read(Path("Security.evtx"))

# Parse an NTFS master file table directly.
mft_records = DissectMftAdapter().read(Path("$MFT"))

result = normalize_records(list(evtx_records) + list(mft_records))
for event in result.events:
    print(event.datetime, event.action, event.object)
```

Every produced event carries `source_tool="dissect"`. EVTX events map the Windows
EventID to a canonical action, principal, and object through the same shared table
Velociraptor uses, so a Dissect-parsed EVTX maps identically to the same event
seen through Velociraptor. `$MFT` events expand each file record into one event
per Standard Information timestamp (created, modified, accessed, and the record
change), mirroring the Eric Zimmerman `$MFT` mapper.

If the `raw` extra is not installed, calling `read` raises a clear
`RawModeDependencyError` that names the extra to install, rather than a bare
`ImportError`.

## Defensive scope

Raw mode does not widen Casebound's defensive scope. Dissect is a read-only parser
of already-collected artifacts. The adapters open evidence files read-only, never
acquire, never collect remotely, and never execute anything (PRD Section 6, Hard
rule 1). The defensive-scope invariant test scans the raw subpackage too.

## The license boundary (decision D2)

The Casebound core is Apache-2.0. Dissect is AGPL-3.0. To keep the core license
permissive while still offering raw mode, Dissect is isolated three ways:

1. Optional install. Dissect is declared only under the `raw` optional-dependency
   extra in `pyproject.toml`, never as a core dependency. A default install brings
   in no AGPL code.
2. Lazy import. Nothing imports Dissect at module load. The import happens inside
   `read`, only when a user invokes raw parsing, so importing the package (or the
   `casebound.ingest.raw` subpackage itself) loads no AGPL code.
3. No core import path. Every Dissect-dependent line lives in the single
   subpackage `casebound/ingest/raw`. No module outside it imports Dissect or that
   subpackage, so the entire core pipeline (ingest of tool output, normalize,
   enrich, verify, narrate, report, the demo) runs with zero AGPL code on its
   import graph.

Because of (3), the normalization of the records the raw adapters emit lives in
the Apache-2.0 core (`casebound/normalize/mappers/dissect.py`) and is fully tested
offline with golden fixtures; only the thin Dissect byte-parsing is gated behind
the extra.

The boundary is enforced in code by `tests/test_license_boundary.py`, which fails
if any core module imports `dissect` or `casebound.ingest.raw`, if Dissect ever
becomes a core dependency, or if the core license stops being Apache-2.0.

When you install the `raw` extra and use these adapters, the resulting combined,
installed work includes AGPL-3.0 code (Dissect) and is then subject to its terms.
Casebound itself neither bundles nor redistributes Dissect.

## Re-verifying the Dissect APIs

Per the project convention, external library APIs are re-verified at author time.
The adapters were written against these Dissect APIs:

- EVTX (`dissect.eventlog`): `Evtx(fh)` takes a binary file handle and is iterable,
  yielding one `KeyValueCollection` (a `dict` subclass) per record. Keys are the
  flattened XML element names (System children such as `EventID`, `Computer`,
  `Channel`, `Provider_Name`, `TimeCreated_SystemTime`, `EventRecordID`), and each
  EventData `Data Name="X"` entry appears under `X`.
- NTFS `$MFT` (`dissect.ntfs`): `Mft(fh)` takes a binary file handle and
  `mft.segments()` yields `MftRecord` objects. A record exposes
  `attributes.STANDARD_INFORMATION` (with `creation_time`,
  `last_modification_time`, `last_access_time`, `last_change_time`),
  `attributes.FILE_NAME` (with `file_name`, `file_size`), `full_path()`,
  `is_dir()`, `segment`, and `header.SequenceNumber`.

If a future Dissect release changes these, the only code that needs updating is the
thin Dissect-facing reader in `casebound/ingest/raw/evtx.py` and
`casebound/ingest/raw/mft.py`; the normalization and its golden tests are
unaffected.
