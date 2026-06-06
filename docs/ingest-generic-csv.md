# Generic CSV ingestion (the column-mapping config)

Not every timeline source warrants a bespoke adapter. The generic CSV adapter
(`casebound.ingest.generic_csv.GenericCsvAdapter`, source tool `generic_csv`,
PRD FR4) ingests any delimited CSV once you describe which columns hold the
canonical event fields. That description is a small `ColumnMap`, loadable from a
JSON file with `ColumnMap.from_json`.

The adapter does all of the config interpretation at read time and resolves every
canonical value, so the normalize pipeline dispatches generic CSV records exactly
like every other source. A row whose timestamp cannot be parsed is still emitted
and reported as a malformed row rather than aborting the run (FR7).

## Config fields

| Field | Required | Meaning |
| --- | --- | --- |
| `timestamp` | yes | Source column holding the event timestamp. |
| `message_column` | no | Column for the human-readable summary. When absent, a short message is built from the action and object. |
| `host_column` | no | Column for the hostname. Null when absent. |
| `principal_column` | no | Column for the account, user, or SID. Null when absent. |
| `object_column` | no | Column for the primary target (path, key, endpoint). Null when absent. |
| `action_column` | no | Column for the action verb. The value is normalized into a canonical snake_case verb (for example `Process Create` becomes `process_create`). Falls back to `default_action` when absent or unusable. |
| `timestamp_desc_column` | no | Column for the timestamp descriptor. Must resolve to one of created, modified, accessed, logged, other; otherwise `default_timestamp_desc` is used. |
| `record_id_column` | no | Column to use as the audit handle in `raw_ref.record`. Without it the 1-based source line number is used. |
| `default_action` | no | The action verb when no action column is present or its value is unusable. Default `other`. |
| `default_timestamp_desc` | no | The descriptor when no descriptor column is present. Default `other`. |
| `source_artifact` | no | Label recorded as the origin of every row. Default `generic_csv`. |
| `assume_timezone` | no | IANA zone name used to interpret timestamps that carry no UTC offset (FR9). |
| `detail_columns` | no | List of columns to preserve in `details`. When omitted, every column not already mapped to a canonical field is preserved. |

## Worked example

Given an EDR export with the columns
`EventTime, Hostname, UserName, Action, Target, Severity, Description`, this
config (see `tests/fixtures/generic_edr_map.json`) maps it into the canonical
schema:

```json
{
  "timestamp": "EventTime",
  "host_column": "Hostname",
  "principal_column": "UserName",
  "action_column": "Action",
  "object_column": "Target",
  "message_column": "Description",
  "default_timestamp_desc": "logged",
  "source_artifact": "edr_export.csv"
}
```

A row reading
`2026-03-14T08:42:17Z, WIN-ACCT-07, CORP\jdoe, Process Create, C:\...\powershell.exe, high, Office application spawned PowerShell`
normalizes to a `process_create` event at `2026-03-14T08:42:17Z` on host
`WIN-ACCT-07` by principal `CORP\jdoe`, with the unmapped `Severity` column
preserved under `details`.

## Usage

```python
from pathlib import Path
from casebound.ingest import ColumnMap, GenericCsvAdapter
from casebound.normalize import normalize_records

column_map = ColumnMap.from_json(Path("my-source.map.json"))
result = normalize_records(GenericCsvAdapter(column_map).read(Path("my-source.csv")))
```
