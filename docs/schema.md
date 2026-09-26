# Canonical event schema 0.2

Every input Casebound reads, whatever tool produced it, is normalized into this one
record (PRD Section 10). Everything downstream hangs off it: enrichment annotates
it, the verifier addresses it by `event_id`, and every sentence of a report links
back to one.

The validation source of truth is the JSON Schema shipped inside the package,
[`casebound/data/event.schema.json`](../casebound/data/event.schema.json). The
Python record that mirrors it is `casebound/normalize/schema.py`; the test suite
and the CI gate hold the two together. Changing the schema needs a stop-and-ask
(AGENTS.md).

## Fields

Every field is present on every event. Only `host`, `principal`, and `object` may
be `null`; arrays and objects may be empty.

| Field | Type | Meaning |
| --- | --- | --- |
| `event_id` | string, 64 hex | SHA-256 content hash of the core fields. Always derived, never authored (see "Identity"). |
| `datetime` | string | The instant in UTC, ISO 8601 with a trailing `Z`, for example `2026-03-14T08:42:17Z`. Sub-second precision is kept to the microsecond; finer digits are truncated. |
| `timestamp_raw` | string | The timestamp exactly as the source wrote it. |
| `source_timezone` | string | How `datetime` was derived: an IANA zone (`America/New_York`), `UTC`, the fixed offset the source printed (`UTC-04:00`), or `assumed_utc` when the source gave no zone. |
| `timestamp_desc` | string | How the time relates to the event: `created`, `modified`, `accessed`, `logged`, or `other` (Timesketch's convention). |
| `message` | string | A short summary. For a detection source it is the rule title. |
| `host` | string or null | The system the event happened on. |
| `principal` | string or null | The acting account, as `DOMAIN\user` when the domain is known. |
| `action` | string | A snake_case verb such as `process_create`, `logon`, `registry_set`, `service_install`, `log_clear`. `KNOWN_ACTIONS` lists the vocabulary the mappers emit; `other` means the source did not say. |
| `object` | string or null | The primary target: an image or file path, a registry value, a service or task name, a share, a remote endpoint, an event log. |
| `source_tool` | string | `hayabusa`, `chainsaw`, `eztools`, `velociraptor`, `plaso`, `generic_csv`, or `dissect`. |
| `source_artifact` | string | The artifact the record came from, for example `Security.evtx` or `$MFT`. |
| `details` | object | Source-specific fields, kept for the evidence appendix. The model never sees them. |
| `attack_techniques` | array | `{technique_id, mapping_source, source_id?}` objects (see below). |
| `ioc_refs` | array of strings | Ids of the indicators extracted from this event. |
| `confidence` | number, 0 to 1 | How fully the record was understood. The Windows event mappers use 1.0 for an EventID their table covers and 0.5 when they fall back to a generic `other`. |
| `raw_ref` | object | `{source_file, record}`: where the record is in the source file (the EVTX record id when the source gives one, else a line or entry number). |
| `tags` | array of strings | Labels such as the event's activity episode (`episode:EP-df801a77c149`). |

### ATT&CK techniques

Each entry of `attack_techniques` records a technique and how it was assigned:

- `technique_id`: a current ATT&CK Enterprise technique or sub-technique id
  (`T1059` or `T1059.001`).
- `mapping_source`: `rule_tag` when the source's own detection rule named it, or
  `mapping_table` when Casebound's documented table inferred it for a source with
  no detection layer (`casebound/enrich/attack.py`).
- `source_id` (new in 0.2, optional): present only when the source wrote an id
  that MITRE has since revoked. The tagger resolves every id against the bundled
  ATT&CK 19.2 catalog, emits the successor as `technique_id`, and keeps what the
  evidence said here. A rule that still tags Clear Windows Event Logs as
  `T1070.001` yields `{"technique_id": "T1685.005", "mapping_source": "rule_tag",
  "source_id": "T1070.001"}`.

## Identity

`event_id` is derived from these eight core fields (`CORE_ID_FIELDS`):

```
datetime, timestamp_desc, host, principal, action, object, source_tool, source_artifact
```

It is the SHA-256 hex digest of the UTF-8 bytes of the compact JSON array
`["casebound-event-v0.1", {...}]`, where the object maps each core field name to
its value with keys sorted, separators `,` and `:`, and non-ASCII characters left
unescaped (`compute_event_id` in `casebound/normalize/schema.py`). A `null` field
hashes like an empty string. `datetime` is canonicalized first: it is parsed to a
real instant and rendered in one form with trailing sub-second zeros trimmed, so
`08:42:17Z` and `08:42:17.000Z` share an id while `08:42:17.5Z` does not. An
impossible calendar instant, such as February 30, is rejected.

Consequences the verifier relies on:

- The same observation always gets the same id, whichever run produced it.
  Enrichment and presentation fields (`message`, `details`, `attack_techniques`,
  `ioc_refs`, `confidence`, `tags`) and the provenance fields (`timestamp_raw`,
  `source_timezone`, `raw_ref`) are outside the identity, so tagging or
  clustering never moves an id.
- Changing any core field changes the id.
- The id is always recomputed. Loading an event whose stored id does not match its
  core fields is an error, so a stale or tampered id cannot pass.
- Records that describe the same observation collapse into one event, and every
  source record is kept as its provenance (FR12): the same export read twice, or
  two overlapping collections, produce one event with a pointer into each file.
  Because `source_tool` and `source_artifact` are core fields, the same real-world
  event seen by two different tools stays two events, each with its own
  provenance; merging across tools would change the identity definition.

The namespace names the identity definition, not the schema version. The core
fields and their encoding are unchanged since 0.1, so event ids are stable across
the 0.1 to 0.2 change.

## Changes from 0.1

- `attack_techniques[].source_id` records a revoked technique id the source wrote.
- The schema moved from `schema/event.schema.json` into the package, so an installed
  Casebound validates against exactly the schema it was built with.

## Worked examples

These are real records from `events.jsonl` for the bundled synthetic scenario,
committed under [`docs/examples/`](examples/) and validated against the schema by
the CI gate.

The Word-spawned PowerShell that opens the intrusion
([`windows_process_create.json`](examples/windows_process_create.json)):

```json
{
  "event_id": "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70",
  "datetime": "2026-03-14T08:42:17Z",
  "timestamp_raw": "2026-03-14 04:42:17.000 -04:00",
  "source_timezone": "UTC-04:00",
  "timestamp_desc": "logged",
  "message": "Office Application Spawned PowerShell (Possible Phishing Macro)",
  "host": "WIN-ACCT-07",
  "principal": "CORP\\jdoe",
  "action": "process_create",
  "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "source_tool": "hayabusa",
  "source_artifact": "Security.evtx",
  "details": {
    "win_event_id": 4688,
    "channel": "Security",
    "fields": {
      "CommandLine": "powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
      "NewProcessName": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "ParentProcessName": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "SubjectDomainName": "CORP",
      "SubjectUserName": "jdoe"
    },
    "level": "high",
    "rule_title": "Office Application Spawned PowerShell (Possible Phishing Macro)",
    "mitre_tactics": ["InitAccess", "Exec"],
    "rule_mitre_tags": ["T1566.001", "T1059.001"]
  },
  "attack_techniques": [
    { "technique_id": "T1566.001", "mapping_source": "rule_tag" },
    { "technique_id": "T1059.001", "mapping_source": "rule_tag" }
  ],
  "ioc_refs": ["ioc-4c86505da896", "ioc-503b5fcafd6e"],
  "confidence": 1.0,
  "raw_ref": { "source_file": "synthetic_hayabusa.csv", "record": "81104" },
  "tags": ["episode:EP-df801a77c149"]
}
```

(`details` is abridged here; the committed file carries every field.) Note that
the principal reads `CORP\jdoe`: Hayabusa's Details template for Security 4688
shows only `SubjectUserName`, and the mapper recovers the domain from the
`ExtraFieldInfo` column.

The log clearing that ends it
([`windows_log_clear.json`](examples/windows_log_clear.json)) shows a revoked rule
tag translated to its successor:

```json
"attack_techniques": [
  { "technique_id": "T1685.005", "mapping_source": "rule_tag", "source_id": "T1070.001" }
]
```

[`windows_logon.json`](examples/windows_logon.json) is the stolen-credential
network logon on the file server, the anchor of the lateral-movement episode.
