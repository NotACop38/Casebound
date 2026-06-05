# Canonical event schema v0.1

This is the human-readable reference for the keystone record described in
`PRD.md` Section 10. Everything downstream of normalization hangs off it: ingest
adapters feed mappers that produce these events, enrichment annotates them, the
verifier addresses them by `event_id`, and the report links every claim back to
one of them.

The machine-readable validation source of truth is
[`schema/event.schema.json`](../schema/event.schema.json). The Python record that
mirrors it exactly is `casebound/normalize/schema.py`. If the two ever disagree,
that is a bug. The schema is frozen for the vertical slice; changing it requires
stopping and asking first (see `AGENTS.md`).

Note on style: no em dashes or en dashes anywhere, per PRD Section 15.

## Fields

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `event_id` | string (64 hex) | yes | Stable SHA-256 content hash of the normalized core fields. Always derived, never authored. See "Event identity" below. |
| `datetime` | string | yes | ISO 8601 timestamp normalized to UTC, with a trailing `Z`, for example `2026-03-14T08:42:17Z`. |
| `timestamp_raw` | string | yes | The original timestamp string exactly as found in the source. |
| `source_timezone` | string | yes | The timezone used to derive `datetime`: an IANA name such as `America/New_York`, or `UTC`, or the literal `assumed_utc` when no zone was known. |
| `timestamp_desc` | string | yes | One of `created`, `modified`, `accessed`, `logged`, `other`. How the timestamp relates to the event (Timesketch-friendly). |
| `message` | string | yes | A short human-readable summary of the event. |
| `host` | string or null | yes | Hostname or system identifier, or `null` when unknown. |
| `principal` | string or null | yes | Account, user, or SID associated with the event, or `null` when unknown. |
| `action` | string | yes | A normalized snake_case verb, for example `process_create`, `logon`, `file_write`, `registry_set`, `service_install`, `network_connect`. The vocabulary is open; `KNOWN_ACTIONS` lists the recommended verbs. |
| `object` | string or null | yes | The primary target (process path, file path, registry key, remote endpoint), or `null` when not applicable. |
| `source_tool` | string | yes | One of `hayabusa`, `eztools`, `chainsaw`, `velociraptor`, `plaso`, `generic_csv`, `dissect`. |
| `source_artifact` | string | yes | The originating artifact, for example `Security.evtx`, `$MFT`, `NTUSER.dat UserAssist`. |
| `details` | object | yes | A structured object holding source-specific fields. May be empty. |
| `attack_techniques` | array | yes | List of `{ technique_id, mapping_source }`. `technique_id` looks like `T1059` or `T1059.001`. `mapping_source` records how the mapping was made, for example `rule_tag` or `mapping_table`. May be empty. |
| `ioc_refs` | array of strings | yes | References into the extracted IOC set. May be empty. |
| `confidence` | number | yes | Normalization and mapping confidence, from 0 to 1. |
| `raw_ref` | object | yes | `{ source_file, record }`: a pointer back to the source record for audit (FR11). |
| `tags` | array of strings | yes | Free-form labels, for example an episode id or analyst tags. May be empty. |

Every field is present on every event. The fields that can be `null` are `host`,
`principal`, and `object`; the array and object fields can be empty but are never
absent.

## Event identity

`event_id` is the SHA-256 hex digest of a canonical encoding of exactly these
core fields, in this order:

```
datetime, timestamp_desc, host, principal, action, object, source_tool, source_artifact
```

A namespace string that includes the schema version is folded into the hashed
content, so ids cannot silently collide across future schema versions. A `null`
core field hashes the same as an empty string.

The `datetime` is canonicalized before it is hashed: it is parsed to a real UTC
instant and re-rendered in one fixed representation, with sub-second precision
preserved but trailing zeros trimmed. So `2026-03-14T08:42:17Z` and
`2026-03-14T08:42:17.000Z` are the same instant, canonicalize to the same
string, and produce the same `event_id`, while a genuinely different instant such
as `2026-03-14T08:42:17.5Z` produces a different id. Impossible calendar instants
are rejected outright.

The record is immutable once constructed. Core identity fields cannot be
reassigned, so an `event_id` can never drift out of sync with the fields it
hashes; enrichment that adds tags or technique mappings builds a new event or
mutates list contents in place rather than rebinding a core field.

Two consequences follow, and they are exactly the guarantees the verifier relies
on:

- Determinism: the same logical event always produces the same `event_id`,
  regardless of which run produced it. Enrichment and presentation fields
  (`message`, `details`, `attack_techniques`, `ioc_refs`, `confidence`, `tags`)
  and the provenance pointer (`timestamp_raw`, `source_timezone`, `raw_ref`) are
  deliberately outside the identity, so re-tagging or re-summarizing an event
  never changes its id.
- No collision: changing any core field changes the `event_id`.

`event_id` is always recomputed from the core fields, never trusted from input.
Loading an event whose stored `event_id` does not match its core fields is an
error, so a tampered or stale id never passes silently. This is what makes an id
an unforgeable handle to a real, deterministically extracted event.

Cross-source de-duplication of otherwise-identical observations (FR12) is a later
phase and does not change this identity definition. If it ever needs to, that is
a schema change: stop and ask first.

## Worked example 1: Windows process create

A Word document spawns an encoded PowerShell command. This is the kind of event
that anchors an initial-access claim in the narrative. The source timestamp was
recorded in `America/New_York` and normalized to UTC.

```json
{
  "event_id": "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70",
  "datetime": "2026-03-14T08:42:17Z",
  "timestamp_raw": "2026-03-14 03:42:17",
  "source_timezone": "America/New_York",
  "timestamp_desc": "logged",
  "message": "winword.exe spawned powershell.exe with an encoded command",
  "host": "WIN-ACCT-07",
  "principal": "CORP\\jdoe",
  "action": "process_create",
  "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
  "source_tool": "hayabusa",
  "source_artifact": "Security.evtx",
  "details": {
    "process_id": 6042,
    "parent_process_id": 4188,
    "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
    "command_line": "powershell.exe -nop -w hidden -enc SQBFAFgA",
    "event_id": 4688
  },
  "attack_techniques": [
    { "technique_id": "T1059.001", "mapping_source": "rule_tag" },
    { "technique_id": "T1566.001", "mapping_source": "mapping_table" }
  ],
  "ioc_refs": ["ioc-0007"],
  "confidence": 0.95,
  "raw_ref": { "source_file": "hayabusa-timeline.csv", "record": "1487" },
  "tags": ["episode-initial-access"]
}
```

This event lives at
[`schema/examples/windows_process_create.json`](../schema/examples/windows_process_create.json)
and is validated against the schema in CI.

## Worked example 2: Windows logon

A successful network logon for a service account from another host on the
network, the kind of event that anchors a lateral-movement claim. Note that the
nested `details.event_id` (the Windows event id 4624) is unrelated to the
canonical `event_id`; the canonical id is always the content hash at the top
level.

```json
{
  "event_id": "4e959251e72c7f9c2bcf43acbcdf51ac69baf4542c49ff55e363316299b1da5e",
  "datetime": "2026-03-14T08:55:03Z",
  "timestamp_raw": "03/14/2026 04:55:03 AM",
  "source_timezone": "America/New_York",
  "timestamp_desc": "logged",
  "message": "Successful network logon for CORP\\svc-backup from 10.4.12.66",
  "host": "WIN-FILE-02",
  "principal": "CORP\\svc-backup",
  "action": "logon",
  "object": "10.4.12.66",
  "source_tool": "hayabusa",
  "source_artifact": "Security.evtx",
  "details": {
    "logon_type": 3,
    "event_id": 4624,
    "source_ip": "10.4.12.66",
    "authentication_package": "NTLM"
  },
  "attack_techniques": [
    { "technique_id": "T1021.002", "mapping_source": "mapping_table" }
  ],
  "ioc_refs": ["ioc-0003"],
  "confidence": 0.9,
  "raw_ref": { "source_file": "hayabusa-timeline.csv", "record": "1623" },
  "tags": ["episode-lateral-movement"]
}
```

This event lives at
[`schema/examples/windows_logon.json`](../schema/examples/windows_logon.json)
and is validated against the schema in CI.
