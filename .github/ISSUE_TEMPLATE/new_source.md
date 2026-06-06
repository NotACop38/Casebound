---
name: New ingestion source
about: Propose or contribute a new evidence source adapter
title: "feat(ingest): add <source> adapter"
labels: ingestion-source
assignees: ''
---

Adding a source is designed to take an afternoon. Read
[`docs/authoring.md`](../../docs/authoring.md) before you start. Every ingestion
source ships with a fixture and a normalization golden test, no exceptions.

## The source

- Tool or product name:
- Output format (CSV, JSON, JSONL, other):
- A link to its docs or output spec:
- A short, real-shaped sample row (synthetic or public data only, never real case
  data):

```text
paste one representative row here
```

## Why a bespoke adapter

If the source is a plain delimited CSV, the generic CSV adapter with a column map
may already cover it (see [`docs/ingest-generic-csv.md`](../../docs/ingest-generic-csv.md)).
Explain what makes this source need its own adapter, or confirm the generic path
does not fit.

## Required for the pull request

The PR that closes this issue must include all of these. This is the adapter
authoring standard:

- [ ] `source_tool` name added to `SOURCE_TOOLS` in `casebound/normalize/schema.py`.
- [ ] Read-only adapter in `casebound/ingest/<source>.py`, exported from the ingest
      package.
- [ ] Mapper in `casebound/normalize/mappers/<source>.py`, registered in
      `default_mappers()`.
- [ ] A **fixture** in `tests/fixtures/<source>_slice.*` (a good row, a fallback
      row, and a malformed row).
- [ ] A **golden file** in `tests/fixtures/<source>_slice.events.json`, verified
      field by field.
- [ ] A **normalization golden test** in `tests/test_<source>.py` that pins the
      fixture to the golden output and proves malformed rows are reported (FR7).
- [ ] `make ci` is green.

## Scope confirmation

- [ ] The adapter is a pure reader: it never acquires, collects remotely,
      executes anything, or reaches the network.
- [ ] No real case data and no secrets are added.
