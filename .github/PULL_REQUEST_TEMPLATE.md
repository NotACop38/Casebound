<!--
Thanks for contributing to Casebound. Read CONTRIBUTING.md if you have not yet.
The prime directive: no unverified claim ever reaches a report. Keep the gate
green and the scope defensive. No em dashes or en dashes anywhere.
-->

## Summary

What this change does and why.

Closes #

## Type of change

- [ ] feat (new behavior)
- [ ] fix (bug fix)
- [ ] docs
- [ ] test
- [ ] refactor
- [ ] chore

## Checklist

- [ ] `make ci` is green locally (lint, types, tests, schema, secrets, bandit,
      deps).
- [ ] New behavior has tests.
- [ ] No real case data and no secrets are added. Only synthetic or public sample
      evidence.
- [ ] No em dashes or en dashes anywhere (code, comments, docs, CLI output, commit
      messages). Use hyphens, colons, or commas.
- [ ] Commits follow conventional style and are focused.

## Verifier (required if you touched `verify/`)

- [ ] This change ships a grounded-accept test and a fabricated-reject test in the
      same commit.
- [ ] The hallucination-trap test still passes.
- [ ] This change does not weaken, bypass, or shortcut the verification guarantee.

If you did not touch `verify/`, write "n/a" here:

## New ingestion source (delete this section if not applicable)

A new source requires both a fixture and a golden test. See
[`docs/authoring.md`](../docs/authoring.md).

- [ ] `source_tool` added to `SOURCE_TOOLS` in `casebound/normalize/schema.py`.
- [ ] Read-only adapter in `casebound/ingest/<source>.py`, exported from the ingest
      package.
- [ ] Mapper in `casebound/normalize/mappers/<source>.py`, registered in
      `default_mappers()`.
- [ ] **Fixture** in `tests/fixtures/<source>_slice.*` (good row, fallback row,
      malformed row).
- [ ] **Golden file** in `tests/fixtures/<source>_slice.events.json`, verified
      field by field.
- [ ] **Normalization golden test** in `tests/test_<source>.py` that proves
      malformed rows are reported (FR7).

## Scope and changes that need a conversation first

- [ ] This change is read-only and defensive: it does not acquire, collect
      remotely, execute suspect binaries, or remediate.
- [ ] It adds no network call to a default, non-opt-in path.
- [ ] It does not change the canonical event schema or the claim-and-citation
      contract. (If it does, link the issue where this was agreed first.)
- [ ] It adds no new dependency. (If it does, link the issue where this was agreed
      first.)
