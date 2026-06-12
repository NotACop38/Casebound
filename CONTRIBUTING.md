# Contributing to Casebound

Thanks for considering a contribution. Casebound is a local-first DFIR
investigation copilot, and it has one reason to exist: the verification guarantee.
This guide explains the line we never cross, the standard every change meets, and
the fastest path to a merged pull request. The most common contribution, a new
ingestion source, has its own afternoon-length walkthrough in
[`docs/authoring.md`](docs/authoring.md).

Before you start, read [`AGENTS.md`](AGENTS.md). It is the operating contract for
this repository and it governs human and agent contributors alike.

## The prime directive

No factual claim reaches a report unless it resolves to a real,
deterministically extracted timeline event and the facts it asserts (time,
principal, action, object) are consistent with that event. The deterministic
layer is the source of truth. The language model is a drafting aid that is fenced
by it and never has the authority to state a fact.

Never weaken, bypass, shortcut, or optimize away the verifier. If a change would
let an unverified claim into a report, we will not merge it. Any change under
`verify/` ships in the same commit with both a grounded-accept test and a
fabricated-reject test, and the hallucination-trap test must always pass.

## The defensive line

Casebound is read-only analysis of evidence that has already been collected, and
it is built to be employer-safe. Contributions stay inside these lines (PRD
Section 6, [`SECURITY.md`](SECURITY.md)):

- Read-only only. No acquisition that modifies an endpoint, no remote collection,
  no remediation or containment.
- No detonation, no sandboxing, no execution of suspect binaries.
- No network on any default path. The deterministic core runs fully offline. Any
  cloud-model path is opt-in behind an explicit flag and must pass the redaction
  step first.
- No real data, ever. Only synthetic or public sample evidence. Never commit a
  secret. The secret scan stays green.
- The model is fenced. It only ever sees the compact, id-addressed event view,
  never raw evidence files, and it never decides what is true.

These are enforced in code, not just prose. `tests/test_defensive_scope.py`,
`tests/test_no_egress.py`, and `tests/test_redact.py` run on every `make ci` and
again as a named step in `make security`. A pull request that trips them does not
merge.

## Project setup

Casebound targets Python 3.11 or newer.

```bash
git clone https://github.com/NotACop38/Casebound.git
cd casebound
python -m venv .venv && source .venv/bin/activate
make install          # editable install plus the pinned dev toolchain
make ci               # the full gate: lint, types, tests, schema, secrets, bandit, deps
```

`make demo` runs the whole pipeline offline on the bundled synthetic scenario and
writes the report, the Navigator layer, and the metrics to `out/`. Use it to see
your change end to end.

## The build surface

These targets are the contract. Keep them working as the project grows.

| Command | What it does |
| --- | --- |
| `make install` | Install the package and the pinned dev dependencies. |
| `make lint` | ruff check, ruff format check, and mypy. Zero errors. |
| `make test` | pytest. All green, no network, no API keys. |
| `make demo` | Run the full pipeline offline, producing `out/report.html` and the metrics. |
| `make ci` | The gate: lint, test, schema validation, secret scan, bandit, dependency audit. |
| `make security` | The gate plus the defensive-scope invariant tests. |

## Definition of done for a pull request

A change is ready when:

- `make ci` is green locally and in the workflow.
- New behavior has tests. New ingestion sources ship a fixture and a
  normalization golden test (see below). Verifier changes ship a grounded-accept
  test and a fabricated-reject test.
- No real case data and no secrets are added.
- The style rule holds: no em dashes or en dashes anywhere. Use hyphens, colons,
  or commas. This applies to code, comments, docs, CLI output, and commit
  messages.
- Commits follow conventional style (`feat`, `fix`, `chore`, `docs`, `test`,
  `refactor`), imperative mood, with a curated history rather than `wip` noise.

## The adapter authoring standard

Adding an ingestion source is the headline contribution, and it is designed to
take an afternoon. The pattern is always the same:

1. An **ingest adapter** (`casebound/ingest/<source>.py`) reads already-collected
   tool output and yields one provenance-bearing `RawRecord` per source row. It
   is a thin, read-only reader. It never interprets fields into the canonical
   schema, and it yields every structurally readable row rather than deciding a
   row is invalid (that is the mapper's job, so malformed rows are reported, not
   dropped, per FR7).
2. A **field mapper** (`casebound/normalize/mappers/<source>.py`) turns each
   `RawRecord` into one canonical `Event`, raising `MappingError` when a row
   cannot become a valid event.
3. A **fixture** (a small, real-shaped slice of the source) and a **golden file**
   (the exact canonical events it must produce).
4. A **golden test** (`tests/test_<source>.py`) that pins the fixture to the
   golden output and proves malformed rows are reported, de-duplication keeps
   provenance, and any ATT&CK rule tags pass through.

The full step-by-step walkthrough, with working code, is in
[`docs/authoring.md`](docs/authoring.md). If your source is just a delimited CSV,
you may not need a bespoke adapter at all: the generic CSV adapter takes a small
column-mapping config (see [`docs/ingest-generic-csv.md`](docs/ingest-generic-csv.md)).

Every ingestion source, without exception, ships with a fixture and a
normalization golden test. A pull request adding a source without both will be
asked to add them before review.

## Changes that need a conversation first

Some changes touch the keystone or the guarantee. Open an issue and discuss
before writing code (this mirrors the "Stop and ask" list in `AGENTS.md`):

- Weakening the verifier or its guarantee in any way.
- Changing the canonical event schema (PRD Section 10) or the claim-and-citation
  contract.
- Adding any network call to a default, non-opt-in path.
- Adding a dependency.
- Changing the license posture.
- Relaxing any hard rule.

## Submitting your change

1. Branch from `main`.
2. Make focused commits. One logical change per commit, with a clear message.
3. Run `make ci` (and `make security` if you touched the defensive scope or the
   verifier). Keep it green.
4. Open a pull request and fill in the template. For a new source, use the "new
   source" pull request checklist so the fixture and golden test are explicit.
5. CI must be green for review. A maintainer will review for correctness, scope,
   and the guarantee.

## Reporting security issues

Please do not open a public issue for a vulnerability. Use GitHub's private
"Report a vulnerability" flow under the repository's Security tab. See
[`SECURITY.md`](SECURITY.md) for the policy and what is in scope.

## License

By contributing, you agree that your contributions are licensed under the
project's Apache-2.0 license. See [`LICENSE`](LICENSE). The optional raw-artifact
mode depends on Dissect (AGPL-3.0) and is kept isolated so the core stays
permissive; see PRD decision D2.
