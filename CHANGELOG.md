# Changelog

All notable changes to Casebound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Style: no em dashes or en dashes anywhere. Use hyphens, colons, or commas.

## [Unreleased]

Nothing yet.

## [0.1.0] - 2026-06-06

The first public release. Casebound is a local-first DFIR investigation copilot
whose AI narrative cannot invent facts: every claim in a report resolves to a real,
deterministically extracted timeline event, or it is dropped and logged before you
ever see it.

### The guarantee

- Verification-fenced narrative. The deterministic layer is the source of truth.
  The language model drafts; a deterministic verifier accepts a claim only when it
  cites a real event whose facts (time, principal, action, object) match. Anything
  unsupported is revised across bounded rounds or dropped to an audit log.
- Measured, not asserted. A seeded hallucination trap proves the verifier rejects
  a fabricated claim. The demo reports a hallucination-rejection rate of 1.0 on the
  seeded set, with citation accuracy 1.0 by construction.
- Offline by default. The deterministic core and the bundled demo run with no
  network and no API keys. The narrative defaults to a local model. Any cloud-model
  path is opt-in behind an explicit flag and is redacted first.

### Added

- Canonical event schema v0.1 (`schema/event.schema.json`) with stable,
  content-derived event ids, UTC normalization, and per-event provenance, plus
  worked examples and `docs/schema.md`.
- Ingestion adapters for Hayabusa, the Eric Zimmerman / KAPE tools (MFTECmd CSV),
  Chainsaw, Velociraptor, Plaso, and a generic column-mapped CSV. Each ships with a
  fixture and a normalization golden test. Malformed rows are reported, not fatal
  (FR7). Cross-source de-duplication retains all provenance (FR12).
- Deterministic ATT&CK tagging via rule-tag passthrough plus a documented mapping
  table, with an auditable mapping source on every tag.
- The verification engine: a claims-and-citations parser, field-consistency
  checks, and a generate-test-refine loop, with a provider-agnostic model interface
  (Anthropic, OpenAI, local) that defaults to local, and a mocked provider for
  tests.
- Enrichment: activity clustering into episodes by time, host, and principal, and
  structured IOC extraction with defanging, surfaced in reports.
- Reports: a self-contained HTML report (timeline, verified narrative with inline
  citations, rejected-claims audit, evidence appendix), plus JSON and Markdown
  renderers and an ATT&CK Navigator layer of observed techniques.
- The no-model path: a full deterministic report (timeline, tags, episodes, IOCs,
  findings summary) with no provider configured.
- The redaction pass that runs before any cloud call, with tests that keys and
  redacted fields never appear in outputs.
- Metrics computation (PRD Section 12) that the demo prints and persists to
  `out/metrics.json`.
- A synthetic, multi-stage intrusion generator with ground-truth labels, and a
  one-command offline demo (`casebound demo`).
- Defensive-scope invariant tests: no acquisition, no remote collection, no
  execution of suspect binaries, no remediation, and no outbound network on the
  no-key demo path.
- The local CI gate (`scripts/ci.py`) and a GitHub Actions workflow running lint,
  types, tests, schema validation, a secret scan, bandit, and a dependency audit,
  layered with the defensive-scope invariants in `make security`.
- Documentation: README, PRD, engineering checklist, `docs/verification.md`,
  `docs/threat-model.md`, `SECURITY.md`, `CONTRIBUTING.md`, and
  `docs/authoring.md` ("add an ingestion source in an afternoon"), plus issue and
  pull request templates including a new-source template that requires a fixture
  and a golden test.

### Security and scope

- Read-only analysis of already-collected evidence only. No acquisition, no remote
  collection, no execution of suspect binaries, no remediation. Enforced by
  invariant tests, not just prose.
- No real case data and no committed secrets. The secret scan is part of the gate.
- Apache-2.0 for the core. The optional raw-artifact mode (Dissect, AGPL-3.0)
  remains isolated and is not part of this release.

[Unreleased]: https://github.com/NotACop38/casebound/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/NotACop38/casebound/releases/tag/v0.1.0
