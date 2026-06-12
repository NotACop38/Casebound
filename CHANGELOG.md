# Changelog

All notable changes to Casebound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Style: no em dashes or en dashes anywhere. Use hyphens, colons, or commas.

## [Unreleased]

Everything below landed after the 0.1.0 notes were written and is not part of a
tagged release yet.

### Added

- `casebound report`: run the full pipeline on your own evidence file with
  `--source` selecting the adapter (hayabusa, eztools, chainsaw, velociraptor,
  plaso, or generic_csv with `--column-map`). Deterministic with no model;
  local-first narrative; cloud only behind the explicit `--allow-cloud` consent.
- Raw-artifact mode (Phase 8): EVTX and NTFS $MFT parsed directly via Dissect,
  license-gated behind the opt-in `raw` extra and isolated in
  `casebound/ingest/raw` so the core stays Apache-2.0 (decision D2).
- The optional web viewer (Phase 9): a loopback-only FastAPI timeline and report
  browser behind the opt-in `web` extra, reusing the report layer unchanged.
- Dark mode and responsive tables in the HTML report.
- An eager `--version` flag, and clean CLI errors for unreadable evidence files
  and output paths blocked by an existing file.

### Fixed

- Verification: rejection details no longer quote the cited event's own field
  values, so a cloud revision round can no longer leak what the redaction pass
  stripped (FR36, Hard rule 2).
- Verification: an accepted claim now renders from the backing event's canonical
  fields; the model's asserted spelling (a different case, a non-UTC offset, a
  confusable look-alike) stays in the audit trail and never reaches the reader
  as the verified statement.
- Normalization: a partial timestamp (time-only, month name, stray number) is
  rejected as malformed instead of being silently completed from the current
  date, which fabricated instants and made event ids differ between runs.
- Normalization: when detection rows collapse in dedup (one row per rule match),
  the kept event now merges the other detections' ATT&CK rule tags and titles
  instead of discarding them based on input order.
- Ingestion: a UTF-8 BOM (PowerShell Export-Csv, Excel, Notepad) no longer
  corrupts any adapter; a malformed JSONL line is skipped, not fatal.
- Enrichment: the domain scan is bounded per token, removing quadratic
  backtracking on hostile input (shared by the cloud redaction pass); document
  file names (docx, pdf, json, ...) are no longer promoted to domain indicators;
  sub-second events order chronologically instead of lexicographically.
- Reports: the Markdown renderer neutralizes hostile evidence content (raw HTML,
  javascript: links, code-span breakouts, structure-breaking newlines); the HTML
  report blanks null fields instead of rendering "None".
- Web viewer: uploads are gated on their headers (cross-site POSTs refused, a
  declared in-cap Content-Length required) before the multipart body is parsed,
  so the size cap actually bounds ingress.

### Changed

- Packaging: the sdist ships the web viewer package and `.env.example`, so an
  unpacked sdist is self-testable again; the CI workflow actions are pinned to
  commit SHAs.

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
