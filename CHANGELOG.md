# Changelog

All notable changes to Casebound are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project follows
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Style: no em dashes or en dashes anywhere. Use hyphens, colons, or commas.

## [Unreleased]

## [0.2.0] - 2026-09-26

A rebuild around one pipeline and a measurable guarantee. Every entry point (the
CLI, the web viewer, the evaluation) now runs the same `casebound.pipeline.analyze`,
the narrative a reader sees is composed from the evidence rather than from a
model's prose, and the verifier is measured by a benchmark designed to catch it
failing.

### Changed (breaking)

- Narrative sentences are composed from the backing event's canonical fields by a
  deterministic phrasing layer ("CORP\jdoe started ...\powershell.exe."). A
  model's text appears only in the rejected-claims audit.
- `casebound report` takes evidence as `SOURCE:PATH` arguments, several per run
  and of mixed sources, or plain paths with `--source`. `--case-name` is now
  `--name` (the old spelling still works).
- Canonical schema 0.2. The schema moved into the package
  (`casebound/data/event.schema.json`) and the worked examples to
  `docs/examples/`. Event ids are unchanged.
- ATT&CK tagging: the mapping table no longer tags rows from detection sources
  (Hayabusa, Chainsaw). Their untagged rows come from informational rules, and
  tagging them put routine administration on the report's matrix.
- The web viewer moved into the package: `casebound serve` or
  `python -m casebound.web` (it was `python -m web` from a source tree).
- The Python API: `render_report`, `run_demo`, `run_report`, and
  `casebound.metrics` are replaced by `casebound.pipeline.analyze`,
  `casebound.report.render_html` and `write_reports`, and `casebound.evaluation`.
  `metrics.json` has a new structure.
- Providers: the Anthropic default is `claude-opus-5`. There is no default local or
  OpenAI model, since a stale default fails confusingly; name the model you serve.

### Added

- A bundled MITRE ATT&CK Enterprise 19.2 catalog (858 techniques), rebuilt
  reproducibly from MITRE's STIX bundle by `scripts/build_attack_catalog.py`. Every
  technique is validated and named against it, a revoked id a rule still uses is
  translated to its successor and kept as `source_id` (schema 0.2), and the HTML
  report gains an ATT&CK matrix in the Enterprise tactic order.
- The verifier benchmark (`casebound.evaluation`): 14 fabrication classes that must
  all be rejected and 8 grounded classes that must all be accepted, derived from
  every event of a case and run through the real parser and checks, with tests
  proving it catches a deliberately weakened verifier. `casebound demo` fails if the
  verifier misjudges a single claim. ATT&CK tagging is scored end to end and table
  only.
- `casebound verify`: check claims drafted anywhere against a case's `events.jsonl`.
  `casebound sources` lists every input format; `python -m casebound` works.
- Hayabusa: JSON and JSONL timelines, every CSV profile, channel and Details
  abbreviations resolved per channel and EventID, `ExtraFieldInfo` and
  `AllFieldInfo` merged, `n/a` read as absent.
- Windows EventID tables keyed by channel (Security, System, Sysmon, Task
  Scheduler), shared by every Windows source. Plaso's logged EVTX rows now resolve
  through them (a System 7045 is a `service_install`).
- Detection severity, normalized from each source's level; high and critical
  detections join the key findings even without a technique.
- Model view budget: at most 300 events (`--view-budget`), ATT&CK-tagged and severe
  first; claims are still verified against the whole case.
- Providers: structured output constrained to the published claim schema
  (`casebound/data/claims.schema.json`); Anthropic streaming with server-side
  refusal fallbacks; refusals, truncation, and SDK failures surface as clean errors
  with keys scrubbed; `CASEBOUND_MAX_OUTPUT_TOKENS` and `CASEBOUND_LOCAL_API_KEY`;
  `local`, `openai`, and `anthropic` install extras.
- The offline demo narrator now exercises the revision loop: one mistake is
  corrected in round 1, two are dropped.
- Web viewer uploads for Hayabusa (CSV, JSON, JSONL), Chainsaw, EZTools,
  Velociraptor, and Plaso.
- Reports: large cases are capped in HTML (2000 events) and Markdown (500) to the
  notable events, while `report.json` and `events.jsonl` keep everything; unparsed
  rows are listed; the masthead names every input.
- A more realistic scenario: 37 detections (12 attack events, including a service
  execution and a log clearing tagged with a revoked id, and 25 benign ones,
  several of them look-alikes of the attack), rendered in Hayabusa's verbose
  profile.
- The gate: Hypothesis property tests, a 93% coverage floor, a no-dash style check,
  warnings as errors, and a CI matrix on Python 3.11, 3.12, and 3.13. The package
  ships `py.typed`.

### Fixed

- The Navigator layer crashed on a technique id missing from its hand-written name
  table; ids are now checked against the catalog and anything that is not a current
  technique is left out and named.
- Episodes: activity by `SYSTEM`, service accounts, and machine accounts no longer
  splits one actor's run.
- Indicators: quoted paths are extracted whole, loopback addresses are not
  indicators, and paths differing only in case collapse.
- Rejection details show Windows accounts as written, not repr-escaped.
- Phrasing never re-cases or trims evidence.
- Everything listed below, which landed after 0.1.0:
  - Verification: rejection details no longer quote the cited event's own field
    values, so a cloud revision round cannot leak what redaction stripped (FR36).
  - Normalization: partial timestamps are rejected instead of completed from the
    current date; detections that collapse in dedup merge their rule tags.
  - Ingestion: a UTF-8 BOM no longer corrupts any adapter; a malformed JSONL line
    is skipped, not fatal.
  - Enrichment: the domain scan is bounded per token; document names are not
    domains; sub-second events order by instant.
  - Reports: the Markdown renderer neutralizes hostile evidence; the HTML report
    blanks null fields.
  - Web viewer: uploads are gated on their headers before the body is parsed.

### Also since 0.1.0

- Raw-artifact mode: `.evtx` and `$MFT` parsed with Dissect behind the opt-in
  `raw` extra, isolated so the core stays Apache-2.0 (decision D2).
- The optional web viewer behind the `web` extra.
- Dark mode and responsive tables in the HTML report; `--version`; clean CLI errors
  for unreadable evidence and blocked output paths.
- CI workflow actions pinned to commit SHAs.

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

[Unreleased]: https://github.com/NotACop38/Casebound/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/NotACop38/Casebound/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/NotACop38/Casebound/releases/tag/v0.1.0
