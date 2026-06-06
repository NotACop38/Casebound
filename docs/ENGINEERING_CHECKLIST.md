# Casebound - Engineering Checklist

> Status: Draft v0.1 - Companion to PRD.md (source of truth). Work top to bottom; do not start a phase before the prior phase’s exit criteria are met.
> Legend: [A] = good candidate to offload to a coding agent for bulk work. [D] = decide or design with the human first.
> Guiding principle: prove the whole pipeline (ingest, normalize, tag, verify, report) on ONE source and ONE scenario in Phase 1 before adding breadth. De-risk the schema and the verifier on a single slice rather than discovering problems across many sources.
> Convention: no em dashes or en dashes anywhere, in code, comments, docs, or CLI output. Use hyphens, colons, or commas.

-----

## Phase 0 - Foundations

Goal: lock the keystone decisions and stand up an empty-but-correct skeleton.
Exit criteria: schema v0.1 committed and validating; repo skeleton builds; pytest runs (even with zero adapters); deps pinned; the CI convention is chosen.

- [x] [D] Confirm blocking decisions: D1 name, D2 license, D3 CI convention. (Recorded in PRD Section 17: D1 Casebound, D2 Apache-2.0, D3 GitHub Actions plus the same local gate. D5 redaction depth is also resolved. The only residual is D1's external name-availability check on GitHub and PyPI, a manual-only step below.)
- [x] [D] Sign off the canonical event schema v0.1 field set (PRD Section 10).
- [x] [A] Scaffold the package per PRD Section 13 (modules as empty-but-importable), pyproject.toml with pinned deps, LICENSE per D2, .gitignore, .env.example, Makefile, ruff and mypy config, pre-commit, README stub.
- [x] [A] Write schema/event.schema.json (JSON Schema) from PRD Section 10, plus docs/schema.md with two worked examples.
- [x] [A] Add a trivial passing test so the harness is green from day one.

## Phase 1 - Vertical slice (tracer bullet)

Goal: one source, end to end, including the verifier, on one synthetic scenario.
Exit criteria: from a clean clone, the demo ingests the synthetic Hayabusa output, normalizes it, tags ATT&CK, runs the verifier against a mocked model, and emits an HTML report; the hallucination-trap test passes.

- [x] [A] Implement the synthetic evidence generator (PRD FR33) for ONE scenario, emitting Hayabusa-style CSV plus a ground-truth label file.
- [x] [A] Implement the base ingest adapter interface and the Hayabusa adapter (FR1, FR2).
- [x] [A] Implement normalization to the canonical schema with UTC timezone handling and stable event ids (FR8 to FR11).
- [x] [A] Implement deterministic ATT&CK tagging via rule-tag passthrough plus a small mapping table (FR13, FR14).
- [x] [D] Define the claim and citation format and the field-consistency check rules; write docs/verification.md.
- [x] [A] Implement the claims parser, the consistency checks, and the generate-test-refine engine (FR17 to FR25), with a mocked model provider for tests.
- [x] [A] Implement the hallucination-trap fixture and test (FR35): assert a seeded fabricated claim is rejected and a grounded claim is accepted.
- [x] [A] Implement the HTML report renderer with the timeline, the verified narrative with inline citations, and the evidence appendix (FR28, FR32).
- [x] [A] Wire the `demo` command to run the full slice offline with no keys (FR34).

## Phase 2 - Continuous integration

Goal: automated quality gates while the surface is small.
Exit criteria: lint, type-check, and the full test suite run automatically per D3; the schema validates in CI; a secret scan runs.

- [x] [A] Per D3: either a GitHub Actions workflow (lint, mypy, pytest, schema validation, secret scan) with a status badge, or a local scripts/ci.py runner with static shields. Get the green signal.
- [x] [A] Add a secret-scanning step (gitleaks or detect-secrets) and a dependency audit (pip-audit) and a static check (bandit).

## Phase 3 - Breadth: ingestion sources

Goal: cover the sources responders actually run.
Exit criteria: each new adapter ships with a fixture and a normalization golden test; malformed rows are reported without aborting (FR7).

- [x] [A] Eric Zimmerman or Timeline Explorer style CSV adapter from KAPE output (FR3), with fixtures and golden tests.
- [x] [A] Generic CSV adapter with a documented column-mapping config (FR4).
- [x] [A] Chainsaw adapter (FR5).
- [x] [A] Velociraptor and Plaso timeline adapters (FR6).
- [x] [A] De-duplication across sources with provenance retained (FR12).

## Phase 4 - Enrichment and reporting depth

Goal: turn events into an investigation.
Exit criteria: episodes cluster sensibly on the scenario; all three report formats and the Navigator layer generate; metrics regenerate from the demo.

- [x] [A] Activity clustering into episodes by time, host, and principal (FR15).
- [x] [A] IOC extraction and defanging into a structured set, surfaced in reports (FR16).
- [x] [A] JSON and Markdown report renderers (FR29, FR30).
- [x] [A] ATT&CK Navigator layer generation of observed techniques (FR31), with the layer committed for the scenario.
- [x] [A] Implement the metrics computation (PRD Section 12) and have the demo print and persist the numbers.
- [x] [A] Expand the synthetic generator to the full multi-stage scenario with complete technique labels.

## Phase 5 - Cloud path and offline guarantees

Goal: make the optional cloud model safe, and prove the no-model path.
Exit criteria: the pipeline produces a full deterministic report with no model configured; any cloud call is gated and redacted; keys never appear in output.

- [x] [A] Implement the provider-agnostic model interface (Anthropic, OpenAI, local), defaulting to local (R8, FR27).
- [x] [A] Implement the no-model path: skip narrative, still emit timeline, tags, episodes, and a deterministic findings summary (FR26). Add a test asserting a full report with no provider configured.
- [x] [D] Decide D5 redaction depth.
- [x] [A] Implement the redaction pass before any cloud call and a test that keys and redacted fields never appear in outputs (FR36, FR37).

## Phase 6 - Security, invariants, and docs

Goal: prove the defensive scope in code, not just prose.
Exit criteria: invariant tests enforce the non-goals; SECURITY.md and the threat model exist.

- [x] [A] Invariant test: the codebase performs no acquisition, no remote collection, no execution of suspect binaries, and no remediation (scan for and forbid the relevant calls; document the invariant).
- [x] [A] Invariant test: in the no-key demo path there are no outbound network calls.
- [x] [A] Write docs/threat-model.md and SECURITY.md restating the defensive scope and non-goals (PRD Section 6).

## Phase 7 - README visual polish

Goal: a README that lands the value in under ten seconds.
Exit criteria: every embedded asset and code snippet exists on disk; the guarantee and the metrics are above the fold.

- [x] [A] Hero: name, one-line value prop, the HTML report screenshot, and the claim-to-evidence side-by-side.
- [x] [A] The guarantee in four bullets, the quickstart, the metrics table, the supported-sources list.
- [x] [A] Gracious prior-art note (credit AIFT and the academic work) and the defensive-scope statement.
- [x] [A] Badges per D3, the limitations section, the license and acknowledgments.

## Phase 8 - Raw mode (optional, license-gated)

Goal: ingest raw artifacts directly for users who have not pre-run the tools.
Exit criteria: at least EVTX and one more artifact parse directly into the schema; the D2 license decision is honored and isolated.

- [ ] [D] Confirm D2: accept AGPL for this path, or isolate it as a separate optional package or process.
- [ ] [A] Implement Dissect-backed adapters for EVTX and one more artifact type (for example MFT or registry), reusing the same normalization.

## Phase 9 - Optional web UI (stretch)

Goal: a browsable timeline and report.
Exit criteria: the UI reuses the report layer unchanged and preserves all offline and no-egress guarantees.

- [ ] [D] Confirm D4.
- [ ] [A] Minimal FastAPI app: load a case, browse the timeline, view the report, with size and type limits on any upload and no auto-fetch of anything.

## Phase 10 - Community readiness and release

Goal: forkable, contributable, releasable.
Exit criteria: a stranger can add an ingestion adapter and get it merged via CI; a clean-clone demo reproduces the metrics with no keys; v0.1.0 is tagged.

- [x] [A] CONTRIBUTING.md (the adapter authoring standard plus the defensive line), docs/authoring.md (“add an ingestion source in an afternoon”).
- [x] [A] Issue and PR templates, including a “new source” template that requires a fixture and a golden test.
- [x] [A] Release dry run: build sdist and wheel, install into a fresh environment, run the demo end to end, confirm the metrics, inspect the wheel for stray fixtures or secrets, draft release notes and CHANGELOG.md.
- [x] [A] Tag v0.1.0. Set the repo description, topics, and social preview per D3 tooling. (Tag applied locally; the repo description, topics, and social preview remain manual-only steps, see below.)

## Cross-cutting / always-on

- [ ] Keep PRD.md and this checklist in sync with reality; log decision changes in the PRD.
- [ ] Every ingestion source: a fixture plus a normalization golden test.
- [ ] Every verifier change: a grounded-accept test and a fabricated-reject test.
- [ ] Re-verify external specifics at author time (ATT&CK ids, Timesketch fields, Dissect and library APIs).
- [ ] No secrets committed; no real case data, ever.

## Manual-only steps (cannot be done from the CLI)

- Confirm the name on GitHub and PyPI.
- Pin the repo on the profile and add a one-line description.
- Upload a social-preview image in repo settings.
- If the chosen CI path needs authenticated tooling, run the printed description, topics, and release commands.