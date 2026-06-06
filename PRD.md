# Casebound - Product Requirements Document

> Status: Draft v0.1 - Type: Source of truth - Last updated: 2026-06-05
> This document and ENGINEERING_CHECKLIST.md are the canonical reference for Casebound. Update them when a decision changes; do not let code drift from them silently.
> Name: “Casebound”. A casebound book is a finished, sewn hardcover, which connotes an authoritative case file, and the name states the wedge: the narrative is bound to the case evidence and cannot exceed it. Confirm GitHub and PyPI availability before you register it. Fallbacks if taken: Cairn, Probative.

-----

## 1. Summary

Casebound is an open-source, local-first DFIR investigation copilot. It ingests host triage output, normalizes every event into one canonical timeline, deterministically maps activity to MITRE ATT&CK, and then produces an analyst-ready investigation narrative in which every factual claim is verified against a real timeline event or rejected before the analyst sees it.

The defining idea: an AI forensic narrative that provably does not invent facts. The language model proposes the story; a deterministic evidence engine refuses to let any claim through unless it resolves to a specific, extracted event by id and the claim’s asserted facts (time, principal, action, object) are consistent with that event. Unsupported claims are revised or dropped, and the rejection is logged for transparency. The headline metric is a hallucination-rejection rate, alongside citation accuracy and ATT&CK tagging precision and recall.

Casebound runs fully offline with no language model configured: you still get the normalized, ATT&CK-tagged timeline plus a deterministic findings summary. The narrative is an optional layer, defaulting to a local model so evidence never leaves the host.

## 2. Problem

Incident responders drown in artifacts. The mature open-source ecosystem (Plaso, Timesketch, Hayabusa, Chainsaw, the Eric Zimmerman tools, Velociraptor, Dissect) is excellent at producing timelines and per-artifact output, but turning that into a defensible written account of what happened is still slow manual work. The emerging answer, having a language model write the account, is dangerous in this setting: forensic-report hallucination is a documented, named risk that can lead to false allegations. The gap is not “AI that writes a report” (that exists). The gap is AI output you can trust in a high-stakes context because it is structurally prevented from asserting anything the evidence does not support.

## 3. Who it is for

- Solo and small-team incident responders and forensic analysts who need fast, defensible triage of already-collected evidence.
- SOC and IR teams that want a repeatable, reviewable first-pass investigation that plugs into existing workflows (for example, export to Timesketch).
- Security researchers studying grounded or verifiable language-model use in high-stakes domains; Casebound is a working reference implementation and an evaluation harness.

## 4. The wedge (what makes this different)

1. Verification-first narrative. Every claim cites one or more event ids; the verifier confirms existence and field-level consistency; ungrounded claims never reach the report. This is the core contribution and the README hero.
1. Measured, not asserted. Casebound ships a “hallucination trap” evaluation: seed the model context to tempt a fabricated event and assert the verifier rejects it. Report the rejection rate as a first-class number.
1. Local-first and evidence-sovereign. Offline deterministic core; local model default; cloud model strictly opt-in behind an explicit consent flag and a redaction pass.
1. Stands on mature parsers. Casebound normalizes and reasons; it does not reinvent artifact parsing in the MVP. It consumes the output of tools responders already run.

Prior art and how we differ. AIFT (FlipForensics) does AI-driven local DFIR triage and report generation over Dissect; commercial forensic-AI tools market themselves as hallucination-free. Casebound’s difference is the provable grounding mechanism and its public measurement, plus the offline-without-a-model deterministic core. Credit prior art in the README and compete on the guarantee.

## 5. MVP scope

The MVP is the smallest end-to-end slice that demonstrates the wedge on one ingestion source and one scenario.

In scope for MVP:

- Ingest tool-output mode: parse CSV and JSON timelines from at least Hayabusa and the Eric Zimmerman tools (via KAPE/Timeline Explorer style CSV), plus a generic CSV adapter.
- Normalize into the canonical event schema (Section 10).
- Deterministic ATT&CK tagging from rule tags and a documented mapping table.
- The verification engine and the generate-test-refine loop against a local or mocked model.
- The synthetic evidence generator producing one ground-truth intrusion scenario.
- Outputs: a self-contained HTML report (the hero deliverable), plus JSON and Markdown, an ATT&CK heatmap, and an evidence appendix.
- A one-command demo that runs offline with the bundled synthetic scenario and no API keys.

Explicitly out of scope for MVP (candidates for later phases):

- Raw-artifact ingestion via Dissect (Phase: Raw mode; see D2 for the AGPL consideration).
- The optional web UI (see D4).
- Timesketch export (fast follow).
- Memory-image analysis, mobile, and cloud-audit-log sources.

## 6. Defensive scope and non-goals (employer-safe)

- Read-only analysis of evidence that has already been collected. Casebound never performs acquisition that modifies an endpoint, never collects remotely, and never takes remediation or containment action.
- No detonation, no sandboxing, no execution of suspect binaries.
- Evidence never leaves the host by default. Any cloud-model path is opt-in, gated by an explicit flag, and preceded by a redaction pass (see D5).
- Repository ships synthetic or public sample evidence only. No real case data, ever.
- Non-goals: not an EDR, not a SIEM, not an acquisition tool, not a malware sandbox, not a courtroom-ready legal product. Casebound assists a qualified analyst; it does not replace one.

## 7. Tech stack and rationale

- Python 3.11+. The DFIR parsing ecosystem is Python-native and the language-model SDKs are first-class; this also keeps contributor accessibility high. (Sextant used Rust for byte-level parsing performance; here the heavy parsing is delegated to existing tools and libraries, so Python is the right call.)
- Language-model interface: provider-agnostic behind a thin abstraction. Anthropic and OpenAI as first-class interchangeable providers; a local provider (Ollama or an OpenAI-compatible local endpoint) is the documented default. Mirrors Sextant’s posture.
- Timeline store: SQLite for portability and zero-server operation in the MVP. Document an export path to OpenSearch and Timesketch for teams.
- CLI: Typer or Click plus rich, consistent with Phishbowl.
- Reporting: Jinja2 with a single self-contained HTML template (no external asset fetches at view time), consistent with Phishbowl.
- Raw mode (later): Dissect for artifact and image parsing. Note D2: Dissect is AGPL-3.0; keep it isolated to the optional Raw-mode path to preserve license flexibility for the core.
- Testing: pytest with synthetic fixtures, golden tests for normalization, and the signature verification tests (accept a grounded claim, reject a fabricated one).

## 8. Architecture

A single Python package with clear module boundaries, each independently testable:

- ingest: one adapter per source (base interface plus eztools, hayabusa, chainsaw, velociraptor, plaso, generic_csv). Adapters emit raw source rows with provenance.
- normalize: the canonical schema, per-source field mappers, and UTC timezone normalization with source-timezone tracking.
- enrich: deterministic ATT&CK mapping (rule-tag passthrough plus a documented mapping table), activity clustering into episodes, and IOC extraction and defanging.
- verify: the claims parser, the field-level consistency checks, and the generate-test-refine engine that gates the narrative.
- narrate: the provider interface, prompt templates, and the loop that calls the model and submits rejected claims for revision.
- report: HTML, JSON, and Markdown renderers; ATT&CK Navigator layer generation; the evidence appendix.
- generate: the synthetic evidence generator and the ground-truth scenario definitions.
- cli: the command surface (ingest, normalize, analyze, report, demo, generate).
- web (stretch, see D4): a minimal FastAPI app and timeline viewer reusing the report layer unchanged.

## 9. Functional requirements

Ingestion

- FR1 Provide a base adapter interface that yields normalized-ready records with provenance (source tool, source artifact, raw reference).
- FR2 Parse Hayabusa CSV output into records.
- FR3 Parse Eric Zimmerman or Timeline Explorer style CSV (KAPE triage output) into records.
- FR4 Provide a generic CSV adapter with a documented column-mapping config.
- FR5 Parse Chainsaw output (MVP or fast follow).
- FR6 Parse Velociraptor and Plaso timelines (fast follow).
- FR7 Detect and report unparseable or malformed rows without aborting the run.

Normalization

- FR8 Map every ingested record to the canonical event schema (Section 10).
- FR9 Normalize all timestamps to UTC, retaining the raw timestamp, the source timezone, and a timestamp description (created, modified, logged, accessed).
- FR10 Assign a stable, content-derived event id.
- FR11 Preserve a raw reference (source file plus record or line identifier) for audit on every event.
- FR12 De-duplicate identical events across sources while retaining all provenance.

Enrichment

- FR13 Map events to ATT&CK techniques via rule tags where present.
- FR14 Apply a documented mapping table for sources without native ATT&CK tags; record the mapping source on each tag.
- FR15 Cluster events into activity episodes (time and host and principal proximity).
- FR16 Extract and defang IOCs (IPs, domains, hashes, paths) into a structured set.

Verification and narrative

- FR17 Present the model with a compact, id-addressed view of events (not raw dumps).
- FR18 Require the model to attach one or more event-id citations to every factual claim.
- FR19 Parse claims and their citations from model output deterministically.
- FR20 For each citation, confirm the event id exists.
- FR21 For each claim, check that asserted facts (time, principal, action, object) are consistent with the cited event’s fields.
- FR22 Reject claims that cite missing ids or assert facts inconsistent with the cited event.
- FR23 Submit rejected claims back to the model for revision, up to a configurable maximum number of rounds.
- FR24 Drop any claim still unsupported after the final round; never emit it.
- FR25 Record every rejected and dropped claim in an audit log included with the output.
- FR26 Operate with no model configured: skip narrative generation and still produce the full deterministic timeline, tags, episodes, and findings summary.
- FR27 Default the narrative provider to local; require an explicit flag to use any cloud provider.

Reporting

- FR28 Render a self-contained HTML report (timeline, verified narrative with inline citations, ATT&CK heatmap, IOC table, evidence appendix, rejected-claims audit).
- FR29 Emit a machine-readable JSON report of the same content.
- FR30 Emit a Markdown report suitable for pasting into a ticket.
- FR31 Generate an ATT&CK Navigator layer of observed techniques.
- FR32 Make every narrative citation in the HTML link to its event in the evidence appendix.

Synthetic data and demo

- FR33 Generate a synthetic, multi-stage intrusion scenario with known ground-truth events and technique labels.
- FR34 Provide a one-command demo that runs the full pipeline on the synthetic scenario offline with no keys.
- FR35 Provide a “hallucination trap” fixture and an assertion that the verifier rejects the seeded fabricated claim.

Cloud path safety

- FR36 Apply a redaction pass to event content before any cloud-model call (see D5).
- FR37 Never log or write model API keys to any output.

## 10. Canonical event schema v0.1 (the keystone)

Everything downstream hangs off this. Field names are deliberately Timesketch-friendly where they overlap (datetime, message, timestamp_desc).

- event_id: stable content hash of the normalized core fields.
- datetime: ISO 8601 timestamp normalized to UTC.
- timestamp_raw: the original timestamp string as found.
- source_timezone: the timezone used to derive datetime (or “assumed_utc” with a flag).
- timestamp_desc: created, modified, accessed, logged, or other.
- message: a short human-readable summary of the event.
- host: hostname or system identifier.
- principal: account, user, or SID associated with the event.
- action: a normalized verb (process_create, logon, file_write, registry_set, service_install, network_connect, and so on).
- object: the primary target (process path, file path, registry key, remote endpoint).
- source_tool: hayabusa, eztools, chainsaw, velociraptor, plaso, generic_csv, dissect.
- source_artifact: the originating artifact (Security.evtx, $MFT, NTUSER.dat UserAssist, and so on).
- details: a structured object holding source-specific fields.
- attack_techniques: a list of objects, each with technique_id and mapping_source.
- ioc_refs: references into the extracted IOC set.
- confidence: normalization and mapping confidence (0 to 1).
- raw_ref: source file plus record or line identifier for audit.
- tags: free-form labels (episode id, analyst tags).

A JSON Schema for this lives at schema/event.schema.json and is the validation source of truth. Document it in docs/schema.md with two worked examples.

## 11. The verification model (spec)

1. Build the model context: a list of events reduced to event_id plus the addressable fields (datetime, host, principal, action, object, key details). Optionally include episode groupings.
1. Prompt the model to produce a narrative as a sequence of claims, each claim carrying one or more [event_id] citations. Define the claim and citation format precisely in docs/verification.md.
1. Parse the output into (claim_text, [event_ids]) pairs deterministically. Malformed citations are treated as unsupported.
1. For each claim: confirm every cited event exists; then run field-level checks that the claim’s asserted facts are consistent with the cited event (for example, a claim asserting a logon by user X at time T must cite an event whose action, principal, and datetime match within tolerance).
1. Accepted claims pass through. Rejected claims are collected with the reason (missing id, time mismatch, principal mismatch, action mismatch, object mismatch).
1. Submit rejected claims to the model for revision, up to max_rounds (default 2). Re-verify.
1. After the final round, drop any still-unsupported claim and record it in the audit log.
1. Emit the verified narrative with inline citations, plus the rejected-claims audit.

Design rule: the model never sees raw evidence files and never has authority to assert a fact. The deterministic layer is the source of truth; the model is a drafting aid fenced by it.

## 12. Evaluation methodology and metrics

Ground-truth corpus: the synthetic generator (FR33) emits a known intrusion (for example: phishing initial access via an Office child process; persistence via a Run key and a scheduled task; credential access via LSASS access; lateral movement via remote service or WMI; collection and exfiltration via archive creation and an outbound connection), with labeled events and technique ids.

Metrics, reported in the README and regenerated by the demo:

- Hallucination-rejection rate: of N seeded fabricated claims, the fraction the verifier rejects. Target: 1.0 on the seeded set.
- Citation accuracy: fraction of emitted narrative claims whose citations resolve to real, field-consistent events. Target: 1.0 by construction (anything less is a verifier bug).
- ATT&CK tagging precision and recall against the scenario labels. Initial targets: precision at least 0.9, recall at least 0.7 for the deterministic tagger on the showcase scenario.
- Coverage: number of distinct techniques observed and represented in the Navigator layer.

## 13. Repository layout

```
casebound/
  ingest/            base.py, hayabusa.py, eztools.py, chainsaw.py, velociraptor.py, plaso.py, generic_csv.py
  normalize/         schema.py, timezone.py, mappers/
  enrich/            attack.py, cluster.py, ioc.py
  verify/            engine.py, claims.py, checks.py
  narrate/           llm.py, loop.py, prompts/
  report/            html.py, json_report.py, markdown.py, attack_layer.py, templates/
  generate/          synth.py, scenarios/
  cli.py
schema/              event.schema.json
samples/             synthetic triage fixtures, ground-truth scenario, hallucination-trap fixture
docs/                PRD.md, ENGINEERING_CHECKLIST.md, schema.md, verification.md, threat-model.md, images/
tests/               test_normalize.py, test_attack.py, test_cluster.py, test_verify.py, test_report.py, golden/
web/                 (stretch) app.py, templates/
AGENTS.md  CLAUDE.md  README.md  LICENSE  .gitignore  .env.example  pyproject.toml  Makefile
```

## 14. README outline (visibility-optimized) and credibility checklist

README order:

1. Name plus one-line value prop, above the fold: a DFIR investigation copilot whose AI narrative cannot invent facts.
1. The hero visual: the generated HTML report, and a side-by-side of a narrative claim with its linked evidence event.
1. What it is: 2 to 3 keyword-dense sentences (DFIR, incident response, forensic timeline, MITRE ATT&CK, grounded or verified language-model output, local-first).
1. The guarantee, in four bullets: every claim cited; verifier rejects ungrounded claims; measured hallucination-rejection rate; runs offline with no model.
1. Quickstart: clone, install, one-command offline demo.
1. How verification works (link docs/verification.md), with the rejected-claims audit shown.
1. Metrics table (Section 12 numbers), regenerated by the demo.
1. Ingestion sources supported and planned.
1. Gracious prior-art note (credit AIFT and the academic work) and the defensive-scope statement.
1. Limitations and scope (synthetic data only; assists not replaces an analyst; raw mode optional).
1. License (see D2) and acknowledgments (SigmaHQ, Hayabusa, Chainsaw, Eric Zimmerman, Velociraptor, Plaso, Dissect, MITRE ATT&CK).

Credibility checklist:

- LICENSE present (D2). Repo description under 160 characters, keyword-dense.
- Topics set (15+): dfir, incident-response, digital-forensics, forensic-timeline, mitre-attack, threat-hunting, soc, blue-team, llm, ai-security, grounded-generation, hallucination, python, hayabusa, velociraptor.
- Demo asset (HTML screenshot or a short recording) committed under docs/images.
- Synthetic samples committed. Metrics reproduce from a clean clone with no keys.
- Curated commit history; a v0.1.0 release with notes; a social-preview image.
- No secrets committed (secret-scan in CI).
- Pinned on the profile with a one-line description.

## 15. Conventions

- No em dashes or en dashes anywhere in prose, code, comments, documentation, or CLI output. Use hyphens, colons, or commas.
- MVP-first within the capstone: prove the full pipeline on one ingestion source and one scenario before adding breadth.
- Every new ingestion source ships with a fixture and a normalization golden test.
- Every change to the verifier ships with both a positive (grounded claim accepted) and a negative (fabricated claim rejected) test.
- Re-verify external specifics at author time (ATT&CK technique ids, Timesketch field names, Dissect and library APIs); these move.
- Built with Claude Code and Codex interchangeably, one checklist step per agent session.

## 16. Resolved decisions

- R1 Domain and product: host DFIR investigation copilot with a verification-first AI narrative.
- R2 Core guarantee: every narrative claim resolves to a real, field-consistent event by id, or it is rejected and logged.
- R3 Local-first: offline deterministic core; local model default; cloud model opt-in only.
- R4 Language: Python 3.11+.
- R5 MVP ingestion: tool-output mode (Hayabusa, EZ Tools or KAPE CSV, generic CSV). Raw mode via Dissect is a later phase.
- R6 Keystone: the canonical event schema (Section 10).
- R7 Hero deliverable: the self-contained HTML report.
- R8 Provider-agnostic model interface (Anthropic, OpenAI, local), local default.

## 17. Open decisions

- D1 Name. Chosen: Casebound (see header). Action: confirm GitHub and PyPI availability before registering; fall back to Cairn or Probative only if taken.
- D2 License. Lean: Apache-2.0 for the core (consistent with Sextant). Constraint: Dissect is AGPL-3.0, so keep the optional Raw-mode path isolated, or be prepared to license that path AGPL. Decide before Raw mode begins.
- D3 CI convention. Chosen: Option A, GitHub Actions for a green status badge (favored for a public-visibility repo; the demo runs offline regardless). Option B, the local-runner convention (scripts/ci.py, no hosted CI, static shields only), was the alternative. The same gate (scripts/ci.py) runs both locally and in the workflow, so the contract holds either way. See .github/workflows/ci.yml and the README badge.
- D4 Optional web UI. Lean: include a minimal FastAPI plus timeline viewer as a stretch after the core is solid, for the capstone wow factor; reuse the report layer unchanged.
- D5 Cloud redaction depth. Chosen: the conservative default. Before any cloud call, strip the free-text message and details, obvious IOCs (IP addresses, domains, hashes, paths), and usernames (the principal, including any username embedded in a path); keep only the id-addressable, non-sensitive fields (event_id, datetime, action). The host is kept by default. Every field is a configurable toggle (see .env.example and RedactionConfig). Implemented in casebound/narrate/redact.py and applied by every cloud provider before sending (FR36); the local provider never redacts, since evidence stays on the host (Hard rule 2). Details are never in the event view to begin with (the Hard rule 4 fence), so there is nothing to strip there.

## 18. Glossary

- Triage output: the CSV or JSON produced by tools run during collection (Hayabusa, KAPE, Chainsaw, Velociraptor, Plaso).
- Episode: a cluster of related events grouped by time, host, and principal.
- Claim: a single factual statement in the narrative, carrying one or more event-id citations.
- Grounding or verification: confirming a claim against the deterministic event store before it is allowed into the report.
- Hallucination-rejection rate: the fraction of deliberately fabricated claims the verifier refuses.

## 19. References

- Academic: benchmarks and methodology for evaluating language-model use in DFIR and forensic timeline analysis; documented forensic-report hallucination risk.
- Tools and libraries: Hayabusa, Chainsaw, Eric Zimmerman tools, KAPE, Velociraptor, Plaso, Timesketch, Dissect (Fox-IT, NCC Group), MITRE ATT&CK and Navigator.
- Prior art: AIFT (FlipForensics) for AI-driven local DFIR triage and report generation.
- Re-verify all external specifics at author time.