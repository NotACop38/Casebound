# Threat model

Companion to PRD Section 6 (defensive scope and non-goals) and the Hard rules in
AGENTS.md. It states what Casebound may do, what it must never do, and the test
that enforces each limit.

## What Casebound is

A read-only analysis tool over evidence an analyst has already collected: tool
output (Hayabusa, Chainsaw, EZTools, Velociraptor, Plaso, generic CSV) and,
optionally, raw `.evtx` and `$MFT` artifacts. It is not an EDR, a SIEM, an
acquisition or collection agent, a sandbox, or a legal product. It assists a
qualified analyst; it does not replace one.

## Assets

1. The evidence under analysis, which may describe a real incident and must not
   leave the host by default.
2. The derived case: the timeline, the reports, the Navigator layer, and
   `metrics.json`.
3. Operator credentials: a provider API key supplied through the environment.
4. The verification guarantee: no claim reaches a report unless the verifier
   resolved it to a real event and confirmed every fact it asserts. This is the
   product's reason to exist and is protected like any other asset.

## Trust boundaries

- **Input.** Adapters open evidence read-only and parse it as data: CSV, JSON, or,
  in raw mode, EVTX and MFT structures through Dissect. Nothing ingested is ever
  executed, and no path or URL found in evidence is ever opened or fetched.
- **Model.** The model receives only the compact, id-addressed event view (never
  `details`, command lines, or files), cut to a deterministic budget. It returns
  claims; the verifier decides which survive, and the report phrases each
  survivor from the backing event's fields, never from the model's prose.
- **Egress.** Nothing leaves the host on a default path. The core is offline, the
  demo narrates with a scripted offline drafter, and the recommended provider is a
  model on the same host. A cloud provider needs `--allow-cloud` (or
  `CASEBOUND_ALLOW_CLOUD=1`) and receives only the redacted view (decision D5).
- **Viewer.** The optional web viewer binds to loopback by default and warns before
  binding elsewhere. Its pages fetch nothing at view time.
- **Output.** Reports are written to a directory the operator chooses. Keys never
  appear in any output or error message (FR37).

## Threats and mitigations

| Threat | Mitigation | Enforced by |
| --- | --- | --- |
| A model states a fact the evidence does not support, and a reader trusts it. | Every claim must cite real events and assert its facts; one cited event must match every asserted fact; the reader sees a sentence composed from the event's fields, never the model's text. | `tests/test_verify.py` (including property tests and the hallucination trap), `tests/test_evaluation.py` (the benchmark and its teeth), `tests/test_report.py` |
| The product executes a collected binary or script. | The package imports no process-execution primitive (`subprocess`, `os.system`, the `os.exec*` and `os.spawn*` families, `pty`, `eval`, `exec`). | `tests/test_defensive_scope.py` |
| The product reaches out to, collects from, or modifies an endpoint. | The package imports no socket, HTTP or RPC client, remote-execution library, live-registry API, or native-API bridge. `urllib.parse`, a pure string parser, is the only allowed member of `urllib`. | `tests/test_defensive_scope.py` |
| Evidence leaves the host without consent. | No default path opens a connection: the library, `report`, `demo`, `verify`, and the web viewer all run with outbound sockets blocked in the tests. A cloud provider without consent fails before any call; a consented one builds no client until it drafts. | `tests/test_no_egress.py` |
| A cloud call carries sensitive content. | The redaction pass strips the message and principal and blanks indicators and usernames in the object; a revision hint quotes only the model's own asserted value, never the event's. | `tests/test_redact.py`, `tests/test_llm.py` |
| An API key leaks. | Keys are excluded from provider reprs; SDK error messages are scrubbed of the configured key and anything key-shaped before they are shown. | `tests/test_llm.py` |
| Hostile evidence content (markup, links, headings, table breaks) injects into a report. | The HTML report autoescapes every value and is self-contained (no scripts, no external resources); the Markdown report escapes structural characters, collapses newlines, and defangs URLs; indicators are defanged in both. | `tests/test_report.py`, `tests/test_report_formats.py`, `tests/test_web.py` |
| A web page in the analyst's browser drives the loopback viewer (CSRF). | Uploads are refused when fetch metadata says cross-site or same-site, or the Origin header names another host. | `tests/test_web.py` |
| An upload exhausts memory or disk. | A Content-Length is required and capped before the body is parsed, the file is re-checked against the byte cap while streaming, and the case store is bounded with oldest-first eviction. | `tests/test_web.py` |
| AGPL code enters the Apache-2.0 core. | Dissect is an optional extra, confined to `casebound/ingest/raw`, and loaded only from a function in the source registry when an operator selects a raw source. | `tests/test_license_boundary.py` (static scan and a fresh-interpreter import check) |
| Real case data or a secret is committed. | Only synthetic or public sample evidence ships. The gate runs detect-secrets against a reviewed baseline. | `make ci` |
| A dependency or workflow is compromised. | Runtime and dev dependencies are pinned exactly and audited with pip-audit in the gate; GitHub Actions are pinned to commit SHAs; the workflow has read-only permissions, does not persist the checkout token, and uses no secrets. | `make ci`, `.github/workflows/ci.yml` |

## Scope of the source scans

The defensive-scope and license scans cover `casebound/`, the code that handles
evidence, including the web viewer. The developer gate `scripts/ci.py` shells out
to the pinned dev tools (ruff, mypy, pytest, bandit, pip-audit) and never touches
evidence, so it is deliberately outside the scan. Each scan carries a self-test
proving it catches a known-bad sample, so a green run is never vacuous.

## Non-goals

- Live or remote acquisition, and any agent deployed to an endpoint.
- Remediation, containment, quarantine, or any change to an investigated system.
- Detonation, sandboxing, or execution of suspect binaries.
- Storing or shipping real case data.

## Residual risks

- Casebound's output supports an analyst's decision; it does not make one. The
  verifier guarantees that each sentence matches its cited event, not that the
  model chose the right events or that the evidence is complete.
- The deterministic layers are only as good as their inputs: a source that
  mislabels a field, or an ATT&CK mapping a detection rule got wrong, carries
  through. The ATT&CK scores in `metrics.json` are measured on a synthetic
  scenario, not on real intrusions.
- An operator who opts into a cloud provider sends redacted event metadata off the
  host by design and owns that decision, the provider, and the key.
- An operator who binds the viewer beyond loopback exposes uploaded evidence to the
  network; the CLI warns, and the viewer has no authentication.
