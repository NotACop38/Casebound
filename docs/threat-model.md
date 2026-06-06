# Casebound threat model

> Companion to PRD.md (source of truth), Section 6 (defensive scope and non-goals)
> and the Hard rules in AGENTS.md. This document restates the defensive posture and
> records how it is enforced in code, not just in prose.
> Style: no em dashes or en dashes anywhere. Use hyphens, colons, or commas.

## Purpose

Casebound is a local-first DFIR investigation copilot. It reads triage output that
has already been collected, normalizes it into one timeline, tags ATT&CK
deterministically, and drafts a narrative in which every factual claim is verified
against a real timeline event or dropped before an analyst sees it. This threat
model states what Casebound is allowed to do, what it must never do, and how those
limits are enforced.

## What Casebound is, and is not

- It is a read-only analysis tool over evidence an analyst has already collected.
- It is not an EDR, a SIEM, an acquisition tool, a malware sandbox, a remote
  collection agent, or a courtroom-ready legal product. It assists a qualified
  analyst; it does not replace one.

## Assets

1. The evidence under analysis: triage CSV and JSON files on the analyst host. These
   may describe real incidents and must never leave the host by default.
2. The normalized timeline and the generated reports (HTML, JSON, Markdown, the
   ATT&CK Navigator layer, the metrics).
3. Operator credentials: any cloud-model API key supplied through the environment.
4. The verification guarantee itself: the property that no unverified claim reaches a
   report. This is the product's reason to exist and is treated as a protected asset.

## Trust boundaries and data flow

- Input boundary: ingest adapters open evidence files for reading only. Parsing is
  delegated to mature upstream tools whose output Casebound consumes; Casebound does
  not parse raw artifacts in the MVP and never executes anything it ingests.
- Model boundary: the language model is a drafting aid, fenced by the deterministic
  verifier. It only ever receives the compact, id-addressed event view, never raw
  evidence files, and it never has authority to assert a fact (Hard rule 4).
- Egress boundary: nothing crosses the host boundary on a default path. The
  deterministic core is fully offline and the narrative defaults to a local model.
  A cloud-model path exists only behind an explicit opt-in flag and is preceded by a
  redaction pass (PRD D5). The local model never redacts, because evidence stays on
  the host.
- Output boundary: reports are written to a local output directory chosen by the
  operator. API keys are never logged or written to any output (FR37).

## Defensive scope (enforced invariants)

These restate PRD Section 6 as properties the code must uphold:

1. Read-only analysis only. No acquisition that modifies an endpoint, no remote
   collection, no remediation, and no containment action.
2. No detonation, no sandboxing, and no execution of suspect binaries.
3. Evidence sovereignty. Evidence never leaves the host by default. Any cloud-model
   call is opt-in, gated by an explicit flag, and redacted first.
4. No real data, ever. The repository ships synthetic or public sample evidence
   only. No secrets are committed.
5. The model is fenced. It cannot state a fact the deterministic layer has not
   verified.

## Threats considered and mitigations

| Threat | Mitigation |
| --- | --- |
| The product shells out and executes a collected binary or script (detonation). | The shipped package imports no process-execution primitive (`subprocess`, `os.system`, `os.exec*`, `os.spawn*`, `pty`, the `eval` and `exec` builtins). Enforced by `tests/test_defensive_scope.py`. |
| The product collects from, or reaches out and modifies, a remote or live endpoint. | The shipped package imports no raw socket, network client, remote-execution, registry, or native-API primitive. Enforced by `tests/test_defensive_scope.py`. |
| Evidence is sent off-host without consent. | The deterministic core and the no-key demo path open no outbound connection; the cloud path is opt-in behind an explicit flag and runs the redaction pass first. Enforced by `tests/test_no_egress.py` and `tests/test_redact.py`. |
| The language model invents a fact and it reaches the report. | The verifier resolves every claim to a real event by id and checks field-level consistency; unsupported claims are revised or dropped and logged. Measured by the hallucination-rejection rate (target 1.0). |
| A cloud call leaks sensitive content or an API key. | The redaction pass strips the message, principal, and obvious indicators before any cloud call; keys are excluded from provider reprs and never logged or written. Enforced by `tests/test_redact.py`. |
| Real case data or a secret is committed to the repository. | Only synthetic or public sample evidence is allowed; the secret scan runs in `make ci` and `make security`. |

## Invariants enforced in code

The defensive scope is proven by tests that run in `make ci` (the gate) and again,
as a named step, in `make security`:

- `tests/test_defensive_scope.py` parses every module under `casebound/` and fails
  if any of them import or call a process-execution, remote-collection,
  network-egress, registry, or native-API primitive. The only sanctioned egress is
  the opt-in, redacted cloud provider SDK, imported lazily by name in
  `narrate/llm.py`. A self-check confirms the scanner catches a known-bad sample, so
  a green run is never vacuous.
- `tests/test_no_egress.py` clears every provider and key environment variable and
  blocks the socket connection primitives, then runs the demo through both entry
  points (with and without a model) and asserts it completes with no outbound call.

Scope note: the scan covers `casebound/`, the code that handles evidence. The
developer gate `scripts/ci.py` shells out to the pinned dev tools (ruff, mypy,
pytest, bandit) and never to evidence, so it is intentionally outside the
source-scan invariant.

## Out of scope (non-goals)

- Remote or live acquisition, remote collection, and any agent deployed to an
  endpoint.
- Remediation, containment, quarantine, or any change to an investigated system.
- Detonation, sandboxing, or execution of suspect binaries.
- Storing or shipping real case data.

## Residual risks and operator responsibilities

- Casebound assists a qualified analyst and does not replace analyst judgment; its
  output supports a human decision, it does not make one.
- If the operator opts into a cloud model, redacted event metadata leaves the host
  by design. The operator owns that decision, the choice of provider, and the
  handling of the supplied API key.
- The deterministic mapping tables and the synthetic scenario are reference data;
  accuracy on real evidence depends on the upstream tools and the operator's inputs.
