# Security policy

> Style: no em dashes or en dashes anywhere. Use hyphens, colons, or commas.

Casebound is a local-first DFIR investigation copilot. This policy states its
defensive scope and non-goals, the guarantees it upholds, how those are enforced,
and how to report a vulnerability. It restates PRD Section 6 and the Hard rules in
AGENTS.md. The full threat model lives in `docs/threat-model.md`.

## Supported versions

Casebound is pre-1.0 (0.1.x). Security fixes target the latest released 0.1.x and
the `main` branch.

| Version | Supported |
| --- | --- |
| 0.1.x | yes |
| < 0.1 | no |

## Defensive scope and non-goals

Casebound performs read-only analysis of evidence that has already been collected.
It is built to be employer-safe and stays inside these lines:

- Read-only analysis only. Casebound never performs acquisition that modifies an
  endpoint, never collects remotely, and never takes remediation or containment
  action.
- No detonation, no sandboxing, and no execution of suspect binaries.
- Evidence never leaves the host by default. Any cloud-model path is opt-in, gated
  by an explicit flag, and preceded by a redaction pass.
- The repository ships synthetic or public sample evidence only. No real case data,
  ever, and no committed secrets.
- Casebound is not an EDR, a SIEM, an acquisition tool, or a malware sandbox. It
  assists a qualified analyst; it does not replace one.

## Guarantees

- The verification guarantee. No factual claim reaches a report unless it resolves
  to a real, deterministically extracted timeline event and its asserted facts
  (time, principal, action, object) are consistent with that event. The model is a
  drafting aid fenced by the deterministic verifier; it never decides what is true.
- Evidence sovereignty. The deterministic core runs fully offline. The narrative
  defaults to a local model. Cloud use is opt-in only and is redacted first.
- Key hygiene. API keys are excluded from provider reprs and are never logged or
  written to any output.

## How the scope is enforced

These invariants run in `make ci` (the gate) and again, as a named step, in
`make security`:

- `tests/test_defensive_scope.py` parses every module under `casebound/` and fails
  if any of them import or call a process-execution, remote-collection,
  network-egress, registry, or native-API primitive. The only sanctioned egress is
  the opt-in, redacted cloud provider SDK, imported lazily in `narrate/llm.py`.
- `tests/test_no_egress.py` proves the no-key demo path opens no outbound network
  connection.
- `tests/test_redact.py` proves the redaction pass strips sensitive fields and that
  keys never appear in outputs before any cloud call.

`make security` also runs the secret scan, the bandit static analysis, and the
dependency audit. See `docs/threat-model.md` for the full model.

## Reporting a vulnerability

Please report suspected vulnerabilities privately rather than opening a public
issue:

- Preferred: open a private report through GitHub's "Report a vulnerability" flow
  under the repository's Security tab.
- Include a clear description, the affected version or commit, reproduction steps,
  and the impact you observed.

We aim to acknowledge a report within a few business days and to keep you updated as
we investigate and prepare a fix. Please give us reasonable time to remediate before
any public disclosure.

Out of scope for reports: findings that require running Casebound outside its
defensive scope (for example, wiring it to perform remote collection or to execute
collected binaries) are not Casebound vulnerabilities, since the tool is designed
and tested not to do those things.
