# Security policy

Casebound performs read-only analysis of evidence that has already been collected.
This policy states its defensive scope, the guarantees it keeps, how they are
enforced, and how to report a vulnerability. It restates PRD Section 6 and the Hard
rules in [`AGENTS.md`](AGENTS.md); the full threat model is
[`docs/threat-model.md`](docs/threat-model.md).

## Supported versions

Casebound is pre-1.0. Security fixes land on `main` and in the latest release.

| Version | Supported |
| --- | --- |
| 0.2.x | yes |
| 0.1.x and earlier | no |

## Scope

- Read-only analysis only: no acquisition that modifies an endpoint, no remote
  collection, no remediation or containment.
- No detonation, no sandboxing, no execution of anything ingested.
- Evidence stays on the host by default. The deterministic core is offline, the
  demo narrates with a scripted offline drafter, and the recommended narrative
  provider is a model on the same host. A cloud provider is opt-in behind an
  explicit flag and receives only a redacted event view.
- The repository ships synthetic sample evidence only, and no secrets.
- Casebound is not an EDR, a SIEM, an acquisition tool, or a sandbox. It assists a
  qualified analyst; it does not replace one.

## Guarantees

- **Verification.** No factual claim reaches a report unless it cites a real,
  deterministically extracted event and every fact it asserts (time, principal,
  action, object) matches that event. The reader sees sentences composed from the
  event's own fields, never the model's prose.
- **Evidence sovereignty.** No default path opens a network connection.
- **Key hygiene.** API keys never appear in provider reprs, reports, logs, or error
  messages; SDK errors are scrubbed of anything key-shaped before they are shown.
- **License isolation.** The Apache-2.0 core never loads the optional AGPL-3.0
  Dissect code unless an operator installs the `raw` extra and selects a raw source.

## Enforcement

Every item below runs in `make ci`, the gate that CI runs on Python 3.11, 3.12,
and 3.13; `make security` runs the gate and then the invariant tests again as a
named step.

| Test or check | Proves |
| --- | --- |
| `tests/test_defensive_scope.py` | No module under `casebound/` imports or calls a process-execution, network, remote-execution, live-registry, or native-API primitive. The only sanctioned egress is a provider SDK, imported lazily by name in `casebound/narrate/llm.py`. |
| `tests/test_no_egress.py` | The library, `report`, `demo`, `verify`, and the web viewer complete with outbound sockets blocked; a cloud provider without consent fails before any call. |
| `tests/test_redact.py`, `tests/test_llm.py` | The cloud view is redacted, revision hints never quote stripped evidence, and keys are scrubbed from errors. |
| `tests/test_license_boundary.py` | No AGPL code is on the core import graph, checked statically and in a fresh interpreter. |
| `tests/test_verify.py`, `tests/test_evaluation.py` | The verifier rejects every fabrication class and accepts every grounded one, and the benchmark catches a deliberately weakened verifier. |
| detect-secrets, bandit, pip-audit | No committed secrets, no unsuppressed static-analysis finding, no known advisory against a pinned dependency. |

## Reporting a vulnerability

Report privately, not in a public issue: use GitHub's "Report a vulnerability" flow
under the repository's Security tab. Include the affected version or commit,
reproduction steps, and the impact you observed. You should get an acknowledgement
within a few business days. Please allow reasonable time for a fix before public
disclosure.

Especially welcome: any way to get an unverified statement into a report, to make
a default path reach the network, to make the web viewer execute or fetch something,
or to inject markup through evidence content.

Out of scope: behavior that requires modifying Casebound to act outside its
defensive scope (for example, wiring it to collect remotely or to run collected
binaries), and exposure caused by binding the web viewer beyond loopback, which the
CLI warns about.
