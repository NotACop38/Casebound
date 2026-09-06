# AGENTS.md - Casebound

This file is the operating contract for coding agents in this repository. `docs/PRD.md` and `docs/ENGINEERING_CHECKLIST.md` define the product and build order. Start with the user's task and `git status --short --branch`; preserve unrelated work. Read supporting documents by the sections needed for the task, and reuse context already read unless it has changed.

## Prime directive

Casebound exists for one reason: the verification guarantee. No factual claim reaches a report unless it resolves to a real, deterministically-extracted timeline event and the facts it asserts (time, principal, action, object) are consistent with that event. The deterministic layer is the source of truth. The language model is a drafting aid that is fenced by it and never has the authority to state a fact.

Never weaken, bypass, shortcut, or optimize away the verifier. If a change would let an unverified claim into a report, do not make it.

## Hard rules (non-negotiable)

1. Defensive scope only. Read-only analysis of evidence that has already been collected. No acquisition that modifies an endpoint, no remote collection, no execution of suspect binaries, no remediation or containment. (Mirrors PRD Section 6.)
1. Evidence sovereignty. The deterministic core runs fully offline. The narrative defaults to a local model. Any cloud-model path is opt-in behind an explicit flag and must pass the redaction step first. Nothing sends evidence to a network endpoint by default.
1. No real data, ever. Only synthetic or public sample evidence in the repository. Never commit secrets. The secret scan stays green.
1. The model is fenced. The model only ever sees the compact, id-addressed event view, never raw evidence files, and it never decides what is true.
1. Style. No em dashes or en dashes anywhere: code, comments, docs, CLI output, commit messages. Use hyphens, colons, or commas. Violations get reverted.

## How to work

- Source of truth. Read `docs/PRD.md` and `docs/ENGINEERING_CHECKLIST.md` before any architectural decision. If a change would contradict them, stop and flag it rather than letting code drift.
- For checklist implementation, work one step per session: take the next unchecked step, meet its exit criteria, then tick the box and make one focused commit. Do not jump ahead or bundle unrelated steps. A specific maintenance, review, or documentation request follows its own scope and does not require advancing the checklist.
- Vertical slice first. The whole pipeline (ingest, normalize, enrich, verify, report) must work end to end on one source and one scenario before any breadth. De-risk the schema and the verifier on that slice.
- Test-first for the verifier. Any change under `verify/` ships in the same commit with both a grounded-accept test and a fabricated-reject test. The hallucination-trap test must always pass.
- Keep the gate green. Use targeted checks during work and run `make ci` before committing the completed change. Reuse a passing result while its checked inputs remain unchanged; rerun affected checks after further changes. Report failures or checks that could not run accurately.
- Make routine, reversible engineering choices within the task and explain material assumptions or tradeoffs. Ask only when a missing decision or authorization changes the result and cannot be inferred; preserve the explicit approval boundaries below.
- Re-verify external specifics at author time: ATT&CK technique ids, Timesketch field names, Dissect and other library APIs. These move; do not trust memory.

## Conventions

- Language: Python 3.11+. Typing enforced with mypy. Lint and format with ruff.
- Layout: follow PRD Section 13. Module boundaries are firm: `ingest`, `normalize`, `enrich`, `verify`, `narrate`, `report`, `generate`, `cli`.
- The canonical event schema (PRD Section 10) is the keystone; everything hangs off it. `schema/event.schema.json` is the validation source of truth.
- Commits: conventional style (feat, fix, chore, docs, test, refactor), imperative mood, no em dashes. Keep a curated history, no “wip” or “asdf”.
- Provider-agnostic by design. The product’s model provider is abstracted behind one interface (Anthropic, OpenAI, local), defaulting to local. Do not hardcode a provider.
- Agent-agnostic by design. This repository is built by Claude Code and Codex interchangeably. Make no assumptions about which agent is running and add no agent-specific code paths or files beyond the standard `AGENTS.md` and `CLAUDE.md`.

## Commands (own and maintain these)

The agent owns the build surface. Keep these working as the project grows. Names can be adjusted if the team prefers, but the contract stays.

- `make install` : install the package and pinned dev dependencies.
- `make lint` : ruff plus mypy, zero errors.
- `make test` : pytest, all green, no network, no API keys.
- `make demo` : run the full pipeline on the bundled synthetic scenario, offline, producing `out/report.html` and the metrics.
- `make ci` : lint, test, schema validation, secret scan, dependency audit. This is the gate. Per PRD decision D3 this may be a local runner or a GitHub Actions workflow; keep the same gate either way.
- `make security` : secret scan, bandit, pip-audit, and the defensive-scope invariant tests.

## Definition of Done

For the requested task: its acceptance criteria are met, relevant verification passes, and the change is focused. For checklist implementation, also satisfy the step's exit criteria, test new behavior, and tick the matching box. Do not invent product work or a release to close out maintenance.

For an explicitly requested initial release: from a clean clone, `make demo` runs offline with no API keys and produces a self-contained HTML report whose every narrative claim links to a real event; the hallucination-rejection rate is 1.0 on the seeded set; the deterministic timeline, the ATT&CK heatmap, and the metrics regenerate; `make ci` is green; the defensive-scope invariants hold; the README sells the value in one screen; v0.1.0 is tagged.

## Stop and ask the human before

- Weakening the verifier or its guarantee in any way.
- Changing the canonical event schema (Section 10) or the claim-and-citation contract.
- Adding any network call to a default (non-opt-in) path.
- Adding a dependency.
- Changing the license posture.
- Relaxing any Hard rule.

An explicit user instruction controls the current task. Do not ask again for authorization already provided.
