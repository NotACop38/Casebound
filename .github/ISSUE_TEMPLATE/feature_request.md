---
name: Feature request
about: Propose a change or an addition (not a new ingestion source)
title: "feat: "
labels: enhancement
assignees: ''
---

> Proposing a new ingestion source? Use the "New ingestion source" template
> instead.

## The problem

What investigative or workflow problem does this solve? Who hits it?

## The proposal

What you would like Casebound to do.

## Scope check

Casebound is read-only analysis of already-collected evidence and stays inside a
defensive scope (see SECURITY.md). Confirm your proposal fits:

- [ ] It is read-only. It does not acquire, collect remotely, execute suspect
      binaries, or remediate.
- [ ] It adds no network call to a default, non-opt-in path.
- [ ] It does not weaken the verification guarantee or let an unverified claim
      reach a report.

## Anything that needs discussion first

Some changes need a conversation before code (schema changes, the claim-and-
citation contract, a new dependency, the license posture). If your proposal
touches any of these, note it here. See the "Stop and ask" list in `AGENTS.md`.

## Alternatives considered

Other approaches you weighed, and why this one.
