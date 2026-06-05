# CLAUDE.md

Read @AGENTS.md first and treat it as the source of truth for working in this repository. Everything that governs how Casebound is built (the prime directive, the hard rules, the conventions, the commands, and the definition of done) lives there, and it applies to Claude Code exactly as written.

Quick orientation for this session:

- What to build and in what order: `docs/PRD.md` and `docs/ENGINEERING_CHECKLIST.md`.
- How to build it: @AGENTS.md.
- Work one checklist step at a time. Meet its exit criteria, run `make ci`, tick the box, make one focused commit.
- Never let an unverified claim reach a report. The model is fenced by the deterministic verifier; it never decides what is true.
- No em dashes or en dashes anywhere. Use hyphens, colons, or commas.

Codex reads `AGENTS.md` natively. This file points Claude Code to the same contract so both agents behave identically.