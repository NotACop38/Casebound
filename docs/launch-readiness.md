# Launch readiness report: Casebound v0.1.0

Date: 2026-06-06. Prepared as the Phase 10 release gate (see
`docs/ENGINEERING_CHECKLIST.md`).

Style: no em dashes or en dashes anywhere. Use hyphens, colons, or commas.

## Verdict

Ready to tag v0.1.0. The full validation passes from a clean clone, the offline
demo reproduces the metrics with no keys, the verification guarantee holds at a
1.0 hallucination-rejection rate on the seeded set, and the built wheel installs
into a fresh environment and runs the demo end to end. One packaging gap was found
during the dry run and resolved. The only remaining items are manual repository
cosmetics and the name-availability confirmation, which cannot be done from the
CLI.

## Validation performed

All commands were run with the pinned toolchain from `pyproject.toml`.

| Check | Result |
| --- | --- |
| `make ci` (lint, format, mypy, pytest, schema, secrets, bandit, deps) | PASS. ruff and format clean, mypy clean on 70 files, 280 tests passed, schema and 2 examples validated, detect-secrets clean, bandit clean, pip-audit clean. |
| `make security` (gate plus defensive-scope invariants) | PASS. 9 invariant tests passed. |
| Clean-clone demo (fresh `git clone`, fresh venv, `pip install -e .`, `make demo`) | PASS, fully offline with all API-key env vars unset. All artifacts regenerated. |
| Claim-to-event linkage in the demo report | PASS. 11/11 accepted claims resolve to real, field-consistent events; 0 orphans; all 58 HTML citation links resolve to event anchors. |
| Metrics | hallucination-rejection rate 1.0 (6/6 seeded fabrications rejected), citation accuracy 1.0 (11/11), ATT&CK precision 1.0, recall 1.0, coverage 12 techniques, targets met. |
| Release dry run: `python -m build` | PASS. sdist and wheel built. |
| Wheel install in a fresh venv, `casebound demo` from an empty directory | PASS. Entry point reports 0.1.0; demo runs end to end; rejection rate 1.0; targets met. |
| Wheel contents inspection | CLEAN. Ships the `casebound` package plus the report template and license metadata only. No tests, fixtures, samples, `.env`, CSV, or secrets. |
| sdist contents inspection | CLEAN of sensitive content. After the fix below, it is a coherent, self-testable source snapshot (280 tests pass from an unpacked sdist). |

## Definition of Done (whole project): evidence

From AGENTS.md, the whole-project bar, with evidence:

- From a clean clone, `make demo` runs offline with no API keys: confirmed in an
  isolated fresh-venv clone.
- A self-contained HTML report whose every narrative claim links to a real event:
  confirmed, 58/58 citation links resolve, 0 orphan claims.
- Hallucination-rejection rate is 1.0 on the seeded set: confirmed (6/6).
- The deterministic timeline, the ATT&CK heatmap, and the metrics regenerate:
  confirmed (`report.html`, `attack_navigator_layer.json`, `metrics.json`).
- `make ci` is green: confirmed.
- The defensive-scope invariants hold: confirmed (9 invariant tests).
- The README sells the value in one screen: in place from Phase 7.
- v0.1.0 is tagged: applied locally as the release tag on the release commit.

## Gaps found during validation and how each was resolved

1. Incoherent source distribution. The default setuptools sdist shipped the
   `tests/*.py` files but not their fixtures, the schema, or the synthetic samples,
   so the shipped tests could not run (three tests raised `FileNotFoundError` from
   an unpacked sdist). Resolved by adding `MANIFEST.in` that grafts `schema`,
   `samples`, `tests`, and `scripts` and prunes caches and build output. The sdist
   is now self-testable: all 280 tests pass from an unpacked sdist. The wheel was
   re-inspected and is unchanged: package only, no tests or fixtures.

No other gaps were found. The verifier, the offline guarantees, the defensive-scope
invariants, the metrics, and the report linkage were already green from the prior
phases.

## Remaining items (manual-only, cannot be done from the CLI)

These are tracked under "Manual-only steps" in the engineering checklist. They do
not block the local tag and are not code gaps:

- Confirm the name "Casebound" is available on GitHub and PyPI before registering
  (decision D1). Decisions D2 (Apache-2.0) and D3 (CI convention) are resolved and
  recorded in PRD Section 17.
- Push the local `v0.1.0` tag and create the GitHub Release once the release commit
  is on the default branch. Suggested release notes are the v0.1.0 section of
  `CHANGELOG.md`.
- Set the repository description, topics, and social-preview image (repository
  settings, authenticated). Suggested values:
  - Description (under 160 characters): "Local-first DFIR investigation copilot
    whose AI narrative cannot invent facts: every claim links to a real, verified
    timeline event or is dropped."
  - Topics: `dfir`, `incident-response`, `digital-forensics`, `forensic-timeline`,
    `mitre-attack`, `grounded-generation`, `hallucination`, `llm`, `python`,
    `security`.

## Intentionally out of scope for v0.1.0

- Phase 8 (raw-artifact mode via Dissect) is deferred. Dissect is AGPL-3.0 and is
  kept isolated to preserve the permissive core license (decision D2). It is not
  part of the whole-project Definition of Done.
- Phase 9 (optional web UI) is a stretch goal and is deferred. It is not part of
  the Definition of Done.

Neither deferral weakens the verifier, the offline guarantee, or the defensive
scope.
