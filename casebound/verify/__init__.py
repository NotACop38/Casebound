"""Verification: the fence between the model and the report (PRD Section 11).

This is the prime directive in code. No factual claim reaches a report unless it
resolves to a real, deterministically-extracted event by id and its asserted facts
(time, principal, action, object) are consistent with that event (FR17 to FR25).
The deterministic layer is the source of truth; the model never decides what is
true. Never weaken, bypass, or shortcut this layer.

Planned layout (PRD Section 13): engine.py, claims.py, checks.py.

TODO(Phase 1): implement the claims parser, the field-level consistency checks,
  and the generate-test-refine engine. Every change here ships with both a
  grounded-accept test and a fabricated-reject test (Hard rule, test-first).
"""

from __future__ import annotations
