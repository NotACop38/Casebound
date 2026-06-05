"""Generation: the synthetic evidence generator and ground-truth scenarios.

Produces synthetic, multi-stage intrusion scenarios with known ground-truth events
and technique labels, plus the hallucination-trap fixture (FR33, FR35). Only
synthetic or public sample evidence ever lives in this repository (Hard rule 3).

Planned layout (PRD Section 13): synth.py, scenarios/.

TODO(Phase 1): emit one scenario as Hayabusa-style CSV plus a ground-truth label
  file, and the hallucination-trap fixture.
"""

from __future__ import annotations
