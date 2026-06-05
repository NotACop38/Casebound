"""Generation: the synthetic evidence generator and ground-truth scenarios.

Produces synthetic, multi-stage intrusion scenarios with known ground-truth events
and technique labels (FR33). Only synthetic or public sample evidence ever lives
in this repository (Hard rule 3): no real hostnames, no real IOCs, no working
payloads.

Layout (PRD Section 13):
  - ``synth``     : renders a scenario into Hayabusa-style CSV plus a ground-truth
                    label file, deterministically from a seed.
  - ``scenarios`` : the ground-truth scenario definitions.

The hallucination-trap fixture (FR35) lands in a later Phase 1 step.
"""

from __future__ import annotations

from casebound.generate.synth import (
    CSV_FILENAME,
    DEFAULT_SEED,
    GROUND_TRUTH_FILENAME,
    GeneratedScenario,
    generate,
    write_samples,
)

__all__ = [
    "CSV_FILENAME",
    "DEFAULT_SEED",
    "GROUND_TRUTH_FILENAME",
    "GeneratedScenario",
    "generate",
    "write_samples",
]
