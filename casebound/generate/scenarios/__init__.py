"""Ground-truth synthetic intrusion scenarios.

Each scenario is a fully synthetic, multi-stage intrusion described as ordered
data: a list of ``ScenarioEvent`` records plus the hosts, principals, and IOCs
they reference. The generator in ``casebound.generate.synth`` renders a scenario
into Hayabusa-style CSV plus a ground-truth label file (PRD FR33).

Only synthetic or public-safe sample data ever lives here (Hard rule 3): no real
hostnames, no real IOCs, no working payloads. External IPs use the
documentation-only range from RFC 5737 (203.0.113.0/24), internal IPs use the
private RFC 1918 range, and domains use the reserved ``.example`` TLD (RFC 2606).
"""

from __future__ import annotations

from casebound.generate.scenarios.office_intrusion import (
    OFFICE_INTRUSION,
    REQUIRED_STAGES,
    Scenario,
    ScenarioEvent,
)

__all__ = [
    "OFFICE_INTRUSION",
    "REQUIRED_STAGES",
    "Scenario",
    "ScenarioEvent",
]
