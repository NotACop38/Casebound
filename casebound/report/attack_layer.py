"""MITRE ATT&CK Navigator layer generation (PRD FR31).

Emits a Navigator layer file of the techniques observed in a case, so an analyst
can load the deterministic ATT&CK coverage straight into the ATT&CK Navigator. The
layer is a heatmap: each observed technique is scored by the number of events that
exhibit it, so a denser technique reads as a hotter cell.

Two guarantees hold here:

  1. The technique ids are real. Every id Casebound can emit (from the rule-tag
     passthrough or the documented mapping table) is in ``ATTACK_TECHNIQUES``, a
     small catalog of id-to-name pairs re-verified against the published ATT&CK
     Enterprise matrix at author time (the standing instruction not to trust memory
     for external specifics, PRD Section 15, AGENTS.md). Building a layer validates
     every observed id against this catalog and raises ``UnknownTechniqueError`` on
     anything unrecognized, so a typo or an invented id can never reach a layer.

  2. The layer is deterministic. Techniques are emitted in sorted id order and the
     document ends with a trailing newline, so a clean clone regenerates a
     byte-identical layer and the committed sample never drifts silently.

Navigator layer format reference: the enterprise-attack layer schema, version 4.5.
See https://github.com/mitre-attack/attack-navigator. Re-verify the layer schema
version at author time.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from casebound.normalize.schema import Event

__all__ = [
    "ATTACK_TECHNIQUES",
    "LAYER_VERSION",
    "OBSERVED_COLOR",
    "UnknownTechniqueError",
    "build_navigator_layer",
    "is_known_technique",
    "render_navigator_layer",
    "write_navigator_layer",
]

# The ATT&CK Navigator layer-format version this module emits. The Navigator reads
# older layer versions too; 4.5 is a stable, widely supported revision.
LAYER_VERSION = "4.5"

# The hot end of the heatmap gradient. Cells are colored by the Navigator from each
# technique's score (its event count) along the white-to-this-hue gradient; no
# per-technique color is set, so the score is what drives the intensity.
OBSERVED_COLOR = "#fd8d3c"

# The catalog of ATT&CK techniques Casebound knows how to emit, mapping each id to
# its current ATT&CK name. This is the validation source of truth for FR31: an id
# is real only if it appears here. It is a superset of the ids the deterministic
# tagger can produce (the showcase scenario's rule-tag ids plus the mapping-table
# ids in casebound.enrich.attack), so a layer never carries an id this catalog
# cannot name. Every id and name was re-verified against the published ATT&CK
# Enterprise matrix at author time.
ATTACK_TECHNIQUES: dict[str, str] = {
    "T1003.001": "OS Credential Dumping: LSASS Memory",
    "T1021.002": "Remote Services: SMB/Windows Admin Shares",
    "T1041": "Exfiltration Over C2 Channel",
    "T1053.005": "Scheduled Task/Job: Scheduled Task",
    "T1059.001": "Command and Scripting Interpreter: PowerShell",
    "T1071.001": "Application Layer Protocol: Web Protocols",
    "T1078.002": "Valid Accounts: Domain Accounts",
    "T1105": "Ingress Tool Transfer",
    "T1543.003": "Create or Modify System Process: Windows Service",
    "T1547.001": "Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder",
    "T1560.001": "Archive Collected Data: Archive via Utility",
    "T1566.001": "Phishing: Spearphishing Attachment",
}


class UnknownTechniqueError(ValueError):
    """Raised when a layer would carry a technique id the catalog does not know.

    A real ATT&CK id is the precondition for a usable Navigator layer (FR31), so an
    unrecognized id is a hard error rather than something to silently emit.
    """


def is_known_technique(technique_id: str) -> bool:
    """True when ``technique_id`` is a real ATT&CK id Casebound can name."""
    return technique_id in ATTACK_TECHNIQUES


def _technique_counts(events: Iterable[Event]) -> dict[str, int]:
    """Count, per technique id, how many events exhibit it (deduplicated per event)."""
    counts: dict[str, int] = {}
    for event in events:
        seen: set[str] = set()
        for tech in event.attack_techniques:
            if tech.technique_id in seen:
                continue
            seen.add(tech.technique_id)
            counts[tech.technique_id] = counts.get(tech.technique_id, 0) + 1
    return counts


def build_navigator_layer(events: Sequence[Event], *, scenario: str) -> dict[str, Any]:
    """Build the ATT&CK Navigator layer dict for the techniques observed in ``events``.

    Each observed technique becomes a scored layer entry; the score is the number of
    events that exhibit it, so the layer renders as a coverage heatmap. Every
    observed id is validated against ``ATTACK_TECHNIQUES``; an unrecognized id raises
    ``UnknownTechniqueError`` (FR31).
    """
    counts = _technique_counts(events)

    unknown = sorted(tid for tid in counts if not is_known_technique(tid))
    if unknown:
        raise UnknownTechniqueError(
            f"observed technique ids are not in the ATT&CK catalog: {unknown}"
        )

    techniques = [
        {
            "techniqueID": tid,
            "score": counts[tid],
            "comment": ATTACK_TECHNIQUES[tid],
            "enabled": True,
        }
        for tid in sorted(counts)
    ]
    max_score = max(counts.values()) if counts else 1

    return {
        "name": f"Casebound: {scenario}",
        # The ATT&CK content version is deliberately omitted so the layer loads
        # against whatever ATT&CK version the Navigator instance carries, rather than
        # pinning a number that goes stale as ATT&CK revises (AGENTS.md: do not trust
        # memory for external specifics, re-verify at author time).
        "versions": {
            "navigator": "5.1.0",
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": (
            "Techniques observed by Casebound in the "
            f"{scenario} scenario, scored by the number of events that exhibit each. "
            "Generated deterministically and offline from the verified timeline."
        ),
        "sorting": 0,
        "hideDisabled": False,
        # No per-technique color: a fixed color would override the score-derived
        # gradient in the Navigator, so every cell would read the same regardless of
        # its event count. The score plus the gradient below drive the heatmap.
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", OBSERVED_COLOR],
            "minValue": 0,
            "maxValue": max_score,
        },
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def render_navigator_layer(events: Sequence[Event], *, scenario: str) -> str:
    """Render the Navigator layer as a deterministic JSON string with a trailing newline."""
    layer = build_navigator_layer(events, scenario=scenario)
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"


def write_navigator_layer(path: Path, events: Sequence[Event], *, scenario: str) -> Path:
    """Render the Navigator layer and write it to ``path``, returning the path written.

    Creates the parent directory if needed. Offline, no network.
    """
    text = render_navigator_layer(events, scenario=scenario)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path
