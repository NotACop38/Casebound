"""MITRE ATT&CK Navigator layer generation (PRD FR31).

Emits a Navigator layer file of the techniques observed in a case, so an analyst
can load the deterministic ATT&CK coverage straight into the ATT&CK Navigator. The
layer is a heatmap: each observed technique is scored by the number of events that
exhibit it, so a denser technique reads as a hotter cell.

Two guarantees hold here:

  1. Every technique in the layer is a current ATT&CK technique. Ids are checked
     against the bundled catalog (``casebound.enrich.catalog``); the tagger has
     already translated revoked ids to their successors, and anything the catalog
     does not list as active (an unknown or deprecated id) is left out of the layer
     and named in its description instead of failing the run. A real case must
     always produce a layer.

  2. The layer is deterministic. Techniques are emitted in sorted id order and the
     document ends with a trailing newline, so the same case always regenerates a
     byte-identical layer.

Layer format reference: the ATT&CK Navigator layer format 4.5, loaded by Navigator
5.x, re-verified against github.com/mitre-attack/attack-navigator at author time.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

from casebound.enrich.catalog import load_catalog
from casebound.normalize.schema import Event

__all__ = [
    "LAYER_VERSION",
    "NAVIGATOR_VERSION",
    "OBSERVED_COLOR",
    "build_navigator_layer",
    "render_navigator_layer",
    "technique_counts",
    "write_navigator_layer",
]

# The layer-format version this module emits and the Navigator release it was
# checked against. Navigator 5.x reads layer format 4.5.
LAYER_VERSION = "4.5"
NAVIGATOR_VERSION = "5.3.2"

# The hot end of the heatmap gradient. The Navigator colors each cell from its
# score along the white-to-this-hue gradient; no per-technique color is set, so
# the score is what drives the intensity.
OBSERVED_COLOR = "#fd8d3c"


def technique_counts(events: Iterable[Event]) -> dict[str, int]:
    """Count, per technique id, how many events exhibit it (once per event)."""
    counts: dict[str, int] = {}
    for event in events:
        for technique_id in {tech.technique_id for tech in event.attack_techniques}:
            counts[technique_id] = counts.get(technique_id, 0) + 1
    return counts


def build_navigator_layer(events: Sequence[Event], *, name: str) -> dict[str, Any]:
    """Build the ATT&CK Navigator layer dict for the techniques observed in ``events``.

    Each current ATT&CK technique observed becomes a scored entry whose score is the
    number of events exhibiting it. Ids the bundled catalog does not list as active
    are excluded and named in the description, so an unexpected id never fails a
    run and never reaches the Navigator as an unloadable cell.
    """
    catalog = load_catalog()
    techniques: list[dict[str, Any]] = []
    excluded: list[str] = []
    for technique_id, count in sorted(technique_counts(events).items()):
        technique = catalog.get(technique_id)
        if technique is None or not technique.is_active:
            excluded.append(technique_id)
            continue
        techniques.append(
            {
                "techniqueID": technique_id,
                "score": count,
                "comment": technique.display_name,
                "enabled": True,
            }
        )

    description = (
        f"Techniques observed by Casebound in {name}, scored by the number of events "
        "that exhibit each. Generated deterministically and offline from the "
        f"normalized timeline against ATT&CK {catalog.version}."
    )
    if excluded:
        description += (
            " Left out because they are not current ATT&CK techniques: " + ", ".join(excluded) + "."
        )

    return {
        "name": f"Casebound: {name}",
        "versions": {
            "attack": catalog.major_version,
            "navigator": NAVIGATOR_VERSION,
            "layer": LAYER_VERSION,
        },
        "domain": "enterprise-attack",
        "description": description,
        "sorting": 3,
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", OBSERVED_COLOR],
            "minValue": 0,
            "maxValue": max((tech["score"] for tech in techniques), default=1),
        },
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }


def render_navigator_layer(events: Sequence[Event], *, name: str) -> str:
    """Render the Navigator layer as deterministic JSON with a trailing newline."""
    layer = build_navigator_layer(events, name=name)
    return json.dumps(layer, indent=2, ensure_ascii=False) + "\n"


def write_navigator_layer(path: Path, events: Sequence[Event], *, name: str) -> Path:
    """Render the Navigator layer and write it to ``path``, returning the path written."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_navigator_layer(events, name=name), encoding="utf-8")
    return path
