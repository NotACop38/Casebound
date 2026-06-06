"""Tests for the ATT&CK Navigator layer renderer (PRD FR31).

The load-bearing properties:

  1. Real technique ids only: every observed id is validated against the ATT&CK
     catalog; an unrecognized id is a hard error, never a silently emitted layer.
  2. The catalog covers the scenario: every ground-truth technique label and every
     id the deterministic tagger can emit is a real, named ATT&CK technique.
  3. The layer is a deterministic heatmap: techniques are sorted and scored by event
     count, and the committed sample regenerates byte-identically from a clean clone.

All tests run offline with no API keys.
"""

from __future__ import annotations

import json
import re
from dataclasses import replace
from pathlib import Path

from casebound.enrich.attack import MAPPING_TABLE, tag_events
from casebound.generate import generate
from casebound.generate.synth import CSV_FILENAME
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, normalize_records
from casebound.normalize.schema import AttackTechnique
from casebound.report.attack_layer import (
    ATTACK_TECHNIQUES,
    UnknownTechniqueError,
    build_navigator_layer,
    is_known_technique,
    render_navigator_layer,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE_LAYER = REPO_ROOT / "samples" / "attack_navigator_layer.json"
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def _events(tmp_path: Path) -> list[Event]:
    scenario = generate()
    csv_path = tmp_path / CSV_FILENAME
    csv_path.write_text(scenario.csv_text, encoding="utf-8")
    return tag_events(normalize_records(HayabusaAdapter().read(csv_path)).events)


def test_catalog_ids_are_well_formed_technique_ids() -> None:
    for tid in ATTACK_TECHNIQUES:
        assert _TECHNIQUE_RE.match(tid), f"catalog id {tid!r} is not a technique id"
        assert ATTACK_TECHNIQUES[tid], f"catalog id {tid!r} has no name"


def test_catalog_covers_ground_truth_and_mapping_table() -> None:
    # Every technique the scenario labels and every id the mapping table can assign
    # must be a real, named ATT&CK technique in the catalog (FR31 validation).
    ground_truth = generate().ground_truth
    for tid in ground_truth["techniques"]:
        assert is_known_technique(tid), f"ground-truth technique {tid} missing from catalog"
    for rule in MAPPING_TABLE:
        assert is_known_technique(rule.technique_id), f"mapping id {rule.technique_id} missing"


def test_layer_scores_observed_techniques(tmp_path: Path) -> None:
    events = _events(tmp_path)
    layer = build_navigator_layer(events, scenario="office_intrusion")

    assert layer["domain"] == "enterprise-attack"
    ids = [tech["techniqueID"] for tech in layer["techniques"]]
    # Sorted, deduplicated, and exactly the observed set.
    assert ids == sorted(ids)
    observed = {tech.technique_id for e in events for tech in e.attack_techniques}
    assert set(ids) == observed
    for tech in layer["techniques"]:
        assert tech["score"] >= 1
        assert tech["enabled"] is True
        assert is_known_technique(tech["techniqueID"])


def test_unknown_technique_id_is_rejected(tmp_path: Path) -> None:
    events = _events(tmp_path)
    # Tamper one event with a well-formed but non-catalog id; the layer must refuse.
    bogus = replace(events[0], attack_techniques=[AttackTechnique("T9999", "rule_tag")])
    try:
        build_navigator_layer([bogus], scenario="office_intrusion")
    except UnknownTechniqueError as exc:
        assert "T9999" in str(exc)
    else:  # pragma: no cover - the call above must raise
        raise AssertionError("expected UnknownTechniqueError for an unknown id")


def test_committed_sample_matches_the_generator(tmp_path: Path) -> None:
    # The committed layer must equal a fresh default-seed generation, so a clean
    # clone reproduces it and it never drifts silently.
    events = _events(tmp_path)
    rendered = render_navigator_layer(events, scenario="office_intrusion")
    assert SAMPLE_LAYER.read_text(encoding="utf-8") == rendered
    # And it is valid JSON with the expected shape.
    layer = json.loads(rendered)
    assert layer["name"] == "Casebound: office_intrusion"
    assert layer["versions"]["layer"]
