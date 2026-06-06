"""Tests for the evaluation metrics (PRD Section 12, FR35).

The headline numbers must be reproducible and must hit their targets on the
showcase scenario:

  1. Hallucination-rejection rate 1.0: the verifier rejects every seeded fabrication.
  2. Citation accuracy 1.0: every accepted claim resolves to a field-consistent event.
  3. ATT&CK precision at least 0.9 and recall at least 0.7 against the ground truth.
  4. Coverage: the distinct techniques observed.

The metrics are a pure function of the deterministic pipeline output, so these run
offline with no API keys.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from typing import Any

from casebound.enrich.attack import tag_events
from casebound.generate import generate
from casebound.generate.synth import CSV_FILENAME
from casebound.ingest import HayabusaAdapter
from casebound.metrics import (
    ATTACK_PRECISION_TARGET,
    ATTACK_RECALL_TARGET,
    attack_metrics,
    build_seeded_fabrications,
    compute_metrics,
    hallucination_rejection_rate,
)
from casebound.normalize import Event, normalize_records
from casebound.normalize.schema import AttackTechnique, RawRef
from casebound.verify import verify_narrative
from casebound.verify.checks import verify_claim


def _scenario(tmp_path: Path) -> tuple[list[Event], dict[str, Any]]:
    generated = generate()
    csv_path = tmp_path / CSV_FILENAME
    csv_path.write_text(generated.csv_text, encoding="utf-8")
    events = tag_events(normalize_records(HayabusaAdapter().read(csv_path)).events)
    return events, generated.ground_truth


def _event(record: str, action: str, technique_ids: tuple[str, ...]) -> Event:
    return Event(
        datetime="2026-03-14T08:42:17Z",
        timestamp_raw="2026-03-14 04:42:17.000 -04:00",
        source_timezone="America/New_York",
        timestamp_desc="logged",
        message="m",
        action=action,
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="f.csv", record=record),
        attack_techniques=[AttackTechnique(tid, "rule_tag") for tid in technique_ids],
    )


# 1. The hallucination-rejection rate.


def test_seeded_fabrications_cover_every_rejection_reason(tmp_path: Path) -> None:
    events, _ = _scenario(tmp_path)
    fabrications = build_seeded_fabrications(events)
    index = {e.event_id: e for e in events}

    # Every seeded fabrication is rejected, and the set exercises every reason.
    reasons = set()
    for claim in fabrications:
        verdict = verify_claim(claim, index)
        assert verdict.ok is False
        assert verdict.reason is not None
        reasons.add(verdict.reason.value)
    assert reasons == {
        "missing_id",
        "malformed_citation",
        "principal_mismatch",
        "time_mismatch",
        "action_mismatch",
        "object_mismatch",
    }


def test_fabrications_stay_false_when_the_event_matches_the_default_replacement() -> None:
    # The principal_mismatch fabrication must differ from the event's real principal
    # even when that principal happens to equal the default replacement, so it can
    # never turn into a true claim the verifier accepts.
    powershell = Event(
        datetime="2026-03-14T08:42:17Z",
        timestamp_raw="2026-03-14 04:42:17.000 -04:00",
        source_timezone="America/New_York",
        timestamp_desc="logged",
        message="encoded PowerShell",
        action="process_create",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="f.csv", record="R1"),
        host="WIN-ACCT-07",
        # The event is actually run by the principal the default fabrication uses.
        principal="CORP\\Administrator",
        object="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    )
    rate, rejected, total = hallucination_rejection_rate(
        [powershell], build_seeded_fabrications([powershell])
    )
    assert rate == 1.0
    assert rejected == total


def test_hallucination_rejection_rate_is_one(tmp_path: Path) -> None:
    events, _ = _scenario(tmp_path)
    rate, rejected, total = hallucination_rejection_rate(events, build_seeded_fabrications(events))
    assert total >= 6
    assert rejected == total
    assert rate == 1.0


# 2 to 4. The full metric set on the showcase scenario.


def test_compute_metrics_hits_every_target(tmp_path: Path) -> None:
    events, ground_truth = _scenario(tmp_path)
    # Draft and verify the narrative with the offline demo narrator so the citation
    # metric scores real accepted claims.
    from casebound.narrate import OfflineDemoNarrator

    verification = verify_narrative(events, OfflineDemoNarrator(), max_rounds=0)
    metrics = compute_metrics(events, verification, ground_truth)

    assert metrics.hallucination_rejection_rate == 1.0
    assert metrics.citation_accuracy == 1.0
    assert metrics.emitted_claims > 0
    assert metrics.attack.precision >= ATTACK_PRECISION_TARGET
    assert metrics.attack.recall >= ATTACK_RECALL_TARGET
    assert metrics.coverage == len(ground_truth["techniques"])
    assert metrics.meets_targets() is True
    # The metric set serializes for persistence.
    assert json.loads(json.dumps(metrics.to_dict()))["meets_targets"] is True


def test_no_model_path_metrics_are_well_defined(tmp_path: Path) -> None:
    events, ground_truth = _scenario(tmp_path)
    metrics = compute_metrics(events, None, ground_truth)
    # No claim was emitted, so citation accuracy is vacuously 1.0, but the
    # hallucination and ATT&CK metrics still compute against the events.
    assert metrics.emitted_claims == 0
    assert metrics.citation_accuracy == 1.0
    assert metrics.hallucination_rejection_rate == 1.0
    assert metrics.attack.recall >= ATTACK_RECALL_TARGET


# ATT&CK precision and recall react to tagger errors.


def test_attack_metrics_perfect_on_matching_tags() -> None:
    events = [_event("R1", "process_create", ("T1059.001",))]
    ground_truth = {"events": [{"record_id": "R1", "technique_ids": ["T1059.001"]}]}
    metrics = attack_metrics(events, ground_truth)
    assert metrics.precision == 1.0
    assert metrics.recall == 1.0
    assert metrics.true_positives == 1


def test_attack_metrics_penalize_false_positive_and_negative() -> None:
    ground_truth = {
        "events": [
            {"record_id": "R1", "technique_ids": ["T1059.001"]},
            {"record_id": "R2", "technique_ids": ["T1003.001"]},
        ]
    }
    events = [
        # R1 carries an extra (wrong) tag: a false positive.
        _event("R1", "process_create", ("T1059.001", "T1071.001")),
        # R2 carries no tag: a false negative.
        replace(_event("R2", "process_access", ()), attack_techniques=[]),
    ]
    metrics = attack_metrics(events, ground_truth)
    assert metrics.true_positives == 1
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 1
    assert metrics.precision == 0.5
    assert metrics.recall == 0.5
