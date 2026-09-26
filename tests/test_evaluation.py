"""Tests for the evaluation: the verifier benchmark and the published numbers.

The load-bearing properties:

  1. The benchmark is honest on the real verifier: over every event of the bundled
     scenario, every fabricated claim is rejected and every grounded claim is
     accepted, across every class.
  2. The benchmark has teeth: a verifier weakened in any one check (a lax time
     tolerance, an ignored principal, an ignored object, a tolerated dangling
     citation) produces false accepts in exactly the classes that probe it. A
     benchmark that stayed green against a broken fence would prove nothing.
  3. Citation accuracy re-verifies accepted claims from scratch, so a claim that
     slipped through is counted as inaccurate.
  4. ATT&CK scoring is exact set arithmetic over (host, record, technique), and
     the bundled scenario meets the PRD targets end to end.

No network, no API keys.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import casebound.evaluation as evaluation_module
from casebound.evaluation import (
    ATTACK_PRECISION_TARGET,
    ATTACK_RECALL_TARGET,
    build_benchmark,
    citation_accuracy,
    evaluate,
    run_benchmark,
    score_attack,
)
from casebound.generate import write_samples
from casebound.narrate import OfflineDemoNarrator
from casebound.normalize.schema import AttackTechnique, Event, RawRef
from casebound.pipeline import Case, EvidenceInput, analyze
from casebound.verify.checks import ClaimVerdict, FieldTolerance, verify_claim
from casebound.verify.claims import Claim

FABRICATION_CLASSES = {
    "nonexistent_id",
    "short_handle_citation",
    "record_number_citation",
    "no_citation",
    "no_assertion",
    "time_just_outside_tolerance",
    "time_hours_off",
    "principal_swap",
    "action_swap",
    "object_swap",
    "confusable_object",
    "stitched_across_events",
    "true_claim_with_dangling_citation",
    "true_claim_with_malformed_citation",
}
GROUNDED_CLASSES = {
    "exact",
    "re_cased",
    "whitespace_padded",
    "offset_notation_same_instant",
    "subsecond_within_tolerance",
    "subset_of_fields",
    "upper_case_id",
    "extra_context_citation",
}


@pytest.fixture(scope="module")
def scenario(tmp_path_factory: pytest.TempPathFactory) -> tuple[Case, dict[str, Any]]:
    out = tmp_path_factory.mktemp("scenario")
    timeline, labels = write_samples(out)
    case = analyze(
        [EvidenceInput(source="hayabusa", path=timeline)],
        name="office_intrusion",
        model=OfflineDemoNarrator(),
        model_label=OfflineDemoNarrator.LABEL,
    )
    return case, json.loads(labels.read_text(encoding="utf-8"))


# 1. Honest on the real verifier.


def test_benchmark_covers_every_class(scenario: tuple[Case, dict[str, Any]]) -> None:
    case, _ = scenario
    cases = build_benchmark(case.events)
    kinds = {(item.kind, item.expect_accept) for item in cases}
    assert {kind for kind, accept in kinds if not accept} == FABRICATION_CLASSES
    assert {kind for kind, accept in kinds if accept} == GROUNDED_CLASSES


def test_real_verifier_has_no_false_accepts_or_rejects(
    scenario: tuple[Case, dict[str, Any]],
) -> None:
    case, _ = scenario
    result = run_benchmark(case.events)
    assert result.passed
    assert result.false_accepts == ()
    assert result.false_rejects == ()
    assert result.false_accept_rate == 0.0
    assert result.false_reject_rate == 0.0
    assert result.fabrications_rejected == result.fabrications > len(case.events) * 10
    assert result.grounded_accepted == result.grounded > len(case.events) * 7
    # Every fabrication is rejected for the reason its class predicts.
    assert result.unexpected_reasons == 0
    assert all(item.correct == item.total for item in result.classes)


# 2. The benchmark has teeth.


def _false_accept_kinds(case: Case, monkeypatch: pytest.MonkeyPatch, weakened: Any) -> set[str]:
    monkeypatch.setattr(evaluation_module, "verify_claim", weakened)
    result = run_benchmark(case.events)
    assert not result.passed
    return {note.split(":", 1)[0] for note in result.false_accepts}


def test_lax_time_tolerance_is_caught(scenario: tuple[Case, dict[str, Any]]) -> None:
    case, _ = scenario
    cases = build_benchmark(case.events)
    result = run_benchmark(
        case.events, cases, tolerance=FieldTolerance(time_tolerance=timedelta(days=1))
    )
    kinds = {note.split(":", 1)[0] for note in result.false_accepts}
    assert kinds == {"time_just_outside_tolerance", "time_hours_off"}


def _ignoring(field: str) -> Any:
    def weakened(claim: Claim, index: Any, tolerance: Any = None) -> ClaimVerdict:
        asserts = replace(claim.asserts, **{field: None})
        return verify_claim(replace(claim, asserts=asserts), index, tolerance)

    return weakened


def test_ignored_principal_is_caught(
    scenario: tuple[Case, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    case, _ = scenario
    kinds = _false_accept_kinds(case, monkeypatch, _ignoring("principal"))
    assert "principal_swap" in kinds
    assert "stitched_across_events" in kinds


def test_ignored_object_is_caught(
    scenario: tuple[Case, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    case, _ = scenario
    kinds = _false_accept_kinds(case, monkeypatch, _ignoring("object"))
    assert {"object_swap", "confusable_object"} <= kinds


def test_tolerated_dangling_citation_is_caught(
    scenario: tuple[Case, dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    case, _ = scenario

    def weakened(claim: Claim, index: Any, tolerance: Any = None) -> ClaimVerdict:
        resolvable = tuple(cid for cid in claim.citations if cid in index)
        return verify_claim(replace(claim, citations=resolvable), index, tolerance)

    kinds = _false_accept_kinds(case, monkeypatch, weakened)
    assert "true_claim_with_dangling_citation" in kinds


# 3. Citation accuracy re-verifies from scratch.


def test_citation_accuracy_is_one_for_the_demo_narrative(
    scenario: tuple[Case, dict[str, Any]],
) -> None:
    case, _ = scenario
    rate, accurate, emitted = citation_accuracy(case)
    assert emitted > 0
    assert (rate, accurate) == (1.0, emitted)


def test_citation_accuracy_counts_a_claim_that_slipped_through(
    scenario: tuple[Case, dict[str, Any]],
) -> None:
    case, _ = scenario
    assert case.verification is not None
    first, *rest = case.verification.accepted
    tampered = replace(first, asserts=replace(first.asserts, principal="CORP\\Administrator"))
    broken = replace(case, verification=replace(case.verification, accepted=(tampered, *rest)))
    rate, accurate, emitted = citation_accuracy(broken)
    assert accurate == emitted - 1
    assert rate < 1.0
    assert not evaluate(broken).passed


def test_citation_accuracy_without_a_narrative_is_vacuously_one(
    scenario: tuple[Case, dict[str, Any]],
) -> None:
    case, _ = scenario
    assert citation_accuracy(replace(case, verification=None)) == (1.0, 0, 0)


# 4. ATT&CK scoring.


def _tagged(host: str, record: str, *technique_ids: str) -> Event:
    return Event(
        datetime="2026-03-14T08:42:17Z",
        timestamp_raw="2026-03-14T08:42:17Z",
        source_timezone="UTC",
        timestamp_desc="logged",
        message="m",
        action="process_create",
        source_tool="hayabusa",
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record=record),
        host=host,
        attack_techniques=[AttackTechnique(tid, "rule_tag") for tid in technique_ids],
    )


def test_score_attack_is_exact_set_arithmetic() -> None:
    labels = {
        "events": [
            {"computer": "H1", "record_id": "1", "technique_ids": ["T1059.001", "T1566.001"]},
            {"computer": "H1", "record_id": "2", "technique_ids": ["T1003.001"]},
        ]
    }
    events = [
        _tagged("H1", "1", "T1059.001"),  # one of two labels found
        _tagged("H1", "2", "T1003.001"),  # exact
        _tagged("H2", "2", "T1003.001"),  # same record id on another host: a false positive
    ]
    score = score_attack(events, labels)
    assert (score.true_positives, score.false_positives, score.false_negatives) == (2, 1, 1)
    assert score.precision == pytest.approx(2 / 3)
    assert score.recall == pytest.approx(2 / 3)
    assert score.false_positive_examples == ("H2 2 T1003.001",)


def test_score_attack_with_nothing_predicted_or_expected() -> None:
    score = score_attack([], {"events": []})
    assert (score.precision, score.recall) == (1.0, 1.0)


def test_evaluation_meets_the_targets_on_the_scenario(
    scenario: tuple[Case, dict[str, Any]],
) -> None:
    case, labels = scenario
    result = evaluate(case, labels)
    assert result.passed
    assert result.attack_end_to_end is not None and result.attack_table_only is not None
    assert result.attack_end_to_end.precision >= ATTACK_PRECISION_TARGET
    assert result.attack_end_to_end.recall >= ATTACK_RECALL_TARGET
    # The table alone is weaker: it labels behaviour, so benign look-alikes cost it.
    assert result.attack_table_only.precision < result.attack_end_to_end.precision
    assert result.attack_table_only.false_positives > 0
    metrics = json.loads(json.dumps(result.to_dict()))
    assert metrics["passed"] is True
    assert metrics["targets"]["attack_end_to_end_precision"] == ATTACK_PRECISION_TARGET
    assert metrics["narrative"]["citation_accuracy"] == 1.0


def test_evaluation_without_labels_skips_the_attack_scores(
    scenario: tuple[Case, dict[str, Any]],
) -> None:
    case, _ = scenario
    result = evaluate(case)
    assert result.attack_end_to_end is None and result.attack_table_only is None
    assert result.to_dict()["attack"]["end_to_end"] is None


def test_write_samples_labels_match_the_committed_file(tmp_path: Path) -> None:
    _, labels = write_samples(tmp_path)
    committed = Path(__file__).resolve().parents[1] / "samples" / "ground_truth.json"
    assert labels.read_text(encoding="utf-8") == committed.read_text(encoding="utf-8")
