"""Tests for the shared analysis pipeline (``casebound.pipeline``).

``analyze`` is the one definition of what Casebound does to evidence; the CLI, the
web viewer, and the evaluation all call it. These tests pin its contract: the case
it returns, the errors it raises, and that ``case_from_events`` yields the same case
for events that were normalized elsewhere.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from casebound.generate import write_samples
from casebound.narrate import OfflineDemoNarrator
from casebound.pipeline import (
    Case,
    EmptyCaseError,
    EvidenceInput,
    InputSummary,
    analyze,
    case_from_events,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures"


@pytest.fixture(scope="module")
def timeline(tmp_path_factory: pytest.TempPathFactory) -> Path:
    path, _ = write_samples(tmp_path_factory.mktemp("scenario"))
    return path


@pytest.fixture(scope="module")
def case(timeline: Path) -> Case:
    return analyze([EvidenceInput(source="hayabusa", path=timeline)], name="office_intrusion")


def test_case_holds_the_enriched_timeline(case: Case) -> None:
    assert case.no_model and case.verification is None and case.narrative_label is None
    assert case.inputs == (InputSummary("hayabusa", "synthetic_hayabusa.csv", 37),)
    assert case.inputs[0].to_dict() == {
        "source": "hayabusa",
        "file": "synthetic_hayabusa.csv",
        "records": 37,
    }
    assert case.records_read == 37 and case.duplicate_count == 0 and case.problems == ()
    instants = [(event.datetime, event.event_id) for event in case.events]
    assert len(instants) == 37
    assert case.episodes and case.iocs
    assert all(event.tags for event in case.events)  # every event carries its episode
    assert "T1685.005" in case.technique_ids()
    first = case.events[0]
    assert case.event(first.event_id) is first
    assert case.event("0" * 64) is None
    assert case.provenance[first.event_id] == (first.raw_ref,)


def test_case_from_events_reproduces_the_case(case: Case) -> None:
    rebuilt = case_from_events(
        case.events, name=case.name, provenance=case.provenance, inputs=case.inputs
    )
    assert rebuilt.events == case.events
    assert rebuilt.episodes == case.episodes
    assert rebuilt.iocs.to_dict() == case.iocs.to_dict()


def test_a_model_adds_a_verified_narrative(timeline: Path) -> None:
    case = analyze(
        [EvidenceInput(source="hayabusa", path=timeline)],
        name="narrated",
        model=OfflineDemoNarrator(),
    )
    assert not case.no_model
    assert case.narrative_label == "configured model"
    assert case.verification is not None and case.verification.accepted


def test_duplicate_inputs_collapse_with_provenance(timeline: Path) -> None:
    case = analyze(
        [
            EvidenceInput(source="hayabusa", path=timeline),
            EvidenceInput(source="hayabusa", path=timeline),
        ],
        name="twice",
    )
    assert case.records_read == 74
    assert len(case.events) == 37
    assert case.duplicate_count == 37
    assert all(len(refs) == 2 for refs in case.provenance.values())


def test_no_inputs_is_a_usage_error() -> None:
    with pytest.raises(ValueError, match="at least one evidence input"):
        analyze([], name="empty")


def test_evidence_with_no_events_raises_with_the_reasons(tmp_path: Path) -> None:
    with pytest.raises(EmptyCaseError) as wrong:
        analyze(
            [EvidenceInput(source="hayabusa", path=FIXTURES / "generic_edr_slice.csv")],
            name="wrong source",
        )
    assert wrong.value.records > 0 and wrong.value.problems
    assert "is the source right for this file?" in str(wrong.value)

    empty = tmp_path / "empty.jsonl"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(EmptyCaseError, match="contained no records") as nothing:
        analyze([EvidenceInput(source="velociraptor", path=empty)], name="empty")
    assert nothing.value.records == 0


def test_file_level_errors_propagate(tmp_path: Path) -> None:
    broken = tmp_path / "detections.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(json.JSONDecodeError):
        analyze([EvidenceInput(source="chainsaw", path=broken)], name="broken")


def test_view_budget_limits_what_the_model_sees(timeline: Path) -> None:
    seen: list[int] = []

    class Recorder:
        def draft(self, request: object) -> str:
            seen.append(len(getattr(request, "events", ())))
            return '{"claims": []}'

    analyze(
        [EvidenceInput(source="hayabusa", path=timeline)],
        name="budget",
        model=Recorder(),
        view_budget=4,
    )
    assert seen == [4]
