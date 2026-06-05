"""Tests for the verification fence (PRD Section 11, FR17 to FR25, FR35).

The load-bearing properties, test-first per AGENTS.md (every verifier change ships
with a grounded-accept test and a fabricated-reject test):

  1. Grounded: a claim that cites a real event and asserts facts consistent with
     it is accepted and linked to that event.
  2. Fabricated: a claim that cites a missing id, or asserts a mismatched time,
     principal, action, or object, or cites a malformed id, is rejected and
     recorded in the audit log.
  3. The loop: rejected claims are resubmitted for revision up to max_rounds, a
     fixed claim is accepted, and anything still unsupported after the final round
     is dropped and never emitted.
  4. The fence: the model only ever sees the compact, id-addressed view, never raw
     evidence (Hard rule 4).
  5. The hallucination trap (FR35): every seeded fabricated claim is rejected, so
     the hallucination-rejection rate is 1.0 on the seeded set.

All tests use a mocked model provider. No network, no API keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, normalize_records
from casebound.verify import (
    ClaimParseError,
    DraftRequest,
    RejectionReason,
    parse_claims,
    verify_claim,
    verify_narrative,
)

# The bundled hallucination-trap fixture (PRD FR35), built against the default
# seed so its hardcoded event ids match the scenario the test regenerates.
TRAP_PATH = Path(__file__).resolve().parents[1] / "samples" / "hallucination_trap.json"

# A real event id from the office_intrusion scenario at the default seed: the
# Word-spawned encoded PowerShell process-create event.
PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"


class StubModel:
    """A mocked ``NarrativeModel`` that replays scripted raw responses.

    Round N returns the Nth scripted response, repeating the last one for any
    further rounds. A single-response stub therefore returns the same draft every
    round (useful for a claim that is never fixed); a two-response stub returns a
    bad draft then a fixed one (useful for the revision path). Every request is
    captured so a test can inspect exactly what the model was shown.
    """

    def __init__(self, responses: list[str]) -> None:
        if not responses:
            raise ValueError("StubModel needs at least one scripted response")
        self.responses = responses
        self.requests: list[DraftRequest] = []

    def draft(self, request: DraftRequest) -> str:
        self.requests.append(request)
        index = min(len(self.requests) - 1, len(self.responses) - 1)
        return self.responses[index]


def _response(*claims: dict[str, Any]) -> str:
    """Serialize claim dicts into the raw model-output format the parser expects."""
    return json.dumps({"claims": list(claims)})


def _events(tmp_path: Path) -> list[Event]:
    """Generate, ingest, and normalize the bundled scenario into canonical events."""
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    assert result.problem_count == 0
    return list(result.events)


def _load_trap() -> dict[str, Any]:
    data: dict[str, Any] = json.loads(TRAP_PATH.read_text(encoding="utf-8"))
    return data


# 1. The claims parser (PRD Section 11 step 3).


def test_parser_splits_well_formed_and_malformed_citations() -> None:
    raw = _response(
        {
            "text": "A process was created.",
            "citations": [PROCESS_CREATE_ID, "EVENT-80038", PROCESS_CREATE_ID.upper()],
            "asserts": {"action": "process_create"},
        }
    )
    [claim] = parse_claims(raw)
    # The valid id is kept once (case-normalized); the record-number string is
    # recorded as malformed and provides no support.
    assert claim.citations == (PROCESS_CREATE_ID,)
    assert claim.malformed_citations == ("EVENT-80038",)
    assert claim.asserts.action == "process_create"


def test_parser_skips_textless_claims_and_empty_asserts() -> None:
    raw = _response(
        {"text": "   ", "citations": [PROCESS_CREATE_ID]},
        {"text": "Real claim.", "citations": [PROCESS_CREATE_ID], "asserts": {}},
    )
    claims = parse_claims(raw)
    assert [c.text for c in claims] == ["Real claim."]
    assert claims[0].asserts.is_empty()


def test_parser_rejects_non_json_output() -> None:
    with pytest.raises(ClaimParseError):
        parse_claims("I could not find any events to narrate.")


# 2. Grounded claim is accepted (the positive case, required every commit).


def test_grounded_claim_is_accepted(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "CORP\\jdoe ran an encoded PowerShell process spawned from Word.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {
                        "datetime": "2026-03-14T08:42:17Z",
                        "principal": "CORP\\jdoe",
                        "action": "process_create",
                        "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    },
                }
            )
        ]
    )
    result = verify_narrative(events, model)

    assert len(result.accepted) == 1
    assert result.accepted[0].backing_event_id == PROCESS_CREATE_ID
    assert result.audit == ()
    assert result.rounds_used == 1


# 3. Fabricated claims are rejected and logged (the negative cases).


def test_missing_id_is_rejected_and_logged(tmp_path: Path) -> None:
    events = _events(tmp_path)
    fake_id = "deadbeef" * 8  # a well-formed but nonexistent event id
    model = StubModel(
        [
            _response(
                {
                    "text": "The attacker deployed ransomware on the file server.",
                    "citations": [fake_id],
                    "asserts": {"action": "file_write"},
                }
            )
        ]
    )
    result = verify_narrative(events, model)

    assert result.accepted == ()
    assert len(result.dropped) == 1
    assert result.dropped[0].reason is RejectionReason.MISSING_ID
    # Every round's rejection is logged, and the last is the drop (FR24, FR25).
    assert all(entry.reason is RejectionReason.MISSING_ID for entry in result.audit)


def test_time_mismatch_is_rejected(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "Word spawned PowerShell hours before the alert.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"datetime": "2026-03-14T02:42:17Z"},
                }
            )
        ]
    )
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.TIME_MISMATCH


def test_principal_mismatch_is_rejected(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "The domain administrator spawned the PowerShell process.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {
                        "datetime": "2026-03-14T08:42:17Z",
                        "principal": "CORP\\Administrator",
                    },
                }
            )
        ]
    )
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.PRINCIPAL_MISMATCH


def test_malformed_only_citation_is_unsupported(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "A process was created from Word.",
                    "citations": ["EVENT-80038"],
                    "asserts": {"action": "process_create"},
                }
            )
        ]
    )
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.MALFORMED_CITATION


def test_claim_without_assertions_is_rejected(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "Something happened on the host.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {},
                }
            )
        ]
    )
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.NO_ASSERTIONS


def test_principal_assertion_against_null_event_field_is_rejected(tmp_path: Path) -> None:
    # The lsass process-access event has a null principal, so asserting any
    # principal for it cannot be satisfied: you cannot assert a fact the evidence
    # does not record.
    events = _events(tmp_path)
    lsass = next(e for e in events if e.object and e.object.lower().endswith("lsass.exe"))
    assert lsass.principal is None
    [claim] = parse_claims(
        _response(
            {
                "text": "CORP\\jdoe opened a handle into lsass.",
                "citations": [lsass.event_id],
                "asserts": {"principal": "CORP\\jdoe"},
            }
        )
    )
    verdict = verify_claim(claim, {e.event_id: e for e in events})
    assert verdict.ok is False
    assert verdict.reason is RejectionReason.PRINCIPAL_MISMATCH


# 4. The generate-test-refine loop (FR23 to FR25).


def test_rejected_claim_is_revised_and_then_accepted(tmp_path: Path) -> None:
    events = _events(tmp_path)
    bad = _response(
        {
            "text": "The administrator spawned the PowerShell process.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\Administrator", "action": "process_create"},
        }
    )
    fixed = _response(
        {
            "text": "CORP\\jdoe spawned the PowerShell process from Word.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\jdoe", "action": "process_create"},
        }
    )
    model = StubModel([bad, fixed])
    result = verify_narrative(events, model)

    # The fixed claim is accepted on round 1, and the round-0 rejection still shows
    # in the audit log for transparency, but it is not a drop.
    assert len(result.accepted) == 1
    assert result.accepted[0].round_index == 1
    assert result.rounds_used == 2
    assert len(result.audit) == 1
    assert result.audit[0].dropped is False
    assert result.audit[0].reason is RejectionReason.PRINCIPAL_MISMATCH
    # The model was handed the rejection as a revision hint on the second round.
    assert model.requests[1].is_revision
    assert model.requests[1].revisions[0].reason is RejectionReason.PRINCIPAL_MISMATCH


def test_unsupported_claim_is_dropped_after_max_rounds(tmp_path: Path) -> None:
    events = _events(tmp_path)
    bad = _response(
        {
            "text": "The administrator spawned the PowerShell process.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\Administrator"},
        }
    )
    model = StubModel([bad])  # never fixed: repeated every round
    result = verify_narrative(events, model, max_rounds=2)

    assert result.accepted == ()
    assert result.rounds_used == 3  # initial draft plus two revision rounds
    assert len(result.audit) == 3  # one rejection per round
    assert sum(1 for entry in result.audit if entry.dropped) == 1
    assert result.dropped[0].reason is RejectionReason.PRINCIPAL_MISMATCH


def test_unparseable_output_produces_no_claims(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(["not json at all"])
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.audit == ()


# 5. The fence: the model only ever sees the compact, id-addressed view.


def test_model_sees_only_the_compact_view_not_raw_evidence(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel([_response()])  # empty narrative; we only inspect the request
    verify_narrative(events, model)

    request = model.requests[0]
    serialized = json.dumps([view.to_dict() for view in request.events])
    # The reduced view exposes only the addressable fields, never details.
    for view in request.events:
        assert set(view.to_dict()) == {
            "event_id",
            "datetime",
            "host",
            "principal",
            "action",
            "object",
            "message",
        }
    # The encoded PowerShell blob lives in event.details (raw evidence) and must
    # not leak into anything the model is shown.
    assert "SQBFAFgA" not in serialized


# 6. The hallucination trap (FR35): rejection rate 1.0 on the seeded set.


def test_hallucination_trap_rejects_every_fabricated_claim(tmp_path: Path) -> None:
    events = _events(tmp_path)
    trap = _load_trap()
    index = {e.event_id: e for e in events}

    # Sanity-check the fixture is aligned with the regenerated scenario: its
    # grounded citation must point at a real event.
    grounded_claim = trap["grounded"]["claim"]
    assert grounded_claim["citations"][0] in index

    # The grounded claim must be accepted.
    grounded_result = verify_narrative(events, StubModel([_response(grounded_claim)]))
    assert len(grounded_result.accepted) == 1
    assert grounded_result.audit == ()

    # Every fabricated claim must be rejected, dropped, and never emitted, with the
    # documented reason.
    rejected = 0
    fabricated = trap["fabricated"]
    for case in fabricated:
        model = StubModel([_response(case["claim"])])  # never fixed
        result = verify_narrative(events, model)
        assert result.accepted == (), f"{case['name']} must not be accepted"
        assert len(result.dropped) == 1, f"{case['name']} must be dropped"
        assert result.dropped[0].reason.value == case["expected_reason"], case["name"]
        rejected += 1

    rejection_rate = rejected / len(fabricated)
    assert rejection_rate == 1.0
