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
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from casebound.enrich.attack import tag_events
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, normalize_records
from casebound.normalize.schema import KNOWN_ACTIONS
from casebound.verify import (
    ClaimParseError,
    DraftRequest,
    RejectionReason,
    parse_claims,
    verify_claim,
    verify_narrative,
)
from casebound.verify.claims import Claim
from casebound.verify.engine import select_view_events

# The bundled hallucination-trap fixture (PRD FR35), built against the default
# seed so its hardcoded event ids match the scenario the test regenerates.
TRAP_PATH = Path(__file__).resolve().parents[1] / "samples" / "hallucination_trap.json"

# Real event ids from the office_intrusion scenario at the default seed: the
# Word-spawned encoded PowerShell process-create event, and the lateral-movement
# network logon.
PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"
LATERAL_LOGON_ID = "4e959251e72c7f9c2bcf43acbcdf51ac69baf4542c49ff55e363316299b1da5e"


# The engine assigns each rejected claim a stable id in rejection order: the first
# rejected claim is "c0", the next "c1", and so on. It passes that id to the model
# in each RevisionRequest, and a revision references the id it fixes through its
# "revises" field. The mocked model echoes the id the same way a real model would.
FIRST_CLAIM_ID = "c0"
SECOND_CLAIM_ID = "c1"


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
    result = verify_narrative(events, model, max_rounds=0)

    assert result.accepted == ()
    assert len(result.dropped) == 1
    assert result.dropped[0].reason is RejectionReason.MISSING_ID
    # The rejection is logged and dropped in the single pass (FR24, FR25).
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
    # The malicious service install on the file server records no principal (the
    # System log's 7045 names none), so asserting any principal for it cannot be
    # satisfied: you cannot assert a fact the evidence does not record.
    events = _events(tmp_path)
    install = next(
        e for e in events if e.action == "service_install" and e.datetime == "2026-03-14T08:56:40Z"
    )
    assert install.principal is None
    [claim] = parse_claims(
        _response(
            {
                "text": "CORP\\svc-backup installed the service.",
                "citations": [install.event_id],
                "asserts": {"principal": "CORP\\svc-backup"},
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
            "revises": FIRST_CLAIM_ID,
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
    # The model was handed the rejection, with its id, as a revision hint.
    assert model.requests[1].is_revision
    assert model.requests[1].revisions[0].claim_id == FIRST_CLAIM_ID
    assert model.requests[1].revisions[0].reason is RejectionReason.PRINCIPAL_MISMATCH


def test_unsupported_claim_is_dropped_after_max_rounds(tmp_path: Path) -> None:
    events = _events(tmp_path)
    # A conforming model resubmits the same outstanding claim by id every round, but
    # never actually fixes it, so it is dropped after the final round.
    bad = _response(
        {
            "text": "The administrator spawned the PowerShell process.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\Administrator"},
            "revises": FIRST_CLAIM_ID,
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
    # The reduced view exposes only the addressable fields plus the event's ATT&CK
    # technique ids and detection severity, never details.
    for view in request.events:
        assert set(view.to_dict()) == {
            "event_id",
            "datetime",
            "host",
            "principal",
            "action",
            "object",
            "message",
            "techniques",
            "severity",
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
        model = StubModel([_response(case["claim"])])
        # One verification pass (no revision rounds): the verifier must reject the
        # fabrication outright.
        result = verify_narrative(events, model, max_rounds=0)
        assert result.accepted == (), f"{case['name']} must not be accepted"
        assert len(result.dropped) == 1, f"{case['name']} must be dropped"
        assert result.dropped[0].reason.value == case["expected_reason"], case["name"]
        rejected += 1

    rejection_rate = rejected / len(fabricated)
    assert rejection_rate == 1.0


# 7. Citations on an accepted claim must all resolve (no unverified links reach the
#    report). Regression for the multi-citation hole.


def test_unresolved_extra_citation_rejects_the_whole_claim(tmp_path: Path) -> None:
    # One valid backing event plus a well-formed but nonexistent id. The claim must
    # not be accepted with a citation that links to nothing.
    events = _events(tmp_path)
    fake_id = "deadbeef" * 8
    model = StubModel(
        [
            _response(
                {
                    "text": "An encoded PowerShell process was created from Word.",
                    "citations": [PROCESS_CREATE_ID, fake_id],
                    "asserts": {"action": "process_create"},
                }
            )
        ]
    )
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.MISSING_ID


def test_malformed_extra_citation_rejects_the_whole_claim(tmp_path: Path) -> None:
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "An encoded PowerShell process was created from Word.",
                    "citations": [PROCESS_CREATE_ID, "EVENT-80038"],
                    "asserts": {"action": "process_create"},
                }
            )
        ]
    )
    result = verify_narrative(events, model)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.MALFORMED_CITATION


# 8. The report content is rendered from checked fields only: prose cannot smuggle
#    an unverified fact into the report.


def test_accepted_claim_renders_only_verified_fields_not_prose(tmp_path: Path) -> None:
    # The prose attributes the process to the domain administrator, but the claim
    # only asserts (and the verifier only checks) the action. The accepted claim
    # must not carry the administrator as a verified fact, and the rendered
    # statement must contain no fact beyond the checked assertion.
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "The domain administrator spawned the encoded PowerShell process.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"action": "process_create"},
                }
            )
        ]
    )
    result = verify_narrative(events, model)

    assert len(result.accepted) == 1
    claim = result.accepted[0]
    # Only the checked field is authoritative; the smuggled principal is not.
    assert claim.asserts.action == "process_create"
    assert claim.asserts.principal is None
    statement = claim.rendered_statement()
    assert "administrator" not in statement.lower()
    assert "process_create" in statement
    # The model's prose is retained for the audit but flagged non-authoritative.
    assert "administrator" in claim.draft_text.lower()


# 9. The loop never silently loses an unsupported claim during revision (FR24, FR25).


def test_omitted_earlier_claim_is_recorded_as_dropped(tmp_path: Path) -> None:
    # The case positional matching got wrong: round 0 rejects two claims; round 1
    # omits the earlier one (c0) and fixes only the later one (c1) by id. The fix
    # must be accepted, the omitted earlier claim must be dropped and recorded, and
    # the fixed claim's original must not be spuriously dropped.
    events = _events(tmp_path)
    bad_principal = {  # becomes c0, the earlier claim that gets omitted
        "text": "The administrator spawned the PowerShell process.",
        "citations": [PROCESS_CREATE_ID],
        "asserts": {"principal": "CORP\\Administrator", "action": "process_create"},
    }
    bad_action = {  # becomes c1, the later claim that gets fixed
        "text": "CORP\\svc-backup created a process during the network logon.",
        "citations": [LATERAL_LOGON_ID],
        "asserts": {"action": "process_create"},
    }
    fixed_action = {
        "text": "CORP\\svc-backup logged on to the file server from 10.4.12.66.",
        "citations": [LATERAL_LOGON_ID],
        "asserts": {"action": "logon"},
        "revises": SECOND_CLAIM_ID,
    }
    model = StubModel(
        [
            _response(bad_principal, bad_action),
            _response(fixed_action),  # fixes c1, omits c0
            _response(),  # nothing further for the omitted c0
        ]
    )
    result = verify_narrative(events, model, max_rounds=2)

    # The later claim was fixed and accepted.
    assert len(result.accepted) == 1
    assert result.accepted[0].asserts.action == "logon"
    # The omitted earlier claim is dropped and recorded, not silently lost.
    assert len(result.dropped) == 1
    assert result.dropped[0].reason is RejectionReason.PRINCIPAL_MISMATCH
    assert "administrator" in result.dropped[0].claim_text.lower()


def test_unparseable_revision_drops_outstanding_claim(tmp_path: Path) -> None:
    events = _events(tmp_path)
    bad = _response(
        {
            "text": "The administrator spawned the PowerShell process.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\Administrator"},
        }
    )
    model = StubModel([bad, "garbage, not json"])
    result = verify_narrative(events, model, max_rounds=1)

    assert result.accepted == ()
    # The outstanding claim is not lost when the revision round is unparseable.
    assert len(result.dropped) == 1
    assert result.dropped[0].reason is RejectionReason.PRINCIPAL_MISMATCH


# 6. Rejection-detail hygiene: details travel to the model as revision hints, so
#    they must never quote the cited event's own field values; on the cloud path
#    that prompt must not carry what the redaction pass stripped (FR36, Hard
#    rule 2). The asserted values come from the model itself, so echoing those
#    back leaks nothing.


def test_rejection_details_never_quote_event_field_values(tmp_path: Path) -> None:
    events = _events(tmp_path)
    index = {event.event_id: event for event in events}
    target = index[PROCESS_CREATE_ID]
    # The scenario records all four checked fields on this event, so each
    # per-field mismatch below is exercised against a real value.
    assert target.principal is not None and target.object is not None

    def _verdict(asserts: dict[str, str]) -> Any:
        [claim] = parse_claims(
            _response(
                {
                    "text": "A fabricated framing of a real event.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": asserts,
                }
            )
        )
        return verify_claim(claim, index)

    time_verdict = _verdict({"datetime": "2026-03-14T02:42:17Z"})
    assert time_verdict.ok is False
    assert time_verdict.reason is RejectionReason.TIME_MISMATCH
    assert "02:42:17" in time_verdict.detail  # the model's own asserted value
    assert "08:42:17" not in time_verdict.detail  # the event's real time

    principal_verdict = _verdict({"principal": "CORP\\Administrator"})
    assert principal_verdict.ok is False
    assert principal_verdict.reason is RejectionReason.PRINCIPAL_MISMATCH
    assert "Administrator" in principal_verdict.detail
    assert target.principal not in principal_verdict.detail

    action_verdict = _verdict({"action": "service_install"})
    assert action_verdict.ok is False
    assert action_verdict.reason is RejectionReason.ACTION_MISMATCH
    assert "service_install" in action_verdict.detail
    assert target.action not in action_verdict.detail

    object_verdict = _verdict({"object": "C:\\Windows\\Temp\\evil.exe"})
    assert object_verdict.ok is False
    assert object_verdict.reason is RejectionReason.OBJECT_MISMATCH
    assert "evil.exe" in object_verdict.detail
    assert target.object not in object_verdict.detail

    # And the grounded counterpart still passes the fence: asserting the event's
    # exact fields is accepted and backed by the cited event.
    grounded = _verdict(
        {
            "datetime": target.datetime,
            "principal": target.principal,
            "action": target.action,
            "object": target.object,
        }
    )
    assert grounded.ok is True
    assert grounded.backing_event_id == PROCESS_CREATE_ID


def test_accepted_claim_renders_the_events_canonical_fields(tmp_path: Path) -> None:
    # The checks are tolerant (case folding, a small time window), so a model can
    # assert an equivalent but differently-spelled value: a different case, or the
    # same instant in a non-UTC offset. The claim is rightly accepted, but the
    # report must show the event's canonical values, never the model's spelling.
    events = _events(tmp_path)
    index = {event.event_id: event for event in events}
    target = index[PROCESS_CREATE_ID]
    assert target.principal is not None and target.object is not None

    offset_time = "2026-03-14T09:42:17+01:00"  # the same instant as the event, +01:00
    model = StubModel(
        [
            _response(
                {
                    "text": "The user ran PowerShell.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {
                        "datetime": offset_time,
                        "principal": target.principal.upper(),
                        "action": target.action.upper(),
                        "object": target.object.lower(),
                    },
                },
                {
                    # The fabricated counterpart: a principal beyond the tolerance
                    # of any spelling difference is still rejected.
                    "text": "The domain administrator ran PowerShell.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"principal": "CORP\\Administrator"},
                },
            )
        ]
    )
    result = verify_narrative(events, model, max_rounds=0)

    [claim] = result.accepted
    assert result.dropped[0].reason is RejectionReason.PRINCIPAL_MISMATCH

    # The verified snapshot carries the canonical values; the model's spellings
    # stay in asserts for the audit.
    assert claim.verified.datetime == target.datetime
    assert claim.verified.principal == target.principal
    assert claim.verified.object == target.object
    assert claim.asserts.datetime == offset_time

    statement = claim.rendered_statement()
    assert target.datetime in statement
    assert target.principal in statement
    assert target.object in statement
    assert offset_time not in statement
    assert target.principal.upper() not in statement
    assert target.object.lower() not in statement

    # Every report format renders through the shared model, which phrases the
    # narrative from the backing event's own fields, never the model's.
    from casebound.pipeline import case_from_events
    from casebound.report import build_report_model, phrase_event, render_html, render_markdown

    case = case_from_events(events, name="canonical-render-test", verification=result)
    report = build_report_model(case)
    [entry] = report.narrative
    assert entry.backing_event_id == PROCESS_CREATE_ID
    assert entry.statement == phrase_event(target)
    assert target.principal in entry.statement
    assert entry.datetime == target.datetime
    assert set(entry.verified_fields) == {"datetime", "principal", "action", "object"}
    for rendered in (render_html(case), render_markdown(case)):
        # Neither the accepted claim's prose nor the model's spellings reach a
        # reader; the rejected claim appears only in the labeled audit.
        assert "The user ran PowerShell." not in rendered
        assert target.principal.upper() not in rendered
        assert offset_time not in rendered


def test_claim_with_no_citation_at_all_is_rejected(tmp_path: Path) -> None:
    # A claim that cites nothing (not even a malformed string) provides no
    # support and is rejected before any field is checked (FR18).
    events = _events(tmp_path)
    model = StubModel(
        [
            _response(
                {
                    "text": "An encoded PowerShell process was spawned from Word.",
                    "citations": [],
                    "asserts": {"action": "process_create"},
                }
            )
        ]
    )
    result = verify_narrative(events, model, max_rounds=0)
    assert result.accepted == ()
    assert result.dropped[0].reason is RejectionReason.NO_CITATIONS


# 10. The view budget decides what the model is shown, never what is verified.


def test_view_budget_shows_tagged_and_severe_events_first(tmp_path: Path) -> None:
    events = tag_events(_events(tmp_path))
    chosen = select_view_events(events, 5)
    assert len(chosen) == 5
    # Every shown event carries a technique, and none left out outranks them.
    assert all(event.attack_techniques for event in chosen)
    # The shown events keep chronological order.
    assert chosen == sorted(chosen, key=lambda event: (event.datetime, event.event_id))


def test_no_budget_or_a_small_case_shows_every_event(tmp_path: Path) -> None:
    events = tag_events(_events(tmp_path))
    assert len(select_view_events(events, None)) == len(events)
    assert len(select_view_events(events, len(events))) == len(events)


def test_budgeted_request_reports_how_many_events_were_left_out(tmp_path: Path) -> None:
    events = tag_events(_events(tmp_path))
    model = StubModel([_response()])
    verify_narrative(events, model, view_budget=5)
    request = model.requests[0]
    assert len(request.events) == 5
    assert request.total_events == len(events)
    assert request.omitted_events == len(events) - 5


def test_claims_are_verified_against_the_whole_case_not_the_view(tmp_path: Path) -> None:
    # Grounded accept and fabricated reject for an event the budget kept out of the
    # view: the cut changes what the model sees, never what the verifier checks.
    events = tag_events(_events(tmp_path))
    shown = {event.event_id for event in select_view_events(events, 1)}
    hidden = next(event for event in events if event.event_id not in shown)
    grounded = {
        "text": "A grounded claim about an event outside the view.",
        "citations": [hidden.event_id],
        "asserts": {"datetime": hidden.datetime, "action": hidden.action},
    }
    fabricated = {
        "text": "A fabricated claim about the same event.",
        "citations": [hidden.event_id],
        "asserts": {"datetime": hidden.datetime, "action": "log_clear"},
    }
    if hidden.action == "log_clear":  # pragma: no cover - the scenario's first event
        fabricated["asserts"] = {"datetime": hidden.datetime, "action": "logon"}
    result = verify_narrative(
        events, StubModel([_response(grounded, fabricated)]), max_rounds=0, view_budget=1
    )
    assert [claim.backing_event_id for claim in result.accepted] == [hidden.event_id]
    assert [entry.reason for entry in result.dropped] == [RejectionReason.ACTION_MISMATCH]


def test_invalid_budget_and_rounds_are_refused(tmp_path: Path) -> None:
    events = _events(tmp_path)
    with pytest.raises(ValueError, match="view_budget"):
        verify_narrative(events, StubModel([_response()]), view_budget=0)
    with pytest.raises(ValueError, match="max_rounds"):
        verify_narrative(events, StubModel([_response()]), max_rounds=-1)


def test_rejection_detail_quotes_windows_paths_readably(tmp_path: Path) -> None:
    # The audit log shows an asserted account as written, not repr-escaped.
    events = _events(tmp_path)
    [claim] = parse_claims(
        _response(
            {
                "text": "The administrator ran PowerShell.",
                "citations": [PROCESS_CREATE_ID],
                "asserts": {"principal": "CORP\\Administrator"},
            }
        )
    )
    verdict = verify_claim(claim, {event.event_id: event for event in events})
    assert "'CORP\\Administrator'" in verdict.detail
    assert "\\\\" not in verdict.detail


# 11. Properties: for every event in the scenario, the exact facts are accepted and
#     any single fact changed beyond tolerance is rejected with the right reason.


@pytest.fixture(scope="module")
def scenario_index(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Event]:
    csv_path, _ = write_samples(tmp_path_factory.mktemp("property"))
    result = normalize_records(HayabusaAdapter().read(csv_path))
    return {event.event_id: event for event in result.events}


def _claim_for(event_id: str, asserts: dict[str, str]) -> Claim:
    [claim] = parse_claims(_response({"text": "t", "citations": [event_id], "asserts": asserts}))
    return claim


def _exact_asserts(event: Event) -> dict[str, str]:
    asserts = {"datetime": event.datetime, "action": event.action}
    if event.principal is not None:
        asserts["principal"] = event.principal
    if event.object is not None:
        asserts["object"] = event.object
    return asserts


@settings(
    max_examples=200, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(data=st.data())
def test_property_exact_facts_are_accepted(
    scenario_index: dict[str, Event], data: st.DataObject
) -> None:
    event = data.draw(st.sampled_from(sorted(scenario_index.values(), key=lambda e: e.event_id)))
    verdict = verify_claim(_claim_for(event.event_id, _exact_asserts(event)), scenario_index)
    assert verdict.ok and verdict.backing_event_id == event.event_id


@settings(
    max_examples=300, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture]
)
@given(data=st.data())
def test_property_any_changed_fact_is_rejected(
    scenario_index: dict[str, Event], data: st.DataObject
) -> None:
    event = data.draw(st.sampled_from(sorted(scenario_index.values(), key=lambda e: e.event_id)))
    fields = ["datetime", "action"]
    fields += [name for name in ("principal", "object") if getattr(event, name) is not None]
    field = data.draw(st.sampled_from(fields))
    asserts = _exact_asserts(event)

    if field == "datetime":
        # Anything more than the tolerance away, in either direction.
        seconds = data.draw(st.integers(min_value=2, max_value=10**8))
        sign = data.draw(st.sampled_from((-1, 1)))
        moment = datetime.fromisoformat(event.datetime.replace("Z", "+00:00"))
        asserts["datetime"] = (moment + timedelta(seconds=sign * seconds)).isoformat()
        expected = RejectionReason.TIME_MISMATCH
    elif field == "action":
        asserts["action"] = data.draw(st.sampled_from(sorted(KNOWN_ACTIONS - {event.action})))
        expected = RejectionReason.ACTION_MISMATCH
    else:
        actual = str(getattr(event, field))
        value = data.draw(
            st.text(min_size=1, max_size=40).filter(
                lambda text: text.strip() and text.strip().casefold() != actual.casefold()
            )
        )
        asserts[field] = value
        expected = (
            RejectionReason.PRINCIPAL_MISMATCH
            if field == "principal"
            else RejectionReason.OBJECT_MISMATCH
        )

    verdict = verify_claim(_claim_for(event.event_id, asserts), scenario_index)
    assert not verdict.ok
    assert verdict.reason is expected
