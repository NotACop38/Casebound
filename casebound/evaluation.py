"""Evaluation: the numbers Casebound publishes, and how each one is measured.

Casebound's value is measured, not asserted (PRD Section 4). This module computes
every published number deterministically and offline, with no model in the loop.

The verifier benchmark (the headline). Two failure modes matter for a fence, and
both are measured:

  - A false accept lets an unsupported claim into a report. The benchmark derives,
    from every event of a case, a set of fabricated claims in the format a model
    emits, one per fabrication class: a nonexistent or malformed citation, no
    citation, no assertion, a time outside tolerance, a swapped principal, action,
    or object, a Unicode look-alike object, a claim stitched from two events, and
    a true claim carrying one dangling or malformed extra citation. Every one must
    be rejected.
  - A false reject throws away a true claim. The benchmark also derives grounded
    claims in every spelling the contract allows: exact, re-cased, padded with
    whitespace, a non-UTC offset for the same instant, a sub-second difference
    within tolerance, a subset of the fields, an extra context citation, an
    upper-case id. Every one must be accepted.

  The claims go through the real parser and the real checks, exactly as a model's
  output would. The target is zero false accepts and zero false rejects.

Citation accuracy. Every claim a narrative run accepted is re-verified from
scratch against the case, rather than trusting the loop. The target is 1.0; less is
a verifier bug.

ATT&CK tagging, scored against the scenario's ground-truth labels at the (event,
technique) level, twice:

  - end to end, exactly as the pipeline tags: a detection source's own rule tags,
    translated through the bundled catalog, and the mapping table for sources with
    no detection layer. On the bundled scenario every attack row is a Hayabusa
    detection, so this checks rule-tag passthrough, revoked-id translation, and
    that no benign row is tagged. The PRD targets (precision at least 0.9, recall
    at least 0.7) are enforced by the test suite.
  - table only, with every rule tag ignored and the table applied to every row,
    which measures the fallback used for sources with no detection layer (raw event
    logs, Plaso, file-system timelines). It labels behaviour, not intent, so the
    scenario's benign look-alikes (a vendor Run key, a Defender LSASS read) cost it
    precision; the number is published so an analyst knows how far to trust it.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from typing import Any

from casebound.enrich.attack import tag_event
from casebound.normalize.schema import KNOWN_ACTIONS, Event
from casebound.pipeline import Case
from casebound.verify.checks import FieldTolerance, RejectionReason, verify_claim
from casebound.verify.claims import Claim, parse_claims

__all__ = [
    "ATTACK_PRECISION_TARGET",
    "ATTACK_RECALL_TARGET",
    "AttackScore",
    "BenchmarkCase",
    "BenchmarkResult",
    "ClassResult",
    "Evaluation",
    "build_benchmark",
    "citation_accuracy",
    "evaluate",
    "run_benchmark",
    "score_attack",
]

# The PRD Section 12 targets for end-to-end ATT&CK tagging on the showcase scenario.
ATTACK_PRECISION_TARGET = 0.9
ATTACK_RECALL_TARGET = 0.7

# A citation that looks like a record number rather than an event id.
_RECORD_NUMBER_CITATION = "EVT-4688-81104"

# Latin letters and a Cyrillic look-alike for each: a confusable object must never
# match the real one.
_CONFUSABLES = {"a": "\u0430", "e": "\u0435", "o": "\u043e", "c": "\u0441", "p": "\u0440"}


@dataclass(frozen=True)
class BenchmarkCase:
    """One benchmark claim: its class, whether it must be accepted, and its JSON."""

    kind: str
    expect_accept: bool
    payload: dict[str, Any]
    expected_reason: RejectionReason | None = None


@dataclass(frozen=True)
class ClassResult:
    """How the verifier did on one benchmark class."""

    kind: str
    expect_accept: bool
    total: int
    correct: int

    def to_dict(self) -> dict[str, Any]:
        """Render the class result as a JSON-ready dict."""
        return {
            "kind": self.kind,
            "expect": "accept" if self.expect_accept else "reject",
            "total": self.total,
            "correct": self.correct,
        }


@dataclass(frozen=True)
class BenchmarkResult:
    """The verifier benchmark's outcome over one case.

    ``false_accepts`` and ``false_rejects`` hold a short description of every
    misjudged claim (none on a correct verifier). ``unexpected_reasons`` counts
    fabrications rejected, correctly, but for a different reason than the class
    predicts; it is informational.
    """

    classes: tuple[ClassResult, ...]
    fabrications: int
    fabrications_rejected: int
    grounded: int
    grounded_accepted: int
    false_accepts: tuple[str, ...]
    false_rejects: tuple[str, ...]
    unexpected_reasons: int

    @property
    def false_accept_rate(self) -> float:
        """Fabricated claims accepted, over fabricated claims (target 0.0)."""
        return len(self.false_accepts) / self.fabrications if self.fabrications else 0.0

    @property
    def false_reject_rate(self) -> float:
        """Grounded claims rejected, over grounded claims (target 0.0)."""
        return len(self.false_rejects) / self.grounded if self.grounded else 0.0

    @property
    def passed(self) -> bool:
        """True when no claim was misjudged in either direction."""
        return not self.false_accepts and not self.false_rejects

    def to_dict(self) -> dict[str, Any]:
        """Render the benchmark result as a JSON-ready dict."""
        return {
            "fabrications": self.fabrications,
            "fabrications_rejected": self.fabrications_rejected,
            "false_accept_rate": self.false_accept_rate,
            "grounded": self.grounded,
            "grounded_accepted": self.grounded_accepted,
            "false_reject_rate": self.false_reject_rate,
            "unexpected_reasons": self.unexpected_reasons,
            "passed": self.passed,
            "classes": [item.to_dict() for item in self.classes],
            "false_accepts": list(self.false_accepts),
            "false_rejects": list(self.false_rejects),
        }


def _parse_utc(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _format_utc(moment: datetime) -> str:
    base = moment.strftime("%Y-%m-%dT%H:%M:%S")
    if moment.microsecond:
        return f"{base}.{moment.microsecond:06d}".rstrip("0") + "Z"
    return f"{base}Z"


def _fold(value: str | None) -> str:
    return (value or "").strip().casefold()


def _grounded_asserts(event: Event) -> dict[str, str]:
    asserts = {"datetime": event.datetime, "action": event.action}
    if event.principal is not None:
        asserts["principal"] = event.principal
    if event.object is not None:
        asserts["object"] = event.object
    return asserts


def _claim(citations: list[str], asserts: dict[str, str], text: str) -> dict[str, Any]:
    return {"text": text, "citations": citations, "asserts": asserts}


def _other(events: Sequence[Event], event: Event, attr: str) -> str | None:
    """A value of ``attr`` from another event that differs from ``event``'s."""
    mine = _fold(getattr(event, attr))
    for other in events:
        value = getattr(other, attr)
        if value is not None and _fold(value) != mine:
            return str(value)
    return None


def _confusable(value: str) -> str | None:
    """``value`` with its first confusable Latin letter swapped for a look-alike."""
    for index, char in enumerate(value):
        if char in _CONFUSABLES:
            return value[:index] + _CONFUSABLES[char] + value[index + 1 :]
    return None


def _fabrications(
    events: Sequence[Event], event: Event, tolerance: timedelta
) -> list[BenchmarkCase]:
    """Every fabrication class, derived from one real event. Each must be rejected."""
    ids = {item.event_id for item in events}
    grounded = _grounded_asserts(event)
    cases: list[BenchmarkCase] = []

    def add(kind: str, payload: dict[str, Any], reason: RejectionReason | None) -> None:
        cases.append(BenchmarkCase(kind, False, payload, reason))

    flipped = ("0" if event.event_id[0] != "0" else "1") + event.event_id[1:]
    if flipped not in ids:
        add(
            "nonexistent_id",
            _claim([flipped], grounded, "cites an event that does not exist"),
            RejectionReason.MISSING_ID,
        )
    add(
        "short_handle_citation",
        _claim([event.event_id[:12]], grounded, "cites a truncated id"),
        RejectionReason.MALFORMED_CITATION,
    )
    add(
        "record_number_citation",
        _claim([_RECORD_NUMBER_CITATION], grounded, "cites a record number"),
        RejectionReason.MALFORMED_CITATION,
    )
    add("no_citation", _claim([], grounded, "cites nothing"), RejectionReason.NO_CITATIONS)
    add(
        "no_assertion",
        _claim([event.event_id], {}, "asserts nothing checkable"),
        RejectionReason.NO_ASSERTIONS,
    )

    instant = _parse_utc(event.datetime)
    add(
        "time_just_outside_tolerance",
        _claim(
            [event.event_id],
            {**grounded, "datetime": _format_utc(instant + tolerance + timedelta(seconds=1))},
            "moves the event just past the tolerance",
        ),
        RejectionReason.TIME_MISMATCH,
    )
    add(
        "time_hours_off",
        _claim(
            [event.event_id],
            {**grounded, "datetime": _format_utc(instant - timedelta(hours=6))},
            "moves the event six hours earlier",
        ),
        RejectionReason.TIME_MISMATCH,
    )

    principal = _other(events, event, "principal") or "CORP\\Administrator"
    if _fold(principal) != _fold(event.principal):
        add(
            "principal_swap",
            _claim(
                [event.event_id],
                {**grounded, "principal": principal},
                "names another account",
            ),
            RejectionReason.PRINCIPAL_MISMATCH,
        )

    action = next(verb for verb in sorted(KNOWN_ACTIONS) if verb != event.action)
    add(
        "action_swap",
        _claim([event.event_id], {**grounded, "action": action}, "names another action"),
        RejectionReason.ACTION_MISMATCH,
    )

    obj = _other(events, event, "object") or "C:\\Windows\\System32\\cmd.exe"
    if _fold(obj) != _fold(event.object):
        add(
            "object_swap",
            _claim([event.event_id], {**grounded, "object": obj}, "names another object"),
            RejectionReason.OBJECT_MISMATCH,
        )
    if event.object is not None:
        lookalike = _confusable(event.object)
        if lookalike is not None:
            add(
                "confusable_object",
                _claim(
                    [event.event_id],
                    {**grounded, "object": lookalike},
                    "swaps one letter of the object for a Unicode look-alike",
                ),
                RejectionReason.OBJECT_MISMATCH,
            )

    partner = next(
        (
            other
            for other in events
            if other.event_id != event.event_id
            and other.action != event.action
            and event.principal is not None
            and _fold(other.principal) != _fold(event.principal)
        ),
        None,
    )
    if partner is not None:
        add(
            "stitched_across_events",
            _claim(
                [event.event_id, partner.event_id],
                {"principal": str(event.principal), "action": partner.action},
                "joins one event's actor to another event's action",
            ),
            None,
        )

    dangling = event.event_id[:-1] + ("0" if event.event_id[-1] != "0" else "1")
    if dangling not in ids:
        add(
            "true_claim_with_dangling_citation",
            _claim([event.event_id, dangling], grounded, "adds a citation to nothing"),
            RejectionReason.MISSING_ID,
        )
    add(
        "true_claim_with_malformed_citation",
        _claim(
            [event.event_id, _RECORD_NUMBER_CITATION],
            grounded,
            "adds a record-number citation",
        ),
        RejectionReason.MALFORMED_CITATION,
    )
    return cases


def _pad(value: str) -> str:
    return f"  {value}\t"


def _groundeds(events: Sequence[Event], event: Event) -> list[BenchmarkCase]:
    """Every allowed spelling of a true claim about one event. Each must be accepted."""
    grounded = _grounded_asserts(event)
    instant = _parse_utc(event.datetime)
    cases = [
        BenchmarkCase("exact", True, _claim([event.event_id], grounded, "exact")),
        BenchmarkCase(
            "re_cased",
            True,
            _claim(
                [event.event_id],
                {
                    key: (value if key == "datetime" else value.swapcase())
                    for key, value in grounded.items()
                },
                "re-cased principal, action, and object",
            ),
        ),
        BenchmarkCase(
            "whitespace_padded",
            True,
            _claim(
                [event.event_id],
                {key: _pad(value) for key, value in grounded.items()},
                "padded values",
            ),
        ),
        BenchmarkCase(
            "offset_notation_same_instant",
            True,
            _claim(
                [event.event_id],
                {
                    **grounded,
                    "datetime": (instant - timedelta(hours=4))
                    .replace(tzinfo=None)
                    .isoformat(timespec="seconds")
                    + "-04:00",
                },
                "the same instant written with a -04:00 offset",
            ),
        ),
        BenchmarkCase(
            "subsecond_within_tolerance",
            True,
            _claim(
                [event.event_id],
                {**grounded, "datetime": _format_utc(instant + timedelta(milliseconds=500))},
                "half a second off, inside the one-second tolerance",
            ),
        ),
        BenchmarkCase(
            "subset_of_fields",
            True,
            _claim(
                [event.event_id],
                {"action": event.action, **({"object": event.object} if event.object else {})},
                "asserts only the action and object",
            ),
        ),
        BenchmarkCase(
            "upper_case_id",
            True,
            _claim([event.event_id.upper()], grounded, "the id in upper case"),
        ),
    ]
    context = next((other for other in events if other.event_id != event.event_id), None)
    if context is not None:
        cases.append(
            BenchmarkCase(
                "extra_context_citation",
                True,
                _claim(
                    [event.event_id, context.event_id],
                    grounded,
                    "cites a second real event for context",
                ),
            )
        )
    return cases


def build_benchmark(
    events: Sequence[Event], *, tolerance: FieldTolerance | None = None
) -> list[BenchmarkCase]:
    """Derive the benchmark's fabricated and grounded claims from every event."""
    window = (tolerance or FieldTolerance()).time_tolerance
    cases: list[BenchmarkCase] = []
    for event in events:
        cases.extend(_fabrications(events, event, window))
        cases.extend(_groundeds(events, event))
    return cases


def run_benchmark(
    events: Sequence[Event],
    cases: Sequence[BenchmarkCase] | None = None,
    *,
    tolerance: FieldTolerance | None = None,
) -> BenchmarkResult:
    """Run the benchmark claims through the real parser and checks and tally them."""
    chosen = list(cases) if cases is not None else build_benchmark(events, tolerance=tolerance)
    # One model-shaped document, parsed the way a model's output is parsed.
    parsed = parse_claims(json.dumps({"claims": [case.payload for case in chosen]}))
    if len(parsed) != len(chosen):  # pragma: no cover - every payload carries text
        raise ValueError("the benchmark lost a claim in parsing")
    index = {event.event_id: event for event in events}

    tallies: dict[tuple[str, bool], list[int]] = {}
    false_accepts: list[str] = []
    false_rejects: list[str] = []
    unexpected = 0
    for case, claim in zip(chosen, parsed, strict=True):
        verdict = verify_claim(claim, index, tolerance)
        correct = verdict.ok == case.expect_accept
        bucket = tallies.setdefault((case.kind, case.expect_accept), [0, 0])
        bucket[0] += 1
        bucket[1] += int(correct)
        if not correct:
            cited = ", ".join(claim.all_citations)[:40]
            note = f"{case.kind}: {claim.text} ({cited})"
            (false_accepts if verdict.ok else false_rejects).append(note)
        elif (
            not case.expect_accept
            and case.expected_reason is not None
            and verdict.reason != case.expected_reason
        ):
            unexpected += 1

    classes = tuple(
        ClassResult(kind=kind, expect_accept=accept, total=total, correct=correct)
        for (kind, accept), (total, correct) in tallies.items()
    )
    fabrications = sum(item.total for item in classes if not item.expect_accept)
    grounded = sum(item.total for item in classes if item.expect_accept)
    return BenchmarkResult(
        classes=classes,
        fabrications=fabrications,
        fabrications_rejected=fabrications - len(false_accepts),
        grounded=grounded,
        grounded_accepted=grounded - len(false_rejects),
        false_accepts=tuple(false_accepts),
        false_rejects=tuple(false_rejects),
        unexpected_reasons=unexpected,
    )


def citation_accuracy(case: Case) -> tuple[float, int, int]:
    """Return (rate, accurate, emitted) for the claims a narrative run accepted.

    Re-verifies every accepted claim from scratch against the case rather than
    trusting the loop: a claim is accurate only if its citations resolve and one
    cited event is consistent with every fact it asserted. 1.0 by construction; a
    lower value exposes a verifier bug.
    """
    accepted = case.verification.accepted if case.verification is not None else ()
    index = {event.event_id: event for event in case.events}
    accurate = sum(
        1
        for claim in accepted
        if verify_claim(
            Claim(
                index=0,
                text=claim.draft_text,
                citations=tuple(claim.citations),
                malformed_citations=(),
                asserts=claim.asserts,
            ),
            index,
        ).ok
    )
    return (accurate / len(accepted) if accepted else 1.0), accurate, len(accepted)


@dataclass(frozen=True)
class AttackScore:
    """Tagger precision and recall against ground-truth labels, per (event, technique).

    ``false_positive_examples`` names up to five false positives as
    ``host record technique`` so a reader can see what the tagger over-labels.
    """

    precision: float
    recall: float
    true_positives: int
    false_positives: int
    false_negatives: int
    false_positive_examples: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Render the score as a JSON-ready dict."""
        return {
            "precision": self.precision,
            "recall": self.recall,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "false_positive_examples": list(self.false_positive_examples),
        }


def score_attack(events: Sequence[Event], ground_truth: Mapping[str, Any]) -> AttackScore:
    """Score tagged events against the labels, joined on (host, source record id)."""
    expected = {
        (str(label["computer"]), str(label["record_id"]), tid)
        for label in ground_truth.get("events", [])
        for tid in label["technique_ids"]
    }
    predicted = {
        (event.host or "", event.raw_ref.record, tech.technique_id)
        for event in events
        for tech in event.attack_techniques
    }
    true_positives = len(predicted & expected)
    false_positives = sorted(predicted - expected)
    precision = true_positives / len(predicted) if predicted else 1.0
    recall = true_positives / len(expected) if expected else 1.0
    return AttackScore(
        precision=precision,
        recall=recall,
        true_positives=true_positives,
        false_positives=len(false_positives),
        false_negatives=len(expected - predicted),
        false_positive_examples=tuple(" ".join(item) for item in false_positives[:5]),
    )


@dataclass(frozen=True)
class Evaluation:
    """Every published number for one case, with the pass criterion.

    ``passed`` is the reproducibility gate the demo enforces: the verifier
    benchmark must have no false accepts and no false rejects, and every accepted
    narrative claim must re-verify. The ATT&CK scores are reported alongside; the
    test suite holds the end-to-end score to its targets on the bundled scenario.
    """

    benchmark: BenchmarkResult
    citation_accuracy: float
    accurate_claims: int
    emitted_claims: int
    attack_end_to_end: AttackScore | None
    attack_table_only: AttackScore | None
    techniques_observed: tuple[str, ...]

    @property
    def passed(self) -> bool:
        """True when the verifier guarantee held on every measured claim."""
        return self.benchmark.passed and self.accurate_claims == self.emitted_claims

    def to_dict(self) -> dict[str, Any]:
        """Render the evaluation as the JSON-ready body of metrics.json."""
        return {
            "passed": self.passed,
            "verifier_benchmark": self.benchmark.to_dict(),
            "narrative": {
                "citation_accuracy": self.citation_accuracy,
                "accurate_claims": self.accurate_claims,
                "emitted_claims": self.emitted_claims,
            },
            "attack": {
                "end_to_end": self.attack_end_to_end.to_dict() if self.attack_end_to_end else None,
                "table_only": self.attack_table_only.to_dict() if self.attack_table_only else None,
                "techniques_observed": list(self.techniques_observed),
            },
            "targets": {
                "false_accept_rate": 0.0,
                "false_reject_rate": 0.0,
                "citation_accuracy": 1.0,
                "attack_end_to_end_precision": ATTACK_PRECISION_TARGET,
                "attack_end_to_end_recall": ATTACK_RECALL_TARGET,
            },
        }


def evaluate(case: Case, ground_truth: Mapping[str, Any] | None = None) -> Evaluation:
    """Compute every published number for ``case``.

    ``ground_truth`` (the generator's label file) enables the ATT&CK scores; without
    it they are None. The verifier benchmark and citation accuracy need no labels.
    """
    benchmark = run_benchmark(case.events)
    rate, accurate, emitted = citation_accuracy(case)
    end_to_end = table_only = None
    if ground_truth is not None:
        end_to_end = score_attack(case.events, ground_truth)
        untagged = [replace(event, attack_techniques=[]) for event in case.events]
        table_only = score_attack(
            [tag_event(event, use_rule_tags=False) for event in untagged], ground_truth
        )
    return Evaluation(
        benchmark=benchmark,
        citation_accuracy=rate,
        accurate_claims=accurate,
        emitted_claims=emitted,
        attack_end_to_end=end_to_end,
        attack_table_only=table_only,
        techniques_observed=case.technique_ids(),
    )
