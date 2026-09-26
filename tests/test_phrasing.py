"""Tests for the deterministic phrasing layer (the verified narrative's sentences).

The load-bearing property: a narrative sentence is composed only from its event's
own canonical fields, with evidence reproduced exactly (never re-cased, trimmed,
or completed), so it can be shown as a verified fact. Every canonical action has a
sentence in an active voice (a named principal) and a passive voice (none), a
missing object reads as a generic noun rather than an invention, and an event with
no template still gets a faithful sentence.
"""

from __future__ import annotations

from typing import Any

import pytest
from hypothesis import given
from hypothesis import strategies as st

from casebound.normalize.schema import KNOWN_ACTIONS, Event, RawRef
from casebound.report.phrasing import _TEMPLATES, phrase_event


def _event(**overrides: Any) -> Event:
    base: dict[str, Any] = {
        "datetime": "2026-03-14T08:42:17Z",
        "timestamp_raw": "2026-03-14T08:42:17Z",
        "source_timezone": "UTC",
        "timestamp_desc": "logged",
        "message": "Rule title from the source",
        "action": "process_create",
        "source_tool": "hayabusa",
        "source_artifact": "Security.evtx",
        "raw_ref": RawRef(source_file="x.csv", record="1"),
        "principal": "CORP\\jdoe",
        "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    }
    base.update(overrides)
    return Event(**base)


# Actions whose sentence names no object: a logoff is about the account alone.
_NO_OBJECT = frozenset({"logoff"})


def test_every_canonical_action_but_other_has_a_template() -> None:
    assert set(_TEMPLATES) == KNOWN_ACTIONS - {"other"}
    for action, template in _TEMPLATES.items():
        names_object = "{object}" in template.active or "{source}" in template.active
        assert names_object == (action not in _NO_OBJECT), action


@pytest.mark.parametrize("action", sorted(KNOWN_ACTIONS - {"other"}))
def test_each_action_reads_in_both_voices_with_its_evidence(action: str) -> None:
    obj = "OBJECT-VALUE"
    active = phrase_event(_event(action=action, object=obj))
    passive = phrase_event(_event(action=action, object=obj, principal=None))
    bare = phrase_event(_event(action=action, object=None, principal=None))
    assert "CORP\\jdoe" in active
    assert "CORP\\jdoe" not in passive
    if action not in _NO_OBJECT:
        assert obj in active and obj in passive
    assert "None" not in bare and obj not in bare
    for sentence in (active, passive, bare):
        assert sentence.endswith(".") and not sentence.endswith("..")
        assert sentence[:1].isupper() or sentence.startswith(("CORP", obj))


@pytest.mark.parametrize(
    ("overrides", "expected"),
    [
        ({}, "CORP\\jdoe started C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe."),
        ({"principal": None, "object": "powershell.exe"}, "powershell.exe started."),
        ({"principal": "jdoe", "object": None}, "jdoe started a process."),
        (
            {"action": "logon", "principal": "CORP\\svc-backup", "object": "10.4.12.66"},
            "CORP\\svc-backup logged on from 10.4.12.66.",
        ),
        ({"action": "logon", "principal": None, "object": None}, "An account logged on."),
        (
            {"action": "logon_failure", "object": "10.4.12.66"},
            "A logon as CORP\\jdoe failed from 10.4.12.66.",
        ),
        (
            {"action": "service_install", "principal": None, "object": "WinHelpSvc"},
            "Service WinHelpSvc was installed.",
        ),
        (
            {"action": "log_clear", "principal": "CORP\\svc-backup", "object": "Security"},
            "CORP\\svc-backup cleared the Security event log.",
        ),
        (
            {"action": "log_clear", "principal": None, "object": "Security"},
            "The Security event log was cleared.",
        ),
        (
            {"action": "process_access", "principal": None, "object": "lsass.exe"},
            "A process accessed lsass.exe.",
        ),
        (
            {"action": "dns_query", "principal": None, "object": "evil.example."},
            "evil.example. was resolved.",
        ),
        (
            {"action": "network_connect", "object": "sync-update.example."},
            "CORP\\jdoe connected to sync-update.example.",
        ),
    ],
)
def test_sentences(overrides: dict[str, Any], expected: str) -> None:
    assert phrase_event(_event(**overrides)) == expected


def test_other_events_read_from_their_own_message() -> None:
    assert phrase_event(_event(action="other")) == "CORP\\jdoe: Rule title from the source."
    assert phrase_event(_event(action="other", principal=None, message="Ends here.")) == (
        "Ends here."
    )


def test_an_action_without_a_template_is_phrased_from_its_verb() -> None:
    assert phrase_event(_event(action="wmi_subscription_create", object="Updater")) == (
        "CORP\\jdoe performed wmi subscription create on Updater."
    )
    assert phrase_event(_event(action="token_theft", principal=None, object=None)) == (
        "An actor performed token theft."
    )


_EVIDENCE = (
    st.text(
        alphabet=st.characters(categories=("L", "N"), include_characters="\\_-.:$ "),
        min_size=1,
        max_size=30,
    )
    .map(str.strip)
    .filter(bool)
)


@given(principal=_EVIDENCE, obj=_EVIDENCE, action=st.sampled_from(sorted(KNOWN_ACTIONS)))
def test_property_evidence_is_reproduced_exactly(principal: str, obj: str, action: str) -> None:
    sentence = phrase_event(_event(action=action, principal=principal, object=obj))
    assert principal in sentence
    if action not in _NO_OBJECT | {"other"}:
        assert obj in sentence
