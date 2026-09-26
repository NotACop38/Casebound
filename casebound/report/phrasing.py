"""Deterministic phrasing: one readable sentence per event, built from its fields.

The verified narrative never shows a language model's prose (AGENTS.md prime
directive). It shows, for each event a model's verified claim cited, a sentence
this module composes from that event's canonical fields alone: the principal, the
action verb, and the object. The model decides which events the story needs and in
what order; every word of fact in the sentence comes from the evidence.

Each canonical action has a template in two voices: active, when the event names
its principal ("CORP\\jdoe started powershell.exe"), and passive, when it does not
("Service WinHelpSvc was installed"). A missing object falls back to a generic noun
("a process") rather than being invented. An action with no template is phrased
generically from its verb, and ``other`` falls back to the event's own message,
which is the source's deterministic summary (for Hayabusa, the rule title).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

from dataclasses import dataclass

from casebound.normalize.schema import Event

__all__ = ["phrase_event"]


@dataclass(frozen=True)
class _Template:
    """How one action reads: active and passive forms, and how its object renders.

    ``object_format`` wraps a present object ("the {} event log"); ``noun`` stands
    in for a null object ("a process").
    """

    active: str
    passive: str
    noun: str
    object_format: str = "{}"


_TEMPLATES: dict[str, _Template] = {
    "process_create": _Template("{principal} started {object}", "{object} started", "a process"),
    "process_terminate": _Template("{principal} ended {object}", "{object} ended", "a process"),
    "process_access": _Template(
        "{principal} accessed process {object}", "A process accessed {object}", "another process"
    ),
    "remote_thread_create": _Template(
        "{principal} created a thread in {object}",
        "A thread was created in {object}",
        "another process",
    ),
    "logon": _Template("{principal} logged on{source}", "An account logged on{source}", ""),
    "logon_failure": _Template(
        "A logon as {principal} failed{source}", "A logon failed{source}", ""
    ),
    "logoff": _Template("{principal} logged off", "An account logged off", ""),
    "file_create": _Template("{principal} created {object}", "{object} was created", "a file"),
    "file_write": _Template("{principal} wrote {object}", "{object} was written", "a file"),
    "file_read": _Template("{principal} accessed {object}", "{object} was accessed", "a file"),
    "file_delete": _Template("{principal} deleted {object}", "{object} was deleted", "a file"),
    "file_rename": _Template("{principal} renamed {object}", "{object} was renamed", "a file"),
    "file_metadata_change": _Template(
        "{principal} changed the file record of {object}",
        "The file record of {object} changed",
        "a file",
    ),
    "registry_set": _Template(
        "{principal} set registry value {object}",
        "Registry value {object} was set",
        "a registry value",
    ),
    "registry_delete": _Template(
        "{principal} deleted registry value {object}",
        "Registry value {object} was deleted",
        "a registry value",
    ),
    "service_install": _Template(
        "{principal} installed service {object}", "Service {object} was installed", "a service"
    ),
    "service_control": _Template(
        "{principal} changed the state of service {object}",
        "Service {object} changed state",
        "a service",
    ),
    "scheduled_task_create": _Template(
        "{principal} created scheduled task {object}",
        "Scheduled task {object} was created",
        "a scheduled task",
    ),
    "network_connect": _Template(
        "{principal} connected to {object}",
        "A connection was made to {object}",
        "a remote host",
    ),
    "network_listen": _Template(
        "{principal} listened on {object}", "A listener opened on {object}", "a port"
    ),
    "network_share_access": _Template(
        "{principal} accessed share {object}", "Share {object} was accessed", "a network share"
    ),
    "account_create": _Template(
        "{principal} created account {object}", "Account {object} was created", "an account"
    ),
    "account_modify": _Template(
        "{principal} modified account {object}", "Account {object} was modified", "an account"
    ),
    "privilege_use": _Template(
        "{principal} used privileges on {object}", "Privileges were used on {object}", "a resource"
    ),
    "dns_query": _Template("{principal} resolved {object}", "{object} was resolved", "a name"),
    "log_clear": _Template(
        "{principal} cleared {object}",
        "{object} was cleared",
        "an event log",
        object_format="the {} event log",
    ),
}


def _capitalize(sentence: str) -> str:
    """Upper-case the first character of template text.

    Callers use this only when the sentence starts with template wording: an
    evidence value (an account, a path) is never re-cased, since ``jdoe`` and
    ``Jdoe`` are different facts to a reader.
    """
    return sentence[:1].upper() + sentence[1:] if sentence else sentence


def _generic(event: Event) -> str:
    """Phrase an action with no template from its verb, or from the message."""
    if event.action == "other":
        if event.principal:
            return f"{event.principal}: {event.message}"
        return event.message
    verb = event.action.replace("_", " ")
    actor = event.principal if event.principal else "An actor"
    target = f" on {event.object}" if event.object else ""
    return f"{actor} performed {verb}{target}"


def _finish(sentence: str) -> str:
    """End a sentence with a period, never altering evidence that already ends in one.

    A value such as the fully qualified name ``evil.example.`` keeps its own dot, so
    the sentence ends with it rather than losing a character of evidence.
    """
    return sentence if sentence.endswith(".") else sentence + "."


def phrase_event(event: Event) -> str:
    """Return one sentence describing ``event``, built only from its canonical fields.

    The sentence ends with a period. It never contains anything that is not one of
    the event's own fields (principal, action, object, or, for an ``other`` event,
    its message), so it can be shown as a verified fact about the event.
    """
    template = _TEMPLATES.get(event.action)
    if template is None:
        return _finish(_generic(event))
    obj = template.object_format.format(event.object) if event.object else template.noun
    source = f" from {event.object}" if event.object else ""
    form = template.active if event.principal else template.passive
    sentence = form.format(principal=event.principal or "", object=obj, source=source)
    # Capitalize only template wording: a sentence that opens with the principal,
    # or with a present object, opens with evidence and keeps its exact spelling.
    opens_with_evidence = form.startswith("{principal}") or (
        form.startswith("{object}") and event.object is not None and template.object_format == "{}"
    )
    return _finish(sentence if opens_with_evidence else _capitalize(sentence))
