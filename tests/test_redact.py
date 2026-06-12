"""Tests for the cloud redaction pass (PRD D5, FR36).

The redaction pass is what makes the opt-in cloud path safe: before any event view
leaves the host it strips the free-text message, the username principal, and obvious
indicators in the object, keeping only the non-sensitive addressable fields. These
tests assert each redacted field is absent from the serialized result and that the
addressable fields the verifier needs survive, plus that every toggle is honored.

No network, no API keys.
"""

from __future__ import annotations

import json

from casebound.enrich.ioc import find_indicators
from casebound.narrate.redact import RedactionConfig, redact_view
from casebound.verify.engine import EventView


def _view(**overrides: str | None) -> EventView:
    base: dict[str, str | None] = {
        "event_id": "a" * 64,
        "datetime": "2026-03-14T08:42:17Z",
        "host": "WIN-ACCT-07",
        "principal": "CORP\\jdoe",
        "action": "network_connect",
        "object": "http://10.10.10.5:443/beacon",
        "message": "CORP\\jdoe beaconed out to 10.10.10.5",
    }
    base.update(overrides)
    return EventView(**base)  # type: ignore[arg-type]


def test_find_indicators_locates_ip_and_path() -> None:
    found = dict(find_indicators("connect to 10.0.0.1 from C:\\tools\\agent.exe"))
    assert found["ip"] == "10.0.0.1"
    assert found["path"] == "C:\\tools\\agent.exe"


def test_redact_view_strips_message_principal_and_iocs() -> None:
    redacted = redact_view(_view(), RedactionConfig())
    blob = json.dumps(redacted)

    # The sensitive content D5 names is gone.
    assert "jdoe" not in blob
    assert "10.10.10.5" not in blob
    assert "beaconed" not in blob
    # The non-sensitive addressable fields the verifier needs survive.
    assert redacted["event_id"] == "a" * 64
    assert redacted["datetime"] == "2026-03-14T08:42:17Z"
    assert redacted["action"] == "network_connect"
    # host is kept by default (not in the D5 strip list).
    assert redacted["host"] == "WIN-ACCT-07"


def test_redact_view_strips_username_embedded_in_a_path() -> None:
    # A whole-path object carries the username in the path; redaction removes it.
    redacted = redact_view(
        _view(object="C:\\Users\\jdoe\\AppData\\evil.exe", message="x"),
        RedactionConfig(),
    )
    assert "jdoe" not in json.dumps(redacted)


def test_redact_view_strips_host_when_configured() -> None:
    redacted = redact_view(_view(), RedactionConfig(strip_host=True))
    assert redacted["host"] == "[redacted]"


def test_redaction_toggles_off_keep_content() -> None:
    config = RedactionConfig(
        strip_message=False,
        strip_principal=False,
        strip_iocs=False,
    )
    blob = json.dumps(redact_view(_view(object="C:\\Users\\jdoe\\evil.exe"), config))
    # With every toggle off nothing is stripped.
    assert "jdoe" in blob
    assert "10.10.10.5" in blob
    assert "beaconed" in blob


def test_redaction_config_from_env() -> None:
    config = RedactionConfig.from_env({"CASEBOUND_REDACT_HOST": "1", "CASEBOUND_REDACT_IOCS": "0"})
    assert config.strip_host is True
    assert config.strip_iocs is False
    # Unset toggles keep their conservative defaults.
    assert config.strip_message is True
    assert config.strip_principal is True


def test_redact_view_does_not_mutate_the_input() -> None:
    view = _view()
    redact_view(view, RedactionConfig())
    # The frozen view is unchanged: redaction returns a new dict.
    assert view.principal == "CORP\\jdoe"
    assert view.message == "CORP\\jdoe beaconed out to 10.10.10.5"


def test_kept_message_still_strips_indicators_and_usernames() -> None:
    # The IOC and username toggles govern their content class in every kept text
    # field: an operator who keeps the message must not silently keep the
    # indicators and usernames inside it.
    from casebound.narrate.redact import RedactionConfig, redact_view
    from casebound.verify.engine import EventView

    view = EventView(
        event_id="c" * 64,
        datetime="2026-03-14T08:42:17Z",
        host="WIN-ACCT-07",
        principal="CORP\\jdoe",
        action="network_connect",
        object=None,
        message="CORP\\jdoe beaconed out to 10.10.10.5",
    )
    payload = redact_view(view, RedactionConfig(strip_message=False))

    message = payload["message"]
    assert "jdoe" not in message
    assert "10.10.10.5" not in message
    assert "beaconed out to" in message
