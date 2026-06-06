"""Tests for the provider-agnostic narrative interface (PRD FR26, FR27, FR36, FR37).

These cover the three things Phase 5 must prove:

  1. Env-driven selection (``build_model_from_env``) defaults to local, gates cloud
     behind an explicit consent flag, and returns None when nothing is configured.
  2. The cloud providers redact every event view before sending, so the redacted
     fields are absent from the cloud-bound payload, and API keys never appear in
     any output (the payload or the provider's repr).
  3. With no provider configured, a complete deterministic report is still produced
     (the no-model path).

Every test injects a fake client or uses an empty env, so there is no network call
and no API key is ever read from the real environment.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from casebound.cli import run_demo
from casebound.narrate.llm import (
    AnthropicProvider,
    CloudConsentError,
    LocalProvider,
    OpenAIProvider,
    Prompt,
    ProviderConfigError,
    build_model_from_env,
    build_prompt,
)
from casebound.verify.engine import DraftRequest, EventView, NarrativeModel

# A deliberately fake, low-entropy credential. Named to avoid tripping the secret
# scan (no "key"/"token"/"secret" in the identifier) and clearly not a real key.
OPAQUE = "fake-provider-credential-not-real"

# One event whose view carries content the cloud redaction pass must strip.
SENSITIVE_VIEW = EventView(
    event_id="b" * 64,
    datetime="2026-03-14T08:42:17Z",
    host="WIN-ACCT-07",
    principal="CORP\\jdoe",
    action="network_connect",
    object="http://10.10.10.5:443/beacon",
    message="CORP\\jdoe beaconed out to 10.10.10.5",
)


# --- Fake SDK clients (no network) -----------------------------------------------


class _AnthropicBlock:
    def __init__(self, text: str) -> None:
        self.text = text


class _AnthropicResponse:
    def __init__(self, text: str) -> None:
        self.content = [_AnthropicBlock(text)]


class _AnthropicMessages:
    def __init__(self, sink: dict[str, Any], text: str) -> None:
        self._sink = sink
        self._text = text

    def create(self, **kwargs: Any) -> _AnthropicResponse:
        self._sink["kwargs"] = kwargs
        return _AnthropicResponse(self._text)


class FakeAnthropicClient:
    """A minimal stand-in for ``anthropic.Anthropic`` that records the call."""

    def __init__(self, text: str = '{"claims": []}') -> None:
        self.calls: dict[str, Any] = {}
        self.messages = _AnthropicMessages(self.calls, text)


class _ChoiceMessage:
    def __init__(self, content: str) -> None:
        self.content = content


class _Choice:
    def __init__(self, content: str) -> None:
        self.message = _ChoiceMessage(content)


class _OpenAIResponse:
    def __init__(self, content: str) -> None:
        self.choices = [_Choice(content)]


class _Completions:
    def __init__(self, sink: dict[str, Any], text: str) -> None:
        self._sink = sink
        self._text = text

    def create(self, **kwargs: Any) -> _OpenAIResponse:
        self._sink["kwargs"] = kwargs
        return _OpenAIResponse(self._text)


class _Chat:
    def __init__(self, sink: dict[str, Any], text: str) -> None:
        self.completions = _Completions(sink, text)


class FakeOpenAIClient:
    """A minimal stand-in for ``openai.OpenAI`` that records the call."""

    def __init__(self, text: str = '{"claims": []}') -> None:
        self.calls: dict[str, Any] = {}
        self.chat = _Chat(self.calls, text)


# --- Factory: env-driven selection -----------------------------------------------


def test_no_provider_configured_returns_none() -> None:
    assert build_model_from_env({}) is None
    assert build_model_from_env({"CASEBOUND_PROVIDER": ""}) is None
    assert build_model_from_env({"CASEBOUND_PROVIDER": "none"}) is None


def test_default_provider_is_local() -> None:
    model = build_model_from_env({"CASEBOUND_PROVIDER": "local"})
    assert isinstance(model, LocalProvider)
    assert isinstance(model, NarrativeModel)
    # Built lazily: no client is constructed (so no network) until draft runs.
    assert model.client is None


def test_cloud_requires_explicit_consent_flag() -> None:
    env = {"CASEBOUND_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": OPAQUE}
    # Without consent the cloud provider is refused (FR27).
    with pytest.raises(CloudConsentError):
        build_model_from_env(env)
    # With the explicit flag it is built.
    model = build_model_from_env(env, allow_cloud=True)
    assert isinstance(model, AnthropicProvider)


def test_cloud_consent_via_env_flag() -> None:
    env = {
        "CASEBOUND_PROVIDER": "openai",
        "OPENAI_API_KEY": OPAQUE,
        "CASEBOUND_ALLOW_CLOUD": "1",
    }
    model = build_model_from_env(env)
    assert isinstance(model, OpenAIProvider)


def test_cloud_without_key_raises_config_error() -> None:
    env = {"CASEBOUND_PROVIDER": "anthropic"}
    # Consent is checked first.
    with pytest.raises(CloudConsentError):
        build_model_from_env(env)
    # With consent but no key, the misconfiguration is reported clearly.
    with pytest.raises(ProviderConfigError):
        build_model_from_env(env, allow_cloud=True)


def test_unknown_provider_raises_config_error() -> None:
    with pytest.raises(ProviderConfigError):
        build_model_from_env({"CASEBOUND_PROVIDER": "hal9000"}, allow_cloud=True)


def test_cloud_provider_uses_env_redaction_config() -> None:
    env = {
        "CASEBOUND_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": OPAQUE,
        "CASEBOUND_REDACT_HOST": "1",
    }
    model = build_model_from_env(env, allow_cloud=True)
    assert isinstance(model, AnthropicProvider)
    assert model.redaction.strip_host is True


# --- Providers: redaction, keys, and no network ----------------------------------


def test_anthropic_provider_redacts_before_send_and_hides_key() -> None:
    fake = FakeAnthropicClient()
    provider = AnthropicProvider(api_key=OPAQUE, client=fake)

    out = provider.draft(DraftRequest(events=(SENSITIVE_VIEW,), round_index=0))
    assert out == '{"claims": []}'

    payload = json.dumps(fake.calls["kwargs"])
    # The redacted fields are absent from the cloud-bound payload (FR36).
    assert "jdoe" not in payload
    assert "10.10.10.5" not in payload
    assert "beaconed" not in payload
    # The addressable fields the verifier needs survive.
    assert "b" * 64 in payload
    assert "network_connect" in payload
    # The API key never appears in the payload or the repr (FR37).
    assert OPAQUE not in payload
    assert OPAQUE not in repr(provider)
    assert OPAQUE not in str(provider)


def test_openai_provider_redacts_before_send_and_hides_key() -> None:
    fake = FakeOpenAIClient()
    provider = OpenAIProvider(api_key=OPAQUE, client=fake)

    out = provider.draft(DraftRequest(events=(SENSITIVE_VIEW,), round_index=0))
    assert out == '{"claims": []}'

    payload = json.dumps(fake.calls["kwargs"])
    assert "jdoe" not in payload
    assert "10.10.10.5" not in payload
    assert "beaconed" not in payload
    assert "b" * 64 in payload
    assert OPAQUE not in payload
    assert OPAQUE not in repr(provider)


def test_local_provider_sends_full_view_without_redaction() -> None:
    # The local endpoint runs on the host, so evidence is not redacted: the full
    # compact view (including the principal) is what the verifier later grounds.
    fake = FakeOpenAIClient()
    provider = LocalProvider(client=fake)

    out = provider.draft(DraftRequest(events=(SENSITIVE_VIEW,), round_index=0))
    assert out == '{"claims": []}'

    payload = json.dumps(fake.calls["kwargs"])
    assert "jdoe" in payload
    assert "10.10.10.5" in payload


def test_build_prompt_redaction_is_opt_in() -> None:
    request = DraftRequest(events=(SENSITIVE_VIEW,), round_index=0)
    # No redaction (local path): the full view is in the user content.
    assert "jdoe" in build_prompt(request).user
    # Redaction (cloud path) strips it.
    from casebound.narrate.redact import RedactionConfig

    redacted = build_prompt(request, redaction=RedactionConfig())
    assert isinstance(redacted, Prompt)
    assert "jdoe" not in redacted.user
    assert "network_connect" in redacted.user


# --- The no-model path: a complete report with no provider configured ------------


def test_no_provider_configured_produces_complete_report(tmp_path: Path) -> None:
    model = build_model_from_env({})
    assert model is None

    result = run_demo(tmp_path, model=model)

    # The deterministic pipeline still ran end to end.
    assert result.no_model is True
    assert result.event_count > 0
    assert result.technique_count > 0
    assert result.episode_count > 0
    assert result.accepted_count == 0
    assert result.rejected_count == 0

    html = result.report_path.read_text(encoding="utf-8")
    assert "No language model configured" in html
    assert "Deterministic timeline" in html
    assert "Activity episodes" in html
    assert "Evidence appendix" in html
    # No narrative was produced on the no-model path (FR26).
    assert 'class="claim"' not in html

    # The JSON report is complete and marks the no-model path.
    data = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert data["no_model"] is True
    assert len(data["events"]) == result.event_count
    assert data["narrative"]["accepted"] == []
