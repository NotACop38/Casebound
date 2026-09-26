"""Tests for the narrative providers (PRD FR27, FR36, FR37, R8).

The load-bearing properties:

  1. Selection is explicit: no provider means no narrative; a cloud provider needs
     consent; a misconfiguration is a clear ``ProviderConfigError``.
  2. The fence holds on the wire: the local path sends the compact view, the cloud
     paths send the redacted view, and a cloud revision round never carries a value
     redaction stripped. No provider ever sees ``details`` (Hard rule 4).
  3. Each provider asks for claim-schema JSON where its API supports it, and turns
     every failure (an SDK error, a refusal, a truncated answer, an empty response)
     into a ``ProviderError`` with any key scrubbed from the message (FR37).
  4. The requests match the pinned SDKs: a contract check against the real
     ``anthropic`` and ``openai`` signatures fails if an SDK bump drops a
     parameter the providers send.

No network and no API keys: every client is a fake; the real SDKs are only
inspected, never called.
"""

from __future__ import annotations

import inspect
import json
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import jsonschema
import pytest

import casebound.narrate.llm as llm
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.narrate.llm import (
    DEFAULT_ANTHROPIC_MODEL,
    DEFAULT_LOCAL_BASE_URL,
    DEFAULT_MAX_TOKENS,
    AnthropicProvider,
    CloudConsentError,
    LocalProvider,
    OpenAIProvider,
    ProviderConfigError,
    ProviderError,
    build_model_from_env,
    build_prompt,
    claims_schema,
)
from casebound.narrate.redact import RedactionConfig
from casebound.normalize import Event, normalize_records
from casebound.verify import DraftRequest, build_event_view, parse_claims, verify_narrative
from casebound.verify.checks import RejectionReason
from casebound.verify.engine import RevisionRequest

# An opaque stand-in for a key. It is not key-shaped, so the secret scan stays quiet.
OPAQUE = "opaque-test-credential-value"


@pytest.fixture(scope="module")
def events(tmp_path_factory: pytest.TempPathFactory) -> list[Event]:
    csv_path, _ = write_samples(tmp_path_factory.mktemp("scenario"))
    return list(normalize_records(HayabusaAdapter().read(csv_path)).events)


@pytest.fixture(scope="module")
def jdoe_event(events: list[Event]) -> Event:
    return next(e for e in events if e.action == "process_create" and e.principal == "CORP\\jdoe")


def _request(events: list[Event], **kwargs: Any) -> DraftRequest:
    return DraftRequest(events=build_event_view(events), round_index=0, **kwargs)


# Fake clients that record exactly what a provider sends.


class FakeAnthropicClient:
    def __init__(self, message: Any = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.message = message or _anthropic_message('{"claims": []}')
        self.error = error
        self.beta = SimpleNamespace(messages=SimpleNamespace(stream=self._stream))

    @contextmanager
    def _stream(self, **kwargs: Any) -> Iterator[Any]:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        yield SimpleNamespace(get_final_message=lambda: self.message)


def _anthropic_message(
    text: str, stop_reason: str = "end_turn", blocks: list[Any] | None = None, **extra: Any
) -> Any:
    content = blocks if blocks is not None else [SimpleNamespace(type="text", text=text)]
    return SimpleNamespace(content=content, stop_reason=stop_reason, **extra)


class FakeOpenAIClient:
    def __init__(self, response: Any = None, error: Exception | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.response = response or _openai_response('{"claims": []}')
        self.error = error
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs: Any) -> Any:
        self.calls.append(kwargs)
        if self.error is not None:
            raise self.error
        return self.response


def _openai_response(
    content: str | None, finish_reason: str = "stop", refusal: str | None = None
) -> Any:
    message = SimpleNamespace(content=content, refusal=refusal)
    return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason=finish_reason)])


# 1. Selection.


@pytest.mark.parametrize("value", [None, "", "none", "off", "No"])
def test_no_provider_means_no_narrative(value: str | None) -> None:
    env = {} if value is None else {"CASEBOUND_PROVIDER": value}
    assert build_model_from_env(env) is None


def test_local_provider_needs_a_model_and_defaults_to_ollama() -> None:
    with pytest.raises(ProviderConfigError, match="CASEBOUND_LOCAL_MODEL"):
        build_model_from_env({"CASEBOUND_PROVIDER": "local"})
    model = build_model_from_env({"CASEBOUND_PROVIDER": "local", "CASEBOUND_LOCAL_MODEL": "m"})
    assert isinstance(model, LocalProvider)
    assert (model.model, model.base_url, model.max_tokens) == ("m", DEFAULT_LOCAL_BASE_URL, None)
    assert model.api_key == "local"  # pragma: allowlist secret
    keyed = build_model_from_env(
        {
            "CASEBOUND_PROVIDER": "local",
            "CASEBOUND_LOCAL_MODEL": "m",
            "CASEBOUND_LOCAL_API_KEY": OPAQUE,
            "CASEBOUND_LOCAL_BASE_URL": "http://127.0.0.1:8000/v1",
        }
    )
    assert isinstance(keyed, LocalProvider)
    assert (keyed.api_key, keyed.base_url) == (OPAQUE, "http://127.0.0.1:8000/v1")
    assert OPAQUE not in repr(keyed)


@pytest.mark.parametrize("provider", ["anthropic", "openai"])
def test_cloud_providers_need_consent(provider: str) -> None:
    env = {
        "CASEBOUND_PROVIDER": provider,
        "ANTHROPIC_API_KEY": OPAQUE,
        "OPENAI_API_KEY": OPAQUE,
        "CASEBOUND_OPENAI_MODEL": "m",
    }
    with pytest.raises(CloudConsentError) as excinfo:
        build_model_from_env(env)
    assert OPAQUE not in str(excinfo.value)
    assert build_model_from_env(env, allow_cloud=True) is not None
    assert build_model_from_env({**env, "CASEBOUND_ALLOW_CLOUD": "1"}) is not None


def test_anthropic_defaults() -> None:
    env = {"CASEBOUND_PROVIDER": "anthropic", "ANTHROPIC_API_KEY": OPAQUE}
    model = build_model_from_env(env, allow_cloud=True)
    assert isinstance(model, AnthropicProvider)
    assert model.model == DEFAULT_ANTHROPIC_MODEL == "claude-opus-5"
    assert model.max_tokens == DEFAULT_MAX_TOKENS
    assert model.structured and model.fallbacks
    assert OPAQUE not in repr(model)


def test_environment_toggles_are_honored() -> None:
    env = {
        "CASEBOUND_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": OPAQUE,
        "CASEBOUND_ANTHROPIC_MODEL": "claude-sonnet-5",
        "CASEBOUND_ANTHROPIC_FALLBACKS": "0",
        "CASEBOUND_STRUCTURED_OUTPUT": "0",
        "CASEBOUND_MAX_OUTPUT_TOKENS": "8000",
        "CASEBOUND_REDACT_HOST": "1",
    }
    model = build_model_from_env(env, allow_cloud=True)
    assert isinstance(model, AnthropicProvider)
    assert (model.model, model.max_tokens) == ("claude-sonnet-5", 8000)
    assert not model.structured and not model.fallbacks
    assert model.redaction.strip_host


@pytest.mark.parametrize(
    ("env", "match"),
    [
        ({"CASEBOUND_PROVIDER": "gemini"}, "unknown provider"),
        ({"CASEBOUND_PROVIDER": "openai", "OPENAI_API_KEY": OPAQUE}, "CASEBOUND_OPENAI_MODEL"),
        ({"CASEBOUND_PROVIDER": "anthropic"}, "ANTHROPIC_API_KEY"),
        (
            {
                "CASEBOUND_PROVIDER": "local",
                "CASEBOUND_LOCAL_MODEL": "m",
                "CASEBOUND_MAX_OUTPUT_TOKENS": "lots",
            },
            "positive integer",
        ),
        (
            {
                "CASEBOUND_PROVIDER": "local",
                "CASEBOUND_LOCAL_MODEL": "m",
                "CASEBOUND_MAX_OUTPUT_TOKENS": "0",
            },
            "positive integer",
        ),
    ],
)
def test_misconfiguration_is_a_clear_error(env: dict[str, str], match: str) -> None:
    with pytest.raises(ProviderConfigError, match=match):
        build_model_from_env(env, allow_cloud=True)


def test_a_missing_sdk_names_the_install(monkeypatch: pytest.MonkeyPatch) -> None:
    def missing(name: str) -> Any:
        raise ModuleNotFoundError(name)

    monkeypatch.setattr(llm, "importlib", SimpleNamespace(import_module=missing))
    provider = AnthropicProvider(api_key=OPAQUE)
    with pytest.raises(ProviderConfigError, match=r'pip install "casebound\[anthropic\]"'):
        provider.draft(DraftRequest(events=(), round_index=0))


# 2. The fence on the wire.


def test_prompt_serializes_the_view_one_event_per_line(events: list[Event]) -> None:
    prompt = build_prompt(_request(events, total_events=len(events) + 5))
    lines = prompt.user.splitlines()
    assert lines[0] == f"Timeline events ({len(events)}, one JSON object per line):"
    views = [json.loads(line) for line in lines[1 : 1 + len(events)]]
    assert {view["event_id"] for view in views} == {event.event_id for event in events}
    assert "5 lower-priority events of this case are not shown" in prompt.user
    assert "details" not in prompt.user
    assert "Return only JSON" in prompt.system


def test_local_provider_sends_the_full_view(events: list[Event], jdoe_event: Event) -> None:
    client = FakeOpenAIClient()
    LocalProvider(model="m", client=client).draft(_request(events))
    assert "CORP\\\\jdoe" in client.calls[0]["messages"][1]["content"]
    assert "max_tokens" not in client.calls[0]
    LocalProvider(model="m", max_tokens=123, client=client).draft(_request(events))
    assert client.calls[1]["max_tokens"] == 123


@pytest.mark.parametrize("provider_name", ["anthropic", "openai"])
def test_cloud_providers_send_the_redacted_view(events: list[Event], provider_name: str) -> None:
    if provider_name == "anthropic":
        anthropic_client = FakeAnthropicClient()
        AnthropicProvider(api_key=OPAQUE, client=anthropic_client).draft(_request(events))
        sent = json.dumps(anthropic_client.calls[0])
    else:
        openai_client = FakeOpenAIClient()
        OpenAIProvider(api_key=OPAQUE, model="m", client=openai_client).draft(_request(events))
        sent = json.dumps(openai_client.calls[0])
    assert "jdoe" not in sent.lower()
    assert "203.0.113.77" not in sent
    assert "[redacted]" in sent
    assert OPAQUE not in sent


def test_cloud_revision_round_never_carries_a_stripped_value(
    events: list[Event], jdoe_event: Event
) -> None:
    # The model misattributes a real event every round. The rejection detail goes
    # back to the model as a revision hint, and must not quote the event's real
    # principal, which the redaction pass stripped (FR36, Hard rule 2).
    bad = json.dumps(
        {
            "claims": [
                {
                    "text": "The domain administrator launched the payload.",
                    "citations": [jdoe_event.event_id],
                    "asserts": {"principal": "CORP\\Administrator"},
                }
            ]
        }
    )
    client = FakeAnthropicClient(message=_anthropic_message(bad))
    result = verify_narrative(
        events, AnthropicProvider(api_key=OPAQUE, client=client), max_rounds=1
    )
    assert result.accepted == ()
    revision = json.dumps(client.calls[1])
    assert "These claims were rejected" in revision
    assert "Administrator" in revision
    assert "jdoe" not in revision.lower()


# 3. Structured output and failure handling.


def test_claims_schema_is_strict_and_valid() -> None:
    schema = claims_schema()
    jsonschema.Draft202012Validator.check_schema(schema)
    assert not any(key.startswith("$") for key in schema)
    claim = schema["properties"]["claims"]["items"]
    assert claim["additionalProperties"] is False
    assert set(claim["required"]) == set(claim["properties"])
    asserts = claim["properties"]["asserts"]
    assert set(asserts["required"]) == {"datetime", "principal", "action", "object"}


def test_a_schema_shaped_answer_parses_into_claims(jdoe_event: Event) -> None:
    answer = {
        "claims": [
            {
                "text": "jdoe started PowerShell.",
                "citations": [jdoe_event.event_id],
                "asserts": {
                    "datetime": jdoe_event.datetime,
                    "principal": jdoe_event.principal,
                    "action": None,
                    "object": None,
                },
                "revises": None,
            }
        ]
    }
    jsonschema.validate(answer, claims_schema())
    [claim] = parse_claims(json.dumps(answer))
    assert claim.asserts.asserted_fields() == ("datetime", "principal")


def test_anthropic_request_shape(events: list[Event]) -> None:
    client = FakeAnthropicClient()
    AnthropicProvider(api_key=OPAQUE, client=client).draft(_request(events))
    [kwargs] = client.calls
    assert kwargs["model"] == DEFAULT_ANTHROPIC_MODEL
    assert kwargs["max_tokens"] == DEFAULT_MAX_TOKENS
    assert kwargs["output_config"] == {"format": {"type": "json_schema", "schema": claims_schema()}}
    assert kwargs["fallbacks"] == "default"
    assert kwargs["betas"] == ["server-side-fallback-2026-07-01"]
    assert kwargs["messages"][0]["role"] == "user"
    assert "temperature" not in kwargs


def test_anthropic_toggles_remove_structured_output_and_fallbacks(events: list[Event]) -> None:
    client = FakeAnthropicClient()
    AnthropicProvider(api_key=OPAQUE, structured=False, fallbacks=False, client=client).draft(
        _request(events)
    )
    [kwargs] = client.calls
    assert "output_config" not in kwargs
    assert "fallbacks" not in kwargs and "betas" not in kwargs


def test_anthropic_reads_only_text_blocks() -> None:
    blocks = [
        SimpleNamespace(type="thinking", thinking=""),
        SimpleNamespace(type="fallback"),
        SimpleNamespace(type="text", text='{"claims": '),
        SimpleNamespace(type="text", text="[]}"),
    ]
    client = FakeAnthropicClient(message=_anthropic_message("", blocks=blocks))
    text = AnthropicProvider(api_key=OPAQUE, client=client).draft(
        DraftRequest(events=(), round_index=0)
    )
    assert text == '{"claims": []}'


@pytest.mark.parametrize(
    ("message", "match"),
    [
        (
            _anthropic_message(
                "", stop_reason="refusal", stop_details=SimpleNamespace(category="cyber")
            ),
            "declined the request \\(category: cyber\\)",
        ),
        (_anthropic_message("", stop_reason="refusal"), "category: unspecified"),
        (_anthropic_message("{", stop_reason="max_tokens"), "CASEBOUND_MAX_OUTPUT_TOKENS"),
    ],
)
def test_anthropic_refusal_and_truncation_are_provider_errors(message: Any, match: str) -> None:
    client = FakeAnthropicClient(message=message)
    with pytest.raises(ProviderError, match=match):
        AnthropicProvider(api_key=OPAQUE, client=client).draft(
            DraftRequest(events=(), round_index=0)
        )


@pytest.mark.parametrize(
    ("response", "match"),
    [
        (_openai_response(None, refusal="I can't help with that"), "declined the request"),
        (_openai_response("{", finish_reason="length"), "output limit"),
        (SimpleNamespace(choices=[]), "no completion"),
    ],
)
def test_openai_refusal_truncation_and_empty_are_provider_errors(response: Any, match: str) -> None:
    client = FakeOpenAIClient(response=response)
    with pytest.raises(ProviderError, match=match):
        OpenAIProvider(api_key=OPAQUE, model="m", client=client).draft(
            DraftRequest(events=(), round_index=0)
        )


def test_openai_request_shape(events: list[Event]) -> None:
    client = FakeOpenAIClient()
    OpenAIProvider(api_key=OPAQUE, model="m", max_tokens=900, client=client).draft(_request(events))
    [kwargs] = client.calls
    assert kwargs["max_completion_tokens"] == 900
    assert kwargs["response_format"]["type"] == "json_schema"
    assert kwargs["response_format"]["json_schema"]["strict"] is True
    assert [message["role"] for message in kwargs["messages"]] == ["system", "user"]


class _StatusError(Exception):
    status_code = 401


@pytest.mark.parametrize("provider_name", ["anthropic", "openai", "local"])
def test_sdk_failures_become_provider_errors_with_keys_scrubbed(provider_name: str) -> None:
    error = _StatusError(f"invalid key {OPAQUE}; also saw sk-proj-abcdef123456 in the header")
    request = DraftRequest(events=(), round_index=0)
    provider: Any
    if provider_name == "anthropic":
        provider = AnthropicProvider(api_key=OPAQUE, client=FakeAnthropicClient(error=error))
    elif provider_name == "openai":
        provider = OpenAIProvider(api_key=OPAQUE, model="m", client=FakeOpenAIClient(error=error))
    else:
        provider = LocalProvider(model="m", api_key=OPAQUE, client=FakeOpenAIClient(error=error))
    with pytest.raises(ProviderError) as excinfo:
        provider.draft(request)
    message = str(excinfo.value)
    assert "(HTTP 401)" in message
    assert OPAQUE not in message
    assert "sk-proj-abcdef123456" not in message
    assert "[redacted]" in message


def test_revision_request_is_rendered_for_the_model(events: list[Event]) -> None:
    revision = RevisionRequest(
        claim_id="c0",
        claim_text="misattributed",
        citations=(events[0].event_id,),
        reason=RejectionReason.PRINCIPAL_MISMATCH,
        detail="asserted principal 'CORP\\Administrator' does not match",
    )
    prompt = build_prompt(_request(events, revisions=(revision,)), redaction=RedactionConfig())
    assert '"claim_id":"c0"' in prompt.user
    assert "setting 'revises' to its claim_id" in prompt.user


# 4. Contract checks against the pinned SDKs.


def test_requests_match_the_pinned_anthropic_sdk(events: list[Event]) -> None:
    anthropic = pytest.importorskip("anthropic")
    client = FakeAnthropicClient()
    AnthropicProvider(api_key=OPAQUE, client=client).draft(_request(events))
    real = anthropic.Anthropic(api_key=OPAQUE)
    accepted = set(inspect.signature(real.beta.messages.stream).parameters)
    assert set(client.calls[0]) <= accepted


def test_requests_match_the_pinned_openai_sdk(events: list[Event]) -> None:
    openai = pytest.importorskip("openai")
    client = FakeOpenAIClient()
    OpenAIProvider(api_key=OPAQUE, model="m", max_tokens=10, client=client).draft(_request(events))
    LocalProvider(model="m", max_tokens=10, client=client).draft(_request(events))
    real = openai.OpenAI(api_key=OPAQUE, base_url="http://localhost:1/v1")
    accepted = set(inspect.signature(real.chat.completions.create).parameters)
    for call in client.calls:
        assert set(call) <= accepted


def test_real_clients_are_built_lazily_without_a_request(tmp_path: Path) -> None:
    pytest.importorskip("anthropic")
    pytest.importorskip("openai")
    anthropic_provider = AnthropicProvider(api_key=OPAQUE)
    assert anthropic_provider.client is None
    assert anthropic_provider._resolve_client() is not None
    local = LocalProvider(model="m")
    assert local.client is None
    assert local._resolve_client() is not None
