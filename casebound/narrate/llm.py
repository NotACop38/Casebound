"""Provider-agnostic narrative model interface (PRD FR27, FR36, FR37, R8).

The narrative is an optional layer over the deterministic core. This module turns a
configuration into a ``NarrativeModel`` the verifier can drive, with three
interchangeable providers and no provider hardcoded:

  - ``LocalProvider`` : an OpenAI-compatible local endpoint (for example Ollama),
    the default and recommended choice. Evidence stays on the host, so it is never
    redacted (Hard rule 2).
  - ``AnthropicProvider`` and ``OpenAIProvider`` : cloud providers, opt-in only.
    Selecting one requires an explicit consent flag, and every event view is run
    through the redaction pass before it leaves the host (PRD D5, FR36).

Selection is env-driven through ``build_model_from_env``: ``CASEBOUND_PROVIDER``
chooses the provider (``local``, ``anthropic``, ``openai``); an unset or ``none``
value means no narrative at all, so the pipeline takes the deterministic no-model
path (FR26). Local is the default provider; cloud is never reached without the
consent flag (FR27).

Keys are never logged or written: a provider's API key is excluded from its repr
and never placed in a prompt or any output (FR37). The cloud SDKs are optional and
imported lazily, so the deterministic core gains no new dependency; a provider
raises a clear error if its SDK is not installed.

The model only ever receives the compact, id-addressed event view (Hard rule 4);
the engine guarantees that, and this module never widens it.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import importlib
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from casebound.narrate.redact import RedactionConfig, env_bool, redact_view
from casebound.verify.engine import DraftRequest, NarrativeModel

__all__ = [
    "CLOUD_PROVIDERS",
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_LOCAL_BASE_URL",
    "DEFAULT_LOCAL_MODEL",
    "DEFAULT_MAX_TOKENS",
    "DEFAULT_OPENAI_MODEL",
    "PROVIDER_ANTHROPIC",
    "PROVIDER_LOCAL",
    "PROVIDER_OPENAI",
    "AnthropicProvider",
    "CloudConsentError",
    "LocalProvider",
    "OpenAIProvider",
    "Prompt",
    "ProviderConfigError",
    "ProviderError",
    "build_model_from_env",
    "build_prompt",
]

PROVIDER_LOCAL = "local"
PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"

# The providers whose calls leave the host: each is opt-in and redacted (FR36).
CLOUD_PROVIDERS = frozenset({PROVIDER_ANTHROPIC, PROVIDER_OPENAI})

# Values of CASEBOUND_PROVIDER that mean "no narrative", taking the no-model path.
_NONE_VALUES = frozenset({"", "none", "off", "no"})

# Environment variable names (documented in .env.example).
ENV_PROVIDER = "CASEBOUND_PROVIDER"
ENV_ALLOW_CLOUD = "CASEBOUND_ALLOW_CLOUD"
ENV_LOCAL_BASE_URL = "CASEBOUND_LOCAL_BASE_URL"
ENV_LOCAL_MODEL = "CASEBOUND_LOCAL_MODEL"
ENV_ANTHROPIC_MODEL = "CASEBOUND_ANTHROPIC_MODEL"
ENV_ANTHROPIC_KEY = "ANTHROPIC_API_KEY"
ENV_OPENAI_MODEL = "CASEBOUND_OPENAI_MODEL"
ENV_OPENAI_KEY = "OPENAI_API_KEY"
ENV_OPENAI_BASE_URL = "CASEBOUND_OPENAI_BASE_URL"

# Documented, overridable defaults. The local endpoint is the Ollama OpenAI-
# compatible API. The cloud model ids are sensible current defaults; both are
# overridable so this never has to chase model releases.
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
DEFAULT_LOCAL_MODEL = "llama3.1"
DEFAULT_ANTHROPIC_MODEL = "claude-sonnet-4-6"
DEFAULT_OPENAI_MODEL = "gpt-4o-mini"
DEFAULT_MAX_TOKENS = 4096

# The system prompt pins the claim-and-citation contract from docs/verification.md.
_SYSTEM_PROMPT = (
    "You are a careful DFIR analyst drafting an investigation narrative. "
    "You are shown only a compact, id-addressed view of timeline events; you never "
    "see raw evidence. Write the narrative as a sequence of factual claims. Every "
    "claim must cite one or more event_id values from the view and must commit, in "
    "an 'asserts' block, to the exact facts it states. Only four fields are checked: "
    "datetime, principal, action, and object. Do not state any fact in prose that "
    "you did not also put in 'asserts', and never assert a fact the view does not "
    "show. A deterministic verifier checks every claim against its cited event and "
    "drops anything it cannot confirm, so unsupported prose is wasted.\n\n"
    "Return only a JSON object of exactly this shape, with no prose around it:\n"
    '{"claims": [{"text": "<readable sentence>", '
    '"citations": ["<event_id>"], '
    '"asserts": {"datetime": "<utc>", "principal": "<account>", '
    '"action": "<verb>", "object": "<target>"}}]}\n'
    "Include in 'asserts' only the fields you are committing to. On a revision "
    "round, each fixed claim must echo the claim_id it revises in a 'revises' field."
)


class ProviderError(RuntimeError):
    """Base class for a narrative-provider configuration or runtime problem."""


class ProviderConfigError(ProviderError):
    """The selected provider is misconfigured (unknown name, missing key or SDK)."""


class CloudConsentError(ProviderError):
    """A cloud provider was selected without the explicit consent flag (FR27)."""


@dataclass(frozen=True)
class Prompt:
    """A built prompt: the system instruction and the user message for one round."""

    system: str
    user: str


def build_prompt(request: DraftRequest, *, redaction: RedactionConfig | None = None) -> Prompt:
    """Build the model prompt for one round from the compact event view.

    When ``redaction`` is given (the cloud path), every event view is run through it
    before serialization, so sensitive fields never enter the cloud-bound payload
    (PRD D5, FR36). With no redaction (the local path) the full compact view is
    sent, since evidence stays on the host.
    """
    if redaction is not None:
        events_payload = [redact_view(view, redaction) for view in request.events]
    else:
        events_payload = [view.to_dict() for view in request.events]

    lines = [
        "Timeline events (compact, id-addressed view):",
        json.dumps(events_payload, indent=2, ensure_ascii=False),
    ]
    if request.revisions:
        lines.append("")
        lines.append("Revise these rejected claims and echo each claim_id in a 'revises' field:")
        lines.append(
            json.dumps([rev.to_dict() for rev in request.revisions], indent=2, ensure_ascii=False)
        )
    return Prompt(system=_SYSTEM_PROMPT, user="\n".join(lines))


def _load_sdk(module_name: str) -> Any:
    """Import an optional provider SDK lazily, with a clear error when it is absent."""
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise ProviderConfigError(
            f"the '{module_name}' package is required for this provider; "
            f"install it with 'pip install {module_name}'"
        ) from exc


def _openai_chat(client: Any, model: str, prompt: Prompt, max_tokens: int) -> str:
    """Call an OpenAI-compatible chat-completions endpoint and return the raw text."""
    response = client.chat.completions.create(
        model=model,
        max_tokens=max_tokens,
        messages=[
            {"role": "system", "content": prompt.system},
            {"role": "user", "content": prompt.user},
        ],
    )
    return str(response.choices[0].message.content)


def _anthropic_text(response: Any) -> str:
    """Join the text blocks of an Anthropic messages response into one string."""
    return "".join(str(getattr(block, "text", "")) for block in response.content)


@dataclass
class LocalProvider:
    """An OpenAI-compatible local endpoint (the default). Evidence stays on the host.

    The local path is not redacted: the endpoint runs on the operator's own machine,
    so the full compact view is sent (Hard rule 2). ``client`` can be injected for
    tests; otherwise the ``openai`` SDK is imported lazily and pointed at
    ``base_url``. No network call is made until ``draft`` runs.
    """

    model: str = DEFAULT_LOCAL_MODEL
    base_url: str = DEFAULT_LOCAL_BASE_URL
    max_tokens: int = DEFAULT_MAX_TOKENS
    # Local servers commonly ignore the key; a non-empty placeholder keeps SDKs happy.
    api_key: str = field(default="local", repr=False)
    client: Any | None = field(default=None, repr=False)

    def draft(self, request: DraftRequest) -> str:
        """Draft id-cited claims from the full compact view (no redaction)."""
        prompt = build_prompt(request, redaction=None)
        return _openai_chat(self._resolve_client(), self.model, prompt, self.max_tokens)

    def _resolve_client(self) -> Any:
        if self.client is None:
            module = _load_sdk("openai")
            self.client = module.OpenAI(base_url=self.base_url, api_key=self.api_key)
        return self.client


@dataclass
class OpenAIProvider:
    """The OpenAI cloud provider. Opt-in only; every view is redacted first (FR36)."""

    api_key: str = field(repr=False)
    model: str = DEFAULT_OPENAI_MODEL
    base_url: str | None = None
    max_tokens: int = DEFAULT_MAX_TOKENS
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    client: Any | None = field(default=None, repr=False)

    def draft(self, request: DraftRequest) -> str:
        """Redact the view, then draft id-cited claims through the OpenAI API."""
        prompt = build_prompt(request, redaction=self.redaction)
        return _openai_chat(self._resolve_client(), self.model, prompt, self.max_tokens)

    def _resolve_client(self) -> Any:
        if self.client is None:
            module = _load_sdk("openai")
            kwargs: dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self.client = module.OpenAI(**kwargs)
        return self.client


@dataclass
class AnthropicProvider:
    """The Anthropic cloud provider. Opt-in only; every view is redacted first (FR36)."""

    api_key: str = field(repr=False)
    model: str = DEFAULT_ANTHROPIC_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    client: Any | None = field(default=None, repr=False)

    def draft(self, request: DraftRequest) -> str:
        """Redact the view, then draft id-cited claims through the Anthropic API."""
        prompt = build_prompt(request, redaction=self.redaction)
        response = self._resolve_client().messages.create(
            model=self.model,
            max_tokens=self.max_tokens,
            system=prompt.system,
            messages=[{"role": "user", "content": prompt.user}],
        )
        return _anthropic_text(response)

    def _resolve_client(self) -> Any:
        if self.client is None:
            module = _load_sdk("anthropic")
            self.client = module.Anthropic(api_key=self.api_key)
        return self.client


def _require_key(env: Mapping[str, str], name: str) -> str:
    """Return a required API key from the environment, or raise a clear error."""
    key = env.get(name)
    if not key:
        raise ProviderConfigError(f"{name} is not set; a cloud provider requires its API key")
    return key


def _resolve_consent(env: Mapping[str, str], allow_cloud: bool) -> bool:
    """A cloud call needs explicit consent: the flag argument or the env opt-in."""
    return allow_cloud or env_bool(env, ENV_ALLOW_CLOUD, False)


def build_model_from_env(
    env: Mapping[str, str] | None = None, *, allow_cloud: bool = False
) -> NarrativeModel | None:
    """Build the configured narrative model from the environment, or None (FR26, FR27).

    ``CASEBOUND_PROVIDER`` selects the provider. Unset, empty, or ``none`` means no
    narrative: the caller takes the deterministic no-model path (FR26). ``local``
    (the default provider) returns a ``LocalProvider``. ``anthropic`` or ``openai``
    return a cloud provider, but only when cloud use is consented to, either through
    ``allow_cloud=True`` or ``CASEBOUND_ALLOW_CLOUD`` (FR27); otherwise this raises
    ``CloudConsentError``. A cloud provider with no API key raises
    ``ProviderConfigError``. No network call is made here; clients are built lazily.
    """
    env = os.environ if env is None else env
    raw = env.get(ENV_PROVIDER)
    if raw is None:
        return None
    provider = raw.strip().lower()
    if provider in _NONE_VALUES:
        return None

    if provider == PROVIDER_LOCAL:
        return LocalProvider(
            model=env.get(ENV_LOCAL_MODEL, DEFAULT_LOCAL_MODEL),
            base_url=env.get(ENV_LOCAL_BASE_URL, DEFAULT_LOCAL_BASE_URL),
        )

    if provider in CLOUD_PROVIDERS:
        if not _resolve_consent(env, allow_cloud):
            raise CloudConsentError(
                f"provider '{provider}' is a cloud provider; opt in with allow_cloud=True "
                f"or {ENV_ALLOW_CLOUD}=1. Event views are redacted before any cloud call."
            )
        redaction = RedactionConfig.from_env(env)
        if provider == PROVIDER_ANTHROPIC:
            return AnthropicProvider(
                api_key=_require_key(env, ENV_ANTHROPIC_KEY),
                model=env.get(ENV_ANTHROPIC_MODEL, DEFAULT_ANTHROPIC_MODEL),
                redaction=redaction,
            )
        return OpenAIProvider(
            api_key=_require_key(env, ENV_OPENAI_KEY),
            model=env.get(ENV_OPENAI_MODEL, DEFAULT_OPENAI_MODEL),
            base_url=env.get(ENV_OPENAI_BASE_URL) or None,
            redaction=redaction,
        )

    raise ProviderConfigError(
        f"unknown provider '{provider}'; expected one of: "
        f"{PROVIDER_LOCAL}, {PROVIDER_ANTHROPIC}, {PROVIDER_OPENAI}"
    )
