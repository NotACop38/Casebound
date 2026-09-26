"""Provider-agnostic narrative model interface (PRD FR27, FR36, FR37, R8).

The narrative is an optional layer over the deterministic core. This module turns
configuration into a ``NarrativeModel`` the verifier can drive, with three
interchangeable providers and no provider hardcoded:

  - ``LocalProvider``: any OpenAI-compatible server on the analyst's machine
    (Ollama, llama.cpp, vLLM, LM Studio). The default provider. Evidence stays on
    the host, so the view is not redacted (Hard rule 2).
  - ``AnthropicProvider`` and ``OpenAIProvider``: cloud providers, opt-in only.
    Selecting one requires an explicit consent flag, and every event view is run
    through the redaction pass before it leaves the host (PRD D5, FR36).

Selection is environment-driven through ``build_model_from_env``:
``CASEBOUND_PROVIDER`` chooses ``local``, ``anthropic``, or ``openai``; unset or
``none`` means no narrative, the deterministic no-model path (FR26).

Every provider asks for JSON constrained to the claim schema
(``casebound/data/claims.schema.json``) where the API supports structured output,
because a claim the parser cannot read is a claim the report cannot use; the
verifier still checks every claim regardless. Any failure of the call itself (a
network error, an HTTP error, a refusal, a truncated answer) surfaces as a
``ProviderError`` with a clear message, never as a stack trace.

API keys are never logged or written: they are excluded from provider reprs and
never placed in a prompt or an error message (FR37). The provider SDKs are
optional and imported lazily, so the deterministic core gains no dependency.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import importlib
import json
import os
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from importlib.resources import files
from typing import Any

from casebound.narrate.redact import RedactionConfig, env_bool, redact_view
from casebound.verify.engine import DraftRequest, NarrativeModel

__all__ = [
    "CLOUD_PROVIDERS",
    "DEFAULT_ANTHROPIC_MODEL",
    "DEFAULT_LOCAL_BASE_URL",
    "DEFAULT_MAX_TOKENS",
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
    "claims_schema",
]

PROVIDER_LOCAL = "local"
PROVIDER_ANTHROPIC = "anthropic"
PROVIDER_OPENAI = "openai"

# The providers whose calls leave the host: each is opt-in and redacted (FR36).
CLOUD_PROVIDERS = frozenset({PROVIDER_ANTHROPIC, PROVIDER_OPENAI})

# Values of CASEBOUND_PROVIDER that mean "no narrative", the no-model path.
_NONE_VALUES = frozenset({"", "none", "off", "no"})

# Environment variable names (documented in .env.example).
ENV_PROVIDER = "CASEBOUND_PROVIDER"
ENV_ALLOW_CLOUD = "CASEBOUND_ALLOW_CLOUD"
ENV_STRUCTURED = "CASEBOUND_STRUCTURED_OUTPUT"
ENV_LOCAL_BASE_URL = "CASEBOUND_LOCAL_BASE_URL"
ENV_LOCAL_MODEL = "CASEBOUND_LOCAL_MODEL"
ENV_LOCAL_KEY = "CASEBOUND_LOCAL_API_KEY"
ENV_ANTHROPIC_MODEL = "CASEBOUND_ANTHROPIC_MODEL"
ENV_ANTHROPIC_FALLBACKS = "CASEBOUND_ANTHROPIC_FALLBACKS"
ENV_ANTHROPIC_KEY = "ANTHROPIC_API_KEY"
ENV_OPENAI_MODEL = "CASEBOUND_OPENAI_MODEL"
ENV_OPENAI_KEY = "OPENAI_API_KEY"
ENV_OPENAI_BASE_URL = "CASEBOUND_OPENAI_BASE_URL"
ENV_MAX_OUTPUT_TOKENS = "CASEBOUND_MAX_OUTPUT_TOKENS"

# The local default is Ollama's OpenAI-compatible endpoint. There is deliberately
# no default local or OpenAI model: the right one is whatever the operator serves
# or has access to, and a stale default would fail in a confusing way.
DEFAULT_LOCAL_BASE_URL = "http://localhost:11434/v1"
DEFAULT_ANTHROPIC_MODEL = "claude-opus-5"
# The Anthropic API requires an output ceiling, and on current models it covers the
# model's thinking as well as its answer: room for a few hundred claims plus the
# reasoning. Anthropic calls stream, so a large ceiling does not risk an HTTP
# timeout. OpenAI-compatible calls send no ceiling unless one is configured, because
# the right value depends on the model and a too-large one is rejected outright.
DEFAULT_MAX_TOKENS = 64000

# Anything in a provider error message that looks like an API key is replaced with
# this before the message is shown, so a key never reaches a log (FR37).
_KEY_LIKE = re.compile(r"\b(?:sk|pk|key)-[A-Za-z0-9_*.\-]{6,}")

# Anthropic's server-side refusal fallback: a request a model's safety classifiers
# decline is re-run on the model Anthropic recommends for that refusal category.
# Security evidence (credential dumping, lateral movement) is exactly the content a
# classifier may flag, so this is on by default; set the env toggle to 0 to turn it
# off for a model that does not support it.
_ANTHROPIC_FALLBACK_BETA = "server-side-fallback-2026-07-01"

_SYSTEM_PROMPT = """\
You are a DFIR analyst writing the narrative of an investigation. You are given a \
compact, id-addressed view of timeline events, never raw evidence. Select the events \
that tell the story of what happened (initial access, execution, persistence, \
credential access, lateral movement, collection, exfiltration, defense impairment) \
and write one claim per event, in chronological order. Routine activity can be left \
out; each event's techniques and severity help you choose.

Every claim is checked by a deterministic verifier before anyone reads it:
- "citations" must contain the event_id of the event the claim is about (copy it \
exactly; a second event may be cited for context).
- "asserts" must repeat, exactly as the view shows them, the facts the claim states: \
datetime, principal, action, and object. Use null for a fact the claim does not state. \
The verifier accepts a claim only if one cited event matches every non-null fact.
- "text" is one readable sentence for the audit trail. The report never shows it as \
fact: it phrases each accepted claim from the event's own fields, so any detail that \
is not in "asserts" is discarded.
- Never assert a fact the view does not show. A claim that fails verification is \
rejected, returned to you with the reason, and dropped if it cannot be fixed.

Return only JSON: {"claims": [{"text": ..., "citations": [...], "asserts": \
{"datetime": ..., "principal": ..., "action": ..., "object": ...}, "revises": null}]}. \
On a revision round, return only the corrected claims, each with "revises" set to the \
claim_id it replaces; omit any claim the evidence cannot support."""


class ProviderError(RuntimeError):
    """Base class for a narrative-provider configuration or runtime problem."""


class ProviderConfigError(ProviderError):
    """The selected provider is misconfigured (unknown name, missing key, SDK, or model)."""


class CloudConsentError(ProviderConfigError):
    """A cloud provider was selected without the explicit consent flag (FR27)."""


@dataclass(frozen=True)
class Prompt:
    """A built prompt: the system instruction and the user message for one round."""

    system: str
    user: str


@lru_cache(maxsize=1)
def claims_schema() -> dict[str, Any]:
    """The claim-output JSON Schema, in the strict form structured output accepts."""
    text = files("casebound").joinpath("data/claims.schema.json").read_text(encoding="utf-8")
    schema: dict[str, Any] = json.loads(text)
    # Structured-output APIs take the schema body; the meta keywords are for readers.
    return {key: value for key, value in schema.items() if not key.startswith("$")}


def _compact(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def build_prompt(request: DraftRequest, *, redaction: RedactionConfig | None = None) -> Prompt:
    """Build the model prompt for one round from the compact event view.

    With ``redaction`` (the cloud path), every event view is redacted before it is
    serialized, so the stripped fields never enter the cloud-bound payload (PRD D5,
    FR36). Without it (the local path) the full compact view is sent, since evidence
    stays on the host. Events are serialized one per line to keep the prompt small.
    """
    if redaction is not None:
        views = [redact_view(view, redaction) for view in request.events]
    else:
        views = [view.to_dict() for view in request.events]

    lines = [f"Timeline events ({len(views)}, one JSON object per line):"]
    lines.extend(_compact(view) for view in views)
    if request.omitted_events:
        lines.append(
            f"({request.omitted_events} lower-priority events of this case are not shown; "
            "every shown event carries an ATT&CK technique or outranks them in severity.)"
        )
    if request.revisions:
        lines.append("")
        lines.append(
            "These claims were rejected. Correct each one the events support, setting "
            "'revises' to its claim_id, and omit the rest:"
        )
        lines.extend(_compact(revision.to_dict()) for revision in request.revisions)
    else:
        lines.append("")
        lines.append("Write the narrative as claims.")
    return Prompt(system=_SYSTEM_PROMPT, user="\n".join(lines))


def _load_sdk(module_name: str, extra: str) -> Any:
    """Import an optional provider SDK lazily, with a clear error when it is absent."""
    try:
        return importlib.import_module(module_name)
    except ModuleNotFoundError as exc:
        raise ProviderConfigError(
            f"the '{module_name}' package is required for this provider; "
            f'install it with: pip install "casebound[{extra}]"'
        ) from exc


def _call_failed(provider: str, exc: Exception, secret: str | None = None) -> ProviderError:
    """Wrap an SDK failure as a ``ProviderError``, with any key scrubbed from it (FR37).

    The message keeps the exception type, the HTTP status, and the SDK's own text,
    which is what an operator needs to fix a model name or a quota, but the
    configured key and anything shaped like a key (some APIs echo a masked key in
    an authentication error) are replaced first.
    """
    status = getattr(exc, "status_code", None)
    code = f" (HTTP {status})" if status is not None else ""
    detail = str(exc)
    if secret:
        detail = detail.replace(secret, "[redacted]")
    detail = _KEY_LIKE.sub("[redacted]", detail)
    return ProviderError(f"{provider} request failed{code}: {type(exc).__name__}: {detail}")


def _openai_response_format(structured: bool) -> dict[str, Any] | None:
    if not structured:
        return None
    return {
        "type": "json_schema",
        "json_schema": {"name": "casebound_claims", "strict": True, "schema": claims_schema()},
    }


def _openai_text(provider: str, response: Any) -> str:
    """Read an OpenAI-compatible chat completion, surfacing refusals and truncation."""
    choices = getattr(response, "choices", None) or []
    if not choices:
        raise ProviderError(f"{provider} returned no completion")
    choice = choices[0]
    refusal = getattr(choice.message, "refusal", None)
    if refusal:
        raise ProviderError(f"{provider} declined the request: {refusal}")
    if getattr(choice, "finish_reason", None) == "length":
        raise ProviderError(
            f"{provider} stopped at its output limit before finishing; "
            f"reduce --view-budget or raise {ENV_MAX_OUTPUT_TOKENS}"
        )
    return str(choice.message.content or "")


@dataclass
class LocalProvider:
    """An OpenAI-compatible model server on this host (the default provider).

    The local path is not redacted: the server runs on the operator's own machine,
    so the full compact view is sent (Hard rule 2). ``client`` can be injected for
    tests; otherwise the ``openai`` SDK is imported lazily and pointed at
    ``base_url``. No network call is made until ``draft`` runs.
    """

    model: str
    base_url: str = DEFAULT_LOCAL_BASE_URL
    max_tokens: int | None = None
    structured: bool = True
    # Most local servers ignore the key (vLLM and LM Studio can require one), but
    # the SDK needs a non-empty value either way.
    api_key: str = field(default="local", repr=False)
    client: Any | None = field(default=None, repr=False)

    def draft(self, request: DraftRequest) -> str:
        """Draft id-cited claims from the full compact view (no redaction)."""
        prompt = build_prompt(request, redaction=None)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
        }
        if self.max_tokens is not None:
            kwargs["max_tokens"] = self.max_tokens
        response_format = _openai_response_format(self.structured)
        if response_format is not None:
            kwargs["response_format"] = response_format
        client = self._resolve_client()
        try:
            response = client.chat.completions.create(**kwargs)
        except Exception as exc:  # any SDK or transport failure
            raise _call_failed(f"the local model at {self.base_url}", exc, self.api_key) from exc
        return _openai_text("the local model", response)

    def _resolve_client(self) -> Any:
        if self.client is None:
            module = _load_sdk("openai", "local")
            self.client = module.OpenAI(base_url=self.base_url, api_key=self.api_key)
        return self.client


@dataclass
class OpenAIProvider:
    """The OpenAI cloud provider. Opt-in only; every view is redacted first (FR36)."""

    api_key: str = field(repr=False)
    model: str
    base_url: str | None = None
    max_tokens: int | None = None
    structured: bool = True
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    client: Any | None = field(default=None, repr=False)

    def draft(self, request: DraftRequest) -> str:
        """Redact the view, then draft id-cited claims through the OpenAI API."""
        prompt = build_prompt(request, redaction=self.redaction)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": prompt.system},
                {"role": "user", "content": prompt.user},
            ],
        }
        if self.max_tokens is not None:
            kwargs["max_completion_tokens"] = self.max_tokens
        response_format = _openai_response_format(self.structured)
        if response_format is not None:
            kwargs["response_format"] = response_format
        client = self._resolve_client()
        try:
            response = client.chat.completions.create(**kwargs)
        except Exception as exc:  # any SDK or transport failure
            raise _call_failed("OpenAI", exc, self.api_key) from exc
        return _openai_text("OpenAI", response)

    def _resolve_client(self) -> Any:
        if self.client is None:
            module = _load_sdk("openai", "openai")
            kwargs: dict[str, Any] = {"api_key": self.api_key}
            if self.base_url:
                kwargs["base_url"] = self.base_url
            self.client = module.OpenAI(**kwargs)
        return self.client


@dataclass
class AnthropicProvider:
    """The Anthropic cloud provider. Opt-in only; every view is redacted first (FR36).

    Calls stream (so a long narrative cannot hit an HTTP timeout), constrain the
    answer to the claim schema, and opt into Anthropic's server-side refusal
    fallback, so a request a model's classifiers decline is re-run on the model
    Anthropic recommends for that category instead of returning no narrative.
    """

    api_key: str = field(repr=False)
    model: str = DEFAULT_ANTHROPIC_MODEL
    max_tokens: int = DEFAULT_MAX_TOKENS
    structured: bool = True
    fallbacks: bool = True
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    client: Any | None = field(default=None, repr=False)

    def draft(self, request: DraftRequest) -> str:
        """Redact the view, then draft id-cited claims through the Anthropic API."""
        prompt = build_prompt(request, redaction=self.redaction)
        kwargs: dict[str, Any] = {
            "model": self.model,
            "max_tokens": self.max_tokens,
            "system": prompt.system,
            "messages": [{"role": "user", "content": prompt.user}],
        }
        if self.structured:
            kwargs["output_config"] = {"format": {"type": "json_schema", "schema": claims_schema()}}
        if self.fallbacks:
            kwargs["betas"] = [_ANTHROPIC_FALLBACK_BETA]
            kwargs["fallbacks"] = "default"
        client = self._resolve_client()
        try:
            with client.beta.messages.stream(**kwargs) as stream:
                message = stream.get_final_message()
        except Exception as exc:  # any SDK or transport failure
            raise _call_failed("Anthropic", exc, self.api_key) from exc

        stop_reason = getattr(message, "stop_reason", None)
        if stop_reason == "refusal":
            details = getattr(message, "stop_details", None)
            category = getattr(details, "category", None) or "unspecified"
            raise ProviderError(f"Anthropic declined the request (category: {category})")
        if stop_reason == "max_tokens":
            raise ProviderError(
                "Anthropic stopped at its output limit before finishing; reduce --view-budget "
                f"or raise {ENV_MAX_OUTPUT_TOKENS}"
            )
        return "".join(
            str(getattr(block, "text", ""))
            for block in message.content
            if getattr(block, "type", "text") == "text"
        )

    def _resolve_client(self) -> Any:
        if self.client is None:
            module = _load_sdk("anthropic", "anthropic")
            self.client = module.Anthropic(api_key=self.api_key)
        return self.client


def _require(env: Mapping[str, str], name: str, why: str) -> str:
    """Return a required setting from the environment, or raise a clear error."""
    value = (env.get(name) or "").strip()
    if not value:
        raise ProviderConfigError(f"{name} is not set; {why}")
    return value


def _max_output_tokens(env: Mapping[str, str]) -> int | None:
    """The optional output ceiling from the environment, validated as a positive int."""
    raw = (env.get(ENV_MAX_OUTPUT_TOKENS) or "").strip()
    if not raw:
        return None
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value <= 0:
        raise ProviderConfigError(f"{ENV_MAX_OUTPUT_TOKENS} must be a positive integer")
    return value


def build_model_from_env(
    env: Mapping[str, str] | None = None, *, allow_cloud: bool = False
) -> NarrativeModel | None:
    """Build the configured narrative model from the environment, or None (FR26, FR27).

    ``CASEBOUND_PROVIDER`` selects the provider. Unset, empty, or ``none`` means no
    narrative. ``local`` returns a ``LocalProvider`` (``CASEBOUND_LOCAL_MODEL`` must
    name the model the server serves). ``anthropic`` or ``openai`` return a cloud
    provider, but only when cloud use is consented to, through ``allow_cloud=True``
    or ``CASEBOUND_ALLOW_CLOUD=1`` (FR27); otherwise this raises
    ``CloudConsentError``. No network call is made here; clients are built lazily.
    """
    env = os.environ if env is None else env
    raw = env.get(ENV_PROVIDER)
    if raw is None:
        return None
    provider = raw.strip().lower()
    if provider in _NONE_VALUES:
        return None
    structured = env_bool(env, ENV_STRUCTURED, True)
    max_tokens = _max_output_tokens(env)

    if provider == PROVIDER_LOCAL:
        return LocalProvider(
            model=_require(
                env, ENV_LOCAL_MODEL, "name the model your local server serves (ollama list)"
            ),
            base_url=(env.get(ENV_LOCAL_BASE_URL) or DEFAULT_LOCAL_BASE_URL).strip(),
            max_tokens=max_tokens,
            structured=structured,
            api_key=(env.get(ENV_LOCAL_KEY) or "").strip() or "local",
        )

    if provider in CLOUD_PROVIDERS:
        if not (allow_cloud or env_bool(env, ENV_ALLOW_CLOUD, False)):
            raise CloudConsentError(
                f"provider '{provider}' sends redacted event views off this host; consent "
                f"with --allow-cloud or {ENV_ALLOW_CLOUD}=1"
            )
        redaction = RedactionConfig.from_env(env)
        if provider == PROVIDER_ANTHROPIC:
            return AnthropicProvider(
                api_key=_require(env, ENV_ANTHROPIC_KEY, "the anthropic provider needs its key"),
                model=(env.get(ENV_ANTHROPIC_MODEL) or DEFAULT_ANTHROPIC_MODEL).strip(),
                max_tokens=max_tokens or DEFAULT_MAX_TOKENS,
                structured=structured,
                fallbacks=env_bool(env, ENV_ANTHROPIC_FALLBACKS, True),
                redaction=redaction,
            )
        return OpenAIProvider(
            api_key=_require(env, ENV_OPENAI_KEY, "the openai provider needs its key"),
            model=_require(env, ENV_OPENAI_MODEL, "name the OpenAI model to use"),
            base_url=(env.get(ENV_OPENAI_BASE_URL) or "").strip() or None,
            max_tokens=max_tokens,
            structured=structured,
            redaction=redaction,
        )

    raise ProviderConfigError(
        f"unknown provider '{provider}'; expected one of: "
        f"{PROVIDER_LOCAL}, {PROVIDER_ANTHROPIC}, {PROVIDER_OPENAI}, none"
    )
