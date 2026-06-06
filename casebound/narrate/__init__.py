"""Narration: the provider-agnostic model interface and the drafting loop.

Calls a model to draft a narrative as a sequence of id-cited claims, then submits
rejected claims back for revision (FR23). The provider is abstracted behind one
interface (Anthropic, OpenAI, local), defaulting to local so evidence never leaves
the host by default (R8, FR27). The model only ever sees the compact, id-addressed
event view, never raw evidence files (Hard rule 4).

Layout (PRD Section 13):

  - ``llm``    : the provider-agnostic interface (``LocalProvider``,
    ``AnthropicProvider``, ``OpenAIProvider``) and ``build_model_from_env``, the
    env-driven selector that defaults to local and gates cloud behind a consent
    flag (FR27). With nothing configured it returns None, the no-model path (FR26).
  - ``redact`` : the cloud redaction pass applied before any cloud call (PRD D5,
    FR36), conservative by default and configurable.
  - ``demo``   : ``OfflineDemoNarrator``, a deterministic, network-free stand-in the
    bundled demo uses so the verifier runs and the report carries a verified
    narrative and a rejected-claims audit, with no model configured and no keys.
"""

from __future__ import annotations

from casebound.narrate.demo import OfflineDemoNarrator
from casebound.narrate.llm import (
    AnthropicProvider,
    CloudConsentError,
    LocalProvider,
    OpenAIProvider,
    Prompt,
    ProviderConfigError,
    ProviderError,
    build_model_from_env,
    build_prompt,
)
from casebound.narrate.redact import RedactionConfig, redact_view

__all__ = [
    "AnthropicProvider",
    "CloudConsentError",
    "LocalProvider",
    "OfflineDemoNarrator",
    "OpenAIProvider",
    "Prompt",
    "ProviderConfigError",
    "ProviderError",
    "RedactionConfig",
    "build_model_from_env",
    "build_prompt",
    "redact_view",
]
