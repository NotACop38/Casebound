"""Cloud redaction: strip sensitive content before any cloud-model call (PRD D5, FR36).

Casebound's deterministic core and the default local narrative never send evidence
off the host (Hard rule 2). The only path that leaves the host is an opt-in cloud
provider, and per decision D5 every event view is redacted first, conservatively by
default and fully configurable.

What a cloud model would otherwise see is already the compact, id-addressed event
view (Hard rule 4, never raw files or ``details``). This pass narrows it further,
removing the fields D5 calls out:

  - the free-text ``message`` (replaced wholesale),
  - the ``principal`` (an account name or SID, a username),
  - obvious indicators in ``object`` (IP addresses, domains, hashes, and file
    paths, reusing the deterministic IOC patterns so this never drifts from the
    extractor), plus any username embedded in a path, and
  - optionally the ``host``.

What survives is what the verifier still needs to address an event and what carries
no sensitive content: ``event_id``, ``datetime``, and ``action``. The redaction is
lossy on purpose: the local verifier re-grounds every returned claim against the
full, unredacted events, so a thinner cloud view never weakens the guarantee, it
only limits what a cloud claim can assert.

``details`` is never present in the event view to begin with, so there is nothing
to strip there; the structural fence already removed it.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from casebound.enrich.ioc import find_indicators
from casebound.verify.engine import EventView

__all__ = ["DEFAULT_PLACEHOLDER", "RedactionConfig", "env_bool", "redact_view"]

# What a redacted field is replaced with in the cloud-bound payload.
DEFAULT_PLACEHOLDER = "[redacted]"

# Shortest username fragment we will blank inside an object, so a two-character
# account name does not cause common substrings to be redacted.
_MIN_USERNAME_LEN = 3

# Environment values that read as true for a boolean toggle.
_TRUTHY = frozenset({"1", "true", "yes", "on"})


def env_bool(env: Mapping[str, str], name: str, default: bool) -> bool:
    """Read a boolean toggle from an environment mapping, with a default."""
    raw = env.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in _TRUTHY


@dataclass(frozen=True)
class RedactionConfig:
    """Which fields the cloud redaction pass strips (PRD D5, conservative defaults).

    Defaults follow the D5 lean: strip the free-text ``message``, the ``principal``
    username, and obvious indicators in ``object``. ``strip_host`` is off by default
    (a hostname is not in the D5 strip list) but available for stricter setups.
    Every toggle is configurable, so an operator can widen or narrow the pass.
    ``strip_iocs`` and ``strip_principal`` govern their content class inside every
    kept text field: a kept message still has indicators and usernames blanked
    unless those toggles are off too.
    """

    strip_message: bool = True
    strip_principal: bool = True
    strip_iocs: bool = True
    strip_host: bool = False
    placeholder: str = DEFAULT_PLACEHOLDER

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> RedactionConfig:
        """Build a config from environment variables, falling back to the defaults."""
        return cls(
            strip_message=env_bool(env, "CASEBOUND_REDACT_MESSAGE", True),
            strip_principal=env_bool(env, "CASEBOUND_REDACT_PRINCIPAL", True),
            strip_iocs=env_bool(env, "CASEBOUND_REDACT_IOCS", True),
            strip_host=env_bool(env, "CASEBOUND_REDACT_HOST", False),
            placeholder=env.get("CASEBOUND_REDACT_PLACEHOLDER", DEFAULT_PLACEHOLDER),
        )


def _redact_field(value: str | None, strip: bool, placeholder: str) -> str | None:
    """Replace a whole field with the placeholder when stripping and it has content."""
    if strip and value:
        return placeholder
    return value


def _strip_indicators(text: str, placeholder: str) -> str:
    """Replace every deterministic indicator found in ``text`` with the placeholder."""
    result = text
    for _ioc_type, value in find_indicators(text):
        if value:
            result = result.replace(value, placeholder)
    return result


def _username_tokens(principal: str) -> list[str]:
    """The username spellings to blank: the whole principal and its account part."""
    tokens = {principal}
    if "\\" in principal:
        tokens.add(principal.rsplit("\\", 1)[-1])
    if "@" in principal:
        tokens.add(principal.split("@", 1)[0])
    # Longest first, so the full principal is blanked before a shorter fragment.
    return sorted(
        (token for token in tokens if len(token) >= _MIN_USERNAME_LEN),
        key=len,
        reverse=True,
    )


def _strip_username(text: str, principal: str | None, placeholder: str) -> str:
    """Blank any occurrence of the principal's username inside ``text``."""
    if not principal:
        return text
    result = text
    for token in _username_tokens(principal):
        result = re.sub(re.escape(token), placeholder, result, flags=re.IGNORECASE)
    return result


def redact_view(view: EventView, config: RedactionConfig) -> dict[str, Any]:
    """Return the JSON-ready, redacted rendering of one event view (PRD D5, FR36).

    Strips the fields D5 names and keeps only the non-sensitive addressable fields
    the verifier still needs. The result is a plain dict so it serializes straight
    into a cloud prompt; the input ``EventView`` is never mutated.
    """
    obj = view.object
    if obj is not None:
        if config.strip_iocs:
            obj = _strip_indicators(obj, config.placeholder)
        if config.strip_principal:
            obj = _strip_username(obj, view.principal, config.placeholder)

    # The IOC and username toggles govern their content class in every kept text
    # field: an operator who keeps the message (strip_message off) still gets
    # indicators and usernames blanked inside it unless those toggles are off
    # too. The host is exempt from IOC stripping: an FQDN hostname would match
    # the domain pattern, and keeping or stripping the host is its own toggle.
    message: str | None = view.message
    if config.strip_message:
        message = _redact_field(message, True, config.placeholder)
    else:
        if config.strip_iocs and message:
            message = _strip_indicators(message, config.placeholder)
        if config.strip_principal and message:
            message = _strip_username(message, view.principal, config.placeholder)

    return {
        "event_id": view.event_id,
        "datetime": view.datetime,
        "host": _redact_field(view.host, config.strip_host, config.placeholder),
        "principal": _redact_field(view.principal, config.strip_principal, config.placeholder),
        "action": view.action,
        "object": obj,
        "message": message,
    }
