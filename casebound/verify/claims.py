"""Claim parsing: turn raw model output into structured, checkable claims.

PRD Section 11 step 3: parse the model output into ``(claim_text, [event_ids])``
pairs deterministically, and treat malformed citations as unsupported. The format
the model must emit is specified in ``docs/verification.md``.

The parser is strict about the overall structure (it must be JSON in the agreed
shape) and lenient about individual citations: a single bad citation does not
crash the parse, it is recorded as malformed and provides no support downstream.
This is what lets the verifier reject a hallucinated citation rather than choke on
it.

Nothing here decides whether a claim is true. This module only extracts what the
model asserted and what it cited; ``checks`` and ``engine`` apply the verifier.

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

# An event_id is a 64-character lowercase SHA-256 hex digest (see the canonical
# schema). A citation is well-formed only if it matches this exactly; anything
# else (a truncated hash, a record number, a made-up label) is malformed and
# carries no support.
EVENT_ID_RE = re.compile(r"^[0-9a-f]{64}$")

# The four machine-checkable fact fields a claim may assert. Exactly the fields
# the verifier compares against the cited event (the PRD wedge: time, principal,
# action, object). Any other key in an ``asserts`` block is ignored.
ASSERTION_FIELDS: tuple[str, ...] = ("datetime", "principal", "action", "object")

__all__ = [
    "ASSERTION_FIELDS",
    "EVENT_ID_RE",
    "Claim",
    "ClaimAssertion",
    "ClaimParseError",
    "parse_claims",
]


class ClaimParseError(ValueError):
    """Raised when model output cannot be parsed into the agreed claim structure.

    This is a structural failure (the output is not JSON, or not the object or
    array shape the format requires), not a per-claim problem. A single malformed
    citation never raises this: it is recorded on the claim instead.
    """


@dataclass(frozen=True)
class ClaimAssertion:
    """The machine-checkable facts a claim commits to.

    Each field mirrors the canonical event field of the same name and is optional;
    only the asserted (non-null) fields are checked against the cited event. A
    claim must assert at least one field, or it is making no checkable factual
    statement and is rejected.
    """

    datetime: str | None = None
    principal: str | None = None
    action: str | None = None
    object: str | None = None

    def asserted_fields(self) -> tuple[str, ...]:
        """Return the names of the fields this claim actually asserts, in order."""
        return tuple(name for name in ASSERTION_FIELDS if getattr(self, name) is not None)

    def is_empty(self) -> bool:
        """True when the claim asserts none of the four checkable facts."""
        return not self.asserted_fields()

    def to_dict(self) -> dict[str, str]:
        """Render the asserted fields as a JSON-ready dict (absent fields omitted)."""
        return {name: getattr(self, name) for name in self.asserted_fields()}


@dataclass(frozen=True)
class Claim:
    """One parsed claim: the prose, its citations, and what it asserts.

    ``citations`` holds the well-formed event ids in first-seen order with
    duplicates removed. ``malformed_citations`` holds the raw strings that were not
    valid event ids, kept for the audit log. ``index`` is the claim's position in
    the parsed claim list (textless entries are skipped during parsing, so it is
    not necessarily the position in the raw model output). ``revises`` is the id
    of the outstanding
    claim this one replaces during a revision round (see ``docs/verification.md``),
    or None for a fresh claim; it is how the engine matches a revision to the claim
    it fixes without relying on ordering.
    """

    index: int
    text: str
    citations: tuple[str, ...]
    malformed_citations: tuple[str, ...]
    asserts: ClaimAssertion
    revises: str | None = None

    @property
    def all_citations(self) -> tuple[str, ...]:
        """Every citation the model wrote, well-formed first, for the audit log."""
        return self.citations + self.malformed_citations

    def to_dict(self) -> dict[str, Any]:
        """Render the claim as a JSON-ready dict."""
        return {
            "index": self.index,
            "text": self.text,
            "citations": list(self.citations),
            "malformed_citations": list(self.malformed_citations),
            "asserts": self.asserts.to_dict(),
            "revises": self.revises,
        }


def _strip_code_fences(raw: str) -> str:
    """Remove a single surrounding Markdown code fence if the model added one.

    Models often wrap JSON in a ```json ... ``` block. We tolerate exactly that
    wrapper and nothing more elaborate, so the parse stays predictable.
    """
    text = raw.strip()
    if not text.startswith("```"):
        return text
    lines = text.splitlines()
    # Drop the opening fence (with an optional language tag) and a closing fence.
    if lines and lines[0].startswith("```"):
        lines = lines[1:]
    if lines and lines[-1].strip() == "```":
        lines = lines[:-1]
    return "\n".join(lines).strip()


def _coerce_optional_str(value: Any) -> str | None:
    """Coerce an asserted-field value to a trimmed string, or None when absent.

    A missing field, an explicit null, or an empty or whitespace-only string all
    mean the claim does not assert that field.
    """
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _parse_citations(value: Any) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Split a claim's raw citations into well-formed and malformed.

    Accepts a list of citation strings, or a single string for leniency. Each
    entry is normalized (trimmed, lowercased) and matched against the event-id
    pattern. Well-formed ids are deduplicated in first-seen order; malformed
    entries keep their original spelling so the audit log shows what the model
    actually wrote.
    """
    if value is None:
        return (), ()
    items = value if isinstance(value, list) else [value]

    well_formed: list[str] = []
    malformed: list[str] = []
    seen: set[str] = set()
    for item in items:
        raw = str(item).strip()
        candidate = raw.lower()
        if EVENT_ID_RE.match(candidate):
            if candidate not in seen:
                seen.add(candidate)
                well_formed.append(candidate)
        elif raw:
            malformed.append(raw)
    return tuple(well_formed), tuple(malformed)


def _claim_objects(payload: Any) -> list[dict[str, Any]]:
    """Extract the list of claim objects from a parsed JSON payload.

    Accepts either the object form ``{"claims": [...]}`` or a bare array of claim
    objects. Non-object entries are skipped rather than aborting the whole parse.
    """
    if isinstance(payload, dict):
        raw_claims = payload.get("claims", [])
    elif isinstance(payload, list):
        raw_claims = payload
    else:
        raise ClaimParseError(
            "model output must be a JSON object with a 'claims' array or a JSON array of claims"
        )
    if not isinstance(raw_claims, list):
        raise ClaimParseError("'claims' must be an array")
    return [item for item in raw_claims if isinstance(item, dict)]


def parse_claims(raw: str) -> list[Claim]:
    """Parse raw model output into a list of ``Claim`` records.

    Raises ``ClaimParseError`` when the output is not JSON in the agreed shape.
    Individual malformed citations never raise: they are recorded on the claim and
    treated as unsupported by the verifier. Claim objects without usable prose
    text are skipped, since an empty claim has nothing to ground or to report.
    """
    if not raw or not raw.strip():
        raise ClaimParseError("model output was empty")

    text = _strip_code_fences(raw)
    try:
        payload = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ClaimParseError(f"model output was not valid JSON: {exc}") from exc

    claims: list[Claim] = []
    for entry in _claim_objects(payload):
        claim_text = str(entry.get("text", "")).strip()
        if not claim_text:
            continue
        well_formed, malformed = _parse_citations(entry.get("citations"))
        raw_asserts = entry.get("asserts")
        asserts_map = raw_asserts if isinstance(raw_asserts, dict) else {}
        asserts = ClaimAssertion(
            datetime=_coerce_optional_str(asserts_map.get("datetime")),
            principal=_coerce_optional_str(asserts_map.get("principal")),
            action=_coerce_optional_str(asserts_map.get("action")),
            object=_coerce_optional_str(asserts_map.get("object")),
        )
        claims.append(
            Claim(
                index=len(claims),
                text=claim_text,
                citations=well_formed,
                malformed_citations=malformed,
                asserts=asserts,
                revises=_coerce_optional_str(entry.get("revises")),
            )
        )
    return claims
