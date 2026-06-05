"""Canonical event schema v0.1 (PRD Section 10): the keystone record.

Everything downstream hangs off this record. Ingest adapters emit raw rows, the
mappers in this package turn them into ``Event`` instances, and enrichment, the
verifier, and the report layer all address events by their stable ``event_id``.

The ``event_id`` is a deterministic content hash of the normalized core fields
(see ``CORE_ID_FIELDS``). It is always derived here, never trusted from input:
this is what lets the verifier treat an id as an unforgeable handle to a real,
extracted event. The same logical event always hashes to the same id, and two
events that differ in any core field get different ids.

``schema/event.schema.json`` is the validation source of truth and mirrors this
module exactly. ``docs/schema.md`` documents the record with two worked examples.

Conventions: timestamps are ISO 8601 normalized to UTC with a trailing ``Z``.
No em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime as _datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

import jsonschema

SCHEMA_VERSION = "0.1"

# Domain-separation prefix folded into the hashed content so that event ids
# cannot silently collide across future schema versions.
_EVENT_ID_NAMESPACE = f"casebound-event-v{SCHEMA_VERSION}"

# The JSON Schema that mirrors this module. Resolved relative to the repo root so
# the path holds whether the package is installed editable or from a wheel.
SCHEMA_PATH = Path(__file__).resolve().parents[2] / "schema" / "event.schema.json"

# Controlled vocabulary: how the timestamp relates to the event (Timesketch's
# timestamp_desc). Open-ended cases fall back to "other".
TIMESTAMP_DESCS: frozenset[str] = frozenset({"created", "modified", "accessed", "logged", "other"})

# Controlled vocabulary: the tool whose output produced the record (PRD Section
# 10). New adapters extend this set as they land.
SOURCE_TOOLS: frozenset[str] = frozenset(
    {
        "hayabusa",
        "eztools",
        "chainsaw",
        "velociraptor",
        "plaso",
        "generic_csv",
        "dissect",
    }
)

# Recommended normalized action verbs. The vocabulary is intentionally open:
# mappers should prefer a verb from this set, but any snake_case verb validates,
# so a new source can describe activity this list does not yet cover.
KNOWN_ACTIONS: frozenset[str] = frozenset(
    {
        "process_create",
        "process_terminate",
        "logon",
        "logoff",
        "file_create",
        "file_write",
        "file_read",
        "file_delete",
        "file_rename",
        "registry_set",
        "registry_delete",
        "service_install",
        "scheduled_task_create",
        "network_connect",
        "network_listen",
        "account_create",
        "account_modify",
        "privilege_use",
        "dns_query",
        "other",
    }
)

_ACTION_RE = re.compile(r"^[a-z][a-z0-9_]*$")
_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_DATETIME_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$")

# The ordered set of fields that define event identity. The event_id is the hash
# of exactly these fields. They capture when the event happened (datetime,
# timestamp_desc), who and what (host, principal, action, object), and the
# provenance of the record (source_tool, source_artifact). Cross-source
# de-duplication of otherwise-identical observations (FR12) is handled later and
# does not change this identity definition; if it ever needs to, stop and ask.
CORE_ID_FIELDS: tuple[str, ...] = (
    "datetime",
    "timestamp_desc",
    "host",
    "principal",
    "action",
    "object",
    "source_tool",
    "source_artifact",
)

__all__ = [
    "CORE_ID_FIELDS",
    "KNOWN_ACTIONS",
    "SCHEMA_PATH",
    "SCHEMA_VERSION",
    "SOURCE_TOOLS",
    "TIMESTAMP_DESCS",
    "AttackTechnique",
    "Event",
    "RawRef",
    "compute_event_id",
    "load_schema",
    "validate_event_dict",
]


class SchemaError(ValueError):
    """Raised when a value cannot be a valid canonical event field."""


def _require_non_empty(name: str, value: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SchemaError(f"{name} must be a non-empty string")
    return value


@dataclass(frozen=True)
class AttackTechnique:
    """A single ATT&CK mapping attached to an event.

    ``technique_id`` is an ATT&CK technique or sub-technique id (for example
    "T1059" or "T1059.001"). ``mapping_source`` records how the mapping was made
    (for example "rule_tag" for a passthrough from a detection rule, or
    "mapping_table" for the documented deterministic table), so every tag is
    auditable (FR14).
    """

    technique_id: str
    mapping_source: str

    def __post_init__(self) -> None:
        if not _TECHNIQUE_RE.match(self.technique_id):
            raise SchemaError(
                f"technique_id must look like T1059 or T1059.001, got {self.technique_id!r}"
            )
        _require_non_empty("mapping_source", self.mapping_source)

    def to_dict(self) -> dict[str, str]:
        return {"technique_id": self.technique_id, "mapping_source": self.mapping_source}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AttackTechnique:
        return cls(
            technique_id=str(data["technique_id"]),
            mapping_source=str(data["mapping_source"]),
        )


@dataclass(frozen=True)
class RawRef:
    """A pointer back to the source record for audit (FR11).

    ``source_file`` is the artifact or export the record came from, and
    ``record`` is the line number or record id within it. Kept out of the
    identity hash so that event ids stay stable across machines and reruns where
    only the file path differs.
    """

    source_file: str
    record: str

    def __post_init__(self) -> None:
        _require_non_empty("raw_ref.source_file", self.source_file)
        _require_non_empty("raw_ref.record", self.record)

    def to_dict(self) -> dict[str, str]:
        return {"source_file": self.source_file, "record": self.record}

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> RawRef:
        return cls(source_file=str(data["source_file"]), record=str(data["record"]))


def _normalize_id_value(value: Any) -> str:
    """Canonicalize a core field for hashing: absent or null becomes empty."""
    if value is None:
        return ""
    return str(value)


def _parse_strict_utc(value: str) -> _datetime:
    """Parse a canonical UTC datetime string into a real instant.

    Accepts only the shape the schema allows (ISO 8601 with a trailing Z) and
    rejects impossible calendar instants such as 2026-99-99T99:99:99Z. Fractional
    seconds longer than microsecond precision are truncated for parsing. Raises
    ``ValueError`` on anything that is not a real UTC instant.
    """
    if not isinstance(value, str) or not _DATETIME_RE.match(value):
        raise ValueError(f"datetime must be ISO 8601 UTC with a trailing Z, got {value!r}")
    core = value[:-1]  # drop the trailing Z
    if "." in core:
        head, frac = core.split(".", 1)
        iso = f"{head}.{(frac + '000000')[:6]}+00:00"
    else:
        iso = f"{core}+00:00"
    # fromisoformat rejects out-of-range months, days, hours, and so on, so this
    # is where impossible instants are caught.
    return _datetime.fromisoformat(iso)


def _canonical_utc_datetime(value: str) -> str:
    """Return the one canonical string for the instant ``value`` denotes.

    Sub-second precision is preserved but represented uniquely (trailing zeros
    trimmed), so 2026-03-14T08:42:17Z and 2026-03-14T08:42:17.000Z collapse to a
    single representation. This is what makes the same instant hash to the same
    event_id regardless of how a source spelled it.
    """
    instant = _parse_strict_utc(value)
    base = instant.strftime("%Y-%m-%dT%H:%M:%S")
    if instant.microsecond:
        return f"{base}.{instant.microsecond:06d}".rstrip("0") + "Z"
    return f"{base}Z"


def compute_event_id(core: Mapping[str, Any]) -> str:
    """Return the stable content hash for a set of core identity fields.

    The hash is taken over a canonical JSON encoding of the namespaced core
    fields, so the same logical event always yields the same id and any change to
    a core field changes the id.
    """
    payload = {key: _normalize_id_value(core.get(key)) for key in CORE_ID_FIELDS}
    blob = json.dumps(
        [_EVENT_ID_NAMESPACE, payload],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Event:
    """The canonical timeline event (PRD Section 10).

    Construct one with the observed and normalized fields; ``datetime`` is
    canonicalized and ``event_id`` is derived in ``__post_init__``, so the id is
    always a faithful hash of the core fields.

    The record is frozen: core identity fields cannot be reassigned after
    construction, so an event_id can never drift out of sync with the fields it
    hashes. Enrichment that adds tags or technique mappings constructs a new
    event or mutates the list contents in place rather than rebinding a field.
    """

    datetime: str
    timestamp_raw: str
    source_timezone: str
    timestamp_desc: str
    message: str
    action: str
    source_tool: str
    source_artifact: str
    raw_ref: RawRef
    host: str | None = None
    principal: str | None = None
    object: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    attack_techniques: list[AttackTechnique] = field(default_factory=list)
    ioc_refs: list[str] = field(default_factory=list)
    confidence: float = 1.0
    tags: list[str] = field(default_factory=list)
    event_id: str = ""

    def __post_init__(self) -> None:
        # Canonicalize the timestamp first so the stored field and the hashed
        # value always agree, then derive the id. The record is frozen, so these
        # assignments go through object.__setattr__.
        try:
            canonical = _canonical_utc_datetime(self.datetime)
        except ValueError as exc:
            raise SchemaError(str(exc)) from exc
        object.__setattr__(self, "datetime", canonical)
        self._validate()
        # The id is always derived, never trusted from input.
        object.__setattr__(self, "event_id", self.compute_id())

    def _validate(self) -> None:
        _require_non_empty("timestamp_raw", self.timestamp_raw)
        _require_non_empty("source_timezone", self.source_timezone)
        _require_non_empty("message", self.message)
        _require_non_empty("source_artifact", self.source_artifact)

        if self.timestamp_desc not in TIMESTAMP_DESCS:
            raise SchemaError(
                f"timestamp_desc must be one of {sorted(TIMESTAMP_DESCS)}, "
                f"got {self.timestamp_desc!r}"
            )
        if self.source_tool not in SOURCE_TOOLS:
            raise SchemaError(
                f"source_tool must be one of {sorted(SOURCE_TOOLS)}, got {self.source_tool!r}"
            )
        if not isinstance(self.action, str) or not _ACTION_RE.match(self.action):
            raise SchemaError(
                f"action must be a snake_case verb like process_create, got {self.action!r}"
            )
        for nullable in ("host", "principal", "object"):
            value = getattr(self, nullable)
            if value is not None and not isinstance(value, str):
                raise SchemaError(f"{nullable} must be a string or null")
        if not isinstance(self.confidence, (int, float)) or isinstance(self.confidence, bool):
            raise SchemaError("confidence must be a number between 0 and 1")
        if not 0.0 <= float(self.confidence) <= 1.0:
            raise SchemaError(f"confidence must be between 0 and 1, got {self.confidence!r}")
        if not isinstance(self.raw_ref, RawRef):
            raise SchemaError("raw_ref must be a RawRef")
        if any(not isinstance(item, AttackTechnique) for item in self.attack_techniques):
            raise SchemaError("attack_techniques must be a list of AttackTechnique")
        if any(not isinstance(ref, str) for ref in self.ioc_refs):
            raise SchemaError("ioc_refs must be a list of strings")
        if any(not isinstance(tag, str) for tag in self.tags):
            raise SchemaError("tags must be a list of strings")

    def compute_id(self) -> str:
        """Derive the event_id from this event's core identity fields."""
        return compute_event_id(
            {
                "datetime": self.datetime,
                "timestamp_desc": self.timestamp_desc,
                "host": self.host,
                "principal": self.principal,
                "action": self.action,
                "object": self.object,
                "source_tool": self.source_tool,
                "source_artifact": self.source_artifact,
            }
        )

    def to_dict(self) -> dict[str, Any]:
        """Render the event as a JSON-ready dict with every Section 10 field."""
        return {
            "event_id": self.event_id,
            "datetime": self.datetime,
            "timestamp_raw": self.timestamp_raw,
            "source_timezone": self.source_timezone,
            "timestamp_desc": self.timestamp_desc,
            "message": self.message,
            "host": self.host,
            "principal": self.principal,
            "action": self.action,
            "object": self.object,
            "source_tool": self.source_tool,
            "source_artifact": self.source_artifact,
            "details": self.details,
            "attack_techniques": [tech.to_dict() for tech in self.attack_techniques],
            "ioc_refs": list(self.ioc_refs),
            "confidence": self.confidence,
            "raw_ref": self.raw_ref.to_dict(),
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Event:
        """Build an Event from a complete, serialized event dict.

        The dict is first validated against the JSON Schema source of truth, so
        a null in a required string field or a string where an array is expected
        is rejected rather than silently coerced (``str(None)`` would otherwise
        become "None", and ``list("abc")`` would split into characters). The
        stored ``event_id`` is then checked against the freshly derived id, so a
        tampered or stale id never passes silently.
        """
        validate_event_dict(data)
        event = cls(
            datetime=data["datetime"],
            timestamp_raw=data["timestamp_raw"],
            source_timezone=data["source_timezone"],
            timestamp_desc=data["timestamp_desc"],
            message=data["message"],
            action=data["action"],
            source_tool=data["source_tool"],
            source_artifact=data["source_artifact"],
            raw_ref=RawRef.from_dict(data["raw_ref"]),
            host=data["host"],
            principal=data["principal"],
            object=data["object"],
            details=dict(data["details"]),
            attack_techniques=[
                AttackTechnique.from_dict(item) for item in data["attack_techniques"]
            ],
            ioc_refs=list(data["ioc_refs"]),
            confidence=float(data["confidence"]),
            tags=list(data["tags"]),
        )
        provided = data["event_id"]
        if provided != event.event_id:
            raise SchemaError(
                f"event_id mismatch: provided {provided!r} but core fields hash to "
                f"{event.event_id!r}"
            )
        return event


@lru_cache(maxsize=1)
def load_schema() -> dict[str, Any]:
    """Load and cache the JSON Schema that mirrors this module."""
    schema: dict[str, Any] = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    return schema


def validate_event_dict(data: Mapping[str, Any]) -> None:
    """Validate a dict against schema/event.schema.json.

    Runs the structural JSON Schema gate, then a semantic check that ``datetime``
    is a real UTC instant (the schema regex matches the shape but cannot reject
    an impossible calendar date such as 2026-99-99T99:99:99Z, which would
    otherwise drift from the dataclass validator). Raises
    ``jsonschema.ValidationError`` on the first problem. This is the gate that
    ingest output and report input both pass through.
    """
    jsonschema.Draft202012Validator(load_schema()).validate(dict(data))
    try:
        _parse_strict_utc(data["datetime"])
    except (ValueError, KeyError, TypeError) as exc:
        raise jsonschema.ValidationError(
            f"datetime is not a real UTC instant: {data.get('datetime')!r}"
        ) from exc
