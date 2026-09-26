"""The bundled MITRE ATT&CK Enterprise catalog.

Every technique id Casebound emits is checked against a compact catalog shipped
inside the package (``casebound/data/attack-enterprise.json``), generated from
MITRE's published STIX bundle by ``scripts/build_attack_catalog.py``. The catalog
is what lets the pipeline:

  - validate an id (a well-formed string such as ``T9999`` is still not a
    technique);
  - translate an id MITRE has since revoked to its current successor, so a
    detection rule written against an older ATT&CK release (``T1070.001`` Clear
    Windows Event Logs, revoked into ``T1685.005`` in ATT&CK 19) still lands on
    the right cell of today's matrix;
  - name a technique ("OS Credential Dumping: LSASS Memory") and place it under
    its tactics, in the Enterprise matrix's own column order, for the report's
    ATT&CK matrix and the Navigator layer.

The catalog is reference data, loaded once and cached. Nothing here reaches the
network: refreshing it for a new ATT&CK release is an explicit, offline developer
step (see the builder script).

Style: no em dashes or en dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import StrEnum
from functools import lru_cache
from importlib.resources import files
from typing import Any

__all__ = [
    "AttackCatalog",
    "Resolution",
    "Tactic",
    "Technique",
    "TechniqueStatus",
    "load_catalog",
]

# The package-relative location of the generated catalog.
_CATALOG_RESOURCE = "data/attack-enterprise.json"


class TechniqueStatus(StrEnum):
    """How a requested technique id relates to the bundled catalog."""

    ACTIVE = "active"
    REVOKED = "revoked"
    DEPRECATED = "deprecated"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Tactic:
    """One ATT&CK tactic, a column of the Enterprise matrix."""

    tactic_id: str
    shortname: str
    name: str


@dataclass(frozen=True)
class Technique:
    """One ATT&CK technique or sub-technique as the catalog records it.

    ``name`` is the technique's own name; ``display_name`` prefixes a
    sub-technique with its parent ("OS Credential Dumping: LSASS Memory").
    ``tactics`` are tactic shortnames and are empty for a revoked technique.
    """

    technique_id: str
    name: str
    display_name: str
    tactics: tuple[str, ...]
    deprecated: bool = False
    revoked_by: str | None = None

    @property
    def is_active(self) -> bool:
        """True when the technique is current: neither revoked nor deprecated."""
        return not self.deprecated and self.revoked_by is None


@dataclass(frozen=True)
class Resolution:
    """The outcome of resolving a requested id against the catalog.

    ``technique_id`` is the id to emit: the successor for a revoked id, otherwise
    the id as requested. ``technique`` is the catalog entry for that id, or None
    when the requested id is unknown to the catalog.
    """

    requested: str
    technique_id: str
    status: TechniqueStatus
    technique: Technique | None

    @property
    def translated(self) -> bool:
        """True when the requested id was revoked and replaced by its successor."""
        return self.technique_id != self.requested


class AttackCatalog:
    """Lookup over the bundled ATT&CK Enterprise catalog."""

    def __init__(self, data: dict[str, Any]) -> None:
        self.version: str = str(data["attack_version"])
        self.modified: str = str(data["modified"])
        self.source: str = str(data["source"])
        self.tactics: tuple[Tactic, ...] = tuple(
            Tactic(tactic_id=item["id"], shortname=item["shortname"], name=item["name"])
            for item in data["tactics"]
        )
        self._tactics_by_shortname = {tactic.shortname: tactic for tactic in self.tactics}
        raw: dict[str, dict[str, Any]] = data["techniques"]
        self._techniques: dict[str, Technique] = {}
        for technique_id, entry in raw.items():
            parent_name = None
            if "." in technique_id:
                parent = raw.get(technique_id.split(".", 1)[0])
                parent_name = parent["name"] if parent is not None else None
            name = str(entry["name"])
            self._techniques[technique_id] = Technique(
                technique_id=technique_id,
                name=name,
                display_name=f"{parent_name}: {name}" if parent_name else name,
                tactics=tuple(entry.get("tactics", ())),
                deprecated=bool(entry.get("deprecated", False)),
                revoked_by=entry.get("revoked_by"),
            )

    @property
    def major_version(self) -> str:
        """The ATT&CK major version, the form the Navigator layer records ("19")."""
        return self.version.split(".", 1)[0]

    def __contains__(self, technique_id: object) -> bool:
        return technique_id in self._techniques

    def __len__(self) -> int:
        return len(self._techniques)

    def get(self, technique_id: str) -> Technique | None:
        """Return the catalog entry for an id exactly as written, or None."""
        return self._techniques.get(technique_id)

    def tactic(self, shortname: str) -> Tactic | None:
        """Return the tactic with this shortname, or None."""
        return self._tactics_by_shortname.get(shortname)

    def active_techniques(self) -> tuple[Technique, ...]:
        """Every current technique and sub-technique, in id order."""
        return tuple(tech for tech in self._techniques.values() if tech.is_active)

    def resolve(self, technique_id: str) -> Resolution:
        """Resolve a requested id to the id Casebound should emit.

        An active id resolves to itself. A revoked id resolves to its final
        successor (chains are flattened when the catalog is built). A deprecated id
        keeps its own id: MITRE names no successor, so there is nothing truthful to
        translate it to. An id the catalog does not know is returned unchanged with
        status ``unknown``; callers decide whether to keep or drop it.
        """
        technique = self._techniques.get(technique_id)
        if technique is None:
            return Resolution(technique_id, technique_id, TechniqueStatus.UNKNOWN, None)
        if technique.revoked_by is not None:
            successor = self._techniques.get(technique.revoked_by)
            return Resolution(
                technique_id, technique.revoked_by, TechniqueStatus.REVOKED, successor
            )
        if technique.deprecated:
            return Resolution(technique_id, technique_id, TechniqueStatus.DEPRECATED, technique)
        return Resolution(technique_id, technique_id, TechniqueStatus.ACTIVE, technique)


@lru_cache(maxsize=1)
def load_catalog() -> AttackCatalog:
    """Load and cache the bundled ATT&CK Enterprise catalog."""
    text = files("casebound").joinpath(_CATALOG_RESOURCE).read_text(encoding="utf-8")
    return AttackCatalog(json.loads(text))
