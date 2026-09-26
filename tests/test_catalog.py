"""Tests for the bundled MITRE ATT&CK Enterprise catalog (``casebound.enrich.catalog``).

The catalog is generated from MITRE's STIX bundle by ``scripts/build_attack_catalog.py``
and validates, names, and places every technique Casebound emits. These tests pin
its integrity: a known release, the matrix's tactic order, internally consistent
tactic references, one-hop revocations to active successors, and the resolution
rules the tagger relies on.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from casebound.enrich.catalog import TechniqueStatus, load_catalog

CATALOG_FILE = Path(__file__).resolve().parents[1] / "casebound" / "data" / "attack-enterprise.json"


def test_catalog_records_its_release_and_source() -> None:
    catalog = load_catalog()
    assert catalog.version == "19.2"
    assert catalog.major_version == "19"
    assert catalog.source.startswith("https://raw.githubusercontent.com/mitre-attack/")
    assert len(catalog) > 800
    assert len(catalog.active_techniques()) > 600


def test_tactics_follow_the_enterprise_matrix_order() -> None:
    names = [tactic.name for tactic in load_catalog().tactics]
    assert names[:4] == ["Reconnaissance", "Resource Development", "Initial Access", "Execution"]
    assert names[-1] == "Impact"
    # ATT&CK v19 split the former Defense Evasion column.
    assert (
        names.index("Stealth")
        < names.index("Defense Impairment")
        < names.index("Credential Access")
    )
    assert len({tactic.tactic_id for tactic in load_catalog().tactics}) == len(names)


def test_every_reference_in_the_catalog_resolves() -> None:
    catalog = load_catalog()
    shortnames = {tactic.shortname for tactic in catalog.tactics}
    for technique in catalog.active_techniques():
        assert technique.tactics, technique.technique_id
        assert set(technique.tactics) <= shortnames, technique.technique_id
    raw = json.loads(CATALOG_FILE.read_text(encoding="utf-8"))["techniques"]
    for technique_id, entry in raw.items():
        successor = entry.get("revoked_by")
        if successor is not None:
            target = catalog.get(successor)
            assert target is not None and target.is_active, (technique_id, successor)
        if "." in technique_id:
            assert technique_id.split(".", 1)[0] in raw, technique_id


def test_sub_techniques_are_named_with_their_parent() -> None:
    catalog = load_catalog()
    lsass = catalog.get("T1003.001")
    assert lsass is not None
    assert lsass.name == "LSASS Memory"
    assert lsass.display_name == "OS Credential Dumping: LSASS Memory"
    exfiltration = catalog.get("T1041")
    assert exfiltration is not None
    assert exfiltration.display_name == "Exfiltration Over C2 Channel"


@pytest.mark.parametrize(
    ("requested", "emitted", "status"),
    [
        ("T1059.001", "T1059.001", TechniqueStatus.ACTIVE),
        ("T1070.001", "T1685.005", TechniqueStatus.REVOKED),
        ("T1043", "T1043", TechniqueStatus.DEPRECATED),
        ("T9999", "T9999", TechniqueStatus.UNKNOWN),
    ],
)
def test_resolution(requested: str, emitted: str, status: TechniqueStatus) -> None:
    resolution = load_catalog().resolve(requested)
    assert (resolution.technique_id, resolution.status) == (emitted, status)
    assert resolution.translated == (requested != emitted)
    assert (resolution.technique is None) == (status is TechniqueStatus.UNKNOWN)
    assert ("T1059.001" in load_catalog()) and ("T9999" not in load_catalog())


def test_tactic_lookup() -> None:
    catalog = load_catalog()
    tactic = catalog.tactic("defense-impairment")
    assert tactic is not None and tactic.tactic_id == "TA0112"
    assert catalog.tactic("defense-evasion") is None
