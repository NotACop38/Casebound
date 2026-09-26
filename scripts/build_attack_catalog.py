#!/usr/bin/env python3
"""Build the bundled MITRE ATT&CK Enterprise catalog from an official STIX bundle.

Casebound validates, names, and places every technique id it emits against a
compact catalog shipped inside the package (``casebound/data/attack-enterprise.json``).
This script regenerates that catalog from MITRE's published STIX 2.1 bundle, so the
catalog is reproducible and re-verifiable rather than hand-maintained.

It is fully offline: it reads a bundle you downloaded yourself and never fetches
anything. To refresh the catalog for a new ATT&CK release:

    curl -LO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack-19.2.json
    python scripts/build_attack_catalog.py enterprise-attack-19.2.json

What the catalog keeps, per technique (sub-techniques included):

  - ``name``: the technique's own ATT&CK name (a sub-technique's display name is
    composed with its parent's at load time, for example
    "OS Credential Dumping: LSASS Memory").
  - ``tactics``: the kill-chain phase shortnames the technique belongs to.
  - ``deprecated``: present and true when MITRE deprecated it without a successor.
  - ``revoked_by``: present when MITRE revoked it, naming the final active successor
    (revocation chains are resolved here, so a lookup is always one hop).

Tactics are recorded in the Enterprise matrix's own left-to-right order, which is
the column order of the report's ATT&CK matrix.

Style: no em dashes or en dashes anywhere.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUTPUT = ROOT / "casebound" / "data" / "attack-enterprise.json"
SOURCE_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
    "enterprise-attack/enterprise-attack-{version}.json"
)


def _attack_id(obj: dict[str, Any]) -> str | None:
    """Return the ATT&CK external id (for example T1059.001 or TA0002) of a STIX object."""
    for ref in obj.get("external_references", []):
        if ref.get("source_name") == "mitre-attack" and ref.get("external_id"):
            return str(ref["external_id"])
    return None


def build_catalog(bundle: dict[str, Any]) -> dict[str, Any]:
    """Distil a STIX bundle into the compact catalog structure."""
    objects: list[dict[str, Any]] = bundle["objects"]
    by_stix_id = {obj["id"]: obj for obj in objects}

    collections = [obj for obj in objects if obj["type"] == "x-mitre-collection"]
    matrices = [obj for obj in objects if obj["type"] == "x-mitre-matrix"]
    if len(collections) != 1 or len(matrices) != 1:
        raise ValueError("expected exactly one ATT&CK collection and one matrix in the bundle")
    collection, matrix = collections[0], matrices[0]
    version = str(collection["x_mitre_version"])

    tactics = []
    for ref in matrix["tactic_refs"]:
        tactic = by_stix_id[ref]
        tactics.append(
            {
                "id": _attack_id(tactic),
                "shortname": tactic["x_mitre_shortname"],
                "name": tactic["name"],
            }
        )

    patterns = {obj["id"]: obj for obj in objects if obj["type"] == "attack-pattern"}
    revoked_by = {
        rel["source_ref"]: rel["target_ref"]
        for rel in objects
        if rel["type"] == "relationship" and rel.get("relationship_type") == "revoked-by"
    }

    def final_successor(stix_id: str) -> str | None:
        """Follow a revocation chain to the first successor that is not itself revoked."""
        seen: set[str] = set()
        current = revoked_by.get(stix_id)
        while current is not None and current not in seen:
            seen.add(current)
            target = patterns.get(current)
            if target is None:
                return None
            if not target.get("revoked"):
                return _attack_id(target)
            current = revoked_by.get(current)
        return None

    techniques: dict[str, dict[str, Any]] = {}
    for stix_id, pattern in patterns.items():
        technique_id = _attack_id(pattern)
        if technique_id is None:
            continue
        entry: dict[str, Any] = {"name": pattern["name"]}
        phases = sorted(
            {
                phase["phase_name"]
                for phase in pattern.get("kill_chain_phases", [])
                if phase.get("kill_chain_name") == "mitre-attack"
            }
        )
        if pattern.get("revoked"):
            successor = final_successor(stix_id)
            if successor is not None:
                entry["revoked_by"] = successor
            else:
                entry["deprecated"] = True
        else:
            entry["tactics"] = phases
            if pattern.get("x_mitre_deprecated"):
                entry["deprecated"] = True
        if technique_id in techniques:
            raise ValueError(f"duplicate technique id in bundle: {technique_id}")
        techniques[technique_id] = entry

    return {
        "domain": "enterprise-attack",
        "attack_version": version,
        "modified": collection["modified"],
        "source": SOURCE_URL.format(version=version),
        "tactics": tactics,
        "techniques": dict(sorted(techniques.items())),
    }


def render_catalog(catalog: dict[str, Any]) -> str:
    """Render the catalog as stable JSON with one technique per line for readable diffs."""
    lines = ["{"]
    for key in ("domain", "attack_version", "modified", "source"):
        lines.append(f"  {json.dumps(key)}: {json.dumps(catalog[key])},")
    lines.append('  "tactics": [')
    tactic_lines = [f"    {json.dumps(tactic, sort_keys=True)}" for tactic in catalog["tactics"]]
    lines.append(",\n".join(tactic_lines))
    lines.append("  ],")
    lines.append('  "techniques": {')
    technique_lines = [
        f"    {json.dumps(tid)}: {json.dumps(entry, sort_keys=True)}"
        for tid, entry in catalog["techniques"].items()
    ]
    lines.append(",\n".join(technique_lines))
    lines.append("  }")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("bundle", type=Path, help="path to an enterprise-attack STIX bundle")
    parser.add_argument(
        "--output", type=Path, default=DEFAULT_OUTPUT, help="where to write the catalog"
    )
    args = parser.parse_args(argv)

    bundle = json.loads(args.bundle.read_text(encoding="utf-8"))
    catalog = build_catalog(bundle)
    text = render_catalog(catalog)
    json.loads(text)  # the hand-rolled layout must still be valid JSON
    args.output.write_text(text, encoding="utf-8")

    active = sum(
        1
        for entry in catalog["techniques"].values()
        if "revoked_by" not in entry and not entry.get("deprecated")
    )
    print(
        f"wrote {args.output} (ATT&CK {catalog['attack_version']}: "
        f"{len(catalog['tactics'])} tactics, {active} active techniques, "
        f"{len(catalog['techniques']) - active} revoked or deprecated)"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
