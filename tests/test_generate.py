"""Tests for the synthetic evidence generator (PRD FR33).

Two properties are load-bearing for the rest of the project:

  1. Determinism: the same seed always produces byte-identical output, so a clean
     clone regenerates the bundled samples exactly (FR34).
  2. Internal consistency: the ground-truth labels and the Hayabusa-style CSV agree
     with each other, the technique ids are well-formed, the full attack lifecycle
     is covered, and every IOC is synthetic and safe (Hard rule 3).
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import re
from pathlib import Path
from typing import Any

from casebound.generate import write_samples
from casebound.generate.scenarios import REQUIRED_STAGES
from casebound.generate.synth import (
    CSV_COLUMNS,
    CSV_FILENAME,
    DEFAULT_SEED,
    GROUND_TRUTH_FILENAME,
    HAYABUSA_SEP,
    generate,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLES_DIR = REPO_ROOT / "samples"

_TECHNIQUE_RE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
# Reserved, non-routable address ranges and TLDs that are always safe to ship.
_DOC_NETWORKS = [
    ipaddress.ip_network(cidr) for cidr in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")
]
_RESERVED_TLDS = (".example", ".invalid", ".test", ".localhost")


def _parse_csv(csv_text: str) -> list[dict[str, str]]:
    reader = csv.DictReader(io.StringIO(csv_text))
    return list(reader)


def _tags(cell: str) -> list[str]:
    return [t for t in cell.split(HAYABUSA_SEP) if t]


# 1. Determinism.


def test_same_seed_is_byte_identical() -> None:
    a = generate(seed=DEFAULT_SEED)
    b = generate(seed=DEFAULT_SEED)
    assert a.csv_text == b.csv_text
    assert a.ground_truth == b.ground_truth
    assert a.ground_truth_json == b.ground_truth_json
    assert a.record_ids == b.record_ids


def test_different_seed_changes_evidence_but_not_labels() -> None:
    a = generate(seed=DEFAULT_SEED)
    b = generate(seed=DEFAULT_SEED + 1)
    # The cosmetic identifiers (record ids, hashes) differ, so the CSV differs.
    assert a.csv_text != b.csv_text
    assert a.record_ids != b.record_ids
    assert a.ground_truth["iocs"]["hashes"] != b.ground_truth["iocs"]["hashes"]
    # The labeled events and the technique set do not depend on the seed.
    assert a.ground_truth["techniques"] == b.ground_truth["techniques"]
    assert a.ground_truth["stages"] == b.ground_truth["stages"]
    assert a.ground_truth["event_count"] == b.ground_truth["event_count"]
    assert [e["label_id"] for e in a.ground_truth["events"]] == [
        e["label_id"] for e in b.ground_truth["events"]
    ]


# 2. Internal consistency of the ground-truth labels.


def test_labels_are_unique_and_well_formed() -> None:
    gt = generate().ground_truth
    events = gt["events"]
    assert events, "expected at least one labeled ground-truth event"

    label_ids = [e["label_id"] for e in events]
    record_ids = [e["record_id"] for e in events]
    assert len(set(label_ids)) == len(label_ids), "label ids must be unique"
    assert len(set(record_ids)) == len(record_ids), "record ids must be unique"

    for event in events:
        assert event["technique_ids"], f"{event['label_id']} must carry a technique"
        for tid in event["technique_ids"]:
            assert _TECHNIQUE_RE.match(tid), f"malformed technique id {tid!r}"


def test_technique_set_is_the_union_of_event_techniques() -> None:
    gt = generate().ground_truth
    union = sorted({tid for e in gt["events"] for tid in e["technique_ids"]})
    assert gt["techniques"] == union
    assert gt["event_count"] == len(gt["events"])


def test_stages_cover_the_full_attack_lifecycle() -> None:
    gt = generate().ground_truth
    stages = {e["stage"] for e in gt["events"]}
    assert stages >= REQUIRED_STAGES, f"missing stages: {REQUIRED_STAGES - stages}"
    assert gt["stages"] == sorted(stages)


# 2b. The labels and the CSV agree with each other.


def test_csv_header_and_row_count() -> None:
    result = generate()
    rows = _parse_csv(result.csv_text)
    reader = csv.reader(io.StringIO(result.csv_text))
    header = next(reader)
    assert tuple(header) == CSV_COLUMNS
    # Every labeled event plus the benign noise events appear as rows.
    assert len(rows) >= len(result.ground_truth["events"])


def test_every_label_maps_to_a_consistent_csv_row() -> None:
    result = generate()
    rows = {row["RecordID"]: row for row in _parse_csv(result.csv_text)}

    for event in result.ground_truth["events"]:
        row = rows.get(event["record_id"])
        assert row is not None, f"record {event['record_id']} missing from CSV"
        assert row["Computer"] == event["computer"]
        assert row["RuleTitle"] == event["rule_title"]
        assert set(_tags(row["MitreTags"])) == set(event["technique_ids"])


def test_tagged_csv_rows_are_exactly_the_labeled_events() -> None:
    # Two-way consistency: a CSV row carries MITRE tags if and only if it is a
    # labeled ground-truth event, and the tag sets match.
    result = generate()
    tagged = {row["RecordID"] for row in _parse_csv(result.csv_text) if _tags(row["MitreTags"])}
    labeled = {e["record_id"] for e in result.ground_truth["events"]}
    assert tagged == labeled


def test_csv_is_sorted_chronologically() -> None:
    rows = _parse_csv(generate().csv_text)
    timestamps = [row["Timestamp"] for row in rows]
    assert timestamps == sorted(timestamps)


def test_spliced_hash_appears_in_both_csv_and_iocs() -> None:
    result = generate()
    hashes = result.ground_truth["iocs"]["hashes"]
    # At least one synthetic hash is spliced into the evidence and recorded as IOC.
    assert any(h in result.csv_text for h in hashes)


# 3. Everything shipped is synthetic and safe (Hard rule 3).


def test_declared_network_and_file_iocs_appear_in_evidence() -> None:
    # Casebound's premise is that findings cannot outrun the evidence, so a declared
    # ground-truth indicator must be recoverable from the evidence the pipeline sees.
    # Every ip, domain, and file IOC the ground truth names must appear in the CSV
    # (hashes are seed-derived and covered by test_spliced_hash_appears...).
    result = generate()
    csv_text = result.csv_text
    iocs = result.ground_truth["iocs"]
    for kind in ("ips", "domains", "files"):
        for indicator in iocs[kind]:
            assert indicator in csv_text, f"declared {kind} IOC {indicator!r} is not in evidence"


def test_all_ip_iocs_are_private_or_documentation_only() -> None:
    gt = generate().ground_truth
    for raw in gt["iocs"]["ips"]:
        addr = ipaddress.ip_address(raw)
        safe = addr.is_private or any(addr in net for net in _DOC_NETWORKS)
        assert safe, f"{raw} is not a private or documentation-only address"


def test_all_domain_iocs_use_reserved_tlds() -> None:
    gt = generate().ground_truth
    for domain in gt["iocs"]["domains"]:
        assert domain.endswith(_RESERVED_TLDS), f"{domain} is not a reserved-TLD domain"


def test_hashes_are_synthetic_hex_digests() -> None:
    gt = generate().ground_truth
    for digest in gt["iocs"]["hashes"]:
        assert re.fullmatch(r"[0-9a-f]{64}", digest), f"{digest!r} is not a SHA-256 hex digest"


def test_evidence_contains_no_working_url_scheme() -> None:
    # Endpoints are host:port, never live URLs, so nothing is click-to-fetch.
    csv_text = generate().csv_text.lower()
    assert "http://" not in csv_text
    assert "https://" not in csv_text


# 4. The committed samples are in sync and round-trip through disk.


def test_write_samples_round_trips(tmp_path: Path) -> None:
    csv_path, gt_path = write_samples(tmp_path)
    result = generate()
    assert csv_path.read_text(encoding="utf-8") == result.csv_text
    assert json.loads(gt_path.read_text(encoding="utf-8")) == result.ground_truth


def test_committed_samples_match_the_generator() -> None:
    # The bundled samples must equal a fresh default-seed generation, so a clean
    # clone reproduces them and they never drift silently.
    result = generate(seed=DEFAULT_SEED)
    csv_on_disk = (SAMPLES_DIR / CSV_FILENAME).read_text(encoding="utf-8")
    gt_on_disk: dict[str, Any] = json.loads(
        (SAMPLES_DIR / GROUND_TRUTH_FILENAME).read_text(encoding="utf-8")
    )
    assert csv_on_disk == result.csv_text
    assert gt_on_disk == result.ground_truth
