"""The synthetic evidence generator (PRD FR33).

Renders a ground-truth scenario (see ``casebound.generate.scenarios``) into the
two bundled artifacts the rest of the pipeline and the metrics run on, fully
offline:

  - a Hayabusa-style CSV timeline (the evidence the ingest layer consumes), and
  - a ground-truth label file (the known events and their MITRE ATT&CK technique
    ids that the metrics score the deterministic tagger against).

Both are produced together from one run so that record ids and synthetic hashes
stay consistent between the CSV and the labels.

Determinism is a hard requirement: the same seed always yields byte-identical
output. The scenario timeline (timestamps, hosts, actions, techniques) is fixed
data; the seed only drives cosmetic synthetic identifiers (the base EVTX record
number and the synthetic file hashes), so a different seed produces visibly
different evidence while preserving the same labeled events and technique set.

Hayabusa output reference: the CSV mirrors a verbose Hayabusa ``csv-timeline``
profile. Columns are Timestamp, Computer, Channel, EventID, Level, MitreTactics,
MitreTags, RecordID, RuleTitle, Details. Multi-value fields join with Hayabusa's
broken-bar separator. Timestamps render in the analyst's local zone with a UTC
offset, exactly as Hayabusa prints them, while the ground truth keeps the
canonical UTC instant. See https://github.com/Yamato-Security/hayabusa/wiki.

Everything emitted is synthetic and safe (Hard rule 3). Style: no em dashes or en
dashes anywhere (PRD Section 15).
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
from dataclasses import dataclass
from pathlib import Path
from random import Random
from typing import Any

from casebound.generate.scenarios import OFFICE_INTRUSION, Scenario, ScenarioEvent
from casebound.generate.scenarios.office_intrusion import (
    OUTPUT_OFFSET_LABEL,
    OUTPUT_TIMEZONE,
    OUTPUT_UTC_OFFSET,
)

# The default seed for the bundled samples. Pinned so a clean clone regenerates
# byte-identical evidence (FR34).
DEFAULT_SEED = 1337

# Hayabusa's default multi-value field separator: a space-padded broken bar
# (U+00A6). Spelled with an escape so it is unambiguous in source.
HAYABUSA_SEP = " ¦ "

# The Hayabusa-style CSV header (a verbose-profile subset). The ingest adapter
# that lands in a later step parses exactly these columns.
CSV_COLUMNS: tuple[str, ...] = (
    "Timestamp",
    "Computer",
    "Channel",
    "EventID",
    "Level",
    "MitreTactics",
    "MitreTags",
    "RecordID",
    "RuleTitle",
    "Details",
)

CSV_FILENAME = "synthetic_hayabusa.csv"
GROUND_TRUTH_FILENAME = "ground_truth.json"

GROUND_TRUTH_VERSION = "0.1"

__all__ = [
    "CSV_COLUMNS",
    "CSV_FILENAME",
    "DEFAULT_SEED",
    "GROUND_TRUTH_FILENAME",
    "GeneratedScenario",
    "generate",
    "write_samples",
]


@dataclass(frozen=True)
class GeneratedScenario:
    """The rendered output of one generation run.

    ``csv_text`` is the Hayabusa-style timeline. ``ground_truth`` is the label
    structure (also available serialized as ``ground_truth_json``). ``record_ids``
    maps each scenario event's ``label_id`` to the EVTX record id it was assigned,
    so callers can cross-reference the CSV and the labels.
    """

    seed: int
    csv_text: str
    ground_truth: dict[str, Any]
    record_ids: dict[str, str]

    @property
    def ground_truth_json(self) -> str:
        """The ground truth serialized to deterministic, human-readable JSON."""
        return json.dumps(self.ground_truth, indent=2, ensure_ascii=False) + "\n"


def _synthetic_hash(scenario_name: str, seed: int, name: str) -> str:
    """A deterministic, obviously-synthetic SHA-256 for a named artifact.

    Derived from the seed so different seeds produce different hashes, while the
    same seed always reproduces the same value. These are not hashes of any real
    file: they exist only to give the IOC set a realistic shape.
    """
    material = f"casebound-synth/{scenario_name}/{seed}/{name}"
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _format_local_timestamp(event: ScenarioEvent) -> str:
    """Render an event time the way Hayabusa prints it: local time plus offset."""
    local = (event.datetime_utc() + OUTPUT_UTC_OFFSET).replace(tzinfo=None)
    return f"{local:%Y-%m-%d %H:%M:%S}.000 {OUTPUT_OFFSET_LABEL}"


def _format_utc_iso(event: ScenarioEvent) -> str:
    """Render an event time as a canonical UTC ISO 8601 string with a trailing Z."""
    return f"{event.datetime_utc():%Y-%m-%dT%H:%M:%S}Z"


def _render_details(event: ScenarioEvent, hashes: dict[str, str]) -> str:
    """Pack an event's detail pairs into the Hayabusa Details field.

    When the event names a hash IOC, the seed-derived hash is spliced in so the
    same value appears in both the CSV and the ground-truth IOC set.
    """
    pairs = list(event.details)
    if event.hash_ioc is not None:
        pairs.append(("Hashes", f"SHA256={hashes[event.hash_ioc]}"))
    return HAYABUSA_SEP.join(f"{key}: {value}" for key, value in pairs)


def _assign_record_ids(scenario: Scenario, rng: Random) -> dict[str, str]:
    """Assign each event a plausible, strictly increasing EVTX record id.

    Hayabusa output is sorted by time, so record ids climb with the timeline. The
    base and the gaps are seed-driven, which is what makes a different seed yield
    visibly different evidence.
    """
    record = rng.randint(10_000, 90_000)
    record_ids: dict[str, str] = {}
    for event in scenario.ordered_events():
        record += rng.randint(3, 97)
        record_ids[event.label_id] = str(record)
    return record_ids


def _render_csv(scenario: Scenario, record_ids: dict[str, str], hashes: dict[str, str]) -> str:
    """Render the scenario to a Hayabusa-style CSV string."""
    buffer = io.StringIO()
    # QUOTE_ALL and a plain newline mirror Hayabusa's quoting and keep the bytes
    # identical across platforms.
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerow(CSV_COLUMNS)
    for event in scenario.ordered_events():
        writer.writerow(
            [
                _format_local_timestamp(event),
                event.computer,
                event.channel,
                str(event.win_event_id),
                event.level,
                HAYABUSA_SEP.join(event.mitre_tactics),
                HAYABUSA_SEP.join(event.technique_ids),
                record_ids[event.label_id],
                event.rule_title,
                _render_details(event, hashes),
            ]
        )
    return buffer.getvalue()


def _build_ground_truth(
    scenario: Scenario,
    seed: int,
    record_ids: dict[str, str],
    hashes: dict[str, str],
) -> dict[str, Any]:
    """Build the ground-truth label structure the metrics score against."""
    labeled = scenario.labeled_events()

    events: list[dict[str, Any]] = []
    for event in labeled:
        events.append(
            {
                "label_id": event.label_id,
                "stage": event.stage,
                "record_id": record_ids[event.label_id],
                "timestamp_utc": _format_utc_iso(event),
                "computer": event.computer,
                "principal": event.principal,
                "action": event.action,
                "object": event.object,
                "technique_ids": list(event.technique_ids),
                "mitre_tactics": list(event.mitre_tactics),
                "rule_title": event.rule_title,
                "message": event.message,
            }
        )

    techniques = sorted({tid for event in labeled for tid in event.technique_ids})
    stages = sorted({event.stage for event in labeled})

    return {
        "scenario": scenario.name,
        "description": scenario.description,
        "version": GROUND_TRUTH_VERSION,
        "seed": seed,
        "source_csv": CSV_FILENAME,
        "source_tool": "hayabusa",
        "output_timezone": OUTPUT_TIMEZONE,
        "hosts": list(scenario.hosts),
        "principals": list(scenario.principals),
        "stages": stages,
        "techniques": techniques,
        "iocs": {
            "ips": list(scenario.ip_iocs),
            "domains": list(scenario.domain_iocs),
            "files": list(scenario.file_iocs),
            "hashes": [hashes[name] for name in scenario.hash_iocs],
        },
        "event_count": len(events),
        "events": events,
    }


def generate(scenario: Scenario = OFFICE_INTRUSION, seed: int = DEFAULT_SEED) -> GeneratedScenario:
    """Render a scenario into a Hayabusa-style CSV plus a ground-truth label set.

    Deterministic: the same ``scenario`` and ``seed`` always produce byte-identical
    ``csv_text`` and ``ground_truth``.
    """
    rng = Random(seed)  # nosec B311  # cosmetic ids only, never for security
    # Hashes are derived directly from the seed (not the rng stream) so they do not
    # depend on how many other draws happen first.
    hashes = {name: _synthetic_hash(scenario.name, seed, name) for name in scenario.hash_iocs}
    record_ids = _assign_record_ids(scenario, rng)

    csv_text = _render_csv(scenario, record_ids, hashes)
    ground_truth = _build_ground_truth(scenario, seed, record_ids, hashes)

    return GeneratedScenario(
        seed=seed,
        csv_text=csv_text,
        ground_truth=ground_truth,
        record_ids=record_ids,
    )


def write_samples(
    dest_dir: Path,
    scenario: Scenario = OFFICE_INTRUSION,
    seed: int = DEFAULT_SEED,
) -> tuple[Path, Path]:
    """Generate the scenario and write both artifacts under ``dest_dir``.

    Returns the (csv_path, ground_truth_path) written. Offline, no network.
    """
    result = generate(scenario, seed)
    dest_dir.mkdir(parents=True, exist_ok=True)
    csv_path = dest_dir / CSV_FILENAME
    ground_truth_path = dest_dir / GROUND_TRUTH_FILENAME
    csv_path.write_text(result.csv_text, encoding="utf-8")
    ground_truth_path.write_text(result.ground_truth_json, encoding="utf-8")
    return csv_path, ground_truth_path
