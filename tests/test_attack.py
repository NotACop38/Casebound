"""Tests for deterministic ATT&CK tagging (PRD FR13, FR14, Section 12).

The load-bearing properties:

  1. Passthrough: a rule-based source's native technique ids reach
     ``attack_techniques`` verbatim, marked ``rule_tag``, deduplicated, with any
     non-id string ignored (FR13).
  2. Mapping table: an event from a source with no detection layer is matched
     against the small documented table on its canonical fields and tagged
     ``mapping_table``, while an ambiguous or unrelated event is left untagged
     (FR14). A detection source's untagged rows stay untagged: the rule already
     judged them informational.
  3. Provenance: every emitted tag records how it was made (FR14), and the table
     never overrides a native tag.
  4. Scenario accuracy: against the showcase ground truth the deterministic
     tagger meets the PRD Section 12 targets, precision at least 0.9 and recall at
     least 0.7, and leaves every benign row untagged.
"""

from __future__ import annotations

import json
from pathlib import Path

from casebound.enrich import (
    MAPPING_SOURCE_RULE_TAG,
    MAPPING_SOURCE_TABLE,
    tag_event,
    tag_events,
)
from casebound.enrich.attack import DETECTION_SOURCES, MAPPING_TABLE
from casebound.enrich.catalog import load_catalog
from casebound.generate.synth import write_samples
from casebound.ingest import HayabusaAdapter
from casebound.normalize import Event, RawRef, normalize_records
from casebound.normalize.schema import SOURCE_TOOLS

# PRD Section 12 targets for the deterministic tagger on the showcase scenario.
MIN_PRECISION = 0.9
MIN_RECALL = 0.7


def _event(
    action: str,
    *,
    obj: str | None = None,
    rule_tags: list[str] | None = None,
    details: dict[str, object] | None = None,
    source_tool: str | None = None,
) -> Event:
    """Build a minimal canonical event for tagging tests.

    ``rule_tags`` populate the native-tag detail key the normalize layer uses;
    ``details`` lets a test override the whole details payload. The source defaults
    to Hayabusa when the event carries rule tags and to Velociraptor (raw event
    logs, no detection layer) otherwise, so table tests exercise the table.
    """
    payload: dict[str, object] = dict(details or {})
    if rule_tags is not None:
        payload["rule_mitre_tags"] = rule_tags
    return Event(
        datetime="2026-03-14T08:42:17Z",
        timestamp_raw="2026-03-14 04:42:17.000 -04:00",
        source_timezone="UTC-04:00",
        timestamp_desc="logged",
        message="synthetic event for tagging",
        action=action,
        source_tool=source_tool or ("hayabusa" if rule_tags is not None else "velociraptor"),
        source_artifact="Security.evtx",
        raw_ref=RawRef(source_file="x.csv", record="1"),
        object=obj,
        details=payload,
    )


# 1. Rule-tag passthrough (FR13).


def test_native_tags_pass_through_marked_rule_tag() -> None:
    event = tag_event(_event("process_create", rule_tags=["T1566.001", "T1059.001"]))
    assert [(t.technique_id, t.mapping_source) for t in event.attack_techniques] == [
        ("T1566.001", MAPPING_SOURCE_RULE_TAG),
        ("T1059.001", MAPPING_SOURCE_RULE_TAG),
    ]


def test_passthrough_dedupes_and_ignores_non_ids() -> None:
    # A duplicate id collapses; a tactic name or junk string is not promoted.
    event = tag_event(
        _event(
            "process_create",
            rule_tags=["T1059.001", "T1059.001", "Execution", "not-an-id"],
        )
    )
    assert [t.technique_id for t in event.attack_techniques] == ["T1059.001"]
    assert all(t.mapping_source == MAPPING_SOURCE_RULE_TAG for t in event.attack_techniques)


def test_event_id_is_unchanged_by_tagging() -> None:
    # attack_techniques is not a core identity field, so tagging never moves the id.
    base = _event("scheduled_task_create")
    assert tag_event(base).event_id == base.event_id


# 2. The documented mapping table (FR14).


def test_table_tags_untagged_scheduled_task() -> None:
    event = tag_event(_event("scheduled_task_create", obj="\\MicrosoftUpdaterTask"))
    assert [(t.technique_id, t.mapping_source) for t in event.attack_techniques] == [
        ("T1053.005", MAPPING_SOURCE_TABLE),
    ]


def test_table_tags_service_install() -> None:
    event = tag_event(_event("service_install", obj="WinHelpSvc"))
    assert [(t.technique_id, t.mapping_source) for t in event.attack_techniques] == [
        ("T1543.003", MAPPING_SOURCE_TABLE),
    ]


def test_table_refines_on_object_for_lsass() -> None:
    lsass = tag_event(_event("process_access", obj="C:\\Windows\\System32\\lsass.exe"))
    assert [t.technique_id for t in lsass.attack_techniques] == ["T1003.001"]
    # Opening a handle into an unrelated process is not credential dumping.
    other = tag_event(_event("process_access", obj="C:\\Windows\\System32\\notepad.exe"))
    assert other.attack_techniques == []


def test_table_refines_on_object_for_run_key() -> None:
    run_key = tag_event(
        _event(
            "registry_set",
            obj="HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Updater",
        )
    )
    assert [t.technique_id for t in run_key.attack_techniques] == ["T1547.001"]
    benign = tag_event(_event("registry_set", obj="HKLM\\Software\\Vendor\\Settings"))
    assert benign.attack_techniques == []


def test_table_tags_admin_share() -> None:
    event = tag_event(_event("network_share_access", obj="\\\\WIN-FILE-02\\ADMIN$"))
    assert [t.technique_id for t in event.attack_techniques] == ["T1021.002"]


def test_detection_source_rows_without_rule_tags_are_not_table_tagged() -> None:
    # An informational Hayabusa rule (a routine service install) carries no tags:
    # the rule judged it context, so the table does not second-guess it.
    for source in sorted(DETECTION_SOURCES):
        event = _event("service_install", obj="WinHelpSvc", source_tool=source)
        assert tag_event(event).attack_techniques == []


def test_table_only_mode_applies_the_table_to_every_source() -> None:
    # The evaluation isolates the table by ignoring rule tags on every source.
    event = _event("service_install", obj="WinHelpSvc", source_tool="hayabusa")
    tagged = tag_event(event, use_rule_tags=False)
    assert [(t.technique_id, t.mapping_source) for t in tagged.attack_techniques] == [
        ("T1543.003", MAPPING_SOURCE_TABLE),
    ]


def test_detection_sources_are_canonical_source_tools() -> None:
    assert DETECTION_SOURCES <= SOURCE_TOOLS


def test_revoked_rule_tag_translates_to_its_successor() -> None:
    # Rules written before ATT&CK v19 tag log clearing as T1070.001, which v19
    # revoked in favour of T1685.005; the original id is kept as source_id.
    event = tag_event(_event("log_clear", rule_tags=["T1070.001"]))
    assert [(t.technique_id, t.source_id) for t in event.attack_techniques] == [
        ("T1685.005", "T1070.001"),
    ]


def test_unknown_rule_tag_is_kept_as_written() -> None:
    # An id newer than the bundled catalog is not dropped: the report flags it.
    event = tag_event(_event("process_create", rule_tags=["T9999.001"]))
    assert [(t.technique_id, t.source_id) for t in event.attack_techniques] == [("T9999.001", None)]


def test_every_table_technique_is_active_in_the_bundled_catalog() -> None:
    catalog = load_catalog()
    for rule in MAPPING_TABLE:
        technique = catalog.get(rule.technique_id)
        assert technique is not None and technique.is_active, rule.technique_id
        assert rule.rationale, rule.technique_id


def test_ambiguous_action_is_left_untagged() -> None:
    # A bare logon is not, on its own, evidence of any single technique, so the
    # table assigns nothing and precision is preserved on benign noise.
    assert tag_event(_event("logon", obj="10.4.12.66")).attack_techniques == []


# 3. Provenance and priority.


def test_native_tags_win_over_the_table() -> None:
    # An event that matches a table rule but already carries a native tag keeps the
    # passthrough provenance only; the table is a fallback, not an addition.
    event = tag_event(
        _event("scheduled_task_create", obj="\\MicrosoftUpdaterTask", rule_tags=["T1053.005"])
    )
    assert [(t.technique_id, t.mapping_source) for t in event.attack_techniques] == [
        ("T1053.005", MAPPING_SOURCE_RULE_TAG),
    ]


def test_tagging_is_idempotent() -> None:
    once = tag_event(_event("service_install", obj="WinHelpSvc"))
    twice = tag_event(once)
    assert [t.to_dict() for t in twice.attack_techniques] == [
        t.to_dict() for t in once.attack_techniques
    ]


def test_every_tag_records_a_known_mapping_source() -> None:
    events = tag_events(
        [
            _event("process_create", rule_tags=["T1059.001"]),
            _event("service_install", obj="WinHelpSvc"),
        ]
    )
    sources = {t.mapping_source for e in events for t in e.attack_techniques}
    assert sources == {MAPPING_SOURCE_RULE_TAG, MAPPING_SOURCE_TABLE}


# 4. Accuracy against the scenario ground truth (PRD Section 12).


def test_precision_and_recall_meet_targets(tmp_path: Path) -> None:
    csv_path, _ = write_samples(tmp_path)
    result = normalize_records(HayabusaAdapter().read(csv_path))
    assert result.problem_count == 0
    tagged = tag_events(result.events)

    # The generator writes the ground truth alongside the CSV; load it from disk so
    # the score is measured against exactly the labels the evidence was built from.
    ground_truth = json.loads((tmp_path / "ground_truth.json").read_text(encoding="utf-8"))

    predicted = {
        (event.raw_ref.record, tech.technique_id)
        for event in tagged
        for tech in event.attack_techniques
    }
    truth = {
        (gt_event["record_id"], tid)
        for gt_event in ground_truth["events"]
        for tid in gt_event["technique_ids"]
    }

    true_positives = predicted & truth
    precision = len(true_positives) / len(predicted)
    recall = len(true_positives) / len(truth)

    assert precision >= MIN_PRECISION, f"precision {precision} below {MIN_PRECISION}"
    assert recall >= MIN_RECALL, f"recall {recall} below {MIN_RECALL}"
    # Every labeled event in this scenario is a Hayabusa detection whose rule
    # carries its technique (one of them under a revoked id the tagger must
    # translate), so the tagger is exact here; assert it to catch any regression.
    assert precision == 1.0
    assert recall == 1.0


def test_benign_noise_rows_get_no_tags(tmp_path: Path) -> None:
    # The benign rows include look-alikes of the intrusion (a vendor Run key, a
    # Defender LSASS read, a routine service install and scheduled task, an admin
    # PowerShell session). They come from informational rules without ATT&CK tags,
    # so none of them may land on the report's ATT&CK matrix.
    csv_path, labels_path = write_samples(tmp_path)
    labeled = {
        str(label["record_id"])
        for label in json.loads(labels_path.read_text(encoding="utf-8"))["events"]
    }
    result = normalize_records(HayabusaAdapter().read(csv_path))
    tagged = tag_events(result.events)
    benign = [event for event in tagged if event.raw_ref.record not in labeled]
    assert len(benign) == len(tagged) - len(labeled) > 0
    assert [event.raw_ref.record for event in benign if event.attack_techniques] == []
