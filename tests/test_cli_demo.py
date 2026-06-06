"""Tests for the one-command offline demo (PRD FR34, Phase 1 exit criteria).

The demo runs the whole slice on the bundled synthetic scenario: ingest,
normalize, tag ATT&CK, verify the narrative against a model, and render the
self-contained HTML report. It must run offline with no API keys.

  1. With a model (the mocked model the tests use), the verifier runs and the
     report carries the verified narrative.
  2. With no model configured, the deterministic no-model path is taken: the
     report is still written and says no narrative was produced (FR26).
  3. The CLI command writes out/report.html and reports what it did.

No network, no API keys.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from casebound.cli import (
    DEMO_JSON_NAME,
    DEMO_LAYER_NAME,
    DEMO_MARKDOWN_NAME,
    DEMO_METRICS_NAME,
    DEMO_REPORT_NAME,
    app,
    run_demo,
)
from casebound.narrate import OfflineDemoNarrator
from casebound.verify import DraftRequest
from typer.testing import CliRunner

# A real event id from the office_intrusion scenario at the default seed: the
# Word-spawned encoded PowerShell process-create event.
PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"

# The grounded claim from the bundled hallucination trap, against the default seed.
GROUNDED_CLAIM: dict[str, Any] = {
    "text": "On WIN-ACCT-07, CORP\\jdoe ran an encoded PowerShell process spawned from Word.",
    "citations": [PROCESS_CREATE_ID],
    "asserts": {
        "datetime": "2026-03-14T08:42:17Z",
        "principal": "CORP\\jdoe",
        "action": "process_create",
        "object": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
    },
}


class StubModel:
    """A mocked ``NarrativeModel`` that replays one grounded claim every round."""

    def draft(self, request: DraftRequest) -> str:
        return json.dumps({"claims": [GROUNDED_CLAIM]})


def test_demo_with_model_produces_a_verified_narrative(tmp_path: Path) -> None:
    result = run_demo(tmp_path, model=StubModel())

    assert result.no_model is False
    assert result.event_count > 0
    assert result.problem_count == 0
    assert result.technique_count > 0
    assert result.accepted_count == 1
    assert result.rejected_count == 0

    assert result.report_path == tmp_path / DEMO_REPORT_NAME
    html = result.report_path.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "<script" not in html
    # The verified narrative links its citation to the backing event in the appendix.
    assert f'href="#event-{PROCESS_CREATE_ID}"' in html
    assert f'id="event-{PROCESS_CREATE_ID}"' in html


def test_demo_writes_all_outputs_and_metrics_hit_targets(tmp_path: Path) -> None:
    # The demo writes the HTML report plus its siblings (JSON, Markdown, the ATT&CK
    # Navigator layer, and the persisted metrics), and the metrics hit their targets.
    result = run_demo(tmp_path, model=StubModel())

    for name in (
        DEMO_REPORT_NAME,
        DEMO_JSON_NAME,
        DEMO_MARKDOWN_NAME,
        DEMO_LAYER_NAME,
        DEMO_METRICS_NAME,
    ):
        assert (tmp_path / name).exists(), f"{name} was not written"

    assert result.metrics.meets_targets() is True
    assert result.metrics.coverage == result.technique_count
    persisted = json.loads(result.metrics_path.read_text(encoding="utf-8"))
    assert persisted["meets_targets"] is True
    assert persisted["hallucination_rejection_rate"] == 1.0


def test_demo_command_prints_the_metrics(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(app, ["demo", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert "hallucination-rejection rate: 1.00" in result.output
    assert "citation accuracy: 1.00" in result.output
    assert "att&ck precision" in result.output.lower()
    assert "technique coverage" in result.output
    assert "targets met: yes" in result.output


def test_demo_command_fails_when_a_metric_misses_its_target(
    tmp_path: Path, monkeypatch: Any
) -> None:
    # The demo is a reproducibility check: a metric below target must fail the run
    # (non-zero exit), not be written out silently. Force a miss and assert that.
    from casebound.metrics import Metrics

    monkeypatch.setattr(Metrics, "meets_targets", lambda self: False)
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(app, ["demo", "--out-dir", str(out_dir)])

    assert result.exit_code == 1
    assert "targets met: no" in result.output
    # The outputs are still written for debugging even though the run failed.
    assert (out_dir / DEMO_METRICS_NAME).exists()


def test_demo_without_model_writes_deterministic_report(tmp_path: Path) -> None:
    result = run_demo(tmp_path, model=None)

    assert result.no_model is True
    assert result.event_count > 0
    assert result.technique_count > 0
    assert result.accepted_count == 0
    assert result.rejected_count == 0

    html = result.report_path.read_text(encoding="utf-8")
    assert "No language model configured" in html
    assert 'class="claim"' not in html


def test_demo_with_offline_narrator_populates_narrative_and_audit(tmp_path: Path) -> None:
    # The bundled offline narrator drafts grounded claims (accepted) plus seeded
    # fabrications (rejected), so the report carries both a verified narrative and a
    # non-empty rejected-claims audit, all offline.
    result = run_demo(
        tmp_path,
        model=OfflineDemoNarrator(),
        model_label=OfflineDemoNarrator.LABEL,
        max_rounds=0,
    )

    assert result.no_model is False
    assert result.accepted_count > 0
    assert result.rejected_count == 2

    html = result.report_path.read_text(encoding="utf-8")
    assert OfflineDemoNarrator.LABEL in html
    assert 'class="claim"' in html
    # The audit shows the two seeded fabrications being caught.
    assert "principal_mismatch" in html
    assert "missing_id" in html


def test_demo_command_default_uses_offline_narrator(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(app, ["demo", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    report = out_dir / DEMO_REPORT_NAME
    assert report.exists()
    # The default path drafts with the bundled offline narrator and runs the verifier.
    assert "offline demo narrator" in result.output.lower()
    assert "verified narrative" in result.output.lower()
    assert str(report) in result.output

    html = report.read_text(encoding="utf-8")
    assert 'class="claim"' in html
    assert "principal_mismatch" in html


def test_demo_command_no_model_flag_is_deterministic(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(app, ["demo", "--out-dir", str(out_dir), "--no-model"])

    assert result.exit_code == 0, result.output
    report = out_dir / DEMO_REPORT_NAME
    assert report.exists()
    assert "no language model configured: wrote the deterministic report" in result.output
    # No narrative was produced on the no-model path (FR26).
    assert 'class="claim"' not in report.read_text(encoding="utf-8")
