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

from casebound.cli import DEMO_REPORT_NAME, app, run_demo
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


def test_demo_command_writes_report_and_reports_status(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(app, ["demo", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    report = out_dir / DEMO_REPORT_NAME
    assert report.exists()
    # The default CLI path has no configured model, so it says so (FR26).
    assert "no language model configured" in result.output.lower()
    assert str(report) in result.output
