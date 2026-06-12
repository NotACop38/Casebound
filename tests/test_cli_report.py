"""Tests for the report command: the full pipeline on user evidence (PRD Section 8).

The report command is how an analyst runs Casebound on their own already-collected
tool output: ingest with the adapter for --source, normalize, tag ATT&CK, cluster
episodes, extract IOCs, verify the narrative when a model is configured, and write
the HTML, JSON, and Markdown reports plus the Navigator layer.

  1. With no model configured the deterministic no-model path is taken (FR26): the
     reports are written with no narrative and no metrics file (user evidence has
     no ground-truth labels).
  2. With a model (the mocked model the tests use), the verifier runs: grounded
     claims are accepted and a fabricated claim is rejected and logged.
  3. The source and column-map flag combinations are validated with clear errors,
     and a wrong --source (no row normalizes) fails with the per-row reasons.

No network, no API keys.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import Any, NoReturn

import pytest
from casebound.cli import (
    METRICS_NAME,
    NAVIGATOR_LAYER_NAME,
    REPORT_HTML_NAME,
    REPORT_JSON_NAME,
    REPORT_MARKDOWN_NAME,
    EmptyTimelineError,
    app,
    run_report,
)
from casebound.verify import DraftRequest
from typer.testing import CliRunner

FIXTURES = Path(__file__).parent / "fixtures"
HAYABUSA_CSV = FIXTURES / "hayabusa_slice.csv"
HAYABUSA_GOLDEN = FIXTURES / "hayabusa_slice.events.json"
GENERIC_CSV = FIXTURES / "generic_edr_slice.csv"
GENERIC_MAP = FIXTURES / "generic_edr_map.json"

# A well-formed but nonexistent event id, for the fabricated claim the verifier
# must reject (FR22).
NONEXISTENT_EVENT_ID = "deadbeef" * 8


def _grounded_claim() -> dict[str, Any]:
    """Build a grounded claim from the hayabusa golden fixture's first event.

    Asserting exactly the golden event's checked fields means the claim is accepted
    by construction, without hardcoding an event id that would rot if the fixture
    changes.
    """
    golden = json.loads(HAYABUSA_GOLDEN.read_text(encoding="utf-8"))
    event = next(e for e in golden["events"] if e["action"] == "process_create")
    return {
        "text": "An encoded PowerShell process was spawned from Word.",
        "citations": [event["event_id"]],
        "asserts": {
            "datetime": event["datetime"],
            "principal": event["principal"],
            "action": event["action"],
            "object": event["object"],
        },
    }


class StubModel:
    """A mocked ``NarrativeModel``: one grounded claim plus one fabrication."""

    def draft(self, request: DraftRequest) -> str:
        if request.is_revision:
            return json.dumps({"claims": []})
        fabricated = {
            "text": "The actor deployed ransomware that encrypted the file server.",
            "citations": [NONEXISTENT_EVENT_ID],
            "asserts": {"action": "file_write"},
        }
        return json.dumps({"claims": [_grounded_claim(), fabricated]})


def test_run_report_no_model_writes_deterministic_outputs(tmp_path: Path) -> None:
    result = run_report(HAYABUSA_CSV, "hayabusa", tmp_path)

    assert result.no_model is True
    assert result.event_count > 0
    assert result.problem_count == 0
    assert result.technique_count > 0
    assert result.accepted_count == 0
    assert result.rejected_count == 0

    for name in (REPORT_HTML_NAME, REPORT_JSON_NAME, REPORT_MARKDOWN_NAME, NAVIGATOR_LAYER_NAME):
        assert (tmp_path / name).exists(), f"{name} was not written"
    # User evidence carries no ground truth, so no metrics file is written.
    assert not (tmp_path / METRICS_NAME).exists()

    html = (tmp_path / REPORT_HTML_NAME).read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in html
    assert "No language model configured" in html
    assert 'class="claim"' not in html


def test_run_report_with_model_verifies_and_audits(tmp_path: Path) -> None:
    result = run_report(
        HAYABUSA_CSV,
        "hayabusa",
        tmp_path,
        model=StubModel(),
        model_label="stub model (test)",
        max_rounds=0,
    )

    assert result.no_model is False
    assert result.accepted_count == 1
    assert result.rejected_count == 1

    html = result.report_path.read_text(encoding="utf-8")
    assert "stub model (test)" in html
    assert 'class="claim"' in html
    # The fabricated claim was rejected for citing a nonexistent event id.
    assert "missing_id" in html

    claim = _grounded_claim()
    backing_id = claim["citations"][0]
    assert f'href="#event-{backing_id}"' in html
    assert f'id="event-{backing_id}"' in html


def test_run_report_labels_the_case_from_the_file_name(tmp_path: Path) -> None:
    result = run_report(HAYABUSA_CSV, "hayabusa", tmp_path)
    payload = json.loads(result.json_path.read_text(encoding="utf-8"))
    assert payload["scenario"] == "hayabusa_slice"
    assert payload["source_tool"] == "hayabusa"


def test_report_command_runs_end_to_end(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "report",
            str(HAYABUSA_CSV),
            "--source",
            "hayabusa",
            "--out-dir",
            str(out_dir),
            "--case-name",
            "ACME triage",
            "--no-model",
        ],
    )

    assert result.exit_code == 0, result.output
    assert "ingested" in result.output
    assert "event(s)" in result.output
    assert "no language model configured" in result.output.lower()
    assert (out_dir / REPORT_HTML_NAME).exists()
    payload = json.loads((out_dir / REPORT_JSON_NAME).read_text(encoding="utf-8"))
    assert payload["scenario"] == "ACME triage"


def test_report_command_generic_csv_with_column_map(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "report",
            str(GENERIC_CSV),
            "--source",
            "generic_csv",
            "--column-map",
            str(GENERIC_MAP),
            "--out-dir",
            str(out_dir),
        ],
    )

    assert result.exit_code == 0, result.output
    assert (out_dir / REPORT_HTML_NAME).exists()
    payload = json.loads((out_dir / REPORT_JSON_NAME).read_text(encoding="utf-8"))
    assert payload["source_tool"] == "generic_csv"
    assert payload["stats"]["events"] > 0


def test_report_command_generic_csv_requires_a_column_map(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["report", str(GENERIC_CSV), "--source", "generic_csv", "--out-dir", str(tmp_path)],
    )

    assert result.exit_code == 2
    assert "--column-map" in result.output


def test_report_command_rejects_a_column_map_for_other_sources(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "report",
            str(HAYABUSA_CSV),
            "--source",
            "hayabusa",
            "--column-map",
            str(GENERIC_MAP),
            "--out-dir",
            str(tmp_path),
        ],
    )

    assert result.exit_code == 2
    assert "generic_csv" in result.output


def test_report_command_missing_evidence_file_fails_cleanly(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["report", str(tmp_path / "nope.csv"), "--source", "hayabusa"],
    )

    assert result.exit_code == 2


def test_report_command_wrong_source_reports_why_nothing_parsed(tmp_path: Path) -> None:
    # The generic EDR export is not Hayabusa output: every row fails to normalize,
    # so the command must fail with the per-row reasons, not write an empty report.
    out_dir = tmp_path / "out"
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["report", str(GENERIC_CSV), "--source", "hayabusa", "--out-dir", str(out_dir)],
    )

    assert result.exit_code == 1
    assert "no events could be normalized" in result.output
    assert "--source" in result.output
    assert not (out_dir / REPORT_HTML_NAME).exists()


def test_run_report_empty_timeline_carries_the_problems() -> None:
    with pytest.raises(EmptyTimelineError) as excinfo:
        run_report(GENERIC_CSV, "hayabusa", Path("unused"))
    assert excinfo.value.problems


def test_report_command_no_model_and_allow_cloud_contradict(tmp_path: Path) -> None:
    runner = CliRunner()
    result = runner.invoke(
        app,
        [
            "report",
            str(HAYABUSA_CSV),
            "--source",
            "hayabusa",
            "--out-dir",
            str(tmp_path),
            "--no-model",
            "--allow-cloud",
        ],
    )

    assert result.exit_code == 2
    assert "contradict" in result.output


def test_report_command_refuses_a_cloud_provider_without_consent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A configured cloud provider without the explicit --allow-cloud consent must
    # be refused before any work is done (FR27, Hard rule 2).
    monkeypatch.setenv("CASEBOUND_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "test-not-a-real-key")
    monkeypatch.delenv("CASEBOUND_ALLOW_CLOUD", raising=False)

    runner = CliRunner()
    result = runner.invoke(
        app,
        ["report", str(HAYABUSA_CSV), "--source", "hayabusa", "--out-dir", str(tmp_path)],
    )

    assert result.exit_code == 2
    assert "cloud" in result.output.lower()
    assert not (tmp_path / REPORT_HTML_NAME).exists()


class NetworkAccessError(AssertionError):
    """Raised when code under test attempts to open a network connection."""


def _deny(*_args: object, **_kwargs: object) -> NoReturn:
    raise NetworkAccessError("outbound network access attempted on the no-key report path")


@pytest.fixture
def no_network_no_keys(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Clear provider env vars and block every outbound socket connection."""
    for name in (
        "CASEBOUND_PROVIDER",
        "CASEBOUND_ALLOW_CLOUD",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(socket, "getaddrinfo", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    yield


@pytest.mark.invariant
def test_report_command_default_makes_no_network_call(
    no_network_no_keys: None, tmp_path: Path
) -> None:
    # With no provider configured the report path is fully offline: evidence never
    # leaves the host by default (Hard rule 2).
    out_dir = tmp_path / "out"
    result = CliRunner().invoke(
        app,
        ["report", str(HAYABUSA_CSV), "--source", "hayabusa", "--out-dir", str(out_dir)],
    )

    assert result.exit_code == 0, result.output
    assert (out_dir / REPORT_HTML_NAME).exists()


def test_report_command_unreadable_evidence_fails_cleanly(tmp_path: Path) -> None:
    # A whole-file failure (a truncated or non-JSON Chainsaw export) must be a
    # clean error, not a traceback. The per-row FR7 contract is unaffected.
    broken = tmp_path / "truncated.json"
    broken.write_text('{"detections": [', encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["report", str(broken), "--source", "chainsaw", "--out-dir", str(tmp_path / "out")],
    )

    assert result.exit_code == 1
    assert "could not read" in result.output


def test_report_command_out_dir_blocked_by_a_file_fails_cleanly(tmp_path: Path) -> None:
    blocker = tmp_path / "out"
    blocker.write_text("a file, not a directory", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(
        app,
        ["report", str(HAYABUSA_CSV), "--source", "hayabusa", "--out-dir", str(blocker)],
    )

    assert result.exit_code == 2
    assert "not a usable directory" in result.output


def test_version_flag_prints_the_version() -> None:
    from casebound import __version__

    result = CliRunner().invoke(app, ["--version"])
    assert result.exit_code == 0
    assert __version__ in result.output
