"""Tests for the command line (``casebound report``, ``demo``, ``verify``, and friends).

The CLI is a thin shell over ``casebound.pipeline.analyze`` and the report layer,
so these tests pin what only the CLI owns: argument handling, which inputs and
models it assembles, the exit-code contract (0 success, 1 the run or a check
failed, 2 a usage or configuration error), and that every expected failure is a
clean one-line error rather than a traceback.

No network, no API keys: a configured model is replaced by a stub.
"""

from __future__ import annotations

import importlib.util
import json
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from typer.testing import CliRunner

import casebound.evaluation as evaluation_module
import casebound.narrate.llm as llm_module
from casebound import __version__
from casebound.cli import app
from casebound.generate import CSV_FILENAME, GROUND_TRUTH_FILENAME, write_samples
from casebound.narrate.llm import ProviderError
from casebound.report import (
    EVENTS_NAME,
    LAYER_NAME,
    REPORT_HTML_NAME,
    REPORT_JSON_NAME,
    REPORT_MARKDOWN_NAME,
)
from casebound.sources import SOURCES

FIXTURES = Path(__file__).resolve().parent / "fixtures"
SAMPLES = Path(__file__).resolve().parents[1] / "samples"
GENERIC_CSV = FIXTURES / "generic_edr_slice.csv"
GENERIC_MAP = FIXTURES / "generic_edr_map.json"
CHAINSAW_JSON = FIXTURES / "chainsaw_detections.json"
VELOCIRAPTOR_JSONL = FIXTURES / "velociraptor_evtx.jsonl"
ARTIFACTS = (REPORT_HTML_NAME, REPORT_MARKDOWN_NAME, REPORT_JSON_NAME, EVENTS_NAME, LAYER_NAME)
PROCESS_CREATE_ID = "6fb28f7a4aa4868c10e5077dbc43226eb111bc824d953c347b6348a6c58e3c70"

_PROVIDER_ENV = (
    "CASEBOUND_PROVIDER",
    "CASEBOUND_ALLOW_CLOUD",
    "CASEBOUND_LOCAL_MODEL",
    "CASEBOUND_LOCAL_BASE_URL",
    "CASEBOUND_ANTHROPIC_MODEL",
    "CASEBOUND_OPENAI_MODEL",
    "CASEBOUND_MAX_OUTPUT_TOKENS",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
)


@pytest.fixture(autouse=True)
def _no_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _PROVIDER_ENV:
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def timeline(tmp_path: Path) -> Path:
    path, _ = write_samples(tmp_path / "evidence")
    return path


def _run(*args: str) -> Any:
    return CliRunner().invoke(app, list(args))


def _report_json(out_dir: Path) -> dict[str, Any]:
    data: dict[str, Any] = json.loads((out_dir / REPORT_JSON_NAME).read_text(encoding="utf-8"))
    return data


class StubModel:
    """A configured model stand-in that returns one scripted draft."""

    def __init__(self, claims: list[dict[str, Any]] | None = None, fail: bool = False) -> None:
        self.claims = claims or []
        self.fail = fail

    def draft(self, request: object) -> str:
        if self.fail:
            raise ProviderError("the local model at http://localhost:11434/v1 is not running")
        return json.dumps({"claims": self.claims})


def _configure(monkeypatch: pytest.MonkeyPatch, model: object) -> None:
    monkeypatch.setattr(llm_module, "build_model_from_env", lambda *args, **kwargs: model)


# report


def test_report_writes_every_artifact_with_no_model(timeline: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = _run("report", f"hayabusa:{timeline}", "--out-dir", str(out_dir))
    assert result.exit_code == 0, result.output
    for name in ARTIFACTS:
        assert (out_dir / name).is_file(), name
    assert "read 37 record(s) from synthetic_hayabusa.csv (hayabusa)" in result.output
    assert "no model: wrote the deterministic report" in result.output
    report = _report_json(out_dir)
    assert report["case"]["name"] == "synthetic_hayabusa"
    assert report["narrative"]["no_model"] is True


def test_report_accepts_a_source_flag_and_a_case_name(timeline: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = _run(
        "report", str(timeline), "-s", "hayabusa", "-o", str(out_dir), "-n", "ACME triage"
    )
    assert result.exit_code == 0, result.output
    assert _report_json(out_dir)["case"]["name"] == "ACME triage"


def test_report_merges_several_sources_into_one_case(timeline: Path, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = _run(
        "report",
        f"hayabusa:{timeline}",
        f"chainsaw:{CHAINSAW_JSON}",
        f"velociraptor:{VELOCIRAPTOR_JSONL}",
        "-o",
        str(out_dir),
    )
    assert result.exit_code == 0, result.output
    report = _report_json(out_dir)
    assert [item["source"] for item in report["case"]["inputs"]] == [
        "hayabusa",
        "chainsaw",
        "velociraptor",
    ]
    assert report["case"]["name"] == "synthetic_hayabusa and 2 more"
    tools = {event["source_tool"] for event in report["events"]}
    assert tools == {"hayabusa", "chainsaw", "velociraptor"}
    records = sum(item["records"] for item in report["case"]["inputs"])
    assert report["stats"]["records_read"] == records
    # The fixtures carry deliberately malformed rows, reported rather than dropped.
    stats = report["stats"]
    assert stats["problems"] == len(report["problems"]) > 0
    assert stats["events"] == records - stats["duplicates"] - stats["problems"]


def test_report_reads_a_generic_csv_through_its_column_map(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = _run(
        "report", f"generic_csv:{GENERIC_CSV}", "--column-map", str(GENERIC_MAP), "-o", str(out_dir)
    )
    assert result.exit_code == 0, result.output
    report = _report_json(out_dir)
    assert {event["source_tool"] for event in report["events"]} == {"generic_csv"}
    # A generic CSV has no detection layer, so the mapping table tags it.
    assert report["stats"]["techniques"] > 0


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["report", str(GENERIC_CSV), "-s", "generic_csv"], "--column-map"),
        (
            ["report", str(GENERIC_CSV), "-s", "hayabusa", "--column-map", str(GENERIC_MAP)],
            "applies only to generic_csv",
        ),
        (["report", str(GENERIC_CSV)], "SOURCE:PATH"),
        (["report", f"bogus:{GENERIC_CSV}"], "SOURCE:PATH"),
        (["report", str(GENERIC_CSV), "-s", "bogus"], "unknown source 'bogus'"),
        (["report", "hayabusa:does-not-exist.csv"], "does not exist"),
        (["report", f"hayabusa:{GENERIC_CSV}", "--no-model", "--allow-cloud"], "contradict"),
    ],
)
def test_report_usage_errors_exit_2(args: list[str], expected: str, tmp_path: Path) -> None:
    result = _run(*args, "-o", str(tmp_path / "out"))
    assert result.exit_code == 2, result.output
    assert expected in result.output
    assert "Traceback" not in result.output


def test_report_with_the_wrong_source_says_why_nothing_parsed(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = _run("report", f"hayabusa:{GENERIC_CSV}", "-o", str(out_dir))
    assert result.exit_code == 1
    assert "no events could be normalized" in result.output
    assert "is the source right for this file?" in result.output
    assert "generic_edr_slice.csv#" in result.output
    assert not (out_dir / REPORT_HTML_NAME).exists()


def test_report_with_unreadable_evidence_fails_cleanly(tmp_path: Path) -> None:
    binary = tmp_path / "blob.json"
    binary.write_bytes(b"\xff\xfe\x00garbage")
    result = _run("report", f"chainsaw:{binary}", "-o", str(tmp_path / "out"))
    assert result.exit_code == 1
    assert "failed reading the evidence" in result.output


def test_report_raw_source_without_the_extra_names_the_install(tmp_path: Path) -> None:
    if importlib.util.find_spec("dissect") is not None:  # pragma: no cover
        pytest.skip("the raw extra is installed")
    log = tmp_path / "Security.evtx"
    log.write_bytes(b"ElfFile\x00")
    result = _run("report", f"evtx:{log}", "-o", str(tmp_path / "out"))
    assert result.exit_code == 2
    assert 'pip install "casebound[raw]"' in result.output


def test_report_out_dir_blocked_by_a_file_fails_cleanly(timeline: Path, tmp_path: Path) -> None:
    blocker = tmp_path / "blocker"
    blocker.write_text("x", encoding="utf-8")
    result = _run("report", f"hayabusa:{timeline}", "-o", str(blocker / "out"))
    assert result.exit_code == 2
    assert "not a usable directory" in result.output


def test_report_refuses_a_cloud_provider_without_consent(
    timeline: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("CASEBOUND_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-not-a-key")
    result = _run("report", f"hayabusa:{timeline}", "-o", str(tmp_path / "out"))
    assert result.exit_code == 2
    assert "--allow-cloud" in result.output
    assert "placeholder-not-a-key" not in result.output


def test_report_with_a_configured_model_verifies_the_narrative(
    timeline: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(
        monkeypatch,
        StubModel(
            [
                {
                    "text": "PowerShell ran.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"action": "process_create"},
                },
                {
                    "text": "The administrator ran PowerShell.",
                    "citations": [PROCESS_CREATE_ID],
                    "asserts": {"principal": "CORP\\Administrator"},
                },
            ]
        ),
    )
    out_dir = tmp_path / "out"
    result = _run("report", f"hayabusa:{timeline}", "-o", str(out_dir), "--max-rounds", "0")
    assert result.exit_code == 0, result.output
    assert "1 claim(s) verified, 1 rejection(s) logged, 1 dropped" in result.output
    report = _report_json(out_dir)
    assert report["narrative"]["label"] == "configured model"
    assert [entry["backing_event_id"] for entry in report["narrative"]["entries"]] == [
        PROCESS_CREATE_ID
    ]


def test_report_no_model_flag_skips_a_configured_model(
    timeline: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch, StubModel(fail=True))
    result = _run("report", f"hayabusa:{timeline}", "-o", str(tmp_path / "out"), "--no-model")
    assert result.exit_code == 0, result.output


def test_report_model_failure_suggests_the_no_model_path(
    timeline: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _configure(monkeypatch, StubModel(fail=True))
    result = _run("report", f"hayabusa:{timeline}", "-o", str(tmp_path / "out"))
    assert result.exit_code == 1
    assert "the narrative model failed" in result.output
    assert "--no-model" in result.output


# demo


def test_demo_runs_offline_and_holds_the_guarantee(tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = _run("demo", "-o", str(out_dir))
    assert result.exit_code == 0, result.output
    for name in (*ARTIFACTS, "metrics.json", CSV_FILENAME, GROUND_TRUTH_FILENAME):
        assert (out_dir / name).is_file(), name
    assert "offline demo narrator" in result.output
    assert "false accepts: 0" in result.output
    assert "false rejects: 0" in result.output
    assert "verification guarantee held on every measured claim" in result.output
    metrics = json.loads((out_dir / "metrics.json").read_text(encoding="utf-8"))
    assert metrics["passed"] is True
    assert metrics["narrative"]["citation_accuracy"] == 1.0
    # The regenerated evidence is byte-identical to the committed sample.
    assert (out_dir / CSV_FILENAME).read_bytes() == (SAMPLES / CSV_FILENAME).read_bytes()


def test_demo_no_model_writes_the_deterministic_report(tmp_path: Path) -> None:
    result = _run("demo", "-o", str(tmp_path / "out"), "--no-model")
    assert result.exit_code == 0, result.output
    assert "no model: wrote the deterministic report" in result.output


def test_demo_never_uses_a_cloud_provider(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CASEBOUND_PROVIDER", "anthropic")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "placeholder-not-a-key")
    monkeypatch.setenv("CASEBOUND_ALLOW_CLOUD", "1")
    result = _run("demo", "-o", str(tmp_path / "out"))
    assert result.exit_code == 0, result.output
    assert "offline demo narrator" in result.output


def test_demo_fails_when_the_guarantee_does_not_hold(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    real = evaluation_module.evaluate

    def broken(*args: Any, **kwargs: Any) -> Any:
        result = real(*args, **kwargs)
        return replace(result, accurate_claims=result.emitted_claims - 1)

    monkeypatch.setattr(evaluation_module, "evaluate", broken)
    result = _run("demo", "-o", str(tmp_path / "out"))
    assert result.exit_code == 1
    assert "the verifier misjudged a benchmark claim" in result.output


# verify


def _events_file(timeline: Path, tmp_path: Path) -> Path:
    out_dir = tmp_path / "case"
    assert _run("report", f"hayabusa:{timeline}", "-o", str(out_dir)).exit_code == 0
    return out_dir / EVENTS_NAME


def _claims_file(tmp_path: Path, *claims: dict[str, Any]) -> Path:
    path = tmp_path / "claims.json"
    path.write_text(json.dumps({"claims": list(claims)}), encoding="utf-8")
    return path


def test_verify_accepts_grounded_claims(timeline: Path, tmp_path: Path) -> None:
    events = _events_file(timeline, tmp_path)
    claims = _claims_file(
        tmp_path,
        {
            "text": "jdoe started PowerShell at 08:42:17.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"datetime": "2026-03-14T08:42:17Z", "principal": "CORP\\jdoe"},
        },
    )
    out = tmp_path / "verdicts.json"
    result = _run("verify", str(claims), "--events", str(events), "--out", str(out))
    assert result.exit_code == 0, result.output
    assert "ACCEPT  CORP\\jdoe started" in result.output
    assert "1 of 1 claim(s) verified against 37 event(s)" in result.output
    [verdict] = json.loads(out.read_text(encoding="utf-8"))
    assert verdict["verdict"]["ok"] is True
    assert verdict["statement"].startswith("CORP\\jdoe started")


def test_verify_rejects_a_fabricated_claim(timeline: Path, tmp_path: Path) -> None:
    events = _events_file(timeline, tmp_path)
    claims = _claims_file(
        tmp_path,
        {
            "text": "The administrator started PowerShell.",
            "citations": [PROCESS_CREATE_ID],
            "asserts": {"principal": "CORP\\Administrator"},
        },
    )
    result = _run("verify", str(claims), "--events", str(events))
    assert result.exit_code == 1
    assert "REJECT  The administrator started PowerShell." in result.output
    assert "principal_mismatch" in result.output


def test_verify_usage_errors_exit_2(timeline: Path, tmp_path: Path) -> None:
    events = _events_file(timeline, tmp_path)
    not_json = tmp_path / "claims.txt"
    not_json.write_text("not json", encoding="utf-8")
    assert _run("verify", str(not_json), "--events", str(events)).exit_code == 2
    empty = _claims_file(tmp_path)
    assert _run("verify", str(empty), "--events", str(events)).exit_code == 2
    bad_events = tmp_path / "bad.jsonl"
    bad_events.write_text('{"event_id": "x"}\n', encoding="utf-8")
    claims = _claims_file(tmp_path, {"text": "t", "citations": [], "asserts": {}})
    result = _run("verify", str(claims), "--events", str(bad_events))
    assert result.exit_code == 2
    assert "is not a valid canonical event" in result.output


# sources, generate, version, serve


def test_sources_lists_every_source_with_its_requirements() -> None:
    result = _run("sources")
    assert result.exit_code == 0
    for name in SOURCES:
        assert name in result.output
    assert 'pip install "casebound[raw]"' in result.output
    assert "needs --column-map" in result.output


def test_generate_reproduces_the_committed_samples(tmp_path: Path) -> None:
    result = _run("generate", "-o", str(tmp_path))
    assert result.exit_code == 0, result.output
    for name in (CSV_FILENAME, GROUND_TRUTH_FILENAME):
        assert (tmp_path / name).read_bytes() == (SAMPLES / name).read_bytes()


def test_version_flag_and_command() -> None:
    assert _run("--version").output.strip() == __version__
    assert _run("version").output.strip() == __version__


def test_serve_warns_before_binding_beyond_loopback(monkeypatch: pytest.MonkeyPatch) -> None:
    pytest.importorskip("fastapi", reason="web extra not installed")
    import casebound.web.app as web_app

    calls: list[tuple[str, int]] = []
    monkeypatch.setattr(web_app, "serve", lambda host, port: calls.append((host, port)))
    loopback = _run("serve", "--port", "8123")
    assert loopback.exit_code == 0, loopback.output
    assert "warning" not in loopback.output
    exposed = _run("serve", "--host", "0.0.0.0", "--port", "8124")
    assert exposed.exit_code == 0, exposed.output
    assert "exposes the viewer beyond this host" in exposed.output
    assert calls == [("127.0.0.1", 8123), ("0.0.0.0", 8124)]
