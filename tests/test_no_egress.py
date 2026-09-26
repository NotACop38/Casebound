"""Defensive-scope invariant: the default paths make no outbound network call.

PRD Section 6 and Hard rule 2 require that evidence never leaves the host by
default: the deterministic core runs fully offline and the bundled demo narrates
with a scripted offline drafter, never a network model, unless a provider is
explicitly configured. This test proves that every default path opens no outbound
connection.

The ``no_network_no_keys`` fixture does two things to model the no-key path:

  - clears every provider and key environment variable, so ``build_model_from_env``
    selects no provider and the demo falls back to the offline narrator (FR26); and
  - replaces the socket connection primitives (``getaddrinfo``, ``create_connection``,
    ``socket.connect``, ``socket.connect_ex``) with guards that raise. Every real
    egress path, including the provider SDKs' HTTP clients, ultimately calls one of
    these, so any attempt to reach the network fails the test loudly.

Under that fixture the pipeline runs through every entry point (the library, the
``demo``, ``report``, and ``verify`` commands, and the optional web viewer) and
must complete with no network call. Selecting a cloud provider without consent
must fail before anything is sent, and even a consented provider must not connect
until it is asked to draft.

No network, no API keys.
"""

from __future__ import annotations

import json
import socket
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest
from typer.testing import CliRunner

from casebound.cli import app
from casebound.generate import write_samples
from casebound.narrate import OfflineDemoNarrator
from casebound.narrate.llm import AnthropicProvider, CloudConsentError, build_model_from_env
from casebound.pipeline import EvidenceInput, analyze
from casebound.report import REPORT_HTML_NAME, write_reports

pytestmark = pytest.mark.invariant

# Provider and key environment variables that select or authorize a network model.
# Cleared so the demo takes the genuine no-key path (offline narrator, FR26).
_PROVIDER_ENV_VARS = (
    "CASEBOUND_PROVIDER",
    "CASEBOUND_ALLOW_CLOUD",
    "CASEBOUND_LOCAL_BASE_URL",
    "CASEBOUND_LOCAL_MODEL",
    "CASEBOUND_ANTHROPIC_MODEL",
    "CASEBOUND_OPENAI_MODEL",
    "CASEBOUND_OPENAI_BASE_URL",
    "CASEBOUND_ANTHROPIC_FALLBACKS",
    "CASEBOUND_STRUCTURED_OUTPUT",
    "CASEBOUND_MAX_OUTPUT_TOKENS",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
)


class NetworkAccessError(AssertionError):
    """Raised when code under test attempts to open a network connection."""


def _deny(*_args: object, **_kwargs: object) -> NoReturn:
    raise NetworkAccessError("outbound network access attempted on the no-key demo path")


@pytest.fixture
def no_network_no_keys(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Clear provider and key env vars and block every outbound socket connection."""
    for name in _PROVIDER_ENV_VARS:
        monkeypatch.delenv(name, raising=False)

    monkeypatch.setattr(socket, "getaddrinfo", _deny)
    monkeypatch.setattr(socket, "create_connection", _deny)
    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)
    yield


def test_no_keys_means_no_provider(no_network_no_keys: None) -> None:
    # With no provider configured the selector returns no model, so the demo falls
    # back to the offline narrator rather than any network model (FR26, FR27).
    assert build_model_from_env() is None


def test_pipeline_with_the_offline_narrator_makes_no_network_call(
    no_network_no_keys: None, tmp_path: Path
) -> None:
    timeline, _ = write_samples(tmp_path)
    case = analyze(
        [EvidenceInput(source="hayabusa", path=timeline)],
        name="office_intrusion",
        model=OfflineDemoNarrator(),
        model_label=OfflineDemoNarrator.LABEL,
    )
    assert case.verification is not None and case.verification.accepted
    paths = write_reports(case, tmp_path / "out")
    assert paths.html.exists()


def test_report_cli_makes_no_network_call(no_network_no_keys: None, tmp_path: Path) -> None:
    timeline, _ = write_samples(tmp_path)
    out_dir = tmp_path / "out"
    result = CliRunner().invoke(app, ["report", f"hayabusa:{timeline}", "--out-dir", str(out_dir)])
    assert result.exit_code == 0, result.output
    assert (out_dir / REPORT_HTML_NAME).exists()


def test_verify_cli_makes_no_network_call(no_network_no_keys: None, tmp_path: Path) -> None:
    timeline, _ = write_samples(tmp_path)
    out_dir = tmp_path / "out"
    runner = CliRunner()
    assert runner.invoke(app, ["report", f"hayabusa:{timeline}", "-o", str(out_dir)]).exit_code == 0
    first = json.loads((out_dir / "events.jsonl").read_text(encoding="utf-8").splitlines()[0])
    claims = tmp_path / "claims.json"
    claims.write_text(
        json.dumps(
            {
                "claims": [
                    {
                        "text": "t",
                        "citations": [first["event_id"]],
                        "asserts": {"datetime": first["datetime"]},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    result = runner.invoke(app, ["verify", str(claims), "--events", str(out_dir / "events.jsonl")])
    assert result.exit_code == 0, result.output


def test_web_viewer_makes_no_network_call(no_network_no_keys: None, tmp_path: Path) -> None:
    pytest.importorskip("fastapi", reason="web extra not installed")
    from fastapi.testclient import TestClient

    from casebound.web.app import create_app

    client = TestClient(create_app())
    assert client.get("/").status_code == 200
    assert client.get("/cases/demo/report").status_code == 200
    timeline, _ = write_samples(tmp_path)
    upload = client.post(
        "/upload",
        data={"source": "hayabusa"},
        files={"file": ("timeline.csv", timeline.read_bytes(), "text/csv")},
        follow_redirects=False,
    )
    assert upload.status_code == 303


def test_cloud_provider_without_consent_fails_before_any_call(no_network_no_keys: None) -> None:
    env = {
        "CASEBOUND_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "placeholder-not-a-key",  # pragma: allowlist secret
    }
    with pytest.raises(CloudConsentError):
        build_model_from_env(env)


def test_consented_cloud_provider_does_not_connect_until_asked(no_network_no_keys: None) -> None:
    env = {
        "CASEBOUND_PROVIDER": "anthropic",
        "ANTHROPIC_API_KEY": "placeholder-not-a-key",  # pragma: allowlist secret
        "CASEBOUND_ALLOW_CLOUD": "1",
    }
    model = build_model_from_env(env)
    assert isinstance(model, AnthropicProvider)
    # Construction is lazy: no client exists and nothing has been sent.
    assert model.client is None


def test_demo_cli_default_makes_no_network_call(no_network_no_keys: None, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = CliRunner().invoke(app, ["demo", "--out-dir", str(out_dir)])

    assert result.exit_code == 0, result.output
    assert (out_dir / REPORT_HTML_NAME).exists()
    # The default no-key path drafts with the offline narrator, never a network model.
    assert "offline demo narrator" in result.output.lower()


def test_demo_cli_no_model_makes_no_network_call(no_network_no_keys: None, tmp_path: Path) -> None:
    out_dir = tmp_path / "out"
    result = CliRunner().invoke(app, ["demo", "--out-dir", str(out_dir), "--no-model"])

    assert result.exit_code == 0, result.output
    assert (out_dir / REPORT_HTML_NAME).exists()


def test_network_guard_blocks_real_connections(no_network_no_keys: None) -> None:
    # Prove the guard itself works: a direct connection attempt must be refused, so
    # the no-call results above are meaningful rather than vacuous.
    with pytest.raises(NetworkAccessError):
        socket.create_connection(("203.0.113.1", 9))
