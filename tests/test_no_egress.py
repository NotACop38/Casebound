"""Defensive-scope invariant: the no-key demo path makes no outbound network calls.

PRD Section 6 and Hard rule 2 require that evidence never leaves the host by
default: the deterministic core runs fully offline and the bundled demo narrates
with a scripted offline drafter, never a network model, unless a cloud provider is
explicitly opted into. This test proves that the no-key demo path opens no outbound
connection.

The ``no_network_no_keys`` fixture does two things to model the no-key path:

  - clears every provider and key environment variable, so ``build_model_from_env``
    selects no provider and the demo falls back to the offline narrator (FR26); and
  - replaces the socket connection primitives (``getaddrinfo``, ``create_connection``,
    ``socket.connect``, ``socket.connect_ex``) with guards that raise. Every real
    egress path, including the cloud SDK HTTP clients, ultimately calls one of
    these, so any attempt to reach the network fails the test loudly.

Under that fixture the demo is exercised through both entry points (``run_demo`` and
the ``casebound demo`` CLI, with and without ``--no-model``) and must complete and
write its report with no network call.

No network, no API keys.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from pathlib import Path
from typing import NoReturn

import pytest
from casebound.cli import REPORT_HTML_NAME, app, run_demo
from casebound.narrate import OfflineDemoNarrator
from casebound.narrate.llm import build_model_from_env
from typer.testing import CliRunner

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


def test_run_demo_offline_narrator_makes_no_network_call(
    no_network_no_keys: None, tmp_path: Path
) -> None:
    result = run_demo(
        tmp_path,
        model=OfflineDemoNarrator(),
        model_label=OfflineDemoNarrator.LABEL,
        max_rounds=0,
    )
    assert result.report_path.exists()
    assert result.accepted_count > 0


def test_run_demo_no_model_makes_no_network_call(no_network_no_keys: None, tmp_path: Path) -> None:
    result = run_demo(tmp_path, model=None)
    assert result.no_model is True
    assert result.report_path.exists()


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
