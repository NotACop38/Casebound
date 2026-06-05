"""Smoke test: the package imports and the CLI is wired.

This keeps the harness green from commit one. Real behavior is tested as each
module lands, one checklist step at a time.
"""

from __future__ import annotations

import casebound
from casebound.cli import app


def test_version_is_set() -> None:
    assert casebound.__version__ == "0.1.0"


def test_modules_import() -> None:
    # Every package per PRD Section 13 must be importable from commit one.
    import importlib

    for module in (
        "casebound.ingest",
        "casebound.normalize",
        "casebound.enrich",
        "casebound.verify",
        "casebound.narrate",
        "casebound.report",
        "casebound.generate",
        "casebound.cli",
    ):
        assert importlib.import_module(module) is not None


def test_cli_app_exists() -> None:
    # The console script "casebound" resolves to this Typer app.
    assert app is not None
