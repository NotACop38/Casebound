"""Smoke tests: the package imports, its version is consistent, and the CLI is wired."""

from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import casebound
from casebound.cli import app

ROOT = Path(__file__).resolve().parent.parent


def test_version_matches_the_project_metadata() -> None:
    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    assert casebound.__version__ == project["version"]


def test_modules_import() -> None:
    # Every package boundary in PRD Section 13, plus the shared pipeline modules.
    for module in (
        "casebound.ingest",
        "casebound.normalize",
        "casebound.enrich",
        "casebound.verify",
        "casebound.narrate",
        "casebound.report",
        "casebound.generate",
        "casebound.cli",
        "casebound.pipeline",
        "casebound.sources",
        "casebound.evaluation",
        "casebound.web",
    ):
        assert importlib.import_module(module) is not None


def test_cli_app_exists() -> None:
    # The console script "casebound" resolves to this Typer app.
    assert app is not None


def test_package_data_ships_with_the_package() -> None:
    # Loaded at runtime from the installed package, so they must live inside it.
    package = Path(casebound.__file__).resolve().parent
    for relative in (
        "py.typed",
        "data/event.schema.json",
        "data/claims.schema.json",
        "data/attack-enterprise.json",
        "report/templates/report.html.j2",
        "web/templates/index.html.j2",
        "web/templates/timeline.html.j2",
    ):
        assert (package / relative).is_file(), relative
