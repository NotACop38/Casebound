"""License-boundary invariant: the Apache-2.0 core never links AGPL code (D2).

Decision D2 (PRD Section 17) keeps the Casebound core Apache-2.0 while allowing an
optional raw-artifact mode built on Dissect, which is AGPL-3.0. The way the two
coexist is isolation: Dissect, and the subpackage that uses it
(``casebound/ingest/raw``), must never appear on the import graph of the core.

This test proves that in code, not just in prose. It parses every module under
``casebound/`` except the raw subpackage (the sanctioned AGPL zone) and fails if
any of them import Dissect (``dissect`` or ``dissect.*``) or the raw subpackage
(``casebound.ingest.raw`` or a submodule). It also confirms, from pyproject, that
Dissect is not a core dependency and is declared only under the ``raw`` optional
extra, and that the raw zone really does depend on Dissect (so the scan is not
vacuous).

The result: a default ``pip install casebound`` and the entire core pipeline (the
demo, ingest of tool output, normalize, enrich, verify, narrate, report) pull in
and load no AGPL code. Only an explicit ``pip install "casebound[raw]"`` plus a
direct call into the raw adapters brings Dissect in, which the raw subpackage's
own documentation flags as subject to AGPL-3.0.

No network, no API keys.
"""

from __future__ import annotations

import ast
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = ROOT / "casebound"
# The single sanctioned AGPL zone: the only place allowed to depend on Dissect.
AGPL_ZONE = PACKAGE_DIR / "ingest" / "raw"
PYPROJECT = ROOT / "pyproject.toml"

# Dotted import namespaces that would put AGPL code on a module's import graph.
# Mapped to the reason, mirroring the defensive-scope invariant's style.
AGPL_NAMESPACES: dict[str, str] = {
    "dissect": "imports Dissect (AGPL-3.0); the core must stay Apache-2.0 (D2)",
    "casebound.ingest.raw": "imports the AGPL-gated raw subpackage onto the core import graph (D2)",
}


def _is_agpl(dotted: str) -> str | None:
    """Return the reason a fully-qualified import name is AGPL-tainted, or None."""
    for namespace, reason in AGPL_NAMESPACES.items():
        if dotted == namespace or dotted.startswith(namespace + "."):
            return reason
    return None


def _imported_names(tree: ast.AST) -> list[tuple[int, str]]:
    """Collect (lineno, fully-qualified-dotted-name) for every absolute import.

    Names are always fully qualified, so a local module merely named ``dissect``
    (for example ``casebound.normalize.mappers.dissect``) is never confused with
    the Dissect library. Relative imports stay inside their own package and are
    skipped.
    """
    found: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name))
        elif isinstance(node, ast.ImportFrom):
            if node.level:  # relative import; not an absolute cross-package link
                continue
            module = node.module or ""
            if module:
                found.append((node.lineno, module))
            for alias in node.names:
                found.append((node.lineno, f"{module}.{alias.name}" if module else alias.name))
    return found


def _core_files() -> list[Path]:
    """Every Python file under casebound/ except the sanctioned AGPL zone."""
    return sorted(p for p in PACKAGE_DIR.rglob("*.py") if AGPL_ZONE not in p.parents)


def _scan(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[str] = []
    for lineno, dotted in _imported_names(tree):
        reason = _is_agpl(dotted)
        if reason is not None:
            findings.append(f"{path.relative_to(ROOT)}:{lineno}: imports {dotted!r} which {reason}")
    return findings


def test_core_files_present() -> None:
    # Guard against the scan passing silently on an empty file set.
    files = _core_files()
    assert files, "no core Python files found under casebound/"
    assert AGPL_ZONE.is_dir(), "the raw subpackage (the AGPL zone) is missing"


def test_core_never_imports_agpl_code() -> None:
    findings: list[str] = []
    for path in _core_files():
        findings.extend(_scan(path))
    assert not findings, "license-boundary invariant breached (D2):\n" + "\n".join(findings)


def test_scanner_detects_boundary_violations() -> None:
    # The scanner must have teeth: a module that links AGPL code every way has to
    # be caught, or a clean result above would prove nothing.
    sample = (
        "import dissect.ntfs\n"
        "from dissect.eventlog.evtx import Evtx\n"
        "from casebound.ingest.raw import DissectEvtxAdapter\n"
        "from casebound.ingest.raw.mft import DissectMftAdapter\n"
        # These must NOT be flagged: a core module merely named 'dissect'.
        "from casebound.normalize.mappers.dissect import DissectMapper\n"
        "from casebound.normalize.mappers import dissect\n"
    )
    tree = ast.parse(sample)
    findings = [dotted for _, dotted in _imported_names(tree) if _is_agpl(dotted)]
    assert "dissect.ntfs" in findings
    assert "dissect.eventlog.evtx" in findings
    assert "casebound.ingest.raw" in findings
    assert "casebound.ingest.raw.mft" in findings
    # The core mapper module named 'dissect' is original Apache code, not the lib.
    assert "casebound.normalize.mappers.dissect" not in findings


def test_raw_zone_actually_depends_on_dissect() -> None:
    # Sanity: the isolation is real. The AGPL zone must import Dissect somewhere, so
    # the scan above is meaningfully distinguishing the zone from the core.
    zone_files = sorted(AGPL_ZONE.rglob("*.py"))
    assert zone_files, "the AGPL zone has no Python files"
    imports_dissect = any(
        any(
            dotted == "dissect" or dotted.startswith("dissect.")
            for _, dotted in _imported_names(
                ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
            )
        )
        for path in zone_files
    )
    assert imports_dissect, "the raw subpackage is expected to import Dissect (D2 isolation)"


def test_pyproject_keeps_dissect_optional() -> None:
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data["project"]
    core_deps = project.get("dependencies", [])
    assert not any("dissect" in dep.lower() for dep in core_deps), (
        "Dissect must not be a core dependency (D2); it belongs only in the 'raw' extra"
    )
    extras = project.get("optional-dependencies", {})
    raw = extras.get("raw", [])
    assert any(dep.lower().startswith("dissect") for dep in raw), (
        "the 'raw' optional extra must declare Dissect"
    )
    # The declared license posture stays Apache-2.0 for the core.
    assert project.get("license", {}).get("text") == "Apache-2.0"
