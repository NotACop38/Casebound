"""License-boundary invariant: the Apache-2.0 core never links AGPL code (D2).

Decision D2 (PRD Section 17) keeps the Casebound core Apache-2.0 while allowing an
optional raw-artifact mode built on Dissect, which is AGPL-3.0. The way the two
coexist is isolation: Dissect, and the subpackage that uses it
(``casebound/ingest/raw``), must never appear on the import graph of the core.

This test proves that in code, not just in prose. It parses every module under
``casebound/`` except the raw subpackage (the sanctioned AGPL zone) and fails if
any of them import Dissect (``dissect`` or ``dissect.*``) anywhere, or import the
raw subpackage (``casebound.ingest.raw`` or a submodule) anywhere but the one
sanctioned gateway: a function body in the source registry
(``casebound/sources.py``), which runs only when an operator selects a raw source.
A subprocess check then confirms the real import graph: loading the CLI, the
pipeline, the reports, the registry, and a tool-output adapter leaves both
Dissect and the raw subpackage out of ``sys.modules``. The test also confirms,
from pyproject, that Dissect is not a core dependency and is declared only under
the ``raw`` optional extra, and that the raw zone really does depend on Dissect
(so the scan is not vacuous).

The result: a default ``pip install casebound`` and the entire core pipeline (the
demo, ingest of tool output, normalize, enrich, verify, narrate, report) pull in
and load no AGPL code. Only an explicit ``pip install "casebound[raw]"`` plus
selecting a raw source brings Dissect in, which the raw subpackage's own
documentation flags as subject to AGPL-3.0.

No network, no API keys.
"""

from __future__ import annotations

import ast
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = ROOT / "casebound"
# The single sanctioned AGPL zone: the only place allowed to depend on Dissect.
AGPL_ZONE = PACKAGE_DIR / "ingest" / "raw"
PYPROJECT = ROOT / "pyproject.toml"
# The one core module allowed to load the raw subpackage, and only lazily.
RAW_GATEWAY = PACKAGE_DIR / "sources.py"

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


def _imports_with_scope(tree: ast.AST) -> list[tuple[int, str, bool]]:
    """Collect (lineno, fully-qualified-dotted-name, in_function) for every import.

    Names are always fully qualified, so a local module merely named ``dissect``
    (for example ``casebound.normalize.mappers.dissect``) is never confused with
    the Dissect library. Relative imports stay inside their own package and are
    skipped. ``in_function`` is True for an import inside a function body, which
    runs only when that function is called.
    """
    found: list[tuple[int, str, bool]] = []

    def visit(node: ast.AST, in_function: bool) -> None:
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.append((node.lineno, alias.name, in_function))
        elif isinstance(node, ast.ImportFrom) and not node.level:
            module = node.module or ""
            if module:
                found.append((node.lineno, module, in_function))
            for alias in node.names:
                name = f"{module}.{alias.name}" if module else alias.name
                found.append((node.lineno, name, in_function))
        nested = in_function or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        for child in ast.iter_child_nodes(node):
            visit(child, nested)

    visit(tree, False)
    return found


def _imported_names(tree: ast.AST) -> list[tuple[int, str]]:
    """Collect (lineno, fully-qualified-dotted-name) for every absolute import."""
    return [(lineno, name) for lineno, name, _ in _imports_with_scope(tree)]


def _core_files() -> list[Path]:
    """Every Python file under casebound/ except the sanctioned AGPL zone."""
    return sorted(p for p in PACKAGE_DIR.rglob("*.py") if AGPL_ZONE not in p.parents)


def _scan(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    findings: list[str] = []
    for lineno, dotted, in_function in _imports_with_scope(tree):
        reason = _is_agpl(dotted)
        if reason is None:
            continue
        lazy_gateway = path == RAW_GATEWAY and in_function and not _is_agpl_library(dotted)
        if not lazy_gateway:
            findings.append(f"{path.relative_to(ROOT)}:{lineno}: imports {dotted!r} which {reason}")
    return findings


def _is_agpl_library(dotted: str) -> bool:
    return dotted == "dissect" or dotted.startswith("dissect.")


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


def test_gateway_may_not_load_the_raw_subpackage_at_module_level(tmp_path: Path) -> None:
    # The registry's exemption covers function bodies only: a module-level import
    # there would load the AGPL zone for every command.
    module_level = "from casebound.ingest.raw import DissectEvtxAdapter\n"
    lazy = "def build():\n    from casebound.ingest.raw import DissectEvtxAdapter\n"
    scopes = {
        name: [in_fn for _, _, in_fn in _imports_with_scope(ast.parse(source))]
        for name, source in (("module_level", module_level), ("lazy", lazy))
    }
    assert scopes["module_level"] and not any(scopes["module_level"])
    assert scopes["lazy"] and all(scopes["lazy"])


def test_default_import_graph_loads_no_agpl_code() -> None:
    # The real graph, in a fresh interpreter: everything a default run imports,
    # including building a tool-output adapter through the registry.
    probe = (
        "import sys\n"
        "import casebound.cli, casebound.pipeline, casebound.report, casebound.sources\n"
        "import casebound.evaluation, casebound.narrate.llm\n"
        "from casebound.sources import build_adapter\n"
        "build_adapter('hayabusa'); build_adapter('plaso')\n"
        "loaded = sorted(m for m in sys.modules\n"
        "                if m == 'dissect' or m.startswith(('dissect.', 'casebound.ingest.raw')))\n"
        "print(','.join(loaded))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True, cwd=ROOT
    )
    assert result.stdout.strip() == "", f"AGPL modules loaded: {result.stdout.strip()}"


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
    assert project.get("license") == "Apache-2.0"
