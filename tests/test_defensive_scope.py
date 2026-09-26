"""Defensive-scope invariant: the shipped package holds no offensive primitives.

PRD Section 6 and Hard rule 1 bind Casebound to read-only analysis of evidence that
has already been collected: no acquisition that modifies an endpoint, no remote
collection, no execution of suspect binaries, no detonation or sandboxing, and no
remediation or containment. This test proves that in code, not just in prose.

It parses every module under ``casebound/`` (the code that handles evidence and
ships to users) and fails if any of them import or call a primitive that could step
outside the defensive scope:

  - Process execution and detonation: ``subprocess``, ``pty``, ``os.system``,
    ``os.popen``, the ``os.exec*`` and ``os.spawn*`` families, ``os.fork``,
    ``os.posix_spawn*``, ``os.startfile``, and the ``eval`` and ``exec`` builtins.
    The product never shells out and never executes a suspect binary.
  - Remote collection and network egress: ``socket`` plus the network-client and
    remote-execution libraries (``urllib`` except the pure string parser
    ``urllib.parse``, ``urllib3``, ``http.client``, ``ftplib``, ``telnetlib``,
    ``smtplib``, ``requests``, ``httpx``, ``httpx2``, ``aiohttp``, ``websockets``,
    ``grpc``, ``pycurl``, ``paramiko``, ``smbprotocol``, ``winrm``, ``wmi``,
    ``impacket``, ``pypsexec``). The only sanctioned egress is the opt-in, redacted
    cloud provider SDK (``openai`` or ``anthropic``), imported lazily by name in
    ``narrate/llm.py`` and never on a default path. Raw sockets and direct HTTP
    clients are forbidden outright.
  - Endpoint modification and remediation: ``winreg`` (the live registry) and
    ``ctypes`` (native OS APIs). The product reads triage output; it never reaches
    out and touches a live endpoint.

Scope: the scan covers ``casebound/``, the code that handles evidence, including
the optional web viewer (which serves on loopback and never fetches anything). The
developer gate ``scripts/ci.py`` shells out to the pinned dev tools (ruff, mypy,
pytest, bandit) and never to evidence, so it is intentionally outside this
invariant. ``test_scanner_detects_forbidden_patterns`` proves the scanner has teeth
so a green run can never be vacuous.

No network, no API keys.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.invariant

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_DIR = ROOT / "casebound"

# Modules whose mere import would breach the defensive scope, mapped to the reason.
# The only sanctioned egress (the opt-in, redacted cloud SDKs openai and anthropic)
# is imported lazily by name in narrate/llm.py and is deliberately absent here.
FORBIDDEN_MODULES: dict[str, str] = {
    # Process execution and detonation.
    "subprocess": "spawns external processes (execution of suspect binaries)",
    "pty": "spawns processes on a pseudo-terminal",
    # Remote collection and network egress.
    "socket": "opens raw network sockets (remote collection or egress)",
    "ftplib": "transfers files over FTP (remote collection or egress)",
    "telnetlib": "opens Telnet sessions (remote collection or egress)",
    "smtplib": "sends mail (egress)",
    "http.client": "opens HTTP connections (egress)",
    "urllib": "opens network connections (egress)",
    "urllib3": "an HTTP client (egress)",
    "xmlrpc": "opens XML-RPC connections (egress)",
    "requests": "an HTTP client (egress)",
    "httpx": "an HTTP client (egress)",
    "httpx2": "an HTTP client (egress)",
    "aiohttp": "an async HTTP client (egress)",
    "websocket": "a WebSocket client (egress)",
    "websockets": "a WebSocket client (egress)",
    "grpc": "an RPC client (egress)",
    "pycurl": "a libcurl client (egress)",
    "paramiko": "SSH remote execution and collection",
    "smbprotocol": "SMB remote collection",
    "winrm": "Windows Remote Management execution",
    "wmi": "WMI remote query and execution",
    "impacket": "a remote execution and collection toolkit",
    "pypsexec": "PsExec-style remote execution",
    # Endpoint modification and remediation.
    "winreg": "reads or writes the live Windows registry (endpoint modification)",
    "ctypes": "calls native OS APIs (endpoint modification)",
}

# Members of the os module that launch processes. The os module itself is allowed
# (os.environ, os.fspath, and so on); only these process-launching members are
# forbidden, so the ban is precise rather than blanket.
FORBIDDEN_OS_FUNCS: frozenset[str] = frozenset(
    {
        "system",
        "popen",
        "exec",
        "execl",
        "execle",
        "execlp",
        "execlpe",
        "execv",
        "execve",
        "execvp",
        "execvpe",
        "spawn",
        "spawnl",
        "spawnle",
        "spawnlp",
        "spawnlpe",
        "spawnv",
        "spawnve",
        "spawnvp",
        "spawnvpe",
        "posix_spawn",
        "posix_spawnp",
        "fork",
        "forkpty",
        "startfile",
    }
)

# Builtins that execute arbitrary code from a string.
FORBIDDEN_BUILTINS: frozenset[str] = frozenset({"eval", "exec"})


# Submodules of a forbidden package that cannot open a connection, allowed by name.
# urllib.parse only splits and quotes strings (the web viewer compares an Origin
# header with it); urllib.request and urllib.robotparser stay forbidden.
ALLOWED_SUBMODULES: frozenset[str] = frozenset({"urllib.parse"})


def _forbidden_module(dotted: str) -> str | None:
    """Return the reason a dotted module name is forbidden, or None if it is allowed."""
    if any(dotted == name or dotted.startswith(name + ".") for name in ALLOWED_SUBMODULES):
        return None
    for name, reason in FORBIDDEN_MODULES.items():
        if dotted == name or dotted.startswith(name + "."):
            return reason
    return None


class _ScopeVisitor(ast.NodeVisitor):
    """Collect every defensive-scope breach in one parsed module."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.findings: list[str] = []

    def _record(self, lineno: int, what: str) -> None:
        try:
            location = self.path.relative_to(ROOT)
        except ValueError:
            location = self.path
        self.findings.append(f"{location}:{lineno}: {what}")

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            reason = _forbidden_module(alias.name)
            if reason is not None:
                self._record(node.lineno, f"imports '{alias.name}' which {reason}")
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        # Each imported name is judged fully qualified, so "from urllib import
        # parse" is the allowed parser while "from urllib import request" is not.
        module = node.module or ""
        for alias in node.names:
            qualified = f"{module}.{alias.name}" if module else alias.name
            reason = _forbidden_module(qualified)
            if reason is not None:
                self._record(node.lineno, f"imports '{qualified}' which {reason}")
            elif module == "os" and alias.name in FORBIDDEN_OS_FUNCS:
                self._record(node.lineno, f"imports 'os.{alias.name}' (process execution)")
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if (
            isinstance(node.value, ast.Name)
            and node.value.id == "os"
            and node.attr in FORBIDDEN_OS_FUNCS
        ):
            self._record(node.lineno, f"uses 'os.{node.attr}' (process execution)")
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Name) and func.id in FORBIDDEN_BUILTINS:
            self._record(node.lineno, f"calls the '{func.id}' builtin (code execution)")
        self.generic_visit(node)


def _python_files() -> list[Path]:
    return sorted(PACKAGE_DIR.rglob("*.py"))


def _scan(path: Path) -> list[str]:
    visitor = _ScopeVisitor(path)
    visitor.visit(ast.parse(path.read_text(encoding="utf-8"), filename=str(path)))
    return visitor.findings


def test_package_has_python_files() -> None:
    # Guard against the scan passing silently on an empty file set.
    assert _python_files(), "no Python files found under casebound/"


def test_no_offensive_primitives_in_package() -> None:
    findings: list[str] = []
    for path in _python_files():
        findings.extend(_scan(path))
    assert not findings, "defensive-scope invariant breached:\n" + "\n".join(findings)


def test_scanner_detects_forbidden_patterns() -> None:
    # The scanner must have teeth: a synthetic module that violates every category
    # has to be caught, or a clean result above would prove nothing.
    sample = (
        "import subprocess\n"
        "import os\n"
        "from os import system\n"
        "import socket\n"
        "import ctypes\n"
        "from urllib.request import urlopen\n"
        "def f(x):\n"
        "    os.popen('whoami')\n"
        "    eval(x)\n"
    )
    visitor = _ScopeVisitor(PACKAGE_DIR / "synthetic_violation.py")
    visitor.visit(ast.parse(sample))
    joined = "\n".join(visitor.findings)

    assert "subprocess" in joined
    assert "socket" in joined
    assert "ctypes" in joined
    assert "urllib.request" in joined
    assert "os.system" in joined  # the from-import form
    assert "os.popen" in joined  # the attribute-call form
    assert "eval" in joined


def test_only_the_pure_urllib_parser_is_allowed() -> None:
    sample = (
        "from urllib.parse import urlsplit\n"
        "import urllib.parse\n"
        "import urllib\n"
        "import urllib.request\n"
        "from urllib import robotparser\n"
        "from urllib import parse\n"
        "import urllib3\n"
        "import httpx2\n"
    )
    visitor = _ScopeVisitor(PACKAGE_DIR / "synthetic_violation.py")
    visitor.visit(ast.parse(sample))
    flagged = {finding.split("'")[1] for finding in visitor.findings}
    assert "urllib.parse" not in flagged
    assert {"urllib", "urllib.request", "urllib.robotparser", "urllib3", "httpx2"} <= flagged
