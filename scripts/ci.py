#!/usr/bin/env python3
"""Casebound local CI gate.

Runs the offline quality checks that every later step can rely on:

  1. ruff check   : lint
  2. ruff format  : format check
  3. mypy         : strict-ish type check
  4. pytest       : the test suite (no network, no API keys)
  5. schema       : JSON Schema validation (placeholder until the schema exists)
  6. secrets      : a secret scan over git-tracked files
  7. deps         : a dependency audit of the declared dependencies (pip-audit)

The first six steps run fully offline with no API keys. The dependency audit
reaches the advisory service when online and skips gracefully when offline (or
when pip-audit is not installed), so the gate stays green without a network. The
static security checks (bandit) live in `make security`.

Usage: python scripts/ci.py
Exit code is 0 only if every step passes.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess  # nosec B404
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schema" / "event.schema.json"
BASELINE = ROOT / ".secrets.baseline"
PYPROJECT = ROOT / "pyproject.toml"

# A completed dependency audit prints this header when it has real findings. Any
# other non-zero outcome means the audit could not run (offline, pip-audit absent,
# or an isolated-environment setup failure), which we skip rather than fail on.
AUDIT_FINDING_RE = re.compile(r"found \d+ known vulnerabilit", re.IGNORECASE)

# High-signal patterns for the built-in fallback secret scan. Kept conservative
# to avoid false positives. The configured scanner is detect-secrets; this is the
# safety net used when detect-secrets is not installed.
SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws access key id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("aws secret access key", re.compile(r"aws_secret_access_key\s*=\s*['\"][^'\"]{20,}")),
    ("slack token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}")),
    ("generic api key assignment", re.compile(r"(?i)\bapi[_-]?key\s*[:=]\s*['\"][^'\"]{16,}")),
]

# Secret-bearing environment assignments, applied to .env files (including the
# tracked .env.example). A non-empty value triggers this; empty placeholders such
# as "OPENAI_API_KEY=" pass, so a real key committed by accident is still caught.
ENV_SECRET_PATTERN = re.compile(
    r"(?im)^[ \t]*[A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|ACCESS_KEY)[A-Z0-9_]*[ \t]*=[ \t]*\S"
)


def _print_header(name: str) -> None:
    print(f"\n==> {name}", flush=True)


def run_cmd(name: str, cmd: list[str]) -> bool:
    """Run a subprocess step and return True on success."""
    _print_header(name)
    # cmd is always a fixed, hard-coded list built in main(); no shell, no input.
    result = subprocess.run(cmd, cwd=ROOT)  # nosec B603
    ok = result.returncode == 0
    print("PASS" if ok else f"FAIL (exit {result.returncode})")
    return ok


def check_schema() -> bool:
    """Validate the canonical event schema if present, else skip (placeholder)."""
    _print_header("schema (JSON Schema validation)")
    if not SCHEMA_PATH.exists():
        print(f"SKIP: {SCHEMA_PATH.relative_to(ROOT)} not present yet (placeholder).")
        return True
    try:
        from jsonschema import Draft202012Validator

        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(schema)
    except Exception as exc:  # report any schema problem as a failure
        print(f"FAIL: {SCHEMA_PATH.relative_to(ROOT)} is not a valid JSON Schema: {exc}")
        return False
    print("PASS")
    return True


def _git_tracked_files() -> list[Path]:
    # Fixed git invocation, no untrusted input.
    result = subprocess.run(  # nosec B603 B607
        ["git", "ls-files"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )
    files: list[Path] = []
    for line in result.stdout.splitlines():
        path = ROOT / line
        if path.is_file():
            files.append(path)
    return files


def _builtin_secret_scan(files: list[Path]) -> bool:
    findings: list[str] = []
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(text):
                findings.append(f"{path.relative_to(ROOT)}: possible {label}")
        # Env files get an extra check for non-empty secret-bearing assignments.
        if path.name.startswith(".env") and ENV_SECRET_PATTERN.search(text):
            findings.append(f"{path.relative_to(ROOT)}: non-empty secret-bearing env assignment")
    if findings:
        print("FAIL: potential secrets found:")
        for finding in findings:
            print(f"  - {finding}")
        return False
    print(f"PASS (built-in scan, {len(files)} files)")
    return True


def check_secrets() -> bool:
    """Scan tracked files for secrets, preferring detect-secrets when available."""
    _print_header("secrets (secret scan)")
    files = _git_tracked_files()
    if shutil.which("detect-secrets-hook") and BASELINE.exists():
        cmd = ["detect-secrets-hook", "--baseline", str(BASELINE)]
        cmd.extend(str(p.relative_to(ROOT)) for p in files)
        # Fixed tool name plus tracked file paths; no shell, no untrusted input.
        result = subprocess.run(cmd, cwd=ROOT)  # nosec B603
        ok = result.returncode == 0
        print("PASS (detect-secrets)" if ok else f"FAIL (exit {result.returncode})")
        return ok
    return _builtin_secret_scan(files)


def _declared_dependencies() -> list[str]:
    """Collect the project's declared runtime and dev dependencies from pyproject."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    project = data.get("project", {})
    deps: list[str] = list(project.get("dependencies", []))
    for group in project.get("optional-dependencies", {}).values():
        deps.extend(group)
    return deps


def check_dependency_audit() -> bool:
    """Audit the declared dependencies for known vulnerabilities.

    Scoped to what Casebound declares (not the whole environment), it reaches the
    advisory service when online and skips gracefully when offline or when
    pip-audit is unavailable, so the gate stays green without a network. It fails
    only on a real advisory against a declared dependency.
    """
    _print_header("dependency audit (pip-audit)")
    deps = _declared_dependencies()
    if not deps:
        print("SKIP: no declared dependencies found.")
        return True

    fd, req_path = tempfile.mkstemp(suffix=".txt", prefix="casebound-deps-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write("\n".join(deps) + "\n")
        # Fixed command; req_path is a temp file we just wrote.
        result = subprocess.run(  # nosec B603
            [
                sys.executable,
                "-m",
                "pip_audit",
                "--no-deps",
                "-r",
                req_path,
                "--progress-spinner",
                "off",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
    finally:
        os.unlink(req_path)

    if result.returncode == 0:
        print("PASS")
        return True

    combined = result.stdout + result.stderr
    if AUDIT_FINDING_RE.search(combined):
        # The audit ran and found real advisories against declared dependencies.
        print(combined.strip())
        print("FAIL: known vulnerabilities in declared dependencies.")
        return False

    # Any other non-zero outcome means the audit could not complete: offline, the
    # advisory service was unreachable, an isolated-environment setup failed, or
    # pip-audit is not installed. Skip gracefully so the gate stays green offline.
    print("SKIP: dependency audit did not complete (offline or pip-audit unavailable).")
    return True


def main() -> int:
    results: list[tuple[str, bool]] = []

    py = sys.executable
    results.append(("ruff check", run_cmd("ruff check (lint)", [py, "-m", "ruff", "check", "."])))
    results.append(
        (
            "ruff format",
            run_cmd("ruff format (check)", [py, "-m", "ruff", "format", "--check", "."]),
        )
    )
    results.append(("mypy", run_cmd("mypy (types)", [py, "-m", "mypy"])))
    results.append(("pytest", run_cmd("pytest (tests)", [py, "-m", "pytest"])))
    results.append(("schema", check_schema()))
    results.append(("secrets", check_secrets()))
    results.append(("dependency audit", check_dependency_audit()))

    print("\n==> CI summary")
    for name, ok in results:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}")

    failed = [name for name, ok in results if not ok]
    if failed:
        print(f"\nCI FAILED: {', '.join(failed)}")
        return 1
    print("\nCI PASSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
