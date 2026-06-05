#!/usr/bin/env python3
"""Casebound local CI gate.

Runs the offline quality checks that every later step can rely on:

  1. ruff check   : lint
  2. ruff format  : format check
  3. mypy         : strict-ish type check
  4. pytest       : the test suite (no network, no API keys)
  5. schema       : JSON Schema validation (placeholder until the schema exists)
  6. secrets      : a secret scan over git-tracked files

Everything here runs fully offline with no API keys. Per PRD decision D3 this
local runner is the gate. The dependency audit (pip-audit) and the static
security checks (bandit) live in `make security`, which may reach the network.

Usage: python scripts/ci.py
Exit code is 0 only if every step passes.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # nosec B404
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = ROOT / "schema" / "event.schema.json"
BASELINE = ROOT / ".secrets.baseline"

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
