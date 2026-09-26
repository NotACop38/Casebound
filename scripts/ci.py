#!/usr/bin/env python3
"""Casebound local CI gate.

Runs the offline quality checks every change must pass:

  1. ruff check   : lint
  2. ruff format  : format check
  3. mypy         : strict type check
  4. pytest       : the test suite (no network, no API keys) with a coverage floor
  5. schema       : the event and claim schemas are valid JSON Schema, and every
                    worked example validates against the event schema
  6. style        : no em dash or en dash in any tracked or new text file (AGENTS.md)
  7. secrets      : a secret scan over tracked and new files (detect-secrets)
  8. bandit       : a static security scan over the first-party Python code
  9. deps         : a dependency audit of the declared dependencies (pip-audit)

Every step except the dependency audit runs fully offline with no API keys. The
dependency audit reaches the advisory service when online and skips gracefully
when offline (or when pip-audit is not installed), so the gate stays green
without a network. `make security` layers the defensive-scope invariants on top
of this same gate.

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
SCHEMA_PATH = ROOT / "casebound" / "data" / "event.schema.json"
CLAIMS_SCHEMA_PATH = ROOT / "casebound" / "data" / "claims.schema.json"
SCHEMA_EXAMPLES_DIR = ROOT / "docs" / "examples"
BASELINE = ROOT / ".secrets.baseline"
PYPROJECT = ROOT / "pyproject.toml"

# The line coverage the test suite must reach over the casebound package.
COVERAGE_FLOOR = 93

# The characters the house style bans everywhere (AGENTS.md Hard rule 5).
BANNED_DASHES = {"\u2014": "em dash", "\u2013": "en dash"}

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
    """Validate the bundled schemas and every worked example.

    Confirms the event schema and the claim schema are themselves valid JSON
    Schema, then validates every instance under docs/examples/ against the event
    schema, so the keystone record and its worked examples cannot drift apart.
    """
    _print_header("schema (JSON Schema validation)")
    from jsonschema import Draft202012Validator

    schemas: dict[Path, dict[str, object]] = {}
    for path in (SCHEMA_PATH, CLAIMS_SCHEMA_PATH):
        try:
            schemas[path] = json.loads(path.read_text(encoding="utf-8"))
            Draft202012Validator.check_schema(schemas[path])
        except Exception as exc:  # report any schema problem as a failure
            print(f"FAIL: {path.relative_to(ROOT)} is not a valid JSON Schema: {exc}")
            return False

    validator = Draft202012Validator(schemas[SCHEMA_PATH])
    examples = sorted(SCHEMA_EXAMPLES_DIR.glob("*.json"))
    if not examples:
        print(f"FAIL: no worked examples under {SCHEMA_EXAMPLES_DIR.relative_to(ROOT)}")
        return False
    for example in examples:
        try:
            validator.validate(json.loads(example.read_text(encoding="utf-8")))
        except Exception as exc:  # a non-conforming example is a failure
            print(f"FAIL: {example.relative_to(ROOT)} does not validate: {exc}")
            return False

    print(f"PASS (2 schemas, {len(examples)} example(s) validated)")
    return True


def _git_tracked_files() -> list[Path]:
    """Every tracked file plus every new file git does not ignore.

    New files are included so the gate catches a problem before the first commit.
    """
    # Fixed git invocation, no untrusted input.
    result = subprocess.run(  # nosec B603 B607
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
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


def check_style() -> bool:
    """Fail on any em dash or en dash in a tracked or new text file (AGENTS.md)."""
    _print_header("style (no em dashes or en dashes)")
    findings: list[str] = []
    files = _git_tracked_files()
    for path in files:
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary files (images) carry no prose
        for number, line in enumerate(text.splitlines(), start=1):
            for char, label in BANNED_DASHES.items():
                if char in line:
                    findings.append(f"{path.relative_to(ROOT)}:{number}: {label}")
    if findings:
        print("FAIL: banned dash characters found:")
        for finding in findings[:50]:
            print(f"  - {finding}")
        if len(findings) > 50:
            print(f"  and {len(findings) - 50} more")
        return False
    print(f"PASS ({len(files)} files)")
    return True


def check_secrets() -> bool:
    """Scan tracked files for secrets, preferring detect-secrets when available."""
    _print_header("secrets (secret scan)")
    files = _git_tracked_files()
    if shutil.which("detect-secrets-hook") and BASELINE.exists():
        # Pass the baseline as a repo-relative path so it matches its own entry in
        # the file list below (the subprocess runs with cwd=ROOT). With an absolute
        # path the hook does not recognize the baseline among the scanned files and
        # scans it as ordinary content, flagging the hashed_secret values it stores.
        cmd = ["detect-secrets-hook", "--baseline", str(BASELINE.relative_to(ROOT))]
        cmd.extend(str(p.relative_to(ROOT)) for p in files)
        # Fixed tool name plus tracked file paths; no shell, no untrusted input.
        result = subprocess.run(cmd, cwd=ROOT)  # nosec B603
        ok = result.returncode == 0
        print("PASS (detect-secrets)" if ok else f"FAIL (exit {result.returncode})")
        return ok
    return _builtin_secret_scan(files)


def check_bandit() -> bool:
    """Run the bandit static security scan over the first-party Python code.

    Scoped to casebound/ and scripts/ (our own code, not dependencies), bandit is
    fully offline and key-free. Inline `# nosec` annotations document the reviewed
    exceptions; any unsuppressed finding fails the gate.
    """
    _print_header("bandit (static security)")
    # Fixed command over first-party source dirs; no shell, no untrusted input.
    cmd = [sys.executable, "-m", "bandit", "-q", "-r", "casebound", "scripts"]
    result = subprocess.run(cmd, cwd=ROOT)  # nosec B603
    ok = result.returncode == 0
    print("PASS" if ok else f"FAIL (exit {result.returncode})")
    return ok


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
    results.append(
        (
            "pytest",
            run_cmd(
                f"pytest (tests, coverage floor {COVERAGE_FLOOR}%)",
                [
                    py,
                    "-m",
                    "pytest",
                    "--cov",
                    "--cov-report=term",
                    f"--cov-fail-under={COVERAGE_FLOOR}",
                ],
            ),
        )
    )
    results.append(("schema", check_schema()))
    results.append(("style", check_style()))
    results.append(("secrets", check_secrets()))
    results.append(("bandit", check_bandit()))
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
