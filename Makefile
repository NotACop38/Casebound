# Casebound build surface. These targets are the contract in AGENTS.md; keep them
# working as the project grows. Style: no em dashes or en dashes anywhere.

PYTHON ?= python3

.PHONY: install lint test demo serve ci security catalog clean

install:  ## Install the package and the pinned dev toolchain.
	$(PYTHON) -m pip install -e ".[dev]"

lint:  ## ruff plus mypy, zero errors.
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy

test:  ## pytest, all green, no network, no API keys.
	$(PYTHON) -m pytest

demo:  ## Run the whole pipeline on the bundled synthetic scenario, offline, and score it.
	$(PYTHON) -m casebound demo

serve:  ## Open the optional web viewer on loopback (needs the web extra).
	$(PYTHON) -m casebound serve

ci:  ## The gate: lint, types, tests with the coverage floor, schemas, style, secrets, bandit, dependency audit.
	$(PYTHON) scripts/ci.py

security:  ## The gate, then the defensive-scope invariants as a named step.
	$(PYTHON) scripts/ci.py
	@echo ""
	@echo "==> defensive-scope invariants (PRD Section 6)"
	$(PYTHON) -m pytest -m invariant

catalog:  ## Rebuild the bundled ATT&CK catalog from a local MITRE STIX bundle (ATTACK_STIX=path).
	$(PYTHON) scripts/build_attack_catalog.py "$(ATTACK_STIX)"

clean:  ## Remove caches and build artifacts.
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
