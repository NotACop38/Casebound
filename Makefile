# Casebound build surface. These targets are the contract in AGENTS.md;
# keep them working as the project grows.

PYTHON ?= python3

.PHONY: install lint test demo web ci security clean

install:  ## Install the package and the pinned dev dependencies.
	$(PYTHON) -m pip install -e ".[dev]"

lint:  ## ruff plus mypy, zero errors.
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy

test:  ## pytest, all green, no network, no API keys.
	$(PYTHON) -m pytest

demo:  ## Run the full pipeline on the bundled synthetic scenario, offline.
	$(PYTHON) -m casebound.cli demo

web:  ## Serve the optional web UI on loopback (needs the 'web' extra installed).
	$(PYTHON) -m web

ci:  ## The gate: lint, test, schema validation, secret scan, bandit, and a dependency audit.
	$(PYTHON) scripts/ci.py

security:  ## The gate (which includes the secret scan, bandit, and pip-audit) plus the defensive-scope invariants.
	$(PYTHON) scripts/ci.py
	@echo ""
	@echo "==> defensive-scope invariants (PRD Section 6)"
	$(PYTHON) -m pytest -m invariant

clean:  ## Remove caches and build artifacts.
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
