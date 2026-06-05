# Casebound build surface. These targets are the contract in AGENTS.md;
# keep them working as the project grows.

PYTHON ?= python3

.PHONY: install lint test demo ci security clean

install:  ## Install the package and the pinned dev dependencies.
	$(PYTHON) -m pip install -e ".[dev]"

lint:  ## ruff plus mypy, zero errors.
	$(PYTHON) -m ruff check .
	$(PYTHON) -m ruff format --check .
	$(PYTHON) -m mypy

test:  ## pytest, all green, no network, no API keys.
	$(PYTHON) -m pytest

demo:  ## Run the full pipeline on the bundled synthetic scenario, offline.
	@echo "demo: the offline synthetic-scenario pipeline lands in Phase 1 (see ENGINEERING CHECKLIST.md)."

ci:  ## The gate: lint, test, schema validation, secret scan, and a dependency audit.
	$(PYTHON) scripts/ci.py

security:  ## The gate plus bandit, and the defensive-scope invariants.
	$(PYTHON) scripts/ci.py
	$(PYTHON) -m bandit -q -r casebound scripts
	@echo "security: defensive-scope invariant tests land in Phase 6 (see ENGINEERING CHECKLIST.md)."

clean:  ## Remove caches and build artifacts.
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache out
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
