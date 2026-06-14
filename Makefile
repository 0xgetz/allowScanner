.PHONY: help install dev doctor scan test lint format typecheck check clean

PYTHON ?= python3
URL ?= https://example.com

help:  ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install:  ## Install the scanner (runtime only)
	$(PYTHON) -m pip install -e .

dev:  ## Install with dev tooling (tests, lint, types)
	$(PYTHON) -m pip install -e ".[dev]"

doctor:  ## Verify the environment is ready to scan
	allowscanner --doctor

scan:  ## Run a scan (override target: make scan URL=https://target)
	allowscanner $(URL)

test:  ## Run the test suite
	$(PYTHON) -m pytest -q

lint:  ## Lint with ruff
	ruff check src tests

format:  ## Auto-format with ruff
	ruff format src tests

typecheck:  ## Strict type-check with mypy
	mypy src/allowscanner --ignore-missing-imports

check: lint typecheck test  ## Run lint + types + tests (the CI gate)

clean:  ## Remove caches and build artifacts
	rm -rf .pytest_cache .ruff_cache .mypy_cache build dist *.egg-info
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
