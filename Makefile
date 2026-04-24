.PHONY: install test lint demo clean scan help

PYTHON ?= python3
PIP ?= $(PYTHON) -m pip

help:
	@echo "Targets:"
	@echo "  install  - install package + dev deps (editable)"
	@echo "  test     - run pytest"
	@echo "  demo     - end-to-end demo against the local fake target"
	@echo "  scan     - scan a user-provided --ip against a scope file"
	@echo "  clean    - remove caches, build artifacts, and local db/logs"

install:
	$(PIP) install -e '.[dev]'

test:
	$(PYTHON) -m pytest

demo:
	$(PYTHON) -m vuln_platform demo

scan:
	$(PYTHON) -m vuln_platform scan --scope-file examples/scope.example.yaml $(ARGS)

clean:
	rm -rf build dist *.egg-info src/*.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -f findings.db audit.jsonl
