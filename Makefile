.PHONY: setup install test demo scan clean help

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

help:
	@echo "Quick start:"
	@echo "  make setup   - one-time: venv + deps + .env + API key prompt + tests"
	@echo "  make demo    - end-to-end demo against the local fake target"
	@echo "  make scan ARGS='--ip 127.0.0.1 --ports 1-1024'"
	@echo "  make test    - run pytest"
	@echo "  make clean   - remove venv, caches, db, and audit log"

# One-shot bootstrap. Idempotent — safe to re-run.
setup: $(VENV)/bin/activate install
	@$(PY) scripts/configure_env.py
	@$(PY) -m pytest -q
	@echo ""
	@echo "Setup complete. Try:  make demo"

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	@$(VENV)/bin/python -m pip install --upgrade pip --quiet

install: $(VENV)/bin/activate
	@$(PIP) install -e '.[dev]' --quiet

test: $(VENV)/bin/activate
	$(PY) -m pytest

demo: $(VENV)/bin/activate
	$(PY) -m vuln_platform demo

scan: $(VENV)/bin/activate
	$(PY) -m vuln_platform scan --scope-file examples/scope.example.yaml $(ARGS)

clean:
	rm -rf build dist *.egg-info src/*.egg-info $(VENV)
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -f findings.db audit.jsonl
