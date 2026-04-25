.PHONY: setup install test demo web scan scan-home discover clean help

VENV := .venv
PY := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# Default port set for home-network scans. Top services likely to be
# present on a home LAN (web, ssh, file shares, databases, IoT panels).
HOME_PORTS ?= 21,22,23,25,53,80,110,143,443,445,548,587,631,993,995,1900,2049,3000,3306,3389,5000,5353,5432,5900,6379,8000,8080,8443,9000,9090,9100,32400

help:
	@echo "Quick start:"
	@echo "  make setup     - one-time: venv + deps + .env + API key prompt + tests"
	@echo "  make demo      - safe end-to-end demo against the local fake target"
	@echo "  make web       - launch the FastAPI dashboard at http://127.0.0.1:8000"
	@echo "  make discover  - print the LAN you're attached to"
	@echo "  make scan-home - generate a scope file for your LAN, then scan it"
	@echo "  make scan ARGS='--ip 127.0.0.1 --ports 1-1024'"
	@echo "  make test      - run pytest"
	@echo "  make clean     - remove venv, caches, db, and audit log"

# One-shot bootstrap. Idempotent — safe to re-run.
setup: $(VENV)/bin/activate install
	@$(PY) scripts/configure_env.py
	@$(PY) -m pytest -q
	@echo ""
	@echo "Setup complete. Try:  make demo  (or: make web)"

$(VENV)/bin/activate:
	python3 -m venv $(VENV)
	@$(VENV)/bin/python -m pip install --upgrade pip --quiet

install: $(VENV)/bin/activate
	@$(PIP) install -e '.[dev,web]' --quiet

test: $(VENV)/bin/activate
	$(PY) -m pytest

demo: $(VENV)/bin/activate
	$(PY) -m vuln_platform demo

web: $(VENV)/bin/activate
	$(PY) -m vuln_platform web

scan: $(VENV)/bin/activate
	$(PY) -m vuln_platform scan --scope-file examples/scope.example.yaml $(ARGS)

discover: $(VENV)/bin/activate
	@$(PY) -m vuln_platform discover

# Two-step home scan: generate a scope file (interactive attestation),
# then scan the detected LAN with the default port list. Re-running
# skips the prompt if home-scope.yaml already exists.
scan-home: $(VENV)/bin/activate
	@if [ ! -f home-scope.yaml ]; then \
		$(PY) -m vuln_platform init-scope --output home-scope.yaml || exit $$?; \
	else \
		echo "Using existing home-scope.yaml (delete it to re-prompt)."; \
	fi
	@CIDR=$$($(PY) -m vuln_platform discover --cidr-only); \
	echo ""; \
	echo "Scanning $$CIDR on ports $(HOME_PORTS)…"; \
	$(PY) -m vuln_platform scan \
		--scope-file home-scope.yaml \
		--ip $$CIDR \
		--ports $(HOME_PORTS) \
		--scan-method connect \
		$(ARGS)

clean:
	rm -rf build dist *.egg-info src/*.egg-info $(VENV)
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
	rm -f findings.db audit.jsonl
