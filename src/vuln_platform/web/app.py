"""FastAPI app factory + routes for the web dashboard.

Pages:
- /            — list of scans with summary counts
- /scans/{id}  — rendered markdown report + findings table
- /audit       — audit log viewer (LLM I/O records)
- /demo        — trigger a one-click demo scan in the background
"""
from __future__ import annotations

import json
import logging
import threading
from collections import defaultdict
from pathlib import Path
from typing import Any

import markdown as md_lib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..agents import (
    AgentContext,
    EnrichmentAgent,
    ReconAgent,
    ReporterAgent,
    TriageAgent,
)
from ..agents.reporter import render_report
from ..audit import AuditLogger
from ..config import Settings, load_settings
from ..ethics import load_scope
from ..orchestrator import Orchestrator
from ..storage import Store


logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or load_settings()
    app = FastAPI(title="Vulnerability Assessment Platform", version="0.1.0")

    templates = Jinja2Templates(directory=str(TEMPLATE_DIR))
    app.mount(
        "/static", StaticFiles(directory=str(STATIC_DIR)), name="static"
    )

    demo_state = _DemoState()

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Any:
        store = Store(settings.db_path)
        scans = store.list_scans()
        return templates.TemplateResponse(
            request,
            "index.html",
            {
                "scans": scans,
                "has_anthropic_key": settings.has_anthropic_key,
                "demo_running": demo_state.is_running(),
            },
        )

    @app.get("/scans/{scan_id}", response_class=HTMLResponse)
    def scan_detail(request: Request, scan_id: int) -> Any:
        store = Store(settings.db_path)
        scan = store.get_scan(scan_id)
        if scan is None:
            raise HTTPException(status_code=404, detail="scan not found")
        hosts = store.list_hosts(scan_id)
        findings = store.list_findings(scan_id)

        # Re-render the markdown report so the page shows the same thing
        # the CLI prints. We don't have the original scope object cached,
        # so build a minimal placeholder for the attestation block.
        scope = _placeholder_scope(scan["scope_target"])
        report_md = render_report(
            scope=scope,
            scope_target=scan["scope_target"],
            findings=findings,
            hosts=hosts,
            cves_by_service=None,
        )
        report_html = md_lib.markdown(
            report_md, extensions=["tables", "fenced_code"]
        )

        findings_by_severity = defaultdict(list)
        for f in findings:
            findings_by_severity[f.severity].append(f)

        return templates.TemplateResponse(
            request,
            "scan.html",
            {
                "scan": scan,
                "hosts": hosts,
                "findings": findings,
                "findings_by_severity": dict(findings_by_severity),
                "report_html": report_html,
            },
        )

    @app.get("/audit", response_class=HTMLResponse)
    def audit_log(request: Request) -> Any:
        entries = _load_audit(settings.audit_log_path)
        return templates.TemplateResponse(
            request, "audit.html", {"entries": entries},
        )

    @app.post("/demo")
    def trigger_demo() -> Any:
        if demo_state.is_running():
            return RedirectResponse(url="/", status_code=303)
        demo_state.start(settings)
        return RedirectResponse(url="/", status_code=303)

    @app.get("/demo/status")
    def demo_status() -> dict:
        return {
            "running": demo_state.is_running(),
            "last_scan_id": demo_state.last_scan_id,
            "last_error": demo_state.last_error,
        }

    return app


class _DemoState:
    """In-process flag + background thread for the one-click demo."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.last_scan_id: int | None = None
        self.last_error: str | None = None

    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(self, settings: Settings) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self.last_error = None
            self._thread = threading.Thread(
                target=self._run, args=(settings,), daemon=True
            )
            self._thread.start()

    def _run(self, settings: Settings) -> None:
        try:
            self.last_scan_id = _run_demo_pipeline(settings)
        except Exception as e:  # noqa: BLE001 - report any failure to the UI
            logger.exception("demo pipeline failed")
            self.last_error = str(e)


def _run_demo_pipeline(settings: Settings) -> int:
    """Run the same demo pipeline as the CLI, against the local fake target."""
    import subprocess
    import sys
    import time

    examples_root = Path(__file__).resolve().parents[3] / "examples"
    fake_target = examples_root / "demo_target" / "fake_service.py"
    scope_file = examples_root / "scope.example.yaml"
    cve_seed = examples_root / "demo_target" / "seed_cves.json"

    proc = subprocess.Popen(
        [sys.executable, str(fake_target), "--port", "18080"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.8)

        scope = load_scope(scope_file)
        store = Store(settings.db_path)
        audit = AuditLogger(settings.audit_log_path)
        scan_id = store.create_scan("127.0.0.1")
        context = AgentContext(scan_id=scan_id, scope_target="127.0.0.1")

        recon = ReconAgent(
            scope=scope, store=store, ports=[18080],
            timeout=0.5, workers=4,
            skip_host_discovery=True, scan_method="connect",
        )
        enrichment = EnrichmentAgent(
            store=store, api_key=settings.nvd_api_key, seed_path=cve_seed,
        )
        agents = [recon, enrichment]
        if settings.has_anthropic_key:
            agents.append(TriageAgent(
                store=store, audit=audit, model=settings.triage_model,
            ))
        agents.append(ReporterAgent(scope=scope))

        Orchestrator(agents).run(context)
        return scan_id
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def _load_audit(path: Path, limit: int = 200) -> list[dict]:
    if not path.exists():
        return []
    out: list[dict] = []
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return list(reversed(out[-limit:]))


def _placeholder_scope(target: str) -> Any:
    """Minimal Scope-like object so the reporter can render attestation."""
    import ipaddress

    from ..ethics import Attestation, Scope

    cidr_str = target if "/" in target else f"{target}/32"
    return Scope(
        classification="lab",
        cidrs=(ipaddress.ip_network(cidr_str, strict=False),),
        attestation=Attestation(
            authorized_by="(historical scan — attestation not retained)",
            date="—",
            statement="This is a historical view of a previously authorized scan.",
        ),
    )
