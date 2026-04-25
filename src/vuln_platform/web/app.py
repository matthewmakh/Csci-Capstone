"""FastAPI app factory + routes for the web dashboard.

Pages:
- /            — list of scans with summary counts
- /scans/{id}  — rendered markdown report + findings table
- /audit       — audit log viewer (LLM I/O records)
- /about       — architecture / walkthrough page
- /live        — real-time pipeline visualization with SSE
- /demo        — POST: trigger a one-click demo scan in the background
- /api/events  — SSE stream of pipeline events for the live view
"""
from __future__ import annotations

import json
import logging
import queue
import re
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Iterator

import markdown as md_lib
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
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
from ..events import Event, EventBus, bus
from ..orchestrator import Orchestrator
from ..storage import Store


logger = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent
TEMPLATE_DIR = WEB_DIR / "templates"
STATIC_DIR = WEB_DIR / "static"


def create_app(
    settings: Settings | None = None,
    event_bus: EventBus | None = None,
) -> FastAPI:
    settings = settings or load_settings()
    event_bus = event_bus or bus
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

        findings_by_severity: dict[str, list] = defaultdict(list)
        for f in findings:
            findings_by_severity[f.severity].append(f)

        # Index audit entries by the per-call extra.cve_id so each finding
        # can deep-link to the exact LLM call that produced it.
        audit_by_cve = _index_audit_by_cve(settings.audit_log_path)

        return templates.TemplateResponse(
            request,
            "scan.html",
            {
                "scan": scan,
                "hosts": hosts,
                "findings": findings,
                "findings_by_severity": dict(findings_by_severity),
                "report_html": report_html,
                "audit_by_cve": audit_by_cve,
            },
        )

    @app.get("/audit", response_class=HTMLResponse)
    def audit_log(request: Request) -> Any:
        entries = _load_audit(settings.audit_log_path)
        return templates.TemplateResponse(
            request, "audit.html", {"entries": entries},
        )

    @app.get("/about", response_class=HTMLResponse)
    def about(request: Request) -> Any:
        return templates.TemplateResponse(request, "about.html", {})

    @app.get("/live", response_class=HTMLResponse)
    def live(request: Request) -> Any:
        return templates.TemplateResponse(
            request, "live.html",
            {
                "has_anthropic_key": settings.has_anthropic_key,
                "demo_running": demo_state.is_running(),
            },
        )

    @app.post("/demo")
    def trigger_demo(request: Request) -> Any:
        if not demo_state.is_running():
            demo_state.start(settings, event_bus)
        # If the user came from /live, keep them there to watch the stream.
        target = "/live" if request.headers.get("referer", "").endswith("/live") else "/"
        return RedirectResponse(url=target, status_code=303)

    @app.get("/demo/status")
    def demo_status() -> dict:
        return {
            "running": demo_state.is_running(),
            "last_scan_id": demo_state.last_scan_id,
            "last_error": demo_state.last_error,
        }

    @app.get("/api/events")
    def event_stream() -> StreamingResponse:
        return StreamingResponse(
            _sse_generator(event_bus),
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
            },
        )

    return app


def _sse_generator(event_bus: EventBus) -> Iterator[bytes]:
    """Subscribe to the bus and yield SSE-formatted events.

    NB: we deliberately do NOT prefix with `event: <type>` lines, because
    the browser splits named-event streams across many addEventListener
    handlers — easy to drop events on the floor. With unnamed events
    everything funnels through `EventSource.onmessage`, where one
    dispatcher routes by `event.type` from the JSON payload.
    """
    sub = event_bus.subscribe()
    try:
        # Initial keep-alive so the browser knows the stream is live.
        yield b": connected\n\n"
        while True:
            try:
                event = sub.get(timeout=15)
            except queue.Empty:
                yield b": keep-alive\n\n"
                continue
            if event is None:
                break
            payload = json.dumps(event.to_dict())
            yield f"data: {payload}\n\n".encode("utf-8")
    finally:
        event_bus.unsubscribe(sub)


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

    def start(self, settings: Settings, event_bus: EventBus) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self.last_error = None
            self._thread = threading.Thread(
                target=self._run, args=(settings, event_bus), daemon=True
            )
            self._thread.start()

    def _run(self, settings: Settings, event_bus: EventBus) -> None:
        try:
            self.last_scan_id = _run_demo_pipeline(settings, event_bus)
        except Exception as e:  # noqa: BLE001
            logger.exception("demo pipeline failed")
            self.last_error = str(e)
            event_bus.publish(Event(type="demo.failed", data={"error": str(e)}))
        else:
            event_bus.publish(Event(
                type="demo.finished",
                data={"scan_id": self.last_scan_id},
            ))


def _run_demo_pipeline(settings: Settings, event_bus: EventBus) -> int:
    """Run the demo pipeline against the local fake target, publishing events."""
    import importlib.util
    import subprocess
    import sys

    examples_root = Path(__file__).resolve().parents[3] / "examples"
    fake_target = examples_root / "demo_target" / "fake_service.py"
    scope_file = examples_root / "scope.example.yaml"
    cve_seed = examples_root / "demo_target" / "seed_cves.json"

    # Pull port list from fake_service.PROFILES so we never drift.
    name = "_demo_fake_service"
    spec = importlib.util.spec_from_file_location(name, fake_target)
    assert spec is not None and spec.loader is not None
    fake_module = importlib.util.module_from_spec(spec)
    sys.modules[name] = fake_module  # dataclass evaluation needs this
    spec.loader.exec_module(fake_module)
    demo_ports = [p.port for p in fake_module.PROFILES]

    event_bus.publish(Event(
        type="demo.starting",
        data={"target": "127.0.0.1", "demo_ports": demo_ports},
    ))

    proc = subprocess.Popen(
        [sys.executable, str(fake_target)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(1.0)  # let all sockets bind

        scope = load_scope(scope_file)
        store = Store(settings.db_path)
        audit = AuditLogger(settings.audit_log_path)
        scan_id = store.create_scan("127.0.0.1")
        context = AgentContext(scan_id=scan_id, scope_target="127.0.0.1")

        recon = ReconAgent(
            scope=scope, store=store, ports=demo_ports,
            timeout=0.5, workers=8,
            skip_host_discovery=True, scan_method="connect",
            event_bus=event_bus,
        )
        enrichment = EnrichmentAgent(
            store=store, api_key=settings.nvd_api_key, seed_path=cve_seed,
            event_bus=event_bus,
        )
        agents = [recon, enrichment]
        if settings.has_anthropic_key:
            agents.append(TriageAgent(
                store=store, audit=audit, model=settings.triage_model,
                event_bus=event_bus,
            ))
        agents.append(ReporterAgent(scope=scope, event_bus=event_bus))

        Orchestrator(agents, event_bus=event_bus).run(context)
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


def _index_audit_by_cve(path: Path) -> dict[str, dict]:
    """Map cve_id -> most recent audit entry that referenced it."""
    if not path.exists():
        return {}
    out: dict[str, dict] = {}
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            extra = rec.get("extra") or {}
            cve_id = extra.get("cve_id")
            if cve_id:
                out[cve_id] = rec  # last-wins is correct for "most recent"
    return out


# CVSS v3 vector parser — best-effort, only labels the components.
_CVSS_LABEL = {
    "AV": ("Attack Vector", {"N": "Network", "A": "Adjacent", "L": "Local", "P": "Physical"}),
    "AC": ("Attack Complexity", {"L": "Low", "H": "High"}),
    "PR": ("Privileges Required", {"N": "None", "L": "Low", "H": "High"}),
    "UI": ("User Interaction", {"N": "None", "R": "Required"}),
    "S": ("Scope", {"U": "Unchanged", "C": "Changed"}),
    "C": ("Confidentiality", {"H": "High", "L": "Low", "N": "None"}),
    "I": ("Integrity", {"H": "High", "L": "Low", "N": "None"}),
    "A": ("Availability", {"H": "High", "L": "Low", "N": "None"}),
}


def parse_cvss_vector(vector: str) -> list[dict[str, str]]:
    """Parse a CVSS v3 vector like CVSS:3.1/AV:N/AC:L/... into labeled rows."""
    out: list[dict[str, str]] = []
    for piece in vector.split("/"):
        if ":" not in piece or piece.startswith("CVSS"):
            continue
        key, val = piece.split(":", 1)
        if key in _CVSS_LABEL:
            label, options = _CVSS_LABEL[key]
            out.append({
                "code": key,
                "label": label,
                "value": options.get(val, val),
            })
    return out


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
