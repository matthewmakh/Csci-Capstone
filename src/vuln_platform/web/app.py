"""FastAPI app factory + routes for the web dashboard.

Pages:
- /              — list of scans with summary counts
- /scans/{id}    — rendered markdown report + findings table
- /audit         — audit log viewer (LLM I/O records)
- /about         — architecture / walkthrough page
- /live          — real-time pipeline visualization with SSE
- /scan-network  — interactive form: detect LAN, prompt for attestation,
                   kick off a real network scan
- /demo          — POST: trigger a one-click demo scan in the background
- /api/events    — SSE stream of pipeline events for the live view
- /api/network   — JSON: detected local network info
"""
from __future__ import annotations

import datetime as _dt
import ipaddress
import json
import logging
import queue
import threading
import time
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable, Iterator

import markdown as md_lib
from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from ..agents import (
    AgentContext,
    ChainAnalysisAgent,
    EnrichmentAgent,
    ReconAgent,
    ReporterAgent,
    TriageAgent,
)
from ..agents.reporter import render_report
from ..audit import AuditLogger
from ..config import Settings, load_settings
from ..ethics import Attestation, Scope, load_scope
from ..events import Event, EventBus, bus
from ..orchestrator import Orchestrator
from ..scanner import detect_local_network
from ..storage import Store


# Hard cap for in-browser network scans. Larger ranges are still fine
# from the CLI, where the user can hand-edit a scope file, but the
# web flow caps to keep one-click scans bounded in time and traffic.
MAX_WEB_SCAN_HOSTS = 1024  # /22

# Default port presets for the network scan form.
HOME_PORT_PRESETS: dict[str, str] = {
    "home": "21,22,23,25,53,80,110,143,443,445,548,587,631,993,995,1900,2049,3000,3306,3389,5000,5353,5432,5900,6379,8000,8080,8443,9000,9090,9100,32400",
    "top1000": "1-1024",
}
ATTESTATION_PHRASE = "yes i authorize"


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

    pipeline_state = _PipelineState()

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
                "demo_running": pipeline_state.is_running(),
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
        chains = store.list_chains(scan_id)
        # Look each finding's CVE up so we can show exploit/patch links.
        cves_by_id: dict[str, Any] = {}
        for f in findings:
            if f.cve_id not in cves_by_id:
                cve = store.get_cve(f.cve_id)
                if cve is not None:
                    cves_by_id[f.cve_id] = cve
        scope = _placeholder_scope(scan["scope_target"])
        report_md = render_report(
            scope=scope,
            scope_target=scan["scope_target"],
            findings=findings,
            hosts=hosts,
            cves_by_service=None,
            chains=chains,
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

        topology = topology_layout(hosts, findings, chains)
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
                "chains": chains,
                "cves_by_id": cves_by_id,
                "topology": topology,
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
                "demo_running": pipeline_state.is_running(),
            },
        )

    @app.post("/demo")
    def trigger_demo(request: Request) -> Any:
        if not pipeline_state.is_running():
            pipeline_state.start(
                lambda: _run_demo_pipeline(settings, event_bus),
                event_bus,
                kind="demo",
            )
        target = "/live" if request.headers.get("referer", "").endswith("/live") else "/"
        return RedirectResponse(url=target, status_code=303)

    @app.get("/demo/status")
    def demo_status() -> dict:
        return {
            "running": pipeline_state.is_running(),
            "last_scan_id": pipeline_state.last_scan_id,
            "last_error": pipeline_state.last_error,
            "kind": pipeline_state.last_kind,
        }

    @app.get("/api/network")
    def api_network() -> dict:
        try:
            net = detect_local_network()
        except Exception as e:  # noqa: BLE001
            return {"error": str(e)}
        return {
            "ip": net.ip,
            "cidr": net.cidr,
            "interface": net.interface,
            "detection_method": net.detection_method,
            "host_count": net.network.num_addresses,
        }

    @app.get("/scan-network", response_class=HTMLResponse)
    def scan_network_form(request: Request) -> Any:
        try:
            detected = detect_local_network()
            detection_error = None
        except Exception as e:  # noqa: BLE001
            detected = None
            detection_error = str(e)
        return templates.TemplateResponse(
            request,
            "scan_network.html",
            {
                "detected": detected,
                "detection_error": detection_error,
                "presets": HOME_PORT_PRESETS,
                "max_hosts": MAX_WEB_SCAN_HOSTS,
                "has_anthropic_key": settings.has_anthropic_key,
                "running": pipeline_state.is_running(),
            },
        )

    @app.post("/scan-network")
    def scan_network_start(
        request: Request,
        authorized_by: str = Form(...),
        cidr: str = Form(...),
        attestation_phrase: str = Form(...),
        attestation_checkbox: str = Form(""),
        port_preset: str = Form("home"),
        custom_ports: str = Form(""),
    ) -> Any:
        # Normalize + validate. Server-side checks repeat the front-end
        # ones because client validation is for UX, not security.
        authorized_by = authorized_by.strip()
        cidr = cidr.strip()
        phrase = attestation_phrase.strip().lower()
        if not authorized_by:
            raise HTTPException(400, "Full name is required.")
        if phrase != ATTESTATION_PHRASE:
            raise HTTPException(
                400, f"You must type the phrase '{ATTESTATION_PHRASE}' verbatim."
            )
        if attestation_checkbox not in ("on", "true", "1", "yes"):
            raise HTTPException(400, "You must check the authorization box.")

        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError as e:
            raise HTTPException(400, f"Invalid CIDR: {e}") from e
        if network.num_addresses > MAX_WEB_SCAN_HOSTS:
            raise HTTPException(
                400,
                f"Network too large for the web flow "
                f"({network.num_addresses} hosts > {MAX_WEB_SCAN_HOSTS}). "
                f"Use the CLI for bigger ranges.",
            )

        if port_preset == "custom":
            ports_csv = custom_ports.strip()
            if not ports_csv:
                raise HTTPException(400, "Custom port list cannot be empty.")
        else:
            ports_csv = HOME_PORT_PRESETS.get(port_preset)
            if not ports_csv:
                raise HTTPException(400, f"Unknown port preset: {port_preset}")

        if pipeline_state.is_running():
            raise HTTPException(
                409, "Another scan is already running. Wait for it to finish."
            )

        scope = _scope_from_form(authorized_by, str(network))
        pipeline_state.start(
            lambda: _run_network_scan_pipeline(
                settings, event_bus, scope, str(network), ports_csv,
            ),
            event_bus,
            kind="network",
        )
        return RedirectResponse(url="/live", status_code=303)

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


class _PipelineState:
    """Generic single-slot runner for any pipeline (demo or real network scan).

    Only one pipeline can run at a time per process, since they share
    the event bus and SQLite store. The thread emits demo.finished /
    demo.failed for either kind so the existing /live JS keeps working.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self.last_scan_id: int | None = None
        self.last_error: str | None = None
        self.last_kind: str | None = None  # "demo" | "network"

    def is_running(self) -> bool:
        with self._lock:
            return self._thread is not None and self._thread.is_alive()

    def start(
        self,
        target: Callable[[], int],
        event_bus: EventBus,
        *,
        kind: str,
    ) -> None:
        with self._lock:
            if self._thread and self._thread.is_alive():
                return
            self.last_error = None
            self.last_kind = kind
            self._thread = threading.Thread(
                target=self._run, args=(target, event_bus, kind), daemon=True
            )
            self._thread.start()

    def _run(
        self,
        target: Callable[[], int],
        event_bus: EventBus,
        kind: str,
    ) -> None:
        try:
            self.last_scan_id = target()
        except Exception as e:  # noqa: BLE001
            logger.exception("%s pipeline failed", kind)
            self.last_error = str(e)
            event_bus.publish(Event(
                type="demo.failed",
                data={"error": str(e), "kind": kind},
            ))
        else:
            event_bus.publish(Event(
                type="demo.finished",
                data={"scan_id": self.last_scan_id, "kind": kind},
            ))


def _scope_from_form(authorized_by: str, cidr: str) -> Scope:
    """Build a Scope object directly from the web attestation form.

    No file is written; the scope lives in memory for the duration of
    the scan. The CLI's init-scope command writes a YAML file to disk;
    the web flow doesn't, so the user's name + statement aren't
    persisted beyond the scan's lifetime.
    """
    today = _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    statement = (
        f"I, {authorized_by}, affirm that I own or have written permission "
        f"to perform vulnerability scanning against {cidr} as of {today}. "
        "Submitted via the web dashboard attestation form."
    )
    return Scope(
        classification="lab",
        cidrs=(ipaddress.ip_network(cidr, strict=False),),
        attestation=Attestation(
            authorized_by=authorized_by,
            date=today,
            statement=statement,
        ),
    )


def _run_network_scan_pipeline(
    settings: Settings,
    event_bus: EventBus,
    scope: Scope,
    cidr: str,
    ports_csv: str,
) -> int:
    """Run the full pipeline against a real network the user authorized."""
    from ..scanner import parse_ports

    ports = parse_ports(ports_csv)
    event_bus.publish(Event(
        type="demo.starting",
        data={"target": cidr, "kind": "network", "port_count": len(ports)},
    ))

    store = Store(settings.db_path)
    audit = AuditLogger(settings.audit_log_path)
    scan_id = store.create_scan(cidr)
    context = AgentContext(scan_id=scan_id, scope_target=cidr)

    recon = ReconAgent(
        scope=scope, store=store, ports=ports,
        timeout=0.5, workers=64,
        skip_host_discovery=False,  # use TCP ping sweep
        scan_method="connect",      # forces userland mode
        event_bus=event_bus,
    )
    enrichment = EnrichmentAgent(
        store=store, api_key=settings.nvd_api_key,
        event_bus=event_bus,
    )
    agents: list = [recon, enrichment]
    if settings.has_anthropic_key:
        agents.append(TriageAgent(
            store=store, audit=audit, model=settings.triage_model,
            event_bus=event_bus,
        ))
        agents.append(ChainAnalysisAgent(
            store=store, audit=audit, model=settings.triage_model,
            event_bus=event_bus,
        ))
    agents.append(ReporterAgent(scope=scope, event_bus=event_bus))

    Orchestrator(agents, event_bus=event_bus).run(context)
    return scan_id


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


# --- network topology layout -----------------------------------------

# Severity → SVG fill color. Maps to the same palette used for finding
# badges so the topology view reads consistently with the rest of the UI.
_SEVERITY_FILL = {
    "critical": "#ef4444",  # red-500
    "high":     "#f97316",  # orange-500
    "medium":   "#f59e0b",  # amber-500
    "low":      "#0ea5e9",  # sky-500
    "info":     "#94a3b8",  # slate-400
    None:       "#cbd5e1",  # slate-300 (no findings)
}


def topology_layout(
    hosts: list,
    findings: list,
    chains: list,
) -> dict:
    """Compute SVG node + edge coordinates for the scan's topology graph.

    Layout strategy:
    - Each host is a labeled circle laid out in a grid (square-ish).
    - Around each host, its open services orbit in a ring.
    - Service nodes are colored by the worst finding severity on them.
    - Attack-chain hops are overlaid as dashed arrows.

    Returned dict is JSON-safe and consumed directly by the Jinja
    template (no per-element math in the .html).
    """
    import math

    if not hosts:
        return {"width": 0, "height": 0, "hosts": [], "chain_paths": []}

    # Index findings by (host, port) -> worst severity for fast lookup.
    sev_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    worst: dict[tuple[str, int], str] = {}
    for f in findings:
        key = (str(f.host_ip), f.port)
        cur = worst.get(key)
        if cur is None or sev_rank.get(f.severity, 0) > sev_rank.get(cur, 0):
            worst[key] = f.severity

    # Per-host service-ring radius scales with port count so dense
    # hosts don't overlap their own labels.
    cols = max(1, math.ceil(math.sqrt(len(hosts))))
    cell_w = 320
    cell_h = 320
    rows = math.ceil(len(hosts) / cols)
    width = cols * cell_w
    height = rows * cell_h

    host_layout: list[dict] = []
    # Service node centers indexed by (host_ip, port) so chain edges can
    # find them.
    svc_centers: dict[tuple[str, int], tuple[float, float]] = {}

    for idx, host in enumerate(hosts):
        col = idx % cols
        row = idx // cols
        cx = col * cell_w + cell_w / 2
        cy = row * cell_h + cell_h / 2
        ip = str(host.ip)

        n_ports = len(host.open_ports) or 1
        # Bigger ring for more services, capped so labels stay readable.
        ring_r = min(120, 50 + n_ports * 8)

        services: list[dict] = []
        for j, port in enumerate(host.open_ports):
            angle = (2 * math.pi * j) / n_ports - (math.pi / 2)
            sx = cx + ring_r * math.cos(angle)
            sy = cy + ring_r * math.sin(angle)
            sev = worst.get((ip, port.number))
            label = port.service.name if port.service else "?"
            version = port.service.version if port.service else None
            services.append({
                "x": sx, "y": sy,
                "port": port.number,
                "label": label,
                "version": version,
                "severity": sev,
                "fill": _SEVERITY_FILL.get(sev, _SEVERITY_FILL[None]),
            })
            svc_centers[(ip, port.number)] = (sx, sy)

        host_layout.append({
            "ip": ip,
            "x": cx, "y": cy,
            "services": services,
            "ring_radius": ring_r,
        })

    # Build dashed-arrow paths for each attack chain hop.
    chain_paths: list[dict] = []
    for chain_idx, chain in enumerate(chains or []):
        for i in range(len(chain.hops) - 1):
            src = chain.hops[i]
            dst = chain.hops[i + 1]
            src_pt = svc_centers.get((src.host_ip, src.port))
            dst_pt = svc_centers.get((dst.host_ip, dst.port))
            if src_pt is None or dst_pt is None:
                continue
            chain_paths.append({
                "x1": src_pt[0], "y1": src_pt[1],
                "x2": dst_pt[0], "y2": dst_pt[1],
                "chain_index": chain_idx,
                "title": chain.title,
                "stroke": _SEVERITY_FILL.get(chain.severity, "#475569"),
            })

    return {
        "width": width,
        "height": height,
        "hosts": host_layout,
        "chain_paths": chain_paths,
    }


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
