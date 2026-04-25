"""Recon Agent: host discovery + port scan + banner grab.

This is the layer that wraps the classmate's original scapy logic.
The scanner primitives live in vuln_platform.scanner; this agent
just coordinates them and persists the results.
"""
from __future__ import annotations

import logging
import os
from typing import TYPE_CHECKING

from ..ethics import Scope, enforce_in_scope

if TYPE_CHECKING:
    from ..events import EventBus
from ..models import Host, Port
from ..scanner import (
    connect_scan,
    grab_banner,
    parse_service,
    ping_scan,
    port_scan,
    tcp_ping_sweep,
)
from ..storage import Store
from .base import AgentContext, BaseAgent


logger = logging.getLogger(__name__)

ScanMethod = str  # "auto" | "syn" | "connect"


class ReconAgent(BaseAgent):
    name = "recon"

    def __init__(
        self,
        *,
        scope: Scope,
        store: Store,
        ports: list[int],
        timeout: float = 0.5,
        workers: int = 100,
        skip_host_discovery: bool = False,
        scan_method: ScanMethod = "auto",
        event_bus: "EventBus | None" = None,
    ) -> None:
        self.scope = scope
        self.store = store
        self.ports = ports
        self.timeout = timeout
        self.workers = workers
        # For single-host local demos where ICMP is unreliable (e.g., scanning
        # 127.0.0.1 when ping returns but scapy may not capture it), skip
        # discovery and assume the target is live.
        self.skip_host_discovery = skip_host_discovery
        self.scan_method = self._resolve_method(scan_method)
        self.event_bus = event_bus

    @staticmethod
    def _resolve_method(method: ScanMethod) -> ScanMethod:
        if method != "auto":
            return method
        # SYN scans need raw sockets. On POSIX without root, fall back to a
        # userland connect scan so the demo + unprivileged runs actually work.
        if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0:
            logger.info("recon: no raw-socket privileges; using TCP connect scan")
            return "connect"
        return "syn"

    def _scan_ports(self, ip: str) -> list[int]:
        if self.scan_method == "connect":
            return connect_scan(
                ip, self.ports, timeout=self.timeout, workers=self.workers
            )
        return port_scan(
            ip, self.ports, timeout=self.timeout, workers=self.workers
        )

    def run(self, context: AgentContext) -> AgentContext:
        logger.info("recon: enforcing scope on %s", context.scope_target)
        enforce_in_scope(self.scope, context.scope_target)
        self.emit(
            "recon.started",
            target=context.scope_target,
            scan_method=self.scan_method,
            port_count=len(self.ports),
        )

        if self.skip_host_discovery:
            live_hosts = [context.scope_target.split("/")[0]]
            logger.info("recon: skipping host discovery, assuming %s is live", live_hosts[0])
            self.emit("recon.host_discovery_skipped", host=live_hosts[0])
        elif self.scan_method == "connect":
            # Userland mode: use TCP ping sweep instead of ICMP (which
            # needs raw sockets). This is what makes /24 home scans
            # actually work without sudo.
            self.emit("recon.host_discovery_method", method="tcp")
            live_hosts = tcp_ping_sweep(context.scope_target)
            logger.info("recon: %d live host(s) via TCP sweep", len(live_hosts))
            self.emit("recon.host_discovery_done",
                      live_count=len(live_hosts), hosts=live_hosts)
        else:
            self.emit("recon.host_discovery_method", method="icmp")
            live_hosts = ping_scan(context.scope_target)
            logger.info("recon: %d live host(s) via ICMP", len(live_hosts))
            self.emit("recon.host_discovery_done",
                      live_count=len(live_hosts), hosts=live_hosts)

        for ip in live_hosts:
            enforce_in_scope(self.scope, ip)
            self.emit("recon.scanning_host",
                      host=ip, ports_to_scan=len(self.ports))
            open_ports = self._scan_ports(ip)
            self.emit("recon.port_scan_done",
                      host=ip, open_count=len(open_ports), open_ports=open_ports)
            ports: list[Port] = []
            for p in open_ports:
                banner = grab_banner(ip, p)
                service = parse_service(p, banner)
                ports.append(Port(number=p, service=service))
                logger.info(
                    "recon: %s:%d -> %s %s",
                    ip, p, service.name, service.version or "?",
                )
                self.emit(
                    "recon.service_identified",
                    host=ip, port=p,
                    service=service.name,
                    version=service.version,
                    banner_preview=(service.banner or "").splitlines()[0][:80] if service.banner else None,
                )
            host = Host(ip=ip, open_ports=ports)  # type: ignore[arg-type]
            context.hosts.append(host)
            self.store.save_host(context.scan_id, host)
        self.emit(
            "recon.done",
            host_count=len(context.hosts),
            port_count=sum(len(h.open_ports) for h in context.hosts),
        )
        return context
