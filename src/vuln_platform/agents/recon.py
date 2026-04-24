"""Recon Agent: host discovery + port scan + banner grab.

This is the layer that wraps the classmate's original scapy logic.
The scanner primitives live in vuln_platform.scanner; this agent
just coordinates them and persists the results.
"""
from __future__ import annotations

import logging

from ..ethics import Scope, enforce_in_scope
from ..models import Host, Port
from ..scanner import grab_banner, parse_service, ping_scan, port_scan
from ..storage import Store
from .base import AgentContext, BaseAgent


logger = logging.getLogger(__name__)


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

    def run(self, context: AgentContext) -> AgentContext:
        logger.info("recon: enforcing scope on %s", context.scope_target)
        enforce_in_scope(self.scope, context.scope_target)

        if self.skip_host_discovery:
            live_hosts = [context.scope_target.split("/")[0]]
            logger.info("recon: skipping host discovery, assuming %s is live", live_hosts[0])
        else:
            live_hosts = ping_scan(context.scope_target)
            logger.info("recon: %d live host(s)", len(live_hosts))

        for ip in live_hosts:
            enforce_in_scope(self.scope, ip)
            open_ports = port_scan(
                ip, self.ports, timeout=self.timeout, workers=self.workers
            )
            ports: list[Port] = []
            for p in open_ports:
                banner = grab_banner(ip, p)
                service = parse_service(p, banner)
                ports.append(Port(number=p, service=service))
                logger.info(
                    "recon: %s:%d -> %s %s",
                    ip, p, service.name, service.version or "?",
                )
            host = Host(ip=ip, open_ports=ports)  # type: ignore[arg-type]
            context.hosts.append(host)
            self.store.save_host(context.scan_id, host)
        return context
