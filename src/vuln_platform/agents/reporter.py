"""Reporter Agent: render a professional pentest-style markdown report."""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from ..ethics import Scope
from ..models import CVE, Finding, Host
from .base import AgentContext, BaseAgent

if TYPE_CHECKING:
    from ..events import EventBus


logger = logging.getLogger(__name__)

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")


class ReporterAgent(BaseAgent):
    name = "reporter"

    def __init__(self, *, scope: Scope, event_bus: "EventBus | None" = None) -> None:
        self.scope = scope
        self.event_bus = event_bus

    def run(self, context: AgentContext) -> AgentContext:
        self.emit("reporter.started")
        context.report_markdown = render_report(
            scope=self.scope,
            scope_target=context.scope_target,
            findings=context.findings,
            hosts=context.hosts,
            cves_by_service=context.cves_by_service,
        )
        self.emit("reporter.done", scan_id=context.scan_id)
        return context


def render_report(
    *,
    scope: Scope,
    scope_target: str,
    findings: list[Finding],
    hosts: list[Host] | None = None,
    cves_by_service: dict[str, list[CVE]] | None = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = _severity_counts(findings)
    lines: list[str] = []

    lines.append("# Vulnerability Assessment Report")
    lines.append("")
    lines.append(f"*Generated: {now}*")
    lines.append("")

    # Executive summary
    lines.append("## Executive Summary")
    lines.append("")
    lines.append(
        f"Scan target: `{scope_target}`. Classification: "
        f"**{scope.classification}**. Authorized by "
        f"{scope.attestation.authorized_by} ({scope.attestation.date})."
    )
    lines.append("")
    host_count = len(hosts or [])
    open_port_count = sum(len(h.open_ports) for h in (hosts or []))
    cve_count = sum(len(v) for v in (cves_by_service or {}).values())
    summary_bits = [
        f"**{host_count}** live host(s)",
        f"**{open_port_count}** open port(s)",
        f"**{cve_count}** CVE(s) discovered",
    ]
    if findings:
        summary_bits.append(_counts_line(counts))
    else:
        summary_bits.append(
            "_Note: triage was not run; set `ANTHROPIC_API_KEY` to enable "
            "LLM-reasoned severity ranking._"
        )
    lines.append("Pipeline summary: " + " · ".join(summary_bits) + ".")
    lines.append("")

    # Methodology
    lines.append("## Methodology")
    lines.append("")
    lines.append(
        "Findings were produced by an automated four-agent pipeline: "
        "(1) **Recon Agent** — ICMP host discovery, concurrent TCP SYN "
        "port scan, banner grabbing; (2) **Enrichment Agent** — NIST NVD "
        "API lookup for CVEs matching the service+version strings "
        "observed; (3) **Triage Agent** — Claude Opus 4.7 assigns severity "
        "and exploit likelihood per finding, grounded in CVSS scores and "
        "service context (full prompt/response audit in `audit.jsonl`); "
        "(4) **Reporter Agent** — rendered this document."
    )
    lines.append("")

    # Scope attestation
    lines.append("## Scope & Authorization")
    lines.append("")
    lines.append(f"> {scope.attestation.statement}")
    lines.append("")
    lines.append("Authorized CIDR ranges:")
    for cidr in scope.cidrs:
        lines.append(f"- `{cidr}`")
    lines.append("")

    # Discovered services (always shown, independent of triage)
    if hosts:
        lines.append("## Discovered Services")
        lines.append("")
        lines.append("| Host | Port | Service | Version | Banner | CVEs |")
        lines.append("|---|---|---|---|---|---|")
        for host in hosts:
            for p in host.open_ports:
                svc = p.service
                name = svc.name if svc else "unknown"
                version = (svc.version if svc else None) or "—"
                banner_preview = _short(svc.banner if svc else None, 60)
                key = f"{name.lower()} {(svc.version if svc else '') or ''}".strip()
                cves = (cves_by_service or {}).get(key, [])
                cve_cell = ", ".join(c.cve_id for c in cves[:3]) if cves else "—"
                if len(cves) > 3:
                    cve_cell += f" (+{len(cves) - 3})"
                lines.append(
                    f"| {host.ip} | {p.number} | {name} | {version} "
                    f"| {banner_preview} | {cve_cell} |"
                )
        lines.append("")

    # Findings summary table
    lines.append("## Findings Summary")
    lines.append("")
    if findings:
        lines.append("| Severity | Host | Port | Service | CVE | Exploit likelihood |")
        lines.append("|---|---|---|---|---|---|")
        for f in findings:
            version = f" {f.service_version}" if f.service_version else ""
            lines.append(
                f"| {f.severity} | {f.host_ip} | {f.port} "
                f"| {f.service_name}{version} | {f.cve_id} "
                f"| {f.exploit_likelihood} |"
            )
    else:
        lines.append("*No findings.*")
    lines.append("")

    # Per-finding detail, grouped by severity
    lines.append("## Detailed Findings")
    lines.append("")
    if not findings:
        lines.append("*No findings to detail.*")
    else:
        by_sev: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            by_sev[f.severity].append(f)
        for sev in _SEVERITY_ORDER:
            group = by_sev.get(sev, [])
            if not group:
                continue
            lines.append(f"### Severity: {sev.upper()}")
            lines.append("")
            for f in group:
                lines.extend(_finding_detail(f))
                lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "*Report generated by the CSCI 401 Capstone Agentic Vulnerability "
        "Assessment Platform. LLM triage reasoning is logged in "
        "`audit.jsonl` for review.*"
    )
    return "\n".join(lines)


def _finding_detail(f: Finding) -> list[str]:
    version = f" {f.service_version}" if f.service_version else ""
    cvss = f"{f.cvss_score}" if f.cvss_score is not None else "n/a"
    return [
        f"#### {f.cve_id} — {f.host_ip}:{f.port} ({f.service_name}{version})",
        "",
        f"**CVSS base score:** {cvss} | "
        f"**Exploit likelihood:** {f.exploit_likelihood}",
        "",
        f"**Description:** {f.cve_description}",
        "",
        f"**Rationale:** {f.rationale}",
        "",
        f"**Recommended action:** {f.recommended_action}",
    ]


def _severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {k: 0 for k in _SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _short(s: str | None, limit: int) -> str:
    if not s:
        return "—"
    flat = " ".join(s.split())
    if len(flat) <= limit:
        return flat
    return flat[: limit - 1] + "…"


def _counts_line(counts: dict[str, int]) -> str:
    parts = [f"**{counts[sev]}** {sev}" for sev in _SEVERITY_ORDER if counts[sev]]
    if not parts:
        return "No vulnerabilities were identified for the scanned services."
    return "Findings by severity: " + ", ".join(parts) + "."
