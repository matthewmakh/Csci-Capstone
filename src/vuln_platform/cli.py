"""Command-line entry point."""
from __future__ import annotations

import argparse
import logging
import os
import subprocess
import sys
import time
from pathlib import Path

from .agents import (
    AgentContext,
    EnrichmentAgent,
    ReconAgent,
    ReporterAgent,
    TriageAgent,
)
from .audit import AuditLogger
from .config import load_settings
from .ethics import InvalidScopeFile, ScopeViolation, load_scope
from .orchestrator import Orchestrator
from .scanner import parse_ports
from .storage import Store


ETHICS_NOTICE = """\
ETHICS NOTICE
-------------
This tool performs active network scanning. Only scan networks you own
or have written permission to test. Unauthorized scanning may violate
the Computer Fraud and Abuse Act (18 U.S.C. 1030) in the United States
and equivalent statutes in other jurisdictions. A scope file with a
signed attestation is REQUIRED for every scan.
"""


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    _configure_logging(args.verbose)

    if args.command == "scan":
        return _cmd_scan(args)
    if args.command == "demo":
        return _cmd_demo(args)
    parser.print_help()
    return 2


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="vuln-platform",
        description=(
            "Agentic Vulnerability Assessment Platform — recon, CVE "
            "enrichment, LLM triage, and report generation in one pipeline.\n\n"
            + ETHICS_NOTICE
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--verbose", action="count", default=0,
                        help="increase log verbosity (-v INFO, -vv DEBUG)")
    sub = parser.add_subparsers(dest="command", required=False)

    scan = sub.add_parser(
        "scan",
        help="Run the full scan pipeline against a target",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    scan.add_argument("--scope-file", required=True, type=Path,
                      help="path to YAML scope file with attestation")
    scan.add_argument("--ip", required=True,
                      help="target IP address or CIDR range")
    scan.add_argument("--ports", default="1-1024",
                      help="ports to scan (e.g., '22,80,443' or '1-1024')")
    scan.add_argument("--timeout", type=float, default=0.5,
                      help="per-probe TCP SYN timeout in seconds")
    scan.add_argument("--workers", type=int, default=100,
                      help="concurrent port-scan workers")
    scan.add_argument("--skip-host-discovery", action="store_true",
                      help="skip ICMP sweep (useful for single localhost targets)")
    scan.add_argument("--report", type=Path,
                      help="write markdown report to this path "
                           "(default: stdout)")
    scan.add_argument("--no-triage", action="store_true",
                      help="skip the Claude triage step (offline mode)")

    demo = sub.add_parser(
        "demo",
        help="Run end-to-end demo against a local fake vulnerable service",
    )
    demo.add_argument("--port", type=int, default=18080,
                      help="port to host the fake vulnerable service on")
    demo.add_argument("--report", type=Path,
                      help="write demo report to this path (default: stdout)")

    return parser


def _configure_logging(verbose: int) -> None:
    level = logging.WARNING
    if verbose == 1:
        level = logging.INFO
    elif verbose >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )


def _cmd_scan(args: argparse.Namespace) -> int:
    settings = load_settings()
    try:
        scope = load_scope(args.scope_file)
    except (InvalidScopeFile, FileNotFoundError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

    if os.name == "posix" and os.geteuid() != 0:
        print(
            "warning: scapy SYN scans typically require root / CAP_NET_RAW. "
            "Continuing, but expect failures without privileges.",
            file=sys.stderr,
        )

    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"error: invalid --ports: {e}", file=sys.stderr)
        return 2

    store = Store(settings.db_path)
    audit = AuditLogger(settings.audit_log_path)
    context = AgentContext(
        scan_id=store.create_scan(args.ip),
        scope_target=args.ip,
    )

    try:
        recon = ReconAgent(
            scope=scope, store=store, ports=ports,
            timeout=args.timeout, workers=args.workers,
            skip_host_discovery=args.skip_host_discovery,
        )
        enrichment = EnrichmentAgent(store=store, api_key=settings.nvd_api_key)
        reporter = ReporterAgent(scope=scope)

        agents = [recon, enrichment]
        if not args.no_triage:
            if not settings.has_anthropic_key:
                print(
                    "error: --no-triage not set but ANTHROPIC_API_KEY is missing. "
                    "Set it in .env or pass --no-triage.",
                    file=sys.stderr,
                )
                return 2
            agents.append(
                TriageAgent(store=store, audit=audit, model=settings.triage_model)
            )
        agents.append(reporter)

        context = Orchestrator(agents).run(context)
    except ScopeViolation as e:
        print(f"scope violation: {e}", file=sys.stderr)
        return 3

    _emit_report(context.report_markdown or "", args.report)
    return 0


def _cmd_demo(args: argparse.Namespace) -> int:
    """Spin up the local fake target, scan it with skip-host-discovery, report."""
    settings = load_settings()
    fake_target_script = (
        Path(__file__).resolve().parent.parent.parent
        / "examples" / "demo_target" / "fake_service.py"
    )
    scope_file = (
        Path(__file__).resolve().parent.parent.parent
        / "examples" / "scope.example.yaml"
    )
    if not fake_target_script.exists() or not scope_file.exists():
        print(
            "error: demo assets missing. Expected "
            f"{fake_target_script} and {scope_file}.",
            file=sys.stderr,
        )
        return 2

    print(f"[demo] starting fake vulnerable service on 127.0.0.1:{args.port}")
    proc = subprocess.Popen(
        [sys.executable, str(fake_target_script), "--port", str(args.port)],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        time.sleep(0.8)  # let the socket bind
        print("[demo] running pipeline...")
        scan_args = argparse.Namespace(
            scope_file=scope_file,
            ip="127.0.0.1",
            ports=str(args.port),
            timeout=0.5,
            workers=10,
            skip_host_discovery=True,
            report=args.report,
            no_triage=not settings.has_anthropic_key,
        )
        if scan_args.no_triage:
            print(
                "[demo] ANTHROPIC_API_KEY not set — running WITHOUT triage. "
                "Set it in .env for the full agentic experience.",
                file=sys.stderr,
            )
        return _cmd_scan(scan_args)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            proc.kill()


def _emit_report(markdown: str, path: Path | None) -> None:
    if path is None:
        print(markdown)
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(markdown, encoding="utf-8")
        print(f"report written to {path}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
