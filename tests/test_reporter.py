"""Tests for report rendering."""
from __future__ import annotations

from vuln_platform.agents.reporter import ReporterAgent, render_report
from vuln_platform.agents.base import AgentContext
from vuln_platform.ethics import Scope
from vuln_platform.models import Finding


def _f(sev: str, cve: str = "CVE-2024-0001") -> Finding:
    return Finding(
        host_ip="127.0.0.1", port=80, service_name="apache",
        service_version="2.4.49",
        cve_id=cve, cve_description="demo",
        cvss_score=7.5,
        severity=sev,  # type: ignore[arg-type]
        exploit_likelihood="medium",
        rationale="because", recommended_action="patch",
    )


def test_report_has_all_required_sections(lab_scope: Scope) -> None:
    md = render_report(
        scope=lab_scope, scope_target="127.0.0.0/24",
        findings=[_f("critical"), _f("low", "CVE-2024-0002")],
    )
    assert "# Vulnerability Assessment Report" in md
    assert "## Executive Summary" in md
    assert "## Methodology" in md
    assert "## Scope & Authorization" in md
    assert "## Findings Summary" in md
    assert "## Detailed Findings" in md


def test_report_attestation_rendered(lab_scope: Scope) -> None:
    md = render_report(scope=lab_scope, scope_target="127.0.0.1", findings=[])
    assert lab_scope.attestation.statement in md
    assert lab_scope.attestation.authorized_by in md


def test_report_handles_empty_findings(lab_scope: Scope) -> None:
    md = render_report(scope=lab_scope, scope_target="127.0.0.1", findings=[])
    assert "*No findings.*" in md


def test_report_groups_by_severity(lab_scope: Scope) -> None:
    md = render_report(
        scope=lab_scope, scope_target="127.0.0.1",
        findings=[
            _f("low", "CVE-A"), _f("critical", "CVE-B"),
            _f("medium", "CVE-C"), _f("high", "CVE-D"),
        ],
    )
    # Critical section should appear before low section in the detail output.
    assert md.index("Severity: CRITICAL") < md.index("Severity: LOW")


def test_reporter_agent_writes_to_context(lab_scope: Scope) -> None:
    ctx = AgentContext(scan_id=1, scope_target="127.0.0.1", findings=[_f("high")])
    ctx = ReporterAgent(scope=lab_scope).run(ctx)
    assert ctx.report_markdown is not None
    assert "CVE-2024-0001" in ctx.report_markdown
