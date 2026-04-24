"""Tests for the Triage Agent (Claude SDK mocked)."""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from vuln_platform.agents import TriageAgent
from vuln_platform.agents.base import AgentContext
from vuln_platform.agents.triage import _TriageOutput, _build_user_prompt
from vuln_platform.audit import AuditLogger
from vuln_platform.models import CVE, Host, Port, Service
from vuln_platform.storage import Store


def _fake_parse_response(output: _TriageOutput | None, usage_tokens: int = 123) -> MagicMock:
    """Shape a response that looks like anthropic.Anthropic.messages.parse(...)."""
    resp = MagicMock()
    resp.parsed_output = output
    resp.usage = SimpleNamespace(
        input_tokens=usage_tokens,
        output_tokens=50,
        cache_creation_input_tokens=0,
        cache_read_input_tokens=0,
    )
    return resp


def test_build_user_prompt_includes_key_context() -> None:
    host = Host(ip="10.0.0.5")  # type: ignore[arg-type]
    cve = CVE(cve_id="CVE-2021-41773", description="Path traversal",
              cvss_score=7.5, references=["https://example.com/a"])
    prompt = _build_user_prompt(host, 80, "apache", "2.4.49", cve)
    assert "10.0.0.5" in prompt
    assert "CVE-2021-41773" in prompt
    assert "7.5" in prompt
    assert "apache 2.4.49" in prompt


def test_triage_agent_happy_path(tmp_store: Store, tmp_audit: AuditLogger) -> None:
    fake_output = _TriageOutput(
        severity="high",
        exploit_likelihood="high",
        rationale="Publicly exploited in the wild.",
        recommended_action="Upgrade to Apache 2.4.51 or later.",
    )
    fake_client = MagicMock()
    fake_client.messages.parse.return_value = _fake_parse_response(fake_output)

    agent = TriageAgent(store=tmp_store, audit=tmp_audit,
                        anthropic_client=fake_client, model="claude-opus-4-7")

    host = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=80, service=Service(name="apache", version="2.4.49"))],
    )
    cve = CVE(cve_id="CVE-2021-41773", description="path traversal",
              cvss_score=7.5, cvss_severity="high")
    ctx = AgentContext(
        scan_id=tmp_store.create_scan("127.0.0.1"),
        scope_target="127.0.0.1",
        hosts=[host],
        cves_by_service={"apache 2.4.49": [cve]},
    )
    ctx = agent.run(ctx)

    assert len(ctx.findings) == 1
    f = ctx.findings[0]
    assert f.cve_id == "CVE-2021-41773"
    assert f.severity == "high"
    assert f.exploit_likelihood == "high"
    assert "Upgrade" in f.recommended_action

    # Verify the Claude call used adaptive thinking + cached system prompt.
    call_kwargs = fake_client.messages.parse.call_args.kwargs
    assert call_kwargs["model"] == "claude-opus-4-7"
    assert call_kwargs["thinking"] == {"type": "adaptive"}
    assert call_kwargs["output_config"] == {"effort": "high"}
    assert call_kwargs["system"][0]["cache_control"] == {"type": "ephemeral"}
    assert call_kwargs["output_format"] is _TriageOutput


def test_triage_agent_writes_audit_log(tmp_store: Store, tmp_audit: AuditLogger) -> None:
    fake_output = _TriageOutput(
        severity="medium", exploit_likelihood="low",
        rationale="r", recommended_action="a",
    )
    fake_client = MagicMock()
    fake_client.messages.parse.return_value = _fake_parse_response(fake_output)

    agent = TriageAgent(store=tmp_store, audit=tmp_audit, anthropic_client=fake_client)
    host = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=22, service=Service(name="openssh", version="7.4"))],
    )
    cve = CVE(cve_id="CVE-2018-15473", description="user enum", cvss_score=5.3)
    ctx = AgentContext(
        scan_id=tmp_store.create_scan("127.0.0.1"),
        scope_target="127.0.0.1",
        hosts=[host],
        cves_by_service={"openssh 7.4": [cve]},
    )
    agent.run(ctx)

    log_contents = tmp_audit.log_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(log_contents) == 1
    import json
    record = json.loads(log_contents[0])
    assert record["model"] == "claude-opus-4-7"
    assert record["usage"]["input_tokens"] == 123
    assert record["extra"]["cve_id"] == "CVE-2018-15473"


def test_triage_agent_skips_hosts_without_cves(tmp_store: Store, tmp_audit: AuditLogger) -> None:
    fake_client = MagicMock()
    agent = TriageAgent(store=tmp_store, audit=tmp_audit, anthropic_client=fake_client)
    host = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=80, service=Service(name="http", version="1.0"))],
    )
    ctx = AgentContext(
        scan_id=tmp_store.create_scan("127.0.0.1"),
        scope_target="127.0.0.1",
        hosts=[host],
        cves_by_service={},  # no CVEs matched
    )
    ctx = agent.run(ctx)
    assert ctx.findings == []
    fake_client.messages.parse.assert_not_called()


def test_triage_agent_falls_back_on_no_parsed_output(
    tmp_store: Store, tmp_audit: AuditLogger,
) -> None:
    fake_client = MagicMock()
    fake_client.messages.parse.return_value = _fake_parse_response(None)

    agent = TriageAgent(store=tmp_store, audit=tmp_audit, anthropic_client=fake_client)
    host = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=80, service=Service(name="apache", version="2.4.49"))],
    )
    cve = CVE(cve_id="CVE-2021-41773", description="d",
              cvss_score=7.5, cvss_severity="high")
    ctx = AgentContext(
        scan_id=tmp_store.create_scan("127.0.0.1"),
        scope_target="127.0.0.1",
        hosts=[host],
        cves_by_service={"apache 2.4.49": [cve]},
    )
    ctx = agent.run(ctx)
    assert len(ctx.findings) == 1
    # Fallback keeps the CVSS severity and marks likelihood unknown.
    assert ctx.findings[0].severity == "high"
    assert ctx.findings[0].exploit_likelihood == "unknown"
