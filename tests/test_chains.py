"""Tests for Chain Analysis agent + AttackChain storage."""
from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from vuln_platform.agents.base import AgentContext
from vuln_platform.agents.chains import (
    ChainAnalysisAgent,
    _ChainAnalysisOutput,
    _ChainSchema,
    _HopSchema,
    _to_attack_chain,
)
from vuln_platform.audit import AuditLogger
from vuln_platform.models import AttackChain, ChainHop, Finding
from vuln_platform.storage import Store


def _finding(cve_id: str, host: str = "127.0.0.1", port: int = 80) -> Finding:
    return Finding(
        host_ip=host, port=port,
        service_name="x", service_version="1.0",
        cve_id=cve_id,
        cve_description="dummy",
        cvss_score=7.5,
        severity="high",
        exploit_likelihood="medium",
        rationale="dummy",
        recommended_action="patch",
    )


def test_to_attack_chain_drops_chains_with_unknown_cves() -> None:
    raw = _ChainSchema(
        title="bogus",
        severity="critical",
        confidence="medium",
        rationale="x",
        prerequisites="x",
        impact="x",
        hops=[
            _HopSchema(cve_id="CVE-REAL", host_ip="1.1.1.1", port=80,
                       action="a", capability_gained="b"),
            _HopSchema(cve_id="CVE-INVENTED", host_ip="1.1.1.1", port=80,
                       action="a", capability_gained="b"),
        ],
    )
    assert _to_attack_chain(raw, valid_cves={"CVE-REAL"}) is None


def test_to_attack_chain_drops_single_hop_chains() -> None:
    raw = _ChainSchema(
        title="too short",
        severity="high",
        confidence="high",
        rationale="x", prerequisites="x", impact="x",
        hops=[_HopSchema(cve_id="CVE-A", host_ip="1.1.1.1", port=80,
                         action="a", capability_gained="b")],
    )
    assert _to_attack_chain(raw, valid_cves={"CVE-A"}) is None


def test_to_attack_chain_accepts_valid_chain() -> None:
    raw = _ChainSchema(
        title="real chain",
        severity="critical",
        confidence="high",
        rationale="r", prerequisites="p", impact="i",
        hops=[
            _HopSchema(cve_id="CVE-A", host_ip="1.1.1.1", port=21,
                       action="exploit FTP backdoor",
                       capability_gained="root shell"),
            _HopSchema(cve_id="CVE-B", host_ip="1.1.1.1", port=6379,
                       action="connect to local Redis",
                       capability_gained="data exfil"),
        ],
    )
    chain = _to_attack_chain(raw, valid_cves={"CVE-A", "CVE-B"})
    assert chain is not None
    assert chain.title == "real chain"
    assert len(chain.hops) == 2
    assert chain.severity == "critical"


def test_chain_storage_roundtrip(tmp_path: Path) -> None:
    store = Store(tmp_path / "f.db")
    scan_id = store.create_scan("127.0.0.1")
    chain = AttackChain(
        title="t", severity="high", confidence="medium",
        rationale="r", prerequisites="p", impact="i",
        hops=[
            ChainHop(cve_id="CVE-A", host_ip="1.1.1.1", port=21,
                     action="a", capability_gained="b"),
            ChainHop(cve_id="CVE-B", host_ip="1.1.1.1", port=80,
                     action="c", capability_gained="d"),
        ],
    )
    store.save_chain(scan_id, chain)
    loaded = store.list_chains(scan_id)
    assert len(loaded) == 1
    assert loaded[0].title == "t"
    assert len(loaded[0].hops) == 2
    assert loaded[0].hops[1].cve_id == "CVE-B"


def test_chain_agent_skips_with_too_few_findings(tmp_path: Path) -> None:
    """One finding can't form a chain; agent should emit a skip event."""
    store = Store(tmp_path / "f.db")
    audit = AuditLogger(tmp_path / "a.jsonl")
    scan_id = store.create_scan("127.0.0.1")
    context = AgentContext(scan_id=scan_id, scope_target="127.0.0.1")
    context.findings.append(_finding("CVE-1"))

    fake_client = MagicMock()
    agent = ChainAnalysisAgent(
        store=store, audit=audit, anthropic_client=fake_client,
    )
    agent.run(context)
    fake_client.messages.parse.assert_not_called()
    assert context.chains == []


def test_chain_agent_persists_returned_chains(tmp_path: Path) -> None:
    store = Store(tmp_path / "f.db")
    audit = AuditLogger(tmp_path / "a.jsonl")
    scan_id = store.create_scan("127.0.0.1")
    context = AgentContext(scan_id=scan_id, scope_target="127.0.0.1")
    context.findings.append(_finding("CVE-A", port=21))
    context.findings.append(_finding("CVE-B", port=6379))

    fake_response = MagicMock()
    fake_response.parsed_output = _ChainAnalysisOutput(chains=[
        _ChainSchema(
            title="ftp -> redis",
            severity="critical", confidence="high",
            rationale="x", prerequisites="x", impact="x",
            hops=[
                _HopSchema(cve_id="CVE-A", host_ip="127.0.0.1", port=21,
                           action="ftp backdoor",
                           capability_gained="shell"),
                _HopSchema(cve_id="CVE-B", host_ip="127.0.0.1", port=6379,
                           action="redis pivot",
                           capability_gained="data"),
            ],
        ),
    ])
    fake_response.usage = type("U", (), {"input_tokens": 1, "output_tokens": 1})()
    fake_client = MagicMock()
    fake_client.messages.parse.return_value = fake_response

    agent = ChainAnalysisAgent(
        store=store, audit=audit, anthropic_client=fake_client,
    )
    agent.run(context)
    assert len(context.chains) == 1
    assert context.chains[0].title == "ftp -> redis"
    persisted = store.list_chains(scan_id)
    assert len(persisted) == 1
    assert persisted[0].hops[0].cve_id == "CVE-A"
