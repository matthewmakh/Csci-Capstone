"""Smoke tests for the FastAPI web dashboard.

Exercises route wiring, template rendering, and the audit-log loader.
The /demo POST is not invoked — it would spawn a subprocess and call
the network. Demo execution is covered by the CLI demo flow.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from vuln_platform.config import Settings
from vuln_platform.models import Finding, Host, Port, Service
from vuln_platform.storage import Store
from vuln_platform.web import create_app


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    return Settings(
        anthropic_api_key=None,
        nvd_api_key=None,
        db_path=tmp_path / "findings.db",
        audit_log_path=tmp_path / "audit.jsonl",
        triage_model="claude-opus-4-7",
    )


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings))


def test_index_empty(client: TestClient) -> None:
    resp = client.get("/")
    assert resp.status_code == 200
    assert "Scan history" in resp.text
    assert "No scans yet" in resp.text


def test_index_lists_scans(client: TestClient, settings: Settings) -> None:
    store = Store(settings.db_path)
    scan_id = store.create_scan("127.0.0.1")
    store.save_host(scan_id, Host(
        ip="127.0.0.1",
        open_ports=[Port(number=18080, service=Service(name="apache", version="2.4.49"))],
    ))
    store.save_finding(scan_id, _make_finding("127.0.0.1", 18080, "critical"))

    resp = client.get("/")
    assert resp.status_code == 200
    assert f"#{scan_id}" in resp.text
    assert "127.0.0.1" in resp.text
    # Critical badge rendered
    assert "bg-red-100" in resp.text


def test_scan_detail_renders_report(client: TestClient, settings: Settings) -> None:
    store = Store(settings.db_path)
    scan_id = store.create_scan("127.0.0.1")
    store.save_host(scan_id, Host(
        ip="127.0.0.1",
        open_ports=[Port(number=18080, service=Service(name="apache", version="2.4.49"))],
    ))
    finding = _make_finding("127.0.0.1", 18080, "critical")
    store.save_finding(scan_id, finding)

    resp = client.get(f"/scans/{scan_id}")
    assert resp.status_code == 200
    assert finding.cve_id in resp.text
    assert "Vulnerability Assessment Report" in resp.text  # markdown rendered
    assert "Discovered Services" in resp.text


def test_scan_detail_404(client: TestClient) -> None:
    assert client.get("/scans/9999").status_code == 404


def test_audit_log_empty(client: TestClient) -> None:
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "No audit entries yet" in resp.text


def test_audit_log_renders_entries(
    client: TestClient, settings: Settings
) -> None:
    settings.audit_log_path.write_text(
        json.dumps({
            "timestamp": "2026-04-24T22:00:00+00:00",
            "model": "claude-opus-4-7",
            "system_prompt_sha256": "a" * 64,
            "user_prompt_sha256": "b" * 64,
            "response_text": "triage rationale here",
            "usage": {"input_tokens": 1500, "output_tokens": 240},
        }) + "\n"
    )
    resp = client.get("/audit")
    assert resp.status_code == 200
    assert "claude-opus-4-7" in resp.text
    assert "triage rationale here" in resp.text
    assert "1500" in resp.text


def test_demo_status_initially_idle(client: TestClient) -> None:
    resp = client.get("/demo/status")
    assert resp.status_code == 200
    body = resp.json()
    assert body["running"] is False
    assert body["last_scan_id"] is None


def _make_finding(host: str, port: int, severity: str) -> Finding:
    return Finding(
        host_ip=host, port=port,
        service_name="apache", service_version="2.4.49",
        cve_id="CVE-2021-41773",
        cve_description="Path traversal in Apache 2.4.49",
        cvss_score=7.5,
        severity=severity,
        exploit_likelihood="high",
        rationale="Public PoCs available; unauthenticated.",
        recommended_action="Upgrade to 2.4.51 or later.",
    )
