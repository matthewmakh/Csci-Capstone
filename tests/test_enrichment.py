"""Tests for the Enrichment Agent (NVD API integration, with mocked HTTP)."""
from __future__ import annotations

from typing import Any

import httpx
import pytest

from vuln_platform.agents import EnrichmentAgent
from vuln_platform.agents.base import AgentContext
from vuln_platform.agents.enrichment import _parse_nvd_response
from vuln_platform.models import Host, Port, Service
from vuln_platform.storage import Store


SAMPLE_NVD_RESPONSE: dict[str, Any] = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-41773",
                "descriptions": [
                    {"lang": "en", "value": "Path traversal in Apache httpd 2.4.49..."}
                ],
                "metrics": {
                    "cvssMetricV31": [{
                        "cvssData": {"baseScore": 7.5, "baseSeverity": "HIGH"}
                    }]
                },
                "published": "2021-10-05T19:15:07.000",
                "references": [{"url": "https://httpd.apache.org/security/vulnerabilities_24.html"}],
            }
        }
    ]
}


def test_parse_nvd_response_happy_path() -> None:
    cves = _parse_nvd_response(SAMPLE_NVD_RESPONSE)
    assert len(cves) == 1
    cve = cves[0]
    assert cve.cve_id == "CVE-2021-41773"
    assert cve.cvss_score == 7.5
    assert cve.cvss_severity == "high"
    assert cve.description.startswith("Path traversal")
    assert cve.references == ["https://httpd.apache.org/security/vulnerabilities_24.html"]


def test_parse_nvd_response_empty_vulnerabilities() -> None:
    assert _parse_nvd_response({"vulnerabilities": []}) == []
    assert _parse_nvd_response({}) == []


def test_parse_nvd_response_no_cvss() -> None:
    payload = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-2024-0001", "descriptions": [{"lang": "en", "value": "d"}]}}
        ]
    }
    cves = _parse_nvd_response(payload)
    assert cves[0].cvss_score is None
    assert cves[0].cvss_severity is None


def test_parse_nvd_response_maps_none_severity_to_info() -> None:
    payload = {
        "vulnerabilities": [{
            "cve": {
                "id": "CVE-2024-0002",
                "descriptions": [{"lang": "en", "value": "d"}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 0.0, "baseSeverity": "NONE"}}]},
            }
        }]
    }
    cves = _parse_nvd_response(payload)
    assert cves[0].cvss_severity == "info"


def test_parse_nvd_response_skips_entries_without_id() -> None:
    payload = {"vulnerabilities": [{"cve": {"descriptions": []}}]}
    assert _parse_nvd_response(payload) == []


def test_enrichment_agent_uses_service_key(tmp_store: Store) -> None:
    """Agent should deduplicate queries by service+version, not by host."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=SAMPLE_NVD_RESPONSE)

    client = httpx.Client(transport=httpx.MockTransport(handler))
    agent = EnrichmentAgent(store=tmp_store, http_client=client)

    host1 = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=80, service=Service(name="apache", version="2.4.49"))],
    )
    host2 = Host(
        ip="127.0.0.2",  # type: ignore[arg-type]
        open_ports=[Port(number=80, service=Service(name="apache", version="2.4.49"))],
    )
    ctx = AgentContext(scan_id=1, scope_target="127.0.0.0/24",
                       hosts=[host1, host2])
    agent.run(ctx)

    # Only one NVD call despite two hosts with the same service.
    assert len(calls) == 1
    assert "apache" in calls[0].lower()
    assert "apache 2.4.49" in ctx.cves_by_service


def test_enrichment_agent_handles_http_error(tmp_store: Store) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="server error")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    agent = EnrichmentAgent(store=tmp_store, http_client=client)
    host = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=22, service=Service(name="openssh", version="9.6"))],
    )
    ctx = AgentContext(scan_id=1, scope_target="127.0.0.1", hosts=[host])
    ctx = agent.run(ctx)
    # Must not crash; just records an empty list for the service.
    assert ctx.cves_by_service.get("openssh 9.6") == []
