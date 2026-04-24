"""Tests for pydantic model validation."""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from vuln_platform.models import CVE, Finding, Host, Port, Service


def test_port_bounds() -> None:
    Port(number=1)
    Port(number=65535)
    with pytest.raises(ValidationError):
        Port(number=0)
    with pytest.raises(ValidationError):
        Port(number=65536)


def test_host_accepts_ipv4() -> None:
    host = Host(ip="192.168.1.1")  # type: ignore[arg-type]
    assert str(host.ip) == "192.168.1.1"


def test_host_rejects_garbage_ip() -> None:
    with pytest.raises(ValidationError):
        Host(ip="not-an-ip")  # type: ignore[arg-type]


def test_service_optional_version() -> None:
    s = Service(name="ssh")
    assert s.version is None
    assert s.banner is None


def test_finding_severity_literal() -> None:
    f = Finding(
        host_ip="127.0.0.1", port=80, service_name="http",
        cve_id="CVE-2024-1234", cve_description="desc",
        severity="high", exploit_likelihood="medium",
        rationale="r", recommended_action="a",
    )
    assert f.severity == "high"
    with pytest.raises(ValidationError):
        Finding(
            host_ip="127.0.0.1", port=80, service_name="http",
            cve_id="CVE-2024-1234", cve_description="desc",
            severity="extreme",  # type: ignore[arg-type]
            exploit_likelihood="medium",
            rationale="r", recommended_action="a",
        )


def test_cve_cvss_optional() -> None:
    c = CVE(cve_id="CVE-2024-0001", description="example")
    assert c.cvss_score is None
    assert c.references == []
