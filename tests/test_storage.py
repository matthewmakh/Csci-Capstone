"""Tests for SQLite DAO."""
from __future__ import annotations

from vuln_platform.models import CVE, Finding, Host, Port, Service
from vuln_platform.storage import Store


def test_create_scan_and_save_host(tmp_store: Store) -> None:
    scan_id = tmp_store.create_scan("127.0.0.1")
    assert isinstance(scan_id, int) and scan_id > 0

    host = Host(
        ip="127.0.0.1",  # type: ignore[arg-type]
        open_ports=[Port(number=22, service=Service(name="ssh", version="9.6"))],
    )
    tmp_store.save_host(scan_id, host)  # doesn't raise


def test_upsert_and_get_cve(tmp_store: Store) -> None:
    cve = CVE(
        cve_id="CVE-2024-1234",
        description="Test CVE",
        cvss_score=7.5,
        cvss_severity="high",
        references=["https://example.com/advisory"],
    )
    tmp_store.upsert_cve(cve)
    fetched = tmp_store.get_cve("CVE-2024-1234")
    assert fetched is not None
    assert fetched.cve_id == "CVE-2024-1234"
    assert fetched.cvss_score == 7.5
    assert fetched.cvss_severity == "high"
    assert fetched.references == ["https://example.com/advisory"]


def test_get_missing_cve_returns_none(tmp_store: Store) -> None:
    assert tmp_store.get_cve("CVE-9999-9999") is None


def test_list_findings_sorted_by_severity(tmp_store: Store) -> None:
    scan_id = tmp_store.create_scan("127.0.0.1")
    for sev in ("low", "critical", "medium", "high"):
        tmp_store.save_finding(
            scan_id,
            Finding(
                host_ip="127.0.0.1", port=80, service_name="http",
                cve_id=f"CVE-2024-{sev}", cve_description="d",
                severity=sev,  # type: ignore[arg-type]
                exploit_likelihood="low",
                rationale="r", recommended_action="a",
            ),
        )
    findings = tmp_store.list_findings(scan_id)
    assert [f.severity for f in findings] == ["critical", "high", "medium", "low"]
