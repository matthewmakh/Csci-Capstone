"""SQLite persistence layer.

A thin DAO so the rest of the code doesn't touch SQL directly. The
abstraction keeps the door open to swap to MySQL later (Unit 3
infrastructure work) without rewiring the agents.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import CVE, Finding, Host


SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY,
    started_at TEXT NOT NULL DEFAULT (datetime('now')),
    scope_target TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS hosts (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    ip TEXT NOT NULL,
    hostname TEXT,
    open_ports_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS cves (
    cve_id TEXT PRIMARY KEY,
    description TEXT NOT NULL,
    cvss_score REAL,
    cvss_severity TEXT,
    published TEXT,
    references_json TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    scan_id INTEGER NOT NULL REFERENCES scans(id),
    host_ip TEXT NOT NULL,
    port INTEGER NOT NULL,
    service_name TEXT NOT NULL,
    service_version TEXT,
    cve_id TEXT NOT NULL,
    cve_description TEXT NOT NULL,
    cvss_score REAL,
    severity TEXT NOT NULL,
    exploit_likelihood TEXT NOT NULL,
    rationale TEXT NOT NULL,
    recommended_action TEXT NOT NULL
);
"""


class Store:
    """SQLite-backed persistence for scans, hosts, CVEs, and findings."""

    def __init__(self, db_path: Path | str) -> None:
        self.db_path = Path(db_path)
        self._init_schema()

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._conn() as conn:
            conn.executescript(SCHEMA)

    def create_scan(self, scope_target: str) -> int:
        with self._conn() as conn:
            cur = conn.execute(
                "INSERT INTO scans (scope_target) VALUES (?)", (scope_target,)
            )
            assert cur.lastrowid is not None
            return cur.lastrowid

    def save_host(self, scan_id: int, host: Host) -> None:
        open_ports_json = json.dumps([p.model_dump() for p in host.open_ports])
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO hosts (scan_id, ip, hostname, open_ports_json) "
                "VALUES (?, ?, ?, ?)",
                (scan_id, str(host.ip), host.hostname, open_ports_json),
            )

    def upsert_cve(self, cve: CVE) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO cves "
                "(cve_id, description, cvss_score, cvss_severity, published, references_json) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    cve.cve_id,
                    cve.description,
                    cve.cvss_score,
                    cve.cvss_severity,
                    cve.published.isoformat() if cve.published else None,
                    json.dumps(cve.references),
                ),
            )

    def get_cve(self, cve_id: str) -> CVE | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT * FROM cves WHERE cve_id = ?", (cve_id,)
            ).fetchone()
        if row is None:
            return None
        return CVE(
            cve_id=row["cve_id"],
            description=row["description"],
            cvss_score=row["cvss_score"],
            cvss_severity=row["cvss_severity"],
            published=row["published"],
            references=json.loads(row["references_json"]),
        )

    def save_finding(self, scan_id: int, finding: Finding) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO findings "
                "(scan_id, host_ip, port, service_name, service_version, "
                " cve_id, cve_description, cvss_score, severity, "
                " exploit_likelihood, rationale, recommended_action) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    finding.host_ip,
                    finding.port,
                    finding.service_name,
                    finding.service_version,
                    finding.cve_id,
                    finding.cve_description,
                    finding.cvss_score,
                    finding.severity,
                    finding.exploit_likelihood,
                    finding.rationale,
                    finding.recommended_action,
                ),
            )

    def list_scans(self, limit: int = 100) -> list[dict]:
        """Return scan rows ordered newest-first, with summary counts."""
        with self._conn() as conn:
            rows = conn.execute(
                """
                SELECT
                    s.id, s.started_at, s.scope_target,
                    (SELECT COUNT(*) FROM hosts h WHERE h.scan_id = s.id)
                        AS host_count,
                    (SELECT COUNT(*) FROM findings f WHERE f.scan_id = s.id)
                        AS finding_count,
                    (SELECT COUNT(*) FROM findings f
                     WHERE f.scan_id = s.id AND f.severity = 'critical')
                        AS critical_count
                FROM scans s
                ORDER BY s.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id: int) -> dict | None:
        with self._conn() as conn:
            row = conn.execute(
                "SELECT id, started_at, scope_target FROM scans WHERE id = ?",
                (scan_id,),
            ).fetchone()
        return dict(row) if row else None

    def list_hosts(self, scan_id: int) -> list[Host]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT ip, hostname, open_ports_json FROM hosts "
                "WHERE scan_id = ? ORDER BY id",
                (scan_id,),
            ).fetchall()
        hosts: list[Host] = []
        for r in rows:
            ports = json.loads(r["open_ports_json"])
            hosts.append(Host(
                ip=r["ip"], hostname=r["hostname"], open_ports=ports
            ))
        return hosts

    def list_findings(self, scan_id: int) -> list[Finding]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE scan_id = ? "
                "ORDER BY CASE severity "
                "  WHEN 'critical' THEN 0 WHEN 'high' THEN 1 "
                "  WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END, "
                "host_ip, port",
                (scan_id,),
            ).fetchall()
        return [
            Finding(
                host_ip=r["host_ip"],
                port=r["port"],
                service_name=r["service_name"],
                service_version=r["service_version"],
                cve_id=r["cve_id"],
                cve_description=r["cve_description"],
                cvss_score=r["cvss_score"],
                severity=r["severity"],
                exploit_likelihood=r["exploit_likelihood"],
                rationale=r["rationale"],
                recommended_action=r["recommended_action"],
            )
            for r in rows
        ]
