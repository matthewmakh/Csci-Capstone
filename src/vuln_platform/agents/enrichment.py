"""Enrichment Agent: NVD / CVE lookup for detected services.

For each unique service+version combination, query the NIST NVD API v2.0
by keyword match. Cache results locally in SQLite so repeat scans of the
same targets don't re-hit the NVD rate limit.
"""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

import httpx

from ..models import CVE
from ..storage import Store
from .base import AgentContext, BaseAgent


logger = logging.getLogger(__name__)

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
# Per-service result cap keeps demos and tests from exploding.
DEFAULT_RESULTS_PER_QUERY = 5


class EnrichmentAgent(BaseAgent):
    name = "enrichment"

    def __init__(
        self,
        *,
        store: Store,
        api_key: str | None = None,
        http_client: httpx.Client | None = None,
        results_per_query: int = DEFAULT_RESULTS_PER_QUERY,
    ) -> None:
        self.store = store
        self.api_key = api_key
        self.http_client = http_client or httpx.Client(timeout=10.0)
        self.results_per_query = results_per_query

    def run(self, context: AgentContext) -> AgentContext:
        queried: set[str] = set()
        for host in context.hosts:
            for port in host.open_ports:
                if port.service is None:
                    continue
                key = _service_key(port.service.name, port.service.version)
                if key in queried:
                    continue
                queried.add(key)

                keyword = _build_keyword(port.service.name, port.service.version)
                logger.info("enrichment: NVD lookup %r", keyword)
                cves = self._fetch_cves(keyword)
                context.cves_by_service[key] = cves
                for cve in cves:
                    self.store.upsert_cve(cve)
        return context

    def _fetch_cves(self, keyword: str) -> list[CVE]:
        params: dict[str, Any] = {
            "keywordSearch": keyword,
            "resultsPerPage": self.results_per_query,
        }
        headers: dict[str, str] = {}
        if self.api_key:
            headers["apiKey"] = self.api_key
        try:
            resp = self.http_client.get(NVD_API_URL, params=params, headers=headers)
            resp.raise_for_status()
        except httpx.HTTPError as e:
            logger.warning("enrichment: NVD request failed (%s); continuing", e)
            return []
        return _parse_nvd_response(resp.json())


def _service_key(name: str, version: str | None) -> str:
    return f"{name.lower()} {version or ''}".strip()


def _build_keyword(name: str, version: str | None) -> str:
    return f"{name} {version}".strip() if version else name


def _parse_nvd_response(payload: dict[str, Any]) -> list[CVE]:
    """Extract CVE objects from the NVD v2.0 JSON shape.

    The API wraps each CVE in {"cve": {...}} inside a "vulnerabilities"
    array. We pull CVSS v3 score if present, falling back to v2, and
    tolerate missing fields silently because the NVD data quality
    varies.
    """
    results: list[CVE] = []
    for item in payload.get("vulnerabilities", []):
        cve_obj = item.get("cve", {})
        cve_id = cve_obj.get("id")
        if not cve_id:
            continue
        descriptions = cve_obj.get("descriptions", [])
        description = next(
            (d.get("value", "") for d in descriptions if d.get("lang") == "en"),
            "",
        )
        score, severity = _extract_cvss(cve_obj.get("metrics", {}))
        published_raw = cve_obj.get("published")
        published = _parse_date(published_raw)
        references = [
            r.get("url", "")
            for r in cve_obj.get("references", [])
            if r.get("url")
        ][:10]
        results.append(
            CVE(
                cve_id=cve_id,
                description=description,
                cvss_score=score,
                cvss_severity=severity,
                published=published,
                references=references,
            )
        )
    return results


def _extract_cvss(metrics: dict[str, Any]) -> tuple[float | None, str | None]:
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key, [])
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity_raw = (
                data.get("baseSeverity")
                or entries[0].get("baseSeverity")
                or ""
            ).lower() or None
            # NVD uses 'none', 'low', 'medium', 'high', 'critical' — the
            # first isn't in our Severity literal, so map it to 'info'.
            if severity_raw == "none":
                severity_raw = "info"
            if severity_raw not in ("critical", "high", "medium", "low", "info"):
                severity_raw = None
            return score, severity_raw  # type: ignore[return-value]
    return None, None


def _parse_date(s: str | None) -> datetime | None:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return None
