"""Enrichment Agent: NVD / CVE lookup for detected services.

For each unique service+version combination, query the NIST NVD API v2.0
by keyword match. Cache results locally in SQLite so repeat scans of the
same targets don't re-hit the NVD rate limit.

When NVD is unreachable (rate-limited, no internet, air-gapped lab) the
agent falls back to a local seed file mapping normalized
'service version' keywords to pre-fetched CVE records. This keeps demos
and offline runs deterministic.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any

import httpx

from ..models import CVE
from ..storage import Store
from .base import AgentContext, BaseAgent

if TYPE_CHECKING:
    from ..events import EventBus


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
        seed_path: Path | None = None,
        event_bus: "EventBus | None" = None,
    ) -> None:
        self.store = store
        self.api_key = api_key
        self.http_client = http_client or httpx.Client(timeout=10.0)
        self.results_per_query = results_per_query
        self.seed: dict[str, list[CVE]] = (
            _load_seed(seed_path) if seed_path else {}
        )
        self.event_bus = event_bus

    def run(self, context: AgentContext) -> AgentContext:
        self.emit("enrichment.started",
                  service_count=sum(len(h.open_ports) for h in context.hosts))
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
                seeded = self.seed.get(key)
                if seeded:
                    logger.info(
                        "enrichment: using %d seeded CVE(s) for %r",
                        len(seeded), keyword,
                    )
                    cves = seeded
                    self.emit("enrichment.using_seed",
                              keyword=keyword, count=len(seeded))
                else:
                    logger.info("enrichment: NVD lookup %r", keyword)
                    self.emit("enrichment.querying_nvd", keyword=keyword)
                    cves = self._fetch_cves(keyword)
                    if not cves and key in self.seed:
                        cves = self.seed[key]
                        self.emit("enrichment.using_seed_fallback",
                                  keyword=keyword, count=len(self.seed[key]))

                self.emit(
                    "enrichment.cves_resolved",
                    keyword=keyword,
                    count=len(cves),
                    cve_ids=[c.cve_id for c in cves],
                )
                context.cves_by_service[key] = cves
                for cve in cves:
                    self.store.upsert_cve(cve)
        self.emit(
            "enrichment.done",
            total_cves=sum(len(v) for v in context.cves_by_service.values()),
        )
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
        # NVD references carry tags ("Exploit", "Patch", "Vendor Advisory",
        # etc.). Keep the full list, plus extract two tagged subsets the
        # UI can promote to badges and direct links.
        all_refs: list[str] = []
        exploit_refs: list[str] = []
        patch_refs: list[str] = []
        for r in cve_obj.get("references", []):
            url = r.get("url")
            if not url:
                continue
            if len(all_refs) < 10:
                all_refs.append(url)
            tags = r.get("tags") or []
            if "Exploit" in tags:
                exploit_refs.append(url)
            if "Patch" in tags:
                patch_refs.append(url)
        results.append(
            CVE(
                cve_id=cve_id,
                description=description,
                cvss_score=score,
                cvss_severity=severity,
                published=published,
                references=all_refs,
                exploit_references=exploit_refs[:5],
                patch_references=patch_refs[:5],
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


def _load_seed(path: Path) -> dict[str, list[CVE]]:
    """Load a CVE seed file: {keyword: [cve_dict, ...]} -> dict of CVE objects."""
    try:
        raw = json.loads(Path(path).read_text())
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("enrichment: could not load seed %s: %s", path, e)
        return {}
    seed: dict[str, list[CVE]] = {}
    for keyword, entries in raw.items():
        if keyword.startswith("_") or not isinstance(entries, list):
            continue
        cves: list[CVE] = []
        for entry in entries:
            try:
                cves.append(CVE(
                    cve_id=entry["cve_id"],
                    description=entry.get("description", ""),
                    cvss_score=entry.get("cvss_score"),
                    cvss_severity=entry.get("cvss_severity"),
                    published=_parse_date(entry.get("published")),
                    references=list(entry.get("references", []))[:10],
                    exploit_references=list(entry.get("exploit_references", []))[:5],
                    patch_references=list(entry.get("patch_references", []))[:5],
                ))
            except (KeyError, TypeError) as e:
                logger.warning(
                    "enrichment: skipping malformed seed entry: %s", e
                )
        seed[keyword.lower().strip()] = cves
    return seed
