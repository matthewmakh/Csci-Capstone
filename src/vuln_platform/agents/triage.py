"""Triage Agent: LLM-driven severity ranking.

For each (host, port, service, CVE) tuple, ask Claude to produce a
structured Finding: severity, exploit likelihood, rationale, recommended
action. Uses:
- `claude-opus-4-7` with adaptive thinking for nuanced severity judgment
- `messages.parse()` with a pydantic schema for structured output
- Prompt caching on the system prompt (frozen rubric)
- Audit log of every call for the ethics/auditability rubric
- Retry with exponential backoff on 429/529 (rate-limit / overloaded);
  if the API stays unavailable, fall back to a CVSS-anchored finding
  rather than crashing the whole pipeline.

Reference: shared/prompt-caching.md and python/claude-api/README.md in
the claude-api skill.
"""
from __future__ import annotations

import logging
import time
from typing import TYPE_CHECKING, Literal

import anthropic
from pydantic import BaseModel

from ..audit import AuditLogger
from ..models import CVE, Finding, Host
from ..storage import Store
from .base import AgentContext, BaseAgent

if TYPE_CHECKING:
    from ..events import EventBus


logger = logging.getLogger(__name__)


TRIAGE_SYSTEM_PROMPT = """\
You are a senior penetration tester performing triage on raw scan + \
CVE-match output. For each finding given to you, produce a structured \
assessment:

- severity: one of critical | high | medium | low | info
- exploit_likelihood: one of high | medium | low | unknown
- rationale: 1-3 sentences explaining your severity call, referencing \
the CVSS score, the service context, and any realistic mitigations \
likely in place
- recommended_action: a concrete next step (patch to version X, disable \
the service, restrict via firewall, etc.)

Grounding rules:
1. Anchor severity to the CVSS base score when available (>=9.0 \
critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low). You may adjust \
one level up or down if the service context strongly warrants it; state \
the adjustment in rationale.
2. Exploit likelihood weighs public exploit availability (reflected in \
CVE description / references), authentication requirements, and network \
reachability.
3. Be honest about uncertainty. If you lack information to judge \
exploit_likelihood, say "unknown" rather than guessing.
4. Do not fabricate CVE IDs, versions, or references. Use only what is \
in the input.
"""


class _TriageOutput(BaseModel):
    """Pydantic schema Claude's `messages.parse()` return conforms to."""

    severity: Literal["critical", "high", "medium", "low", "info"]
    exploit_likelihood: Literal["high", "medium", "low", "unknown"]
    rationale: str
    recommended_action: str


class TriageAgent(BaseAgent):
    name = "triage"

    def __init__(
        self,
        *,
        store: Store,
        audit: AuditLogger,
        anthropic_client: anthropic.Anthropic | None = None,
        model: str = "claude-opus-4-7",
        event_bus: "EventBus | None" = None,
    ) -> None:
        self.store = store
        self.audit = audit
        self.client = anthropic_client or anthropic.Anthropic()
        self.model = model
        self.event_bus = event_bus

    def run(self, context: AgentContext) -> AgentContext:
        total_cves = sum(len(v) for v in context.cves_by_service.values())
        self.emit("triage.started", total=total_cves, model=self.model)
        for host in context.hosts:
            for port in host.open_ports:
                if port.service is None:
                    continue
                key = f"{port.service.name.lower()} {port.service.version or ''}".strip()
                cves = context.cves_by_service.get(key, [])
                if not cves:
                    logger.info(
                        "triage: %s:%d (%s) — no CVEs matched, skipping",
                        host.ip, port.number, port.service.name,
                    )
                    continue
                for cve in cves:
                    self.emit(
                        "triage.thinking",
                        host=str(host.ip), port=port.number,
                        cve_id=cve.cve_id,
                    )
                    try:
                        finding = self._triage_one(host, port.number, port.service.name,
                                                   port.service.version, cve)
                    except anthropic.APIError as e:
                        logger.warning(
                            "triage: API error for %s on %s:%d after retries: %s — "
                            "falling back to CVSS-anchored finding",
                            cve.cve_id, host.ip, port.number, e,
                        )
                        self.emit(
                            "triage.api_error",
                            cve_id=cve.cve_id, error=str(e)[:200],
                        )
                        finding = _cvss_fallback_finding(
                            host, port.number, port.service.name,
                            port.service.version, cve,
                            reason=f"LLM API unavailable ({type(e).__name__}); "
                                   f"using CVSS severity directly.",
                        )
                    context.findings.append(finding)
                    self.store.save_finding(context.scan_id, finding)
                    self.emit(
                        "triage.finding_produced",
                        host=str(host.ip), port=port.number,
                        cve_id=finding.cve_id,
                        severity=finding.severity,
                        exploit_likelihood=finding.exploit_likelihood,
                    )
        self.emit("triage.done", finding_count=len(context.findings))
        return context

    def _triage_one(
        self,
        host: Host,
        port: int,
        service_name: str,
        service_version: str | None,
        cve: CVE,
    ) -> Finding:
        user_prompt = _build_user_prompt(host, port, service_name, service_version, cve)
        logger.info("triage: %s on %s:%d (%s)", cve.cve_id, host.ip, port, service_name)

        # System prompt is frozen per run; mark it cacheable so repeat
        # triage calls in the same pipeline reuse the cache. See
        # shared/prompt-caching.md — frozen prefix first, volatile
        # content (the per-CVE user prompt) after.
        response = self._call_with_retry(user_prompt)

        parsed = response.parsed_output
        response_text = parsed.model_dump_json() if parsed else "<no parsed output>"
        self.audit.log_llm_call(
            model=self.model,
            system_prompt=TRIAGE_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            response_text=response_text,
            usage=_usage_to_dict(response.usage),
            extra={
                "host_ip": str(host.ip),
                "port": port,
                "cve_id": cve.cve_id,
                "agent": "triage",
            },
        )

        if parsed is None:
            # Fallback: low-confidence finding rather than crashing the pipeline.
            return Finding(
                host_ip=str(host.ip),
                port=port,
                service_name=service_name,
                service_version=service_version,
                cve_id=cve.cve_id,
                cve_description=cve.description,
                cvss_score=cve.cvss_score,
                severity=cve.cvss_severity or "medium",
                exploit_likelihood="unknown",
                rationale="LLM did not return a structured response; falling back to CVSS severity.",
                recommended_action="Review manually.",
            )

        return Finding(
            host_ip=str(host.ip),
            port=port,
            service_name=service_name,
            service_version=service_version,
            cve_id=cve.cve_id,
            cve_description=cve.description,
            cvss_score=cve.cvss_score,
            severity=parsed.severity,
            exploit_likelihood=parsed.exploit_likelihood,
            rationale=parsed.rationale,
            recommended_action=parsed.recommended_action,
        )


    def _call_with_retry(self, user_prompt: str):
        """Call messages.parse(), retrying on transient overload/rate errors.

        Anthropic's 529 (overloaded_error) and 429 (rate_limit_error) are
        transient. The SDK retries automatically but gives up quickly under
        sustained load; we add an outer retry with jittered backoff so a
        single hot minute doesn't tank an entire scan.
        """
        delays = [2.0, 4.0, 8.0]
        last_exc: Exception | None = None
        for attempt, delay in enumerate([0.0, *delays]):
            if delay:
                time.sleep(delay)
            try:
                return self.client.messages.parse(
                    model=self.model,
                    max_tokens=2048,
                    thinking={"type": "adaptive"},
                    output_config={"effort": "high"},
                    system=[
                        {
                            "type": "text",
                            "text": TRIAGE_SYSTEM_PROMPT,
                            "cache_control": {"type": "ephemeral"},
                        }
                    ],
                    messages=[{"role": "user", "content": user_prompt}],
                    output_format=_TriageOutput,
                )
            except (
                anthropic.APIStatusError,
                anthropic.APIConnectionError,
            ) as e:
                last_exc = e
                status = getattr(e, "status_code", None)
                if status not in (429, 529, 503, 502, 500):
                    raise  # don't retry non-transient errors
                logger.warning(
                    "triage: transient API error (status=%s) on attempt %d; "
                    "retrying after %.1fs",
                    status, attempt + 1, delay if delay else 0,
                )
                self.emit(
                    "triage.retrying",
                    attempt=attempt + 1, status_code=status,
                )
        # All retries exhausted.
        assert last_exc is not None
        raise last_exc


def _cvss_fallback_finding(
    host: Host,
    port: int,
    service_name: str,
    service_version: str | None,
    cve: CVE,
    *,
    reason: str,
) -> Finding:
    """Produce a Finding when the LLM is unavailable, anchored to CVSS."""
    return Finding(
        host_ip=str(host.ip),
        port=port,
        service_name=service_name,
        service_version=service_version,
        cve_id=cve.cve_id,
        cve_description=cve.description,
        cvss_score=cve.cvss_score,
        severity=cve.cvss_severity or "medium",
        exploit_likelihood="unknown",
        rationale=reason,
        recommended_action="Review manually and re-run triage when LLM is available.",
    )


def _build_user_prompt(
    host: Host,
    port: int,
    service_name: str,
    service_version: str | None,
    cve: CVE,
) -> str:
    return (
        f"Host: {host.ip}\n"
        f"Port: {port}\n"
        f"Service: {service_name} {service_version or '(version unknown)'}\n\n"
        f"CVE: {cve.cve_id}\n"
        f"CVSS score: {cve.cvss_score if cve.cvss_score is not None else 'unknown'}\n"
        f"NVD severity: {cve.cvss_severity or 'unknown'}\n"
        f"Description: {cve.description}\n"
        f"References: {', '.join(cve.references[:3]) if cve.references else 'none'}\n\n"
        f"Produce the structured triage assessment per the rubric."
    )


def _usage_to_dict(usage: object) -> dict[str, int]:
    """Best-effort extraction of token-usage fields across SDK versions."""
    out: dict[str, int] = {}
    for field in ("input_tokens", "output_tokens",
                  "cache_creation_input_tokens", "cache_read_input_tokens"):
        value = getattr(usage, field, None)
        if isinstance(value, int):
            out[field] = value
    return out
