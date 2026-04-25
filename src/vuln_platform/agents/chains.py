"""Chain Analysis Agent: identify multi-CVE exploitation paths.

A second LLM pass that runs after Triage. Where Triage looks at one
(host, port, CVE) at a time, this agent reads the entire findings
list together and reasons about how they combine into attack chains.

This is the capstone-defendable claim: not "we wrap an LLM" but "we
build a multi-stage agentic pipeline where each stage uses the LLM
for the kind of reasoning it's best at — Triage for severity calls
on known data, Chain Analysis for synthesis across the whole picture."

Reference: shared/prompt-caching.md and python/claude-api/README.md.
"""
from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Literal

import anthropic
from pydantic import BaseModel, Field

from ..audit import AuditLogger
from ..models import AttackChain, ChainHop
from ..storage import Store
from .base import AgentContext, BaseAgent

if TYPE_CHECKING:
    from ..events import EventBus


logger = logging.getLogger(__name__)


CHAIN_SYSTEM_PROMPT = """\
You are a senior penetration tester analyzing the full set of findings
from a single network scan. Your job is to identify realistic
exploitation chains: sequences of vulnerabilities that, used together,
let an attacker achieve more than any single one alone.

For each chain you identify, produce:
- title: short descriptive name (e.g. "FTP backdoor to root via Redis pivot")
- hops: ordered list of (cve_id, host_ip, port, action, capability_gained)
- severity: combined severity of the chain — usually equal to or higher
  than the worst single hop (critical | high | medium | low)
- confidence: how realistic this chain is given the evidence
  (high | medium | low)
- rationale: 2-4 sentences explaining why this chain works in practice
- prerequisites: what additional conditions must be true for it to
  succeed (e.g. "attacker must be on the same L2 segment", "CGI must
  be enabled in mod_cgi")
- impact: what an attacker achieves at the end (data exfil, lateral
  movement, persistent backdoor, etc.)

Grounding rules:
1. Only reference CVE IDs from the provided findings list. Never
   invent CVEs, hosts, or ports.
2. Each chain must contain AT LEAST 2 hops. Single-CVE "chains" are
   already covered by per-CVE Triage and should not appear here.
3. Be honest about confidence. If a chain requires unrealistic or
   unverified preconditions, downgrade confidence and say why in the
   rationale and prerequisites fields.
4. Identify at most 5 chains. Quality over quantity.
5. If no realistic multi-CVE chain exists, return an empty list.
6. Order hops causally — earlier hops establish the access that
   later hops require.
"""


class _HopSchema(BaseModel):
    cve_id: str
    host_ip: str
    port: int
    action: str
    capability_gained: str


class _ChainSchema(BaseModel):
    title: str
    severity: Literal["critical", "high", "medium", "low"]
    confidence: Literal["high", "medium", "low"]
    rationale: str
    prerequisites: str
    impact: str
    hops: list[_HopSchema]


class _ChainAnalysisOutput(BaseModel):
    chains: list[_ChainSchema] = Field(default_factory=list)


class ChainAnalysisAgent(BaseAgent):
    name = "chains"

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
        if len(context.findings) < 2:
            self.emit("chains.skipped", reason="need at least 2 findings")
            return context

        self.emit("chains.started", finding_count=len(context.findings))
        user_prompt = _build_user_prompt(context)
        try:
            response = self._call(user_prompt)
        except anthropic.APIError as e:
            logger.warning("chains: API error, skipping chain analysis: %s", e)
            self.emit("chains.api_error", error=str(e)[:200])
            return context

        parsed = response.parsed_output
        response_text = (
            parsed.model_dump_json() if parsed else "<no parsed output>"
        )
        self.audit.log_llm_call(
            model=self.model,
            system_prompt=CHAIN_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            response_text=response_text,
            usage=_usage_to_dict(response.usage),
            extra={"agent": "chains", "scan_id": context.scan_id},
        )

        if parsed is None:
            self.emit("chains.no_parse")
            return context

        valid_cves = {f.cve_id for f in context.findings}
        for raw_chain in parsed.chains:
            chain = _to_attack_chain(raw_chain, valid_cves)
            if chain is None:
                continue
            context.chains.append(chain)
            self.store.save_chain(context.scan_id, chain)
            self.emit(
                "chains.chain_identified",
                title=chain.title,
                severity=chain.severity,
                confidence=chain.confidence,
                hop_count=len(chain.hops),
            )
        self.emit("chains.done", chain_count=len(context.chains))
        return context

    def _call(self, user_prompt: str):
        # Use the same prompt-caching approach as Triage: frozen system
        # prompt is cacheable, volatile findings list is the user msg.
        return self.client.messages.parse(
            model=self.model,
            max_tokens=4096,
            thinking={"type": "adaptive"},
            output_config={"effort": "high"},
            system=[
                {
                    "type": "text",
                    "text": CHAIN_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral"},
                }
            ],
            messages=[{"role": "user", "content": user_prompt}],
            output_format=_ChainAnalysisOutput,
        )


def _build_user_prompt(context: AgentContext) -> str:
    """Render every finding as a numbered list item the LLM can reason over."""
    lines = [
        f"Scan target: {context.scope_target}",
        f"Findings ({len(context.findings)}):",
        "",
    ]
    for i, f in enumerate(context.findings, 1):
        lines.append(
            f"{i}. {f.cve_id} (CVSS {f.cvss_score or '?'}, "
            f"severity={f.severity}, exploit_likelihood={f.exploit_likelihood})"
        )
        lines.append(
            f"   Host: {f.host_ip}:{f.port}  "
            f"Service: {f.service_name} "
            f"{f.service_version or '(version unknown)'}"
        )
        # Trim long descriptions so we don't burn tokens on boilerplate.
        desc = f.cve_description.strip().replace("\n", " ")
        if len(desc) > 400:
            desc = desc[:397] + "…"
        lines.append(f"   Description: {desc}")
        lines.append("")
    lines.append(
        "Identify realistic multi-CVE exploitation chains across these "
        "findings, per the system rubric. Return an empty `chains` list "
        "if no meaningful chains exist."
    )
    return "\n".join(lines)


def _to_attack_chain(
    raw: _ChainSchema, valid_cves: set[str]
) -> AttackChain | None:
    """Validate raw LLM output before persisting. Drop bad chains silently."""
    if len(raw.hops) < 2:
        return None
    hops: list[ChainHop] = []
    for raw_hop in raw.hops:
        # Hard reject hops that reference CVEs not in our findings list.
        # Otherwise the LLM could hallucinate plausible-sounding chains.
        if raw_hop.cve_id not in valid_cves:
            logger.warning(
                "chains: dropping chain '%s' — hop references unknown CVE %s",
                raw.title, raw_hop.cve_id,
            )
            return None
        hops.append(ChainHop(
            cve_id=raw_hop.cve_id,
            host_ip=raw_hop.host_ip,
            port=raw_hop.port,
            action=raw_hop.action,
            capability_gained=raw_hop.capability_gained,
        ))
    return AttackChain(
        title=raw.title,
        severity=raw.severity,
        confidence=raw.confidence,
        rationale=raw.rationale,
        prerequisites=raw.prerequisites,
        impact=raw.impact,
        hops=hops,
    )


def _usage_to_dict(usage: object) -> dict[str, int]:
    out: dict[str, int] = {}
    for field in ("input_tokens", "output_tokens",
                  "cache_creation_input_tokens", "cache_read_input_tokens"):
        value = getattr(usage, field, None)
        if isinstance(value, int):
            out[field] = value
    return out
