"""Agent base class + shared context passed through the pipeline."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from ..events import Event, EventBus
from ..models import CVE, Finding, Host


@dataclass
class AgentContext:
    """Shared state passed between pipeline agents.

    Each agent reads from and writes to specific fields:
    - ReconAgent writes `hosts`.
    - EnrichmentAgent reads `hosts`, writes `cves_by_service`.
    - TriageAgent reads everything above, writes `findings`.
    - ReporterAgent reads `findings` and emits `report_markdown`.
    """

    scan_id: int
    scope_target: str
    hosts: list[Host] = field(default_factory=list)
    # Keyed by "service_name service_version" (version may be empty).
    cves_by_service: dict[str, list[CVE]] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    report_markdown: str | None = None


class BaseAgent(ABC):
    """Abstract agent — one `run(context)` method, returns the (mutated) context."""

    name: str = "agent"
    event_bus: EventBus | None = None

    def emit(self, event_type: str, **data: object) -> None:
        """Publish an event if a bus is attached. No-op otherwise."""
        if self.event_bus is None:
            return
        self.event_bus.publish(Event(type=event_type, data=dict(data)))

    @abstractmethod
    def run(self, context: AgentContext) -> AgentContext:  # pragma: no cover
        ...
