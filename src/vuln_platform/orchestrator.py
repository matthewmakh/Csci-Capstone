"""Pipeline orchestrator — wires the four agents together."""
from __future__ import annotations

import logging
from collections.abc import Iterable

from .agents import AgentContext, BaseAgent
from .events import Event, EventBus


logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(
        self,
        agents: Iterable[BaseAgent],
        event_bus: EventBus | None = None,
    ) -> None:
        self.agents = list(agents)
        self.event_bus = event_bus

    def run(self, context: AgentContext) -> AgentContext:
        agent_names = [a.name for a in self.agents]
        self._publish("pipeline.started", scan_id=context.scan_id,
                      target=context.scope_target, agents=agent_names)
        for agent in self.agents:
            logger.info("orchestrator: running %s", agent.name)
            self._publish("pipeline.agent_started", agent=agent.name)
            try:
                context = agent.run(context)
            except Exception as e:  # noqa: BLE001 - report and re-raise
                self._publish("pipeline.agent_failed",
                              agent=agent.name, error=str(e))
                raise
            self._publish("pipeline.agent_finished", agent=agent.name)
        self._publish("pipeline.finished",
                      scan_id=context.scan_id,
                      finding_count=len(context.findings))
        return context

    def _publish(self, event_type: str, **data: object) -> None:
        if self.event_bus is None:
            return
        self.event_bus.publish(Event(type=event_type, data=dict(data)))
