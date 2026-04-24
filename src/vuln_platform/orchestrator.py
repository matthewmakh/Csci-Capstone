"""Pipeline orchestrator — wires the four agents together."""
from __future__ import annotations

import logging
from collections.abc import Iterable

from .agents import AgentContext, BaseAgent


logger = logging.getLogger(__name__)


class Orchestrator:
    def __init__(self, agents: Iterable[BaseAgent]) -> None:
        self.agents = list(agents)

    def run(self, context: AgentContext) -> AgentContext:
        for agent in self.agents:
            logger.info("orchestrator: running %s", agent.name)
            context = agent.run(context)
        return context
