"""End-to-end orchestrator test with all agents mocked."""
from __future__ import annotations

from unittest.mock import MagicMock

from vuln_platform.agents.base import AgentContext, BaseAgent
from vuln_platform.orchestrator import Orchestrator


class _Tagger(BaseAgent):
    def __init__(self, name: str) -> None:
        self.name = name
        self.ran = False

    def run(self, context: AgentContext) -> AgentContext:
        self.ran = True
        context.scope_target = f"{context.scope_target}|{self.name}"
        return context


def test_orchestrator_runs_agents_in_order() -> None:
    a = _Tagger("first")
    b = _Tagger("second")
    c = _Tagger("third")
    ctx = AgentContext(scan_id=1, scope_target="start")
    ctx = Orchestrator([a, b, c]).run(ctx)
    assert a.ran and b.ran and c.ran
    assert ctx.scope_target == "start|first|second|third"


def test_orchestrator_empty_agent_list_is_noop() -> None:
    ctx = AgentContext(scan_id=1, scope_target="127.0.0.1")
    ctx = Orchestrator([]).run(ctx)
    assert ctx.scope_target == "127.0.0.1"


def test_orchestrator_propagates_agent_exceptions() -> None:
    class _Broken(BaseAgent):
        name = "broken"

        def run(self, context: AgentContext) -> AgentContext:
            raise RuntimeError("agent failed")

    import pytest
    with pytest.raises(RuntimeError, match="agent failed"):
        Orchestrator([_Broken()]).run(AgentContext(scan_id=1, scope_target="x"))
