"""Pipeline event bus for live progress streaming.

Agents publish typed events as they run; the web layer subscribes to a
queue and forwards events to the browser via Server-Sent Events. The bus
is process-local and thread-safe — fine for a single-operator capstone
tool, not for distributed deployments.
"""
from __future__ import annotations

import queue
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class Event:
    """One pipeline event. `type` is a dotted name; `data` is JSON-safe."""

    type: str
    data: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class EventBus:
    """Fan-out event bus. Subscribers each get their own queue."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue[Event | None]] = []

    def subscribe(self) -> queue.Queue[Event | None]:
        q: queue.Queue[Event | None] = queue.Queue(maxsize=1024)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue[Event | None]) -> None:
        with self._lock:
            try:
                self._subscribers.remove(q)
            except ValueError:
                pass

    def publish(self, event: Event) -> None:
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(event)
            except queue.Full:
                # Drop events if a slow subscriber backs up — better than
                # blocking the scanner thread.
                pass

    def close(self) -> None:
        """Send a sentinel to every subscriber to terminate their stream."""
        with self._lock:
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(None)
            except queue.Full:
                pass


# Process-wide singleton used by the web demo flow.
bus = EventBus()
