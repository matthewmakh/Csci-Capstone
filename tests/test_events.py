"""Tests for the pipeline event bus."""
from __future__ import annotations

import queue

from vuln_platform.events import Event, EventBus


def test_publish_to_single_subscriber() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    bus.publish(Event(type="test.foo", data={"x": 1}))
    event = sub.get(timeout=0.5)
    assert event is not None and event.type == "test.foo"
    assert event.data == {"x": 1}


def test_fanout_to_multiple_subscribers() -> None:
    bus = EventBus()
    a = bus.subscribe()
    b = bus.subscribe()
    bus.publish(Event(type="test.shared"))
    assert a.get(timeout=0.5).type == "test.shared"
    assert b.get(timeout=0.5).type == "test.shared"


def test_unsubscribe_removes_sink() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    bus.unsubscribe(sub)
    bus.publish(Event(type="test.lost"))
    # No event should arrive — get() blocks then raises Empty.
    try:
        sub.get(timeout=0.1)
    except queue.Empty:
        return
    raise AssertionError("event delivered after unsubscribe")


def test_close_sends_sentinel() -> None:
    bus = EventBus()
    sub = bus.subscribe()
    bus.close()
    assert sub.get(timeout=0.5) is None


def test_event_to_dict_is_json_safe() -> None:
    e = Event(type="t", data={"k": "v"})
    d = e.to_dict()
    assert d["type"] == "t"
    assert d["data"] == {"k": "v"}
    assert "timestamp" in d
