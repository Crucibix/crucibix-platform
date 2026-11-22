"""Event publishing ports + an in-memory implementation for tests/local.

Production uses a transactional outbox: use cases append envelopes to the outbox table in the
same DB transaction as the domain change; a relay publishes them to EventBridge. The AWS
adapter lives in ``infrastructure`` of the deployable (or a platform extra) and implements the
same ``EventPublisher`` port.
"""

from __future__ import annotations

from typing import Protocol

from crucibix_platform.events.envelope import EventEnvelope


class EventPublisher(Protocol):
    def publish(self, envelope: EventEnvelope) -> None: ...


class InMemoryEventPublisher:
    """Collects published envelopes; used in unit/application tests to assert events."""

    def __init__(self) -> None:
        self.published: list[EventEnvelope] = []

    def publish(self, envelope: EventEnvelope) -> None:
        self.published.append(envelope)

    def types(self) -> list[str]:
        return [e.type for e in self.published]
