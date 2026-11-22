"""DDD building blocks shared by every service's domain layer.

Pure Python — no FastAPI/SQLAlchemy imports. Value objects are immutable; aggregate roots
record domain events that the application layer publishes via the transactional outbox.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime


@dataclass(frozen=True, slots=True)
class ValueObject:
    """Marker base for immutable, equality-by-value objects. Subclass with
    ``@dataclass(frozen=True, slots=True)``."""


@dataclass(frozen=True, slots=True)
class DomainEvent:
    """Something that happened in the domain. Subclasses add a typed ``data`` payload via
    attributes; the envelope fields below are filled by the base."""

    event_id: uuid.UUID = field(default_factory=uuid.uuid4, kw_only=True)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC), kw_only=True)
    version: int = field(default=1, kw_only=True)

    @property
    def type(self) -> str:
        """Dotted event type, e.g. ``identity.MembershipRolesChanged`` — override per context
        by setting ``_type`` or rely on the class name."""
        return getattr(self, "_type", self.__class__.__name__)


class Entity:
    """Identity-based equality. ``id`` is immutable."""

    def __init__(self, id: uuid.UUID) -> None:
        self._id = id

    @property
    def id(self) -> uuid.UUID:
        return self._id

    def __eq__(self, other: object) -> bool:
        return isinstance(other, type(self)) and other._id == self._id

    def __hash__(self) -> int:
        return hash((type(self).__name__, self._id))


class AggregateRoot(Entity):
    """Transactional + consistency boundary. Protects its invariants and records the domain
    events it produces; the application layer pulls and publishes them atomically."""

    def __init__(self, id: uuid.UUID) -> None:
        super().__init__(id)
        self._events: list[DomainEvent] = []

    def record(self, event: DomainEvent) -> None:
        self._events.append(event)

    def pull_events(self) -> list[DomainEvent]:
        events, self._events = self._events, []
        return events

    @classmethod
    def next_id(cls) -> uuid.UUID:
        return uuid.uuid4()
