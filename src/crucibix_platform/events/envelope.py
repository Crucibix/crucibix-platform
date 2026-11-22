"""The shared event envelope — matches the AsyncAPI ``EnvelopeBase`` in crucibix-contracts.
Every published domain event is wrapped in this before hitting the bus."""

from __future__ import annotations

import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True, slots=True)
class EventEnvelope:
    type: str
    data: dict[str, Any]
    tenant_id: uuid.UUID | None
    correlation_id: str | None = None
    version: int = 1
    event_id: uuid.UUID = field(default_factory=uuid.uuid4)
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["event_id"] = str(self.event_id)
        d["tenant_id"] = str(self.tenant_id) if self.tenant_id else None
        d["occurred_at"] = self.occurred_at.isoformat()
        return d
