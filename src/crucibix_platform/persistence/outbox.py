"""Transactional outbox: domain events are written to this table in the same transaction as
the aggregate change, then a relay publishes them to the bus (at-least-once). Consumers are
idempotent on ``event_id``."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from crucibix_platform.events.envelope import EventEnvelope
from crucibix_platform.persistence.base import Base


class OutboxRecord(Base):
    __tablename__ = "outbox"

    event_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    type: Mapped[str] = mapped_column(String(200), index=True)
    tenant_id: Mapped[uuid.UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    published_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    @classmethod
    def from_envelope(cls, env: EventEnvelope) -> OutboxRecord:
        return cls(event_id=env.event_id, type=env.type, tenant_id=env.tenant_id, payload=env.to_dict())


class ProcessedEvent(Base):
    """Idempotency ledger for event consumers."""

    __tablename__ = "processed_events"

    event_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)
    processed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
