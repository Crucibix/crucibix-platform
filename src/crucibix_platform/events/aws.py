"""EventBridge publisher + transactional-outbox relay (AWS; LocalStack in local-dev).

Reusable by every service. The relay drains the shared ``OutboxRecord`` table and publishes each
envelope to the EventBridge bus (at-least-once; consumers are idempotent on ``event_id``). The
outbox read/mark is behind a port so the relay is unit-testable without a database or boto3.

Requires the ``aws`` extra (boto3) only at runtime for the real clients; the pure logic has no
AWS dependency.
"""

from __future__ import annotations

import json
import uuid
from datetime import UTC, datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session, sessionmaker

from crucibix_platform.events.bus import EventPublisher
from crucibix_platform.events.envelope import EventEnvelope
from crucibix_platform.persistence.outbox import OutboxRecord


def envelope_from_payload(payload: dict[str, Any]) -> EventEnvelope:
    """Reconstruct an :class:`EventEnvelope` from a stored/serialized ``to_dict`` payload."""
    tenant = payload.get("tenant_id")
    return EventEnvelope(
        type=payload["type"],
        data=payload["data"],
        tenant_id=uuid.UUID(tenant) if tenant else None,
        correlation_id=payload.get("correlation_id"),
        version=int(payload.get("version", 1)),
        event_id=uuid.UUID(payload["event_id"]),
        occurred_at=datetime.fromisoformat(payload["occurred_at"]),
    )


class EventBridgePublisher:
    """Publishes envelopes to an EventBridge bus. ``source`` groups one service's events."""

    def __init__(
        self,
        *,
        bus_name: str,
        source: str,
        region: str,
        endpoint_url: str | None = None,
        client: Any | None = None,
    ) -> None:
        self._bus = bus_name
        self._source = source
        if client is not None:
            self._client = client
        else:
            import boto3  # lazy: only needed for the real adapter

            self._client = boto3.client("events", region_name=region, endpoint_url=endpoint_url)

    def publish(self, envelope: EventEnvelope) -> None:
        resp = self._client.put_events(
            Entries=[
                {
                    "Source": self._source,
                    "DetailType": envelope.type,
                    "Detail": json.dumps(envelope.to_dict()),
                    "EventBusName": self._bus,
                }
            ]
        )
        failed = int(resp.get("FailedEntryCount", 0))
        if failed:
            raise RuntimeError(f"EventBridge put_events failed ({failed}): {resp.get('Entries')}")


class OutboxStore(Protocol):
    """Read/mark the unpublished outbox — the only DB surface the relay needs."""

    def fetch_unpublished(self, limit: int) -> list[EventEnvelope]: ...
    def mark_published(self, event_ids: list[uuid.UUID]) -> None: ...


class SqlOutboxStore:
    """SQLAlchemy-backed :class:`OutboxStore` over the shared ``OutboxRecord`` table."""

    def __init__(self, session_factory: sessionmaker[Session]) -> None:
        self._sf = session_factory

    def fetch_unpublished(self, limit: int) -> list[EventEnvelope]:
        with self._sf() as s:
            rows = (
                s.execute(
                    select(OutboxRecord)
                    .where(OutboxRecord.published_at.is_(None))
                    .order_by(OutboxRecord.created_at)
                    .limit(limit)
                )
                .scalars()
                .all()
            )
            return [envelope_from_payload(r.payload) for r in rows]

    def mark_published(self, event_ids: list[uuid.UUID]) -> None:
        if not event_ids:
            return
        now = datetime.now(UTC)
        with self._sf() as s:
            for row in (
                s.execute(select(OutboxRecord).where(OutboxRecord.event_id.in_(event_ids))).scalars().all()
            ):
                row.published_at = now
            s.commit()


class OutboxRelay:
    """Drains unpublished outbox envelopes to the publisher, then marks them published."""

    def __init__(self, store: OutboxStore, publisher: EventPublisher, *, batch_size: int = 100) -> None:
        self._store = store
        self._publisher = publisher
        self._batch = batch_size

    def drain_once(self) -> int:
        envelopes = self._store.fetch_unpublished(self._batch)
        published: list[uuid.UUID] = []
        try:
            for env in envelopes:
                self._publisher.publish(env)
                published.append(env.event_id)
        finally:
            self._store.mark_published(published)
        return len(published)


__all__ = [
    "EventBridgePublisher",
    "OutboxRelay",
    "OutboxStore",
    "SqlOutboxStore",
    "envelope_from_payload",
]
