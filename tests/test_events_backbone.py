"""Unit tests for the event backbone: outbox relay, EventBridge publisher, SQS consumer.

No AWS and no database: the relay uses a fake OutboxStore, the publisher/consumer use fake boto3
clients injected via the ``client=`` seam.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from crucibix_platform.events.aws import (
    EventBridgePublisher,
    OutboxRelay,
    envelope_from_payload,
)
from crucibix_platform.events.bus import InMemoryEventPublisher
from crucibix_platform.events.consumer import SqsConsumer, envelope_from_sqs_body
from crucibix_platform.events.envelope import EventEnvelope

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")


def _envelope(type_: str = "billing.ModuleEntitlementChanged") -> EventEnvelope:
    return EventEnvelope(
        type=type_,
        data={"organizationId": str(TENANT), "entitledModules": [{"module": "investors", "tier": "pro"}]},
        tenant_id=TENANT,
        correlation_id="corr-1",
    )


def test_envelope_payload_roundtrip() -> None:
    env = _envelope()
    back = envelope_from_payload(env.to_dict())
    assert back.event_id == env.event_id
    assert back.type == env.type
    assert back.tenant_id == TENANT
    assert back.data == env.data
    assert back.occurred_at == env.occurred_at


class _FakeEventsClient:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def put_events(self, *, Entries: list[dict[str, Any]]) -> dict[str, Any]:  # noqa: N803 (boto3 kwarg)
        self.entries.extend(Entries)
        return {"FailedEntryCount": 0, "Entries": [{"EventId": "x"}]}


def test_eventbridge_publisher_puts_detail() -> None:
    fake = _FakeEventsClient()
    pub = EventBridgePublisher(
        bus_name="crucibix", source="crucibix.billing", region="ap-south-1", client=fake
    )
    env = _envelope()
    pub.publish(env)
    assert len(fake.entries) == 1
    e = fake.entries[0]
    assert e["EventBusName"] == "crucibix"
    assert e["DetailType"] == env.type
    assert json.loads(e["Detail"])["event_id"] == str(env.event_id)


class _FakeStore:
    def __init__(self, envelopes: list[EventEnvelope]) -> None:
        self._pending = list(envelopes)
        self.marked: list[uuid.UUID] = []

    def fetch_unpublished(self, limit: int) -> list[EventEnvelope]:
        return self._pending[:limit]

    def mark_published(self, event_ids: list[uuid.UUID]) -> None:
        self.marked.extend(event_ids)
        self._pending = [e for e in self._pending if e.event_id not in set(event_ids)]


def test_outbox_relay_publishes_and_marks() -> None:
    envs = [_envelope(), _envelope()]
    store = _FakeStore(envs)
    pub = InMemoryEventPublisher()
    relay = OutboxRelay(store, pub)

    assert relay.drain_once() == 2
    assert pub.types() == ["billing.ModuleEntitlementChanged"] * 2
    assert set(store.marked) == {e.event_id for e in envs}
    # Idempotent drain: nothing left.
    assert relay.drain_once() == 0


def test_outbox_relay_marks_only_published_on_failure() -> None:
    envs = [_envelope(), _envelope()]
    store = _FakeStore(envs)

    class _Boom(InMemoryEventPublisher):
        def publish(self, envelope: EventEnvelope) -> None:
            if len(self.published) >= 1:
                raise RuntimeError("bus down")
            super().publish(envelope)

    relay = OutboxRelay(store, _Boom())
    try:
        relay.drain_once()
    except RuntimeError:
        pass
    # Only the first was published → only it is marked; the second stays pending.
    assert store.marked == [envs[0].event_id]
    assert store.fetch_unpublished(10) == [envs[1]]


class _FakeSqsClient:
    def __init__(self, bodies: list[str]) -> None:
        self._bodies = bodies
        self.deleted: list[str] = []

    def receive_message(self, **_: Any) -> dict[str, Any]:
        msgs = [{"Body": b, "ReceiptHandle": f"rh-{i}"} for i, b in enumerate(self._bodies)]
        self._bodies = []
        return {"Messages": msgs}

    def delete_message(self, *, QueueUrl: str, ReceiptHandle: str) -> None:  # noqa: N803
        self.deleted.append(ReceiptHandle)


def test_sqs_consumer_dispatches_and_acks() -> None:
    env = _envelope()
    # EventBridge-style delivery: envelope under "detail".
    eb_body = json.dumps({"detail-type": env.type, "source": "crucibix.billing", "detail": env.to_dict()})
    seen: list[EventEnvelope] = []
    fake = _FakeSqsClient([eb_body])
    consumer = SqsConsumer(
        queue_url="q",
        handlers={env.type: seen.append},
        region="ap-south-1",
        client=fake,
    )
    assert consumer.poll_once() == 1
    assert seen[0].event_id == env.event_id
    assert seen[0].data["organizationId"] == str(TENANT)
    assert fake.deleted == ["rh-0"]


def test_sqs_consumer_acks_unregistered_type() -> None:
    env = _envelope(type_="billing.InvoicePaid")
    fake = _FakeSqsClient([json.dumps({"detail": env.to_dict()})])
    consumer = SqsConsumer(queue_url="q", handlers={}, region="ap-south-1", client=fake)
    assert consumer.poll_once() == 0  # no handler
    assert fake.deleted == ["rh-0"]  # still acked


def test_envelope_from_raw_sqs_body() -> None:
    env = _envelope()
    back = envelope_from_sqs_body(json.dumps(env.to_dict()))
    assert back.event_id == env.event_id


def test_sqs_consumer_poison_message_does_not_stall_batch() -> None:
    good = _envelope()
    poison = json.dumps({"detail": {"not": "an envelope"}})  # missing 'type' → KeyError
    good_body = json.dumps({"detail": good.to_dict()})
    seen: list[EventEnvelope] = []
    fake = _FakeSqsClient([poison, good_body])
    consumer = SqsConsumer(queue_url="q", handlers={good.type: seen.append}, region="ap-south-1", client=fake)

    # Does not raise; the good message is still handled.
    assert consumer.poll_once() == 1
    assert [e.event_id for e in seen] == [good.event_id]
    # Poison (rh-0) is NOT acked (left for redrive→DLQ); good (rh-1) is acked.
    assert "rh-0" not in fake.deleted
    assert "rh-1" in fake.deleted
