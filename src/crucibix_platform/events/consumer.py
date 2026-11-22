"""SQS consumer: polls a queue, unwraps EventBridge-delivered envelopes, and dispatches to
per-type handlers. Reusable; a service registers ``{event_type: handler}``.

EventBridge delivers to SQS with the envelope under the ``detail`` key of the EventBridge event
JSON; a raw (non-EventBridge) body is also accepted. Delivery is at-least-once, so handlers must
be idempotent (e.g. keyed on ``envelope.event_id``). A message is deleted only after its handler
succeeds; an unhandled type is acked (deleted) to avoid poisoning the queue.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any

import structlog

from crucibix_platform.events.aws import envelope_from_payload
from crucibix_platform.events.envelope import EventEnvelope

Handler = Callable[[EventEnvelope], None]

_log = structlog.get_logger(__name__)


def envelope_from_sqs_body(body: str) -> EventEnvelope:
    """Parse an SQS message body into an :class:`EventEnvelope` (EventBridge or raw)."""
    parsed = json.loads(body)
    detail = parsed.get("detail", parsed) if isinstance(parsed, dict) else parsed
    return envelope_from_payload(detail)


class SqsConsumer:
    def __init__(
        self,
        *,
        queue_url: str,
        handlers: dict[str, Handler],
        region: str,
        endpoint_url: str | None = None,
        client: Any | None = None,
        wait_seconds: int = 10,
        max_messages: int = 10,
    ) -> None:
        self._queue_url = queue_url
        self._handlers = handlers
        self._wait = wait_seconds
        self._max = max_messages
        if client is not None:
            self._client = client
        else:
            import boto3  # lazy: only needed for the real adapter

            self._client = boto3.client("sqs", region_name=region, endpoint_url=endpoint_url)

    def poll_once(self) -> int:
        resp = self._client.receive_message(
            QueueUrl=self._queue_url,
            MaxNumberOfMessages=self._max,
            WaitTimeSeconds=self._wait,
        )
        messages = resp.get("Messages", []) or []
        handled = 0
        for msg in messages:
            try:
                env = envelope_from_sqs_body(msg["Body"])
                handler = self._handlers.get(env.type)
                if handler is not None:
                    handler(env)
                    handled += 1
                # Ack: handled, or an unregistered type we don't want requeued.
                self._client.delete_message(QueueUrl=self._queue_url, ReceiptHandle=msg["ReceiptHandle"])
            except Exception:
                # Poison or transient failure: do NOT delete — SQS redelivers, then DLQs after
                # maxReceiveCount. One bad message never stalls the batch or crashes the loop.
                _log.exception("event_consume_failed", queue=self._queue_url)
        return handled

    def run_forever(self) -> None:  # pragma: no cover - long-running loop
        while True:
            self.poll_once()


def resolve_queue_url(
    queue_name: str,
    *,
    region: str,
    endpoint_url: str | None = None,
    client: Any | None = None,
) -> str:
    """Resolve an SQS queue URL by name (lazy boto3 import keeps it out of static deps)."""
    if client is None:
        import boto3

        client = boto3.client("sqs", region_name=region, endpoint_url=endpoint_url)
    return str(client.get_queue_url(QueueName=queue_name)["QueueUrl"])


__all__ = ["Handler", "SqsConsumer", "envelope_from_sqs_body", "resolve_queue_url"]
