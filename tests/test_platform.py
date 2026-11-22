from __future__ import annotations

import uuid

from fastapi.testclient import TestClient

from crucibix_platform.domain.base import AggregateRoot, DomainEvent
from crucibix_platform.events.bus import InMemoryEventPublisher
from crucibix_platform.events.envelope import EventEnvelope


# ── API / health ─────────────────────────────────────────────────────────────
def test_health(client: TestClient) -> None:
    assert client.get("/healthz").json() == {"status": "ok"}
    assert client.get("/readyz").json() == {"status": "ready"}


def test_correlation_header_echoed(client: TestClient) -> None:
    resp = client.get("/healthz", headers={"X-Correlation-Id": "abc-123"})
    assert resp.headers["X-Correlation-Id"] == "abc-123"


# ── Errors → problem+json ────────────────────────────────────────────────────
def test_domain_error_maps_to_problem_json(client: TestClient) -> None:
    resp = client.get("/v1/boom", headers={"Authorization": "Bearer investors:read"})
    assert resp.status_code == 409
    assert resp.headers["content-type"].startswith("application/problem+json")
    body = resp.json()
    assert body["status"] == 409 and body["detail"] == "cannot do that"
    assert body["type"].endswith("/invariant_violation")


# ── Auth / privilege enforcement ─────────────────────────────────────────────
def test_missing_token_is_forbidden(client: TestClient) -> None:
    assert client.get("/v1/secure").status_code == 403


def test_privilege_granted(client: TestClient) -> None:
    resp = client.get("/v1/secure", headers={"Authorization": "Bearer investors:read"})
    assert resp.status_code == 200 and resp.json() == {"ok": True}


def test_privilege_denied_names_missing(client: TestClient) -> None:
    resp = client.get("/v1/secure", headers={"Authorization": "Bearer crm:read"})
    assert resp.status_code == 403
    assert resp.json()["missingPrivilege"] == "investors:read"


def test_invalid_token_denied(client: TestClient) -> None:
    assert client.get("/v1/secure", headers={"Authorization": "Bearer invalid"}).status_code == 403


# ── Domain building blocks ───────────────────────────────────────────────────
class _Thing(AggregateRoot):
    pass


def test_aggregate_records_and_pulls_events() -> None:
    agg = _Thing(_Thing.next_id())
    agg.record(DomainEvent())
    agg.record(DomainEvent())
    pulled = agg.pull_events()
    assert len(pulled) == 2
    assert agg.pull_events() == []  # drained


def test_entity_equality_by_id() -> None:
    i = uuid.uuid4()
    assert _Thing(i) == _Thing(i)
    assert _Thing(i) != _Thing(uuid.uuid4())


# ── Events ───────────────────────────────────────────────────────────────────
def test_in_memory_publisher_collects() -> None:
    pub = InMemoryEventPublisher()
    pub.publish(EventEnvelope(type="identity.UserRegistered", data={"userId": "x"}, tenant_id=None))
    assert pub.types() == ["identity.UserRegistered"]


def test_envelope_serializes() -> None:
    env = EventEnvelope(type="identity.RoleUpdated", data={"roleId": "r"}, tenant_id=uuid.uuid4())
    d = env.to_dict()
    assert d["type"] == "identity.RoleUpdated"
    assert isinstance(d["event_id"], str) and isinstance(d["occurred_at"], str)
