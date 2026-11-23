"""Unit tests for the promoted commerce-payments producer client + service-to-service auth seam.

All HTTP is driven through ``httpx.MockTransport`` — no network, no commerce-payments, no Keycloak.
Covers: request shaping + headers, response parsing, the one bounded retry on timeout/5xx, no retry on
4xx, graceful failure (``PaymentInitiationError``), both token-provider modes, and the settings-driven
factory.
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Callable

import httpx
import pytest

from crucibix_platform.payments import (
    CallerContext,
    CommercePaymentsClientSettings,
    HttpCommercePaymentsClient,
    KeycloakServiceTokenProvider,
    PayerRef,
    PaymentInitiationError,
    PaymentIntentRequest,
    PaymentReference,
    StaticServiceTokenProvider,
    build_commerce_payments_client,
)

ORG = uuid.uuid4()
INTENT_ID = str(uuid.uuid4())


def _request() -> PaymentIntentRequest:
    return PaymentIntentRequest(
        reference=PaymentReference(entity_type="invoice", entity_id="inv-1"),
        amount_minor=1599,
        currency="GBP",
        idempotency_key="invoice:inv-1:v1",
        payer=PayerRef(ref="cust-7"),
        method_types=("card",),
        capture_mode="auto",
    )


def _created_body() -> dict[str, object]:
    return {
        "id": INTENT_ID,
        "status": "requires_payment",
        "clientSecret": "cs_live_abc",
        "checkoutUrl": "https://pay.example/redirect/abc",
        "reference": {"entityType": "invoice", "entityId": "inv-1"},
    }


def _client(
    handler: Callable[[httpx.Request], httpx.Response],
    *,
    token: StaticServiceTokenProvider | None = None,
) -> HttpCommercePaymentsClient:
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return HttpCommercePaymentsClient(
        base_url="http://commerce-payments:8000",
        token_provider=token or StaticServiceTokenProvider("svc-token", assert_tenant=True),
        http=http,
    )


def _caller() -> CallerContext:
    return CallerContext(organization_id=ORG, subject_token="inbound-user-token")


def test_happy_path_shapes_request_and_parses_response() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        import json

        seen["url"] = str(request.url)
        seen["body"] = json.loads(request.content)
        seen["idem"] = request.headers.get("Idempotency-Key")
        seen["auth"] = request.headers.get("Authorization")
        seen["tenant"] = request.headers.get("X-Tenant-Id")
        return httpx.Response(201, json=_created_body())

    result = _client(handler).create_intent(_request(), caller=_caller())

    assert seen["url"] == "http://commerce-payments:8000/v1/payment-intents"
    assert seen["body"] == {
        "reference": {"entityType": "invoice", "entityId": "inv-1"},
        "amount": {"amountMinor": 1599, "currency": "GBP"},
        "captureMode": "auto",
        "payerRef": "cust-7",
        "methodTypes": ["card"],
    }
    assert seen["idem"] == "invoice:inv-1:v1"
    assert seen["auth"] == "Bearer svc-token"
    assert seen["tenant"] == str(ORG)

    assert result.gateway_intent_ref == INTENT_ID
    assert result.status == "requires_payment"
    assert result.client_secret == "cs_live_abc"
    assert result.redirect_url == "https://pay.example/redirect/abc"


def test_retries_once_on_5xx_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            return httpx.Response(503, json={"title": "unavailable"})
        return httpx.Response(201, json=_created_body())

    result = _client(handler).create_intent(_request(), caller=_caller())
    assert calls["n"] == 2
    assert result.gateway_intent_ref == INTENT_ID


def test_retries_once_on_timeout_then_succeeds() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        if calls["n"] == 1:
            raise httpx.ConnectTimeout("boom", request=request)
        return httpx.Response(201, json=_created_body())

    result = _client(handler).create_intent(_request(), caller=_caller())
    assert calls["n"] == 2
    assert result.gateway_intent_ref == INTENT_ID


def test_persistent_5xx_raises_after_retry() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(500, json={"title": "kaboom"})

    with pytest.raises(PaymentInitiationError):
        _client(handler).create_intent(_request(), caller=_caller())
    assert calls["n"] == 2  # one initial + one retry


def test_4xx_is_not_retried() -> None:
    calls = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        calls["n"] += 1
        return httpx.Response(422, json={"title": "bad amount"})

    with pytest.raises(PaymentInitiationError):
        _client(handler).create_intent(_request(), caller=_caller())
    assert calls["n"] == 1  # client error — no retry


def test_response_without_id_raises() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(201, json={"status": "requires_payment"})

    with pytest.raises(PaymentInitiationError):
        _client(handler).create_intent(_request(), caller=_caller())


# ── Service token providers ──────────────────────────────────────────────────
def test_token_exchange_provider_posts_rfc8693_grant() -> None:
    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["form"] = dict(httpx.QueryParams(request.content.decode()))
        return httpx.Response(200, json={"access_token": "downstream-xyz", "expires_in": 300})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    provider = KeycloakServiceTokenProvider(
        mode="token_exchange",
        token_url="https://auth.example/token",
        client_id="finance-svc",
        client_secret="shh",
        audience="commerce-payments",
        scope="payments:collect",
        http=http,
    )
    headers = provider.auth_headers(organization_id=ORG, subject_token="user-token")
    assert headers == {"Authorization": "Bearer downstream-xyz"}
    assert seen["url"] == "https://auth.example/token"
    form = seen["form"]
    assert isinstance(form, dict)
    assert form["grant_type"] == "urn:ietf:params:oauth:grant-type:token-exchange"
    assert form["subject_token"] == "user-token"
    assert form["audience"] == "commerce-payments"
    assert form["scope"] == "payments:collect"

    # Second call is served from cache (no second HTTP round trip would change the token).
    again = provider.auth_headers(organization_id=ORG, subject_token="user-token")
    assert again == headers


def test_token_exchange_without_subject_token_raises() -> None:
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    provider = KeycloakServiceTokenProvider(
        mode="token_exchange",
        token_url="https://auth.example/token",
        client_id="finance-svc",
        client_secret="shh",
        audience="commerce-payments",
        scope="payments:collect",
        http=http,
    )
    with pytest.raises(PaymentInitiationError):
        provider.auth_headers(organization_id=ORG, subject_token=None)


def test_client_credentials_provider_asserts_tenant() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        form = dict(httpx.QueryParams(request.content.decode()))
        assert form["grant_type"] == "client_credentials"
        return httpx.Response(200, json={"access_token": "svc-abc", "expires_in": 120})

    http = httpx.Client(transport=httpx.MockTransport(handler))
    provider = KeycloakServiceTokenProvider(
        mode="client_credentials",
        token_url="https://auth.example/token",
        client_id="investors-svc",
        client_secret="shh",
        audience="commerce-payments",
        scope="payments:collect",
        http=http,
    )
    headers = provider.auth_headers(organization_id=ORG, subject_token=None)
    assert headers == {"Authorization": "Bearer svc-abc", "X-Tenant-Id": str(ORG)}


def test_unknown_auth_mode_rejected() -> None:
    http = httpx.Client(transport=httpx.MockTransport(lambda r: httpx.Response(200, json={})))
    with pytest.raises(ValueError):
        KeycloakServiceTokenProvider(
            mode="nope",
            token_url="https://auth.example/token",
            client_id="svc",
            client_secret="shh",
            audience="commerce-payments",
            scope="payments:collect",
            http=http,
        )


# ── Settings-driven factory ────────────────────────────────────────────────────
def test_factory_returns_none_when_disabled() -> None:
    settings = CommercePaymentsClientSettings(commerce_payments_base_url="")
    assert build_commerce_payments_client(settings) is None


def test_factory_builds_static_client_that_posts_intent() -> None:
    settings = CommercePaymentsClientSettings(
        environment="dev",
        commerce_payments_base_url="http://commerce-payments:8000",
        commerce_payments_auth_mode="static",
        commerce_payments_static_token="fixed-token",
        commerce_payments_client_id="finance-svc",
    )
    port = build_commerce_payments_client(settings)
    assert port is not None

    seen: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers.get("Authorization")
        seen["tenant"] = request.headers.get("X-Tenant-Id")
        return httpx.Response(201, json=_created_body())

    # Swap the factory's real client for the mock transport (same construction otherwise).
    port._http = httpx.Client(transport=httpx.MockTransport(handler))  # type: ignore[attr-defined]
    result = port.create_intent(_request(), caller=_caller())
    assert result.gateway_intent_ref == INTENT_ID
    assert seen["auth"] == "Bearer fixed-token"
    assert seen["tenant"] == str(ORG)


def test_factory_client_credentials_resolves_secret_from_env() -> None:
    os.environ["CRUCIBIX_SECRET_FINANCE_SVC"] = "resolved-secret"
    try:
        settings = CommercePaymentsClientSettings(
            environment="dev",
            commerce_payments_base_url="http://commerce-payments:8000",
            commerce_payments_auth_mode="client_credentials",
            commerce_payments_client_id="finance-svc",
            commerce_payments_client_secret_ref="finance-svc",
            commerce_payments_token_url="https://auth.example/token",
        )
        port = build_commerce_payments_client(settings)
        assert port is not None

        def token_handler(request: httpx.Request) -> httpx.Response:
            form = dict(httpx.QueryParams(request.content.decode()))
            assert form["client_secret"] == "resolved-secret"
            return httpx.Response(200, json={"access_token": "cc-token", "expires_in": 120})

        # Point both the token provider and the client at the mock transport.
        mock = httpx.Client(transport=httpx.MockTransport(token_handler))
        port._tokens._http = mock  # type: ignore[attr-defined]
        headers = port._tokens.auth_headers(organization_id=ORG, subject_token=None)  # type: ignore[attr-defined]
        assert headers["Authorization"] == "Bearer cc-token"
        assert headers["X-Tenant-Id"] == str(ORG)
    finally:
        del os.environ["CRUCIBIX_SECRET_FINANCE_SVC"]
