"""HTTP adapter for the commerce-payments producer call — the one sanctioned sync cross-service call.

``HttpCommercePaymentsClient`` POSTs ``{base_url}/v1/payment-intents`` shaped by the frozen
commerce-payments OpenAPI (``PaymentIntentWrite`` request → ``PaymentIntentCreated`` response), with a
deterministic ``Idempotency-Key`` and a downstream bearer from a :class:`ServiceTokenProvider`. It
retries **once** on a timeout / network error / 5xx (safe: the call is idempotent — commerce-payments
enforces ``(tenant_id, Idempotency-Key)`` unique and returns the existing intent), and otherwise
raises :class:`PaymentInitiationError`, which callers degrade on — never blocking their primary flow
on the PSP being up.

Service-to-service auth is the key decision, kept pluggable behind :class:`ServiceTokenProvider`:

* :class:`KeycloakServiceTokenProvider` — **preferred** ``token_exchange`` (RFC 8693): exchange the
  inbound end-user token for a downstream token scoped to the same tenant with ``payments:collect``.
  The tenant stays inside the token (honest + auditable, no ambient service super-power). Falls back
  to ``client_credentials`` (a per-service service account) which must assert the tenant via an
  ``X-Tenant-Id`` header — commerce-payments has to trust an asserted tenant **only** from that
  service principal, which widens trust, so ``token_exchange`` is preferred.
* :class:`StaticServiceTokenProvider` — a fixed bearer for local-dev / tests (no Keycloak needed to
  run the loop end to end).
"""

from __future__ import annotations

import time
import uuid
from typing import Any, Protocol

import httpx

from crucibix_platform.payments.initiation import (
    CallerContext,
    InitiatedPayment,
    PaymentInitiationError,
    PaymentIntentRequest,
)

_TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
_ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"


class ServiceTokenProvider(Protocol):
    """Yield the outbound auth headers (a downstream bearer, plus any tenant assertion) for a call."""

    def auth_headers(self, *, organization_id: uuid.UUID, subject_token: str | None) -> dict[str, str]: ...


class StaticServiceTokenProvider:
    """A fixed bearer — local-dev / tests. Optionally asserts the tenant (as the service modes do)."""

    def __init__(self, token: str, *, assert_tenant: bool = False) -> None:
        self._token = token
        self._assert_tenant = assert_tenant

    def auth_headers(self, *, organization_id: uuid.UUID, subject_token: str | None) -> dict[str, str]:
        headers = {"Authorization": f"Bearer {self._token}"}
        if self._assert_tenant:
            headers["X-Tenant-Id"] = str(organization_id)
        return headers


class KeycloakServiceTokenProvider:
    """Mint a downstream token from Keycloak, via RFC 8693 token exchange (preferred) or
    client-credentials. Tokens are cached in-process until just before they expire."""

    def __init__(
        self,
        *,
        mode: str,
        token_url: str,
        client_id: str,
        client_secret: str,
        audience: str,
        scope: str,
        http: httpx.Client,
        leeway_seconds: int = 15,
    ) -> None:
        if mode not in ("token_exchange", "client_credentials"):
            raise ValueError(f"Unsupported auth mode '{mode}'")
        self._mode = mode
        self._token_url = token_url
        self._client_id = client_id
        self._client_secret = client_secret
        self._audience = audience
        self._scope = scope
        self._http = http
        self._leeway = leeway_seconds
        self._cache: dict[str, tuple[float, str]] = {}

    def auth_headers(self, *, organization_id: uuid.UUID, subject_token: str | None) -> dict[str, str]:
        if self._mode == "token_exchange":
            if not subject_token:
                raise PaymentInitiationError("token exchange requires an inbound subject token")
            token = self._fetch(
                cache_key=f"exchange:{subject_token}",
                data={
                    "grant_type": _TOKEN_EXCHANGE_GRANT,
                    "client_id": self._client_id,
                    "client_secret": self._client_secret,
                    "subject_token": subject_token,
                    "subject_token_type": _ACCESS_TOKEN_TYPE,
                    "audience": self._audience,
                    "scope": self._scope,
                },
            )
            return {"Authorization": f"Bearer {token}"}
        # client_credentials: a service-account token + an explicit, trusted tenant assertion.
        token = self._fetch(
            cache_key="client_credentials",
            data={
                "grant_type": "client_credentials",
                "client_id": self._client_id,
                "client_secret": self._client_secret,
                "audience": self._audience,
                "scope": self._scope,
            },
        )
        return {"Authorization": f"Bearer {token}", "X-Tenant-Id": str(organization_id)}

    def _fetch(self, *, cache_key: str, data: dict[str, str]) -> str:
        now = time.monotonic()
        cached = self._cache.get(cache_key)
        if cached is not None and now < cached[0]:
            return cached[1]
        try:
            resp = self._http.post(self._token_url, data=data)
        except httpx.HTTPError as exc:  # network / timeout talking to Keycloak
            raise PaymentInitiationError(f"token endpoint unreachable: {exc}") from exc
        if resp.status_code >= 300:
            raise PaymentInitiationError(f"token endpoint returned {resp.status_code}")
        body: dict[str, Any] = resp.json()
        token = body.get("access_token")
        if not token:
            raise PaymentInitiationError("token endpoint response missing access_token")
        expires_in = int(body.get("expires_in", 60))
        self._cache[cache_key] = (now + max(expires_in - self._leeway, 0), str(token))
        return str(token)


def _to_write(request: PaymentIntentRequest) -> dict[str, Any]:
    """Shape the ``PaymentIntentWrite`` body (camelCase; money in integer minor units)."""
    body: dict[str, Any] = {
        "reference": {
            "entityType": request.reference.entity_type,
            "entityId": request.reference.entity_id,
        },
        "amount": {
            "amountMinor": request.amount_minor,
            "currency": request.currency,
        },
        "captureMode": request.capture_mode,
    }
    if request.payer.ref:
        body["payerRef"] = request.payer.ref
    if request.payer.email:
        body["payerEmail"] = request.payer.email
    if request.method_types:
        body["methodTypes"] = list(request.method_types)
    return body


def _parse(data: dict[str, Any]) -> InitiatedPayment:
    """Parse a ``PaymentIntentCreated`` response."""
    intent_id = data.get("id")
    if not intent_id:
        raise PaymentInitiationError("commerce-payments response missing intent id")
    return InitiatedPayment(
        gateway_intent_ref=str(intent_id),
        status=str(data.get("status", "")),
        client_secret=str(data["clientSecret"]) if data.get("clientSecret") else None,
        redirect_url=str(data["checkoutUrl"]) if data.get("checkoutUrl") else None,
    )


class HttpCommercePaymentsClient:
    """``PaymentInitiationPort`` adapter: ``POST {base_url}/v1/payment-intents``."""

    def __init__(
        self,
        *,
        base_url: str,
        token_provider: ServiceTokenProvider,
        http: httpx.Client,
        max_retries: int = 1,
    ) -> None:
        self._url = base_url.rstrip("/") + "/v1/payment-intents"
        self._tokens = token_provider
        self._http = http
        self._max_retries = max_retries

    def create_intent(self, request: PaymentIntentRequest, *, caller: CallerContext) -> InitiatedPayment:
        body = _to_write(request)
        last_error: Exception | None = None
        # One bounded retry (max_retries=1 → two attempts). Idempotent, so a retry can only dedupe.
        for _attempt in range(self._max_retries + 1):
            headers = {
                **self._tokens.auth_headers(
                    organization_id=caller.organization_id, subject_token=caller.subject_token
                ),
                "Idempotency-Key": request.idempotency_key,
            }
            try:
                resp = self._http.post(self._url, json=body, headers=headers)
            except httpx.HTTPError as exc:  # timeout / connect / network — retryable
                last_error = exc
                continue
            if resp.status_code < 300:
                return _parse(resp.json())
            if 500 <= resp.status_code < 600:  # server-side — retryable
                last_error = PaymentInitiationError(f"commerce-payments returned {resp.status_code}")
                continue
            # 4xx — a client error won't change on retry (bad request / forbidden / conflict).
            raise PaymentInitiationError(
                f"commerce-payments rejected the intent: {resp.status_code}"
            )
        raise PaymentInitiationError("commerce-payments unavailable after retry") from last_error


__all__ = [
    "ServiceTokenProvider",
    "StaticServiceTokenProvider",
    "KeycloakServiceTokenProvider",
    "HttpCommercePaymentsClient",
]
