"""Wire an :class:`HttpCommercePaymentsClient` from service settings.

:func:`build_commerce_payments_client` is the single entry point a paying service's composition root
calls: it selects the secret resolver (env in dev, AWS Secrets Manager otherwise) and the
service-to-service auth provider (token exchange / client-credentials / static) from the
``CRUCIBIX_COMMERCE_PAYMENTS_*`` settings, and returns a ready port — or ``None`` when origination is
disabled (empty base URL), so the caller's primary flow still runs.
"""

from __future__ import annotations

import httpx

from crucibix_platform.payments.client import (
    HttpCommercePaymentsClient,
    KeycloakServiceTokenProvider,
    ServiceTokenProvider,
    StaticServiceTokenProvider,
)
from crucibix_platform.payments.initiation import PaymentInitiationPort
from crucibix_platform.payments.settings import CommercePaymentsClientSettings
from crucibix_platform.secrets import (
    EnvSecretResolver,
    SecretResolver,
    SecretsManagerResolver,
)


def _secret_resolver(settings: CommercePaymentsClientSettings) -> SecretResolver:
    if settings.environment == "dev":
        return EnvSecretResolver()
    return SecretsManagerResolver(region=settings.aws_region, endpoint_url=settings.aws_endpoint_url)


def _token_provider(
    settings: CommercePaymentsClientSettings, http: httpx.Client, secrets: SecretResolver
) -> ServiceTokenProvider:
    mode = settings.commerce_payments_auth_mode
    if mode == "static":
        token = settings.commerce_payments_static_token or f"dev-{settings.commerce_payments_client_id}-token"
        return StaticServiceTokenProvider(token, assert_tenant=True)
    client_secret = secrets.resolve(settings.commerce_payments_client_secret_ref) or ""
    return KeycloakServiceTokenProvider(
        mode=mode,
        token_url=settings.resolved_token_url(),
        client_id=settings.commerce_payments_client_id,
        client_secret=client_secret,
        audience=settings.commerce_payments_audience,
        scope=settings.commerce_payments_scope,
        http=http,
    )


def build_commerce_payments_client(
    settings: CommercePaymentsClientSettings,
) -> PaymentInitiationPort | None:
    """Build the payment-origination port from settings, or ``None`` when origination is disabled."""
    if not settings.commerce_payments_base_url:
        return None  # origination disabled — the caller's primary flow still runs
    http = httpx.Client(timeout=settings.commerce_payments_timeout_seconds)
    provider = _token_provider(settings, http, _secret_resolver(settings))
    return HttpCommercePaymentsClient(
        base_url=settings.commerce_payments_base_url, token_provider=provider, http=http
    )


__all__ = ["build_commerce_payments_client"]
