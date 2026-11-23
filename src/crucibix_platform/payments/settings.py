"""Settings mixin for a context that originates commerce-payments intents.

A paying service extends this instead of :class:`~crucibix_platform.config.PlatformSettings`
directly, and overrides ``commerce_payments_client_id`` with its own service-account id. All env vars
carry the platform ``CRUCIBIX_`` prefix, e.g. ``commerce_payments_base_url`` ←
``CRUCIBIX_COMMERCE_PAYMENTS_BASE_URL``.
"""

from __future__ import annotations

from crucibix_platform.config import PlatformSettings


class CommercePaymentsClientSettings(PlatformSettings):
    """The ``CRUCIBIX_COMMERCE_PAYMENTS_*`` knobs for the producer-side payment-origination call."""

    # Base URL of commerce-payments. Local compose: the service hostname on the compose network;
    # prod: the ALB ``/payments`` route. Empty disables origination (the primary flow still runs).
    commerce_payments_base_url: str = "http://commerce-payments:8000"
    commerce_payments_timeout_seconds: float = 5.0
    # Default payment method types + capture mode offered when originating an intent (config, not
    # hardcoded per tenant). Empty method_types lets commerce-payments route by its gateway config.
    commerce_payments_method_types: list[str] = []
    commerce_payments_capture_mode: str = "auto"

    # Service-to-service auth: "token_exchange" (preferred, RFC 8693) | "client_credentials" | "static".
    commerce_payments_auth_mode: str = "token_exchange"
    # Keycloak token endpoint (defaults to the OIDC issuer's token endpoint when unset).
    commerce_payments_token_url: str | None = None
    # Each service overrides this with its own service-account client id (e.g. ``orders-svc``).
    commerce_payments_client_id: str = "crucibix-svc"
    # Secrets Manager REFERENCE (ARN/name) for the service-account secret — never an inline secret.
    commerce_payments_client_secret_ref: str | None = None
    commerce_payments_audience: str = "commerce-payments"
    commerce_payments_scope: str = "payments:collect"
    # Local-dev / test only: a fixed bearer used when auth_mode == "static" (no Keycloak needed).
    commerce_payments_static_token: str | None = None

    def resolved_token_url(self) -> str:
        if self.commerce_payments_token_url:
            return self.commerce_payments_token_url
        return self.oidc_issuer.rstrip("/") + "/protocol/openid-connect/token"


__all__ = ["CommercePaymentsClientSettings"]
