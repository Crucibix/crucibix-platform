"""Producer-side payment origination — the fleet's one sanctioned synchronous cross-service call.

A paying context (orders at checkout, finance at "pay invoice", investors at "pay capital call")
**originates** a ``PaymentIntent`` in the commerce-payments service and gets a client secret /
redirect back to hand the payer. This is the only request/response cross-service call in the fleet;
everything after creation stays event-driven (the PSP webhook settles the intent → commerce-payments
emits ``payments.PaymentCaptured`` → the paying context's already-wired consumer reconciles the
domain entity).

This package holds the reusable seam promoted out of ``crucibix-orders``:

* :mod:`~crucibix_platform.payments.initiation` — the application ``PaymentInitiationPort`` + its
  value types (opaque reference, amount, payer, caller context, result, error).
* :mod:`~crucibix_platform.payments.client` — the service-to-service auth providers
  (:class:`ServiceTokenProvider` / RFC 8693 token exchange / client-credentials / static) and the
  HTTP adapter :class:`HttpCommercePaymentsClient`.
* :mod:`~crucibix_platform.payments.settings` — the ``CRUCIBIX_COMMERCE_PAYMENTS_*`` settings mixin.
* :mod:`~crucibix_platform.payments.factory` — :func:`build_commerce_payments_client`, which wires an
  :class:`HttpCommercePaymentsClient` from settings (secrets resolved via a
  :class:`~crucibix_platform.secrets.SecretResolver`).
"""

from __future__ import annotations

from crucibix_platform.payments.client import (
    HttpCommercePaymentsClient,
    KeycloakServiceTokenProvider,
    ServiceTokenProvider,
    StaticServiceTokenProvider,
)
from crucibix_platform.payments.factory import build_commerce_payments_client
from crucibix_platform.payments.initiation import (
    CallerContext,
    InitiatedPayment,
    PayerRef,
    PaymentInitiationError,
    PaymentInitiationPort,
    PaymentIntentRequest,
    PaymentReference,
)
from crucibix_platform.payments.settings import CommercePaymentsClientSettings

__all__ = [
    "PaymentReference",
    "PayerRef",
    "PaymentIntentRequest",
    "CallerContext",
    "InitiatedPayment",
    "PaymentInitiationError",
    "PaymentInitiationPort",
    "ServiceTokenProvider",
    "StaticServiceTokenProvider",
    "KeycloakServiceTokenProvider",
    "HttpCommercePaymentsClient",
    "CommercePaymentsClientSettings",
    "build_commerce_payments_client",
]
