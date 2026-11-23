"""The application port for the one sanctioned sync call and its value types.

A paying context originates a ``PaymentIntent`` via :class:`PaymentInitiationPort`; the HTTP adapter
(:class:`~crucibix_platform.payments.client.HttpCommercePaymentsClient`) implements it. These types
are domain-agnostic on purpose: ``amount`` is carried as integer **minor units** + an ISO currency
(the frozen commerce-payments OpenAPI shape), so no service's ``Money`` value object leaks into the
shared kernel — each caller converts its own money at the boundary.
"""

from __future__ import annotations

import uuid
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Protocol


@dataclass(frozen=True, slots=True)
class PaymentReference:
    """The opaque link to the thing being paid for. The consumer loop keys on ``(entity_type, id)``.

    Fleet ``entity_type`` vocabulary: ``"order"`` (orders), ``"invoice"`` (finance),
    ``"capital_call"`` (investors).
    """

    entity_type: str
    entity_id: str


@dataclass(frozen=True, slots=True)
class PayerRef:
    """Opaque payer identity for the PSP. Never carries card data."""

    ref: str | None = None
    email: str | None = None


@dataclass(frozen=True, slots=True)
class PaymentIntentRequest:
    """What to originate: a reference, the amount (minor units + currency), and a deterministic
    idempotency key so a retried origination never double-creates an intent."""

    reference: PaymentReference
    amount_minor: int
    currency: str
    idempotency_key: str
    payer: PayerRef = field(default_factory=PayerRef)
    method_types: Sequence[str] = ()
    capture_mode: str = "auto"


@dataclass(frozen=True, slots=True)
class CallerContext:
    """Who the outbound call acts for: the tenant + (optionally) the inbound end-user token.

    ``subject_token`` is the raw inbound bearer, propagated from the HTTP edge so the adapter can
    perform an RFC 8693 token exchange for a downstream token scoped to this tenant with
    ``payments:collect``. It is ``None`` for non-HTTP callers or the client-credentials auth mode.
    """

    organization_id: uuid.UUID
    subject_token: str | None = None


@dataclass(frozen=True, slots=True)
class InitiatedPayment:
    """The originated intent — what the interface layer needs to collect payment from the payer."""

    gateway_intent_ref: str
    status: str
    client_secret: str | None = None
    redirect_url: str | None = None


class PaymentInitiationError(Exception):
    """The intent could not be originated (commerce-payments/PSP unavailable, or it rejected the
    call) after the adapter's bounded retry. Callers degrade gracefully on this — origination must
    NEVER block the primary flow on the PSP being up."""


class PaymentInitiationPort(Protocol):
    """Originate a payment intent in commerce-payments. Implemented by the HTTP adapter."""

    def create_intent(
        self, request: PaymentIntentRequest, *, caller: CallerContext
    ) -> InitiatedPayment: ...


__all__ = [
    "PaymentReference",
    "PayerRef",
    "PaymentIntentRequest",
    "CallerContext",
    "InitiatedPayment",
    "PaymentInitiationError",
    "PaymentInitiationPort",
]
