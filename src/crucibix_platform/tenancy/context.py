"""Request-scoped tenancy + correlation context.

Threaded through logs, traces, events and the tenant-scoped DB session so isolation is a
cross-cutting invariant rather than something each query remembers to apply.
"""

from __future__ import annotations

import uuid
from contextvars import ContextVar
from dataclasses import dataclass

_tenant_id: ContextVar[uuid.UUID | None] = ContextVar("tenant_id", default=None)
_correlation_id: ContextVar[str | None] = ContextVar("correlation_id", default=None)
_subject: ContextVar[uuid.UUID | None] = ContextVar("subject", default=None)


@dataclass(frozen=True, slots=True)
class RequestContext:
    tenant_id: uuid.UUID | None
    correlation_id: str | None
    subject: uuid.UUID | None


def set_request_context(
    *, tenant_id: uuid.UUID | None, correlation_id: str | None, subject: uuid.UUID | None
) -> None:
    _tenant_id.set(tenant_id)
    _correlation_id.set(correlation_id)
    _subject.set(subject)


def current_tenant_id() -> uuid.UUID | None:
    return _tenant_id.get()


def current_correlation_id() -> str | None:
    return _correlation_id.get()


def require_tenant_id() -> uuid.UUID:
    tid = _tenant_id.get()
    if tid is None:
        raise RuntimeError("No tenant in context — a tenant-scoped operation ran unscoped")
    return tid


def get_request_context() -> RequestContext:
    return RequestContext(_tenant_id.get(), _correlation_id.get(), _subject.get())
