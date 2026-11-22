"""SQLAlchemy foundations shared by services: declarative base, a tenant-scoped column mixin,
and the Unit-of-Work port. Repositories MUST filter tenant-scoped reads/writes by the current
tenant (``require_tenant_id``); the tenant-isolation test suite proves they do."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Protocol

from sqlalchemy import DateTime, func
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class TenantScopedMixin:
    """Every tenant-owned row carries organization_id (pooled multi-tenancy, ADR-013)."""

    organization_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), index=True, nullable=False)


class UnitOfWork(Protocol):
    """Transactional boundary: a use case does its work, then the UoW commits aggregate
    changes + outbox rows atomically."""

    def __enter__(self) -> UnitOfWork: ...
    def __exit__(self, *args: object) -> None: ...
    def commit(self) -> None: ...
    def rollback(self) -> None: ...
