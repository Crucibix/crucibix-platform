"""Tests for the reusable tenant-isolation invariant (``crucibix_platform.testing``).

Uses a self-contained toy domain: two tenant-owned tables and a pair of in-memory repositories —
one correctly scoped, one with the classic risk-#4 bug (a listing that forgets its tenant filter) —
so we can prove the helper *passes* on correct code and *catches* a leak, without a database.
"""

from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

import pytest
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from crucibix_platform.persistence.base import TenantScopedMixin
from crucibix_platform.testing import (
    IsolationCase,
    TenantIsolationViolation,
    assert_tenant_isolation,
    assert_tenant_tables_covered,
    tenant_owned_tables,
)


# ── A toy mapped domain, on its own Base so it never pollutes the platform metadata ──────────────
class ToyBase(DeclarativeBase):
    pass


class Widget(ToyBase, TenantScopedMixin):
    __tablename__ = "widgets"
    id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)


class WidgetSettings(ToyBase):
    """A read-model that declares organization_id directly (as PK) — still tenant-owned."""

    __tablename__ = "widget_settings"
    organization_id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)


class GlobalRegistry(ToyBase):
    """Not tenant-owned: no organization_id column."""

    __tablename__ = "global_registry"
    id: Mapped[uuid.UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True)


# ── A tiny tenant-scoped repository + UoW, in memory ─────────────────────────────────────────────
class _Row:
    def __init__(self, rid: uuid.UUID, org: uuid.UUID) -> None:
        self.id = rid
        self.organization_id = org


class _Store:
    def __init__(self) -> None:
        self.rows: dict[uuid.UUID, _Row] = {}


class _FakeUow:
    def __init__(self, store: _Store, scope: uuid.UUID | None, *, leaky: bool) -> None:
        self.tenant_id = scope
        self._store = store
        self._scope = scope
        self._leaky = leaky

    def add(self, org: uuid.UUID) -> uuid.UUID:
        row = _Row(uuid.uuid4(), org)
        self._store.rows[row.id] = row
        return row.id

    def get(self, rid: uuid.UUID) -> _Row | None:
        row = self._store.rows.get(rid)
        if row is None or (self._scope is not None and row.organization_id != self._scope):
            return None
        return row

    def listing(self) -> list[_Row]:
        rows = list(self._store.rows.values())
        if self._leaky:
            return rows  # BUG: forgets to filter by self._scope — risk #4.
        if self._scope is None:
            return rows
        return [r for r in rows if r.organization_id == self._scope]

    def commit(self) -> None:  # no-op; the store is already mutated
        pass


def _factory(store: _Store, *, leaky: bool):  # type: ignore[no-untyped-def]
    @contextmanager
    def factory(scope: uuid.UUID | None) -> Iterator[_FakeUow]:
        yield _FakeUow(store, scope, leaky=leaky)

    return factory


def _case() -> IsolationCase:
    return IsolationCase(
        name="widgets",
        table="widgets",
        seed=lambda uow, org: uow.add(org),
        read_by_id=lambda uow, rid: uow.get(rid),
        list_in_scope=lambda uow: uow.listing(),
    )


# ── Behavioural contract ─────────────────────────────────────────────────────────────────────────
def test_passes_for_correctly_scoped_repository() -> None:
    assert_tenant_isolation(_factory(_Store(), leaky=False), [_case()])


def test_catches_a_listing_that_forgets_its_tenant_filter() -> None:
    with pytest.raises(TenantIsolationViolation, match="CROSS-TENANT LEAK"):
        assert_tenant_isolation(_factory(_Store(), leaky=True), [_case()])


def test_catches_a_read_by_id_that_leaks() -> None:
    store = _Store()

    class _LeakyReadUow(_FakeUow):
        def get(self, rid: uuid.UUID) -> _Row | None:
            return self._store.rows.get(rid)  # BUG: no scope check at all

    @contextmanager
    def factory(scope: uuid.UUID | None) -> Iterator[_FakeUow]:
        yield _LeakyReadUow(store, scope, leaky=False)

    case = IsolationCase(
        name="widgets",
        table="widgets",
        seed=lambda uow, org: uow.add(org),
        read_by_id=lambda uow, rid: uow.get(rid),
    )
    with pytest.raises(TenantIsolationViolation, match="read tenant A's"):
        assert_tenant_isolation(factory, [case])


def test_rejects_a_case_whose_seed_returns_none() -> None:
    case = IsolationCase(
        name="widgets",
        table="widgets",
        seed=lambda uow, org: None,
        read_by_id=lambda uow, rid: None,
    )
    with pytest.raises(TenantIsolationViolation, match="must return the new row's identifier"):
        assert_tenant_isolation(_factory(_Store(), leaky=False), [case])


def test_requires_distinct_tenants() -> None:
    org = uuid.uuid4()
    with pytest.raises(ValueError, match="must differ"):
        assert_tenant_isolation(_factory(_Store(), leaky=False), [_case()], tenant_a=org, tenant_b=org)


# ── Completeness / coverage ──────────────────────────────────────────────────────────────────────
def test_tenant_owned_tables_detects_mixin_and_direct_columns() -> None:
    owned = tenant_owned_tables(ToyBase)
    assert owned == {"widgets", "widget_settings"}
    assert "global_registry" not in owned


def test_coverage_passes_when_every_table_is_cased_or_allowed() -> None:
    cases = [_case()]
    assert_tenant_tables_covered(ToyBase, cases, allow={"widget_settings"})


def test_coverage_fails_on_a_forgotten_table() -> None:
    with pytest.raises(TenantIsolationViolation, match="widget_settings"):
        assert_tenant_tables_covered(ToyBase, [_case()])


def test_coverage_fails_on_a_case_for_an_unknown_table() -> None:
    bogus = IsolationCase(
        name="nope",
        table="does_not_exist",
        seed=lambda uow, org: uow.add(org),
        read_by_id=lambda uow, rid: uow.get(rid),
    )
    with pytest.raises(TenantIsolationViolation, match="non-tenant-owned"):
        assert_tenant_tables_covered(ToyBase, [_case(), bogus], allow={"widget_settings"})
