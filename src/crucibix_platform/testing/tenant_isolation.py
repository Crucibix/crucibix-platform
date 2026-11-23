"""The tenant-isolation invariant — the reusable net that replaces Postgres RLS.

Background
----------
Multi-tenancy used to be a hard database guarantee: every tenant-owned row carried
``organization_id`` and a Row-Level-Security policy (``current_org_id()``) made it physically
impossible for one tenant's session to read another's rows — even a query that *forgot* to filter
was fenced in by the database. Under the Keycloak/OIDC model the tenant is a claim on the token,
read into :class:`~crucibix_platform.auth.context.AuthContext` and enforced in application code by
tenant-scoped repositories. That is more flexible but removes the DB-level net: **any repository
method that forgets to constrain a query by the caller's tenant silently leaks cross-tenant data**
(auth-migration spike, risk #4).

This module gives services two complementary, implementation-agnostic checks that together restore
what RLS guaranteed, with almost no per-query ceremony:

1. :func:`assert_tenant_isolation` — the **behavioural contract**. For each tenant-owned aggregate
   a service declares an :class:`IsolationCase`, then this helper proves the observable invariant:
   a row seeded under tenant *A* is invisible (and unwritable) under tenant *B*'s scope. It does not
   care *how* isolation is achieved (a ``WHERE`` predicate, a fetch-then-check, a FK-derived scope),
   so it never false-positives on legitimate patterns — it checks the only thing that actually
   matters, which is what RLS enforced: *B cannot observe A's data*.

2. :func:`assert_tenant_tables_covered` — the **completeness** net. It introspects the SQLAlchemy
   metadata for every tenant-owned table (any table with an ``organization_id`` column) and fails if
   one is neither exercised by an :class:`IsolationCase` nor explicitly allow-listed. This is the
   part that catches *the forgotten table* — add a new tenant-owned model and CI stays red until its
   isolation is proven or consciously waived. RLS covered every such table automatically; this makes
   the application-level net just as total.

Why a behavioural contract rather than a static "every query must filter ``organization_id``" lint?
Real repositories legitimately scope without an ``organization_id`` predicate in the SQL — e.g. a
``session.get(Model, pk)`` followed by a Python ownership check, or a child read filtered by a
parent FK whose row was already scoped. A predicate linter flags all of those as violations and
forces an allow-list that erodes into rubber-stamping. The contract test asserts the actual security
property instead, and the coverage check guarantees no table escapes it.

Usage (a service ``conftest.py`` / acceptance test)::

    from crucibix_platform.persistence.base import Base
    from crucibix_platform.testing import (
        IsolationCase, assert_tenant_isolation, assert_tenant_tables_covered,
    )
    import crucibix_finance.infrastructure.models  # noqa: F401  (register tables on Base)

    CASES = [
        IsolationCase(
            name="invoices",
            table="invoices",
            seed=lambda uow, org: _seed_invoice(uow, org),       # returns the new id
            read_by_id=lambda uow, iid: uow.invoices.get(iid),    # None/not-found == isolated
            list_in_scope=lambda uow: uow.invoices.list_for_org(uow.tenant_id),
            id_of=lambda inv: inv.id,
        ),
        # ... one per tenant-owned aggregate ...
    ]

    def test_tenant_isolation_contract(sql_uow_factory):
        assert_tenant_isolation(sql_uow_factory, CASES)

    def test_every_tenant_table_is_covered():
        assert_tenant_tables_covered(
            Base,
            CASES,
            allow={"outbox"},  # cross-tenant infra, org not an isolation boundary
        )

``sql_uow_factory`` is whatever the service already uses: a callable mapping a tenant id (or
``None`` for the unscoped consumer) to a context-managed unit of work, exactly like
``make_sql_uow_factory(engine)`` / ``make_uow_factory(store)``. The helper opens the scopes itself.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable, Sequence
from contextlib import AbstractContextManager
from dataclasses import dataclass
from typing import Any

from sqlalchemy import MetaData
from sqlalchemy.orm import DeclarativeBase

from crucibix_platform.domain.errors import EntityNotFound

# A unit of work is service-specific; the helper only ever opens it and calls the case's own
# closures against it, so it stays deliberately untyped (``Any``) rather than over-constraining.
Uow = Any
UowFactory = Callable[[uuid.UUID | None], AbstractContextManager[Uow]]

TENANT_COLUMN = "organization_id"

# Stable demo tenants. Any two distinct ids work; these are fixed so failure messages are readable.
_TENANT_A = uuid.UUID("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa")
_TENANT_B = uuid.UUID("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb")


def _default_id_of(entity: Any) -> Any:
    """Default identifier accessor: assume the entity exposes ``.id`` (every Crucibix aggregate does)."""
    return entity.id


class TenantIsolationViolation(AssertionError):
    """A tenant-owned table is observable across tenants, or escapes the isolation contract.

    Subclasses :class:`AssertionError` so it reads as a test failure (and pytest renders it as one)
    without this module depending on pytest.
    """


@dataclass(frozen=True)
class IsolationCase:
    """How to prove isolation for one tenant-owned aggregate.

    The closures receive a unit of work already opened at a given tenant scope and are expected to
    use that scope implicitly (the service's normal repository API), never to re-pass a tenant id of
    their own choosing — that is exactly the mistake under test.
    """

    #: Human label used in failure messages.
    name: str
    #: The SQL table name this case covers (ties the behavioural proof to the coverage check).
    table: str
    #: Seed one row under ``org`` using the scoped ``uow`` and return its identifier.
    #: The helper commits the surrounding unit of work for you if it exposes ``commit()``.
    seed: Callable[[Uow, uuid.UUID], Any]
    #: Read the entity back by the identifier ``seed`` returned, under the scoped ``uow``.
    #: Isolation means: under a *foreign* tenant this returns ``None`` **or** raises
    #: :class:`~crucibix_platform.domain.errors.EntityNotFound` (existence must not leak).
    read_by_id: Callable[[Uow, Any], Any | None]
    #: Optionally list the entities visible in the scoped ``uow``. The foreign tenant's listing must
    #: not contain the seeded id. This is the assertion that catches a dropped ``WHERE`` on a scan.
    list_in_scope: Callable[[Uow], Sequence[Any]] | None = None
    #: Extract the identifier from an entity returned by ``read_by_id`` / ``list_in_scope``.
    id_of: Callable[[Any], Any] = _default_id_of
    #: Optionally attempt to write the seeded (tenant-A) entity while scoped to tenant B. A correct
    #: repository rejects this (any exception); if the write silently succeeds it is a leak.
    write_foreign: Callable[[Uow, Any], None] | None = None


def _commit_if_possible(uow: Uow) -> None:
    commit = getattr(uow, "commit", None)
    if callable(commit):
        commit()


def _read_is_isolated(case: IsolationCase, uow: Uow, ident: Any) -> bool:
    """True when a foreign-tenant read does not expose the row (None, or a not-found error)."""
    try:
        found = case.read_by_id(uow, ident)
    except EntityNotFound:
        return True
    return found is None


def assert_tenant_isolation(
    uow_factory: UowFactory,
    cases: Sequence[IsolationCase],
    *,
    tenant_a: uuid.UUID | None = None,
    tenant_b: uuid.UUID | None = None,
) -> None:
    """Prove, for every case, that tenant B cannot observe or mutate tenant A's row.

    Raises :class:`TenantIsolationViolation` on the first breach, naming the case and the exact
    assertion that failed. Passing silently means the aggregates behave as RLS used to guarantee.
    """
    org_a = tenant_a or _TENANT_A
    org_b = tenant_b or _TENANT_B
    if org_a == org_b:
        raise ValueError("tenant_a and tenant_b must differ")

    for case in cases:
        # 1. Seed one row under tenant A and persist it.
        with uow_factory(org_a) as uow:
            ident = case.seed(uow, org_a)
            _commit_if_possible(uow)
        if ident is None:
            raise TenantIsolationViolation(
                f"[{case.name}] seed() returned None; it must return the new row's identifier"
            )

        # 2a. Under tenant A the row is of course visible — guards against a seed/read mismatch that
        #     would make the isolation assertions vacuously pass.
        with uow_factory(org_a) as uow:
            if _read_is_isolated(case, uow, ident):
                raise TenantIsolationViolation(
                    f"[{case.name}] the owning tenant cannot read back the row it seeded — the case's "
                    "seed()/read_by_id() disagree, so the isolation checks would be meaningless"
                )

        # 2b. Under tenant B the row must be invisible by id (no existence leak).
        with uow_factory(org_b) as uow:
            if not _read_is_isolated(case, uow, ident):
                raise TenantIsolationViolation(
                    f"[{case.name}] CROSS-TENANT LEAK: tenant B read tenant A's '{case.table}' row by id "
                    f"({ident}). read_by_id must return None or raise EntityNotFound out of scope."
                )

        # 3. Under tenant B the row must not appear in a scoped listing (catches a dropped WHERE).
        if case.list_in_scope is not None:
            with uow_factory(org_b) as uow:
                visible = [case.id_of(e) for e in case.list_in_scope(uow)]
            if ident in visible:
                raise TenantIsolationViolation(
                    f"[{case.name}] CROSS-TENANT LEAK: tenant A's '{case.table}' row ({ident}) is visible "
                    f"in tenant B's listing — the scan is not scoped by {TENANT_COLUMN}."
                )

        # 4. Optionally: tenant B must not be able to write tenant A's row.
        if case.write_foreign is not None:
            with uow_factory(org_b) as uow:
                try:
                    case.write_foreign(uow, ident)
                    _commit_if_possible(uow)
                except Exception:
                    # Any rejection is acceptable; a silent success is the bug we are hunting.
                    pass
                else:
                    raise TenantIsolationViolation(
                        f"[{case.name}] CROSS-TENANT WRITE: tenant B wrote tenant A's '{case.table}' row "
                        f"({ident}) without being rejected."
                    )


def tenant_owned_tables(metadata_or_base: MetaData | type[DeclarativeBase]) -> frozenset[str]:
    """Names of every mapped table that is tenant-owned, i.e. carries an ``organization_id`` column.

    Accepts either a :class:`~sqlalchemy.MetaData` or a declarative ``Base`` class. This catches both
    tables using :class:`~crucibix_platform.persistence.base.TenantScopedMixin` and read-models that
    declare ``organization_id`` directly (e.g. as a primary key). Tables keyed by a different tenant
    column (the outbox's nullable ``tenant_id``) are intentionally *not* flagged: there the org is not
    an isolation boundary, and such tables belong in the ``allow`` set of the coverage check.
    """
    metadata = metadata_or_base if isinstance(metadata_or_base, MetaData) else metadata_or_base.metadata
    return frozenset(
        name for name, table in metadata.tables.items() if TENANT_COLUMN in table.columns
    )


def assert_tenant_tables_covered(
    metadata_or_base: MetaData | type[DeclarativeBase],
    cases: Sequence[IsolationCase],
    *,
    allow: frozenset[str] | set[str] | Sequence[str] = (),
) -> None:
    """Fail if any tenant-owned table is neither exercised by a case nor explicitly allow-listed.

    This is the completeness half of the invariant: it is what makes *forgetting* a table loud. A
    table belongs in ``allow`` only when the org id is genuinely not an isolation boundary for it
    (cross-tenant infrastructure such as the outbox) — and every entry should carry a comment saying
    why, because an allow-list entry is a waiver of the net RLS used to provide for free.
    """
    owned = tenant_owned_tables(metadata_or_base)
    covered = {case.table for case in cases} | set(allow)

    missing = sorted(owned - covered)
    if missing:
        raise TenantIsolationViolation(
            "tenant-owned tables with no isolation coverage: "
            + ", ".join(missing)
            + ". Add an IsolationCase for each (asserting a foreign tenant cannot read it), or, only "
            "if the organization is not an isolation boundary there, add it to `allow` with a reason."
        )

    stale = sorted({case.table for case in cases} - owned)
    if stale:
        raise TenantIsolationViolation(
            "IsolationCase declared for non-tenant-owned (or unknown) table(s): "
            + ", ".join(stale)
            + f". Each case.table must be a mapped table carrying an '{TENANT_COLUMN}' column — check "
            "the table name and that its models module was imported so the table is registered."
        )
