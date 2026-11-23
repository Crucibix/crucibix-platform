"""Test-support helpers that services import from their own test suites.

Nothing in this subpackage is imported by the runtime package, so pulling it in never drags
test-only machinery into a service image. The headline export is the **tenant-isolation
invariant** (``tenant_isolation``): the reusable net that replaces the DB-level guarantee
Postgres RLS used to give (see ``crucibix-docs/architecture/auth-migration-spike.md`` risk #4).
"""

from __future__ import annotations

from crucibix_platform.testing.tenant_isolation import (
    IsolationCase,
    TenantIsolationViolation,
    assert_tenant_isolation,
    assert_tenant_tables_covered,
    tenant_owned_tables,
)

__all__ = [
    "IsolationCase",
    "TenantIsolationViolation",
    "assert_tenant_isolation",
    "assert_tenant_tables_covered",
    "tenant_owned_tables",
]
