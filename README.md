# crucibix-platform

The shared **FastAPI + hexagonal/DDD** foundation every Crucibix service is built on. Provides
the cross-cutting machinery so each `crucibix-<context>` service focuses on its domain:

| Area | What you get |
|---|---|
| **API** | `create_app()` factory, RFC 9457 `problem+json` errors, health/readiness, correlation-id + structured access logging |
| **AuthN/Z** | `AuthContext` (tenant, subject, roles, effective privileges), OIDC JWT verification behind a swappable port, `require_privilege("...")` dependency |
| **Tenancy** | request-scoped tenant/correlation context, tenant-scoped column mixin (pooled multi-tenancy), and a reusable **tenant-isolation invariant** (`crucibix_platform.testing`) that replaces the DB-level net RLS used to give |
| **Domain** | `AggregateRoot` / `Entity` / `ValueObject` / `DomainEvent` base classes + a domain error hierarchy |
| **Events** | the shared event envelope (matches the AsyncAPI contract), `EventPublisher` port + transactional **outbox** + `ProcessedEvent` idempotency ledger |
| **Observability** | structlog JSON logging + optional OpenTelemetry wiring |
| **PII encryption** | per-org envelope encryption (`crucibix_platform.security.pii`): a KMS-wrapped data key, an `EnvelopeCipher` with key rotation, and an `EncryptedType` SQLAlchemy column for PII fields |

## Use it in a service

```python
from crucibix_platform import create_app, PlatformSettings, require_privilege
from fastapi import APIRouter, Depends

router = APIRouter()


@router.get("/investors", dependencies=[Depends(require_privilege("investors:read"))])
async def list_investors(): ...


app = create_app(PlatformSettings(service_name="investors"), routers=[router])
```

## CI

Services inherit the full Definition-of-Done gate by calling the reusable workflow:

```yaml
jobs:
  ci:
    uses: Crucibix/crucibix-platform/.github/workflows/python-service.yml@main
    with: { service: identity }
```

That runs lint (ruff), type-check (mypy --strict), SAST + dependency + secret scans, unit +
integration + acceptance tests with coverage (Postgres service container + Alembic migrate),
contract verification, and a Trivy-scanned container build. `templates/Dockerfile` is the
reference image.

## Tenant isolation (the RLS replacement)

Under the old model, cross-tenant isolation was a hard Postgres guarantee: every tenant-owned row
carried `organization_id` and a Row-Level-Security policy fenced each tenant into its own rows, so a
query that *forgot* to filter still could not leak. With the tenant now a token claim enforced in
application code (`AuthContext.tenant_id` + tenant-scoped repositories), that database net is gone —
**any repository method that forgets to scope a query silently leaks another tenant's data**
(auth-migration spike, risk #4).

`crucibix_platform.testing` restores that net at the application layer with two complementary checks
a service runs in its own suite — no runtime cost, nothing shipped in the image:

- **`assert_tenant_isolation`** — the behavioural contract. Per tenant-owned aggregate you declare an
  `IsolationCase`; the helper seeds a row under tenant *A* and proves it is invisible (and unwritable)
  under tenant *B*. It is implementation-agnostic (works whether you scope with a `WHERE`, a
  fetch-then-check, or a parent FK), so it asserts the security property itself and never
  false-positives on a legitimate pattern.
- **`assert_tenant_tables_covered`** — the completeness net. It introspects the SQLAlchemy metadata
  for every tenant-owned table (any table with an `organization_id` column) and fails if one is
  neither exercised by a case nor explicitly allow-listed. Add a new tenant-owned model and CI stays
  red until its isolation is proven — this is what makes *forgetting a whole table* loud, exactly as
  RLS covered every table for free.

### Adopt it in a service

Add the two tests to your suite (they need no database — run them against your in-memory UoW factory,
or against the Postgres one in the integration job):

```python
# tests/acceptance/test_tenant_isolation.py
from crucibix_platform.persistence.base import Base
from crucibix_platform.testing import (
    IsolationCase, assert_tenant_isolation, assert_tenant_tables_covered,
)
import crucibix_<ctx>.infrastructure.models  # noqa: F401  — register tables on Base

CASES = [
    IsolationCase(
        name="invoices",
        table="invoices",
        seed=lambda uow, org: _seed_invoice(uow, org),     # returns the new row's id
        read_by_id=lambda uow, iid: uow.invoices.get(iid),  # None / EntityNotFound out of scope
        list_in_scope=lambda uow: uow.invoices.list_for_org(uow.tenant_id),
        id_of=lambda inv: inv.id,
        # optional: write_foreign=lambda uow, iid: uow.invoices.update(_mutate(iid)),
    ),
    # ... one per tenant-owned aggregate ...
]

def test_tenant_isolation_contract(sql_uow_factory):     # your make_sql_uow_factory(engine)
    assert_tenant_isolation(sql_uow_factory, CASES)

def test_every_tenant_table_is_covered():
    assert_tenant_tables_covered(
        Base, CASES,
        allow={"outbox"},  # cross-tenant infra — org is not an isolation boundary here
    )
```

The UoW factory is whatever you already have: a callable mapping a tenant id (or `None` for the
unscoped consumer) to a context-managed unit of work. Every entry in `allow` is a conscious waiver —
keep a comment saying why the organization is not an isolation boundary for that table.

## PII field encryption (per-org)

Sensitive columns — `investor_pii`, `employee_pii`, `salary`, `patient_pii` — must be encrypted at
rest under a **per-org** key (compliance gate, gap #15). `crucibix_platform.security.pii` provides
the shared kernel; the identity-access *org keyring API* (DEK storage + rotation endpoint) wires it
to a key store separately.

It is textbook **envelope encryption**. A per-org 256-bit **DEK** encrypts field values with
AES-256-GCM (random nonce per value, org id + key version bound as associated data). The DEK is
itself wrapped by a **KEK** through a `KmsPort` — `LocalKms` (a config master key, for dev/compose)
or `AwsKms` (AWS KMS; the KEK never leaves KMS). Only the *wrapped* DEK is ever persisted, and the
decrypt path uses a cached unwrapped DEK, so there is **no KMS/network hop per value**. Any tamper,
wrong key, wrong org, or malformed envelope **raises** `PiiDecryptionError` — plaintext is never
returned on failure. Rotation mints a new DEK version (current for new writes) while old versions
keep decrypting until each value is re-encrypted.

The org context reaches the SQLAlchemy column type through a context var (same pattern as the request
tenant), bound per unit of work:

```python
from crucibix_platform.security.pii import (
    EncryptedType, EnvelopeCipher, OrgKeyring, build_kms, pii_encryption,
)

class Employee(Base, TenantScopedMixin):
    __tablename__ = "employees"
    employee_pii: Mapped[str] = mapped_column(EncryptedType())
    salary: Mapped[int] = mapped_column(EncryptedType(serializer=str, deserializer=int))

kms = build_kms(settings)                                        # LocalKms (dev) | AwsKms (prod)
cipher = EnvelopeCipher(OrgKeyring.load(org_id, kms, versions, current))  # versions from the key store
with pii_encryption(cipher):                                     # bind once per request/UoW
    session.add(Employee(organization_id=org_id, employee_pii="…", salary=90_000))
    session.commit()                                             # both columns encrypted with THIS org's DEK
```

`OrgKeyring.create(org_id, kms)` mints a brand-new keyring (first-time onboarding);
`cipher.rotate(values)` mints the next DEK version and re-encrypts the values you pass. Configure the
KEK with the `CRUCIBIX_PII_*` settings (`PiiEncryptionSettings`): `pii_kms_mode` (`local`/`aws`),
`pii_master_key` (base64, local mode — required outside dev), `pii_kms_key_id` (aws mode).

## Develop

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests && mypy src && pytest -q
```

Status: core is implemented and tested (`ruff` + `mypy --strict` + `pytest` all green).
