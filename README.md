# crucibix-platform

The shared **FastAPI + hexagonal/DDD** foundation every Crucibix service is built on. Provides
the cross-cutting machinery so each `crucibix-<context>` service focuses on its domain:

| Area | What you get |
|---|---|
| **API** | `create_app()` factory, RFC 9457 `problem+json` errors, health/readiness, correlation-id + structured access logging |
| **AuthN/Z** | `AuthContext` (tenant, subject, roles, effective privileges), OIDC JWT verification behind a swappable port, `require_privilege("...")` dependency |
| **Tenancy** | request-scoped tenant/correlation context, tenant-scoped column mixin (pooled multi-tenancy) |
| **Domain** | `AggregateRoot` / `Entity` / `ValueObject` / `DomainEvent` base classes + a domain error hierarchy |
| **Events** | the shared event envelope (matches the AsyncAPI contract), `EventPublisher` port + transactional **outbox** + `ProcessedEvent` idempotency ledger |
| **Observability** | structlog JSON logging + optional OpenTelemetry wiring |

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

## Develop

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests && mypy src && pytest -q
```

Status: core is implemented and tested (`ruff` + `mypy --strict` + `pytest` all green).
