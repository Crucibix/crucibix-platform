from __future__ import annotations

import uuid

import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from crucibix_platform import PlatformSettings, create_app, require_privilege
from crucibix_platform.auth.context import AuthContext
from crucibix_platform.domain.errors import InvariantViolation

TENANT = uuid.UUID("11111111-1111-1111-1111-111111111111")
SUBJECT = uuid.UUID("22222222-2222-2222-2222-222222222222")


class FakeVerifier:
    """Test verifier: the bearer token is a comma-separated privilege list.
    'invalid' raises; 'operator' yields a platform operator with no tenant."""

    def verify(self, token: str, *, correlation_id: str | None = None) -> AuthContext:
        from crucibix_platform.domain.errors import AccessDenied

        if token == "invalid":
            raise AccessDenied("Invalid token")
        if token == "operator":
            return AuthContext(
                subject=SUBJECT, email="op@crucibix.com", tenant_id=None,
                is_platform_operator=True, privileges=frozenset({"platform.tenants:manage"}),
            )
        privileges = frozenset(p for p in token.split(",") if p)
        return AuthContext(
            subject=SUBJECT, email="user@acme.test", tenant_id=TENANT,
            roles=frozenset({"director"}), privileges=privileges, correlation_id=correlation_id,
        )


def _sample_router() -> APIRouter:
    r = APIRouter(tags=["sample"])

    @r.get("/secure", dependencies=[Depends(require_privilege("investors:read"))])
    async def secure() -> dict[str, bool]:
        return {"ok": True}

    @r.get("/boom")
    async def boom() -> dict[str, str]:
        raise InvariantViolation("cannot do that")

    return r


@pytest.fixture
def client() -> TestClient:
    app = create_app(
        PlatformSettings(service_name="test"),
        routers=[_sample_router()],
        token_verifier=FakeVerifier(),
    )
    return TestClient(app)
